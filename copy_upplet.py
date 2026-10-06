#!/usr/bin/env python3
"""
copy_upplet.py — copy one upplet onto another (the dashboard's New Upplet → Copy).

The two agents do the work between themselves; the dashboard only starts it and
hands both of them the same one-off key (the agent's /copy-key on the copied
upplet, /copy-start on the new one). Every byte goes from agent to agent.

On the copied upplet (the source) a copy is read-only: these read files and
databases and write nothing but their output.

    copy_upplet.py inventory <app,app,… | ->
                    the calculation stage, before anything is created: how much
                    of the disk is in use, and for each app how big its database
                    is, as the database itself reports it — and from that a rough
                    guess at its archive (ARCHIVE_RATIO). Nothing is dumped. Its
                    output is the agent's log of it, ending with the result as
                    JSON on one line. "-": every app.
    copy_upplet.py stream <item>
                    one archive, written to stdout as it is made (the agent's
                    /copy/file sends it on as it comes):
                      db:<app>       the app's database, dumped and gzipped
                                     (pg_dump custom format, mysqldump SQL, or
                                     SQLite's SQL dump)
                      config:<app>   /etc/<app>.env, /etc/<app>/ (not its certs)
                                     and the app's untracked .env files
                      site           the static site Nginx serves (/var/www/html)
                      letsencrypt    /etc/letsencrypt
                      squid          Squid's passwd file and whitelist
                    all but db:<app> as a gzipped tar. A stream that fails stops
                    before its end, so the receiver sees it is incomplete.
    copy_upplet.py manifest
                    what the new upplet needs to know, as JSON on stdout: each
                    app's install request (repo, branch, key, type, command,
                    ports, dependencies), its database and Nginx settings, Squid,
                    the static site; the agent adds the firewall and allowed
                    addresses from the grant, which it keeps in memory

On the new upplet (the target), as its install — the same lock, /progress and
setup.log an app install uses (the agent's /copy-start):

    copy_upplet.py import <request.json>
                    installs every app chosen from scratch and brings its config
                    files and database over; sets Nginx and Squid up as they are
                    there; copies P5AGENT_ALLOW_IP and the firewall rules 1:1;
                    makes sure every service needed is running; then logs
                    "copy installation completed" — the agent's marker.

Standard library only, like the agent.
"""

import json
import os
import re
import shlex
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from datetime import datetime

HERE = os.path.dirname(os.path.realpath(__file__))
DATA_DIR = os.environ.get("P5AGENT_DATA_DIR", "/var/lib/p5agent")
APPS_DIR = os.environ.get("P5AGENT_APPS_DIR", "/opt")
TMP_DIR = os.environ.get("P5AGENT_TMP_DIR", "/tmp")
ENV_FILE = os.environ.get("P5AGENT_ENV_FILE", "/etc/p5agent.env")
AGENT_PORT = int(os.environ.get("P5AGENT_PORT", "5005"))

INSTALLED = os.path.join(DATA_DIR, "installed_apps.json")
SETUP_LOG = os.path.join(DATA_DIR, "setup.log")
PENDING = os.path.join(DATA_DIR, "pending_install.json")
TIMED_RULES = os.path.join(DATA_DIR, "timed_rules.json")
INVENTORY_RESULT = "[p5agent] inventory result: "     # the agent reads it from the log

INSTALL_SCRIPT = os.path.join(HERE, "install_app.sh")
FIREWALL_SCRIPT = os.path.join(HERE, "firewall.sh")
NGINX_SCRIPT = os.path.join(HERE, "utilities", "nginx", "nginx.sh")
SQUID_SCRIPT = os.path.join(HERE, "utilities", "squid", "squid.sh")

SITE_ROOT = os.environ.get("P5AGENT_SITE_ROOT", "/var/www/html")
STATIC_SITE_CONF = "/etc/nginx/sites-available/p5-static.conf"
SQUID_CONF = "/etc/squid/squid.conf"
SQUID_PASSWD = "/etc/squid/passwd"
SQUID_WHITELIST_LIVE = "/etc/squid/whitelist.txt"
LE_DIR = "/etc/letsencrypt"
CERT_GROUP = "certaccess"           # certs.sh's: the group that reads /etc/letsencrypt

DB_TYPES = ("postgresql", "mysql", "mariadb", "sqlite")
DB_LABELS = {"postgresql": "PostgreSQL", "mysql": "MySQL", "mariadb": "MariaDB", "sqlite": "SQLite"}
DB_SERVICES = {"postgresql": "postgresql", "mysql": "mysql", "mariadb": "mariadb", "redis": "redis-server"}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
IDENT_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.$-]{0,62}$")   # a database, role or user name
ITEM_RE = re.compile(r"^(?:(?:db|config):[A-Za-z0-9][A-Za-z0-9._-]*|site|letsencrypt|squid)$")
# The settings each upplet keeps for itself when an app's env file is copied:
# the agent's own token, and how the app is reached here (Nginx sets those).
OWN_ENV_KEYS = ("MGMT_TOKEN", "PORT", "HOST", "TLS_CERT_PATH", "TLS_KEY_PATH")


class CopyError(Exception):
    """A step that ends the copy, with the reason as the log says it."""


# ── small helpers ────────────────────────────────────────────────────────────

def read_file(path, default=""):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return default


def read_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o600):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1)
    os.replace(tmp, path)


def installed_apps():
    apps = read_json(INSTALLED, [])
    return [a for a in apps if isinstance(a, dict) and NAME_RE.match(str(a.get("name") or ""))] \
        if isinstance(apps, list) else []


def human(n):
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024
    return "%d B" % n


def run(cmd, input_text=None, stdout=None, env=None, timeout=3600):
    """Run a command; returns (rc, combined output). `stdout` may be an open
    file the command writes to (a dump), in which case only stderr comes back."""
    try:
        proc = subprocess.run(
            cmd, input=input_text.encode("utf-8") if input_text is not None else None,
            stdout=stdout if stdout is not None else subprocess.PIPE,
            stderr=subprocess.PIPE if stdout is not None else subprocess.STDOUT,
            env=dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive", **(env or {})),
            timeout=timeout)
    except subprocess.TimeoutExpired:
        return 124, "timed out after %ds" % timeout
    except OSError as exc:
        return 127, str(exc)
    out = proc.stderr if stdout is not None else proc.stdout
    return proc.returncode, (out or b"").decode("utf-8", "replace")


def parse_env(text):
    """KEY=VALUE lines of an env file, as systemd's EnvironmentFile reads them."""
    env = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        env[key.strip()] = value
    return env


def env_key(line):
    s = line.strip()
    if not s or s.startswith("#") or "=" not in s:
        return None
    return s.split("=", 1)[0].strip()


def unit_user(name):
    """The user an app's service runs as (its unit's User=), or ""."""
    m = re.search(r"^User=(\S+)", read_file("/etc/systemd/system/%s.service" % name), re.M)
    return m.group(1) if m else ""


def chown_user(path, user, recursive=False):
    if not user:
        return
    run(["chown"] + (["-R"] if recursive else []) + ["%s:%s" % (user, user), path])


def service_exists(unit):
    rc, _ = run(["systemctl", "cat", unit + ".service"])
    return rc == 0


def service_active(unit):
    rc, out = run(["systemctl", "is-active", unit])
    return out.strip() == "active"


def add_to_tar(tar, path, arcname, exclude=()):
    """Add a file or a directory (recursively, links kept as links), leaving
    out the top-level entries named in `exclude`."""
    if os.path.isdir(path) and not os.path.islink(path):
        tar.add(path, arcname=arcname, recursive=False)
        for entry in sorted(os.listdir(path)):
            if entry in exclude:
                continue
            tar.add(os.path.join(path, entry), arcname=arcname + "/" + entry)
    else:
        tar.add(path, arcname=arcname)


def safe_members(tar, dest):
    """The archive's members, checked: nothing absolute, nothing climbing out of
    `dest`, no hard links or devices, and a symbolic link only when it points
    inside (Let's Encrypt's live/ is links into archive/)."""
    members = []
    real = os.path.realpath(dest)
    for m in tar.getmembers():
        name = m.name
        if name.startswith("/") or os.path.isabs(name):
            raise CopyError("the archive has an absolute path: %s" % name)
        parts = [p for p in name.replace("\\", "/").split("/") if p not in ("", ".")]
        if ".." in parts:
            raise CopyError("the archive has a path leaving it: %s" % name)
        if m.islnk() or not (m.isfile() or m.isdir() or m.issym()):
            raise CopyError("the archive has something that is not a file: %s" % name)
        if m.issym():
            if os.path.isabs(m.linkname):
                raise CopyError("the archive has a link out of it: %s" % name)
            target = os.path.realpath(os.path.join(real, os.path.dirname("/".join(parts)), m.linkname))
            if not (target == real or target.startswith(real + os.sep)):
                raise CopyError("the archive has a link out of it: %s" % name)
        members.append(m)
    return members


def extract(archive, dest):
    """Unpack a gzipped tar into `dest` (created when missing). One that
    stops short — the copied upplet failed part-way — is refused."""
    os.makedirs(dest, exist_ok=True)
    try:
        # The whole gzip stream first, to its trailer: tarfile stops reading
        # at the archive's end-of-files mark and would not notice a stream
        # that was cut off after it.
        import gzip
        with gzip.open(archive, "rb") as fh:
            while fh.read(1024 * 1024):
                pass
        with tarfile.open(archive, "r:gz") as tar:
            members = safe_members(tar, dest)
            kwargs = {"filter": "tar"} if hasattr(tarfile, "tar_filter") else {}
            tar.extractall(dest, members=members, **kwargs)
    except (tarfile.TarError, EOFError, zlib.error, OSError) as exc:
        raise CopyError("%s arrived incomplete or damaged (%s)" % (os.path.basename(archive), exc))


def gunzip(archive, dest):
    """Unpack a gzipped dump, refusing one that stops short."""
    import gzip
    try:
        with gzip.open(archive, "rb") as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out, 1024 * 1024)
    except (EOFError, OSError, zlib.error) as exc:
        raise CopyError("%s arrived incomplete or damaged (%s)" % (os.path.basename(archive), exc))


# ── what an app is made of (both sides) ──────────────────────────────────────

def env_db_type(env):
    """The database type an app's env file points at, or "": DATABASE_URL's
    scheme; else DATABASE_PATH (SQLite); else DATABASE_NAME/HOST — the
    fields ChatServer's own installer writes, with no URL — by DATABASE_PORT,
    or by which database server is installed here."""
    url = env.get("DATABASE_URL", "")
    if url:
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        found = {"postgres": "postgresql", "postgresql": "postgresql", "mysql": "mysql",
                 "mariadb": "mariadb", "sqlite": "sqlite", "sqlite3": "sqlite"}.get(scheme, "")
        if found:
            return found
    if env.get("DATABASE_PATH"):
        return "sqlite"
    if env.get("DATABASE_NAME") or env.get("DATABASE_HOST"):
        port = env.get("DATABASE_PORT", "")
        if port == "5432":
            return "postgresql"
        if port == "3306":
            return "mysql"
        if os.path.isdir("/etc/postgresql") or shutil.which("pg_dump"):
            return "postgresql"
        if os.path.isdir("/etc/mysql") or shutil.which("mysqldump"):
            return "mysql"
    return ""


def app_db(app):
    """The app's database as its env file and dependencies describe it:
    {type, name, user, path} (path: SQLite only), or None when it has none."""
    name = app["name"]
    deps = [str(d).split()[0].lower() for d in (app.get("dependencies") or []) if str(d).strip()]
    env = parse_env(read_file("/etc/%s.env" % name))
    url = env.get("DATABASE_URL", "")
    parsed = urllib.parse.urlsplit(url) if url else None
    scheme = (parsed.scheme if parsed else "").lower()
    dtype = next((d for d in deps if d in DB_TYPES), "") or env_db_type(env)
    if not dtype:
        return None
    if dtype == "sqlite":
        path = env.get("DATABASE_PATH") or ""
        if not path and url:
            path = url.split("://", 1)[-1]
            path = path if path.startswith("/") else "/" + path.lstrip("/")
        return {"type": "sqlite", "name": name, "user": "", "path": path or "/var/lib/%s/db.sqlite" % name}
    db_name = env.get("DATABASE_NAME") or ((parsed.path or "").lstrip("/") if parsed else "") or name
    db_user = env.get("DATABASE_USERNAME") or (urllib.parse.unquote(parsed.username) if parsed and parsed.username else "") or name
    return {"type": dtype, "name": db_name, "user": db_user, "path": ""}


# The archive against the database's own size: a dump leaves the indexes out
# and gzip shrinks the rest. A guess, and meant as one — it only decides
# whether the dashboard asks before copying a lot.
ARCHIVE_RATIO = 0.3


def db_size(db):
    """The database's size as it reports it (on disk: data and indexes)."""
    if db["type"] == "sqlite":
        return sum(os.path.getsize(p) for p in (db["path"], db["path"] + "-wal") if os.path.isfile(p))
    if db["type"] == "postgresql":
        rc, out = run(["runuser", "-u", "postgres", "--", "psql", "-tAc",
                       "SELECT pg_database_size('%s')" % db["name"]])
    else:
        rc, out = run(["mysql", "-N", "-e",
                       "SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables "
                       "WHERE table_schema = '%s'" % db["name"]])
    try:
        if rc != 0:
            raise ValueError
        return int(out.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise CopyError("its size could not be read: %s" % (out.strip().splitlines() or ["no answer"])[-1])


def db_present(db):
    """Whether the database is there to be dumped."""
    if db["type"] == "sqlite":
        return os.path.isfile(db["path"])
    if not IDENT_RE.match(db["name"]):
        return False
    if db["type"] == "postgresql":
        if not shutil.which("psql"):
            return False
        rc, out = run(["runuser", "-u", "postgres", "--", "psql", "-tAc",
                       "SELECT 1 FROM pg_database WHERE datname='%s'" % db["name"]])
        return rc == 0 and out.strip() == "1"
    if not shutil.which("mysql"):
        return False
    rc, out = run(["mysql", "-N", "-e", "SHOW DATABASES LIKE '%s'" % db["name"].replace("_", "\\_")])
    return rc == 0 and out.strip() == db["name"]


class GzipOut:
    """A gzip stream written to a binary file as it is made. Its end — the
    trailer that says the stream is whole — is written only by finish()."""

    def __init__(self, out):
        self.out = out
        self.z = zlib.compressobj(6, zlib.DEFLATED, 31)

    def write(self, data):
        chunk = self.z.compress(data)
        if chunk:
            self.out.write(chunk)

    def finish(self):
        self.out.write(self.z.flush())
        self.out.flush()


def stream_db(db, out):
    """Dump the database straight into `out`, gzipped — nothing touches the
    disk. The gzip end is written only when the dump succeeded."""
    gz = GzipOut(out)
    if db["type"] == "sqlite":
        # One read transaction: the dump is a consistent snapshot even while
        # the app writes; the file is opened read-only.
        con = sqlite3.connect("file:%s?mode=ro" % db["path"], uri=True, isolation_level=None)
        try:
            con.execute("BEGIN")
            for line in con.iterdump():
                gz.write((line + "\n").encode("utf-8"))
            con.execute("COMMIT")
        finally:
            con.close()
        gz.finish()
        return
    if db["type"] == "postgresql":
        # -Z0: uncompressed custom format, gzipped once below.
        cmd = ["runuser", "-u", "postgres", "--", "pg_dump", "-Fc", "-Z0", "--no-owner", "--no-acl", db["name"]]
    else:
        cmd = ["mysqldump", "--single-transaction", "--routines", "--triggers", "--events", db["name"]]
    proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=dict(os.environ, HOME="/root"))
    errors = []
    drain = threading.Thread(target=lambda: errors.append(proc.stderr.read()), daemon=True)
    drain.start()
    while True:
        chunk = proc.stdout.read(256 * 1024)
        if not chunk:
            break
        gz.write(chunk)
    rc = proc.wait()
    drain.join(5)
    if rc != 0:
        err = b"".join(errors).decode("utf-8", "replace").strip().splitlines()
        raise CopyError("the dump failed: %s" % (err or ["exit code %d" % rc])[-1])
    gz.finish()


def untracked_dotenvs(app):
    """An app's .env-style files at the top of its folder that its repo does
    not have — settings put there by hand, which a fresh clone lacks."""
    app_dir = app.get("path") or os.path.join(APPS_DIR, app["name"])
    repo = os.path.join(APPS_DIR, app["name"])
    found = []
    try:
        entries = sorted(os.listdir(app_dir))
    except OSError:
        return found
    for entry in entries:
        path = os.path.join(app_dir, entry)
        if not (entry == ".env" or entry.startswith(".env.")) or not os.path.isfile(path) or os.path.islink(path):
            continue
        if entry in (".env.example", ".env.sample", ".env.template"):
            continue
        rc, _ = run(["git", "-c", "safe.directory=*", "-C", repo, "ls-files", "--error-unmatch",
                     os.path.relpath(path, repo)])
        if rc != 0:
            found.append(entry)
    return found


def install_request(app):
    """The /install-app request that installs `app` from scratch the way it
    was installed here — or (None, why not)."""
    name = app["name"]
    req = {
        "name": name,
        "product-name": app.get("product-name") or "",
        "app-type": app.get("app-type") or "",
        "app-cmd": app.get("app-cmd") or "",
        "dependencies": app.get("dependencies") or [],
        "path": app.get("source") or "",
    }
    if app.get("demo"):
        if not req["path"]:
            return None, "a demo with no folder on record"
        req["demo"] = True
        return req, ""
    repo_dir = os.path.join(APPS_DIR, name)
    git = ["git", "-c", "safe.directory=*", "-C", repo_dir]
    rc, url = run(git + ["config", "--get", "remote.origin.url"])
    url = url.strip()
    if rc != 0 or not url:
        return None, "no git checkout at %s to tell where it came from" % repo_dir
    # A private repo was cloned with its token in the URL (install_app.sh): it
    # travels as the request's key, as the dashboard first sent it.
    parts = urllib.parse.urlsplit(url)
    if parts.scheme in ("http", "https") and (parts.username or parts.password):
        key = parts.password if parts.username == "x-access-token" or parts.password else parts.username
        host = parts.hostname or ""
        if parts.port:
            host += ":%d" % parts.port
        url = urllib.parse.urlunsplit((parts.scheme, host, parts.path, parts.query, parts.fragment))
        req["key"] = urllib.parse.unquote(key or "")
    req["repo"] = url
    rc, branch = run(git + ["symbolic-ref", "-q", "--short", "HEAD"])
    branch = branch.strip() if rc == 0 else ""
    if not branch:
        rc, tag = run(git + ["describe", "--tags", "--exact-match", "HEAD"])
        branch = tag.strip() if rc == 0 else ""
    if branch:
        req["branch"] = branch
    return req, ""


def static_site():
    """The static site Nginx serves here: {port, domain}, or None."""
    conf = read_file(STATIC_SITE_CONF)
    port = re.search(r"^\s*listen\s+(\d+)\s+ssl", conf, re.M)
    if not port:
        return None
    name = re.search(r"^\s*server_name\s+([^;\s]+)\s*;", conf, re.M)
    domain = name.group(1) if name and name.group(1) != "_" else ""
    return {"port": int(port.group(1)), "domain": domain}


def squid_setup():
    """Squid as squid.sh set it up here: {port, user, whitelist}, or None."""
    conf = read_file(SQUID_CONF)
    if not conf or "Generated by setup-squid.sh" not in conf:
        return None
    port = re.search(r"^http_port\s+(\d+)", conf, re.M)
    user = (read_file(SQUID_PASSWD) or "").split(":", 1)[0].strip()
    return {
        "port": int(port.group(1)) if port else 3128,
        "user": user,
        "whitelist": bool(re.search(r"^http_access allow authenticated whitelist", conf, re.M)),
    }


# ── the copied upplet (source) ───────────────────────────────────────────────

def say(text):
    print(text, flush=True)


def agent_port_listing():
    """The addresses the agent port is open to when it is open to listed
    ones only (firewall.sh --plan reads ufw, changes nothing), else []."""
    rc, out = run(["bash", FIREWALL_SCRIPT, "--plan"])
    try:
        table = json.loads(out.strip().splitlines()[-1]) if rc == 0 else {}
    except (ValueError, IndexError):
        return []
    rc, status = run(["ufw", "status"])
    if "Status: active" not in status:
        return []
    row = next((r for r in table.get("rules") or [] if r.get("port") == AGENT_PORT and r.get("proto") == "tcp"), None)
    return list(row.get("from") or []) if row else []


def cmd_inventory(wanted):
    """The calculation stage: disk in use, and each app's database size with
    a guess at its archive — asked of the database, never dumped. Writes
    nothing: its output is the log, ending with the result as JSON."""
    wanted = None if wanted == "-" else [w for w in wanted.split(",") if w]
    apps = [a for a in installed_apps() if wanted is None or a["name"] in wanted]
    du = shutil.disk_usage("/")
    say("Disk: %s in use of %s" % (human(du.used), human(du.total)))
    result = {"disk": {"used": du.used, "total": du.total}, "apps": [], "db_total": 0,
              "at": int(time.time())}
    failed = []
    for app in apps:
        name = app["name"]
        entry = {"name": name, "product": app.get("product-name") or name, "db": None, "db_bytes": 0}
        db = app_db(app)
        if not db:
            say("%s: no database" % name)
        elif not db_present(db):
            say("%s: its %s database (%s) is not there — nothing to copy" % (name, DB_LABELS[db["type"]], db["name"]))
            entry["db"] = dict(db, missing=True)
        else:
            try:
                size = db_size(db)
                guess = int(size * ARCHIVE_RATIO)
                entry["db"] = db
                entry["db_size"] = size
                entry["db_bytes"] = guess
                result["db_total"] += guess
                say("%s: %s database %s — archive about %s" % (name, DB_LABELS[db["type"]], human(size), human(guess)))
            except CopyError as exc:
                entry["error"] = str(exc)
                failed.append(name)
                say("✗ %s: %s" % (name, exc))
        result["apps"].append(entry)
    listing = agent_port_listing()
    if listing:
        # A copy changes nothing here, the firewall included: the new upplet,
        # whose address is not known yet, could not reach this agent.
        result["agent_port_listed"] = listing
        say("✗ The agent port (%d) is open to %s only — the new upplet could not reach it" % (
            AGENT_PORT, ", ".join(listing)))
    if failed:
        say("✗ The database of %s could not be measured" % ", ".join(failed))
    if not failed and not listing:
        say("Database archives: about %s in all" % human(result["db_total"]))
    say(INVENTORY_RESULT + json.dumps(result))
    return 1 if failed or listing else 0


def cmd_stream(item):
    """One archive to stdout, made as it goes; errors to stderr. On failure the
    process ends at once, without the archive's end: the receiver sees the
    archive is incomplete rather than taking a short one for whole."""
    out = sys.stdout.buffer
    try:
        if not ITEM_RE.match(item):
            raise CopyError("unknown item: %s" % item)
        kind, _, name = item.partition(":")
        apps = {a["name"]: a for a in installed_apps()}
        if kind in ("db", "config") and name not in apps:
            raise CopyError("%s is not installed here" % name)
        if kind == "db":
            db = app_db(apps[name])
            if not db or not db_present(db):
                raise CopyError("%s has no database to copy" % name)
            stream_db(db, out)
            return 0
        tar = tarfile.open(fileobj=out, mode="w|gz")
        if kind == "config":
            app = apps[name]
            env = "/etc/%s.env" % name
            if os.path.isfile(env):
                tar.add(env, arcname="env")
            etc = "/etc/%s" % name
            if os.path.isdir(etc):
                # Its certificates are this upplet's: the new one makes its own.
                add_to_tar(tar, etc, "etc", exclude=("certs",))
            for entry in untracked_dotenvs(app):
                tar.add(os.path.join(app.get("path") or os.path.join(APPS_DIR, name), entry), arcname="app/" + entry)
        elif kind == "site":
            if not os.path.isdir(SITE_ROOT):
                raise CopyError("there is no %s here" % SITE_ROOT)
            for entry in sorted(os.listdir(SITE_ROOT)):
                tar.add(os.path.join(SITE_ROOT, entry), arcname=entry)
        elif kind == "letsencrypt":
            if not os.path.isdir(LE_DIR):
                raise CopyError("there are no certificates here")
            for entry in sorted(os.listdir(LE_DIR)):
                tar.add(os.path.join(LE_DIR, entry), arcname=entry)
        elif kind == "squid":
            if not squid_setup():
                raise CopyError("Squid is not set up here")
            for path, arcname in ((SQUID_PASSWD, "passwd"), (SQUID_WHITELIST_LIVE, "whitelist.txt")):
                if os.path.isfile(path):
                    tar.add(path, arcname=arcname)
        tar.close()
        out.flush()
        return 0
    except (CopyError, OSError, sqlite3.Error, tarfile.TarError) as exc:
        sys.stderr.write("%s\n" % exc)
        sys.stderr.flush()
        # Not a normal exit: that would let the tar stream write its end.
        os._exit(1)


def cmd_manifest():
    """What the new upplet needs to rebuild this one, as JSON on stdout."""
    apps = []
    for app in installed_apps():
        name = app["name"]
        req, why = install_request(app)
        db = app_db(app)
        if db and not db_present(db):
            db = None
        public = str(app.get("public-port") or "").strip()
        nginx = None
        if public.isdigit():
            nginx = {"public": int(public), "domain": app.get("nginx-domain") or "",
                     "bots": bool(app.get("nginx-bots")), "fail2ban": bool(app.get("nginx-fail2ban"))}
        has_config = os.path.isfile("/etc/%s.env" % name) or os.path.isdir("/etc/%s" % name) \
            or bool(untracked_dotenvs(app))
        apps.append({
            "name": name,
            "product": app.get("product-name") or name,
            "install": req,
            "skip": why,
            "port": str(app.get("port") or "").strip(),
            "nginx": nginx,
            "db": db,
            "config": has_config,
            "services": sorted({DB_SERVICES[d] for d in (str(x).split()[0].lower()
                                for x in (app.get("dependencies") or []) if str(x).strip())
                                if d in DB_SERVICES}),
        })
    squid = squid_setup()
    manifest = {
        "hostname": socket.gethostname(),
        "apps": apps,
        "nginx": bool(shutil.which("nginx")),
        "site": static_site(),
        "letsencrypt": os.path.isdir(os.path.join(LE_DIR, "live")),
        "squid": squid,
    }
    sys.stdout.write(json.dumps(manifest))
    return 0


# ── the new upplet (target) ──────────────────────────────────────────────────

def logline(text):
    os.makedirs(DATA_DIR, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(SETUP_LOG, "a") as fh:
        for line in str(text).rstrip("\n").split("\n"):
            fh.write("[%s] %s\n" % (stamp, line))


def log_output(text, indent="    "):
    """A command's output, each line indented under the step that ran it."""
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", l).rstrip() for l in (text or "").splitlines()]
    lines = [l for l in lines if l.strip()]
    if lines:
        logline("\n".join(indent + l for l in lines))


class Peer:
    """The copied upplet's agent, reached with the copy key."""

    def __init__(self, ip, key, name):
        self.ip, self.key, self.name = ip, key, name
        self.ctx = ssl.create_default_context()
        # The agents serve self-signed certificates for their IPs, as the
        # dashboard finds them; the copy key is what this connection carries.
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        # Straight to the other agent: never through a proxy the environment
        # may name (HTTPS_PROXY), which would not reach port 5005 anyway.
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=self.ctx))

    def url(self, path):
        return "https://%s:%d%s" % (self.ip, AGENT_PORT, path)

    def request(self, method, path, body=None, timeout=60):
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(self.url(path), data=data, method=method)
        req.add_header("Authorization", "Bearer " + self.key)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with self.opener.open(req, timeout=timeout) as res:
                return res.status, res.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except (urllib.error.URLError, OSError) as exc:
            raise CopyError("%s did not answer: %s" % (self.name, getattr(exc, "reason", exc)))

    def json(self, method, path, body=None, timeout=60):
        status, raw = self.request(method, path, body, timeout)
        try:
            data = json.loads(raw.decode("utf-8", "replace") or "{}")
        except ValueError:
            data = {}
        if status < 200 or status >= 300:
            raise CopyError("%s refused %s: %s" % (self.name, path.split("?")[0],
                                                     data.get("error") or "HTTP %d" % status))
        return data

    def fetch(self, item, dest):
        """Receive one archive straight from the copied upplet's agent, made
        as it is sent; its length is not known until it has arrived. Returns
        its size. Whether it arrived whole is checked when it is unpacked."""
        req = urllib.request.Request(self.url("/copy/file?item=" + urllib.parse.quote(item)))
        req.add_header("Authorization", "Bearer " + self.key)
        got = 0
        try:
            with self.opener.open(req, timeout=300) as res, open(dest, "wb") as out:
                last = time.time()
                while True:
                    chunk = res.read(256 * 1024)
                    if not chunk:
                        break
                    out.write(chunk)
                    got += len(chunk)
                    if time.time() - last >= 15:
                        last = time.time()
                        logline("    %s received so far" % human(got))
        except urllib.error.HTTPError as exc:
            try:
                reason = json.loads(exc.read().decode("utf-8", "replace") or "{}")
                reason = reason.get("detail") or reason.get("error") or ""
            except ValueError:
                reason = ""
            raise CopyError("%s did not send %s (HTTP %d%s)" % (self.name, item, exc.code, ": " + reason if reason else ""))
        except (urllib.error.URLError, OSError) as exc:
            raise CopyError("receiving %s from %s failed: %s" % (item, self.name, getattr(exc, "reason", exc)))
        return got


class Import:
    def __init__(self, req):
        self.peer = Peer(req["source"], req["key"], req.get("source_name") or req["source"])
        self.src = self.peer.name
        self.dst = req.get("target_name") or socket.gethostname()
        self.wanted_apps = req.get("apps")              # None: every app
        self.want_nginx = req.get("nginx") is not False
        self.want_squid = req.get("squid") is not False
        self.caller = req.get("caller") or ""
        self.work = tempfile.mkdtemp(prefix="p5copy-", dir=TMP_DIR)
        os.chmod(self.work, 0o700)
        self.warnings = []
        self.services = []          # what has to be running at the end
        self.archives = {}          # item -> its archive, fetched here
        self.released = False       # the copied upplet told it is not needed any more

    def warn(self, text):
        self.warnings.append(text)
        logline("! " + text)

    # ── the whole run ────────────────────────────────────────────────────────
    def run(self):
        logline("Copying %s (%s) to %s" % (self.src, self.peer.ip, self.dst))
        logline("Asking %s what it runs..." % self.src)
        m = self.peer.json("GET", "/copy/manifest")
        apps = [a for a in m.get("apps") or []
                if self.wanted_apps is None or a["name"] in self.wanted_apps]
        missing = [n for n in (self.wanted_apps or []) if n not in [a["name"] for a in m.get("apps") or []]]
        for name in missing:
            self.warn("%s is no longer installed on %s — skipped" % (name, self.src))
        nginx_apps = [a for a in apps if a.get("nginx")] if self.want_nginx else []
        site = m.get("site") if self.want_nginx else None
        logline("To copy: %s" % (", ".join(
            [a["product"] for a in apps] +
            (["Nginx"] if nginx_apps or site else []) +
            (["Squid"] if self.want_squid and m.get("squid") else []) +
            ["the firewall rules", "p5agent's allowed addresses"])))

        # Everything is fetched first: the copied upplet's grant only lives a
        # few minutes past its last use, and installing the apps here can take
        # far longer than that. Once all of it is here, the copied upplet is
        # done with — the rest happens on this one alone.
        squid = m.get("squid") if self.want_squid else None
        self.gather(apps, site, squid, bool(m.get("letsencrypt") and (nginx_apps or site or apps)))

        if "letsencrypt" in self.archives:
            self.copy_certificates()

        taken = set()
        for app in apps:
            self.copy_app(app, nginx_apps, taken)

        if nginx_apps or site:
            self.setup_nginx(nginx_apps, site)
        elif m.get("nginx") and self.want_nginx:
            logline("Nginx on %s serves nothing — not set up here" % self.src)

        if squid:
            self.setup_squid(squid, m.get("timed") or [])

        self.copy_allow_list(m.get("allow") or [], m.get("timed") or [])
        self.copy_firewall(m.get("firewall"))
        self.ensure_services()

    # ── everything from the copied upplet ────────────────────────────────────
    def gather(self, apps, site, squid, certificates):
        logline("Fetching everything to copy from %s first..." % self.src)
        if certificates:
            self.receive("letsencrypt", "the Let's Encrypt certificates")
        for app in apps:
            if not app.get("install"):
                continue
            name, product = app["name"], app["product"]
            if app.get("config"):
                self.receive("config:" + name, "the config files of %s" % product)
            if app.get("db"):
                db = app["db"]
                logline("Dumping the %s database of %s on %s and sending it to %s..." % (
                    DB_LABELS[db["type"]], product, self.src, self.dst))
                self.receive("db:" + name, "the database file of %s" % product, said=True)
        if site:
            self.receive("site", "the static site's files")
        if squid:
            self.receive("squid", "Squid's credentials and whitelist")
        self.release(True)
        logline("✓ Everything is here — %s is no longer involved" % self.src)

    def receive(self, item, what, said=False):
        """One archive from the copied upplet, into this run's folder."""
        if not said:
            logline("Sending %s from %s to %s..." % (what, self.src, self.dst))
        dest = os.path.join(self.work, item.replace(":", "_") + (".gz" if item.startswith("db:") else ".tar.gz"))
        size = self.peer.fetch(item, dest)
        logline("    received %s" % human(size))
        self.archives[item] = dest
        return dest

    def release(self, ok):
        """Tell the copied upplet it is done with: it drops the key."""
        if self.released:
            return
        self.released = True
        try:
            self.peer.json("POST", "/copy/done", {"ok": ok}, timeout=30)
        except Exception:  # noqa: BLE001 - unused, its grant ends on its own in minutes
            pass

    # ── certificates ─────────────────────────────────────────────────────────
    def copy_certificates(self):
        archive = self.archives["letsencrypt"]
        extract(archive, LE_DIR)
        # The group the apps read them through (certs.sh's grant_cert_access).
        run(["groupadd", "--system", "-f", CERT_GROUP])
        for top in ("live", "archive"):
            path = os.path.join(LE_DIR, top)
            if os.path.isdir(path):
                run(["chgrp", CERT_GROUP, path])
                os.chmod(path, 0o750)
                for domain in os.listdir(path):
                    d = os.path.join(path, domain)
                    if os.path.isdir(d) and not os.path.islink(d):
                        run(["chgrp", CERT_GROUP, d])
                        os.chmod(d, 0o750)
                        if top == "archive":
                            for f in os.listdir(d):
                                if f.startswith("privkey"):
                                    run(["chgrp", CERT_GROUP, os.path.join(d, f)])
                                    os.chmod(os.path.join(d, f), 0o640)
        logline("✓ Certificates in place (renewals work here once the domains point to this upplet)")

    # ── one app ──────────────────────────────────────────────────────────────
    def copy_app(self, app, nginx_apps, taken):
        name, product = app["name"], app["product"]
        if not app.get("install"):
            self.warn("%s cannot be installed from scratch (%s) — skipped" % (product, app.get("skip") or "no recipe"))
            return
        # The port: behind Nginx it is installed on its private port, which
        # Nginx then serves; without Nginx it serves itself, on the port Nginx
        # served it on (unless another app copied has that one already).
        port = app.get("port") or "443"
        if app.get("nginx") and app not in nginx_apps:
            public = str(app["nginx"]["public"])
            if public not in taken:
                port = public
        taken.add(port)

        req = dict(app["install"], port=port)
        logline("Installing %s from scratch on %s..." % (product, self.dst))
        path = os.path.join(self.work, "install_%s.json" % name)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(req, fh)
        # Nested: the install logs into this same setup.log, and leaves the
        # install lock — this copy's — where it is.
        proc = subprocess.run(["bash", INSTALL_SCRIPT, path], cwd=HERE,
                              env=dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive",
                                       P5AGENT_NESTED="1"),
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.remove(path)
        if proc.returncode != 0:
            raise CopyError("%s was not installed" % product)
        self.services.append(name)
        self.services += app.get("services") or []

        if "config:" + name in self.archives:
            logline("Putting the config files of %s in place..." % product)
            self.apply_config(app, self.archives["config:" + name])

        if "db:" + name in self.archives:
            logline("Restoring the database of %s on %s..." % (product, self.dst))
            self.restore_db(app, self.archives["db:" + name])

        if service_exists(name):
            run(["systemctl", "restart", name])
        logline("✓ %s copied" % product)

    def apply_config(self, app, archive):
        name = app["name"]
        out = os.path.join(self.work, "config_" + name)
        extract(archive, out)
        user = unit_user(name)
        src_env = os.path.join(out, "env")
        if os.path.isfile(src_env):
            target = "/etc/%s.env" % name
            mine = parse_env(read_file(target))
            theirs = read_file(src_env).splitlines()
            lines = []
            for line in theirs:
                key = env_key(line)
                if key in OWN_ENV_KEYS:
                    continue
                lines.append(line)
            theirs_env = parse_env("\n".join(theirs))
            # A certificate copied over (Let's Encrypt's) stays the app's own —
            # the pair together, or this upplet's pair.
            tls_theirs = all(theirs_env.get(k) and os.path.isfile(theirs_env[k])
                             for k in ("TLS_CERT_PATH", "TLS_KEY_PATH"))
            for key in OWN_ENV_KEYS:
                value = mine.get(key)
                if key.startswith("TLS_") and tls_theirs:
                    value = theirs_env[key]
                if value:
                    lines.append("%s=%s" % (key, value))
            fd = os.open(target + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(target + ".tmp", target)
            chown_user(target, user)
            if any(theirs_env.get(k, "").startswith(LE_DIR + "/") for k in ("TLS_CERT_PATH", "TLS_KEY_PATH")) and user:
                run(["usermod", "-aG", CERT_GROUP, user])
            logline("    /etc/%s.env — %s's settings, with this upplet's token and addresses" % (name, self.src))
        etc = os.path.join(out, "etc")
        if os.path.isdir(etc):
            dest = "/etc/%s" % name
            os.makedirs(dest, exist_ok=True)
            for entry in os.listdir(etc):
                s, d = os.path.join(etc, entry), os.path.join(dest, entry)
                if os.path.isdir(d) and not os.path.islink(d):
                    shutil.rmtree(d)
                elif os.path.lexists(d):
                    os.remove(d)
                shutil.move(s, d)
            chown_user(dest, user, recursive=True)
            logline("    /etc/%s/" % name)
        files = os.path.join(out, "app")
        if os.path.isdir(files):
            app_dir = self.app_dir(name)
            for entry in os.listdir(files):
                shutil.copy2(os.path.join(files, entry), os.path.join(app_dir, entry))
                chown_user(os.path.join(app_dir, entry), user)
                logline("    %s/%s" % (app_dir, entry))

    def app_dir(self, name):
        for a in installed_apps():
            if a["name"] == name:
                return a.get("path") or os.path.join(APPS_DIR, name)
        return os.path.join(APPS_DIR, name)

    def restore_db(self, app, archive):
        name = app["name"]
        meta = app["db"]
        dump = os.path.join(self.work, "db_%s.dump" % name)
        gunzip(archive, dump)
        dtype = meta.get("type")
        env = parse_env(read_file("/etc/%s.env" % name))
        db_name = env.get("DATABASE_NAME") or meta.get("name") or name
        db_user = env.get("DATABASE_USERNAME") or meta.get("user") or name
        password = env.get("DATABASE_PASSWORD") or ""
        if not password and env.get("DATABASE_URL"):
            password = urllib.parse.unquote(urllib.parse.urlsplit(env["DATABASE_URL"]).password or "")
        was_running = service_exists(name)
        if was_running:
            run(["systemctl", "stop", name])
        try:
            if dtype == "sqlite":
                # The dump is SQL: a new database file is built from it, then
                # put in the old one's place.
                path = meta.get("path") or "/var/lib/%s/db.sqlite" % name
                os.makedirs(os.path.dirname(path), exist_ok=True)
                built = path + ".copy"
                if os.path.exists(built):
                    os.remove(built)
                con = sqlite3.connect(built)
                try:
                    with open(dump, encoding="utf-8") as fh:
                        con.executescript(fh.read())
                    con.commit()
                except sqlite3.Error as exc:
                    raise CopyError("the SQLite dump of %s did not load: %s" % (name, exc))
                finally:
                    con.close()
                for extra in (path + "-wal", path + "-shm", path + "-journal"):
                    if os.path.exists(extra):
                        os.remove(extra)
                os.replace(built, path)
                user = unit_user(name)
                chown_user(os.path.dirname(path), user, recursive=True)
            elif dtype == "postgresql":
                self.restore_postgres(dump, db_name, db_user, password)
            elif dtype in ("mysql", "mariadb"):
                self.restore_mysql(dump, db_name, db_user, password)
            else:
                raise CopyError("unknown database type %r" % dtype)
        finally:
            if was_running:
                run(["systemctl", "start", name])
        logline("✓ The database of %s is restored" % app["product"])

    @staticmethod
    def sql_text(value):
        return "'" + str(value).replace("'", "''") + "'"

    def restore_postgres(self, dump, db_name, db_user, password):
        if not shutil.which("pg_restore"):
            raise CopyError("PostgreSQL is not installed here")
        for ident in (db_name, db_user):
            if not IDENT_RE.match(ident):
                raise CopyError("not a database name: %r" % ident)
        sql = (
            "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = %(u)s) THEN "
            "CREATE ROLE \"%(user)s\" LOGIN; END IF; END $$;\n" % {"u": self.sql_text(db_user), "user": db_user})
        if password:
            sql += "ALTER ROLE \"%s\" WITH LOGIN PASSWORD %s;\n" % (db_user, self.sql_text(password))
        rc, out = run(["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", "-q"], input_text=sql)
        if rc != 0:
            raise CopyError("the database role %s could not be set up: %s" % (db_user, out.strip()))
        rc, out = run(["runuser", "-u", "postgres", "--", "psql", "-tAc",
                       "SELECT 1 FROM pg_database WHERE datname=%s" % self.sql_text(db_name)])
        if out.strip() != "1":
            rc, out = run(["runuser", "-u", "postgres", "--", "createdb", "-O", db_user, db_name])
            if rc != 0:
                raise CopyError("the database %s could not be created: %s" % (db_name, out.strip()))
        # On stdin: the dump sits in this run's private folder, which the
        # postgres user cannot read.
        with open(dump, "rb") as fh:
            proc = subprocess.run(["runuser", "-u", "postgres", "--", "pg_restore", "--clean", "--if-exists", "--no-owner",
                                   "--no-acl", "--role=" + db_user, "-d", db_name],
                                  stdin=fh, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        rc, out = proc.returncode, proc.stdout.decode("utf-8", "replace")
        if rc != 0:
            # pg_restore exits 1 for warnings it carried on through (an object
            # the fresh database did not have to drop, say): logged, not fatal.
            log_output(out)
            if "errors ignored on restore" not in out:
                raise CopyError("pg_restore failed for %s" % db_name)
            self.warn("pg_restore reported warnings for %s (above)" % db_name)

    def restore_mysql(self, dump, db_name, db_user, password):
        if not shutil.which("mysql"):
            raise CopyError("MySQL/MariaDB is not installed here")
        for ident in (db_name, db_user):
            if not IDENT_RE.match(ident):
                raise CopyError("not a database name: %r" % ident)
        sql = "CREATE DATABASE IF NOT EXISTS `%s`;\n" % db_name
        if password:
            who = "%s@'localhost'" % self.sql_text(db_user)
            sql += ("CREATE USER IF NOT EXISTS %s IDENTIFIED BY %s;\n" % (who, self.sql_text(password)) +
                    "ALTER USER %s IDENTIFIED BY %s;\n" % (who, self.sql_text(password)) +
                    "GRANT ALL PRIVILEGES ON `%s`.* TO %s;\nFLUSH PRIVILEGES;\n" % (db_name, who))
        rc, out = run(["mysql"], input_text=sql)
        if rc != 0:
            raise CopyError("the database %s could not be set up: %s" % (db_name, out.strip()))
        with open(dump, "rb") as fh:
            proc = subprocess.run(["mysql", db_name], stdin=fh, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if proc.returncode != 0:
            log_output(proc.stdout.decode("utf-8", "replace"))
            raise CopyError("the dump of %s did not load" % db_name)

    # ── Nginx ────────────────────────────────────────────────────────────────
    def setup_nginx(self, nginx_apps, site):
        installed = {a["name"] for a in installed_apps()}
        groups = {}
        for app in nginx_apps:
            if app["name"] not in installed:
                continue
            n = app["nginx"]
            key = (n["public"], bool(n["bots"]), bool(n["fail2ban"]) and bool(n["bots"]))
            groups.setdefault(key, []).append(app)
        static_done = False
        for (public, bots, f2b), members in sorted(groups.items()):
            args = ["install", "sites", "--public", str(public)]
            if bots:
                args.append("--bots")
            if f2b:
                args.append("--fail2ban")
            if site and not static_done and site["port"] == public:
                args += ["--static", site["domain"] or ""]
                static_done = True
            args += ["%s:%s:%s" % (a["name"], a.get("port") or 0, a["nginx"]["domain"]) for a in members]
            logline("Setting up Nginx on %s: port %d for %s%s..." % (
                self.dst, public, ", ".join(a["product"] for a in members),
                " and the static site" if "--static" in args else ""))
            self.nginx(args)
        if site and not static_done:
            logline("Setting up Nginx on %s: the static site on port %d..." % (self.dst, site["port"]))
            args = ["static", str(site["port"])]
            if site.get("domain"):
                args += ["--domain", site["domain"]]
            self.nginx(args)
        if site and "site" in self.archives:
            archive = self.archives["site"]
            staged = SITE_ROOT + ".new"
            shutil.rmtree(staged, ignore_errors=True)
            extract(archive, staged)
            old = SITE_ROOT + ".old"
            shutil.rmtree(old, ignore_errors=True)
            if os.path.isdir(SITE_ROOT):
                os.rename(SITE_ROOT, old)
            os.rename(staged, SITE_ROOT)
            shutil.rmtree(old, ignore_errors=True)
            os.chmod(SITE_ROOT, 0o755)
            logline("✓ The static site's files are in place")
        self.services.append("nginx")

    def nginx(self, args):
        rc, out = run(["bash", NGINX_SCRIPT] + args, env={"P5AGENT_PORT": str(AGENT_PORT)})
        log_output(out)
        if rc != 0:
            raise CopyError("Nginx was not set up")

    # ── Squid ────────────────────────────────────────────────────────────────
    def setup_squid(self, squid, timed):
        archive = self.archives["squid"]
        out = os.path.join(self.work, "squid")
        extract(archive, out)
        env = {"PROXY_PORT": str(squid.get("port") or 3128), "SQUID_MANAGED": "1",
               "SQUID_WHITELIST": "1" if squid.get("whitelist") else "0"}
        passwd = os.path.join(out, "passwd")
        if os.path.isfile(passwd):
            # Kept as they are: the same users and passwords as there.
            os.makedirs(os.path.dirname(SQUID_PASSWD), exist_ok=True)
            shutil.copyfile(passwd, SQUID_PASSWD)
            os.chmod(SQUID_PASSWD, 0o640)
            env["SQUID_KEEP_PASSWD"] = "1"
        else:
            raise CopyError("Squid's credentials did not come over")
        whitelist = os.path.join(out, "whitelist.txt")
        if squid.get("whitelist"):
            if not os.path.isfile(whitelist):
                raise CopyError("Squid's whitelist did not come over")
            env["WHITELIST_FILE"] = whitelist
        logline("Setting up Squid on %s: port %s, user %s, %s..." % (
            self.dst, env["PROXY_PORT"], squid.get("user") or "?",
            "whitelist on" if squid.get("whitelist") else "no whitelist"))
        rc, text = run(["bash", SQUID_SCRIPT, "install"], env=env, input_text="")
        log_output(text)
        if rc != 0:
            raise CopyError("Squid was not set up")
        if not squid.get("whitelist") and os.path.isfile(whitelist):
            # A list kept from before comes back when the whitelist is turned on.
            shutil.copyfile(whitelist, SQUID_WHITELIST_LIVE)
        proxy_rules = [r for r in timed if r.get("kind") == "proxy"]
        if proxy_rules:
            self.merge_timed(proxy_rules)
        self.services.append("squid")
        logline("✓ Squid set up with the same credentials")

    # ── p5agent's allowed addresses ──────────────────────────────────────────
    def merge_timed(self, rules):
        now = time.time()
        current = read_json(TIMED_RULES, [])
        current = current if isinstance(current, list) else []
        have = {(r.get("kind"), r.get("value")) for r in current if isinstance(r, dict)}
        for r in rules:
            if not isinstance(r, dict) or (r.get("kind"), r.get("value")) in have:
                continue
            if not isinstance(r.get("until"), (int, float)) or r["until"] <= now:
                continue
            current.append({k: r[k] for k in ("kind", "value", "until", "restore") if k in r})
        write_json(TIMED_RULES, current, 0o644)

    def copy_allow_list(self, allow, timed):
        lines = read_file(ENV_FILE).splitlines()
        current = []
        for line in lines:
            if line.startswith("P5AGENT_ALLOW_IP="):
                current = [a.strip() for a in line.split("=", 1)[1].split(",") if a.strip()]
        merged = list(current)
        for ip in allow:
            if ip and ip not in merged:
                merged.append(ip)
        added = [ip for ip in merged if ip not in current]
        if added:
            lines = [l for l in lines if not l.startswith("P5AGENT_ALLOW_IP=")] + ["P5AGENT_ALLOW_IP=" + ",".join(merged)]
            fd = os.open(ENV_FILE + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(lines) + "\n")
            os.replace(ENV_FILE + ".tmp", ENV_FILE)
        self.merge_timed([r for r in timed if r.get("kind") == "agent" and r.get("value") in added])
        logline("✓ p5agent's allowed addresses: %s" % (", ".join(merged) or "none") +
                (" (added from %s: %s)" % (self.src, ", ".join(added)) if added else " — the same as %s's" % self.src))

    # ── the firewall, 1:1 ────────────────────────────────────────────────────
    def copy_firewall(self, table):
        if not table or not isinstance(table.get("rules"), list):
            self.warn("%s did not report its firewall — this upplet keeps its own rules" % self.src)
            return
        logline("Copying the firewall rules of %s..." % self.src)
        rules, raws = [], []
        for r in table["rules"]:
            if r.get("raw"):
                raws.append(str(r["raw"]))
            elif r.get("port"):
                rules.append({"port": r["port"], "proto": r.get("proto") or "tcp", "from": r.get("from") or []})
        # Rules firewall.sh cannot read (ranges, limit, deny…) are added as ufw
        # has them; the table then keeps them.
        rc, have = run(["ufw", "show", "added"])
        for raw in raws:
            if ("ufw " + raw) in have:
                continue
            words = shlex.split(raw)
            rc, out = run(["ufw"] + words)
            if rc != 0:
                self.warn("could not add the rule %r: %s" % (raw, out.strip()))
        path = os.path.join(self.work, "firewall.json")
        with open(path, "w") as fh:
            json.dump({"rules": rules + [{"raw": r} for r in raws]}, fh)
        rc, out = run(["bash", FIREWALL_SCRIPT, "--set", path], env={"P5AGENT_CALLER_IP": self.caller})
        log_output(out)
        if rc != 0:
            raise CopyError("the firewall rules were not applied")
        logline("✓ Firewall: the same rules as %s" % self.src)

    # ── every service up ─────────────────────────────────────────────────────
    def ensure_services(self):
        logline("Checking that every service is running on %s..." % self.dst)
        seen, down = set(), []
        for unit in self.services:
            if unit in seen:
                continue
            seen.add(unit)
            if not service_exists(unit):
                continue
            if not service_active(unit):
                run(["systemctl", "enable", unit])
                run(["systemctl", "start", "--no-block", unit])
            state = "unknown"
            for _ in range(30):
                rc, state = run(["systemctl", "is-active", unit])
                state = state.strip()
                if state in ("active", "failed"):
                    break
                time.sleep(1)
            if state == "active":
                # A crash loop passes through active: look again.
                time.sleep(2)
                state = "active" if service_active(unit) else "stopped again"
            if state == "active":
                logline("    %s: running" % unit)
            else:
                rc, journal = run(["journalctl", "-u", unit, "-n", "10", "--no-pager"])
                log_output(journal)
                down.append(unit)
        if down:
            raise CopyError("these did not start: %s" % ", ".join(down))
        logline("✓ Every service is running")


def cmd_import(req_path):
    req = read_json(req_path, {})
    try:
        os.remove(req_path)               # it holds the copy key
    except OSError:
        pass
    imp = None
    ok = False
    try:
        if not req.get("source") or not req.get("key"):
            raise CopyError("the request names no upplet to copy")
        imp = Import(req)
        imp.run()
        ok = True
    except CopyError as exc:
        logline("✗ %s" % exc)
    except Exception as exc:  # noqa: BLE001 - the log must say how it ended
        logline("✗ Unexpected error: %s" % exc)
    finally:
        if imp:
            imp.release(ok)     # when it failed before everything was fetched
            shutil.rmtree(imp.work, ignore_errors=True)
    if ok:
        if imp.warnings:
            logline("Done, with %d warning(s): %s" % (len(imp.warnings), "; ".join(imp.warnings)))
        logline("✓ %s is a copy of %s" % (imp.dst, imp.src))
        # The agent's completion marker: the log's last line.
        logline("copy installation completed")
    else:
        logline("copy installation failed")
    try:
        os.remove(PENDING)
    except OSError:
        pass
    return 0 if ok else 1


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    mode = argv[1]
    if mode == "inventory" and len(argv) == 3:
        return cmd_inventory(argv[2])
    if mode == "stream" and len(argv) == 3:
        return cmd_stream(argv[2])
    if mode == "manifest":
        return cmd_manifest()
    if mode == "import" and len(argv) == 3:
        return cmd_import(argv[2])
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
