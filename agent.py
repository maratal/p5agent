#!/usr/bin/env python3
"""
p5agent — minimal remote management agent.

A tiny HTTP control plane for a deployed droplet, written with the Python
standard library only (no pip installs; Ubuntu ships python3). It runs as a
root systemd service on port 5005 and exposes:

    GET  /            liveness probe (no token required)
    *    /update      git-pull this checkout, then run update.sh
    *    /command     save the request to /tmp/command_<dd_mm_yy_hh_mm_ss>.sh and
                      run it as root — restricted to P5AGENT_ALLOW_IP.
                      Built-in aliases, answered without running a script:
                        token --print | -p         the management token
                        agent --print | -p         the P5AGENT_ALLOW_IP list
                        agent --allow | -a <ip>    add <ip> to P5AGENT_ALLOW_IP
                        agent --remove | -r <ip>   take <ip> off P5AGENT_ALLOW_IP
                        proxy --allow | -a <names> add comma-separated domain
                                                   names to Squid's whitelist
                        proxy --remove | -r <names> take domain names off it
                        proxy --whitelist | -wl    the whitelist Squid has loaded
    *    /install-app  spawn install_app.sh in the background to install an app
                      and its dependencies; returns 200 once the job is launched.
                      One install runs at a time: the request is recorded in
                      pending_install.json the moment it is accepted, and a
                      second request is refused with 409 while one is running
    GET  /progress    current install status as JSON:
                      { "app", "started_at", "log"?, "completed"? } — {} when idle
    GET  /supported   the supported_deps.json registry
    GET  /apps        the installed_apps.json list, each app with "service"
                      (systemctl is-active) and "backup" (a rollback is possible)
    POST /app         one installed app's lifecycle, via app_ops.sh:
                      {"op": start|stop|backup|update|rollback|uninstall|nginx, "name": ...,
                       "drop_db": bool (uninstall), "port": int (nginx: the
                       app's new private port, 0 = pick one), "public_port":
                       int (nginx: the port it serves the app on), "bots": bool,
                       "fail2ban": bool (nginx: bot protection, on or off)} -> {returncode, output};
                      update and nginx run in the background -> {"status": "started"}
    GET  /app-log     the current (or last) app job — an update or an nginx wire:
                      {name, op, started_at, log, finished, returncode} — {} if none
    GET  /firewall    the firewall table as ufw has it (firewall.sh --plan): each
                      port with the addresses it is open to, built-in ones marked
    POST /firewall    {"rules": [{port, proto, from: [addr…]} | {raw}]} — bring ufw
                      to that table (only the difference), in the background
    GET  /firewall-log the current (or last) firewall run: {log, finished, returncode}
    GET  /squid       Setup Squid's starting point: {whitelist: [domains, sorted] —
                      the upplet's list in effect, or the squid/whitelist.txt
                      template before the first setup; whitelistSource:
                      "upplet" | "template"; current: {port, user, whitelist}
                      of the proxy set up already, or null}
    POST /squid       {user, password, port, whitelist: bool, domains: [...]} —
                      run squid/setup.sh with them, in the background;
                      {keep_credentials: true} instead of user and password
                      changes the rest and keeps the proxy's credentials
    GET  /squid-log   the current (or last) Squid setup: {log, finished, returncode}
    GET  /utilities   what is set up on the upplet besides apps: {squid: {port,
                      user, whitelist} | null, nginx: [apps behind Nginx]}
    GET  /info        the upplet itself: OS, kernel, uptime, memory, disk, this
                      agent's commit, installed versions of the supported
                      dependencies, and the firewall's rules

All endpoints except `/` require the shared secret token. `/command` and `/app`
are also restricted by source IP.

Configuration is read from the environment (see /etc/p5agent.env):

    P5AGENT_TOKEN     shared secret required on every privileged request
    P5AGENT_ALLOW_IP  comma-separated client IPs allowed to call /command (default: 127.0.0.1)
    P5AGENT_PORT      listen port                        (default: 5005)
    P5AGENT_DATA_DIR  runtime state dir                  (default: /var/lib/p5agent)
    P5AGENT_TMP_DIR   where command scripts are written  (default: /tmp)
    P5AGENT_TIMEOUT   max seconds for any command        (default: 1800)
    P5AGENT_TLS_CERT  TLS certificate (PEM) — enables HTTPS
    P5AGENT_TLS_KEY   TLS private key (PEM) — enables HTTPS

The token must be supplied in the request header — never in the URL, so it
cannot leak into access logs, proxies, or browser history:

    Authorization: Bearer <TOKEN>
"""

import hmac
import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

TOKEN = os.environ.get("P5AGENT_TOKEN", "")
# The agent operates on its own checkout, so the install dir/name is never
# duplicated here — it is derived at runtime from this file's location (which
# install.sh decides via PROJECT). update.sh lives alongside this file.
APP_DIR = os.path.dirname(os.path.realpath(__file__))
APP_NAME = os.path.basename(APP_DIR)
ALLOW_IP = {ip.strip() for ip in os.environ.get("P5AGENT_ALLOW_IP", "127.0.0.1").split(",") if ip.strip()}
ENV_FILE = os.environ.get("P5AGENT_ENV_FILE", "/etc/p5agent.env")


def change_allow_ip(text, remove=False, caller=None):
    """`agent --allow | --remove <ip>`: add one address to P5AGENT_ALLOW_IP or
    take one off — in effect at once, and written to ENV_FILE so it survives a
    restart. The address the request came from (`caller`) cannot be removed:
    that would shut the one asking out of Run Command. Returns (rc, output)."""
    try:
        ip = str(ipaddress.ip_address(text.strip()))
    except ValueError:
        return 2, "Not an IP address: %s\n" % text
    allowed = [a.strip() for a in os.environ.get("P5AGENT_ALLOW_IP", "").split(",") if a.strip()] or sorted(ALLOW_IP)
    if remove:
        if ip not in ALLOW_IP:
            return 0, "%s is not on the list\n" % ip
        if ip == caller:
            return 1, "Not removed: %s is the address this request came from\n" % ip
        allowed = [a for a in allowed if a != ip]
    else:
        if ip in ALLOW_IP:
            return 0, "%s is already allowed\n" % ip
        allowed.append(ip)
    value = ",".join(allowed)
    try:
        with open(ENV_FILE) as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        lines = []
    lines = [l for l in lines if not l.startswith("P5AGENT_ALLOW_IP=")] + ["P5AGENT_ALLOW_IP=" + value]
    try:
        tmp = ENV_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        os.replace(tmp, ENV_FILE)
    except OSError as exc:
        return 1, "Not saved: %s\n" % exc
    if remove:
        ALLOW_IP.discard(ip)
    else:
        ALLOW_IP.add(ip)
    # Scripts the agent runs (firewall.sh) read it from the environment first.
    os.environ["P5AGENT_ALLOW_IP"] = value
    return 0, "%s %s — Run Command is now accepted from %s\n" % (
        ip, "removed" if remove else "added", ", ".join(allowed) or "nowhere")


BIND = os.environ.get("P5AGENT_BIND", "0.0.0.0")
PORT = int(os.environ.get("P5AGENT_PORT", "5005"))
DATA_DIR = os.environ.get("P5AGENT_DATA_DIR", "/var/lib/p5agent")
TMP_DIR = os.environ.get("P5AGENT_TMP_DIR", "/tmp")
CMD_TIMEOUT = int(os.environ.get("P5AGENT_TIMEOUT", "1800"))  # 30 minutes
TLS_CERT = os.environ.get("P5AGENT_TLS_CERT", "")
TLS_KEY = os.environ.get("P5AGENT_TLS_KEY", "")

# Files the agent serves/spawns. The install lifecycle (deps, clone, setup,
# logging, progress) lives entirely in install_app.sh + supported_deps.json.
INSTALL_SCRIPT = os.path.join(APP_DIR, "install_app.sh")
CERTS_SCRIPT = os.path.join(APP_DIR, "certs.sh")
# A certificate run is a job, not a request: issuing a first certificate installs
# certbot before it does anything else, and the caller's socket times out long
# before that finishes — losing the result of work that had already succeeded.
# So /certs starts it and returns, /certs-log follows it, exactly as
# /install-app and /progress do for an install.
CERTS_LOG = os.path.join(DATA_DIR, "certs.log")
CERTS_STATUS = os.path.join(DATA_DIR, "certs_status.json")
# The last line the runner writes. Its presence is what "finished" means.
CERTS_DONE = "[p5agent] certs finished rc="
# A hostname and nothing else. The domain reaches certs.sh as an argv element
# rather than inside a shell string, so this is not the only thing standing
# between a caller and the shell — but a name that cannot be a flag or a path is
# worth insisting on before anything runs as root.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
SUPPORTED_DEPS = os.path.join(APP_DIR, "supported_deps.json")
# Firewall Settings: ufw is the record, firewall.sh edits it; a save is a short
# job, followed like a certificate run.
FIREWALL_SCRIPT = os.path.join(APP_DIR, "firewall.sh")
FIREWALL_LOG = os.path.join(DATA_DIR, "firewall.log")
FIREWALL_STATUS = os.path.join(DATA_DIR, "firewall_status.json")
FIREWALL_DONE = "[p5agent] firewall finished rc="
# Setup Squid: squid/setup.sh (an authenticated, optionally domain-whitelisted
# forward proxy), run as a job and followed like a firewall save.
SQUID_SCRIPT = os.path.join(APP_DIR, "squid", "setup.sh")
SQUID_WHITELIST = os.path.join(APP_DIR, "squid", "whitelist.txt")
SQUID_CONF = "/etc/squid/squid.conf"
SQUID_PASSWD = "/etc/squid/passwd"
SQUID_WHITELIST_LIVE = "/etc/squid/whitelist.txt"   # the list in effect (setup.sh installs it)
SQUID_LOG = os.path.join(DATA_DIR, "squid.log")
SQUID_STATUS = os.path.join(DATA_DIR, "squid_status.json")
SQUID_DONE = "[p5agent] squid finished rc="
SQUID_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
# A dstdomain entry: a host name, a leading dot for "and its subdomains".
SQUID_DOMAIN_RE = re.compile(r"^\.?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$")
SETUP_LOG = os.path.join(DATA_DIR, "setup.log")
INSTALLED_APPS = os.path.join(DATA_DIR, "installed_apps.json")
APPS_DIR = os.environ.get("P5AGENT_APPS_DIR", "/opt")      # where install_app.sh puts apps
APP_OPS_SCRIPT = os.path.join(APP_DIR, "app_ops.sh")
APP_OPS = ("start", "stop", "backup", "update", "rollback", "uninstall", "nginx")
# The ops that run as a background job, one at a time, followed through /app-log.
APP_JOBS = ("update", "nginx")
# An update is a job like a certificate run: a rebuild can take far longer than
# a request may stay open, so /app starts it and /app-log follows it.
APP_UPDATE_LOG = os.path.join(DATA_DIR, "app_update.log")
APP_UPDATE_STATUS = os.path.join(DATA_DIR, "app_update_status.json")
APP_UPDATE_DONE = "[p5agent] update finished rc="
# The install lock/status record, written the moment /install-app accepts a
# request: {"app": <name>, "started_at": <unix ts>}. While it exists no second
# install is accepted. install_app.sh removes it right after logging the
# completion marker; a failed install is cleared here (stall rule) or by fail().
PENDING_INSTALL = os.path.join(DATA_DIR, "pending_install.json")
INSTALL_STALL_SECS = 1800  # no log activity for 30 min → the install failed


def run(cmd, cwd=None, extra_env=None):
    """Run a command, capturing combined stdout+stderr. Returns (rc, output)."""
    env = dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive", **(extra_env or {}))
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=CMD_TIMEOUT,
        )
        return proc.returncode, proc.stdout.decode("utf-8", "replace")
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", "replace")
        return 124, out + "\n[p5agent] timed out after %ds\n" % CMD_TIMEOUT
    except Exception as exc:  # noqa: BLE001 - report any failure to the caller
        return 1, "[p5agent] failed to run %r: %s\n" % (cmd, exc)


def job_status(status_file, log_file, done_marker):
    """What the last background job (a certificate run, an app update) is doing,
    or {} when there has never been one. The log carries the answer: the runner
    appends a completion marker as its final act, so its absence means the job
    is still going."""
    raw = read_file(status_file)
    if not raw:
        return {}
    try:
        status = json.loads(raw)
    except ValueError:
        return {}
    log = read_file(log_file) or ""
    status["log"] = log
    marker = log.rfind(done_marker)
    if marker == -1:
        status["finished"] = False
        status["returncode"] = None
    else:
        status["finished"] = True
        tail = log[marker + len(done_marker):].strip().split()
        try:
            status["returncode"] = int(tail[0]) if tail else None
        except ValueError:
            status["returncode"] = None
    return status


def certs_status():
    return job_status(CERTS_STATUS, CERTS_LOG, CERTS_DONE)


def firewall_status():
    status = job_status(FIREWALL_STATUS, FIREWALL_LOG, FIREWALL_DONE)
    if status.get("finished"):
        log = status["log"]
        status["log"] = log[:log.rfind(FIREWALL_DONE)].rstrip("\n") + "\n"
    return status


def squid_status():
    status = job_status(SQUID_STATUS, SQUID_LOG, SQUID_DONE)
    if status.get("finished"):
        log = status["log"]
        status["log"] = log[:log.rfind(SQUID_DONE)].rstrip("\n") + "\n"
    return status


def nginx_in_use():
    """Why this upplet counts as an Nginx one — an app behind Nginx, or Nginx
    running — or "" when it does not. Squid and Nginx do not share an upplet:
    a proxy upplet's firewall is SSH, the agent and the proxy port only."""
    try:
        apps = json.loads(read_file(INSTALLED_APPS) or "[]")
    except ValueError:
        apps = []
    wired = [str(a.get("name")) for a in apps if isinstance(a, dict) and a.get("public-port")]
    if wired:
        return "%s %s behind Nginx" % (", ".join(wired), "is" if len(wired) == 1 else "are")
    rc, _ = run(["systemctl", "is-active", "--quiet", "nginx"])
    return "Nginx is running" if rc == 0 else ""


def squid_whitelist_domains(text):
    """The entries of a whitelist file: comments, blanks and case dropped,
    each once, in alphabetical order (a leading dot does not count)."""
    seen = set()
    for line in (text or "").splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry:
            seen.add(entry)
    return sorted(seen, key=lambda d: (d.lstrip("."), d))


def squid_current():
    """The proxy a previous Setup Squid left: {port, user, whitelist}, or None."""
    conf = read_file(SQUID_CONF)
    if not conf or "Generated by setup-squid.sh" not in conf:
        return None
    port = re.search(r"^http_port\s+(\d+)", conf, re.M)
    user = (read_file(SQUID_PASSWD) or "").split(":", 1)[0].strip()
    return {
        "port": int(port.group(1)) if port else None,
        "user": user or None,
        "whitelist": bool(re.search(r"^http_access allow authenticated whitelist", conf, re.M)),
    }


def squid_names(text):
    """Comma- or space-separated domain names, lower case, each once — or
    (None, message) when one is not a domain name."""
    names = [n.lower().rstrip(".") for n in re.split(r"[,\s]+", text or "")]
    names = list(dict.fromkeys(n for n in names if n and n != "."))
    bad = [n for n in names if len(n) > 253 or not SQUID_DOMAIN_RE.match(n)]
    if bad:
        return None, "Not a domain name: %s\n" % ", ".join(bad)
    return names, ""


def squid_covers(entry, name):
    """Does whitelist `entry` match everything `name` matches?"""
    if entry == name:
        return True
    return entry.startswith(".") and (name.lstrip(".") == entry[1:] or name.endswith(entry))


def squid_save_whitelist(entries, old_text):
    """Write the whitelist Squid uses and have Squid re-read it, checking the
    whole configuration first; a list Squid refuses goes back to what it was.
    Returns (rc, output) — output empty on success."""
    try:
        st = os.stat(SQUID_WHITELIST_LIVE)
        tmp = SQUID_WHITELIST_LIVE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, st.st_mode & 0o777)
        with os.fdopen(fd, "w") as fh:
            fh.write("\n".join(entries) + "\n")
        os.chown(tmp, st.st_uid, st.st_gid)
        os.replace(tmp, SQUID_WHITELIST_LIVE)
    except OSError as exc:
        return 1, "Not saved: %s\n" % exc
    rc, out = run(["squid", "-k", "parse"])
    if rc == 0:
        rc, out = run(["squid", "-k", "reconfigure"])
    if rc != 0:
        try:
            with open(SQUID_WHITELIST_LIVE, "w") as fh:
                fh.write(old_text)
        except OSError:
            pass
        return 1, out + "\nSquid did not accept the new list — the whitelist is unchanged\n"
    return 0, ""


def squid_whitelist_ready():
    """(rc, message) when the whitelist cannot be edited here, else None."""
    current = squid_current()
    if not current:
        return 1, "Squid is not set up on this upplet — run Setup Squid first\n"
    if not current.get("whitelist"):
        return 1, "Squid has no whitelist: every domain is allowed already\n"
    return None


def squid_allow(text):
    """`proxy --allow | -a <names>`: add comma-separated domain names to the
    whitelist Squid uses, and have Squid re-read it. A name with a leading dot
    covers its subdomains too; one without is that host only. A name already
    covered by an entry is skipped; entries the new ones cover are dropped
    (Squid warns about overlapping dstdomain entries). Returns (rc, output)."""
    names, error = squid_names(text)
    if error:
        return 2, error
    if not names:
        return 2, Handler.ALIAS_USAGE["proxy"]
    blocked = squid_whitelist_ready()
    if blocked:
        return blocked
    covers = squid_covers

    old_text = read_file(SQUID_WHITELIST_LIVE)
    entries = squid_whitelist_domains(old_text)
    added, skipped, dropped = [], [], []
    for name in names:
        holder = next((e for e in entries if covers(e, name)), None)
        if holder:
            skipped.append(name if holder == name else "%s (covered by %s)" % (name, holder))
            continue
        covered = [e for e in entries if covers(name, e)]
        dropped += covered
        entries = [e for e in entries if e not in covered] + [name]
        added.append(name)
    if not added:
        return 0, "Nothing to add — already allowed: %s\n" % ", ".join(skipped)

    entries = squid_whitelist_domains("\n".join(entries))
    rc, out = squid_save_whitelist(entries, old_text)
    if rc != 0:
        return rc, out
    lines = ["Added: %s" % ", ".join(added)]
    if dropped:
        lines.append("Dropped, now covered: %s" % ", ".join(dropped))
    if skipped:
        lines.append("Already allowed: %s" % ", ".join(skipped))
    lines.append("Squid reloaded — %d domain(s) on the whitelist" % len(entries))
    return 0, "\n".join(lines) + "\n"


def squid_remove(text):
    """`proxy --remove | -r <names>`: take comma-separated entries off the
    whitelist Squid uses, and have Squid re-read it. Only an entry as it is
    written goes (".github.com" and "github.com" are different entries); a
    name still reached through a broader entry is said so. The list is never
    left empty — turning the whitelist off is Setup Squid's. Returns
    (rc, output)."""
    names, error = squid_names(text)
    if error:
        return 2, error
    if not names:
        return 2, Handler.ALIAS_USAGE["proxy"]
    blocked = squid_whitelist_ready()
    if blocked:
        return blocked
    old_text = read_file(SQUID_WHITELIST_LIVE)
    entries = squid_whitelist_domains(old_text)
    removed, missing = [], []
    for name in names:
        if name in entries:
            entries.remove(name)
            removed.append(name)
        else:
            missing.append(name)
    notes = []
    for name in removed + missing:
        holder = next((e for e in entries if squid_covers(e, name)), None)
        if holder:
            notes.append("%s is still allowed through %s" % (name, holder))
    if not removed:
        return 0, "Nothing to remove — not on the list: %s\n%s" % (
            ", ".join(missing), "".join(n + "\n" for n in notes))
    if not entries:
        return 1, ("Not removed: the whitelist would be empty. To allow every domain, "
                   "turn the whitelist off in Setup Squid\n")
    rc, out = squid_save_whitelist(entries, old_text)
    if rc != 0:
        return rc, out
    lines = ["Removed: %s" % ", ".join(removed)]
    if missing:
        lines.append("Not on the list: %s" % ", ".join(missing))
    lines += notes
    lines.append("Squid reloaded — %d domain(s) on the whitelist" % len(entries))
    return 0, "\n".join(lines) + "\n"


def squid_whitelist_report():
    """`proxy --whitelist | -wl`: the whitelist as Squid has it loaded, asked
    from Squid's cache manager (its configuration, open to 127.0.0.1 only —
    see squid/setup.sh). When Squid does not answer, the file it reads is
    shown instead, and said so. Returns (rc, output)."""
    current = squid_current()
    if not current:
        return 1, "Squid is not set up on this upplet — run Setup Squid first\n"
    file_list = squid_whitelist_domains(read_file(SQUID_WHITELIST_LIVE))
    loaded, why, hint = None, "", ""
    try:
        import urllib.error
        import urllib.request
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        url = "http://127.0.0.1:%d/squid-internal-mgr/config" % (current.get("port") or 3128)
        # Squid's port is closed for a moment while it reloads (as after
        # `proxy --allow`): a refused connection is tried again, briefly.
        for attempt in range(12):
            try:
                with opener.open(url, timeout=5) as resp:
                    config = resp.read().decode("utf-8", "replace")
                break
            except urllib.error.URLError as exc:
                if isinstance(exc, urllib.error.HTTPError) or attempt == 11 or \
                        not isinstance(exc.reason, ConnectionRefusedError):
                    raise
                time.sleep(0.25)
        if re.search(r"^\s*http_access\b", config, re.M):
            loaded = []
            for line in config.splitlines():
                parts = line.split()
                if parts[:3] == ["acl", "whitelist", "dstdomain"]:
                    loaded += [p for p in parts[3:] if not p.startswith("-")]
            loaded = squid_whitelist_domains("\n".join(loaded))
        else:
            why = "Squid answered without its configuration"
    except urllib.error.HTTPError as exc:
        # Squid is up but will not tell: a configuration from before it did.
        why = "Squid refused to show its configuration (HTTP %d)" % exc.code
        hint = " Re-run Setup Squid to let the agent ask Squid itself."
    except Exception as exc:  # noqa: BLE001 - any failure means: fall back to the file
        why = "Squid did not answer (%s)" % getattr(exc, "reason", exc)

    if loaded is None:
        head = ("%s — this is %s, which Squid loads on start and reload.%s\n"
                % (why, SQUID_WHITELIST_LIVE, hint))
        return 0, head + "%d domain(s):\n%s" % (len(file_list), "".join(d + "\n" for d in file_list))
    if not loaded and not current.get("whitelist"):
        return 0, "Squid has no whitelist: every domain is allowed\n"
    out = "%d domain(s) loaded in Squid:\n%s" % (len(loaded), "".join(d + "\n" for d in loaded))
    if loaded != file_list:
        out += ("\n%s differs from what Squid has loaded — `squid -k reconfigure` loads it\n"
                % SQUID_WHITELIST_LIVE)
    return 0, out


def listening_ports():
    """{port: process} for every TCP port something listens on (ss -ltnpH)."""
    rc, out = run(["ss", "-ltnpH"])
    ports = {}
    if rc != 0:
        return ports
    for line in out.splitlines():
        cols = line.split()
        m = re.search(r":(\d+)$", cols[3]) if len(cols) > 3 else None
        if not m:
            continue
        proc = re.search(r'users:\(\("([^"]+)"', line)
        ports.setdefault(int(m.group(1)), proc.group(1) if proc else "another process")
    return ports


def app_update_status():
    """As certs_status, with the completion marker left out of the log: the
    update's own last line already says how it went."""
    status = job_status(APP_UPDATE_STATUS, APP_UPDATE_LOG, APP_UPDATE_DONE)
    if status.get("finished"):
        log = status["log"]
        status["log"] = log[:log.rfind(APP_UPDATE_DONE)].rstrip("\n") + "\n"
    return status


def unique_script_path():
    """Build /tmp/command_<dd_mm_yy_hh_mm_ss>.sh, avoiding same-second clashes."""
    ts = datetime.now().strftime("%d_%m_%y_%H_%M_%S")
    path = os.path.join(TMP_DIR, "command_%s.sh" % ts)
    n = 1
    while os.path.exists(path):
        path = os.path.join(TMP_DIR, "command_%s_%d.sh" % (ts, n))
        n += 1
    return path


def read_file(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""


def is_demo(req):
    """A demo is a folder of the agent's own checkout ("path"), not a repo."""
    return req.get("demo") in (True, "true", "1", 1, "yes")


def app_name_from_request(req):
    """The app's install name: explicit "name", else the repo basename (a
    demo: its folder's name)."""
    name = (req.get("name") or "").strip()
    if name:
        return name
    if is_demo(req):
        return (req.get("path") or "").strip().strip("/").rsplit("/", 1)[-1]
    base = (req.get("repo") or "").rstrip("/").rsplit("/", 1)[-1]
    return base[:-4] if base.endswith(".git") else base


def clear_install(failed=False):
    """Drop pending_install.json; archive setup.log out of the way."""
    if os.path.exists(SETUP_LOG):
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        suffix = "-failed" if failed else ""
        try:
            os.replace(SETUP_LOG, os.path.join(TMP_DIR, "p5agent_setup_%s%s.log" % (stamp, suffix)))
        except OSError:
            try:
                os.remove(SETUP_LOG)
            except OSError:
                pass
    try:
        os.remove(PENDING_INSTALL)
    except OSError:
        pass


COMPLETED_SUFFIX = " installation completed"


def completed_app(log):
    """The app name from the completion marker — the log's LAST line being
    "[ts] <app> installation completed" — or None."""
    lines = log.rstrip().splitlines() if log.strip() else []
    if not lines or not lines[-1].endswith(COMPLETED_SUFFIX):
        return None
    app = lines[-1][:-len(COMPLETED_SUFFIX)]
    if app.startswith("[") and "] " in app:
        app = app.split("] ", 1)[1]
    return app.strip() or None


def log_started_at(log):
    """Unix timestamp of the log's first "[Y-m-d H:M:S] ..." line; falls back
    to the log file's mtime."""
    try:
        first = log.lstrip().splitlines()[0]
        return int(datetime.strptime(first[1:20], "%Y-%m-%d %H:%M:%S").timestamp())
    except (IndexError, ValueError):
        pass
    try:
        return int(os.stat(SETUP_LOG).st_mtime)
    except OSError:
        return 0


def install_status():
    """The current install, or None when idle. The agent — and only the agent —
    decides the install's fate:

      completed  the log's last line is "<app> installation completed";
                 install_app.sh removes pending_install.json right after
                 logging it, so a completed install is reported from the log
                 alone (which stays until the next accepted install)
      failed     pending exists but there was no log activity (setup.log
                 mtime, else started_at) for more than 30 minutes → cleared
                 here; the polling peer learns of the failure by /progress
                 dropping back to {}
    """
    log = read_file(SETUP_LOG)
    raw = read_file(PENDING_INSTALL)

    if not raw:
        # No lock: either the last install completed (its log remains, ending
        # with the marker) or nothing is running.
        app = completed_app(log)
        if not app:
            return None
        return {"app": app, "started_at": log_started_at(log),
                "log": log, "completed": True}

    try:
        pending = json.loads(raw)
    except ValueError:
        pending = {}
    app = (pending.get("app") or "").strip() if isinstance(pending, dict) else ""
    if not app:
        clear_install(failed=True)  # unreadable record — drop it
        return None

    status = {"app": app, "started_at": int(pending.get("started_at") or 0)}
    if log:
        status["log"] = log
    if completed_app(log) == app:
        # Marker logged, lock removal not observed yet (tiny race) — done.
        status["completed"] = True
        return status

    last = status["started_at"]
    try:
        last = max(last, int(os.stat(SETUP_LOG).st_mtime))
    except OSError:
        pass
    if time.time() - last > INSTALL_STALL_SECS:
        clear_install(failed=True)
        return None
    return status



# ---- /info ---------------------------------------------------------------
# Everything here is read, never changed, and each part fails on its own: a
# missing tool leaves its field empty rather than failing the whole report.

def _run(args, timeout=10):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _os_release():
    fields = {}
    for line in read_file("/etc/os-release").splitlines():
        key, _, value = line.partition("=")
        fields[key] = value.strip().strip('"')
    return fields.get("PRETTY_NAME") or fields.get("NAME") or ""


def _clean_version(pkg, version):
    """A Debian package version, reduced to the upstream one people know:
    "2:8.3+93" -> "8.3", "18.19.1+dfsg-6ubuntu5" -> "18.19.1". default-jdk
    counts Java as "1.21"; that is Java 21."""
    v = re.sub(r"^\d+:", "", version)
    v = re.split(r"[+~-]", v, 1)[0]
    if pkg == "default-jdk" and v.startswith("1."):
        v = v[2:]
    return v


def installed_packages():
    """The supported dependencies that are installed, with versions — one
    dpkg-query for all of them."""
    try:
        registry = json.loads(read_file(SUPPORTED_DEPS) or "[]")
    except ValueError:
        registry = []
    wanted = []   # (name, display, apt package or None)
    for entry in registry:
        name = entry.get("name", "")
        pkg = entry.get("package") or (entry.get("name") if entry.get("package-manager") == "apt" else None)
        wanted.append((name, entry.get("display-name") or name, pkg))

    apt = [pkg for _, _, pkg in wanted if pkg]
    versions = {}
    out = _run(["dpkg-query", "-W", "-f", "${Package}\t${db:Status-Abbrev}\t${Version}\n"] + apt)
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[1].startswith("ii"):
            versions[parts[0]] = parts[2]

    found = []
    for name, display, pkg in wanted:
        if pkg and pkg in versions:
            found.append({"name": name, "display": display, "version": _clean_version(pkg, versions[pkg]),
                          "package": pkg, "package_version": versions[pkg]})
        elif name == "swift" and shutil.which("swift"):
            m = re.search(r"Swift version (\S+)", _run(["swift", "--version"]))
            found.append({"name": name, "display": display, "version": m.group(1) if m else ""})
    return found


def firewall_rules():
    """ufw's allow/deny rules, one per port — the IPv6 twin of a rule is folded
    into it. None when ufw is not there."""
    if not shutil.which("ufw"):
        return None
    out = _run(["ufw", "status"])
    status = ""
    rules, seen, table = [], set(), False
    for line in out.splitlines():
        if line.startswith("Status:"):
            status = line.split(":", 1)[1].strip()
        elif line.startswith("--"):
            table = True
        elif table and line.strip():
            text, _, comment = line.partition("#")
            cols = re.split(r"\s{2,}", text.strip())
            if len(cols) < 3:
                continue
            to, action, source = (c.replace(" (v6)", "") for c in cols[:3])
            if (to, action, source) in seen:
                continue
            seen.add((to, action, source))
            rules.append({"to": to, "action": action, "from": source, "comment": comment.strip()})
    return {"status": status, "rules": rules}


def agent_version():
    out = _run(["git", "-C", APP_DIR, "log", "-1", "--format=%h%x09%cI%x09%s"]).strip()
    commit, _, rest = out.partition("\t")
    date, _, subject = rest.partition("\t")
    return {"commit": commit, "date": date, "subject": subject}


def upplet_info():
    uname = os.uname()
    try:
        uptime = int(float(read_file("/proc/uptime").split()[0]))
    except (IndexError, ValueError):
        uptime = None
    mem = {}
    for line in read_file("/proc/meminfo").splitlines():
        key, _, value = line.partition(":")
        if key in ("MemTotal", "MemAvailable"):
            mem[key] = int(value.split()[0]) * 1024
    try:
        du = shutil.disk_usage("/")
        disk = {"total": du.total, "used": du.used, "free": du.free}
    except OSError:
        disk = None
    return {
        "hostname": uname.nodename,
        "os": _os_release(),
        "kernel": uname.release,
        "arch": uname.machine,
        "uptime_seconds": uptime,
        "memory": {"total": mem.get("MemTotal"), "available": mem.get("MemAvailable")},
        "disk": disk,
        "agent": agent_version(),
        "packages": installed_packages(),
        "firewall": firewall_rules(),
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "p5agent/1.0"
    protocol_version = "HTTP/1.1"

    # ---- low-level helpers ----------------------------------------------
    def _send(self, status, payload):
        self._send_raw(status, json.dumps(payload), "application/json")

    def _send_raw(self, status, text, content_type):
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _path(self):
        return urlparse(self.path).path.rstrip("/") or "/"

    def _body(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _authorized(self):
        if not TOKEN:
            # Fail closed: refuse privileged ops when no token is configured.
            return False
        # The token is accepted ONLY via the Authorization: Bearer header —
        # never the URL — so it cannot end up in access logs or history.
        supplied = ""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            supplied = auth[len("Bearer "):]
        return hmac.compare_digest(supplied, TOKEN)

    def _ip_allowed(self):
        # Per-endpoint source-IP check (enforced in-process, not just by the
        # firewall). Loopback is treated as equivalent when ALLOW_IP is local.
        ip = self.client_address[0]
        if ip in ALLOW_IP:
            return True
        if ALLOW_IP & {"127.0.0.1", "localhost"} and ip in ("127.0.0.1", "::1"):
            return True
        return False

    def log_message(self, fmt, *args):
        sys.stderr.write("[p5agent] %s %s\n" % (self.address_string(), fmt % args))

    # ---- dispatch --------------------------------------------------------
    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()

    ROUTES = ("/update", "/command", "/install-app", "/progress",
              "/supported", "/apps", "/certs", "/certs-log", "/info", "/app",
              "/app-log", "/firewall", "/firewall-log", "/squid", "/squid-log", "/utilities")
    # Only running arbitrary commands is locked to the allowed source IP; every
    # other operation needs just the token.
    IP_RESTRICTED = ("/command",)

    def _dispatch(self):
        path = self._path()
        if path == "/":
            return self._send(200, {"status": "ok", "service": "p5agent"})
        if path not in self.ROUTES:
            return self._send(404, {"error": "not found", "path": path})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        # Running commands is locked to the allowed source IP.
        if path in self.IP_RESTRICTED and not self._ip_allowed():
            def _mask_ip(ip):
                return ip[:2] + "*" * max(0, len(ip) - 4) + ip[-2:] if len(ip) > 4 else ip
            return self._send(403, {"error": "forbidden",
                                    "detail": "%s is restricted to %s" % (path, ", ".join(_mask_ip(ip) for ip in sorted(ALLOW_IP)))})
        try:
            return {
                "/update": self._do_update,
                "/command": self._do_command,
                "/install-app": self._do_install_app,
                "/progress": self._do_progress,
                "/supported": self._do_supported,
                "/apps": self._do_apps,
                "/certs": self._do_certs,
                "/certs-log": self._do_certs_log,
                "/info": self._do_info,
                "/app": self._do_app,
                "/app-log": self._do_app_log,
                "/firewall": self._do_firewall,
                "/firewall-log": self._do_firewall_log,
                "/squid": self._do_squid,
                "/squid-log": self._do_squid_log,
                "/utilities": self._do_utilities,
            }[path]()
        except Exception as exc:  # noqa: BLE001 - never leak a traceback as 500 HTML
            try:
                return self._send(500, {"error": "internal error", "detail": str(exc)})
            except OSError as send_exc:
                # The client hung up before we answered — a long job outliving
                # the caller's timeout, most often. Writing the 500 fails the
                # same way the first write did, and the pair of tracebacks says
                # nothing about the original error. Log the one that matters.
                sys.stderr.write(
                    "[p5agent] request failed and the reply could not be sent "
                    "(%s); original error: %s\n" % (send_exc, exc)
                )
                return None

    # ---- operations ------------------------------------------------------
    def _do_update(self):
        """1) sync this checkout to the remote, 2) run its update.sh.

        We fetch and hard-reset to the upstream branch rather than `git pull`:
        a fast-forward pull cannot handle a force-pushed (rewritten) history, and
        resetting to local HEAD would keep the old code. Resetting to the remote
        tracking branch always lands exactly what was pushed. The overall result
        reflects update.sh, the authoritative step.
        """
        parts = []

        if os.path.isdir(os.path.join(APP_DIR, ".git")):
            subprocess.run(
                ["git", "config", "--global", "--add", "safe.directory", APP_DIR],
                check=False,
            )
            rc, out = run(["git", "-C", APP_DIR, "fetch", "--prune", "origin"])
            parts.append("$ git -C %s fetch --prune origin\n%s" % (APP_DIR, out))

            # Resolve the upstream ref (e.g. origin/main), falling back to the
            # remote's default branch if no upstream is configured.
            rc_u, upstream = run(
                ["git", "-C", APP_DIR, "rev-parse", "--abbrev-ref",
                 "--symbolic-full-name", "@{u}"]
            )
            upstream = upstream.strip()
            if rc_u != 0 or not upstream:
                rc_u, upstream = run(
                    ["git", "-C", APP_DIR, "rev-parse", "--abbrev-ref", "origin/HEAD"]
                )
                upstream = upstream.strip() or "origin/HEAD"

            # Hard-reset to the remote — honours force-pushes and clears any
            # local changes so update.sh runs against exactly the pushed code.
            rc, out = run(["git", "-C", APP_DIR, "reset", "--hard", upstream])
            parts.append("$ git -C %s reset --hard %s\n%s" % (APP_DIR, upstream, out))
        else:
            parts.append("[p5agent] %s is not a git checkout; skipping git sync" % APP_DIR)

        update_sh = os.path.join(APP_DIR, "update.sh")
        if not os.path.isfile(update_sh):
            parts.append("[p5agent] no update.sh found at %s" % update_sh)
            return self._send(500, {"returncode": 1, "output": "\n".join(parts)})

        rc, out = run(["bash", update_sh], cwd=APP_DIR)
        parts.append("$ bash %s\n%s" % (update_sh, out))
        status = 200 if rc == 0 else 500
        return self._send(status, {"returncode": rc, "output": "\n".join(parts)})

    def _do_command(self):
        """Save the request command to a timestamped script and run it as root."""
        text = self._body().decode("utf-8", "replace")
        if not text.strip():
            return self._send(400, {"error": "empty command body"})

        if self._alias(text):
            return

        if not text.startswith("#!"):
            text = "#!/usr/bin/env bash\n" + text

        path = unique_script_path()
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, 0o700)  # grant execute permission (owner: root)

        rc, out = run([path], cwd=TMP_DIR)
        status = 200 if rc == 0 else 500
        return self._send(status, {"returncode": rc, "output": out, "script": path})

    # Built-in Run Command aliases, answered here without a script. Any single
    # line starting with an alias name is the alias's, even a wrong one:
    # falling through to bash would leave whatever was typed in /tmp.
    ALIAS = re.compile(r"^\s*(token|agent|proxy)(?:[ \t]+([^\n]*?))?\s*$")
    ALIAS_USAGE = {
        "token": "usage: token --print | -p\n",
        "agent": "usage: agent --print | -p\n       agent --allow | -a <ip>\n"
                 "       agent --remove | -r <ip>\n",
        "proxy": "usage: proxy --allow | -a <name>[,<name>...]\n"
                 "       proxy --remove | -r <name>[,<name>...]\n"
                 "       proxy --whitelist | -wl\n",
    }

    def _alias(self, text):
        """Answer a built-in alias:
            token --print | -p      the management token
            agent --print | -p       P5AGENT_ALLOW_IP — the addresses Run
                                     Command is accepted from
            agent --allow | -a <ip>  add <ip> to it
            agent --remove | -r <ip> take <ip> off it
            proxy --allow | -a <names>  add comma-separated domain names to
                                     Squid's whitelist (squid_allow)
            proxy --remove | -r <names>  take them off it (squid_remove)
            proxy --whitelist | -wl  the whitelist Squid has loaded
        Returns True when it answered, False when `text` is not an alias."""
        m = self.ALIAS.match(text)
        if not m:
            return False
        name, args = m.group(1), (m.group(2) or "").split()
        if name == "token" and args in (["--print"], ["-p"]):
            self._send(200, {"returncode": 0, "output": TOKEN + "\n"})
        elif name == "agent" and args in (["--print"], ["-p"]):
            self._send(200, {"returncode": 0, "output": ", ".join(sorted(ALLOW_IP)) + "\n"})
        elif name == "agent" and len(args) == 2 and args[0] in ("--allow", "-a", "--remove", "-r"):
            rc, out = change_allow_ip(args[1], remove=args[0] in ("--remove", "-r"),
                                      caller=self.client_address[0])
            self._send(200 if rc == 0 else 500, {"returncode": rc, "output": out})
        elif name == "proxy" and args in (["--whitelist"], ["-wl"]):
            rc, out = squid_whitelist_report()
            self._send(200 if rc == 0 else 500, {"returncode": rc, "output": out})
        elif name == "proxy" and len(args) >= 2 and args[0] in ("--allow", "-a", "--remove", "-r"):
            # The names as typed after the flag: "a.com, b.com" is one list.
            names = m.group(2).split(None, 1)[1]
            rc, out = squid_allow(names) if args[0] in ("--allow", "-a") else squid_remove(names)
            self._send(200 if rc == 0 else 500, {"returncode": rc, "output": out})
        else:
            self._send(500, {"returncode": 2, "output": self.ALIAS_USAGE[name]})
        return True

    def _do_install_app(self):
        """Accept one install at a time: refuse while one is running, record
        the accepted request in pending_install.json immediately, then launch
        install_app.sh in the background and return."""
        raw = self._body().decode("utf-8", "replace").strip()
        if not raw:
            return self._send(400, {"error": "empty body"})
        try:
            req = json.loads(raw)
        except ValueError:
            return self._send(400, {"error": "body must be JSON"})
        if is_demo(req):
            if not (req.get("path") or "").strip():
                return self._send(400, {"error": "path is required for a demo"})
        elif not (req.get("repo") or "").strip():
            return self._send(400, {"error": "repo is required"})
        if not os.path.isfile(INSTALL_SCRIPT):
            return self._send(500, {"error": "install_app.sh not found"})

        current = install_status()
        if current and not current.get("completed"):
            return self._send(409, {"error": "%s installation is in progress" % current["app"]})

        name = app_name_from_request(req)
        if not name:
            return self._send(400, {"error": "cannot derive the app name"})

        ts = datetime.now().strftime("%d_%m_%y_%H_%M_%S")
        req_path = os.path.join(TMP_DIR, "install_request_%s.json" % ts)
        with open(req_path, "w") as fh:
            json.dump(req, fh)

        # Take the lock the moment the request is accepted: archive the previous
        # (completed) install's leftovers and record the new one.
        clear_install()
        with open(PENDING_INSTALL, "w") as fh:
            json.dump({"app": name, "started_at": int(time.time())}, fh)

        try:
            subprocess.Popen(
                ["bash", INSTALL_SCRIPT, req_path],
                cwd=APP_DIR,
                env=dict(os.environ, HOME="/root"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,  # survive the agent and this request
            )
        except Exception as exc:  # noqa: BLE001
            clear_install(failed=True)  # release the lock — nothing is running
            return self._send(500, {"error": "failed to launch installer",
                                    "detail": str(exc)})
        return self._send(200, {"status": "started", "app": name})

    def _do_progress(self):
        """Return the current install status as JSON:
        { "app", "started_at", "log"?, "completed"? } — {} when idle."""
        return self._send(200, install_status() or {})

    def _do_supported(self):
        """Return the supported dependencies registry."""
        return self._send_raw(200, read_file(SUPPORTED_DEPS) or "[]", "application/json")

    def _do_apps(self):
        """Return the installed apps list, each with its service state and
        whether a backup to roll back to exists."""
        try:
            apps = json.loads(read_file(INSTALLED_APPS) or "[]")
        except ValueError:
            apps = []
        for app in apps if isinstance(apps, list) else []:
            name = str(app.get("name") or "")
            if not name:
                continue
            _, state = run(["systemctl", "is-active", name])
            app["service"] = state.strip() or "unknown"
            app["backup"] = os.path.isdir(os.path.join(APPS_DIR, name + "_backup"))
        return self._send(200, apps)

    def _do_app(self):
        """Run one lifecycle operation on one installed app (app_ops.sh checks
        the name against installed_apps.json before touching anything)."""
        try:
            req = json.loads(self._body().decode("utf-8", "replace") or "{}")
        except ValueError:
            return self._send(400, {"error": "body must be JSON"})
        op = str(req.get("op") or "")
        name = str(req.get("name") or "")
        if op not in APP_OPS:
            return self._send(400, {"error": "op must be one of " + ", ".join(APP_OPS)})
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*$", name):
            return self._send(400, {"error": "a valid app name is required"})
        current = install_status()
        if current and not current.get("completed") and current.get("app") == name:
            return self._send(409, {"error": "%s is being installed" % name})
        updating = app_update_status()
        if updating and not updating.get("finished"):
            if op in APP_JOBS or updating.get("name") == name:
                return self._send(409, {"error": "%s is being %s" % (
                    updating.get("name"), "set up behind Nginx" if updating.get("op") == "nginx" else "updated")})
        if op == "update":
            return self._start_app_job(name, "update")
        if op == "nginx":
            if squid_current():
                return self._send(409, {"error": "Squid is set up on this upplet — Nginx runs on an upplet without Squid"})
            port = req.get("port")
            # 0: nginx.sh picks the port.
            if not isinstance(port, int) or isinstance(port, bool) or not (port == 0 or 1024 <= port <= 65535):
                return self._send(400, {"error": "port must be 0 or a number from 1024 to 65535"})
            # Bot protection is set on every run: a flag left out turns it off.
            flags = ["--port", str(port)]
            # The port Nginx serves the app on; left out, it stays where it is.
            public = req.get("public_port")
            if public is not None:
                if not isinstance(public, int) or isinstance(public, bool) or not 1 <= public <= 65535 or public in (80, PORT):
                    return self._send(400, {"error": "public_port must be a number from 1 to 65535, not 80 or %d" % PORT})
                flags += ["--public", str(public)]
            if req.get("bots") is True:
                flags.append("--bots")
                if req.get("fail2ban") is True:
                    flags.append("--fail2ban")
            return self._start_app_job(name, "nginx", flags)
        cmd = ["bash", APP_OPS_SCRIPT, op, name]
        if op == "uninstall" and req.get("drop_db") is True:
            cmd.append("--drop-db")
        rc, out = run(cmd)
        return self._send(200 if rc == 0 else 500, {"returncode": rc, "output": out})

    def _start_app_job(self, name, op, extra=()):
        """Launch `app_ops.sh <op> <name> [extra]` detached and return at once;
        /app-log follows it (its status says which op)."""
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(APP_UPDATE_LOG, "w") as fh:
            fh.write("")
        with open(APP_UPDATE_STATUS, "w") as fh:
            json.dump({"name": name, "op": op, "started_at": int(time.time())}, fh)
        # The runner appends the completion marker whatever the script does.
        runner = 'exec >>"$1" 2>&1; bash "$2" "$5" "$3" "${@:6}"; printf "\\n%s%s\\n" "$4" "$?"'
        try:
            subprocess.Popen(
                ["bash", "-c", runner, "p5agent-app-job",
                 APP_UPDATE_LOG, APP_OPS_SCRIPT, name, APP_UPDATE_DONE, op] + list(extra),
                cwd=APP_DIR,
                env=dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,   # survive the agent and this request
            )
        except Exception as exc:  # noqa: BLE001
            return self._send(500, {"error": "failed to start " + op, "detail": str(exc)})
        return self._send(200, {"status": "started", "name": name, "op": op})

    def _do_app_log(self):
        """The current (or last) app update: {name, log, finished, returncode}."""
        return self._send(200, app_update_status())

    def _do_info(self):
        """Describe the upplet: system, this agent, packages, firewall."""
        return self._send(200, upplet_info())

    def _do_certs(self):
        """Start a certificate run for a domain and return at once.

        The work — certbot, wiring every installed app, restarting them — is in
        certs.sh. It can take minutes on a droplet that has never had certbot
        installed, which is longer than any caller will hold a connection open,
        so this launches it detached and answers immediately. Follow it with
        /certs-log.
        """
        raw = self._body().decode("utf-8", "replace").strip()
        try:
            req = json.loads(raw) if raw else {}
        except ValueError:
            return self._send(400, {"error": "body must be JSON"})
        domain = str(req.get("domain", "")).strip().lower().rstrip(".")
        if not DOMAIN_RE.match(domain):
            return self._send(400, {"error": "a valid domain name is required"})
        if not os.path.isfile(CERTS_SCRIPT):
            return self._send(500, {"error": "certs.sh not found"})

        current = certs_status()
        if current and not current.get("finished"):
            return self._send(409, {"error": "a certificate run for %s is already in progress"
                                             % current.get("domain", "this upplet")})

        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CERTS_LOG, "w") as fh:
            fh.write("[p5agent] starting certificate run for %s\n" % domain)
        with open(CERTS_STATUS, "w") as fh:
            json.dump({"domain": domain, "started_at": int(time.time())}, fh)

        # The runner appends the completion marker whatever the script does, so
        # a crash is still an ending rather than a log that simply stops.
        runner = 'exec >>"$1" 2>&1; bash "$2" domain "$3"; printf "\\n%s%s\\n" "$4" "$?"'
        try:
            subprocess.Popen(
                ["bash", "-c", runner, "p5agent-certs",
                 CERTS_LOG, CERTS_SCRIPT, domain, CERTS_DONE],
                cwd=APP_DIR,
                env=dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive"),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,   # survive the agent and this request
            )
        except Exception as exc:  # noqa: BLE001
            return self._send(500, {"error": "failed to start the certificate run",
                                    "detail": str(exc)})
        return self._send(200, {"status": "started", "domain": domain})

    def _do_firewall(self):
        """GET: the rule table. POST: save the user's rules and apply them —
        started here, followed through /firewall-log."""
        if not os.path.isfile(FIREWALL_SCRIPT):
            return self._send(500, {"error": "firewall.sh not found"})
        # The address this request came from — the dashboard, as the upplet's
        # firewall sees it. firewall.sh puts it on every address list next to
        # P5AGENT_ALLOW_IP, so a list never shuts out the dashboard driving it,
        # even on an upplet whose P5AGENT_ALLOW_IP is unset.
        caller = {"P5AGENT_CALLER_IP": self.client_address[0]}
        if self.command == "GET":
            rc, out = run(["bash", FIREWALL_SCRIPT, "--plan"], extra_env=caller)
            try:
                table = json.loads(out.strip().splitlines()[-1]) if rc == 0 else None
            except (ValueError, IndexError):
                table = None
            if table is None:
                return self._send(500, {"error": "could not read the firewall rules", "output": out})
            fw = firewall_rules()
            table["ufw"] = fw["status"] if fw else None
            return self._send(200, table)

        try:
            req = json.loads(self._body().decode("utf-8", "replace") or "{}")
        except ValueError:
            return self._send(400, {"error": "body must be JSON"})
        if not isinstance(req.get("rules"), list):
            return self._send(400, {"error": "rules must be a list"})
        current = firewall_status()
        if current and not current.get("finished"):
            return self._send(409, {"error": "the firewall is being updated"})

        os.makedirs(DATA_DIR, exist_ok=True)
        # The table travels in a temporary file the runner removes when done.
        request = os.path.join(TMP_DIR, "firewall_request_%s.json" % datetime.now().strftime("%d_%m_%y_%H_%M_%S"))
        with open(request, "w") as fh:
            json.dump({"rules": req["rules"]}, fh)
        with open(FIREWALL_LOG, "w") as fh:
            fh.write("")
        with open(FIREWALL_STATUS, "w") as fh:
            json.dump({"started_at": int(time.time())}, fh)
        runner = 'exec >>"$1" 2>&1; bash "$2" --set "$3"; rc=$?; rm -f "$3"; printf "\\n%s%s\\n" "$4" "$rc"'
        try:
            subprocess.Popen(
                ["bash", "-c", runner, "p5agent-firewall",
                 FIREWALL_LOG, FIREWALL_SCRIPT, request, FIREWALL_DONE],
                cwd=APP_DIR,
                env=dict(os.environ, HOME="/root", **caller),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,   # survive the agent and this request
            )
        except Exception as exc:  # noqa: BLE001
            return self._send(500, {"error": "failed to start the firewall update", "detail": str(exc)})
        return self._send(200, {"status": "started"})

    def _do_firewall_log(self):
        """The current (or last) firewall run: {log, finished, returncode}."""
        return self._send(200, firewall_status())

    def _do_squid(self):
        """GET: the default whitelist and the proxy already set up, if any.
        POST: run squid/setup.sh with the dashboard's settings — started here,
        followed through /squid-log. The password reaches the script in its
        environment only; it is never written to disk except as the bcrypt
        hash in /etc/squid/passwd, and never logged."""
        if not os.path.isfile(SQUID_SCRIPT):
            return self._send(500, {"error": "squid/setup.sh not found"})
        if self.command == "GET":
            # The repo's whitelist.txt is a template for the first setup; once
            # Squid is set up, the list in effect is what gets edited. (A setup
            # with the whitelist off leaves an earlier list in place, so it
            # comes back when the whitelist is turned on again.)
            current = squid_current()
            live = read_file(SQUID_WHITELIST_LIVE) if current else ""
            domains = squid_whitelist_domains(live)
            return self._send(200, {
                "whitelist": domains or squid_whitelist_domains(read_file(SQUID_WHITELIST)),
                "whitelistSource": "upplet" if domains else "template",
                "current": current,
                "nginx": nginx_in_use() or None,     # set: Setup Squid is refused here
            })

        try:
            req = json.loads(self._body().decode("utf-8", "replace") or "{}")
        except ValueError:
            return self._send(400, {"error": "body must be JSON"})
        keep = req.get("keep_credentials") is True
        current_setup = squid_current()
        if keep and not current_setup:
            return self._send(409, {"error": "Squid is not set up here — there are no credentials to keep"})
        user = str(req.get("user") or "").strip() if not keep else (current_setup.get("user") or "")
        password = str(req.get("password") or "") if not keep else "kept"
        use_whitelist = bool(req.get("whitelist"))
        try:
            port = int(req.get("port"))
        except (TypeError, ValueError):
            port = 0
        if not SQUID_USER_RE.match(user):
            return self._send(400, {"error": "the username may have letters, digits, '.', '_' and '-' only"})
        if not password or len(password) > 128 or any(c in password for c in "\r\n\0"):
            return self._send(400, {"error": "a password of 1 to 128 characters, on one line, is required"})
        if not 1024 <= port <= 65535 or port == PORT:
            return self._send(400, {"error": "pick a port from 1024 to 65535, other than the agent's %d" % PORT})
        domains = []
        if use_whitelist:
            raw = req.get("domains")
            if not isinstance(raw, list) or not raw or len(raw) > 5000:
                return self._send(400, {"error": "the whitelist needs at least one domain"})
            domains = squid_whitelist_domains("\n".join(str(d) for d in raw))
            bad = [d for d in domains if len(d) > 253 or not SQUID_DOMAIN_RE.match(d)]
            if bad:
                return self._send(400, {"error": "not a domain name: %s" % bad[0]})
        nginx = nginx_in_use()
        if nginx:
            return self._send(409, {"error": "%s on this upplet — Squid runs on an upplet without Nginx" % nginx})
        holder = listening_ports().get(port)
        if holder and holder != "squid":
            return self._send(409, {"error": "port %d is in use by %s" % (port, holder)})
        current = squid_status()
        if current and not current.get("finished"):
            return self._send(409, {"error": "Squid is being set up already"})

        os.makedirs(DATA_DIR, exist_ok=True)
        extra = {"PROXY_PORT": str(port), "SQUID_MANAGED": "1",
                 "SQUID_WHITELIST": "1" if use_whitelist else "0"}
        if keep:
            extra["SQUID_KEEP_PASSWD"] = "1"
        else:
            extra.update({"PROXY_USER": user, "PROXY_PASS": password})
        request = ""
        if use_whitelist:
            request = os.path.join(TMP_DIR, "squid_whitelist_%s.txt" % datetime.now().strftime("%d_%m_%y_%H_%M_%S"))
            fd = os.open(request, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write("\n".join(domains) + "\n")
            extra["WHITELIST_FILE"] = request
        with open(SQUID_LOG, "w") as fh:
            fh.write("[p5agent] setting up Squid on port %d for user %s%s%s\n"
                     % (port, user, " (credentials kept)" if keep else "",
                        " with %d whitelisted domain(s)" % len(domains) if use_whitelist else ", no whitelist"))
        with open(SQUID_STATUS, "w") as fh:
            json.dump({"started_at": int(time.time()), "port": port, "user": user}, fh)
        runner = ('exec >>"$1" 2>&1 </dev/null; bash "$2"; rc=$?; '
                  '[ -n "$3" ] && rm -f "$3"; printf "\\n%s%s\\n" "$4" "$rc"')
        try:
            subprocess.Popen(
                ["bash", "-c", runner, "p5agent-squid", SQUID_LOG, SQUID_SCRIPT, request, SQUID_DONE],
                cwd=os.path.dirname(SQUID_SCRIPT),
                env=dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive", **extra),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,   # survive the agent and this request
            )
        except Exception as exc:  # noqa: BLE001
            if request:
                try:
                    os.remove(request)
                except OSError:
                    pass
            return self._send(500, {"error": "failed to start the Squid setup", "detail": str(exc)})
        return self._send(200, {"status": "started"})

    def _do_utilities(self):
        """What is set up here besides apps — for the dashboard's upplet menu:
        Squid (as squid/setup.sh left it) and the apps behind Nginx."""
        try:
            apps = json.loads(read_file(INSTALLED_APPS) or "[]")
        except ValueError:
            apps = []
        wired = [str(a.get("name")) for a in apps if isinstance(a, dict) and a.get("public-port")]
        return self._send(200, {"squid": squid_current(), "nginx": wired})

    def _do_squid_log(self):
        """The current (or last) Squid setup: {log, finished, returncode}."""
        return self._send(200, squid_status())

    def _do_certs_log(self):
        """The current (or last) certificate run: its domain, its output so far,
        whether it is still going and what it exited with."""
        status = certs_status()
        if not status:
            return self._send(200, {})
        return self._send(200, status)


class Server(ThreadingHTTPServer):
    """Threaded HTTP(S) server.

    Crucially, the listening socket is NOT TLS-wrapped. Instead each accepted
    connection gets a timeout and (when TLS is enabled) its handshake is done in
    get_request under that timeout. Wrapping the listening socket would run the
    TLS handshake inside accept() on the single accept loop, so a client that
    finishes the TCP connection but stalls the handshake — a laptop sleeping
    mid-request, a plain-HTTP probe to the TLS port, a port scan — would block
    the loop forever and wedge the whole agent. Here a stalled/garbage handshake
    just times out, raising OSError, which serve_forever swallows; the loop keeps
    accepting.
    """

    daemon_threads = True
    ssl_ctx = None
    conn_timeout = 30  # seconds; bounds the handshake and request/response I/O

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(self.conn_timeout)
        if self.ssl_ctx is not None:
            sock = self.ssl_ctx.wrap_socket(sock, server_side=True)
        return sock, addr


def main():
    if not TOKEN:
        sys.stderr.write(
            "[p5agent] WARNING: P5AGENT_TOKEN is empty — every privileged "
            "request will be rejected with 401.\n"
        )
    server = Server((BIND, PORT), Handler)

    scheme = "http"
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        server.ssl_ctx = ctx
        scheme = "https"
    else:
        sys.stderr.write(
            "[p5agent] WARNING: no TLS cert/key configured — serving PLAIN HTTP. "
            "Set P5AGENT_TLS_CERT and P5AGENT_TLS_KEY to enable HTTPS.\n"
        )

    sys.stderr.write(
        "[p5agent] listening on %s://%s:%d  (app dir: %s)\n"
        % (scheme, BIND, PORT, APP_DIR)
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()


if __name__ == "__main__":
    main()
