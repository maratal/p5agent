#!/usr/bin/env python3
"""
p5agent — minimal remote management agent.

A tiny HTTP control plane for a deployed droplet, written with the Python
standard library only (no pip installs; Ubuntu ships python3). It runs as a
root systemd service on port 5005 and exposes:

    GET  /            liveness probe (no token required)
    *    /update      git-pull this checkout, then run update.sh
    *    /command     save the request to /tmp/command_<dd_mm_yy_hh_mm_ss>.sh and
                      run it as root — restricted to P5AGENT_ALLOW_IP
    *    /install-app  spawn install_app.sh in the background to install an app
                      and its dependencies; returns 200 once the job is launched.
                      One install runs at a time: the request is recorded in
                      pending_install.json the moment it is accepted, and a
                      second request is refused with 409 while one is running
    GET  /progress    current install status as JSON:
                      { "app", "started_at", "log"?, "completed"? } — {} when idle
    GET  /supported   the supported_deps.json registry
    GET  /apps        the installed_apps.json list

All endpoints except `/` require the shared secret token. `/command` is the only
one restricted by source IP.

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
import json
import os
import re
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
SETUP_LOG = os.path.join(DATA_DIR, "setup.log")
INSTALLED_APPS = os.path.join(DATA_DIR, "installed_apps.json")
# The install lock/status record, written the moment /install-app accepts a
# request: {"app": <name>, "started_at": <unix ts>}. While it exists no second
# install is accepted. install_app.sh removes it right after logging the
# completion marker; a failed install is cleared here (stall rule) or by fail().
PENDING_INSTALL = os.path.join(DATA_DIR, "pending_install.json")
INSTALL_STALL_SECS = 1800  # no log activity for 30 min → the install failed


def run(cmd, cwd=None):
    """Run a command, capturing combined stdout+stderr. Returns (rc, output)."""
    env = dict(os.environ, HOME="/root", DEBIAN_FRONTEND="noninteractive")
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


def certs_status():
    """What the last certificate run is doing, or {} when there has never been
    one. The log carries the answer: the runner appends a completion marker as
    its final act, so its absence means the job is still going."""
    raw = read_file(CERTS_STATUS)
    if not raw:
        return {}
    try:
        status = json.loads(raw)
    except ValueError:
        return {}
    log = read_file(CERTS_LOG) or ""
    status["log"] = log
    marker = log.rfind(CERTS_DONE)
    if marker == -1:
        status["finished"] = False
        status["returncode"] = None
    else:
        status["finished"] = True
        tail = log[marker + len(CERTS_DONE):].strip().split()
        try:
            status["returncode"] = int(tail[0]) if tail else None
        except ValueError:
            status["returncode"] = None
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


def app_name_from_request(req):
    """The app's install name: explicit "name", else the repo basename."""
    name = (req.get("name") or "").strip()
    if name:
        return name
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
              "/supported", "/apps", "/certs", "/certs-log")

    def _dispatch(self):
        path = self._path()
        if path == "/":
            return self._send(200, {"status": "ok", "service": "p5agent"})
        if path not in self.ROUTES:
            return self._send(404, {"error": "not found", "path": path})
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        # /command is the only endpoint locked to the allowed source IP.
        if path == "/command" and not self._ip_allowed():
            def _mask_ip(ip):
                return ip[:2] + "*" * max(0, len(ip) - 4) + ip[-2:] if len(ip) > 4 else ip
            return self._send(403, {"error": "forbidden",
                                    "detail": "/command is restricted to %s" % ", ".join(_mask_ip(ip) for ip in sorted(ALLOW_IP))})
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

        if not text.startswith("#!"):
            text = "#!/usr/bin/env bash\n" + text

        path = unique_script_path()
        with open(path, "w") as fh:
            fh.write(text)
        os.chmod(path, 0o700)  # grant execute permission (owner: root)

        rc, out = run([path], cwd=TMP_DIR)
        status = 200 if rc == 0 else 500
        return self._send(status, {"returncode": rc, "output": out, "script": path})

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
        if not (req.get("repo") or "").strip():
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
        """Return the installed apps list."""
        return self._send_raw(200, read_file(INSTALLED_APPS) or "[]", "application/json")

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
