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
                      and its dependencies; returns 200 once the job is launched
    GET  /progress    current install log (setup.log); empty when nothing runs
    GET  /supported   the supported_deps.json registry
    GET  /apps        the installed_apps.json list

All endpoints except `/` require the shared secret token. `/command` is the only
one restricted by source IP.

Configuration is read from the environment (see /etc/p5agent.env):

    P5AGENT_TOKEN     shared secret required on every privileged request
    P5AGENT_ALLOW_IP  client IP allowed to call /command (default: 127.0.0.1)
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
import ssl
import subprocess
import sys
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

TOKEN = os.environ.get("P5AGENT_TOKEN", "")
# The agent operates on its own checkout, so the install dir/name is never
# duplicated here — it is derived at runtime from this file's location (which
# install.sh decides via PROJECT). update.sh lives alongside this file.
APP_DIR = os.path.dirname(os.path.realpath(__file__))
APP_NAME = os.path.basename(APP_DIR)
ALLOW_IP = os.environ.get("P5AGENT_ALLOW_IP", "127.0.0.1")
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
SUPPORTED_DEPS = os.path.join(APP_DIR, "supported_deps.json")
SETUP_LOG = os.path.join(DATA_DIR, "setup.log")
INSTALLED_APPS = os.path.join(DATA_DIR, "installed_apps.json")


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
        if ip == ALLOW_IP:
            return True
        if ALLOW_IP in ("127.0.0.1", "localhost") and ip in ("127.0.0.1", "::1"):
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
              "/supported", "/apps")

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
            return self._send(403, {"error": "forbidden",
                                    "detail": "/command is restricted to %s" % ALLOW_IP})
        try:
            return {
                "/update": self._do_update,
                "/command": self._do_command,
                "/install-app": self._do_install_app,
                "/progress": self._do_progress,
                "/supported": self._do_supported,
                "/apps": self._do_apps,
            }[path]()
        except Exception as exc:  # noqa: BLE001 - never leak a traceback as 500 HTML
            return self._send(500, {"error": "internal error", "detail": str(exc)})

    # ---- operations ------------------------------------------------------
    def _do_update(self):
        """1) git pull this checkout (best effort), 2) run its update.sh.

        The git pull is advisory: update.sh re-fetches and hard-resets the repo
        itself, so a pull hiccup (e.g. no upstream tracking) must not fail the
        request. The overall result reflects update.sh, the authoritative step.
        """
        parts = []

        if os.path.isdir(os.path.join(APP_DIR, ".git")):
            subprocess.run(
                ["git", "config", "--global", "--add", "safe.directory", APP_DIR],
                check=False,
            )
            rc, out = run(["git", "-C", APP_DIR, "pull", "--ff-only"])
            parts.append("$ git -C %s pull --ff-only\n%s" % (APP_DIR, out))
            if rc != 0:
                # Pull was refused (dirty working tree or diverged history).
                # Reset to HEAD so the tree is clean for update.sh to reconcile.
                rc, out = run(["git", "-C", APP_DIR, "reset", "--hard", "HEAD"])
                parts.append(
                    "[p5agent] pull failed; resetting to HEAD\n"
                    "$ git -C %s reset --hard HEAD\n%s" % (APP_DIR, out)
                )
        else:
            parts.append("[p5agent] %s is not a git checkout; skipping git pull" % APP_DIR)

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
        """Launch install_app.sh in the background and return immediately."""
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

        ts = datetime.now().strftime("%d_%m_%y_%H_%M_%S")
        req_path = os.path.join(TMP_DIR, "install_request_%s.json" % ts)
        with open(req_path, "w") as fh:
            json.dump(req, fh)

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
            return self._send(500, {"error": "failed to launch installer",
                                    "detail": str(exc)})
        return self._send(200, {"status": "started"})

    def _do_progress(self):
        """Return the live install log; empty when nothing is installing."""
        return self._send_raw(200, read_file(SETUP_LOG), "text/plain; charset=utf-8")

    def _do_supported(self):
        """Return the supported dependencies registry."""
        return self._send_raw(200, read_file(SUPPORTED_DEPS) or "[]", "application/json")

    def _do_apps(self):
        """Return the installed apps list."""
        return self._send_raw(200, read_file(INSTALLED_APPS) or "[]", "application/json")


def main():
    if not TOKEN:
        sys.stderr.write(
            "[p5agent] WARNING: P5AGENT_TOKEN is empty — every privileged "
            "request will be rejected with 401.\n"
        )
    server = ThreadingHTTPServer((BIND, PORT), Handler)

    scheme = "http"
    if TLS_CERT and TLS_KEY:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=TLS_CERT, keyfile=TLS_KEY)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
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
