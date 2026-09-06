# p5agent

A small remote management agent for a droplet. It runs as a root systemd
service and exposes an HTTPS control plane that lets an authorized caller update
the agent, run commands on the box, and install an app from a git repo.

It uses the Python standard library only — Ubuntu ships `python3`, so there is
nothing to install. The idle process uses roughly 12–18 MB of RAM.

## Endpoints

| Method     | Path           | Auth | Source IP | Purpose |
|------------|----------------|------|-----------|---------|
| GET        | `/`            | no   | any       | Liveness probe. Returns `{"status":"ok"}`. |
| GET / POST | `/update`      | yes  | any       | `git pull` this checkout, then run its `update.sh`. |
| GET / POST | `/command`     | yes  | allowed IP | Save the request body to `/tmp/command_<dd_mm_yy_hh_mm_ss>.sh`, make it executable, and run it as **root**. |
| POST       | `/install-app` | yes  | any       | Launch `install_app.sh` in the background to install an app + dependencies. Returns once the job is spawned. |
| GET        | `/progress`    | yes  | any       | The live install log (`setup.log`). Empty when nothing is installing. Poll it (~every 5s) to follow an install. |
| GET        | `/supported`   | yes  | any       | The `supported_deps.json` registry of installable dependencies. |
| GET        | `/apps`        | yes  | any       | The `installed_apps.json` list of installed apps. |
| POST       | `/certs`       | yes  | any       | Start a Let's Encrypt run for a domain: obtain or renew, point every installed app at it, restart them. Returns once the job is spawned. |
| GET        | `/certs-log`   | yes  | any       | The current (or last) certificate run: `{domain, log, finished, returncode}`. Poll it (~every 2s) to follow one. |

### `/update`

```bash
curl -X POST "https://<ip>:5005/update" -H "Authorization: Bearer $TOKEN"
```

Runs `git -C /opt/p5agent pull --ff-only` (if the pull is refused, the repo is
reset to HEAD), then `bash /opt/p5agent/update.sh`. The response status comes
from `update.sh`'s exit code (200 on success, 500 on failure).

### `/command`

The command is read from the request body. If it does not start with a shebang,
`#!/usr/bin/env bash` is prepended. It is written to the tmp directory with a
timestamped name, given `0700` permissions, and executed as root. This endpoint
is restricted to `P5AGENT_ALLOW_IP` (returns `403` from any other source IP).

```bash
curl -X POST "https://<ip>:5005/command" \
     -H "Authorization: Bearer $TOKEN" \
     --data-binary $'systemctl restart myapp\nsystemctl is-active myapp'
```

### `/certs`

Takes `{"domain": "chat.example.com"}` and launches `certs.sh domain <domain>`,
which obtains a Let's Encrypt certificate for that name (or renews the existing
one if it is due), writes `TLS_CERT_PATH` and `TLS_KEY_PATH` into every installed
app's `/etc/<name>.env`, and restarts each service.

A job, not a request. Issuing a first certificate installs certbot before it does
anything else, which takes minutes — longer than a caller will hold a connection
open. Holding it open cost one run its result: the socket was closed underneath a
job that had already succeeded, so the work landed and the reply did not. `/certs`
returns `{"status":"started"}` and `/certs-log` carries the transcript, exactly as
`/install-app` and `/progress` do for an install. A second run is refused with
`409` while one is going.

The domain must be a plain hostname; anything else is rejected with `400` before
a root script is started. The name is also checked to resolve to this droplet
first, because Let's Encrypt rate-limits failed attempts and a typo should not
spend one.

The certificates are read by each app's own user, granted through a shared
`certaccess` group rather than by handing `/etc/letsencrypt` to one user —
a host can run more than one TLS service, and a per-user `chgrp` takes the
previous one's access away. ChatServer's standalone `install.sh` names the same
group, so the two provisioning paths can share a droplet.

Renewal is certbot's own systemd timer. `certs.sh` installs a deploy hook at
`/etc/letsencrypt/renewal-hooks/deploy/p5agent-restart-apps.sh` that restarts
every installed app, so a renewed certificate actually reaches them; the hook
reads `installed_apps.json` at run time, so apps installed later are covered
without rewriting it.

```bash
curl -X POST "https://<ip>:5005/certs" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"domain":"chat.example.com"}'
```

### `/install-app`

Installs an app from a git repo plus a list of dependencies. It does **not**
accept raw scripts — only a repo (with a key if private) and named dependencies
drawn from `supported_deps.json`. The agent itself does no installing: it writes
the request to a temp file and launches `install_app.sh` **detached**, returning
`{"status":"started"}` as soon as the job is spawned. Progress is followed via
`/progress`.

```bash
curl -X POST "https://<ip>:5005/install-app" \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "repo": "https://github.com/user/app.git",
       "key": "<token-for-private-repo>",
       "branch": "main",
       "name": "app",
       "product-name": "My App",
       "app-type": "swift",
       "app-cmd": "App serve --env production",
       "port": "8080",
       "dependencies": ["postgresql", "swift 6"]
     }'
```

Only `repo` is required. `install_app.sh` then, logging every step to
`setup.log` with per-line timestamps:

1. **Installs dependencies.** Each name is looked up in `supported_deps.json`
   and installed via its `package-manager` (apt) or `install-cmd`. No
   dependencies → nothing installed. Each is logged as
   `<name> installation began … <name> installation completed`.
2. **Clones the repo** into `/opt/<name>` (the key is embedded for a private
   clone and never echoed back).
3. **Sets the app up.** If the repo ships a `setup.sh` or `install.sh`, that is
   run (it builds the app and configures its own service). Otherwise the generic
   path: it creates a dedicated non-root user to run the app, wires its database
   (`wire_<db>.sh`), generates a self-signed TLS cert (written to
   `/etc/<name>.env`), runs the per-type builder `install_<app-type>_app.sh`
   (e.g. `install_swift_app.sh` → `swift build -c release`), and creates a
   systemd service from the request's `app-cmd` — running as that user with
   `AmbientCapabilities=CAP_NET_BIND_SERVICE` so it can bind 443. (`app-type`
   selects the builder.)
4. **Records the app** in `installed_apps.json` and writes `Setup completed.`,
   then moves `setup.log` to `<tmp>/p5agent_setup_<timestamp>.log` (so `/progress`
   goes empty — the signal that nothing is running).

A version may be appended after a space (e.g. `swift 6`, `ruby 3.4.5`). Most
dependencies install via apt; `swift` is fetched from swift.org. The full,
current list comes from `/supported`.

**Progress & concurrency.** While an install runs, `setup.log` is updated and
served by `/progress`. A second `/install-app` while one is active is a no-op.
If `setup.log` is stale (untouched > 10 min), the next run waits 30s and, if
still unchanged, treats the previous install as failed — archiving it to
`<tmp>/p5agent_setup_<timestamp>-failed.log` and clearing `setup.log`.

## Authorization

Every request except `/` must carry the shared secret token in the
`Authorization` header (never in the URL, so it stays out of logs and history):

```
Authorization: Bearer <TOKEN>
```

The token is compared in constant time. If no token is configured, the agent
rejects every privileged request with `401`. `/command` additionally requires
the request to originate from `P5AGENT_ALLOW_IP`.

## Configuration

The agent reads its configuration from the environment (`install.sh` writes it
to `/etc/p5agent.env`, mode 600):

| Variable | Default | Meaning |
|----------|---------|---------|
| `P5AGENT_TOKEN` | *(empty)* | Shared secret required on privileged endpoints. |
| `P5AGENT_ALLOW_IP` | `127.0.0.1` | Client IP allowed to call `/command`. |
| `P5AGENT_PORT` | `5005` | Listen port. |
| `P5AGENT_BIND` | `0.0.0.0` | Listen address. |
| `P5AGENT_DATA_DIR` | `/var/lib/p5agent` | Runtime state: `setup.log`, `installed_apps.json`. |
| `P5AGENT_TMP_DIR` | `/tmp` | Where `/command` scripts and archived install logs go. |
| `P5AGENT_TIMEOUT` | `1800` | Max seconds any command may run. |
| `P5AGENT_TLS_CERT` | *(empty)* | TLS certificate (PEM). If unset, install.sh generates a self-signed one. |
| `P5AGENT_TLS_KEY` | *(empty)* | TLS private key (PEM). If unset, install.sh generates a self-signed one. |

The agent always serves HTTPS (TLS 1.2+). Point `P5AGENT_TLS_CERT`/`KEY` at your
own PEM files, or leave them unset and `install.sh` generates a self-signed
certificate (for the droplet's IP) under `/opt/p5agent/certs`.

## Files

| File | Where | Purpose |
|------|-------|---------|
| `agent.py` | repo | The HTTP agent. |
| `update.sh` | repo | Restarts the service to apply a pulled update. |
| `install_app.sh` | repo | Backgrounded app installer (deps + clone + setup). |
| `install_swift.sh` | repo | Dedicated Swift installer; referenced by the `swift` entry's `install-cmd`. |
| `app_support/install_<type>_app.sh` | repo | Standard minimal builder per app type (swift, nodejs, python, ruby, go, php, java), used when a cloned repo has no `setup.sh`/`install.sh`. It builds the app and creates its systemd service. |
| `app_support/wire_<dbtype>.sh` | repo | Per-database-type wiring (postgresql, mysql, mariadb, sqlite): creates the app's database/user and writes `/etc/<name>.env` (loaded by the service). Used for repos with no installer of their own. |
| `supported_deps.json` | repo | Registry of installable dependencies: `name`, `display-name`, `icon-url`, and a `package-manager` (+ optional `package`) or `install-cmd`. Served by `/supported`. |
| `setup.log` | data dir | Live install log; served by `/progress`. |
| `installed_apps.json` | data dir | Installed apps (`name`, `product-name`, `path`, `port`, `dependencies`); served by `/apps`. |
| `p5agent-restart-apps.sh` | `/etc/letsencrypt/renewal-hooks/deploy` | Restarts every installed app after a certificate renewal; written by `certs.sh`. |
| `certs.log` | data dir | The running (or last) certificate run's output; served by `/certs-log`. |
| `certs_status.json` | data dir | That run's domain and start time. Its log's final marker line is what "finished" means. |

### Certificates

`certs.sh` is the only place the agent makes a certificate — `install.sh` uses it
for the agent's own listener, `install_app.sh` for each installed app, and
`/certs` for the Let's Encrypt certificate that replaces those once a domain
points at the droplet:

```bash
certs.sh self-signed --cert <path> --key <path> [--cn <name>] [--days <n>] \
                     [--env <file>] [--owner <user>]
certs.sh domain <domain>
```

Both modes print `TLS_CERT_PATH=` and `TLS_KEY_PATH=` on stdout and everything
else on stderr, so a caller can `eval` the result rather than reconstructing the
paths. `--env` rewrites the pair in an env file instead of appending a second
one. An existing self-signed pair is reused, so re-installing an app does not
throw away a certificate a domain is already using.

To add a new installable dependency, add an entry to `supported_deps.json` —
there is no per-package code. An entry either names a `package-manager` (`apt`,
with an optional `package` if it differs from `name`) or carries an
`install-cmd`. An `install-cmd` is one of:

- an **inline shell one-liner**, with `{version}` substituted from the request; or
- a **local script** — any value ending in `.sh` is resolved against the repo
  and run with the requested version as its argument (e.g. Swift uses
  `install_swift.sh`, which receives `6` or `6.0.3`).

### Where things live

The layout follows the Filesystem Hierarchy Standard (FHS), the standard Ubuntu
convention for where a service keeps its files:

| Path | FHS role | Used for |
|------|----------|----------|
| `/opt/p5agent` | add-on application software | the agent's code (this checkout) |
| `/etc/p5agent.env` | host configuration | the agent's config, mode 600 |
| `/var/lib/p5agent` | persistent application state | `setup.log` and `installed_apps.json` |
| `/tmp` | temporary files | archived install logs (`p5agent_setup_<ts>.log`) and `/command` scripts |
| `/opt/<name>` | add-on application software | installed apps |

## Install

Run as root from a checkout of this repo:

```bash
P5AGENT_TOKEN=<secret> P5AGENT_ALLOW_IP=<dashboard_ip> bash install.sh
```

Only `P5AGENT_TOKEN` is required. The script ensures `git` and `openssl` are
installed, copies the agent to `/opt/p5agent`, generates a self-signed TLS cert
(unless one is provided), writes `/etc/p5agent.env`, installs and starts the
`p5agent` systemd service, and configures the firewall.

The firewall (UFW) is reset to **deny all incoming by default**, with these ways
in:

- SSH (`22`) — open to all, so admins and the DigitalOcean console can always
  reach the box;
- the agent port (`5005`) — open to all hosts (per-endpoint source-IP
  enforcement is done inside the agent, only `/command` is IP-locked);
- HTTP (`80`) — for the ACME http-01 challenge. Nothing listens on it between
  challenges; it stays open because certbot's unattended renewal needs it too,
  and a port opened only while someone is watching means a certificate that
  expires when nobody is;
- a port per installed app — re-opened on every run from the `port` of each
  entry in `installed_apps.json`.

Every other port is closed. (`P5AGENT_ALLOW_IP` only governs who may call `/command`)

```bash
systemctl status p5agent     # service state
journalctl -u p5agent -f     # live logs
```

## Security

The agent runs arbitrary commands as root, so the token and the network
boundary are what protect it:

- Serve over HTTPS (`P5AGENT_TLS_CERT` / `P5AGENT_TLS_KEY`) so the token and
  commands are never sent in cleartext.
- Keep `P5AGENT_TOKEN` long and secret; it is the entire access control.
- Set `P5AGENT_ALLOW_IP` to the dashboard's IP so `/command` (raw root commands)
  is reachable only from there; it defaults to localhost.
