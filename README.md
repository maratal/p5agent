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
3. **Runs the setup script** — `setup.sh` or `install.sh` from the repo, if
   present.
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
| `supported_deps.json` | repo | Registry of installable dependencies: `name`, `display-name`, `icon-url`, and a `package-manager` (+ optional `package`) or `install-cmd`. Served by `/supported`. |
| `setup.log` | data dir | Live install log; served by `/progress`. |
| `installed_apps.json` | data dir | Installed apps (`name`, `product-name`, `path`, `port`, `dependencies`); served by `/apps`. |

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
