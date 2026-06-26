# p5agent

A small remote management agent for a droplet. It runs as a root systemd
service and exposes an HTTPS control plane that lets an authorized caller
update the deployed app and run commands on the box.

It uses the Python standard library only — Ubuntu ships `python3`, so there is
nothing to install. The idle process uses roughly 12–18 MB of RAM.

## Endpoints

| Method     | Path       | Auth | Purpose |
|------------|------------|------|---------|
| GET        | `/`        | no   | Liveness probe. Returns `{"status":"ok"}`. |
| GET / POST | `/update`  | yes  | `git pull` the app repo, then run its `update.sh`. |
| GET / POST | `/command` | yes  | Save the request body to `/tmp/command_<dd_mm_yy_hh_mm_ss>.sh`, make it executable, and run it as **root**. Returns the combined output, exit code, and script path. |

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
timestamped name, given `0700` permissions, and executed as root.

```bash
curl -X POST "https://<ip>:5005/command" \
     -H "Authorization: Bearer $TOKEN" \
     --data-binary $'systemctl restart myapp\nsystemctl is-active myapp'
```

## Authorization

Every privileged request must carry the shared secret token in the
`Authorization` header (never in the URL, so it stays out of logs and history):

```
Authorization: Bearer <TOKEN>
```

The token is compared in constant time. If no token is configured, the agent
rejects every privileged request with `401`.

## Configuration

The agent reads its configuration from the environment (`install.sh` writes it
to `/etc/p5agent.env`, mode 600):

| Variable | Default | Meaning |
|----------|---------|---------|
| `P5AGENT_TOKEN` | *(empty)* | Shared secret required on privileged endpoints. |
| `P5AGENT_PORT` | `5005` | Listen port. |
| `P5AGENT_BIND` | `0.0.0.0` | Listen address. |
| `P5AGENT_TMP_DIR` | `/tmp` | Where `/command` scripts are written. |
| `P5AGENT_TIMEOUT` | `1800` | Max seconds any command may run. |
| `P5AGENT_TLS_CERT` | *(empty)* | TLS certificate (PEM). Enables HTTPS. |
| `P5AGENT_TLS_KEY` | *(empty)* | TLS private key (PEM). Enables HTTPS. |

When `P5AGENT_TLS_CERT` and `P5AGENT_TLS_KEY` point to PEM files, the agent
serves HTTPS (TLS 1.2+).

## Install

Run as root from a checkout of this repo:

```bash
P5AGENT_TOKEN=<secret> \
P5AGENT_ALLOW_IP=<dashboard_ip> \
P5AGENT_TLS_CERT=/opt/p5agent/certs/cert.pem \
P5AGENT_TLS_KEY=/opt/p5agent/certs/key.pem \
bash install.sh
```

Only `P5AGENT_TOKEN` is required. The script copies the agent to `/opt/p5agent`,
writes `/etc/p5agent.env`, installs and starts the `p5agent` systemd service,
and adds a UFW rule that allows the port only from `P5AGENT_ALLOW_IP`. If
`P5AGENT_ALLOW_IP` is omitted it defaults to `127.0.0.1` (localhost only — reach
the agent via an SSH tunnel). It aborts if `P5AGENT_TOKEN` is missing or if UFW
is unavailable.

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
- Restrict the port to the dashboard's IP (`P5AGENT_ALLOW_IP`) so the agent is
  not reachable from the open internet.
