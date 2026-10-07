# p5agent

A small remote management agent for a droplet. It runs as a root systemd
service and exposes an HTTPS control plane that lets an authorized caller update
the agent, run commands on the box, and install an app from a git repo.

It uses the Python standard library only — Ubuntu ships `python3`, so there is
nothing to install. The idle process uses roughly 12–18 MB of RAM.

## Endpoints

| Method     | Path           | Auth | Source IP  | Purpose |
|------------|----------------|------|------------|---------|
| GET        | `/`            | no   | any        | Liveness probe. Returns `{"status":"ok"}`. |
| GET / POST | `/update`      | yes  | any        | `git pull` this checkout, then run its `update.sh`. |
| GET / POST | `/command`     | yes  | restricted | Save the request body to `/tmp/command_<dd_mm_yy_hh_mm_ss>.sh`, make it executable, and run it as **root**. |
| POST       | `/install-app` | yes  | any        | Launch `install_app.sh` in the background to install an app + dependencies. Returns once the job is spawned. |
| POST       | `/install-util` | yes | any        | Install a utility (`squid`, `nginx`): `install_util.sh` runs `utilities/<name>/<name>.sh install` in the background, through the same lock, `/progress` and `setup.log` as an app install. |
| GET        | `/progress`    | yes  | any        | The current install — app or utility: `{app, kind, started_at, completed?}`. Empty when nothing is installing. Poll it (~every 5s) to follow an install. |
| GET        | `/setup-log`   | yes  | any        | The current (or last) install's log, only what the caller lacks: `?from=<lines it has>&id=<log id>` → `{id, from, next, lines, installing}`. A different `id` (a new install) starts over from 0. |
| GET        | `/supported`   | yes  | any        | The `supported_deps.json` registry of installable dependencies. |
| GET        | `/apps`        | yes  | any        | The `installed_apps.json` list of installed apps, each with `service` (its `systemctl is-active` state) `backup` (whether `<apps dir>/<name>_backup` exists) and `database` (its type — from its dependencies, else `/etc/<name>.env`: its `DATABASE_URL`, `DATABASE_PATH`, or `DATABASE_NAME` with the type told by `DATABASE_PORT` or the database server installed — or empty). |
| POST       | `/app`         | yes  | restricted | Run an operation on one installed app through `app_ops.sh`: `start`, `stop`, `backup`, `update`, `rollback` or `uninstall`. Answers when it is done — except `update`, which runs in the background. |
| GET        | `/app-log`     | yes  | any        | The current (or last) app update: `{name, started_at, log, finished, returncode}`. Poll it (~every 2s) to follow one. |
| POST       | `/certs`       | yes  | any        | Start a Let's Encrypt run for one domain or several: obtain or renew each, point the apps at it, restart them. Returns once the job is spawned. |
| GET        | `/certs-log`   | yes  | any        | The current (or last) certificate run: `{domain, log, finished, returncode}`. Poll it (~every 2s) to follow one. |
| GET        | `/info`        | yes  | any        | The upplet itself: OS, kernel, arch, uptime, memory, disk, this agent's commit, installed versions of the supported dependencies, and the firewall's rules. |
| GET / POST | `/copy-inventory` | yes | any      | Copy's calculation stage, on the upplet to be copied: disk in use, each app's database size and a guess at its archive (nothing is dumped), and the size of its data folders. A job: POST starts it, GET follows it. |
| POST       | `/copy-key`    | yes  | any        | Let another upplet copy this one: `{key, peer}` — kept in memory only, gone 5 minutes after its last use. `{revoke: true}` ends it. |
| POST       | `/copy-start`  | yes  | any        | On the new upplet: copy `{source, key, …}` here — an install (lock, `/progress`, `setup.log`) named `copy`. |
| GET / POST | `/copy/…`      | copy key | the granted peer | What the new upplet's agent fetches from the copied one: `manifest`, `file`, `done`. |

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

### `/app`

Takes `{"op": "<op>", "name": "<app>"}` (plus `"drop_db": true` for an
uninstall that should also delete the app's database) and runs
`app_ops.sh <op> <name> [--drop-db]`. Responds `{returncode, output}` — 200 on
success, 500 on failure — or 409 while that app is being installed or updated.
`update` instead starts in the background and answers `{"status": "started"}`
at once (409 while another update is running); follow it with `/app-log`. Like
`/command`, it is restricted to `P5AGENT_ALLOW_IP` (`403` from any other source IP).

| Op | What it does |
|----|--------------|
| `start` / `stop` | `systemctl start <name>` / `systemctl stop <name>`. |
| `update` | Backs the app up (as `backup`), then updates it. When the app's folder has its own `update.sh`, that runs (with `P5AGENT=1`) and does the whole job. Otherwise the standard update: the new code — `git fetch` + reset of the app's branch (a private repo's token is in the remote URL the install cloned with), or a fresh copy of a demo — then the install's build again: the repo's `setup.sh`/`install.sh`, else `app_support/install_<type>_app.sh`. A failure leaves the backup for Rollback Update. Ends by asking the app's own `/api/info` what is running now and logging its version. |
| `backup` | Copies `<apps dir>/<name>` to `<apps dir>/<name>_backup`. An existing backup is first renamed to `<name>_backup_deleted` and deleted only once the new copy succeeds; if the copy fails, it is renamed back. The dashboard runs it before every update. |
| `rollback` | Needs `<name>_backup`: stops the app, deletes `<name>`, renames `<name>_backup` to `<name>` and starts it, then logs the version its `/api/info` reports. |
| `uninstall` | Stops and removes the service, the app's folder and all its `<name>_backup*` folders (every deleted folder is logged), its sudoers file, the user, its firewall port (unless another app, SSH or the agent uses it) and its `installed_apps.json` entry. The database and `/etc/<name>.env` are kept — so a reinstall picks them up — unless `drop_db` is set. |

```bash
curl -X POST "https://<ip>:5005/app" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" -d '{"op": "stop", "name": "chat"}'
```

### `/certs`

Takes `{"domain": "chat.example.com"}` and launches `certs.sh domain <domain>`,
which obtains a Let's Encrypt certificate for that name (or renews the existing
one if it is due), writes `TLS_CERT_PATH` and `TLS_KEY_PATH` into every installed
app's `/etc/<name>.env`, and restarts each service.

`{"domains": ["chat.example.com", "www.example.com"]}` (or `"domain"` with the
names comma-separated) runs `certs.sh domain` for each, one after another, in
the same job and log. Each name gets a certificate of its own, so one whose DNS
is not ready yet fails alone: the others are still issued, and the run ends
failed, naming it. Behind Nginx each certificate goes to the sites for that
name; apps that serve themselves take the one run last.

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
       "path": "",
       "name": "app",
       "product-name": "My App",
       "app-type": "swift",
       "app-cmd": "App serve --env production",
       "port": "8080",
       "dependencies": ["postgresql", "swift 6"]
     }'
```

Only `repo` is required — or, for one of the agent's own demos, `"demo": true`
with `path` (e.g. `"path": "demos/python"`) and no `repo`: the demo is copied
from the agent's checkout into `/opt/<name>` instead of cloned, so it installs
at the agent's own version (`branch` and `key` are ignored).

`install_app.sh` then, logging every step to `setup.log` with per-line
timestamps:

1. **Installs dependencies.** Each name is looked up in `supported_deps.json`
   and installed via its `package-manager` (apt) or `install-cmd`. No
   dependencies → nothing installed. Each is logged as
   `<name> installation began … <name> installation completed`.
2. **Clones the repo** into `/opt/<name>` (the key is embedded for a private
   clone and never echoed back). With `path` set (e.g. `demos/python`), the app
   lives in that folder of the repo: the whole repo is still cloned, and every
   later step — `setup.sh`/`install.sh`, the builder, the service, the path
   recorded in `installed_apps.json` — works from `/opt/<name>/<path>`. A path
   that is missing from the repo, or climbs out of it, fails the install.
3. **Sets the app up.** If the repo ships a `setup.sh` or `install.sh`, that is
   run (it builds the app and configures its own service). Otherwise the generic
   path: it creates a dedicated non-root user to run the app, wires its database
   (`wire_<db>.sh`), generates a self-signed TLS cert (written to
   `/etc/<name>.env`), runs the per-type builder `install_<app-type>_app.sh`
   (e.g. `install_swift_app.sh` → `swift build -c release`), and creates a
   systemd service from the request's `app-cmd` — running as that user with
   `AmbientCapabilities=CAP_NET_BIND_SERVICE` so it can bind 443. (`app-type`
   selects the builder.)
4. **Records the app** in `installed_apps.json`, logs
   `<name> installation completed` as the log's last line and releases the
   install lock.

A version may be appended after a space (e.g. `swift 6`, `ruby 3.4.5`). Most
dependencies install via apt; `swift` is fetched from swift.org. The full,
current list comes from `/supported`.

**Progress & concurrency.** One install runs at a time, app or utility: the
agent takes the lock (`pending_install.json`) when it accepts a request and a
second `/install-app` or `/install-util` meanwhile is refused with `409`.
`setup.log` holds the current install, every line timestamped, starting with
`<name> installation started` and ending with `<name> installation completed`
or `<name> installation failed`. It stays after the install ends — for View
Setup Log — until the next install is accepted, which moves it to
`<tmp>/p5agent_setup_<timestamp>.log` (`-failed.log` for a failed one). A run
with no log activity for 30 minutes is marked failed by the agent.
`/setup-log` hands it out incrementally: the caller says how many lines it has
(`from`) of which log (`id`), and gets only the rest.

### `/install-util`

A utility is installed like an app: `install_util.sh <name> [args]` runs
`utilities/<name>/<name>.sh install [args]` detached, its output timestamped
into `setup.log`.

```bash
# Squid: an authenticated forward proxy (password in the environment only)
curl -X POST "https://<ip>:5005/install-util" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "squid", "users": [{"user": "alice"}, {"user": "bob", "password": "…"}],
          "port": 3128, "whitelist": true, "domains": [".github.com"]}'
# The proxy's users become exactly those listed: one with a password gets it, one
# without keeps the password it has, and any user not listed is removed.

# Nginx in front of an installed app (port 0: picked on the upplet)
curl -X POST "https://<ip>:5005/install-util" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "nginx", "app": "chatserver", "port": 0, "public_port": 443,
          "bots": true, "fail2ban": false}'

# Several apps on one port, told apart by domain. The one without a domain
# is the port's default: it answers for the IP and any other name.
curl -X POST "https://<ip>:5005/install-util" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "nginx", "public_port": 443, "bots": true,
          "sites": [{"app": "chatserver", "port": 0, "domain": ""},
                    {"app": "blog", "port": 0, "domain": "blog.example.com"},
                    {"static": true, "domain": "www.example.com"}]}'
# ({"static": true, …} among them: the static site, /var/www/html, on the same port.)

# The static site (no app at all), optionally for one domain
curl -X POST "https://<ip>:5005/install-util" -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"name": "nginx", "static": true, "port": 443, "domain": "www.example.com"}'
```

`POST /squid` and `POST /app {op: "nginx"}` are the same installs.

Several sites share a port only when Nginx can tell them apart by name: at
most one without a domain per port, and no domain twice. That is checked
before anything changes. A certificate from `/certs` goes to the sites whose
domain it is for, and to the sites without a domain when it is for none of
them. An app's `/apps` entry carries `nginx-domain` while it has one.

### Copy (`/copy-inventory`, `/copy-key`, `/copy-start`, `/copy/…`)

The dashboard's New Upplet → Copy makes a new upplet a copy of another. The
two agents do the work between themselves — every byte goes from agent to
agent — and `copy_upplet.py` holds all of it.

**Read-only for the copied upplet.** A copy reads its files and databases and
writes nothing there but logs: the calculation's (`copy_inventory.log`) and the
agent's own. The key and everything the grant records live in the agent's
memory; the archives are made as they are sent, straight into the reply; and
its firewall is never touched.

1. **Calculation stage** (before anything is created): `POST /copy-inventory
   {apps, data}` on the upplet to be copied runs `copy_upplet.py inventory`: disk in
   use, and for each app its database's size as the database reports it
   (`pg_database_size`, `information_schema`, the SQLite file) with a rough
   guess at its archive (30% of that) — nothing is dumped — and the files in
   its data folders. `data` maps an app to folders of its own that a fresh
   clone does not have (its uploads, say), as the dashboard's registry names
   them (apps.json `data`): relative to the app's folder, plain names only,
   and checked to stay inside it, links followed. It also reads the
   firewall: an agent port open to listed addresses only would shut the new
   upplet out, so the calculation fails then. Its state lives in the agent;
   its output is its log, the last line the result as JSON, which `GET
   /copy-inventory` hands back. The dashboard refuses a copy whose disk in use
   is more than the new upplet's disk ("Not enough space on the new upplet"),
   and asks before going on when the databases and files come to more than 1 GB.
2. **Keys**: once the new upplet's agent answers, the dashboard checks both
   upplets' disks again (`/info`), makes a one-off key and gives it to both:
   `POST /copy-key {key, peer: <new upplet's IP>}` on the copied one, which
   keeps the grant in its memory only — the key's sha256, never on disk — and
   drops it 5 minutes after its last use (or at `/copy/done`, `{revoke:
   true}`, or a restart). The grant snapshots the firewall table and
   `P5AGENT_ALLOW_IP` (what gets copied). It is refused when the agent port is
   open to listed addresses only and the new upplet's is not one of them. Then `POST
   /copy-start {source, key, source_name, target_name, apps, installs, data,
   nginx, squid}` on the new one. `installs` maps each app to the install request the
   dashboard builds from its own registry, as it would install the app
   anywhere — dependencies included, less those switched off in Details. The
   copied upplet's record of an app is not used for it: only where an app the
   registry does not list comes from, and for the same repo the branch it is
   on and the key a private one is cloned with, are read off its checkout.
3. **Copy**: the new upplet's agent runs `copy_upplet.py import` as an install
   (app name `copy`). It first fetches everything it needs from the copied
   agent's `/copy/…` endpoints with the key — accepted only from the granted
   address — and then lets the copied upplet go, so the grant is in use for
   minutes, not for as long as the apps take to install:
   - `GET /copy/manifest` — each app's install request as recorded there
     (repo, branch and token from its git checkout; the rest is used only
     when the dashboard sends no `installs`), its database
     and Nginx settings, Squid, the static site, and the snapshot;
   - `GET /copy/file?item=[&path=]` — one archive, made by `copy_upplet.py stream` as
     it is sent: `db:<app>` (the database dumped and gzipped: `pg_dump -Fc`,
     `mysqldump`, or SQLite's SQL dump in one read transaction),
     `config:<app>` (`/etc/<app>.env`, `/etc/<app>/` without its certs, and
     the app's untracked `.env` files), `data:<app>` with `path=<folder>` (one
     of its data folders, put in place of what the install left there and
     owned by the user the app runs as), `site` (`/var/www/html`),
     `letsencrypt`, `squid` (passwd and whitelist) — gzipped tars. Its length
     is not known ahead, so the reply ends with the connection; one that
     fails part-way stops before its gzip end, and the new upplet refuses it
     as incomplete;
   - `POST /copy/done` — the key is dropped.

   **Busy.** While either upplet is in a copy — the grant is live on the
   copied one, the copy install runs on the new one — its agent refuses every
   request that installs, sets up, changes or removes something (`/update`,
   `/install-app`, `/install-util`, `/squid`, `/app`, `/utility`, `/firewall`,
   `/certs`, `/squid-password`, `/static-site`, `/copy-start`, `/copy-key`)
   with `409 {"error": "busy", "reason": …}`. Reading stays open. The copied
   upplet is free again as soon as everything is fetched (`/copy/done`).

   In order: the Let's Encrypt certificates; each app installed from scratch
   (`install_app.sh` with `P5AGENT_NESTED=1` and the dashboard's request, logging into the same
   `setup.log` and leaving the lock alone), its config files (its env file
   keeps this upplet's `MGMT_TOKEN`, `PORT`, `HOST` and TLS pair), its
   database restored; Nginx (`nginx.sh install sites` per public port, the
   static site and its files); Squid with the same credentials and whitelist;
   `P5AGENT_ALLOW_IP` merged in (the agent re-reads `/etc/p5agent.env` when it
   changes — no restart); the firewall rules 1:1 (`firewall.sh --set`); and
   last, every service the copy needs is checked to be running. The log ends
   `copy installation completed` (or `failed`). An app behind Nginx on the
   copied upplet is installed serving itself on the port Nginx served it on —
   as it was installed there before Nginx, and as an app's own installer may
   bind anyway — and stopped once copied, so the next app can do the same;
   Nginx then moves each to its private port and starts it. When Nginx is
   not copied, such an app serves itself on that port (unless another app
   copied has it already).

## Authorization

Every request except `/` must carry the shared secret token in the
`Authorization` header (never in the URL, so it stays out of logs and history):

```
Authorization: Bearer <TOKEN>
```

The token is compared in constant time. If no token is configured, the agent
rejects every privileged request with `401`. `/command` and `/app` additionally require
the request to originate from `P5AGENT_ALLOW_IP`.

## Configuration

The agent reads its configuration from the environment (`install.sh` writes it
to `/etc/p5agent.env`, mode 600):

| Variable | Default | Meaning |
|----------|---------|---------|
| `P5AGENT_TOKEN` | *(empty)* | Shared secret required on privileged endpoints. |
| `P5AGENT_ALLOW_IP` | `127.0.0.1` | Client IPs allowed to call `/command` and `/app`. |
| `P5AGENT_PORT` | `5005` | Listen port. |
| `P5AGENT_BIND` | `0.0.0.0` | Listen address. |
| `P5AGENT_DATA_DIR` | `/var/lib/p5agent` | Runtime state: `setup.log`, `installed_apps.json`. |
| `P5AGENT_APPS_DIR` | `/opt` | Where installed apps live (`<dir>/<name>`, and `<dir>/<name>_backup`). |
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
| `copy_upplet.py` | repo | Copying an upplet: the calculation stage, the archives and manifest on the copied upplet, the import on the new one. |
| `copy_inventory.log` | data dir | The last calculation stage's log (its result is the last line). Nothing else of a copy is written on the copied upplet. |
| `install_util.sh` | repo | Backgrounded utility installer: `utilities/<name>/<name>.sh install`, logged like an app install. |
| `app_support/common.sh` | repo | Helpers shared by `install_app.sh` and `app_ops.sh`: `create_service`, and `app_version_line` (asks the app's `/api/info` which version is running — logged at the end of an install, an update and a rollback). |
| `app_ops.sh` | repo | Start, stop, back up, update, roll back or uninstall one installed app; run by `/app`. |
| `install_swift.sh` | repo | Dedicated Swift installer; referenced by the `swift` entry's `install-cmd`. |
| `app_support/install_<type>_app.sh` | repo | Standard minimal builder per app type (swift, nodejs, python, ruby, go, php, java), used when a cloned repo has no `setup.sh`/`install.sh`. It builds the app and creates its systemd service. |
| `app_support/wire_<dbtype>.sh` | repo | Per-database-type wiring (postgresql, mysql, mariadb, sqlite): creates the app's database/user and writes `/etc/<name>.env` (loaded by the service). Used for repos with no installer of their own. |
| `supported_deps.json` | repo | Registry of installable dependencies: `name`, `display-name`, `icon-url`, and a `package-manager` (+ optional `package`) or `install-cmd`. Served by `/supported`. |
| `setup.log` | data dir | The current (or last) install's log, app or utility; served by `/setup-log`, archived to `<tmp>` when the next install starts. |
| `installed_apps.json` | data dir | Installed apps (`name`, `product-name`, `path`, `port`, `dependencies`, and for updates `app-type`, `app-cmd`, `demo`, `source`); served by `/apps`. |
| `app_update.log`, `app_update_status.json` | data dir | The current (or last) app update; served by `/app-log`. |
| `p5agent-restart-apps.sh` | `/etc/letsencrypt/renewal-hooks/deploy` | Restarts every installed app after a certificate renewal; written by `certs.sh`. |
| `MGMT_TOKEN` | `/etc/<name>.env` | The agent's own token, handed to each installed app at install so a panel can authenticate to the app's management endpoints. |
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

Every other port is closed. (`P5AGENT_ALLOW_IP` only governs who may call `/command` and `/app`)

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
  and `/app` (app start/stop/rollback/uninstall) are reachable only from there; it defaults to localhost.
