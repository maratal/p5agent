#!/usr/bin/env bash
# install_app.sh <request.json>
#
# Installs an app: its dependencies (from supported_deps.json) and the app
# itself (clone repo, then run setup.sh or install.sh). The app may live in a
# subfolder of the repo ("path", e.g. src/server): the whole repo is cloned and
# that folder is the app's directory from then on. A demo ("demo": true) is a
# folder of this agent's own checkout instead — "path" names it (e.g.
# demos/python) and it is copied, not cloned. Run detached by the
# agent; it is the single owner of the install lifecycle.
#
# Everything is logged, line-by-line with timestamps, to $SETUP_LOG, which the
# agent serves as the "log" field of /progress. The AGENT owns the install
# lifecycle: it takes the lock (pending_install.json) before spawning this
# script, refuses concurrent installs, and decides the outcome —
#   completed: the log's LAST line is "<name> installation completed" (written
#              at the very end below, upon which pending_install.json is
#              removed; the log stays until the next accepted install);
#   failed:    fail() archives the log and removes the lock, so /progress
#              drops back to {} — the polling peer's failure signal. A run
#              that dies silently is cleared by the agent's 30-minute stall rule.

REQ="${1:?usage: install_app.sh <request.json>}"

HERE="$(cd "$(dirname "$0")" && pwd)"
SUPPORT="$HERE/app_support"   # per-app-type builders + per-db-type wiring scripts
SUPPORTED="$HERE/supported_deps.json"
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
TMP_DIR="${P5AGENT_TMP_DIR:-/tmp}"
APPS_DIR="${P5AGENT_APPS_DIR:-/opt}"
SETUP_LOG="$DATA_DIR/setup.log"
INSTALLED="$DATA_DIR/installed_apps.json"
PENDING="$DATA_DIR/pending_install.json"   # the agent's install lock/status record

mkdir -p "$DATA_DIR" "$TMP_DIR"

ts()       { date '+%Y-%m-%d %H:%M:%S'; }
logline()  { printf '[%s] %s\n' "$(ts)" "$*" >> "$SETUP_LOG"; }
stamp()    { while IFS= read -r line; do printf '[%s] %s\n' "$(ts)" "$line"; done >> "$SETUP_LOG"; }
runlog()   { bash -c "$1" 2>&1 | stamp; return "${PIPESTATUS[0]}"; }

archive() {  # archive() <suffix>  — move the log out of the way
    cp "$SETUP_LOG" "$TMP_DIR/p5agent_setup_$(date +%Y%m%d_%H%M%S)${1:-}.log" 2>/dev/null || true
    rm -f "$SETUP_LOG"
}

fail() { logline "$*"; archive "-failed"; rm -f "$PENDING"; exit 1; }

# Create + start a systemd service that runs $APP_CMD in $APP_DIR. The only
# per-type difference is where the built artifact lives, so the builder passes
# that as the PATH prefix; everything else is uniform. Exported so the per-type
# install_<type>_app.sh scripts (run as child shells) can call it; it uses plain
# echo (captured into the install log by the caller) — no logline/runlog deps.
create_service() {  # create_service <path-prefix>  (uses APP_NAME/APP_DIR/APP_PORT/APP_CMD/APP_SERVICES/APP_USER)
    [[ -n "${APP_CMD:-}" ]] || { echo "No run command (app-cmd) — skipping service"; return 0; }
    echo "Creating systemd service ${APP_NAME}"
    # Order (and pull in) after any service dependencies the app needs — the
    # database etc. — so they are up before the app starts. APP_SERVICES is a
    # space-separated list of unit names (e.g. "postgresql.service").
    local after="network.target" wants=""
    if [[ -n "${APP_SERVICES:-}" ]]; then
        after="network.target ${APP_SERVICES}"
        wants="Wants=${APP_SERVICES}"
    fi
    # Run as the dedicated non-root app user when one exists, granting it the
    # capability to bind privileged ports (443) — no setcap on the binary needed.
    # Hand it ownership of the app dir, env file and cert dir so it can read them.
    local user_lines=""
    if [[ -n "${APP_USER:-}" ]] && id "${APP_USER}" &>/dev/null; then
        user_lines="User=${APP_USER}
Group=${APP_USER}
AmbientCapabilities=CAP_NET_BIND_SERVICE"
        chown -R "${APP_USER}:${APP_USER}" "${APP_DIR}" 2>/dev/null || true
        [[ -f "/etc/${APP_NAME}.env" ]]  && chown "${APP_USER}:${APP_USER}" "/etc/${APP_NAME}.env" 2>/dev/null || true
        [[ -d "/etc/${APP_NAME}" ]]      && chown -R "${APP_USER}:${APP_USER}" "/etc/${APP_NAME}" 2>/dev/null || true
        [[ -d "/var/lib/${APP_NAME}" ]]  && chown -R "${APP_USER}:${APP_USER}" "/var/lib/${APP_NAME}" 2>/dev/null || true
    fi
    cat > "/etc/systemd/system/${APP_NAME}.service" <<EOF
[Unit]
Description=${APP_NAME} (p5agent)
After=${after}
${wants}

[Service]
Type=simple
${user_lines}
WorkingDirectory=${APP_DIR}
EnvironmentFile=-/etc/${APP_NAME}.env
Environment=PORT=${APP_PORT}
Environment=HOST=0.0.0.0
Environment=PATH=${1}:/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/env ${APP_CMD}
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=${APP_NAME}

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "${APP_NAME}" 2>/dev/null || true
    systemctl restart "${APP_NAME}" || echo "service ${APP_NAME} failed to start (journalctl -u ${APP_NAME})"
}
export -f create_service

# Shared DB helpers for the per-type wire_<dbtype>.sh scripts. Like create_service
# they run in those child shells, so they are exported. db_password re-uses the
# existing password on re-install; write_db_env writes /etc/<name>.env (loaded by
# the service via EnvironmentFile) with both DATABASE_* fields and a DATABASE_URL.
db_password() {  # db_password <env-file>  -> reused-or-new password
    if [[ -f "$1" ]] && grep -q '^DATABASE_PASSWORD=' "$1"; then
        sed -n 's/^DATABASE_PASSWORD=//p' "$1" | head -1
    else
        openssl rand -hex 16
    fi
}
write_db_env() {  # write_db_env <scheme> <port> <password>   (uses $DB_NAME)
    local f="/etc/${DB_NAME}.env"
    ( umask 077; cat > "$f" <<EOF
DATABASE_HOST=localhost
DATABASE_PORT=$2
DATABASE_NAME=$DB_NAME
DATABASE_USERNAME=$DB_NAME
DATABASE_PASSWORD=$3
DATABASE_URL=$1://$DB_NAME:$3@localhost:$2/$DB_NAME
EOF
    )
    echo "Wrote DB connection settings to $f"
}
export -f db_password write_db_env

# Hand the app the management token, so a control panel can drive the app's own
# refresh/update endpoints the way it drives the agent — same secret, presented
# as a bearer token. Without it an app either has no way to authenticate the
# panel or needs the token placed by hand, which is easy to forget and looks
# exactly like a broken button.
#
# Written after the install, not before: an app that ships its own installer
# writes /etc/<name>.env itself with a truncating redirect, taking anything
# already there with it.
write_mgmt_token() {  # uses $name
    local env_file="/etc/${name}.env" app_user
    if [[ -z "${P5AGENT_TOKEN:-}" ]]; then
        logline "No P5AGENT_TOKEN in the environment — skipping MGMT_TOKEN for $name"
        return 0
    fi
    touch "$env_file"; chmod 600 "$env_file"
    sed -i '/^MGMT_TOKEN=/d' "$env_file"
    echo "MGMT_TOKEN=$P5AGENT_TOKEN" >> "$env_file"
    # sed -i replaces the file rather than editing it, so hand it back to
    # whoever runs the app — otherwise the service loses its own environment
    # file at the next start.
    app_user=$(grep -oP '^User=\K.*' "/etc/systemd/system/${name}.service" 2>/dev/null || true)
    if [[ -n "$app_user" ]] && id "$app_user" &>/dev/null; then
        chown "${app_user}:${app_user}" "$env_file"
    fi
    logline "Wrote MGMT_TOKEN to $env_file"
}

# Give the app a TLS certificate for the droplet's IP (so generic apps can serve
# HTTPS) and record its paths in /etc/<name>.env.
#
# The work is certs.sh's — it is the only place this project makes certificates,
# and the same script issues the Let's Encrypt certificate that replaces this one
# once a domain points here. An existing pair is reused rather than replaced, so
# re-installing an app does not throw away a certificate a domain is using.
setup_tls() {  # uses $name
    bash "$HERE/certs.sh" self-signed \
        --cert "/etc/${name}/certs/cert.pem" \
        --key  "/etc/${name}/certs/key.pem" \
        --env  "/etc/${name}.env" 2>&1 | stamp
}

# ── Read the request ─────────────────────────────────────────────────────────
# (No concurrency guard here: the agent refuses a second install and clears the
# previous run's log before spawning this script.)
jget() { python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],'') or '')" "$REQ" "$1"; }
repo=$(jget repo); key=$(jget key); branch=$(jget branch)
name=$(jget name); product=$(jget product-name); port=$(jget port)
app_type=$(jget app-type); app_cmd=$(jget app-cmd); path=$(jget path)
# A demo is one of this repo's own demos/<type> apps: it is already on the
# upplet (the agent runs from a checkout of the same repo), so it is copied
# from here rather than cloned from anywhere.
case "$(jget demo)" in True|true|1|yes) demo=1 ;; *) demo="" ;; esac
# The app's own directory inside the repo. Relative, tidied of "./" and
# surrounding slashes; anything climbing out of the repo is refused below.
path="${path#./}"; path="${path#/}"; path="${path%/}"
if [[ -z "$name" ]]; then
    if [[ -n "$demo" ]]; then name="${path##*/}"; else base="${repo##*/}"; name="${base%.git}"; fi
fi
target="$APPS_DIR/$name"   # where the repo is cloned (a demo: copied)
app_dir="$target${path:+/$path}"
[[ -n "$demo" ]] && app_dir="$target"   # a demo's folder IS the copy

mapfile -t DEPS < <(python3 -c "
import json,re,sys
d=json.load(open(sys.argv[1])).get('dependencies') or []
if isinstance(d,str): d=[x for x in re.split(r'[,\n]',d) if x.strip()]
for x in d: print(str(x).strip())
" "$REQ")

# ── Start a fresh log ────────────────────────────────────────────────────────
: > "$SETUP_LOG"
logline "Setup started for ${product:-$name}"

# ── Install dependencies ─────────────────────────────────────────────────────
# Look up how to install a dependency in supported_deps.json (no per-package
# logic lives here — the registry carries the package-manager or install-cmd).
depinfo() {  # depinfo <name> -> "display-name<TAB>mode<TAB>payload"  (mode: cmd|apt|none)
    python3 - "$SUPPORTED" "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
dn = sys.argv[2].lower()
e = next((x for x in data if x.get("name", "").lower() == dn), None)
if not e:
    print("\t\t"); raise SystemExit
disp = e.get("display-name") or e.get("name")
if e.get("install-cmd"):
    print("%s\tcmd\t%s" % (disp, e["install-cmd"]))
elif e.get("package-manager") == "apt":
    print("%s\tapt\t%s" % (disp, e.get("package") or e.get("name")))
else:
    print("%s\tnone\t" % disp)
PY
}

app_services=""   # systemd units of service deps (postgres, redis, …) the app needs
if (( ${#DEPS[@]} == 0 )); then
    logline "No dependencies requested"
else
    # DigitalOcean password-auth droplets flag root's password "must change on
    # first login". That makes PAM abort chfn/adduser inside package postinst
    # scripts (notably postgresql) with "authentication token is no longer
    # valid", failing the whole apt step. Reset root's last-change date so those
    # service-user setups succeed.
    runlog "chage -d \"\$(date +%F)\" root || true"

    logline "Updating package lists"
    runlog "apt-get update -qq"
    for dep in "${DEPS[@]}"; do
        depname="${dep%% *}"; depname="${depname,,}"
        version=""; [[ "$dep" == *" "* ]] && version="${dep#* }"

        IFS=$'\t' read -r display mode payload < <(depinfo "$depname")
        [[ -n "$display" ]] || fail "Unknown dependency '$depname' — aborting"

        logline "$display installation began"
        case "$mode" in
            cmd)
                # An install-cmd ending in .sh is a local script (in the repo),
                # run with the version as its argument; anything else is an
                # inline shell one-liner with {version} substituted.
                if [[ "$payload" == *.sh ]]; then
                    script="$HERE/$payload"
                    [[ -f "$script" ]] || fail "$display: install script not found ($payload)"
                    runlog "bash '$script' '$version'" || fail "$display installation failed"
                else
                    runlog "${payload//\{version\}/$version}" || fail "$display installation failed"
                fi
                ;;
            apt)
                if [[ -n "$version" ]]; then
                    runlog "DEBIAN_FRONTEND=noninteractive apt-get install -y '$payload=$version'" \
                        || runlog "DEBIAN_FRONTEND=noninteractive apt-get install -y '$payload'" \
                        || fail "$display installation failed"
                else
                    runlog "DEBIAN_FRONTEND=noninteractive apt-get install -y '$payload'" \
                        || fail "$display installation failed"
                fi
                ;;
            *)
                fail "No install method for '$depname'"
                ;;
        esac

        # Enable + start service-type dependencies (they aren't reliably started
        # on a non-interactive install, and the app needs them running).
        svc=""
        case "$depname" in
            postgresql) svc=postgresql ;;
            mysql)      svc=mysql ;;
            mariadb)    svc=mariadb ;;
            redis)      svc=redis-server ;;
            nginx)      svc=nginx ;;
        esac
        if [[ -n "$svc" ]]; then
            runlog "systemctl enable --now '$svc'" || logline "Could not enable/start $svc"
            app_services="${app_services:+$app_services }${svc}.service"
        fi

        logline "$display installation completed"
    done
fi

# ── Install the app (clone + setup) ──────────────────────────────────────────
if [[ -n "$repo" || -n "$demo" ]]; then
    if [[ -n "$demo" ]]; then
        # Copied fresh every time: a re-install gets the demo as this agent
        # version ships it, never a mix with what an earlier build left behind.
        [[ -n "$path" ]] || fail "$name: a demo needs a path (e.g. demos/python)"
        [[ "/$path/" != *"/../"* ]] || fail "$name: path '$path' leaves the repo"
        [[ -d "$HERE/$path" ]] || fail "$name: demo '$path' not found in p5agent"
        logline "$name installation began"
        logline "Copying demo $path from p5agent"
        rm -rf "$target"
        runlog "mkdir -p '$target' && cp -a '$HERE/$path/.' '$target/'" || fail "$name: copying the demo failed"
    elif [[ -d "$target/.git" ]]; then
        logline "$name already present at $target"
    else
        logline "$name installation began"
        clone_url="$repo"
        if [[ -n "$key" ]]; then
            case "$repo" in
                https://github.com/*) clone_url="https://x-access-token:$key@github.com/${repo#https://github.com/}" ;;
                https://*)            clone_url="https://$key@${repo#https://}" ;;
            esac
        fi
        # Target the requested ref (branch or tag); no version given → main. A
        # semver also tries the common "v"-prefixed / unprefixed variant (so
        # "1.2.3" matches a "v1.2.3" release tag).
        ref_in="${branch:-main}"
        refs=("$ref_in")
        if [[ "$ref_in" =~ ^v?[0-9]+(\.[0-9]+){1,2}$ ]]; then
            if [[ "$ref_in" == v* ]]; then refs+=("${ref_in#v}"); else refs+=("v$ref_in"); fi
        fi
        cloned=0
        for ref in "${refs[@]}"; do
            if runlog "git clone --depth 1 --branch '$ref' '$clone_url' '$target'"; then
                cloned=1; break
            fi
            logline "ref '$ref' not found"
            rm -rf "$target"
        done
        (( cloned )) || fail "$name clone failed (no branch or tag matching '$ref_in')"
    fi

    if [[ -n "$path" && -z "$demo" ]]; then
        [[ "/$path/" != *"/../"* ]] || fail "$name: path '$path' leaves the repo"
        [[ -d "$app_dir" ]] || fail "$name: path '$path' not found in the repo"
        logline "$name app directory: $path"
    fi

    # Open the app's port in the firewall (everything else is denied by default).
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        if command -v ufw >/dev/null 2>&1; then
            logline "Opening firewall port $port for $name"
            runlog "ufw allow '$port/tcp' comment '$name'"
        fi
    fi

    setup=""
    for candidate in setup.sh install.sh; do
        [[ -f "$app_dir/$candidate" ]] && { setup="$app_dir/$candidate"; break; }
    done
    if [[ -n "$setup" ]]; then
        # The repo ships its own installer — it builds and sets up its service.
        # P5AGENT=1 tells the repo installer it is running under the agent, so it
        # can skip droplet-level provisioning the agent already did (firewall,
        # system upgrade, dependency install).
        logline "Running ${setup##*/}"
        ( cd "$app_dir" && P5AGENT=1 runlog "bash '$setup'" ) || fail "$name setup failed"
    else
        # No repo installer. Create a dedicated non-root user to run the app as,
        # wire its database, generate a self-signed TLS cert, then run the per-type
        # builder (which builds and creates the service, running as that user).
        app_user="$name"
        if ! id "$app_user" &>/dev/null; then
            runlog "useradd --system --user-group --no-create-home --shell /usr/sbin/nologin '$app_user'" \
                || logline "Could not create user $app_user"
        fi

        db_type=""
        for d in "${DEPS[@]}"; do
            case "${d%% *}" in postgresql|mysql|mariadb|sqlite) db_type="${d%% *}"; break ;; esac
        done
        if [[ -n "$db_type" && -f "$SUPPORT/wire_${db_type}.sh" ]]; then
            logline "Wiring $db_type database for $name"
            ( DB_NAME="$name" runlog "bash '$SUPPORT/wire_${db_type}.sh'" ) || logline "DB wiring failed ($db_type)"
        fi

        setup_tls

        type_script="$SUPPORT/install_${app_type}_app.sh"
        if [[ -n "$app_type" && -f "$type_script" ]]; then
            logline "No setup.sh/install.sh found in the repo — running default install_${app_type}_app.sh"
            ( cd "$app_dir" && APP_DIR="$app_dir" APP_NAME="$name" APP_PORT="$port" APP_CMD="$app_cmd" \
                APP_SERVICES="$app_services" APP_USER="$app_user" \
                runlog "bash '$type_script'" ) || fail "$name install failed (install_${app_type}_app.sh)"
        else
            logline "No setup.sh/install.sh and no builder for app type '${app_type:-?}' — skipping"
        fi

        # Let the app user trigger its own redeploy if the repo ships those scripts.
        if [[ -f "$app_dir/refresh.sh" || -f "$app_dir/update.sh" ]]; then
            cat > "/etc/sudoers.d/$name" <<EOF
$app_user ALL=(root) NOPASSWD: $app_dir/refresh.sh, /usr/bin/systemd-run --collect $app_dir/update.sh
EOF
            chmod 440 "/etc/sudoers.d/$name"
            logline "Configured sudoers for $app_user"
        fi
    fi

    # ── Management token ─────────────────────────────────────────────────────
    # The app is installed and its env file is final, so the token can go in and
    # the service can be restarted with it in the running environment.
    write_mgmt_token
    if [[ -f "/etc/systemd/system/${name}.service" ]]; then
        runlog "systemctl restart '$name'" || logline "Could not restart $name after writing MGMT_TOKEN"
    fi

    # ── Record the installed app ─────────────────────────────────────────────
    python3 - "$REQ" "$name" "$app_dir" "$INSTALLED" <<'PY'
import json, os, sys
req_path, name, target, installed = sys.argv[1:5]
req = json.load(open(req_path))
apps = []
if os.path.exists(installed):
    try:
        apps = json.load(open(installed))
    except Exception:
        apps = []
apps = [a for a in apps if a.get("name") != name]
apps.append({
    "name": name,
    "product-name": req.get("product-name", ""),
    "path": target,
    "port": req.get("port", ""),
    "dependencies": req.get("dependencies") or [],
})
os.makedirs(os.path.dirname(installed), exist_ok=True)
json.dump(apps, open(installed, "w"), indent=2)
PY
    logline "Recorded $name in installed_apps.json"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
# This MUST be the log's last line: it is the agent's completion marker —
# /progress reports completed=true when the log ends with it. Logging it
# releases the install lock (pending_install.json); the log itself stays in
# place as the record until the next accepted install archives it.
logline "$name installation completed"
rm -f "$PENDING"
