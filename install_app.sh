#!/usr/bin/env bash
# install_app.sh <request.json>
#
# Installs an app: its dependencies (from supported_deps.json) and the app
# itself (clone repo, then run setup.sh or install.sh). Run detached by the
# agent; it is the single owner of the install lifecycle.
#
# Everything is logged, line-by-line with timestamps, to $SETUP_LOG. The browser
# polls /progress (which returns that file) every few seconds. While the file
# exists and is being updated, an install is "in progress". On completion the
# log is moved to $TMP_DIR/p5agent_setup_<ts>.log (and to ...-failed.log on failure),
# which leaves /progress empty — the browser's signal that nothing is running.
#
# Concurrency: a second invocation sees a recent $SETUP_LOG and exits. A stale
# log (untouched > 10 min) is treated as a failed run and archived first.

REQ="${1:?usage: install_app.sh <request.json>}"

HERE="$(cd "$(dirname "$0")" && pwd)"
SUPPORT="$HERE/app_support"   # per-app-type builders + per-db-type wiring scripts
SUPPORTED="$HERE/supported_deps.json"
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
TMP_DIR="${P5AGENT_TMP_DIR:-/tmp}"
APPS_DIR="${P5AGENT_APPS_DIR:-/opt}"
SETUP_LOG="$DATA_DIR/setup.log"
INSTALLED="$DATA_DIR/installed_apps.json"

mkdir -p "$DATA_DIR" "$TMP_DIR"

ts()       { date '+%Y-%m-%d %H:%M:%S'; }
logline()  { printf '[%s] %s\n' "$(ts)" "$*" >> "$SETUP_LOG"; }
stamp()    { while IFS= read -r line; do printf '[%s] %s\n' "$(ts)" "$line"; done >> "$SETUP_LOG"; }
runlog()   { bash -c "$1" 2>&1 | stamp; return "${PIPESTATUS[0]}"; }

archive() {  # archive() <suffix>  — move the log out of the way
    cp "$SETUP_LOG" "$TMP_DIR/p5agent_setup_$(date +%Y%m%d_%H%M%S)${1:-}.log" 2>/dev/null || true
    rm -f "$SETUP_LOG"
}

fail() { logline "$*"; printf '\nSetup failed.\n' >> "$SETUP_LOG"; archive "-failed"; exit 1; }

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

# Generate a self-signed TLS cert for the droplet's IP (so generic apps can serve
# HTTPS) and record its paths in /etc/<name>.env. Re-uses an existing cert.
setup_tls() {  # uses $name
    local cert_dir="/etc/${name}/certs" cert="/etc/${name}/certs/cert.pem" key="/etc/${name}/certs/key.pem"
    local env_file="/etc/${name}.env" ip
    mkdir -p "$cert_dir"
    if [[ ! -f "$cert" || ! -f "$key" ]]; then
        ip=$(curl -s --max-time 10 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null \
             || hostname -I | awk '{print $1}')
        logline "Generating self-signed TLS certificate for ${ip:-the server}"
        openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
            -keyout "$key" -out "$cert" \
            -subj "/CN=${ip:-localhost}" -addext "subjectAltName=IP:${ip:-127.0.0.1}" 2>&1 | stamp
    fi
    touch "$env_file"; chmod 600 "$env_file"
    sed -i '/^TLS_CERT_PATH=/d;/^TLS_KEY_PATH=/d' "$env_file"
    { echo "TLS_CERT_PATH=$cert"; echo "TLS_KEY_PATH=$key"; } >> "$env_file"
    logline "Wrote TLS cert paths to $env_file"
}

# ── Concurrency / stale-log check ────────────────────────────────────────────
if [[ -f "$SETUP_LOG" ]]; then
    last=$(stat -c %Y "$SETUP_LOG" 2>/dev/null || echo 0)
    if (( $(date +%s) - last < 600 )); then
        exit 0   # an install is actively running — leave it alone
    fi
    # Stale (>10 min). Wait 30s; if still untouched, the previous run failed.
    sleep 30
    if [[ "$(stat -c %Y "$SETUP_LOG" 2>/dev/null || echo 0)" == "$last" ]]; then
        archive "-failed"
    else
        exit 0   # it moved — another run is active after all
    fi
fi

# ── Read the request ─────────────────────────────────────────────────────────
jget() { python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],'') or '')" "$REQ" "$1"; }
repo=$(jget repo); key=$(jget key); branch=$(jget branch)
name=$(jget name); product=$(jget product-name); port=$(jget port)
app_type=$(jget app-type); app_cmd=$(jget app-cmd)
[[ -n "$name" ]] || { base="${repo##*/}"; name="${base%.git}"; }
target="$APPS_DIR/$name"

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
if [[ -n "$repo" ]]; then
    if [[ -d "$target/.git" ]]; then
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

    # Open the app's port in the firewall (everything else is denied by default).
    if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
        if command -v ufw >/dev/null 2>&1; then
            logline "Opening firewall port $port for $name"
            runlog "ufw allow '$port/tcp' comment '$name'"
        fi
    fi

    setup=""
    for candidate in setup.sh install.sh; do
        [[ -f "$target/$candidate" ]] && { setup="$target/$candidate"; break; }
    done
    if [[ -n "$setup" ]]; then
        # The repo ships its own installer — it builds and sets up its service.
        # P5AGENT=1 tells the repo installer it is running under the agent, so it
        # can skip droplet-level provisioning the agent already did (firewall,
        # system upgrade, dependency install).
        logline "Running ${setup##*/}"
        ( cd "$target" && P5AGENT=1 runlog "bash '$setup'" ) || fail "$name setup failed"
        logline "$name installation completed"
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
            logline "No setup.sh/install.sh — running install_${app_type}_app.sh"
            ( cd "$target" && APP_DIR="$target" APP_NAME="$name" APP_PORT="$port" APP_CMD="$app_cmd" \
                APP_SERVICES="$app_services" APP_USER="$app_user" \
                runlog "bash '$type_script'" ) || fail "$name install failed (install_${app_type}_app.sh)"
        else
            logline "No setup.sh/install.sh and no builder for app type '${app_type:-?}' — skipping"
        fi

        # Let the app user trigger its own redeploy if the repo ships those scripts.
        if [[ -f "$target/refresh.sh" || -f "$target/update.sh" ]]; then
            cat > "/etc/sudoers.d/$name" <<EOF
$app_user ALL=(root) NOPASSWD: $target/refresh.sh, /usr/bin/systemd-run --collect $target/update.sh
EOF
            chmod 440 "/etc/sudoers.d/$name"
            logline "Configured sudoers for $app_user"
        fi

        logline "$name installation completed"
    fi

    # ── Record the installed app ─────────────────────────────────────────────
    python3 - "$REQ" "$name" "$target" "$INSTALLED" <<'PY'
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
printf '\nSetup completed.\n' >> "$SETUP_LOG"
archive ""
