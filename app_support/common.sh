#!/usr/bin/env bash
# Helpers shared by install_app.sh and app_ops.sh (whose update rebuilds an app
# the way its install built it). Sourced, not run.

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

# Ask the app itself what it is now running: its /api/info, which every app the
# dashboard shows serves (productName, version). Printed at the end of an
# install, an update and a rollback, so the log says which version ended up
# running rather than only that something restarted. The service has just been
# (re)started, so it is given a few seconds to come up. Prints the line and
# returns 0 when the app answered, 1 when it did not — a silent app is not a
# failed operation, only an unknown version, and the caller marks it as such.
app_version_line() {  # app_version_line <name> <port>
    local name="$1" port="${2:-}" body="" scheme
    [[ "$port" =~ ^[0-9]+$ ]] || { echo "No port on record for $name — cannot ask it for its version"; return 1; }
    command -v curl >/dev/null 2>&1 || { echo "curl is not installed — cannot ask $name for its version"; return 1; }
    local attempt
    for (( attempt = 0; attempt < 10; attempt++ )); do
        for scheme in https http; do
            body=$(curl -fsSk --max-time 3 "$scheme://127.0.0.1:$port/api/info" 2>/dev/null) && [[ -n "$body" ]] && break 2
        done
        body=""
        sleep 1
    done
    [[ -n "$body" ]] || { echo "$name did not answer /api/info — its version is unknown"; return 1; }
    python3 - "$name" "$body" <<'PY'
import json, sys
try:
    info = json.loads(sys.argv[2])
except Exception:
    info = {}
product = info.get("productName") or sys.argv[1]
version = info.get("version")
print("%s %s is running" % (product, version) if version else "%s is running (it reports no version)" % product)
PY
}
export -f app_version_line
