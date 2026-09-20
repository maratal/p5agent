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
