#!/usr/bin/env bash
# Install p5agent on an Ubuntu droplet as a root systemd service.
#
# Usage (run as root from a checkout of this repo):
#   P5AGENT_TOKEN=<secret> P5AGENT_ALLOW_IP=<dashboard_ip> bash install.sh
#
# Environment:
#   P5AGENT_TOKEN     required — shared secret for privileged endpoints
#   P5AGENT_ALLOW_IP  optional — restrict the port to this source IP
#                     (the dashboard's IP); defaults to 127.0.0.1 (localhost only)
#   P5AGENT_PORT      optional — listen port (default: 5005)
#   P5AGENT_TLS_CERT  recommended — TLS cert (PEM) to serve HTTPS
#   P5AGENT_TLS_KEY   recommended — TLS key  (PEM) to serve HTTPS

set -euo pipefail

log()  { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || fail "This script must be run as root"
command -v python3 >/dev/null 2>&1 || fail "python3 is required but not installed"

# Project name — drives the install dir, env file, and systemd unit names.
# (The P5AGENT_* env keys below are read by agent.py and are intentionally fixed.)
PROJECT="p5agent"
INSTALL_DIR="/opt/$PROJECT"
ENV_FILE="/etc/$PROJECT.env"
SERVICE="$PROJECT.service"

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
PORT="${P5AGENT_PORT:-5005}"
TOKEN="${P5AGENT_TOKEN:-}"
TLS_CERT="${P5AGENT_TLS_CERT:-}"
TLS_KEY="${P5AGENT_TLS_KEY:-}"
ALLOW_IP="${P5AGENT_ALLOW_IP:-127.0.0.1}"

[[ -n "$TOKEN" ]] || fail "P5AGENT_TOKEN is required (the shared secret)"
if [[ -z "$TLS_CERT" || -z "$TLS_KEY" ]]; then
    log "WARNING: no TLS cert/key given — agent will serve plain HTTP"
fi

# ── Place the agent code ─────────────────────────────────────────────────────
log "Installing agent to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
# Copy the whole repo (keeps .git so the agent dir can self-update later) unless
# we are already running from the install dir.
if [[ "$SRC_DIR" != "$INSTALL_DIR" ]]; then
    cp -a "$SRC_DIR/." "$INSTALL_DIR/"
fi
ok "Agent code in place"

# ── Configuration (root-only readable) ───────────────────────────────────────
log "Writing $ENV_FILE"
umask 077
cat > "$ENV_FILE" <<EOF
P5AGENT_TOKEN=$TOKEN
P5AGENT_PORT=$PORT
P5AGENT_TLS_CERT=$TLS_CERT
P5AGENT_TLS_KEY=$TLS_KEY
EOF
chmod 600 "$ENV_FILE"
ok "Configuration written"

# ── systemd service ──────────────────────────────────────────────────────────
log "Installing systemd service"
cp "$INSTALL_DIR/$SERVICE" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable "$PROJECT" >/dev/null 2>&1 || true
systemctl restart "$PROJECT"
ok "Service $PROJECT started"

# ── Firewall ─────────────────────────────────────────────────────────────────
# Lock the agent port to a single source IP (the dashboard) so the root control
# plane is not reachable from the open internet. Defaults to 127.0.0.1, i.e.
# localhost only — reach it via an SSH tunnel until a dashboard IP is set.
if command -v ufw >/dev/null 2>&1; then
    # Clear any prior, broader rule for this port to avoid leaving it open.
    ufw delete allow "${PORT}/tcp" >/dev/null 2>&1 || true
    log "Restricting port $PORT to $ALLOW_IP in UFW"
    ufw allow from "$ALLOW_IP" to any port "$PORT" proto tcp \
        comment "$PROJECT (dashboard)" >/dev/null 2>&1 || true
    ok "Firewall: $PORT/tcp allowed only from $ALLOW_IP"
else
    fail "ufw not found — cannot restrict port $PORT to $ALLOW_IP; refusing to install without firewall scoping"
fi

ok "$PROJECT installed — listening on :$PORT"
echo "Check status: systemctl status $PROJECT   |   logs: journalctl -u $PROJECT -f"
