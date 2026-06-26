#!/usr/bin/env bash
# Install p5agent on an Ubuntu droplet as a root systemd service.
#
# Usage (run as root from a checkout of this repo):
#   P5AGENT_TOKEN=<secret> P5AGENT_ALLOW_IP=<dashboard_ip> bash install.sh
#
# Environment:
#   P5AGENT_TOKEN     required — shared secret for privileged endpoints
#   P5AGENT_ALLOW_IP  optional — client IP allowed to call /command (saved to the
#                     env file and enforced by the agent); default 127.0.0.1
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
DATA_DIR="/var/lib/$PROJECT"

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
P5AGENT_ALLOW_IP=$ALLOW_IP
P5AGENT_PORT=$PORT
P5AGENT_DATA_DIR=$DATA_DIR
P5AGENT_TLS_CERT=$TLS_CERT
P5AGENT_TLS_KEY=$TLS_KEY
EOF
chmod 600 "$ENV_FILE"
ok "Configuration written"

# ── Runtime state ────────────────────────────────────────────────────────────
# Mutable state (the live install log and the installed-apps list) lives outside
# the git checkout so /update never disturbs it.
log "Preparing data dir $DATA_DIR"
mkdir -p "$DATA_DIR"
[[ -f "$DATA_DIR/installed_apps.json" ]] || echo "[]" > "$DATA_DIR/installed_apps.json"
ok "Data dir ready"

# ── systemd service ──────────────────────────────────────────────────────────
log "Installing systemd service"
cp "$INSTALL_DIR/$SERVICE" "/etc/systemd/system/$SERVICE"
systemctl daemon-reload
systemctl enable "$PROJECT" >/dev/null 2>&1 || true
systemctl restart "$PROJECT"
ok "Service $PROJECT started"

# ── Firewall ─────────────────────────────────────────────────────────────────
# Open the port to all hosts. Source-IP enforcement is done per-endpoint inside
# the agent (only /command is locked to P5AGENT_ALLOW_IP); /install-app and
# /update must be reachable from any IP, so the firewall does not scope by IP.
if command -v ufw >/dev/null 2>&1; then
    log "Opening port $PORT in UFW"
    ufw allow "${PORT}/tcp" comment "$PROJECT" >/dev/null 2>&1 || true
    ok "Firewall: $PORT/tcp open"
else
    log "ufw not found — skipping firewall rule (port governed by host firewall)"
fi

ok "$PROJECT installed — listening on :$PORT"
echo "Check status: systemctl status $PROJECT   |   logs: journalctl -u $PROJECT -f"
