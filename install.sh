#!/usr/bin/env bash
# Install p5agent on an Ubuntu droplet as a root systemd service.
#
# Usage (run as root from a checkout of this repo):
#   P5AGENT_TOKEN=<secret> P5AGENT_ALLOW_IP=<dashboard_ip> bash install.sh
#
# Environment:
#   P5AGENT_TOKEN     required — shared secret for privileged endpoints
#   P5AGENT_ALLOW_IP  optional — client IP allowed to call /command (enforced by
#                     the agent) and the only IP allowed to SSH in; default
#                     127.0.0.1 (which blocks remote SSH — set your admin IP)
#   P5AGENT_PORT      optional — listen port (default: 5005)
#   P5AGENT_TLS_CERT  optional — TLS cert (PEM); a self-signed one is generated if unset
#   P5AGENT_TLS_KEY   optional — TLS key  (PEM); a self-signed one is generated if unset

set -euo pipefail

log()  { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

[[ "$(id -u)" -eq 0 ]] || fail "This script must be run as root"
command -v python3 >/dev/null 2>&1 || fail "python3 is required but not installed"

# Ensure git (the agent self-updates via git pull) and openssl (for the
# self-signed cert below) are present — neither is guaranteed on a fresh image.
if ! command -v git >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || true
    apt-get install -y git openssl || fail "could not install git and openssl"
fi

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

# ── Place the agent code ─────────────────────────────────────────────────────
log "Installing agent to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
# Copy the whole repo (keeps .git so the agent dir can self-update later) unless
# we are already running from the install dir.
if [[ "$SRC_DIR" != "$INSTALL_DIR" ]]; then
    cp -a "$SRC_DIR/." "$INSTALL_DIR/"
fi
ok "Agent code in place"

# ── TLS certificate ──────────────────────────────────────────────────────────
# Use the provided cert/key, or generate a self-signed one (under the install
# dir) so the agent always serves HTTPS on :5005.
if [[ -z "$TLS_CERT" || -z "$TLS_KEY" ]]; then
    log "No TLS cert/key provided — generating a self-signed certificate"
    CERT_DIR="$INSTALL_DIR/certs"
    mkdir -p "$CERT_DIR"
    IP=$(curl -s --max-time 10 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null || hostname -I | awk '{print $1}')
    openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
        -keyout "$CERT_DIR/key.pem" -out "$CERT_DIR/cert.pem" \
        -subj "/CN=$IP" -addext "subjectAltName=IP:$IP"
    TLS_CERT="$CERT_DIR/cert.pem"
    TLS_KEY="$CERT_DIR/key.pem"
    ok "Self-signed certificate generated for $IP"
fi

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
# Apply the firewall rule set (shared with update.sh; reads /etc/p5agent.env,
# just written above). Aborts the install if ufw is unavailable.
log "Configuring firewall"
bash "$INSTALL_DIR/firewall.sh"

ok "$PROJECT installed — listening on :$PORT"
echo "Check status: systemctl status $PROJECT   |   logs: journalctl -u $PROJECT -f"
