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
# Lock the box to two ways in and deny everything else:
#   - the agent port: open to all (per-endpoint source-IP enforcement is done
#     inside the agent, since /install-app and /update must reach any IP)
#   - SSH (22): restricted to the allowed IP
# A reset guarantees no stray rules leave another port open.
if command -v ufw >/dev/null 2>&1; then
    log "Configuring UFW (deny by default; allow $PORT; SSH from $ALLOW_IP)"
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming >/dev/null 2>&1 || true
    ufw default allow outgoing >/dev/null 2>&1 || true
    ufw allow "${PORT}/tcp" comment "$PROJECT" >/dev/null 2>&1 || true
    ufw allow from "$ALLOW_IP" to any port 22 proto tcp comment "SSH ($ALLOW_IP)" >/dev/null 2>&1 || true

    # Also allow SSH from peer droplets on the same internal (VPC) network.
    # DigitalOcean assigns each droplet a private IP in a 10.x.0.0/20 VPC range;
    # detect this droplet's private subnet and allow 22 from it.
    PRIV_CIDR=$(ip -o -f inet addr show 2>/dev/null | awk '$4 ~ /^10\./ {print $4; exit}')
    if [[ -n "$PRIV_CIDR" ]]; then
        VPC_NET=$(python3 -c "import ipaddress,sys;print(ipaddress.ip_network(sys.argv[1],strict=False))" "$PRIV_CIDR" 2>/dev/null)
        if [[ -n "$VPC_NET" ]]; then
            ufw allow from "$VPC_NET" to any port 22 proto tcp comment "SSH (VPC $VPC_NET)" >/dev/null 2>&1 || true
            log "SSH also allowed from internal network $VPC_NET"
        fi
    fi

    ufw --force enable >/dev/null 2>&1 || true
    ok "Firewall: default deny; ${PORT}/tcp open; 22/tcp from $ALLOW_IP${VPC_NET:+ + $VPC_NET}"
    if [[ "$ALLOW_IP" == "127.0.0.1" || "$ALLOW_IP" == "localhost" ]]; then
        log "WARNING: SSH is now limited to $ALLOW_IP — remote SSH is blocked."
        log "         Set P5AGENT_ALLOW_IP to your admin IP to keep SSH access."
    fi
else
    fail "ufw not found — cannot configure the firewall"
fi

ok "$PROJECT installed — listening on :$PORT"
echo "Check status: systemctl status $PROJECT   |   logs: journalctl -u $PROJECT -f"
