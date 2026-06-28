#!/usr/bin/env bash
# Configure UFW for p5agent — the single source of the firewall rule set, shared
# by install.sh and update.sh.
#
# Policy (deliberately permissive): deny incoming by default, then open
#   - SSH (22) to all (so admins and the DigitalOcean console can always get in)
#   - the agent port to all (the agent enforces per-endpoint source IP itself)
#   - one port per installed app (read from installed_apps.json)
# A reset clears stray rules; the rules above are re-added on every run.

set -euo pipefail

log() { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }

[[ "$(id -u)" -eq 0 ]] || { echo "firewall.sh must be run as root" >&2; exit 1; }
command -v ufw >/dev/null 2>&1 || { echo "ufw not found — cannot configure the firewall" >&2; exit 1; }

ENV_FILE="/etc/p5agent.env"
getenvval() {  # value of KEY: from the environment, else from $ENV_FILE
    local key="$1" cur="${!1:-}"
    if [[ -n "$cur" ]]; then printf '%s' "$cur"; return; fi
    [[ -f "$ENV_FILE" ]] && sed -n "s/^${key}=//p" "$ENV_FILE" | head -n1
}
PORT="$(getenvval P5AGENT_PORT)";          PORT="${PORT:-5005}"
DATA_DIR="$(getenvval P5AGENT_DATA_DIR)";   DATA_DIR="${DATA_DIR:-/var/lib/p5agent}"
INSTALLED="$DATA_DIR/installed_apps.json"

log "Configuring UFW (deny incoming by default; open 22, ${PORT}, app ports)"
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming >/dev/null 2>&1 || true
ufw default allow outgoing >/dev/null 2>&1 || true
ufw allow 22/tcp comment "SSH" >/dev/null 2>&1 || true
ufw allow "${PORT}/tcp" comment "p5agent" >/dev/null 2>&1 || true

# One port per installed app (the reset above cleared them; no-op on first
# install). An entry with no port defaults to 443.
if [[ -f "$INSTALLED" ]]; then
    while IFS=$'\t' read -r aname aport; do
        [[ "$aport" =~ ^[0-9]+$ ]] || continue
        ufw allow "${aport}/tcp" comment "$aname" >/dev/null 2>&1 || true
        log "Opened app port $aport ($aname)"
    done < <(python3 -c "
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
for a in apps:
    p = str(a.get('port', '')).strip() or '443'
    n = str(a.get('name', 'app')).strip() or 'app'
    print('%s\t%s' % (n, p))
" "$INSTALLED")
fi

ufw --force enable >/dev/null 2>&1 || true
ok "Firewall: default deny incoming; 22, ${PORT}, and app ports open"
