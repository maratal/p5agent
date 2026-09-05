#!/usr/bin/env bash
# certs.sh — the one place this project makes TLS certificates.
#
#   certs.sh self-signed --cert <path> --key <path> [--cn <name>] [--days <n>]
#                        [--env <file>] [--owner <user>]
#   certs.sh domain <domain>
#
# self-signed  A certificate for this host's IP — all that can be issued before
#              a name points here. An existing pair is reused, not replaced.
#              Used for the agent's own listener and for each installed app.
# domain       A Let's Encrypt certificate for a name that already points here,
#              wired into every installed app and with renewal set up. This is
#              what the agent's /certs endpoint runs.
#
#   --env      write TLS_CERT_PATH and TLS_KEY_PATH into this env file, replacing
#              any previous pair rather than appending a second one
#   --owner    the user the app runs as; it is given read access to the key
#
# Both modes end with the same two facts on stdout, so a caller that needs the
# paths can read them back instead of reconstructing them:
#
#   TLS_CERT_PATH=<path>
#   TLS_KEY_PATH=<path>
#
# Everything else — logs, progress, errors — goes to stderr.

set -uo pipefail

DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
INSTALLED="$DATA_DIR/installed_apps.json"
HOOK_DIR="/etc/letsencrypt/renewal-hooks/deploy"
HOOK="$HOOK_DIR/p5agent-restart-apps.sh"

# Group granting read access to /etc/letsencrypt. chgrp'ing to a single app user
# is enough for one app and wrong for two — the second silently loses its read.
#
# The name is a contract with anything else provisioning certificates on this
# host, not just with the apps here: ChatServer's own install.sh names the same
# group, so a standalone install and an agent-managed one can share a droplet
# without the later one taking the earlier one's access away. Do not rename it
# on one side alone.
CERT_GROUP="certaccess"

log()  { printf '→ %s\n' "$*" >&2; }
ok()   { printf '✓ %s\n' "$*" >&2; }
fail() { printf '✗ %s\n' "$*" >&2; exit 1; }
usage() { sed -n '2,25p' "$0" >&2; exit 2; }

# ── Arguments ────────────────────────────────────────────────────────────────
MODE="${1:-}"
[[ -n "$MODE" ]] || usage
shift

DOMAIN="" CERT="" KEY="" CN="" DAYS=825 ENV_FILE="" OWNER=""

case "$MODE" in
    self-signed) ;;
    domain)
        DOMAIN="${1:-}"
        [[ -n "$DOMAIN" && "$DOMAIN" != --* ]] || fail "certs.sh domain <domain>"
        shift
        ;;
    *) usage ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --cert)  CERT="${2:?--cert needs a path}"; shift 2 ;;
        --key)   KEY="${2:?--key needs a path}"; shift 2 ;;
        --cn)    CN="${2:?--cn needs a name}"; shift 2 ;;
        --days)  DAYS="${2:?--days needs a number}"; shift 2 ;;
        --env)   ENV_FILE="${2:?--env needs a path}"; shift 2 ;;
        --owner) OWNER="${2:?--owner needs a user}"; shift 2 ;;
        *) fail "Unknown option: $1" ;;
    esac
done

# ── Helpers ──────────────────────────────────────────────────────────────────

# This host's public address. The metadata service is authoritative on a
# droplet; hostname -I is the fallback anywhere else.
host_ip() {
    local ip
    ip=$(curl -s --max-time 10 http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address 2>/dev/null)
    [[ -n "$ip" ]] || ip=$(hostname -I | awk '{print $1}')
    printf '%s' "$ip"
}

# The names of the apps installed on this upplet, one per line.
installed_apps() {
    [[ -f "$INSTALLED" ]] || return 0
    python3 -c "
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
for a in apps:
    n = str(a.get('name', '')).strip()
    if n:
        print(n)
" "$INSTALLED" 2>/dev/null
}

# The user a unit runs as. The unit file is the only record of it.
app_user() {
    grep -oP '^User=\K.*' "/etc/systemd/system/${1}.service" 2>/dev/null || true
}

# Record the paths in an env file. Previous entries are removed first: appending
# blindly leaves a file that grows a pair every re-run, and while systemd takes
# the last one, the file stops being readable by a person.
write_env() {
    local file="$1" cert="$2" key="$3" owner="$4"
    [[ -n "$file" ]] || return 0
    touch "$file"
    chmod 600 "$file"
    sed -i '/^TLS_CERT_PATH=/d;/^TLS_KEY_PATH=/d' "$file"
    printf 'TLS_CERT_PATH=%s\nTLS_KEY_PATH=%s\n' "$cert" "$key" >> "$file"
    if [[ -n "$owner" ]] && id "$owner" &>/dev/null; then
        chown "${owner}:${owner}" "$file"
    fi
    ok "TLS paths written to $file"
}

# The private key lives under archive/ and live/ holds symlinks into it, so both
# directories have to be traversable by whoever runs the app.
grant_cert_access() {
    getent group "$CERT_GROUP" >/dev/null || groupadd --system "$CERT_GROUP"
    chgrp "$CERT_GROUP" /etc/letsencrypt/live /etc/letsencrypt/archive
    chmod 750 /etc/letsencrypt/live /etc/letsencrypt/archive
}

# ── self-signed ──────────────────────────────────────────────────────────────
if [[ "$MODE" == "self-signed" ]]; then
    [[ -n "$CERT" && -n "$KEY" ]] || fail "self-signed needs --cert and --key"
    mkdir -p "$(dirname "$CERT")" "$(dirname "$KEY")"

    if [[ -f "$CERT" && -f "$KEY" ]]; then
        ok "Reusing the existing certificate at $CERT"
    else
        [[ -n "$CN" ]] || CN=$(host_ip)
        [[ -n "$CN" ]] || CN="localhost"
        log "Generating a self-signed certificate for $CN"
        openssl req -x509 -newkey rsa:2048 -nodes -days "$DAYS" \
            -keyout "$KEY" -out "$CERT" \
            -subj "/CN=$CN" -addext "subjectAltName=IP:$CN" >&2 \
            || fail "Could not generate a certificate for $CN"
        ok "Self-signed certificate generated for $CN"
    fi

    if [[ -n "$OWNER" ]] && id "$OWNER" &>/dev/null; then
        chown "${OWNER}:${OWNER}" "$CERT" "$KEY"
    fi
    write_env "$ENV_FILE" "$CERT" "$KEY" "$OWNER"
    printf 'TLS_CERT_PATH=%s\nTLS_KEY_PATH=%s\n' "$CERT" "$KEY"
    exit 0
fi

# ── domain ───────────────────────────────────────────────────────────────────
# Apps are installed with a self-signed certificate for the droplet's IP. Once a
# domain points here this replaces it: certbot answers the ACME challenge on
# port 80, the paths go into each app's /etc/<name>.env, and each is restarted.
#
# Renewal is certbot's own timer. What this adds is a deploy hook, so a renewed
# certificate reaches the running apps instead of sitting on disk until someone
# notices the expiry.
#
# The agent validates the domain before running this; the check below is the
# second lock on the same door, since this also runs by hand.
DOMAIN="${DOMAIN,,}"
DOMAIN="${DOMAIN%.}"
[[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] \
    || fail "Not a valid domain name: $DOMAIN"

# Check the name points here before spending an attempt. Let's Encrypt
# rate-limits failures (5 per hour), so a typo that goes straight to certbot
# costs more than a typo caught here.
SERVER_IP=$(host_ip)
RESOLVED=$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')
[[ -n "$RESOLVED" ]] \
    || fail "$DOMAIN does not resolve. Add an A record pointing at $SERVER_IP and try again once it has propagated."
[[ " $RESOLVED " == *" $SERVER_IP "* ]] \
    || fail "$DOMAIN resolves to $RESOLVED, not to this upplet ($SERVER_IP). Point its A record here and try again."
ok "$DOMAIN resolves to this upplet ($SERVER_IP)"

if ! command -v certbot >/dev/null 2>&1; then
    log "Installing certbot"
    apt-get -qq update >/dev/null 2>&1
    apt-get -qq install -y certbot >/dev/null || fail "Could not install certbot"
fi

# The http-01 challenge is answered on port 80. firewall.sh opens it on new
# upplets; an upplet provisioned before that still has it closed, and certbot
# would fail with a timeout that says nothing about the firewall.
if command -v ufw >/dev/null 2>&1; then
    ufw allow 80/tcp comment "ACME http-01" >/dev/null 2>&1 || true
    ok "Port 80 open for the ACME challenge"
fi

# Written before the certificate is issued, so the first issue restarts the apps
# through the same path every renewal will take. It reads the installed apps at
# run time rather than baking in today's list, so an app installed later is
# picked up by the next renewal without anyone rewriting this.
mkdir -p "$HOOK_DIR"
cat > "$HOOK" <<'HOOKEOF'
#!/usr/bin/env bash
# Restart every installed app after certbot renews a certificate. Written by
# p5agent's certs.sh; edits here are lost the next time it runs.
INSTALLED="${P5AGENT_DATA_DIR:-/var/lib/p5agent}/installed_apps.json"
[[ -f "$INSTALLED" ]] || exit 0
python3 -c "
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
for a in apps:
    n = str(a.get('name', '')).strip()
    if n:
        print(n)
" "$INSTALLED" | while read -r app; do
    systemctl restart "$app" 2>/dev/null || true
done
HOOKEOF
chmod +x "$HOOK"
ok "Renewal hook installed at $HOOK"

LE_DIR="/etc/letsencrypt/live/$DOMAIN"
if [[ -d "$LE_DIR" ]]; then
    log "A certificate for $DOMAIN already exists — renewing if it is due"
    # Not --force-renewal: a certificate with weeks left is not reissued just
    # because someone clicked the menu item, and reissues count against a weekly
    # limit. Nothing to renew is a success, not a failure.
    certbot renew --cert-name "$DOMAIN" --standalone --non-interactive >&2 \
        || fail "Renewal failed for $DOMAIN"
else
    log "Requesting a certificate for $DOMAIN"
    certbot certonly --standalone --non-interactive --agree-tos \
        --register-unsafely-without-email -d "$DOMAIN" >&2 \
        || fail "Could not obtain a certificate for $DOMAIN"
    ok "Certificate obtained for $DOMAIN"
fi

CERT="$LE_DIR/fullchain.pem"
KEY="$LE_DIR/privkey.pem"
[[ -f "$CERT" && -f "$KEY" ]] || fail "certbot reported success but $LE_DIR is not readable"

grant_cert_access

# The certbot package ships a systemd timer and enables it, but an upplet where
# it was masked or never started would look fine for sixty days and then stop
# serving. Cheap to be sure.
if systemctl list-unit-files certbot.timer >/dev/null 2>&1; then
    systemctl enable --now certbot.timer >/dev/null 2>&1 \
        && ok "Renewal timer active" \
        || log "Could not enable certbot.timer — renewals will not run unattended"
fi

APPS=$(installed_apps)
if [[ -z "$APPS" ]]; then
    ok "No apps installed yet — the certificate is in place for the next one"
else
    while read -r app; do
        [[ -n "$app" ]] || continue
        owner=$(app_user "$app")
        write_env "/etc/${app}.env" "$CERT" "$KEY" "$owner"
        if [[ -n "$owner" ]] && id "$owner" &>/dev/null; then
            usermod -aG "$CERT_GROUP" "$owner" 2>/dev/null || true
        fi
        if systemctl restart "$app" >&2 2>&1; then
            ok "$app now serving $DOMAIN"
        else
            printf '✗ %s failed to restart (journalctl -u %s)\n' "$app" "$app" >&2
        fi
    done <<< "$APPS"
fi

ok "Done. $DOMAIN is live; certbot's timer handles renewal from here."
printf 'TLS_CERT_PATH=%s\nTLS_KEY_PATH=%s\n' "$CERT" "$KEY"
