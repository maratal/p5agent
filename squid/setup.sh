#!/usr/bin/env bash
#
# setup-squid.sh - configure Squid as an authenticated, domain-whitelisted proxy.
#
# - Prompts for a username and password (basic auth)
# - Reads allowed domains from whitelist.txt located next to this script
#
# Usage:  sudo ./setup-squid.sh
# Env:    PROXY_PORT      (default 3128)
#         PROXY_USER      username — skips the prompt when set
#         PROXY_PASS      password — skips the prompt when set
#         WHITELIST_FILE  domain list to use instead of whitelist.txt
#         SQUID_WHITELIST 0 = no domain whitelist: any destination for an
#                         authenticated user (default 1)
#         SQUID_MANAGED   1 = run by p5agent (the dashboard's Setup Squid): the
#                         firewall is p5agent's, so only the proxy port is
#                         opened (and a previous proxy port closed) — SSH and
#                         the agent's rules, restrictions included, are left
#                         alone

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHITELIST_SRC="${WHITELIST_FILE:-$SCRIPT_DIR/whitelist.txt}"
USE_WHITELIST="${SQUID_WHITELIST:-1}"
MANAGED="${SQUID_MANAGED:-0}"

SQUID_DIR="/etc/squid"
SQUID_CONF="$SQUID_DIR/squid.conf"
PASSWD_FILE="$SQUID_DIR/passwd"
WHITELIST_DST="$SQUID_DIR/whitelist.txt"
PROXY_PORT="${PROXY_PORT:-3128}"

die() { echo "Error: $*" >&2; exit 1; }

# --- Preconditions ---------------------------------------------------------
[[ $EUID -eq 0 ]] || die "run as root (sudo $0)"
[[ "$PROXY_PORT" =~ ^[0-9]{1,5}$ ]] && (( PROXY_PORT >= 1 && PROXY_PORT <= 65535 )) || die "invalid proxy port: '$PROXY_PORT'"

CLEAN_WHITELIST=""
if [[ "$USE_WHITELIST" == "1" ]]; then
    [[ -f "$WHITELIST_SRC" ]] || die "whitelist not found: $WHITELIST_SRC"
    # Clean whitelist: strip CRLF, comments, blank lines, whitespace; dedupe.
    CLEAN_WHITELIST="$(sed -e 's/\r$//' -e 's/#.*$//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$WHITELIST_SRC" \
        | grep -v '^$' | sort -u || true)"
    [[ -n "$CLEAN_WHITELIST" ]] || die "whitelist has no usable entries"
fi

# The port a previous run left Squid on — its firewall rule goes if it changes.
OLD_PORT="$(awk '$1=="http_port"{print $2; exit}' "$SQUID_CONF" 2>/dev/null || true)"

# --- Install dependencies --------------------------------------------------
install_deps() {
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq
        apt-get install -y -qq squid apache2-utils
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y squid httpd-tools
    elif command -v yum >/dev/null 2>&1; then
        yum install -y squid httpd-tools
    else
        die "unsupported package manager; install squid and htpasswd manually"
    fi
}

if ! command -v squid >/dev/null 2>&1 || ! command -v htpasswd >/dev/null 2>&1; then
    echo "Installing squid and htpasswd..."
    install_deps
fi

# --- Locate basic auth helper ---------------------------------------------
AUTH_HELPER=""
for p in /usr/lib/squid/basic_ncsa_auth /usr/lib64/squid/basic_ncsa_auth \
         /usr/libexec/squid/basic_ncsa_auth; do
    [[ -x "$p" ]] && { AUTH_HELPER="$p"; break; }
done
[[ -n "$AUTH_HELPER" ]] || die "basic_ncsa_auth helper not found"

# --- Prompt for credentials ------------------------------------------------
if [[ -z "${PROXY_USER:-}" ]]; then
    read -r -p "Proxy username: " PROXY_USER
fi
[[ -n "$PROXY_USER" ]] || die "username cannot be empty"
[[ "$PROXY_USER" != *:* ]] || die "username cannot contain ':'"

if [[ -z "${PROXY_PASS:-}" ]]; then
    read -r -s -p "Proxy password: " PROXY_PASS; echo
    read -r -s -p "Confirm password: " PROXY_PASS2; echo
    [[ -n "$PROXY_PASS" ]] || die "password cannot be empty"
    [[ "$PROXY_PASS" == "$PROXY_PASS2" ]] || die "passwords do not match"
fi

# --- p5agent port (for the firewall) --------------------------------------
# Defaults to 5005/tcp; override with e.g. P5AGENT_PORT=5006/tcp in the environment.
P5AGENT_PORT="${P5AGENT_PORT:-5005/tcp}"
[[ "$P5AGENT_PORT" =~ ^[0-9]{1,5}(/(tcp|udp))?$ ]] || die "invalid p5agent port: '$P5AGENT_PORT'"
[[ "$P5AGENT_PORT" == */* ]] || P5AGENT_PORT="$P5AGENT_PORT/tcp"

# --- Write password file (password read from stdin, not visible in ps) ----
printf '%s' "$PROXY_PASS" | htpasswd -i -c -B "$PASSWD_FILE" "$PROXY_USER" >/dev/null
unset PROXY_PASS PROXY_PASS2
echo "Password file written for user '$PROXY_USER'."

# Determine the user Squid runs as
SQUID_USER="proxy"
getent passwd squid >/dev/null 2>&1 && SQUID_USER="squid"
chown "root:$SQUID_USER" "$PASSWD_FILE"
chmod 640 "$PASSWD_FILE"

# --- Install whitelist -----------------------------------------------------
if [[ "$USE_WHITELIST" == "1" ]]; then
    printf '%s\n' "$CLEAN_WHITELIST" > "$WHITELIST_DST"
    chown "root:$SQUID_USER" "$WHITELIST_DST"
    chmod 640 "$WHITELIST_DST"
    echo "Whitelist installed: $(wc -l < "$WHITELIST_DST") domain(s)."
    WHITELIST_ACL="acl whitelist dstdomain \"$WHITELIST_DST\""
    ALLOW_RULE="http_access allow authenticated whitelist"
    # Destinations given as an IP address instead of a domain name:
    #   - last label numeric (dotted IPv4, and decimal forms like 2130706433)
    #   - last label hex (0x7f000001, 127.0.0.0x1)
    #   - anything containing ':' (IPv6 literals)
    # Real domain names never have a numeric TLD, so this cannot match a valid
    # host. Whitelist mode only: for an IP-address URL that matches nothing,
    # dstdomain falls back to the IP's reverse DNS name — which whoever owns
    # the IP can set to e.g. x.github.com, and pass the whitelist with it.
    IP_DEST_ACL='acl ip_dest dstdom_regex (^|\.)[0-9]+$
acl ip_dest dstdom_regex -i (^|\.)0x[0-9a-f]+$
acl ip_dest dstdom_regex :'
    IP_DEST_DENY="http_access deny ip_dest"
else
    echo "No domain whitelist: any destination is allowed for an authenticated user."
    WHITELIST_ACL="# no domain whitelist"
    ALLOW_RULE="http_access allow authenticated"
    IP_DEST_ACL="# no whitelist: IP address destinations are allowed (except internal_dst)"
    IP_DEST_DENY="# (no ip_dest rule without a whitelist)"
fi

# --- Write squid.conf ------------------------------------------------------
if [[ -f "$SQUID_CONF" ]]; then
    BACKUP="$SQUID_CONF.bak.$(date +%Y%m%d-%H%M%S)"
    cp -p "$SQUID_CONF" "$BACKUP"
    echo "Existing config backed up to $BACKUP"
fi

cat > "$SQUID_CONF" <<EOF
# Generated by setup-squid.sh

http_port $PROXY_PORT

# --- Authentication ---
auth_param basic program $AUTH_HELPER $PASSWD_FILE
auth_param basic realm Squid Proxy
auth_param basic credentialsttl 2 hours
auth_param basic casesensitive on
acl authenticated proxy_auth REQUIRED

# --- ACLs ---
$WHITELIST_ACL
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 443
acl CONNECT method CONNECT

$IP_DEST_ACL

# Internal addresses — never through the proxy, in either mode. Matched on the
# resolved address, so a domain pointing at one (DNS rebinding included) is
# refused too: loopback, link-local (169.254.169.254 is the cloud metadata
# service, whose user-data holds the agent token), private ranges (the
# droplet's VPC), and their IPv6 counterparts.
acl internal_dst dst 0.0.0.0/8 127.0.0.0/8 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10
acl internal_dst dst ::1 fe80::/10 fc00::/7

# --- Access rules (first match wins) ---
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny manager
http_access deny internal_dst
$IP_DEST_DENY
$ALLOW_RULE
http_access deny all

# --- Privacy / hygiene ---
forwarded_for delete
via off
cache deny all
access_log stdio:/var/log/squid/access.log squid
EOF

# --- Validate and (re)start ------------------------------------------------
echo "Validating configuration..."
squid -k parse >/dev/null 2>&1 || { squid -k parse; die "squid config validation failed"; }

if command -v systemctl >/dev/null 2>&1; then
    systemctl enable squid >/dev/null 2>&1 || true
    systemctl restart squid
    systemctl --no-pager --lines=0 status squid || true
else
    service squid restart
fi

# --- Firewall (ufw) --------------------------------------------------------
# Policy: deny all incoming except SSH, the proxy port and p5agent; allow all outgoing.
# Set UFW_RESET=1 to wipe pre-existing ufw rules first (otherwise they are kept).
echo "Configuring firewall (ufw)..."

if ! command -v ufw >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y -qq ufw
    else
        die "ufw is not installed and cannot be installed automatically on this system"
    fi
fi

if [[ "$MANAGED" == "1" ]]; then
    # p5agent owns this firewall (deny incoming by default, SSH and the agent
    # already allowed — maybe restricted to addresses, which a blanket allow
    # here would undo). Only the proxy's own port changes.
    if [[ -n "$OLD_PORT" && "$OLD_PORT" != "$PROXY_PORT" ]]; then
        ufw delete allow "$OLD_PORT/tcp" >/dev/null 2>&1 && echo "Closed the previous proxy port $OLD_PORT/tcp." || true
    fi
    ufw allow "$PROXY_PORT/tcp" comment 'squid proxy' >/dev/null
    echo "Port $PROXY_PORT/tcp is open."
    echo
    echo "Done. Squid is listening on port $PROXY_PORT."
    exit 0
fi

# Detect SSH port(s) so we never lock ourselves out (falls back to 22).
SSH_PORTS="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' || true)"
[[ -n "$SSH_PORTS" ]] || SSH_PORTS="22"
# If this script is running over SSH, also keep the port of the current session open.
[[ -z "${SSH_CONNECTION:-}" ]] || SSH_PORTS+=$'\n'"${SSH_CONNECTION##* }"
SSH_PORTS="$(printf '%s\n' "$SSH_PORTS" | sort -un)"

if [[ "${UFW_RESET:-0}" == "1" ]]; then
    ufw --force reset >/dev/null
fi

ufw default deny incoming  >/dev/null
ufw default allow outgoing >/dev/null

for port in $SSH_PORTS; do
    ufw allow "$port/tcp" comment 'ssh' >/dev/null
done
ufw allow "$PROXY_PORT/tcp" comment 'squid proxy' >/dev/null
ufw allow "$P5AGENT_PORT"   comment 'p5agent'     >/dev/null

# Rules are added before enabling, so an active SSH session is not cut off.
ufw --force enable >/dev/null
ufw status verbose

echo
echo "Done. Squid is listening on port $PROXY_PORT."
echo "Allowed domains ($(wc -l < "$WHITELIST_DST")): $WHITELIST_DST"
echo "Test with:"
echo "  curl -x http://$PROXY_USER@localhost:$PROXY_PORT https://<allowed-domain>/"
