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
#         SQUID_KEEP_PASSWD 1 = keep the credentials a previous run set up
#                         (its passwd file): no prompt, PROXY_USER/PROXY_PASS
#                         unused — for changing the rest (port, whitelist)
#         WHITELIST_FILE  domain list to use instead of whitelist.txt
#         SQUID_WHITELIST 0 = no domain whitelist: any destination for an
#                         authenticated user (default 1)
#         SQUID_MANAGED   1 = run by p5agent (the dashboard's Setup Squid): the
#                         firewall is p5agent's, so SSH and the agent's rules,
#                         restrictions included, are left as they are
#
# Either way the firewall ends up open on SSH, p5agent and the proxy port only:
# every other allow rule is removed. A Squid upplet has no Nginx, so p5agent's
# firewall.sh no longer counts port 80 as built-in here and keeps it closed; an
# installed app's port is still re-opened by Update Provisioning and app
# installs.

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
KEEP_PASSWD=0
if [[ "${SQUID_KEEP_PASSWD:-0}" == "1" ]]; then
    PROXY_USER="$(head -n1 "$PASSWD_FILE" 2>/dev/null | cut -d: -f1 || true)"
    [[ -n "$PROXY_USER" ]] || die "no credentials to keep: $PASSWD_FILE is missing or empty"
    KEEP_PASSWD=1
    PROXY_PASS="kept"             # not used: the passwd file stays as it is
elif [[ -z "${PROXY_USER:-}" ]]; then
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
if [[ "$KEEP_PASSWD" == "1" ]]; then
    echo "Credentials kept for user '$PROXY_USER'."
else
    printf '%s' "$PROXY_PASS" | htpasswd -i -c -B "$PASSWD_FILE" "$PROXY_USER" >/dev/null
    echo "Password file written for user '$PROXY_USER'."
fi
unset PROXY_PASS PROXY_PASS2

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

# --- Cache manager ---
# Only the upplet itself may ask Squid about its state, and only for its
# configuration (p5agent's "proxy --whitelist" reads the whitelist Squid has
# loaded from it). First, as the request is to Squid's own port on 127.0.0.1.
cachemgr_passwd none config
cachemgr_passwd disable all

# --- Access rules (first match wins) ---
http_access allow localhost manager
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
# Policy: deny all incoming except SSH, the proxy port and p5agent; allow all
# outgoing. Every other allow rule is removed.
# Set UFW_RESET=1 to wipe pre-existing ufw rules first.
echo "Configuring firewall (ufw)..."

if ! command -v ufw >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get install -y -qq ufw
    else
        die "ufw is not installed and cannot be installed automatically on this system"
    fi
fi

# Detect SSH port(s) so we never lock ourselves out (falls back to 22).
SSH_PORTS="$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' || true)"
[[ -n "$SSH_PORTS" ]] || SSH_PORTS="22"
# If this script is running over SSH, also keep the port of the current session open.
[[ -z "${SSH_CONNECTION:-}" ]] || SSH_PORTS+=$'\n'"${SSH_CONNECTION##* }"
SSH_PORTS="$(printf '%s\n' "$SSH_PORTS" | sort -un)"
AGENT_PORT_NUM="${P5AGENT_PORT%/*}"

# Remove every allow rule that opens anything but the given ports: other
# ports, port ranges that reach beyond them, and rules with no port at all
# ("allow from <ip>" opens every port to it). Rules on the kept ports stay as
# they are, address restrictions included; deny/limit/reject rules stay too.
close_other_ports() {
    python3 - "$@" <<'PY'
import re, shlex, subprocess, sys

keep = {int(p) for p in sys.argv[1:]}

def ports(spec):
    """'80', '80,443', '8000:8100' -> set of ints."""
    out = set()
    for part in spec.split(","):
        a, _, b = part.partition(":")
        out |= set(range(int(a), int(b or a) + 1))
    return out

added = subprocess.run(["ufw", "show", "added"], capture_output=True, text=True).stdout
for line in added.splitlines():
    if not line.startswith("ufw "):
        continue
    rule = re.sub(r" comment .*$", "", line[4:].strip())
    try:
        words = shlex.split(rule)                  # 'Nginx Full' is one word
    except ValueError:
        words = rule.split()
    if not words or words[0] != "allow":
        continue                                   # deny, limit, reject, route …
    spec = app = None
    if len(words) > 1 and re.fullmatch(r"[\d,:]+(/(tcp|udp))?", words[1]):
        spec = words[1].split("/")[0]
    elif "port" in words:
        spec = words[words.index("port") + 1]
    elif "app" in words:
        i = words.index("app") + 1
        app = " ".join(words[i:])
        words = words[:i] + [app]
    elif len(words) > 1 and words[1] not in ("from", "to", "in", "out", "on"):
        app = " ".join(words[1:])                  # an application profile
        words = ["allow", app]
    if app is not None and "ssh" in app.lower():
        continue                                   # OpenSSH: SSH stays reachable
    if spec is not None and ports(spec) <= keep:
        continue
    rc = subprocess.run(["ufw", "--force", "delete"] + words, capture_output=True, text=True)
    print(("Closed: %s" % rule) if rc.returncode == 0
          else "Could not close %s: %s" % (rule, (rc.stdout or rc.stderr).strip()))
PY
}

# The proxy port is opened to anyone only when it has no rule yet — one
# restricted to addresses (in Firewall Settings) stays restricted.
open_proxy_port() {
    if ufw show added | grep -Eq "allow ${PROXY_PORT}(/tcp)?( |\$)|port ${PROXY_PORT}( |\$)"; then
        echo "Port $PROXY_PORT/tcp keeps its existing rules."
    else
        ufw allow "$PROXY_PORT/tcp" comment 'squid proxy' >/dev/null
        echo "Port $PROXY_PORT/tcp is open."
    fi
}

if [[ "$MANAGED" == "1" ]]; then
    # p5agent owns this firewall (deny incoming by default, SSH and the agent
    # already allowed — maybe restricted to addresses, which a blanket allow
    # here would undo), so those rules are left alone.
    open_proxy_port
    # shellcheck disable=SC2086
    close_other_ports $SSH_PORTS "$AGENT_PORT_NUM" "$PROXY_PORT"
    echo "Open: SSH ($(echo $SSH_PORTS | tr ' ' ',')), p5agent ($AGENT_PORT_NUM), proxy ($PROXY_PORT) — every other port is closed."
    echo
    echo "Done. Squid is listening on port $PROXY_PORT."
    exit 0
fi

if [[ "${UFW_RESET:-0}" == "1" ]]; then
    ufw --force reset >/dev/null
fi

ufw default deny incoming  >/dev/null
ufw default allow outgoing >/dev/null

for port in $SSH_PORTS; do
    ufw allow "$port/tcp" comment 'ssh' >/dev/null
done
open_proxy_port
ufw allow "$P5AGENT_PORT"   comment 'p5agent'     >/dev/null
# shellcheck disable=SC2086
close_other_ports $SSH_PORTS "$AGENT_PORT_NUM" "$PROXY_PORT"

# Rules are added before enabling, so an active SSH session is not cut off.
ufw --force enable >/dev/null
ufw status verbose

echo
echo "Done. Squid is listening on port $PROXY_PORT."
echo "Allowed domains ($(wc -l < "$WHITELIST_DST")): $WHITELIST_DST"
echo "Test with:"
echo "  curl -x http://$PROXY_USER@localhost:$PROXY_PORT https://<allowed-domain>/"
