#!/usr/bin/env bash
# nginx.sh — puts Nginx in front of installed apps, or serves a static site with
# no app behind it at all (utilities/nginx/ in p5agent).
#
#   nginx.sh install|wire <name> <app-port> [--public <port>] [--domain <name>]
#                                     [--bots] [--fail2ban]
#                                     move the app to <app-port> (plain HTTP,
#                                     loopback only) and let Nginx serve its old
#                                     port over HTTPS, plus port 80. 0 picks the
#                                     port: the app's current private one on a
#                                     re-wire, else the first free from 5656.
#                                     --public: the port Nginx serves the app on
#                                     instead (the old one is closed); left out,
#                                     it stays where it is
#                                     --domain: the name Nginx serves the app
#                                     for (its server_name), so several apps
#                                     share one port — see "Several sites on
#                                     one port" below. "" takes it away; left
#                                     out, the app keeps the one it has
#                                     --bots / --fail2ban: see "Bot protection"
#                                     below; leaving a flag out on a re-run
#                                     turns that protection off again
#   nginx.sh install sites [--public <port>] [--bots] [--fail2ban]
#                          [--static <domain>] <name>:<app-port>[:<domain>] …
#                                     the same for several apps at once, all
#                                     on one public port (each keeps its own
#                                     when --public is left out), each with
#                                     its own domain — what the dashboard's
#                                     Install / Setup Nginx send. --static:
#                                     the static site too, on the same port
#                                     ("" for no domain: the default)
#   nginx.sh static [port] [--domain <name>]
#                                     no app in front: Nginx serves the files in
#                                     /var/www/html over HTTPS on [port] (443 by
#                                     default), plus port 80. A directory is
#                                     served through its index.html, index.htm
#                                     or main.html, in that order. An empty one
#                                     gets a placeholder page; the dashboard's
#                                     attach (the agent's /static-site) fills it
#   nginx.sh certs <cert> <key>       point the sites the certificate is for at
#                                     it (by domain; the sites without one when
#                                     it is for none of them) and reload (run
#                                     by certs.sh)
#   nginx.sh unwire <name>            drop the app's Nginx site (run by uninstall)
#   nginx.sh start | stop             the service (its card's Start / Stop)
#   nginx.sh update                   upgrade the package, check the config, restart
#   nginx.sh remove                   take Nginx away (the dashboard's Uninstall on
#                                     its card): every app behind it serves itself
#                                     again — HTTPS on the port Nginx served it on
#                                     (apps that shared a port by domain: the one
#                                     without a domain keeps it, the others take
#                                     their private port), with the certificate
#                                     Nginx used — then Nginx is stopped, disabled
#                                     and its package removed (its config and
#                                     /etc/nginx/p5 certificates stay)
#
# The layout it builds is the usual one:
#
#   :80    /.well-known/acme-challenge/ from $WEBROOT (certbot --webroot), and a
#          redirect to https for everything else
#   :<p>   TLS with the app's certificate, proxied to http://127.0.0.1:<app-port>
#   :<p>   TLS serving $SITE_ROOT from disk, for the static site
#
# The app's installed_apps.json entry keeps its new private port as "port" and
# gains "public-port" — the port Nginx serves it on, which is what the dashboard
# links to and what firewall.sh opens — and "nginx-domain" when it has one. The
# app's own port stays closed.
#
# Several sites on one port: a site with a domain answers only for that name
# (server_name), so any number of them share a port — 443 for all of them is
# the usual layout. On each port, the one site without a domain (if any) is
# the default_server: it answers for an IP, and for any name no other site
# claims. Two sites without a domain, or two for the same name, can't share a
# port; that is checked before anything changes. A certificate goes to the
# sites whose name it is for (nginx.sh certs).
#
# Wiring is all-or-nothing: the app's unit, env file and entry are saved first,
# and put back if Nginx does not come up.
#
# Bot protection — per app, recorded in its entry as "nginx-bots" and
# "nginx-fail2ban", and rebuilt from those records on every run, so a flag
# left out is protection taken away:
#
#   --bots       rate limit (10 req/s per IP, bursts of 40 → 429), scanner
#                probes (/.env, /.git, /wp-admin, …) and self-declared
#                crawlers/scanners (GPTBot, AhrefsBot, sqlmap, …) closed
#                unanswered (444). The dashboard's IP and this host are exempt.
#   --fail2ban   (needs --bots) ban an IP for an hour after 20 of those
#                429/444 answers in a minute.
#
# The shared pieces — conf.d/p5-bots.conf, snippets/p5-bots.conf and the
# fail2ban jail — exist only while some app uses them.

set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"     # the agent's checkout: certs.sh, firewall.sh
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
INSTALLED="$DATA_DIR/installed_apps.json"
AGENT_PORT="${P5AGENT_PORT:-5005}"
[[ -f /etc/p5agent.env ]] && AGENT_PORT="$(sed -n 's/^P5AGENT_PORT=//p' /etc/p5agent.env | head -n1)" && AGENT_PORT="${AGENT_PORT:-5005}"

WEBROOT="/var/www/p5-acme"
SITE_ROOT="/var/www/html"                          # the static site's files
SITES="/etc/nginx/sites-available"
ENABLED="/etc/nginx/sites-enabled"
ACME_SITE="p5-acme.conf"
STATIC_SITE="p5-static.conf"
STATIC_PORT=443                                    # where the static site is served
CERT_DIR="/etc/nginx/p5"
BOTS_HTTP="/etc/nginx/conf.d/p5-bots.conf"         # http{} level: zones and maps
BOTS_SNIPPET="/etc/nginx/snippets/p5-bots.conf"    # included by an app's server{}
JAIL="/etc/fail2ban/jail.d/p5-nginx.conf"
JAIL_FILTER="/etc/fail2ban/filter.d/p5-nginx.conf"

# Bot protection settings — one place, read by the configs below and by
# show_bot_settings, so what the log says is what Nginx and fail2ban apply.
BOT_RATE=10                 # requests per second per IP, sustained
BOT_BURST=40                # extra requests let through at once (a page load)
BOT_PATHS="wp-admin wp-login.php wp-content wp-includes xmlrpc.php phpmyadmin pma myadmin cgi-bin vendor/phpunit boaform hnap1"
BOT_DOTFILES="env git svn hg aws htaccess htpasswd ds_store"
BOT_AGENTS="gptbot chatgpt-user claudebot anthropic-ai ccbot bytespider perplexitybot amazonbot google-extended meta-externalagent ahrefsbot semrushbot mj12bot dotbot petalbot blexbot dataforseobot masscan zgrab nikto sqlmap nmap nuclei wpscan dirbuster gobuster ffuf"
F2B_MAXRETRY=20             # refused requests (429/444) ...
F2B_FINDTIME=60             # ... within this many seconds ...
F2B_BANTIME=3600            # ... ban the IP for this many seconds

# a|b|c from a space-separated list, regex-escaping dots.
alt() { local x; x=$(printf '%s' "$*" | sed 's/\./\\./g'); printf '%s' "${x// /|}"; }

# The dashboard's address(es): its probes must never be limited or banned.
TRUSTED_IPS="127.0.0.1 ::1"
if [[ -f /etc/p5agent.env ]]; then
    TRUSTED_IPS="$TRUSTED_IPS $(sed -n 's/^P5AGENT_ALLOW_IP=//p' /etc/p5agent.env | head -n1 | tr ',' ' ')"
fi

log()  { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()   { printf '✓ %s\n' "$*"; }                       # a step done: plain
done_() { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }        # the outcome: green
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*"; exit 1; }

[[ "$(id -u)" -eq 0 ]] || fail "nginx.sh must be run as root"

site_of() { printf 'p5-app-%s.conf' "$1"; }

# Every p5 site that serves TLS: the apps' and the static one.
tls_sites() {
    local f
    for f in "$SITES"/p5-app-*.conf "$SITES/$STATIC_SITE"; do [[ -f "$f" ]] && printf '%s\n' "$f"; done
}

# The port the static site is served on, empty when there is no static site.
static_port() {
    [[ -f "$SITES/$STATIC_SITE" ]] || return 0
    sed -n 's/^\s*listen \([0-9]\+\) ssl.*/\1/p' "$SITES/$STATIC_SITE" | head -1
}

# The IPv6 twin of a listen line — only where the kernel has IPv6, since Nginx
# refuses to start on a [::] socket it cannot open.
listen6() { [[ -f /proc/net/if_inet6 ]] && printf '    listen [::]:%s;' "$1"; }

# A site's server_name — empty for the catch-all "_".
site_domain() {
    [[ -f "$1" ]] || return 0
    sed -n 's/^\s*server_name \([^;]*\);/\1/p' "$1" | head -1 | sed 's/^_$//'
}
static_domain() { site_domain "$SITES/$STATIC_SITE"; }

# A host name Nginx can serve: letters, digits and hyphens in dot-separated
# labels, at least two of them. Lowercase only (the callers lowercase first).
DOMAIN_RE='^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]([a-z0-9-]*[a-z0-9])?$'
check_domain() {
    [[ -z "$1" ]] && return 0
    [[ ${#1} -le 253 && "$1" =~ $DOMAIN_RE ]] || fail "Not a domain name: $1"
}

# The listen options of a site: the one without a domain is its port's
# default_server — what answers for an IP, or a name no other site there has.
listen_opts() { printf '%s ssl%s' "$1" "$([[ -z "$2" ]] && printf ' default_server')"; }

# How a site on a shared port is told apart, for messages.
for_whom() { if [[ -n "$1" ]]; then printf 'for %s' "$1"; else printf 'as its default site (no domain)'; fi; }

# What keeps a site for <domain> off <port>: an app listening there itself,
# an app's private port, or a site Nginx serves there for the same name
# (no domain counts as one name: the port's default). Prints who, or nothing.
# <self>: the app being set up — or "static" — which never stands in its own way.
port_holder() {
    local port="$1" domain="${2,,}" self="$3" n p pub d
    while IFS=$'\t' read -r n p pub d; do
        [[ -n "$n" && "$n" != "$self" ]] || continue
        if [[ "$p" == "$port" ]]; then printf '%s' "$n"; return; fi
        if [[ "$pub" == "$port" && "$d" == "$domain" ]]; then printf '%s' "$n"; return; fi
    done <<< "$(apps_table)"
    if [[ "$self" != static && "$(static_port)" == "$port" && "$(static_domain)" == "$domain" ]]; then
        printf 'the static site'
    fi
}

# Whether anything but <self> is served on <port> — before closing it.
port_used_by_others() {  # port_used_by_others <port> <self>
    local n p pub d
    while IFS=$'\t' read -r n p pub d; do
        [[ -n "$n" && "$n" != "$2" ]] || continue
        [[ "$p" == "$1" || "$pub" == "$1" ]] && return 0
    done <<< "$(apps_table)"
    [[ "$2" != static && "$(static_port)" == "$1" ]]
}

# The process listening on a port, or nothing.
listener_on() {
    ss -ltnpH "sport = :$1" 2>/dev/null | grep -o 'users:(("[^"]*"' | head -1 | sed 's/^users:(("//; s/"$//'
}

# The HTTP status https://<domain or 127.0.0.1>:<port>/ answers with from
# here — by name when there is one, so Nginx picks that site.
probe() {  # probe <port> [domain]
    local port="$1" domain="${2:-}"
    if [[ -n "$domain" ]]; then
        curl --noproxy '*' -sk -o /dev/null -w '%{http_code}' --max-time 5 --resolve "$domain:$port:127.0.0.1" \
            "https://$domain:$port/" 2>/dev/null
    else
        curl --noproxy '*' -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:$port/" 2>/dev/null
    fi
}

# The names a certificate is for (its subjectAltName DNS entries), lowercased;
# for a Let's Encrypt one openssl can't read, the name of its live/ directory.
cert_names() {
    local names
    names=$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null \
        | tr ',' '\n' | sed -n 's/^\s*DNS:\(.*\)$/\1/p' | tr 'A-Z' 'a-z')
    if [[ -z "$names" && "$1" == /etc/letsencrypt/live/*/* ]]; then
        names="$(basename "$(dirname "$1")")"
    fi
    printf '%s' "$names"
}

# Whether one of <names> (cert_names) covers <domain>, a wildcard one label deep.
cert_covers() {
    local n base
    while IFS= read -r n; do
        [[ -n "$n" ]] || continue
        [[ "$n" == "$2" ]] && return 0
        if [[ "$n" == '*.'* ]]; then
            base="${n#\*.}"
            [[ "$2" == *".$base" && "${2%".$base"}" != *.* ]] && return 0
        fi
    done <<< "$1"
    return 1
}

# The Let's Encrypt certificate for a name, when certs.sh has obtained one:
# "<cert>\t<key>", or nothing.
le_cert_for() {
    local dir="/etc/letsencrypt/live/$1"
    [[ -n "$1" && -f "$dir/fullchain.pem" && -f "$dir/privkey.pem" ]] && printf '%s\t%s' "$dir/fullchain.pem" "$dir/privkey.pem"
}

# Every app's name, port, public-port (empty when not behind Nginx) and Nginx
# domain (empty when none), tab-separated.
apps_table() {
    python3 - "$INSTALLED" <<'PY'
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
for a in apps:
    print("%s\t%s\t%s\t%s" % (a.get("name", ""), a.get("port", "") or "443", a.get("public-port", ""),
                            str(a.get("nginx-domain") or "").lower()))
PY
}

# Whether any app has <field> set, with <name>'s value replaced by <value>
# (1, 0, or "drop" for an app on its way out). Prints 1 or 0.
any_app_flag() {
    python3 - "$INSTALLED" "$1" "${2:-}" "${3:-}" <<'PY'
import json, sys
path, field, name, value = sys.argv[1:5]
try:
    apps = json.load(open(path))
except Exception:
    apps = []
flags = {a.get("name"): bool(a.get(field)) for a in apps if a.get("public-port")}
if name:
    if value == "drop":
        flags.pop(name, None)
    else:
        flags[name] = value == "1"
print(1 if any(flags.values()) else 0)
PY
}

# The http-level half of bot protection, present while any app uses it (an
# app's site that includes the snippet needs these zones and maps to exist).
sync_bots_conf() {  # sync_bots_conf [<name> <1|0|drop>]
    if [[ "$(any_app_flag nginx-bots "${1:-}" "${2:-}")" != 1 ]]; then
        rm -f "$BOTS_HTTP" "$BOTS_SNIPPET"
        return 0
    fi
    local ip geo=""
    for ip in $TRUSTED_IPS; do geo+="    $ip 1;"$'\n'; done
    cat > "$BOTS_HTTP" <<CONF
# Written by p5agent's nginx.sh (bot protection) — edits here are lost.
geo \$p5_trusted {
    default 0;
$geo}
# Trusted clients get an empty key, which limit_req does not count.
map \$p5_trusted \$p5_limit_key {
    1 "";
    default \$binary_remote_addr;
}
limit_req_zone \$p5_limit_key zone=p5_req:10m rate=${BOT_RATE}r/s;
# Crawlers and scanners that say what they are. Browsers, apps and plain
# HTTP libraries are not on it.
map "\$p5_trusted:\$http_user_agent" \$p5_bad_agent {
    default 0;
    "~^1:" 0;
    "~*($(alt $BOT_AGENTS))" 1;
}
CONF
    mkdir -p "$(dirname "$BOTS_SNIPPET")"
    cat > "$BOTS_SNIPPET" <<CONF
# Written by p5agent's nginx.sh (bot protection) — edits here are lost.
limit_req zone=p5_req burst=$BOT_BURST nodelay;
limit_req_status 429;
if (\$p5_bad_agent) { return 444; }
# What scanners try on every host: secrets, VCS folders, WordPress, admin kits.
location ~* (^/($(alt $BOT_PATHS))|/\.($(alt $BOT_DOTFILES))) {
    return 444;
}
CONF
}

# The fail2ban jail, present while any app asks for it. The package stays once
# installed; only the jail comes and goes.
sync_fail2ban() {  # sync_fail2ban [<name> <1|0|drop>]
    if [[ "$(any_app_flag nginx-fail2ban "${1:-}" "${2:-}")" != 1 ]]; then
        if [[ -f "$JAIL" ]]; then
            rm -f "$JAIL" "$JAIL_FILTER"
            systemctl reload fail2ban 2>/dev/null || systemctl restart fail2ban 2>/dev/null || true
            ok "fail2ban off — the p5-nginx jail is removed"
        else
            ok "fail2ban off — no IPs are banned"
        fi
        return 0
    fi
    if ! command -v fail2ban-client >/dev/null 2>&1; then
        log "Installing fail2ban"
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -qq install -y fail2ban || true
        command -v fail2ban-client >/dev/null 2>&1 || { warn "fail2ban did not install — no bans"; return 0; }
    fi
    cat > "$JAIL_FILTER" <<'CONF'
# Written by p5agent's nginx.sh — requests Nginx refused as a bot (444) or
# rate-limited (429), from its combined access log (fail2ban removes the
# [timestamp] before matching, so the pattern skips over where it was).
[Definition]
failregex = ^<HOST> \S+ \S+ .*?"[^"]*" (?:444|429) 
ignoreregex =
CONF
    cat > "$JAIL" <<CONF
# Written by p5agent's nginx.sh — edits here are lost.
[p5-nginx]
enabled  = true
filter   = p5-nginx
logpath  = /var/log/nginx/access.log
backend  = auto
maxretry = $F2B_MAXRETRY
findtime = $F2B_FINDTIME
bantime  = $F2B_BANTIME
ignoreip = $TRUSTED_IPS
CONF
    systemctl enable fail2ban >/dev/null 2>&1 || true
    if fail2ban-client -t >/dev/null 2>&1; then
        systemctl restart fail2ban 2>/dev/null || true
        ok "fail2ban on — jail p5-nginx, reading /var/log/nginx/access.log:"
        detail "Ban:        an IP for ${F2B_BANTIME}s after $F2B_MAXRETRY refused requests (429/444) within ${F2B_FINDTIME}s"
        detail "Never ban:  $TRUSTED_IPS"
    else
        fail2ban-client -t 2>&1 | tail -5
        rm -f "$JAIL" "$JAIL_FILTER"
        warn "fail2ban rejected the jail — left off"
    fi
}

detail() { printf '    %s\n' "$*"; }

# Everything bot protection does, as configured — printed on every run.
show_bot_settings() {
    ok "Bot protection on — $SITES/$(site_of "$1") includes $BOTS_SNIPPET:"
    detail "Rate limit: $BOT_RATE requests/s per IP, bursts of $BOT_BURST; over it → 429"
    detail "Paths closed unanswered (444): $(printf '/%s ' $BOT_PATHS)"
    detail "Dotfiles closed unanswered (444): $(printf '/.%s ' $BOT_DOTFILES)"
    detail "User agents closed unanswered (444): ${BOT_AGENTS// /, }"
    detail "Exempt from rate limit and agent list: $TRUSTED_IPS"
}

reload_nginx() {
    nginx -t >/dev/null 2>&1 || { nginx -t; return 1; }
    systemctl reload nginx 2>/dev/null || systemctl restart nginx
}

# Port 80: ACME challenges for certbot, and a redirect to https — only when
# something is served on 443 (otherwise there is nowhere sensible to send it).
write_acme_site() {
    local redirect='return 404;'
    if tls_sites | xargs -r grep -qsE '^\s*listen 443 ssl'; then
        redirect='return 301 https://$host$request_uri;'
    fi
    mkdir -p "$WEBROOT"
    cat > "$SITES/$ACME_SITE" <<CONF
# Written by p5agent's nginx.sh — edits here are lost the next time it runs.
server {
    listen 80 default_server;
$(listen6 "80 default_server")
    server_name _;
    location ^~ /.well-known/acme-challenge/ {
        root $WEBROOT;
        default_type text/plain;
    }
    location / {
        $redirect
    }
}
CONF
    ln -sf "$SITES/$ACME_SITE" "$ENABLED/$ACME_SITE"
}

# A Let's Encrypt certificate's renewal is recorded with how it was obtained.
# certs.sh used --standalone, which needs port 80 free — Nginx holds it now, so
# the renewal is switched to answer from the webroot Nginx serves.
switch_renewal_to_webroot() {
    local cert="$1" name conf
    [[ "$cert" == /etc/letsencrypt/live/*/* ]] || return 0
    name="$(basename "$(dirname "$cert")")"
    conf="/etc/letsencrypt/renewal/$name.conf"
    [[ -f "$conf" ]] || return 0
    python3 - "$conf" "$name" "$WEBROOT" <<'PY' && ok "Renewal of $name now answers through Nginx ($WEBROOT)"
import sys
path, name, webroot = sys.argv[1:4]
lines = open(path).read().splitlines()
out, skip = [], False
for line in lines:
    s = line.strip()
    if s.startswith("[[webroot_map]]"):
        skip = True
        continue
    if skip and s.startswith("["):
        skip = False
    if skip:
        continue
    if s.startswith("authenticator") or s.startswith("webroot_path"):
        continue
    out.append(line)
    if s == "[renewalparams]":
        out.append("authenticator = webroot")
        out.append("webroot_path = %s," % webroot)
# [[webroot_map]] belongs to [renewalparams]; certbot writes that section last.
out += ["[[webroot_map]]", "%s = %s" % (name, webroot)]
open(path, "w").write("\n".join(out) + "\n")
PY
}

# policy-rc.d answering 101 ("action forbidden") keeps packages from starting
# their services while they install. Only a file this script wrote is removed.
POLICY_RC=/usr/sbin/policy-rc.d
POLICY_MARK="# p5agent nginx.sh — services start after install"
no_service_starts() {
    [[ -e "$POLICY_RC" ]] && return 0          # someone else's: leave it be
    printf '#!/bin/sh\n%s\nexit 101\n' "$POLICY_MARK" > "$POLICY_RC"
    chmod 755 "$POLICY_RC"
    trap allow_service_starts EXIT
}
allow_service_starts() {
    grep -qsF "$POLICY_MARK" "$POLICY_RC" && rm -f "$POLICY_RC"
    return 0
}

# Port 80 is Nginx's or nobody's — anything else on it would only show up
# later, as Nginx failing to start.
port80_free() {
    local holder; holder=$(listener_on 80)
    [[ -z "$holder" || "$holder" == nginx ]] \
        || fail "Port 80 is held by $holder — Nginx needs it for certificates and the redirect to HTTPS. Stop $holder or move it off port 80 first"
}

install_nginx() {
    # Nginx needs port 80 (certificates, the redirect). Said before apt runs:
    # the package's own first start on 80 would fail and leave apt broken.
    port80_free
    # A package left half-configured by an earlier run: finish it first.
    if command -v dpkg >/dev/null 2>&1 && dpkg --audit 2>/dev/null | grep -q .; then
        log "Finishing an interrupted package install first"
        no_service_starts
        dpkg --configure -a 2>&1 | tail -n 20
        apt-get -o DPkg::Lock::Timeout=120 -qq -f install -y || warn "apt could not fix the broken packages (above)"
        allow_service_starts
    fi
    if command -v nginx >/dev/null 2>&1; then
        ok "Nginx is installed ($(nginx -v 2>&1 | sed 's/^.*: //'))"
    else
        log "Installing Nginx"
        export DEBIAN_FRONTEND=noninteractive
        # apt's own messages stay in the output (quiet: errors and warnings
        # only) — when it fails, they are the reason, and the install's log
        # is where anyone will look for it.
        apt-get -o DPkg::Lock::Timeout=120 -qq update || warn "The package lists could not be refreshed"
        # The package would start Nginx on port 80 with its stock site. When
        # that start fails (80 taken), dpkg leaves the package half-configured
        # and every later apt run stops at "Unmet dependencies". So services
        # are kept from starting while it installs (policy-rc.d); this script
        # starts Nginx itself once its own sites are written.
        no_service_starts
        if ! apt-get -o DPkg::Lock::Timeout=120 -qq install -y nginx; then
            # A half-done install from before (this one's or another's) is what
            # usually stands in the way: finish it, then try again.
            warn "apt could not install nginx — finishing interrupted installs and fixing dependencies, then trying again"
            dpkg --configure -a 2>&1 | tail -n 20
            apt-get -o DPkg::Lock::Timeout=120 -qq -f install -y || true
            if ! apt-get -o DPkg::Lock::Timeout=120 -qq install -y nginx; then
                # -qq says that something is broken, not what: name it.
                warn "apt reported a problem installing nginx (above). What apt finds broken:"
                apt-get check 2>&1 | grep -v '^Reading\|^Building' | tail -n 20
                dpkg --audit 2>&1 | tail -n 20
            fi
        fi
        allow_service_starts
        command -v nginx >/dev/null 2>&1 || fail "Nginx did not install — apt's messages above say why"
        ok "Nginx installed"
    fi
    rm -f "$ENABLED/default"
    cat > /etc/nginx/conf.d/p5-upgrade.conf <<'CONF'
# WebSocket upgrades for the p5 app sites (a map may be declared only once).
map $http_upgrade $connection_upgrade { default upgrade; '' close; }
CONF
}

# The port for "0": on a re-wire the app keeps its private port; otherwise the
# first from 5656 that no app holds and nothing is listening on.
pick_port() {
    local name="$1" cur_port="$2" public="$3" p
    if [[ -n "$public" && "$cur_port" =~ ^[0-9]+$ ]] && (( cur_port >= 1024 )); then
        printf '%s' "$cur_port"; return
    fi
    local held; held=$(apps_table | awk -F'\t' '{print $2; if ($3 != "") print $3}')
    for (( p = 5656; p <= 65535; p++ )); do
        (( p == AGENT_PORT )) && continue
        grep -qxF "$p" <<< "$held" && continue
        ss -ltnH "sport = :$p" 2>/dev/null | grep -q . && continue
        printf '%s' "$p"; return
    done
}

# ── wire ─────────────────────────────────────────────────────────────────────
do_wire() {
    # domain: "-" keeps the one the app has (a caller from before domains).
    local name="$1" new_port="$2" bots="$3" f2b="$4" new_public="${5:-}" domain="${6--}"
    [[ "$bots" == 1 || "$f2b" != 1 ]] || fail "fail2ban bans what bot protection refuses — turn bot protection on too"
    local row cur_port public cur_domain
    row=$(apps_table | awk -F'\t' -v n="$name" '$1 == n')
    [[ -n "$row" ]] || fail "No installed app named '$name'"
    IFS=$'\t' read -r _ cur_port public cur_domain <<< "$row"
    [[ "$domain" == - ]] && domain="$cur_domain"
    domain="${domain,,}"
    check_domain "$domain"

    if [[ "$new_port" == 0 ]]; then
        new_port=$(pick_port "$name" "$cur_port" "$public")
        [[ -n "$new_port" ]] || fail "Could not find a free port for $name"
        ok "Picked port $new_port for $name"
    fi
    public="${public:-$cur_port}"
    # The port Nginx serves the app on: where it is now (the app's own port on a
    # first wire), or the one asked for — the old one is closed afterwards.
    local old_public="$public"
    if [[ -n "$new_public" ]]; then
        [[ "$new_public" =~ ^[0-9]+$ ]] && (( new_public >= 1 && new_public <= 65535 )) \
            || fail "The public port must be a number from 1 to 65535"
        public="$new_public"
    fi
    [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1024 && new_port <= 65535 )) \
        || fail "The app's new port must be a number from 1024 to 65535 (or 0 to pick one)"
    (( new_port != AGENT_PORT )) || fail "Port $new_port is the agent's"
    [[ "$public" != 80 ]] || fail "Port 80 is Nginx's own (certificates, the redirect to HTTPS) — pick another public port"
    (( public != AGENT_PORT )) || fail "Port $public is the agent's"
    (( new_port != public )) || fail "The app's new port must differ from the port Nginx takes ($public)"

    # The private port: no other app's, privately or through Nginx.
    local clash holder
    clash=$(apps_table | awk -F'\t' -v n="$name" -v p="$new_port" '$1 != n && ($2 == p || $3 == p) {print $1}' | head -1)
    [[ -z "$clash" ]] || fail "Port $new_port is already used by $clash"
    [[ "$new_port" != "$(static_port)" ]] || fail "Port $new_port serves the static site"
    # The public port: shared only by sites Nginx tells apart by name.
    clash=$(port_holder "$public" "$domain" "$name")
    [[ -z "$clash" ]] || fail "Port $public already serves $clash $(for_whom "$domain") — give $name another domain or public port"
    # Free, unless it is this app's own port (which it is leaving) or Nginx's
    # (another site there, told apart by name).
    if [[ "$public" != "$cur_port" ]]; then
        holder=$(listener_on "$public")
        [[ -z "$holder" || "$holder" == nginx ]] || fail "Something is already listening on port $public ($holder)"
    fi
    if [[ "$new_port" != "$cur_port" ]] && ss -ltnH "sport = :$new_port" 2>/dev/null | grep -q .; then
        fail "Something is already listening on port $new_port"
    fi

    local unit="/etc/systemd/system/${name}.service" env="/etc/${name}.env"
    [[ -f "$unit" ]] || fail "$unit not found"

    log "Nginx will serve $name on $public (HTTPS)${domain:+ for $domain} and 80; $name moves to 127.0.0.1:$new_port (HTTP)"
    install_nginx

    # The certificate: Let's Encrypt's for the app's domain when certs.sh has
    # one; else the one the app serves now, which becomes Nginx's. A re-wire
    # finds it in the app's existing site instead; with neither, a self-signed
    # one is made.
    local cert="" key="" le
    le=$(le_cert_for "$domain")
    [[ -n "$le" ]] && IFS=$'\t' read -r cert key <<< "$le"
    if [[ -z "$cert" && -f "$env" ]]; then
        cert=$(sed -n 's/^TLS_CERT_PATH=//p' "$env" | tail -1)
        key=$(sed -n 's/^TLS_KEY_PATH=//p' "$env" | tail -1)
    fi
    if [[ -z "$cert" || -z "$key" ]] && [[ -f "$SITES/$(site_of "$name")" ]]; then
        cert=$(sed -n 's/^\s*ssl_certificate \(.*\);/\1/p' "$SITES/$(site_of "$name")" | head -1)
        key=$(sed -n 's/^\s*ssl_certificate_key \(.*\);/\1/p' "$SITES/$(site_of "$name")" | head -1)
    fi
    if [[ -z "$cert" || -z "$key" || ! -f "$cert" || ! -f "$key" ]]; then
        log "No certificate on record for $name — making a self-signed one"
        out=$(bash "$ROOT/certs.sh" self-signed --cert "$CERT_DIR/$name.crt" --key "$CERT_DIR/$name.key" 2>&1) \
            || { printf '%s\n' "$out"; fail "Could not make a certificate"; }
        cert="$CERT_DIR/$name.crt"; key="$CERT_DIR/$name.key"
    fi
    ok "Certificate: $cert"
    if [[ -n "$domain" ]] && ! cert_covers "$(cert_names "$cert")" "$domain"; then
        warn "That certificate is not for $domain — browsers will warn until Update Certificates gets one for it"
    fi

    # Save what is about to change, so a failure can put it all back.
    local bak; bak=$(mktemp -d /tmp/p5-nginx-XXXXXX)
    cp -a "$unit" "$bak/unit"
    [[ -f "$env" ]] && cp -a "$env" "$bak/env"
    cp -a "$INSTALLED" "$bak/installed.json"
    [[ -f "$SITES/$(site_of "$name")" ]] && cp -a "$SITES/$(site_of "$name")" "$bak/site"

    log "Writing $SITES/$(site_of "$name")"
    cat > "$SITES/$(site_of "$name")" <<CONF
# Written by p5agent's nginx.sh for $name — edits here are lost the next time it runs.
server {
    listen $(listen_opts "$public" "$domain");
$(listen6 "$(listen_opts "$public" "$domain")")
    server_name ${domain:-_};
    ssl_certificate $cert;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 100m;
$([[ "$bots" == 1 ]] && printf '    include %s;' "$BOTS_SNIPPET")
    location / {
        proxy_pass http://127.0.0.1:$new_port;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$connection_upgrade;
        proxy_read_timeout 300s;
    }
}
CONF
    ln -sf "$SITES/$(site_of "$name")" "$ENABLED/$(site_of "$name")"
    sync_bots_conf "$name" "$bots"
    write_acme_site
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t
        restore "$name" "$bak"
        fail "The Nginx configuration did not check out — nothing was changed"
    fi
    ok "Nginx configuration checks out"

    log "Moving $name to 127.0.0.1:$new_port over plain HTTP"
    systemctl stop "$name" 2>/dev/null || true
    # The port and the bind address, wherever the unit spells them: the p5agent
    # builders use PORT/HOST, an app's own installer may pass --port/--hostname.
    sed -i -E \
        -e "s/^Environment=PORT=.*/Environment=PORT=$new_port/" \
        -e "s/^Environment=HOST=.*/Environment=HOST=127.0.0.1/" \
        -e "/^ExecStart=/ s/--port[= ][0-9]+/--port $new_port/" \
        -e "/^ExecStart=/ s/--hostname[= ][^ ]+/--hostname 127.0.0.1/" \
        "$unit"
    if [[ -f "$env" ]]; then
        # Without a certificate the app serves HTTP; Nginx does TLS for it now.
        # The env file overrides the unit's Environment=, so PORT/HOST go here too.
        sed -i '/^TLS_CERT_PATH=/d;/^TLS_KEY_PATH=/d;/^PORT=/d;/^HOST=/d' "$env"
    else
        touch "$env"; chmod 600 "$env"
    fi
    printf 'PORT=%s\nHOST=127.0.0.1\n' "$new_port" >> "$env"
    python3 - "$INSTALLED" "$name" "$new_port" "$public" "$bots" "$f2b" "$domain" <<'PY'
import json, sys
path, name, port, public, bots, f2b, domain = sys.argv[1:8]
apps = json.load(open(path))
for a in apps:
    if a.get("name") == name:
        a["port"] = port
        a["public-port"] = public
        a["nginx-bots"] = bots == "1"
        a["nginx-fail2ban"] = f2b == "1"
        if domain:
            a["nginx-domain"] = domain
        else:
            a.pop("nginx-domain", None)
json.dump(apps, open(path, "w"), indent=2)
PY
    systemctl daemon-reload
    systemctl start "$name" || true

    local up=""
    for _ in $(seq 1 30); do
        if curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$new_port/"; then up=1; break; fi
        sleep 1
    done
    if [[ -z "$up" ]]; then
        journalctl -u "$name" -n 15 --no-pager 2>/dev/null
        restore "$name" "$bak"
        fail "$name did not answer on http://127.0.0.1:$new_port — everything was put back as it was"
    fi
    ok "$name answers on http://127.0.0.1:$new_port"

    log "Starting Nginx"
    systemctl enable nginx >/dev/null 2>&1 || true
    if ! systemctl restart nginx; then
        journalctl -u nginx -n 15 --no-pager 2>/dev/null
        restore "$name" "$bak"
        fail "Nginx did not start — everything was put back as it was"
    fi
    ok "Nginx serves $name on port $public $(for_whom "$domain")"

    # The entry now has public-port: firewall.sh opens it and 80 if they have no
    # rule yet (a restriction from Firewall Settings stays), and the private
    # port is closed outright.
    if command -v ufw >/dev/null 2>&1; then
        bash "$ROOT/firewall.sh" >/dev/null 2>&1 || true
        bash "$ROOT/firewall.sh" --close "$new_port/tcp" >/dev/null 2>&1 || true
        ok "Firewall: $public and 80 open, $new_port closed"
        # The port it leaves stays open while another site is served there.
        if [[ "$old_public" != "$public" && "$old_public" != "$new_port" ]]; then
            if port_used_by_others "$old_public" "$name"; then
                ok "Firewall: $old_public stays open — other sites are served there"
            else
                bash "$ROOT/firewall.sh" --close "$old_public/tcp" >/dev/null 2>&1 || true
                ok "Firewall: $old_public closed — $name is served on $public now"
            fi
        fi
    fi

    switch_renewal_to_webroot "$cert"
    rm -rf "$bak"

    if [[ "$bots" == 1 ]]; then
        show_bot_settings "$name"
    else
        ok "Bot protection off — no rate limit, no paths or agents refused"
    fi
    sync_fail2ban

    # Through Nginx to the app, not just to Nginx: any answer counts except
    # the 502/503/504 Nginx gives when it cannot reach the app behind it.
    local code=""
    for _ in $(seq 1 5); do
        code=$(probe "$public" "$domain")
        [[ "$code" =~ ^[1-4][0-9][0-9]$|^50[01]$ ]] && break
        sleep 1
    done
    if [[ "$code" =~ ^[1-4][0-9][0-9]$|^50[01]$ ]]; then
        done_ "Done — https://${domain:-<this upplet>}:$public reaches $name through Nginx (HTTP $code)"
    elif [[ "$code" =~ ^50[234]$ ]]; then
        warn "Nginx answers on $public, but cannot reach $name behind it (HTTP $code)"
    else
        warn "Nginx is running, but https://127.0.0.1:$public did not answer"
    fi
}

# ── sites: several apps at once ──────────────────────────────────────────────
# Each <name>:<app-port>[:<domain>] is wired as `wire` would, one after the
# other, all on <public> (each keeps its own when it is empty). The list is
# checked as a whole first — one app without a domain per port, no name or
# private port twice — so a mistake in it changes nothing. Each wire is still
# all-or-nothing on its own: if one fails, those before it stay done.
do_sites() {  # do_sites <bots> <f2b> <public|""> <static: "-" none, else its domain> <entry>…
    local bots="$1" f2b="$2" public="$3" static="$4"; shift 4
    (( $# )) || [[ "$static" != - ]] || fail "No apps to put behind Nginx"
    [[ -z "$public" || "$public" =~ ^[0-9]+$ ]] || fail "Not a port: $public"
    local entry name port domain row cur_port cur_public
    local names=" " ports=" " domains=" " defaults=0 first=() named=() plain=()
    for entry in "$@"; do
        IFS=: read -r name port domain <<< "$entry"
        domain="${domain,,}"
        [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || fail "Not an app name: $name"
        [[ "$port" =~ ^[0-9]+$ ]] || fail "The new port for $name must be a number (0 picks one)"
        check_domain "$domain"
        [[ "$names" != *" $name "* ]] || fail "$name is listed twice"
        names+="$name "
        if [[ "$port" != 0 ]]; then
            [[ "$ports" != *" $port "* ]] || fail "Port $port is given to two apps"
            ports+="$port "
        fi
        row=$(apps_table | awk -F'\t' -v n="$name" '$1 == n')
        [[ -n "$row" ]] || fail "No installed app named '$name'"
        IFS=$'\t' read -r _ cur_port cur_public _ <<< "$row"
        if [[ -n "$public" ]]; then
            if [[ -z "$domain" ]]; then
                defaults=$((defaults + 1))
                (( defaults == 1 )) || fail "Only one app on port $public can go without a domain — it answers for every name the others don't have"
            else
                [[ "$domains" != *" $domain "* ]] || fail "$domain is given to two apps"
                domains+="$domain "
            fi
        fi
        # In an order that never has two sites in each other's way: an app
        # still serving the shared port itself moves off it first, then those
        # with a domain, then the one without.
        if [[ -n "$public" && -z "$cur_public" && "$cur_port" == "$public" ]]; then first+=("$name:$port:$domain")
        elif [[ -n "$domain" ]]; then named+=("$name:$port:$domain")
        else plain+=("$name:$port:$domain"); fi
    done
    # The static site is one more site on the port, after the apps that
    # move off it and alongside the others with or without a domain.
    if [[ "$static" != - ]]; then
        static="${static,,}"
        check_domain "$static"
        if [[ -n "$public" ]]; then
            if [[ -z "$static" ]]; then
                defaults=$((defaults + 1))
                (( defaults == 1 )) || fail "Only one site on port $public can go without a domain — the static site or an app, not both"
            else
                [[ "$domains" != *" $static "* ]] || fail "$static is given to the static site and an app"
            fi
        fi
        if [[ -n "$static" ]]; then named+=("%static::$static"); else plain+=("%static::"); fi
    fi
    local all=("${first[@]}" "${named[@]}" "${plain[@]}") i=0
    for entry in "${all[@]}"; do
        i=$((i + 1))
        IFS=: read -r name port domain <<< "$entry"
        if [[ "$name" == %static ]]; then
            (( ${#all[@]} == 1 )) || log "── the static site ($i of ${#all[@]})"
            # Its port: the shared one, else the one it has, else 443.
            ( do_static "${public:-$(static_port)}" "$domain" ) \
                || fail "The static site was not set up$( (( i < ${#all[@]} )) && printf ' — the sites after it were left as they are')"
            continue
        fi
        (( ${#all[@]} == 1 )) || log "── $name ($i of ${#all[@]})"
        # A subshell: wire's fail() ends that wire, then the list stops here.
        ( do_wire "$name" "$port" "$bots" "$f2b" "$public" "$domain" ) \
            || fail "$name was not put behind Nginx$( (( i < ${#all[@]} )) && printf ' — the sites after it were left as they are')"
    done
    (( ${#all[@]} == 1 )) || done_ "Done — Nginx serves ${#all[@]} sites${public:+ on port $public}"
}

# Put the app back the way it was before a failed wire.
restore() {
    local name="$1" bak="$2"
    warn "Restoring $name"
    systemctl stop "$name" 2>/dev/null || true
    cp -a "$bak/unit" "/etc/systemd/system/${name}.service"
    if [[ -f "$bak/env" ]]; then cp -a "$bak/env" "/etc/${name}.env"; else rm -f "/etc/${name}.env"; fi
    cp -a "$bak/installed.json" "$INSTALLED"
    if [[ -f "$bak/site" ]]; then
        cp -a "$bak/site" "$SITES/$(site_of "$name")"
    else
        rm -f "$SITES/$(site_of "$name")" "$ENABLED/$(site_of "$name")"
    fi
    sync_bots_conf
    write_acme_site
    systemctl daemon-reload
    # Nginx may hold the port the app wants back — it goes first when it has nothing else to serve.
    if ! ls "$ENABLED"/p5-app-*.conf >/dev/null 2>&1; then systemctl stop nginx 2>/dev/null || true
    else reload_nginx >/dev/null 2>&1 || true; fi
    systemctl start "$name" 2>/dev/null || true
    rm -rf "$bak"
}

# ── static ───────────────────────────────────────────────────────────────────
# Nginx with no app in front of it: it serves $SITE_ROOT itself. The upload
# that fills that directory is the agent's (/static-site); this only builds the site.
write_placeholder() {
    cat > "$SITE_ROOT/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Nothing here yet</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  html { color-scheme: dark light; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         font: 16px/1.6 system-ui, sans-serif; }
  div { max-width: 32rem; padding: 2rem; text-align: center; }
  code { font-size: 0.95em; }
  p { opacity: 0.7; }
</style>
<div>
  <h1>Nothing here yet</h1>
  <p>Nginx serves this upplet's files from <code>/var/www/html</code>.
     Attach a folder in the dashboard, or copy files here, to replace this page.</p>
</div>
HTML
    chmod 644 "$SITE_ROOT/index.html"
}


do_static() {
    # domain: "-" keeps the one the site has.
    local port="${1:-$STATIC_PORT}" domain="${2--}"
    [[ "$domain" == - ]] && domain="$(static_domain)"
    domain="${domain,,}"
    check_domain "$domain"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || fail "Not a port: $port"
    (( port != AGENT_PORT )) || fail "Port $port is the agent's"
    (( port != 80 )) || fail "Port 80 answers certificate challenges and redirects to https"

    # An app served on that port for the same name (or both without one) would
    # lose it: two default_servers on one port do not load.
    local clash
    clash=$(port_holder "$port" "$domain" static)
    [[ -z "$clash" ]] || fail "Port $port serves $clash $(for_whom "$domain") — give the static site another port or domain"

    log "Nginx will serve $SITE_ROOT on $port (HTTPS)${domain:+ for $domain}, with 80 for certificates and the redirect"
    install_nginx

    mkdir -p "$SITE_ROOT"
    # The nginx package drops its own welcome page here. It is not this site's
    # content, and serving it would say Nginx works rather than that the site
    # is empty.
    rm -f "$SITE_ROOT/index.nginx-debian.html"
    if [[ -z "$(find "$SITE_ROOT" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
        write_placeholder
        ok "Wrote a placeholder page — the site has no files yet"
    else
        ok "Serving the files already in $SITE_ROOT"
    fi

    # The certificate: Let's Encrypt's for its domain, else the one this site
    # has, else any another p5 site serves (Update Certificates hands the real
    # one to every site), else self-signed.
    local cert="" key="" f le
    le=$(le_cert_for "$domain")
    [[ -n "$le" ]] && IFS=$'\t' read -r cert key <<< "$le"
    if [[ -z "$cert" && -f "$SITES/$STATIC_SITE" ]]; then
        cert=$(sed -n 's/^\s*ssl_certificate \(.*\);/\1/p' "$SITES/$STATIC_SITE" | head -1)
        key=$(sed -n 's/^\s*ssl_certificate_key \(.*\);/\1/p' "$SITES/$STATIC_SITE" | head -1)
    fi
    if [[ -z "$cert" || ! -f "$cert" ]]; then
        f=$(tls_sites | head -1)
        if [[ -n "$f" ]]; then
            cert=$(sed -n 's/^\s*ssl_certificate \(.*\);/\1/p' "$f" | head -1)
            key=$(sed -n 's/^\s*ssl_certificate_key \(.*\);/\1/p' "$f" | head -1)
        fi
    fi
    if [[ -z "$cert" || -z "$key" || ! -f "$cert" || ! -f "$key" ]]; then
        log "No certificate on record — making a self-signed one"
        out=$(bash "$ROOT/certs.sh" self-signed --cert "$CERT_DIR/site.crt" --key "$CERT_DIR/site.key" 2>&1) \
            || { printf '%s\n' "$out"; fail "Could not make a certificate"; }
        cert="$CERT_DIR/site.crt"; key="$CERT_DIR/site.key"
    fi
    ok "Certificate: $cert"

    local bak=""
    [[ -f "$SITES/$STATIC_SITE" ]] && { bak=$(mktemp /tmp/p5-static-XXXXXX); cp -a "$SITES/$STATIC_SITE" "$bak"; }

    log "Writing $SITES/$STATIC_SITE"
    cat > "$SITES/$STATIC_SITE" <<CONF
# Written by p5agent's nginx.sh — edits here are lost the next time it runs.
server {
    listen $(listen_opts "$port" "$domain");
$(listen6 "$(listen_opts "$port" "$domain")")
    server_name ${domain:-_};
    ssl_certificate $cert;
    ssl_certificate_key $key;
    ssl_protocols TLSv1.2 TLSv1.3;

    root $SITE_ROOT;
    # In order: a site whose entry page is main.html is served as it is.
    index index.html index.htm main.html;
    autoindex off;
    # A directory without an index, or a path that is not there, is a 404 —
    # never a listing of the files.
    location / {
        try_files \$uri \$uri/ =404;
    }
}
CONF
    ln -sf "$SITES/$STATIC_SITE" "$ENABLED/$STATIC_SITE"
    write_acme_site
    if ! nginx -t >/dev/null 2>&1; then
        nginx -t
        if [[ -n "$bak" ]]; then cp -a "$bak" "$SITES/$STATIC_SITE"; rm -f "$bak"
        else rm -f "$SITES/$STATIC_SITE" "$ENABLED/$STATIC_SITE"; fi
        write_acme_site
        fail "The Nginx configuration did not check out — nothing was changed"
    fi
    rm -f "$bak"
    ok "Nginx configuration checks out"

    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx || fail "Nginx did not start — 'journalctl -u nginx' says why"
    wait_active || fail "Nginx did not come up"
    ok "Nginx is running"

    if command -v ufw >/dev/null 2>&1; then
        bash "$ROOT/firewall.sh" >/dev/null 2>&1 || true
        ok "Firewall: port $port is open"
    fi

    local code
    code=$(probe "$port" "$domain")
    [[ "$code" == 200 ]] || warn "The site answered HTTP ${code:-nothing} on ${domain:-127.0.0.1}:$port"
    done_ "Done — https on port $port serves $SITE_ROOT $(for_whom "$domain")"
}

# ── certs ────────────────────────────────────────────────────────────────────
# A certificate goes to the sites whose domain it is for. When it is for none
# of them, it goes to the sites without a domain — the default ones, reached
# by the upplet's own name — as it always did.
do_certs() {
    local cert="$1" key="$2" n=0 f d names
    local matched=() plain=() targets=()
    [[ -f "$cert" && -f "$key" ]] || fail "Certificate not found: $cert"
    names=$(cert_names "$cert")
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        d=$(site_domain "$f")
        if [[ -z "$d" ]]; then plain+=("$f")
        elif cert_covers "$names" "$d"; then matched+=("$f"); fi
    done <<< "$(tls_sites)"
    if (( ${#matched[@]} )); then targets=("${matched[@]}"); else targets=("${plain[@]}"); fi
    for f in "${targets[@]}"; do
        sed -i -E "s#^(\s*)ssl_certificate .*;#\1ssl_certificate $cert;#; s#^(\s*)ssl_certificate_key .*;#\1ssl_certificate_key $key;#" "$f"
        d=$(site_domain "$f")
        ok "$(basename "$f" .conf | sed 's/^p5-app-//; s/^p5-static$/the static site/') takes it${d:+ ($d)}"
        n=$((n + 1))
    done
    (( n > 0 )) || { ok "No site Nginx serves is for $(tr '\n' ' ' <<< "$names")— nothing changed"; return 0; }
    reload_nginx || fail "Nginx rejected the new certificate"
    switch_renewal_to_webroot "$cert"
    ok "Nginx serves $cert for $n site(s)"
}

# ── unwire ───────────────────────────────────────────────────────────────────
do_unwire() {
    local name="$1" site; site="$(site_of "$name")"
    [[ -f "$SITES/$site" || -L "$ENABLED/$site" ]] || return 0
    rm -f "$SITES/$site" "$ENABLED/$site"
    sync_bots_conf "$name" drop
    sync_fail2ban "$name" drop
    write_acme_site
    if command -v nginx >/dev/null 2>&1; then reload_nginx >/dev/null 2>&1 || true; fi
    ok "Removed $name's Nginx site"
}

# ── start / stop / update ────────────────────────────────────────────────────
nginx_version() { nginx -v 2>&1 | sed -n 's/^.*nginx\///p'; }

wait_active() {
    for _ in $(seq 1 15); do systemctl is-active --quiet nginx && return 0; sleep 1; done
    return 1
}

do_start() {
    command -v nginx >/dev/null 2>&1 || fail "Nginx is not installed"
    log "Starting Nginx"
    nginx -t >/dev/null 2>&1 || { nginx -t; fail "The Nginx configuration does not check out"; }
    systemctl start nginx || { journalctl -u nginx -n 15 --no-pager 2>/dev/null; fail "Nginx did not start"; }
    wait_active || fail "Nginx did not start"
    done_ "Nginx is running"
}

do_stop() {
    log "Stopping Nginx — the apps behind it are unreachable until it starts again"
    systemctl stop nginx || fail "Nginx did not stop"
    done_ "Nginx stopped"
}

do_update() {
    command -v nginx >/dev/null 2>&1 || fail "Nginx is not installed"
    local before after
    before="$(nginx_version)"
    log "Updating Nginx${before:+ (now $before)}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get -o DPkg::Lock::Timeout=120 -qq update >/dev/null 2>&1 || warn "The package lists could not be refreshed"
    apt-get -o DPkg::Lock::Timeout=120 -qq install -y --only-upgrade nginx || fail "The nginx package did not upgrade"
    after="$(nginx_version)"
    if [[ "$before" == "$after" ]]; then ok "Nginx $after is the latest"; else ok "Nginx $before → $after"; fi
    nginx -t >/dev/null 2>&1 || { nginx -t; fail "The Nginx configuration does not check out"; }
    log "Restarting Nginx"
    systemctl restart nginx || { journalctl -u nginx -n 15 --no-pager 2>/dev/null; fail "Nginx did not restart"; }
    wait_active || fail "Nginx did not come back"
    done_ "Done — Nginx $after is running"
}

# ── remove ───────────────────────────────────────────────────────────────────
# certs.sh's --standalone renewals were switched to Nginx's webroot; without
# Nginx on port 80 they need their own server again.
switch_renewal_to_standalone() {
    local cert="$1" name conf
    [[ "$cert" == /etc/letsencrypt/live/*/* ]] || return 0
    name="$(basename "$(dirname "$cert")")"
    conf="/etc/letsencrypt/renewal/$name.conf"
    [[ -f "$conf" ]] || return 0
    python3 - "$conf" <<'PY' && ok "Renewal of $name answers on its own again (standalone)"
import sys
path = sys.argv[1]
out, skip = [], False
for line in open(path).read().splitlines():
    s = line.strip()
    if s.startswith("[[webroot_map]]"):
        skip = True
        continue
    if skip and s.startswith("["):
        skip = False
    if skip or s.startswith("authenticator") or s.startswith("webroot_path"):
        continue
    out.append(line)
    if s == "[renewalparams]":
        out.append("authenticator = standalone")
open(path, "w").write("\n".join(out) + "\n")
PY
}

do_remove() {
    local rows name port public domain serve site cert key unit env failed=0 claimed=" "
    # The app without a domain goes first on its port: it is the one that
    # keeps it. Others served there by name can't all have it back.
    rows=$(apps_table | awk -F'\t' '$3 != ""' | sort -t$'\t' -k4,4)
    [[ -n "$rows" ]] && log "Nginx serves: $(awk -F'\t' '{printf "%s%s", (NR>1?", ":""), $1}' <<< "$rows")"

    # Nginx holds the ports the apps take back: it goes first.
    if command -v nginx >/dev/null 2>&1; then
        systemctl stop nginx 2>/dev/null || true
        systemctl disable nginx >/dev/null 2>&1 || true
        ok "Nginx stopped"
    fi

    while IFS=$'\t' read -r name port public domain; do
        [[ -n "$name" ]] || continue
        site="$SITES/$(site_of "$name")"
        unit="/etc/systemd/system/${name}.service" env="/etc/${name}.env"
        cert=$(sed -n 's/^\s*ssl_certificate \(.*\);/\1/p' "$site" 2>/dev/null | head -1)
        key=$(sed -n 's/^\s*ssl_certificate_key \(.*\);/\1/p' "$site" 2>/dev/null | head -1)
        serve="$public"
        if [[ "$claimed" == *" $public "* ]]; then
            serve="$port"
            warn "$name shared port $public with another app — it serves itself on $port instead"
        fi
        claimed+="$serve "
        log "$name serves itself again: HTTPS on $serve"
        if [[ ! -f "$unit" ]]; then warn "$unit not found — $name left as it is"; failed=1; continue; fi
        systemctl stop "$name" 2>/dev/null || true
        sed -i -E \
            -e "s/^Environment=PORT=.*/Environment=PORT=$serve/" \
            -e "s/^Environment=HOST=.*/Environment=HOST=0.0.0.0/" \
            -e "/^ExecStart=/ s/--port[= ][0-9]+/--port $serve/" \
            -e "/^ExecStart=/ s/--hostname[= ][^ ]+/--hostname 0.0.0.0/" \
            "$unit"
        [[ -f "$env" ]] || { touch "$env"; chmod 600 "$env"; }
        sed -i '/^TLS_CERT_PATH=/d;/^TLS_KEY_PATH=/d;/^PORT=/d;/^HOST=/d' "$env"
        if [[ -n "$cert" && -f "$cert" && -n "$key" && -f "$key" ]]; then
            printf 'TLS_CERT_PATH=%s\nTLS_KEY_PATH=%s\n' "$cert" "$key" >> "$env"
            switch_renewal_to_standalone "$cert"
        else
            warn "No certificate found for $name — it will serve plain HTTP until Update Certificates"
        fi
        printf 'PORT=%s\nHOST=0.0.0.0\n' "$serve" >> "$env"
        python3 - "$INSTALLED" "$name" "$serve" <<'PY'
import json, sys
path, name, public = sys.argv[1:4]
apps = json.load(open(path))
for a in apps:
    if a.get("name") == name:
        a["port"] = public
        for k in ("public-port", "nginx-bots", "nginx-fail2ban", "nginx-domain"):
            a.pop(k, None)
json.dump(apps, open(path, "w"), indent=2)
PY
        rm -f "$site" "$ENABLED/$(site_of "$name")"
        systemctl daemon-reload
        systemctl start "$name" || true
        local up="" code
        for _ in $(seq 1 30); do
            code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 2 "https://127.0.0.1:$serve/" 2>/dev/null)
            [[ "$code" =~ ^[1-5][0-9][0-9]$ ]] && { up=1; break; }
            sleep 1
        done
        if [[ -n "$up" ]]; then ok "$name answers on https port $serve (HTTP $code)"
        else warn "$name did not answer on https port $serve yet"; journalctl -u "$name" -n 10 --no-pager 2>/dev/null; failed=1; fi
        # Its private port is nobody's now.
        if command -v ufw >/dev/null 2>&1 && [[ "$port" != "$serve" ]]; then
            bash "$ROOT/firewall.sh" --close "$port/tcp" >/dev/null 2>&1 || true
        fi
    done <<< "$rows"

    if [[ -f "$SITES/$STATIC_SITE" ]]; then
        rm -f "$SITES/$STATIC_SITE" "$ENABLED/$STATIC_SITE"
        ok "The static site is gone — its files stay in $SITE_ROOT"
    fi
    rm -f "$ENABLED/$ACME_SITE" "$SITES/$ACME_SITE" "$BOTS_HTTP" "$BOTS_SNIPPET" /etc/nginx/conf.d/p5-upgrade.conf
    sync_fail2ban
    if command -v nginx >/dev/null 2>&1; then
        log "Removing the Nginx package (its /etc/nginx stays, certificates included)"
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o DPkg::Lock::Timeout=120 -qq remove -y nginx nginx-core nginx-common >/dev/null 2>&1 \
            || apt-get -o DPkg::Lock::Timeout=120 -qq remove -y nginx >/dev/null 2>&1 || true
        command -v nginx >/dev/null 2>&1 && warn "Nginx is still installed" || ok "Nginx removed"
    fi
    # Built-in ports are the apps' own now (and 80, for certificates).
    command -v ufw >/dev/null 2>&1 && { bash "$ROOT/firewall.sh" >/dev/null 2>&1 || true; ok "Firewall: the apps' ports are open"; }
    (( failed == 0 )) || fail "Nginx is gone, but not every app came back — see above"
    done_ "Done — Nginx removed"
}

# static [port] [--domain <name>]
parse_static() {
    local port="" domain="-"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --domain) [[ $# -ge 2 ]] || fail "--domain needs a name (\"\" for none)"; domain="$2"; shift ;;
            --*) fail "Unknown option: $1" ;;
            *) [[ -z "$port" ]] || fail "usage: nginx.sh static [port] [--domain <name>]"; port="$1" ;;
        esac
        shift
    done
    do_static "${port:-$STATIC_PORT}" "$domain"
}

case "${1:-}" in
    # install: what p5agent's install_util.sh runs (/install-util nginx) —
    # the same as wire.
    wire|install)
        # install_util.sh runs "<script> install <args…>", so the static site
        # and the list arrive here too: install static …, install sites ….
        if [[ "${2:-}" == static ]]; then
            shift 2
            parse_static "$@"
            exit 0
        fi
        if [[ "${2:-}" == sites ]]; then
            shift 2
            bots=0 f2b=0 public_port="" static_domain="-" entries=()
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --static) [[ $# -ge 2 ]] || fail "--static needs a domain (\"\" for none)"; static_domain="$2"; shift ;;
                    --bots) bots=1 ;;
                    --fail2ban) f2b=1 ;;
                    --public) [[ $# -ge 2 ]] || fail "--public needs a port"; public_port="$2"; shift ;;
                    --*) fail "Unknown option: $1" ;;
                    *) entries+=("$1") ;;
                esac
                shift
            done
            do_sites "$bots" "$f2b" "$public_port" "$static_domain" "${entries[@]}"
            exit $?
        fi
        [[ $# -ge 3 ]] || fail "usage: nginx.sh install <name> <app-port> [--public <port>] [--domain <name>] [--bots] [--fail2ban]"
        wire_name="$2" wire_port="$3" bots=0 f2b=0 public_port="" wire_domain="-"
        shift 3
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --bots) bots=1 ;;
                --fail2ban) f2b=1 ;;
                --public) [[ $# -ge 2 ]] || fail "--public needs a port"; public_port="$2"; shift ;;
                --domain) [[ $# -ge 2 ]] || fail "--domain needs a name (\"\" for none)"; wire_domain="$2"; shift ;;
                *) fail "Unknown option: $1" ;;
            esac
            shift
        done
        do_wire "$wire_name" "$wire_port" "$bots" "$f2b" "$public_port" "$wire_domain" ;;
    # static: Nginx with no app in front of it — it serves $SITE_ROOT itself.
    static) shift; parse_static "$@" ;;
    certs)  [[ $# -eq 3 ]] || fail "usage: nginx.sh certs <cert> <key>"; do_certs "$2" "$3" ;;
    unwire) [[ $# -eq 2 ]] || fail "usage: nginx.sh unwire <name>"; do_unwire "$2" ;;
    start)  do_start ;;
    stop)   do_stop ;;
    update) do_update ;;
    remove) do_remove ;;
    *) sed -n '2,53p' "$0"; exit 2 ;;
esac
