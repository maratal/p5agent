#!/usr/bin/env bash
# nginx.sh — puts Nginx in front of installed apps.
#
#   nginx.sh wire <name> <app-port> [--public <port>] [--bots] [--fail2ban]
#                                     move the app to <app-port> (plain HTTP,
#                                     loopback only) and let Nginx serve its old
#                                     port over HTTPS, plus port 80. 0 picks the
#                                     port: the app's current private one on a
#                                     re-wire, else the first free from 5656.
#                                     --public: the port Nginx serves the app on
#                                     instead (the old one is closed); left out,
#                                     it stays where it is
#                                     --bots / --fail2ban: see "Bot protection"
#                                     below; leaving a flag out on a re-run
#                                     turns that protection off again
#   nginx.sh certs <cert> <key>       point every Nginx-served app at this
#                                     certificate and reload (run by certs.sh)
#   nginx.sh unwire <name>            drop the app's Nginx site (run by uninstall)
#
# The layout it builds is the usual one:
#
#   :80    /.well-known/acme-challenge/ from $WEBROOT (certbot --webroot), and a
#          redirect to https for everything else
#   :<p>   TLS with the app's certificate, proxied to http://127.0.0.1:<app-port>
#
# The app's installed_apps.json entry keeps its new private port as "port" and
# gains "public-port" — the port Nginx serves it on, which is what the dashboard
# links to and what firewall.sh opens. The app's own port stays closed.
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
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
INSTALLED="$DATA_DIR/installed_apps.json"
AGENT_PORT="${P5AGENT_PORT:-5005}"
[[ -f /etc/p5agent.env ]] && AGENT_PORT="$(sed -n 's/^P5AGENT_PORT=//p' /etc/p5agent.env | head -n1)" && AGENT_PORT="${AGENT_PORT:-5005}"

WEBROOT="/var/www/p5-acme"
SITES="/etc/nginx/sites-available"
ENABLED="/etc/nginx/sites-enabled"
ACME_SITE="p5-acme.conf"
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

# The IPv6 twin of a listen line — only where the kernel has IPv6, since Nginx
# refuses to start on a [::] socket it cannot open.
listen6() { [[ -f /proc/net/if_inet6 ]] && printf '    listen [::]:%s;' "$1"; }

# Every app's name, port and public-port (empty when not behind Nginx), tab-separated.
apps_table() {
    python3 - "$INSTALLED" <<'PY'
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
for a in apps:
    print("%s\t%s\t%s" % (a.get("name", ""), a.get("port", "") or "443", a.get("public-port", "")))
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
        DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 -qq install -y fail2ban >/dev/null 2>&1 || true
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
    if grep -qsE '^\s*listen 443 ssl' "$SITES"/p5-app-*.conf; then
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

install_nginx() {
    if command -v nginx >/dev/null 2>&1; then
        ok "Nginx is installed ($(nginx -v 2>&1 | sed 's/^.*: //'))"
    else
        log "Installing Nginx"
        export DEBIAN_FRONTEND=noninteractive
        apt-get -o DPkg::Lock::Timeout=120 -qq update >/dev/null 2>&1
        # Installing starts it on port 80 with the stock site; that is replaced below.
        apt-get -o DPkg::Lock::Timeout=120 -qq install -y nginx >/dev/null 2>&1 || true
        command -v nginx >/dev/null 2>&1 || fail "Nginx did not install"
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
    local name="$1" new_port="$2" bots="$3" f2b="$4" new_public="${5:-}"
    [[ "$bots" == 1 || "$f2b" != 1 ]] || fail "fail2ban bans what bot protection refuses — turn bot protection on too"
    local row cur_port public
    row=$(apps_table | awk -F'\t' -v n="$name" '$1 == n')
    [[ -n "$row" ]] || fail "No installed app named '$name'"
    IFS=$'\t' read -r _ cur_port public <<< "$row"

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

    # Not a port another app has, privately or through Nginx.
    local clash
    clash=$(apps_table | awk -F'\t' -v n="$name" -v p="$new_port" '$1 != n && ($2 == p || $3 == p) {print $1}' | head -1)
    [[ -z "$clash" ]] || fail "Port $new_port is already used by $clash"
    if [[ "$public" != "$old_public" ]]; then
        clash=$(apps_table | awk -F'\t' -v n="$name" -v p="$public" '$1 != n && ($2 == p || $3 == p) {print $1}' | head -1)
        [[ -z "$clash" ]] || fail "Port $public is already used by $clash"
        # Free, unless it is this app's own port — which it is leaving.
        if [[ "$public" != "$cur_port" ]] && ss -ltnH "sport = :$public" 2>/dev/null | grep -q .; then
            fail "Something is already listening on port $public"
        fi
    fi
    if [[ "$new_port" != "$cur_port" ]] && ss -ltnH "sport = :$new_port" 2>/dev/null | grep -q .; then
        fail "Something is already listening on port $new_port"
    fi

    local unit="/etc/systemd/system/${name}.service" env="/etc/${name}.env"
    [[ -f "$unit" ]] || fail "$unit not found"

    log "Nginx will serve $name on $public (HTTPS) and 80; $name moves to 127.0.0.1:$new_port (HTTP)"
    install_nginx

    # The certificate the app serves now becomes Nginx's. A re-wire finds it in
    # the app's existing site instead; with neither, a self-signed one is made.
    local cert="" key=""
    if [[ -f "$env" ]]; then
        cert=$(sed -n 's/^TLS_CERT_PATH=//p' "$env" | tail -1)
        key=$(sed -n 's/^TLS_KEY_PATH=//p' "$env" | tail -1)
    fi
    if [[ -z "$cert" || -z "$key" ]] && [[ -f "$SITES/$(site_of "$name")" ]]; then
        cert=$(sed -n 's/^\s*ssl_certificate \(.*\);/\1/p' "$SITES/$(site_of "$name")" | head -1)
        key=$(sed -n 's/^\s*ssl_certificate_key \(.*\);/\1/p' "$SITES/$(site_of "$name")" | head -1)
    fi
    if [[ -z "$cert" || -z "$key" || ! -f "$cert" || ! -f "$key" ]]; then
        log "No certificate on record for $name — making a self-signed one"
        out=$(bash "$HERE/certs.sh" self-signed --cert "$CERT_DIR/$name.crt" --key "$CERT_DIR/$name.key" 2>&1) \
            || { printf '%s\n' "$out"; fail "Could not make a certificate"; }
        cert="$CERT_DIR/$name.crt"; key="$CERT_DIR/$name.key"
    fi
    ok "Certificate: $cert"

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
    listen $public ssl default_server;
$(listen6 "$public ssl default_server")
    server_name _;
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
    python3 - "$INSTALLED" "$name" "$new_port" "$public" "$bots" "$f2b" <<'PY'
import json, sys
path, name, port, public, bots, f2b = sys.argv[1:7]
apps = json.load(open(path))
for a in apps:
    if a.get("name") == name:
        a["port"] = port
        a["public-port"] = public
        a["nginx-bots"] = bots == "1"
        a["nginx-fail2ban"] = f2b == "1"
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
    ok "Nginx serves $name on port $public"

    # The entry now has public-port: firewall.sh opens it and 80 if they have no
    # rule yet (a restriction from Firewall Settings stays), and the private
    # port is closed outright.
    if command -v ufw >/dev/null 2>&1; then
        bash "$HERE/firewall.sh" >/dev/null 2>&1 || true
        bash "$HERE/firewall.sh" --close "$new_port/tcp" >/dev/null 2>&1 || true
        ok "Firewall: $public and 80 open, $new_port closed"
        if [[ "$old_public" != "$public" && "$old_public" != "$new_port" ]]; then
            bash "$HERE/firewall.sh" --close "$old_public/tcp" >/dev/null 2>&1 || true
            ok "Firewall: $old_public closed — $name is served on $public now"
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
        code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "https://127.0.0.1:$public/" 2>/dev/null)
        [[ "$code" =~ ^[1-4][0-9][0-9]$|^50[01]$ ]] && break
        sleep 1
    done
    if [[ "$code" =~ ^[1-4][0-9][0-9]$|^50[01]$ ]]; then
        done_ "Done — https on port $public reaches $name through Nginx (HTTP $code)"
    elif [[ "$code" =~ ^50[234]$ ]]; then
        warn "Nginx answers on $public, but cannot reach $name behind it (HTTP $code)"
    else
        warn "Nginx is running, but https://127.0.0.1:$public did not answer"
    fi
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

# ── certs ────────────────────────────────────────────────────────────────────
do_certs() {
    local cert="$1" key="$2" n=0 f
    [[ -f "$cert" && -f "$key" ]] || fail "Certificate not found: $cert"
    for f in "$SITES"/p5-app-*.conf; do
        [[ -f "$f" ]] || continue
        sed -i -E "s#^(\s*)ssl_certificate .*;#\1ssl_certificate $cert;#; s#^(\s*)ssl_certificate_key .*;#\1ssl_certificate_key $key;#" "$f"
        n=$((n + 1))
    done
    (( n > 0 )) || { ok "No apps behind Nginx"; return 0; }
    reload_nginx || fail "Nginx rejected the new certificate"
    switch_renewal_to_webroot "$cert"
    ok "Nginx serves $cert for $n app(s)"
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

case "${1:-}" in
    wire)
        [[ $# -ge 3 ]] || fail "usage: nginx.sh wire <name> <app-port> [--public <port>] [--bots] [--fail2ban]"
        wire_name="$2" wire_port="$3" bots=0 f2b=0 public_port=""
        shift 3
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --bots) bots=1 ;;
                --fail2ban) f2b=1 ;;
                --public) [[ $# -ge 2 ]] || fail "--public needs a port"; public_port="$2"; shift ;;
                *) fail "Unknown option: $1" ;;
            esac
            shift
        done
        do_wire "$wire_name" "$wire_port" "$bots" "$f2b" "$public_port" ;;
    certs)  [[ $# -eq 3 ]] || fail "usage: nginx.sh certs <cert> <key>"; do_certs "$2" "$3" ;;
    unwire) [[ $# -eq 2 ]] || fail "usage: nginx.sh unwire <name>"; do_unwire "$2" ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
esac
