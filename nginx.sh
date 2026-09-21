#!/usr/bin/env bash
# nginx.sh — puts Nginx in front of installed apps.
#
#   nginx.sh wire <name> <app-port>   move the app to <app-port> (plain HTTP,
#                                     loopback only) and let Nginx serve its old
#                                     port over HTTPS, plus port 80. 0 picks the
#                                     port: the app's current private one on a
#                                     re-wire, else the first free from 5656
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

log()  { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
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
    local name="$1" new_port="$2"
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
    [[ "$new_port" =~ ^[0-9]+$ ]] && (( new_port >= 1024 && new_port <= 65535 )) \
        || fail "The app's new port must be a number from 1024 to 65535 (or 0 to pick one)"
    (( new_port != AGENT_PORT )) || fail "Port $new_port is the agent's"
    [[ "$public" != 80 ]] || fail "$name is on port 80, which Nginx needs for itself — reinstall it on 443"
    (( new_port != public )) || fail "The app's new port must differ from the port Nginx takes ($public)"

    # Not a port another app has, privately or through Nginx.
    local clash
    clash=$(apps_table | awk -F'\t' -v n="$name" -v p="$new_port" '$1 != n && ($2 == p || $3 == p) {print $1}' | head -1)
    [[ -z "$clash" ]] || fail "Port $new_port is already used by $clash"
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
    python3 - "$INSTALLED" "$name" "$new_port" "$public" <<'PY'
import json, sys
path, name, port, public = sys.argv[1:5]
apps = json.load(open(path))
for a in apps:
    if a.get("name") == name:
        a["port"] = port
        a["public-port"] = public
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

    if command -v ufw >/dev/null 2>&1; then
        ufw allow "$public/tcp" comment "$name (nginx)" >/dev/null 2>&1 || true
        ufw allow 80/tcp comment "ACME http-01" >/dev/null 2>&1 || true
        ufw delete allow "$new_port/tcp" >/dev/null 2>&1 || true
        ok "Firewall: $public and 80 open, $new_port closed"
    fi

    switch_renewal_to_webroot "$cert"
    rm -rf "$bak"

    if curl -sk -o /dev/null --max-time 5 "https://127.0.0.1:$public/"; then
        ok "Done — https on port $public reaches $name through Nginx"
    else
        warn "Nginx is running, but https://127.0.0.1:$public did not answer yet"
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
    write_acme_site
    if command -v nginx >/dev/null 2>&1; then reload_nginx >/dev/null 2>&1 || true; fi
    ok "Removed $name's Nginx site"
}

case "${1:-}" in
    wire)   [[ $# -eq 3 ]] || fail "usage: nginx.sh wire <name> <app-port>"; do_wire "$2" "$3" ;;
    certs)  [[ $# -eq 3 ]] || fail "usage: nginx.sh certs <cert> <key>"; do_certs "$2" "$3" ;;
    unwire) [[ $# -eq 2 ]] || fail "usage: nginx.sh unwire <name>"; do_unwire "$2" ;;
    *) sed -n '2,20p' "$0"; exit 2 ;;
esac
