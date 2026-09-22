#!/usr/bin/env bash
# app_ops.sh <op> <name> [--drop-db]
#
# One installed app's lifecycle after install, run by the agent's /app:
#
#   start | stop   systemctl start/stop the app's service
#   backup         copy the app's folder (/opt/<name>) to /opt/<name>_backup,
#                  replacing any older backup
#   update         back up, then update: the app's own refresh.sh + update.sh
#                  when it has them; otherwise fetch the new code (git, or a
#                  fresh copy of a demo) and rebuild it the way it was
#                  installed — its repo's setup.sh/install.sh, else the
#                  standard builder for its type
#   rollback       put /opt/<name>_backup back in place of /opt/<name> and
#                  start the app again (the backup is used up)
#   nginx          put Nginx in front of the app (nginx.sh wire): the app moves
#                  to --port <n> (0 = pick one) over plain HTTP on 127.0.0.1, Nginx serves its
#                  old port over HTTPS plus port 80; [--bots] [--fail2ban]
#                  turn bot protection on (left out: off)
#   uninstall      stop and remove the app: its service, folder and backups,
#                  certificate dir, sudoers entry, user, firewall port and its
#                  installed_apps.json entry. The database and /etc/<name>.env
#                  (which holds its credentials) stay unless --drop-db is given,
#                  so a reinstall picks the data up again.
#
# <name> must be an app in installed_apps.json — nothing else is ever touched.
# Output is the transcript the dashboard shows; the exit code is the result.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SUPPORT="$HERE/app_support"
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
APPS_DIR="${P5AGENT_APPS_DIR:-/opt}"
INSTALLED="$DATA_DIR/installed_apps.json"
AGENT_PORT="${P5AGENT_PORT:-5005}"

# shellcheck source=app_support/common.sh
source "$SUPPORT/common.sh"   # create_service (a rebuild) + app_version_line

log()  { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*"; exit 1; }

op="${1:-}"; name="${2:-}"; drop_db=""; new_port=""; nginx_flags=()
[[ "${3:-}" == "--drop-db" ]] && drop_db=1
[[ "${3:-}" == "--port" ]] && new_port="${4:-}" && nginx_flags=("${@:5}")   # --bots --fail2ban
[[ -n "$op" && -n "$name" ]] || fail "usage: app_ops.sh <start|stop|backup|update|rollback|uninstall|nginx> <name> [--drop-db | --port <n>]"

# The app's installed_apps.json entry, as port, db-type, app-dir, app-type,
# app-cmd, demo and source separated by US (\x1f: tabs would merge empty
# fields) — or nothing when there is no such app. The name is checked here, before any path is built from it. Apps
# installed before the last four fields were recorded have them empty.
entry=$(python3 - "$INSTALLED" "$name" <<'PY'
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
for a in apps:
    if a.get("name") == sys.argv[2]:
        deps = [str(d).split()[0].lower() for d in (a.get("dependencies") or [])]
        db = next((d for d in deps if d in ("postgresql", "mysql", "mariadb", "sqlite")), "")
        print("\x1f".join(str(v) for v in (
            a.get("port", ""), db, a.get("path", ""), a.get("app-type", ""),
            a.get("app-cmd", ""), "1" if a.get("demo") else "", a.get("source", ""),
            a.get("public-port", ""))))
        break
PY
)
[[ -n "$entry" ]] || fail "No installed app named '$name'"
IFS=$'\x1f' read -r port db_type app_dir app_type app_cmd demo source public_port <<< "$entry"

target="$APPS_DIR/$name"
backup="${target}_backup"
deleted="${backup}_deleted"
app_dir="${app_dir:-$target}"   # the app's own folder: the repo root or a subfolder of it

# What the app reports as running now, at the end of an update or a rollback.
report_version() {
    local line
    if line=$(app_version_line "$name" "$port"); then ok "$line"; else warn "$line"; fi
}

remove_dir() {  # remove_dir <dir> — delete it and say so
    [[ -d "$1" ]] || return 0
    if rm -rf "$1"; then ok "Deleted $1"; else warn "Could not delete $1"; fi
}

# Copy the app's folder to <app>_backup. The previous backup is set aside, not
# deleted, until the new one is complete: a failed copy puts it back, so there
# is always one to roll back to. A run cut short can leave only
# <app>_backup_deleted — then it is the previous backup and is taken back first.
make_backup() {
    [[ -d "$target" ]] || fail "$target not found"
    if [[ -d "$deleted" && ! -d "$backup" ]]; then
        mv "$deleted" "$backup"
    fi
    rm -rf "$deleted"
    if [[ -d "$backup" ]]; then
        log "Moving the previous backup to $deleted"
        mv "$backup" "$deleted" || fail "Could not move $backup aside"
    fi
    log "Backing up $target"
    if ! cp -a "$target" "$backup"; then
        rm -rf "$backup"
        [[ -d "$deleted" ]] && mv "$deleted" "$backup" && warn "Previous backup restored"
        fail "Backup failed"
    fi
    if [[ -d "$deleted" ]]; then
        rm -rf "$deleted"
        ok "Previous backup deleted"
    fi
    ok "Backed up to $backup ($(du -sh "$backup" 2>/dev/null | cut -f1))"
}

# The app type, for an app installed before it was recorded: from the files
# that mark each kind of project.
guess_app_type() {
    local d="$1"
    if   [[ -f "$d/Package.swift" ]]; then echo swift
    elif [[ -f "$d/package.json" ]]; then echo nodejs
    elif [[ -f "$d/go.mod" ]] || compgen -G "$d/*.go" >/dev/null; then echo go
    elif [[ -f "$d/Gemfile" ]] || compgen -G "$d/*.rb" >/dev/null; then echo ruby
    elif [[ -f "$d/composer.json" ]] || compgen -G "$d/*.php" >/dev/null; then echo php
    elif [[ -f "$d/pom.xml" || -f "$d/build.gradle" ]] || compgen -G "$d/*.java" >/dev/null; then echo java
    elif [[ -f "$d/requirements.txt" || -f "$d/pyproject.toml" ]] || compgen -G "$d/*.py" >/dev/null; then echo python
    fi
}

# One setting of the app's existing systemd unit (User, Wants, ExecStart).
unit_value() {
    grep -oP "^$1=\K.*" "/etc/systemd/system/${name}.service" 2>/dev/null | head -1
}

case "$op" in
start|stop)
    log "systemctl $op $name"
    systemctl "$op" "$name" || fail "Could not $op $name (journalctl -u $name)"
    state=$(systemctl is-active "$name" 2>/dev/null || true)
    ok "$name is ${state:-unknown}"
    ;;

backup)
    make_backup
    ;;

nginx)
    [[ -n "$new_port" ]] || fail "nginx needs --port <the app's new port>"
    bash "$HERE/nginx.sh" wire "$name" "$new_port" "${nginx_flags[@]}"
    exit $?
    ;;

update)
    # Refuse before touching anything when there is nothing to update from.
    if [[ ! -f "$app_dir/update.sh" ]]; then
        if [[ -n "$demo" ]]; then
            [[ -n "$source" && "/$source/" != *"/../"* && -d "$HERE/$source" ]] \
                || fail "Cannot tell which demo $name was copied from — reinstall it once to make it updatable"
        elif [[ ! -d "$target/.git" ]]; then
            # A demo installed before demos were recorded as such lands here too.
            fail "$target is neither a git checkout nor a known demo — reinstall $name once to make it updatable"
        fi
    fi

    make_backup

    # The app's own scripts come first: they know how the app is built. Its
    # refresh.sh (fetch the new code) runs before its update.sh, so the update
    # that runs is the new one — bash reads a script as it goes, and an
    # update.sh that fetches over itself is rewritten mid-read.
    if [[ -f "$app_dir/update.sh" ]]; then
        if [[ -f "$app_dir/refresh.sh" ]]; then
            log "Running the app's own refresh.sh"
            ( cd "$app_dir" && P5AGENT=1 bash ./refresh.sh ) \
                || fail "refresh.sh failed — nothing has been changed"
        fi
        log "Running the app's own update.sh"
        ( cd "$app_dir" && P5AGENT=1 bash ./update.sh ) \
            || fail "update.sh failed — Rollback Update restores the previous version"
        ok "$name updated"
        report_version
        exit 0
    fi

    # Otherwise the standard update: the new code, then the install's build.
    if [[ -n "$demo" ]]; then
        log "Copying demo $source from p5agent"
        find "$target" -mindepth 1 -delete && cp -a "$HERE/$source/." "$target/" \
            || fail "Copying the demo failed — Rollback Update restores the previous version"
    else
        git_() { git -c safe.directory="$target" -C "$target" "$@"; }
        branch=$(git_ symbolic-ref --short -q HEAD) \
            || fail "$name is pinned to $(git_ describe --tags 2>/dev/null || echo a fixed commit) — there is no branch to fetch newer code from"
        log "Fetching the latest $branch"
        git_ fetch --depth 1 origin "$branch" && git_ reset --hard FETCH_HEAD \
            || fail "Fetching $branch failed"
        ok "Now at $(git_ log -1 --pretty='%h %s')"
    fi

    setup=""
    for candidate in setup.sh install.sh; do
        [[ -f "$app_dir/$candidate" ]] && { setup="$app_dir/$candidate"; break; }
    done
    if [[ -n "$setup" ]]; then
        log "Running ${setup##*/}"
        ( cd "$app_dir" && P5AGENT=1 bash "$setup" ) \
            || fail "${setup##*/} failed — Rollback Update restores the previous version"
    else
        app_type="${app_type:-$(guess_app_type "$app_dir")}"
        builder="$SUPPORT/install_${app_type}_app.sh"
        [[ -n "$app_type" && -f "$builder" ]] || fail "No builder for app type '${app_type:-?}'"
        app_cmd="${app_cmd:-$(unit_value ExecStart | sed 's|^/usr/bin/env ||')}"
        log "Rebuilding with install_${app_type}_app.sh"
        ( cd "$app_dir" && APP_DIR="$app_dir" APP_NAME="$name" APP_PORT="$port" APP_CMD="$app_cmd" \
            APP_SERVICES="$(unit_value Wants)" APP_USER="$(unit_value User)" bash "$builder" ) \
            || fail "The rebuild failed — Rollback Update restores the previous version"
    fi
    systemctl restart "$name" 2>/dev/null || true
    state=$(systemctl is-active "$name" 2>/dev/null || true)
    ok "$name updated — its service is ${state:-unknown}"
    report_version
    ;;

rollback)
    [[ -d "$backup" ]] || fail "There is no backup of $name to roll back to"
    log "Stopping $name"
    systemctl stop "$name" 2>/dev/null || true
    log "Replacing $target with $backup"
    rm -rf "$target" || fail "Could not remove $target"
    mv "$backup" "$target" || fail "Could not move $backup into place"
    log "Starting $name"
    systemctl start "$name" || fail "$name did not start (journalctl -u $name)"
    ok "$name rolled back to the version before its last update"
    report_version
    ;;

uninstall)
    log "Stopping and removing the $name service"
    systemctl stop "$name" 2>/dev/null || true
    systemctl disable "$name" 2>/dev/null || true
    rm -f "/etc/systemd/system/${name}.service"
    systemctl daemon-reload
    systemctl reset-failed "$name" 2>/dev/null || true

    remove_dir "$target"
    # Every backup folder it left: <app>_backup, <app>_backup_deleted and any
    # other <app>_backup* — but never the folder of another installed app whose
    # name happens to start the same way.
    others=$(python3 - "$INSTALLED" "$name" <<'PY'
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
print("\n".join(a.get("name", "") for a in apps if a.get("name") != sys.argv[2]))
PY
)
    for dir in "$target"_backup*; do
        [[ -d "$dir" ]] || continue
        grep -qxF "$(basename "$dir")" <<< "$others" && continue
        remove_dir "$dir"
    done
    remove_dir "/etc/${name}"             # its certificate dir
    rm -f "/etc/sudoers.d/${name}"
    bash "$HERE/nginx.sh" unwire "$name" || warn "Could not remove $name's Nginx site"

    if [[ -n "$drop_db" ]]; then
        case "$db_type" in
            postgresql)
                log "Dropping PostgreSQL database and role $name"
                sudo -u postgres dropdb --if-exists "$name" && sudo -u postgres dropuser --if-exists "$name" \
                    && ok "Database dropped" || warn "Could not drop the database" ;;
            mysql|mariadb)
                log "Dropping ${db_type} database and user $name"
                mysql -e "DROP DATABASE IF EXISTS \`$name\`; DROP USER IF EXISTS '$name'@'localhost';" \
                    && ok "Database dropped" || warn "Could not drop the database" ;;
            sqlite)
                remove_dir "/var/lib/${name}" ;;
            *)
                ok "No database to drop" ;;
        esac
        rm -f "/etc/${name}.env"
    elif [[ -n "$db_type" ]]; then
        ok "The $db_type database and /etc/${name}.env are kept — reinstalling $name picks them up"
    else
        rm -f "/etc/${name}.env"
    fi

    if id "$name" &>/dev/null; then
        userdel "$name" 2>/dev/null && ok "Removed user $name" || warn "Could not remove user $name"
    fi

    python3 - "$INSTALLED" "$name" <<'PY'
import json, sys
path, name = sys.argv[1:3]
try:
    apps = json.load(open(path))
except Exception:
    apps = []
json.dump([a for a in apps if a.get("name") != name], open(path, "w"), indent=2)
PY
    # Its ports close now that it is gone from installed_apps.json — the one it
    # was reached on and, behind Nginx, its private one. --close leaves a port
    # open that another app still uses.
    if command -v ufw >/dev/null 2>&1; then
        for p in ${public_port:-} $port; do
            [[ "$p" =~ ^[0-9]+$ ]] && bash "$HERE/firewall.sh" --close "$p/tcp"
        done
    fi
    ok "$name uninstalled"
    ;;

*)
    fail "Unknown operation '$op'"
    ;;
esac
