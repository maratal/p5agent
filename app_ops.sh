#!/usr/bin/env bash
# app_ops.sh <op> <name> [--drop-db]
#
# One installed app's lifecycle after install, run by the agent's /app:
#
#   start | stop   systemctl start/stop the app's service
#   backup         copy the app's folder (/opt/<name>) to /opt/<name>_backup,
#                  replacing any older backup — taken before an update
#   rollback       put /opt/<name>_backup back in place of /opt/<name> and
#                  start the app again (the backup is used up)
#   uninstall      stop and remove the app: its service, folder and backup,
#                  certificate dir, sudoers entry, user, firewall port and its
#                  installed_apps.json entry. The database and /etc/<name>.env
#                  (which holds its credentials) stay unless --drop-db is given,
#                  so a reinstall picks the data up again.
#
# <name> must be an app in installed_apps.json — nothing else is ever touched.
# Output is the transcript the dashboard shows; the exit code is the result.
set -uo pipefail

DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
APPS_DIR="${P5AGENT_APPS_DIR:-/opt}"
INSTALLED="$DATA_DIR/installed_apps.json"
AGENT_PORT="${P5AGENT_PORT:-5005}"

log()  { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m✗ %s\033[0m\n' "$*"; exit 1; }

op="${1:-}"; name="${2:-}"; drop_db=""
[[ "${3:-}" == "--drop-db" ]] && drop_db=1
[[ -n "$op" && -n "$name" ]] || fail "usage: app_ops.sh <start|stop|backup|rollback|uninstall> <name> [--drop-db]"

# The app's installed_apps.json entry, as "port<TAB>db-type" — or nothing when
# there is no such app. The name is checked here, before any path is built from it.
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
        print("%s\t%s" % (a.get("port", ""), db))
        break
PY
)
[[ -n "$entry" ]] || fail "No installed app named '$name'"
IFS=$'\t' read -r port db_type <<< "$entry"

target="$APPS_DIR/$name"
backup="${target}_backup"
deleted="${backup}_deleted"

case "$op" in
start|stop)
    log "systemctl $op $name"
    systemctl "$op" "$name" || fail "Could not $op $name (journalctl -u $name)"
    state=$(systemctl is-active "$name" 2>/dev/null || true)
    ok "$name is ${state:-unknown}"
    ;;

backup)
    [[ -d "$target" ]] || fail "$target not found"
    # The previous backup is set aside, not deleted, until the new one is
    # complete: a failed copy puts it back, so there is always one to roll
    # back to. A run cut short can leave only <app>_backup_deleted — then it is
    # the previous backup and is taken back first.
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
    ;;

uninstall)
    log "Stopping and removing the $name service"
    systemctl stop "$name" 2>/dev/null || true
    systemctl disable "$name" 2>/dev/null || true
    rm -f "/etc/systemd/system/${name}.service"
    systemctl daemon-reload
    systemctl reset-failed "$name" 2>/dev/null || true

    log "Removing $target"
    rm -rf "$target"
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
        rm -rf "$dir" && ok "Removed $dir"
    done
    rm -rf "/etc/${name}"                 # its certificate dir
    rm -f "/etc/sudoers.d/${name}"

    # The port, unless another app uses it too — or it is SSH or the agent's.
    if [[ "$port" =~ ^[0-9]+$ && "$port" != 22 && "$port" != "$AGENT_PORT" ]] && command -v ufw >/dev/null 2>&1; then
        shared=$(python3 - "$INSTALLED" "$name" "$port" <<'PY'
import json, sys
try:
    apps = json.load(open(sys.argv[1]))
except Exception:
    apps = []
print(any(str(a.get("port")) == sys.argv[3] and a.get("name") != sys.argv[2] for a in apps))
PY
)
        if [[ "$shared" == "True" ]]; then
            ok "Port $port stays open — another app uses it"
        else
            ufw delete allow "${port}/tcp" >/dev/null 2>&1 && ok "Closed port $port" || warn "No firewall rule for port $port"
        fi
    fi

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
                rm -rf "/var/lib/${name}" && ok "SQLite data removed" ;;
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
    ok "$name uninstalled"
    ;;

*)
    fail "Unknown operation '$op'"
    ;;
esac
