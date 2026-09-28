#!/usr/bin/env bash
# install_util.sh <name> [args…]
#
# Installs a utility (utilities/<name>/<name>.sh install [args…]) the way
# install_app.sh installs an app: run detached by the agent's /install-util,
# which has taken the install lock (pending_install.json) and started
# setup.log afresh (the last install's log archived to <tmp>). Every line the
# script prints goes to that log, timestamped; /setup-log serves it while it
# runs and afterwards, until the next install. Settings arrive in the environment (Squid's password among
# them) and are never logged here.
#
#   completed: the log's LAST line is "<name> installation completed", and
#              the lock is removed;
#   failed:    "<name> installation failed" is logged and the lock removed —
#              /progress drops back to {}, the polling peer's failure signal.

NAME="${1:?usage: install_util.sh <name> [args…]}"
shift

HERE="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
SETUP_LOG="$DATA_DIR/setup.log"
PENDING="$DATA_DIR/pending_install.json"
SCRIPT="$HERE/utilities/$NAME/$NAME.sh"

mkdir -p "$DATA_DIR"

ts()      { date '+%Y-%m-%d %H:%M:%S'; }
logline() { printf '[%s] %s\n' "$(ts)" "$*" >> "$SETUP_LOG"; }
stamp()   { while IFS= read -r line; do printf '[%s] %s\n' "$(ts)" "$line"; done >> "$SETUP_LOG"; }

# A whitelist the agent wrote for this run only (Squid): gone either way.
cleanup() { [[ -n "${WHITELIST_FILE:-}" ]] && rm -f "$WHITELIST_FILE"; }
fail() { logline "$*"; logline "$NAME installation failed"; cleanup; rm -f "$PENDING"; exit 1; }

[[ "$NAME" =~ ^[a-z0-9-]+$ && -f "$SCRIPT" ]] || fail "No install script for $NAME ($SCRIPT)"

logline "Running utilities/$NAME/$NAME.sh install${*:+ $*}"
bash "$SCRIPT" install "$@" 2>&1 </dev/null | stamp
rc=${PIPESTATUS[0]}
(( rc == 0 )) || fail "utilities/$NAME/$NAME.sh install ended with exit code $rc"
cleanup

# The log's last line: the agent's completion marker (see install_app.sh).
logline "$NAME installation completed"
rm -f "$PENDING"
