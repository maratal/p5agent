#!/usr/bin/env bash
# Apply a freshly pulled p5agent update by restarting the service.
#
# agent.py pulls the latest code (and resets to HEAD if the pull is refused)
# BEFORE invoking this script, so by the time this runs its directory already
# holds the new code — including the newest version of this very script. All
# that remains is to load it by restarting the service.
#
# The restart is detached via systemd-run: this script is spawned by the running
# agent, so restarting the agent directly would kill this process and cut off
# the in-flight /update response. Running the restart as a transient unit a
# second later lets the HTTP response flush and survives the restart.

set -euo pipefail

log() { printf '\033[1;34m→ %s\033[0m\n' "$*"; }
ok()  { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }

[[ "$(id -u)" -eq 0 ]] || { echo "This script must be run as root" >&2; exit 1; }

log "Scheduling p5agent restart to load the updated code"
systemd-run --collect --on-active=1s --unit=p5agent-restart \
    systemctl restart p5agent
ok "Restart scheduled — updated agent will be live in ~1s"
