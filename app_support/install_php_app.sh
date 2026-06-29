#!/usr/bin/env bash
# Standard minimal PHP app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

if command -v composer >/dev/null 2>&1 && [[ -f composer.json ]]; then
    echo "Installing dependencies: composer install"
    composer install --no-interaction --no-progress
else
    echo "No composer.json (or composer missing) — nothing to build"
fi
echo "PHP setup complete"

# Service — the app dir is on the unit's PATH (php is in /usr/bin).
create_service "${APP_DIR}"
