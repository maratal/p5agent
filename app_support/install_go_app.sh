#!/usr/bin/env bash
# Standard minimal Go app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

echo "Building Go app: go build -o app ."
go build -o app .
echo "Go build complete"

# Service — the compiled ./app is in the app dir (on the unit's PATH).
create_service "${APP_DIR}"
