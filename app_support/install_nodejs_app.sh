#!/usr/bin/env bash
# Standard minimal Node.js app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

if [[ -f package-lock.json ]]; then
    echo "Installing dependencies: npm ci"
    npm ci
else
    echo "Installing dependencies: npm install"
    npm install
fi
npm run build --if-present
echo "Node.js setup complete"

# Service — node_modules/.bin is on the unit's PATH, so "npm start" or a bare
# bin name resolves.
create_service "${APP_DIR}/node_modules/.bin:${APP_DIR}"
