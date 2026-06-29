#!/usr/bin/env bash
# Standard minimal Ruby app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

command -v bundle >/dev/null 2>&1 || gem install bundler --no-document
if [[ -f Gemfile ]]; then
    echo "Installing gems: bundle install"
    bundle install
fi
echo "Ruby setup complete"

# Service — the app dir and its bin/ are on the unit's PATH.
create_service "${APP_DIR}/bin:${APP_DIR}"
