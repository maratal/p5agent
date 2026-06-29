#!/usr/bin/env bash
# Standard minimal Python app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

echo "Creating virtualenv (.venv)"
python3 -m venv .venv
.venv/bin/pip install --upgrade pip >/dev/null
if [[ -f requirements.txt ]]; then
    echo "Installing requirements.txt"
    .venv/bin/pip install -r requirements.txt
fi
echo "Python setup complete"

# Service — .venv/bin is on the unit's PATH, so "python3 app.py" / "gunicorn …"
# use the virtualenv interpreter.
create_service "${APP_DIR}/.venv/bin:${APP_DIR}"
