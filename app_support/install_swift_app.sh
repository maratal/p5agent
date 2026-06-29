#!/usr/bin/env bash
# Standard minimal Swift app builder + service. Run from the app directory by
# install_app.sh (with APP_DIR / APP_NAME / APP_PORT / APP_CMD in the env) when
# the cloned repo has no setup.sh/install.sh of its own.
set -e

# swiftc is memory-hungry; on small droplets the build OOMs/hangs without swap.
# Add a 2G swapfile if none is active (best-effort).
if ! swapon --show 2>/dev/null | grep -q .; then
    echo "Adding 2G swap for the build"
    if [[ ! -f /swapfile ]]; then
        fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 2>/dev/null || true
        chmod 600 /swapfile 2>/dev/null || true
        mkswap /swapfile >/dev/null 2>&1 || true
    fi
    swapon /swapfile 2>/dev/null || true
fi

echo "Building Swift app: swift build -c release"
# Filter the (very verbose) build output to progress + warnings/errors. Capture
# swift's own exit code via PIPESTATUS so a failed build still fails the install
# (grep would otherwise mask it).
set +e
swift build -c release 2>&1 | grep -E "^(Compiling|Linking|Build complete)|warning:|error:"
build_rc=${PIPESTATUS[0]}
set -e
[[ "$build_rc" -eq 0 ]] || exit "$build_rc"

# Move the built executable(s) into the app root so the run command resolves
# them there (e.g. "App serve" → $APP_DIR/App).
bin_path=$(swift build -c release --show-bin-path)
find "$bin_path" -maxdepth 1 -type f -perm -u+x -exec mv -f {} "$APP_DIR/" \;
echo "Swift build complete"

# Service — the binary now lives in the app root.
create_service "${APP_DIR}"
