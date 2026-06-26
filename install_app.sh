#!/usr/bin/env bash
# install_app.sh <request.json>
#
# Installs an app: its dependencies (from supported_deps.json) and the app
# itself (clone repo, then run setup.sh or install.sh). Run detached by the
# agent; it is the single owner of the install lifecycle.
#
# Everything is logged, line-by-line with timestamps, to $SETUP_LOG. The browser
# polls /progress (which returns that file) every few seconds. While the file
# exists and is being updated, an install is "in progress". On completion the
# log is moved to $TMP_DIR/x_setup_<ts>.log (and to ...-failed.log on failure),
# which leaves /progress empty — the browser's signal that nothing is running.
#
# Concurrency: a second invocation sees a recent $SETUP_LOG and exits. A stale
# log (untouched > 10 min) is treated as a failed run and archived first.

REQ="${1:?usage: install_app.sh <request.json>}"

HERE="$(cd "$(dirname "$0")" && pwd)"
SUPPORTED="$HERE/supported_deps.json"
DATA_DIR="${P5AGENT_DATA_DIR:-/var/lib/p5agent}"
TMP_DIR="${P5AGENT_TMP_DIR:-/tmp}"
APPS_DIR="${P5AGENT_APPS_DIR:-/opt}"
SETUP_LOG="$DATA_DIR/setup.log"
INSTALLED="$DATA_DIR/installed_apps.json"

mkdir -p "$DATA_DIR" "$TMP_DIR"

ts()       { date '+%Y-%m-%d %H:%M:%S'; }
logline()  { printf '[%s] %s\n' "$(ts)" "$*" >> "$SETUP_LOG"; }
stamp()    { while IFS= read -r line; do printf '[%s] %s\n' "$(ts)" "$line"; done >> "$SETUP_LOG"; }
runlog()   { bash -c "$1" 2>&1 | stamp; return "${PIPESTATUS[0]}"; }

archive() {  # archive() <suffix>  — move the log out of the way
    cp "$SETUP_LOG" "$TMP_DIR/x_setup_$(date +%Y%m%d_%H%M%S)${1:-}.log" 2>/dev/null || true
    rm -f "$SETUP_LOG"
}

fail() { logline "$*"; printf '\nSetup failed.\n' >> "$SETUP_LOG"; archive "-failed"; exit 1; }

# ── Concurrency / stale-log check ────────────────────────────────────────────
if [[ -f "$SETUP_LOG" ]]; then
    last=$(stat -c %Y "$SETUP_LOG" 2>/dev/null || echo 0)
    if (( $(date +%s) - last < 600 )); then
        exit 0   # an install is actively running — leave it alone
    fi
    # Stale (>10 min). Wait 30s; if still untouched, the previous run failed.
    sleep 30
    if [[ "$(stat -c %Y "$SETUP_LOG" 2>/dev/null || echo 0)" == "$last" ]]; then
        archive "-failed"
    else
        exit 0   # it moved — another run is active after all
    fi
fi

# ── Read the request ─────────────────────────────────────────────────────────
jget() { python3 -c "import json,sys;print(json.load(open(sys.argv[1])).get(sys.argv[2],'') or '')" "$REQ" "$1"; }
repo=$(jget repo); key=$(jget key); branch=$(jget branch)
name=$(jget name); product=$(jget product-name); port=$(jget port)
[[ -n "$name" ]] || { base="${repo##*/}"; name="${base%.git}"; }
target="$APPS_DIR/$name"

mapfile -t DEPS < <(python3 -c "
import json,re,sys
d=json.load(open(sys.argv[1])).get('dependencies') or []
if isinstance(d,str): d=[x for x in re.split(r'[,\n]',d) if x.strip()]
for x in d: print(str(x).strip())
" "$REQ")

# ── Start a fresh log ────────────────────────────────────────────────────────
: > "$SETUP_LOG"
logline "Setup started for ${product:-$name}"

# ── Install dependencies ─────────────────────────────────────────────────────
# Look up how to install a dependency in supported_deps.json (no per-package
# logic lives here — the registry carries the package-manager or install-cmd).
depinfo() {  # depinfo <name> -> "display-name<TAB>mode<TAB>payload"  (mode: cmd|apt|none)
    python3 - "$SUPPORTED" "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
dn = sys.argv[2].lower()
e = next((x for x in data if x.get("name", "").lower() == dn), None)
if not e:
    print("\t\t"); raise SystemExit
disp = e.get("display-name") or e.get("name")
if e.get("install-cmd"):
    print("%s\tcmd\t%s" % (disp, e["install-cmd"]))
elif e.get("package-manager") == "apt":
    print("%s\tapt\t%s" % (disp, e.get("package") or e.get("name")))
else:
    print("%s\tnone\t" % disp)
PY
}

if (( ${#DEPS[@]} == 0 )); then
    logline "No dependencies requested"
else
    logline "Updating package lists"
    runlog "apt-get update -qq"
    for dep in "${DEPS[@]}"; do
        depname="${dep%% *}"; depname="${depname,,}"
        version=""; [[ "$dep" == *" "* ]] && version="${dep#* }"

        IFS=$'\t' read -r display mode payload < <(depinfo "$depname")
        [[ -n "$display" ]] || fail "Unknown dependency '$depname' — aborting"

        logline "$display installation began"
        case "$mode" in
            cmd)
                # An install-cmd ending in .sh is a local script (in the repo),
                # run with the version as its argument; anything else is an
                # inline shell one-liner with {version} substituted.
                if [[ "$payload" == *.sh ]]; then
                    script="$HERE/$payload"
                    [[ -f "$script" ]] || fail "$display: install script not found ($payload)"
                    runlog "bash '$script' '$version'" || fail "$display installation failed"
                else
                    runlog "${payload//\{version\}/$version}" || fail "$display installation failed"
                fi
                ;;
            apt)
                if [[ -n "$version" ]]; then
                    runlog "DEBIAN_FRONTEND=noninteractive apt-get install -y '$payload=$version'" \
                        || runlog "DEBIAN_FRONTEND=noninteractive apt-get install -y '$payload'" \
                        || fail "$display installation failed"
                else
                    runlog "DEBIAN_FRONTEND=noninteractive apt-get install -y '$payload'" \
                        || fail "$display installation failed"
                fi
                ;;
            *)
                fail "No install method for '$depname'"
                ;;
        esac
        logline "$display installation completed"
    done
fi

# ── Install the app (clone + setup) ──────────────────────────────────────────
if [[ -n "$repo" ]]; then
    if [[ -d "$target/.git" ]]; then
        logline "$name already present at $target"
    else
        logline "$name installation began"
        clone_url="$repo"
        if [[ -n "$key" ]]; then
            case "$repo" in
                https://github.com/*) clone_url="https://x-access-token:$key@github.com/${repo#https://github.com/}" ;;
                https://*)            clone_url="https://$key@${repo#https://}" ;;
            esac
        fi
        if [[ -n "$branch" ]]; then
            runlog "git clone --depth 1 --branch '$branch' '$clone_url' '$target'" || fail "$name clone failed"
        else
            runlog "git clone --depth 1 '$clone_url' '$target'" || fail "$name clone failed"
        fi
    fi

    setup=""
    for candidate in setup.sh install.sh; do
        [[ -f "$target/$candidate" ]] && { setup="$target/$candidate"; break; }
    done
    if [[ -n "$setup" ]]; then
        logline "Running ${setup##*/}"
        ( cd "$target" && runlog "bash '$setup'" ) || fail "$name setup failed"
        logline "$name installation completed"
    else
        logline "No setup.sh or install.sh in repo — skipping setup"
    fi

    # ── Record the installed app ─────────────────────────────────────────────
    python3 - "$REQ" "$name" "$target" "$INSTALLED" <<'PY'
import json, os, sys
req_path, name, target, installed = sys.argv[1:5]
req = json.load(open(req_path))
apps = []
if os.path.exists(installed):
    try:
        apps = json.load(open(installed))
    except Exception:
        apps = []
apps = [a for a in apps if a.get("name") != name]
apps.append({
    "name": name,
    "product-name": req.get("product-name", ""),
    "path": target,
    "port": req.get("port", ""),
    "dependencies": req.get("dependencies") or [],
})
os.makedirs(os.path.dirname(installed), exist_ok=True)
json.dump(apps, open(installed, "w"), indent=2)
PY
    logline "Recorded $name in installed_apps.json"
fi

# ── Done ─────────────────────────────────────────────────────────────────────
printf '\nSetup completed.\n' >> "$SETUP_LOG"
archive ""
