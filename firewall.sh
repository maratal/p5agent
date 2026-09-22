#!/usr/bin/env bash
# The upplet's firewall (ufw) — a whitelist: deny all incoming, always, then
# allow listed ports. ufw itself is the record: its rules persist on disk and
# are what the dashboard's Firewall Settings shows and edits. Nothing here
# resets ufw; it is only ever changed rule by rule.
#
#   firewall.sh                 ensure: deny incoming by default; open each
#                               built-in port that has no rule yet (anyone may
#                               reach it); enable. Never removes a rule — a
#                               restriction set in Firewall Settings stays.
#   firewall.sh --plan          print the table as JSON: ufw's rules grouped by
#                               port, built-in ports marked, nothing changed
#   firewall.sh --set <file>    bring ufw to the table in <file>
#                               ({"rules": [{port, proto, from, raw?}]}) — only
#                               the difference is applied, removals first, so
#                               a changing rule is briefly closed, never open
#   firewall.sh --close <port>[/tcp|udp]
#                               remove every rule for that port — unless it is
#                               still a built-in port (an app uses it)
#
# Built-in ports: SSH (22), the agent (5005), 80 (ACME http-01, Nginx's
# redirect) and each installed app's port — its public-port when it is behind
# Nginx. They can be restricted to addresses but not removed. Any list of
# addresses always includes the dashboard's (P5AGENT_ALLOW_IP, and the address
# the agent received the request from): it drives the agent and probes every app.

set -uo pipefail

[[ "$(id -u)" -eq 0 ]] || { echo "firewall.sh must be run as root" >&2; exit 1; }
command -v ufw >/dev/null 2>&1 || { echo "ufw not found — cannot configure the firewall" >&2; exit 1; }

ENV_FILE="/etc/p5agent.env"
getenvval() {  # value of KEY: from the environment, else from $ENV_FILE
    local key="$1" cur="${!1:-}"
    if [[ -n "$cur" ]]; then printf '%s' "$cur"; return; fi
    [[ -f "$ENV_FILE" ]] && sed -n "s/^${key}=//p" "$ENV_FILE" | head -n1
}
PORT="$(getenvval P5AGENT_PORT)";          PORT="${PORT:-5005}"
DATA_DIR="$(getenvval P5AGENT_DATA_DIR)";   DATA_DIR="${DATA_DIR:-/var/lib/p5agent}"

case "${1:-}" in
    ""|--plan|--set|--close) ;;
    *) echo "usage: firewall.sh [--plan | --set <file> | --close <port>[/proto]]" >&2; exit 2 ;;
esac

exec python3 - "$DATA_DIR/installed_apps.json" "$PORT" "$(getenvval P5AGENT_ALLOW_IP)" "$@" <<'PY'
import ipaddress, json, os, re, subprocess, sys

installed, agent_port, allow_ip = sys.argv[1], int(sys.argv[2]), sys.argv[3]
args = sys.argv[4:]
mode = args[0] if args else "ensure"

def public_addr(text):
    """`text` as a plain address, or None for loopback, unspecified or not an
    address at all."""
    try:
        a = ipaddress.ip_address(str(text).strip())
    except ValueError:
        return None
    if getattr(a, "ipv4_mapped", None):
        a = a.ipv4_mapped
    return None if a.is_loopback or a.is_unspecified else str(a)

# The dashboard's addresses: P5AGENT_ALLOW_IP, plus the address the request
# that runs this came from (P5AGENT_CALLER_IP, set by the agent) — so it is
# known even when P5AGENT_ALLOW_IP is unset.
dashboard = []
for ip in allow_ip.split(",") + [os.environ.get("P5AGENT_CALLER_IP", "")]:
    ip = public_addr(ip)
    if ip and ip not in dashboard:
        dashboard.append(ip)

def say(mark, text):
    colour = {"→": "\033[1;34m", "✗": "\033[1;31m", "!": "\033[1;33m"}.get(mark)
    print(("%s%s %s\033[0m" % (colour, mark, text)) if colour else "%s %s" % (mark, text), flush=True)

def fail(text):
    say("✗", text)
    sys.exit(1)

def ufw(*a):
    p = subprocess.run(["ufw"] + list(a), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout.strip()

def src(text):
    """An address or network as ufw would compare it; 'any' for anyone."""
    text = str(text).strip()
    if text in ("", "any", "Anywhere"):
        return "any"
    net = ipaddress.ip_network(text, strict=False)   # ValueError on garbage
    return str(net.network_address) if net.num_addresses == 1 else str(net)

def show(port, proto, source):
    return "%s/%s from %s" % (port, proto, "anywhere" if source == "any" else source)

# ── Built-in ports ────────────────────────────────────────────────────────────
def builtin():
    rows = {(22, "tcp"): "SSH", (agent_port, "tcp"): "p5agent", (80, "tcp"): "ACME http-01 / Nginx"}
    try:
        apps = json.load(open(installed))
    except Exception:
        apps = []
    for a in apps:
        p = str(a.get("public-port") or a.get("port") or "443").strip()
        if p.isdigit():
            k = (int(p), "tcp")
            label = str(a.get("name") or "app") + (" (nginx)" if a.get("public-port") else "")
            rows[k] = rows[k] + ", " + label if k in rows else label
    return rows

# ── What ufw has ──────────────────────────────────────────────────────────────
# ufw prints a comment quoted ('SSH'); an unquoted one is read the same way.
COMMENT = r"(?: comment (?:'(.*)'|(\S+)))?$"
SIMPLE = re.compile(r"^allow (\d+)/(tcp|udp)" + COMMENT)
FROM = re.compile(r"^allow from (\S+) to any port (\d+) proto (tcp|udp)" + COMMENT)

def current():
    """{(port, proto): {"from": set, "label": str}} and the rules this cannot
    read (ranges, limit, deny, …) as their ufw text."""
    rc, out = ufw("show", "added")
    groups, raw = {}, []
    for line in out.splitlines():
        if not line.startswith("ufw "):
            continue
        rule = line[4:].strip()
        m, f = SIMPLE.match(rule), FROM.match(rule)
        if m:
            k, s, label = (int(m.group(1)), m.group(2)), "any", m.group(3) or m.group(4) or ""
        elif f:
            try:
                k, s, label = (int(f.group(2)), f.group(3)), src(f.group(1)), f.group(4) or f.group(5) or ""
            except ValueError:
                raw.append(rule)
                continue
        else:
            raw.append(rule)
            continue
        g = groups.setdefault(k, {"from": set(), "label": label})
        g["from"].add(s)
        g["label"] = g["label"] or label
    return groups, raw

def add(k, s, label):
    a = ["allow", "%s/%s" % k] if s == "any" else ["allow", "from", s, "to", "any", "port", str(k[0]), "proto", k[1]]
    rc, msg = ufw(*(a + ["comment", label or "custom"]))
    say("✓" if rc == 0 else "!", ("Opened %s — %s" % (show(k[0], k[1], s), label or "custom")) if rc == 0 else "Could not open %s: %s" % (show(k[0], k[1], s), msg))

def delete(k, s):
    a = ["allow", "%s/%s" % k] if s == "any" else ["allow", "from", s, "to", "any", "port", str(k[0]), "proto", k[1]]
    rc, msg = ufw("--force", "delete", *a)
    say("✓" if rc == 0 else "!", ("Closed %s" % show(k[0], k[1], s)) if rc == 0 else "Could not close %s: %s" % (show(k[0], k[1], s), msg))

def floor():
    ufw("default", "deny", "incoming")
    ufw("default", "allow", "outgoing")
    say("✓", "Default: deny all incoming, allow outgoing")

def ensure_builtin(groups):
    for k, label in builtin().items():
        if k not in groups:
            add(k, "any", label)
            groups[k] = {"from": {"any"}, "label": label}

def enable():
    rc, msg = ufw("--force", "enable")
    if rc != 0:
        fail("Could not enable the firewall: %s" % msg)
    say("✓", "Firewall active: only the listed ports accept incoming connections")

# ── plan ──────────────────────────────────────────────────────────────────────
if mode == "--plan":
    groups, raw = current()
    rows, bi = [], builtin()
    for k in list(bi) + sorted(k for k in groups if k not in bi):
        g = groups.get(k, {"from": {"any"}, "label": ""})   # a built-in port with no rule yet opens to anyone
        sources = sorted(s for s in g["from"] if s != "any")
        rows.append({"port": k[0], "proto": k[1],
                     "from": [] if "any" in g["from"] else sources,
                     "label": bi.get(k) or g["label"] or "custom", "managed": k in bi})
    for r in raw:
        rows.append({"raw": r, "label": "added by hand", "managed": False})
    print(json.dumps({"rules": rows, "agent_port": agent_port, "dashboard": dashboard}))
    sys.exit(0)

# ── close ─────────────────────────────────────────────────────────────────────
if mode == "--close":
    spec = (args[1] if len(args) > 1 else "").split("/")
    if not spec[0].isdigit():
        fail("usage: firewall.sh --close <port>[/tcp|udp]")
    k = (int(spec[0]), spec[1] if len(spec) > 1 else "tcp")
    if k in builtin():
        say("✓", "Port %s/%s stays open — %s still uses it" % (k[0], k[1], builtin()[k]))
        sys.exit(0)
    groups, _ = current()
    for s in sorted(groups.get(k, {"from": set()})["from"]):
        delete(k, s)
    sys.exit(0)

# ── set ───────────────────────────────────────────────────────────────────────
if mode == "--set":
    try:
        posted = json.load(open(args[1]))
        rules = posted["rules"]
        assert isinstance(rules, list)
    except Exception:
        fail("The request is not a rule list")
    bi = builtin()
    wanted, raw_kept = {}, set()
    for r in rules:
        if r.get("raw"):
            raw_kept.add(str(r["raw"]))
            continue
        try:
            k = (int(r.get("port")), str(r.get("proto") or "tcp").lower())
        except (TypeError, ValueError):
            fail("Not a port: %r" % r.get("port"))
        if not 1 <= k[0] <= 65535 or k[1] not in ("tcp", "udp"):
            fail("Not a valid port/protocol: %s/%s" % k)
        try:
            sources = {src(a) for a in (r.get("from") or []) if str(a).strip()}
        except ValueError as exc:
            fail("Not an IP address or network: %s" % exc)
        if sources:
            if k == (agent_port, "tcp") and not dashboard:
                fail("P5AGENT_ALLOW_IP is not set, so the agent port cannot be restricted "
                     "without locking the dashboard out")
            sources |= {src(ip) for ip in dashboard}    # the dashboard is always on a list
        wanted[k] = sources or {"any"}

    groups, raw = current()
    floor()
    # Built-in ports cannot be removed: one missing from the request is left as it is.
    for k in bi:
        if k not in wanted and k in groups:
            wanted[k] = set(groups[k]["from"])
    # Removals first — a changing rule is briefly closed, never briefly open.
    for r in raw:
        if r not in raw_kept:
            rc, msg = ufw("--force", "delete", *re.sub(r" comment .*$", "", r).split())
            say("✓" if rc == 0 else "!", ("Removed %s" % r) if rc == 0 else "Could not remove %s: %s" % (r, msg))
    for k in sorted(groups):
        for s in sorted(groups[k]["from"] - wanted.get(k, set())):
            delete(k, s)
    for k in sorted(wanted):
        label = bi.get(k) or (groups.get(k) or {}).get("label") or "custom"
        for s in sorted(wanted[k] - (groups.get(k) or {"from": set()})["from"]):
            add(k, s, label)
    ensure_builtin({k: {"from": v} for k, v in wanted.items()})
    enable()
    sys.exit(0)

# ── ensure (install, update, app and Nginx changes) ───────────────────────────
say("→", "Checking the firewall")
groups, _ = current()
floor()
ensure_builtin(groups)
enable()
PY
