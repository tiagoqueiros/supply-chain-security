#!/bin/bash
export PATH="$HOME/.local/bin:$PATH"
# =============================================================
# daily_security_check.sh
# Supply Chain & Credential Security — Daily Check Script
# Updated: 2026-03-25
#
# Now auto-discovers all Node.js and Python projects under
# SCAN_ROOT and runs npm audit / pip-audit in each.
#
# Usage:  bash daily_security_check.sh [scan_root]
#         Default scan_root: ~
# =============================================================

SCAN_ROOT="${1:-$HOME}"
SCAN_DEPTH=10          # how deep to look for projects
MAX_AUDIT_TIME=60      # seconds per audit before timeout
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Detect interactive vs non-interactive (scheduled task, CI, pipe)
[ -t 0 ] && INTERACTIVE=true || INTERACTIVE=false

# Auto-create MEMORY.md from template if it doesn't exist
MEMORY_FILE="$SCRIPT_DIR/MEMORY.md"
MEMORY_TEMPLATE="$SCRIPT_DIR/MEMORY.template.md"
PACKAGES_CONF="$SCRIPT_DIR/packages.conf"
if [ ! -f "$MEMORY_FILE" ] && [ -f "$MEMORY_TEMPLATE" ]; then
    cp "$MEMORY_TEMPLATE" "$MEMORY_FILE"
    echo "Created MEMORY.md from template"
fi

# ─────────────────────────────────────────────
# Setup check — verify required tools are installed
# ─────────────────────────────────────────────
SETUP_OK=true
if ! command -v pip-audit &>/dev/null; then
    SETUP_OK=false
    if $INTERACTIVE; then
        echo ""
        echo "╔══════════════════════════════════════════════════════════╗"
        echo "║  SETUP: Missing recommended tools                        ║"
        echo "╚══════════════════════════════════════════════════════════╝"
        echo "  pip-audit not found — Python vulnerability scanning disabled."
        echo "  To install: pipx install pip-audit"
        echo ""
        printf "  Install pip-audit now? [y/N] "
        read -r REPLY </dev/tty
        if [ "$REPLY" = "y" ] || [ "$REPLY" = "Y" ]; then
            if command -v pipx &>/dev/null; then
                pipx install pip-audit && echo "  pip-audit installed via pipx." && SETUP_OK=true
            else
                pip3 install pip-audit && echo "  pip-audit installed." && SETUP_OK=true
            fi
        fi
    fi
    # Non-interactive: silently noted in section 8 output
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

WARNINGS=0
CHECKS=0

pass()   { echo -e "  ${GREEN}✓${NC} $1"; CHECKS=$((CHECKS+1)); }
warn()   { echo -e "  ${RED}⚠️  WARNING:${NC} $1"; WARNINGS=$((WARNINGS+1)); CHECKS=$((CHECKS+1)); }
info()   { echo -e "  ${YELLOW}ℹ${NC}  $1"; }
header() { echo -e "\n${BLUE}━━━ $1 ━━━${NC}"; }
sub()    { echo -e "  ${CYAN}→${NC} $1"; }

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║      Daily Supply Chain Security Check                   ║"
echo "║      $(date '+%Y-%m-%d %H:%M')                                   ║"
echo "║      Scan root: ${SCAN_ROOT}                             ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ─────────────────────────────────────────────
header "1. Known Compromised Packages (packages.conf)"
# ─────────────────────────────────────────────
if [ ! -f "$PACKAGES_CONF" ]; then
    warn "packages.conf not found at $PACKAGES_CONF — skipping compromised package checks"
else
python3 - "$PACKAGES_CONF" <<'PKGCHECK'
import sys, re, importlib.metadata as meta, subprocess

packages_conf = sys.argv[1]
pip_packages = []   # (name, bad_versions, all_bad, notes)
npm_packages = []   # (name, bad_versions, all_bad, notes)

def parse_conf(path):
    pip, npm = [], []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 3:
                continue
            ecosystem, pkg, bad_str = parts[0], parts[1], parts[2]
            notes = parts[3] if len(parts) > 3 else ""
            if bad_str.lower() == "all":
                bad_versions, all_bad = [], True
            elif bad_str.lower() in ("monitor", "-", ""):
                bad_versions, all_bad = [], False
            else:
                bad_versions = [v.strip() for v in bad_str.split(",") if v.strip()]
                all_bad = False
            if ecosystem == "pip":
                pip.append((pkg, bad_versions, all_bad, notes))
            elif ecosystem == "npm":
                npm.append((pkg, bad_versions, all_bad, notes))
    return pip, npm

try:
    pip_packages, npm_packages = parse_conf(packages_conf)
except Exception as e:
    print(f"  ERROR reading packages.conf: {e}")
    sys.exit(1)

# ── pip (global) ──
print("\n  \033[0;34m— pip (global) —\033[0m")
for pkg, bad_versions, all_bad, notes in pip_packages:
    try:
        v = meta.version(pkg)
        if all_bad:
            print(f"  \033[0;31m⚠️  WARNING: MALICIOUS pip package installed: {pkg} {v} — remove immediately! ({notes})\033[0m")
        elif bad_versions and v in bad_versions:
            print(f"  \033[0;31m⚠️  WARNING: COMPROMISED version {pkg}=={v} — remove immediately! ({notes})\033[0m")
        elif bad_versions:
            print(f"  \033[0;32m✓\033[0m {pkg} {v} (safe; bad versions: {', '.join(bad_versions)})")
        else:
            print(f"  \033[1;33mℹ\033[0m  {pkg} {v} installed — monitoring ({notes})")
    except meta.PackageNotFoundError:
        print(f"  \033[0;32m✓\033[0m {pkg} not installed")

# ── npm (global) ──
print("\n  \033[0;34m— npm (global) —\033[0m")
try:
    result = subprocess.run(["npm", "list", "-g", "--depth=0"], capture_output=True, text=True, timeout=15)
    npm_global = result.stdout
except Exception:
    npm_global = ""

for pkg, bad_versions, all_bad, notes in npm_packages:
    m = re.search(rf"(?:^|\s){re.escape(pkg)}@([\d.\w-]+)", npm_global, re.MULTILINE)
    if m:
        v = m.group(1)
        if all_bad:
            print(f"  \033[0;31m⚠️  WARNING: MALICIOUS npm package globally: {pkg}@{v} — remove immediately!\033[0m")
        elif bad_versions and v in bad_versions:
            print(f"  \033[0;31m⚠️  WARNING: COMPROMISED npm version {pkg}@{v} — remove immediately! ({notes})\033[0m")
        elif bad_versions:
            print(f"  \033[1;33mℹ\033[0m  {pkg}@{v} installed globally (safe version; bad: {', '.join(bad_versions)})")
        else:
            print(f"  \033[1;33mℹ\033[0m  {pkg}@{v} installed globally — monitoring ({notes})")
    else:
        print(f"  \033[0;32m✓\033[0m {pkg} not installed globally")
PKGCHECK
fi

# ─────────────────────────────────────────────
header "1b. Malicious npm Packages — Project node_modules"
# ─────────────────────────────────────────────
if [ ! -f "$PACKAGES_CONF" ]; then
    info "packages.conf not found — skipping project node_modules check"
else
    PROJ_HIT=false
    while IFS='|' read -r ecosystem pkg bad_versions notes; do
        [[ -z "$ecosystem" || "$ecosystem" == \#* || "$ecosystem" != "npm" ]] && continue
        pkg="${pkg// /}"
        MATCHES=$(find "$SCAN_ROOT" -maxdepth $((SCAN_DEPTH+1)) -type d \
            -path "*/node_modules/$pkg" 2>/dev/null)
        if [ -n "$MATCHES" ]; then
            while IFS= read -r match; do
                warn "Malicious npm package in project: $pkg → ${match#$SCAN_ROOT/}"
                PROJ_HIT=true
            done <<< "$MATCHES"
        fi
    done < "$PACKAGES_CONF"
    $PROJ_HIT || pass "No malicious npm packages found in project node_modules"
fi

# ─────────────────────────────────────────────
header "2. Python — Suspicious .pth Auto-Exec Files"
# ─────────────────────────────────────────────
LEGIT_PTH=("uno.pth" "coloredlogs.pth" "easy-install.pth" "distutils-precedence.pth" "README.pth" "setuptools.pth" "_virtualenv.pth")
SITE_PKG=$(python3 -c "import site; print(site.getsitepackages()[0])" 2>/dev/null)
if [ -n "$SITE_PKG" ]; then
    while IFS= read -r -d '' pth_file; do
        fname=$(basename "$pth_file")
        is_legit=false
        for legit in "${LEGIT_PTH[@]}"; do
            [ "$fname" = "$legit" ] && is_legit=true && break
        done
        if $is_legit; then
            pass "$fname — known legitimate"
        else
            if grep -qE "import |exec\(|os\.|subprocess|__import__" "$pth_file" 2>/dev/null; then
                warn "SUSPICIOUS .pth file with executable code: $pth_file"
                head -3 "$pth_file" | sed 's/^/    /'
            else
                info "Unknown .pth file (review manually): $pth_file"
            fi
        fi
    done < <(find "$SITE_PKG" -name "*.pth" -print0 2>/dev/null)
else
    info "Could not determine site-packages directory"
fi

# ─────────────────────────────────────────────
header "3. Exposed .env Files"
# ─────────────────────────────────────────────
ENV_COUNT=0
while IFS= read -r -d '' f; do
    # Skip .env.example / .env.template / .env.sample
    case "$f" in *.example|*.template|*.sample) continue ;; esac
    warn "Exposed .env file: $f"
    ENV_COUNT=$((ENV_COUNT+1))
done < <(find "$HOME" /tmp /var/tmp -maxdepth 6 \( -name ".env" -o -name "*.env" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" -not -path "*/venv/*" \
    -not -path "*/.venv/*" -not -name "*.example" -not -name "*.template" \
    -not -name "*.sample" -print0 2>/dev/null)
[ "$ENV_COUNT" -eq 0 ] && pass "No exposed .env files found"

# ─────────────────────────────────────────────
header "3b. Registry Credential Files (.npmrc / .pypirc)"
# ─────────────────────────────────────────────
# Global ~/.npmrc
if [ -f "$HOME/.npmrc" ]; then
    if grep -qE "_authToken|password" "$HOME/.npmrc" 2>/dev/null; then
        info "~/.npmrc contains registry auth tokens — ensure it's not committed to git"
        grep -E "_authToken|password" "$HOME/.npmrc" | sed 's/=.*/=[REDACTED]/' | sed 's/^/    /'
    else
        pass "~/.npmrc — no auth tokens"
    fi
fi
# Project .npmrc files with credentials
NPMRC_HIT=false
while IFS= read -r -d '' f; do
    if grep -qE "_authToken|password" "$f" 2>/dev/null; then
        warn "Project .npmrc with credentials: ${f#$SCAN_ROOT/}"
        NPMRC_HIT=true
    fi
done < <(find "$SCAN_ROOT" -maxdepth "$SCAN_DEPTH" -name ".npmrc" \
    -not -path "$HOME/.npmrc" -not -path "*/node_modules/*" -print0 2>/dev/null)
$NPMRC_HIT || pass "No project .npmrc files with exposed credentials"

# ~/.pypirc
if [ -f "$HOME/.pypirc" ]; then
    if grep -qE "password|token" "$HOME/.pypirc" 2>/dev/null; then
        info "~/.pypirc contains credentials — ensure it's not committed to git"
    else
        pass "~/.pypirc — no plaintext credentials"
    fi
fi

# .npmrc registry spoofing — non-official registry URLs can enable dependency confusion
REGISTRY_HIT=false
for npmrc in "$HOME/.npmrc" $(find "$SCAN_ROOT" -maxdepth "$SCAN_DEPTH" -name ".npmrc" \
    -not -path "$HOME/.npmrc" -not -path "*/node_modules/*" 2>/dev/null); do
    [ -f "$npmrc" ] || continue
    CUSTOM_REG=$(grep -E "^registry\s*=" "$npmrc" 2>/dev/null | grep -v "registry.npmjs.org" || true)
    if [ -n "$CUSTOM_REG" ]; then
        info "Non-official npm registry in ${npmrc#$HOME/}: $CUSTOM_REG"
        REGISTRY_HIT=true
    fi
done
$REGISTRY_HIT || pass "All .npmrc files point to official registry (or none set)"

# ─────────────────────────────────────────────
header "4. Shell Startup File Integrity"
# ─────────────────────────────────────────────
SHELL_FILES=("$HOME/.bashrc" "$HOME/.bash_profile" "$HOME/.zshrc" "$HOME/.zprofile" "$HOME/.profile" "$HOME/.bash_aliases")
SUSPICIOUS_PATTERNS='(curl|wget)\s+(http|-).*\|.*sh|python.*-c.*http|base64.*decode.*exec|nc\s+-e|ncat\s+-e|mkfifo.*>/dev/tcp'
for f in "${SHELL_FILES[@]}"; do
    if [ -f "$f" ]; then
        if grep -qE "$SUSPICIOUS_PATTERNS" "$f" 2>/dev/null; then
            warn "Suspicious content in $f — review immediately"
            grep -nE "$SUSPICIOUS_PATTERNS" "$f" | head -5
        else
            pass "$(basename "$f") — clean"
        fi
    fi
done

# ─────────────────────────────────────────────
header "5. Crontab Check"
# ─────────────────────────────────────────────
CRON_CONTENT=$(crontab -l 2>/dev/null)
if [ -z "$CRON_CONTENT" ]; then
    pass "No user crontab entries"
else
    if echo "$CRON_CONTENT" | grep -qE "$SUSPICIOUS_PATTERNS"; then
        warn "Suspicious crontab entry detected"
        echo "$CRON_CONTENT"
    else
        info "Crontab has entries — review below:"
        echo "$CRON_CONTENT" | sed 's/^/    /'
    fi
fi

# ─────────────────────────────────────────────
header "6. SSH Key Check"
# ─────────────────────────────────────────────
if [ -d "$HOME/.ssh" ]; then
    KEY_COUNT=$(find "$HOME/.ssh" -name "*.pub" 2>/dev/null | wc -l | tr -d ' ')
    AUTH_KEYS="$HOME/.ssh/authorized_keys"
    if [ -f "$AUTH_KEYS" ]; then
        AUTH_COUNT=$(wc -l < "$AUTH_KEYS" | tr -d ' ')
        info "$AUTH_COUNT authorized key(s) — verify these are all yours"
    fi
    pass "$KEY_COUNT SSH public key(s) in ~/.ssh"
else
    pass "No .ssh directory found"
fi

# ─────────────────────────────────────────────
header "6b. macOS Launch Agents / Daemons"
# ─────────────────────────────────────────────
if [ "$(uname)" = "Darwin" ]; then
    LAUNCH_DIRS=(
        "$HOME/Library/LaunchAgents"
        "/Library/LaunchAgents"
        "/Library/LaunchDaemons"
    )
    LAUNCH_SUSPICIOUS='(curl|wget)\s+(http|-).*\|.*sh|python.*-c.*http|base64.*decode|nc\s+-e|/tmp/|ProgramArguments.*curl'
    LAUNCH_HIT=false
    for ldir in "${LAUNCH_DIRS[@]}"; do
        [ -d "$ldir" ] || continue
        while IFS= read -r -d '' plist; do
            plist_name="${plist#$HOME/}"
            if grep -qE "$LAUNCH_SUSPICIOUS" "$plist" 2>/dev/null; then
                warn "Suspicious Launch Agent/Daemon: $plist_name"
                grep -E "$LAUNCH_SUSPICIOUS" "$plist" | head -2 | sed 's/^/    /'
                LAUNCH_HIT=true
            else
                info "$plist_name — $(basename "$plist")"
            fi
        done < <(find "$ldir" -maxdepth 1 -name "*.plist" -print0 2>/dev/null)
    done
    $LAUNCH_HIT || pass "No suspicious Launch Agents/Daemons found"
else
    info "Not macOS — skipping Launch Agent check"
fi

# ─────────────────────────────────────────────
header "7. Node.js Projects — Recursive audit (npm / pnpm / yarn / bun)"
# ─────────────────────────────────────────────
if command -v npm &>/dev/null || command -v pnpm &>/dev/null; then
    NPM_PROJECTS=()
    while IFS= read -r -d '' pj; do
        NPM_PROJECTS+=("$(dirname "$pj")")
    done < <(find "$SCAN_ROOT" -maxdepth "$SCAN_DEPTH" -name "package.json" \
        -not -path "*/node_modules/*" -not -path "*/.git/*" \
        -not -path "*/dist/*" -not -path "*/build/*" -print0 2>/dev/null)

    if [ ${#NPM_PROJECTS[@]} -eq 0 ]; then
        info "No Node.js projects found under $SCAN_ROOT"
    else
        info "Found ${#NPM_PROJECTS[@]} Node.js project(s)"
        for proj in "${NPM_PROJECTS[@]}"; do
            proj_name="${proj#$SCAN_ROOT/}"
            if [ ! -d "$proj/node_modules" ]; then
                info "$proj_name — no node_modules (skipped, not installed)"
                continue
            fi

            # Pick the right auditor based on lockfile
            if [ -f "$proj/pnpm-lock.yaml" ] && command -v pnpm &>/dev/null; then
                AUDIT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" pnpm audit --json 2>/dev/null)
                AUDITOR="pnpm"
            elif [ -f "$proj/yarn.lock" ] && command -v yarn &>/dev/null; then
                AUDIT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" yarn audit --json 2>/dev/null)
                AUDITOR="yarn"
            elif [ -f "$proj/bun.lockb" ] && command -v bun &>/dev/null; then
                AUDIT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" bun pm audit --json 2>/dev/null)
                AUDITOR="bun"
            else
                AUDIT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" npm audit --json 2>/dev/null)
                AUDITOR="npm"
            fi

            if [ $? -eq 124 ]; then
                info "$proj_name — $AUDITOR audit timed out"
                continue
            fi
            VULN_COUNT=$(echo "$AUDIT" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    v=d.get('metadata',{}).get('vulnerabilities',{})
    print(v.get('high',0) + v.get('critical',0))
except: print('?')" 2>/dev/null)
            TOTAL=$(echo "$AUDIT" | python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    print(d.get('metadata',{}).get('vulnerabilities',{}).get('total',0))
except: print('?')" 2>/dev/null)
            if [ "$TOTAL" = "0" ]; then
                pass "$proj_name [$AUDITOR] — 0 vulnerabilities"
            elif [ "$VULN_COUNT" != "0" ] && [ "$VULN_COUNT" != "?" ]; then
                warn "$proj_name [$AUDITOR] — $VULN_COUNT high/critical vulns ($TOTAL total)"
            elif [ "$TOTAL" != "?" ]; then
                info "$proj_name [$AUDITOR] — $TOTAL vulnerabilities (none high/critical)"
            else
                info "$proj_name [$AUDITOR] — audit parse error, run manually"
            fi
        done
    fi

    # Global npm packages
    GLOBAL_PKGS=$(npm list -g --depth=0 2>/dev/null | grep -c "@" || echo 0)
    info "$GLOBAL_PKGS global npm packages — run 'npm list -g --depth=0' to review"
else
    info "npm/pnpm not found — skipping Node.js checks"
fi

# ─────────────────────────────────────────────
header "8. Python Projects — Recursive pip-audit"
# ─────────────────────────────────────────────
PY_PROJECTS=()
while IFS= read -r -d '' pf; do
    PY_PROJECTS+=("$(dirname "$pf")")
done < <(find "$SCAN_ROOT" -maxdepth "$SCAN_DEPTH" \
    \( -name "requirements.txt" -o -name "pyproject.toml" -o -name "Pipfile" -o -name "setup.py" \) \
    -not -path "*/node_modules/*" -not -path "*/.git/*" \
    -not -path "*/venv/*" -not -path "*/.venv/*" -print0 2>/dev/null)

# Deduplicate (a project may have both requirements.txt and pyproject.toml)
# Uses bash 3.2-compatible approach (no associative arrays)
PY_UNIQUE=()
for p in "${PY_PROJECTS[@]}"; do
    already_seen=false
    for seen in "${PY_UNIQUE[@]}"; do
        [ "$seen" = "$p" ] && already_seen=true && break
    done
    $already_seen || PY_UNIQUE+=("$p")
done

if [ ${#PY_UNIQUE[@]} -eq 0 ]; then
    info "No Python projects found under $SCAN_ROOT"
else
    info "Found ${#PY_UNIQUE[@]} Python project(s)"
    if command -v pip-audit &>/dev/null; then
        for proj in "${PY_UNIQUE[@]}"; do
            proj_name="${proj#$SCAN_ROOT/}"
            # Try venv first, then global
            VENV_PYTHON=""
            for vp in "$proj/.venv/bin/python" "$proj/venv/bin/python"; do
                [ -x "$vp" ] && VENV_PYTHON="$vp" && break
            done

            if [ -n "$VENV_PYTHON" ]; then
                AUDIT_OUT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" pip-audit --python "$VENV_PYTHON" 2>&1)
            elif [ -f "$proj/requirements.txt" ]; then
                AUDIT_OUT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" pip-audit -r requirements.txt 2>&1)
            else
                AUDIT_OUT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" pip-audit 2>&1)
            fi

            VULN_LINES=$(echo "$AUDIT_OUT" | grep -c "^Name" 2>/dev/null || echo 0)
            FOUND=$(echo "$AUDIT_OUT" | grep -oE "Found [0-9]+ known vulnerabilit" | grep -oE "[0-9]+" || echo "0")

            if [ "$FOUND" = "0" ]; then
                pass "$proj_name — no known vulnerabilities"
            else
                warn "$proj_name — $FOUND known vulnerability(ies)"
                echo "$AUDIT_OUT" | grep -E "^[A-Za-z]" | grep -v "^Name" | sed 's/^/    /'
            fi
        done
    else
        warn "pip-audit not installed — run: pip install pip-audit"
    fi
fi

# Also run pip-audit globally
header "8b. Python Global Environment"
if command -v pip-audit &>/dev/null; then
    GLOBAL_AUDIT=$(timeout "$MAX_AUDIT_TIME" pip-audit 2>&1)
    GLOBAL_FOUND=$(echo "$GLOBAL_AUDIT" | grep -oE "Found [0-9]+ known vulnerabilit" | grep -oE "[0-9]+" || echo "0")
    if [ "$GLOBAL_FOUND" = "0" ]; then
        pass "Global Python env — no known vulnerabilities"
    else
        warn "Global Python env — $GLOBAL_FOUND vulnerability(ies)"
        echo "$GLOBAL_AUDIT" | grep -E "^[A-Za-z]" | grep -v "^Name" | sed 's/^/    /'
    fi
else
    info "pip-audit not installed globally"
fi

# ─────────────────────────────────────────────
header "9. Docker — Suspicious Images"
# ─────────────────────────────────────────────
if command -v docker &>/dev/null; then
    IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null)
    DOCKER_HIT=false
    if [ -f "$PACKAGES_CONF" ]; then
        while IFS='|' read -r ecosystem pkg bad_versions notes; do
            [[ -z "$ecosystem" || "$ecosystem" == \#* || "$ecosystem" != "docker" ]] && continue
            pkg="${pkg// /}"; bad_versions="${bad_versions// /}"
            IFS=',' read -ra BADS <<< "$bad_versions"
            for bv in "${BADS[@]}"; do
                bv="${bv// /}"
                if echo "$IMAGES" | grep -q "^${pkg}:${bv}$"; then
                    warn "COMPROMISED Docker image: ${pkg}:${bv} — ${notes}"
                    DOCKER_HIT=true
                fi
            done
        done < "$PACKAGES_CONF"
    fi
    $DOCKER_HIT || pass "No known compromised Docker images found"
    CONTAINER_COUNT=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
    info "$CONTAINER_COUNT running container(s)"
else
    pass "Docker not installed — skip"
fi

# ─────────────────────────────────────────────
header "10. GitHub Actions — Pinning Check (Recursive)"
# ─────────────────────────────────────────────
UNPINNED=0
GHA_SUSPICIOUS=0
while IFS= read -r -d '' wf; do
    wf_name="${wf#$SCAN_ROOT/}"
    UNPINNED_LINES=$(grep -nE "uses:\s+[^@]+@v[0-9]" "$wf" 2>/dev/null)
    if [ -n "$UNPINNED_LINES" ]; then
        warn "Unpinned GitHub Action in $wf_name:"
        echo "$UNPINNED_LINES" | head -3 | sed 's/^/    /'
        UNPINNED=$((UNPINNED+1))
    fi
    SUSPICIOUS_RUN=$(grep -nE "(curl|wget).*(http|\-).*\|.*(sh|bash|python)|base64.*decode|eval.*curl" "$wf" 2>/dev/null)
    if [ -n "$SUSPICIOUS_RUN" ]; then
        warn "Suspicious run: step in GitHub Action $wf_name:"
        echo "$SUSPICIOUS_RUN" | head -3 | sed 's/^/    /'
        GHA_SUSPICIOUS=$((GHA_SUSPICIOUS+1))
    fi
done < <(find "$SCAN_ROOT" -maxdepth "$SCAN_DEPTH" -path "*/.github/workflows/*.yml" -print0 2>/dev/null)
[ "$UNPINNED" -eq 0 ] && pass "All GitHub Actions pinned (or none found)"
[ "$GHA_SUSPICIOUS" -eq 0 ] && pass "No suspicious run: patterns in GitHub Actions"

# ─────────────────────────────────────────────
header "11. VS Code / Cursor Extensions Check"
# ─────────────────────────────────────────────
EXT_COUNT=0
for ext_dir in "$HOME/.vscode/extensions" "$HOME/.cursor/extensions"; do
    if [ -d "$ext_dir" ]; then
        count=$(ls -1 "$ext_dir" 2>/dev/null | wc -l | tr -d ' ')
        EXT_COUNT=$((EXT_COUNT + count))
        info "$count extensions in $(basename "$(dirname "$ext_dir")")"
    fi
done
if [ "$EXT_COUNT" -gt 0 ]; then
    info "Review extensions periodically — GlassWorm campaign targeted VS Code/Cursor"
else
    pass "No VS Code/Cursor extensions found"
fi

# ─────────────────────────────────────────────
header "12. Supply Chain Feed Alerts (Last 3 Days)"
# ─────────────────────────────────────────────
FEED_SCRIPT="$(dirname "$0")/security_feed_check.sh"
if [ -x "$FEED_SCRIPT" ]; then
    bash "$FEED_SCRIPT" 3
else
    info "Feed checker not found at $FEED_SCRIPT — run it separately"
fi

# ─────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════════"
if [ "$WARNINGS" -eq 0 ]; then
    echo -e "  ${GREEN}✅ ALL CLEAR — $CHECKS checks passed, 0 warnings${NC}"
else
    echo -e "  ${RED}⚠️  $WARNINGS WARNING(S) found across $CHECKS checks${NC}"
    echo -e "  ${RED}   Review items marked ⚠️  above immediately${NC}"
fi
echo "══════════════════════════════════════════════════════════"
echo ""
echo "  Scanned: $SCAN_ROOT (depth $SCAN_DEPTH)"
echo "  Tip: Pass a different root: bash daily_security_check.sh /path/to/code"
echo ""
