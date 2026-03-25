#!/bin/bash
# =============================================================
# daily_security_check.sh
# Supply Chain & Credential Security — Daily Check Script
# Updated: 2026-03-25
#
# Now auto-discovers all Node.js and Python projects under
# SCAN_ROOT and runs npm audit / pip-audit in each.
#
# Usage:  bash daily_security_check.sh [scan_root]
#         Default scan_root: ~/Code
# =============================================================

SCAN_ROOT="${1:-$HOME/Code}"
SCAN_DEPTH=10          # how deep to look for projects
MAX_AUDIT_TIME=60      # seconds per audit before timeout
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-create MEMORY.md from template if it doesn't exist
MEMORY_FILE="$SCRIPT_DIR/MEMORY.md"
MEMORY_TEMPLATE="$SCRIPT_DIR/MEMORY.template.md"
if [ ! -f "$MEMORY_FILE" ] && [ -f "$MEMORY_TEMPLATE" ]; then
    cp "$MEMORY_TEMPLATE" "$MEMORY_FILE"
    echo "Created MEMORY.md from template"
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
header "1. Python — Known Compromised Packages (Global)"
# ─────────────────────────────────────────────
python3 - <<'PYCHECK'
import importlib.metadata as meta
compromised = {
    "litellm":       ["1.82.7", "1.82.8"],
    "ultralytics":   ["8.3.41", "8.3.42", "8.3.45", "8.3.46"],
    "aiohttp":       [],
    "requests":      [],
}
for pkg, bad in compromised.items():
    try:
        v = meta.version(pkg)
        if bad and v in bad:
            print(f"WARN: COMPROMISED version of {pkg} == {v} — uninstall immediately!")
        elif not bad:
            print(f"INFO: {pkg} {v} installed — monitor for compromise alerts")
        else:
            print(f"OK: {pkg} {v} (not a known bad version)")
    except meta.PackageNotFoundError:
        print(f"OK: {pkg} not installed")
PYCHECK

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
header "7. Node.js Projects — Recursive npm audit"
# ─────────────────────────────────────────────
if command -v npm &>/dev/null; then
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
            AUDIT=$(cd "$proj" && timeout "$MAX_AUDIT_TIME" npm audit --json 2>/dev/null)
            if [ $? -eq 124 ]; then
                info "$proj_name — npm audit timed out"
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
                pass "$proj_name — 0 vulnerabilities"
            elif [ "$VULN_COUNT" != "0" ] && [ "$VULN_COUNT" != "?" ]; then
                warn "$proj_name — $VULN_COUNT high/critical vulns ($TOTAL total)"
            elif [ "$TOTAL" != "?" ]; then
                info "$proj_name — $TOTAL vulnerabilities (none high/critical)"
            else
                info "$proj_name — npm audit parse error, run manually"
            fi
        done
    fi

    # Global npm packages
    GLOBAL_PKGS=$(npm list -g --depth=0 2>/dev/null | grep -c "@" || echo 0)
    info "$GLOBAL_PKGS global npm packages — run 'npm list -g --depth=0' to review"
else
    info "npm not found — skipping Node.js checks"
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
declare -A PY_SEEN
PY_UNIQUE=()
for p in "${PY_PROJECTS[@]}"; do
    if [ -z "${PY_SEEN[$p]}" ]; then
        PY_SEEN[$p]=1
        PY_UNIQUE+=("$p")
    fi
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
    TRIVY_BAD=("aquasec/trivy:0.69.4" "aquasec/trivy:0.69.5" "aquasec/trivy:0.69.6")
    IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null)
    for bad_img in "${TRIVY_BAD[@]}"; do
        echo "$IMAGES" | grep -q "^$bad_img$" && warn "COMPROMISED Docker image: $bad_img"
    done
    CONTAINER_COUNT=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
    info "$CONTAINER_COUNT running container(s)"
    pass "Docker image check complete"
else
    pass "Docker not installed — skip"
fi

# ─────────────────────────────────────────────
header "10. GitHub Actions — Pinning Check (Recursive)"
# ─────────────────────────────────────────────
UNPINNED=0
while IFS= read -r -d '' wf; do
    UNPINNED_LINES=$(grep -nE "uses:\s+[^@]+@v[0-9]" "$wf" 2>/dev/null)
    if [ -n "$UNPINNED_LINES" ]; then
        wf_name="${wf#$SCAN_ROOT/}"
        warn "Unpinned GitHub Action in $wf_name:"
        echo "$UNPINNED_LINES" | head -3 | sed 's/^/    /'
        UNPINNED=$((UNPINNED+1))
    fi
done < <(find "$SCAN_ROOT" -maxdepth "$SCAN_DEPTH" -path "*/.github/workflows/*.yml" -print0 2>/dev/null)
[ "$UNPINNED" -eq 0 ] && pass "All GitHub Actions pinned (or none found)"

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
