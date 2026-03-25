#!/bin/bash
# =============================================================
# security_feed_check.sh
# Checks supply chain security RSS feeds for recent alerts
# Usage: bash security_feed_check.sh [days_back]
#        Default: 3 days
# =============================================================

DAYS_BACK="${1:-3}"
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo ""
echo "╔══════════════════════════════════════════════════════════╗"
echo "║      Supply Chain Security Feed Check                    ║"
echo "║      $(date '+%Y-%m-%d %H:%M')  —  Last ${DAYS_BACK} day(s)              ║"
echo "╚══════════════════════════════════════════════════════════╝"

# ─────────────────────────────────────────────
# Feed URLs
# ─────────────────────────────────────────────
FEEDS=(
    "Socket.dev|https://socket.dev/api/blog/feed.atom|atom"
    "Snyk Blog|https://snyk.io/blog/feed/|rss"
    "GitHub Security Lab|https://github.blog/tag/github-security-lab/feed/|rss"
    "Checkmarx|https://checkmarx.com/blog/feed/|rss"
)

# GitHub Advisory Database (malware-specific, via API)
GH_ADVISORY_API="https://api.github.com/advisories?type=malware&per_page=10"

CUTOFF_EPOCH=$(date -v-${DAYS_BACK}d +%s 2>/dev/null || date -d "-${DAYS_BACK} days" +%s 2>/dev/null)

# ─────────────────────────────────────────────
# Parse feeds with Python (handles both RSS and Atom)
# ─────────────────────────────────────────────
python3 - "$DAYS_BACK" "$CUTOFF_EPOCH" <<'PYFEED'
import sys, json, re, urllib.request, ssl
from xml.etree import ElementTree as ET
from datetime import datetime, timedelta, timezone

days_back = int(sys.argv[1])
cutoff_epoch = int(sys.argv[2])
cutoff_dt = datetime.fromtimestamp(cutoff_epoch, tz=timezone.utc)

feeds = [
    ("Socket.dev", "https://socket.dev/api/blog/feed.atom", "atom"),
    ("Snyk Blog", "https://snyk.io/blog/feed/", "rss"),
    ("GitHub Security Lab", "https://github.blog/tag/github-security-lab/feed/", "rss"),
]

# Supply chain keywords to highlight
KEYWORDS = re.compile(
    r"supply.chain|malicious.package|malware|typosquat|compromised|backdoor|"
    r"npm.attack|pypi.attack|credential.steal|exfiltrat|dependency.confus|"
    r"trojan|poisoned|hijack|protestware",
    re.IGNORECASE
)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

total_alerts = 0

for name, url, fmt in feeds:
    print(f"\n\033[0;34m━━━ {name} ━━━\033[0m")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecurityFeedCheck/1.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = resp.read()
        root = ET.fromstring(data)

        entries = []
        if fmt == "atom":
            ns = {"a": "http://www.w3.org/2005/Atom"}
            for entry in root.findall("a:entry", ns):
                title = entry.findtext("a:title", "", ns).strip()
                link_el = entry.find("a:link[@rel='alternate']", ns)
                if link_el is None:
                    link_el = entry.find("a:link", ns)
                link = link_el.get("href", "") if link_el is not None else ""
                pub = entry.findtext("a:updated", "", ns) or entry.findtext("a:published", "", ns)
                entries.append((title, link, pub))
        else:
            for item in root.iter("item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()
                entries.append((title, link, pub))

        found = 0
        for title, link, pub in entries[:20]:
            # Parse date loosely
            is_recent = True  # default to showing if we can't parse
            try:
                # Try ISO format
                for fmt_str in ["%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z",
                                "%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"]:
                    try:
                        dt = datetime.strptime(pub.strip(), fmt_str)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        is_recent = dt >= cutoff_dt
                        break
                    except ValueError:
                        continue
            except Exception:
                pass

            if not is_recent:
                continue

            is_sc = bool(KEYWORDS.search(title))
            if is_sc:
                print(f"  \033[0;31m⚠️  {title}\033[0m")
                total_alerts += 1
            else:
                print(f"  \033[0;32m•\033[0m  {title}")
            found += 1
            if link:
                print(f"     {link}")

        if found == 0:
            print(f"  \033[1;33mℹ\033[0m  No posts in the last {days_back} day(s)")

    except Exception as e:
        print(f"  \033[1;33mℹ\033[0m  Feed unavailable: {e}")

# ─────────────────────────────────────────────
# GitHub Advisory Database — recent malware
# ─────────────────────────────────────────────
print(f"\n\033[0;34m━━━ GitHub Advisory Database (Malware) ━━━\033[0m")
try:
    req = urllib.request.Request(
        "https://api.github.com/advisories?type=malware&per_page=10&sort=published&direction=desc",
        headers={"User-Agent": "SecurityFeedCheck/1.0", "Accept": "application/vnd.github+json"}
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        advisories = json.loads(resp.read())

    found = 0
    for adv in advisories:
        pub = adv.get("published_at", "")
        try:
            dt = datetime.strptime(pub[:19] + "+0000", "%Y-%m-%dT%H:%M:%S%z")
            if dt < cutoff_dt:
                continue
        except Exception:
            pass
        ecosystems = set()
        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            eco = pkg.get("ecosystem", "")
            if eco:
                ecosystems.add(eco)
        eco_str = ", ".join(ecosystems) if ecosystems else "unknown"
        summary = adv.get("summary", "No summary")[:120]
        url = adv.get("html_url", "")
        severity = adv.get("severity", "unknown")
        print(f"  \033[0;31m⚠️  [{eco_str}] {summary}\033[0m")
        if url:
            print(f"     {url}")
        found += 1
        total_alerts += 1

    if found == 0:
        print(f"  \033[1;33mℹ\033[0m  No new malware advisories in the last {days_back} day(s)")

except Exception as e:
    print(f"  \033[1;33mℹ\033[0m  GitHub API unavailable: {e}")

# ─────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────
print()
print("══════════════════════════════════════════════════════════")
if total_alerts > 0:
    print(f"  \033[0;31m⚠️  {total_alerts} supply chain alert(s) in the last {days_back} day(s)\033[0m")
else:
    print(f"  \033[0;32m✅ No supply chain alerts in the last {days_back} day(s)\033[0m")
print("══════════════════════════════════════════════════════════")
print()
PYFEED
