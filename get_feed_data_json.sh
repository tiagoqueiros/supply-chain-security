#!/bin/bash
DAYS_BACK="${1:-3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FEEDS_CONF="$SCRIPT_DIR/feeds.conf"

python3 - "$DAYS_BACK" "$FEEDS_CONF" <<'PYJSON'
import sys, json, urllib.request, ssl
from xml.etree import ElementTree as ET
from datetime import datetime, timedelta, timezone

days_back = int(sys.argv[1])
feeds_conf = sys.argv[2]
cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days_back)

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

all_alerts = []
try:
    url = "https://api.github.com/advisories?type=malware&per_page=50&sort=published&direction=desc"
    req = urllib.request.Request(url, headers={"User-Agent": "SecurityFeedCheck/1.0"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        advisories = json.loads(resp.read())
    
    for adv in advisories:
        pub_str = adv.get("published_at", "")
        try:
            pub_dt = datetime.fromisoformat(pub_str.replace("Z", "+00:00"))
            if pub_dt < cutoff_dt:
                continue
        except:
            pass
        
        packages = []
        for vuln in adv.get("vulnerabilities", []):
            pkg = vuln.get("package", {})
            ecosystem = pkg.get("ecosystem", "")
            name = pkg.get("name", "")
            if ecosystem and name:
                packages.append({
                    "ecosystem": ecosystem.lower(),
                    "name": name,
                    "affected_versions": vuln.get("vulnerable_version_range", "all")
                })
        
        if packages:
            all_alerts.append({
                "source": "GitHub Advisory API",
                "title": adv.get("summary", ""),
                "url": adv.get("html_url", ""),
                "published": pub_str,
                "severity": adv.get("severity", "unknown"),
                "packages": packages
            })
except Exception as e:
    pass

feeds = []
try:
    with open(feeds_conf) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) == 3:
                feeds.append((parts[0].strip(), parts[1].strip(), parts[2].strip()))
except Exception as e:
    pass

for feed_name, feed_url, feed_fmt in feeds:
    try:
        req = urllib.request.Request(feed_url, headers={"User-Agent": "SecurityFeedCheck/1.0"})
        with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
            data = resp.read()
        root = ET.fromstring(data)
        
        entries = []
        if feed_fmt == "atom":
            ns = {"a": "http://www.w3.org/2005/Atom"}
            for entry in root.findall("a:entry", ns):
                title = entry.findtext("a:title", "", ns).strip()
                link_el = entry.find("a:link[@rel='alternate']", ns)
                if link_el is None:
                    link_el = entry.find("a:link", ns)
                link = link_el.get("href", "") if link_el is not None else ""
                pub = entry.findtext("a:updated", "", ns) or entry.findtext("a:published", "", ns)
                desc = entry.findtext("a:summary", "", ns) or entry.findtext("a:content", "", ns) or ""
                entries.append((title, link, pub, desc.strip()))
        else:
            for item in root.iter("item"):
                title = (item.findtext("title") or "").strip()
                link = (item.findtext("link") or "").strip()
                pub = (item.findtext("pubDate") or "").strip()
                desc = (item.findtext("description") or item.findtext("content:encoded") or "").strip()
                entries.append((title, link, pub, desc))
        
        for title, link, pub, description in entries[:10]:
            is_recent = True
            try:
                for fmt_str in ["%Y-%m-%dT%H:%M:%SZ", "%a, %d %b %Y %H:%M:%S %z"]:
                    try:
                        dt = datetime.strptime(pub.strip(), fmt_str)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        is_recent = dt >= cutoff_dt
                        break
                    except:
                        continue
            except:
                pass

            if is_recent:
                content = ""
                try:
                    req_article = urllib.request.Request(link, headers={"User-Agent": "SecurityFeedCheck/1.0"})
                    with urllib.request.urlopen(req_article, timeout=10, context=ctx) as resp:
                        html = resp.read().decode('utf-8', errors='ignore')
                        import re
                        html = re.sub(r'<script[^>]*>.*?</script>', '', html, flags=re.DOTALL | re.IGNORECASE)
                        html = re.sub(r'<style[^>]*>.*?</style>', '', html, flags=re.DOTALL | re.IGNORECASE)
                        text = re.sub(r'<[^>]+>', ' ', html)
                        text = re.sub(r'\s+', ' ', text).strip()
                        content = text[:5000]
                except:
                    content = description

                all_alerts.append({
                    "source": feed_name,
                    "title": title,
                    "url": link,
                    "published": pub,
                    "severity": "unknown",
                    "content": content,
                    "packages": []
                })
    except Exception as e:
        pass

print(json.dumps({
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "days_back": days_back,
    "total_alerts": len(all_alerts),
    "alerts": all_alerts
}, indent=2))
PYJSON

