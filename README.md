# Supply Chain Security Toolkit

A lightweight, self-updating security scanner for developer machines. Detects compromised packages, exposed credentials, malicious dependencies, and new supply chain attacks — before they hit your codebase.

## Why This Exists

In March 2026, the TeamPCP group compromised Trivy (a security scanner), used stolen credentials to hijack LiteLLM on PyPI, and within two weeks hit five package ecosystems: PyPI, npm, Docker Hub, GitHub Actions, and Open VSX. The malicious code fired on Python startup — no import needed. It came in silently as a dependency of a Cursor MCP plugin.

This is not an isolated incident. In the past year alone:
- **Shai-Hulud npm Worm** — self-replicating worm compromised 796 npm packages across 25,000+ repos
- **tj-actions/changed-files** — retroactive GitHub Actions tag manipulation affecting 23,000+ repos
- **Ultralytics YOLOv8** — AI/ML library compromised via GitHub Actions shell injection
- **GlassWorm** — 72 malicious VS Code extensions with 9M+ installs
- **Docker Hub** — 10,456 images exposing secrets including 4,000+ AI API tokens

Every AI agent, copilot, and internal tool your company ships runs on hundreds of packages exactly like these. Nobody chooses to install most of them — they come in as dependencies of dependencies. One compromised maintainer account turns the entire trust chain into a credential harvesting operation.

This toolkit gives you a daily automated check to catch these threats early.

## What It Checks

### `daily_security_check.sh`

| # | Check | What it catches |
|---|-------|-----------------|
| 1 | Known compromised Python packages | LiteLLM, Ultralytics, and any newly discovered bad versions |
| 2 | Suspicious `.pth` auto-exec files | The exact attack vector used in the LiteLLM compromise |
| 3 | Exposed `.env` files | Leaked API keys and credentials sitting in your filesystem |
| 4 | Shell startup file integrity | Backdoor injections in `.zshrc`, `.bashrc`, etc. |
| 5 | Crontab integrity | Malicious scheduled jobs |
| 6 | SSH key audit | Unauthorized keys in `~/.ssh` |
| 7 | npm audit (recursive) | Auto-finds all Node.js projects and audits each one |
| 8 | pip-audit (recursive) | Auto-finds all Python projects and audits each one |
| 9 | Docker image check | Compromised Trivy and other known-bad images |
| 10 | GitHub Actions pinning | Actions using tags instead of commit hashes (vulnerable to tag tampering) |
| 11 | VS Code / Cursor extensions | Flags for review after GlassWorm campaign |
| 12 | Supply chain feed alerts | Live RSS/API check for new attacks (calls `security_feed_check.sh`) |

### `security_feed_check.sh`

Pulls recent supply chain alerts from:
- [Socket.dev](https://socket.dev/blog) — malicious package detection across npm, PyPI, Go
- [Snyk Blog](https://snyk.io/blog/) — AppSec and dependency vulnerabilities
- [GitHub Security Lab](https://github.blog/tag/github-security-lab/) — vulnerability research
- [GitHub Advisory Database API](https://github.com/advisories) — real-time malware advisories

Highlights supply-chain-specific keywords (malware, typosquat, backdoor, exfiltration, etc.) in red.

## Quick Start

```bash
# Clone the repo
git clone https://github.com/tiagoqueiros/supply-chain-security.git
cd supply-chain-security

# Run the full daily check (scans ~/Code by default, 10 levels deep)
bash daily_security_check.sh

# Scan a specific directory
bash daily_security_check.sh /path/to/your/code

# Just check security feeds (last 3 days)
bash security_feed_check.sh

# Feed alerts for last 7 days
bash security_feed_check.sh 7
```

## Requirements

- macOS or Linux with Bash
- Python 3
- [`pip-audit`](https://github.com/pypa/pip-audit) — `pip install pip-audit`
- `npm` (for Node.js project auditing)

## Local Run Log

On first run, the script auto-creates a `MEMORY.md` from `MEMORY.template.md` to track findings across runs. This file is gitignored — it's your local security journal.

The memory file tracks:
- Known compromised packages and their bad versions
- Run history with dates and findings
- Action items and resolution status

## Automating with Claude Code Scheduled Tasks

If you use [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (in Claude Desktop or the CLI), you can set up a **self-updating scheduled task** that not only runs the scan daily, but also:

1. Reads the security feeds for new threats
2. Automatically adds newly discovered compromised packages to the blocklist
3. Runs the full scan against all your projects
4. Logs findings to `MEMORY.md` so it has context across runs

### Setup

In Claude Code, create a scheduled task (via `/schedule` or the `create_scheduled_task` tool):

```
Task ID: daily-security-check
Schedule: 0 9 * * * (every day at 9am)
```

Use this prompt for the task:

```
You are a supply chain security scanner. Your job is to check for new
threats and scan the local machine.

## Context
- Scripts: ~/path/to/supply-chain-security/
- Memory: ~/path/to/supply-chain-security/MEMORY.md (read FIRST)
- Scan: ~/path/to/supply-chain-security/daily_security_check.sh
- Feeds: ~/path/to/supply-chain-security/security_feed_check.sh

## Steps

### 1. Read MEMORY.md
Read the memory file to understand what packages are already tracked
and what was found in previous runs.

### 2. Check Feeds for New Threats
Run: bash ~/path/to/supply-chain-security/security_feed_check.sh 3
Also query GitHub Advisory API for recent malware:
curl -s "https://api.github.com/advisories?type=malware&per_page=20&sort=published&direction=desc"

### 3. Update Compromised Package List
If feeds reveal NEW compromised packages (not already in MEMORY.md):
- Add them to the "Compromised Packages" table in MEMORY.md
- Update the compromised dict in daily_security_check.sh (Python block
  in section 1) to include the new package + bad versions
- Only add widely-used packages (>1000 weekly downloads) or packages
  that appear in your dependency trees

### 4. Run Full Scan
Run: bash ~/path/to/supply-chain-security/daily_security_check.sh

### 5. Update MEMORY.md Run History
Append a new entry with date, warnings found, new packages added,
notable alerts, and action items.

### 6. Report
Concise summary. Flag critical warnings prominently.
```

Replace `~/path/to/supply-chain-security/` with wherever you cloned the repo.

The key advantage of using Claude Code as the scheduler is that it **reasons about new advisories** — it doesn't just pattern-match; it reads the advisory, understands whether it's relevant to your stack, and decides whether to add it to the blocklist.

## Manual Weekly/Monthly Checks

Beyond the daily automated scan:

**Weekly:**
- Review GitHub Actions in your repos — pin to commit hashes, not version tags
- Audit VS Code / Cursor extensions — remove anything unused
- Rotate API keys older than 90 days

**Monthly:**
- Run `pip list` and `npm list -g` — remove anything unrecognized
- Audit `.gitignore` files — confirm `.env` exclusion in all projects
- Check Docker images for exposed credentials

**After any `pip install` or `npm install`:**
1. Check the package exists on GitHub with matching source (no "PyPI-only" releases)
2. Verify the release has a corresponding git tag
3. Search `[package name] malware` or `[package name] compromised`
4. Run `pip-audit` or `npm audit` immediately after

## Recommended Tools

| Tool | Purpose | Cost |
|------|---------|------|
| [pip-audit](https://github.com/pypa/pip-audit) | Python vulnerability scanning | Free |
| [npm audit](https://docs.npmjs.com/cli/v10/commands/npm-audit) | Node.js vulnerability scanning | Free (built-in) |
| [GitGuardian](https://www.gitguardian.com/) | Secrets detection in code/repos | Free tier |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Git repo secret scanning | Free |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Pre-commit secret scanning | Free |
| [Snyk](https://snyk.io/) | Full dependency + container scanning | Free tier |
| [Socket.dev](https://socket.dev/) | Supply chain attack detection | Free tier |

## Contributing

Found a new attack vector or feed source? PRs welcome. The compromised package list in `MEMORY.template.md` and `daily_security_check.sh` should be kept in sync.

## License

MIT
