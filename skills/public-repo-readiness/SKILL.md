---
name: public-repo-readiness
description: Use when the user asks to "make this repo public ready", "publicize the repo", "genericize the repo", "public-ready check", or any similar request to audit a codebase before open-sourcing or public exposure. Audits for secrets, PII, internal infrastructure references, and licensing issues, then produces a remediation plan for user approval.
---

# Public Repo Readiness Audit

## Overview

Systematically audit a codebase for anything that should not be in a public repository. Then write a remediation plan, get approval, and execute it in a fresh context.

**Workflow: Tool check → Fingerprint → EnterPlanMode → Scan → Interview → Plan → /clear → executing-plans**

**Never modify files during the audit phase. Find and report first.**

---

## Pre-Plan Phase A: Tool Check & Install Interview

Run before entering plan mode. Check which tools are available:

```bash
echo "=== Secret Scanners ===" && which gitleaks trufflehog 2>/dev/null || echo "not found"
echo "=== License Tools ===" && which pip-licenses go-licenses 2>/dev/null || echo "not found"
echo "=== Package Managers ===" && which npm pip3 go cargo 2>/dev/null || echo "not found"
```

For each missing tool that applies to this repo, ask the user in **one consolidated prompt**:

```
The following tools are missing and recommended for a thorough audit:

  [ ] gitleaks     — fast secret scanner, checks full git history
  [ ] trufflehog   — deep secret scanner, VERIFIES if credentials are still active
  [ ] pip-licenses — Python dependency license audit  (only if requirements.txt/pyproject.toml present)
  [ ] go-licenses  — Go dependency license audit      (only if go.mod present)

Should I install any of these? (yes to all / pick specific ones / skip)
```

Install approved tools:
```bash
# gitleaks
curl -sSfL https://raw.githubusercontent.com/gitleaks/gitleaks/master/scripts/install.sh | sh -s -- -b /usr/local/bin
# trufflehog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
# pip-licenses
pip install pip-licenses
# go-licenses
go install github.com/google/go-licenses@latest
```

Note which tools were installed vs. skipped. Mark any skipped scans as "UNVERIFIED — tool not available."

---

## Pre-Plan Phase B: Auto-Detect Internal Fingerprint

Run before entering plan mode. **Do not ask the user** — infer from the environment:

```bash
# Local machine identity
hostname
hostname -f 2>/dev/null
hostname -d 2>/dev/null

# Network interfaces → actual internal subnets
ip addr show | grep "inet " | awk '{print $2}'

# /etc/hosts → explicit internal hostname mappings
grep -v "^#\|^$\|localhost\|127\.0\|::1\|fe80" /etc/hosts

# SSH config → known internal hosts
grep -iE "^Host |^HostName " ~/.ssh/config 2>/dev/null | grep -v "\*"

# Git identity in this repo
git -C . config --list 2>/dev/null | grep -E "remote\.|user\."
git log --all --format="%ae %an" 2>/dev/null | sort -u | head -20

# Docker service names
find . \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" \) 2>/dev/null \
  | xargs grep -hE "^  [a-z_-]+:" 2>/dev/null | awk '{print $1}' | tr -d ':' | sort -u
```

Build the fingerprint:
- **`INTERNAL_NAMES`** = hostname short + /etc/hosts names + SSH Host entries + docker service names
- **`INTERNAL_SUBNETS`** = all RFC1918 defaults + subnets from `ip addr`
- **`INTERNAL_DOMAINS`** = domain from `hostname -d/f` + any `.local/.internal/.home/.lab/.arpa` from /etc/hosts

---

## EnterPlanMode

**Enter plan mode now.** All scanning, finding compilation, and plan writing happen in plan mode.

---

## Scan Phase 1: Secret & Credential Scanning

### 1a. Git History

```bash
# TruffleHog first — verifies if leaked creds are STILL ACTIVE
trufflehog git file://. --json 2>/dev/null | tee /tmp/trufflehog-report.json

# Gitleaks — broader pattern coverage, structured report
gitleaks detect --source . --report-format json --report-path /tmp/gitleaks-report.json 2>&1

# Fallback: manual history inspection
git log --all --oneline | head -50
git log --all --diff-filter=D --name-only --format="" | sort -u   # deleted files
git stash list
git reflog | head -20
```

**Per finding: state whether the file is tracked/committed (needs history rewrite) or untracked (needs gitignore only).**

### 1b. Working Tree

```bash
EXCLUDE="--exclude-dir=node_modules --exclude-dir=vendor --exclude-dir=.git --exclude-dir=venv --exclude-dir=__pycache__ --exclude-dir=dist --exclude-dir=build"
REPO="."

# Generic secrets
grep -rn $EXCLUDE -E "(password|passwd|secret|token|api_key|apikey|api-key|auth_token|access_token|private_key|client_secret)\s*[=:]\s*['\"][^'\"]{6,}" $REPO 2>/dev/null

# Service-specific formats
grep -rn $EXCLUDE -E "AKIA[0-9A-Z]{16}" $REPO                                      # AWS
grep -rn $EXCLUDE -E "sk_(live|test)_[0-9a-zA-Z]{24}" $REPO                        # Stripe
grep -rn $EXCLUDE -E "xox[baprs]-[0-9]{12}-[0-9]{12}" $REPO                        # Slack
grep -rn $EXCLUDE -E "ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}" $REPO       # GitHub PAT
grep -rn $EXCLUDE -E "-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY" $REPO        # Private keys
grep -rn $EXCLUDE -E "eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}" $REPO             # JWT

# DB connection strings
grep -rn $EXCLUDE -E "(postgresql|mysql|mongodb|redis|sqlite)://[^@]+@[^/\s]+" $REPO

# Sensitive files that shouldn't be committed
find $REPO -name ".env*" ! -name ".env.example" ! -name ".env.sample" 2>/dev/null
find $REPO \( -name "*.pem" -o -name "*.key" -o -name "*.p12" -o -name "id_rsa" -o -name "id_ed25519" \) 2>/dev/null
find $REPO \( -name "*.sqlite" -o -name "*.db" \) 2>/dev/null
```

---

## Scan Phase 2: PII & Internal Infrastructure

```bash
# Email addresses in code (exclude obvious non-personal)
grep -rn $EXCLUDE -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" $REPO \
  --include="*.{js,ts,py,go,rb,java,sh,yaml,yml,json,toml,md,txt,cfg,conf,ini}" 2>/dev/null \
  | grep -v "example\.com\|@types\|noreply\|github\.com\|placeholder"

# Email addresses in git commit history
git log --all --format="%ae %ce %an %cn" | sort -u

# Internal IPs — RFC1918 + subnets from INTERNAL_SUBNETS fingerprint
grep -rn $EXCLUDE -E "((10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3})" $REPO 2>/dev/null
grep -rn $EXCLUDE -E "169\.254\.[0-9]{1,3}\.[0-9]{1,3}" $REPO 2>/dev/null  # cloud metadata

# Internal hostnames from INTERNAL_NAMES fingerprint (build grep pattern from detected names)
# e.g.: grep -rn -i "roci\|aftermath1\|udm1" $REPO

# Internal domain patterns — standard + INTERNAL_DOMAINS fingerprint
grep -rn $EXCLUDE -E "\.(internal|local|corp|lan|lab|home|arpa|intranet|private)\b" $REPO 2>/dev/null

# Internal URLs
grep -rn $EXCLUDE -E "https?://[a-zA-Z0-9-]+\.(internal|local|corp|lan|home|lab|arpa)" $REPO 2>/dev/null
grep -rn $EXCLUDE -E "https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" $REPO 2>/dev/null

# Private Docker registries
grep -rn $EXCLUDE -E "[a-z0-9.-]+:[0-9]{4,5}/[a-z0-9._/-]+" $REPO 2>/dev/null
```

---

## Scan Phase 3: License Audit

```bash
# LICENSE file
ls $REPO/LICENSE $REPO/LICENSE.md $REPO/LICENSE.txt 2>/dev/null || echo "NO LICENSE FILE"

# Copyright headers
grep -rn $EXCLUDE -i "copyright\|all rights reserved" $REPO \
  --include="*.{js,ts,py,go,rb,java}" 2>/dev/null | head -20

# Dependency license audit (run whichever applies)
[ -f package.json ]    && npx license-checker --summary 2>/dev/null
[ -f requirements.txt ] || [ -f pyproject.toml ] && pip-licenses 2>/dev/null
[ -f go.mod ]          && go-licenses report . 2>/dev/null
[ -f Cargo.toml ]      && cargo license 2>/dev/null
# Flag any GPL/AGPL/LGPL results — these are copyleft and may restrict how you can license the repo
```

---

## Final Interview (still in plan mode)

After completing all scans, ask the user in **one consolidated prompt** covering any open decisions:

```
Scan complete. Before I write the remediation plan, I need a few decisions:

1. LICENSE: No LICENSE file found. Which license do you want?
   (MIT / Apache 2.0 / GPL-3.0 / other)

2. GIT HISTORY REWRITE: [X] secrets found in committed history.
   Rewriting history is destructive and requires coordinating with all collaborators.
   Proceed with history rewrite plan? (yes / no / I'll handle manually)

3. SCOPE: These items are borderline — include in remediation or leave?
   - [list any MEDIUM/LOW items that need judgment]
```

Only ask about decisions that are actually needed based on findings. Skip questions with obvious answers.

---

## Write Remediation Plan

Write the plan to a file: `./public-repo-remediation-plan.md`

Structure:

```markdown
# Public Repo Remediation Plan

## Auto-Detected Internal Fingerprint
- Hostnames: [list]
- Subnets: [list]
- Domains: [list]
- Git identity: [emails/names found in commits]
⚠️ If incomplete, add missing names and re-run.

## Findings Summary
| Severity | Count |
|----------|-------|
| CRITICAL | X |
| HIGH     | X |
| MEDIUM   | X |
| LOW      | X |

## CRITICAL Findings
- `file:line` — description — tracked/untracked

## HIGH Findings
...

## Remediation Tasks

### Task 1: Rotate All Exposed Credentials (IMMEDIATE — before any other step)
Assume all found credentials are compromised. Rotate NOW.
- [credential] in [file] — rotate at [service URL]

### Task 2: Remove Secrets from Working Tree
- [specific file edits with before/after]
- Add to .gitignore: [list]

### Task 3: Git History Rewrite (if applicable)
⚠️ DESTRUCTIVE — coordinate with all collaborators first
- git filter-repo --path <file> --invert-paths
- Force-push all branches after rewrite
- Invalidate any clones/forks

### Task 4: Remove/Replace Internal References
- [file:line] — replace "[internal value]" with "[generic placeholder]"

### Task 5: Add LICENSE File
- Create LICENSE with [chosen license] text

### Task 6: Dependency License Cleanup (if needed)
- [specific dependency] — [issue] — [resolution]

## Scan Limitations
- Tools not available: [list]
- Items not checked: binary files, [other]
- Fingerprint may be incomplete: [note if confidence is low]
```

---

## ExitPlanMode

Exit plan mode and present the plan for user approval.

---

## After Approval: Execute

Tell the user:

> "Plan saved to `./public-repo-remediation-plan.md`. Use `/clear` then tell me to implement the plan using the `executing-plans` skill to execute it in a fresh context."

---

## Key Rules

1. **Audit first — never modify files during scanning**
2. **All found credentials must be rotated immediately** — assume compromised whether or not the repo is already public
3. **Git history rewrite is destructive** — flag prominently, get explicit confirmation
4. **Report the auto-detected fingerprint** so the user can verify it's complete
5. **Per finding, state tracked vs. untracked** — this determines whether history rewrite is needed

## Common Mistakes

| Mistake | Fix |
|---------|-----|
| Only scanning working tree | Always check git history — deleted secrets persist |
| No tool scan | Grep misses service-specific patterns; use gitleaks + trufflehog |
| Rotating credentials after pushing | Rotate on discovery, before any push |
| Forgetting stash and reflog | Check `git stash list` and `git reflog` |
| Missing transitive dependency licenses | Run `license-checker --summary`, not manual review |
| Scanning node_modules/vendor | Exclude — not your code |
| Not distinguishing tracked vs. untracked | Committed secrets need history rewrite; untracked need gitignore |
