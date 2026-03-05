# public-repo-readiness

A Claude Code skill that audits your codebase before you open-source it.

It checks for secrets, PII, internal infrastructure references, and licensing issues — then writes a remediation plan and walks you through fixing everything.

## Install

```bash
mkdir -p ~/.claude/skills/public-repo-readiness && \
  curl -o ~/.claude/skills/public-repo-readiness/SKILL.md \
  https://raw.githubusercontent.com/dlewis7444/public-repo-readiness/main/skills/public-repo-readiness/SKILL.md
```

## Usage

In Claude Code, say:

> "make this repo public ready"

or any similar phrasing: *"publicize the repo"*, *"public-ready check"*, *"genericize the repo"*.

## What it checks

- **Secrets & credentials** — API keys, tokens, private keys, DB connection strings; checks both working tree and full git history
- **PII** — email addresses in code and commit history
- **Internal infrastructure** — hostnames, IPs, internal domain names, private Docker registries; auto-detected from your local environment
- **Licensing** — missing LICENSE file, copyleft dependencies that may restrict your chosen license

## Walkthrough

Here's what a typical run looks like:

```
You: make this repo public ready

Claude: I'll run a public repo readiness audit. First, let me check for recommended
        scanning tools...

        The following tools are missing and recommended for a thorough audit:

          [ ] gitleaks     — fast secret scanner, checks full git history
          [ ] trufflehog   — deep secret scanner, verifies if credentials are still active

        Should I install any of these? (yes to all / pick specific ones / skip)

You: yes to all

Claude: Installing gitleaks and trufflehog...
        [installs tools]

        Running auto-detection of internal hostnames, subnets, and domains from
        your local environment...

        Detected:
          Hostnames: webserver1, db-primary, ci-runner
          Subnets:   10.0.0.0/8, 192.168.1.0/24
          Domains:   home.lab, internal

        Starting scan...

        [scans git history, working tree, licenses]

        Scan complete. Before I write the remediation plan, I need a few decisions:

        1. LICENSE: No LICENSE file found. Which license do you want?
           (MIT / Apache 2.0 / GPL-3.0 / other)

        2. GIT HISTORY REWRITE: 1 secret found in committed history.
           Proceed with history rewrite plan? (yes / no / I'll handle manually)

        3. SCOPE: These are borderline — include in remediation or leave?
           - README.md:14 — mentions "db-primary" which matches your internal hostname

You: MIT, yes to history rewrite, include the README mention

Claude: Writing remediation plan to ./public-repo-remediation-plan.md...

        Plan saved. Use /clear then tell me to implement the plan using the
        executing-plans skill to execute it in a fresh context.
```

## Requirements

- [Claude Code](https://claude.ai/code)
- Optional (skill will prompt to install): [`gitleaks`](https://github.com/gitleaks/gitleaks), [`trufflehog`](https://github.com/trufflesecurity/trufflehog)

## Contributing

Issues and PRs welcome. The skill logic lives entirely in `skills/public-repo-readiness/SKILL.md`.
