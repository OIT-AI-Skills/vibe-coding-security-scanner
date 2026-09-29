# Vibe-Coded Application Security Review Skills

A collection of five GitHub Copilot instruction files for structured security review
of AI-generated ("vibe-coded") applications. Designed to be run interactively in
VS Code agent mode and non-interactively in CI/CD pipelines.

## Installation

Install this skill using the Claude Code CLI:

```bash
npx skills add OIT-AISkills/vibe-coded-security-checks-skill
```

Once installed, use it with `/vibe-coded-security-checks` in any Claude Code session.

---

## Skills Overview

| File | Purpose |
|------|---------|
| `vibe-security-entrypoint.instructions.md` | **Start here.** Fingerprints the codebase, selects a review strategy, defines the output schema, and dispatches to the other skills. |
| `vibe-security-data-exfiltration.instructions.md` | Maps all paths through which data exits the application boundary. |
| `vibe-security-secrets-audit.instructions.md` | Audits how secrets and sensitive configuration values are stored, transmitted, and accessed. |
| `vibe-security-privilege-escalation.instructions.md` | Identifies privilege escalation paths assuming AuthN/AuthZ happens upstream. |
| `vibe-security-language-extensions.instructions.md` | Language-specific rules for Ruby/Rails and Python, plus a template for adding others. |

### What These Skills Do NOT Duplicate

For Ruby/Rails and Python projects, **Brakeman** and **Bandit** are assumed to already
be running in the pipeline. These skills focus on what those tools miss:
- Logic-level access control and IDOR
- Architectural data flow issues
- Contextual and cross-component vulnerabilities
- Business logic flaws

For all other languages (Go, Node.js, Java, etc.), the skills apply a more
comprehensive enumeration including issues that SAST tools would normally catch.

---

## Usage: Interactive (VS Code)

### Full Review (Recommended for Onboarding)

1. Open the target codebase in VS Code.
2. Open GitHub Copilot Chat in agent mode (`@workspace`).
3. Attach all five skill files using `#file:` references and run:

```
#file:path/to/skills/vibe-security-entrypoint.instructions.md
#file:path/to/skills/vibe-security-data-exfiltration.instructions.md
#file:path/to/skills/vibe-security-secrets-audit.instructions.md
#file:path/to/skills/vibe-security-privilege-escalation.instructions.md
#file:path/to/skills/vibe-security-language-extensions.instructions.md

Perform a complete security review of this codebase following the instructions
in the attached skills. Produce the full Security Review Report.
```

### Targeted Ad Hoc Review

Attach only the relevant skill(s) for a focused query:

```
#file:path/to/skills/vibe-security-data-exfiltration.instructions.md

Review only the data exfiltration surface of app/services/reporting_service.rb
```

### PR Review

For a pull request, attach the entrypoint plus any skills relevant to the changed
files. Scope the prompt to the diff:

```
#file:path/to/skills/vibe-security-entrypoint.instructions.md
#file:path/to/skills/vibe-security-privilege-escalation.instructions.md

Review the security implications of the changes in these files for privilege
escalation risks. Changed files: [list files from the PR diff]
```

---

## Usage: Non-Interactive (CI/CD)

The skills are designed to produce deterministic, machine-parseable markdown output
without requiring interactive clarification. Use them with any AI CLI tool that
supports instruction files.

### GitHub Actions — Example Workflow

```yaml
name: AI Security Review

on:
  pull_request:
    branches: [main, develop]
  workflow_dispatch:  # Allow manual trigger for onboarding reviews

jobs:
  ai-security-review:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout target repo
        uses: actions/checkout@v4

      - name: Checkout security skills
        uses: actions/checkout@v4
        with:
          repository: your-org/citizen-developer-skill
          path: security-skills
          token: ${{ secrets.SKILLS_REPO_TOKEN }}

      - name: Run AI security review
        uses: github/copilot-cli-action@v1  # Adjust to your AI CLI tool
        with:
          prompt: |
            Follow the instructions in the attached skill files to perform a complete
            security review of this codebase. Produce the full Security Review Report
            in markdown format. Do not ask clarifying questions; state assumptions
            in the report header.
          instruction-files: |
            security-skills/skills/vibe-security-entrypoint.instructions.md
            security-skills/skills/vibe-security-data-exfiltration.instructions.md
            security-skills/skills/vibe-security-secrets-audit.instructions.md
            security-skills/skills/vibe-security-privilege-escalation.instructions.md
            security-skills/skills/vibe-security-language-extensions.instructions.md
          output-file: security-review-report.md

      - name: Upload report as artifact
        uses: actions/upload-artifact@v4
        with:
          name: security-review-report
          path: security-review-report.md

      - name: Post report summary to PR
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v7
        with:
          script: |
            const fs = require('fs');
            const report = fs.readFileSync('security-review-report.md', 'utf8');
            // Extract findings summary table (lines between ## Findings Summary and ## Detailed)
            const summaryMatch = report.match(/## Findings Summary[\s\S]*?(?=## Detailed)/);
            const summary = summaryMatch ? summaryMatch[0] : 'See full report artifact.';
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: `## AI Security Review\n\n${summary}\n\n[Full report available as workflow artifact](${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId})`
            });
```

> **Note:** The exact CI/CD action (`github/copilot-cli-action`) is illustrative.
> Adapt to whatever AI CLI tooling your organization uses (e.g., the GitHub Copilot
> CLI, a custom wrapper around the OpenAI or Anthropic API, etc.).

---

## Report Output Structure

Every review produces a report with this structure:

```
# Security Review Report
[Header: app name, date, detected stack, review mode, skills applied]

## Review Completeness
[Checklist of what was reviewed + assumptions + unreviewed files]

## Executive Summary
[2–4 sentences for non-technical stakeholders]

## Findings Summary
[Severity counts table]

## Detailed Findings
[One VIBE-NNN section per finding with severity, location, evidence, and remediation]

## Positive Observations
[Security controls that are correctly in place]

## Data Flow Map           ← from data exfiltration skill
## Secret Inventory        ← from secrets audit skill
## Authorization Coverage Matrix  ← from privilege escalation skill
```

---

## Adding a New Language

1. Open `vibe-security-language-extensions.instructions.md`
2. Add a new section following the template in Section C of that file
3. Update the entrypoint skill's stack detection table if the new language requires
   new fingerprint signals
4. Submit a PR to this repository

Minimum required sections for a new language are documented in the extensions skill.

---

## Maintenance Notes

- **Review these skills against Brakeman and Bandit release notes** when those tools
  ship major updates. If a new Brakeman/Bandit rule covers something currently in
  the skills, annotate or remove the duplicate instruction to avoid redundancy.
- **Severity definitions** are calibrated for organizational risk tolerance. Adjust
  the severity reference table in the entrypoint skill if your organization uses
  a different risk framework (e.g., CVSS-based severity).
- **The language extensions skill is the most likely to need updates** as new
  framework versions, new attack patterns, or new languages are onboarded.
