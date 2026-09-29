# Vibe-Coded Application Security Review

A comprehensive security review skill for AI-generated ("vibe-coded") applications. Focuses on logic-level vulnerabilities and architectural issues that automated SAST tools miss, including data exfiltration paths, secrets management, privilege escalation, and language-specific vulnerabilities.

## Usage

### Full Review
```
/vibe-coded-security-checks

Perform a complete security review of this codebase.
```

### Targeted Review (Data Exfiltration Only)
```
/vibe-coded-security-checks

Review only the data exfiltration surface of [file path]
```

### Privilege Escalation Focus
```
/vibe-coded-security-checks

Review this codebase for privilege escalation risks, focusing on authorization boundaries.
```

## What This Skill Covers

This skill provides structured analysis across five dimensions:

1. **Entrypoint & Strategy** — Fingerprints your codebase to detect tech stack and selects appropriate review strategy
2. **Data Exfiltration** — Maps all paths through which data exits the application boundary
3. **Secrets Audit** — Audits how secrets and sensitive configuration values are stored, transmitted, and accessed
4. **Privilege Escalation** — Identifies privilege escalation paths assuming AuthN/AuthZ happens upstream
5. **Language Extensions** — Language-specific rules for Ruby/Rails, Python, and extensible templates for other languages

## What This Skill Does NOT Duplicate

For Ruby/Rails and Python projects:
- **Brakeman** and **Bandit** are assumed to already be running in your pipeline
- This skill focuses on logic-level access control, IDOR, architectural data flow issues, and business logic flaws
- These complement, not replace, automated SAST tools

For other languages (Go, Node.js, Java, etc.):
- More comprehensive enumeration including issues that SAST tools would normally catch

## Output Format

Every review produces a structured report with:
- **Review Completeness** — Checklist of what was reviewed + assumptions
- **Executive Summary** — For non-technical stakeholders
- **Findings Summary** — Severity counts and categorization
- **Detailed Findings** — One issue per finding with location, evidence, and remediation
- **Positive Observations** — Security controls correctly in place
- **Data Flow Map** — All paths data takes through the system
- **Secret Inventory** — Complete accounting of secrets/sensitive config
- **Authorization Coverage Matrix** — Where AuthZ is and isn't enforced

## For CI/CD Integration

This skill is designed to produce deterministic, machine-parseable markdown output without interactive clarification. It can be integrated into GitHub Actions, GitLab CI, or other automation using an AI CLI tool that supports instruction files.

See the [README](./README.md) for example CI/CD workflows.

---

## Implementation Details

To perform the review, Claude will:

1. Analyze the codebase structure and technology stack
2. Apply the appropriate security review strategy based on detected tech
3. Map data flows through the application
4. Audit secrets and sensitive configuration handling
5. Identify privilege escalation and authorization boundaries
6. Apply language-specific vulnerability checks
7. Produce a comprehensive markdown report

### Files Used

- `vibe-security-entrypoint.instructions.md` — Entry point and orchestration
- `vibe-security-data-exfiltration.instructions.md` — Data flow analysis
- `vibe-security-secrets-audit.instructions.md` — Secrets and config audit
- `vibe-security-privilege-escalation.instructions.md` — AuthZ and privilege escalation
- `vibe-security-language-extensions.instructions.md` — Language-specific rules

### Customization

To add a new language or extend the review:

1. Edit `vibe-security-language-extensions.instructions.md` to add new language rules
2. Update the stack detection table in `vibe-security-entrypoint.instructions.md` if needed
3. Submit a PR to the repository

---

## Support and Contributing

- **Found an issue?** Open an issue on [GitHub](https://github.com/OIT-AISkills/vibe-coded-security-checks-skill/issues)
- **Want to add a language?** See the language extensions file and submit a PR
- **Questions?** Check the [README](./README.md) for more detailed usage examples

