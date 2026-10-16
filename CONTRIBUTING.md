# Contributing to VibePGSec

Thank you for your interest in contributing to **VibePGSec** — the PostgreSQL Security AI Skill. This project aims to give AI agents the knowledge and reasoning of a PostgreSQL security specialist.

---

## What We're Looking For

We welcome contributions across all areas of the project:

| Area | Examples |
|------|---------|
| **Reference docs** | New security domains, deeper coverage of existing ones |
| **Attack playbooks** | New attack vectors with detection queries and mitigations |
| **Checklists** | New security frameworks (CIS, PCI-DSS, SOC 2 mappings) |
| **Version notes** | PG19+ security changes as they are released |
| **SKILL.md improvements** | Better detection queries, new audit steps, improved AI reasoning patterns |
| **Bug fixes** | Incorrect SQL, broken links, outdated version information |

---

## Contribution Guidelines

### 1. Fork and Branch
```bash
git clone https://github.com/imtiazqa/VibePGSec.git
cd VibePGSec
git checkout -b feature/my-improvement
```

### 2. Content Standards

Every contribution should follow these standards:

**SQL Queries**
- All SQL must be valid PostgreSQL syntax (tested against at least one recent PG version)
- Include the minimum PG version required as a comment where relevant: `-- PG 15+`
- Use lowercase SQL keywords consistently
- Schema-qualify system catalog references: `pg_catalog.pg_roles` not just `pg_roles`

**Documentation Structure**
- All reference files follow: Overview → Mechanics → Detection Queries → Remediation → Verification Checklist
- All attack playbooks follow: Overview → Mechanics → Detection → Prevention
- Use severity labels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- Include a `## Verification Checklist` section with `- [ ]` checkboxes at the end

**Markdown**
- Use GitHub Flavored Markdown
- SQL blocks use ` ```sql ` fencing
- Shell blocks use ` ```bash ` fencing
- Config blocks use ` ```ini ` fencing

### 3. SKILL.md Changes

Changes to `SKILL.md` are high-impact. For SKILL.md contributions:
- Explain in your PR description how the change improves AI agent reasoning
- Include example detection queries or reasoning steps
- Avoid reducing existing coverage — only add or improve
- Test by reading your addition as if you were an AI agent — does it teach useful reasoning?

### 4. New Attack Playbooks

Attack playbooks should:
- Frame everything from a **defensive** perspective (detect, prevent, verify)
- Include concrete detection SQL queries that actually work
- Include a step-by-step exploitation **verification** procedure for authorized testers
- Never include working credential-stealing or data-exfiltration scripts

### 5. Version Files

For new PostgreSQL version files (e.g., `versions/pg19.md`):
- Cover only security-relevant changes (not performance or SQL features)
- Reference the official PostgreSQL release notes
- Include migration notes for common security configurations
- Keep to 80–150 lines

---

## Testing Your SQL

Test all SQL queries against a live PostgreSQL instance before submitting. A quick Docker setup:

```bash
# Spin up a PostgreSQL instance for testing
docker run --rm -e POSTGRES_PASSWORD=testpass -p 5432:5432 postgres:16

# Connect
psql -h localhost -U postgres -c "SELECT version();"
```

For security configuration testing, you may need specific setups (e.g., multiple roles, pg_hba.conf changes). Document any prerequisites in your PR.

---

## Pull Request Process

1. **One topic per PR** — keep PRs focused on a single change or addition
2. **Descriptive title** — e.g., `Add pg_cron security reference` or `Fix incorrect SCRAM detection query`
3. **Summary in PR description** — what changed, why, and what PostgreSQL versions it applies to
4. **Link related issues** — reference any open issues your PR addresses

---

## Reporting Security Issues

If you discover a security issue **in VibePGSec itself** (e.g., a SQL query that could cause harm if run without understanding), please open a GitHub Issue labeled `security` rather than submitting a public PR with the details.

---

## Code of Conduct

- Be respectful in all interactions
- Security knowledge shared here is for **defensive** purposes
- Do not include functional exploit payloads or weaponized scripts

---

## Recognition

Contributors are acknowledged in [CHANGELOG.md](CHANGELOG.md). Thank you for making PostgreSQL environments more secure.
