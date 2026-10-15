# VibePGSec

> **Stop shipping insecure PostgreSQL configurations to production.**

An AI skill that brings deep PostgreSQL security expertise directly into your AI coding workflow — so your AI agent thinks like a PostgreSQL security auditor, not just a code assistant.

<p align="center">
  <img src="https://img.shields.io/badge/PostgreSQL-14--18-336791?logo=postgresql&logoColor=white" alt="PostgreSQL 14-18">
  <img src="https://img.shields.io/badge/AI_Skill-Security-red" alt="AI Skill">
  <img src="https://img.shields.io/badge/Approach-Offensive_%2B_Defensive-orange" alt="Approach">
</p>

## Introduction

PostgreSQL is the world's most advanced open-source database — but advanced doesn't mean secure by default.

We've all seen the misconfigurations:

* `trust` authentication in `pg_hba.conf` exposed to the network
* `SECURITY DEFINER` functions with unsafe `search_path`
* Superuser credentials used by application services
* Row-Level Security enabled but trivially bypassable
* `COPY ... PROGRAM` accessible to unprivileged roles
* Extensions like `plpython3u` granting OS-level access

Security gaps in PostgreSQL aren't obvious until someone exploits them. Without the right guidance, AI will confidently deploy vulnerable configurations alongside your features.

**VibePGSec** is an AI Skill that acts as a PostgreSQL security specialist. It teaches your AI agent to approach PostgreSQL from an **attacker's perspective**, catching vulnerabilities before they ship.

## 📚 Table of Contents

- [VibePGSec](#vibepgsec)
  - [📥 Installation](#-installation)
  - [🛡️ Three Modes](#️-three-modes)
  - [🔒 Covered Security Domains](#-covered-security-domains)
  - [🐘 PostgreSQL Version Support](#-postgresql-version-support)
  - [📁 Repository Structure](#-repository-structure)
  - [🚀 Quick Start](#-quick-start)
  - [🤝 Contributing](#-contributing)
  - [📬 Contact](#-contact)

## 📥 Installation

<details><summary>Claude Code</summary>

* Clone this repository: `git clone https://github.com/imtiazqa/VibePGSec.git`
* Add it to `~/.claude/skills` (global) or `.claude/skills` in your project directory (project-only).

</details>

<details><summary>Cursor</summary>

* Clone this repository: `git clone https://github.com/imtiazqa/VibePGSec.git`
* Add it to `~/.cursor/skills` (global) or `.cursor/skills` in your project directory (project-only).

</details>

<details><summary>Codex</summary>

* Clone this repository: `git clone https://github.com/imtiazqa/VibePGSec.git`
* Add it to your Codex skill configuration.

</details>

<details><summary>GitHub Copilot</summary>

* Clone this repository: `git clone https://github.com/imtiazqa/VibePGSec.git`
* Reference the `SKILL.md` in your Copilot instructions.

</details>

<details><summary>Antigravity</summary>

* Clone this repository: `git clone https://github.com/imtiazqa/VibePGSec.git`
* Add it to `~/.gemini/config/skills/` (global) or `.agents/skills/` in your project directory.

</details>

## 🛡️ Three Modes

VibePGSec operates in three complementary modes:

| Mode | Purpose | When to Use |
|------|---------|-------------|
| 🔍 **AUDIT** | Find security weaknesses | "Audit this PostgreSQL instance for security issues" |
| 🛡️ **HARDEN** | Recommend and fix configuration | "Harden this PostgreSQL deployment" |
| ⚔️ **VERIFY** | Attempt controlled security tests | "Verify whether this finding is exploitable" |

### Example: AUDIT Mode

**Prompt:**
```
Audit this PostgreSQL instance for security issues.
```

**Example Output:**
```
╔══════════════════════════════════════════════╗
║     PostgreSQL Security Assessment           ║
║     CRITICAL: 1  HIGH: 3  MEDIUM: 5  LOW: 2 ║
╚══════════════════════════════════════════════╝

[CRITICAL] SECURITY DEFINER Privilege Escalation
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Function:    public.get_user_data()
Owner:       postgres (superuser)
EXECUTE:     Granted to PUBLIC
search_path: Not explicitly set
Risk:        Any user can execute a superuser-owned function
             with uncontrolled search_path

Evidence:
  SELECT proname, proowner::regrole, prosecdef,
         proconfig
  FROM pg_proc WHERE prosecdef = true;

Remediation:
  REVOKE EXECUTE ON FUNCTION public.get_user_data()
    FROM PUBLIC;
  ALTER FUNCTION public.get_user_data()
    SET search_path = pg_catalog, pg_temp;
```

## 🔒 Covered Security Domains

| Area | Examples |
|------|----------|
| 🔐 Authentication | `pg_hba.conf`, SCRAM-SHA-256, `trust` auth, password policies |
| 👤 Roles & Privileges | Superuser abuse, role inheritance, `CREATEROLE`, `CREATEDB` |
| 🔑 Privilege Grants | Excessive grants, `PUBLIC` privileges, default privileges |
| 🛡️ Row-Level Security | Missing RLS, bypass risks, owner/superuser bypass |
| 🌐 Network Exposure | `listen_addresses`, `pg_hba.conf`, CIDR mistakes |
| 🔒 TLS/SSL | SSL configuration, `hostssl`, certificate validation |
| 💉 SQL Injection | PostgreSQL-specific injection, `quote_literal`, prepared statements |
| 🧩 Extensions | Untrusted PLs, `CREATE EXTENSION`, extension privileges |
| ⚙️ Functions | `SECURITY DEFINER`, `search_path` vulnerabilities |
| 📁 Filesystem & OS | `COPY ... PROGRAM`, server-side file access |
| 🐘 Configuration | `postgresql.conf`, `pg_hba.conf`, insecure parameters |
| 🔄 Replication | Replication privileges, slots, physical/logical exposure |
| 🗄️ Schema & Database | Public schema, `CONNECT` privileges |
| 🔍 Auditing | `pgaudit`, logging, failed authentication tracking |
| 🕵️ Data Exposure | Sensitive columns, views, masking |
| 🚨 Dangerous Privileges | `SUPERUSER`, `BYPASSRLS`, `REPLICATION` |
| 📦 Backup Security | `pg_dump`, credentials, exposed backup files |

## 🐘 PostgreSQL Version Support

| Version | Status | Key Security Features |
|---------|--------|----------------------|
| PostgreSQL 14 | ✅ Supported | `pg_read_all_data`, SCRAM default |
| PostgreSQL 15 | ✅ Supported | PUBLIC schema CREATE revoked |
| PostgreSQL 16 | ✅ Supported | CREATEROLE privilege redesign |
| PostgreSQL 17 | ✅ Supported | Incremental backup, event trigger changes |
| PostgreSQL 18 | ✅ Supported | OAuth/OAUTHBEARER, UUIDv7, MAINTAIN privilege |

## 📁 Repository Structure

```
VibePGSec/
│
├── SKILL.md                    # Main skill — AI reads this first
├── README.md                   # You're reading this
│
├── references/                 # Deep-dive security reference docs
│   ├── authentication.md
│   ├── roles-and-privileges.md
│   ├── rls.md
│   ├── security-definer.md
│   ├── search-path.md
│   ├── extensions.md
│   ├── tls-and-network.md
│   ├── replication.md
│   ├── sql-injection.md
│   ├── filesystem-and-os.md
│   └── backup-security.md
│
├── attacks/                    # Offensive security playbooks
│   ├── privilege-escalation.md
│   ├── role-escalation.md
│   ├── rls-bypass.md
│   ├── search-path-hijacking.md
│   ├── copy-program-exploitation.md
│   └── extension-abuse.md
│
├── versions/                   # Version-specific security notes
│   ├── pg14.md
│   ├── pg15.md
│   ├── pg16.md
│   ├── pg17.md
│   └── pg18.md
│
└── checklists/                 # Actionable checklists
    ├── security-audit.md
    ├── hardening.md
    └── penetration-test.md
```

## 🚀 Quick Start

After installation, try these prompts with your AI agent:

| Prompt | Mode |
|--------|------|
| "Audit this PostgreSQL instance for security issues" | 🔍 AUDIT |
| "Check if this SECURITY DEFINER function is exploitable" | ⚔️ VERIFY |
| "Harden this PostgreSQL configuration" | 🛡️ HARDEN |
| "Review pg_hba.conf for security weaknesses" | 🔍 AUDIT |
| "Check for privilege escalation paths" | ⚔️ VERIFY |
| "Set up pgaudit for compliance logging" | 🛡️ HARDEN |

## 🤝 Contributing

Contributions are welcome! If you have:

- New attack patterns or bypass techniques
- PostgreSQL version-specific security findings
- Improved detection queries
- Better remediation strategies

Please open a pull request or issue.

## 📬 Contact

For questions, suggestions, or security findings, please open an issue on this repository.

---

*Inspired by [VibeSec-Skill](https://github.com/BehiSecc/VibeSec-Skill) — security-first AI skills for secure coding.*
