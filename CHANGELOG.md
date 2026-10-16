# Changelog

All notable changes to VibePGSec will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [0.2.0] — 2026-10-16

### Added
- `references/pg-hba.md` — Deep-dive on `pg_hba.conf` authentication methods, CIDR risks, replication entries, and a secure configuration template
- `references/postgresql-config.md` — Comprehensive security reference for all `postgresql.conf` parameters with hardened values and detection queries
- `references/pgaudit.md` — Full pgaudit installation guide, session/object audit configuration, per-role settings, log querying, and SIEM integration
- `references/observability.md` — Ready-to-use SQL queries for detecting suspicious sessions, privilege escalation indicators, anomalous query patterns, and replication anomalies
- `CONTRIBUTING.md` — Contribution guidelines, SQL standards, PR process, and content standards

### Improved
- `versions/pg14.md` — Expanded to full coverage: predefined roles deep-dive, SCRAM migration queries, MD5 detection, comprehensive audit SQL
- `versions/pg15.md` — Expanded: full `public` schema change analysis, `security_invoker` views, MERGE + RLS coverage, publication column auditing
- `versions/pg16.md` — Expanded: `CREATEROLE` redesign with migration SQL, `pg_use_reserved_connections`, `pg_create_subscription`, `require_auth`, regex `pg_hba.conf`
- `versions/pg17.md` — Expanded: incremental backup security, `LOGIN` event triggers with examples and lock-out mitigation, `allow_alter_system`, SQL/JSON security
- `versions/pg18.md` — Expanded: `MAINTAIN` privilege with migration SQL, OAuth deep-dive with risk table, UUIDv7 IDOR prevention, virtual generated columns
- `checklists/hardening.md` — Expanded from 6 to 9 steps; added extension hardening, backup security, connection pooler (PgBouncer) hardening, monitoring setup, and final verification query
- `checklists/penetration-test.md` — Full expansion: 5 complete phases with exploitation verification procedures and professional reporting templates (finding template, severity guide, executive summary)

---

## [0.1.0] — 2026-10-15

### Added
- Initial release of VibePGSec PostgreSQL Security AI Skill
- `SKILL.md` — Core AI skill with 13 security domains, three operating modes (AUDIT / HARDEN / VERIFY), and comprehensive audit workflow
- `README.md` — Project overview, multi-platform installation guide, and quick-start examples
- `references/authentication.md` — pg_hba.conf, SCRAM, MD5, trust, peer, cert authentication
- `references/roles-and-privileges.md` — Role system, superuser risks, CREATEROLE, predefined roles, PUBLIC grants
- `references/rls.md` — Row-Level Security, policy types, BYPASSRLS, FORCE ROW LEVEL SECURITY
- `references/security-definer.md` — SECURITY DEFINER internals, search_path risks, privilege escalation
- `references/search-path.md` — search_path resolution, pg_temp risks, trojan objects
- `references/extensions.md` — Trusted vs untrusted extensions, dangerous extensions list
- `references/tls-and-network.md` — TLS/SSL configuration, hostssl, listen_addresses
- `references/replication.md` — Streaming and logical replication security
- `references/sql-injection.md` — PostgreSQL-specific injection, EXECUTE … USING, format()
- `references/filesystem-and-os.md` — COPY PROGRAM, pg_read_file, large objects
- `references/backup-security.md` — pg_dump, pg_basebackup, credential security, encryption
- `attacks/privilege-escalation.md` — SECURITY DEFINER exploitation, predefined role abuse, untrusted PLs
- `attacks/role-escalation.md` — CREATEROLE exploitation, SET ROLE chains, ADMIN OPTION
- `attacks/rls-bypass.md` — Table owner bypass, BYPASSRLS, missing WITH CHECK, leaky functions
- `attacks/search-path-hijacking.md` — Trojan objects, pg_temp exploitation, prevention
- `attacks/copy-program-exploitation.md` — COPY PROGRAM mechanics, detection, restriction
- `attacks/extension-abuse.md` — Untrusted PLs, dblink SSRF, file_fdw, postgres_fdw credentials
- `checklists/security-audit.md` — 100+ item audit checklist across 9 security domains
- `checklists/hardening.md` — Step-by-step production hardening guide
- `checklists/penetration-test.md` — Penetration testing methodology
- `versions/pg14.md` through `versions/pg18.md` — Version-specific security notes for PG 14–18
