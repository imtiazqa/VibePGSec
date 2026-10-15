# PostgreSQL Comprehensive Security Audit Checklist

This checklist provides a structured 100+ point security inspection for PostgreSQL environments. Use this checklist during routine security audits, pre-production reviews, or compliance assessments.

---

## 1. Authentication & Access Control

- [ ] `pg_hba.conf` contains no `trust` authentication methods for non-local or networked connections.
- [ ] No `password` (plaintext) authentication methods configured in `pg_hba.conf`.
- [ ] `password_encryption` parameter is set to `'scram-sha-256'`.
- [ ] No active user accounts have passwords hashed with legacy `md5`.
- [ ] No login-enabled roles (`rolcanlogin = true`) have blank or null passwords.
- [ ] Remote connections are constrained to narrow CIDR blocks rather than `0.0.0.0/0`.
- [ ] `authentication_timeout` is set to an appropriate duration (e.g., 30s to 1min).
- [ ] Account lifecycle processes exist to revoke access for departed personnel.
- [ ] Separate accounts exist for individual administrators (no shared `postgres` superuser credentials).
- [ ] Application service accounts connect using dedicated, least-privilege database roles.

---

## 2. Roles, Privileges & Superusers

- [ ] Number of `SUPERUSER` accounts is minimized (ideally 1–2 administrative accounts).
- [ ] Applications and services do NOT connect as a superuser.
- [ ] Unnecessary roles do not hold `CREATEROLE` or `CREATEDB` attributes.
- [ ] Roles with `BYPASSRLS` are audited and restricted solely to administrative/backup tools.
- [ ] Predefined role `pg_execute_server_program` is not granted to any non-admin role.
- [ ] Predefined roles `pg_read_server_files` and `pg_write_server_files` are strictly controlled.
- [ ] Predefined roles `pg_read_all_data` and `pg_write_all_data` are restricted to backup/ETL roles.
- [ ] Default privileges on newly created schemas are explicitly configured (`ALTER DEFAULT PRIVILEGES`).
- [ ] `PUBLIC` pseudo-role has no direct `CREATE` privileges on schemas (specifically PG < 15 check).
- [ ] `PUBLIC` has no unnecessary `EXECUTE` privileges on security-sensitive functions.
- [ ] No unauthorized roles have `ADMIN OPTION` over privileged roles.
- [ ] Role inheritance (`INHERIT`) is reviewed to ensure roles do not gain unintended indirect permissions.

---

## 3. Network & Transport Layer Security (TLS)

- [ ] `ssl = on` is explicitly set in `postgresql.conf`.
- [ ] Valid, non-expired TLS certificates issued by a trusted or internal CA are configured.
- [ ] `hostssl` directives are enforced in `pg_hba.conf` for all client-facing connection types.
- [ ] Weak or legacy TLS ciphers are disabled (`ssl_ciphers` configured securely).
- [ ] Client applications configure `sslmode=verify-full` or `sslmode=verify-ca`.
- [ ] Client certificate authentication (`cert`) is enforced for high-security service integrations.
- [ ] `listen_addresses` is bound only to necessary network interfaces (not `*` unless behind a firewall).
- [ ] PostgreSQL default port (`5432`) is not exposed directly to the public internet.
- [ ] Firewall rules (iptables, security groups) enforce network perimeter boundaries around the database.

---

## 4. Row-Level Security (RLS)

- [ ] Multi-tenant or user-isolated tables have Row-Level Security enabled (`ENABLE ROW LEVEL SECURITY`).
- [ ] Critical tables enforce `FORCE ROW LEVEL SECURITY` to prevent table owners from bypassing policies.
- [ ] Every RLS-enabled table has at least one explicit policy defined.
- [ ] Policies cover all required commands (`SELECT`, `INSERT`, `UPDATE`, `DELETE`).
- [ ] `WITH CHECK` clauses are implemented on `INSERT` and `UPDATE` policies to prevent data injection into other tenants.
- [ ] Policy definitions avoid calling leaky user-defined functions or non-deterministic functions.
- [ ] Views querying RLS tables utilize `WITH (security_invoker = true)` on PostgreSQL 15+.
- [ ] Application connection pooling appropriately sets and resets session variables used in RLS policies.

---

## 5. Functions & Procedures (`SECURITY DEFINER`)

- [ ] All `SECURITY DEFINER` functions explicitly set a secure `search_path` (e.g., `SET search_path = pg_catalog, pg_temp`).
- [ ] `SECURITY DEFINER` functions are owned by least-privileged roles rather than `postgres` where possible.
- [ ] Default `EXECUTE` privilege on `SECURITY DEFINER` functions is revoked from `PUBLIC`.
- [ ] All database object references within function bodies are fully schema-qualified (`schema.table`).
- [ ] Stored procedures that execute dynamic SQL use parameterized `EXECUTE ... USING` or `format('%I', ...)`.
- [ ] No stored procedure concatenates untrusted user input directly into dynamic queries.
- [ ] Functions do not write temporary files or expose filesystem paths.

---

## 6. Extensions & Procedural Languages

- [ ] Untrusted procedural languages (`plpython3u`, `plperlu`, `pltclu`) are uninstalled unless strictly necessary.
- [ ] External access extensions (`dblink`, `postgres_fdw`, `file_fdw`) are audited and restricted.
- [ ] Only superusers can create new extensions.
- [ ] Third-party extensions are reviewed for known CVEs and updated regularly.
- [ ] Cryptographic extensions (such as `pgcrypto`) use secure hashing and encryption algorithms.

---

## 7. PostgreSQL Configuration & Hardening

- [ ] `logging_collector = on` is enabled for central log capture.
- [ ] `log_connections = on` and `log_disconnections = on` are enabled.
- [ ] `log_statement` is set to an appropriate level (e.g., `ddl` or `mod`) based on compliance needs.
- [ ] `log_line_prefix` contains timestamp, process ID, user, and database: `%m [%p] %q%u@%d `.
- [ ] `shared_preload_libraries` is audited to ensure no untrusted libraries are loaded into server memory.
- [ ] Resource exhaustion timeouts are configured:
  - `statement_timeout`
  - `idle_in_transaction_session_timeout`
  - `lock_timeout`
- [ ] `max_connections` is tuned appropriately with a connection pooler to prevent DoS.

---

## 8. Replication Security

- [ ] Standby nodes connect over TLS using `hostssl` in `pg_hba.conf`.
- [ ] Replication accounts use dedicated roles with minimal privileges and strong SCRAM passwords.
- [ ] Logical replication subscriptions do not expose plaintext credentials in `subconninfo`.
- [ ] Logical replication publications only export authorized tables (avoid unbounded `ALL TABLES` when sensitive tables exist).
- [ ] Replication slots are actively monitored to prevent disk exhaustion.

---

## 9. Backup & Disaster Recovery

- [ ] Automated backups execute with least-privileged backup roles (`pg_read_all_data`).
- [ ] Backup artifacts and WAL archives are encrypted at rest and during transit.
- [ ] `.pgpass` files have restrictive file permissions (`0600`) and secure ownership.
- [ ] Backup storage environments enforce strict access control and anti-tamper policies.
- [ ] Regular backup restoration tests are conducted and validated.
