# pgaudit — PostgreSQL Audit Logging

## Overview

`pgaudit` is the standard PostgreSQL extension for **session-level and object-level audit logging**. While PostgreSQL's built-in `log_statement` setting provides basic query logging, it lacks the structure, granularity, and reliability needed for security compliance (SOC 2, PCI-DSS, HIPAA, ISO 27001).

`pgaudit` logs structured, tamper-evident audit records for:
- All DDL operations (CREATE, ALTER, DROP)
- All DML operations (SELECT, INSERT, UPDATE, DELETE)
- Role and privilege changes (GRANT, REVOKE)
- Connection events
- Specific object-level access

---

## 1. Installation

### Via Package Manager
```bash
# Debian/Ubuntu
apt-get install postgresql-16-pgaudit

# RHEL/Rocky/Alma
dnf install pgaudit16

# macOS (Homebrew)
brew install pgaudit
```

### Enable in `postgresql.conf`
```ini
shared_preload_libraries = 'pgaudit'
```

> **Requires a PostgreSQL restart** (not just reload) when adding to `shared_preload_libraries`.

### Install the Extension
```sql
CREATE EXTENSION pgaudit;
```

---

## 2. Configuration Parameters

`pgaudit` is configured via `postgresql.conf` or `ALTER SYSTEM`:

### Session Audit (`pgaudit.log`)
Controls which statement classes are logged for **all sessions**:

| Class | Logs |
|-------|------|
| `READ` | `SELECT`, `COPY TO` |
| `WRITE` | `INSERT`, `UPDATE`, `DELETE`, `TRUNCATE`, `COPY FROM` |
| `FUNCTION` | Function/procedure calls |
| `ROLE` | `GRANT`, `REVOKE`, `CREATE ROLE`, `ALTER ROLE`, `DROP ROLE` |
| `DDL` | All DDL statements except those in ROLE class |
| `MISC` | `DISCARD`, `FETCH`, `CHECKPOINT`, `VACUUM` |
| `MISC_SET` | `SET` commands |
| `ALL` | All of the above |
| `-DDL` | All except DDL (negate with minus prefix) |

### Recommended Configuration
```ini
# Log all DDL and privilege changes (minimum for compliance)
pgaudit.log = 'ddl, role'

# For higher security environments, also log reads and writes
pgaudit.log = 'read, write, ddl, role'

# Log the relation (table name) in each audit record
pgaudit.log_relation = on

# Include parameter values in logged statements
pgaudit.log_parameter = on

# Catalog queries (system table SELECTs) — usually excluded for noise reduction
pgaudit.log_catalog = off
```

### Apply Without Restart
```sql
ALTER SYSTEM SET pgaudit.log = 'ddl, role';
SELECT pg_reload_conf();
```

---

## 3. Object-Level Auditing

For fine-grained auditing of specific tables or columns, use **object-level audit**:

```sql
-- Create a dedicated audit role (no login, no password)
CREATE ROLE auditor;

-- Grant auditor role specific table access for auditing
-- pgaudit will log access whenever this role's privileges are used
GRANT SELECT ON TABLE users TO auditor;
GRANT SELECT ON TABLE payments TO auditor;

-- Enable object-level auditing using the audit role
ALTER SYSTEM SET pgaudit.role = 'auditor';
SELECT pg_reload_conf();
```

This means any access to `users` or `payments` tables will be audit-logged regardless of which role performs the access, as long as `auditor` has privilege on those objects.

---

## 4. Reading Audit Logs

pgaudit writes structured log entries to the PostgreSQL log file prefixed with `AUDIT:`:

```
2024-01-15 10:23:45 UTC [1234] app_user@appdb LOG:  AUDIT: SESSION,1,1,DDL,CREATE TABLE,TABLE,public.accounts,"CREATE TABLE public.accounts (id serial PRIMARY KEY, balance numeric)",<not logged>
```

Fields:
1. `AUDIT:` prefix
2. Log type: `SESSION` or `OBJECT`
3. Statement ID
4. Substatement ID
5. Statement class (DDL, WRITE, etc.)
6. Command (CREATE TABLE, INSERT, etc.)
7. Object type
8. Object name
9. Statement text
10. Parameter values (if `pgaudit.log_parameter = on`)

---

## 5. Detecting Privilege Escalation via pgaudit Logs

```sql
-- Find GRANT statements in logs (if using log_fdw or external log ingestion)
-- Direct grep on log file:
-- grep "AUDIT:.*ROLE.*GRANT" /var/log/postgresql/postgresql-*.log

-- Alternatively, enable log_fdw to query logs from SQL:
CREATE EXTENSION file_fdw;
CREATE SERVER pglog FOREIGN DATA WRAPPER file_fdw;
CREATE FOREIGN TABLE pg_log (
    log_time          timestamp,
    user_name         text,
    database_name     text,
    process_id        integer,
    connection_from   text,
    session_id        text,
    session_line_num  bigint,
    command_tag       text,
    session_start_time timestamp,
    virtual_transaction_id text,
    transaction_id    bigint,
    error_severity    text,
    sql_state_code    text,
    message           text,
    detail            text,
    hint              text,
    internal_query    text,
    internal_query_pos integer,
    context           text,
    query             text,
    query_pos         integer,
    location          text,
    application_name  text
) SERVER pglog
OPTIONS (filename '/var/log/postgresql/postgresql-2024-01-15.log', format 'csv');

-- Query for audit events
SELECT log_time, user_name, database_name, message
FROM pg_log
WHERE message LIKE 'AUDIT:%ROLE%'
ORDER BY log_time DESC;
```

---

## 6. Per-Role Audit Configuration

Override global `pgaudit.log` for specific high-risk roles:

```sql
-- Log ALL activity for the DBA role (no exceptions)
ALTER ROLE dba_user SET pgaudit.log = 'all';

-- Log only writes for the application service account
ALTER ROLE app_user SET pgaudit.log = 'write';

-- Log everything for the replication user
ALTER ROLE repl_user SET pgaudit.log = 'all';
```

---

## 7. Verifying pgaudit is Active

```sql
-- Check if pgaudit is installed
SELECT extname, extversion FROM pg_extension WHERE extname = 'pgaudit';

-- Check current pgaudit settings
SELECT name, setting FROM pg_settings WHERE name LIKE 'pgaudit%';

-- Trigger a test event and verify it appears in logs
CREATE TABLE pgaudit_test_table (id int);
DROP TABLE pgaudit_test_table;
-- Then check: grep "AUDIT:.*pgaudit_test_table" /path/to/postgres.log
```

---

## 8. SIEM Integration

Structured audit logs can be forwarded to SIEM systems:

- **JSON logging** (PG15+): Set `log_destination = 'jsonlog'` for machine-parseable JSON output
- **Syslog**: Set `log_destination = 'syslog'` and configure `syslog_facility`
- **Splunk/Elastic**: Use Filebeat or Logstash with the PostgreSQL log format
- **Amazon CloudWatch / Azure Monitor**: Use cloud-native PostgreSQL logging integrations

```ini
# postgresql.conf for JSON log output (PG 15+)
log_destination = 'jsonlog'
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d.json'
```

---

## Verification Checklist

- [ ] `pgaudit` extension is installed and listed in `shared_preload_libraries`
- [ ] `pgaudit.log` is set to at minimum `'ddl, role'`
- [ ] `pgaudit.log_relation = on` for detailed object tracking
- [ ] High-privilege roles (DBAs, superusers) have `pgaudit.log = 'all'` set per-role
- [ ] An object-level audit role is configured for sensitive tables
- [ ] Audit logs are being written to a persistent, protected directory
- [ ] Log file permissions prevent modification by the `postgres` OS user
- [ ] Logs are forwarded to a centralized SIEM or log aggregation system
- [ ] A process exists to review audit logs for anomalies regularly
