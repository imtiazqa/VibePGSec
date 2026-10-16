# PostgreSQL Production Hardening Guide

A practical, step-by-step hardening guide for PostgreSQL database clusters with concrete SQL commands and configuration snippets. Apply these in order — each step builds on the previous.

---

## Step 1: Authentication & Connection Security

### 1.1 Enforce SCRAM-SHA-256 Authentication
```ini
# postgresql.conf
password_encryption = 'scram-sha-256'
authentication_timeout = 30s
```
```sql
SELECT pg_reload_conf();

-- Identify accounts still using MD5
SELECT rolname FROM pg_authid WHERE rolpassword LIKE 'md5%' AND rolcanlogin;

-- Reset those accounts' passwords to trigger SCRAM hash generation
ALTER ROLE legacy_user PASSWORD 'NewSecurePassword';
```

### 1.2 Secure `pg_hba.conf`
```
# TYPE  DATABASE  USER      ADDRESS          METHOD
local   all       postgres                   peer
local   all       all                        scram-sha-256
hostssl all       all       10.0.0.0/8       scram-sha-256
hostssl replication repl    10.0.1.50/32     scram-sha-256
host    all       all       0.0.0.0/0        reject
host    all       all       ::/0             reject
```

### 1.3 Enable TLS
```ini
ssl = on
ssl_min_protocol_version = 'TLSv1.3'
ssl_ciphers = 'HIGH:!aNULL:!kEDH:!3DES'
ssl_prefer_server_ciphers = on
ssl_cert_file = '/etc/ssl/postgresql/server.crt'
ssl_key_file = '/etc/ssl/postgresql/server.key'
ssl_ca_file = '/etc/ssl/postgresql/ca.crt'
```
```bash
# Ensure key permissions are correct
chmod 0600 /etc/ssl/postgresql/server.key
chown postgres:postgres /etc/ssl/postgresql/server.key
```

---

## Step 2: Role & Privilege Hardening

### 2.1 Revoke Public Schema CREATE (PG < 15)
```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Verify
SELECT has_schema_privilege('public', 'public', 'CREATE'); -- must be false
```

### 2.2 Revoke Dangerous Default Function Privileges
```sql
REVOKE EXECUTE ON FUNCTION pg_read_file(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_file(text, bigint, bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_ls_dir(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_stat_file(text) FROM PUBLIC;
```

### 2.3 Create Dedicated Application Roles
```sql
-- Read-only role for analytics / reporting
CREATE ROLE app_readonly WITH LOGIN PASSWORD 'ReadPass123!';
GRANT CONNECT ON DATABASE appdb TO app_readonly;
GRANT USAGE ON SCHEMA app TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT SELECT ON TABLES TO app_readonly;

-- Application service role (DML only)
CREATE ROLE app_service WITH LOGIN PASSWORD 'ServicePass123!';
GRANT CONNECT ON DATABASE appdb TO app_service;
GRANT USAGE ON SCHEMA app TO app_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app TO app_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA app TO app_service;
ALTER DEFAULT PRIVILEGES IN SCHEMA app 
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_service;
ALTER DEFAULT PRIVILEGES IN SCHEMA app 
    GRANT USAGE, SELECT ON SEQUENCES TO app_service;

-- Maintenance role (PG18+)
CREATE ROLE app_maintenance WITH LOGIN PASSWORD 'MaintPass123!';
GRANT MAINTAIN ON ALL TABLES IN SCHEMA app TO app_maintenance;
ALTER DEFAULT PRIVILEGES IN SCHEMA app GRANT MAINTAIN ON TABLES TO app_maintenance;
```

### 2.4 Audit and Revoke Unnecessary Superusers
```sql
-- List all superusers
SELECT rolname FROM pg_roles WHERE rolsuper = true;

-- Revoke superuser from any role that doesn't need it
ALTER ROLE old_admin NOSUPERUSER;

-- Remove pg_execute_server_program from non-admin roles
SELECT r.rolname FROM pg_auth_members m
JOIN pg_roles g ON m.roleid = g.oid AND g.rolname = 'pg_execute_server_program'
JOIN pg_roles r ON m.member = r.oid;
-- Then:
REVOKE pg_execute_server_program FROM <role>;
```

---

## Step 3: Function Security

### 3.1 Fix `SECURITY DEFINER` Functions
```sql
-- Find all SECURITY DEFINER functions without safe search_path
SELECT n.nspname || '.' || p.proname AS function_name,
       p.prosecdef, p.proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND (p.proconfig IS NULL OR NOT array_to_string(p.proconfig, ',') LIKE '%search_path%');

-- Fix each one:
ALTER FUNCTION schema.function_name() SET search_path = pg_catalog, pg_temp;

-- Revoke PUBLIC execution on sensitive SECURITY DEFINER functions
REVOKE EXECUTE ON FUNCTION schema.function_name() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION schema.function_name() TO app_service;
```

---

## Step 4: Row-Level Security

### 4.1 Enable and Force RLS on Sensitive Tables
```sql
ALTER TABLE app.user_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE app.user_data FORCE ROW LEVEL SECURITY;

CREATE POLICY user_isolation ON app.user_data
    FOR ALL
    TO app_service
    USING (user_id = current_setting('app.user_id')::uuid)
    WITH CHECK (user_id = current_setting('app.user_id')::uuid);
```

---

## Step 5: Extension Hardening

### 5.1 Remove Untrusted Procedural Languages
```sql
-- Check installed untrusted languages
SELECT lanname, lanpltrusted FROM pg_language WHERE lanpltrusted = false;

-- Remove if not needed
DROP EXTENSION IF EXISTS plpython3u;
DROP EXTENSION IF EXISTS plperlu;
DROP EXTENSION IF EXISTS pltclu;
```

### 5.2 Install Security Extensions
```sql
-- Install pgaudit for audit logging
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Install pg_stat_statements for query monitoring
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;
```

---

## Step 6: Logging and Audit Configuration

```ini
# postgresql.conf
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d.log'
log_file_mode = 0600
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d '
log_statement = 'ddl'
log_min_messages = warning
log_min_error_statement = error
log_timezone = 'UTC'

# pgaudit (requires shared_preload_libraries = 'pgaudit')
pgaudit.log = 'ddl, role'
pgaudit.log_relation = on
pgaudit.log_parameter = on
pgaudit.log_catalog = off
```

---

## Step 7: Resource Limits and DoS Prevention

```ini
# postgresql.conf
statement_timeout = 30000
idle_in_transaction_session_timeout = 60000
lock_timeout = 10000
deadlock_timeout = 1000
max_connections = 100
superuser_reserved_connections = 3
tcp_keepalives_idle = 60
tcp_keepalives_interval = 10
tcp_keepalives_count = 6
```

### Connection Pooler (PgBouncer) Hardening
For high-traffic applications, place PgBouncer in front of PostgreSQL:
```ini
# pgbouncer.ini
[databases]
appdb = host=localhost dbname=appdb pool_size=20

[pgbouncer]
listen_port = 6432
listen_addr = 127.0.0.1
auth_type = scram-sha-256
auth_file = /etc/pgbouncer/userlist.txt
pool_mode = transaction
max_client_conn = 200
server_tls_sslmode = verify-full
server_tls_ca_file = /etc/ssl/ca.crt
# Disable direct superuser connections through pooler
admin_users = pgbouncer_admin
```

---

## Step 8: Backup Security

```sql
-- Create dedicated backup role
CREATE ROLE backup_agent WITH LOGIN PASSWORD 'BackupPass123!';
GRANT pg_read_all_data TO backup_agent;

-- For physical backups (pg_basebackup)
CREATE ROLE basebackup_agent WITH REPLICATION LOGIN PASSWORD 'BaseBackupPass123!';
```
```bash
# Encrypt pg_dump output
pg_dump -Fc -U backup_agent appdb | \
  gpg --encrypt --recipient ops-backup-key > appdb_$(date +%Y%m%d).dump.gpg

# Secure .pgpass
chmod 0600 ~/.pgpass
echo "localhost:5432:appdb:backup_agent:BackupPass123!" >> ~/.pgpass
```

---

## Step 9: Monitoring and Alerting

```sql
-- Install pg_stat_statements
-- (Add to shared_preload_libraries first, then:)
CREATE EXTENSION pg_stat_statements;

-- Schedule these monitoring queries via pg_cron or external tool:

-- 1. Security health check (run every 5 min)
SELECT
    (SELECT COUNT(*) FROM pg_roles WHERE rolsuper) AS superuser_count,
    (SELECT COUNT(*) FROM pg_roles WHERE rolbypassrls) AS bypassrls_count,
    (SELECT COUNT(*) FROM pg_stat_activity 
     WHERE state = 'idle in transaction'
     AND state_change < now() - INTERVAL '5 min') AS stuck_txns,
    (SELECT setting FROM pg_settings WHERE name = 'ssl') AS ssl_on;

-- 2. Replication slot health (run every 10 min)
SELECT slot_name, active,
       pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS lag_bytes
FROM pg_replication_slots WHERE NOT active;
-- Alert if any inactive slots with lag > 1GB
```

---

## Hardening Verification Summary

```sql
-- Run this query as a final hardening verification
SELECT 
    (SELECT setting FROM pg_settings WHERE name = 'ssl') = 'on' AS ssl_on,
    (SELECT setting FROM pg_settings WHERE name = 'password_encryption') = 'scram-sha-256' AS scram_on,
    (SELECT setting FROM pg_settings WHERE name = 'log_connections') = 'on' AS log_connections_on,
    (SELECT setting FROM pg_settings WHERE name = 'logging_collector') = 'on' AS collector_on,
    NOT has_schema_privilege('public', 'public', 'CREATE') AS public_schema_locked,
    (SELECT COUNT(*) FROM pg_roles WHERE rolsuper) <= 2 AS superuser_count_ok,
    (SELECT COUNT(*) FROM pg_hba_file_rules WHERE auth_method = 'trust') = 0 AS no_trust_auth;
```
