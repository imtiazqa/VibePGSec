# PostgreSQL Production Hardening Guide

A practical, step-by-step hardening guide for PostgreSQL database clusters with concrete SQL commands and configuration snippets.

---

## Step 1: Authentication & Connection Security

### 1.1 Enforce SCRAM-SHA-256 Authentication
Set `password_encryption` in `postgresql.conf`:
```ini
password_encryption = 'scram-sha-256'
```
Reload PostgreSQL configuration:
```sql
SELECT pg_reload_conf();
```

### 1.2 Secure `pg_hba.conf`
Ensure all network connections require TLS and SCRAM-SHA-256 authentication:
```
# TYPE  DATABASE        USER            ADDRESS                 METHOD
local   all             all                                     peer
hostssl all             all             10.0.0.0/8              scram-sha-256
hostssl all             all             172.16.0.0/12           scram-sha-256
host    all             all             all                     reject
```

### 1.3 Enable SSL/TLS Encryption
Configure TLS parameters in `postgresql.conf`:
```ini
ssl = on
ssl_cert_file = '/etc/ssl/certs/server.crt'
ssl_key_file = '/etc/ssl/private/server.key'
ssl_min_protocol_version = 'TLSv1.3'
ssl_ciphers = 'HIGH:!aNULL:!kEDH'
```

---

## Step 2: Role & Privilege Hardening

### 2.1 Revoke Public Schema Permissions (PostgreSQL < 15)
In PostgreSQL 14 and earlier, revoke `CREATE` privilege on the `public` schema from `PUBLIC`:
```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### 2.2 Revoke Default Function Execution Privileges
Revoke default `EXECUTE` privileges from `PUBLIC` on sensitive functions:
```sql
REVOKE EXECUTE ON FUNCTION pg_read_file(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_file(text, bigint, bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_ls_dir(text) FROM PUBLIC;
```

### 2.3 Establish Principle of Least Privilege
Create dedicated roles with minimal permissions instead of using `postgres`:
```sql
-- Read-only role for analytics
CREATE ROLE readonly_analyst WITH LOGIN PASSWORD 'SecurePasswordHere';
GRANT CONNECT ON DATABASE appdb TO readonly_analyst;
GRANT USAGE ON SCHEMA app_schema TO readonly_analyst;
GRANT SELECT ON ALL TABLES IN SCHEMA app_schema TO readonly_analyst;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_schema GRANT SELECT ON TABLES TO readonly_analyst;

-- Application service role
CREATE ROLE app_service WITH LOGIN PASSWORD 'AppServicePasswordHere';
GRANT CONNECT ON DATABASE appdb TO app_service;
GRANT USAGE ON SCHEMA app_schema TO app_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA app_schema TO app_service;
ALTER DEFAULT PRIVILEGES IN SCHEMA app_schema GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_service;
```

---

## Step 3: Function & Stored Procedure Hardening

### 3.1 Lock Down `SECURITY DEFINER` Functions
Always fix the `search_path` and revoke `PUBLIC` execute rights:
```sql
CREATE OR REPLACE FUNCTION secure_lookup(target_id integer)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    result text;
BEGIN
    SELECT name INTO result FROM app_schema.users WHERE id = target_id;
    RETURN result;
END;
$$;

-- Revoke default PUBLIC execution and grant explicitly
REVOKE EXECUTE ON FUNCTION secure_lookup(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secure_lookup(integer) TO app_service;
```

---

## Step 4: Row-Level Security (RLS) Hardening

### 4.1 Enable and Force RLS
```sql
ALTER TABLE app_schema.tenant_data ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_schema.tenant_data FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy ON app_schema.tenant_data
    FOR ALL
    TO app_service
    USING (tenant_id = current_setting('app.current_tenant')::uuid)
    WITH CHECK (tenant_id = current_setting('app.current_tenant')::uuid);
```

---

## Step 5: Logging and Audit Configuration

Configure structured logging in `postgresql.conf`:
```ini
logging_collector = on
log_directory = 'log'
log_filename = 'postgresql-%Y-%m-%d_%H%M%S.log'
log_file_mode = 0600
log_connections = on
log_disconnections = on
log_duration = off
log_line_prefix = '%m [%p] %q%u@%d '
log_statement = 'ddl'
log_min_messages = warning
log_min_error_statement = error
```

---

## Step 6: Resource Limits & DoS Prevention

Set query and transaction timeouts in `postgresql.conf`:
```ini
statement_timeout = 30000                 # 30 seconds
idle_in_transaction_session_timeout = 60000 # 60 seconds
lock_timeout = 10000                      # 10 seconds
max_connections = 100
```
