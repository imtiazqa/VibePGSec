---
name: VibePGSec
description: >-
  This skill helps AI agents perform PostgreSQL security auditing, hardening, and
  verification. Use this when working with any PostgreSQL database, reviewing
  PostgreSQL configurations, or when a user requests a security scan or audit of
  their PostgreSQL environment.
---

# PostgreSQL Security Specialist Guide

## Overview

This guide transforms an AI agent into a **PostgreSQL security specialist**. Your role is to approach PostgreSQL environments from an **attacker's perspective** — finding vulnerabilities, verifying exploitability, and providing actionable remediation.

You are not a checklist runner. You are a PostgreSQL security auditor who thinks like a penetration tester.

**Key Principles:**
- **Assume breach**: Assume every configuration is wrong until proven otherwise
- **Defense in depth**: Never rely on a single security control
- **Fail securely**: When something fails, fail closed (deny access)
- **Least privilege**: Grant only the minimum permissions necessary
- **Verify, don't trust**: Test findings to confirm exploitability
- **Evidence-based**: Every finding must include proof (SQL query + output)

---

## Three Modes of Operation

### 🔍 AUDIT — Find Security Weaknesses

Systematically inspect the PostgreSQL environment for security issues. Walk through every domain in this guide, execute detection queries, classify findings by severity, and produce a structured report.

### 🛡️ HARDEN — Recommend and Fix

Based on audit findings (or proactively), provide specific configuration changes, SQL commands, and `pg_hba.conf` modifications to harden the environment.

### ⚔️ VERIFY — Confirm Exploitability

For specific findings, perform controlled tests to determine whether the vulnerability is actually exploitable in the current environment. This distinguishes theoretical risks from real threats.

---

## Audit Output Format

For every finding, use this structured format:

```
[SEVERITY] Finding Title
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Component:   <what is affected>
Risk:        <what an attacker could do>
Evidence:    <SQL query that proves the finding>
Impact:      <business/security impact>
Remediation: <specific SQL or config change>
Reference:   <link to reference doc>
```

**Severity Levels:**
- **CRITICAL**: Immediate exploitation possible, superuser access or data breach
- **HIGH**: Privilege escalation or significant data exposure likely
- **MEDIUM**: Security weakness that increases attack surface
- **LOW**: Minor issue, defense-in-depth improvement
- **INFO**: Informational finding, no immediate risk

---

## Security Domain 1: Authentication

### What to Check

Authentication is the front door. Misconfigured authentication can grant anyone database access.

### Detection Queries

```sql
-- Check pg_hba.conf rules (PostgreSQL 15+)
SELECT line_number, type, database, user_name, address, netmask, auth_method
FROM pg_hba_file_rules
ORDER BY line_number;

-- Find trust authentication (CRITICAL)
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'trust';

-- Find password (plaintext) authentication (HIGH)
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'password';

-- Find MD5 authentication (MEDIUM — should use SCRAM)
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'md5';

-- Check password encryption method
SHOW password_encryption;
-- Should be 'scram-sha-256', not 'md5'

-- Find roles still using MD5 passwords
SELECT rolname, rolpassword LIKE 'md5%' AS uses_md5
FROM pg_authid
WHERE rolcanlogin = true AND rolpassword IS NOT NULL;

-- Check for roles without passwords that can login
SELECT rolname FROM pg_authid
WHERE rolcanlogin = true AND rolpassword IS NULL;

-- Check authentication timeout
SHOW authentication_timeout;
```

### Attack Reasoning

```
AUTHENTICATION AUDIT
1. Read pg_hba_file_rules for trust entries.
   → If trust exists for non-local connections: CRITICAL
   → If trust exists for local connections to sensitive databases: HIGH
2. Check for password (plaintext) method.
   → Credentials transmitted in cleartext: HIGH
3. Check for MD5 authentication.
   → MD5 is cryptographically broken, susceptible to hash cracking: MEDIUM
4. Identify roles without passwords.
   → Combined with trust auth, this is direct access: CRITICAL
5. Check listen_addresses.
   → If '*' or '0.0.0.0' with weak auth: CRITICAL
6. Verify SCRAM-SHA-256 is the default.
   → If not, all new passwords use weak hashing: MEDIUM
```

### Common Misconfigurations

| Misconfiguration | Risk | Severity |
|-----------------|------|----------|
| `trust` for `host` connections | Anyone on the network can connect as any user | CRITICAL |
| `trust` for `local` on superuser | Local process escalation to superuser | HIGH |
| `password` auth method | Cleartext credential transmission | HIGH |
| `md5` instead of `scram-sha-256` | Weak hashing, susceptible to cracking | MEDIUM |
| Overly broad CIDR (`0.0.0.0/0`) | Any IP can attempt authentication | HIGH |
| Missing `hostssl` requirement | Non-encrypted connections allowed | MEDIUM |

### Remediation

```sql
-- Force SCRAM-SHA-256 for all new passwords
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SELECT pg_reload_conf();

-- Reset existing MD5 passwords to SCRAM
-- (user must re-enter password)
ALTER ROLE username PASSWORD 'new_secure_password';
```

```
# pg_hba.conf — secure configuration example
# TYPE  DATABASE  USER       ADDRESS         METHOD

# Local superuser access (peer = OS user must match)
local   all       postgres                   peer

# Local application access via SCRAM
local   appdb     appuser                    scram-sha-256

# Remote access via SCRAM over SSL only
hostssl appdb     appuser    10.0.0.0/8      scram-sha-256

# Reject everything else
host    all       all        0.0.0.0/0       reject
hostssl all       all        0.0.0.0/0       reject
```

**Reference:** [references/authentication.md](references/authentication.md)

---

## Security Domain 2: Roles and Privileges

### What to Check

PostgreSQL's role system controls who can do what. Overprivileged roles are the most common PostgreSQL security issue.

### Detection Queries

```sql
-- Find all superusers (CRITICAL if more than 1-2)
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
FROM pg_roles
WHERE rolsuper = true;

-- Find roles with dangerous attributes
SELECT rolname,
  CASE WHEN rolsuper THEN 'SUPERUSER ' ELSE '' END ||
  CASE WHEN rolcreaterole THEN 'CREATEROLE ' ELSE '' END ||
  CASE WHEN rolcreatedb THEN 'CREATEDB ' ELSE '' END ||
  CASE WHEN rolreplication THEN 'REPLICATION ' ELSE '' END ||
  CASE WHEN rolbypassrls THEN 'BYPASSRLS ' ELSE '' END AS dangerous_attributes
FROM pg_roles
WHERE rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls;

-- Find roles that are members of predefined admin roles
SELECT r.rolname AS role, m.rolname AS member_of
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.roleid
JOIN pg_roles m ON m.oid = am.member
WHERE r.rolname IN (
  'pg_read_all_data', 'pg_write_all_data',
  'pg_read_all_settings', 'pg_read_all_stats',
  'pg_execute_server_program',
  'pg_read_server_files', 'pg_write_server_files',
  'pg_signal_backend', 'pg_monitor'
);

-- Check for PUBLIC grants on schemas
SELECT nspname, nspacl
FROM pg_namespace
WHERE nspacl IS NOT NULL
  AND array_to_string(nspacl, ',') LIKE '%=U%';

-- Check for PUBLIC grants on functions
SELECT n.nspname, p.proname, p.proacl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proacl IS NOT NULL
  AND array_to_string(p.proacl, ',') LIKE '%=X%'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');

-- Find excessive table grants
SELECT grantee, table_schema, table_name, privilege_type
FROM information_schema.table_privileges
WHERE grantee NOT IN ('postgres', 'PUBLIC')
  AND table_schema NOT IN ('pg_catalog', 'information_schema')
ORDER BY grantee, table_schema, table_name;

-- Check default privileges
SELECT d.defaclrole::regrole AS role,
       d.defaclnamespace::regnamespace AS schema,
       d.defaclobjtype AS object_type,
       d.defaclacl AS default_acl
FROM pg_default_acl d;
```

### Attack Reasoning

```
ROLE AND PRIVILEGE AUDIT
1. Count superusers.
   → More than 2 superusers is suspicious: HIGH
   → Application roles with superuser: CRITICAL
2. Check CREATEROLE holders.
   → CREATEROLE can manage other roles (pre-PG16: nearly superuser): HIGH
3. Check predefined role membership.
   → pg_execute_server_program = OS command execution: CRITICAL
   → pg_read_server_files / pg_write_server_files = filesystem access: HIGH
   → pg_read_all_data = read all tables: HIGH
4. Inspect PUBLIC grants.
   → PUBLIC CREATE on schemas = search_path hijacking: HIGH
   → PUBLIC EXECUTE on functions = unintended access: MEDIUM
5. Check role inheritance chains.
   → A role may inherit dangerous privileges indirectly: HIGH
6. Check for roles with BYPASSRLS.
   → Can bypass all Row-Level Security: HIGH
```

### Remediation

```sql
-- Remove unnecessary superuser privilege
ALTER ROLE appuser NOSUPERUSER;

-- Revoke CREATEROLE if not needed
ALTER ROLE devuser NOCREATEROLE;

-- Revoke PUBLIC CREATE on public schema (PG < 15)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Revoke PUBLIC EXECUTE on sensitive functions
REVOKE EXECUTE ON FUNCTION sensitive_function() FROM PUBLIC;

-- Create least-privilege application role
CREATE ROLE app_readonly;
GRANT CONNECT ON DATABASE appdb TO app_readonly;
GRANT USAGE ON SCHEMA app TO app_readonly;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO app_readonly;
ALTER DEFAULT PRIVILEGES IN SCHEMA app
  GRANT SELECT ON TABLES TO app_readonly;
```

**Reference:** [references/roles-and-privileges.md](references/roles-and-privileges.md)

---

## Security Domain 3: Row-Level Security (RLS)

### What to Check

RLS provides fine-grained access control at the row level. Misconfigured RLS creates a false sense of security.

### Detection Queries

```sql
-- Find tables WITHOUT RLS that probably should have it
-- (tables with user_id or tenant_id columns)
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND tablename IN (
    SELECT tablename FROM information_schema.columns
    WHERE column_name IN ('user_id', 'tenant_id', 'org_id', 'owner_id', 'account_id')
  )
  AND NOT EXISTS (
    SELECT 1 FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relname = tablename
      AND n.nspname = schemaname
      AND c.relrowsecurity = true
  );

-- Find tables with RLS enabled
SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relrowsecurity = true;

-- List all RLS policies
SELECT schemaname, tablename, policyname, permissive, roles, cmd, qual, with_check
FROM pg_policies
ORDER BY schemaname, tablename;

-- Find tables with RLS but NO policies (blocks all access!)
SELECT n.nspname, c.relname
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relrowsecurity = true
  AND NOT EXISTS (
    SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid
  );

-- Find roles that bypass RLS
SELECT rolname FROM pg_roles
WHERE rolbypassrls = true OR rolsuper = true;

-- Check if RLS is forced for table owners
SELECT n.nspname, c.relname, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relrowsecurity = true AND c.relforcerowsecurity = false;
```

### Attack Reasoning

```
RLS AUDIT
1. Identify tables with sensitive data lacking RLS.
   → Multi-tenant tables without RLS: CRITICAL
2. Check if RLS is forced for table owners.
   → relforcerowsecurity = false means owner bypasses RLS: HIGH
3. Find roles with BYPASSRLS.
   → Application roles with BYPASSRLS: CRITICAL
4. Review policy definitions.
   → Policies using PERMISSIVE only (no RESTRICTIVE): review needed
   → Policies with overly broad quals: MEDIUM
5. Check for tables with RLS enabled but no policies.
   → This silently blocks all access — may indicate incomplete setup: MEDIUM
6. Check SECURITY DEFINER functions accessing RLS-protected tables.
   → SECURITY DEFINER runs as owner, bypasses RLS if not forced: HIGH
```

### Remediation

```sql
-- Enable RLS on a table
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;

-- Force RLS even for table owner
ALTER TABLE sensitive_data FORCE ROW LEVEL SECURITY;

-- Create a tenant isolation policy
CREATE POLICY tenant_isolation ON sensitive_data
  USING (tenant_id = current_setting('app.current_tenant')::uuid);

-- Remove BYPASSRLS from application roles
ALTER ROLE appuser NOBYPASSRLS;
```

**Reference:** [references/rls.md](references/rls.md)

---

## Security Domain 4: SECURITY DEFINER Functions

### What to Check

`SECURITY DEFINER` functions execute with the privileges of the function **owner**, not the caller. This is PostgreSQL's equivalent of `setuid` — and equally dangerous if misconfigured.

### Detection Queries

```sql
-- Find ALL SECURITY DEFINER functions (outside system schemas)
SELECT n.nspname AS schema,
       p.proname AS function_name,
       pg_get_function_arguments(p.oid) AS arguments,
       r.rolname AS owner,
       r.rolsuper AS owner_is_superuser,
       p.proconfig AS config,
       p.proacl AS acl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_roles r ON r.oid = p.proowner
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');

-- Check if EXECUTE is granted to PUBLIC
SELECT n.nspname, p.proname, p.proacl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (p.proacl IS NULL  -- NULL means PUBLIC has EXECUTE (default!)
       OR array_to_string(p.proacl, ',') LIKE '%=X%');

-- Check search_path configuration of SECURITY DEFINER functions
SELECT n.nspname, p.proname, p.proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND (p.proconfig IS NULL
       OR NOT EXISTS (
         SELECT 1 FROM unnest(p.proconfig) c
         WHERE c LIKE 'search_path=%'
       ));
```

### Attack Reasoning

```
SECURITY DEFINER AUDIT
1. Find all SECURITY DEFINER functions.
2. For each function:
   a. Check function owner.
      → Owner is superuser: CRITICAL risk
   b. Check EXECUTE privileges.
      → PUBLIC can EXECUTE (NULL ACL = default = PUBLIC): HIGH
   c. Inspect search_path.
      → No explicit search_path SET: HIGH (search_path hijacking possible)
      → search_path contains writable schemas: HIGH
   d. Check if objects in function body are schema-qualified.
      → Unqualified references + unsafe search_path = exploitable: CRITICAL
   e. Determine whether pg_temp is in search_path.
      → pg_temp allows session-local object injection: HIGH
3. Combine findings:
   → Superuser owner + PUBLIC EXECUTE + no search_path = CRITICAL
   → Non-superuser owner + restricted EXECUTE + safe search_path = LOW
```

### Remediation

```sql
-- Set safe search_path on SECURITY DEFINER function
ALTER FUNCTION schema_name.function_name()
  SET search_path = pg_catalog, pg_temp;

-- Revoke PUBLIC EXECUTE
REVOKE EXECUTE ON FUNCTION schema_name.function_name() FROM PUBLIC;

-- Grant only to specific roles
GRANT EXECUTE ON FUNCTION schema_name.function_name() TO app_role;

-- Consider switching to SECURITY INVOKER if appropriate
-- (PostgreSQL 15+ for procedures, always available for functions)
ALTER FUNCTION schema_name.function_name() SECURITY INVOKER;
```

**Reference:** [references/security-definer.md](references/security-definer.md)

---

## Security Domain 5: search_path Security

### What to Check

`search_path` controls how PostgreSQL resolves unqualified object names. An attacker who can create objects in a schema that appears early in `search_path` can hijack function calls, operators, and type casts.

### Detection Queries

```sql
-- Check session search_path
SHOW search_path;

-- Check all users' search_path settings
SELECT rolname, rolconfig
FROM pg_roles
WHERE rolconfig IS NOT NULL
  AND array_to_string(rolconfig, ',') LIKE '%search_path%';

-- Check database-level search_path
SELECT datname, datconfig
FROM pg_database
WHERE datconfig IS NOT NULL;

-- Find schemas where PUBLIC has CREATE privilege
SELECT nspname, nspacl
FROM pg_namespace
WHERE nspacl IS NOT NULL
  AND array_to_string(nspacl, ',') LIKE '%=UC%'
  AND nspname NOT IN ('pg_catalog', 'information_schema');

-- Check if public schema allows PUBLIC to create objects
SELECT has_schema_privilege('public', 'public', 'CREATE') AS public_can_create;
```

### Attack Reasoning

```
SEARCH_PATH AUDIT
1. Check if PUBLIC has CREATE on schemas in search_path.
   → If public schema is writable + in search_path: HIGH
2. Check functions for unqualified object references.
   → Combined with writable schema in search_path: exploitable
3. Check SECURITY DEFINER functions specifically.
   → Unsafe search_path + SECURITY DEFINER = privilege escalation: CRITICAL
4. Check for pg_temp in search_path.
   → pg_temp is always implicitly first unless explicitly positioned
5. Verify PostgreSQL version.
   → PG 15+ revokes PUBLIC CREATE on public schema by default
   → PG < 15: public schema is writable by all by default: HIGH
```

### Remediation

```sql
-- Revoke PUBLIC CREATE on public schema (required for PG < 15)
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Set secure search_path at database level
ALTER DATABASE mydb SET search_path = myschema, pg_catalog;

-- Set secure search_path for a role
ALTER ROLE myrole SET search_path = myschema, pg_catalog;

-- Set search_path on functions (especially SECURITY DEFINER)
ALTER FUNCTION myschema.myfunc()
  SET search_path = myschema, pg_catalog, pg_temp;
```

**Reference:** [references/search-path.md](references/search-path.md)

---

## Security Domain 6: Extensions

### What to Check

Extensions can introduce security vulnerabilities ranging from information disclosure to full OS command execution.

### Detection Queries

```sql
-- List all installed extensions
SELECT e.extname, e.extversion, n.nspname AS schema, r.rolname AS owner,
  CASE
    WHEN e.extname IN ('plpython3u', 'plperlu', 'pltclu') THEN 'CRITICAL: Untrusted PL'
    WHEN e.extname IN ('dblink', 'postgres_fdw', 'file_fdw') THEN 'HIGH: External access'
    WHEN e.extname = 'pg_cron' THEN 'MEDIUM: Scheduled execution'
    ELSE 'LOW: Review needed'
  END AS risk_level
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
JOIN pg_roles r ON r.oid = e.extowner;

-- Check available but not installed extensions
SELECT name, default_version, installed_version, trusted
FROM pg_available_extensions
WHERE installed_version IS NULL
ORDER BY name;

-- Find untrusted procedural languages
SELECT lanname, lanpltrusted, r.rolname AS owner
FROM pg_language l
JOIN pg_roles r ON r.oid = l.lanowner
WHERE lanpltrusted = false AND lanispl = true;

-- Check who can create extensions
SELECT rolname FROM pg_roles
WHERE rolsuper = true OR rolcreatedb = true;

-- Find functions created by extensions with SECURITY DEFINER
SELECT n.nspname, p.proname, p.prosecdef, e.extname
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_depend d ON d.objid = p.oid
JOIN pg_extension e ON e.oid = d.refobjid
WHERE p.prosecdef = true AND d.deptype = 'e';
```

### Attack Reasoning

```
EXTENSION AUDIT
1. Check for untrusted procedural languages.
   → plpython3u, plperlu, pltclu allow arbitrary OS code execution: CRITICAL
2. Check for external access extensions.
   → dblink: Can make connections to other databases / SSRF: HIGH
   → postgres_fdw: Can access remote PostgreSQL servers: HIGH
   → file_fdw: Can read server filesystem files: HIGH
3. Check for pg_cron.
   → Can schedule arbitrary SQL execution: MEDIUM
4. Check extension ownership.
   → Extensions owned by superuser have elevated privileges: review needed
5. Review SECURITY DEFINER functions from extensions.
   → Extension functions may have unsafe configurations: HIGH
```

### Remediation

```sql
-- Remove unnecessary dangerous extensions
DROP EXTENSION IF EXISTS plpython3u;
DROP EXTENSION IF EXISTS dblink;

-- Restrict who can use remaining dangerous extensions
REVOKE USAGE ON LANGUAGE plpgsql FROM PUBLIC;

-- Review and restrict extension function permissions
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC;
```

**Reference:** [references/extensions.md](references/extensions.md)

---

## Security Domain 7: SQL Injection

### What to Check

PostgreSQL-specific SQL injection patterns differ from other databases. PostgreSQL supports stacked queries, dollar-quoting, and unique type casting that create additional attack surface.

### Detection Queries

```sql
-- Find PL/pgSQL functions using string concatenation with EXECUTE
-- (potential SQL injection in stored procedures)
SELECT n.nspname, p.proname, l.lanname, pg_get_functiondef(p.oid) AS definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE l.lanname = 'plpgsql'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND pg_get_functiondef(p.oid) LIKE '%EXECUTE%||%';

-- Find functions using EXECUTE with format (safer, but verify)
SELECT n.nspname, p.proname, pg_get_functiondef(p.oid) AS definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE l.lanname = 'plpgsql'
  AND pg_get_functiondef(p.oid) LIKE '%EXECUTE%format(%';
```

### PostgreSQL-Specific Injection Patterns

| Pattern | Example | Risk |
|---------|---------|------|
| Stacked queries | `'; DROP TABLE users; --` | PostgreSQL processes multiple statements |
| Dollar-quoting | `$$malicious$$` | Can bypass single-quote escaping |
| Type casting | `'1'::int` or `CAST('1' AS int)` | Type confusion attacks |
| `COPY ... PROGRAM` | `COPY t FROM PROGRAM 'command'` | OS command execution if reachable |
| `pg_sleep()` | `'; SELECT pg_sleep(10); --` | Time-based blind injection |
| Error extraction | `'::int` | Extracts data via error messages |
| `current_setting()` | Extracts server configuration | Information disclosure |
| System catalogs | `pg_roles`, `pg_shadow` | User enumeration, password hash extraction |

### Safe Coding Patterns

```sql
-- UNSAFE: String concatenation in PL/pgSQL
EXECUTE 'SELECT * FROM users WHERE name = ''' || user_input || '''';

-- SAFE: Parameterized EXECUTE
EXECUTE 'SELECT * FROM users WHERE name = $1' USING user_input;

-- SAFE: format() with %I (identifier) and %L (literal)
EXECUTE format('SELECT * FROM %I WHERE name = %L', table_name, user_input);

-- SAFE: quote_literal() and quote_ident()
EXECUTE 'SELECT * FROM ' || quote_ident(table_name) ||
        ' WHERE name = ' || quote_literal(user_input);
```

**Reference:** [references/sql-injection.md](references/sql-injection.md)

---

## Security Domain 8: Filesystem and OS Access

### What to Check

PostgreSQL provides several mechanisms for filesystem access and OS command execution. These should be tightly controlled.

### Detection Queries

```sql
-- Find roles with pg_execute_server_program
SELECT r.rolname
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.member
WHERE am.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'pg_execute_server_program');

-- Find roles with pg_read_server_files
SELECT r.rolname
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.member
WHERE am.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'pg_read_server_files');

-- Find roles with pg_write_server_files
SELECT r.rolname
FROM pg_auth_members am
JOIN pg_roles r ON r.oid = am.member
WHERE am.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'pg_write_server_files');

-- Check for COPY PROGRAM usage (requires superuser or pg_execute_server_program)
-- This checks if the capability exists, not usage history
SELECT rolname FROM pg_roles
WHERE rolsuper = true
   OR rolname IN (
     SELECT m.rolname FROM pg_auth_members am
     JOIN pg_roles m ON m.oid = am.member
     WHERE am.roleid = (SELECT oid FROM pg_roles WHERE rolname = 'pg_execute_server_program')
   );

-- Check for large object functions (lo_import/lo_export)
-- Superusers and roles with specific grants can use these
SELECT rolname FROM pg_roles WHERE rolsuper = true;

-- Check for functions using pg_read_file
SELECT n.nspname, p.proname, pg_get_functiondef(p.oid) AS def
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE pg_get_functiondef(p.oid) LIKE '%pg_read_file%'
   OR pg_get_functiondef(p.oid) LIKE '%pg_read_binary_file%'
   OR pg_get_functiondef(p.oid) LIKE '%pg_ls_dir%';
```

### Attack Reasoning

```
FILESYSTEM/OS AUDIT
1. Check predefined role grants.
   → pg_execute_server_program: OS command execution: CRITICAL
   → pg_read_server_files: Read any file on server: HIGH
   → pg_write_server_files: Write any file on server: CRITICAL
2. Count superusers (they have all filesystem access).
   → Each superuser = full filesystem + OS access: review
3. Check for SECURITY DEFINER functions wrapping file operations.
   → May expose file access to unprivileged roles: CRITICAL
4. Check installed extensions.
   → file_fdw: read files as tables: HIGH
   → plpython3u: arbitrary OS access: CRITICAL
5. Check for lo_import/lo_export usage.
   → Large objects can be used to read/write files: HIGH
```

### Remediation

```sql
-- Revoke predefined filesystem roles
REVOKE pg_execute_server_program FROM username;
REVOKE pg_read_server_files FROM username;
REVOKE pg_write_server_files FROM username;

-- Ensure application roles don't have superuser
ALTER ROLE appuser NOSUPERUSER;

-- Remove unnecessary extensions providing file access
DROP EXTENSION IF EXISTS file_fdw;
```

**Reference:** [references/filesystem-and-os.md](references/filesystem-and-os.md)

---

## Security Domain 9: PostgreSQL Configuration

### What to Check

`postgresql.conf` contains many security-relevant settings that are often left at insecure defaults.

### Detection Queries

```sql
-- Security-critical settings audit
SELECT name, setting, source, boot_val,
  CASE
    WHEN name = 'ssl' AND setting = 'off' THEN 'HIGH: SSL disabled'
    WHEN name = 'password_encryption' AND setting = 'md5' THEN 'MEDIUM: Using MD5'
    WHEN name = 'log_connections' AND setting = 'off' THEN 'MEDIUM: Not logging connections'
    WHEN name = 'log_disconnections' AND setting = 'off' THEN 'LOW: Not logging disconnections'
    WHEN name = 'log_statement' AND setting = 'none' THEN 'MEDIUM: Not logging statements'
    WHEN name = 'log_min_duration_statement' AND setting::int < 0 THEN 'INFO: No slow query logging'
    ELSE 'OK'
  END AS security_assessment
FROM pg_settings
WHERE name IN (
  'ssl', 'password_encryption', 'log_connections', 'log_disconnections',
  'log_statement', 'log_min_duration_statement', 'listen_addresses',
  'max_connections', 'superuser_reserved_connections',
  'authentication_timeout', 'idle_in_transaction_session_timeout',
  'statement_timeout', 'log_line_prefix', 'shared_preload_libraries'
);

-- Check listen_addresses
SHOW listen_addresses;
-- '*' or '0.0.0.0' means listening on all interfaces

-- Check shared_preload_libraries (can load malicious code)
SHOW shared_preload_libraries;

-- Check logging configuration
SELECT name, setting FROM pg_settings
WHERE name LIKE 'log_%'
ORDER BY name;

-- Check connection limits
SELECT datname, datconnlimit FROM pg_database;
SELECT rolname, rolconnlimit FROM pg_roles WHERE rolconnlimit > 0;
```

### Recommended Security Settings

```sql
-- Enable SSL
ALTER SYSTEM SET ssl = 'on';

-- Use SCRAM-SHA-256
ALTER SYSTEM SET password_encryption = 'scram-sha-256';

-- Enable connection logging
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';

-- Log DDL statements
ALTER SYSTEM SET log_statement = 'ddl';

-- Set timeouts to prevent resource abuse
ALTER SYSTEM SET authentication_timeout = '30s';
ALTER SYSTEM SET idle_in_transaction_session_timeout = '10min';
ALTER SYSTEM SET statement_timeout = '60s';

-- Set informative log line prefix
ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d ';

-- Restrict listen_addresses
ALTER SYSTEM SET listen_addresses = 'localhost';  -- or specific IPs

-- Reload configuration
SELECT pg_reload_conf();
```

---

## Security Domain 10: Replication

### What to Check

Replication configuration can expose WAL data, allow unauthorized data access, or enable privilege escalation.

### Detection Queries

```sql
-- Find roles with REPLICATION privilege
SELECT rolname, rolreplication FROM pg_roles WHERE rolreplication = true;

-- Check replication slots
SELECT slot_name, plugin, slot_type, database, active
FROM pg_replication_slots;

-- Check pg_hba.conf replication entries
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE database = '{replication}';

-- Check publications (logical replication)
SELECT pubname, puballtables, pubinsert, pubupdate, pubdelete, pubtruncate
FROM pg_publication;

-- Check subscriptions
SELECT subname, subconninfo, subpublications FROM pg_subscription;
-- WARNING: subconninfo may contain plaintext passwords
```

### Attack Reasoning

```
REPLICATION AUDIT
1. Check roles with REPLICATION privilege.
   → REPLICATION privilege allows WAL streaming: HIGH
   → Combined with pg_hba access: can extract all database changes
2. Check replication pg_hba.conf entries.
   → Overly permissive CIDR for replication: HIGH
   → Trust authentication for replication: CRITICAL
3. Check for puballtables publications.
   → Publishes ALL tables including sensitive ones: HIGH
4. Check subscription connection strings.
   → Plaintext passwords in subconninfo: HIGH
5. Check replication slot activity.
   → Inactive slots consume WAL: operational risk
```

### Remediation

```sql
-- Remove unnecessary REPLICATION privilege
ALTER ROLE username NOREPLICATION;

-- Create dedicated replication role with minimal privileges
CREATE ROLE replicator REPLICATION LOGIN PASSWORD 'strong_password';

-- Limit publications to specific tables
CREATE PUBLICATION app_pub FOR TABLE public.orders, public.products;
-- Instead of: CREATE PUBLICATION all_pub FOR ALL TABLES;
```

**Reference:** [references/replication.md](references/replication.md)

---

## Security Domain 11: Auditing and Logging

### What to Check

Without proper auditing, security incidents go undetected.

### Detection Queries

```sql
-- Check if pgaudit is installed
SELECT * FROM pg_extension WHERE extname = 'pgaudit';

-- Check current logging settings
SELECT name, setting FROM pg_settings
WHERE name IN (
  'log_connections', 'log_disconnections', 'log_statement',
  'log_min_duration_statement', 'log_min_error_statement',
  'log_checkpoints', 'log_lock_waits', 'log_temp_files',
  'log_autovacuum_min_duration', 'log_line_prefix',
  'log_destination', 'logging_collector',
  'log_directory', 'log_filename', 'log_rotation_age',
  'log_rotation_size', 'log_file_mode'
);

-- Check for failed authentication logging
SHOW log_connections;  -- Must be 'on' to log failed auth attempts
```

### Recommended Audit Configuration

```sql
-- Install pgaudit (if available)
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Configure pgaudit
ALTER SYSTEM SET pgaudit.log = 'ddl, role, misc_set';
ALTER SYSTEM SET pgaudit.log_catalog = 'on';
ALTER SYSTEM SET pgaudit.log_parameter = 'on';
ALTER SYSTEM SET pgaudit.log_statement_once = 'on';

-- Essential logging
ALTER SYSTEM SET log_connections = 'on';
ALTER SYSTEM SET log_disconnections = 'on';
ALTER SYSTEM SET log_statement = 'ddl';
ALTER SYSTEM SET log_line_prefix = '%m [%p] %q%u@%d %a ';
ALTER SYSTEM SET log_checkpoints = 'on';
ALTER SYSTEM SET log_lock_waits = 'on';
ALTER SYSTEM SET log_temp_files = '0';

SELECT pg_reload_conf();
```

---

## Security Domain 12: Data Exposure

### What to Check

Sensitive data may be exposed through views, functions, error messages, or insufficient column-level access control.

### Detection Queries

```sql
-- Find columns likely containing sensitive data
SELECT table_schema, table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
  AND (
    column_name ILIKE '%password%'
    OR column_name ILIKE '%secret%'
    OR column_name ILIKE '%token%'
    OR column_name ILIKE '%ssn%'
    OR column_name ILIKE '%social_security%'
    OR column_name ILIKE '%credit_card%'
    OR column_name ILIKE '%card_number%'
    OR column_name ILIKE '%api_key%'
    OR column_name ILIKE '%private_key%'
    OR column_name ILIKE '%encryption_key%'
  );

-- Check if sensitive columns are accessible to non-admin roles
-- (run as the application role to test)
-- SELECT has_column_privilege('app_role', 'users', 'password_hash', 'SELECT');

-- Check for views that expose more data than needed
SELECT schemaname, viewname, definition
FROM pg_views
WHERE schemaname NOT IN ('pg_catalog', 'information_schema');

-- Check for functions returning sensitive data
SELECT n.nspname, p.proname, pg_get_function_result(p.oid) AS return_type
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND p.prorettype IN (SELECT oid FROM pg_type WHERE typname IN ('record', 'setof'));
```

### Remediation

```sql
-- Use column-level privileges
REVOKE SELECT ON TABLE users FROM app_role;
GRANT SELECT (id, username, email, created_at) ON TABLE users TO app_role;

-- Create views that exclude sensitive columns
CREATE VIEW users_safe AS
  SELECT id, username, email, created_at FROM users;
GRANT SELECT ON users_safe TO app_role;

-- Ensure password hashes use bcrypt/scrypt, not MD5
-- (application-level, but PostgreSQL can store via pgcrypto)
SELECT id, username,
  CASE
    WHEN password_hash LIKE '$2b$%' THEN 'bcrypt (OK)'
    WHEN password_hash LIKE '$2a$%' THEN 'bcrypt (OK)'
    WHEN password_hash LIKE 'md5%' THEN 'MD5 (WEAK!)'
    WHEN password_hash LIKE '$argon2%' THEN 'argon2 (OK)'
    ELSE 'UNKNOWN'
  END AS hash_algorithm
FROM users;
```

---

## Security Domain 13: Backup Security

### What to Check

Backups often contain the same sensitive data as the production database but with fewer protections.

### Detection Queries

```sql
-- Check data_directory (backup source)
SHOW data_directory;

-- Check archive configuration
SHOW archive_mode;
SHOW archive_command;

-- Check WAL level (needed for PITR)
SHOW wal_level;
```

### Key Concerns

- `pg_dump` output files contain plaintext data (no encryption)
- `.pgpass` files may contain plaintext passwords
- `PGPASSWORD` environment variable visible in process listings
- WAL archive files contain all data changes in plaintext
- Backup scripts often hardcode credentials
- Backup storage locations may lack access controls

**Reference:** [references/backup-security.md](references/backup-security.md)

---

## Version-Specific Security Notes

When auditing, always identify the PostgreSQL version first:

```sql
SELECT version();
SHOW server_version;
SHOW server_version_num;
```

Then consult the version-specific security notes:

- [PostgreSQL 14](versions/pg14.md) — `pg_read_all_data`, SCRAM default
- [PostgreSQL 15](versions/pg15.md) — **PUBLIC schema CREATE revoked** (major security improvement)
- [PostgreSQL 16](versions/pg16.md) — **CREATEROLE privilege redesign** (major security improvement)
- [PostgreSQL 17](versions/pg17.md) — Incremental backup, event trigger changes
- [PostgreSQL 18](versions/pg18.md) — OAuth/OAUTHBEARER, UUIDv7, MAINTAIN privilege

---

## Comprehensive Audit Workflow

When asked to audit a PostgreSQL instance, follow this workflow:

```
1. IDENTIFY
   ├── PostgreSQL version
   ├── Installed extensions
   ├── Number of databases
   └── Server environment (bare metal, container, cloud)

2. AUTHENTICATE
   ├── Review pg_hba.conf rules
   ├── Check for trust authentication
   ├── Verify SCRAM-SHA-256 usage
   └── Check password encryption setting

3. AUTHORIZE
   ├── Count and review superusers
   ├── Audit role privileges
   ├── Check predefined role memberships
   ├── Review PUBLIC grants
   └── Audit default privileges

4. INSPECT FUNCTIONS
   ├── Find SECURITY DEFINER functions
   ├── Check search_path settings
   ├── Review EXECUTE grants
   └── Identify SQL injection in PL/pgSQL

5. CHECK RLS
   ├── Find tables needing RLS
   ├── Review existing policies
   ├── Check BYPASSRLS roles
   └── Verify FORCE ROW LEVEL SECURITY

6. REVIEW EXTENSIONS
   ├── Identify untrusted PLs
   ├── Check external access extensions
   ├── Review extension SECURITY DEFINER functions
   └── Check CREATE EXTENSION permissions

7. VERIFY NETWORK
   ├── Check listen_addresses
   ├── Review TLS/SSL config
   ├── Check pg_hba CIDR rules
   └── Verify hostssl usage

8. AUDIT REPLICATION
   ├── Check replication roles
   ├── Review replication pg_hba entries
   ├── Inspect publications/subscriptions
   └── Check for plaintext connection strings

9. CHECK CONFIGURATION
   ├── Review postgresql.conf security settings
   ├── Verify logging configuration
   ├── Check timeout settings
   └── Inspect shared_preload_libraries

10. ASSESS DATA
    ├── Find sensitive columns
    ├── Check column-level privileges
    ├── Review views and functions for data leakage
    └── Verify backup security

11. REPORT
    ├── Classify findings by severity
    ├── Provide evidence for each finding
    ├── Include remediation SQL
    └── Prioritize by exploitability
```

---

## Checklists

For structured assessments, use the provided checklists:

- [Security Audit Checklist](checklists/security-audit.md) — 100+ item comprehensive audit
- [Hardening Guide](checklists/hardening.md) — Step-by-step hardening
- [Penetration Test Methodology](checklists/penetration-test.md) — Offensive testing approach

---

## Attack Playbooks

For understanding how specific attacks work (for verification and defense):

- [Privilege Escalation](attacks/privilege-escalation.md)
- [Role Escalation](attacks/role-escalation.md)
- [RLS Bypass](attacks/rls-bypass.md)
- [search_path Hijacking](attacks/search-path-hijacking.md)
- [COPY PROGRAM Exploitation](attacks/copy-program-exploitation.md)
- [Extension Abuse](attacks/extension-abuse.md)

---

## Reference Documentation

For deep technical details on each security domain:

- [Authentication](references/authentication.md)
- [pg_hba.conf](references/pg-hba.md)
- [Roles and Privileges](references/roles-and-privileges.md)
- [Row-Level Security](references/rls.md)
- [SECURITY DEFINER](references/security-definer.md)
- [search_path](references/search-path.md)
- [Extensions](references/extensions.md)
- [TLS and Network](references/tls-and-network.md)
- [Replication](references/replication.md)
- [SQL Injection](references/sql-injection.md)
- [Filesystem and OS](references/filesystem-and-os.md)
- [Backup Security](references/backup-security.md)
- [postgresql.conf Security](references/postgresql-config.md)
- [pgaudit — Audit Logging](references/pgaudit.md)
- [Observability — Suspicious Activity Detection](references/observability.md)
