# PostgreSQL Penetration Testing Methodology

A structured guide for authorized security assessments of PostgreSQL databases. Each phase includes specific SQL queries, what to look for, and how to document findings.

> **Important**: Only perform penetration testing on systems you have explicit written authorization to test.

---

## Phase 1: Reconnaissance & Environment Fingerprinting

**Goal**: Understand the target PostgreSQL environment — version, topology, configuration.

### 1.1 Version and Build Information
```sql
SELECT version();
SELECT current_setting('server_version_num')::integer AS version_num;
-- version_num: 160003 = PG 16.3, 150007 = PG 15.7, etc.
```

### 1.2 Server Topology
```sql
-- Data directory, config file locations
SHOW data_directory;
SHOW config_file;
SHOW hba_file;
SHOW ident_file;

-- Server uptime
SELECT now() - pg_postmaster_start_time() AS uptime;

-- Is this a primary or standby?
SELECT pg_is_in_recovery() AS is_standby;
```

### 1.3 Network and TLS
```sql
SHOW listen_addresses;
SHOW port;
SHOW ssl;

-- Current connection TLS status
SELECT ssl, version, cipher, bits, client_dn
FROM pg_stat_ssl
WHERE pid = pg_backend_pid();
```

### 1.4 Installed Extensions
```sql
SELECT extname, extversion, nspname AS schema
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
ORDER BY extname;
```

---

## Phase 2: User and Role Enumeration

**Goal**: Map all roles, their attributes, and privilege chains to identify escalation paths.

### 2.1 Current Session Context
```sql
SELECT current_user, session_user, current_database();

SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb,
       rolcanlogin, rolreplication, rolbypassrls, rolconnlimit
FROM pg_roles WHERE rolname = current_user;
```

### 2.2 All Roles with Dangerous Attributes
```sql
SELECT 
    rolname,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolcanlogin,
    rolreplication,
    rolbypassrls,
    CASE 
        WHEN rolpassword LIKE 'md5%' THEN 'MD5 (WEAK)'
        WHEN rolpassword LIKE 'SCRAM%' THEN 'SCRAM-SHA-256'
        WHEN rolpassword IS NULL THEN 'No password'
        ELSE 'Unknown'
    END AS password_type,
    rolvaliduntil
FROM pg_roles
ORDER BY rolsuper DESC, rolcreaterole DESC, rolname;
```

### 2.3 Role Membership and Inheritance Chains
```sql
SELECT 
    r.rolname AS member,
    g.rolname AS member_of,
    m.admin_option AS has_admin_option
FROM pg_auth_members m
JOIN pg_roles r ON m.member = r.oid
JOIN pg_roles g ON m.roleid = g.oid
ORDER BY r.rolname, g.rolname;
```

### 2.4 Public Schema Privileges
```sql
SELECT has_schema_privilege('public', 'public', 'CREATE') AS public_can_create;
-- true = pg_hba.conf or PG < 15 default is insecure
```

---

## Phase 3: Vulnerability Assessment

**Goal**: Identify and classify specific security weaknesses.

### 3.1 Authentication Weaknesses
```sql
-- Trust authentication (CRITICAL)
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules WHERE auth_method = 'trust';

-- Plaintext password auth (HIGH)
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules WHERE auth_method = 'password';

-- MD5 instead of SCRAM (MEDIUM)
SELECT line_number, auth_method FROM pg_hba_file_rules WHERE auth_method = 'md5';
```

### 3.2 SECURITY DEFINER Functions (Privilege Escalation Risk)
```sql
SELECT n.nspname AS schema, p.proname AS function,
       pg_get_userbyid(p.proowner) AS owner,
       has_function_privilege(current_user, p.oid, 'EXECUTE') AS can_execute,
       p.proconfig AS config_overrides
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_roles r ON r.oid = p.proowner
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY r.rolsuper DESC, can_execute DESC;
```

### 3.3 RLS Coverage Gaps
```sql
-- Tables that SHOULD have RLS but don't
SELECT schemaname, tablename, rowsecurity, forcerowsecurity
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND rowsecurity = false
ORDER BY schemaname, tablename;

-- Policies without WITH CHECK (data injection risk)
SELECT schemaname, tablename, policyname, cmd, qual, with_check
FROM pg_policies
WHERE cmd IN ('ALL', 'INSERT', 'UPDATE')
  AND with_check IS NULL;
```

### 3.4 Dangerous Extensions and Languages
```sql
-- Untrusted procedural languages (OS code execution)
SELECT lanname, lanpltrusted FROM pg_language WHERE lanpltrusted = false;

-- High-risk extensions
SELECT extname FROM pg_extension
WHERE extname IN ('dblink', 'postgres_fdw', 'file_fdw', 'plpython3u', 'plperlu', 'pg_cron');
```

### 3.5 search_path Analysis
```sql
-- Functions with unsafe search_path
SELECT n.nspname, p.proname, p.proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND (p.proconfig IS NULL
    OR NOT array_to_string(p.proconfig, ',') LIKE '%search_path%')
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

### 3.6 Overprivileged Roles
```sql
-- Roles with access to OS execution
SELECT r.rolname, g.rolname AS dangerous_membership
FROM pg_auth_members m
JOIN pg_roles r ON m.member = r.oid
JOIN pg_roles g ON m.roleid = g.oid
WHERE g.rolname IN (
    'pg_execute_server_program',
    'pg_read_server_files',
    'pg_write_server_files'
);

-- COPY PROGRAM access check
SELECT has_function_privilege(current_user, 'pg_catalog.pg_execute_server_program()', 'EXECUTE') 
    AS can_execute_program;
```

---

## Phase 4: Exploitation Verification (Controlled Testing)

**Goal**: Confirm whether identified vulnerabilities are actually exploitable in the target environment. Do not cause damage or data modification.

### 4.1 Verify search_path Hijacking Potential
```sql
-- Step 1: Check if current user can create objects in public schema
SELECT has_schema_privilege(current_user, 'public', 'CREATE') AS can_create_in_public;

-- Step 2: If yes, check for SECURITY DEFINER functions with public in their search_path
SELECT n.nspname, p.proname, p.proconfig
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND (array_to_string(COALESCE(p.proconfig, '{}'), ',') LIKE '%public%'
    OR p.proconfig IS NULL);
-- Finding: If can_create = true AND function has public in search_path → hijack possible
```

### 4.2 Verify RLS Bypass (Table Owner Test)
```sql
-- Check if current user owns any RLS-protected table
SELECT c.relname AS table_name, c.relrowsecurity AS rls_enabled
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE pg_get_userbyid(c.relowner) = current_user
  AND c.relrowsecurity = true
  AND c.forcerowsecurity = false;
-- Finding: If results exist, the user bypasses their own RLS policies
```

### 4.3 Verify COPY PROGRAM Access
```sql
-- Only attempt if explicitly authorized for this test
-- Create a safe test table
CREATE TEMP TABLE test_rce (output text);
-- Attempt (safely — just reads system date):
COPY test_rce FROM PROGRAM 'date';
SELECT * FROM test_rce;
DROP TABLE test_rce;
-- Finding: If COPY executes → RCE is possible at OS level
```

---

## Phase 5: Post-Assessment Reporting

**Goal**: Document findings with full evidence, severity, and remediation SQL.

### 5.1 Finding Report Template

```
FINDING: [SHORT TITLE]
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity:     [CRITICAL / HIGH / MEDIUM / LOW / INFO]
CVSS Score:   [e.g., 8.8]
Category:     [Authentication / Privilege Escalation / Data Exposure / ...]
Component:    [pg_hba.conf / Role: xyz / Function: abc() / Extension: dblink]

Description:
  [Clear explanation of the issue, what it means, and why it matters]

Evidence:
  SQL Query:
    [Exact query used to detect the finding]

  Result:
    [Actual output from the query — redact sensitive data if needed]

Impact:
  [Specific business/security impact: e.g., "Any authenticated user can read
   all rows in the payments table regardless of tenant context"]

Affected Versions:
  [e.g., All PostgreSQL versions / PG < 16 only]

Remediation:
  [Step-by-step fix with exact SQL or config changes]

  SQL:
    [Exact remediation commands]

  Verification:
    [SQL query to confirm the fix is applied]

References:
  - VibePGSec: references/[relevant-file].md
  - PostgreSQL Docs: https://www.postgresql.org/docs/current/...
```

### 5.2 Severity Classification Guide

| Severity | Criteria | Example |
|----------|----------|---------|
| CRITICAL | Immediate, unauthenticated or low-privilege exploitation leads to full cluster compromise or mass data breach | `trust` auth on any network type; `plpython3u` SECURITY DEFINER function executable by PUBLIC |
| HIGH | Authenticated user can escalate privileges or access unauthorized data with limited effort | SECURITY DEFINER function with no `search_path` fix; table without RLS but with cross-tenant data |
| MEDIUM | Meaningful security control weakened; exploitation requires specific conditions | MD5 auth instead of SCRAM; SSL not enforced; overly broad CIDR in `pg_hba.conf` |
| LOW | Defense-in-depth opportunity; not directly exploitable | Missing `statement_timeout`; `log_connections` disabled; unused extensions installed |
| INFO | Observation with no current exploitability; worth noting for baseline | Non-default `search_path`; custom predefined role grants that appear intentional |

### 5.3 Executive Summary Template

```
PostgreSQL Security Assessment — Executive Summary
═══════════════════════════════════════════════════
Target:       [hostname / cluster name]
Version:      [e.g., PostgreSQL 16.3]
Date:         [Assessment date]
Assessed By:  [Name / Team]

Finding Summary:
  CRITICAL: [n]
  HIGH:     [n]
  MEDIUM:   [n]
  LOW:      [n]
  INFO:     [n]
  TOTAL:    [n]

Critical Findings:
  1. [One-line description] → Remediation: [One-line fix]
  2. ...

High Findings:
  1. [One-line description] → Remediation: [One-line fix]
  ...

Recommended Immediate Actions (in priority order):
  1. [Highest priority action]
  2. ...

Overall Risk Rating: [CRITICAL / HIGH / MEDIUM / LOW]
```
