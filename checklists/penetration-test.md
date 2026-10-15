# PostgreSQL Penetration Testing Methodology

A structured guide for security professionals and ethical auditors conducting authorized security assessments of PostgreSQL databases.

---

## Phase 1: Reconnaissance & Environment Fingerprinting

### 1.1 Version & Cluster Identification
Identify the PostgreSQL version, compile architecture, and server settings:
```sql
SELECT version();
SELECT current_setting('server_version_num')::integer AS version_num;
SELECT current_setting('data_directory') AS data_dir;
SELECT current_setting('config_file') AS config_file;
SELECT current_setting('hba_file') AS hba_file;
```

### 1.2 Network & SSL Status
Check whether current connection is SSL-encrypted and cipher in use:
```sql
SELECT ssl, version, cipher, bits, client_dn 
FROM pg_stat_ssl 
WHERE pid = pg_backend_pid();
```

---

## Phase 2: User & Role Enumeration

### 2.1 Current Session Context
Identify active user, session user, and current database privileges:
```sql
SELECT current_user, session_user, current_database();
SELECT rolsuper, rolinherit, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication, rolbypassrls
FROM pg_roles
WHERE rolname = current_user;
```

### 2.2 Enumerate All Roles and Attributes
```sql
SELECT 
    rolname,
    rolsuper,
    rolinherit,
    rolcreaterole,
    rolcreatedb,
    rolcanlogin,
    rolreplication,
    rolbypassrls,
    rolconnlimit,
    rolvaliduntil
FROM pg_roles
ORDER BY rolsuper DESC, rolname;
```

### 2.3 Role Membership and Inheritance Graph
```sql
SELECT 
    r.rolname AS member_role,
    g.rolname AS granted_role,
    m.admin_option
FROM pg_auth_members m
JOIN pg_roles r ON m.member = r.oid
JOIN pg_roles g ON m.roleid = g.oid
ORDER BY r.rolname, g.rolname;
```

---

## Phase 3: Privilege & Schema Surface Assessment

### 3.1 Identify `SECURITY DEFINER` Functions
Check for functions running with elevated owner privileges:
```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS is_secdef,
    proconfig AS runtime_settings,
    has_function_privilege(current_user, p.oid, 'EXECUTE') AS can_execute
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

### 3.2 Inspect `search_path` and Schema Permissions
Determine if unprivileged users have write access to schemas in the search path:
```sql
SHOW search_path;

SELECT 
    nspname,
    pg_get_userbyid(nspowner) AS owner,
    has_schema_privilege(current_user, nspname, 'CREATE') AS can_create_objects
FROM pg_namespace
WHERE nspname NOT LIKE 'pg_%' AND nspname != 'information_schema';
```

### 3.3 Check Installed Extensions & Procedural Languages
```sql
-- Extensions
SELECT extname, extversion, nspname AS schema_name
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace;

-- Procedural Languages
SELECT lanname, lanpltrusted, lanacl 
FROM pg_language;
```

---

## Phase 4: Data Boundary & RLS Testing

### 4.1 Enumerate RLS Policies
```sql
SELECT 
    schemaname,
    tablename,
    rowsecurity AS rls_enabled,
    forcerowsecurity AS rls_forced
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND rowsecurity = true;

SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies;
```

---

## Phase 5: Verification & Reporting

Document all findings with:
1. **Title & CWE / CVSS classification**
2. **PostgreSQL Version affected**
3. **Evidence query & output**
4. **Impact analysis (Least Privilege violation, Data Exposure, Remote Execution)**
5. **Concrete SQL remediation command**
