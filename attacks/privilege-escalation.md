# Privilege Escalation Analysis in PostgreSQL

## Overview

Privilege escalation in PostgreSQL occurs when a user with low privileges gains access to higher administrative privileges (such as `SUPERUSER`, `BYPASSRLS`, or system command execution). This document analyzes the primary vectors for privilege escalation in PostgreSQL clusters, indicators of compromise, and defensive mitigations.

---

## 1. Vector: Insecure `SECURITY DEFINER` Functions

### Mechanics
A `SECURITY DEFINER` function executes with the privileges of the user who owns the function, rather than the caller. If a function is owned by a `SUPERUSER` (e.g. `postgres`), any caller who can execute that function effectively runs its statements as superuser.

Vulnerabilities arise when:
1. The function does not explicitly fix `search_path` (`SET search_path = pg_catalog, pg_temp`).
2. The function references unqualified objects (e.g. `SELECT * FROM config`).
3. The function uses dynamic SQL (`EXECUTE`) concatenating user-controlled input.
4. Default `EXECUTE` privilege is granted to `PUBLIC`.

### Detection Query
```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS is_secdef,
    p.proconfig AS runtime_settings,
    has_function_privilege('public', p.oid, 'EXECUTE') AS public_can_execute
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_roles r ON r.oid = p.proowner
WHERE p.prosecdef = true
  AND r.rolsuper = true
  AND (p.proconfig IS NULL OR NOT ('search_path=' = ANY(p.proconfig)));
```

### Prevention
- Always attach `SET search_path = pg_catalog, pg_temp` to `SECURITY DEFINER` functions.
- Revoke `EXECUTE` on the function from `PUBLIC`:
  ```sql
  REVOKE EXECUTE ON FUNCTION function_name(...) FROM PUBLIC;
  ```
- Qualify all schema object references explicitly.

---

## 2. Vector: Predefined Role Abuse

### Mechanics
PostgreSQL includes predefined roles that grant elevated capabilities without the full `SUPERUSER` attribute:
- `pg_execute_server_program`: Allows executing OS commands via `COPY ... PROGRAM`.
- `pg_read_server_files` / `pg_write_server_files`: Allows reading/writing files on the server host.
- `pg_read_all_data` / `pg_write_all_data`: Allows reading/writing all tables in all databases.

If an untrusted role is granted membership into one of these predefined roles, it may read sensitive files (such as database configuration or cryptographic keys) or execute host-level processes.

### Detection Query
```sql
SELECT 
    r.rolname AS role_name,
    m.rolname AS elevated_role
FROM pg_auth_members am
JOIN pg_roles r ON am.member = r.oid
JOIN pg_roles m ON am.roleid = m.oid
WHERE m.rolname LIKE 'pg_%';
```

### Prevention
- Reserve predefined system roles strictly for automated backup or monitoring daemons.
- Audit role memberships routinely.

---

## 3. Vector: Untrusted Procedural Languages

### Mechanics
Untrusted procedural languages (such as `plpython3u`, `plperlu`, `pltclu`) do not enforce sandboxing. Code written in these languages runs with the full OS privileges of the PostgreSQL daemon process.

Only superusers can create functions in untrusted languages, but if a superuser creates a `SECURITY DEFINER` function wrapping an untrusted language routine, unprivileged callers may achieve OS-level command execution.

### Detection Query
```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    l.lanname AS language,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS is_secdef
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE l.lanpltrusted = false;
```

### Prevention
- Remove untrusted languages from production databases unless strictly required.
- Do not mark functions written in untrusted languages as `SECURITY DEFINER`.
