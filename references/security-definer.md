# SECURITY DEFINER Functions

In PostgreSQL, functions execute with the privileges of the user calling them (`SECURITY INVOKER` - the default) or with the privileges of the user who owns the function (`SECURITY DEFINER`). Misusing `SECURITY DEFINER` is a primary vector for local privilege escalation in PostgreSQL.

## SECURITY DEFINER vs SECURITY INVOKER

*   **SECURITY INVOKER** (Default): The function executes contextually as the calling user. If the caller lacks `SELECT` on a table queried in the function, the function fails.
*   **SECURITY DEFINER**: The function executes contextually as the *owner* of the function. If a low-privileged user calls a `SECURITY DEFINER` function owned by a `SUPERUSER`, the function code runs with `SUPERUSER` privileges.

## The Privilege Escalation Vector

If a `SECURITY DEFINER` function is poorly written and vulnerable to SQL injection, or if it doesn't strictly control its environment, an attacker can leverage it to execute arbitrary commands as the function owner.

### 1. The search_path Risk (Temp Schema Injection)

PostgreSQL resolves unqualified object names (e.g., `SELECT * FROM my_table`) using the `search_path`. By default, the `search_path` includes the temporary schema (`pg_temp`).
If a `SECURITY DEFINER` function does not explicitly secure its `search_path`, an attacker can:
1.  Create a temporary table or a malicious temporary function (e.g., a fake `upper()` function).
2.  Call the `SECURITY DEFINER` function.
3.  When the function executes an unqualified query or function call, it resolves to the attacker's malicious temporary object *executing as the owner*.

### 2. EXECUTE Privilege and PUBLIC

By default, when a function is created, PostgreSQL grants `EXECUTE` privilege on that function to `PUBLIC` (everyone). Therefore, unless explicitly revoked, *any* user can execute a newly created `SECURITY DEFINER` function.

## Detection Queries

### 1. Find all SECURITY DEFINER functions

Identify high-value targets for an attacker. Focus on functions owned by superusers or highly privileged roles.

```sql
-- Find all SECURITY DEFINER functions, their owner, and arguments
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner_name,
    pg_get_function_arguments(p.oid) AS args,
    p.prosecdef AS is_secdef
FROM 
    pg_proc p
JOIN 
    pg_namespace n ON p.pronamespace = n.oid
WHERE 
    p.prosecdef = true
    AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

### 2. Check for Insecure search_path Configuration

This query checks if the `SECURITY DEFINER` functions have a securely configured `search_path` explicitly attached to the function definition.

```sql
-- Find SECURITY DEFINER functions missing a secured search_path
SELECT 
    n.nspname AS schema,
    p.proname AS function_name,
    p.proconfig AS configuration
FROM 
    pg_proc p
JOIN 
    pg_namespace n ON p.pronamespace = n.oid
WHERE 
    p.prosecdef = true 
    AND (p.proconfig IS NULL OR NOT 'search_path' = ANY(ARRAY(SELECT split_part(unnest(p.proconfig), '=', 1))))
    AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

### 3. Check for PUBLIC EXECUTE Grants

Check if anyone can run these functions.

```sql
-- Find SECURITY DEFINER functions executable by PUBLIC
SELECT 
    n.nspname AS schema,
    p.proname AS function,
    pg_get_userbyid(p.proowner) AS owner
FROM 
    pg_proc p
JOIN 
    pg_namespace n ON p.pronamespace = n.oid
WHERE 
    p.prosecdef = true
    AND has_function_privilege('public', p.oid, 'EXECUTE')
    AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

## Step-by-Step Audit Walkthrough

1.  **Enumerate**: Run Query 1 to list all `SECURITY DEFINER` functions. Filter for those owned by `postgres` or other powerful roles.
2.  **Review Source**: Use `\sf schema.function_name` in psql to read the source code. Look for dynamic SQL (`EXECUTE` in plpgsql) that concatenates user input (SQL Injection).
3.  **Check Path**: Verify the `search_path` is hardcoded. If not, the function is vulnerable to search path hijacking.
4.  **Check Grants**: Ensure `EXECUTE` is granted *only* to the specific roles that need it, not `PUBLIC`.

## Remediation

To secure a `SECURITY DEFINER` function, you must do two things:

1.  **Set `search_path` safely**: Empty it, or set it to `pg_catalog` and the target schema.
2.  **Revoke default public execution**: Restrict who can call it.

```sql
-- 1. Secure the search_path (Drops temp schema and public from path)
ALTER FUNCTION sensitive_admin_task(text) 
SET search_path = pg_catalog, admin_schema;

-- 2. Revoke default PUBLIC execution
REVOKE EXECUTE ON FUNCTION sensitive_admin_task(text) FROM PUBLIC;

-- 3. Grant to specific role
GRANT EXECUTE ON FUNCTION sensitive_admin_task(text) TO trusted_app_role;
```

## Verification Checklist

- [ ] All `SECURITY DEFINER` functions have been audited for necessity. Can they be `SECURITY INVOKER`?
- [ ] Every `SECURITY DEFINER` function has an explicit `SET search_path` configuration attached to it.
- [ ] `EXECUTE` privilege on `SECURITY DEFINER` functions has been `REVOKED FROM PUBLIC`.
- [ ] `EXECUTE` privilege is granted strictly on a least-privilege basis.
- [ ] Function source code does not contain vulnerable dynamic SQL (concatenation) using unvalidated input.
