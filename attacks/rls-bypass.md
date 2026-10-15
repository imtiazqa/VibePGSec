# Row-Level Security (RLS) Bypass Analysis

## Overview

Row-Level Security (RLS) restricts which rows can be returned or modified by specific users based on SQL policy predicates. When improperly designed or deployed, RLS policies can be bypassed, resulting in cross-tenant data leakage or unauthorized data manipulation.

---

## 1. Vector: Table Owner Bypass

### Mechanics
By default, the owner of a table is exempt from all Row-Level Security policies on that table. If an application database connection authenticates as the role that owns the database schema/tables, RLS is completely bypassed regardless of whether policies are defined.

### Detection Query
```sql
SELECT 
    schemaname,
    tablename,
    tableowner,
    rowsecurity AS rls_enabled,
    forcerowsecurity AS rls_forced
FROM pg_tables
WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
  AND rowsecurity = true
  AND forcerowsecurity = false;
```

### Prevention
1. Use separate schema owner roles (which do not handle application queries) and application roles (which possess only DML grants).
2. Explicitly force RLS on all sensitive tables so table owners are also subject to policies:
   ```sql
   ALTER TABLE app_schema.tenants FORCE ROW LEVEL SECURITY;
   ```

---

## 2. Vector: `BYPASSRLS` Attribute Abuse

### Mechanics
PostgreSQL allows assigning the `BYPASSRLS` attribute to a role (`ALTER ROLE user_name BYPASSRLS`). Roles with this attribute ignore all RLS policies across the entire database cluster.

### Detection Query
```sql
SELECT rolname, rolsuper, rolbypassrls
FROM pg_roles
WHERE rolbypassrls = true;
```

### Prevention
- Never grant `BYPASSRLS` to application connection accounts.
- Restrict `BYPASSRLS` solely to offline backup or migration tools.

---

## 3. Vector: Missing `WITH CHECK` on Modification Policies

### Mechanics
If an RLS policy defines a `USING` expression for `INSERT` or `UPDATE` but omits the `WITH CHECK` expression:
- The user can insert rows belonging to other tenants.
- Although the user may not immediately see those inserted rows with `SELECT`, data integrity is compromised and data poisoning occurs.

### Detection Query
```sql
SELECT 
    schemaname,
    tablename,
    policyname,
    cmd,
    qual AS using_expression,
    with_check AS with_check_expression
FROM pg_policies
WHERE cmd IN ('ALL', 'INSERT', 'UPDATE')
  AND with_check IS NULL;
```

### Prevention
Always define `WITH CHECK` clauses matching or refining the `USING` clause:
```sql
CREATE POLICY tenant_update ON documents
    FOR UPDATE
    USING (tenant_id = current_setting('app.tenant_id')::uuid)
    WITH CHECK (tenant_id = current_setting('app.tenant_id')::uuid);
```

---

## 4. Vector: Leaky Functions and Side Channels

### Mechanics
PostgreSQL query planners can reorder operators and functions. If an unprivileged user executes a query containing a user-defined function in the `WHERE` clause, the optimizer might evaluate that function before the RLS policy filter is applied, leaking row values through function execution or side channels (e.g. error messages).

### Prevention
- Mark functions evaluated inside RLS policies as `LEAKPROOF`.
- Only superusers can mark a function as `LEAKPROOF`, indicating it has been audited not to leak inputs via errors or timing.
