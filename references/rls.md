# Row-Level Security (RLS)

Row-Level Security (RLS) enables database administrators to define policies that restrict which rows in a table can be returned by `SELECT` queries or modified by `INSERT`, `UPDATE`, and `DELETE` commands. When auditing a database relying on RLS for tenant isolation (multi-tenancy) or access control, understanding bypass mechanisms is critical.

## RLS Internals

RLS policies are boolean expressions appended to the internal query tree by the PostgreSQL optimizer. If RLS is enabled on a table, all access to that table must pass the policy checks.

### Policy Types: PERMISSIVE vs RESTRICTIVE

*   **PERMISSIVE**: Multiple permissive policies on a table are combined using `OR`. If *any* permissive policy evaluates to true, the row is accessible.
*   **RESTRICTIVE**: Multiple restrictive policies are combined using `AND`. *All* restrictive policies must evaluate to true for the row to be accessible.
*   *Security Implication*: A poorly written permissive policy can inadvertently expose all records, bypassing intended restrictive policies.

### Bypass Mechanisms (Critical Risks)

RLS is not a bulletproof shield. Several conditions bypass RLS silently:

1.  **Table Owner Bypass**: By default, the owner of a table is NOT subject to RLS policies on that table. If the application connects as the table owner, RLS is completely ignored.
    *   *Remediation*: `ALTER TABLE table_name FORCE ROW LEVEL SECURITY;` forces the owner to abide by RLS.
2.  **BYPASSRLS Privilege**: Roles granted the `BYPASSRLS` attribute ignore all RLS policies across the cluster. Used for logical backup utilities (like `pg_dump`).
3.  **Superuser Bypass**: `SUPERUSER` roles always bypass RLS.

### Leaky Views and Functions

If a user lacks direct access to a table but has access to a `SECURITY DEFINER` function or a view created by a higher-privileged user that queries the RLS-protected table, they might bypass RLS.
Furthermore, malicious user-defined functions in `WHERE` clauses can extract data via side channels (e.g., throwing an error with the row data) *before* the RLS policy is fully evaluated, known as a "leaky" function.

### Performance Considerations

Complex RLS policies (e.g., containing subqueries or `EXISTS` clauses against large tables) run on *every single row* evaluated. This can lead to catastrophic performance degradation and potential DoS vectors if an attacker can trigger full table scans.

## Detection SQL Queries

### 1. Identify Tables with RLS Disabled

```sql
-- Find tables that lack RLS enforcement
SELECT 
    schemaname, 
    tablename 
FROM 
    pg_tables 
WHERE 
    rowsecurity = false 
    AND schemaname NOT IN ('pg_catalog', 'information_schema');
```

### 2. Identify Missing FORCE ROW LEVEL SECURITY

This checks if the owner is exempt from RLS, a common misconfiguration when apps connect as the table owner.

```sql
-- Find tables where RLS is enabled, but FORCE is off
SELECT 
    relname, 
    relrowsecurity, 
    relforcerowsecurity 
FROM 
    pg_class 
WHERE 
    relrowsecurity = true 
    AND relforcerowsecurity = false;
```

### 3. Check for BYPASSRLS Roles

```sql
-- Find roles that can bypass RLS globally
SELECT 
    rolname 
FROM 
    pg_roles 
WHERE 
    rolbypassrls = true;
```

### 4. Audit Existing Policies

```sql
-- Review all defined RLS policies
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM 
    pg_policies
WHERE 
    schemaname NOT IN ('pg_catalog', 'information_schema');
```

## Remediation SQL

### 1. Enforce RLS and FORCE RLS

```sql
-- Enable RLS
ALTER TABLE sensitive_data ENABLE ROW LEVEL SECURITY;

-- Ensure table owner is also restricted
ALTER TABLE sensitive_data FORCE ROW LEVEL SECURITY;
```

### 2. Secure Policy Example (Multi-Tenant)

```sql
-- Policy enforcing access based on a session variable
CREATE POLICY tenant_isolation_policy ON sensitive_data
    AS RESTRICTIVE
    FOR ALL
    TO application_role
    USING (tenant_id = current_setting('app.current_tenant')::UUID);
```

## Testing Methodology

1.  Connect as the target application role.
2.  Set necessary session variables (e.g., `SET app.current_tenant = '...';`).
3.  Execute `SELECT * FROM target_table;`. Ensure only the expected tenant's rows are returned.
4.  Attempt to `UPDATE` a row belonging to a different tenant. It should fail or affect 0 rows silently.
5.  Check `EXPLAIN ANALYZE SELECT * FROM target_table` to ensure the RLS policy is being injected into the query plan.

## Verification Checklist

- [ ] `ENABLE ROW LEVEL SECURITY` is set on all tables containing tenant or sensitive data.
- [ ] `FORCE ROW LEVEL SECURITY` is set if the application authenticates using the table owner role.
- [ ] `BYPASSRLS` is not granted to any application or user roles.
- [ ] Policies use `RESTRICTIVE` where appropriate to prevent accidental overrides by `PERMISSIVE` policies.
- [ ] RLS logic relies on secure, tamper-proof session variables (`current_setting`) or current user identity (`current_user`).
- [ ] Custom functions used in RLS policies are marked `LEAKPROOF` only if truly safe.
