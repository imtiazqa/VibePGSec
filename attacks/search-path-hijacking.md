# search_path Hijacking Analysis

## Overview

In PostgreSQL, the `search_path` determines the schema lookup order when SQL statements reference objects (tables, functions, operators) without schema qualification. If an attacker can create objects in a schema that precedes the intended schema in the search order, they can intercept calls made by other users, including superusers and `SECURITY DEFINER` functions.

---

## 1. Mechanics of search_path Hijacking

### The Resolution Order
When a query executes `SELECT count(*) FROM users`, PostgreSQL searches each schema listed in `search_path` from left to right.
Default `search_path`:
```sql
"$user", public
```

### Attack Scenario
1. A privileged user or `SECURITY DEFINER` function runs with an unrestricted `search_path`.
2. The function calls an unqualified function or table: `SELECT * FROM helper_table;` or `SELECT lower(email);`.
3. An unprivileged user has `CREATE` privileges on the `public` schema or temporary schema (`pg_temp`).
4. The unprivileged user creates a trojan object with the same name in that schema.
5. When the privileged session executes, PostgreSQL resolves the attacker's object first, executing arbitrary malicious code within the privileged context.

---

## 2. Exploiting `pg_temp`

By default, the temporary schema `pg_temp` is searched implicitly before all other schemas, even if not listed in `search_path`.
If a function without a fixed `search_path` is invoked, an attacker who previously created a temporary function or operator with the matching signature can hijack execution.

### Secure search_path Design
PostgreSQL documentation recommends pinning `search_path` with `pg_temp` explicitly placed last:
```sql
SET search_path = pg_catalog, pg_temp;
```
When `pg_temp` is listed last, PostgreSQL does not search temporary objects ahead of `pg_catalog`.

---

## 3. Detection Query: Insecure Functions Lacking Fixed `search_path`

Find all `SECURITY DEFINER` functions that do not specify a safe `search_path`:

```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS is_secdef,
    p.proconfig AS configuration_settings
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef = true
  AND (
    p.proconfig IS NULL 
    OR NOT ARRAY['search_path='] && (
        SELECT ARRAY_AGG(SPLIT_PART(c, '=', 1) || '=') FROM UNNEST(p.proconfig) AS c
    )
  );
```

---

## 4. Defensive Remediations

### 1. Fix `search_path` on Stored Procedures
Attach an explicit `search_path` to all functions:
```sql
ALTER FUNCTION my_sensitive_function() SET search_path = pg_catalog, pg_temp;
```

### 2. Fully Qualify All Object References
In application code and procedural definitions, always qualify objects with their schema name:
```sql
-- VULNERABLE: Unqualified object
SELECT * FROM users;

-- SAFE: Schema-qualified object
SELECT * FROM app_schema.users;
```

### 3. Revoke `CREATE` on Public Schema (PostgreSQL < 15)
Ensure unprivileged users cannot write objects into `public`:
```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```
