# search_path Security

## 🔍 How `search_path` Resolution Works in PostgreSQL

In PostgreSQL, a database contains one or more named schemas, which in turn contain tables, functions, and other objects. The `search_path` configuration parameter determines the order in which schemas are searched when an object is referenced by a simple (unqualified) name.

When a query references an unqualified object (e.g., `SELECT * FROM users;`), PostgreSQL scans the schemas listed in `search_path` sequentially. The first schema found containing an object with that name is used. If the object isn't found in any schema in the path, an error is thrown.

### The Default `search_path`
Historically and in many default installations, the `search_path` is defined as:
```sql
SHOW search_path;
-- Typically returns: "$user", public
```
1. `"$user"`: Translates to a schema with the same name as the currently connected role (if it exists).
2. `public`: A default schema created in every database.

### Schema Resolution Order and Implicit Schemas
Even if not explicitly listed, the system schemas `pg_catalog` (containing system tables and built-in functions) and `pg_temp` (temporary objects) influence resolution. 
- `pg_catalog` is generally searched *before* explicitly specified schemas to protect core system functions.
- `pg_temp` is implicitly searched *first* for tables, but not necessarily for functions (unless explicitly added to the path).

---

## 🚨 Security Risks

### 1. The `pg_temp` Schema Risks
Temporary objects (tables, functions) are created in a special `pg_temp` schema unique to the session. If `pg_temp` is implicitly or explicitly searched first, a malicious user can create a temporary object (e.g., a function or table) that overrides an object in a persistent schema. When a highly privileged user runs a query with unqualified names in that same session, the attacker's temporary object might be executed instead.

### 2. The `public` Schema Risks
If the `public` schema has `CREATE` privileges granted to `PUBLIC` (the default prior to PostgreSQL 15), any user can create objects in it. If a superuser or application role uses a `search_path` that includes `public`, an attacker can create malicious tables, views, or functions in `public` with the same name as objects in other schemas to hijack execution.

### 3. `search_path` in Functions vs. Sessions (SECURITY DEFINER)
Functions can be defined with `SECURITY DEFINER`, causing them to execute with the privileges of the user who created them, rather than the user invoking them. If a `SECURITY DEFINER` function relies on the caller's session `search_path` and uses unqualified names, an attacker can manipulate their `search_path` to force the privileged function to execute attacker-controlled objects.

### 4. Qualified vs. Unqualified Object References
- **Unqualified (`SELECT * FROM users`)**: Vulnerable to `search_path` hijacking.
- **Qualified (`SELECT * FROM app_schema.users`)**: Immune to `search_path` hijacking, as the exact schema is specified.

---

## 🔎 Detection Queries

### Check Current Global and Database-Level `search_path`
Identify if databases are using insecure defaults.

```sql
-- Check global default
SELECT name, setting, source 
FROM pg_settings 
WHERE name = 'search_path';

-- Check per-database configurations
SELECT datname, unnest(setconfig) AS config
FROM pg_db_role_setting s
JOIN pg_database d ON s.setdatabase = d.oid
WHERE unnest(setconfig) LIKE 'search_path%';
```

### Check Per-Role `search_path`
Users can have custom search paths that might include vulnerable schemas.

```sql
SELECT r.rolname, unnest(s.setconfig) AS config
FROM pg_db_role_setting s
JOIN pg_roles r ON s.setrole = r.oid
WHERE unnest(s.setconfig) LIKE 'search_path%';
```

### Find Functions with Unsafe `search_path`
Identify `SECURITY DEFINER` functions that do not explicitly force a secure `search_path`.

```sql
SELECT n.nspname AS schema_name,
       p.proname AS function_name,
       pg_get_functiondef(p.oid) AS function_def
FROM pg_proc p
JOIN pg_namespace n ON p.pronamespace = n.oid
WHERE p.prosecdef = true
  AND p.proconfig IS NULL  -- Missing SET search_path configuration
  AND n.nspname NOT IN ('pg_catalog', 'information_schema');
```

---

## 🛠️ Remediation & Exploitation Prevention

### 1. Revoke `CREATE` from `public`
Starting in PostgreSQL 15, `CREATE` on `public` is revoked from `PUBLIC` by default. Apply this to older versions manually:

```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
```

### 2. Lock Down `search_path` in `SECURITY DEFINER` Functions
Always use `SET search_path = ...` when creating `SECURITY DEFINER` functions. Ensure `pg_temp` is handled safely.

```sql
CREATE OR REPLACE FUNCTION admin_task() RETURNS void
    SECURITY DEFINER
    SET search_path = admin_schema, pg_temp
    LANGUAGE plpgsql
AS $$
BEGIN
    -- Secure execution block
    PERFORM cleanup_action();
END;
$$;
```

### 3. Remove `public` from Default `search_path`
Configure the database or role to exclude `public` unless explicitly required.

```sql
-- For the entire database cluster (in postgresql.conf)
-- search_path = '"$user"'

-- For a specific role
ALTER ROLE app_user SET search_path TO app_schema;

-- For a specific database
ALTER DATABASE app_db SET search_path TO app_schema;
```

### 4. Use Qualified Names
Best practice for applications is to always use schema-qualified names (e.g., `schema.table`) in code and queries.

---

## ✅ Verification Checklist

- [ ] `CREATE` privilege on the `public` schema has been revoked from the `PUBLIC` role.
- [ ] No regular users have `CREATE` privileges on schemas shared with highly privileged roles.
- [ ] The default `search_path` in `postgresql.conf` does not include `public` or untrusted schemas.
- [ ] All `SECURITY DEFINER` functions have a hardcoded, safe `search_path` via the `SET` clause.
- [ ] Temporary schemas (`pg_temp`) are explicitly placed at the end of the `search_path` in privileged functions to avoid shadowing core schema objects.
- [ ] Application queries and stored procedures use fully qualified object names (`schema.object`) wherever practical.
