# Roles and Privileges Security

PostgreSQL uses a unified concept of "roles" that encompasses both users (can log in) and groups (cannot log in, used for privilege inheritance). Mismanagement of roles, particularly granting excessive privileges or failing to understand inheritance, leads to severe privilege escalation vulnerabilities.

## PostgreSQL Role System Internals

Roles are cluster-wide (not tied to a specific database). Permissions granted to those roles are database-specific (tables, schemas) or cluster-wide (login, superuser, createdb).

### Superuser Risks and Detection

The `SUPERUSER` attribute is a bypass for all permission checks in PostgreSQL, except for `pg_hba.conf` login restrictions. A compromised superuser can execute arbitrary OS commands via `COPY ... PROGRAM` or lo_export/import, fully compromising the underlying server.

*Detection:*
```sql
-- Find all superusers
SELECT rolname 
FROM pg_roles 
WHERE rolsuper = true;
```

### CREATEROLE Privilege Escalation

Historically (prior to PG16), `CREATEROLE` was extremely dangerous. A role with `CREATEROLE` could create a new role, grant itself membership in that role, and alter its own attributes. 
*   **PG16 Changes**: PostgreSQL 16 locked this down significantly. Now, a role with `CREATEROLE` can only grant membership in roles it has `ADMIN OPTION` for, preventing trivial self-escalation to superuser or other high-privileged accounts unless explicitly misconfigured.

### CREATEDB Abuse

A user with `CREATEDB` can create a database. By default, they become the owner. Within that database, they are effectively a local superuser (can create extensions if trusted, map local objects, etc.).

### Role Inheritance Chains

By default, roles inherit privileges from roles they are members of (`INHERIT` attribute). This can lead to unexpected privilege accumulation.
*   If `user_a` is granted `group_b`, and `user_a` connects, it automatically has all `group_b` permissions.

### SET ROLE / SET SESSION AUTHORIZATION

*   `SET ROLE`: Allows a user to switch their current session context to another role they are a member of.
*   `SET SESSION AUTHORIZATION`: Generally reserved for superusers; changes the session user entirely.

### Predefined Roles

PostgreSQL provides built-in roles that grant dangerous systemic access without granting full superuser status:
*   `pg_read_all_data`: Bypasses all table-level `SELECT` restrictions (including RLS in some contexts).
*   `pg_write_all_data`: Bypasses all `INSERT`, `UPDATE`, `DELETE` restrictions.
*   `pg_execute_server_program`: Allows executing OS commands (essentially equivalent to OS-level execution).

### PUBLIC Role Grants

`PUBLIC` is a special pseudo-role representing "all users." By default, in versions prior to PG15, `PUBLIC` had `CREATE` and `USAGE` on the `public` schema. This allowed any authenticated user to create objects, leading to local privilege escalation via search_path hijacking. In PG15+, this default was revoked.

## Detection SQL Queries

### 1. Identify Overprivileged Roles

```sql
-- Find roles with dangerous cluster-wide privileges (excluding postgres)
SELECT 
    rolname, 
    rolsuper, 
    rolcreaterole, 
    rolcreatedb, 
    rolcanlogin,
    rolreplication,
    rolbypassrls
FROM 
    pg_roles
WHERE 
    (rolsuper = true OR rolcreaterole = true OR rolcreatedb = true OR rolbypassrls = true)
    AND rolname != 'postgres';
```

### 2. Check for Dangerous Predefined Role Grants

```sql
-- Find who has membership in highly sensitive predefined roles
SELECT 
    r.rolname AS member_role,
    pr.rolname AS predefined_role
FROM 
    pg_auth_members m
JOIN 
    pg_roles r ON m.member = r.oid
JOIN 
    pg_roles pr ON m.roleid = pr.oid
WHERE 
    pr.rolname IN (
        'pg_execute_server_program', 
        'pg_read_server_files', 
        'pg_write_server_files',
        'pg_read_all_settings'
    );
```

### 3. Check PUBLIC Schema Grants (Search Path Hijacking Risk)

```sql
-- Verify if PUBLIC has CREATE on the public schema (Bad pattern pre-PG15)
SELECT 
    nspname, 
    has_schema_privilege('public', nspname, 'CREATE') AS public_can_create
FROM 
    pg_namespace
WHERE 
    nspname = 'public';
```

## Remediation Patterns

### 1. Revoke PUBLIC CREATE (Crucial for < PG15)
```sql
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
-- Ensure the database owner still has access
GRANT ALL ON SCHEMA public TO database_owner;
```

### 2. Implement Least Privilege Roles
Do not grant `SUPERUSER`. Instead, use specific predefined roles or targeted grants.
```sql
-- Bad:
ALTER ROLE app_user SUPERUSER;

-- Good:
GRANT pg_read_all_data TO audit_user;
```

## Verification Checklist

- [ ] Number of `SUPERUSER` roles is strictly limited (ideally just `postgres` or the cloud provider admin).
- [ ] No application users possess `SUPERUSER`, `CREATEROLE`, or `CREATEDB` privileges.
- [ ] `CREATE` privilege on the `public` schema has been revoked from the `PUBLIC` pseudo-role.
- [ ] Role inheritance is understood and explicitly disabled (`NOINHERIT`) for sensitive service accounts.
- [ ] Membership in system roles (`pg_execute_server_program`, `pg_read_server_files`) is strictly audited.
- [ ] Passwords are required for all roles with `LOGIN` (`rolcanlogin = true`).
