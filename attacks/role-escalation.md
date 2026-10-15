# Role Escalation Analysis in PostgreSQL

## Overview

Role escalation occurs when a database user gains unauthorized access to other database roles, either horizontally (accessing another tenant's or user's role) or vertically (gaining administrative role attributes like `CREATEROLE` or `SUPERUSER`).

---

## 1. Vector: `CREATEROLE` Exploitation (PostgreSQL < 16)

### Mechanics
In PostgreSQL versions prior to 16, a role granted `CREATEROLE` had broad authority over existing roles. A `CREATEROLE` user could:
- Alter existing non-superuser roles and modify their passwords.
- Grant themselves membership into any non-superuser role (such as DBA group roles or roles with `BYPASSRLS`).
- In certain historical configurations, manipulate system attributes.

In PostgreSQL 16+, `CREATEROLE` was redesigned: a user with `CREATEROLE` can now only grant roles for which they explicitly possess the `ADMIN OPTION`.

### Detection Query (PostgreSQL < 16)
```sql
SELECT rolname, rolsuper, rolcreaterole
FROM pg_roles
WHERE rolcreaterole = true AND rolsuper = false;
```

### Detection Query (PostgreSQL 16+)
Inspect which roles have `ADMIN OPTION` over other roles:
```sql
SELECT 
    r.rolname AS member,
    g.rolname AS target_role,
    m.admin_option
FROM pg_auth_members m
JOIN pg_roles r ON m.member = r.oid
JOIN pg_roles g ON m.roleid = g.oid
WHERE m.admin_option = true;
```

---

## 2. Vector: Role Inheritance & `SET ROLE` Chains

### Mechanics
When a role is created with the `INHERIT` attribute (the default), it automatically inherits all permissions of roles to which it is added as a member. If permissions are granted carelessly, users may unknowingly inherit broad read, write, or administrative powers.

Furthermore, roles without `NOINHERIT` can execute `SET ROLE <target_role>` to switch security contexts dynamically, bypassing logging checks that monitor only session users.

### Detection Query: Transitive Role Memberships
```sql
WITH RECURSIVE role_tree AS (
    SELECT 
        member AS root_member_oid,
        member AS current_member_oid,
        roleid AS target_role_oid,
        1 AS depth
    FROM pg_auth_members
    UNION ALL
    SELECT 
        rt.root_member_oid,
        m.member,
        m.roleid,
        rt.depth + 1
    FROM pg_auth_members m
    JOIN role_tree rt ON m.member = rt.target_role_oid
)
SELECT 
    r_user.rolname AS member_role,
    r_target.rolname AS inherited_role,
    rt.depth
FROM role_tree rt
JOIN pg_roles r_user ON r_user.oid = rt.root_member_oid
JOIN pg_roles r_target ON r_target.oid = rt.target_role_oid
ORDER BY r_user.rolname, rt.depth;
```

---

## 3. Defensive Mitigations

- **Adopt PostgreSQL 16+**: Upgrade to take advantage of the `CREATEROLE` security redesign.
- **Enforce `NOINHERIT`**: For sensitive or elevated group roles, enforce explicit role adoption with `NOINHERIT` rather than implicit inheritance:
  ```sql
  ALTER ROLE admin_group NOINHERIT;
  ```
- **Audit `ADMIN OPTION`**: Ensure administrative grant rights are restricted only to principal DBAs.
