# Filesystem and Operating System Access Security

## Overview

PostgreSQL provides several native mechanisms that allow interactions with the underlying host filesystem and operating system execution environment. If improperly guarded, these features can result in arbitrary host file disclosure, file modification, or remote operating system command execution (RCE).

This guide covers:
- `COPY ... TO/FROM [PROGRAM | 'filename']`
- Server-side administrative file functions (`pg_read_file`, `pg_read_binary_file`, `pg_write_file`, `pg_ls_dir`)
- Large Object functionality (`lo_import`, `lo_export`)
- Predefined system roles controlling filesystem & program execution
- Auditing and defensive hardening

---

## 1. `COPY ... PROGRAM` and File Operations

### Mechanics
- **`COPY tablename FROM PROGRAM 'command'`**: Executes an operating system command through the database server process shell (`/bin/sh` or `cmd.exe`) and pipes stdout into a table.
- **`COPY tablename TO PROGRAM 'command'`**: Pipes table rows as stdin into an OS command.
- **`COPY tablename FROM '/path/to/file'`**: Reads directly from server-side files.
- **`COPY tablename TO '/path/to/file'`**: Writes directly to server-side files as the OS user running the database cluster (typically `postgres`).

### Privilege Requirements
Direct execution of `COPY ... [PROGRAM | 'filename']` requires:
- Superuser privileges (`SUPERUSER`), OR
- Membership in the predefined role `pg_execute_server_program` (for `PROGRAM`), OR
- Membership in `pg_read_server_files` / `pg_write_server_files` (for file paths).

### Detection Query: Roles with Program/File Execution Capabilities
```sql
SELECT 
    r.rolname,
    r.rolsuper AS is_superuser,
    ARRAY_AGG(g.rolname) FILTER (WHERE g.rolname IS NOT NULL) AS granted_predefined_roles
FROM pg_roles r
LEFT JOIN pg_auth_members m ON r.oid = m.member
LEFT JOIN pg_roles g ON m.roleid = g.oid AND g.rolname IN (
    'pg_execute_server_program',
    'pg_read_server_files',
    'pg_write_server_files'
)
WHERE r.rolsuper = true OR g.rolname IS NOT NULL
GROUP BY r.rolname, r.rolsuper
ORDER BY r.rolsuper DESC, r.rolname;
```

---

## 2. Server-Side Administrative File Functions

PostgreSQL provides built-in functions in `pg_catalog`:
- `pg_read_file(filename, offset, length)`
- `pg_read_binary_file(filename, offset, length)`
- `pg_ls_dir(dirname)`
- `pg_stat_file(filename)`

By default, access to these functions is restricted to superusers and members of `pg_read_server_files`. However, custom wrapper functions (especially with `SECURITY DEFINER`) or manual `GRANT EXECUTE` can inadvertently expose them.

### Detection Query: Functions Exposing File System Operations
```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS is_security_definer,
    p.proacl AS acl
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND pg_get_functiondef(p.oid) ~* '(pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export)'
ORDER BY n.nspname, p.proname;
```

---

## 3. Large Object Security (`lo_import` / `lo_export`)

PostgreSQL Large Objects allow storing large data up to 4TB. Functions like `lo_import()` read a server filesystem file into a Large Object OID, while `lo_export()` writes a Large Object out to the filesystem.

### Security Concerns
- Reading sensitive configuration files (e.g., `postgresql.conf`, SSL private keys, `.pgpass`) into database tables.
- Overwriting server files or dropping unauthorized scripts into web root / cron directories if file permissions permit.

---

## 4. Remediation & Hardening Guidelines

### 1. Enforce Role Separation & Revoke Predefined Privileges
Never grant `pg_execute_server_program`, `pg_read_server_files`, or `pg_write_server_files` to non-administrative application users:

```sql
REVOKE pg_execute_server_program FROM app_user;
REVOKE pg_read_server_files FROM app_user;
REVOKE pg_write_server_files FROM app_user;
```

### 2. Lock Down `PUBLIC` Function Execution
Verify that `EXECUTE` on administrative file functions has not been granted to `PUBLIC`:

```sql
REVOKE EXECUTE ON FUNCTION pg_read_file(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_file(text, bigint, bigint) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_read_binary_file(text) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION pg_ls_dir(text) FROM PUBLIC;
```

### 3. Restrict Operating System Permissions
Run the PostgreSQL service daemon under a dedicated, unprivileged operating system user (e.g. `postgres`) with minimal read/write permissions outside the data cluster directory (`PGDATA`). Ensure sensitive host directories (e.g., `/etc/shadow`, `/root`, web document roots) are not readable or writable by the `postgres` system account.

---

## Verification Checklist

- [ ] Only trusted DBAs have `SUPERUSER` or membership in `pg_execute_server_program`.
- [ ] No application or tenant role holds `pg_read_server_files` or `pg_write_server_files`.
- [ ] No `SECURITY DEFINER` function exposes `COPY ... PROGRAM` or `pg_read_file` to unprivileged roles or `PUBLIC`.
- [ ] Database service account runs with least OS-level filesystem privileges.
