# Extension Security Risks & Abuse Analysis

## Overview

PostgreSQL extensions add powerful capabilities, custom data types, procedural languages, and foreign data wrappers. However, loading untrusted or vulnerable extensions introduces significant security risks, ranging from Server-Side Request Forgery (SSRF) and file disclosure to arbitrary host-level code execution.

---

## 1. High-Risk Extension Categories

### A. Untrusted Procedural Languages (`plpython3u`, `plperlu`, `pltclu`)
- **Risk**: Execute code directly in the host environment without memory or capability restrictions.
- **Impact**: Operating system command execution, access to local files and network sockets.
- **Auditing**:
  ```sql
  SELECT lanname, lanpltrusted FROM pg_language WHERE lanpltrusted = false;
  ```

### B. Foreign Data Wrappers (`file_fdw`, `postgres_fdw`)
- **`file_fdw`**: Allows mapping host filesystem files as foreign database tables. Can be exploited to read sensitive server configuration files or secrets if granted to unprivileged roles.
- **`postgres_fdw`**: Manages remote PostgreSQL database connections. User mappings (`pg_user_mappings`) may store plaintext credentials in catalog tables.
- **Auditing**:
  ```sql
  SELECT fdwname, fdwowner::regrole FROM pg_foreign_data_wrapper;
  SELECT * FROM pg_user_mappings;
  ```

### C. Database Links (`dblink`)
- **Risk**: Allows opening outbound TCP connections to arbitrary database servers. Can be leveraged for SSRF (probing internal networks, querying cloud metadata endpoints, or pivoting to other network resources).
- **Auditing**:
  ```sql
  SELECT extname, extversion FROM pg_extension WHERE extname = 'dblink';
  ```

### D. Job Schedulers (`pg_cron`)
- **Risk**: Schedules recurring background SQL tasks. If scheduled jobs run under superuser context, tasks can execute persistent privileged actions.

---

## 2. Auditing Extension Permissions

### Query: List Installed Extensions & Creation Roles
```sql
SELECT 
    e.extname AS extension_name,
    e.extversion AS version,
    n.nspname AS target_schema,
    pg_get_userbyid(e.extowner) AS owner
FROM pg_extension e
JOIN pg_namespace n ON n.oid = e.extnamespace
ORDER BY e.extname;
```

---

## 3. Defensive Mitigations

1. **Restrict Extension Creation**:
   Ensure only trusted superusers have rights to run `CREATE EXTENSION`.
2. **Isolate Extension Objects**:
   Install extensions into dedicated schemas (e.g. `extensions` or `shared_extensions`) rather than `public` or application schemas, preventing namespace clutter and hijacking.
3. **Uninstall Unneeded Extensions**:
   ```sql
   DROP EXTENSION IF EXISTS dblink;
   DROP EXTENSION IF EXISTS plpython3u;
   ```
4. **Regular Vulnerability Scanning**:
   Keep all compiled C extensions updated alongside PostgreSQL minor security releases.
