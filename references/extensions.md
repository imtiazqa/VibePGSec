# Extension Security

## 🧩 Extension Security Model

PostgreSQL extensions allow administrators to extend database functionality. By default, only superusers can install most extensions using the `CREATE EXTENSION` command. However, extensions bring third-party code and powerful functions into the database memory space, significantly expanding the attack surface.

### Trusted vs. Untrusted Extensions
- **Trusted Extensions:** Written safely enough that non-superusers can be trusted to run them. They generally operate within normal SQL constraints.
- **Untrusted Extensions:** Execute arbitrary code, access the filesystem, or interact with the operating system network. Non-superusers should **never** be allowed to execute functions from untrusted extensions or install them.

### Untrusted Procedural Languages
Languages suffixed with `u` (untrusted) are dangerous because they are not sandboxed. 
- `plpython3u`, `plperlu`, `pltclu`, `plsh`
Functions written in these languages execute with the privileges of the OS user running the PostgreSQL service (usually `postgres`), allowing full OS command execution, arbitrary file reads/writes, and network lateral movement.

### CREATE EXTENSION Privileges
Starting from PostgreSQL 13, the concept of "trusted extensions" was introduced. Superusers can mark an extension as trusted in its control file (`superuser = false`, `trusted = true`), allowing roles with `CREATE` privilege on the current database to install it. 

---

## 🚨 Dangerous Extensions List

### 1. External Data Wrappers (FDWs)
- **`postgres_fdw`:** Used to connect to external PostgreSQL databases. Misconfiguration can lead to credentials leakage (if `user mapping` passwords are stored in plaintext) or Server-Side Request Forgery (SSRF) to internal network instances.
- **`file_fdw`:** Allows mapping a database table to an external file. If abused, an attacker could read sensitive OS files (e.g., `/etc/passwd`) or read PostgreSQL configuration files (`pg_hba.conf`).

### 2. System and Network Access
- **`dblink`:** Allows queries to external databases. Often used for SSRF attacks or brute-forcing remote database credentials from within the target.
- **`plpython3u` / OS Execution:** Complete remote code execution.
```sql
-- Example of RCE if attacker has plpython3u access
CREATE OR REPLACE FUNCTION os_cmd(cmd text) RETURNS text AS $$
  import os
  return os.popen(cmd).read()
$$ LANGUAGE plpython3u;
SELECT os_cmd('id');
```

### 3. Application Extensions
- **`pgcrypto`:** Secure if used correctly, but exposes encryption functions. Attackers often target functions like `pgp_sym_decrypt` to find and decrypt sensitive data if they can access the keys.
- **`PostGIS` / `pgvector`:** Extensive attack surface due to the complexity of the C code. Vulnerabilities in spatial or vector parsing could lead to denial of service or memory corruption.

---

## 🔎 Detection Queries

### Find Installed Extensions
List all extensions installed in the current database.

```sql
SELECT e.extname AS extension_name, 
       e.extversion AS version,
       n.nspname AS schema_name
FROM pg_extension e
JOIN pg_namespace n ON e.extnamespace = n.oid;
```

### Find Untrusted Languages Installed
Identify procedural languages that could execute arbitrary code.

```sql
SELECT lanname, lanpltrusted 
FROM pg_language 
WHERE lanispl = true AND lanpltrusted = false;
```

### Find Users with Access to Untrusted Functions
Check who has EXECUTE privileges on functions created using untrusted languages.

```sql
SELECT p.proname AS function_name,
       l.lanname AS language,
       pg_get_userbyid(p.proowner) AS owner,
       HAS_FUNCTION_PRIVILEGE('public', p.oid, 'EXECUTE') AS public_execute,
       p.proacl AS acl
FROM pg_proc p
JOIN pg_language l ON p.prolang = l.oid
WHERE l.lanpltrusted = false;
```

### Check FDW User Mappings for Passwords
Detect plaintext passwords in FDW mappings.

```sql
SELECT um.srvname,
       pg_get_userbyid(um.umuser) AS mapping_user,
       um.umoptions
FROM pg_user_mappings um;
```

---

## 🛠️ Remediation

### 1. Restrict Extension Installation
Ensure only superusers can install non-trusted extensions. Do not grant superuser to application roles.

### 2. Remove Unused Extensions
Audit and remove any extension not actively required.
```sql
DROP EXTENSION IF EXISTS dblink;
DROP EXTENSION IF EXISTS file_fdw CASCADE;
```

### 3. Revoke Public Execution on Extension Functions
If `dblink` or `pgcrypto` is necessary, ensure `PUBLIC` cannot execute its functions.
```sql
REVOKE EXECUTE ON FUNCTION dblink_connect(text) FROM PUBLIC;
```

### 4. Restrict Untrusted Languages
Only highly trusted database administrators should own or execute functions written in untrusted languages (`plpython3u`, `plsh`, etc.).

---

## ✅ Verification Checklist

- [ ] All installed extensions are actively required by the application.
- [ ] No untrusted procedural languages (`*u` suffix like `plpython3u`) are installed unless absolutely necessary.
- [ ] Non-superusers cannot execute functions written in untrusted languages.
- [ ] Passwords in `user_mapping` configurations for FDWs are secured and not exposed to unauthorized users.
- [ ] The `file_fdw` extension is either uninstalled or restricted strictly to superusers to prevent unauthorized file access.
- [ ] Extension schemas do not grant excessive privileges to application roles.
