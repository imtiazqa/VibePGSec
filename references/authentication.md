# Authentication Security

As a PostgreSQL security auditor, analyzing authentication mechanisms is the critical first step in securing any database instance. PostgreSQL controls client authentication primarily through the `pg_hba.conf` (Host-Based Authentication) file and role password management.

## pg_hba.conf Deep Dive

The `pg_hba.conf` file determines which hosts are allowed to connect, how clients are authenticated, which PostgreSQL user names they can use, and which databases they can access.

### Authentication Methods

*   **`trust`**: Completely insecure for remote connections. PostgreSQL assumes that anyone who can connect to the server is authorized to access the database with whatever database user name they specify.
*   **`reject`**: Unconditionally rejects the connection. Useful for explicitly blocking certain hosts or networks before a broader rule allows them.
*   **`scram-sha-256`**: The modern, highly recommended password-based authentication method. It performs challenge-response authentication and prevents password sniffing.
*   **`md5`**: Older challenge-response method. Now considered weak due to MD5 vulnerabilities. Should be migrated to `scram-sha-256`.
*   **`password`**: Sends the password in cleartext. Absolutely must be avoided unless wrapped in SSL/TLS.
*   **`gss` / `sspi`**: Uses GSSAPI (usually Kerberos) or Windows SSPI for single sign-on. Highly secure and recommended for enterprise environments.
*   **`ident`**: Relies on the client operating system's ident server (RFC 1413). Extremely spoofable over TCP/IP and should only be used on trusted, isolated local networks (if at all).
*   **`peer`**: Obtains the client's operating system user name from the kernel and uses it as the permitted database user name (only for local connections). Highly secure for local Unix-domain sockets.
*   **`pam`**: Uses Pluggable Authentication Modules. Defers authentication to the OS PAM stack.
*   **`ldap`**: Authenticates using an LDAP server. Useful for centralized identity management.
*   **`radius`**: Authenticates using a RADIUS server.
*   **`cert`**: Authenticates clients using SSL client certificates. Excellent for high-security environments and machine-to-machine authentication.

### Why `trust` Authentication is Dangerous

When `trust` is used over a network (TCP/IP), any user who can route to the PostgreSQL port can log in as *any* user, including a superuser (e.g., `postgres`), simply by specifying the username. This bypasses all password checks and completely compromises the database. `trust` is only minimally acceptable on local Unix sockets (`local`) for administrative convenience, and even then, `peer` is significantly safer.

### SCRAM-SHA-256 vs MD5

Historically, `md5` was the default. However, MD5 is cryptographically broken. PostgreSQL 10 introduced `scram-sha-256`, and it became the default in version 14.
*   **SCRAM-SHA-256** mitigates dictionary attacks against captured password hashes and prevents pass-the-hash attacks, as the server and client mutually authenticate using a salt and iterations.
*   **Migration**: Change `password_encryption = 'scram-sha-256'` in `postgresql.conf`, update all user passwords, and then change `pg_hba.conf` rules from `md5` to `scram-sha-256`.

## Password Policies

PostgreSQL does not natively enforce complex password policies (length, special characters) without extensions. However, an auditor must check:
1.  **Encryption Type**: Are passwords stored as SCRAM-SHA-256?
2.  **Valid Until**: Are passwords set to expire?
3.  **Extensions**: Is `auth_delay` configured to slow down brute force attacks? Is a custom passwordcheck module used?

## Detection SQL Queries

Use these queries to hunt for misconfigurations.

### 1. Audit pg_hba.conf via System View

This query requires superuser or `pg_read_all_settings` / `pg_read_all_file` privileges. It identifies dangerous network-based rules.

```sql
-- Find dangerous authentication methods on non-local network interfaces
SELECT 
    line_number,
    type,
    database,
    user_name,
    address,
    auth_method,
    error
FROM 
    pg_hba_file_rules
WHERE 
    type IN ('host', 'hostssl', 'hostnossl')
    AND auth_method IN ('trust', 'password', 'ident')
ORDER BY 
    line_number;
```

### 2. Check Password Storage Encryption

Identify roles with weak password hashes (MD5 or plaintext).

```sql
-- Identify weak password hashes
SELECT 
    rolname,
    CASE 
        WHEN rolpassword LIKE 'SCRAM-SHA-256$%' THEN 'SCRAM-SHA-256 (Good)'
        WHEN rolpassword LIKE 'md5%' THEN 'MD5 (Weak)'
        WHEN rolpassword IS NULL THEN 'No Password/External Auth'
        ELSE 'Plaintext / Unknown (Critical)'
    END AS hash_type,
    rolvaliduntil
FROM 
    pg_authid
WHERE 
    rolcanlogin = true;
```

### 3. Check Global Password Settings

Ensure the server is configured to use SCRAM for newly set passwords.

```sql
-- Check server password encryption setting
SELECT 
    name, 
    setting, 
    context 
FROM 
    pg_settings 
WHERE 
    name = 'password_encryption';
```

## Common Misconfigurations Table

| Misconfiguration | Severity | Attack Vector |
| :--- | :--- | :--- |
| `host all all 0.0.0.0/0 trust` | **CRITICAL** | Any attacker on the internet can log in as `postgres` superuser. |
| `password` over `hostnossl` | **CRITICAL** | Cleartext password transmission. Attacker on network can sniff credentials. |
| Weak password (`md5`) hashes | **HIGH** | If `pg_authid` is dumped (e.g., via SQL injection), hashes can be cracked. |
| Unrestricted admin access (`host all postgres 0.0.0.0/0 scram-sha-256`) | **MEDIUM** | Exposes superuser account to brute-force attacks from anywhere. |
| Missing SSL enforcement | **MEDIUM** | Connection details and data can be intercepted on untrusted networks. |

## Remediation

### 1. Hardening pg_hba.conf

Replace dangerous `pg_hba.conf` entries. A secure baseline looks like this:

```text
# TYPE  DATABASE        USER            ADDRESS                 METHOD

# Local administrative access via Unix sockets (secure)
local   all             postgres                                peer

# Reject cleartext connections over the network unconditionally
hostnossl all           all             0.0.0.0/0               reject
hostnossl all           all             ::/0                    reject

# Allow SCRAM-SHA-256 connections over SSL only, restricted to internal network
hostssl all             all             10.0.0.0/8              scram-sha-256

# Reject everything else (explicit deny)
host    all             all             0.0.0.0/0               reject
```

*Apply changes:* `SELECT pg_reload_conf();`

### 2. Upgrading Passwords to SCRAM-SHA-256

```sql
-- 1. Ensure the setting is correct
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
SELECT pg_reload_conf();

-- 2. Force a user to change their password to generate a new SCRAM hash
-- Note: The user MUST log in and run \password or ALTER ROLE to do this.
-- As admin, you can set it if you know it:
ALTER ROLE app_user WITH PASSWORD 'NewSecurePassword123!';
```

## Verification Checklist

- [ ] All `trust` authentication methods have been removed from network (`host`) interfaces in `pg_hba.conf`.
- [ ] Cleartext `password` authentication is strictly prohibited.
- [ ] `password_encryption` in `postgresql.conf` is set to `scram-sha-256`.
- [ ] All login roles have SCRAM-SHA-256 hashes in `pg_authid`.
- [ ] Default `md5` entries in `pg_hba.conf` have been updated to `scram-sha-256`.
- [ ] `hostssl` is enforced for remote connections to prevent credential sniffing.
- [ ] External auth methods (LDAP, GSSAPI, Cert) are utilized for administrative accounts where possible.
- [ ] Passwords have expiration dates (`rolvaliduntil`) if an external identity provider is not used.
- [ ] Connections are restricted by IP address, adhering to the principle of least privilege network access.
