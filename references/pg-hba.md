# pg_hba.conf Security Deep-Dive

## Overview

`pg_hba.conf` (Host-Based Authentication) is PostgreSQL's primary access control gate. Every inbound connection — from an application, a DBA shell, a replication standby, or an attacker — is evaluated against this file **before** any SQL is executed.

A misconfigured `pg_hba.conf` can render all database-level role security meaningless: `trust` authentication, for example, allows any OS user to connect as any database user without a password.

---

## File Format

Each rule is a single line with up to 8 fields:

```
TYPE  DATABASE  USER  ADDRESS  [IP-MASK]  AUTH-METHOD  [AUTH-OPTIONS]
```

Rules are evaluated **top-to-bottom** and the **first match wins**. No fallthrough.

---

## 1. Connection Types (`TYPE`)

| Type | Description | Risk |
|------|-------------|------|
| `local` | Unix domain socket | Secure if OS user access is controlled |
| `host` | TCP/IP — plaintext or SSL | Dangerous without `hostssl` enforcement |
| `hostssl` | TCP/IP, SSL **required** | Recommended for all remote connections |
| `hostnossl` | TCP/IP, SSL **forbidden** | Should never be used in production |
| `hostgssenc` | TCP/IP, GSSAPI encryption required | Kerberos environments |
| `hostnogssenc` | TCP/IP, no GSSAPI | Rarely used; prefer `hostssl` |

### Detection: Find `host` (non-TLS) remote rules
```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE type = 'host'
  AND address IS NOT NULL;
-- Any result here means plaintext remote connections are permitted
```

---

## 2. Authentication Methods (`AUTH-METHOD`)

### ❌ `trust` — CRITICAL Risk
Allows connection without any credential. Any OS user connecting from the matching address is accepted unconditionally.

```sql
-- Detect trust authentication
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'trust';
```

**Remediation**: Remove all `trust` entries except possibly `local` for the `postgres` OS superuser in tightly controlled environments. Even then, prefer `peer`.

### ❌ `password` — HIGH Risk
Sends passwords in **plaintext** over the network. Even with TLS, this is weaker than challenge-response methods.

```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'password';
```

**Remediation**: Replace with `scram-sha-256`.

### ⚠️ `md5` — MEDIUM Risk
MD5 hashed credentials. Vulnerable to offline dictionary attacks if hashes are exposed. Deprecated in PostgreSQL 16+.

```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE auth_method = 'md5';
```

**Remediation**: Migrate to `scram-sha-256`.

### ✅ `scram-sha-256` — Recommended
Challenge-response authentication. The server never receives the plaintext password. Resistant to replay attacks. Default since PostgreSQL 14.

### ✅ `peer` — Recommended for local connections
Verifies that the OS user name matches the database role name. Appropriate for local administrative connections (e.g., `postgres` OS user → `postgres` database role).

```
local   all   postgres   peer
```

### ✅ `cert` — Recommended for service-to-service
Client certificate authentication. Requires TLS. The database validates the client's X.509 certificate CN against the database role name. No password needed.

```
hostssl all   service_role   10.0.0.0/8   cert  clientcert=verify-full
```

### Others
| Method | Notes |
|--------|-------|
| `reject` | Explicitly denies matching connections. Use as a catch-all deny rule. |
| `ldap` | LDAP bind authentication. Ensure `ldaptls=1` and validate server certs. |
| `gss` | Kerberos/GSSAPI. Secure when properly configured. |
| `pam` | PAM authentication. Security depends on PAM module config. |
| `radius` | RADIUS authentication. Requires encrypted transport. |
| `ident` | Maps OS username via identd daemon. Not recommended — identd is untrustworthy on networks. |

---

## 3. Address and CIDR Specification

Overly broad address ranges are a common misconfiguration:

| Address | Risk Level | Notes |
|---------|-----------|-------|
| `0.0.0.0/0` | 🔴 CRITICAL | Accepts connections from the entire internet |
| `all` | 🔴 CRITICAL | Accepts from all addresses |
| `samenet` | 🟠 HIGH | Entire subnet — often broader than intended |
| `10.0.0.0/8` | 🟡 MEDIUM | Entire RFC-1918 block — use narrower ranges |
| `10.0.1.100/32` | ✅ GOOD | Single host — least privilege |

### Detection: Overly Broad Ranges
```sql
SELECT line_number, type, database, user_name, address, netmask, auth_method
FROM pg_hba_file_rules
WHERE address IN ('0.0.0.0/0', 'all', 'samenet', '0.0.0.0')
   OR address LIKE '%/8'
   OR address LIKE '%/16';
```

---

## 4. Database and User Wildcards

| Value | Meaning | Risk |
|-------|---------|------|
| `all` | All databases / all users | Broad — check carefully |
| `sameuser` | Database matching user name | Usually safe |
| `samerole` | Databases matching a role | Context-dependent |
| `replication` | Replication connections only | Should be locked to specific IPs |
| `@/path/file` | Read list from file | Ensure file permissions are strict |

### Detection: Rules Granting Access to All Databases as All Users
```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE 'all' = ANY(database) AND 'all' = ANY(user_name);
```

---

## 5. Replication Entries

Replication connections require a special `replication` pseudo-database entry and a role with the `REPLICATION` attribute.

```
# GOOD: TLS-only, specific IP, SCRAM auth
hostssl   replication   repl_user   10.0.1.50/32   scram-sha-256

# BAD: Trust from any host
host      replication   all         0.0.0.0/0      trust
```

### Detection: Insecure Replication Entries
```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE 'replication' = ANY(database)
  AND (auth_method = 'trust'
    OR type = 'host'
    OR address IN ('0.0.0.0/0', 'all'));
```

---

## 6. Secure `pg_hba.conf` Template

```
# TYPE   DATABASE        USER            ADDRESS                 METHOD

# Superuser: OS peer authentication only (no network access)
local    all             postgres                                peer

# Local Unix socket: SCRAM for all other users
local    all             all                                     scram-sha-256

# Application connections: TLS required, narrow IP range, SCRAM
hostssl  app_database    app_user        10.0.1.0/24             scram-sha-256

# Replication: TLS required, specific replica IP only
hostssl  replication     repl_user       10.0.1.50/32            scram-sha-256

# Monitoring: TLS required, monitoring server only
hostssl  postgres        monitoring      10.0.2.10/32            scram-sha-256

# Catch-all: deny everything else
host     all             all             0.0.0.0/0               reject
host     all             all             ::/0                    reject
```

---

## 7. Viewing and Reloading Configuration

```sql
-- View parsed rules (PostgreSQL 10+)
SELECT * FROM pg_hba_file_rules ORDER BY line_number;

-- View file location
SHOW hba_file;

-- Reload after changes (no restart needed)
SELECT pg_reload_conf();

-- Verify reload success
SELECT pg_conf_load_time();
```

---

## 8. Common Misconfigurations Table

| Misconfiguration | Severity | Impact |
|-----------------|----------|--------|
| `trust` on any host type | CRITICAL | Authentication bypass |
| `host` instead of `hostssl` for remote | HIGH | Credentials exposed in transit |
| `0.0.0.0/0` address range | HIGH | World-accessible database |
| `all` user with `all` database | HIGH | No targeted restriction |
| `md5` auth method | MEDIUM | Weak credential hashing |
| `password` auth method | HIGH | Plaintext credentials |
| Missing catch-all `reject` rule | MEDIUM | Implicit deny may not exist |
| Replication open to `all` users | CRITICAL | Anyone can pull WAL data |

---

## Verification Checklist

- [ ] No `trust` entries exist for non-`local` connection types
- [ ] No `password` (plaintext) authentication method is configured
- [ ] All remote connections use `hostssl` (not `host`)
- [ ] All remote connections use `scram-sha-256` (not `md5`)
- [ ] No address entries use `0.0.0.0/0`, `all`, or `/8` ranges
- [ ] Replication entries are locked to specific IP addresses
- [ ] A catch-all `reject` rule exists as the last entry for both IPv4 and IPv6
- [ ] `pg_hba_file_rules` is regularly audited
- [ ] File permissions on `pg_hba.conf` are `0600` owned by `postgres`
