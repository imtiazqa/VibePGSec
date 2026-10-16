# postgresql.conf Security Reference

## Overview

`postgresql.conf` is the primary server configuration file for PostgreSQL. Many parameters directly affect the security posture of the cluster — from authentication behaviour and TLS settings to logging, resource limits, and extension loading.

This reference covers every security-relevant parameter, its dangerous defaults, and the recommended hardened value.

---

## 1. File Location and Access

```sql
-- Find the config file location
SHOW config_file;

-- View all non-default settings
SELECT name, setting, unit, source, sourcefile, sourceline
FROM pg_settings
WHERE source NOT IN ('default', 'override')
ORDER BY name;

-- View all security-relevant settings at once
SELECT name, setting, boot_val AS default_value, source
FROM pg_settings
WHERE name IN (
    'ssl', 'ssl_min_protocol_version', 'ssl_ciphers',
    'password_encryption', 'authentication_timeout',
    'log_connections', 'log_disconnections', 'log_statement',
    'log_min_messages', 'logging_collector', 'log_line_prefix',
    'shared_preload_libraries', 'statement_timeout',
    'idle_in_transaction_session_timeout', 'lock_timeout',
    'listen_addresses', 'port', 'max_connections',
    'track_activities', 'track_io_timing', 'archive_mode', 'wal_level'
)
ORDER BY name;
```

---

## 2. TLS / SSL Parameters

| Parameter | Insecure Default | Hardened Value | Impact |
|-----------|-----------------|----------------|--------|
| `ssl` | `off` (some builds) | `on` | Enables TLS for all remote connections |
| `ssl_min_protocol_version` | `TLSv1.2` | `TLSv1.3` | Prevents downgrade attacks |
| `ssl_ciphers` | `HIGH:MEDIUM:+3DES:!aNULL` | `HIGH:!aNULL:!kEDH:!3DES` | Removes weak ciphers |
| `ssl_prefer_server_ciphers` | `on` | `on` | Server controls cipher negotiation |
| `ssl_cert_file` | `server.crt` | Valid CA-signed cert | Identity authentication |
| `ssl_key_file` | `server.key` | Permissions: `0600` | Key confidentiality |
| `ssl_ca_file` | (empty) | Set to CA cert | Enables client cert validation |
| `ssl_crl_file` | (empty) | Set if using CRL | Revocation support |

### Detection
```sql
SELECT name, setting FROM pg_settings
WHERE name LIKE 'ssl%'
ORDER BY name;

-- Verify current connections are using SSL
SELECT pid, usename, application_name, client_addr, ssl, version, cipher, bits
FROM pg_stat_ssl
JOIN pg_stat_activity USING (pid)
WHERE ssl = false AND client_addr IS NOT NULL;
-- Any results indicate unencrypted remote connections
```

---

## 3. Authentication Parameters

| Parameter | Insecure Default | Hardened Value | Notes |
|-----------|-----------------|----------------|-------|
| `password_encryption` | `scram-sha-256` (PG14+) | `scram-sha-256` | Do not allow `md5` |
| `authentication_timeout` | `60s` | `30s` | Limits authentication brute-force windows |
| `krb_server_keyfile` | (empty) | Set for Kerberos | Kerberos keytab protection |

```sql
SHOW password_encryption;
-- Must be 'scram-sha-256'

SHOW authentication_timeout;

-- Find accounts still using MD5 hashes
SELECT rolname, rolpassword
FROM pg_authid
WHERE rolpassword LIKE 'md5%';
```

---

## 4. Network / Connectivity Parameters

| Parameter | Insecure Default | Hardened Value | Notes |
|-----------|-----------------|----------------|-------|
| `listen_addresses` | `localhost` | Specific IPs only | `'*'` exposes all interfaces |
| `port` | `5432` | `5432` (or custom) | Security through obscurity — minor value |
| `max_connections` | `100` | Tune + use pooler | Prevents connection exhaustion DoS |
| `reserved_connections` | `0` | `3` (PG16+) | Reserves slots for superusers |
| `superuser_reserved_connections` | `3` | `3` | Keeps admin access during overload |

```sql
SHOW listen_addresses;
-- '*' means all interfaces — dangerous if not behind firewall

SHOW max_connections;
SHOW superuser_reserved_connections;
```

---

## 5. Logging and Audit Parameters

These parameters are critical for detecting and investigating security incidents.

| Parameter | Insecure Default | Hardened Value | Notes |
|-----------|-----------------|----------------|-------|
| `logging_collector` | `off` | `on` | Required for persistent log files |
| `log_destination` | `stderr` | `csvlog` or `jsonlog` | Structured logs for SIEM ingestion |
| `log_connections` | `off` | `on` | Log all connection attempts |
| `log_disconnections` | `off` | `on` | Log session terminations |
| `log_duration` | `off` | `off` (use `log_min_duration_statement`) | Full duration logging is noisy |
| `log_min_duration_statement` | `-1` | `1000` (ms) | Log slow queries |
| `log_statement` | `none` | `ddl` | Log schema changes; `mod` for DML |
| `log_min_messages` | `warning` | `warning` | |
| `log_min_error_statement` | `error` | `error` | |
| `log_line_prefix` | `'%m [%p] '` | `'%m [%p] %q%u@%d '` | Includes user, database, timestamp |
| `log_timezone` | server timezone | `UTC` | Consistent audit timestamps |
| `log_file_mode` | `0600` | `0600` | Log file permissions |

```sql
-- Check current logging configuration
SELECT name, setting FROM pg_settings
WHERE name LIKE 'log%'
ORDER BY name;

-- Verify logging collector is running
SHOW logging_collector;
SHOW log_line_prefix;
```

---

## 6. Dangerous / High-Risk Parameters

### `shared_preload_libraries`
Loads shared libraries into server memory **at startup**. A malicious or vulnerable library loaded here has full access to PostgreSQL internals.

```sql
SHOW shared_preload_libraries;
-- Audit every entry — only load known-safe extensions (pg_stat_statements, pgaudit, etc.)
```

### `archive_command`
Executes a shell command after each WAL segment is completed. If attacker-controlled input reaches this command, it results in server-side command injection.

```sql
SHOW archive_command;
-- Should not contain user-derived variables
```

### `restore_command`
Same risk as `archive_command` during recovery scenarios.

### `local_preload_libraries`
Allows regular (non-superuser) users to load libraries without explicit superuser grants. Should be empty in production.

```sql
SHOW local_preload_libraries;
-- Should be empty: ''
```

### `session_preload_libraries`
Loaded for every session. Superuser-controlled but worth auditing.

```sql
SHOW session_preload_libraries;
```

---

## 7. Resource Limit Parameters (DoS Prevention)

| Parameter | Recommended | Purpose |
|-----------|-------------|---------|
| `statement_timeout` | `30000` (30s) | Kill runaway queries |
| `idle_in_transaction_session_timeout` | `60000` (60s) | Kill idle transactions holding locks |
| `lock_timeout` | `10000` (10s) | Prevent lock contention deadlocks |
| `deadlock_timeout` | `1000` (1s) | Detect deadlocks quickly |
| `tcp_keepalives_idle` | `60` | Detect dead connections |
| `tcp_keepalives_interval` | `10` | Keepalive retry interval |
| `tcp_keepalives_count` | `6` | Max keepalive retries |

```sql
SELECT name, setting, unit FROM pg_settings
WHERE name IN (
    'statement_timeout', 'idle_in_transaction_session_timeout',
    'lock_timeout', 'deadlock_timeout',
    'tcp_keepalives_idle', 'tcp_keepalives_interval', 'tcp_keepalives_count'
);
```

---

## 8. Activity Tracking Parameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `track_activities` | `on` | Populate `pg_stat_activity` with query text |
| `track_activity_query_size` | `4096` | How much query text to track |
| `track_counts` | `on` | Enable table/index statistics |
| `track_io_timing` | `on` | Track I/O timing (needed for performance analysis) |

```sql
SHOW track_activities;
-- Must be 'on' for pg_stat_activity monitoring

-- See currently running queries
SELECT pid, usename, application_name, client_addr, state, query_start, query
FROM pg_stat_activity
WHERE state != 'idle'
ORDER BY query_start;
```

---

## 9. Recommended Security Hardened `postgresql.conf` Snippet

```ini
# =============================================================================
# VibePGSec: Hardened postgresql.conf Settings
# =============================================================================

# --- Network ---
listen_addresses = 'localhost,10.0.1.10'   # Bind specific interfaces only
port = 5432
max_connections = 100
superuser_reserved_connections = 3

# --- TLS/SSL ---
ssl = on
ssl_min_protocol_version = 'TLSv1.3'
ssl_ciphers = 'HIGH:!aNULL:!kEDH:!3DES'
ssl_prefer_server_ciphers = on
ssl_cert_file = '/etc/ssl/postgresql/server.crt'
ssl_key_file = '/etc/ssl/postgresql/server.key'
ssl_ca_file = '/etc/ssl/postgresql/ca.crt'

# --- Authentication ---
password_encryption = 'scram-sha-256'
authentication_timeout = 30s

# --- Logging ---
logging_collector = on
log_directory = '/var/log/postgresql'
log_filename = 'postgresql-%Y-%m-%d.log'
log_file_mode = 0600
log_connections = on
log_disconnections = on
log_line_prefix = '%m [%p] %q%u@%d '
log_statement = 'ddl'
log_min_messages = warning
log_min_error_statement = error
log_timezone = 'UTC'

# --- Resource Limits (DoS prevention) ---
statement_timeout = 30000
idle_in_transaction_session_timeout = 60000
lock_timeout = 10000

# --- Extensions ---
shared_preload_libraries = 'pg_stat_statements,pgaudit'

# --- Replication (if not a primary) ---
# wal_level = replica
# archive_mode = on
# archive_command = 'test ! -f /mnt/wal/%f && cp %p /mnt/wal/%f'
```

---

## Verification Checklist

- [ ] `ssl = on` and `ssl_min_protocol_version = 'TLSv1.3'`
- [ ] `password_encryption = 'scram-sha-256'`
- [ ] `listen_addresses` is not set to `'*'` unless behind a firewall
- [ ] `logging_collector = on` with persistent log storage
- [ ] `log_connections = on` and `log_disconnections = on`
- [ ] `log_statement = 'ddl'` (minimum) or `'mod'` for DML logging
- [ ] `statement_timeout` and `idle_in_transaction_session_timeout` are set
- [ ] `shared_preload_libraries` only contains audited, necessary extensions
- [ ] `local_preload_libraries` is empty
- [ ] `archive_command` does not include user-controlled variables
- [ ] Log file permissions are `0600` owned by `postgres` OS user
