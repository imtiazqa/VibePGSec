# Observability — Suspicious Activity Detection

## Overview

Real-time and historical observability of PostgreSQL activity allows security teams to detect anomalies, investigate incidents, and identify attackers who have already gained access. This guide provides ready-to-use SQL queries for detecting suspicious database behavior from within the database itself.

---

## 1. Detect Suspicious Active Sessions

### Long-Running Queries (Potential Data Exfiltration)
```sql
SELECT 
    pid,
    usename,
    application_name,
    client_addr,
    state,
    wait_event_type,
    wait_event,
    EXTRACT(EPOCH FROM (now() - query_start))::int AS query_seconds,
    LEFT(query, 200) AS query_preview
FROM pg_stat_activity
WHERE state != 'idle'
  AND query_start < now() - INTERVAL '5 minutes'
ORDER BY query_start ASC;
```

### Idle Transactions (Lock Holding, Potential Abuse)
```sql
SELECT 
    pid,
    usename,
    client_addr,
    state,
    EXTRACT(EPOCH FROM (now() - state_change))::int AS idle_seconds,
    LEFT(query, 200) AS last_query
FROM pg_stat_activity
WHERE state = 'idle in transaction'
  AND state_change < now() - INTERVAL '60 seconds'
ORDER BY state_change ASC;
```

### Unexpected Client Addresses
```sql
-- Find connections from unexpected IP ranges
SELECT DISTINCT
    usename,
    client_addr,
    application_name,
    COUNT(*) AS connection_count
FROM pg_stat_activity
WHERE client_addr IS NOT NULL
  AND family(client_addr) = 4  -- IPv4
  AND NOT (client_addr << '10.0.0.0/8'::inet    -- not internal
        OR client_addr << '172.16.0.0/12'::inet
        OR client_addr << '192.168.0.0/16'::inet)
GROUP BY usename, client_addr, application_name
ORDER BY connection_count DESC;
```

### Multiple Sessions from Same User (Potential Credential Abuse)
```sql
SELECT 
    usename,
    client_addr,
    COUNT(*) AS session_count,
    MIN(backend_start) AS oldest_session,
    MAX(backend_start) AS newest_session
FROM pg_stat_activity
WHERE usename NOT IN ('postgres')
GROUP BY usename, client_addr
HAVING COUNT(*) > 10
ORDER BY session_count DESC;
```

---

## 2. Detect Privilege Escalation Indicators

### Superuser Connections (Should Be Rare)
```sql
SELECT 
    pid,
    usename,
    client_addr,
    application_name,
    backend_start,
    state,
    LEFT(query, 200) AS current_query
FROM pg_stat_activity
JOIN pg_roles r ON r.rolname = pg_stat_activity.usename
WHERE r.rolsuper = true
  AND usename != 'postgres';
-- Alert if non-postgres superusers are actively connected
```

### Recently Created Superuser Accounts
```sql
SELECT 
    rolname,
    rolsuper,
    rolcreaterole,
    rolcreatedb,
    rolcanlogin,
    -- pg_authid.rolpassword changes on password reset; no reliable creation timestamp in catalog
    -- Use this to identify all current superusers
    rolvaliduntil
FROM pg_roles
WHERE rolsuper = true
ORDER BY rolname;
```

### BYPASSRLS Roles (High Risk)
```sql
SELECT rolname, rolsuper, rolbypassrls, rolcanlogin
FROM pg_roles
WHERE rolbypassrls = true;
```

### Roles with Dangerous Predefined Memberships
```sql
SELECT 
    r.rolname AS member,
    g.rolname AS dangerous_role
FROM pg_auth_members m
JOIN pg_roles r ON m.member = r.oid
JOIN pg_roles g ON m.roleid = g.oid
WHERE g.rolname IN (
    'pg_execute_server_program',
    'pg_read_server_files',
    'pg_write_server_files',
    'pg_read_all_data',
    'pg_write_all_data'
)
ORDER BY g.rolname, r.rolname;
```

---

## 3. Detect Anomalous Query Patterns

### High-Volume SELECT on Sensitive Tables (Potential Exfiltration)
```sql
-- Requires pg_stat_statements extension
SELECT 
    usename,
    LEFT(query, 200) AS query_pattern,
    calls,
    total_exec_time::numeric(12,2) AS total_ms,
    rows AS total_rows_returned,
    (rows / calls)::numeric(12,1) AS avg_rows_per_call
FROM pg_stat_statements
JOIN pg_roles ON pg_roles.oid = pg_stat_statements.userid
WHERE query ILIKE '%SELECT%'
  AND (query ILIKE '%users%' OR query ILIKE '%payments%' OR query ILIKE '%credentials%')
  AND rows > 10000
ORDER BY rows DESC
LIMIT 20;
```

### DDL Operations by Non-Admin Roles
```sql
-- Requires pgaudit or pg_stat_statements
SELECT 
    usename,
    LEFT(query, 300) AS ddl_query,
    calls,
    mean_exec_time::numeric(10,2) AS avg_ms
FROM pg_stat_statements
JOIN pg_roles ON pg_roles.oid = pg_stat_statements.userid
WHERE (query ILIKE 'CREATE%'
    OR query ILIKE 'ALTER%'
    OR query ILIKE 'DROP%'
    OR query ILIKE 'GRANT%'
    OR query ILIKE 'REVOKE%')
  AND NOT pg_roles.rolsuper
ORDER BY calls DESC;
```

### `COPY PROGRAM` Usage (OS Command Execution)
```sql
SELECT 
    usename,
    query,
    query_start,
    state
FROM pg_stat_activity
WHERE query ILIKE '%COPY%PROGRAM%';

-- Historical (requires pg_stat_statements)
SELECT usename, query, calls
FROM pg_stat_statements
JOIN pg_roles ON pg_roles.oid = pg_stat_statements.userid
WHERE query ILIKE '%COPY%PROGRAM%';
```

---

## 4. Detect Failed Connections and Authentication Attempts

PostgreSQL logs failed authentication to the server log but does not expose it via SQL views by default. Use these approaches:

### Via `log_fdw` (Query Logs from SQL)
```sql
-- Requires file_fdw and appropriate log format setup
-- See references/pgaudit.md for log_fdw setup

SELECT log_time, user_name, database_name, message
FROM pg_log
WHERE error_severity IN ('FATAL', 'ERROR')
  AND message LIKE '%authentication failed%'
ORDER BY log_time DESC
LIMIT 50;
```

### Via `pg_stat_activity` (Current Failures Won't Appear — Use Log Monitoring)
Failed authentications are rejected before a backend process is created, so they do not appear in `pg_stat_activity`. Implement external log monitoring:

```bash
# Bash: Count authentication failures in the last hour
grep "authentication failed" /var/log/postgresql/postgresql-$(date +%Y-%m-%d).log | \
  grep "$(date '+%Y-%m-%d %H')" | wc -l

# Bash: Top failing usernames
grep "authentication failed" /var/log/postgresql/postgresql-$(date +%Y-%m-%d).log | \
  grep -oP 'user ".*?"' | sort | uniq -c | sort -rn | head -10
```

---

## 5. Lock Contention and Blocking

Excessive lock waits can indicate abuse of idle transactions or intentional lock-based DoS:

```sql
SELECT 
    blocked.pid                 AS blocked_pid,
    blocked.usename             AS blocked_user,
    blocked_activity.query      AS blocked_query,
    blocker.pid                 AS blocker_pid,
    blocker.usename             AS blocker_user,
    blocker_activity.query      AS blocker_query,
    EXTRACT(EPOCH FROM (now() - blocked_activity.query_start))::int AS wait_seconds
FROM pg_locks AS blocked
JOIN pg_stat_activity AS blocked_activity ON blocked.pid = blocked_activity.pid
JOIN pg_locks AS blocker ON blocker.transactionid = blocked.transactionid
    AND blocker.pid != blocked.pid
JOIN pg_stat_activity AS blocker_activity ON blocker.pid = blocker_activity.pid
WHERE NOT blocked.granted
ORDER BY wait_seconds DESC;
```

---

## 6. Replication Anomalies

```sql
-- Replication lag (large lag can indicate stale standby or WAL retention abuse)
SELECT 
    client_addr,
    usename,
    application_name,
    state,
    sent_lsn,
    replay_lsn,
    (sent_lsn - replay_lsn) AS replication_lag_bytes,
    sync_state
FROM pg_stat_replication
ORDER BY replication_lag_bytes DESC;

-- Unused replication slots (causes WAL accumulation, disk exhaustion)
SELECT 
    slot_name,
    plugin,
    slot_type,
    active,
    restart_lsn,
    pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn) AS lag_bytes
FROM pg_replication_slots
WHERE active = false;
-- Alert on inactive slots with large lag — may be orphaned
```

---

## 7. Security Event Monitoring Dashboard Queries

Combine these into a security monitoring routine (run every 5 minutes via pg_cron or external cron):

```sql
-- Security health summary
SELECT 
    (SELECT COUNT(*) FROM pg_roles WHERE rolsuper = true) AS superuser_count,
    (SELECT COUNT(*) FROM pg_roles WHERE rolbypassrls = true) AS bypassrls_count,
    (SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'idle in transaction' 
     AND state_change < now() - INTERVAL '5 minutes') AS stuck_transactions,
    (SELECT COUNT(*) FROM pg_stat_activity WHERE client_addr IS NOT NULL) AS remote_connections,
    (SELECT COUNT(*) FROM pg_replication_slots WHERE active = false) AS inactive_repl_slots,
    (SELECT setting FROM pg_settings WHERE name = 'ssl') AS ssl_enabled,
    (SELECT setting FROM pg_settings WHERE name = 'password_encryption') AS password_encryption;
```

---

## Verification Checklist

- [ ] `pg_stat_statements` is installed and `track_activities = on`
- [ ] Monitoring queries are run regularly (every 5–15 minutes) via external scheduler
- [ ] Alerts exist for: new superuser connections, `COPY PROGRAM` usage, authentication failures exceeding threshold
- [ ] Inactive replication slots are monitored and cleaned up
- [ ] Long-running queries (>5 min) are automatically logged and reviewed
- [ ] `pg_stat_activity` is reviewed for unexpected client IP addresses
- [ ] Failed authentication spikes trigger security alerts
