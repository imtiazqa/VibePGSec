# Replication Security

## 🔄 Replication Security Models in PostgreSQL

PostgreSQL supports two main types of replication:
1. **Physical (Streaming) Replication:** Copies the entire database cluster bit-for-bit via Write-Ahead Logs (WAL).
2. **Logical Replication:** Copies specific data changes (inserts, updates, deletes) on selected tables using a publication/subscription model.

Both mechanisms require specialized network connections, user roles, and access to internal data streams, presenting unique security risks if not properly hardened.

---

## 🚨 Security Risks

### 1. `REPLICATION` Privilege Risks
A role with the `REPLICATION` attribute is exceptionally powerful. It can read all data across all databases in the cluster by tapping directly into the WAL stream, bypassing standard table-level `GRANT`/`REVOKE` permissions and Row-Level Security (RLS) policies.
- **Risk:** Compromise of a replication role results in full data exposure.

### 2. Physical Replication Slots Exposure
Physical replication slots retain WAL data until the replica consumes it. 
- **Risk:** If an attacker can create a slot but not consume from it, they can cause a Denial of Service (DoS) by filling the primary server's disk space with retained WAL files.

### 3. Logical Replication: Privilege Boundaries
Logical replication separates the sender (Publication) from the receiver (Subscription).
- **Publication:** The user creating the publication does not need access to the data, but the tables being published must be explicitly added.
- **Subscription:** Creating a subscription requires superuser privileges because the apply worker executes locally, potentially running triggers or accessing the filesystem.
- **Risk:** Malicious triggers on the subscriber side can result in privilege escalation or arbitrary code execution when the replication worker applies changes.

### 4. `pg_hba.conf` Replication Entries
Connections for streaming replication use a special database keyword: `replication`.
- **Risk:** If `pg_hba.conf` is overly permissive (`host replication all 0.0.0.0/0 trust`), an attacker on the network can masquerade as a standby server and silently siphon all database changes.

---

## 🔎 Detection Queries

### Check Roles with Replication Privileges
Identify all roles that possess the `REPLICATION` or `SUPERUSER` attribute.
```sql
SELECT rolname, rolsuper, rolreplication 
FROM pg_roles 
WHERE rolreplication = true OR rolsuper = true;
```

### Inspect `pg_hba.conf` for Replication Access
Identify loose network rules allowing replication connections.
```sql
SELECT line_number, type, database, user_name, address, auth_method
FROM pg_hba_file_rules
WHERE 'replication' = ANY(database);
```

### Check Active Replication Slots
Monitor replication slots to ensure there are no unauthorized or orphaned slots consuming disk space.
```sql
SELECT slot_name, plugin, slot_type, active, restart_lsn
FROM pg_replication_slots;
```

### Audit Publications and Subscriptions
Check logical replication setups to ensure only authorized tables are published.
```sql
-- List Publications
SELECT pubname, puballtables FROM pg_publication;

-- List Subscriptions
SELECT subname, subconninfo, synccommit FROM pg_subscription;
```

---

## 🛠️ Remediation & Best Practices

### 1. Privilege Minimization
- Never use a superuser account for replication.
- Create a dedicated role solely for replication with no login privileges outside of replication.
```sql
CREATE ROLE repl_user WITH REPLICATION LOGIN PASSWORD 'strong_password';
```

### 2. Secure `pg_hba.conf`
Restrict replication connections strictly to the IP addresses of known standby servers and enforce SSL and strong authentication.
```text
# Secure replication entry
hostssl replication repl_user 10.0.1.25/32 scram-sha-256
```

### 3. Manage Replication Slots
Monitor `pg_replication_slots` and drop inactive or unauthorized slots to prevent WAL buildup and DoS attacks.
```sql
SELECT pg_drop_replication_slot('unauthorized_slot_name');
```

### 4. Secure Logical Subscriptions
When configuring logical replication on the subscriber database, ensure that no untrusted triggers or foreign keys are attached to the subscribed tables, as the apply worker runs with high privileges.

---

## ✅ Verification Checklist

- [ ] Dedicated roles exist for replication, and they are not superusers.
- [ ] Replication roles are strictly used for replication, not application connections.
- [ ] `pg_hba.conf` entries for `database = 'replication'` are restricted to specific standby IP addresses using `hostssl`.
- [ ] Strong authentication (e.g., `scram-sha-256` or client certificates) is enforced for replication connections.
- [ ] Monitoring is in place for orphaned or inactive entries in `pg_replication_slots`.
- [ ] Subscriptions on the receiving end do not execute untrusted user-defined triggers.
