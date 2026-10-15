# PostgreSQL Backup and Recovery Security

## Overview

Database backups represent a high-value attack target because they contain the entirety of the database state, often stored outside the protected perimeter of the primary database server. An insecure backup pipeline can bypass all runtime authentication, RLS, and role-based access controls.

This reference covers security considerations for:
- Logical backups (`pg_dump`, `pg_dumpall`)
- Physical backups (`pg_basebackup`, WAL archiving)
- Credential management during backup routines (`.pgpass`, environment variables)
- At-rest and in-transit encryption of backup artifacts

---

## 1. Credential Security in Backup Automations

### Insecure Practices
- **`PGPASSWORD` environment variable in cron scripts**: Process listings (`ps aux`, `/proc/<pid>/cmdline`) on Unix systems expose environment variables to other processes or local users under certain kernel configurations.
- **Unprotected `.pgpass` files**: Storing plain credentials without restrictive file permissions (must be `chmod 0600`).
- **Connection strings in scripts**: Embedding passwords in URLs (`postgresql://user:pass@host/db`).

### Best Practices
- Use client certificate authentication (`sslmode=verify-full`, `sslcert`, `sslkey`) for backup tasks where feasible.
- Store connection credentials in a tightly secured `~/.pgpass` owned strictly by the backup OS user:
  ```bash
  touch ~/.pgpass && chmod 0600 ~/.pgpass
  echo "hostname:5432:dbname:backup_role:SecretPasswordHere" > ~/.pgpass
  ```
- Use dedicated backup service roles with minimal required privileges rather than `postgres` superuser.

---

## 2. Dedicated Least-Privilege Backup Roles

### Logical Backups (`pg_dump`)
Instead of running `pg_dump` as superuser, PostgreSQL 14+ introduces the predefined role `pg_read_all_data`:

```sql
CREATE ROLE backup_user WITH LOGIN PASSWORD 'SecurePassHere';
GRANT pg_read_all_data TO backup_user;
GRANT CONNECT ON DATABASE production TO backup_user;
```

### Physical Base Backups (`pg_basebackup`)
Physical backups require the `REPLICATION` attribute or membership in the predefined role (PG 10+):

```sql
CREATE ROLE basebackup_user WITH REPLICATION LOGIN PASSWORD 'SecurePassHere';
```
Ensure in `pg_hba.conf` that `basebackup_user` is strictly limited to specified IP addresses and requires SSL:
```
# pg_hba.conf
hostssl replication basebackup_user 10.0.1.50/32 scram-sha-256
```

---

## 3. Storage and Archive Security

### Encryption at Rest
Logical SQL dumps and raw WAL files are stored in plain text by default unless explicitly encrypted.
- Always pipe `pg_dump` through an encryption utility:
  ```bash
  pg_dump -Fc mydb | gpg --encrypt --recipient ops-key > mydb_$(date +%F).dump.gpg
  ```
- For WAL archiving (`archive_command`), encrypt segments before transfer:
  ```ini
  archive_command = 'gpg --encrypt --recipient backup-key %p -o /mnt/wal_archive/%f.gpg'
  ```

### Storage Permissions
- Ensure backup destination directories, S3 buckets, or network shares enforce access control lists (ACLs) and immutability (WORM / Object Lock) to prevent ransomware tampering.

---

## Verification Checklist

- [ ] Automated backup scripts do not pass plaintext passwords in command-line arguments or world-readable files.
- [ ] Dedicated, non-superuser roles (`pg_read_all_data` / `REPLICATION`) are utilized for backups.
- [ ] `pg_basebackup` connections are constrained by `hostssl` and IP whitelist in `pg_hba.conf`.
- [ ] Backup dumps and WAL archive segments are encrypted at rest.
- [ ] Retention and access policies on backup targets prevent unauthorized exfiltration and deletion.
