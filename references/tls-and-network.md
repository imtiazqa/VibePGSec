# TLS and Network Security

## 🌐 PostgreSQL TLS/SSL Configuration

Network security for PostgreSQL focuses on ensuring that connections between clients and the server are encrypted and authenticated. Without TLS, all data, including queries, results, and plaintext passwords, is transmitted over the network in cleartext, vulnerable to packet sniffing and Man-in-the-Middle (MitM) attacks.

### `ssl` Setting in `postgresql.conf`
To enable TLS, the `ssl` parameter in `postgresql.conf` must be set to `on`.

```ini
# postgresql.conf
listen_addresses = '*'
port = 5432
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
ssl_ca_file = 'ca.crt'
```

### `pg_hba.conf`: `host` vs. `hostssl` vs. `hostnossl`
The `pg_hba.conf` (Host-Based Authentication) file controls client access. The connection type dictates whether SSL is enforced.
- `host`: Allows both SSL and non-SSL connections.
- `hostssl`: **Strictly enforces** SSL connections. Rejecting cleartext connections.
- `hostnossl`: Strictly enforces non-SSL (cleartext) connections. Avoid using this.

**Insecure `pg_hba.conf` example:**
```text
# TYPE  DATABASE        USER            ADDRESS                 METHOD
host    all             all             0.0.0.0/0               md5
```
This allows global internet access (`0.0.0.0/0`) over cleartext connections if the client does not request SSL.

**Secure `pg_hba.conf` example:**
```text
# TYPE  DATABASE        USER            ADDRESS                 METHOD
hostssl all             app_user        10.0.0.0/8              scram-sha-256
```
Enforces SSL, restricts to a specific subnet, and uses modern hashing.

### Client Certificate Authentication
For strict authentication (Zero Trust), use `cert` authentication in `pg_hba.conf`. Clients must present a valid X.509 certificate signed by the server's trusted CA (`ssl_ca_file`). 
```text
hostssl all             all             10.0.0.0/8              cert
```

---

## 🚨 Security Risks

### 1. `listen_addresses` and Port Exposure
Setting `listen_addresses = '*'` binds PostgreSQL to all network interfaces, including public IPs. If the firewall is misconfigured, the database port (default `5432`) is exposed to the internet, leading to brute-force attacks and CVE exploitation.

### 2. CIDR Mask Mistakes
A common mistake in `pg_hba.conf` is using overly permissive CIDR blocks:
- `0.0.0.0/0`: Any IPv4 address (Global Internet).
- `::/0`: Any IPv6 address.
If used with weak authentication methods like `trust`, any attacker can connect without a password.

### 3. Insecure `sslmode` on Clients
Even if the server supports SSL, clients determine how they connect via the `sslmode` parameter:
- `disable` / `allow` / `prefer` (Default): Vulnerable to MitM stripping attacks.
- `require`: Encrypts data, but vulnerable to MitM if certificate verification is ignored.
- `verify-ca` / `verify-full`: Secure. Verifies the server's certificate against a trusted CA, and `verify-full` checks the hostname.

---

## 🔎 Detection Queries

### Check Current SSL Status
Verify if SSL is enabled globally.
```sql
SELECT name, setting 
FROM pg_settings 
WHERE name IN ('ssl', 'ssl_cert_file', 'ssl_key_file', 'ssl_ca_file');
```

### Inspect Active Connections for SSL
Identify clients currently connected without SSL.
```sql
SELECT datname, usename, client_addr, ssl, version, cipher
FROM pg_stat_ssl
JOIN pg_stat_activity ON pg_stat_ssl.pid = pg_stat_activity.pid
WHERE backend_type = 'client backend';
```

### Audit `pg_hba.conf` Rules
Check for permissive CIDR ranges or weak methods (`trust`, `password`).
*(Requires PostgreSQL 10+)*
```sql
SELECT line_number, type, database, user_name, address, netmask, auth_method
FROM pg_hba_file_rules
WHERE type = 'host' OR auth_method IN ('trust', 'password', 'md5') OR address = '{0.0.0.0/0}';
```

### Check Listen Addresses
```sql
SELECT name, setting FROM pg_settings WHERE name = 'listen_addresses';
```

---

## 🛠️ Remediation

1. **Enforce `hostssl`**: Change `host` rules in `pg_hba.conf` to `hostssl` for all remote connections.
2. **Restrict Networks**: Replace `0.0.0.0/0` with strict internal subnets or specific IP addresses (e.g., `192.168.1.50/32`).
3. **Upgrade Authentication**: Migrate from `md5` or `password` to `scram-sha-256`. Never use `trust` on network interfaces.
4. **Bind Internally**: Change `listen_addresses = 'localhost'` or specific internal IPs if external access is not required. Block port `5432` at the firewall level from the public internet.

---

## ✅ Verification Checklist

- [ ] PostgreSQL is configured with `ssl = on` in `postgresql.conf`.
- [ ] `pg_hba.conf` strictly uses `hostssl` for remote connections.
- [ ] All connections use secure, modern ciphers (enforced via `ssl_ciphers`).
- [ ] `pg_hba.conf` does not contain `0.0.0.0/0` entries unless explicitly required and mitigated by strict firewall rules.
- [ ] `trust` authentication is completely removed from all network interfaces.
- [ ] Application connection strings use `sslmode=verify-full` or `sslmode=verify-ca`.
- [ ] No active connections in `pg_stat_ssl` show `ssl = false` for remote clients.
