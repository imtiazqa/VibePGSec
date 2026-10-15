# SQL Injection in PostgreSQL

## Overview

SQL Injection in PostgreSQL exhibits unique characteristics due to PostgreSQL's feature set:
- Support for stacked/multi-statement queries (`query1; query2`)
- Dollar-quoted string literals (`$$...$$` or `$tag$...$tag$`)
- Rich typecasting operators (`::type` and `CAST()`)
- Server-side procedural languages (PL/pgSQL, PL/Python, etc.) with dynamic SQL (`EXECUTE`)
- Server-side administrative functions capable of interacting with filesystem, network, or server sleep/delays

This document provides a technical reference on PostgreSQL SQL injection mechanics, auditing stored procedures for unsafe dynamic SQL, and implementing robust defenses.

---

## PostgreSQL-Specific Injection Behaviors

### 1. Stacked Queries (Multi-Statement Execution)
Unlike MySQL/Oracle with standard drivers where multi-query execution is often disabled by default, PostgreSQL protocols and many client drivers (e.g., `libpq`, `psycopg2`, `node-postgres`) support stacked queries separated by semicolons:

```sql
SELECT * FROM products WHERE id = 1; UPDATE users SET rolsuper = true WHERE rolname = 'attacker';
```

If an application concatenates untrusted input into a SQL statement, an attacker is not restricted to altering the current query (e.g. via `UNION SELECT`); they can execute arbitrary new statements.

### 2. Dollar-Quoting (`$$`)
PostgreSQL allows strings to be enclosed in dollar quotes rather than single quotes:
```sql
SELECT $$Injected string without single quote escaping$$;
SELECT $tag$Enclosed body$tag$;
```
If dynamic SQL generators filter or escape single quotes (`'`) but leave dollar signs untouched, an attacker can construct valid string constants without using single quotes.

### 3. Typecasting Injection and Error-Based Extraction
PostgreSQL strict type checking can be leveraged for error-based information extraction:
```sql
-- Forcing type conversion error that exposes query results in the error message
SELECT * FROM products WHERE id = 1 AND 1 = CAST((SELECT rolname || ':' || rolpassword FROM pg_authid LIMIT 1) AS integer);
```
Error message produced:
```
ERROR:  invalid input syntax for type integer: "postgres:SCRAM-SHA-256$..."
```

### 4. Time-Based Blind Extraction with `pg_sleep()`
When error messages and query results are suppressed:
```sql
SELECT * FROM products WHERE id = 1 AND (SELECT CASE WHEN (SELECT current_user) = 'postgres' THEN pg_sleep(5) ELSE pg_sleep(0) END) IS NOT NULL;
```

---

## Auditing PL/pgSQL Dynamic SQL

In stored procedures and functions, SQL injection frequently occurs via `EXECUTE` with unescaped string concatenation.

### Vulnerable Pattern
```sql
CREATE OR REPLACE FUNCTION get_user_by_name(uname text)
RETURNS SETOF users AS $$
BEGIN
    -- VULNERABLE: Direct string concatenation into EXECUTE
    RETURN QUERY EXECUTE 'SELECT * FROM users WHERE username = ''' || uname || '''';
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### Detection Query for Vulnerable Functions
Run the following query to detect PL/pgSQL functions that use string concatenation (`||`) within `EXECUTE` blocks:

```sql
SELECT 
    n.nspname AS schema_name,
    p.proname AS function_name,
    pg_get_userbyid(p.proowner) AS owner,
    p.prosecdef AS is_security_definer,
    pg_get_functiondef(p.oid) AS definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
JOIN pg_language l ON l.oid = p.prolang
WHERE l.lanname = 'plpgsql'
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND pg_get_functiondef(p.oid) ~* 'EXECUTE\s+.*\|\|.*'
ORDER BY n.nspname, p.proname;
```

---

## Defensive Remediations

### 1. Parameterized `EXECUTE` with `USING`
For dynamic values (literals), use the `USING` clause rather than concatenation:

```sql
CREATE OR REPLACE FUNCTION get_user_by_name(uname text)
RETURNS SETOF users AS $$
BEGIN
    -- SAFE: Parameterized dynamic query
    RETURN QUERY EXECUTE 'SELECT * FROM users WHERE username = $1' USING uname;
END;
$$ LANGUAGE plpgsql;
```

### 2. Identifier Sanitization with `format()`
When table names, column names, or schema names must be dynamic, use `format()` with `%I` (for SQL identifiers) and `%L` (for SQL literals):

```sql
CREATE OR REPLACE FUNCTION query_custom_table(tbl_name text, status_filter text)
RETURNS SETOF record AS $$
DECLARE
    sql_query text;
BEGIN
    -- SAFE: %I correctly quotes identifiers; %L quotes literals
    sql_query := format('SELECT id, status FROM %I WHERE status = %L', tbl_name, status_filter);
    RETURN QUERY EXECUTE sql_query;
END;
$$ LANGUAGE plpgsql;
```

`format()` specifiers:
- `%I`: Identifiers (table names, column names). Automatically applies `quote_ident()`.
- `%L`: Literals (values). Automatically applies `quote_literal()`.
- `%s`: Raw string insertion (DO NOT use for untrusted user inputs).

### 3. Built-in Sanitization Functions
Alternatively, manually wrap dynamic elements:
- `quote_ident(text)`: Quotes an identifier if needed (handles double quotes and reserved words).
- `quote_literal(text)`: Safely quotes a literal string with single quotes and escapes embedded quotes.
- `quote_nullable(text)`: Same as `quote_literal()`, but returns `NULL` without quotes if input is `NULL`.

---

## Verification Checklist

- [ ] All client applications use parameterized queries / prepared statements (never string interpolation).
- [ ] Stored procedures using dynamic SQL utilize `EXECUTE ... USING $1, $2`.
- [ ] Any dynamic schema, table, or column names in `EXECUTE` are validated against an allowlist and wrapped in `format('%I', ...)` or `quote_ident()`.
- [ ] No `SECURITY DEFINER` functions execute dynamic SQL concatenated with user parameters.
- [ ] Database error messages are sanitized by the application before reaching end users.
