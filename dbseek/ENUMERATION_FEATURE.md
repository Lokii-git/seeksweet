# DbSeek Database Enumeration Feature

## Overview
DbSeek now supports **SAFE** database enumeration after successful authentication. This feature lists all accessible databases without modifying any data.

## Safety First ⚠️
- **READ-ONLY OPERATIONS ONLY**
- No INSERT, UPDATE, DELETE, DROP, or modification commands
- System databases excluded where appropriate
- Graceful error handling (returns empty list on failure)

## Usage

### Basic Enumeration
```bash
# Enumerate with custom credentials (e.g., from Responder)
./dbseek.py -u admin -p Password123 -e

# Test default creds + enumerate
./dbseek.py -t -e

# Combine custom + default creds + enumerate
./dbseek.py -t -u admin -p captured_pass -e
```

### Arguments
- `-e, --enumerate` - Enable database enumeration (SAFE: read-only)
- `-u, --username` - Custom username to test
- `-p, --password` - Custom password to test

## Supported Databases

### MySQL/MariaDB
- **Query**: `SHOW DATABASES`
- **Method**: Native pymysql or CLI fallback
- **Notes**: Lists all accessible databases

### PostgreSQL
- **Query**: `SELECT datname FROM pg_database WHERE datistemplate = false`
- **Method**: Native psycopg2 or CLI fallback
- **Notes**: Excludes template databases

### Microsoft SQL Server
- **Query**: `SELECT name FROM sys.databases WHERE name NOT IN ('master','tempdb','model','msdb')`
- **Method**: Native pymssql or CLI fallback
- **Notes**: Excludes system databases

### MongoDB
- **Method**: `client.list_database_names()`
- **Library**: pymongo or CLI fallback
- **Notes**: Lists all accessible databases

## Output

### Terminal Display
```
[+] 192.168.1.100:3306 - MySQL Access Found (admin / Password123) [Version: 8.0.32]
    📊 Databases: app_db, customer_db, inventory, logs, staging_db (5 total)
```

### File Output
Results saved to:
- `dbseek_results_YYYYMMDD_HHMMSS.txt` - Human-readable summary
- `dbseek_results_YYYYMMDD_HHMMSS.json` - Machine-parseable JSON

## Workflow Integration

### With Responder
```bash
# Step 1: Capture credentials with Responder
sudo responder -I eth0 -wv

# Step 2: Test captured credentials + enumerate
./dbseek.py -u captured_user -p captured_pass -e

# Step 3: Screenshot output for client report
```

### With ntlmrelayx
```bash
# Step 1: Relay attacks to capture plaintext passwords
ntlmrelayx.py -tf targets.txt -smb2support --dump-ntds

# Step 2: Test harvested creds + enumerate databases
./dbseek.py -u DOMAIN\\admin -p harvested_pass -e
```

## Implementation Details

### Enumeration Functions
- `enumerate_mysql_databases()` - MySQL/MariaDB enumeration
- `enumerate_postgresql_databases()` - PostgreSQL enumeration
- `enumerate_mssql_databases()` - MSSQL enumeration
- `enumerate_mongodb_databases()` - MongoDB enumeration

### Integration Points
Enumeration is triggered after successful authentication:
1. Custom credentials (provided via -u/-p)
2. Default credentials (from built-in credential list)
3. No authentication (MongoDB)

### Error Handling
- Connection failures: Returns empty list `[]`
- Query errors: Caught and logged, returns empty list
- Missing libraries: Falls back to CLI tools
- Timeout: Respects connection timeout setting

## Real-World Example

```bash
# Scenario: Found credentials in Responder
# User: admin
# Password: P@ssw0rd123!

./dbseek.py -u admin -p 'P@ssw0rd123!' -e

# Output:
# [+] 10.0.0.50:3306 - MySQL Access Found (admin / P@ssw0rd123!)
#     📊 Databases: company_db, hr_system, payroll, sales_data (4 total)
# [+] 10.0.0.51:5432 - PostgreSQL Access Found (admin / P@ssw0rd123!)
#     📊 Databases: prod_db, analytics, audit_log (3 total)
```

## Security Considerations

### What This Does
✅ Lists database names (metadata only)
✅ Proves successful authentication
✅ Provides reconnaissance for pentest reports
✅ Uses read-only SQL queries

### What This Does NOT Do
❌ Access table data
❌ Modify any data
❌ Create or drop databases
❌ Execute stored procedures
❌ Alter database configuration

## Dependencies

### Required
- Python 3.6+
- colorama (for terminal colors)

### Optional (with fallbacks)
- `pymysql` - MySQL native support
- `psycopg2` - PostgreSQL native support
- `pymssql` - MSSQL native support
- `pymongo` - MongoDB native support

**Note**: If Python libraries are not installed, DbSeek automatically falls back to CLI tools (mysql, psql, sqlcmd, mongo).

## Troubleshooting

### No Databases Listed
- Check credentials are valid
- Verify network connectivity
- Ensure user has database listing privileges
- Check firewall rules

### Missing Library Warnings
```bash
# Install all optional libraries
pip install pymysql psycopg2-binary pymssql pymongo
```

### Permission Denied
- User may not have SHOW DATABASES privilege (MySQL)
- User may not have CONNECT privilege (PostgreSQL)
- User may not be in db_datareader role (MSSQL)
- User may not have listDatabases privilege (MongoDB)

## Feature Comparison

| Feature | Basic Scan | With -t | With -e | With -t -e |
|---------|-----------|---------|---------|------------|
| Detect Services | ✅ | ✅ | ✅ | ✅ |
| Test Custom Creds | ❌ | ❌ | ✅* | ✅* |
| Test Default Creds | ❌ | ✅ | ❌ | ✅ |
| List Databases | ❌ | ❌ | ✅ | ✅ |

*Requires -u and -p arguments

## Credits
- Feature requested for Responder integration
- Implements SAFE read-only queries only
- Designed for pentesting reconnaissance workflows
