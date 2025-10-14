# WebSeek Technical Summary

## Overview
WebSeek is a web vulnerability scanner optimized for internal network assessments. It identifies common security misconfigurations including exposed version control systems, backup files, information disclosure, and missing security controls.

## Architecture

### Core Components
1. **Port Scanner**: Multi-port TCP connect scanner
2. **HTTP Client**: Requests-based HTTP/HTTPS client with SSL bypass
3. **Pattern Matcher**: Regex-based content analysis
4. **Path Enumerator**: Common path dictionary attack
5. **Header Analyzer**: Security header presence checker
6. **Result Processor**: Severity classification and reporting

### Detection Modules
```
┌─────────────────────────────────────────────┐
│              WebSeek Scanner                │
├─────────────────────────────────────────────┤
│  1. Git Exposure Detection                  │
│  2. Backup File Discovery                   │
│  3. Information Disclosure                  │
│  4. Common Path Enumeration                 │
│  5. Security Header Analysis                │
│  6. Directory Listing Detection             │
│  7. SQL Error Detection                     │
└─────────────────────────────────────────────┘
```

## Vulnerability Detection Methods

### 1. Git Repository Exposure

**Detection Strategy**: Sequential probing of Git metadata files

**Checked Paths**:
```python
git_paths = [
    '/.git/',              # Directory listing (if enabled)
    '/.git/config',        # Git configuration
    '/.git/HEAD',          # Current branch reference
    '/.git/index'          # Staging area index
]
```

**HTTP Status Analysis**:
- **200 OK**: File accessible (VULNERABLE)
- **403 Forbidden**: File exists but denied (LIKELY VULNERABLE)
- **404 Not Found**: File doesn't exist (NOT VULNERABLE)

**Content Verification**:
```python
# .git/HEAD should contain ref pointer
if response.status_code == 200 and 'ref:' in response.text:
    # CONFIRMED: Valid Git repository
    severity = 'CRITICAL'
```

**Example Response**:
```
GET /.git/HEAD HTTP/1.1
HTTP/1.1 200 OK
Content-Type: text/plain

ref: refs/heads/master
```

### 2. Backup File Discovery

**Detection Strategy**: Dictionary attack with common backup patterns

**File Generation Logic**:
```python
# Common filenames
COMMON_FILES = ['index', 'login', 'admin', 'config', 'database']

# Backup extensions
BACKUP_EXTENSIONS = ['.bak', '.old', '.save', '.orig', 
                     '.copy', '.zip', '.tar.gz', '~']

# Generate combinations
for filename in COMMON_FILES:
    for ext in BACKUP_EXTENSIONS:
        test_url = f'{base_url}/{filename}{ext}'
        # Test with HEAD request (faster)
```

**HEAD Request Advantage**:
- Faster than GET (no body download)
- Confirms existence via status code
- Can check Content-Length header

**Example**:
```http
HEAD /config.php.bak HTTP/1.1

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 4521
```

**Severity Classification**:
- Config files: HIGH
- Source code: MEDIUM-HIGH
- Archive files: MEDIUM (may contain multiple files)

### 3. Information Disclosure Detection

**Detection Strategy**: Pattern matching on response bodies

**Patterns Checked**:
```python
INFO_PATTERNS = {
    'phpinfo': [
        r'phpinfo\(\)',              # Function call
        r'PHP Version',              # Version header
        r'System.*Linux',            # System info
        r'Server API'                # API info
    ],
    'debug': [
        r'Debug Mode',               # Debug flag
        r'Stack Trace',              # Error traces
        r'Exception',                # Exceptions
        r'Traceback'                 # Python errors
    ],
    'directory_listing': [
        r'Index of /',               # Apache style
        r'Parent Directory',         # Common text
        r'<title>Index of'           # Title tag
    ],
    'sql_error': [
        r'SQL syntax',               # MySQL errors
        r'mysql_fetch',              # PHP MySQL
        r'pg_query',                 # PostgreSQL
        r'ORA-[0-9]+',              # Oracle errors
        r'SQLSTATE'                  # Generic SQL
    ]
}
```

**Content Sampling**:
```python
# Only analyze first 10KB (performance)
content = response.text[:10000]

for info_type, patterns in INFO_PATTERNS.items():
    for pattern in patterns:
        if re.search(pattern, content, re.IGNORECASE):
            # FINDING DETECTED
            severity = determine_severity(info_type)
```

**PHP Info Page Structure**:
```html
<html>
<head><title>phpinfo()</title></head>
<body>
<table>
    <tr><td>PHP Version</td><td>7.4.3</td></tr>
    <tr><td>System</td><td>Linux ubuntu 5.4.0</td></tr>
    <tr><td>Server API</td><td>Apache 2.0 Handler</td></tr>
    <!-- Sensitive configuration exposed -->
</table>
</body>
</html>
```

### 4. Common Path Enumeration

**Detection Strategy**: Status code analysis of known paths

**Path Categories**:
```python
COMMON_PATHS = [
    # Admin panels
    '/admin', '/administrator', '/admin.php', '/wp-admin/',
    '/phpmyadmin', '/cpanel', '/webadmin',
    
    # Backup locations
    '/backup', '/backups', '/backup.zip', '/db_backup',
    
    # Configuration
    '/config', '/config.php', '/configuration.php',
    '/.env', '/config.json', '/web.config',
    
    # Version control
    '/.git', '/.svn', '/.hg',
    
    # Debug/Test
    '/phpinfo.php', '/test.php', '/debug.php', '/console'
]
```

**Status Code Interpretation**:
```python
# 200 OK - Accessible (HIGH severity)
if status_code == 200:
    severity = 'HIGH'

# 401 Unauthorized - Protected but exists (MEDIUM)
elif status_code == 401:
    severity = 'MEDIUM'
    description = 'Panel exists, requires authentication'

# 403 Forbidden - Exists but denied (LOW-MEDIUM)
elif status_code == 403:
    severity = 'LOW'
    description = 'Path exists, access forbidden'

# 301/302 Redirect - May indicate existence
elif status_code in [301, 302]:
    severity = 'LOW'
    description = 'Redirect detected, verify manually'
```

**Redirect Following**:
```python
# allow_redirects=False to detect original response
response = requests.get(url, allow_redirects=False)

if response.status_code in [301, 302]:
    location = response.headers.get('Location')
    # Analyze redirect target
```

### 5. Security Header Analysis

**Detection Strategy**: HTTP response header presence check

**Headers Checked**:
```python
SECURITY_HEADERS = [
    'X-Frame-Options',                    # Clickjacking protection
    'X-Content-Type-Options',             # MIME sniffing protection
    'X-XSS-Protection',                   # XSS filter
    'Strict-Transport-Security',          # HTTPS enforcement
    'Content-Security-Policy',            # Resource policy
    'X-Permitted-Cross-Domain-Policies'   # Flash policy
]
```

**Analysis Logic**:
```python
def check_security_headers(response):
    missing_headers = []
    present_headers = []
    
    for header in SECURITY_HEADERS:
        if header in response.headers:
            present_headers.append({
                'name': header,
                'value': response.headers[header]
            })
        else:
            missing_headers.append(header)
    
    return {
        'missing': missing_headers,
        'present': present_headers,
        'severity': 'LOW' if missing_headers else 'INFO'
    }
```

**Recommended Values**:
```http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## Implementation Details

### Port Scanning
```python
def check_web_port(ip, port, timeout=3):
    """TCP connect scan"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0  # 0 = success
```

**Default Ports**: 80, 443, 8000, 8080, 8443, 8888, 9090

**Concurrent Scanning**:
```python
with ThreadPoolExecutor(max_workers=workers) as executor:
    futures = {
        executor.submit(scan_host, ip, port): (ip, port)
        for ip in ips
        for port in ports
    }
    
    for future in as_completed(futures):
        result = future.result()
        # Process findings
```

### HTTP Request Handling

**SSL/TLS Bypass**:
```python
import urllib3
from urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Make request with verify=False
response = requests.get(url, verify=False, timeout=5)
```

**Rationale**: Internal pentesting often involves self-signed certificates

**Timeout Management**:
```python
try:
    response = requests.get(url, timeout=timeout)
except requests.exceptions.Timeout:
    # Mark as timeout, continue
    pass
except requests.exceptions.ConnectionError:
    # Host unreachable, skip
    pass
```

### URL Construction
```python
from urllib.parse import urljoin

# Proper URL joining
base_url = 'http://example.com'
path = '/.git/config'
full_url = urljoin(base_url, path)
# Result: http://example.com/.git/config

# Handles edge cases
base_url = 'http://example.com/app/'
path = '/admin'
full_url = urljoin(base_url, path)
# Result: http://example.com/admin (not /app/admin)
```

### Pattern Matching Performance
```python
# Compile regex once for performance
import re

compiled_patterns = {
    info_type: [re.compile(p, re.IGNORECASE) for p in patterns]
    for info_type, patterns in INFO_PATTERNS.items()
}

# Use compiled patterns
for pattern in compiled_patterns[info_type]:
    if pattern.search(content):
        # Match found
```

## Output Formats

### findings.txt (Human-Readable)
```
[CRITICAL] Git Repository Exposed
URL: http://192.168.1.10/.git/HEAD
Description: Full git repository accessible, source code can be extracted
Evidence: ref: refs/heads/master
Recommendation: Remove .git directory from web root immediately
Impact: Complete source code disclosure, potential credential exposure

[HIGH] PHPInfo Page Accessible
URL: http://192.168.1.11/info.php
Description: Detailed PHP configuration exposed
Evidence: PHP Version 7.4.3, System: Linux ubuntu 5.4.0
Recommendation: Remove phpinfo page from production servers
Impact: Information gathering for targeted attacks
```

### git_repos.txt (Machine-Readable)
```
http://192.168.1.10/.git/
http://192.168.1.15/.git/
http://10.0.0.50/.git/
http://internal-app.corp.local/.git/
```

**Format**: One URL per line, ready for piping to git-dumper

### web_details.json (Structured)
```json
{
  "scan_metadata": {
    "start_time": "2025-10-13T15:00:00.123Z",
    "end_time": "2025-10-13T15:45:30.456Z",
    "duration_seconds": 2730,
    "scanner_version": "1.0",
    "scan_options": {
      "full_scan": true,
      "workers": 10,
      "timeout": 5,
      "ports": [80, 443, 8080, 8443, 8888, 9090]
    }
  },
  "statistics": {
    "total_targets": 254,
    "hosts_scanned": 254,
    "web_servers_found": 89,
    "vulnerable_hosts": 23,
    "total_findings": 67,
    "by_severity": {
      "critical": 5,
      "high": 12,
      "medium": 35,
      "low": 15
    },
    "by_type": {
      "git_exposure": 5,
      "backup_files": 18,
      "info_disclosure": 12,
      "directory_listing": 8,
      "missing_headers": 24
    }
  },
  "findings": [
    {
      "host": "192.168.1.10",
      "ip": "192.168.1.10",
      "ports": [80, 443],
      "findings": [
        {
          "id": "GIT-001",
          "type": "git_exposure",
          "severity": "CRITICAL",
          "title": "Git Repository Exposed",
          "url": "http://192.168.1.10/.git/HEAD",
          "method": "GET",
          "status_code": 200,
          "evidence": "ref: refs/heads/master",
          "description": "Full git repository accessible",
          "impact": "Complete source code disclosure",
          "recommendation": "Remove .git directory from web root",
          "references": [
            "CWE-538: Insertion of Sensitive Information into Externally-Accessible File",
            "OWASP-A06:2021 – Vulnerable and Outdated Components"
          ],
          "timestamp": "2025-10-13T15:05:12.789Z"
        }
      ]
    }
  ]
}
```

## Performance Characteristics

### Timing Analysis
**Per-Host Times** (average):
- Port scan: ~100ms per port
- Git check: ~500ms (4 paths)
- Backup check: ~2-5 seconds (25 combinations)
- Info disclosure: ~1-2 seconds (5 paths)
- Common paths: ~3-5 seconds (15 paths)
- Headers: ~500ms (1 request)

**Full Scan**: ~10-15 seconds per host

### Scalability
**Network Size vs Time** (10 workers):
- /30 (4 hosts): ~1 minute
- /24 (254 hosts): ~30-45 minutes
- /16 (65,536 hosts): ~100-150 hours

**Worker Optimization**:
- 10 workers: Balanced (default)
- 50 workers: Fast, higher load
- 100 workers: Very fast, detection risk

### Resource Usage
- **Memory**: ~100-200 MB
- **CPU**: Low (I/O bound)
- **Network**: ~50-100 KB per host
- **Disk**: Output files typically <5 MB per scan

## Detection & Evasion

### Detection Indicators

**Network Patterns**:
```
# Sequential scanning pattern
192.168.1.100 → 80, 443, 8080, 8443, 8888, 9090
192.168.1.101 → 80, 443, 8080, 8443, 8888, 9090
192.168.1.102 → 80, 443, 8080, 8443, 8888, 9090
```

**Web Server Logs**:
```
192.168.1.100 [13/Oct/2025:15:30:00] "GET /.git/HEAD HTTP/1.1" 200
192.168.1.100 [13/Oct/2025:15:30:01] "GET /.git/config HTTP/1.1" 200
192.168.1.100 [13/Oct/2025:15:30:02] "HEAD /index.php.bak HTTP/1.1" 404
192.168.1.100 [13/Oct/2025:15:30:03] "HEAD /config.php.old HTTP/1.1" 200
```

**User-Agent**:
```
python-requests/2.31.0
```

### Evasion Techniques

**Rate Limiting**:
```python
import time

# Add delay between requests
time.sleep(random.uniform(1, 3))
```

**User-Agent Spoofing**:
```python
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}
response = requests.get(url, headers=headers)
```

**Request Ordering Randomization**:
```python
import random

paths = COMMON_PATHS.copy()
random.shuffle(paths)  # Randomize order
```

## Defense Mechanisms

### Web Server Configuration

**Apache (.htaccess)**:
```apache
# Deny access to Git
<DirectoryMatch "^/.*/\.git/">
    Order 'deny,allow'
    Deny from all
</DirectoryMatch>

# Deny backup files
<FilesMatch "\.(bak|old|save|orig|swp|tmp)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Disable directory listing
Options -Indexes

# Add security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000"
```

**Nginx**:
```nginx
# Deny Git access
location ~ /\.git {
    deny all;
    return 404;
}

# Deny SVN access
location ~ /\.svn {
    deny all;
    return 404;
}

# Deny backup files
location ~ \.(bak|old|save|orig|swp|tmp)$ {
    deny all;
    return 404;
}

# Disable directory listing
autoindex off;

# Security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000" always;
```

### WAF Rules (ModSecurity)
```apache
# Block Git access attempts
SecRule REQUEST_URI "@contains /.git" \
    "id:1000,phase:1,deny,status:404,msg:'Git directory access blocked'"

# Block backup file access
SecRule REQUEST_URI "@rx \.(bak|old|save|orig|swp|tmp)$" \
    "id:1001,phase:1,deny,status:404,msg:'Backup file access blocked'"

# Block common admin paths
SecRule REQUEST_URI "@pmFromFile admin_paths.txt" \
    "id:1002,phase:1,deny,status:404,msg:'Admin path probing blocked'"
```

### Monitoring & Alerting
```bash
# Alert on Git access attempts
tail -f /var/log/apache2/access.log | \
    grep -E '\.git' | \
    while read line; do
        echo "[ALERT] Git access attempt: $line" | \
        mail -s "Security Alert" security@company.com
    done
```

## Common Misconfigurations

### 1. Git in Web Root
```bash
# How it happens
cd /var/www/html
git clone https://github.com/company/app.git .
# Result: .git/ directory is web-accessible
```

**Fix**:
```bash
# Clone outside web root
cd /var/www
git clone https://github.com/company/app.git
rsync -av --exclude='.git' app/ html/
```

### 2. Backup Files
```bash
# How it happens
cp config.php config.php.bak  # Quick backup
vim config.php                 # Edit, creates config.php~
# Result: Backup files web-accessible
```

**Fix**:
```bash
# Backup outside web root
cp /var/www/html/config.php /backups/config.php.$(date +%Y%m%d)

# Or use .gitignore patterns
echo "*.bak" >> /var/www/html/.gitignore
echo "*~" >> /var/www/html/.gitignore
```

### 3. Info Pages in Production
```bash
# How it happens
# Developer creates phpinfo.php for debugging
<?php phpinfo(); ?>
# Forgets to remove before production deployment
```

**Fix**:
```bash
# Automated cleanup
find /var/www/html -name "phpinfo.php" -delete
find /var/www/html -name "test.php" -delete
find /var/www/html -name "debug.php" -delete
```

## Error Handling

### HTTP Errors
```python
try:
    response = requests.get(url, timeout=timeout, verify=False)
    
except requests.exceptions.Timeout:
    # Timeout: slow server or network
    log_error(f"Timeout: {url}")
    
except requests.exceptions.ConnectionError:
    # Connection refused: service down or firewalled
    log_error(f"Connection error: {url}")
    
except requests.exceptions.TooManyRedirects:
    # Redirect loop
    log_error(f"Redirect loop: {url}")
    
except requests.exceptions.RequestException as e:
    # Generic error
    log_error(f"Request failed: {url} - {e}")
```

### Socket Errors
```python
import socket

try:
    sock.connect_ex((ip, port))
    
except socket.gaierror:
    # DNS resolution failed
    log_error(f"DNS error: {ip}")
    
except socket.timeout:
    # Connection timeout
    log_error(f"Timeout: {ip}:{port}")
    
except OSError as e:
    # System error (no route, etc.)
    log_error(f"OS error: {ip}:{port} - {e}")
```

## Dependencies

### Required
- **Python 3.6+**
- **requests**: HTTP client library
- **urllib3**: HTTP library with connection pooling
- **socket**: TCP connections (standard library)
- **re**: Regular expressions (standard library)
- **json**: JSON handling (standard library)

### Optional (for exploitation)
- **git-dumper**: Download exposed Git repositories
- **GitTools**: Alternative Git extraction
- **TruffleHog**: Secret scanning in Git repos
- **wget/curl**: File downloading

### Installation
```bash
pip install requests urllib3

# Optional tools
git clone https://github.com/arthaud/git-dumper.git
git clone https://github.com/internetwache/GitTools.git
pip install truffleHog
```

## Use Cases

### 1. Penetration Testing
- Initial web reconnaissance
- Low-hanging fruit identification
- Quick wins for engagement start

### 2. Red Team Operations
- Passive information gathering
- Source code acquisition for analysis
- Credential harvesting from leaked files

### 3. Security Auditing
- Configuration review
- Compliance checking (missing headers)
- Vulnerability assessment

### 4. Bug Bounty Hunting
- Quick triaging of scope
- Git exposure hunting (common bounty)
- Backup file discovery

## Limitations

### Technical Limitations
- No JavaScript execution (no SPAs)
- Limited to HTTP/HTTPS protocols
- No authentication bypass attempts
- Basic pattern matching (may miss complex cases)

### Scope Limitations
- Cannot bypass WAF/IPS
- No brute-forcing capabilities
- No automated exploitation
- No content analysis beyond patterns

### Detection Risk
- Obvious scanning patterns
- High request volume
- Logged User-Agent
- Sequential path probing

## Future Enhancements
- JavaScript rendering for SPAs
- Custom wordlist support
- Authenticated scanning
- Screenshot capture
- Integration with CVE databases
- Advanced WAF evasion
- Distributed scanning
- Machine learning for pattern detection

## References
- **CWE-538**: Insertion of Sensitive Information into Externally-Accessible File
- **OWASP Top 10 2021**: A05:2021 – Security Misconfiguration
- **OWASP Testing Guide**: Information Gathering
- **MITRE ATT&CK**: T1213.002 (Data from Information Repositories: SharePoint)
- **Git-Dumper**: https://github.com/arthaud/git-dumper
- **OWASP Secure Headers Project**: https://owasp.org/www-project-secure-headers/
