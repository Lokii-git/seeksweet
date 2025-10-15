# WebSeek v2 - Smart Reporting Features

## Overview
WebSeek v2 uses Nuclei as its scanning engine and generates **smart, report-ready outputs** specifically designed for penetration testing documentation.

## Key Features

### 🎯 Smart Filtering
Instead of manually sifting through hundreds of findings, WebSeek v2 automatically:
- Groups identical vulnerabilities across multiple hosts
- Sorts by severity and impact
- Generates separate files for each severity level
- Creates ready-to-use IP lists per vulnerability

### 📋 Generated Reports

After a scan, you'll get these files:

#### **For Report Writing (Priority)**
1. **CRITICAL_FINDINGS.txt** - Start here!
   - Only Critical and High severity issues
   - Sorted by severity, then by number of affected hosts
   - Includes:
     - Full description
     - Easy-to-copy IP lists
     - CVE/CWE/CVSS information
     - References for each vulnerability
   - Perfect for cutting and pasting into your pentest report

2. **HIGH_VULNS.txt** / **MEDIUM_VULNS.txt** / **LOW_VULNS.txt**
   - Quick one-liners per vulnerability
   - Shows: Name, Template ID, Affected Hosts (comma-separated)
   - Sorted by number of affected hosts (most impacted first)

#### **For Asset-Based Analysis**
3. **IP_TO_VULNS.txt**
   - Organized by IP address (most vulnerable hosts first)
   - Shows all vulnerabilities per host
   - Severity breakdown per host
   - Great for:
     - Host-based remediation
     - Identifying "crown jewels" (most vulnerable assets)
     - Client presentations

#### **Standard Output**
4. **findings.txt** - Complete detailed list
5. **findings.json** - JSON export for parsing
6. **vulnerable_hosts.txt** - Simple IP list
7. **webseek_report/** - Nuclei's markdown reports (organized by template)

## Usage Examples

```bash
# Full scan (all templates)
./webseek-v2.py

# Critical/High only (faster for quick wins)
./webseek-v2.py --severity critical,high

# CVEs and default credentials (common report items)
./webseek-v2.py --tags cve,default-login

# Specific tags for targeted scanning
./webseek-v2.py --tags exposure,panel,config

# Update templates first
./webseek-v2.py --update
```

## Report Writing Workflow

### Step 1: Run the scan
```bash
./webseek-v2.py --severity critical,high
```

### Step 2: Open CRITICAL_FINDINGS.txt
This file has everything you need:
- **Vulnerability name** - Use as your finding title
- **Description** - Ready-to-use explanation
- **Affected Systems** - Bullet-pointed IP list
- **CVE/CWE/CVSS** - Impact scores
- **References** - For additional research

### Step 3: Copy findings to report
Each vulnerability is formatted like this:

```
================================================================================
[1] [HIGH] HP Printer Default Login
================================================================================

Template ID: hp-printer-default-login
Affected Hosts: 3

AFFECTED SYSTEMS:
----------------------------------------
  • 10.64.51.14
  • 10.64.51.23
  • 10.65.51.138

DESCRIPTION:
----------------------------------------
HP printers allow administrative access without authentication...

CVE ID: CVE-2024-XXXXX
CVSS Score: 7.5

REFERENCES:
----------------------------------------
  • https://...
```

Just copy the sections you need!

### Step 4: Use IP_TO_VULNS.txt for remediation plans
Shows which hosts are most vulnerable - great for prioritization discussions with clients.

## Example Output

From a real scan:
```
SCAN SUMMARY
============================================================

Total Findings: 847
Unique Vulnerabilities: 79
Vulnerable Hosts: 154

Findings by Severity:
  [CRITICAL] 0
  [HIGH] 11
  [MEDIUM] 3
  [LOW] 14
  [INFO] 819

📋 For Report Writing:
  • CRITICAL_FINDINGS.txt     - 11 priority vulnerabilities
  • HIGH_VULNS.txt            - High severity grouped
  
🔍 Detailed Analysis:
  • IP_TO_VULNS.txt          - 154 hosts analyzed
```

## Advanced Filtering

### By Severity
```bash
# Only critical
./webseek-v2.py --severity critical

# Critical + High
./webseek-v2.py --severity critical,high

# Everything except info
./webseek-v2.py --severity critical,high,medium,low
```

### By Tags
Common useful tag combinations:
```bash
# CVEs only
./webseek-v2.py --tags cve

# Default credentials
./webseek-v2.py --tags default-login

# Information disclosure
./webseek-v2.py --tags exposure,disclosure

# Configuration issues
./webseek-v2.py --tags config,misconfig

# Admin panels
./webseek-v2.py --tags panel,admin
```

### Custom Templates
```bash
# Use your own template directory
./webseek-v2.py --templates /path/to/custom/templates/

# Use a specific template file
./webseek-v2.py --templates ~/nuclei-templates/cves/2024/
```

## Performance Tuning

```bash
# Faster scans (more aggressive)
./webseek-v2.py --rate-limit 300 --concurrency 50

# Slower/quieter scans (stealth)
./webseek-v2.py --rate-limit 50 --concurrency 10

# Increase timeout for slow networks
./webseek-v2.py --timeout 30

# Limit total scan time
./webseek-v2.py --max-scan-time 1800  # 30 minutes
```

## Tips

1. **Start with High/Critical** - Get the important findings first
   ```bash
   ./webseek-v2.py --severity critical,high
   ```

2. **CRITICAL_FINDINGS.txt is your friend** - This file alone can populate most of your report findings section

3. **Use IP_TO_VULNS.txt for client meetings** - Shows them which systems are most at risk

4. **Group similar findings** - If you have 20 printers with default logins, that's ONE finding with 20 affected hosts (not 20 findings)

5. **Check the markdown reports** - For proof-of-concept details, check `webseek_report/[vulnerability-name]/`

6. **Update templates regularly**
   ```bash
   ./webseek-v2.py --update
   ```

## Integration with SeekSweet

WebSeek v2 can be run from the SeekSweet orchestrator:
```bash
./seeksweet.py
# Choose WebSeek from menu
```

Or standalone:
```bash
cd webseek
./webseek-v2.py iplist.txt --severity high,critical
```

## CIDR Support

Like all SeekSweet tools, WebSeek v2 supports CIDR notation:
```
# iplist.txt
10.64.0.0/16      # Expands to 65,534 hosts
192.168.1.0/24    # Expands to 254 hosts
10.0.0.50         # Single host
http://test.com   # URLs work too
```

## Comparison: v1 vs v2

| Feature | v1 (Original) | v2 (Nuclei) |
|---------|--------------|-------------|
| Templates | ~50 hardcoded | 5000+ Nuclei |
| CVE Detection | Limited | Comprehensive |
| Updates | Manual code | Auto template updates |
| Report Format | Basic text | Smart grouped reports |
| Speed | Custom engine | Optimized Nuclei |
| Best For | Quick custom scans | Production pentests |

## Troubleshooting

**Nuclei not found?**
```bash
# Install Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

**No findings?**
- Check if targets are reachable
- Try with `--severity info` to see everything
- Check `findings.json` for raw data

**Too much output?**
- Use severity filters: `--severity critical,high`
- Filter by tags: `--tags cve`
- Check only specific templates: `--templates cves/`

## Questions?

Check the Nuclei documentation for template usage:
https://docs.projectdiscovery.io/nuclei/
