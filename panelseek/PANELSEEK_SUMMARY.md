# PanelSeek Summary

## Overview
PanelSeek is a Python-based reconnaissance tool for discovering exposed web-based admin panels across network environments. It identifies 40+ panel types including routers, firewalls, switches, management consoles, and application dashboards.

## Core Capabilities

### Discovery Engine
- **Multi-threaded web scanning** using ThreadPoolExecutor (10 workers default, configurable 1-100)
- **11 default ports**: 80, 443, 8080, 8443, 8000, 8888, 9090, 10000, 3000, 5000, 4443
- **30+ admin paths** checked (/, /admin, /login, /console, /dashboard, etc.)
- **Scan modes**: Quick (3 paths), Default (7 paths), Full (30+ paths)
- **SSL/TLS handling** with self-signed certificate support
- **Hostname resolution** via reverse DNS lookup

### Panel Identification
- **40+ vendor signatures** including:
  - Network: Cisco, Juniper, pfSense, FortiGate, Palo Alto, SonicWall, WatchGuard
  - Routers: Netgear, TP-Link, Ubiquiti, MikroTik, DD-WRT, OpenWrt, Tomato
  - Management: VMware, iDRAC, iLO, IPMI, Webmin, cPanel, Plesk, Proxmox
  - Applications: Jenkins, Grafana, Kibana, Portainer, Kubernetes, Docker
  - Databases: phpMyAdmin, Adminer, MongoDB Express

### Intelligence Extraction
- **Web title parsing** from HTML <title> tags
- **Vendor identification** via regex pattern matching
- **Authentication detection** (login forms, HTTP auth)
- **Default credentials flagging** for common panels
- **Confidence scoring**: High (+++), Medium (++), Low (+)
- **HTTP status tracking** (200, 301, 302, 401, 403)
- **Redirect chain following**

## Technical Architecture

### Key Functions
```python
read_ip_list()          # Parse IPs/CIDR from input file
check_port()            # TCP connectivity check with timeout
get_hostname()          # Reverse DNS lookup
fetch_web_page()        # HTTP/HTTPS GET with SSL handling
identify_panel()        # Pattern matching against signatures
scan_host()             # Main per-host scanning logic
save_panel_list()       # Write URLs to panellist.txt
save_panel_details()    # Export TXT and JSON results
```

### Data Structures
- **ADMIN_PORTS** (dict): Port → service type mapping
- **PANEL_SIGNATURES** (dict): Panel type → regex patterns
- **ADMIN_PATHS** (list): 30+ common admin paths
- **Results**: List of dicts with IP, hostname, panels, errors

### Dependencies
- **Standard Library Only**: http.client, ssl, socket, ipaddress, threading, json, argparse
- **No external tools required** (unlike DCSeek/PrintSeek)

## Comparison with Other Seek Tools

| Feature | DCSeek | PrintSeek | PanelSeek |
|---------|--------|-----------|-----------|
| **Target** | Domain Controllers | Printers | Admin Panels |
| **Protocols** | LDAP, Kerberos, SMB | SNMP, HTTP | HTTP/HTTPS |
| **Ports** | 88, 389, 445 | 161, 80, 443, 515, 631, 9100 | 80, 443, 8080, 8443, etc. |
| **External Tools** | enum4linux | snmpget | None |
| **Enumeration** | Users, shares, policies | Model, serial, location | Panel type, vendor, auth |
| **Output Files** | dclist.txt, JSON | printerlist.txt, JSON | panellist.txt, JSON |
| **Confidence Scoring** | No | Yes (High/Med/Low) | Yes (High/Med/Low) |
| **Default Creds Flag** | No | No | Yes |

## Command-Line Interface

### Arguments
```
-f, --file FILE         Input file (default: iplist.txt)
-w, --workers N         Thread count (default: 10, range: 1-100)
-t, --timeout N         Connection timeout seconds (default: 2)
    --ports [PORTS...]  Custom port list
    --quick             Quick mode (3 paths)
    --full              Full mode (30+ paths)
-v, --verbose           Show all hosts (not just panels)
```

### Usage Examples
```bash
./panelseek.py                    # Basic scan
./panelseek.py --full -v          # Comprehensive verbose
./panelseek.py --quick -w 50      # Fast scan
./panelseek.py --ports 80 443     # HTTP/HTTPS only
./panelseek.py -f targets.txt     # Custom input
```

## Output Formats

### panellist.txt (URLs)
```
http://192.168.1.1:80/
https://192.168.1.10:443/admin
http://192.168.1.50:8080/console
```

### panel_details.txt (Human-Readable)
```
Host: 192.168.1.1
Hostname: router.corp.local
Panels Found: 1

  URL: http://192.168.1.1:80/
  Status: 200
  Panel Type: Tp Link
  Confidence: HIGH
  Vendor: Tp Link
  Title: TP-Link Wireless Router WR841N
  Auth Required: Yes
  ⚠ DEFAULT CREDENTIALS LIKELY
```

### panel_details.json (Automation)
```json
{
  "ip": "192.168.1.1",
  "hostname": "router.corp.local",
  "panels": [{
    "url": "http://192.168.1.1:80/",
    "status_code": 200,
    "panel_type": "tp_link",
    "vendor": "Tp Link",
    "confidence": "high",
    "default_creds_likely": true
  }]
}
```

## Use Cases

### Internal Penetration Testing
1. **Asset Discovery**: Map all web-based admin interfaces
2. **Attack Surface Assessment**: Identify exposed management consoles
3. **Default Credentials Testing**: Flag panels likely using defaults
4. **Vulnerability Assessment**: Cross-reference versions with CVEs

### Network Security Audits
1. **Compliance Checking**: Find unauthorized admin panels
2. **Segmentation Testing**: Verify management networks isolated
3. **Configuration Review**: Check for weak authentication

### Red Team Operations
1. **Initial Recon**: Quick wins via default creds
2. **Lateral Movement**: Identify management interfaces
3. **Privilege Escalation**: Target high-value panels

## Workflow Integration

### Typical Assessment Flow
```bash
# 1. Discovery phase
./dcseek.py               # Find domain infrastructure
./printseek.py            # Map printers
./panelseek.py --full     # Locate admin panels

# 2. Enumeration
./dcseek.py -e            # Enumerate domain
./printseek.py -e         # SNMP enumeration

# 3. Panel analysis
grep "DEFAULT CREDS" panel_details.txt
eyewitness -f panellist.txt --web

# 4. Exploitation (authorized only)
# Test default credentials
# Check for CVEs
# Manual testing
```

### Tool Chaining
```bash
# Extract high-value targets
cat panel_details.json | jq -r '.[] | .panels[] | select(.confidence == "high") | .url'

# Screenshot all panels
eyewitness -f panellist.txt --web --no-prompt

# Detailed port scan
cat panellist.txt | sed 's|http[s]*://||' | cut -d: -f1 | sort -u > panel_ips.txt
nmap -sV -sC -A -iL panel_ips.txt
```

## Security Implications

### For Defenders
- **Findings = Immediate Risks**: Every panel found is potential entry point
- **Default Credentials**: Often unchanged, especially on network devices
- **Attack Surface**: Exposed management interfaces are prime targets
- **Mitigation Priority**: 
  1. Change default credentials
  2. Restrict access to management networks
  3. Implement strong authentication
  4. Enable logging and monitoring

### For Penetration Testers
- **High-Value Targets**: Management consoles = privileged access
- **Low-Hanging Fruit**: Default creds on routers/switches
- **Evidence Collection**: Screenshot all panels for report
- **Responsible Testing**: Don't lock accounts, avoid DoS

## Performance Characteristics

### Speed Benchmarks (approximate)
- **/24 network (256 hosts)**: 2-5 minutes (default mode)
- **/16 network (65k hosts)**: 2-4 hours (quick mode, 50 workers)
- **Quick mode**: ~3-10 seconds per host
- **Full mode**: ~20-60 seconds per host

### Optimization Tips
- **Quick mode** for large networks (>1000 hosts)
- **Increase workers** for faster scanning (-w 50)
- **Reduce timeout** for responsive networks (-t 1)
- **Custom ports** to focus scan (--ports 80 443)

## Error Handling

### Graceful Degradation
- **Invalid IPs/CIDR**: Validated and skipped with warning
- **SSL certificate errors**: Handled via unverified context
- **Connection timeouts**: Logged but don't stop scan
- **HTTP errors**: Captured in error field of JSON
- **Keyboard interrupt**: Clean shutdown with stats

### Logging
- **Real-time progress**: Console updates during scan
- **Error tracking**: Per-host errors in JSON output
- **Summary statistics**: Total hosts, panels found, errors

## Implementation Highlights

### SSL/TLS Handling
```python
ssl_context = ssl._create_unverified_context()
conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ssl_context)
```

### Pattern Matching
```python
PANEL_SIGNATURES = {
    'cisco': {
        'patterns': [
            r'cisco',
            r'<title>Cisco\s',
            r'ciscologo'
        ],
        'vendor': 'Cisco',
        'confidence': 'high'
    },
    # ... 40+ more signatures
}
```

### Confidence Scoring Logic
- **High**: Known vendor signature + multiple indicators
- **Medium**: Auth page detected OR generic admin keywords
- **Low**: Minimal indicators (single keyword match)

## Limitations

### Current Constraints
- **No JavaScript rendering**: Can't handle dynamic/SPA panels
- **No credential testing**: Only flags likely defaults, doesn't test
- **Basic pattern matching**: May miss obfuscated panels
- **No stealth mode**: Generates significant web traffic

### Future Enhancements
- Selenium/Puppeteer for JavaScript panels
- Automated default credential testing
- Screenshot capture integration
- Stealth scanning with delays
- Custom user agents
- Additional panel signatures
- Version detection improvements

## Best Practices

### For Effective Scanning
1. **Start with quick mode** to get initial overview
2. **Use full mode** for comprehensive assessments
3. **Always check default credentials** on found panels
4. **Screenshot everything** for documentation
5. **Cross-reference vendors** with CVE databases
6. **Verify findings manually** (especially low confidence)
7. **Store results securely** (contains sensitive data)

### For Reporting
1. **Group by confidence level** for prioritization
2. **Include screenshots** of panel login pages
3. **Note default credential risks** prominently
4. **Provide specific remediation** per panel type
5. **Export JSON for metrics** (counts by vendor, etc.)

## Version Information
- **Current Version**: 1.0
- **Release Date**: October 2025
- **Platform**: Kali Linux 2024+
- **Python Version**: 3.6+
- **Dependencies**: Standard library only

## Related Documentation
- **PANELSEEK_README.md** - Complete user guide
- **PANELSEEK_QUICKREF.txt** - Quick command reference
- **SEEK_TOOLS_OVERVIEW.md** - Suite comparison
- **SEEK_TOOLS_README.md** - Master documentation
