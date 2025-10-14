# PanelSeek v1.0

**Exposed Admin Panel Discovery Tool**

PanelSeek is a comprehensive pentesting tool designed to discover web-based admin interfaces including routers, firewalls, switches, management consoles, and application dashboards.

## Features

### 🔍 Discovery Phase
- Fast multi-threaded web scanning
- Identifies admin panels on common ports:
  - 80, 443 (HTTP/HTTPS)
  - 8080, 8443 (Alt HTTP/HTTPS)
  - 8000, 8888, 9090, 10000
  - 3000, 5000, 4443
- Multiple path checking per port
- Handles SSL/TLS (self-signed certs)
- Hostname resolution

### 🎯 Identification
- Recognizes 40+ panel types including:
  - **Network:** Cisco, Juniper, pfSense, FortiGate, Palo Alto, SonicWall
  - **Routers:** Netgear, TP-Link, Ubiquiti, MikroTik, DD-WRT, OpenWrt
  - **Management:** VMware, iDRAC, iLO, IPMI, Webmin, cPanel, Proxmox
  - **Applications:** Jenkins, Grafana, Kibana, Portainer, Kubernetes
  - **Databases:** phpMyAdmin, Adminer, MongoDB Express
- Confidence scoring (High/Medium/Low)
- Authentication detection
- Default credentials likelihood

### 📊 Intelligence Gathering
- Extracts page titles
- Identifies panel vendor/type
- Detects authentication requirements
- Flags panels likely using default creds
- Tracks redirects
- HTTP status codes

## Installation

### Prerequisites (Kali Linux)
```bash
# PanelSeek uses Python standard library
# No additional packages required!
python3 --version  # Verify Python 3.6+
```

### Make Script Executable
```bash
chmod +x panelseek.py
```

## Usage

### Basic Discovery
```bash
# Scan IPs from iplist.txt
./panelseek.py

# Verbose mode (show all hosts)
./panelseek.py -v

# Custom input file
./panelseek.py -f targets.txt
```

### Scan Modes
```bash
# Quick scan (only /, /admin, /login)
./panelseek.py --quick

# Full scan (all ~30 paths)
./panelseek.py --full

# Balanced scan (default - 7 common paths)
./panelseek.py
```

### Custom Options
```bash
# Custom ports
./panelseek.py --ports 80 443 8080

# Performance tuning
./panelseek.py -w 20 -t 3  # 20 workers, 3s timeout

# Everything custom
./panelseek.py \
  -f targets.txt \
  --ports 80 443 8080 10000 \
  -w 25 \
  -t 2 \
  --full \
  -v
```

## Output Files

### Discovery Output
- **`panellist.txt`** - Simple list of panel URLs (one per line)
- **`panel_details.txt`** - Human-readable detailed information
- **`panel_details.json`** - JSON format for automation
- **Console output** - Real-time discovery with confidence levels

### Example Output Structure
```
Internal/
├── panelseek.py
├── iplist.txt
├── panellist.txt              # List of panel URLs
├── panel_details.txt          # Detailed panel info
└── panel_details.json         # JSON format
```

## Confidence Levels

PanelSeek assigns confidence scores:

### High Confidence [+++]
- Known vendor signature detected (Cisco, FortiGate, etc.)
- Multiple indicators match
- Most reliable

### Medium Confidence [++]
- Authentication page detected
- Generic admin panel indicators
- Worth investigating

### Low Confidence [+]
- Minimal indicators
- May be false positive
- Requires manual verification

## Detected Panel Types

### Network Devices
- Cisco (routers, switches, ASA)
- Juniper (JUNOS, SRX)
- pfSense
- FortiGate/Fortinet
- Palo Alto Networks
- SonicWall
- WatchGuard
- Netgear
- TP-Link
- Ubiquiti (UniFi, EdgeOS)
- MikroTik (RouterOS)
- DD-WRT
- OpenWrt
- Tomato

### Management Interfaces
- VMware (vSphere, ESXi, vCenter)
- Dell iDRAC
- HP iLO
- IPMI (Supermicro, etc.)
- Webmin
- cPanel/WHM
- Plesk
- Proxmox VE

### Application Dashboards
- Jenkins
- Grafana
- Kibana
- Prometheus
- Portainer
- Rancher
- Kubernetes Dashboard
- Docker

### Database Admin Tools
- phpMyAdmin
- Adminer
- MongoDB Express

## Workflow Examples

### Full Network Assessment
```bash
# 1. Discover admin panels
echo "192.168.1.0/24" > iplist.txt
./panelseek.py --full -v

# 2. Review findings
cat panellist.txt
cat panel_details.txt

# 3. Check for default credentials
grep "DEFAULT CREDS" panel_details.txt
```

### Quick Check
```bash
# Fast scan of specific hosts
./panelseek.py --quick -w 50
```

### Integration with Other Tools
```bash
# Get panel URLs
./panelseek.py
cat panellist.txt

# Screenshot panels (with EyeWitness)
eyewitness -f panellist.txt --web

# Try default credentials (with hydra)
# Extract IPs with likely default creds
cat panel_details.json | jq -r '.[] | select(.panels[].default_creds_likely == true) | .panels[].url'

# Nmap detailed scan
cat panellist.txt | sed 's|http[s]*://||' | cut -d: -f1 | sort -u > panel_ips.txt
nmap -sV -sC -iL panel_ips.txt
```

## Common Default Credentials

When `DEFAULT CREDS LIKELY` is flagged, try:

### Routers/Switches
- **Cisco:** admin/admin, admin/cisco
- **Netgear:** admin/password
- **TP-Link:** admin/admin
- **Ubiquiti:** ubnt/ubnt
- **MikroTik:** admin/(blank)
- **DD-WRT:** root/admin

### Management
- **Webmin:** root/(root password)
- **Jenkins:** admin/admin
- **Tomcat:** admin/admin, tomcat/tomcat

### Applications
- **Grafana:** admin/admin
- **Kibana:** elastic/changeme
- **Portainer:** admin/(set on first login)

## Checked Paths

### Quick Mode (3 paths)
```
/, /admin, /login
```

### Default Mode (7 paths)
```
/, /admin, /login, /admin.php, /administrator, /console, /dashboard
```

### Full Mode (30+ paths)
```
/, /admin, /login, /admin.php, /administrator, /wp-admin, /admin/login,
/user/login, /console, /dashboard, /management, /config, /system, /setup,
/cgi-bin, /web, /ui, /portal, /api, /manager/html, /phpmyadmin,
/adminer.php, /webmin, /cpanel, /plesk, /admin/index.php, /login.php, /signin
```

## Error Handling

PanelSeek handles:
- Invalid IP/CIDR detection
- SSL/TLS certificate errors (self-signed)
- Network timeouts
- Connection refused
- HTTP errors gracefully
- File permission issues
- Keyboard interrupts (Ctrl+C)

## Performance Tuning

### Scanning Speed
```bash
# Fast scan
./panelseek.py -w 50 -t 1 --quick

# Balanced (default)
./panelseek.py -w 10 -t 2

# Thorough
./panelseek.py -w 5 -t 5 --full
```

### Large Networks
```bash
# For /16 or larger
./panelseek.py -w 100 -t 1 --quick
```

## Troubleshooting

### No panels found
- Try `--full` for more paths
- Increase timeout `-t 5`
- Check network connectivity
- Try verbose mode `-v`
- Verify ports are accessible

### Too many false positives
- Use `--quick` mode
- Filter by confidence level
- Review `panel_details.json`

### Scan too slow
- Reduce workers `-w 5`
- Increase timeout `-t 3`
- Use `--quick` mode
- Reduce number of IPs

### Permission denied
```bash
chmod +x panelseek.py
```

## Security Considerations

⚠️ **Important**: This tool is for authorized penetration testing only.

- Obtain proper authorization before scanning
- Web scanning generates significant traffic
- Access attempts are logged by web servers
- May trigger IDS/IPS alerts
- WAFs may block aggressive scanning
- Some panels rate-limit login attempts
- Store results securely
- Follow responsible disclosure

## Output Format Examples

### panellist.txt
```
http://192.168.1.1:80/
https://192.168.1.10:443/admin
http://192.168.1.50:8080/console
https://192.168.1.100:10000/
```

### panel_details.txt
```
PanelSeek - Exposed Admin Panels Found
======================================================================
Scan Date: 2025-10-13 16:45:30
Total Hosts with Panels: 5
Total Panels Found: 7
======================================================================

Host: 192.168.1.1
Hostname: router.corp.local
Panels Found: 1
----------------------------------------------------------------------

  URL: http://192.168.1.1:80/
  Status: 200
  Panel Type: Tp Link
  Confidence: HIGH
  Vendor: Tp Link
  Title: TP-Link Wireless Router WR841N
  Auth Required: Yes
  ⚠ DEFAULT CREDENTIALS LIKELY - Try common passwords
  Indicators: TP-Link, Login

======================================================================
```

### panel_details.json
```json
[
  {
    "ip": "192.168.1.1",
    "hostname": "router.corp.local",
    "panels": [
      {
        "port": 80,
        "path": "/",
        "protocol": "http",
        "url": "http://192.168.1.1:80/",
        "status_code": 200,
        "panel_type": "tp_link",
        "vendor": "Tp Link",
        "title": "TP-Link Wireless Router WR841N",
        "auth_required": true,
        "default_creds_likely": true,
        "confidence": "high",
        "indicators": ["TP-Link", "Login"],
        "redirects_to": null
      }
    ],
    "error": null
  }
]
```

## Integration Examples

### With EyeWitness
```bash
./panelseek.py
eyewitness -f panellist.txt --web --no-prompt
```

### With Burp Suite
```bash
# Import URLs into Burp target scope
cat panellist.txt
```

### Extract by Type
```bash
# Find all Cisco panels
cat panel_details.json | jq -r '.[] | select(.panels[].vendor == "Cisco") | .panels[].url'

# Find panels with default creds likely
cat panel_details.json | jq -r '.[] | .panels[] | select(.default_creds_likely == true) | .url'

# Find all HTTPS panels
grep "^https://" panellist.txt

# Group by vendor
cat panel_details.json | jq -r '.[] | .panels[].vendor' | sort | uniq -c | sort -rn
```

## Attack Vectors (For Authorized Testing)

After finding panels, test for:
1. **Default credentials** - Try vendor defaults
2. **Weak passwords** - admin, password, 123456
3. **Known vulnerabilities** - CVE lookups by vendor/version
4. **Configuration issues** - Anonymous access
5. **Information disclosure** - Version numbers, usernames
6. **Directory traversal** - Path manipulation
7. **Authentication bypass** - SQL injection, etc.

## Related Tools

- **EyeWitness** - Screenshot web interfaces
- **Burp Suite** - Web application testing
- **Hydra** - Credential brute forcing
- **Metasploit** - Exploitation frameworks
- **Nikto** - Web server scanner

## Tips & Tricks

1. **Use --full for thorough assessments** - Finds more panels
2. **Check default credentials first** - Often still in use
3. **Screenshot everything** - Use EyeWitness
4. **Look for version numbers** - Search for CVEs
5. **Check HTTP headers** - May reveal additional info
6. **Try common paths** - /backup, /old, /test
7. **Note redirect locations** - May reveal additional URLs

## Version History

### v1.0 (Current)
- Initial release
- 40+ panel type signatures
- Multi-threaded discovery
- SSL/TLS support
- Confidence scoring
- Default credentials detection
- JSON export

## Contributing

Improvements welcome:
- Additional panel signatures
- More default paths
- Better identification logic
- Additional output formats
- Credential testing integration

## License

Use responsibly. For authorized security assessments only.

---

**Author**: Internal Red Team  
**Last Updated**: October 2025  
**Tested On**: Kali Linux 2024+
