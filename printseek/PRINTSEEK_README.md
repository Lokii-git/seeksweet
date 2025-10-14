# PrintSeek v1.0

**Network Printer Discovery and Enumeration Tool**

PrintSeek is a comprehensive pentesting tool designed to discover network printers and extract configuration details via SNMP and web interfaces.

## Features

### 🔍 Discovery Phase
- Fast multi-threaded port scanning
- Identifies printers by checking common ports:
  - 9100 (HP JetDirect)
  - 515 (LPD/LPR)
  - 631 (IPP/CUPS)
  - 161 (SNMP)
  - 80/443 (Web Interface)
  - 8080 (Alt Web)
  - 21 (FTP)
- Confidence scoring (High/Medium/Low)
- Hostname resolution
- CIDR notation support

### 📋 Enumeration Phase
- Automated SNMP queries (v2c)
- Extracts printer information:
  - Printer name and model
  - Serial number
  - Location and contact
  - Page count
  - System description and uptime
- Web interface title grabbing
- Custom SNMP community support

## Installation

### Prerequisites (Kali Linux)
```bash
# Install SNMP tools
sudo apt update
sudo apt install snmp snmp-mibs-downloader

# Enable MIBs (optional but recommended)
sudo sed -i 's/mibs :/# mibs :/' /etc/snmp/snmp.conf
```

### Make Script Executable
```bash
chmod +x printseek.py
```

## Usage

### Basic Discovery
```bash
# Scan IPs from iplist.txt and find printers
./printseek.py

# Use custom IP list
./printseek.py -f targets.txt

# Verbose mode
./printseek.py -v
```

### With Custom SNMP Community
```bash
# Use 'private' community string
./printseek.py -c private

# Try multiple communities (run multiple times)
./printseek.py -c public
./printseek.py -c private
./printseek.py -c community
```

### SNMP-Only Mode
```bash
# Skip discovery, enumerate printers from printerlist.txt
./printseek.py --snmp-only -c private
```

### Advanced Options
```bash
# Full control
./printseek.py \
  -f iplist.txt \          # Input IP file
  -w 20 \                  # 20 concurrent workers
  -t 2 \                   # 2 second timeout
  -c private \             # SNMP community
  -o printer_info.txt \    # Custom output file
  -v                       # Verbose mode
```

## Output Files

### Discovery Output
- **`printerlist.txt`** - Simple list of printer IPs (one per line)
- **`printer_details.txt`** - Detailed printer information
- **`printer_details.json`** - JSON format for automation
- **Console output** - Real-time discovery results

### Example Output Structure
```
Internal/
├── printseek.py
├── iplist.txt
├── printerlist.txt              # List of printer IPs
├── printer_details.txt          # Detailed printer info
└── printer_details.json         # JSON format
```

## Confidence Levels

PrintSeek assigns confidence scores:

### High Confidence
- JetDirect (9100) OR IPP (631) port open
- AND SNMP data retrieved
- Most reliable indicators

### Medium Confidence
- Two or more printer ports open (515, 631, 161, 9100)
- OR SNMP port + printer-related hostname
- Likely a printer

### Low Confidence
- Single printer port open
- Needs manual verification

## Workflow Examples

### Full Discovery Workflow
```bash
# 1. Discover printers from network range
echo "192.168.1.0/24" > iplist.txt
./printseek.py -v

# 2. Review findings
cat printerlist.txt
cat printer_details.txt

# 3. Re-enumerate with different community
./printseek.py --snmp-only -c private
```

### Quick Printer Census
```bash
# Find all printers
./printseek.py

# View summary
cat printer_details.json | jq -r '.[] | "\(.ip) - \(.snmp_info.model // "Unknown")"'
```

### Integration with Other Tools
```bash
# Get printer list
./printseek.py
cat printerlist.txt

# Nmap detailed scan
nmap -sV -p 21,80,161,443,515,631,9100 -iL printerlist.txt -oA printer_scan

# PRET (Printer Exploitation Toolkit)
while read ip; do
  python pret.py $ip pjl
done < printerlist.txt
```

## Extracted Information

### Via SNMP
- **Printer Name** - System name (sysName)
- **Model** - Device description
- **Serial Number** - Hardware serial
- **Location** - Physical location (if configured)
- **Contact** - Admin contact info
- **Page Count** - Total pages printed
- **Description** - System description
- **Uptime** - How long printer has been running

### Via Web Interface
- **Web Title** - HTML title of web interface
- **Printer Type Detection** - Keywords in HTML

### Via Port Scanning
- **Open Services** - Which printer protocols available
- **Service Types** - JetDirect, IPP, LPD, SNMP, HTTP/HTTPS

## Error Handling

PrintSeek includes comprehensive error handling:
- Invalid IP/CIDR detection
- Network timeout management
- File permission checks
- Missing dependencies detection (snmpget)
- Keyboard interrupt (Ctrl+C) support
- Graceful failure recovery
- SNMP timeout handling

## Performance Tuning

### Scanning Speed
```bash
# Fast scan (more workers, lower timeout)
./printseek.py -w 50 -t 0.5

# Thorough scan (fewer workers, higher timeout)
./printseek.py -w 5 -t 3
```

### Large Networks
```bash
# For /16 or larger networks
echo "10.0.0.0/16" > iplist.txt
./printseek.py -w 100 -t 0.5
```

## Common SNMP Communities

Try these common community strings:
- `public` (default, read-only)
- `private` (often read-write)
- `admin`
- `community`
- Company name
- `0` or `1`

## Troubleshooting

### snmpget not found
```bash
# Install SNMP tools
sudo apt install snmp

# Verify installation
which snmpget
```

### No SNMP data
- Try different community strings
- Check if SNMP is enabled on printer
- Verify port 161 is open
- Some printers disable SNMP by default

### Permission denied errors
```bash
# Make script executable
chmod +x printseek.py

# Check write permissions
ls -la .
```

### No printers found
- Verify network connectivity
- Check if IPs are reachable: `ping <ip>`
- Try verbose mode: `-v`
- Increase timeout: `-t 3`
- Check firewall rules

### Web title not grabbed
- Normal for printers without web interface
- Some require authentication
- May have non-standard web ports

## Security Considerations

⚠️ **Important**: This tool is for authorized penetration testing only.

- Obtain proper authorization before scanning
- Scanning may trigger IDS/IPS alerts
- SNMP queries are logged by many devices
- Store results securely (contains network topology)
- Some printers log access to web interface
- Follow responsible disclosure practices

## SNMP OIDs Reference

Common printer SNMP OIDs used:
```
1.3.6.1.2.1.1.1.0    - sysDescr (Description)
1.3.6.1.2.1.1.5.0    - sysName (Name)
1.3.6.1.2.1.1.6.0    - sysLocation (Location)
1.3.6.1.2.1.1.4.0    - sysContact (Contact)
1.3.6.1.2.1.1.3.0    - sysUpTime (Uptime)
1.3.6.1.2.1.25.3.2.1.3.1    - hrDeviceDescr (Model)
1.3.6.1.2.1.43.5.1.1.17.1   - prtGeneralSerialNumber
1.3.6.1.2.1.43.10.2.1.4.1.1 - prtMarkerLifeCount (Page Count)
```

## Output Format Examples

### printerlist.txt
```
192.168.1.50
192.168.1.51
192.168.1.52
```

### printer_details.txt
```
PrintSeek - Network Printers Found
======================================================================
Scan Date: 2025-10-13 15:30:45
Total Printers Found: 3
======================================================================

IP: 192.168.1.50
Hostname: HP-LaserJet-4050.corp.local
Confidence: HIGH
Open Ports: 9100 (HP JetDirect), 161 (SNMP), 80 (Web Interface)
Web Title: HP LaserJet 4050
Printer Name: HP-LJ-4050-Floor2
Model: HP LaserJet 4050
Serial Number: USAQ123456
Location: 2nd Floor, IT Department
Contact: it-admin@corp.local
Page Count: 145678

----------------------------------------------------------------------
```

### printer_details.json
```json
[
  {
    "ip": "192.168.1.50",
    "hostname": "HP-LaserJet-4050.corp.local",
    "open_ports": {
      "9100": "HP JetDirect",
      "161": "SNMP",
      "80": "Web Interface"
    },
    "is_likely_printer": true,
    "confidence": "high",
    "snmp_info": {
      "name": "HP-LJ-4050-Floor2",
      "model": "HP LaserJet 4050",
      "serial": "USAQ123456",
      "location": "2nd Floor, IT Department",
      "contact": "it-admin@corp.local",
      "page_count": "145678",
      "description": "HP ETHERNET MULTI-ENVIRONMENT"
    },
    "web_title": "HP LaserJet 4050"
  }
]
```

## Integration Examples

### With Nmap
```bash
./printseek.py
nmap -sV -sC -p 9100,161,631 -iL printerlist.txt
```

### Extract Locations
```bash
cat printer_details.json | jq -r '.[] | "\(.snmp_info.location // "Unknown") - \(.ip)"'
```

### Find High Page Count
```bash
cat printer_details.json | jq -r '.[] | select(.snmp_info.page_count != null) | "\(.ip): \(.snmp_info.page_count) pages"'
```

### List All Models
```bash
cat printer_details.json | jq -r '.[].snmp_info.model' | sort -u
```

## Attack Vectors (For Authorized Testing)

After finding printers, test for:
1. **Default credentials** on web interface
2. **SNMP write access** (community string 'private')
3. **PostScript/PJL injection** (via port 9100)
4. **Stored documents** in printer memory
5. **File system access** via FTP (port 21)
6. **Cross-site printing** (send jobs remotely)
7. **Firmware vulnerabilities** (check model/version)

## Related Tools

- **PRET** - Printer Exploitation Toolkit
- **Praeda** - Automated printer data harvesting
- **Nmap** - Network scanning
- **Metasploit** - Printer exploit modules
- **snmpwalk** - Manual SNMP enumeration

## Tips & Tricks

1. **Try multiple community strings** - Run with different `-c` values
2. **Check web interfaces** - Many printers have admin panels
3. **Look for locations** - SNMP location field often reveals floor plans
4. **Page counts** - High counts = frequently used = important
5. **Serial numbers** - Useful for warranty lookups and model info
6. **Contact info** - May reveal admin email addresses

## Version History

### v1.0 (Current)
- Initial release
- Multi-threaded printer discovery
- SNMP enumeration (v2c)
- Web interface detection
- Confidence scoring
- JSON export
- SNMP-only mode

## Contributing

Improvements welcome:
- SNMPv3 support
- Additional OID queries
- IPP enumeration
- Web interface crawling
- Credential testing

## License

Use responsibly. For authorized security assessments only.

---

**Author**: Internal Red Team  
**Last Updated**: October 2025  
**Tested On**: Kali Linux 2024+
