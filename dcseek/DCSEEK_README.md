# DCSeek v1.1

**Domain Controller Discovery Tool with Enum4linux Integration**

DCSeek is a comprehensive pentesting tool designed to discover Active Directory Domain Controllers and enumerate users and SMB shares.

## Features

### 🔍 Discovery Phase
- Fast multi-threaded port scanning
- Identifies DCs by checking critical services:
  - Kerberos (88)
  - LDAP (389)
  - SMB (445)
  - DNS (53)
  - LDAPS (636)
  - Global Catalog (3268/3269)
- Hostname resolution
- DNS SRV record validation
- CIDR notation support

### 📋 Enumeration Phase
- Automated enum4linux execution on discovered DCs
- Parses and extracts:
  - Domain users
  - SMB shares
  - Domain groups
  - Password policies
  - OS information
  - Domain name
- Raw and parsed output saved

## Installation

### Prerequisites (Kali Linux)
```bash
# Install enum4linux if not present
sudo apt update
sudo apt install enum4linux

# Or install enum4linux-ng (newer version)
sudo apt install enum4linux-ng
```

### Make Script Executable
```bash
chmod +x dcseek.py
```

## Usage

### Basic Discovery
```bash
# Scan IPs from iplist.txt and find DCs
./dcseek.py

# Use custom IP list
./dcseek.py -f targets.txt

# Verbose mode
./dcseek.py -v
```

### Discovery with Enumeration
```bash
# Discover DCs and run enum4linux on each
./dcseek.py --enum

# Use custom options
./dcseek.py -f targets.txt --enum --enum-dir my_results -v
```

### Enumeration Only Mode
```bash
# Skip discovery, enumerate DCs from dclist.txt
./dcseek.py --enum-only
```

### Advanced Options
```bash
# Full control
./dcseek.py \
  -f iplist.txt \          # Input IP file
  -w 20 \                  # 20 concurrent workers
  -t 2 \                   # 2 second timeout
  -o results.txt \         # Custom output file
  --dclist mydc.txt \      # Custom DC list file
  --enum \                 # Run enumeration
  --enum-dir enum_output \ # Enum output directory
  -v                       # Verbose mode
```

## Output Files

### Discovery Output
- **`dclist.txt`** - Simple list of discovered DC IPs (one per line)
- **`domain_controllers.txt`** - Detailed DC information with ports and services
- **Console output** - Real-time discovery results

### Enumeration Output
- **`enum4linux_results/`** - Directory containing raw enum4linux output
  - `enum4linux_<IP>.txt` - Full enum4linux output per DC
- **`enum4linux_summary.txt`** - Human-readable summary of all findings
- **`enum4linux_summary.json`** - Machine-parsable JSON summary

### Example Output Structure
```
Internal/
├── dcseek.py
├── iplist.txt
├── dclist.txt                    # List of DC IPs
├── domain_controllers.txt        # Detailed DC info
├── enum4linux_summary.txt        # Parsed enumeration results
├── enum4linux_summary.json       # JSON format
└── enum4linux_results/           # Raw enum4linux output
    ├── enum4linux_192_168_1_10.txt
    └── enum4linux_10_0_0_5.txt
```

## Workflow Examples

### Full Pentest Workflow
```bash
# 1. Discover DCs from network range
echo "192.168.1.0/24" > iplist.txt
./dcseek.py --enum -v

# 2. Review findings
cat dclist.txt
cat enum4linux_summary.txt

# 3. Re-enumerate specific DCs
echo "192.168.1.10" > dclist.txt
./dcseek.py --enum-only
```

### Quick User Enumeration
```bash
# Find DCs and enumerate users
./dcseek.py --enum

# Extract just usernames for further attacks
grep "  - " enum4linux_summary.txt | grep -A 100 "Users Found"
```

### Integration with Other Tools
```bash
# Get DC list for further testing
./dcseek.py
cat dclist.txt

# Use DCs with other tools
while read ip; do
  crackmapexec smb $ip -u userlist.txt -p passwordlist.txt
done < dclist.txt
```

## Parsed Information

### Users
- Extracts domain user accounts
- Filters out system accounts
- Identifies RID information

### SMB Shares
- Lists accessible shares
- Excludes IPC$ and admin shares from summary
- Shows share types (Disk, Printer, etc.)

### Password Policy
- Minimum password length
- Password history requirements
- Maximum password age
- Complexity requirements

### Domain Information
- Domain name
- OS version
- Domain groups
- Group memberships

## Error Handling

DCSeek includes comprehensive error handling:
- Invalid IP/CIDR detection
- Network timeout management
- File permission checks
- Missing dependencies detection
- Keyboard interrupt (Ctrl+C) support
- Graceful failure recovery

## Performance Tuning

### Scanning Speed
```bash
# Fast scan (more workers, lower timeout)
./dcseek.py -w 50 -t 0.5

# Thorough scan (fewer workers, higher timeout)
./dcseek.py -w 5 -t 3
```

### Large Networks
```bash
# For /16 or larger networks
echo "10.0.0.0/16" > iplist.txt
./dcseek.py -w 100 -t 0.5  # Warning: generates ~65k hosts
```

## Troubleshooting

### enum4linux not found
```bash
# Install enum4linux
sudo apt install enum4linux

# Or try enum4linux-ng
sudo apt install enum4linux-ng
```

### Permission denied errors
```bash
# Make script executable
chmod +x dcseek.py

# Check write permissions
ls -la .
```

### No DCs found
- Verify network connectivity
- Check if IPs are reachable: `ping <ip>`
- Try verbose mode: `-v`
- Increase timeout: `-t 3`
- Check firewall rules

### Enum4linux timeout
- Increase worker timeout in code
- Check if DC is responsive
- Verify SMB ports (445) are open
- Try manual enum4linux: `enum4linux -a <ip>`

## Security Considerations

⚠️ **Important**: This tool is for authorized penetration testing only.

- Obtain proper authorization before scanning
- Scanning may trigger IDS/IPS alerts
- Aggressive scanning can impact network performance
- Store results securely (contains sensitive data)
- Follow responsible disclosure practices

## Version History

### v1.1 (Current)
- Added enum4linux integration
- Intelligent parsing of users and shares
- JSON output support
- DC list export to dclist.txt
- Enum-only mode
- Password policy extraction
- Enhanced error handling

### v1.0
- Initial release
- DC discovery by port scanning
- DNS SRV record validation
- Multi-threaded scanning
- Basic output formatting

## Contributing

Improvements welcome:
- Additional parsing patterns
- Support for other enumeration tools
- Output format options
- Performance optimizations

## License

Use responsibly. For authorized security assessments only.

---

**Author**: Internal Red Team  
**Last Updated**: October 2025  
**Tested On**: Kali Linux 2024+
