# SMBSeek v1.0

**SMB Share Discovery and Enumeration Tool**

SMBSeek is a comprehensive penetration testing tool designed to discover SMB-enabled hosts, enumerate accessible shares, and test for common security misconfigurations including null sessions and guest access.

## Features

### 🔍 Discovery Phase
- Fast multi-threaded SMB scanning
- Checks SMB ports: 139 (NetBIOS), 445 (SMB)
- Hostname resolution via reverse DNS
- Automatic SMB service detection

### 📊 Share Enumeration
- Enumerates all SMB shares using smbclient
- Falls back to rpcclient if needed
- Lists share types and comments
- Identifies interesting shares (ADMIN$, C$, backups, etc.)

### 🔓 Access Testing
- Tests null session access
- Tests guest account access
- Tests with provided credentials
- Attempts to list share contents
- Counts files/directories in accessible shares
- Tests read/write permissions

### ⚠️ Security Findings
- **Null Session Detection** - Anonymous share enumeration
- **Guest Access Detection** - Unauthenticated access
- **Interesting Shares** - Common high-value targets
- **Accessible Shares** - Readable/writable shares
- **Admin Shares** - ADMIN$, C$, IPC$ exposure

### 📊 Intelligence Gathering
- Share names and types
- Share comments/descriptions
- File counts in accessible shares
- UNC path generation
- Hostname mapping

## Installation

### Prerequisites (Kali Linux)
```bash
# Install SMB client tools
sudo apt update
sudo apt install smbclient

# Verify installation
smbclient --version
```

### Make Script Executable
```bash
chmod +x smbseek.py
```

## Usage

### Basic Discovery
```bash
# Scan IPs from iplist.txt
./smbseek.py

# Verbose mode (show all hosts)
./smbseek.py -v

# Custom input file
./smbseek.py -f targets.txt
```

### Access Testing
```bash
# Test access to discovered shares
./smbseek.py -t

# Test with credentials
./smbseek.py -t -u administrator -p password123

# Full scan with credentials
./smbseek.py -f targets.txt -t -u admin -p pass -v
```

### Performance Tuning
```bash
# Fast scan (50 workers)
./smbseek.py -w 50

# Custom timeout
./smbseek.py --timeout 3

# Everything custom
./smbseek.py -f targets.txt -w 25 --timeout 2 -t -v
```

## Output Files

### Discovery Output
- **`smblist.txt`** - Simple list of IPs with SMB enabled (one per line)
- **`sharelist.txt`** - UNC paths to accessible shares
- **`smb_details.txt`** - Human-readable detailed information
- **`smb_details.json`** - JSON format for automation
- **Console output** - Real-time discovery with security findings

### Example Output Structure
```
Internal/smbseek/
├── smbseek.py
├── iplist.txt
├── smblist.txt              # List of SMB hosts
├── sharelist.txt            # List of accessible shares (UNC paths)
├── smb_details.txt          # Detailed share info
└── smb_details.json         # JSON format
```

## Security Findings

### Null Session (Critical)
Allows unauthenticated enumeration of shares, users, and system information.
```
[HIGH] 192.168.1.10 (DC01.corp.local), 5 shares [NULL SESSION]
```

### Guest Access (High)
Allows guest account to enumerate shares without password.
```
[HIGH] 192.168.1.50 (FILES01), 8 shares [GUEST ACCESS]
```

### Interesting Shares (Medium/High)
Common high-value share names detected:
- **ADMIN$** - Administrative share (usually C:\Windows)
- **C$** - Default drive share
- **SYSVOL** - Domain policies (Domain Controllers)
- **NETLOGON** - Logon scripts (Domain Controllers)
- **Users** - User home directories
- **Backup/Backups** - Backup files
- **Share/Shares** - General file shares
- **IT/Software** - IT resources

### Accessible Shares (High)
Shares that can be browsed and read:
```
✓ \\192.168.1.50\Users (Files: 15)
✓ \\192.168.1.50\Public (Files: 32)
```

## Detected Share Types

### Windows Default Shares
- **ADMIN$** - Remote Admin
- **C$, D$, E$** - Drive shares
- **IPC$** - Inter-Process Communication
- **PRINT$** - Printer drivers

### Domain Shares
- **SYSVOL** - Group Policy and scripts
- **NETLOGON** - Domain logon scripts

### User/Data Shares
- Users, Public, Share, Data, Files
- Backup, Transfer, Temp, Common
- IT, Software, Installers

## Workflow Examples

### Basic Network Assessment
```bash
# 1. Discover SMB hosts
echo "192.168.1.0/24" > iplist.txt
./smbseek.py -v

# 2. Test share access
./smbseek.py -t

# 3. Review findings
cat smblist.txt
cat sharelist.txt
cat smb_details.txt
```

### Authenticated Scan
```bash
# Scan with domain credentials
./smbseek.py -u 'CORP\admin' -p 'P@ssw0rd' -t -v

# Check for accessible shares
grep "ACCESSIBLE" smb_details.txt
```

### Quick Null Session Check
```bash
# Fast scan for null sessions only
./smbseek.py -w 50
grep "NULL SESSION" smb_details.txt
```

## Integration with Other Tools

### Extract and Connect
```bash
# Get accessible shares
cat sharelist.txt

# Mount a share (Linux)
sudo mkdir /mnt/share
sudo mount -t cifs //192.168.1.50/Users /mnt/share -o username=guest,password=

# Connect via smbclient
smbclient //192.168.1.50/Users -U guest%
```

### Enum4linux Follow-up
```bash
# Run enum4linux on SMB hosts
cat smblist.txt | while read ip; do
    enum4linux -a $ip > "enum4linux_$ip.txt"
done
```

### CrackMapExec Integration
```bash
# Test credentials on SMB hosts
cme smb smblist.txt -u admin -p passwords.txt

# Spider shares
cme smb smblist.txt -u admin -p password --spider C$ --pattern .*
```

### Impacket Tools
```bash
# List shares with smbclient.py
cat smblist.txt | while read ip; do
    smbclient.py guest@$ip
done

# Get files
smbget -R smb://192.168.1.50/Public/
```

### Metasploit Integration
```bash
# Use auxiliary modules
msfconsole
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS file:/path/to/smblist.txt
run
```

## Common Attacks (Authorized Testing Only)

### 1. Null Session Enumeration
```bash
# Enumerate with null session
rpcclient -U "" 192.168.1.10
smbclient -L //192.168.1.10 -N

# Enumerate users
enum4linux -U 192.168.1.10

# Get password policy
enum4linux -P 192.168.1.10
```

### 2. Share Browsing
```bash
# List share contents
smbclient //192.168.1.50/Users -U guest%
smb: \> ls
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

### 3. Sensitive File Search
```bash
# Search for passwords
cme smb 192.168.1.50 -u admin -p pass --spider Users --pattern pass

# Search for configs
cme smb 192.168.1.50 -u admin -p pass --spider C$ --pattern .*\.conf
```

### 4. Credential Harvesting
```bash
# Download interesting files
smbclient //192.168.1.50/IT -U 'CORP\user%pass'
smb: \> cd Passwords
smb: \> mget *
```

## Error Handling

SMBSeek handles:
- Invalid IP/CIDR detection
- Connection timeouts
- Authentication failures
- Access denied errors
- Host unreachable conditions
- SMB service unavailable
- File permission issues
- Keyboard interrupts (Ctrl+C)

## Performance Tuning

### Scanning Speed
```bash
# Fast scan (large networks)
./smbseek.py -w 50 --timeout 1

# Balanced (default)
./smbseek.py -w 10 --timeout 2

# Thorough (slow networks)
./smbseek.py -w 5 --timeout 5
```

### Large Networks
```bash
# For /16 or larger
./smbseek.py -w 100 --timeout 1

# With access testing (slower)
./smbseek.py -w 20 --timeout 3 -t
```

## Troubleshooting

### No shares found
- Verify smbclient is installed: `which smbclient`
- Check firewall/network connectivity
- Try with credentials: `-u username -p password`
- Increase timeout: `--timeout 5`
- Try verbose mode: `-v`

### Access denied
- Null session may be disabled
- Try guest account (automatic)
- Use valid credentials: `-u admin -p pass`
- Check domain/workgroup

### Timeouts
- Increase timeout: `--timeout 5`
- Reduce workers: `-w 5`
- Check network latency

### Permission errors
```bash
chmod +x smbseek.py
```

## Security Considerations

⚠️ **Important**: This tool is for authorized penetration testing only.

- Obtain proper authorization before scanning
- SMB scanning may trigger IDS/IPS alerts
- Share enumeration is logged on target systems
- Accessing shares without permission is illegal
- Failed auth attempts may lock accounts
- Store results securely (contains sensitive data)
- Follow responsible disclosure
- Comply with local laws and regulations

## Output Format Examples

### smblist.txt
```
192.168.1.10
192.168.1.50
192.168.1.75
```

### sharelist.txt (UNC Paths)
```
\\192.168.1.10\SYSVOL
\\192.168.1.10\NETLOGON
\\192.168.1.50\Users
\\192.168.1.50\Public
\\192.168.1.75\Backup
```

### smb_details.txt
```
SMBSeek - SMB Share Discovery Results
======================================================================
Scan Date: 2025-10-13 17:30:45
Total Hosts with SMB: 3
Hosts with Accessible Shares: 2
======================================================================

Host: 192.168.1.10
Hostname: DC01.corp.local
Ports: 139, 445
⚠ NULL SESSION ALLOWED
Shares Found: 5
----------------------------------------------------------------------
  Share: ADMIN$
  Type: Disk
  Comment: Remote Admin
  
  Share: C$
  Type: Disk
  Comment: Default share
  
  Share: IPC$
  Type: IPC
  Comment: Remote IPC
  
  Share: NETLOGON
  Type: Disk
  Comment: Logon server share
  ✓ ACCESSIBLE (Readable: True, Files: 3)
  ★ INTERESTING SHARE
  
  Share: SYSVOL
  Type: Disk
  Comment: Logon server share
  ✓ ACCESSIBLE (Readable: True, Files: 12)
  ★ INTERESTING SHARE

======================================================================
```

### smb_details.json
```json
[
  {
    "ip": "192.168.1.10",
    "hostname": "DC01.corp.local",
    "smb_enabled": true,
    "ports_open": [
      {"port": 139, "service": "NetBIOS"},
      {"port": 445, "service": "SMB"}
    ],
    "shares": [
      {"name": "ADMIN$", "type": "Disk", "comment": "Remote Admin"},
      {"name": "C$", "type": "Disk", "comment": "Default share"},
      {"name": "IPC$", "type": "IPC", "comment": "Remote IPC"},
      {"name": "NETLOGON", "type": "Disk", "comment": "Logon server share"},
      {"name": "SYSVOL", "type": "Disk", "comment": "Logon server share"}
    ],
    "accessible_shares": [
      {"name": "NETLOGON", "readable": true, "writable": false, "files_found": 3},
      {"name": "SYSVOL", "readable": true, "writable": false, "files_found": 12}
    ],
    "interesting_shares": ["ADMIN$", "C$", "NETLOGON", "SYSVOL"],
    "null_session": true,
    "guest_access": false,
    "error": null
  }
]
```

## Tips & Tricks

1. **Start without credentials** - Null sessions often work
2. **Check guest access** - Automatic fallback
3. **Focus on interesting shares** - SYSVOL, NETLOGON, C$, Backups
4. **Test access (-t flag)** - Know what you can actually read
5. **Use credentials from DCSeek** - Enumerate users first
6. **Check SYSVOL for passwords** - Group Policy Preferences XML files
7. **Spider accessible shares** - Use CrackMapExec
8. **Download sensitive files** - Passwords, configs, credentials
9. **Cross-reference with PrintSeek** - Printer drivers may contain creds
10. **Export to JSON** - Automate reporting and analysis

## Related Tools

- **enum4linux** - Comprehensive SMB enumeration
- **CrackMapExec (cme)** - Swiss army knife for pentesting
- **Impacket** - Python SMB tools
- **smbmap** - SMB share enumeration
- **smbget** - Download files from SMB shares
- **Metasploit** - SMB auxiliary modules
- **nmap** - SMB scripts (--script smb-*)

## Common Findings

### Critical
- **Null sessions on Domain Controllers** - Full user/group enumeration
- **C$ accessible** - Full system access
- **ADMIN$ accessible** - Administrative access

### High
- **Backup shares accessible** - May contain credentials
- **User home directories readable** - Sensitive files
- **IT/Software shares** - May contain credentials/keys

### Medium
- **Public shares with sensitive data** - Misconfigured permissions
- **SYSVOL readable** - Domain policy information
- **Guest access enabled** - Weak security

## Remediation

### For System Administrators
1. **Disable null sessions** - Set RestrictAnonymous registry key
2. **Disable guest account** - Not needed in most environments
3. **Remove unnecessary shares** - Default shares (C$, ADMIN$)
4. **Implement SMB signing** - Prevent relay attacks
5. **Use SMB encryption** - SMBv3 encryption
6. **Audit share permissions** - Regular reviews
7. **Monitor SMB access** - Log and alert
8. **Segment SMB traffic** - Separate VLANs

### Registry Settings
```
HKLM\SYSTEM\CurrentControlSet\Control\Lsa
RestrictAnonymous = 2

HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters
NullSessionShares = (remove all)
RestrictNullSessAccess = 1
```

## Version History

### v1.0 (Current)
- Initial release
- Multi-threaded discovery
- smbclient integration
- rpcclient fallback
- Null session detection
- Guest access detection
- Share access testing
- Interesting share identification
- UNC path generation
- JSON export

## Contributing

Improvements welcome:
- Additional interesting share patterns
- More enumeration techniques
- Better error handling
- Performance optimizations
- Additional output formats

## License

Use responsibly. For authorized security assessments only.

---

**Author**: Internal Red Team  
**Last Updated**: October 2025  
**Tested On**: Kali Linux 2024+
