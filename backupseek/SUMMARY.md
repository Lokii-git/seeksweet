# BackupSeek Technical Summary

## Overview
BackupSeek is a specialized reconnaissance tool for discovering and enumerating backup infrastructure in enterprise environments. It identifies backup servers, management consoles, and storage repositories across multiple platforms including Veeam, Acronis, Bacula, Dell EMC Networker, IBM Spectrum Protect, CommVault, and Veritas NetBackup.

Backup systems are critical security targets because they contain:
- Complete system images and snapshots
- Domain administrator credentials
- Database backups with sensitive data
- Configuration files
- Historical data archives
- Encryption keys and certificates

## Architecture

### Core Components
1. **Port Scanner**: Multi-threaded TCP port scanning
2. **System Identifier**: Pattern-based backup system identification
3. **Web Detector**: HTTP/HTTPS interface discovery
4. **Share Enumerator**: SMB backup share detection
5. **Report Generator**: Text and JSON output

### Detection Logic Flow
```
Target IPs
   ↓
Port Scanning (TCP)
   ↓
Open Port Analysis
   ↓
System Identification (pattern matching)
   ↓
Web Interface Detection (HTTP/HTTPS)
   ↓
Share Enumeration (SMB)
   ↓
Results Aggregation
   ↓
Output (TXT/JSON)
```

## Implementation Details

### Port Scanning
```python
def check_port(ip, port, timeout=3):
    """
    TCP connection test
    Returns: True if port open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0  # 0 = success (open port)
    except:
        return False
```

**TCP Three-Way Handshake**:
1. SYN → Target
2. SYN-ACK ← Target (port open)
3. ACK → Target
4. Connection established
5. Close connection

### System Identification
```python
def identify_backup_system(open_ports):
    """
    Pattern-based identification
    Returns: List of identified systems with confidence
    """
    systems = []
    
    # Veeam signature
    veeam_ports = [9392, 9393, 9401, 9419, 6160]
    if any(port in open_ports for port in veeam_ports):
        systems.append({
            'system': 'Veeam Backup & Replication',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in veeam_ports]
        })
    
    # Similar logic for other systems...
    return systems
```

**Confidence Levels**:
- **High**: Multiple characteristic ports open
- **Medium**: Single characteristic port (could be coincidence)
- **Low**: Generic backup port (needs further verification)

## Backup System Port Mappings

### Veeam Backup & Replication

**Service Ports**:
```python
VEEAM_PORTS = {
    9392: 'Veeam Backup Service',        # Main backup service
    9393: 'Veeam Data Mover',            # Data transfer
    9394: 'Veeam Agent',                 # Agent communication
    9395: 'Veeam Agent',                 # Additional agent port
    9401: 'Veeam Cloud Connect',         # Cloud backup
    9419: 'Veeam Enterprise Manager',    # Web management
    6160: 'Veeam vPower NFS',            # Instant VM recovery
    6162: 'Veeam Mount Server'           # Backup mounting
}
```

**Architecture**:
```
Backup & Replication Server (9392)
   ├── Enterprise Manager (9419) [Web UI]
   ├── Proxy Servers (9393) [Data Mover]
   ├── Repository Servers (6160, 6162)
   └── Agents (9394, 9395)
```

**Data Storage**:
- SQL Server database: VeeamBackup
- Credentials stored encrypted in [dbo].[Credentials] table
- Configuration: `C:\ProgramData\Veeam\Backup`

### Acronis Cyber Backup

**Service Ports**:
```python
ACRONIS_PORTS = {
    9876: 'Acronis Backup Service',      # Main service
    43234: 'Acronis Agent',              # Client agent
    44445: 'Acronis Management Server'   # Web console
}
```

**Architecture**:
```
Management Server (44445)
   ├── Web Console (9877 or 44445)
   ├── Backup Service (9876)
   └── Agents (43234)
```

### Bacula

**Service Ports**:
```python
BACULA_PORTS = {
    9101: 'Bacula Director',        # Control daemon
    9102: 'Bacula File Daemon',     # Client (files to backup)
    9103: 'Bacula Storage Daemon'   # Storage management
}
```

**Architecture**:
```
Director (9101)
   ├── File Daemons (9102) [Clients]
   └── Storage Daemons (9103) [Backup Storage]
```

**Configuration Files**:
- Director: `/etc/bacula/bacula-dir.conf`
- Storage: `/etc/bacula/bacula-sd.conf`
- Client: `/etc/bacula/bacula-fd.conf`

**Passwords**: Plaintext in config files

### Dell EMC Networker

**Service Ports**:
```python
NETWORKER_PORTS = {
    7937: 'Dell Networker',
    7938: 'Dell Networker NSR',
    7939: 'Dell Networker RPC'
}
```

### IBM Spectrum Protect (TSM)

**Service Ports**:
```python
TSM_PORTS = {
    1500: 'TSM Server',
    1501: 'TSM Scheduler',
    1581: 'TSM Web Client'
}
```

**Components**:
- Server (1500): Main TSM server
- Scheduler (1501): Automated backups
- Web Interface (1581): Admin console

### CommVault

**Service Ports**:
```python
COMMVAULT_PORTS = {
    8400: 'CommVault CommCell',
    8401: 'CommVault Web Console',
    8403: 'CommVault Firewall'
}
```

### Veritas NetBackup

**Service Ports**:
```python
NETBACKUP_PORTS = {
    1556: 'vnetd (Master Server)',
    13701: 'bprd (Request Daemon)',
    13702: 'bpdbm (Database Manager)',
    13720: 'bpcd (Client Daemon)',
    13724: 'vopied (Media Daemon)'
}
```

## Web Interface Detection

### HTTPS Probing
```python
def detect_veeam_web(ip, timeout=5):
    """
    HTTP/HTTPS detection with SSL verification disabled
    """
    findings = []
    
    for port in VEEAM_WEB_PORTS:  # [9443, 9419, 9399]
        try:
            url = f'https://{ip}:{port}'
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,          # Ignore SSL cert errors
                allow_redirects=True
            )
            
            # Pattern matching in response
            if 'veeam' in response.text.lower():
                findings.append({
                    'type': 'veeam_web',
                    'url': url,
                    'port': port,
                    'status_code': response.status_code
                })
                
                # Component identification
                if 'enterprise manager' in response.text.lower():
                    findings[-1]['component'] = 'Enterprise Manager'
        except:
            continue
    
    return findings
```

**Detection Indicators**:
- HTML title tags: "Veeam", "Backup", "Acronis"
- Server headers: "Veeam", "Acronis"
- Response bodies: Product-specific strings
- URL patterns: `/em/`, `/console/`, `/web/`

## SMB Share Enumeration

### Share Detection
```python
def check_smb_backup_shares(ip, timeout=3):
    """
    Enumerate SMB shares for backup-related names
    """
    backup_shares = []
    backup_share_names = [
        'Backup', 'Backups', 'VeeamBackup', 
        'BackupExec', 'Acronis'
    ]
    
    # Use smbclient for enumeration
    cmd = ['smbclient', '-L', f'//{ip}', '-N', '--timeout', str(timeout)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
    
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            for backup_name in backup_share_names:
                if backup_name.lower() in line.lower() and 'Disk' in line:
                    # Parse share name from output
                    parts = line.split()
                    if parts:
                        share_name = parts[0].strip()
                        backup_shares.append(share_name)
    
    return backup_shares
```

**SMB Protocol Flow**:
1. TCP connection to port 445 (or 139)
2. SMB negotiate protocol
3. Session setup (anonymous or authenticated)
4. Tree connect to IPC$
5. NetShareEnumAll RPC call
6. Parse share list response

**Common Share Names**:
- `Backup`, `Backups`
- `VeeamBackup`, `VeeamRepository`
- `BackupExec`
- `Acronis`
- `TSM`, `NetBackup`

## Concurrent Execution

### Threading Model
```python
from concurrent.futures import ThreadPoolExecutor, as_completed

def main():
    results = []
    
    with ThreadPoolExecutor(max_workers=workers) as executor:
        # Submit all scan jobs
        future_to_ip = {
            executor.submit(scan_host, ip, args): ip 
            for ip in ips
        }
        
        # Process results as they complete
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                result = future.result()
                results.append(result)
                
                # Real-time output
                if result['identified_systems']:
                    print_finding(result)
            
            except KeyboardInterrupt:
                executor.shutdown(wait=False, cancel_futures=True)
                break
            except Exception as e:
                handle_error(ip, e)
```

**Performance Characteristics**:
- Default: 10 concurrent workers
- Recommended max: 50-100 workers
- Each worker: Independent thread
- I/O bound: Network latency dominant factor

**Timing**:
- Port check: ~100-500ms per port
- Web detection: ~1-3 seconds
- Share enum: ~2-5 seconds
- Total per host: ~5-15 seconds (full scan)

## Output Formats

### backuplist.txt (Simple)
```
192.168.10.50
192.168.10.51
10.0.5.10
```
**Format**: One IP per line  
**Use case**: Input for other tools

### backup_details.txt (Detailed)
```
================================================================================
Host: 192.168.10.50
================================================================================

Backup Systems Detected:
  • Veeam Backup & Replication (Confidence: high)
    Ports: 9392, 9393, 9401, 9419

Open Ports (4):
  • 9392 - Veeam Backup Service
  • 9393 - Veeam Data Mover
  • 9401 - Veeam Cloud Connect
  • 9419 - Veeam Backup Enterprise Manager

Web Interfaces:
  • https://192.168.10.50:9419 - Enterprise Manager

Backup Shares:
  • \\192.168.10.50\VeeamBackup

Exploitation Notes:
  Veeam:
    - Default creds: administrator/password or admin/admin
    - Check Veeam database for credentials
    - Backup files may contain domain credentials
```

### backup_details.json (Structured)
```json
[
  {
    "ip": "192.168.10.50",
    "open_ports": [9392, 9393, 9401, 9419],
    "identified_systems": [
      {
        "system": "Veeam Backup & Replication",
        "confidence": "high",
        "ports": [9392, 9393, 9401, 9419]
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
    "backup_shares": ["VeeamBackup"],
    "status": "backup_found"
  }
]
```

**JSON Schema**:
- `ip`: Target IP address (string)
- `open_ports`: Array of integers
- `identified_systems`: Array of objects
  - `system`: Product name (string)
  - `confidence`: "high" | "medium" | "low"
  - `ports`: Array of open ports for this system
- `web_interfaces`: Array of objects
  - `type`: Interface type (string)
  - `url`: Full URL (string)
  - `port`: Port number (integer)
  - `status_code`: HTTP response code (integer)
  - `component`: Component name (string, optional)
- `backup_shares`: Array of share names (strings)
- `status`: "backup_found" | "no_backup"

## Security Implications

### Attack Surface

**Credential Storage**:
- **Veeam**: SQL Server database (VeeamBackup)
  - Table: [dbo].[Credentials]
  - Encryption: DPAPI (can be decrypted with proper access)
- **Bacula**: Plaintext in config files
- **Others**: Various credential stores

**Default Credentials**:
```python
COMMON_DEFAULTS = {
    'Veeam': [
        ('administrator', 'password'),
        ('admin', 'admin')
    ],
    'Acronis': [
        ('admin', 'admin'),
        ('administrator', 'password')
    ],
    # Others vary by installation
}
```

**Exploitation Paths**:
1. **Web Interface Access**:
   - Default credentials → Full backup access
   - Session hijacking → Restore arbitrary files
   - API abuse → Download backups

2. **Database Access**:
   - SQL injection → Credential extraction
   - Direct DB access → Decrypt stored credentials
   - Backup database → Offline analysis

3. **Share Access**:
   - Anonymous shares → Download backups
   - Weak permissions → Modify backups
   - Backup files → Extract credentials

4. **Configuration Files**:
   - Bacula configs → Director passwords
   - NetBackup configs → Master server credentials
   - TSM configs → Admin credentials

### High-Value Targets in Backups

**Domain Controllers**:
- NTDS.dit (Active Directory database)
- SYSTEM registry hive (boot key)
- Result: All domain password hashes

**Database Servers**:
- SQL backups (.bak files)
- MySQL dumps
- PostgreSQL archives
- Result: Application data and credentials

**Application Servers**:
- Web.config files
- Application properties
- Connection strings
- Result: Database and service credentials

**File Servers**:
- User home directories
- Shared folders
- Historical data
- Result: Sensitive documents and files

## Detection & Defense

### Detection Signatures

**Network IDS (Snort/Suricata)**:
```
# Multiple backup port scans
alert tcp any any -> $HOME_NET any (
    msg:"Multiple Backup Port Scan";
    flags:S;
    threshold:type threshold, track by_src, count 5, seconds 60;
    metadata:attack_target backup-infrastructure;
    sid:1000050;
)

# Veeam web access from unusual source
alert tcp !$ADMIN_NET any -> $BACKUP_NET 9419 (
    msg:"Veeam Web Access from Non-Admin Network";
    flow:to_server,established;
    sid:1000051;
)
```

**SIEM Correlation Rules**:
```
# Rule 1: Backup port scanning
source_type = "firewall"
destination_port IN [9392, 9393, 9419, 9876, 44445, 9101, 9102, 9103]
unique_ports > 3
within 5 minutes
→ ALERT: Backup infrastructure scan detected

# Rule 2: Failed backup web logins
source_type = "backup_web_logs"
status = "authentication_failed"
count > 5 within 10 minutes
→ ALERT: Backup system brute force attempt

# Rule 3: Unusual backup access time
source_type = "backup_access_logs"
time NOT IN [backup_windows]
user NOT IN [backup_admins]
→ ALERT: Off-hours backup system access

# Rule 4: Bulk backup downloads
source_type = "smb_logs"
share_name IN ["Backup", "VeeamBackup", "Backups"]
file_extension IN [".vbk", ".vib", ".tib", ".bak"]
count > 10 within 1 hour
→ ALERT: Bulk backup file download
```

**Log Monitoring**:

*Veeam Event Logs*:
```powershell
# Failed logins
Get-EventLog -LogName Application -Source "Veeam*" | 
    Where-Object {$_.EventID -eq 4625}

# Successful logins from unusual IPs
Get-EventLog -LogName Security -Source "Veeam*" | 
    Where-Object {$_.EventID -eq 4624 -and $_.Message -notmatch "192.168.10.*"}
```

*Bacula Logs*:
```bash
# Failed authentication
grep "Failed auth" /var/log/bacula/bacula.log

# Connections from unexpected IPs
grep "Connection from" /var/log/bacula/bacula.log | 
    grep -v "192.168.10."
```

### Defense Measures

**Network Segmentation**:
```
Backup Network (VLAN 50) - 192.168.50.0/24
├── Firewall Rules:
│   ├── Allow: Admin workstations (VLAN 10) → Backup servers (TCP 9392, 9419)
│   ├── Allow: Backup proxies (VLAN 51) → Backup servers (TCP 9392, 9393)
│   ├── Allow: Production servers (VLAN 20-40) → Backup agents (TCP 9394)
│   └── Deny: All other traffic
└── Internet Access: BLOCKED (no outbound except updates)
```

**Authentication Hardening**:
1. **Disable default accounts**: Remove/rename administrator
2. **Strong passwords**: 20+ characters, complex
3. **MFA**: Enable on all web interfaces
4. **Certificate auth**: Use for service-to-service
5. **AD integration**: Leverage existing authentication

**Access Control**:
```powershell
# Veeam: Restrict console access
# Only specific security groups
Add-VBRUserRoleScope -Role "BackupAdministrator" 
    -User "DOMAIN\BackupAdmins"

# File system: Backup repository access
icacls "E:\Backups" /grant "BackupService:(OI)(CI)M" /inheritance:r
# Remove all other permissions
```

**Encryption**:
- **In-transit**: TLS 1.2+ for all backup traffic
- **At-rest**: AES-256 encryption for backup files
- **Password protection**: 20+ character passphrases
- **Key management**: Separate from backup infrastructure

**Monitoring**:
```powershell
# Enable auditing on backup servers
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable

# Forward logs to SIEM
# Veeam: Enable syslog forwarding
# Others: Configure log shipping
```

## Limitations

### Technical Limitations
- **Port-based detection**: Can produce false positives
- **Requires connectivity**: Firewall/ACLs can block scans
- **No vulnerability assessment**: Only discovery, not exploitation
- **Limited credential testing**: No built-in bruteforce
- **SMB dependency**: Share enum requires smbclient

### Scope Limitations
- **No service version detection**: Cannot identify specific versions
- **No configuration analysis**: Cannot assess security posture
- **No backup content inspection**: Cannot analyze backup files
- **No cloud backup detection**: Only on-premise systems

## Performance Optimization

### Worker Tuning
```python
# Network size vs worker count
WORKER_RECOMMENDATIONS = {
    'small (<256 hosts)': 10,
    'medium (256-1024)': 25,
    'large (1024-4096)': 50,
    'very large (4096+)': 100
}

# Timeout tuning
TIMEOUT_RECOMMENDATIONS = {
    'local LAN': 2,
    'remote LAN': 5,
    'WAN': 10
}
```

### Performance Characteristics
**Network Size vs Time** (10 workers, 3s timeout):
- /24 (254 hosts): ~5-10 minutes (probe only)
- /24 with --full: ~20-30 minutes
- /16 (65,536 hosts): ~10-20 hours
- /16 with --full: ~40-80 hours

## Dependencies

### Required
- Python 3.6+
- `requests` library
- `socket` (standard library)
- `subprocess` (standard library)
- `concurrent.futures` (standard library)

### Optional
- `smbclient` (for share enumeration)

### Installation
```bash
# Python packages
pip3 install requests

# System tools (Ubuntu/Debian)
sudo apt install python3 python3-pip smbclient

# System tools (CentOS/RHEL)
sudo yum install python3 python3-pip samba-client

# System tools (macOS)
brew install python3 samba
```

## Future Enhancements
- Service version fingerprinting
- Built-in credential testing
- Backup configuration analysis
- Cloud backup platform support (AWS Backup, Azure Backup)
- Automated vulnerability assessment
- Backup integrity verification
- Real-time monitoring mode
- Integration with offensive security frameworks

## References
- **MITRE ATT&CK**: T1213 (Data from Information Repositories)
- **CWE-522**: Insufficiently Protected Credentials
- **CWE-798**: Use of Hard-coded Credentials
- **NIST SP 800-209**: Security Guidelines for Storage Infrastructure
- **Veeam Best Practices**: https://bp.veeam.com/
- **Backup Security Guide**: https://www.sans.org/reading-room/whitepapers/backup/

---

**Note**: This tool is for authorized security testing only. Unauthorized access to backup systems is illegal and unethical.
