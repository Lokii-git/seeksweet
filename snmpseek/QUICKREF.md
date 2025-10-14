# SNMPSeek Quick Reference

## Quick Start

```bash
# Basic SNMP discovery
./snmpseek.py 192.168.1.0/24

# Bruteforce community strings
./snmpseek.py --bruteforce 10.0.0.0/24

# Full scan with MIB walk
./snmpseek.py --full -f targets.txt

# Test for writable SNMP
./snmpseek.py --writable 192.168.1.0/24
```

## Common Commands

### Discovery
```bash
# Network scan
./snmpseek.py 10.0.0.0/16 -w 100

# From file
./snmpseek.py -f routers.txt --bruteforce

# Specific communities
./snmpseek.py -c "mycommunity,custom" 192.168.1.0/24
```

### Enumeration
```bash
# Full device info extraction
./snmpseek.py --walk -f snmplist.txt

# Test write access
./snmpseek.py --writable --bruteforce 10.0.0.0/24

# SNMPv3 testing
./snmpseek.py --v3 --users userlist.txt 192.168.1.0/24
```

### Performance
```bash
# Fast scan
./snmpseek.py -w 50 --timeout 2 10.0.0.0/24

# Slow/stealthy
./snmpseek.py -w 5 --timeout 10 192.168.1.0/24
```

## Output Files

| File | Description |
|------|-------------|
| `snmplist.txt` | SNMP-enabled hosts |
| `snmp_creds.txt` | Valid community strings |
| `snmp_info.txt` | Device information |
| `snmp_details.json` | JSON export |

## Common Community Strings

| String | Type | Common On |
|--------|------|-----------|
| `public` | Read-only | Everything |
| `private` | Read-write | Cisco, HP |
| `community` | Read-only | Generic |
| `admin` | Read-write | Printers |
| `cisco` | Varies | Cisco devices |
| `manager` | Read-only | Windows |

## Important OIDs

### System Info
```
1.3.6.1.2.1.1.1.0    System description
1.3.6.1.2.1.1.5.0    Hostname
1.3.6.1.2.1.1.6.0    Location
1.3.6.1.2.1.1.4.0    Contact
```

### Network Info
```
1.3.6.1.2.1.4.20.1.1    IP addresses
1.3.6.1.2.1.4.21.1.7    Routing table
1.3.6.1.2.1.4.22.1.2    ARP cache
1.3.6.1.2.1.2.2.1.2     Interfaces
```

### Cisco Specific
```
1.3.6.1.4.1.9.2.1.53    Running config
1.3.6.1.4.1.9.2.1.55    Enable password
1.3.6.1.4.1.9.9.23.1.2  CDP neighbors
```

### Windows Specific
```
1.3.6.1.4.1.77.1.2.25   Users
1.3.6.1.4.1.77.1.4.2    Shares
1.3.6.1.2.1.25.4.2.1.2  Processes
```

## Manual SNMP Commands

### snmpget (Single Value)
```bash
# Get hostname
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.5.0

# Get system description
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0
```

### snmpwalk (Multiple Values)
```bash
# Walk entire system tree
snmpwalk -v2c -c public 192.168.1.1 system

# Get all IP addresses
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.4.20.1.1

# Get routing table
snmpwalk -v2c -c public 192.168.1.1 ipRouteNextHop
```

### snmpset (Write Operations)
```bash
# Set hostname
snmpset -v2c -c private 192.168.1.1 1.3.6.1.2.1.1.5.0 s "newhostname"

# Set location
snmpset -v2c -c private 192.168.1.1 1.3.6.1.2.1.1.6.0 s "Server Room"

# Set contact
snmpset -v2c -c private 192.168.1.1 1.3.6.1.2.1.1.4.0 s "admin@example.com"
```

## Attack Workflows

### Workflow 1: Quick Wins
```bash
# 1. Fast discovery with defaults
./snmpseek.py 192.168.0.0/16 --bruteforce -w 100

# 2. Review findings
cat snmp_creds.txt | grep "WRITE"

# 3. Extract sensitive info
snmpwalk -v2c -c public 192.168.1.1 system
```

### Workflow 2: Network Mapping
```bash
# 1. Find SNMP devices
./snmpseek.py --full 10.0.0.0/24

# 2. Extract all IPs
for ip in $(cut -d: -f1 snmplist.txt); do
    snmpwalk -v2c -c public $ip ipAdEntAddr
done

# 3. Extract routing tables
snmpwalk -v2c -c public 192.168.1.1 ipRouteNextHop
```

### Workflow 3: Cisco Exploitation
```bash
# 1. Find Cisco devices
./snmpseek.py --bruteforce -f cisco_devices.txt

# 2. Check for write access
grep "WRITE" snmp_creds.txt

# 3. Extract config via TFTP (Metasploit)
msfconsole
use auxiliary/scanner/snmp/cisco_config_tftp
set COMMUNITY private
set RHOST 192.168.1.1
run
```

### Workflow 4: Windows Enumeration
```bash
# 1. Find Windows SNMP
./snmpseek.py --bruteforce -f windows_servers.txt

# 2. Extract users
snmpwalk -v2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.2.25

# 3. Extract shares
snmpwalk -v2c -c public 192.168.1.50 1.3.6.1.4.1.77.1.4.2

# 4. Extract processes
snmpwalk -v2c -c public 192.168.1.50 1.3.6.1.2.1.25.4.2.1.2
```

## Integration Examples

### With Metasploit
```bash
# 1. Discover with SNMPSeek
./snmpseek.py --bruteforce 192.168.1.0/24

# 2. Import to MSF
msfconsole
use auxiliary/scanner/snmp/snmp_enum
set COMMUNITY public
set RHOSTS file:snmplist.txt
run

# 3. Exploit writable
use auxiliary/scanner/snmp/snmp_set
set COMMUNITY private
set RHOSTS 192.168.1.10
run
```

### With onesixtyone
```bash
# 1. Fast scan with onesixtyone
echo -e "public\nprivate\ncommunity" > communities.txt
onesixtyone -c communities.txt -i targets.txt > found.txt

# 2. Detailed enum with SNMPSeek
./snmpseek.py -f found.txt --walk
```

### With Nmap
```bash
# 1. Discover UDP 161
nmap -sU -p 161 --open 192.168.1.0/24 -oG snmp.txt

# 2. Extract IPs
grep "161/open" snmp.txt | cut -d' ' -f2 > snmp_ips.txt

# 3. SNMPSeek bruteforce
./snmpseek.py -f snmp_ips.txt --bruteforce
```

## Common Options

```
Targeting:
  IP/CIDR               IP or range (192.168.1.0/24)
  -f, --file FILE       File with targets

Modes:
  --bruteforce          Test common communities
  --walk                MIB walk
  --writable            Test write access
  --full                All features
  -c, --communities STR Custom communities

Connection:
  --timeout N           Timeout (default: 3)
  -w, --workers N       Threads (default: 10)

Output:
  -v, --verbose         Detailed output
  --json                JSON only
```

## Quick Checks

```bash
# Count SNMP hosts
wc -l snmplist.txt

# Count valid communities
wc -l snmp_creds.txt

# Find writable access
grep "WRITE" snmp_creds.txt

# Extract IPs only
cut -d: -f1 snmplist.txt

# Find Cisco devices
grep -i "cisco\|ios" snmp_info.txt
```

## Detection Indicators

### Network
- Multiple UDP packets to port 161
- Sequential SNMP queries
- Failed authentication attempts
- Unusual OID access patterns

### Logs
```
# SNMP auth failures
Authentication failure from 192.168.1.100

# Community string attempts
Failed community: test
Failed community: admin
Failed community: cisco
```

## Defense Quick Tips

```bash
# Disable SNMP
sudo systemctl stop snmpd
sudo systemctl disable snmpd

# Change default communities (Linux)
# Edit /etc/snmp/snmpd.conf
rocommunity "MyStr0ng!Community!" 10.0.0.0/24

# Cisco
conf t
no snmp-server community public
snmp-server community "MyStr0ng!" RO
end

# ACL restriction (Cisco)
access-list 10 permit 10.0.0.0 0.0.0.255
snmp-server community mycomm RO 10
```

## Troubleshooting

### No Responses
```bash
# Test locally
snmpwalk -v2c -c public localhost system

# Check service
sudo systemctl status snmpd

# Check firewall
sudo iptables -L -n | grep 161
```

### Timeout Errors
```bash
# Increase timeout
./snmpseek.py --timeout 10

# Test manually
snmpget -v2c -c public -t 10 target.ip 1.3.6.1.2.1.1.1.0
```

### "snmpget not found"
```bash
# Ubuntu/Debian
sudo apt install snmp

# CentOS/RHEL
sudo yum install net-snmp-utils

# macOS
brew install net-snmp
```

## Tips & Tricks

### 🎯 Targeting
- **Network devices**: Routers, switches, firewalls
- **Printers**: Often have SNMP enabled
- **Windows servers**: Check for SNMP service
- **IoT devices**: Cameras, sensors, thermostats

### 🔒 Stealth
- **Slow scans**: Use `-w 5`
- **Custom wordlists**: Environment-specific
- **Avoid writes**: Read-only unless necessary
- **Blend in**: During business hours

### ⚡ Speed
- **More workers**: `-w 100` for large nets
- **Reduce timeout**: `--timeout 2` for fast nets
- **Target selection**: Known device types
- **Parallel instances**: Split networks

### 🎓 Learning
- **Practice locally**: Set up test SNMP devices
- **Read RFCs**: 1157 (v1), 3416 (v2c), 3414 (v3)
- **MIB browsers**: Explore OID hierarchies
- **Study vendors**: Cisco, HP, Windows OIDs

## One-Liners

```bash
# Quick discovery and extraction
./snmpseek.py --bruteforce 10.0.0.0/24 && cat snmp_info.txt

# Find all writable SNMP
./snmpseek.py --writable 192.168.0.0/16 | grep "WRITE"

# Extract all hostnames
for ip in $(cut -d: -f1 snmplist.txt); do snmpget -v2c -c public -Oqv $ip 1.3.6.1.2.1.1.5.0; done

# Map all IP addresses in network
for ip in $(cut -d: -f1 snmplist.txt); do echo "==$ip=="; snmpwalk -v2c -c public -Oqv $ip ipAdEntAddr; done
```

## Real-World Examples

### Example 1: Corporate Network
```bash
./snmpseek.py 10.0.0.0/16 --bruteforce -w 100
# Scanned: 65,536 hosts
# Found: 234 SNMP devices
# Valid communities: 189 (public), 12 (private)
# Time: ~30 minutes
```

### Example 2: Default Communities
```bash
./snmpseek.py --bruteforce 192.168.1.0/24
# Found: 15 devices with 'public'
# Found: 2 devices with 'private' (WRITE access)
# Extracted: Full device configs
```

### Example 3: Network Mapping
```bash
./snmpseek.py --full 10.0.0.0/24
# Extracted: 300+ IP addresses
# Extracted: Complete routing tables
# Extracted: ARP caches
# Result: Full network topology mapped
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - SNMP found |
| 1 | No SNMP services |
| 2 | SNMP tools missing |
| 3 | No targets |

## Quick Reference Card

```
┌────────────────────────────────────────────┐
│          SNMPSEEK CHEAT SHEET              │
├────────────────────────────────────────────┤
│ PORT                                       │
│  161 UDP         SNMP queries              │
├────────────────────────────────────────────┤
│ DEFAULTS                                   │
│  public          Read-only (common)        │
│  private         Read-write (common)       │
├────────────────────────────────────────────┤
│ DISCOVERY                                  │
│  --bruteforce    Test common communities   │
│  --walk          Extract device info       │
│  --writable      Find write access         │
├────────────────────────────────────────────┤
│ KEY OIDS                                   │
│  1.3.6.1.2.1.1.5.0    Hostname            │
│  1.3.6.1.2.1.4.20.1.1 IP addresses        │
│  1.3.6.1.4.1.9.2.1.53 Cisco config        │
└────────────────────────────────────────────┘
```

## Related Commands

```bash
# List all OIDs
snmpwalk -v2c -c public target.ip .1

# Get specific OID
snmpget -v2c -c public target.ip OID

# Set OID value
snmpset -v2c -c private target.ip OID type value

# Bulk get
snmpbulkget -v2c -c public target.ip OID

# Translate OID to name
snmptranslate 1.3.6.1.2.1.1.5.0
```

## Learning Resources

- **RFC 1157**: SNMP v1 specification
- **RFC 3416**: SNMP v2c specification
- **RFC 3414**: SNMP v3 security
- **MIB Browser**: iReasoning MIB Browser
- **SNMP Labs**: Practice environments online
