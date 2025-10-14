# 🎯 Seek Tools Suite - Complete Overview

A comprehensive collection of network discovery and enumeration tools for penetration testing.

---

## 📦 Tools in the Suite

### 1. DCSeek v1.1 - Domain Controller Discovery
**Purpose:** Find and enumerate Active Directory Domain Controllers

**Key Features:**
- Multi-threaded DC discovery
- enum4linux integration
- User and share enumeration
- Password policy extraction
- JSON export

**Output Files:**
- `dclist.txt` - DC IP addresses
- `domain_controllers.txt` - Detailed DC info
- `enum4linux_summary.txt` - Enumeration results
- `enum4linux_summary.json` - JSON format
- `enum4linux_results/` - Raw output

**Typical Use:**
```bash
./dcseek.py --enum -v
```

---

### 2. PrintSeek v1.0 - Network Printer Discovery
**Purpose:** Find and enumerate network printers

**Key Features:**
- Multi-threaded printer discovery
- SNMP enumeration (v2c)
- Model, serial, location extraction
- Web interface detection
- Confidence scoring

**Output Files:**
- `printerlist.txt` - Printer IP addresses
- `printer_details.txt` - Detailed printer info
- `printer_details.json` - JSON format

**Typical Use:**
```bash
./printseek.py -c private -v
```

---

### 3. PanelSeek v1.0 - Admin Panel Discovery
**Purpose:** Find exposed web-based admin interfaces

**Key Features:**
- Multi-threaded web scanning
- 40+ panel type signatures
- SSL/TLS support (self-signed certs)
- Default credentials flagging
- Confidence scoring
- Quick/Full scan modes

**Output Files:**
- `panellist.txt` - Panel URLs
- `panel_details.txt` - Detailed panel info
- `panel_details.json` - JSON format

**Typical Use:**
```bash
./panelseek.py --full -v
```

---

## 🔄 Quick Comparison

| Feature | DCSeek | PrintSeek | PanelSeek |
|---------|--------|-----------|-----------|
| **Target** | Domain Controllers | Network Printers | Admin Panels |
| **Protocol** | LDAP, Kerberos, SMB | JetDirect, IPP, SNMP | HTTP/HTTPS |
| **Key Ports** | 88, 389, 445 | 9100, 161, 631 | 80, 443, 8080, 8443 |
| **Enumeration** | enum4linux | SNMP queries | Web scanning |
| **Extracts** | Users, Shares, Groups | Model, Serial, Location | Panel type, Vendor, Auth |
| **Confidence** | Binary (is/isn't DC) | 3 levels (High/Med/Low) | 3 levels (High/Med/Low) |
| **Output Formats** | TXT, JSON, Raw | TXT, JSON | TXT, JSON |
| **Workers** | 10 (default) | 10 (default) | 10 (default) |
| **CIDR Support** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Verbose Mode** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Default Creds** | ❌ No | ❌ No | ✅ Yes |
| **External Tools** | enum4linux | snmpget | None (stdlib) |

---

## 📊 Side-by-Side Usage

### Discovery Phase

**DCSeek:**
```bash
# Find Domain Controllers
./dcseek.py -f iplist.txt -v
```

**PrintSeek:**
```bash
# Find Printers
./printseek.py -f iplist.txt -v
```

**PanelSeek:**
```bash
# Find Admin Panels
./panelseek.py -f iplist.txt --full -v
```

### Enumeration Phase

**DCSeek:**
```bash
# Enumerate DCs with enum4linux
./dcseek.py --enum
```

**PrintSeek:**
```bash
# Enumerate printers via SNMP
./printseek.py -c private
```

**PanelSeek:**
```bash
# Check found panels (manual)
cat panellist.txt
# Try default credentials
# Screenshot with EyeWitness
```

### Re-enumeration

**DCSeek:**
```bash
# Re-run enum4linux only
./dcseek.py --enum-only
```

**PrintSeek:**
```bash
# Re-run SNMP only
./printseek.py --snmp-only -c admin
```

**PanelSeek:**
```bash
# Quick rescan with different ports
./panelseek.py --quick --ports 80 443
```

---

## 🎯 Typical Pentest Workflow

### Step 1: Network Discovery
```bash
# Discover all asset types
./dcseek.py -f 192.168.1.0/24 > /dev/null 2>&1 &
./printseek.py -f 192.168.1.0/24 > /dev/null 2>&1 &
./panelseek.py -f 192.168.1.0/24 --full > /dev/null 2>&1 &
wait
```

### Step 2: Review Findings
```bash
# Check what was found
echo "=== Domain Controllers ==="
cat dclist.txt

echo "=== Printers ==="
cat printerlist.txt

echo "=== Admin Panels ==="
cat panellist.txt
```

### Step 3: Enumerate
```bash
# Deep enumeration
./dcseek.py --enum
./printseek.py -c private
./printseek.py -c admin

# Panel analysis
grep "DEFAULT CREDS" panel_details.txt
eyewitness -f panellist.txt --web
```

### Step 4: Extract Intelligence
```bash
# Extract users from DCs
cat enum4linux_summary.json | jq -r '.[].users[]' > users.txt

# Extract printer locations (may reveal floor plans)
cat printer_details.json | jq -r '.[] | "\(.snmp_info.location)"' | sort -u > locations.txt

# Extract printer models (for CVE lookups)
cat printer_details.json | jq -r '.[] | .snmp_info.model' | sort -u > printer_models.txt

# Extract high-confidence panels
cat panel_details.json | jq -r '.[] | .panels[] | select(.confidence == "high") | .url' > high_value_panels.txt

# Group panels by vendor
cat panel_details.json | jq -r '.[] | .panels[].vendor' | sort | uniq -c | sort -rn
```

### Step 5: Attack
```bash
# Password spray against DCs
cme smb $(cat dclist.txt) -u users.txt -p 'Summer2024!'

# Test printers for vulnerabilities
nmap --script "printer-*" -iL printerlist.txt

# Test default credentials on panels
cat panel_details.json | jq -r '.[] | .panels[] | select(.default_creds_likely == true) | .url'
# Manually test: admin/admin, admin/password, etc.
```

---

## 📁 File Structure

After running all three tools:

```
Internal/
├── dcseek.py                      # DC discovery tool
├── printseek.py                   # Printer discovery tool
├── panelseek.py                   # Panel discovery tool
├── iplist.txt                     # Input: IP addresses
│
├── dclist.txt                     # Output: DC IPs
├── domain_controllers.txt         # Output: DC details
├── enum4linux_summary.txt         # Output: DC enumeration
├── enum4linux_summary.json        # Output: DC JSON
├── enum4linux_results/            # Output: Raw enum4linux
│
├── printerlist.txt                # Output: Printer IPs
├── printer_details.txt            # Output: Printer details
├── printer_details.json           # Output: Printer JSON
│
├── panellist.txt                  # Output: Panel URLs
├── panel_details.txt              # Output: Panel details
├── panel_details.json             # Output: Panel JSON
│
├── DCSEEK_README.md               # DCSeek documentation
├── DCSEEK_QUICKREF.txt            # DCSeek quick ref
├── DCSEEK_SUMMARY.md              # DCSeek summary
├── DCSEEK_ENHANCEMENTS.md         # DCSeek technical docs
├── DCSEEK_EXAMPLES.md             # DCSeek examples
├── DCSEEK_CHANGELOG.md            # DCSeek changelog
│
├── PRINTSEEK_README.md            # PrintSeek documentation
├── PRINTSEEK_QUICKREF.txt         # PrintSeek quick ref
├── PRINTSEEK_SUMMARY.md           # PrintSeek summary
│
├── PANELSEEK_README.md            # PanelSeek documentation
├── PANELSEEK_QUICKREF.txt         # PanelSeek quick ref
└── PANELSEEK_SUMMARY.md           # PanelSeek summary
```

---

## 🚀 Installation & Setup

### Prerequisites (Kali Linux)

```bash
# For DCSeek - enum4linux
sudo apt update
sudo apt install enum4linux

# For PrintSeek - SNMP tools
sudo apt install snmp snmp-mibs-downloader

# Enable MIBs (optional)
sudo sed -i 's/mibs :/# mibs :/' /etc/snmp/snmp.conf

# For PanelSeek - No dependencies!
# Uses Python standard library only
```

### Make Executable

```bash
chmod +x dcseek.py printseek.py panelseek.py
```

### Verify Installation

```bash
# Check DCSeek
./dcseek.py --help

# Check PrintSeek
./printseek.py --help

# Check PanelSeek
./panelseek.py --help

# Verify dependencies
which enum4linux   # For DCSeek
which snmpget      # For PrintSeek
```

---

## 💡 Advanced Usage

### Parallel Discovery
```bash
# Run both simultaneously on different subnets
./dcseek.py -f subnet1.txt > dc_scan.log 2>&1 &
./printseek.py -f subnet2.txt > printer_scan.log 2>&1 &
wait
```

### Multiple Networks
```bash
# Scan multiple network ranges
for subnet in "192.168.1.0/24" "10.0.0.0/24" "172.16.0.0/24"; do
    echo $subnet > temp_ips.txt
    ./dcseek.py -f temp_ips.txt
    ./printseek.py -f temp_ips.txt
done
```

### Automated Enumeration Loop
```bash
#!/bin/bash
# Complete discovery and enumeration

# Phase 1: Discovery
./dcseek.py -f iplist.txt
./printseek.py -f iplist.txt

# Phase 2: Enumeration
./dcseek.py --enum

# Try multiple SNMP communities
for community in public private admin community; do
    echo "[*] Trying SNMP community: $community"
    ./printseek.py --snmp-only -c $community
done

# Phase 3: Summary
echo "=== DISCOVERY SUMMARY ==="
echo "Domain Controllers: $(wc -l < dclist.txt)"
echo "Printers: $(wc -l < printerlist.txt)"
echo "Users Found: $(jq -r '.[].users[]' enum4linux_summary.json | wc -l)"
```

---

## 📊 Output Comparison

### DCSeek Output Example
```
[+] DOMAIN CONTROLLER FOUND: 192.168.1.10
    Hostname: DC01.CORP.LOCAL
    Open DC Ports: 88 (Kerberos), 389 (LDAP), 445 (SMB)
    
    Users found: 47
    Shares found: 6
    Sample users: Administrator, john.doe, jane.smith
```

### PrintSeek Output Example
```
[+++] PRINTER FOUND: 192.168.1.50 (Confidence: HIGH)
    Hostname: HP-LaserJet-4050.corp.local
    Open Ports: 9100 (HP JetDirect), 161 (SNMP), 80 (Web Interface)
    Name: HP-LJ-4050-Floor2
    Model: HP LaserJet 4050
    Location: 2nd Floor, IT Department
    Page Count: 145678
```

---

## 🎓 Training Scenarios

### Scenario 1: Initial Network Assessment
```bash
# Goal: Map AD infrastructure and identify printers
./dcseek.py -f 10.0.0.0/16 -w 50
./printseek.py -f 10.0.0.0/16 -w 50
```

### Scenario 2: Credential Validation
```bash
# After obtaining credentials
# Test against DCs
cme smb $(cat dclist.txt) -u admin -p 'P@ssw0rd'

# Try elevated SNMP access
./printseek.py --snmp-only -c obtained_community
```

### Scenario 3: Lateral Movement Prep
```bash
# Gather intelligence for next phase
./dcseek.py --enum               # Get user list
cat enum4linux_summary.json | jq -r '.[].shares[]' | grep -v 'SYSVOL\|NETLOGON'  # Find interesting shares
cat printer_details.json | jq -r '.[] | select(.snmp_info.page_count > "100000")'  # High-use printers
```

---

## 🔒 Security Considerations

### For DCSeek
- May trigger Windows Event logs (4624, 4625, 4768, 4776)
- enum4linux generates significant network traffic
- SMB/LDAP queries logged by domain controllers
- Kerberos pre-auth attempts visible to SOC

### For PrintSeek
- SNMP queries often logged by printers
- Web interface access may generate alerts
- Port scanning detected by network IDS
- Multiple failed community strings suspicious

### Best Practices
1. Obtain proper authorization
2. Inform SOC/Blue Team during exercises
3. Use rate limiting (-w lower, -t higher)
4. Operate during maintenance windows if possible
5. Clean up output files securely
6. Document findings properly

---

## 🛠️ Troubleshooting

### Common Issues

**DCSeek:**
- `enum4linux not found` → `sudo apt install enum4linux`
- `No DCs found` → Increase timeout `-t 3`, check network
- `Permission denied` → `chmod +x dcseek.py`
- `Timeout errors` → Reduce workers `-w 5`

**PrintSeek:**
- `snmpget not found` → `sudo apt install snmp`
- `No SNMP data` → Try different community `-c private`
- `No printers found` → Increase timeout, check ports
- `Web title fails` → Normal, some printers block HTTP

---

## 📈 Performance Guidelines

### Small Networks (< 256 hosts)
```bash
./dcseek.py -w 10 -t 1.0        # Default settings work well
./printseek.py -w 10 -t 1.0
```

### Medium Networks (256-4096 hosts)
```bash
./dcseek.py -w 25 -t 0.8        # Increase workers slightly
./printseek.py -w 25 -t 0.8
```

### Large Networks (> 4096 hosts)
```bash
./dcseek.py -w 50 -t 0.5        # Fast scanning
./printseek.py -w 50 -t 0.5
```

---

## 🎯 Success Metrics

After running both tools, you should have:

✅ List of all Domain Controllers  
✅ List of all network printers  
✅ User accounts from DCs  
✅ SMB shares from DCs  
✅ Printer models and locations  
✅ Printer serial numbers  
✅ Page counts (usage metrics)  
✅ JSON data for automation  

---

## 📞 Quick Reference

| Task | Command |
|------|---------|
| Find DCs | `./dcseek.py` |
| Find Printers | `./printseek.py` |
| Enumerate DCs | `./dcseek.py --enum` |
| Enumerate Printers | `./printseek.py -c private` |
| Fast scan | `-w 50 -t 0.5` |
| Thorough scan | `-w 5 -t 3` |
| Verbose output | `-v` |
| Custom input | `-f targets.txt` |
| Get help | `--help` |

---

## 🎉 Summary

You now have two powerful reconnaissance tools:

- **DCSeek** for Active Directory infrastructure mapping
- **PrintSeek** for printer discovery and enumeration

Both tools:
- Support multi-threading for fast scans
- Handle CIDR notation
- Export to multiple formats
- Include comprehensive error handling
- Are production-ready for pentesting

**Ready to use in Kali Linux!** 🎯

---

**Suite Version:** 1.0  
**Last Updated:** October 2025  
**Platform:** Kali Linux 2024+  
**Status:** ✅ Production Ready  
**Documentation:** Complete
