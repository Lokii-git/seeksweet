# 🎯 Seek Tools Suite

**Network Discovery and Enumeration Toolkit for Penetration Testing**

A collection of specialized Python tools for discovering and enumerating network assets during security assessments.

---

## 📦 Tools

### 🏢 DCSeek v1.1 - Domain Controller Discovery
**Location:** `dcseek/dcseek.py`

Discover and enumerate Active Directory Domain Controllers with automated enum4linux integration.

**Quick Start:**
```bash
cd dcseek
./dcseek.py --enum
```

**Features:**
- Multi-threaded DC discovery (ports 88, 389, 445)
- Automated enum4linux execution
- User and share enumeration
- Password policy extraction
- JSON export for automation

**Documentation:**
- [Full README](dcseek/DCSEEK_README.md)
- [Quick Reference](dcseek/DCSEEK_QUICKREF.txt)
- [Examples](dcseek/DCSEEK_EXAMPLES.md)

---

### 🖨️ PrintSeek v1.0 - Network Printer Discovery
**Location:** `printseek.py`

Discover and enumerate network printers with SNMP integration.

**Quick Start:**
```bash
./printseek.py -c private
```

**Features:**
- Multi-threaded printer discovery (ports 9100, 161, 631)
- SNMP v2c enumeration
- Model, serial number, location extraction
- Confidence scoring (High/Medium/Low)
- Web interface detection

**Documentation:**
- [Full README](PRINTSEEK_README.md)
- [Quick Reference](PRINTSEEK_QUICKREF.txt)
- [Summary](PRINTSEEK_SUMMARY.md)

---

### 🌐 PanelSeek v1.0 - Admin Panel Discovery
**Location:** `panelseek.py`

Discover exposed web-based admin panels including routers, firewalls, and management consoles.

**Quick Start:**
```bash
./panelseek.py --full
```

**Features:**
- Multi-threaded web scanning (11 common ports)
- 40+ panel type signatures
- SSL/TLS support (self-signed certs)
- Default credentials flagging
- Confidence scoring (High/Medium/Low)
- Quick/Full scan modes

**Documentation:**
- [Full README](PANELSEEK_README.md)
- [Quick Reference](PANELSEEK_QUICKREF.txt)
- [Summary](PANELSEEK_SUMMARY.md)

---

## 🚀 Quick Start Guide

### Installation

```bash
# Install dependencies (Kali Linux)
sudo apt update
sudo apt install enum4linux snmp snmp-mibs-downloader

# PanelSeek requires no dependencies (stdlib only)

# Make scripts executable
chmod +x dcseek/dcseek.py printseek.py panelseek.py

# Verify installation
./dcseek/dcseek.py --help
./printseek.py --help
./panelseek.py --help
```

### Basic Usage

```bash
# Prepare IP list
echo "192.168.1.0/24" > iplist.txt

# Find Domain Controllers
cd dcseek && ./dcseek.py --enum && cd ..

# Find Printers
./printseek.py -c private

# Find Admin Panels
./panelseek.py --full

# Review findings
cat dcseek/dclist.txt       # DC IPs
cat printerlist.txt          # Printer IPs
cat panellist.txt            # Panel URLs
```

---

## 📊 Quick Comparison

| Feature | DCSeek | PrintSeek | PanelSeek |
|---------|--------|-----------|-----------|
| **Target** | Domain Controllers | Network Printers | Admin Panels |
| **Key Ports** | 88, 389, 445 | 9100, 161, 631 | 80, 443, 8080, 8443 |
| **Enumeration** | enum4linux | SNMP queries | Web scanning |
| **Outputs** | Users, Shares, Groups | Model, Serial, Location | Panel type, Vendor, Auth |
| **JSON Export** | ✅ Yes | ✅ Yes | ✅ Yes |
| **Default Creds** | ❌ No | ❌ No | ✅ Yes |
| **External Tools** | enum4linux | snmpget | None (stdlib) |

---

## 📁 Output Files

### DCSeek Outputs
```
dcseek/dclist.txt                  # DC IP list
dcseek/domain_controllers.txt      # Detailed DC info
dcseek/enum4linux_summary.txt      # Enumeration results
dcseek/enum4linux_summary.json     # JSON format
dcseek/enum4linux_results/         # Raw enum4linux output
```

### PrintSeek Outputs
```
printerlist.txt                    # Printer IP list
printer_details.txt                # Detailed printer info
printer_details.json               # JSON format
```

### PanelSeek Outputs
```
panellist.txt                      # Panel URL list
panel_details.txt                  # Detailed panel info
panel_details.json                 # JSON format
```

---

## 🎯 Typical Workflow

```bash
# Step 1: Discovery
cd dcseek && ./dcseek.py -f ../iplist.txt && cd ..
./printseek.py -f iplist.txt
./panelseek.py -f iplist.txt --full

# Step 2: Enumeration
cd dcseek && ./dcseek.py --enum && cd ..
./printseek.py -c private

# Panel analysis
grep "DEFAULT CREDS" panel_details.txt
eyewitness -f panellist.txt --web

# Step 3: Extract Intelligence
cat dcseek/enum4linux_summary.json | jq -r '.[].users[]' > users.txt
cat printer_details.json | jq -r '.[] | .snmp_info.location' > locations.txt
cat panel_details.json | jq -r '.[] | .panels[] | select(.confidence == "high") | .url' > high_value.txt

# Step 4: Attack
cme smb $(cat dcseek/dclist.txt) -u users.txt -p 'Password123'
# Test default credentials on panels from panellist.txt
```

---

## 📚 Documentation

### Overview
- [Seek Tools Overview](SEEK_TOOLS_OVERVIEW.md) - Complete suite documentation

### DCSeek Documentation
- [README](dcseek/DCSEEK_README.md) - Full user manual
- [Quick Reference](dcseek/DCSEEK_QUICKREF.txt) - Command cheat sheet
- [Examples](dcseek/DCSEEK_EXAMPLES.md) - Sample outputs
- [Enhancements](dcseek/DCSEEK_ENHANCEMENTS.md) - Technical details
- [Changelog](dcseek/DCSEEK_CHANGELOG.md) - Version history
- [Summary](dcseek/DCSEEK_SUMMARY.md) - Quick overview

### PrintSeek Documentation
- [README](PRINTSEEK_README.md) - Full user manual
- [Quick Reference](PRINTSEEK_QUICKREF.txt) - Command cheat sheet
- [Summary](PRINTSEEK_SUMMARY.md) - Quick overview

### PanelSeek Documentation
- [README](PANELSEEK_README.md) - Full user manual
- [Quick Reference](PANELSEEK_QUICKREF.txt) - Command cheat sheet
- [Summary](PANELSEEK_SUMMARY.md) - Quick overview

---

## 🛠️ Common Commands

### Discovery
```bash
# Find DCs
cd dcseek && ./dcseek.py -v

# Find Printers
./printseek.py -v

# Find Admin Panels
./panelseek.py --full -v

# Fast scan (large networks)
cd dcseek && ./dcseek.py -w 50 -t 0.5
./printseek.py -w 50 -t 0.5
./panelseek.py --quick -w 50 -t 1

# Thorough scan
cd dcseek && ./dcseek.py -w 5 -t 3
./printseek.py -w 5 -t 3
```

### Enumeration
```bash
# Enumerate DCs with enum4linux
cd dcseek && ./dcseek.py --enum

# Enumerate printers via SNMP
./printseek.py -c public
./printseek.py -c private
./printseek.py -c admin

# Re-enumerate only (skip discovery)
cd dcseek && ./dcseek.py --enum-only
./printseek.py --snmp-only -c private
```

### Data Extraction
```bash
# Extract users from DCs
cat dcseek/enum4linux_summary.json | jq -r '.[].users[]' > users.txt

# Extract shares
cat dcseek/enum4linux_summary.json | jq -r '.[].shares[]' > shares.txt

# Extract printer models
cat printer_details.json | jq -r '.[].snmp_info.model' | sort -u

# Find high-use printers
cat printer_details.json | jq '.[] | select(.snmp_info.page_count > "100000")'
```

---

## 🔧 Integration Examples

### With CrackMapExec
```bash
# Password spray against DCs
cme smb $(cat dcseek/dclist.txt) -u users.txt -p passwords.txt

# Check shares
cme smb $(cat dcseek/dclist.txt) -u username -p password --shares
```

### With Nmap
```bash
# Detailed DC scan
nmap -sV -sC -p- -iL dcseek/dclist.txt -oA dc_scan

# Detailed printer scan
nmap -sV -sC -p 9100,161,631 -iL printerlist.txt -oA printer_scan
```

### With PRET (Printers)
```bash
# Test each printer with PRET
while read ip; do
  python pret.py $ip pjl
done < printerlist.txt
```

---

## 🎓 Prerequisites

### Required (Both Tools)
- Python 3.6+
- Network connectivity
- Kali Linux (recommended)

### DCSeek Requirements
```bash
sudo apt install enum4linux
```

### PrintSeek Requirements
```bash
sudo apt install snmp snmp-mibs-downloader
```

---

## ⚠️ Security Notice

**IMPORTANT:** These tools are for authorized penetration testing only.

- Obtain proper authorization before scanning
- Tools may trigger IDS/IPS alerts
- Activity is logged by target systems
- Store results securely
- Follow responsible disclosure practices

---

## 📊 Statistics

### DCSeek
- **Lines of Code:** 704
- **Version:** 1.1
- **Features:** 15+
- **Output Formats:** 5

### PrintSeek
- **Lines of Code:** 668
- **Version:** 1.0
- **Features:** 16+
- **Output Formats:** 3

---

## 🐛 Troubleshooting

### DCSeek
```bash
# enum4linux not found
sudo apt install enum4linux

# No DCs found
./dcseek.py -v -t 3  # Verbose, longer timeout

# Permission denied
chmod +x dcseek.py
```

### PrintSeek
```bash
# snmpget not found
sudo apt install snmp

# No SNMP data
./printseek.py -c private  # Try different community

# No printers found
./printseek.py -v -t 3  # Verbose, longer timeout
```

---

## 💡 Tips & Tricks

### For DCSeek
1. Use `--enum` for full intelligence gathering
2. JSON output perfect for automation
3. Re-run with `--enum-only` after initial discovery
4. Check `enum4linux_results/` for detailed raw data

### For PrintSeek
1. Try multiple SNMP communities (`public`, `private`, `admin`)
2. Location field often reveals floor plans
3. High page counts indicate important printers
4. Serial numbers useful for CVE lookups
5. Web interfaces may have default credentials

---

## 🎯 Use Cases

### Red Team Operations
- Map AD infrastructure (DCSeek)
- Identify persistence targets (both)
- Gather user lists for spraying (DCSeek)
- Find data exfiltration points (both)

### Internal Penetration Testing
- Discover domain controllers
- Enumerate users and shares
- Find network printers
- Extract configuration data

### Network Assessment
- Inventory Active Directory
- Map print infrastructure
- Identify misconfigurations
- Gather network intelligence

---

## 🏆 Success Criteria

After running the suite, you should have:

✅ Complete list of Domain Controllers  
✅ User accounts and groups from DCs  
✅ SMB shares inventory  
✅ Password policy information  
✅ Complete list of network printers  
✅ Printer models and locations  
✅ SNMP configuration data  
✅ JSON exports for automation  

---

## 📞 Getting Help

### Quick Help
```bash
./dcseek/dcseek.py --help
./printseek.py --help
```

### Documentation
- Check the README files for detailed usage
- Review Quick Reference files for commands
- See SEEK_TOOLS_OVERVIEW.md for comprehensive guide

---

## 🎉 Ready to Use!

Both tools are production-ready and tested on Kali Linux.

**Start with:**
```bash
# Make executable
chmod +x dcseek/dcseek.py printseek.py

# Run basic discovery
cd dcseek && ./dcseek.py -v
cd .. && ./printseek.py -v
```

---

**Suite Version:** 1.0  
**Last Updated:** October 2025  
**Platform:** Kali Linux 2024+  
**Status:** ✅ Production Ready  

**Created by:** Internal Red Team  
**Purpose:** Authorized Security Assessments  
**License:** Internal Use Only

---

**Happy Hunting! 🎯🔍**
