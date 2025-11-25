# SeekSweet Dependencies Documentation

## Overview
SeekSweet is a modular pentesting toolkit with 18 specialized seek modules. While most functionality works with Python's standard library and basic Kali tools, enhanced features require additional external tools.

**Quick Summary:**
- **Python Dependencies:** 2 required, 7 optional (see requirements.txt)
- **System Tools:** 6 critical, 4 optional
- **Installation Time:** ~5-10 minutes on fresh Kali

---

## Python Dependencies

### Required (Core Functionality)
```bash
pip install requests>=2.31.0 urllib3>=2.0.0
```

**Used by:** WebSeek, WinRMSeek, BackupSeek, PanelSeek

### Optional (Enhanced Features)
```bash
# Database testing (DbSeek)
pip install PyMySQL>=1.1.0 psycopg2-binary>=2.9.9 pymssql>=2.2.11 pymongo>=4.6.0 redis>=5.0.0

# Enhanced WinRM testing (WinRMSeek)
pip install pywinrm>=0.4.3
```

---

## System Tool Dependencies

### CRITICAL Tools (Core Functionality)

#### 1. **enum4linux** - Domain Controller Enumeration
- **Used by:** DCSeek
- **Purpose:** Comprehensive AD enumeration (users, shares, groups, policies)
- **Installation:**
  ```bash
  sudo apt-get install enum4linux
  # Alternative: enum4linux-ng (newer version)
  sudo apt-get install enum4linux-ng
  ```
- **Verification:** `enum4linux --help` or `enum4linux-ng --help`

#### 2. **ldap-utils** (ldapsearch) - LDAP Queries
- **Used by:** LDAPSeek
- **Purpose:** Direct LDAP enumeration of users, groups, computers
- **Installation:**
  ```bash
  sudo apt-get install ldap-utils
  ```
- **Verification:** `ldapsearch -VV`

#### 3. **smbclient** - SMB Share Testing
- **Used by:** SMBSeek, ShareSeek, CredSeek
- **Purpose:** SMB share enumeration and access testing
- **Installation:**
  ```bash
  sudo apt-get install smbclient
  ```
- **Verification:** `smbclient --version`

#### 4. **nmap** - Network Scanning & Vulnerability Scripts
- **Used by:** VulnSeek
- **Purpose:** NSE scripts for CVE detection (10+ vulnerability checks)
- **Installation:**
  ```bash
  sudo apt-get install nmap
  ```
- **Verification:** `nmap --version`

#### 5. **snmp / snmp-mibs-downloader** - SNMP Enumeration
- **Used by:** SNMPSeek
- **Purpose:** SNMP community string testing and OID enumeration
- **Installation:**
  ```bash
  sudo apt-get install snmp snmp-mibs-downloader
  ```
- **Verification:** `snmpwalk -V` and `snmpget -V`

#### 6. **impacket-scripts** - Kerberos Attacks
- **Used by:** KerbSeek
- **Purpose:** AS-REP roasting (GetNPUsers.py) and Kerberoasting (GetUserSPNs.py)
- **Installation:**
  ```bash
  sudo apt-get install impacket-scripts
  ```
- **Verification:** `GetUserSPNs.py -h` and `GetNPUsers.py -h`

### OPTIONAL Tools (Enhanced Features)

#### 7. **netexec** (formerly crackmapexec) - Advanced SMB Testing
- **Used by:** SMBSeek, DCSeek
- **Purpose:** SMB signing detection, advanced authentication testing
- **Installation:**
  ```bash
  # Method 1: pipx (recommended)
  sudo apt-get install pipx
  pipx install netexec
  
  # Method 2: pip
  pip install netexec
  
  # Legacy: crackmapexec (if netexec unavailable)
  sudo apt-get install crackmapexec
  ```
- **Verification:** `netexec --version`

#### 8. **rpcclient** - SMB RPC Enumeration
- **Used by:** SMBSeek (optional enhancement)
- **Purpose:** Additional SMB enumeration via RPC
- **Installation:**
  ```bash
  sudo apt-get install samba-common-bin
  ```
- **Verification:** `rpcclient --version`

#### 9. **nikto** - Web Vulnerability Scanning
- **Used by:** WebSeek (optional enhancement)
- **Purpose:** Web server vulnerability scanning
- **Installation:**
  ```bash
  sudo apt-get install nikto
  ```
- **Verification:** `nikto -Version`

#### 10. **nuclei** - Modern Web Vulnerability Scanner
- **Used by:** WebSeek (optional enhancement)
- **Purpose:** Fast, template-based vulnerability scanning
- **Installation:**
  ```bash
  # Method 1: Go install
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  
  # Method 2: Download binary
  wget -O nuclei.zip https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_2.9.15_linux_amd64.zip
  unzip nuclei.zip && sudo mv nuclei /usr/local/bin/
  ```
- **Verification:** `nuclei -version`

---

## Module-Specific Dependencies

| Module | Required Tools | Optional Tools | Python Packages |
|--------|---------------|----------------|------------------|
| **AliveSeek** | None | None | None |
| **BackupSeek** | None | None | requests, urllib3 |
| **BloodSeek** | None | None | None |
| **CredSeek** | None | smbclient | None |
| **DbSeek** | None | None | PyMySQL, psycopg2, pymssql, pymongo, redis |
| **DCSeek** | enum4linux | netexec, rpcclient | None |
| **KerbSeek** | impacket-scripts | None | None |
| **LDAPSeek** | ldapsearch | None | None |
| **NessusSeek** | None | None | None |
| **PanelSeek** | None | None | urllib3 |
| **PrintSeek** | None | None | None |
| **ShareSeek** | smbclient | None | None |
| **SMBSeek** | netexec | smbclient, rpcclient | None |
| **SNMPSeek** | snmpwalk, snmpget | None | None |
| **SSLSeek** | None | None | None |
| **VulnSeek** | nmap | None | None |
| **WebSeek** | None | nikto, nuclei | requests, urllib3 |
| **WinRMSeek** | None | None | requests, urllib3, pywinrm |

---

## Installation Commands

### Complete Installation (All Dependencies)

#### Kali Linux / Debian / Ubuntu
```bash
# Update package list
sudo apt-get update

# Install critical system tools
sudo apt-get install -y enum4linux ldap-utils smbclient nmap snmp snmp-mibs-downloader impacket-scripts

# Install optional tools
sudo apt-get install -y crackmapexec samba-common-bin nikto

# Install Python dependencies (required)
pip install requests>=2.31.0 urllib3>=2.0.0

# Install optional Python packages (uncomment what you need)
# pip install PyMySQL>=1.1.0 psycopg2-binary>=2.9.9 pymssql>=2.2.11 pymongo>=4.6.0 redis>=5.0.0 pywinrm>=0.4.3

# Install modern alternatives
pipx install netexec  # Modern crackmapexec replacement
```

#### RHEL / CentOS / Fedora
```bash
sudo yum install -y smbclient openldap-clients nmap net-snmp-utils
pip install requests urllib3
```

#### macOS (Homebrew)
```bash
brew install samba openldap nmap net-snmp
pip install requests urllib3
```

### Minimal Installation (Core Functionality Only)
```bash
# System tools
sudo apt-get install enum4linux ldap-utils smbclient nmap snmp impacket-scripts

# Python packages
pip install requests urllib3
```

---

## Verification Script

Create a dependency checker:

```bash
#!/bin/bash
# check_dependencies.sh

echo "=== SeekSweet Dependency Checker ==="

# Critical tools
for tool in enum4linux ldapsearch smbclient nmap snmpwalk snmpget GetUserSPNs.py GetNPUsers.py; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool found"
    else
        echo "✗ $tool MISSING (CRITICAL)"
    fi
done

# Optional tools
for tool in netexec crackmapexec rpcclient nikto nuclei; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool found (optional)"
    else
        echo "- $tool not found (optional)"
    fi
done

echo ""
echo "=== Python Package Check ==="
python3 -c "
import sys
required = ['requests', 'urllib3']
optional = ['PyMySQL', 'psycopg2', 'pymssql', 'pymongo', 'redis', 'pywinrm']

for pkg in required:
    try:
        __import__(pkg)
        print(f'✓ {pkg} found')
    except ImportError:
        print(f'✗ {pkg} MISSING (CRITICAL)')

for pkg in optional:
    try:
        __import__(pkg)
        print(f'✓ {pkg} found (optional)')
    except ImportError:
        print(f'- {pkg} not found (optional)')
"
```

---

## Common Issues & Solutions

### Issue: "enum4linux not found"
**Solution:**
```bash
sudo apt-get install enum4linux
# Or try the newer version:
sudo apt-get install enum4linux-ng
```

### Issue: "GetUserSPNs.py not found"
**Solution:**
```bash
sudo apt-get install impacket-scripts
# Verify installation:
find /usr -name "GetUserSPNs.py" 2>/dev/null
```

### Issue: "snmpwalk not found"
**Solution:**
```bash
sudo apt-get install snmp snmp-mibs-downloader
sudo download-mibs  # Download MIB files
```

### Issue: "netexec vs crackmapexec"
**Explanation:** NetExec is the modern replacement for CrackMapExec. SeekSweet supports both:
```bash
# Preferred (modern):
pipx install netexec

# Legacy (if needed):
sudo apt-get install crackmapexec
```

### Issue: Python packages not installing
**Solution:**
```bash
# Update pip first
python3 -m pip install --upgrade pip

# Install with explicit Python version
python3 -m pip install requests urllib3

# For database packages on Debian/Ubuntu:
sudo apt-get install python3-dev libpq-dev
```

---

## seek_utils.py Analysis

The shared utility module provides:

### `find_ip_list(filename: str) -> str`
**Purpose:** Intelligent IP list file discovery across multiple locations
**Search Order:**
1. Exact path (if absolute or exists as-is)
2. Current working directory
3. Script's directory
4. Parent directory (seeksweet root)
5. Two levels up (for nested tools)

**Usage:** Used by all seek modules to locate IP list files
**Error Handling:** Exits with helpful error message showing all search paths

---

## Environment Requirements

- **Python:** 3.8+ (tested on 3.8-3.13)
- **OS:** Linux (Kali recommended), macOS (limited), Windows WSL
- **Memory:** ~100MB for basic operation
- **Disk:** ~50MB for tool storage + logs
- **Network:** Outbound access for tool updates

---

## Security Considerations

⚠️ **Important:** These tools perform active network reconnaissance and may trigger security monitoring systems. Use only on authorized networks with proper permission.

**Recommended practices:**
- Test in isolated lab environments first
- Use VPN/proxy for external testing
- Monitor network traffic for detection signatures
- Follow responsible disclosure for findings

---

## Support & Updates

- **Documentation:** This file and individual module README files
- **Issues:** Check tool-specific error messages and logs
- **Updates:** Run `pip install -r requirements.txt --upgrade` periodically
- **Community:** Refer to individual tool documentation for advanced usage

**Last Updated:** 2024 - Compatible with current Kali Linux repositories