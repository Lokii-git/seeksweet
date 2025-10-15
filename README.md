# SeekSweet 🍬

**A Sweet Suite of Network Reconnaissance Tools**

SeekSweet is an orchestrated collection of **16 specialized penetration testing tools** designed for comprehensive Active Directory and network reconnaissance. Each tool focuses on a specific attack surface, providing deep enumeration and vulnerability assessment capabilities.

![Version](https://img.shields.io/badge/version-1.1-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-orange)

## ✨ What's New in v1.1

**Major Enhancements - October 2025:**

- 🔥 **SMB Relay Detection** - SMBSeek and DCSeek now detect SMB signing status for relay attacks
- 🔐 **LAPS Detection** - LDAPSeek identifies readable LAPS passwords
- 👥 **Enhanced Delegation** - Comprehensive unconstrained/constrained/RBCD detection
- 🎫 **Kerberos Cracking Guide** - Full hashcat/john guide with GPU time estimates
- 🩸 **BloodSeek** - NEW! BloodHound collection wrapper (11 collection methods)
- 🔒 **SSLSeek** - NEW! SSL/TLS vulnerability scanner wrapper (testssl.sh)
- 🗝️ **GPP Password Extraction** - Enhanced CredSeek with MS14-025 exploitation guide
- 📚 **10 Attack Guides** - Comprehensive exploitation guides auto-generated

## 🎯 Features

- **Guided Workflow** - Smart menu system with priority-based tool ordering
- **Persistent Tracking** - Automatic progress saving across sessions
- **Unified Interface** - Single orchestration tool for the entire suite
- **Comprehensive Coverage** - 14 specialized tools covering all major attack surfaces
- **Cross-Platform** - Works on Windows and Linux (Kali)
- **Intelligent IP List Sharing** - Shared `iplist.txt` across all tools
- **Rich Output** - Multiple formats (TXT, JSON) with detailed findings

## 🛠️ The Tools

### 🔍 Discovery Phase (CRITICAL)
1. **DCSeek** - Domain Controller discovery and enumeration + **SMB Signing Detection** 🆕
2. **LDAPSeek** - Active Directory LDAP enumeration + **LAPS Detection** + **Enhanced Delegation** + **Password Policy** 🆕
3. **SMBSeek** - SMB share discovery and enumeration + **SMB Relay Target Identification** 🆕
4. **ShareSeek** - Deep share analysis with permissions

### 🔐 Authentication Phase (HIGH)
5. **KerbSeek** - Kerberos service enumeration and Kerberoasting + **Hash Cracking Guide** 🆕
6. **CredSeek** - Credential store and password vault discovery + **GPP Password Extraction** 🆕

### 🚪 Access Phase (MEDIUM)
7. **WinRMSeek** - Windows Remote Management endpoint discovery

### 🌐 Web Phase (MEDIUM)
8. **WebSeek** - Web server discovery with vulnerability scanning
9. **PanelSeek** - Admin panel and management interface detection

### ⚙️ Services Phase (MEDIUM/LOW)
10. **DbSeek** - Database server discovery and enumeration
11. **BackupSeek** - Backup system infrastructure discovery
12. **PrintSeek** - Print server and printer enumeration
13. **SNMPSeek** - SNMP service discovery and device enumeration

### 🎯 Assessment Phase (CRITICAL/HIGH)
14. **VulnSeek** - Comprehensive vulnerability scanning
15. **BloodSeek** 🆕 - BloodHound collection wrapper with complete AD attack path analysis
16. **SSLSeek** 🆕 - SSL/TLS security scanner (Heartbleed, POODLE, DROWN, weak ciphers, etc.)

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Lokii-git/seeksweet.git
cd seeksweet

# Install Python dependencies (required for web/HTTP tools)
pip install -r requirements.txt

# Install system tools (Linux/Kali - highly recommended)
sudo apt-get install enum4linux ldap-utils smbclient nmap snmp impacket-scripts
```

### Basic Usage

1. **Create your target list:**
```bash
# Create iplist.txt in the seeksweet root
echo "192.168.1.0/24" > iplist.txt
echo "10.0.0.1" >> iplist.txt
```

2. **Run the orchestrator:**
```bash
python seeksweet.py
```

3. **Follow the guided menu:**
- Tools are organized by phase and priority
- Select individual tools (1-14)
- Run all sequentially (90)
- Run recommended sequence (92)

### Running Individual Tools

```bash
cd dcseek
python dcseek.py -f ../iplist.txt -v

cd ../ldapseek
python ldapseek.py ../iplist.txt -v

# New tools
cd ../bloodseek
python bloodseek.py -d DOMAIN.LOCAL -u user -p password -dc 10.10.10.10 --method All

cd ../sslseek
python sslseek.py target.com --full
```

## 🔥 Key Features Explained

### SMB Relay Attack Detection
**Tools: SMBSeek, DCSeek**

Automatically identifies systems vulnerable to NTLM relay attacks:
```bash
# SMBSeek detects SMB signing on all hosts
python smbseek.py iplist.txt -v

# Output includes:
# - smb_relay_targets.txt (hosts with signing disabled)
# - SMB_ATTACK_GUIDE.txt (ntlmrelayx commands)

# DCSeek focuses on Domain Controllers (critical!)
python dcseek.py -f iplist.txt -v
# - dc_smb_status.txt shows DC signing status
```

**Why it matters**: Unsigned SMB allows credential relay → Instant Domain Admin if DC is unsigned!

### LAPS Password Discovery
**Tool: LDAPSeek**

Identifies systems with readable LAPS passwords:
```bash
python ldapseek.py iplist.txt -u 'DOMAIN\user' -p 'password' -v

# Output includes:
# - laps_readable.txt (systems with LAPS passwords you can read)
# - LAPS_ATTACK_GUIDE.txt (extraction techniques)
```

**Why it matters**: LAPS passwords are local admin creds → Instant local admin access!

### Delegation Vulnerability Detection
**Tool: LDAPSeek**

Comprehensive delegation detection (unconstrained, constrained, RBCD):
```bash
python ldapseek.py iplist.txt -u 'DOMAIN\user' -p 'password' -v

# Output includes:
# - delegation_targets.txt (vulnerable accounts/computers)
# - DELEGATION_ATTACK_GUIDE.txt (Rubeus exploitation commands)
```

**Why it matters**: Delegation vulnerabilities can lead to Domain Admin via S4U2Self/S4U2Proxy attacks!

### Password Policy Extraction
**Tool: LDAPSeek**

Extracts domain password policy for safe password spraying:
```bash
python ldapseek.py iplist.txt -u 'DOMAIN\user' -p 'password' -v

# Output includes:
# - password_policy.txt (lockout threshold, complexity requirements)
# - USERS_ATTACK_GUIDE.txt (safe password spray commands)
```

**Why it matters**: Avoid account lockouts! Guide respects lockout policy and suggests safe spray timing.

### Kerberos Hash Cracking
**Tool: KerbSeek**

Enhanced hash output with cracking time estimates:
```bash
python kerbseek.py iplist.txt -u 'DOMAIN\user' -p 'password' -v

# Output includes:
# - spns.txt (Kerberoastable accounts)
# - asrep_users.txt (ASREPRoastable accounts)
# - KERBEROS_ATTACK_GUIDE.txt (hashcat/john commands + GPU timing)
```

**Why it matters**: Know if cracking is feasible before wasting time! Guide includes optimal hashcat parameters.

### GPP Password Extraction
**Tool: CredSeek**

Exploit MS14-025 vulnerability in Group Policy Preferences:
```bash
python credseek.py --gpp dclist.txt -v

# Output includes:
# - cred_details.txt (found GPP passwords)
# - GPP_ATTACK_GUIDE.txt (decryption methods, automated tools)
```

**Why it matters**: GPP passwords often grant local admin → Massive lateral movement opportunity!

### BloodHound Collection
**Tool: BloodSeek** 🆕

Wrapper for BloodHound-Python with comprehensive guide:
```bash
python bloodseek.py -d DOMAIN.LOCAL -u user -p password -dc 10.10.10.10 --method All

# Output includes:
# - *.json files (BloodHound data for Neo4j import)
# - bloodlist.txt (collection summary)
# - BLOODHOUND_GUIDE.txt (complete setup and analysis workflow)
```

**Why it matters**: Visualize AD attack paths, identify privilege escalation routes, find quick wins!

### SSL/TLS Vulnerability Scanning
**Tool: SSLSeek** 🆕

Wrapper for testssl.sh to detect SSL/TLS vulnerabilities:
```bash
python sslseek.py target.com --full

# Output includes:
# - ssllist.txt (vulnerability summary)
# - testssl_*.json (detailed results)
# - SSL_ATTACK_GUIDE.txt (exploitation techniques)
```

**Why it matters**: Detect Heartbleed, POODLE, DROWN, weak ciphers, certificate issues!

## 📊 Menu System

```
═══ DISCOVERY PHASE ═══              ═══ WEB PHASE ═══
 1. DCSeek [CRITICAL]                 8. WebSeek [MEDIUM]
 2. LDAPSeek [CRITICAL]               9. PanelSeek [MEDIUM]
 3. SMBSeek [CRITICAL]
 4. ShareSeek [HIGH]                 ═══ SERVICES PHASE ═══
                                     10. DbSeek [MEDIUM]
═══ AUTHENTICATION PHASE ═══        11. BackupSeek [MEDIUM]
 5. KerbSeek [HIGH]                  12. PrintSeek [LOW]
 6. CredSeek [HIGH]                  13. SNMPSeek [LOW]

═══ ACCESS PHASE ═══                ═══ ASSESSMENT PHASE ═══
 7. WinRMSeek [MEDIUM]               14. VulnSeek [HIGH]
```

## � Attack Guides (NEW!)

SeekSweet now auto-generates **comprehensive exploitation guides** with each tool:

| Guide File | Tool | Content | Lines |
|------------|------|---------|-------|
| `SMB_ATTACK_GUIDE.txt` | SMBSeek | ntlmrelayx commands, Responder integration, relay chains | ~400 |
| `LAPS_ATTACK_GUIDE.txt` | LDAPSeek | LAPS extraction, PyLAPSdumper, crackmapexec techniques | ~450 |
| `DELEGATION_ATTACK_GUIDE.txt` | LDAPSeek | Unconstrained/constrained/RBCD exploitation, Rubeus commands | ~600 |
| `USERS_ATTACK_GUIDE.txt` | LDAPSeek | Password spraying with lockout policy respect, kerbrute | ~350 |
| `KERBEROS_ATTACK_GUIDE.txt` | KerbSeek | Hash cracking (hashcat/john), GPU time estimates, rules | ~500 |
| `GPP_ATTACK_GUIDE.txt` | CredSeek | MS14-025 exploitation, gpp-decrypt, manual decryption | ~650 |
| `BLOODHOUND_GUIDE.txt` | BloodSeek | BloodHound-Python, SharpHound, Neo4j setup, Cypher queries | ~600 |
| `SSL_ATTACK_GUIDE.txt` | SSLSeek | Heartbleed, POODLE, DROWN, cipher attacks, certificate issues | ~700 |

**Total: 10 comprehensive guides covering AD attacks, network exploitation, and cryptographic vulnerabilities**

## �📝 Output Files

Each tool generates standardized output:

- `*list.txt` - Simple list of discovered hosts/services
- `*_details.txt` - Detailed findings with context
- `*_details.json` - Machine-readable JSON export (when available)
- `*_ATTACK_GUIDE.txt` 🆕 - Step-by-step exploitation instructions

**Example for LDAPSeek:**
```
ldaplist.txt                - Domain controllers found
users.txt                   - Enumerated usernames  
spns.txt                    - Kerberoastable accounts
asrep_users.txt             - ASREPRoastable accounts
admin_users.txt             - Administrative accounts
laps_readable.txt           🆕 - LAPS-enabled systems with readable passwords
delegation_targets.txt      🆕 - Delegation vulnerabilities found
password_policy.txt         🆕 - Domain password policy details
ldap_details.txt            - Full detailed output
ldap_details.json           - JSON export
LAPS_ATTACK_GUIDE.txt       🆕 - LAPS exploitation guide
DELEGATION_ATTACK_GUIDE.txt 🆕 - Delegation attack techniques
USERS_ATTACK_GUIDE.txt      🆕 - Password spray guide (respects lockout!)
```

## 🎓 Recommended Workflow

1. **Start with Discovery** - Run DCSeek, LDAPSeek, SMBSeek
2. **Authentication Recon** - Run KerbSeek, CredSeek
3. **Expand Coverage** - Run WinRMSeek, WebSeek, PanelSeek
4. **Service Discovery** - Run DbSeek, BackupSeek, SNMPSeek
5. **Final Assessment** - Run VulnSeek for vulnerability checks

Or use **Option 92** (Run Recommended Sequence) to automate critical tools in order.

## 🔧 Advanced Features

### Persistent Session Tracking

SeekSweet automatically saves progress to `.seeksweet_status.json`:
```json
{
  "completed_scans": {
    "1": "2025-10-14 15:30:45",
    "2": "2025-10-14 15:32:10"
  },
  "scan_outputs": {
    "1": "C:\\...\\dclist.txt",
    "2": "C:\\...\\ldaplist.txt, C:\\...\\ldap_details.txt"
  }
}
```

Completed tools show: `✓ COMPLETE` in the menu

### Shared IP List

All tools automatically search for `iplist.txt` in:
1. Current directory
2. Tool's directory
3. **Parent directory (seeksweet root)** ← Best practice
4. Specified path

### Cross-Platform Support

- **Windows**: Uses `python` and PowerShell
- **Linux/Kali**: Uses `python3` and Bash
- All path handling is OS-agnostic via Python's `os.path`

## 📚 Documentation

Each tool includes comprehensive documentation:

- `README.md` - Full feature documentation and usage examples
- `QUICKREF.md` - Quick reference and cheat sheet
- `SUMMARY.md` - Technical overview and use cases

**Suite Documentation:**
- `SEEK_TOOLS_OVERVIEW.md` - Complete suite overview
- `SEEK_TOOLS_README.md` - Master documentation
- `OUTPUT_FILE_COMPARISON.md` - Output file reference

## 🐛 Dependencies

### Required Python Packages
```bash
pip install -r requirements.txt
```
- **requests** - HTTP/HTTPS requests (WebSeek, WinRMSeek, BackupSeek)
- **urllib3** - URL handling (WebSeek, WinRMSeek, BackupSeek, PanelSeek)

### Optional Python Packages (Database Support)
Uncomment in `requirements.txt` as needed:
- **PyMySQL** - MySQL/MariaDB enumeration
- **psycopg2** - PostgreSQL enumeration
- **pymssql** - Microsoft SQL Server enumeration
- **pymongo** - MongoDB enumeration
- **redis** - Redis enumeration

### Required External Tools (Install via apt/brew/choco)
- **enum4linux** - DCSeek enumeration
- **ldapsearch** - LDAPSeek queries (ldap-utils package)
- **smbclient** - SMBSeek/ShareSeek share testing
- **nmap** - VulnSeek NSE scripts
- **snmpwalk** - SNMPSeek enumeration (snmp package)
- **impacket** - KerbSeek attacks (GetUserSPNs.py, GetNPUsers.py)

See `requirements.txt` for complete installation instructions per OS.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED TESTING ONLY**

These tools are designed for authorized penetration testing, security research, and educational purposes. You must have explicit permission to scan and test target networks.

Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of these tools.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with clear commit messages
4. Test thoroughly on both Windows and Linux
5. Submit a pull request

## 📄 License

MIT License - See LICENSE file for details

## 🙏 Credits

Created with ❤️ for the penetration testing community.

## 📧 Contact

- Issues: [GitHub Issues](https://github.com/yourusername/seeksweet/issues)
- Discussions: [GitHub Discussions](https://github.com/yourusername/seeksweet/discussions)

---

**Remember:** Always get proper authorization before running these tools against any network! 🔒
