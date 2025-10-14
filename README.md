# SeekSweet 🍬

**A Sweet Suite of Network Reconnaissance Tools**

SeekSweet is an orchestrated collection of 14 specialized penetration testing tools designed for comprehensive Active Directory and network reconnaissance. Each tool focuses on a specific attack surface, providing deep enumeration and vulnerability assessment capabilities.

![Version](https://img.shields.io/badge/version-1.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![License](https://img.shields.io/badge/license-MIT-orange)

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
1. **DCSeek** - Domain Controller discovery and enumeration
2. **LDAPSeek** - Active Directory LDAP enumeration (users, groups, SPNs)
3. **SMBSeek** - SMB share discovery and enumeration
4. **ShareSeek** - Deep share analysis with permissions

### 🔐 Authentication Phase (HIGH)
5. **KerbSeek** - Kerberos service enumeration and Kerberoasting
6. **CredSeek** - Credential store and password vault discovery

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

### 🎯 Assessment Phase (HIGH)
14. **VulnSeek** - Comprehensive vulnerability scanning

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yourusername/seeksweet.git
cd seeksweet
pip install -r requirements.txt  # If dependencies needed
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
```

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

## 📝 Output Files

Each tool generates standardized output:

- `*list.txt` - Simple list of discovered hosts/services
- `*_details.txt` - Detailed findings with context
- `*_details.json` - Machine-readable JSON export (when available)

**Example for LDAPSeek:**
```
ldaplist.txt          - Domain controllers found
users.txt             - Enumerated usernames
spns.txt              - Kerberoastable accounts
asrep_users.txt       - ASREPRoastable accounts
admin_users.txt       - Administrative accounts
ldap_details.txt      - Full detailed output
ldap_details.json     - JSON export
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

### Core Requirements
- Python 3.8+
- Standard library only (no pip packages for basic functionality)

### Optional External Tools (for enhanced features)
- `enum4linux` - For DCSeek enumeration
- `ldapsearch` - For LDAPSeek queries
- `smbclient` - For SMBSeek share access testing
- `nmap` - For VulnSeek NSE scripts
- `snmpwalk` - For SNMPSeek enumeration

Most tools work without external dependencies for basic discovery.

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
