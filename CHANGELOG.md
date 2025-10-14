# SeekSweet Changelog

All notable changes to the SeekSweet project will be documented in this file.

## [1.0.0] - 2025-10-14

### 🎉 Initial Release

Complete suite of 14 network reconnaissance tools with orchestration system.

### Added

#### Core Features
- **SeekSweet Orchestrator** - Guided menu system for entire tool suite
- **Persistent Session Tracking** - Automatic progress saving with `.seeksweet_status.json`
- **Shared Utilities** - `seek_utils.py` for centralized IP list discovery
- **Cross-Platform Support** - Windows and Linux (Kali) compatibility
- **Completion Tracking** - Visual indicators for completed scans

#### The 14 Tools

**Discovery Phase (CRITICAL)**
1. **DCSeek** - Domain Controller discovery and enum4linux integration
2. **LDAPSeek** - Active Directory LDAP enumeration (users, groups, SPNs, ASREP)
3. **SMBSeek** - SMB share discovery with version detection
4. **ShareSeek** - Deep share analysis with permissions and content discovery

**Authentication Phase (HIGH)**
5. **KerbSeek** - Kerberos enumeration, Kerberoasting, and ASREPRoasting
6. **CredSeek** - Credential store discovery (SAM, NTDS, password vaults)

**Access Phase (MEDIUM)**
7. **WinRMSeek** - Windows Remote Management endpoint discovery and authentication testing

**Web Phase (MEDIUM)**
8. **WebSeek** - Web server discovery with directory bruteforcing and git repo detection
9. **PanelSeek** - Admin panel and management interface discovery

**Services Phase (MEDIUM/LOW)**
10. **DbSeek** - Database server discovery (SQL, MySQL, PostgreSQL, MongoDB, Redis)
11. **BackupSeek** - Backup system infrastructure discovery (Veeam, TSM, etc.)
12. **PrintSeek** - Print server and printer enumeration
13. **SNMPSeek** - SNMP service discovery with community string bruteforce

**Assessment Phase (HIGH)**
14. **VulnSeek** - Comprehensive vulnerability scanning with Nmap NSE scripts

#### Documentation
- Individual README.md for each tool with full feature documentation
- QUICKREF.md cheat sheets for rapid reference
- SUMMARY.md technical overviews
- Suite-level documentation (OVERVIEW, README, CHANGELOG)
- Main repository README with installation and usage guide

#### Features Per Tool
- Multi-threaded scanning for performance
- Multiple output formats (TXT, JSON where applicable)
- Verbose and quiet modes
- Progress indicators
- Error handling and logging
- CIDR notation support for IP ranges
- Credential discovery and validation
- Service-specific enumeration techniques

### Fixed

#### Version 1.0.0 Fixes
- **CIDR Expansion Bug** (BackupSeek) - Fixed 192.168.1.0/24 being treated as single IP
  - Added `ipaddress` module for proper CIDR expansion
  - Now correctly expands /24 to 254 individual IPs
  
- **Unicode Encoding Issues** (BackupSeek, DCSeek) - Fixed cp1252 encoding errors on Windows
  - Replaced Unicode box-drawing characters with ASCII equivalents
  - Ensured cross-platform banner compatibility
  
- **IP List Discovery** (All tools) - Fixed tools not finding iplist.txt in parent directory
  - Created `seek_utils.py` with `find_ip_list()` function
  - Searches CWD, script dir, parent dir, 2 levels up
  - All 13 IP-based tools updated to use shared utility
  
- **Output File Tracking** (SeekSweet) - Fixed incorrect output file expectations
  - Validated all 14 tools' actual output files
  - Corrected SEEK_TOOLS definitions for 7 tools:
    * DCSeek: Removed non-existent dc_details files
    * SMBSeek: Added missing sharelist.txt
    * ShareSeek: Removed non-existent JSON file
    * PrintSeek: Fixed filename mismatch (printerlist vs printlist)
    * DbSeek: Added missing db_creds.txt
    * PanelSeek: Removed non-existent JSON file
    * VulnSeek: Removed non-existent JSON file
  - Completion tracking now accurately detects finished scans

### Technical Details

#### Architecture
- Python 3.8+ standard library only (no pip dependencies)
- Subprocess-based tool execution
- JSON-based persistence system
- ANSI color codes for terminal output
- Path-independent tool discovery

#### Testing
- Verified on Windows 10/11 with PowerShell
- Verified on Kali Linux 2024.x
- Tested DCSeek and LDAPSeek against live targets
- CIDR expansion validated (192.168.1.0/24 → 254 IPs)
- Persistent tracking validated across sessions

### Known Issues
- Some external tools (enum4linux, ldapsearch) must be installed separately
- Windows requires manual installation of many Linux tools
- JSON output not available for all tools (by design - only where useful)

### Security Notes
- All tools are for **authorized testing only**
- Requires explicit permission to scan target networks
- No default credentials or exploit code included
- Focuses on discovery and enumeration, not exploitation

---

## Future Roadmap

### Planned for v1.1
- [ ] Export to CrackMapExec and BloodHound formats
- [ ] Integration with common pentest frameworks
- [ ] HTML report generation
- [ ] Automated credential validation across tools
- [ ] Enhanced error logging to file

### Planned for v2.0
- [ ] Web-based dashboard
- [ ] Real-time progress monitoring
- [ ] Distributed scanning support
- [ ] Plugin system for custom tools
- [ ] Timeline visualization of discovery process

---

## Version History

- **v1.0.0** (2025-10-14) - Initial release with 14 tools and orchestrator

---

## Contributing

See CONTRIBUTING.md for guidelines on submitting changes and bug reports.

## License

MIT License - See LICENSE file for details.
