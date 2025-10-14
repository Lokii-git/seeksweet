# DCSeek Changelog

All notable changes to the DCSeek project.

---

## [1.1] - 2025-10-13

### 🎉 Major Release - Enum4linux Integration

### Added
- **Enum4linux Integration**
  - `--enum` flag to run enum4linux on discovered DCs
  - `--enum-only` mode to skip discovery and enumerate from existing dclist.txt
  - Automated enum4linux execution with timeout handling
  - Support for both enum4linux and enum4linux-ng

- **Intelligent Parsing**
  - Extract domain users from enum4linux output
  - Parse SMB shares (excluding IPC$)
  - Capture domain groups
  - Parse password policy (min length, complexity, history, max age)
  - Extract domain name and OS information

- **Enhanced Output**
  - `dclist.txt` - Simple DC IP list (one per line)
  - `enum4linux_summary.txt` - Human-readable enumeration summary
  - `enum4linux_summary.json` - Machine-parsable JSON format
  - `enum4linux_results/` - Directory with raw enum4linux output per DC

- **New CLI Options**
  - `--enum` - Run enum4linux on discovered DCs
  - `--enum-only` - Enumerate from dclist.txt without discovery
  - `--dclist FILE` - Specify custom DC list file
  - `--enum-dir DIR` - Custom directory for enum4linux results

- **Progress Tracking**
  - Real-time enumeration progress (1/5, 2/5, etc.)
  - Per-DC summary during enumeration
  - Sample users displayed during scan
  - Final summary with totals

- **Error Handling**
  - Check for enum4linux installation
  - Handle subprocess timeouts (5 min default)
  - Continue on individual DC failures
  - Better keyboard interrupt handling
  - Directory creation with permission checks

### Changed
- Updated banner to v1.1 with "Enum4linux Integration" tagline
- Enhanced help text with enum examples
- Improved summary output formatting
- Better progress indicators

### Technical
- Added `parse_enum4linux_output()` function with regex patterns
- Added `run_enum4linux()` for subprocess management
- Added `save_dclist()` for DC list export
- Added `save_enum_summary()` for result aggregation
- Imported: `re`, `json`, `datetime` modules
- Added type hint: `Dict` from typing

### Documentation
- Created `DCSEEK_README.md` - Full user manual
- Created `DCSEEK_ENHANCEMENTS.md` - Technical details
- Created `DCSEEK_QUICKREF.txt` - Quick reference card
- Created `DCSEEK_EXAMPLES.md` - Sample outputs
- Created `DCSEEK_SUMMARY.md` - Complete summary
- Created `DCSEEK_CHANGELOG.md` - This file

---

## [1.0] - 2025-10-13

### 🎯 Initial Release - Domain Controller Discovery

### Added
- **Core Discovery Features**
  - Multi-threaded port scanning
  - DC identification by critical ports (88, 389, 445)
  - Additional DC port checks (53, 636, 3268, 3269)
  - Hostname resolution via reverse DNS
  - DNS SRV record validation
  - CIDR notation support for IP ranges

- **Error Handling**
  - File existence and permission checks
  - Invalid IP/CIDR detection with line numbers
  - CIDR size limits (prevents huge network scans)
  - Socket error handling with proper cleanup
  - Network timeout management
  - Keyboard interrupt support (Ctrl+C)

- **CLI Options**
  - `-f, --file` - Input IP file (default: iplist.txt)
  - `-t, --timeout` - Connection timeout (default: 1.0s)
  - `-w, --workers` - Concurrent workers (default: 10)
  - `-o, --output` - Output file (default: domain_controllers.txt)
  - `-v, --verbose` - Show all scanned hosts

- **Output**
  - ASCII banner
  - Real-time DC discovery notifications
  - Progress indicators (every 50 hosts)
  - Scan summary with statistics
  - Detailed output file with DC information

- **Input Validation**
  - IP address validation
  - CIDR notation parsing
  - Comment support in input file
  - Empty file detection
  - Line-by-line error reporting

### Technical
- Language: Python 3
- Dependencies: Standard library only (socket, ipaddress, subprocess, argparse, os)
- Threading: ThreadPoolExecutor for concurrent scanning
- Port scan timeout: Configurable per connection
- Default workers: 10 (configurable 1-100)

### Functions Implemented
- `read_ip_list()` - Parse and expand IP list
- `check_port()` - TCP port connectivity check
- `get_hostname()` - Reverse DNS lookup
- `check_dns_srv_records()` - AD DNS SRV validation
- `scan_host()` - Comprehensive DC detection
- `print_banner()` - ASCII art banner
- `main()` - CLI and orchestration

### Security Features
- Input sanitization
- Safe file operations with context managers
- Timeout protection against hanging connections
- Error messages without stack traces (user-friendly)
- Graceful degradation on failures

---

## Future Enhancements (Backlog)

### Planned for v1.2
- [ ] LDAP anonymous bind enumeration
- [ ] Kerberos pre-auth testing
- [ ] SMB null session detection
- [ ] Export to CSV format
- [ ] Colored terminal output
- [ ] Configuration file support

### Planned for v2.0
- [ ] Interactive mode
- [ ] Web-based dashboard
- [ ] Database backend for results
- [ ] Historical tracking
- [ ] Diff between scans
- [ ] Integration with other tools (Bloodhound, CrackMapExec)

### Community Requests
- [ ] Windows PowerShell version
- [ ] Docker container
- [ ] REST API
- [ ] Slack/Discord notifications
- [ ] Report generation (PDF/HTML)

---

## Version History Summary

| Version | Date | Description | Lines of Code |
|---------|------|-------------|---------------|
| 1.1 | 2025-10-13 | Enum4linux integration, parsing, JSON output | 704 |
| 1.0 | 2025-10-13 | Initial release, DC discovery | 365 |

---

## Breaking Changes

### From 1.0 to 1.1
- **None** - All v1.0 functionality preserved
- New flags are optional
- Backward compatible with v1.0 usage

---

## Known Issues

### Current
- None reported

### Resolved
- ✅ v1.0: Socket cleanup in error cases → Fixed with finally blocks
- ✅ v1.0: Large CIDR expansion → Added size limits
- ✅ v1.1: Variable scope in enum-only mode → Fixed initialization

---

## Credits

### Tools Integrated
- **enum4linux** - SMB/LDAP enumeration (Original by Portcullis Labs)
- **enum4linux-ng** - Modern Python rewrite (Alternative)

### Inspiration
- Inspired by standard pentesting workflows
- Built for Internal Red Team operations
- Designed for Kali Linux environment

---

## License

Internal use only. For authorized security assessments.

---

## Contributors

- **Internal Red Team** - Initial development and testing

---

## Changelog Format

This changelog follows [Keep a Changelog](https://keepachangelog.com/) principles.

### Categories
- **Added** - New features
- **Changed** - Changes to existing functionality
- **Deprecated** - Soon-to-be removed features
- **Removed** - Removed features
- **Fixed** - Bug fixes
- **Security** - Vulnerability fixes

---

**Last Updated:** October 13, 2025  
**Current Version:** 1.1  
**Status:** Stable
