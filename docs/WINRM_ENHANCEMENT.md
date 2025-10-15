# WinRMSeek v1.1 - Connection Testing Enhancement

## Overview
WinRMSeek has been enhanced from basic port scanning to **full connection testing with command execution**, similar to DbSeek's credential validation approach.

## Implementation Date
October 15, 2025

## What Was Added

### 1. Real Connection Testing (~300 lines)
**Function**: `test_winrm_auth_pywinrm()`

**Features**:
- Opens actual WinRM shell using pywinrm library
- Executes commands to verify access:
  * `whoami` - Validates authentication
  * `hostname` - Gets computer name
  * `systeminfo` - Retrieves OS information
- Enhanced error handling with specific messages:
  * 401 Unauthorized - Invalid credentials
  * 403 Forbidden - Valid creds but insufficient privileges
  * Connection timeout
  * Connection refused
- Returns detailed authentication results

**Before**: Only checked if ports were open  
**After**: Actually tests if you can connect and execute commands

### 2. Enhanced Access List (~100 lines)
**File**: `winrm_access.txt`

**New Content**:
- Hostname and OS information
- Whoami output showing context
- Connection commands for multiple tools:
  * evil-winrm (Linux/Kali)
  * PowerShell remoting (Windows)
  * Python pywinrm code snippets
- Copy/paste ready commands

### 3. Comprehensive Attack Guide (~800 lines)
**File**: `WINRM_ATTACK_GUIDE.txt`

**Sections**:
1. **evil-winrm** - Installation, usage, advanced features, pass-the-hash
2. **PowerShell Remoting** - Interactive sessions, one-liners, file copy
3. **pywinrm** - Python library examples for automation
4. **Credential Attacks** - Password spraying, pass-the-hash, Kerberos
5. **Post-Exploitation** - Enumeration, credential harvesting, lateral movement
6. **CrackMapExec** - WinRM module usage and examples
7. **Defense Evasion** - AMSI bypass, AV disabling, log clearing
8. **Detection** - Event IDs, network indicators, defensive measures
9. **Secure Configuration** - Blue team guidance
10. **References** - Tools and documentation links

### 4. Enhanced Console Output
**Before**: `[WINRM] 192.168.1.100 - HTTP:5985`  
**After**: `[WINRM] 192.168.1.100 (SERVER01) - HTTP:5985 [✓ ACCESS] as DOMAIN\admin`

Shows:
- Hostname (if discovered)
- Authentication status
- Username context

### 5. Improved Details File
**File**: `winrm_details.txt`

**Added**:
- Hostname
- Whoami output
- OS information
- Authentication failure reasons (if applicable)

## Philosophy Compliance

✅ **"Guide, don't exploit"** - Maintained!

**What it does**:
- ✅ Tests if credentials work
- ✅ Extracts system information for documentation
- ✅ Generates exploitation guides for operators
- ✅ Provides copy/paste commands

**What it doesn't do**:
- ❌ No automatic exploitation
- ❌ No payload execution
- ❌ No credential dumping
- ❌ No lateral movement

**Justification**: 
Testing if you can connect with provided credentials is **validation**, not exploitation. This is equivalent to:
- DbSeek testing database credentials
- SMBSeek checking share access
- LDAPSeek authenticating to LDAP

The tool validates access, operators decide what to do next.

## Code Statistics

| Component | Lines Added | Description |
|-----------|-------------|-------------|
| Connection Testing | ~300 | pywinrm integration with command execution |
| Access List Enhancement | ~100 | Multi-tool connection commands |
| Attack Guide Generation | ~800 | Comprehensive exploitation guide |
| Console Output | ~50 | Enhanced display with system info |
| Details File | ~50 | Improved output formatting |
| **Total** | **~1,300** | **Total lines of new code** |

## Usage Examples

### Basic Discovery
```bash
python winrmseek.py iplist.txt
```

### With Connection Testing
```bash
python winrmseek.py iplist.txt -t -u admin -p P@ssw0rd123
```

### Verbose Output
```bash
python winrmseek.py iplist.txt -t -u admin -p P@ssw0rd123 -v
```

### HTTPS Only
```bash
python winrmseek.py iplist.txt -t -u admin -p P@ssw0rd123 --ssl
```

## Output Files

| File | Description |
|------|-------------|
| `winrmlist.txt` | List of WinRM enabled hosts |
| `winrm_access.txt` | **NEW:** Hosts with valid credentials + connection commands |
| `winrm_details.txt` | Detailed findings with system info |
| `winrm_details.json` | JSON export for automation |
| `WINRM_ATTACK_GUIDE.txt` | **NEW:** Comprehensive exploitation guide (~800 lines) |

## Comparison: Before vs After

### Before (v1.0)
```
[WINRM] 192.168.1.100 - HTTP:5985
[WINRM] 192.168.1.101 - HTTP:5985, HTTPS:5986
```

**Limitations**:
- Only showed open ports
- No connection validation
- No system information
- Minimal guidance

### After (v1.1)
```
[WINRM] 192.168.1.100 (SERVER01) - HTTP:5985 [✓ ACCESS] as CONTOSO\admin
[WINRM] 192.168.1.101 (DC01) - HTTP:5985, HTTPS:5986 [✓ ACCESS] as CONTOSO\admin
```

**Enhancements**:
- ✅ Shows hostnames
- ✅ Validates connections
- ✅ Extracts system info
- ✅ Comprehensive guide
- ✅ Multiple tool commands
- ✅ Enhanced error messages

## Dependencies

### Required
- Python 3.6+
- Standard library (socket, subprocess, json, etc.)

### Optional (for connection testing)
- `pywinrm` - For actual connection testing
  ```bash
  pip install pywinrm
  ```

**Note**: If pywinrm is not installed, tool falls back to basic port scanning.

## Rating Improvement

| Version | Rating | Reason |
|---------|--------|--------|
| v1.0 | ⭐⭐☆☆☆ (2/5) | Basic port scanning only |
| v1.1 | ⭐⭐⭐⭐☆ (4/5) | Real connection testing + comprehensive guide |

**Improvement**: +2 stars

## Future Enhancements (Optional)

1. **Kerberos Authentication** - Test with TGT/service tickets
2. **Certificate-Based Auth** - Test cert authentication
3. **Session Monitoring** - Track active WinRM sessions
4. **Batch Execution** - Run commands on multiple hosts

## References

- **WinRM Protocol**: https://docs.microsoft.com/en-us/windows/win32/winrm/portal
- **PowerShell Remoting**: https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands
- **pywinrm Library**: https://github.com/diyan/pywinrm
- **evil-winrm**: https://github.com/Hackplayers/evil-winrm
- **MITRE ATT&CK T1021.006**: https://attack.mitre.org/techniques/T1021/006/

---

**Status**: ✅ COMPLETE - Production Ready  
**Version**: 1.1  
**Author**: Lokii-git  
**Repository**: github.com/Lokii-git/seeksweet
