# LDAPSeek v1.0

## 🔍 Active Directory LDAP Enumeration Tool

LDAPSeek is a comprehensive Active Directory enumeration tool that performs deep LDAP reconnaissance to identify attack vectors including Kerberoastable accounts, ASREPRoastable users, privileged accounts, delegation issues, and more. It's designed to map the AD attack surface for penetration testing.

---

## 🎯 Key Features

### Active Directory Enumeration
- **Domain Information** - Domain name, functional level, Domain Controllers
- **User Enumeration** - All users with detailed attributes (UPN, UAC flags, SPNs)
- **Group Enumeration** - All groups, especially privileged groups
- **Computer Enumeration** - Domain-joined computers with OS information
- **SPN Discovery** - Service Principal Names for Kerberoasting

### Attack Surface Identification
- **Kerberoastable Users** - Users with SPNs (TGS ticket request targets)
- **ASREPRoastable Users** - Users with DONT_REQ_PREAUTH flag
- **Privileged Accounts** - Domain Admins, Enterprise Admins, etc.
- **Delegation Issues** - Unconstrained/constrained delegation
- **Admin Accounts** - Users with adminCount=1 or high-value group membership

### User Account Control (UAC) Analysis
- **Flag Parsing** - Interprets all 26 UAC bit flags
- **Security Flags** - DONT_REQ_PREAUTH, TRUSTED_FOR_DELEGATION, etc.
- **Account Status** - ACCOUNTDISABLE, PASSWORD_EXPIRED, LOCKOUT
- **Password Policy** - DONT_EXPIRE_PASSWORD, PASSWD_NOTREQD

---

## 📦 Installation

### Prerequisites
```bash
# Install ldapsearch (OpenLDAP utilities)
sudo apt install ldap-utils

# Or on Red Hat/CentOS
sudo yum install openldap-clients
```

### Setup
```bash
cd Internal/ldapseek/
chmod +x ldapseek.py
```

---

## 🚀 Usage

### Basic Usage
```bash
# Scan Domain Controllers from file
./ldapseek.py dclist.txt

# Scan single DC
./ldapseek.py dc01.corp.local

# Scan with IP address
./ldapseek.py 192.168.1.10
```

### Authenticated Scanning
```bash
# With domain credentials (recommended)
./ldapseek.py dclist.txt -u username -p password

# With domain prefix
./ldapseek.py dclist.txt -u CORP\\username -p password

# With UPN format
./ldapseek.py dclist.txt -u user@corp.local -p password
```

### Enumeration Modes
```bash
# Full enumeration (all features)
./ldapseek.py dclist.txt --full -u user -p pass

# Only enumerate users
./ldapseek.py dclist.txt --users -u user -p pass

# Only find Kerberoastable accounts
./ldapseek.py dclist.txt --spns -u user -p pass

# Only find ASREPRoastable accounts
./ldapseek.py dclist.txt --asrep -u user -p pass

# Only find admin accounts
./ldapseek.py dclist.txt --admins -u user -p pass

# Only enumerate groups
./ldapseek.py dclist.txt --groups -u user -p pass
```

### Advanced Options
```bash
# Increase threading (default: 5)
./ldapseek.py dclist.txt --threads 10

# Output to JSON
./ldapseek.py dclist.txt --json

# LDAPS (port 636) instead of LDAP (port 389)
./ldapseek.py dclist.txt --ldaps

# Specify custom base DN
./ldapseek.py dclist.txt --base "DC=corp,DC=local"
```

---

## 📊 Output Files

### ldaplist.txt
List of accessible Domain Controllers:
```
dc01.corp.local:389
dc02.corp.local:389
192.168.1.10:389
```

### users.txt
All discovered usernames:
```
administrator
jsmith
svc_sql
svc_backup
testuser
```

### spns.txt
Kerberoastable accounts (users with SPNs):
```
svc_sql
svc_iis
svc_sharepoint
HTTP/webserver.corp.local
MSSQLSvc/sqlserver.corp.local:1433
```

### asrep_users.txt
ASREPRoastable accounts (no Kerberos pre-auth):
```
testuser
vendor_account
oldaccount
```

### admin_users.txt
Privileged user accounts:
```
administrator
domain_admin_jdoe
enterprise_admin_bob
backup_operator_alice
```

### ldap_details.txt
Comprehensive text report with:
- Domain information
- User statistics
- UAC flag analysis
- Group memberships
- Delegation findings
- Security recommendations

### ldap_details.json
Machine-readable JSON output:
```json
{
  "domain": "CORP.LOCAL",
  "domain_controllers": ["dc01.corp.local", "dc02.corp.local"],
  "users": {
    "total": 1523,
    "enabled": 1401,
    "disabled": 122,
    "kerberoastable": 15,
    "asrep_roastable": 3,
    "admin_accounts": 42
  },
  "findings": [
    {
      "username": "svc_sql",
      "upn": "svc_sql@corp.local",
      "uac_flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"],
      "spns": ["MSSQLSvc/sqlserver.corp.local:1433"],
      "member_of": ["Domain Users"],
      "admin_count": 0,
      "kerberoastable": true
    }
  ]
}
```

---

## 🔍 Understanding UAC Flags

### What is User Account Control (UAC)?
UAC is a 32-bit field in Active Directory that stores account properties using bit flags. LDAPSeek decodes these flags to identify security-relevant configurations.

### Important Security Flags

| Flag | Value | Security Impact |
|------|-------|-----------------|
| **DONT_REQ_PREAUTH** | 0x400000 | ASREPRoastable - can request AS-REP without password |
| **TRUSTED_FOR_DELEGATION** | 0x80000 | Unconstrained delegation - can impersonate any user |
| **TRUSTED_TO_AUTH_FOR_DELEGATION** | 0x1000000 | Constrained delegation - S4U2Self/S4U2Proxy |
| **NOT_DELEGATED** | 0x100000 | Protected from delegation attacks |
| **DONT_EXPIRE_PASSWORD** | 0x10000 | Password never expires |
| **PASSWD_NOTREQD** | 0x20 | No password required |
| **ACCOUNTDISABLE** | 0x2 | Account is disabled |
| **LOCKOUT** | 0x10 | Account is locked out |

### Complete UAC Flag List
```
SCRIPT (0x1)                           - Login script executed
ACCOUNTDISABLE (0x2)                   - Account disabled
HOMEDIR_REQUIRED (0x8)                 - Home directory required
LOCKOUT (0x10)                         - Account locked out
PASSWD_NOTREQD (0x20)                  - No password required
PASSWD_CANT_CHANGE (0x40)              - User cannot change password
ENCRYPTED_TEXT_PWD_ALLOWED (0x80)      - Store password using reversible encryption
TEMP_DUPLICATE_ACCOUNT (0x100)         - Local user account
NORMAL_ACCOUNT (0x200)                 - Default account type
INTERDOMAIN_TRUST_ACCOUNT (0x800)      - Trust account
WORKSTATION_TRUST_ACCOUNT (0x1000)     - Computer account
SERVER_TRUST_ACCOUNT (0x2000)          - Domain Controller account
DONT_EXPIRE_PASSWORD (0x10000)         - Password never expires
MNS_LOGON_ACCOUNT (0x20000)            - MNS logon account
SMARTCARD_REQUIRED (0x40000)           - Smartcard required
TRUSTED_FOR_DELEGATION (0x80000)       - Unconstrained delegation
NOT_DELEGATED (0x100000)               - Cannot be delegated
USE_DES_KEY_ONLY (0x200000)            - Use DES keys only
DONT_REQ_PREAUTH (0x400000)            - Kerberos pre-authentication not required
PASSWORD_EXPIRED (0x800000)            - Password expired
TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000) - Constrained delegation
```

---

## 💡 Common Workflows

### Workflow 1: Find Attack Paths
```bash
# 1. Discover Domain Controllers
../dcseek/dcseek.py iplist.txt

# 2. Full AD enumeration
./ldapseek.py dclist.txt --full -u user -p pass

# 3. Identify Kerberoasting targets
cat spns.txt

# 4. Identify ASREPRoasting targets
cat asrep_users.txt

# 5. Attack with KerbSeek
../kerbseek/kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01.corp.local
```

### Workflow 2: Find Privileged Accounts
```bash
# 1. Enumerate all users
./ldapseek.py dclist.txt --users -u user -p pass

# 2. Find admin accounts
./ldapseek.py dclist.txt --admins -u user -p pass

# 3. Review admin accounts
cat admin_users.txt

# 4. Check for weak admin passwords (if you have credentials)
# Use admin accounts in password spray attacks
```

### Workflow 3: Unauthenticated Enumeration
```bash
# 1. Try anonymous LDAP bind
./ldapseek.py dclist.txt

# 2. If anonymous works, get users
./ldapseek.py dclist.txt --users

# 3. Find ASREPRoastable accounts (no auth needed)
./ldapseek.py dclist.txt --asrep

# 4. ASREPRoast them
../kerbseek/kerbseek.py --asreproast --users asrep_users.txt -d CORP --dc dc01.corp.local
```

### Workflow 4: Delegation Hunting
```bash
# 1. Full enumeration with delegation detection
./ldapseek.py dclist.txt --full -u user -p pass

# 2. Review delegation findings in ldap_details.txt
grep -A 10 "Delegation Accounts" ldap_details.txt

# 3. Look for unconstrained delegation
grep "TRUSTED_FOR_DELEGATION" ldap_details.txt

# 4. Exploit delegation (manual process or use Rubeus)
```

---

## 🎯 Integration with Other Tools

### Chain 1: LDAP → Kerberos → WinRM
```bash
# 1. Enumerate AD
./ldapseek.py dclist.txt --full -u user -p pass

# 2. Kerberoast service accounts
../kerbseek/kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01.corp.local

# 3. Crack hashes
hashcat -m 13100 tgs_hashes.txt rockyou.txt

# 4. Use cracked credentials on WinRM
../winrmseek/winrmseek.py iplist.txt -t -u cracked_user -p cracked_pass
evil-winrm -i target -u cracked_user -p cracked_pass
```

### Chain 2: LDAP → Password Spray
```bash
# 1. Get all usernames
./ldapseek.py dclist.txt --users -u user -p pass

# 2. Password spray (use external tool like CrackMapExec)
crackmapexec smb iplist.txt -u users.txt -p 'Password123!' --continue-on-success

# 3. Use valid credentials
./ldapseek.py dclist.txt --full -u valid_user -p valid_pass
```

### Chain 3: LDAP → Delegation Abuse
```bash
# 1. Find delegation accounts
./ldapseek.py dclist.txt --full -u user -p pass
grep "TRUSTED_FOR_DELEGATION" ldap_details.txt

# 2. Compromise delegation account
# (via password crack, credential dump, etc.)

# 3. Request TGT for any user (if unconstrained delegation)
# Use Rubeus or Impacket for this
```

---

## 🔐 Attack Techniques

### Kerberoasting
**What:** Request TGS service tickets for accounts with SPNs, crack offline

**Why:** Service accounts often have weak passwords that never expire

**How:**
1. LDAPSeek identifies accounts with SPNs → `spns.txt`
2. KerbSeek requests TGS tickets for each SPN
3. Crack tickets with Hashcat (mode 13100)
4. Use cracked credentials for lateral movement

**Example:**
```bash
./ldapseek.py dclist.txt --spns -u user -p pass
../kerbseek/kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01.corp.local
hashcat -m 13100 tgs_hashes.txt rockyou.txt
```

### ASREPRoasting
**What:** Request AS-REP for users without Kerberos pre-authentication

**Why:** No valid password needed - can attack without credentials!

**How:**
1. LDAPSeek identifies users with DONT_REQ_PREAUTH → `asrep_users.txt`
2. KerbSeek requests AS-REP without authentication
3. Crack AS-REP with Hashcat (mode 18200)
4. Use cracked password to access systems

**Example:**
```bash
./ldapseek.py dclist.txt --asrep  # No credentials needed!
../kerbseek/kerbseek.py --asreproast --users asrep_users.txt -d CORP --dc dc01.corp.local
hashcat -m 18200 asrep_hashes.txt rockyou.txt
```

### Unconstrained Delegation
**What:** Accounts with TRUSTED_FOR_DELEGATION can impersonate any user

**Why:** If compromised, can obtain TGT for Domain Admin

**How:**
1. LDAPSeek identifies accounts with TRUSTED_FOR_DELEGATION
2. Compromise the delegation account
3. Wait for admin to authenticate (or force authentication)
4. Extract admin TGT from memory
5. Pass-the-ticket to become Domain Admin

**Detection:**
```bash
./ldapseek.py dclist.txt --full -u user -p pass
grep "TRUSTED_FOR_DELEGATION" ldap_details.txt
```

### Constrained Delegation
**What:** Accounts with TRUSTED_TO_AUTH_FOR_DELEGATION can impersonate users to specific services

**Why:** Can abuse S4U2Self and S4U2Proxy to access services as any user

**How:**
1. LDAPSeek identifies constrained delegation accounts
2. Compromise account with delegation rights
3. Use S4U2Self to get forwardable ticket
4. Use S4U2Proxy to access allowed services as admin

**Detection:**
```bash
./ldapseek.py dclist.txt --full -u user -p pass
grep "TRUSTED_TO_AUTH_FOR_DELEGATION" ldap_details.txt
```

---

## 🛡️ Detection & Defense

### Detection
- **LDAP query logs** - Monitor for bulk LDAP queries
- **Anonymous bind** - Detect unauthenticated LDAP enumeration
- **Kerberos logs** - Multiple TGS/AS-REP requests (follow-on from LDAP enum)

### Defense
**High Priority:**
1. **Disable Anonymous LDAP** - Require authentication for LDAP queries
2. **Remove DONT_REQ_PREAUTH** - Disable ASREPRoasting attack vector
3. **Limit Service Account SPNs** - Reduce Kerberoasting targets
4. **Use Managed Service Accounts (gMSA)** - Long, random passwords

**Medium Priority:**
5. **Restrict Unconstrained Delegation** - Only Domain Controllers should have this
6. **Monitor Privileged Groups** - Alert on membership changes
7. **Enable adminCount Auditing** - Detect privilege escalation attempts
8. **Strong Service Account Passwords** - 25+ character random passwords

**Low Priority:**
9. **Disable DONT_EXPIRE_PASSWORD** - Force password rotation
10. **Review Delegation** - Audit all delegation configurations

### LDAP Hardening
```powershell
# Disable anonymous LDAP bind
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LDAPServerIntegrity /t REG_DWORD /d 2 /f

# Require LDAP signing
reg add "HKLM\System\CurrentControlSet\Services\NTDS\Parameters" /v LdapEnforceChannelBinding /t REG_DWORD /d 2 /f

# Enable LDAP auditing
auditpol /set /subcategory:"Directory Service Access" /success:enable /failure:enable
```

---

## 📝 Tips & Best Practices

### Maximizing Findings
1. **Use Valid Credentials** - Authenticated queries return much more data
2. **Full Enumeration** - Use `--full` to get all information
3. **Check for Anonymous Bind** - Try without credentials first
4. **LDAPS for Stealth** - Use `--ldaps` to encrypt queries
5. **Save JSON Output** - Easier to parse and analyze

### Common Pitfalls
❌ **Skipping unauthenticated scan** - Always try without creds first  
❌ **Not checking UAC flags** - May miss ASREPRoastable accounts  
❌ **Ignoring service accounts** - Often have weak passwords  
❌ **Missing delegation** - Critical for privilege escalation  
❌ **Not following up** - Use KerbSeek after finding targets  

### Performance
- **Threading** - Default (5 threads) is safe and quiet
- **Increase threads** - Faster but noisier (`--threads 10`)
- **Single DC** - Query one DC instead of all for speed
- **Specific queries** - Use `--spns`, `--asrep` instead of `--full`

---

## 🚨 Common Findings

### Critical Findings
✅ **ASREPRoastable Accounts**
- No Kerberos pre-auth required
- Can crack passwords offline without credentials
- Often forgotten test/vendor accounts

✅ **Unconstrained Delegation**
- Computers/users can impersonate anyone
- Leads to Domain Admin compromise
- Should only be on Domain Controllers

✅ **Weak Service Accounts with SPNs**
- Kerberoastable targets
- Often have weak, never-expiring passwords
- High-value targets for credential cracking

### High-Value Findings
✅ **Admin Accounts with DONT_EXPIRE_PASSWORD**
- Passwords never rotate
- High-value targets for password spraying
- Check if these are in use

✅ **Service Accounts in Admin Groups**
- Over-privileged accounts
- Compromise = Domain Admin
- Common misconfiguration

✅ **Constrained Delegation**
- Can impersonate users to specific services
- Less obvious than unconstrained
- Still leads to privilege escalation

---

## 🔧 Troubleshooting

### Cannot Connect to LDAP
```bash
# Test LDAP connectivity
ldapsearch -x -H ldap://dc01.corp.local -b "" -s base

# Try with credentials
ldapsearch -x -H ldap://dc01.corp.local -D "user@corp.local" -w password -b "DC=corp,DC=local"

# Try LDAPS (port 636)
./ldapseek.py dclist.txt --ldaps
```

### Anonymous Bind Denied
```bash
# Use valid domain credentials
./ldapseek.py dclist.txt -u username -p password

# Try null credentials (guest access)
./ldapseek.py dclist.txt -u "" -p ""
```

### No Results Returned
```bash
# Check base DN
ldapsearch -x -H ldap://dc01 -b "" -s base namingContexts

# Specify base DN manually
./ldapseek.py dclist.txt --base "DC=corp,DC=local" -u user -p pass

# Verify DC is reachable
ping dc01.corp.local
```

### Slow Performance
```bash
# Reduce threading
./ldapseek.py dclist.txt --threads 3

# Query specific data only
./ldapseek.py dclist.txt --spns  # Faster than --full

# Query single DC
./ldapseek.py dc01.corp.local
```

---

## 📚 References

- [Active Directory LDAP Syntax Filters](https://docs.microsoft.com/en-us/windows/win32/adsi/search-filter-syntax)
- [User Account Control Flags](https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties)
- [Kerberoasting Attack](https://attack.mitre.org/techniques/T1558/003/)
- [ASREPRoasting Attack](https://attack.mitre.org/techniques/T1558/004/)
- [Delegation Attacks](https://attack.mitre.org/techniques/T1134/005/)

---

## 🎓 Related Tools

### In This Suite
- **DCSeek** - Find Domain Controllers (use before LDAPSeek)
- **KerbSeek** - Attack users found by LDAPSeek (Kerberoast/ASREPRoast)
- **WinRMSeek** - Test cracked credentials via WinRM
- **CredSeek** - Find credentials in shares for LDAP authentication

### External Tools
- **BloodHound** - Visualize AD attack paths
- **Impacket GetUserSPNs.py** - Request TGS tickets
- **PowerView** - PowerShell AD enumeration
- **ADExplorer** - GUI LDAP browser

---

## ⚖️ Legal Notice

**FOR AUTHORIZED PENETRATION TESTING ONLY**

LDAPSeek is designed for legitimate security assessments with proper authorization. Unauthorized enumeration of Active Directory is illegal. Always ensure you have written permission before testing.

---

**Version:** 1.0  
**Author:** Internal Red Team  
**License:** Internal Use Only  
**Last Updated:** October 2025
