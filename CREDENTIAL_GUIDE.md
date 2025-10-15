# SeekSweet Credential Support Guide

## Overview
Some SeekSweet tools support or require credentials for enhanced functionality. The orchestrator (`seeksweet.py`) will prompt for credentials when needed.

## Tools Requiring Credentials

### KerbSeek (REQUIRED)
**Description**: Find Kerberos services (requires domain creds)

**Why Credentials Are Needed**:
- Kerberoasting requires authenticated domain access
- ASREPRoasting can be unauthenticated, but authenticated provides better results
- SPN enumeration requires domain user context

**Credential Format**:
- `user@domain.local` (UPN format)
- `DOMAIN\username` (NetBIOS format)

**Command-line Flags**:
```bash
python kerbseek/kerbseek.py iplist.txt -u user@domain.local -p Password123 -v
```

**Usage Notes**:
- Credentials obtained from Responder, password spray, or default accounts work well
- Low-privileged domain user is sufficient
- Will automatically attempt Kerberoasting and ASREPRoasting

## Tools Supporting Optional Credentials

### LDAPSeek (OPTIONAL - HIGHLY RECOMMENDED)
**Description**: Enumerate AD via LDAP (optional: auth for more data)

**Why Credentials Help**:
- Anonymous LDAP bind is often disabled in modern Active Directory
- Authenticated queries return **significantly more data**:
  - Full user account details (description, groups, last logon, etc.)
  - Computer accounts and attributes
  - Group memberships and nested groups
  - Service Principal Names (SPNs)
  - Domain trust relationships
- Anonymous bind may only show basic DN structure

**Credential Format**:
- `user@domain.local` (UPN format)
- `DOMAIN\username` (NetBIOS format)

**Command-line Flags**:
```bash
python ldapseek/ldapseek.py iplist.txt -u user@domain.local -p Password123 -v
```

**Usage Notes**:
- Works without credentials (tests anonymous bind)
- **Much more effective with credentials** (even low-privileged user)
- Any domain user account will work
- Perfect for post-Responder enumeration

### DbSeek (OPTIONAL)
**Description**: Find database servers (optional: test creds)

**Why Credentials Help**:
- Test authentication to discovered database servers
- Enumerate database instances with valid credentials
- Identify weak or default database passwords

**Credential Format**:
- Username: Database-specific (sa, root, postgres, etc.)
- Password: Obtained from Responder, default lists, or password spray

**Command-line Flags**:
```bash
python dbseek/dbseek.py -f iplist.txt -u sa -p Password123 -v
```

**Usage Notes**:
- Works without credentials (just discovers database ports)
- With credentials: tests authentication to MSSQL, MySQL, PostgreSQL
- Great for validating credentials captured from Responder

### WinRMSeek (OPTIONAL)
**Description**: Find WinRM endpoints (optional: test creds)

**Why Credentials Help**:
- Test authentication to discovered WinRM endpoints
- Identify accessible remote administration points
- Validate captured credentials

**Credential Format**:
- `user@domain.local` or `DOMAIN\username`
- Password: Obtained from Responder or password spray

**Command-line Flags**:
```bash
python winrmseek/winrmseek.py iplist.txt -u admin@domain.local -p Password123 -v
```

**Usage Notes**:
- Works without credentials (discovers WinRM ports 5985/5986)
- With credentials: tests authentication and identifies accessible hosts
- Perfect for post-Responder validation

## Tools Not Requiring Credentials

The following tools work without any credentials:
- **DCSeek**: Port scanning and domain enumeration
- **SMBSeek**: Null session and anonymous share enumeration
- **ShareSeek**: Share discovery and permission checking
- **CredSeek**: File system scanning for credential stores
- **WebSeek**: Web vulnerability scanning
- **PanelSeek**: Admin panel discovery
- **BackupSeek**: Backup system discovery
- **PrintSeek**: Print server discovery
- **SNMPSeek**: SNMP community string testing
- **VulnSeek**: Vulnerability scanning (no auth needed)

## Workflow Examples

### Example 1: Basic Reconnaissance (No Credentials)
```bash
# 1. Discover domain controllers
python dcseek/dcseek.py iplist.txt -v

# 2. Enumerate LDAP (anonymous)
python ldapseek/ldapseek.py iplist.txt -v

# 3. Find SMB shares
python smbseek/smbseek.py -f iplist.txt -v

# 4. Scan for vulnerabilities
python vulnseek/vulnseek.py -f iplist.txt --full --nuclei -v
```

### Example 2: Post-Responder Attack (With Captured Credentials)
```bash
# After capturing credentials with Responder:
# Username: jsmith@contoso.local
# Password: Summer2024!

# 1. Enumerate LDAP with authentication (get full AD data)
python ldapseek/ldapseek.py iplist.txt -u jsmith@contoso.local -p Summer2024! -v

# 2. Enumerate Kerberos (Kerberoasting)
python kerbseek/kerbseek.py iplist.txt -u jsmith@contoso.local -p Summer2024! -v

# 3. Test database access
python dbseek/dbseek.py -f iplist.txt -u jsmith -p Summer2024! -v

# 4. Test WinRM access
python winrmseek/winrmseek.py iplist.txt -u jsmith@contoso.local -p Summer2024! -v
```

### Example 3: Using SeekSweet Orchestrator
When running tools through `seeksweet.py`, the menu will automatically prompt for credentials:

```
═══ AUTHENTICATION PHASE ═══
   5. KerbSeek [HIGH]
      Find Kerberos services (requires domain creds)
```

**Selection Process**:
1. Select tool from menu (e.g., option 5 for KerbSeek)
2. Enter target file (e.g., `iplist.txt`)
3. **Credential prompt appears**:
   ```
   [!] KerbSeek requires domain credentials for authenticated attacks
   Enter username (user@domain or DOMAIN\user): jsmith@contoso.local
   Enter password: [hidden]
   ```
4. Tool executes with credentials automatically passed

**Optional Credentials**:
```
═══ SERVICES PHASE ═══
  10. DbSeek [MEDIUM]
      Find database servers (optional: test creds)
```

**Selection Process**:
1. Select tool from menu (e.g., option 10 for DbSeek)
2. Enter target file
3. **Optional prompt**:
   ```
   [?] DbSeek supports optional credentials for authentication testing
   Test with credentials? [y/N]: y
   Enter username: sa
   Enter password: [hidden]
   ```
4. Tool executes with or without credentials based on choice

## Credential Sources

### Responder
```bash
# Capture credentials via LLMNR/NBT-NS poisoning
sudo responder -I eth0 -wrf

# Check captured hashes
cat /usr/share/responder/logs/*.txt
```

### Password Spray
```bash
# After initial recon, spray common passwords
crackmapexec smb iplist.txt -u users.txt -p 'Winter2024!' --continue-on-success
```

### Default Credentials
- SQL Server: `sa` / `sa`, `sa` / empty
- MySQL: `root` / empty, `root` / `root`
- PostgreSQL: `postgres` / `postgres`

### NTLM Relay
```bash
# Relay captured hashes (no plaintext needed)
ntlmrelayx.py -tf targets.txt -smb2support
```

## Security Considerations

### Password Handling
- Passwords are passed via command-line arguments
- **Not visible in process list** (Python's getpass module)
- Passwords are **not logged** to scan output files
- Use `-v` flag carefully in shared environments

### Credential Storage
- SeekSweet **does not store** credentials
- Credentials are only used during tool execution
- Output files contain **results**, not credentials
- Always protect output files (contain sensitive enum data)

### Best Practices
1. ✅ Use low-privileged domain accounts when possible
2. ✅ Test credentials on non-production systems first
3. ✅ Rotate credentials after engagement
4. ✅ Secure all output files and logs
5. ❌ Don't use Domain Admin credentials for scanning
6. ❌ Don't hardcode credentials in scripts

## Technical Implementation

### Menu Detection
```python
# seeksweet.py checks for credential flags
if tool.get('needs_creds'):
    # Required credentials (KerbSeek)
    print("[!] Tool requires credentials")
    username = input("Enter username: ")
    password = getpass.getpass("Enter password: ")
elif tool.get('optional_creds'):
    # Optional credentials (DbSeek, WinRMSeek)
    use_creds = input("Test with credentials? [y/N]: ")
```

### Command Building
```python
# Credentials are appended to command
cmd = [python, script, target_file, '-v']
if username and password:
    cmd.extend(['-u', username, '-p', password])
```

### Tool Definitions
```python
SEEK_TOOLS = [
    {
        'name': 'KerbSeek',
        'needs_creds': True,  # Required
    },
    {
        'name': 'DbSeek',
        'optional_creds': True,  # Optional
    },
]
```

## Troubleshooting

### "Authentication Failed"
- Verify credential format: `user@domain.local` or `DOMAIN\user`
- Check password for special characters (quote in shell)
- Confirm account is not locked or disabled
- Ensure network connectivity to target

### "Permission Denied"
- Account may lack required privileges
- Try different credential set
- Check if account has logon restrictions

### "Credentials Not Prompted"
- Ensure using latest version of seeksweet.py
- Check tool has `needs_creds` or `optional_creds` flag
- Verify running through orchestrator menu

---

**Date**: October 15, 2025  
**Author**: Lokii-git  
**Commit**: Pending
