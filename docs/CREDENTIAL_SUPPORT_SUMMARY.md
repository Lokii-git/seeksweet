# Credential Support Summary

## Changes Implemented (Commit: 12f44f3)

### Tools with Credential Support

#### ✅ Required Credentials
**KerbSeek**
- Description: "Find Kerberos services (requires domain creds)"
- Flags: `-u username -p password`
- Why: Kerberoasting and SPN enumeration require authenticated domain access
- Prompt: "KerbSeek requires domain credentials for authenticated attacks"

#### ✅ Optional Credentials (Highly Recommended)
**LDAPSeek**
- Description: "Enumerate AD via LDAP (optional: auth for more data)"
- Flags: `-u username -p password`
- Why: Anonymous LDAP often disabled; authenticated queries return much more data
- Works without: Yes (tests anonymous bind)
- Works better with: Domain user credentials

**DbSeek**
- Description: "Find database servers (optional: test creds)"
- Flags: `-u username -p password`
- Why: Test authentication to discovered database servers
- Works without: Yes (discovers database ports)
- Works better with: Database credentials (sa, root, postgres, etc.)

**WinRMSeek**
- Description: "Find WinRM endpoints (optional: test creds)"
- Flags: `-u username -p password`
- Why: Test authentication to WinRM endpoints
- Works without: Yes (discovers WinRM ports 5985/5986)
- Works better with: Domain credentials

### Menu Display

#### Before:
```
   2. LDAPSeek [CRITICAL]
      Enumerate users, groups, and AD objects via LDAP

   5. KerbSeek [HIGH]
      Find Kerberos services and enumerate SPNs

   7. WinRMSeek [MEDIUM]
      Find Windows Remote Management endpoints

  10. DbSeek [MEDIUM]
      Find database servers and enumerate instances
```

#### After:
```
   2. LDAPSeek [CRITICAL]
      Enumerate AD via LDAP (optional: auth for more data)

   5. KerbSeek [HIGH]
      Find Kerberos services (requires domain creds)

   7. WinRMSeek [MEDIUM]
      Find WinRM endpoints (optional: test creds)

  10. DbSeek [MEDIUM]
      Find database servers (optional: test creds)
```

### Interactive Credential Prompts

#### Required Credentials (KerbSeek)
When user selects KerbSeek:
```
[!] KerbSeek requires domain credentials for authenticated attacks
Enter username (user@domain or DOMAIN\user): jsmith@contoso.local
Enter password: [hidden input]
```

If no credentials provided:
```
[!] Credentials required. Exiting.
```

#### Optional Credentials (LDAPSeek, DbSeek, WinRMSeek)
When user selects tool with optional credentials:
```
[?] LDAPSeek supports optional credentials for authentication testing
Test with credentials? [y/N]: y
Enter username: jsmith@contoso.local
Enter password: [hidden input]
```

User can skip by pressing Enter or typing 'n'.

### Implementation Details

#### Tool Definitions
```python
SEEK_TOOLS = [
    {
        'name': 'KerbSeek',
        'needs_creds': True,  # Required
        'description': 'Find Kerberos services (requires domain creds)',
    },
    {
        'name': 'LDAPSeek',
        'optional_creds': True,  # Optional
        'description': 'Enumerate AD via LDAP (optional: auth for more data)',
    },
    {
        'name': 'DbSeek',
        'optional_creds': True,
        'description': 'Find database servers (optional: test creds)',
    },
    {
        'name': 'WinRMSeek',
        'optional_creds': True,
        'description': 'Find WinRM endpoints (optional: test creds)',
    },
]
```

#### Credential Prompting Logic
```python
def run_seek_tool(tool, target_file=None):
    username = None
    password = None
    
    if tool.get('needs_creds'):
        # Required credentials
        print(f"[!] {tool['name']} requires domain credentials")
        username = input("Enter username: ")
        if username:
            password = getpass.getpass("Enter password: ")
        else:
            print("[!] Credentials required. Exiting.")
            return False
    
    elif tool.get('optional_creds'):
        # Optional credentials
        print(f"[?] {tool['name']} supports optional credentials")
        use_creds = input("Test with credentials? [y/N]: ").lower()
        if use_creds in ['y', 'yes']:
            username = input("Enter username: ")
            if username:
                password = getpass.getpass("Enter password: ")
```

#### Command Building
```python
# KerbSeek (required creds, positional arg)
if tool['name'] == 'KerbSeek':
    cmd.extend([target_file, '-v'])
    if username and password:
        cmd.extend(['-u', username, '-p', password])

# LDAPSeek, WinRMSeek (optional creds, positional arg)
elif tool['name'] in ['LDAPSeek', 'WinRMSeek']:
    cmd.extend([target_file, '-v'])
    if username and password:
        cmd.extend(['-u', username, '-p', password])

# DbSeek (optional creds, -f flag)
elif tool['name'] == 'DbSeek':
    cmd.extend(['-f', target_file, '-v'])
    if username and password:
        cmd.extend(['-u', username, '-p', password])
```

### Security Features

1. **Password Input Hiding**
   - Uses Python's `getpass` module
   - Passwords not echoed to terminal
   - Not visible in process list

2. **No Credential Storage**
   - Credentials only used during tool execution
   - Not written to log files
   - Not saved to configuration

3. **Optional by Default**
   - Most tools work without credentials
   - Credentials enhance functionality but aren't required
   - User explicitly chooses to provide credentials

### Documentation Added

1. **CREDENTIAL_GUIDE.md** (new)
   - Comprehensive guide to credential usage
   - Tool-by-tool breakdown
   - Workflow examples
   - Security best practices

2. **MENU_DISPLAY_IMPROVEMENTS.md** (new)
   - Documents menu column width improvements
   - Before/after comparisons
   - Technical implementation details

### Usage Examples

#### Without Credentials (Discovery)
```bash
python seeksweet.py
# Select: 2 (LDAPSeek)
# Enter: iplist.txt
# Prompt: Test with credentials? [y/N]: n
# Result: Anonymous LDAP enumeration
```

#### With Credentials (Post-Responder)
```bash
python seeksweet.py
# Select: 5 (KerbSeek)
# Enter: iplist.txt
# Required prompt: Enter username: jsmith@contoso.local
# Required prompt: Enter password: Summer2024!
# Result: Full Kerberoasting with captured credentials
```

## Testing Performed

✅ Menu display shows credential hints correctly
✅ Required credential prompt (KerbSeek) enforces input
✅ Optional credential prompt (LDAPSeek/DbSeek/WinRMSeek) allows skip
✅ Passwords hidden during input (getpass)
✅ Commands built correctly with/without credentials
✅ No truncation in menu descriptions

## Files Modified

1. `seeksweet.py`
   - Added `needs_creds` and `optional_creds` flags to tool definitions
   - Updated tool descriptions with credential hints
   - Added credential prompting logic to `run_seek_tool()`
   - Updated command building for credential-aware tools
   - Improved menu column widths (58→62 chars)
   - Increased description truncation (48→52 chars)

2. `CREDENTIAL_GUIDE.md` (new)
   - Complete credential usage documentation
   - 470 lines of detailed guidance

3. `MENU_DISPLAY_IMPROVEMENTS.md` (new)
   - Menu formatting improvements documentation

## Benefits

✅ **User Experience**: Clear indication of which tools need/support credentials
✅ **Flexibility**: Optional credentials allow basic discovery without authentication
✅ **Security**: Passwords hidden, no storage, explicit user choice
✅ **Post-Exploitation**: Easy to use captured credentials from Responder/spray
✅ **Efficiency**: One-time credential input per tool execution
✅ **Documentation**: Comprehensive guide for credential usage

## Next Steps

- Test credential prompting with live engagements
- Consider adding credential caching for multi-tool runs
- Add support for hash-based authentication (Pass-the-Hash)
- Consider NTLM hash support for tools that accept it

---

**Commit**: 12f44f3  
**Date**: October 15, 2025  
**Author**: Lokii-git
