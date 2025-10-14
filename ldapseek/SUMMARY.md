# LDAPSeek Technical Summary

## Architecture Overview

**Purpose:** Comprehensive Active Directory LDAP enumeration for attack surface mapping

**Language:** Python 3.6+  
**Threading:** ThreadPoolExecutor (configurable, default: 5)  
**Dependencies:** ldapsearch (openldap-clients)  
**Lines of Code:** ~850  

---

## Core Components

### 1. Domain Information Retrieval
**Function:** `get_domain_info_ldapsearch(target, username, password)`

**Process:**
1. Query rootDSE: `ldapsearch -x -H ldap://target -b "" -s base`
2. Extract `defaultNamingContext` (e.g., DC=corp,DC=local)
3. Parse to get domain name (CORP.LOCAL)
4. Return base DN for subsequent queries

**LDAP Query:**
```bash
ldapsearch -x -H ldap://dc01 -b "" -s base "(objectClass=*)" defaultNamingContext
```

### 2. User Enumeration
**Function:** `enumerate_users_ldapsearch(target, base_dn, username, password)`

**Process:**
1. Query all user objects with comprehensive attributes
2. Parse userAccountControl (UAC) flags
3. Extract SPNs (servicePrincipalName attribute)
4. Identify group memberships (memberOf attribute)
5. Check adminCount attribute
6. Return structured user data

**LDAP Filter:**
```ldap
(&(objectClass=user)(objectCategory=person))
```

**Attributes Retrieved:**
- `sAMAccountName` - Username
- `userPrincipalName` - UPN (user@domain)
- `distinguishedName` - Full DN
- `userAccountControl` - UAC bit flags
- `servicePrincipalName` - SPNs (multi-valued)
- `memberOf` - Group memberships (multi-valued)
- `adminCount` - Privileged account indicator
- `pwdLastSet` - Password last changed
- `lastLogonTimestamp` - Last logon time
- `description` - User description

**Command:**
```bash
ldapsearch -x -H ldap://target -D user@domain -w password \
  -b "DC=corp,DC=local" \
  "(&(objectClass=user)(objectCategory=person))" \
  sAMAccountName userPrincipalName userAccountControl \
  servicePrincipalName memberOf adminCount
```

### 3. UAC Flag Parsing
**Function:** `parse_uac_flags(uac_value)`

**Process:**
1. Convert UAC value to integer
2. Bitwise AND with each flag value
3. Return list of active flags

**Algorithm:**
```python
UAC_FLAGS = {
    0x0001: 'SCRIPT',
    0x0002: 'ACCOUNTDISABLE',
    0x0008: 'HOMEDIR_REQUIRED',
    0x0010: 'LOCKOUT',
    0x0020: 'PASSWD_NOTREQD',
    0x0040: 'PASSWD_CANT_CHANGE',
    0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x0100: 'TEMP_DUPLICATE_ACCOUNT',
    0x0200: 'NORMAL_ACCOUNT',
    0x0800: 'INTERDOMAIN_TRUST_ACCOUNT',
    0x1000: 'WORKSTATION_TRUST_ACCOUNT',
    0x2000: 'SERVER_TRUST_ACCOUNT',
    0x10000: 'DONT_EXPIRE_PASSWORD',
    0x20000: 'MNS_LOGON_ACCOUNT',
    0x40000: 'SMARTCARD_REQUIRED',
    0x80000: 'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x200000: 'USE_DES_KEY_ONLY',
    0x400000: 'DONT_REQ_PREAUTH',
    0x800000: 'PASSWORD_EXPIRED',
    0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION'
}

def parse_uac_flags(uac_value):
    flags = []
    for flag_value, flag_name in UAC_FLAGS.items():
        if uac_value & flag_value:
            flags.append(flag_name)
    return flags
```

**Example:**
```
UAC Value: 66048 (0x10200)
Binary: 0000 0000 0000 0001 0000 0010 0000 0000
Flags: NORMAL_ACCOUNT (0x200) + DONT_EXPIRE_PASSWORD (0x10000)
```

### 4. Kerberoastable User Identification
**Function:** `identify_kerberoastable_users(users)`

**Detection Logic:**
```python
if user['spns'] and len(user['spns']) > 0:
    # User has at least one SPN
    if 'ACCOUNTDISABLE' not in user['uac_flags']:
        # Account is enabled
        kerberoastable_users.append(user)
```

**Why It Matters:**
- Users with SPNs can be Kerberoasted
- TGS ticket encrypted with user's password hash
- Ticket can be cracked offline
- Often service accounts with weak passwords

### 5. ASREPRoastable User Identification
**Function:** `identify_asrep_users(users)`

**Detection Logic:**
```python
if 'DONT_REQ_PREAUTH' in user['uac_flags']:
    # Kerberos pre-authentication not required
    if 'ACCOUNTDISABLE' not in user['uac_flags']:
        # Account is enabled
        asrep_users.append(user)
```

**Why It Matters:**
- Can request AS-REP without password
- AS-REP encrypted with user's password hash
- No valid credentials needed for attack!
- Crack AS-REP offline

**LDAP Filter for Direct Query:**
```ldap
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

### 6. Delegation Account Identification
**Function:** `identify_delegation_accounts(users)`

**Detection Logic:**
```python
# Unconstrained Delegation
if 'TRUSTED_FOR_DELEGATION' in user['uac_flags']:
    delegation_accounts.append({
        'user': user,
        'type': 'Unconstrained',
        'risk': 'CRITICAL'
    })

# Constrained Delegation
if 'TRUSTED_TO_AUTH_FOR_DELEGATION' in user['uac_flags']:
    delegation_accounts.append({
        'user': user,
        'type': 'Constrained',
        'risk': 'HIGH'
    })
```

**Why It Matters:**
- **Unconstrained:** Can impersonate ANY user to ANY service
- **Constrained:** Can impersonate ANY user to SPECIFIC services
- Compromise = potential Domain Admin

### 7. Privileged Account Identification
**Function:** `identify_admin_users(users, groups)`

**Detection Logic:**
```python
PRIVILEGED_GROUPS = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Backup Operators',
    'Account Operators',
    'Server Operators',
    'Print Operators',
    'DNSAdmins',
    'Group Policy Creator Owners',
    'Hyper-V Administrators',
    'Remote Desktop Users'
]

# Method 1: adminCount attribute
if user.get('adminCount') == 1:
    admin_users.append(user)

# Method 2: Privileged group membership
for group in user.get('memberOf', []):
    if any(priv_group in group for priv_group in PRIVILEGED_GROUPS):
        admin_users.append(user)
        break
```

**adminCount Attribute:**
- Set to 1 for members of protected groups
- Protected by AdminSDHolder
- Persists even after removal from group
- Good indicator of current or past privilege

---

## LDAP Query Patterns

### All Users
```ldap
(&(objectClass=user)(objectCategory=person))
```

### All Groups
```ldap
(objectClass=group)
```

### All Computers
```ldap
(objectClass=computer)
```

### Users with SPNs (Kerberoastable)
```ldap
(&(objectClass=user)(servicePrincipalName=*))
```

### Users without Preauth (ASREPRoastable)
```ldap
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

### Enabled Users Only
```ldap
(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))
```

### Unconstrained Delegation
```ldap
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))
```

### Constrained Delegation
```ldap
(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=16777216))
```

### Admin Accounts
```ldap
(|(adminCount=1)(memberOf=CN=Domain Admins,CN=Users,DC=corp,DC=local))
```

### LDAP Matching Rule OID
- `1.2.840.113556.1.4.803` - LDAP_MATCHING_RULE_BIT_AND
- Used for bitwise AND on userAccountControl

**Example:**
```ldap
(userAccountControl:1.2.840.113556.1.4.803:=2)
# Returns objects where UAC & 0x2 (ACCOUNTDISABLE) is true
```

---

## Threading Model

### Strategy
```python
max_workers = args.threads  # Default: 5
executor = ThreadPoolExecutor(max_workers=max_workers)

# Parallel DC enumeration
futures = []
for dc in domain_controllers:
    future = executor.submit(enumerate_users_ldapsearch, dc, base_dn, username, password)
    futures.append(future)

# Collect results
for future in as_completed(futures):
    users.extend(future.result())
```

### Concurrency Levels
1. **Domain Controllers:** Queried in parallel
2. **Users/Groups/Computers:** Sequential per DC (LDAP limitation)
3. **Analysis:** Post-processing in main thread

### Thread Safety
- LDAP queries are thread-safe (separate connections)
- Results aggregated with locks
- No shared state between threads

---

## Performance Characteristics

### Time Complexity
- **Domain info:** O(1) - Single query
- **User enumeration:** O(n) where n = number of users
- **UAC parsing:** O(n * f) where f = flags per user
- **Admin identification:** O(n * g) where g = groups

### Memory Usage
- **User data:** ~1KB per user
- **1000 users:** ~1MB
- **10,000 users:** ~10MB
- All results held in memory

### Network Impact
- **LDAP queries:** Low bandwidth
- **Connection per DC:** Minimal
- **Query complexity:** Simple filters, fast

### Optimization
- **Attribute filtering:** Only request needed attributes
- **Paging:** Handled automatically by ldapsearch
- **Caching:** No caching (fresh data every run)

---

## Output Format

### Text Output (ldap_details.txt)
```
=== LDAPSeek Results ===
Scan Date: 2025-10-13 10:30:00

Domain Information:
  Domain: CORP.LOCAL
  Base DN: DC=corp,DC=local
  Domain Controllers: dc01.corp.local, dc02.corp.local

User Statistics:
  Total Users: 1523
  Enabled Users: 1401
  Disabled Users: 122
  Users with SPNs (Kerberoastable): 15
  Users without Preauth (ASREPRoastable): 3
  Admin Accounts: 42
  Users with Delegation: 5

Kerberoastable Accounts (SPNs):
  svc_sql (MSSQLSvc/sqlserver.corp.local:1433)
  svc_iis (HTTP/webserver.corp.local)
  ...

ASREPRoastable Accounts:
  testuser (UAC: DONT_REQ_PREAUTH)
  vendor_account (UAC: DONT_REQ_PREAUTH)
  ...
```

### JSON Output (ldap_details.json)
```json
{
  "scan_date": "2025-10-13T10:30:00",
  "domain": "CORP.LOCAL",
  "base_dn": "DC=corp,DC=local",
  "domain_controllers": ["dc01.corp.local", "dc02.corp.local"],
  "statistics": {
    "total_users": 1523,
    "enabled_users": 1401,
    "disabled_users": 122,
    "kerberoastable": 15,
    "asrep_roastable": 3,
    "admin_accounts": 42,
    "delegation_accounts": 5
  },
  "users": [
    {
      "username": "svc_sql",
      "upn": "svc_sql@corp.local",
      "dn": "CN=Service SQL,OU=Service Accounts,DC=corp,DC=local",
      "uac_value": 66048,
      "uac_flags": ["NORMAL_ACCOUNT", "DONT_EXPIRE_PASSWORD"],
      "spns": ["MSSQLSvc/sqlserver.corp.local:1433"],
      "member_of": ["CN=Domain Users,DC=corp,DC=local"],
      "admin_count": 0,
      "kerberoastable": true,
      "asrep_roastable": false,
      "delegation": null
    }
  ],
  "kerberoastable_accounts": ["svc_sql", "svc_iis", ...],
  "asrep_accounts": ["testuser", "vendor_account", ...],
  "admin_accounts": ["administrator", "domain_admin_jdoe", ...]
}
```

---

## Security Considerations

### Detection Vectors
1. **LDAP query logs** - Event ID 1644 (expensive queries)
2. **Anonymous bind attempts** - Event ID 2889
3. **Multiple attribute queries** - Unusual user behavior
4. **Bulk user enumeration** - Rapid sequential queries

### OPSEC Recommendations
1. **Use valid credentials** - Blend with normal queries
2. **Limit threading** - Reduce query rate
3. **LDAPS encryption** - Hide query content
4. **Targeted queries** - Query specific users, not all

### Blue Team Detection

**Event IDs:**
```
1644 - Expensive LDAP query
2889 - LDAP bind without SSL/TLS
4662 - Operation performed on object (with auditing)
4624 - Successful logon (LDAP authentication)
```

**Detection Rules:**
```
# Bulk LDAP enumeration
event_id=1644 AND count > 10 IN 60s

# Anonymous LDAP bind
event_id=2889 AND bind_type="simple" AND user="anonymous"

# Multiple DC queries from single source
event_id=4662 AND source_ip AND dc_count > 3 IN 300s
```

---

## Algorithm Efficiency

### User Enumeration
```
Time: O(n)
  n = number of users in domain
Space: O(n)
  Store all user data in memory
```

### UAC Flag Parsing
```
Time: O(n * f)
  n = number of users
  f = number of UAC flags (constant: 26)
Effective: O(n)
Space: O(n)
```

### SPN Detection
```
Time: O(n)
  n = number of users
  Check if SPN attribute exists
Space: O(k)
  k = number of Kerberoastable users
```

### Admin Detection
```
Time: O(n * g)
  n = number of users
  g = average groups per user
Space: O(a)
  a = number of admin users
```

---

## Comparison to Similar Tools

| Feature | LDAPSeek | BloodHound | PowerView | ADExplorer |
|---------|----------|-----------|-----------|-----------|
| User enumeration | ✅ | ✅ | ✅ | ✅ |
| Kerberoastable detection | ✅ | ✅ | ✅ | ❌ |
| ASREPRoastable detection | ✅ | ✅ | ✅ | ❌ |
| Delegation detection | ✅ | ✅ | ✅ | ✅ |
| UAC flag parsing | ✅ | ❌ | ✅ | ✅ |
| Cross-platform | ✅ | ✅ | ❌ (PowerShell) | ❌ (Windows) |
| No dependencies | ❌ (ldapsearch) | ❌ (Neo4j) | ❌ (PowerShell) | ❌ (GUI) |
| JSON output | ✅ | ✅ | ❌ | ❌ |
| Attack path analysis | ❌ | ✅ | ❌ | ❌ |
| Visualization | ❌ | ✅ | ❌ | ✅ |

**Advantages:**
- Lightweight (no database required)
- Cross-platform (Linux/Windows)
- Focused on attack vectors
- JSON output for automation
- UAC flag interpretation

**Disadvantages:**
- No graph visualization
- No attack path analysis
- Requires ldapsearch binary
- No caching/incremental updates

---

## Error Handling

### LDAP Connection Errors
```python
try:
    result = subprocess.run(['ldapsearch', ...])
except subprocess.TimeoutExpired:
    print("[-] LDAP query timeout")
except FileNotFoundError:
    print("[-] ldapsearch not found - install ldap-utils")
```

### Authentication Errors
```python
if "invalid credentials" in output.lower():
    print("[-] Invalid credentials")
elif "bind failed" in output.lower():
    print("[-] LDAP bind failed")
```

### Parsing Errors
```python
try:
    uac_value = int(uac_string)
except ValueError:
    print("[-] Invalid UAC value")
    uac_value = 0
```

---

## Future Enhancements

### Planned Features
1. **Native LDAP library** - Remove ldapsearch dependency (python-ldap)
2. **LDAPS by default** - Encrypted queries
3. **Kerberos authentication** - Use tickets instead of passwords
4. **Incremental scanning** - Only query changes since last scan
5. **Attack path suggestions** - Basic graph analysis
6. **GPO enumeration** - Group Policy analysis
7. **LAPS password check** - Detect LAPS deployment

### Performance Improvements
1. **Connection pooling** - Reuse LDAP connections
2. **Async queries** - Non-blocking I/O
3. **Result caching** - Store previous results
4. **Delta queries** - Only fetch changes

### Analysis Enhancements
1. **Stale account detection** - Last logon > 90 days
2. **Password age analysis** - pwdLastSet analysis
3. **SID history enumeration** - Detect SID history injection
4. **ACL enumeration** - Permission analysis
5. **Trust enumeration** - Domain trust relationships

---

## Technical Notes

### LDAP Matching Rules
Microsoft-specific matching rules used for bitwise operations:

- **1.2.840.113556.1.4.803** - LDAP_MATCHING_RULE_BIT_AND
  - Bitwise AND: `(uac & flag_value) != 0`
  - Example: `(userAccountControl:1.2.840.113556.1.4.803:=2)` - Disabled accounts

- **1.2.840.113556.1.4.804** - LDAP_MATCHING_RULE_BIT_OR
  - Bitwise OR: `(uac | flag_value) != 0`

### UAC Flag Calculation
```python
# Example: Account with NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD
uac = 0x200 | 0x10000
# Result: 66048 (decimal) = 0x10200 (hex)

# To check if flag is set:
if uac & 0x400000:  # DONT_REQ_PREAUTH
    print("ASREPRoastable!")
```

### AdminCount Attribute
- Automatically set to 1 for members of protected groups
- Protected by AdminSDHolder
- Updated every 60 minutes by SDPROP process
- Persists after removal from protected group (manual cleanup needed)

### SPN Format
```
ServiceClass/Host:Port
Examples:
  MSSQLSvc/sqlserver.corp.local:1433
  HTTP/webserver.corp.local
  CIFS/fileserver.corp.local
```

---

**Version:** 1.0  
**Status:** Production Ready  
**Tested On:** Kali Linux 2024.1, Ubuntu 22.04  
**Python Version:** 3.6+  
**LDAP Version:** LDAPv3
