# SeekSweet Philosophy & Revised Roadmap

## Core Philosophy 🎯

**SeekSweet is NOT:**
- ❌ An exploitation framework
- ❌ An automation tool that does everything
- ❌ A reporting/dashboard platform
- ❌ A replacement for manual pentesting

**SeekSweet IS:**
- ✅ A reconnaissance guide
- ✅ A "what to look at next" advisor
- ✅ A data collector and organizer
- ✅ A command generator (not executor)
- ✅ A focus keeper for large networks

---

## Design Principles

### 1. Guide, Don't Exploit
- **Discover** vulnerabilities, don't exploit them
- **Suggest** commands, don't execute them
- **Identify** targets, let user choose action
- **Generate** wordlists/targets, user runs attacks

### 2. Keep It Simple
- Terminal-only interface (no web UI)
- Real-time results (parse while next scan runs)
- Minimal abstraction
- Clear, actionable output

### 3. Non-Destructive
- Port scanning only
- Read-only enumeration
- No exploitation payloads
- No password spraying (suggest only)
- No cracking (suggest only)

### 4. Large Network Focus
- Handle 9+ subnets gracefully
- Progressive results
- Prioritized findings
- Don't overwhelm with data

### 5. Chain Tools, Don't Replace Them
- Generate users.txt → user runs CrackMapExec
- Find relay targets → user runs ntlmrelayx
- Detect LAPS → user extracts with proper tool
- Identify SPNs → user runs Rubeus/hashcat

---

## Revised Tool Improvements

### ✅ APPROVED: Keep & Enhance

#### SMB Signing Detection (RelaySeek)
**Purpose**: Detect relay-vulnerable hosts  
**Output**:
```
relay_targets.txt          # List of vulnerable IPs
RELAY_ATTACK_GUIDE.txt     # Suggested commands

# RELAY_ATTACK_GUIDE.txt contents:
[+] Found 45 relay-vulnerable hosts

Suggested Attack Flow:
1. Start ntlmrelayx:
   impacket-ntlmrelayx -tf relay_targets.txt -smb2support

2. Start Responder (in another terminal):
   sudo responder -I eth0 -wrf

3. Monitor Responder logs:
   tail -f /usr/share/responder/logs/*

Note: Hashes will be captured by Responder. Use hashsweep for cracking.
```

#### LDAP Enhancements
**Additions**:
- ✅ LAPS detection (read-only, identify readable passwords)
- ✅ Delegation enumeration (unconstrained/constrained/RBCD)
- ✅ Password policy extraction
- ✅ Privileged group membership

**Output Format**:
```
HIGH_VALUE_TARGETS.txt
  [LAPS Readable]
  • WORKSTATION01 - ms-Mcs-AdmPwd is readable
  • WORKSTATION02 - ms-Mcs-AdmPwd is readable
  
  [Unconstrained Delegation]
  • SERVER01 - Full unconstrained delegation
  • SERVER02 - Trusts for delegation
  
  [Kerberoastable]
  • svc_sql - SPN: MSSQLSvc/sql01.domain.local
  • svc_web - SPN: HTTP/web01.domain.local

Suggested Actions:
1. Extract LAPS passwords:
   Get-ADComputer WORKSTATION01 -Properties ms-Mcs-AdmPwd
   
2. Request TGS tickets:
   python kerbseek.py dclist.txt -u user@domain.local -p password
```

#### Kerberos Enhancements
**Additions**:
- ✅ Better hash formatting
- ✅ Identify weak encryption (RC4 vs AES)
- ✅ Generate hashcat command suggestions

**Output Format**:
```
kerberoast_hashes.txt      # Ready for hashcat
asrep_hashes.txt           # Ready for hashcat
KERBEROS_ATTACK_GUIDE.txt  # Suggested commands

# KERBEROS_ATTACK_GUIDE.txt contents:
[+] Found 5 Kerberoastable accounts (RC4 encryption - crackable!)
[+] Found 2 ASREPRoastable accounts

Suggested Attack Flow:
1. Crack Kerberoast hashes:
   hashcat -m 13100 kerberoast_hashes.txt rockyou.txt

2. Crack ASREP hashes:
   hashcat -m 18200 asrep_hashes.txt rockyou.txt

3. Or use John:
   john --wordlist=rockyou.txt kerberoast_hashes.txt
```

#### Credential Store Discovery
**Additions**:
- ✅ GPP password detection (identify, don't extract)
- ✅ Browser credential store locations
- ✅ KeePass database locations

**Output Format**:
```
CRED_LOCATIONS.txt
  [Group Policy Passwords Found]
  • \\DC01\SYSVOL\domain.local\Policies\{GUID}\Machine\Preferences\Groups.xml
  
  [KeePass Databases]
  • \\FILE01\Share\IT\Database.kdbx
  • \\FILE01\Users\john.smith\Documents\passwords.kdbx
  
  [Browser Credential Stores]
  • C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\Login Data
  
Suggested Actions:
1. Extract GPP passwords:
   Get-GPPPassword.ps1
   
2. Copy KeePass databases for offline cracking:
   smbclient //FILE01/Share -U user
```

#### User Enumeration Enhancement
**New Feature**: Generate users.txt from LDAP results

**Output**:
```
users.txt                  # Clean username list
USERS_ATTACK_GUIDE.txt     # Suggested password spray commands

# USERS_ATTACK_GUIDE.txt contents:
[+] Extracted 1,247 domain users

Password Policy:
  - Minimum Length: 8
  - Complexity Required: Yes
  - Lockout Threshold: 5 attempts
  - Lockout Duration: 30 minutes

Suggested Password Spray (MANUAL - DO NOT AUTOMATE):
1. Safe approach (1 password per 30 minutes):
   crackmapexec smb DC01 -u users.txt -p 'Winter2024!' --continue-on-success
   
2. Wait 30 minutes, try another:
   crackmapexec smb DC01 -u users.txt -p 'Company123!' --continue-on-success

WARNING: Respect lockout policy! Max 4 attempts per 30 minutes.
```

---

### ✅ APPROVED: New Tools (Reconnaissance Only)

#### 1. RelaySeek - SMB Signing Detection
**What it does**: Scans for SMB signing status  
**What it doesn't do**: Execute relay attacks  
**Output**: Target list + command suggestions

#### 2. BloodSeek - BloodHound Data Collection
**What it does**: Runs BloodHound.py for data collection  
**What it doesn't do**: Analyze data, suggest attack paths  
**Output**: BloodHound JSON files + "Import to BloodHound" instructions

#### 3. SSLSeek - SSL/TLS Scanner
**What it does**: Scans SSL/TLS with testssl.sh  
**What it doesn't do**: Exploit vulnerabilities  
**Output**: Weak cipher list + vulnerability list

#### 4. GPPSeek - GPP Password Finder
**What it does**: Scans SYSVOL for GPP files  
**What it doesn't do**: Decrypt passwords (just identify location)  
**Output**: File locations + decryption command suggestions

#### 5. LAPSSeek - LAPS Password Detection
**What it does**: Identifies computers with readable LAPS passwords  
**What it doesn't do**: Extract passwords (just identify readable ones)  
**Output**: Computer list + PowerShell command to read passwords

#### 6. DelegSeek - Delegation Detection
**What it does**: Finds delegation configurations  
**What it doesn't do**: Exploit delegation  
**Output**: List of delegated accounts + exploitation references

#### 7. IPv6Seek - IPv6 Discovery
**What it does**: Discovers IPv6-enabled hosts  
**What it doesn't do**: Execute mitm6  
**Output**: IPv6 host list + mitm6 command suggestions

---

### ❌ REMOVED: Out of Scope

#### Removed: Automatic Hash Cracking
**Why**: User should control cracking with their own wordlists/rules  
**Instead**: Generate hashcat/john commands

#### Removed: Password Spraying Tool (PassSeek)
**Why**: Too risky to automate, user should control timing  
**Instead**: Generate users.txt + suggest safe spray commands

#### Removed: Responder Integration (RespSeek)
**Why**: User should run Responder manually (with hashsweep for cracking)  
**Instead**: Suggest Responder commands after relay detection

#### Removed: Report Generation
**Why**: User should review results in real-time, not at the end  
**Instead**: Clear, focused output files per tool

#### Removed: Web Interface
**Why**: Terminal is simpler, no complexity needed  
**Instead**: Keep clean terminal menu

#### Removed: Automatic Tool Chaining
**Why**: User should control flow, especially with large networks  
**Instead**: Suggest next steps in output

#### Removed: Exploitation Tools
**Why**: Out of scope, too dangerous  
**Instead**: Reference CVE numbers, suggest safe verification

---

## Revised Orchestrator Improvements

### ✅ KEEP: Simple Enhancements

#### 1. Credential Caching (Session Only)
- Store credentials once per session
- Clear on exit
- Don't persist to disk

#### 2. Centralized Output (Optional)
- `results/{engagement_name}/` directory
- Copy outputs after tool completion
- Keep originals in tool directories too

#### 3. Command Suggestion Files
**New Output Type**: `*_ATTACK_GUIDE.txt`

Every tool that finds something actionable generates a guide:
```
RELAY_ATTACK_GUIDE.txt     # From RelaySeek
KERBEROS_ATTACK_GUIDE.txt  # From KerbSeek
LAPS_ATTACK_GUIDE.txt      # From LAPSSeek
GPP_ATTACK_GUIDE.txt       # From GPPSeek
```

These contain:
- What was found
- Suggested commands (ready to copy/paste)
- Warnings about detection/safety
- Reference links

#### 4. Smart Filtering for Large Networks
**Problem**: 9 subnets = too much data  
**Solution**: Severity-based filtering

```python
def generate_priority_findings(results: List[dict]) -> None:
    """Filter to only HIGH/CRITICAL findings for large networks"""
    
    if len(results) > 500:  # Large network
        print("[!] Large network detected. Showing only HIGH/CRITICAL findings.")
        print("[*] See detailed reports for full data.\n")
        
        # Show only critical findings in terminal
        critical = [r for r in results if r['severity'] == 'CRITICAL']
        high = [r for r in results if r['severity'] == 'HIGH']
        
        print(f"CRITICAL: {len(critical)}")
        for finding in critical[:10]:  # Top 10
            print(f"  • {finding['description']}")
        
        print(f"\nHIGH: {len(high)}")
        for finding in high[:10]:  # Top 10
            print(f"  • {finding['description']}")
        
        print(f"\n[*] Full results: {output_file}")
```

### ❌ REMOVE: Complex Features

- ❌ Dependency management (user controls order)
- ❌ Configuration files (keep it simple)
- ❌ Plugin system (not needed)
- ❌ Notification system (user is watching terminal)
- ❌ Retry logic (user can re-run)
- ❌ HTML reports (text files are enough)

---

## Final Approved Tool List

### Existing Tools (Enhance)
1. **DCSeek** - Add SMB signing detection
2. **LDAPSeek** - Add LAPS, delegation, password policy, generate users.txt
3. **SMBSeek** - Add SMB signing detection, merge with ShareSeek
4. **KerbSeek** - Add command suggestions, better hash formatting
5. **CredSeek** - Identify GPP/KeePass/browser stores (not extract)
6. **WinRMSeek** - Add actual connection testing (optional)
7. **WebSeek** - ✅ Already excellent
8. **VulnSeek** - ✅ Already excellent
9. **DbSeek** - Add default cred testing (manual)
10. **PanelSeek** - Keep as-is (simple)
11. **BackupSeek** - Keep as-is (simple)
12. **PrintSeek** - Keep as-is (niche)
13. **SNMPSeek** - Keep as-is (functional)

### New Tools (Add)
14. **RelaySeek** - SMB relay vulnerability detection
15. **BloodSeek** - BloodHound data collection wrapper
16. **SSLSeek** - SSL/TLS scanning wrapper (testssl.sh)
17. **GPPSeek** - Group Policy Password file finder
18. **LAPSSeek** - LAPS password readability detector
19. **DelegSeek** - Delegation configuration finder
20. **IPv6Seek** - IPv6 discovery and mitm6 prep

---

## Implementation Priority (Revised)

### Phase 1: Critical Gaps (Week 1-2) ⭐⭐⭐
1. Add SMB signing to SMBSeek (**CRITICAL**)
2. Add SMB signing to DCSeek
3. Create RelaySeek (standalone)
4. Add LAPS detection to LDAPSeek
5. Add delegation enumeration to LDAPSeek

### Phase 2: High Value Tools (Week 3-4) ⭐⭐
6. Create BloodSeek (BloodHound wrapper)
7. Add GPP detection to CredSeek
8. Add users.txt generation to LDAPSeek
9. Create GPPSeek (standalone)
10. Create LAPSSeek (standalone)

### Phase 3: Supporting Tools (Week 5-6) ⭐
11. Create SSLSeek (testssl.sh wrapper)
12. Create DelegSeek (standalone delegation finder)
13. Create IPv6Seek
14. Add password policy to LDAPSeek
15. Add command suggestion files to all tools

---

## Output Philosophy

### Every Tool Should Generate:

1. **{tool}_list.txt** - Clean list (for piping)
   ```
   192.168.1.10
   192.168.1.15
   192.168.1.20
   ```

2. **{tool}_details.txt** - Human-readable findings
   ```
   [+] SMB Signing Analysis
   
   Relay Vulnerable (45 hosts):
   • 192.168.1.10 - WORKSTATION01 - Signing: Disabled
   • 192.168.1.15 - WORKSTATION02 - Signing: Enabled (not required)
   ```

3. **{tool}_details.json** - Machine-readable (optional)
   ```json
   {
     "timestamp": "2025-10-15T14:30:00",
     "hosts_scanned": 254,
     "findings": [...]
   }
   ```

4. **{TOOL}_ATTACK_GUIDE.txt** - Suggested next steps (if actionable findings)
   ```
   [+] Found 45 relay-vulnerable hosts
   
   Next Steps:
   1. Review relay_targets.txt
   2. Set up ntlmrelayx:
      impacket-ntlmrelayx -tf relay_targets.txt -smb2support
   3. Run Responder in another terminal:
      sudo responder -I eth0 -wrf
   
   References:
   - https://www.example.com/smb-relay-guide
   ```

---

## Testing Philosophy

### User Testing Focus
- Can user find critical findings quickly? ✅
- Are suggested commands copy/paste ready? ✅
- Is output clear on 9+ subnets? ✅
- Does user know what to do next? ✅
- Is any data overwhelming/useless? ❌

### What NOT to Test
- Automatic exploitation (not in scope)
- Report quality (text files are fine)
- GUI usability (no GUI)
- Multi-user scenarios (single user)

---

## Success Criteria (Revised)

### ✅ SeekSweet is Successful When:

1. **Pentester can run full internal assessment in 2-3 hours**
   - Not including manual exploitation time
   - Just reconnaissance phase

2. **User knows exactly what to do next**
   - Clear HIGH/CRITICAL findings
   - Copy/paste commands ready
   - References for complex attacks

3. **Large networks (9+ subnets) are manageable**
   - Not drowning in data
   - Prioritized output
   - Progressive results

4. **No system crashes or account lockouts**
   - Read-only operations
   - Respects policies
   - Non-destructive

5. **Output files integrate with other tools**
   - users.txt → CrackMapExec
   - relay_targets.txt → ntlmrelayx
   - hashes.txt → hashcat
   - JSON files → custom scripts

---

## What SeekSweet Will Never Do

- ❌ Exploit vulnerabilities
- ❌ Spray passwords automatically
- ❌ Crack hashes automatically
- ❌ Execute attack commands
- ❌ Generate fancy HTML reports
- ❌ Replace manual pentesting
- ❌ Run Responder/mitm6
- ❌ Drop payloads
- ❌ Privilege escalation
- ❌ Post-exploitation
- ❌ Data exfiltration

---

## Conclusion

SeekSweet stays true to its mission:
> **A reconnaissance guide that helps pentesters stay focused and know what to look at next.**

Not an autopilot exploitation framework.  
Not a reporting tool.  
Not a replacement for skill.

Just a smart helper for large, complex networks.

---

**Philosophy**: ✅ Approved  
**Scope**: ✅ Refined  
**Next Step**: Implement Phase 1 (SMB signing + LAPS detection)
