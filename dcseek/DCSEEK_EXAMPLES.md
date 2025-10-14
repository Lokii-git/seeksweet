# Example DCSeek Output

## Sample Run

```bash
$ ./dcseek.py --enum -v

╔══════════════════════════════════════════════════════════╗
║                        DCSeek v1.1                       ║
║          Domain Controller Discovery Tool                ║
║            with Enum4linux Integration                   ║
╚══════════════════════════════════════════════════════════╝

[*] Reading IPs from: iplist.txt
[*] Found 256 IP addresses to scan
[*] Starting scan with 10 workers (timeout: 1.0s)...

[+] DOMAIN CONTROLLER FOUND: 192.168.1.10
    Hostname: DC01.CORP.LOCAL
    Open DC Ports: 53 (DNS), 88 (Kerberos), 389 (LDAP), 445 (SMB), 636 (LDAPS), 3268 (Global Catalog)
    DNS SRV Records: _ldap._tcp.dc._msdcs, _kerberos._tcp.dc._msdcs

[+] DOMAIN CONTROLLER FOUND: 192.168.1.11
    Hostname: DC02.CORP.LOCAL
    Open DC Ports: 53 (DNS), 88 (Kerberos), 389 (LDAP), 445 (SMB), 3268 (Global Catalog)

[*] Progress: 50/256 hosts scanned
[*] Progress: 100/256 hosts scanned
[*] Progress: 150/256 hosts scanned
[*] Progress: 200/256 hosts scanned
[*] Progress: 250/256 hosts scanned

======================================================================
SCAN SUMMARY
======================================================================
Total IPs scanned: 256
Domain Controllers found: 2

DOMAIN CONTROLLERS:
----------------------------------------------------------------------
  192.168.1.10    | DC01.CORP.LOCAL
  192.168.1.11    | DC02.CORP.LOCAL

[+] DC IP list saved to: dclist.txt

[*] Results saved to: domain_controllers.txt

======================================================================
ENUM4LINUX ENUMERATION
======================================================================
[*] Starting enum4linux on 2 Domain Controllers...
[*] Results will be saved to: enum4linux_results/

[1/2] Enumerating 192.168.1.10...
[*] Running enum4linux on 192.168.1.10...
[+] Enum4linux output saved to: enum4linux_results/enum4linux_192_168_1_10.txt
[+] Enumeration complete for 192.168.1.10
    Domain: CORP
    Users found: 47
    Shares found: 6
    Sample users: Administrator, Guest, krbtgt, john.doe, jane.smith
    Shares: NETLOGON, SYSVOL, IT_Shared, HR_Docs, Finance, Marketing

[2/2] Enumerating 192.168.1.11...
[*] Running enum4linux on 192.168.1.11...
[+] Enum4linux output saved to: enum4linux_results/enum4linux_192_168_1_11.txt
[+] Enumeration complete for 192.168.1.11
    Domain: CORP
    Users found: 45
    Shares found: 5
    Sample users: Administrator, Guest, krbtgt, backup.admin, helpdesk
    Shares: NETLOGON, SYSVOL, Backups, Scripts, Tools

======================================================================
ENUMERATION SUMMARY
======================================================================
DCs enumerated: 2
Total unique users found: 92
Total shares found: 11
[+] Enum4linux summary saved to: enum4linux_summary.txt
[+] JSON summary saved to: enum4linux_summary.json
```

## Sample dclist.txt

```
192.168.1.10
192.168.1.11
```

## Sample enum4linux_summary.txt

```
DCSeek - Enum4linux Enumeration Summary
======================================================================
Scan Date: 2025-10-13 14:35:22
Total DCs Enumerated: 2
======================================================================

Target: 192.168.1.10
----------------------------------------------------------------------
Domain: CORP
OS Info: Windows Server 2019 Standard 17763

Users Found (47):
  - Administrator
  - Guest
  - krbtgt
  - john.doe
  - jane.smith
  - bob.wilson
  - alice.johnson
  - tom.anderson
  - sarah.martinez
  - michael.brown
  - emily.davis
  - david.miller
  - lisa.garcia
  - james.rodriguez
  - mary.wilson
  ... (32 more)

SMB Shares Found (6):
  - NETLOGON
  - SYSVOL
  - IT_Shared
  - HR_Docs
  - Finance
  - Marketing

Groups Found (12):
  - Domain Admins
  - Domain Users
  - Enterprise Admins
  - IT Staff
  - HR Department
  - Finance Team
  - Marketing Team
  ... (5 more)

Password Policy:
  min_length: 8
  history_length: 24
  max_age: 42 days
  complexity: DOMAIN_PASSWORD_COMPLEX

======================================================================

Target: 192.168.1.11
----------------------------------------------------------------------
Domain: CORP
OS Info: Windows Server 2022 Standard 20348

Users Found (45):
  - Administrator
  - Guest
  - krbtgt
  - backup.admin
  - helpdesk
  - sql.service
  - web.service
  - exchange.admin
  - monitoring.svc
  - reporting.svc
  ... (35 more)

SMB Shares Found (5):
  - NETLOGON
  - SYSVOL
  - Backups
  - Scripts
  - Tools

Groups Found (10):
  - Domain Admins
  - Domain Users
  - Backup Operators
  - Server Operators
  - Help Desk
  ... (5 more)

Password Policy:
  min_length: 10
  history_length: 24
  max_age: 90 days
  complexity: DOMAIN_PASSWORD_COMPLEX

======================================================================
```

## Sample enum4linux_summary.json

```json
[
  {
    "ip": "192.168.1.10",
    "users": [
      "Administrator",
      "Guest",
      "krbtgt",
      "john.doe",
      "jane.smith",
      "bob.wilson",
      "alice.johnson"
    ],
    "shares": [
      "NETLOGON",
      "SYSVOL",
      "IT_Shared",
      "HR_Docs",
      "Finance",
      "Marketing"
    ],
    "domain": "CORP",
    "os_info": "Windows Server 2019 Standard 17763",
    "groups": [
      "Domain Admins",
      "Domain Users",
      "Enterprise Admins",
      "IT Staff",
      "HR Department"
    ],
    "password_policy": {
      "min_length": "8",
      "history_length": "24",
      "max_age": "42 days",
      "complexity": "DOMAIN_PASSWORD_COMPLEX"
    }
  },
  {
    "ip": "192.168.1.11",
    "users": [
      "Administrator",
      "Guest",
      "krbtgt",
      "backup.admin",
      "helpdesk",
      "sql.service"
    ],
    "shares": [
      "NETLOGON",
      "SYSVOL",
      "Backups",
      "Scripts",
      "Tools"
    ],
    "domain": "CORP",
    "os_info": "Windows Server 2022 Standard 20348",
    "groups": [
      "Domain Admins",
      "Domain Users",
      "Backup Operators"
    ],
    "password_policy": {
      "min_length": "10",
      "history_length": "24",
      "max_age": "90 days",
      "complexity": "DOMAIN_PASSWORD_COMPLEX"
    }
  }
]
```

## Using the Output

### Extract all users to a file
```bash
cat enum4linux_summary.json | jq -r '.[].users[]' | sort -u > all_users.txt
```

### Find interesting shares
```bash
cat enum4linux_summary.json | jq -r '.[].shares[]' | grep -v "NETLOGON\|SYSVOL"
```

### Check password policies
```bash
cat enum4linux_summary.json | jq -r '.[] | "\(.ip): Min PW Length = \(.password_policy.min_length)"'
```

### Use with CrackMapExec
```bash
cme smb 192.168.1.10 192.168.1.11 -u all_users.txt -p 'Password123'
```

### Nmap service scan on DCs
```bash
nmap -sV -sC -p- -iL dclist.txt -oA dc_full_scan
```
