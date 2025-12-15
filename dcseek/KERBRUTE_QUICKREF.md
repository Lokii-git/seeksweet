# DCSeek v1.2 - Kerbrute Integration Quick Reference

## Quick Commands

### Basic Discovery with Interactive Kerbrute
```bash
python dcseek.py -f iplist.txt
# Will prompt for username enumeration after finding DCs
```

### Automated Kerbrute with Default Settings  
```bash
python dcseek.py -f iplist.txt --kerbrute --domain corp.local
# Uses {f}{last} format, 40k username limit
```

### Custom Format and Limits
```bash
python dcseek.py -f iplist.txt --kerbrute --domain company.com --username-format "{first}.{last}" --username-limit 20000
```

### Full Enumeration Pipeline
```bash
python dcseek.py -f targets.txt --enum --kerbrute --domain internal.local --username-format "{f}.{last}"
# Runs DC discovery + enum4linux + kerbrute
```

## Username Format Quick Reference

| Format | Example Output | Description |
|--------|---------------|-------------|
| `{f}{last}` | jsmith | First initial + last name |
| `{f}.{last}` | j.smith | First initial dot last name |  
| `{first}.{last}` | john.smith | Full names with dot |
| `{first}{last}` | johnsmith | Combined names |
| `{last}{f}` | smithj | Last name + first initial |
| `{first}_{last}` | john_smith | Underscore separated |
| `{f}{l}{last}` | jssmith | First + last initial + last name |

## Expected Output Files

### After DC Discovery:
- `dclist.txt` - DC IP addresses
- `domain_controllers.txt` - Detailed DC info  
- `dc_smb_relay_status.txt` - SMB vulnerability report

### After Username Enumeration:
- `{domain}_{format}_usernames_{count}.txt` - Generated usernames
- `validusers_{domain}_{timestamp}.txt` - Kerbrute results

## Example Kerbrute Command
The tool generates and runs commands like:
```bash
kerbrute userenum --dc 192.168.54.11 -d phin.local phin_flast_usernames_40k.txt -o validusers.txt
```

## Prerequisites Checklist
- [ ] Kerbrute binary installed and in PATH
- [ ] Python `requests` module installed  
- [ ] Network connectivity to target DCs
- [ ] Valid domain name for enumeration

## Troubleshooting Quick Fixes

**Kerbrute not found**: Download from https://github.com/ropnop/kerbrute/releases  
**Download fails**: Check internet, manually download SecLists files  
**No usernames generated**: Check format syntax, verify name files exist  
**Kerbrute errors**: Verify DC IP, domain name, network connectivity