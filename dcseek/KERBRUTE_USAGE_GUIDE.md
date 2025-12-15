# DCSeek v1.2 - Kerbrute Integration Guide

## Overview

DCSeek v1.2 now includes integrated username enumeration using Kerbrute and SecLists name files. After discovering Domain Controllers, you can automatically generate and test usernames against the target domain.

## New Features

### 1. Username Generation
- Downloads name files from SecLists GitHub repository (names.txt, familynames-usa-top1000.txt)
- Generates usernames based on customizable formats
- Supports common formats like {f}{last}, {first}.{last}, etc.

### 2. Kerbrute Integration
- Automatic username enumeration against discovered Domain Controllers
- Configurable username limits and formats
- Results saved to timestamped output files

## Usage Examples

### Interactive Mode (Default)
```bash
# Basic DC discovery - will prompt for Kerbrute after finding DCs
python dcseek.py -f iplist.txt

# With enum4linux enumeration
python dcseek.py -f iplist.txt --enum
```

### Automated Kerbrute Mode
```bash
# Auto-run Kerbrute with default format ({f}{last})
python dcseek.py -f iplist.txt --kerbrute --domain corp.local

# Custom username format
python dcseek.py -f iplist.txt --kerbrute --domain test.local --username-format "{first}.{last}"

# Limit username generation
python dcseek.py -f iplist.txt --kerbrute --domain company.com --username-limit 20000

# Full automation with custom settings
python dcseek.py -f targets.txt --kerbrute --domain internal.local --username-format "{f}.{last}" --username-limit 50000
```

## Username Formats

The tool supports flexible username formats using these placeholders:

- `{first}` - Full first name (e.g., "john")
- `{last}` - Full last name (e.g., "smith") 
- `{f}` - First initial (e.g., "j")
- `{l}` - Last initial (e.g., "s")

### Common Format Examples:
1. `{f}{last}` → jsmith, bdoe
2. `{f}.{last}` → j.smith, b.doe  
3. `{first}.{last}` → john.smith, bob.doe
4. `{first}{last}` → johnsmith, bobdoe
5. `{last}{f}` → smithj, doeb
6. `{first}_{last}` → john_smith, bob_doe
7. `{f}{l}{last}` → jssmith, bddoe

## Interactive Menu

When running without --kerbrute flag, DCSeek will offer an interactive menu after DC discovery:

1. **Format Selection Menu** - Choose from 7 common formats or enter custom
2. **DC Selection** - Pick which discovered DC to target
3. **Domain Input** - Enter the target domain name
4. **Username Limit** - Set generation limit (default: 40,000, max: 100,000)

## Output Files

### Standard DCSeek Files:
- `dclist.txt` - List of discovered Domain Controller IPs
- `domain_controllers.txt` - Detailed DC information
- `dc_smb_relay_status.txt` - SMB signing vulnerability report

### Username Enumeration Files:
- `{domain}_{format}_usernames_{count}.txt` - Generated username list
- `validusers_{domain}_{timestamp}.txt` - Kerbrute results with valid usernames

## Prerequisites

### Required Tools:
1. **Kerbrute** - Download from https://github.com/ropnop/kerbrute/releases
   - Place binary as `./kerbrute`, `./kerbrute_linux_amd64`, or in PATH
2. **Python modules**: `requests` (for downloading SecLists files)

### Installation:
```bash
# Install Python requirements
pip install requests

# Download Kerbrute (Linux example)
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64

# Or place in PATH as 'kerbrute'
sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute
```

## Example Workflow

### 1. Discovery Phase
```bash
python dcseek.py -f company_ips.txt -v
```

### 2. Choose Username Enumeration
When prompted:
- Select "y" for username enumeration
- Choose DC target (if multiple found)
- Enter domain name (e.g., "corp.local")  
- Select username format from menu
- Set username limit

### 3. Results Analysis
```bash
# Check generated usernames
cat corp_flast_usernames_40000.txt

# Review valid users found by Kerbrute  
cat validusers_corp_20241215_143022.txt
```

## Advanced Usage

### Batch Processing
```bash
# Process multiple target files
for targets in company1_ips.txt company2_ips.txt; do
    python dcseek.py -f $targets --kerbrute --domain $(basename $targets .txt).local
done
```

### Custom Name Lists
If you have custom name lists, replace the downloaded files:
```bash
# Use your own name files (format: one name per line)
cp custom_firstnames.txt names.txt
cp custom_lastnames.txt familynames-usa-top1000.txt

# Then run DCSeek normally
python dcseek.py -f targets.txt --kerbrute --domain company.local
```

## Security Notes

1. **SMB Relay Detection**: DCSeek automatically checks for SMB signing vulnerabilities
2. **Rate Limiting**: Kerbrute includes built-in rate limiting to avoid account lockouts
3. **Stealth**: Use smaller username lists and longer timeouts for stealth operations
4. **Detection**: Username enumeration may trigger security alerts in monitored environments

## Troubleshooting

### Common Issues:

1. **Kerbrute not found**:
   ```
   [!] Kerbrute binary not found. Please install kerbrute:
       https://github.com/ropnop/kerbrute/releases
   ```
   **Solution**: Download and install Kerbrute binary

2. **Download failures**:
   ```
   [!] Error downloading SecLists files: ...
   ```
   **Solution**: Check internet connection, manually download files if needed

3. **No usernames generated**:
   ```
   [!] No usernames generated
   ```
   **Solution**: Check username format syntax, ensure name files exist

4. **Domain connection issues**:
   ```
   [!] Kerbrute failed with return code: ...
   ```  
   **Solution**: Verify DC IP, domain name, network connectivity

### Manual File Download:
If automatic download fails:
```bash
# Download SecLists files manually
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/familynames-usa-top1000.txt
```

## Integration with Other Tools

The generated username lists can be used with other tools:

```bash
# Use with Hydra for password attacks  
hydra -L validusers_corp.txt -P passwords.txt smb://192.168.1.10

# Use with CrackMapExec
crackmapexec smb 192.168.1.10 -u validusers_corp.txt -p 'Password123!'

# Use with Impacket tools
python GetNPUsers.py -usersfile validusers_corp.txt -dc-ip 192.168.1.10 corp.local/
```

## Version History

- **v1.2**: Added Kerbrute integration and username generation
- **v1.1**: Enhanced SMB relay detection and enum4linux integration  
- **v1.0**: Basic Domain Controller discovery