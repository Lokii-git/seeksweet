#!/usr/bin/env python3
"""
DCSeek - Advanced Domain Controller Discovery & Enumeration Tool
Reads IPs from iplist.txt and identifies potential Active Directory Domain Controllers

Features:
- Multi-threaded DC discovery with port scanning
- SMB signing vulnerability detection (critical for relay attacks)
- Username enumeration with Kerbrute integration
- Automatic SecLists download and username generation (8 formats)
- enum4linux integration for user/share enumeration
- Real-time output display and comprehensive reporting
- Cross-platform Kerbrute auto-download (Windows/Linux/macOS)
"""

import socket
import ipaddress
import subprocess
import sys
import argparse
import os
import re
import json
import requests
import itertools
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list

# Common DC ports
DC_PORTS = {
    53: "DNS",
    88: "Kerberos",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    3268: "Global Catalog",
    3269: "Global Catalog SSL"
}

# Minimum ports for DC detection (having these suggests it's likely a DC)
CRITICAL_DC_PORTS = {88, 389, 445}


def read_ip_list(filename: str) -> Set[str]:
    """Read and expand IP addresses from file"""
    ips = set()
    
    # Use shared utility to find the file
    filename = find_ip_list(filename)
    
    try:
        with open(filename, 'r') as f:
            line_number = 0
            for line in f:
                line_number += 1
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Handle CIDR notation
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        # Limit expansion for safety
                        host_count = network.num_addresses - 2  # Exclude network and broadcast
                        if host_count > 65534:
                            print(f"[!] Warning: Line {line_number}: CIDR {line} is too large (>{host_count} hosts). Skipping.")
                            continue
                        for ip in network.hosts():
                            ips.add(str(ip))
                    except ValueError as e:
                        print(f"[!] Warning: Line {line_number}: Invalid CIDR notation '{line}': {e}")
                else:
                    # Validate single IP
                    try:
                        ipaddress.ip_address(line)
                        ips.add(line)
                    except ValueError as e:
                        print(f"[!] Warning: Line {line_number}: Invalid IP address '{line}': {e}")
    except PermissionError:
        print(f"[!] Error: Permission denied reading {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading file {filename}: {e}")
        sys.exit(1)
    
    if not ips:
        print(f"[!] Error: No valid IP addresses found in {filename}")
        sys.exit(1)
    
    return ips


def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except socket.error as e:
        return False
    except Exception as e:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def get_hostname(ip: str) -> str:
    """Try to resolve hostname"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname else "N/A"
    except socket.herror:
        return "N/A"
    except socket.gaierror:
        return "N/A"
    except socket.timeout:
        return "N/A"
    except Exception as e:
        return "N/A"


def check_dns_srv_records(ip: str) -> List[str]:
    """Check for AD DNS SRV records"""
    srv_records = []
    
    # Try to query common AD SRV records
    srv_queries = [
        "_ldap._tcp.dc._msdcs",
        "_kerberos._tcp.dc._msdcs",
        "_gc._tcp"
    ]
    
    for query in srv_queries:
        try:
            result = subprocess.run(
                ['nslookup', '-type=SRV', query, ip],
                capture_output=True,
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0 and 'service' in result.stdout.lower():
                srv_records.append(query)
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            # nslookup not available
            break
        except Exception as e:
            continue
    
    return srv_records


def check_smb_signing(ip: str, timeout: int = 5) -> Dict:
    """
    Check SMB signing status using crackmapexec.
    
    Args:
        ip: Target IP address
        timeout: Command timeout in seconds
        
    Returns:
        Dict with signing status
    """
    result = {
        'signing_enabled': False,
        'signing_required': False,
        'relay_vulnerable': False,
        'error': None
    }
    
    try:
        # Use crackmapexec to check SMB signing
        cmd = ['crackmapexec', 'smb', ip, '--gen-relay-list', 'temp_relay_dc.txt']
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout + proc.stderr
        
        # Parse output for signing status
        if 'signing:False' in output.lower():
            result['signing_enabled'] = False
            result['signing_required'] = False
            result['relay_vulnerable'] = True
        elif 'signing:True' in output.lower():
            result['signing_enabled'] = True
            # Check if required or just enabled
            if 'signing required' not in output.lower():
                result['signing_required'] = False
                result['relay_vulnerable'] = True
            else:
                result['signing_required'] = True
                result['relay_vulnerable'] = False
        
        # Clean up temp file
        if os.path.exists('temp_relay_dc.txt'):
            os.remove('temp_relay_dc.txt')
        
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'crackmapexec not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_host(ip: str, timeout: float = 1.0) -> Optional[dict]:
    """Scan a single host for DC indicators"""
    try:
        result = {
            'ip': ip,
            'hostname': None,
            'open_ports': {},
            'is_likely_dc': False,
            'srv_records': [],
            'smb_signing': None,
            'error': None
        }
        
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            result['error'] = "Invalid IP address"
            return result
        
        # Get hostname
        result['hostname'] = get_hostname(ip)
        
        # Check DC ports
        open_dc_ports = set()
        for port, service in DC_PORTS.items():
            try:
                if check_port(ip, port, timeout):
                    result['open_ports'][port] = service
                    open_dc_ports.add(port)
            except Exception as e:
                continue
        
        # Check if it's likely a DC
        if CRITICAL_DC_PORTS.issubset(open_dc_ports):
            result['is_likely_dc'] = True
            # Check DNS SRV records if DNS is open
            if 53 in open_dc_ports:
                try:
                    result['srv_records'] = check_dns_srv_records(ip)
                except Exception as e:
                    pass
            
            # Check SMB signing status (CRITICAL for DCs)
            if 445 in open_dc_ports:
                try:
                    result['smb_signing'] = check_smb_signing(ip, timeout=5)
                except Exception as e:
                    result['smb_signing'] = {'error': str(e)}
        
        return result
    except Exception as e:
        return {
            'ip': ip,
            'hostname': None,
            'open_ports': {},
            'is_likely_dc': False,
            'srv_records': [],
            'error': str(e)
        }


def parse_enum4linux_output(output: str, ip: str) -> Dict:
    """Parse enum4linux output for users and shares"""
    result = {
        'ip': ip,
        'users': [],
        'shares': [],
        'domain': None,
        'os_info': None,
        'groups': [],
        'password_policy': {}
    }
    
    lines = output.split('\n')
    
    # Parse domain info
    for line in lines:
        if 'Domain Name:' in line:
            match = re.search(r'Domain Name:\s*(\S+)', line)
            if match:
                result['domain'] = match.group(1)
        elif 'OS:' in line:
            result['os_info'] = line.strip()
    
    # Parse users (look for user list section)
    in_user_section = False
    for i, line in enumerate(lines):
        if 'Users on' in line or 'user:' in line.lower():
            in_user_section = True
        elif in_user_section:
            # Match patterns like: user:[username] rid:[0x...]
            user_match = re.search(r'user:\[([^\]]+)\]', line, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
                if username and username not in result['users']:
                    result['users'].append(username)
            # Exit section on empty line or new section
            elif line.strip() == '' or line.startswith('='):
                in_user_section = False
    
    # Parse shares
    in_share_section = False
    for i, line in enumerate(lines):
        if 'Share Enumeration' in line or 'Sharename' in line:
            in_share_section = True
            continue
        elif in_share_section:
            # Match share names (typically in format: Sharename   Type   Comment)
            if line.strip() and not line.startswith('=') and not line.startswith('-'):
                # Look for common share patterns
                share_match = re.match(r'\s*(\S+)\s+(Disk|IPC|Printer)', line)
                if share_match:
                    share_name = share_match.group(1)
                    share_type = share_match.group(2)
                    if share_name not in ['IPC$'] and share_name not in result['shares']:
                        result['shares'].append(share_name)
            elif 'Failed' in line or line.startswith('==='):
                in_share_section = False
    
    # Parse groups
    in_group_section = False
    for line in lines:
        if 'Group' in line and ('Members' in line or 'rid:' in line.lower()):
            in_group_section = True
        elif in_group_section:
            group_match = re.search(r'group:\[([^\]]+)\]', line, re.IGNORECASE)
            if group_match:
                group_name = group_match.group(1)
                if group_name and group_name not in result['groups']:
                    result['groups'].append(group_name)
    
    # Parse password policy
    for line in lines:
        if 'Minimum password length:' in line:
            match = re.search(r'Minimum password length:\s*(\d+)', line)
            if match:
                result['password_policy']['min_length'] = match.group(1)
        elif 'Password history length:' in line:
            match = re.search(r'Password history length:\s*(\d+)', line)
            if match:
                result['password_policy']['history_length'] = match.group(1)
        elif 'Maximum password age:' in line:
            result['password_policy']['max_age'] = line.split(':', 1)[1].strip()
        elif 'Password Complexity Flags:' in line:
            match = re.search(r'Password Complexity Flags:\s*(.+)', line)
            if match:
                result['password_policy']['complexity'] = match.group(1)
    
    return result


def run_enum4linux(ip: str, output_dir: str = "enum4linux_results") -> Optional[Dict]:
    """Run enum4linux on a target IP and parse results"""
    print(f"[*] Running enum4linux on {ip}...")
    
    # Create output directory if it doesn't exist
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"[!] Error creating directory {output_dir}: {e}")
        return None
    
    # Run enum4linux
    output_file = os.path.join(output_dir, f"enum4linux_{ip.replace('.', '_')}.txt")
    
    try:
        # Check if enum4linux is available
        check_cmd = subprocess.run(
            ['which', 'enum4linux'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if check_cmd.returncode != 0:
            # Try enum4linux-ng as alternative
            check_cmd = subprocess.run(
                ['which', 'enum4linux-ng'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if check_cmd.returncode != 0:
                print(f"[!] enum4linux not found. Install with: sudo apt install enum4linux")
                return None
            else:
                enum_cmd = 'enum4linux-ng'
        else:
            enum_cmd = 'enum4linux'
        
        # Run enum4linux with comprehensive options
        cmd = [enum_cmd, '-a', ip]  # -a = all simple enumeration
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        output = result.stdout + result.stderr
        
        # Save raw output
        try:
            with open(output_file, 'w') as f:
                f.write(f"Enum4linux scan of {ip}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*70 + "\n\n")
                f.write(output)
            print(f"[+] Enum4linux output saved to: {output_file}")
        except Exception as e:
            print(f"[!] Error saving enum4linux output: {e}")
        
        # Parse the output
        parsed = parse_enum4linux_output(output, ip)
        
        return parsed
        
    except subprocess.TimeoutExpired:
        print(f"[!] enum4linux timed out for {ip}")
        return None
    except FileNotFoundError:
        print(f"[!] enum4linux not found. Install with: sudo apt install enum4linux")
        return None
    except Exception as e:
        print(f"[!] Error running enum4linux on {ip}: {e}")
        return None


def save_dc_smb_status(domain_controllers: List[Dict], filename: str = "dc_smb_status.txt"):
    """Save DC SMB signing status report - CRITICAL for identifying relay vulnerabilities"""
    try:
        relay_vulnerable = [dc for dc in domain_controllers if dc.get('smb_signing') and dc['smb_signing'].get('relay_vulnerable')]
        signing_required = [dc for dc in domain_controllers if dc.get('smb_signing') and dc['smb_signing'].get('signing_required')]
        
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("DOMAIN CONTROLLER SMB SIGNING STATUS\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Total Domain Controllers: {len(domain_controllers)}\n")
            f.write(f"Relay Vulnerable (CRITICAL): {len(relay_vulnerable)}\n")
            f.write(f"Signing Required (Protected): {len(signing_required)}\n\n")
            
            if relay_vulnerable:
                f.write("=" * 70 + "\n")
                f.write("⚠⚠⚠ RELAY VULNERABLE DOMAIN CONTROLLERS ⚠⚠⚠\n")
                f.write("=" * 70 + "\n\n")
                f.write("These DCs do not require SMB signing and are vulnerable to relay attacks!\n")
                f.write("This is a CRITICAL security misconfiguration.\n\n")
                
                for dc in relay_vulnerable:
                    f.write(f"IP: {dc['ip']}\n")
                    f.write(f"Hostname: {dc.get('hostname', 'N/A')}\n")
                    if dc.get('smb_signing') and dc['smb_signing'].get('signing_enabled'):
                        f.write("Status: Signing ENABLED but NOT REQUIRED (still vulnerable)\n")
                    else:
                        f.write("Status: Signing DISABLED\n")
                    f.write("\n")
                
                f.write("=" * 70 + "\n")
                f.write("RECOMMENDED REMEDIATION\n")
                f.write("=" * 70 + "\n\n")
                f.write("1. Enable SMB signing requirement on all Domain Controllers:\n")
                f.write("   Group Policy: Computer Configuration > Policies > Windows Settings >\n")
                f.write("   Security Settings > Local Policies > Security Options\n")
                f.write("   Set: 'Microsoft network server: Digitally sign communications (always)' to Enabled\n\n")
                f.write("2. Or via PowerShell:\n")
                f.write("   Set-SmbServerConfiguration -RequireSecuritySignature $true -Force\n\n")
                f.write("3. Restart SMB service or reboot for changes to take effect\n\n")
            
            if signing_required:
                f.write("=" * 70 + "\n")
                f.write("✓ PROTECTED DOMAIN CONTROLLERS\n")
                f.write("=" * 70 + "\n\n")
                f.write("These DCs properly require SMB signing.\n\n")
                
                for dc in signing_required:
                    f.write(f"IP: {dc['ip']}\n")
                    f.write(f"Hostname: {dc.get('hostname', 'N/A')}\n")
                    f.write("Status: Signing REQUIRED (Protected)\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("REFERENCES\n")
            f.write("=" * 70 + "\n\n")
            f.write("• https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing\n")
            f.write("• https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-347a\n")
            f.write("• https://attack.mitre.org/techniques/T1557/001/\n\n")
        
        print(f"[+] DC SMB status saved to: {filename}")
        return True
        
    except Exception as e:
        print(f"[!] Error saving DC SMB status: {e}")
        return False

def save_dclist(domain_controllers: List[Dict], filename: str = "dclist.txt"):
    """Save discovered DCs to dclist.txt"""
    try:
        with open(filename, 'w') as f:
            for dc in domain_controllers:
                f.write(f"{dc['ip']}\n")
        print(f"[+] DC IP list saved to: {filename}")
        return True
    except Exception as e:
        print(f"[!] Error saving DC list: {e}")
        return False


def save_enum_summary(enum_results: List[Dict], filename: str = "enum4linux_summary.txt"):
    """Save parsed enum4linux results summary"""
    try:
        with open(filename, 'w') as f:
            f.write("DCSeek - Enum4linux Enumeration Summary\n")
            f.write("="*70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total DCs Enumerated: {len(enum_results)}\n")
            f.write("="*70 + "\n\n")
            
            for result in enum_results:
                f.write(f"\nTarget: {result['ip']}\n")
                f.write("-"*70 + "\n")
                
                if result.get('domain'):
                    f.write(f"Domain: {result['domain']}\n")
                if result.get('os_info'):
                    f.write(f"OS Info: {result['os_info']}\n")
                
                f.write(f"\nUsers Found ({len(result['users'])}):\n")
                if result['users']:
                    for user in result['users']:
                        f.write(f"  - {user}\n")
                else:
                    f.write("  (none)\n")
                
                f.write(f"\nSMB Shares Found ({len(result['shares'])}):\n")
                if result['shares']:
                    for share in result['shares']:
                        f.write(f"  - {share}\n")
                else:
                    f.write("  (none)\n")
                
                if result.get('groups'):
                    f.write(f"\nGroups Found ({len(result['groups'])}):\n")
                    for group in result['groups']:
                        f.write(f"  - {group}\n")
                
                if result.get('password_policy'):
                    f.write("\nPassword Policy:\n")
                    for key, value in result['password_policy'].items():
                        f.write(f"  {key}: {value}\n")
                
                f.write("\n" + "="*70 + "\n")
        
        print(f"[+] Enum4linux summary saved to: {filename}")
        
        # Also save JSON for easy parsing
        json_file = filename.replace('.txt', '.json')
        try:
            with open(json_file, 'w') as f:
                json.dump(enum_results, f, indent=2)
            print(f"[+] JSON summary saved to: {json_file}")
        except Exception as e:
            print(f"[!] Error saving JSON summary: {e}")
        
        return True
    except Exception as e:
        print(f"[!] Error saving enum summary: {e}")
        return False


def download_seclists_names() -> tuple[str, str]:
    """
    Download names.txt and familynames-usa-top1000.txt from SecLists GitHub repo.
    
    Returns:
        Tuple of (first_names_file, last_names_file) paths
    """
    first_names_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt"
    last_names_url = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/familynames-usa-top1000.txt"
    
    first_names_file = "names.txt"
    last_names_file = "familynames-usa-top1000.txt"
    
    print("[*] Downloading SecLists name files...")
    
    try:
        # Download first names
        if not os.path.exists(first_names_file):
            print(f"[*] Downloading {first_names_file}...")
            response = requests.get(first_names_url, timeout=30)
            response.raise_for_status()
            with open(first_names_file, 'w') as f:
                f.write(response.text)
            print(f"[+] Downloaded {first_names_file}")
        else:
            print(f"[*] {first_names_file} already exists, skipping download")
        
        # Download last names
        if not os.path.exists(last_names_file):
            print(f"[*] Downloading {last_names_file}...")
            response = requests.get(last_names_url, timeout=30)
            response.raise_for_status()
            with open(last_names_file, 'w') as f:
                f.write(response.text)
            print(f"[+] Downloaded {last_names_file}")
        else:
            print(f"[*] {last_names_file} already exists, skipping download")
        
        return first_names_file, last_names_file
    
    except requests.RequestException as e:
        print(f"[!] Error downloading SecLists files: {e}")
        return None, None
    except Exception as e:
        print(f"[!] Unexpected error downloading files: {e}")
        return None, None


def load_names_from_file(filename: str) -> List[str]:
    """
    Load names from a file, one name per line.
    
    Args:
        filename: Path to the names file
        
    Returns:
        List of names
    """
    names = []
    try:
        with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                name = line.strip().lower()
                if name and not name.startswith('#'):
                    names.append(name)
        return names
    except Exception as e:
        print(f"[!] Error loading names from {filename}: {e}")
        return []


def generate_usernames(first_names: List[str], last_names: List[str], format_string: str, limit: int = 50000) -> List[str]:
    """
    Generate usernames based on format string.
    
    Args:
        first_names: List of first names
        last_names: List of last names
        format_string: Format like '{f}{last}', '{first}.{last}', etc.
        limit: Maximum number of usernames to generate
        
    Returns:
        List of generated usernames
    """
    usernames = set()
    count = 0
    
    print(f"[*] Generating usernames with format: {format_string}")
    
    for first, last in itertools.product(first_names, last_names):
        if count >= limit:
            break
            
        try:
            username = format_string.format(
                first=first.lower(),
                last=last.lower(),
                f=first[0].lower() if first else '',
                l=last[0].lower() if last else ''
            )
            
            # Only add valid usernames (no spaces, reasonable length)
            if username and ' ' not in username and 2 <= len(username) <= 20:
                usernames.add(username)
                count += 1
        except (IndexError, KeyError):
            continue
    
    return sorted(list(usernames))


def get_username_format() -> str:
    """
    Get username format from user via menu or manual input.
    
    Returns:
        Format string for username generation
    """
    print("\n" + "="*70)
    print("USERNAME FORMAT SELECTION")
    print("="*70)
    print("Common username formats:")
    print("  1. {f}{last}        - jsmith, bdoe, etc.")
    print("  2. {f}.{last}       - j.smith, b.doe, etc.")
    print("  3. {first}.{last}   - john.smith, bob.doe, etc.")
    print("  4. {first}{last}    - johnsmith, bobdoe, etc.")
    print("  5. {last}{f}        - smithj, doeb, etc.")
    print("  6. {first}_{last}   - john_smith, bob_doe, etc.")
    print("  7. {f}{l}{last}     - jssmith, bddoe, etc.")
    print("  8. Custom format    - Enter your own")
    
    formats = {
        '1': '{f}{last}',
        '2': '{f}.{last}',
        '3': '{first}.{last}',
        '4': '{first}{last}',
        '5': '{last}{f}',
        '6': '{first}_{last}',
        '7': '{f}{l}{last}'
    }
    
    while True:
        try:
            choice = input("\nSelect format (1-8): ").strip()
            
            if choice in formats:
                return formats[choice]
            elif choice == '8':
                print("\nCustom format options:")
                print("  {first} - Full first name")
                print("  {last}  - Full last name")
                print("  {f}     - First initial")
                print("  {l}     - Last initial")
                print("\nExample: {first}.{l}.{last} would generate john.s.smith")
                
                custom = input("Enter custom format: ").strip()
                if custom:
                    return custom
                else:
                    print("[!] Invalid format, please try again")
            else:
                print("[!] Invalid choice, please select 1-8")
        except KeyboardInterrupt:
            print("\n[!] Operation cancelled")
            return None


def save_usernames(usernames: List[str], domain: str, format_desc: str) -> str:
    """
    Save generated usernames to file.
    
    Args:
        usernames: List of usernames
        domain: Domain name for filename
        format_desc: Format description for filename
        
    Returns:
        Filename where usernames were saved
    """
    # Create safe filename
    safe_domain = re.sub(r'[^a-zA-Z0-9]', '_', domain.lower())
    safe_format = re.sub(r'[^a-zA-Z0-9]', '_', format_desc)
    filename = f"{safe_domain}_{safe_format}_usernames_{len(usernames)}.txt"
    
    try:
        with open(filename, 'w') as f:
            f.write(f"# Generated usernames for domain: {domain}\n")
            f.write(f"# Format: {format_desc}\n")
            f.write(f"# Total usernames: {len(usernames)}\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("\n")
            
            for username in usernames:
                f.write(f"{username}\n")
        
        print(f"[+] Saved {len(usernames)} usernames to: {filename}")
        return filename
    
    except Exception as e:
        print(f"[!] Error saving usernames: {e}")
        return None


def download_kerbrute() -> str:
    """
    Download appropriate Kerbrute binary for the current platform.
    
    Returns:
        Path to downloaded kerbrute binary, or None if failed
    """
    import platform
    
    print("[*] Kerbrute not found, attempting to download...")
    
    # Determine platform and architecture
    system = platform.system().lower()
    machine = platform.machine().lower()
    
    # Map to kerbrute release naming
    if system == "windows":
        if "64" in machine or "amd64" in machine:
            binary_name = "kerbrute_windows_amd64.exe"
            local_name = "kerbrute.exe"
        else:
            binary_name = "kerbrute_windows_386.exe"
            local_name = "kerbrute.exe"
    elif system == "linux":
        if "64" in machine or "amd64" in machine or "x86_64" in machine:
            binary_name = "kerbrute_linux_amd64"
            local_name = "kerbrute"
        elif "arm64" in machine or "aarch64" in machine:
            binary_name = "kerbrute_linux_arm64"
            local_name = "kerbrute"
        else:
            binary_name = "kerbrute_linux_386"
            local_name = "kerbrute"
    elif system == "darwin":  # macOS
        if "arm64" in machine:
            binary_name = "kerbrute_darwin_arm64"
            local_name = "kerbrute"
        else:
            binary_name = "kerbrute_darwin_amd64"
            local_name = "kerbrute"
    else:
        print(f"[!] Unsupported platform: {system}")
        return None
    
    # Download URL (using latest release)
    download_url = f"https://github.com/ropnop/kerbrute/releases/latest/download/{binary_name}"
    
    try:
        print(f"[*] Downloading {binary_name} from GitHub...")
        response = requests.get(download_url, timeout=60)
        response.raise_for_status()
        
        # Save to current directory
        with open(local_name, 'wb') as f:
            f.write(response.content)
        
        # Make executable on Unix systems
        if system != "windows":
            import stat
            os.chmod(local_name, os.stat(local_name).st_mode | stat.S_IEXEC)
        
        print(f"[+] Downloaded kerbrute to: {local_name}")
        return local_name
        
    except requests.RequestException as e:
        print(f"[!] Failed to download kerbrute: {e}")
        return None
    except Exception as e:
        print(f"[!] Error downloading kerbrute: {e}")
        return None


def run_kerbrute(dc_ip: str, domain: str, usernames_file: str) -> bool:
    """
    Run Kerbrute to enumerate valid usernames.
    
    Args:
        dc_ip: Domain Controller IP address
        domain: Domain name
        usernames_file: Path to usernames file
        
    Returns:
        True if successful, False otherwise
    """
    # Look for kerbrute binary
    kerbrute_paths = [
        './kerbrute',
        './kerbrute.exe',
        './kerbrute_linux_amd64',
        'kerbrute',
        '/usr/local/bin/kerbrute',
        '/opt/kerbrute/kerbrute'
    ]
    
    kerbrute_binary = None
    for path in kerbrute_paths:
        try:
            result = subprocess.run([path, '--help'], capture_output=True, timeout=5)
            if result.returncode == 0 or 'kerbrute' in result.stderr.decode().lower():
                kerbrute_binary = path
                break
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
    
    if not kerbrute_binary:
        # Try to download kerbrute automatically
        kerbrute_binary = download_kerbrute()
        if not kerbrute_binary:
            print("[!] Failed to download kerbrute automatically.")
            print("[!] Please manually install kerbrute:")
            print("    https://github.com/ropnop/kerbrute/releases")
            return False
    
    output_file = f"validusers_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    print(f"[*] Running Kerbrute against {dc_ip} for domain {domain}...")
    print(f"[*] Using usernames file: {usernames_file}")
    print(f"[*] Output will be saved to: {output_file}")
    
    try:
        cmd = [
            kerbrute_binary, 'userenum',
            '--dc', dc_ip,
            '-d', domain,
            usernames_file,
            '-o', output_file
        ]
        
        print(f"[*] Command: {' '.join(cmd)}")
        print("[*] This may take several minutes depending on the username list size...")
        print(f"[*] Kerbrute output will be displayed in real-time below:")
        print("-" * 70)
        
        # Run kerbrute with real-time output display
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Display output in real-time and capture valid users
        valid_users = []
        
        try:
            for line in iter(process.stdout.readline, ''):
                if line:
                    # Print the line for real-time viewing
                    print(line.rstrip())
                    
                    # Also capture valid usernames from stdout
                    if '[+] VALID USERNAME:' in line:
                        username_match = re.search(r'\[\+\] VALID USERNAME:\s*(\S+)', line)
                        if username_match:
                            username = username_match.group(1).split('@')[0]  # Remove @domain if present
                            if username not in valid_users:
                                valid_users.append(username)
            
            # Wait for process to complete
            return_code = process.wait(timeout=3600)
            
        except subprocess.TimeoutExpired:
            process.kill()
            print("\n[!] Kerbrute timed out after 1 hour")
            return False
        
        print("-" * 70)
        
        if return_code == 0:
            print(f"[+] Kerbrute completed successfully!")
            
            # Also try to parse the output file for any missed users
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        content = f.read()
                        for line in content.split('\n'):
                            if '[+] VALID USERNAME:' in line:
                                username_match = re.search(r'\[\+\] VALID USERNAME:\s*(\S+)', line)
                                if username_match:
                                    username = username_match.group(1).split('@')[0]
                                    if username not in valid_users:
                                        valid_users.append(username)
                except Exception as e:
                    print(f"[!] Error reading kerbrute output file: {e}")
            
            # Display summary of found users
            if valid_users:
                print(f"\n[+] SUMMARY: Found {len(valid_users)} valid usernames!")
                print("Valid users discovered:")
                for user in valid_users[:15]:  # Show first 15
                    print(f"  - {user}")
                if len(valid_users) > 15:
                    print(f"  ... and {len(valid_users) - 15} more (check {output_file} for full list)")
                
                # Save clean username list
                clean_users_file = f"validusers_clean_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                try:
                    with open(clean_users_file, 'w') as f:
                        f.write(f"# Valid usernames found for domain: {domain}\n")
                        f.write(f"# Total users: {len(valid_users)}\n")
                        f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                        for user in sorted(valid_users):
                            f.write(f"{user}\n")
                    print(f"[+] Clean username list saved to: {clean_users_file}")
                except Exception as e:
                    print(f"[!] Error saving clean username list: {e}")
                    
            else:
                print("\n[-] No valid usernames found")
            
            return True
        else:
            print(f"[!] Kerbrute failed with return code: {return_code}")
            return False
    
    except subprocess.TimeoutExpired:
        print("[!] Kerbrute timed out after 1 hour")
        return False
    except Exception as e:
        print(f"[!] Error running Kerbrute: {e}")
        return False


def username_enumeration_menu(domain_controllers: List[Dict]) -> bool:
    """
    Interactive menu for username enumeration.
    
    Args:
        domain_controllers: List of discovered DCs
        
    Returns:
        True if enumeration was performed, False otherwise
    """
    if not domain_controllers:
        print("[!] No domain controllers available for username enumeration")
        return False
    
    print("\n" + "="*70)
    print("USERNAME ENUMERATION WITH KERBRUTE")
    print("="*70)
    print("This will:")
    print("  1. Download SecLists name files (names.txt, familynames-usa-top1000.txt)")
    print("  2. Generate usernames based on your chosen format")
    print("  3. Use Kerbrute to test for valid usernames against the DC")
    print("\nAvailable Domain Controllers:")
    
    for i, dc in enumerate(domain_controllers, 1):
        print(f"  {i}. {dc['ip']} ({dc.get('hostname', 'Unknown hostname')})")
    
    # Get user confirmation
    try:
        choice = input("\nProceed with username enumeration? (y/N): ").strip().lower()
        if choice not in ['y', 'yes']:
            return False
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled")
        return False
    
    # Select DC
    if len(domain_controllers) > 1:
        try:
            dc_choice = input(f"\nSelect DC to target (1-{len(domain_controllers)}): ").strip()
            dc_index = int(dc_choice) - 1
            if not (0 <= dc_index < len(domain_controllers)):
                print("[!] Invalid DC selection")
                return False
        except (ValueError, KeyboardInterrupt):
            print("[!] Invalid selection")
            return False
    else:
        dc_index = 0
    
    selected_dc = domain_controllers[dc_index]
    
    # Get domain name
    domain = input("\nEnter domain name (e.g., corp.local, contoso.com): ").strip()
    if not domain:
        print("[!] Domain name is required")
        return False
    
    # Download SecLists files
    first_names_file, last_names_file = download_seclists_names()
    if not first_names_file or not last_names_file:
        return False
    
    # Load names
    print("[*] Loading names from files...")
    first_names = load_names_from_file(first_names_file)
    last_names = load_names_from_file(last_names_file)
    
    if not first_names or not last_names:
        print("[!] Failed to load names from files")
        return False
    
    print(f"[+] Loaded {len(first_names)} first names and {len(last_names)} last names")
    
    # Get username format
    format_string = get_username_format()
    if not format_string:
        return False
    
    # Ask about limit
    try:
        limit_input = input("\nUsername limit (default 40000, max 100000): ").strip()
        if limit_input:
            limit = min(int(limit_input), 100000)
        else:
            limit = 40000
    except ValueError:
        limit = 40000
    
    # Generate usernames
    usernames = generate_usernames(first_names, last_names, format_string, limit)
    
    if not usernames:
        print("[!] No usernames generated")
        return False
    
    print(f"[+] Generated {len(usernames)} unique usernames")
    
    # Save usernames
    format_desc = format_string.replace('{', '').replace('}', '')
    usernames_file = save_usernames(usernames, domain, format_desc)
    
    if not usernames_file:
        return False
    
    # Run Kerbrute
    print(f"\n[*] Starting Kerbrute enumeration against {selected_dc['ip']}...")
    success = run_kerbrute(selected_dc['ip'], domain, usernames_file)
    
    if success:
        print("\n[+] Username enumeration completed!")
        print(f"[*] Check the generated files:")
        print(f"    - {usernames_file} (generated usernames)")
        print(f"    - validusers_{domain}_*.txt (kerbrute results)")
    
    return success


def print_banner():
    """Print DCSeek banner"""
    banner = """
================================================================
                    DCSeek v1.3
     Advanced Domain Controller Discovery & Enumeration
   DC Discovery | SMB Relay Detection | Username Enumeration
        Enum4linux + Kerbrute + SecLists Integration
               github.com/Lokii-git/seeksweet
================================================================
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='DCSeek - Find Domain Controllers from IP list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default iplist.txt
  %(prog)s -f targets.txt               # Custom input file
  %(prog)s -w 20 -t 2 -v                # 20 workers, 2s timeout, verbose
  %(prog)s -f ips.txt -o results.txt    # Custom output file
  %(prog)s --enum                       # Run enum4linux on found DCs
  %(prog)s --enum --enum-only           # Only enumerate (skip DC discovery)
  %(prog)s --kerbrute --domain corp.local --username-format "{f}{last}"  # Auto Kerbrute
  %(prog)s --kerbrute --domain test.local --username-limit 20000         # Kerbrute with limit
        """
    )
    parser.add_argument('-f', '--file', default='iplist.txt', help='Input file with IPs (default: iplist.txt)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-o', '--output', default='domain_controllers.txt', help='Output file (default: domain_controllers.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all scanned hosts')
    parser.add_argument('--enum', action='store_true', help='Run enum4linux on discovered DCs')
    parser.add_argument('--enum-only', action='store_true', help='Only run enum4linux on IPs from dclist.txt (skip discovery)')
    parser.add_argument('--dclist', default='dclist.txt', help='DC list file (default: dclist.txt)')
    parser.add_argument('--enum-dir', default='enum4linux_results', help='Directory for enum4linux results (default: enum4linux_results)')
    parser.add_argument('--kerbrute', action='store_true', help='Automatically run username enumeration with Kerbrute after DC discovery')
    parser.add_argument('--domain', type=str, help='Domain name for Kerbrute enumeration (e.g., corp.local)')
    parser.add_argument('--username-format', type=str, help='Username format for generation (e.g., {f}{last}, {first}.{last})')
    parser.add_argument('--username-limit', type=int, default=40000, help='Maximum usernames to generate (default: 40000, max: 100000)')
    
    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit(1)
    
    # Validate arguments
    if args.timeout <= 0:
        print("[!] Error: Timeout must be greater than 0")
        sys.exit(1)
    
    if args.workers <= 0 or args.workers > 100:
        print("[!] Error: Workers must be between 1 and 100")
        sys.exit(1)
    
    print_banner()
    
    domain_controllers = []
    completed = 0
    errors = 0
    
    # Handle enum-only mode
    if args.enum_only:
        print(f"[*] Enum-only mode: Reading DCs from {args.dclist}")
        if not os.path.exists(args.dclist):
            print(f"[!] Error: {args.dclist} not found. Run discovery first without --enum-only")
            sys.exit(1)
        
        try:
            with open(args.dclist, 'r') as f:
                dc_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for ip in dc_ips:
                domain_controllers.append({'ip': ip, 'hostname': 'N/A', 'open_ports': {}})
            
            print(f"[*] Loaded {len(domain_controllers)} DCs from {args.dclist}")
        except Exception as e:
            print(f"[!] Error reading {args.dclist}: {e}")
            sys.exit(1)
    else:
        # Normal discovery mode
        print(f"[*] Reading IPs from: {args.file}")
        
        try:
            ips = read_ip_list(args.file)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            sys.exit(1)
        
        print(f"[*] Found {len(ips)} IP addresses to scan")
        print(f"[*] Starting scan with {args.workers} workers (timeout: {args.timeout}s)...\n")
        
        all_results = []
        errors = 0
        completed = 0
        
        try:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {executor.submit(scan_host, ip, args.timeout): ip for ip in ips}
                
                for future in as_completed(futures):
                    completed += 1
                    try:
                        result = future.result()
                        if not result or result is None:
                            errors += 1
                            if args.verbose:
                                print(f"[!] {futures[future]}: Scan returned no result")
                            continue
                        
                        all_results.append(result)
                        
                        if result.get('error'):
                            errors += 1
                            if args.verbose:
                                print(f"[!] {result['ip']}: {result['error']}")
                            continue
                        
                        if result['is_likely_dc']:
                            domain_controllers.append(result)
                            print(f"[+] DOMAIN CONTROLLER FOUND: {result['ip']}")
                            if result['hostname'] != "N/A":
                                print(f"    Hostname: {result['hostname']}")
                            print(f"    Open DC Ports: {', '.join([f'{p} ({s})' for p, s in result['open_ports'].items()])}")
                            if result['srv_records']:
                                print(f"    DNS SRV Records: {', '.join(result['srv_records'])}")
                            
                            # Show SMB signing status (CRITICAL for DCs)
                            if result.get('smb_signing'):
                                signing = result['smb_signing']
                                if signing.get('relay_vulnerable'):
                                    print(f"    ⚠⚠⚠ SMB SIGNING: DISABLED/NOT REQUIRED - RELAY VULNERABLE! ⚠⚠⚠")
                                elif signing.get('signing_required'):
                                    print(f"    ✓ SMB SIGNING: REQUIRED (Protected)")
                                elif signing.get('error'):
                                    print(f"    SMB Signing Check: Error - {signing['error']}")
                            
                            print()
                        elif args.verbose and result['open_ports']:
                            print(f"[-] {result['ip']}: Open ports {list(result['open_ports'].keys())} (not a DC)")
                        
                        if completed % 50 == 0:
                            print(f"[*] Progress: {completed}/{len(ips)} hosts scanned")
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        errors += 1
                        if args.verbose:
                            print(f"[!] Error scanning {futures[future]}: {e}")
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            print(f"[*] Scanned {completed}/{len(ips)} hosts before interruption")
    
    # Summary
    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
    if not args.enum_only:
        print(f"Total IPs scanned: {completed}")
    print(f"Domain Controllers found: {len(domain_controllers)}")
    if not args.enum_only and errors > 0:
        print(f"Errors encountered: {errors}")
    
    if domain_controllers:
        # Check for relay-vulnerable DCs (CRITICAL!)
        relay_vulnerable_dcs = []
        for dc in domain_controllers:
            if dc.get('smb_signing') and dc['smb_signing'].get('relay_vulnerable'):
                relay_vulnerable_dcs.append(dc)
        
        if relay_vulnerable_dcs:
            print(f"\n{'⚠'*35}")
            print(f"CRITICAL: {len(relay_vulnerable_dcs)} DOMAIN CONTROLLER(S) VULNERABLE TO SMB RELAY!")
            print(f"{'⚠'*35}")
            for dc in relay_vulnerable_dcs:
                print(f"  {dc['ip']:<15} | {dc['hostname']}")
        
        print("\nDOMAIN CONTROLLERS:")
        print("-"*70)
        for dc in domain_controllers:
            relay_str = " [RELAY VULNERABLE]" if dc in relay_vulnerable_dcs else ""
            print(f"  {dc['ip']:<15} | {dc['hostname']}{relay_str}")
    else:
        print("\n[!] No Domain Controllers detected")
    
    # Save DC list to dclist.txt
    if domain_controllers and not args.enum_only:
        save_dclist(domain_controllers, args.dclist)
        # Save SMB signing status report
        save_dc_smb_status(domain_controllers)
    
    # Save detailed results
    if domain_controllers and not args.enum_only:
        try:
            with open(args.output, 'w') as f:
                f.write("DCSeek - Domain Controllers Found\n")
                f.write("="*70 + "\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if completed > 0:
                    f.write(f"Total IPs Scanned: {completed}\n")
                f.write(f"Domain Controllers Found: {len(domain_controllers)}\n")
                f.write("="*70 + "\n\n")
                
                for dc in domain_controllers:
                    f.write(f"IP: {dc['ip']}\n")
                    f.write(f"Hostname: {dc.get('hostname', 'N/A')}\n")
                    if dc.get('open_ports'):
                        f.write(f"Open Ports: {', '.join([f'{p} ({s})' for p, s in dc['open_ports'].items()])}\n")
                    if dc.get('srv_records'):
                        f.write(f"DNS SRV Records: {', '.join(dc['srv_records'])}\n")
                    
                    # SMB Signing status (CRITICAL for DCs)
                    if dc.get('smb_signing'):
                        signing = dc['smb_signing']
                        if signing.get('relay_vulnerable'):
                            f.write("⚠⚠⚠ SMB SIGNING: DISABLED/NOT REQUIRED - RELAY VULNERABLE ⚠⚠⚠\n")
                        elif signing.get('signing_required'):
                            f.write("✓ SMB SIGNING: REQUIRED (Protected)\n")
                        elif signing.get('error'):
                            f.write(f"SMB Signing Check Error: {signing['error']}\n")
                    f.write("\n" + "-"*70 + "\n\n")
            print(f"\n[*] Results saved to: {args.output}")
        except PermissionError:
            print(f"\n[!] Error: Permission denied writing to {args.output}")
        except Exception as e:
            print(f"\n[!] Error saving results: {e}")
    
    # Run enum4linux if requested
    if args.enum or args.enum_only:
        if not domain_controllers:
            print("\n[!] No Domain Controllers to enumerate")
            sys.exit(0)
        
        print("\n" + "="*70)
        print("ENUM4LINUX ENUMERATION")
        print("="*70)
        print(f"[*] Starting enum4linux on {len(domain_controllers)} Domain Controllers...")
        print(f"[*] Results will be saved to: {args.enum_dir}/\n")
        
        enum_results = []
        
        for i, dc in enumerate(domain_controllers, 1):
            print(f"\n[{i}/{len(domain_controllers)}] Enumerating {dc['ip']}...")
            
            try:
                parsed = run_enum4linux(dc['ip'], args.enum_dir)
                
                if parsed:
                    enum_results.append(parsed)
                    
                    # Print summary
                    print(f"[+] Enumeration complete for {dc['ip']}")
                    if parsed.get('domain'):
                        print(f"    Domain: {parsed['domain']}")
                    print(f"    Users found: {len(parsed['users'])}")
                    print(f"    Shares found: {len(parsed['shares'])}")
                    
                    if parsed['users']:
                        print(f"    Sample users: {', '.join(parsed['users'][:5])}")
                    if parsed['shares']:
                        print(f"    Shares: {', '.join(parsed['shares'])}")
                else:
                    print(f"[-] No results from enum4linux for {dc['ip']}")
            
            except KeyboardInterrupt:
                print("\n[!] Enum4linux enumeration interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error enumerating {dc['ip']}: {e}")
        
            # Save enum summary
        if enum_results:
            print("\n" + "="*70)
            print("ENUMERATION SUMMARY")
            print("="*70)
            
            total_users = sum(len(r['users']) for r in enum_results)
            total_shares = sum(len(r['shares']) for r in enum_results)
            
            print(f"DCs enumerated: {len(enum_results)}")
            print(f"Total unique users found: {total_users}")
            print(f"Total shares found: {total_shares}")
            
            save_enum_summary(enum_results, "enum4linux_summary.txt")
    
    # Username enumeration with Kerbrute
    if domain_controllers and not args.enum_only:
        if args.kerbrute:
            # Automated Kerbrute mode
            if not args.domain:
                print("\n[!] --domain parameter required for automated Kerbrute mode")
                sys.exit(1)
            
            print("\n" + "="*70)
            print("AUTOMATED KERBRUTE ENUMERATION")
            print("="*70)
            
            # Use first DC
            selected_dc = domain_controllers[0]
            
            # Download SecLists files
            first_names_file, last_names_file = download_seclists_names()
            if not first_names_file or not last_names_file:
                print("[!] Failed to download SecLists files")
                sys.exit(1)
            
            # Load names
            print("[*] Loading names from files...")
            first_names = load_names_from_file(first_names_file)
            last_names = load_names_from_file(last_names_file)
            
            if not first_names or not last_names:
                print("[!] Failed to load names from files")
                sys.exit(1)
            
            print(f"[+] Loaded {len(first_names)} first names and {len(last_names)} last names")
            
            # Use provided format or default
            format_string = args.username_format or '{f}{last}'
            limit = min(args.username_limit, 100000)
            
            print(f"[*] Using username format: {format_string}")
            print(f"[*] Username limit: {limit}")
            
            # Generate usernames
            usernames = generate_usernames(first_names, last_names, format_string, limit)
            
            if not usernames:
                print("[!] No usernames generated")
                sys.exit(1)
            
            print(f"[+] Generated {len(usernames)} unique usernames")
            
            # Save usernames
            format_desc = format_string.replace('{', '').replace('}', '')
            usernames_file = save_usernames(usernames, args.domain, format_desc)
            
            if usernames_file:
                # Run Kerbrute
                print(f"\n[*] Starting Kerbrute enumeration against {selected_dc['ip']}...")
                success = run_kerbrute(selected_dc['ip'], args.domain, usernames_file)
                
                if success:
                    print("\n[+] Automated username enumeration completed!")
                else:
                    print("\n[!] Kerbrute enumeration failed")
        else:
            # Interactive menu mode
            try:
                print(f"\n{'='*70}")
                print("NEXT STEP: USERNAME ENUMERATION")
                print(f"{'='*70}")
                print("DCSeek can now enumerate valid usernames using Kerbrute:")
                print("  • Downloads SecLists name files automatically")
                print("  • Generates usernames with customizable formats") 
                print("  • Tests usernames against discovered Domain Controllers")
                print("  • Shows real-time results with valid usernames found")
                print(f"{'='*70}")
                
                choice = input("\n[*] Would you like to perform username enumeration with Kerbrute? (y/N): ").strip().lower()
                if choice in ['y', 'yes']:
                    username_enumeration_menu(domain_controllers)
            except KeyboardInterrupt:
                print("\n[!] Operation cancelled")
    
    sys.exit(0)


if __name__ == "__main__":
    main()
