#!/usr/bin/env python3
"""
LDAPSeek v1.0 - Active Directory LDAP Enumeration Tool
Deep reconnaissance of Active Directory environments

Features:
- User enumeration (all users, admin users, service accounts)
- Group enumeration (Domain Admins, Enterprise Admins, etc.)
- Computer enumeration (workstations, servers, DCs)
- SPN discovery (Kerberoasting targets)
- ASREPRoast candidate detection (users without pre-auth)
- Delegation enumeration (unconstrained, constrained)
- Password policy extraction
- Trust enumeration
- Anonymous LDAP bind testing

Usage:
    ./ldapseek.py                          # Quick scan (enumerate users/groups)
    ./ldapseek.py --full                   # Full enumeration (SPNs, delegation, etc.)
    ./ldapseek.py --spns                   # Kerberoasting targets only
    ./ldapseek.py --asrep                  # ASREPRoast targets only
    ./ldapseek.py -u user -p pass          # Authenticated scan
    
Output:
    ldaplist.txt        - Domain controllers found
    users.txt           - All usernames
    spns.txt            - SPN accounts (Kerberoasting targets)
    asrep_users.txt     - ASREPRoast candidates
    admin_users.txt     - Admin accounts
    ldap_details.txt    - Detailed findings
    ldap_details.json   - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import argparse
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list

# Color codes for terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

# LDAP ports
LDAP_PORTS = {
    389: 'LDAP',
    636: 'LDAPS',
    3268: 'Global Catalog',
    3269: 'Global Catalog SSL'
}

# Privileged groups to check
PRIVILEGED_GROUPS = [
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Administrators',
    'Account Operators',
    'Backup Operators',
    'Server Operators',
    'Print Operators',
    'DNSAdmins',
    'Group Policy Creator Owners',
    'Remote Desktop Users',
    'Distributed COM Users'
]

# User Account Control flags
UAC_FLAGS = {
    0x0001: 'SCRIPT',
    0x0002: 'ACCOUNTDISABLE',
    0x0008: 'HOMEDIR_REQUIRED',
    0x0010: 'LOCKOUT',
    0x0020: 'PASSWD_NOTREQD',
    0x0040: 'PASSWD_CANT_CHANGE',
    0x0080: 'ENCRYPTED_TEXT_PWD_ALLOWED',
    0x0100: 'TEMP_DUPLICATE_ACCOUNT',
    0x0200: 'NORMAL_ACCOUNT',
    0x0800: 'INTERDOMAIN_TRUST_ACCOUNT',
    0x1000: 'WORKSTATION_TRUST_ACCOUNT',
    0x2000: 'SERVER_TRUST_ACCOUNT',
    0x10000: 'DONT_EXPIRE_PASSWORD',
    0x20000: 'MNS_LOGON_ACCOUNT',
    0x40000: 'SMARTCARD_REQUIRED',
    0x80000: 'TRUSTED_FOR_DELEGATION',
    0x100000: 'NOT_DELEGATED',
    0x200000: 'USE_DES_KEY_ONLY',
    0x400000: 'DONT_REQ_PREAUTH',
    0x800000: 'PASSWORD_EXPIRED',
    0x1000000: 'TRUSTED_TO_AUTH_FOR_DELEGATION'
}

# Banner
BANNER = f"""{CYAN}{BOLD}
██╗     ██████╗  █████╗ ██████╗ ███████╗███████╗███████╗██╗  ██╗
██║     ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
██║     ██║  ██║███████║██████╔╝███████╗█████╗  █████╗  █████╔╝ 
██║     ██║  ██║██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
███████╗██████╔╝██║  ██║██║  ██║███████║███████╗███████╗██║  ██╗
╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}LDAPSeek v1.0 - Active Directory LDAP Enumeration{RESET}
{BLUE}Deep reconnaissance of AD environments{RESET}
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_ip_list(file_path):
    """Read IP addresses from a file"""
    # Use shared utility to find the file
    file_path = find_ip_list(file_path)
    
    ips = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ip = line.split()[0]
                    ips.append(ip)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return ips


def check_ldap_port(ip, port=389, timeout=3):
    """Check if LDAP port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def get_domain_info_ldapsearch(dc_ip, username=None, password=None, timeout=10):
    """
    Get domain information using ldapsearch
    Returns: dict with domain info
    """
    info = {
        'domain': None,
        'naming_context': None,
        'ldap_version': None
    }
    
    try:
        # Build ldapsearch command
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}', 
                   '-D', username, '-w', password,
                   '-b', '', '-s', 'base', 'namingContexts']
        else:
            # Anonymous bind
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', '', '-s', 'base', 'namingContexts']
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'defaultNamingContext:' in line:
                    info['naming_context'] = line.split(':', 1)[1].strip()
                    # Extract domain from DN (DC=domain,DC=com)
                    dc_parts = [part.split('=')[1] for part in info['naming_context'].split(',') if part.startswith('DC=')]
                    info['domain'] = '.'.join(dc_parts)
    except Exception:
        pass
    
    return info


def enumerate_users_ldapsearch(dc_ip, base_dn, username=None, password=None, timeout=30):
    """
    Enumerate users using ldapsearch
    Returns: list of user objects
    """
    users = []
    
    try:
        # Build ldapsearch command for users
        ldap_filter = '(&(objectClass=user)(objectCategory=person))'
        attrs = ['sAMAccountName', 'userPrincipalName', 'displayName', 
                'userAccountControl', 'servicePrincipalName', 'memberOf',
                'adminCount', 'lastLogon', 'pwdLastSet', 'description']
        
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-D', username, '-w', password,
                   '-b', base_dn, ldap_filter] + attrs
        else:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', base_dn, ldap_filter] + attrs
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            current_user = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('dn:'):
                    if current_user:
                        users.append(current_user)
                    current_user = {'dn': line.split(':', 1)[1].strip()}
                
                elif ': ' in line and current_user:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    
                    if key == 'sAMAccountName':
                        current_user['username'] = value
                    elif key == 'userPrincipalName':
                        current_user['upn'] = value
                    elif key == 'displayName':
                        current_user['display_name'] = value
                    elif key == 'userAccountControl':
                        current_user['uac'] = int(value)
                    elif key == 'servicePrincipalName':
                        if 'spns' not in current_user:
                            current_user['spns'] = []
                        current_user['spns'].append(value)
                    elif key == 'memberOf':
                        if 'groups' not in current_user:
                            current_user['groups'] = []
                        current_user['groups'].append(value)
                    elif key == 'adminCount':
                        current_user['admin_count'] = int(value)
                    elif key == 'description':
                        current_user['description'] = value
            
            if current_user:
                users.append(current_user)
    
    except Exception as e:
        pass
    
    return users


def enumerate_groups_ldapsearch(dc_ip, base_dn, username=None, password=None, timeout=30):
    """
    Enumerate groups using ldapsearch
    Returns: list of group objects
    """
    groups = []
    
    try:
        ldap_filter = '(objectClass=group)'
        attrs = ['sAMAccountName', 'distinguishedName', 'member', 'description', 'adminCount']
        
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-D', username, '-w', password,
                   '-b', base_dn, ldap_filter] + attrs
        else:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', base_dn, ldap_filter] + attrs
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            current_group = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('dn:'):
                    if current_group:
                        groups.append(current_group)
                    current_group = {'dn': line.split(':', 1)[1].strip()}
                
                elif ': ' in line and current_group:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    
                    if key == 'sAMAccountName':
                        current_group['name'] = value
                    elif key == 'member':
                        if 'members' not in current_group:
                            current_group['members'] = []
                        current_group['members'].append(value)
                    elif key == 'description':
                        current_group['description'] = value
                    elif key == 'adminCount':
                        current_group['admin_count'] = int(value)
            
            if current_group:
                groups.append(current_group)
    
    except Exception:
        pass
    
    return groups


def enumerate_computers_ldapsearch(dc_ip, base_dn, username=None, password=None, timeout=30):
    """
    Enumerate computers using ldapsearch
    Returns: list of computer objects
    """
    computers = []
    
    try:
        ldap_filter = '(objectClass=computer)'
        attrs = ['sAMAccountName', 'dNSHostName', 'operatingSystem', 
                'userAccountControl', 'servicePrincipalName']
        
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-D', username, '-w', password,
                   '-b', base_dn, ldap_filter] + attrs
        else:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', base_dn, ldap_filter] + attrs
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if result.returncode == 0:
            current_computer = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('dn:'):
                    if current_computer:
                        computers.append(current_computer)
                    current_computer = {'dn': line.split(':', 1)[1].strip()}
                
                elif ': ' in line and current_computer:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    
                    if key == 'sAMAccountName':
                        current_computer['name'] = value.rstrip('$')
                    elif key == 'dNSHostName':
                        current_computer['hostname'] = value
                    elif key == 'operatingSystem':
                        current_computer['os'] = value
                    elif key == 'userAccountControl':
                        current_computer['uac'] = int(value)
            
            if current_computer:
                computers.append(current_computer)
    
    except Exception:
        pass
    
    return computers


def parse_uac_flags(uac_value):
    """Parse User Account Control flags"""
    flags = []
    for flag_value, flag_name in UAC_FLAGS.items():
        if uac_value & flag_value:
            flags.append(flag_name)
    return flags


def identify_asrep_users(users):
    """Identify users vulnerable to ASREPRoasting"""
    asrep_users = []
    for user in users:
        if 'uac' in user:
            flags = parse_uac_flags(user['uac'])
            # DONT_REQ_PREAUTH = no Kerberos pre-authentication
            if 'DONT_REQ_PREAUTH' in flags:
                asrep_users.append(user)
    return asrep_users


def identify_kerberoastable_users(users):
    """Identify users with SPNs (Kerberoastable)"""
    kerberoastable = []
    for user in users:
        if 'spns' in user and user['spns']:
            kerberoastable.append(user)
    return kerberoastable


def identify_delegation_accounts(users, computers):
    """Identify accounts with delegation configured"""
    delegation_accounts = []
    
    # Check users
    for user in users:
        if 'uac' in user:
            flags = parse_uac_flags(user['uac'])
            if 'TRUSTED_FOR_DELEGATION' in flags:
                delegation_accounts.append({
                    'type': 'user',
                    'name': user.get('username', 'Unknown'),
                    'delegation_type': 'unconstrained'
                })
            elif 'TRUSTED_TO_AUTH_FOR_DELEGATION' in flags:
                delegation_accounts.append({
                    'type': 'user',
                    'name': user.get('username', 'Unknown'),
                    'delegation_type': 'constrained'
                })
    
    # Check computers
    for computer in computers:
        if 'uac' in computer:
            flags = parse_uac_flags(computer['uac'])
            if 'TRUSTED_FOR_DELEGATION' in flags:
                delegation_accounts.append({
                    'type': 'computer',
                    'name': computer.get('name', 'Unknown'),
                    'delegation_type': 'unconstrained'
                })
    
    return delegation_accounts


def identify_admin_users(users, groups):
    """Identify administrative users"""
    admin_users = []
    
    # Users with adminCount=1
    for user in users:
        if user.get('admin_count') == 1:
            admin_users.append({
                'username': user.get('username', 'Unknown'),
                'reason': 'adminCount=1',
                'groups': user.get('groups', [])
            })
            continue
        
        # Users in privileged groups
        if 'groups' in user:
            for group_dn in user['groups']:
                group_cn = group_dn.split(',')[0].replace('CN=', '')
                if group_cn in PRIVILEGED_GROUPS:
                    admin_users.append({
                        'username': user.get('username', 'Unknown'),
                        'reason': f'Member of {group_cn}',
                        'groups': user.get('groups', [])
                    })
                    break
    
    return admin_users


def scan_domain_controller(dc_ip, args):
    """
    Scan a single domain controller
    Returns: dict with findings
    """
    result = {
        'dc_ip': dc_ip,
        'domain': None,
        'ldap_accessible': False,
        'anonymous_bind': False,
        'users': [],
        'groups': [],
        'computers': [],
        'spn_users': [],
        'asrep_users': [],
        'delegation_accounts': [],
        'admin_users': [],
        'status': 'unreachable'
    }
    
    try:
        # Check LDAP port
        if not check_ldap_port(dc_ip, timeout=args.timeout):
            return result
        
        result['ldap_accessible'] = True
        result['status'] = 'accessible'
        
        # Get domain info
        domain_info = get_domain_info_ldapsearch(dc_ip, args.username, args.password, timeout=args.timeout)
        
        if domain_info['domain']:
            result['domain'] = domain_info['domain']
            result['naming_context'] = domain_info['naming_context']
            
            if not args.username:
                result['anonymous_bind'] = True
            
            # Enumerate users
            if args.full or args.spns or args.asrep or not (args.spns or args.asrep):
                users = enumerate_users_ldapsearch(dc_ip, domain_info['naming_context'], 
                                                   args.username, args.password, timeout=args.timeout*2)
                result['users'] = users
                
                # Identify Kerberoastable users
                result['spn_users'] = identify_kerberoastable_users(users)
                
                # Identify ASREPRoastable users
                result['asrep_users'] = identify_asrep_users(users)
                
                # Identify admin users
                result['admin_users'] = identify_admin_users(users, [])
            
            # Enumerate groups
            if args.full:
                groups = enumerate_groups_ldapsearch(dc_ip, domain_info['naming_context'],
                                                    args.username, args.password, timeout=args.timeout*2)
                result['groups'] = groups
                
                # Re-identify admin users with group info
                result['admin_users'] = identify_admin_users(result['users'], groups)
            
            # Enumerate computers
            if args.full:
                computers = enumerate_computers_ldapsearch(dc_ip, domain_info['naming_context'],
                                                          args.username, args.password, timeout=args.timeout*2)
                result['computers'] = computers
                
                # Identify delegation accounts
                result['delegation_accounts'] = identify_delegation_accounts(result['users'], computers)
            
            result['status'] = 'enumerated'
    
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_ldaplist(results, filename='ldaplist.txt'):
    """Save list of domain controllers"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['ldap_accessible']:
                    f.write(f"{result['dc_ip']}\n")
        print(f"{GREEN}[+] DC list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving DC list: {e}{RESET}")


def save_usernames(results, filename='users.txt'):
    """Save list of usernames"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                for user in result['users']:
                    if 'username' in user:
                        f.write(f"{user['username']}\n")
        print(f"{GREEN}[+] Username list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving usernames: {e}{RESET}")


def save_spn_users(results, filename='spns.txt'):
    """Save list of SPN users (Kerberoasting targets)"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LDAPSEEK - Kerberoastable Accounts (SPNs)\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['spn_users']:
                    f.write(f"\nDomain: {result.get('domain', 'Unknown')}\n")
                    f.write(f"DC: {result['dc_ip']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    for user in result['spn_users']:
                        f.write(f"Username: {user.get('username', 'Unknown')}\n")
                        if 'upn' in user:
                            f.write(f"UPN: {user['upn']}\n")
                        f.write(f"SPNs:\n")
                        for spn in user.get('spns', []):
                            f.write(f"  • {spn}\n")
                        f.write("\n")
        
        print(f"{GREEN}[+] SPN users saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving SPN users: {e}{RESET}")


def save_asrep_users(results, filename='asrep_users.txt'):
    """Save list of ASREPRoast candidates"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LDAPSEEK - ASREPRoastable Accounts\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            f.write("These accounts do not require Kerberos pre-authentication.\n")
            f.write("Use GetNPUsers.py or Rubeus to request AS-REP hashes.\n\n")
            
            for result in results:
                if result['asrep_users']:
                    f.write(f"\nDomain: {result.get('domain', 'Unknown')}\n")
                    f.write(f"DC: {result['dc_ip']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    for user in result['asrep_users']:
                        f.write(f"• {user.get('username', 'Unknown')}\n")
        
        print(f"{GREEN}[+] ASREPRoast candidates saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving ASREPRoast users: {e}{RESET}")


def save_admin_users(results, filename='admin_users.txt'):
    """Save list of administrative users"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LDAPSEEK - Administrative Accounts\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['admin_users']:
                    f.write(f"\nDomain: {result.get('domain', 'Unknown')}\n")
                    f.write(f"DC: {result['dc_ip']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    for admin in result['admin_users']:
                        f.write(f"Username: {admin['username']}\n")
                        f.write(f"Reason: {admin['reason']}\n\n")
        
        print(f"{GREEN}[+] Admin users saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving admin users: {e}{RESET}")


def save_details(results, filename='ldap_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("LDAPSEEK - Detailed LDAP Enumeration Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['status'] in ['accessible', 'enumerated']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Domain Controller: {result['dc_ip']}\n")
                    if result.get('domain'):
                        f.write(f"Domain: {result['domain']}\n")
                    f.write(f"Anonymous Bind: {'Yes' if result['anonymous_bind'] else 'No'}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    if result['users']:
                        f.write(f"Users Found: {len(result['users'])}\n")
                    
                    if result['spn_users']:
                        f.write(f"\n🎯 Kerberoastable Accounts: {len(result['spn_users'])}\n")
                        for user in result['spn_users'][:10]:  # Limit output
                            f.write(f"  • {user.get('username', 'Unknown')}\n")
                    
                    if result['asrep_users']:
                        f.write(f"\n🎯 ASREPRoastable Accounts: {len(result['asrep_users'])}\n")
                        for user in result['asrep_users']:
                            f.write(f"  • {user.get('username', 'Unknown')}\n")
                    
                    if result['delegation_accounts']:
                        f.write(f"\n⚠ Delegation Accounts: {len(result['delegation_accounts'])}\n")
                        for account in result['delegation_accounts']:
                            f.write(f"  • {account['name']} ({account['type']}) - {account['delegation_type']}\n")
                    
                    if result['admin_users']:
                        f.write(f"\n👑 Administrative Users: {len(result['admin_users'])}\n")
                        for admin in result['admin_users'][:10]:
                            f.write(f"  • {admin['username']} - {admin['reason']}\n")
                    
                    f.write("\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='ldap_details.json'):
    """Save results as JSON"""
    try:
        # Remove non-serializable data
        clean_results = []
        for result in results:
            clean_result = {k: v for k, v in result.items() if k != 'error'}
            clean_results.append(clean_result)
        
        with open(filename, 'w') as f:
            json.dump(clean_results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='LDAPSeek - Active Directory LDAP Enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./ldapseek.py dclist.txt                        # Quick enumeration (anonymous)
  ./ldapseek.py dclist.txt --full                 # Full enumeration
  ./ldapseek.py dclist.txt --spns                 # Kerberoasting targets only
  ./ldapseek.py dclist.txt --asrep                # ASREPRoast targets only
  ./ldapseek.py dclist.txt -u user@domain -p pass # Authenticated scan
        """
    )
    
    parser.add_argument('input_file', help='File containing DC IP addresses')
    parser.add_argument('--full', action='store_true', help='Full enumeration (groups, computers, delegation)')
    parser.add_argument('--spns', action='store_true', help='Only enumerate SPN users (Kerberoasting)')
    parser.add_argument('--asrep', action='store_true', help='Only enumerate ASREPRoast candidates')
    parser.add_argument('-u', '--username', help='Username for authenticated LDAP bind (user@domain or DOMAIN\\user)')
    parser.add_argument('-p', '--password', help='Password for authenticated LDAP bind')
    parser.add_argument('-t', '--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read DC IPs
    dc_ips = read_ip_list(args.input_file)
    
    if not dc_ips:
        print(f"{RED}[!] No DCs to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting LDAP enumeration...{RESET}")
    print(f"{CYAN}[*] Domain Controllers: {len(dc_ips)}{RESET}")
    print(f"{CYAN}[*] Authentication: {'Yes' if args.username else 'Anonymous'}{RESET}")
    print(f"{CYAN}[*] Mode: {'Full' if args.full else 'SPNs only' if args.spns else 'ASREPRoast only' if args.asrep else 'Quick'}{RESET}")
    print()
    
    results = []
    
    try:
        for dc_ip in dc_ips:
            try:
                print(f"{BLUE}[*]{RESET} Enumerating {dc_ip}...")
                result = scan_domain_controller(dc_ip, args)
                results.append(result)
                
                if result['status'] == 'enumerated':
                    print(f"{GREEN}[+]{RESET} {dc_ip} - Domain: {result.get('domain', 'Unknown')}")
                    
                    if result['anonymous_bind']:
                        print(f"  {YELLOW}⚠{RESET}  Anonymous LDAP bind allowed!")
                    
                    if result['users']:
                        print(f"  └─ Users: {len(result['users'])}")
                    
                    if result['spn_users']:
                        print(f"  └─ {RED}Kerberoastable:{RESET} {len(result['spn_users'])}")
                    
                    if result['asrep_users']:
                        print(f"  └─ {RED}ASREPRoastable:{RESET} {len(result['asrep_users'])}")
                    
                    if result['delegation_accounts']:
                        print(f"  └─ {YELLOW}Delegation accounts:{RESET} {len(result['delegation_accounts'])}")
                    
                    if result['admin_users']:
                        print(f"  └─ Admin users: {len(result['admin_users'])}")
                
                elif result['status'] == 'accessible':
                    print(f"{YELLOW}[~]{RESET} {dc_ip} - LDAP accessible but enumeration failed")
                else:
                    if args.verbose:
                        print(f"{RED}[!]{RESET} {dc_ip} - Unreachable")
                
            except KeyboardInterrupt:
                print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
                break
            except Exception as e:
                if args.verbose:
                    print(f"{RED}[!]{RESET} {dc_ip} - Error: {e}")
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
    
    # Print summary
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    print(f"{CYAN}Enumeration Complete{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}")
    
    accessible_dcs = len([r for r in results if r['ldap_accessible']])
    total_users = sum(len(r['users']) for r in results)
    total_spns = sum(len(r['spn_users']) for r in results)
    total_asrep = sum(len(r['asrep_users']) for r in results)
    total_admins = sum(len(r['admin_users']) for r in results)
    
    print(f"Accessible DCs: {accessible_dcs}/{len(dc_ips)}")
    print(f"Total users: {total_users}")
    print(f"Kerberoastable accounts: {total_spns}")
    print(f"ASREPRoastable accounts: {total_asrep}")
    print(f"Admin accounts: {total_admins}")
    
    # Save results
    if results:
        save_ldaplist(results)
        if total_users > 0:
            save_usernames(results)
        if total_spns > 0:
            save_spn_users(results)
        if total_asrep > 0:
            save_asrep_users(results)
        if total_admins > 0:
            save_admin_users(results)
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Enumeration complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
