#!/usr/bin/env python3
"""
SMBSeek v1.0 - SMB Share Discovery and Enumeration Tool

Discovers hosts with SMB enabled and enumerates accessible shares.
Tests for anonymous access, null sessions, and guest access.

Author: Internal Red Team
Date: October 2025
Platform: Kali Linux
"""

import subprocess
import socket
import ipaddress
import argparse
import json
import os

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list
import re
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
║                   SMBSeek v1.0                            ║
║            SMB Share Discovery & Enumeration              ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}
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

def check_smbclient() -> bool:
    """
    Check if smbclient is installed.
    
    Returns:
        True if smbclient is available, False otherwise
    """
    try:
        subprocess.run(['smbclient', '--version'], 
                      capture_output=True, 
                      timeout=5)
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def enumerate_shares_smbclient(ip: str, username: str = '', password: str = '', 
                               timeout: int = 10) -> Tuple[Optional[List[Dict]], Optional[str]]:
    """
    Enumerate SMB shares using smbclient.
    
    Args:
        ip: Target IP address
        username: Username for authentication (empty for null session)
        password: Password for authentication (empty for null session)
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (list of share dicts, error message)
    """
    shares = []
    
    # Build smbclient command
    if username:
        cmd = ['smbclient', '-L', f'//{ip}', '-U', f'{username}%{password}', '-N']
    else:
        # Try null session (no username/password)
        cmd = ['smbclient', '-L', f'//{ip}', '-N']
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        # Check for common errors
        if 'NT_STATUS_ACCESS_DENIED' in output:
            return None, 'Access Denied'
        elif 'NT_STATUS_LOGON_FAILURE' in output:
            return None, 'Logon Failure'
        elif 'NT_STATUS_HOST_UNREACHABLE' in output:
            return None, 'Host Unreachable'
        elif 'Connection to' in output and 'failed' in output:
            return None, 'Connection Failed'
        
        # Parse share list
        in_share_section = False
        for line in output.split('\n'):
            line = line.strip()
            
            # Look for share section
            if 'Sharename' in line and 'Type' in line:
                in_share_section = True
                continue
            
            # End of share section
            if in_share_section and (line.startswith('Reconnecting') or 
                                     line.startswith('Server') or 
                                     line.startswith('Workgroup') or
                                     not line):
                if line.startswith('Server') or line.startswith('Workgroup'):
                    in_share_section = False
                continue
            
            # Parse share line
            if in_share_section and line and not line.startswith('-'):
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    share_type = parts[1]
                    comment = ' '.join(parts[2:]) if len(parts) > 2 else ''
                    
                    shares.append({
                        'name': share_name,
                        'type': share_type,
                        'comment': comment
                    })
        
        if shares:
            return shares, None
        else:
            return None, 'No shares found or access denied'
            
    except subprocess.TimeoutExpired:
        return None, 'Timeout'
    except Exception as e:
        return None, str(e)

def test_share_access(ip: str, share_name: str, username: str = '', 
                     password: str = '', timeout: int = 10) -> Dict:
    """
    Test if a share is accessible and attempt to list contents.
    
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
    
    # Build smbclient command to list share contents
    if username:
        cmd = ['smbclient', f'//{ip}/{share_name}', '-U', f'{username}%{password}', 
               '-c', 'ls']
    else:
        cmd = ['smbclient', f'//{ip}/{share_name}', '-N', '-c', 'ls']
    
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout + proc.stderr
        
        # Check for access
        if 'NT_STATUS_ACCESS_DENIED' in output:
            result['error'] = 'Access Denied'
        elif 'NT_STATUS_BAD_NETWORK_NAME' in output:
            result['error'] = 'Invalid Share Name'
        elif 'NT_STATUS_LOGON_FAILURE' in output:
            result['error'] = 'Logon Failure'
        elif proc.returncode == 0 or 'blocks of size' in output:
            result['accessible'] = True
            result['readable'] = True
            
            # Count files/directories
            file_count = 0
            for line in output.split('\n'):
                # Look for file listings (lines with file attributes)
                if re.match(r'\s+\S+\s+[DAH]+\s+\d+', line):
                    file_count += 1
            
            result['files_found'] = file_count
        else:
            result['error'] = 'Unknown error'
    
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def enumerate_shares_rpcclient(ip: str, username: str = '', password: str = '', 
                                timeout: int = 10) -> Tuple[Optional[List[Dict]], Optional[str]]:
    """
    Enumerate SMB shares using rpcclient (alternative method).
    
    Args:
        ip: Target IP address
        username: Username for authentication
        password: Password for authentication
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (list of share dicts, error message)
    """
    shares = []
    
    # Build rpcclient command
    if username:
        cmd = ['rpcclient', '-U', f'{username}%{password}', ip, '-c', 'netshareenum']
    else:
        cmd = ['rpcclient', '-U', '%', ip, '-c', 'netshareenum']
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        # Check for errors
        if 'NT_STATUS_ACCESS_DENIED' in output or 'ACCESS_DENIED' in output:
            return None, 'Access Denied'
        elif 'NT_STATUS_LOGON_FAILURE' in output:
            return None, 'Logon Failure'
        
        # Parse share list
        for line in output.split('\n'):
            line = line.strip()
            
            # Look for netname lines (format: netname: SHARE_NAME)
            if line.startswith('netname:'):
                match = re.search(r'netname:\s*(\S+)', line)
                if match:
                    share_name = match.group(1)
                    shares.append({
                        'name': share_name,
                        'type': 'Unknown',
                        'comment': ''
                    })
        
        if shares:
            return shares, None
        else:
            return None, 'No shares found'
            
    except subprocess.TimeoutExpired:
        return None, 'Timeout'
    except Exception as e:
        return None, str(e)

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
        'smb_enabled': False,
        'ports_open': [],
        'shares': [],
        'accessible_shares': [],
        'interesting_shares': [],
        'null_session': False,
        'guest_access': False,
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
    
    # Try to enumerate shares (null session first)
    shares, error = enumerate_shares_smbclient(ip, '', '', timeout=10)
    
    if shares:
        result['null_session'] = True
        result['shares'] = shares
    else:
        # Try with guest account
        shares, error = enumerate_shares_smbclient(ip, 'guest', '', timeout=10)
        if shares:
            result['guest_access'] = True
            result['shares'] = shares
        elif username:
            # Try with provided credentials
            shares, error = enumerate_shares_smbclient(ip, username, password, timeout=10)
            if shares:
                result['shares'] = shares
            else:
                # Try rpcclient as fallback
                shares, rpc_error = enumerate_shares_rpcclient(ip, username, password, timeout=10)
                if shares:
                    result['shares'] = shares
                else:
                    result['error'] = error or rpc_error
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

def main():
    parser = argparse.ArgumentParser(
        description='SMBSeek v1.0 - SMB Share Discovery and Enumeration',
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
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check for smbclient
    if not check_smbclient():
        print(f"{Colors.FAIL}[!] Error: smbclient not found. Please install: sudo apt install smbclient{Colors.ENDC}")
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
    
    print(f"\n{Colors.OKBLUE}[*] Starting SMB scan...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets: {len(ips)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Workers: {args.workers}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Test Access: {'Yes' if args.test_access else 'No'}{Colors.ENDC}")
    if args.username:
        print(f"{Colors.OKBLUE}[*] Authentication: {args.username}:{'*' * len(args.password)}{Colors.ENDC}")
    print()
    
    # Scan hosts
    results = []
    completed = 0
    smb_found = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {
                executor.submit(scan_host, ip, args.timeout, args.test_access, 
                              args.username, args.password): ip 
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['smb_enabled']:
                        smb_found += 1
                        
                        # Determine confidence
                        if result['accessible_shares']:
                            confidence = f"{Colors.OKGREEN}[HIGH]{Colors.ENDC}"
                        elif result['shares']:
                            confidence = f"{Colors.WARNING}[MEDIUM]{Colors.ENDC}"
                        else:
                            confidence = f"{Colors.OKBLUE}[LOW]{Colors.ENDC}"
                        
                        hostname_str = f" ({result['hostname']})" if result['hostname'] else ""
                        shares_str = f", {len(result['shares'])} shares" if result['shares'] else ""
                        access_str = f", {len(result['accessible_shares'])} accessible" if result['accessible_shares'] else ""
                        
                        null_str = f"{Colors.WARNING} [NULL SESSION]{Colors.ENDC}" if result['null_session'] else ""
                        guest_str = f"{Colors.WARNING} [GUEST ACCESS]{Colors.ENDC}" if result['guest_access'] else ""
                        
                        print(f"{confidence} {result['ip']}{hostname_str}{shares_str}{access_str}{null_str}{guest_str}")
                        
                        # Show interesting shares
                        if result['interesting_shares']:
                            print(f"    {Colors.WARNING}★ Interesting: {', '.join(result['interesting_shares'])}{Colors.ENDC}")
                        
                        # Show accessible shares
                        if result['accessible_shares']:
                            for share in result['accessible_shares']:
                                print(f"    {Colors.OKGREEN}✓ \\\\{result['ip']}\\{share['name']} "
                                     f"(Files: {share['files_found']}){Colors.ENDC}")
                    
                    elif args.verbose:
                        print(f"[ ] {ip} - No SMB")
                    
                    # Progress
                    if completed % 10 == 0 or completed == len(ips):
                        print(f"\n{Colors.OKCYAN}[*] Progress: {completed}/{len(ips)} "
                             f"({smb_found} with SMB){Colors.ENDC}\n")
                
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error scanning {ip}: {e}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
    
    # Summary
    print(f"\n{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Scan Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"Total Hosts Scanned: {completed}")
    print(f"Hosts with SMB: {smb_found}")
    
    hosts_with_shares = sum(1 for r in results if r['shares'])
    hosts_with_access = sum(1 for r in results if r['accessible_shares'])
    null_session_hosts = sum(1 for r in results if r['null_session'])
    guest_access_hosts = sum(1 for r in results if r['guest_access'])
    
    print(f"Hosts with Shares: {hosts_with_shares}")
    if args.test_access:
        print(f"Hosts with Accessible Shares: {hosts_with_access}")
    print(f"Null Session Allowed: {null_session_hosts}")
    print(f"Guest Access Allowed: {guest_access_hosts}")
    
    # Save results
    if smb_found > 0:
        print()
        save_smb_list(results)
        if hosts_with_access > 0:
            save_share_list(results)
        save_details(results)
    
    return 0

if __name__ == '__main__':
    exit(main())
