#!/usr/bin/env python3
"""
WinRMSeek v1.0 - Windows Remote Management Discovery
Find and enumerate WinRM/PSRemoting enabled hosts

Features:
- WinRM port scanning (5985 HTTP, 5986 HTTPS)
- WinRM service detection
- Authentication testing
- PowerShell remoting capability detection
- Integration with evil-winrm
- Credential validation

Usage:
    ./winrmseek.py                         # Basic WinRM discovery
    ./winrmseek.py -t                      # Test authentication
    ./winrmseek.py -u user -p pass         # Authenticated testing
    ./winrmseek.py --ssl                   # HTTPS only (port 5986)
    
Output:
    winrmlist.txt       - WinRM enabled hosts
    winrm_access.txt    - Hosts with valid credentials
    winrm_details.txt   - Detailed findings
    winrm_details.json  - JSON export
"""

import socket
import subprocess
import sys
import json
import argparse
import requests
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# Import shared utilities
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list


# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

# WinRM ports
WINRM_PORTS = {
    5985: 'WinRM-HTTP',
    5986: 'WinRM-HTTPS'
}

# Banner
BANNER = f"""{CYAN}{BOLD}
██╗    ██╗██╗███╗   ██╗██████╗ ███╗   ███╗███████╗███████╗███████╗██╗  ██╗
██║    ██║██║████╗  ██║██╔══██╗████╗ ████║██╔════╝██╔════╝██╔════╝██║ ██╔╝
██║ █╗ ██║██║██╔██╗ ██║██████╔╝██╔████╔██║███████╗█████╗  █████╗  █████╔╝ 
██║███╗██║██║██║╚██╗██║██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
╚███╔███╔╝██║██║ ╚████║██║  ██║██║ ╚═╝ ██║███████║███████╗███████╗██║  ██╗
 ╚══╝╚══╝ ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}WinRMSeek v1.0 - Windows Remote Management Discovery{RESET}
{BLUE}Find and enumerate WinRM/PSRemoting hosts{RESET}
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


def check_port(ip, port, timeout=3):
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def detect_winrm_http(ip, timeout=5):
    """
    Detect WinRM over HTTP using HTTP request
    Returns: True if WinRM detected
    """
    try:
        url = f'http://{ip}:5985/wsman'
        response = requests.get(url, timeout=timeout, verify=False)
        
        # WinRM typically returns 405 Method Not Allowed for GET
        # Or returns XML with wsman namespace
        if response.status_code in [401, 405] or 'wsman' in response.text.lower():
            return True
        
    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass
    
    return False


def detect_winrm_https(ip, timeout=5):
    """
    Detect WinRM over HTTPS
    Returns: True if WinRM detected
    """
    try:
        url = f'https://{ip}:5986/wsman'
        response = requests.get(url, timeout=timeout, verify=False)
        
        if response.status_code in [401, 405] or 'wsman' in response.text.lower():
            return True
        
    except requests.exceptions.SSLError:
        # SSL error usually means service is there but SSL handshake failed
        return True
    except requests.exceptions.Timeout:
        pass
    except Exception:
        pass
    
    return False


def test_winrm_auth_powershell(ip, port, username, password, timeout=10):
    """
    Test WinRM authentication using PowerShell (Windows only)
    Returns: dict with auth result
    """
    result = {
        'authenticated': False,
        'method': 'powershell',
        'error': None
    }
    
    try:
        # Build PowerShell command
        ps_cmd = f'''
$password = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential('{username}', $password)
$session = New-PSSession -ComputerName {ip} -Port {port} -Credential $cred -ErrorAction Stop
if ($session) {{
    Remove-PSSession $session
    Write-Output "SUCCESS"
}}
'''
        
        cmd = ['powershell.exe', '-Command', ps_cmd]
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if 'SUCCESS' in proc_result.stdout:
            result['authenticated'] = True
        elif proc_result.stderr:
            result['error'] = proc_result.stderr[:100]
    
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'PowerShell not found (Linux?)'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def test_winrm_auth_evil_winrm(ip, username, password, ssl=False, timeout=10):
    """
    Test WinRM authentication using evil-winrm (Linux)
    Returns: dict with auth result
    """
    result = {
        'authenticated': False,
        'method': 'evil-winrm',
        'error': None
    }
    
    try:
        cmd = ['evil-winrm', '-i', ip, '-u', username, '-p', password]
        
        if ssl:
            cmd.append('-S')
        
        # Try to execute 'whoami' command
        cmd.extend(['-e', 'whoami'])
        
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        
        if proc_result.returncode == 0 or 'Evil-WinRM shell' in proc_result.stdout:
            result['authenticated'] = True
        else:
            result['error'] = 'Authentication failed'
    
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'evil-winrm not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def test_winrm_auth_pywinrm(ip, port, username, password, timeout=10):
    """
    Test WinRM authentication using pywinrm library
    Returns: dict with auth result
    """
    result = {
        'authenticated': False,
        'method': 'pywinrm',
        'error': None
    }
    
    try:
        from winrm.protocol import Protocol
        
        protocol = 'https' if port == 5986 else 'http'
        endpoint = f'{protocol}://{ip}:{port}/wsman'
        
        p = Protocol(
            endpoint=endpoint,
            transport='ntlm',
            username=username,
            password=password,
            server_cert_validation='ignore'
        )
        
        # Try to open a shell
        shell_id = p.open_shell(timeout=timeout)
        
        if shell_id:
            p.close_shell(shell_id)
            result['authenticated'] = True
    
    except ImportError:
        result['error'] = 'pywinrm not installed (pip install pywinrm)'
    except Exception as e:
        result['error'] = str(e)[:100]
    
    return result


def scan_host(ip, args):
    """
    Scan a single host for WinRM
    Returns: dict with findings
    """
    result = {
        'ip': ip,
        'winrm_http': False,
        'winrm_https': False,
        'authenticated': False,
        'open_ports': [],
        'status': 'closed'
    }
    
    try:
        # Check HTTP port (5985)
        if not args.ssl_only:
            if check_port(ip, 5985, timeout=args.timeout):
                result['open_ports'].append(5985)
                result['status'] = 'open'
                
                if detect_winrm_http(ip, timeout=args.timeout):
                    result['winrm_http'] = True
        
        # Check HTTPS port (5986)
        if check_port(ip, 5986, timeout=args.timeout):
            result['open_ports'].append(5986)
            result['status'] = 'open'
            
            if detect_winrm_https(ip, timeout=args.timeout):
                result['winrm_https'] = True
        
        # Test authentication if credentials provided
        if args.test_auth and args.username and args.password:
            if result['winrm_http'] or result['winrm_https']:
                port = 5985 if result['winrm_http'] else 5986
                
                # Try pywinrm first (cross-platform)
                auth_result = test_winrm_auth_pywinrm(ip, port, args.username, args.password, timeout=args.timeout)
                
                if auth_result['authenticated']:
                    result['authenticated'] = True
                    result['auth_method'] = auth_result['method']
    
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_winrmlist(results, filename='winrmlist.txt'):
    """Save list of WinRM enabled hosts"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['winrm_http'] or result['winrm_https']:
                    f.write(f"{result['ip']}\n")
        print(f"{GREEN}[+] WinRM host list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving WinRM list: {e}{RESET}")


def save_access_list(results, filename='winrm_access.txt'):
    """Save list of hosts with valid credentials"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WINRMSEEK - Hosts with Valid Credentials\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['authenticated']:
                    protocol = 'https' if result['winrm_https'] else 'http'
                    port = 5986 if result['winrm_https'] else 5985
                    
                    f.write(f"\nHost: {result['ip']}\n")
                    f.write(f"Protocol: {protocol}\n")
                    f.write(f"Port: {port}\n")
                    f.write(f"\nConnect with evil-winrm:\n")
                    f.write(f"  evil-winrm -i {result['ip']} -u USERNAME -p PASSWORD")
                    if protocol == 'https':
                        f.write(" -S")
                    f.write("\n\n")
                    f.write(f"{'=' * 80}\n")
        
        print(f"{GREEN}[+] Access list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving access list: {e}{RESET}")


def save_details(results, filename='winrm_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WINRMSEEK - Detailed Scan Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['status'] == 'open':
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    f.write(f"Open Ports: {', '.join(map(str, result['open_ports']))}\n")
                    
                    if result['winrm_http']:
                        f.write(f"WinRM HTTP: ✓ (port 5985)\n")
                    
                    if result['winrm_https']:
                        f.write(f"WinRM HTTPS: ✓ (port 5986)\n")
                    
                    if result['authenticated']:
                        f.write(f"Authentication: ✓ SUCCESS\n")
                        f.write(f"Method: {result.get('auth_method', 'N/A')}\n")
                    
                    f.write("\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='winrm_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='WinRMSeek - Windows Remote Management Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./winrmseek.py iplist.txt                     # Basic discovery
  ./winrmseek.py iplist.txt -t -u admin -p pass # Test authentication
  ./winrmseek.py iplist.txt --ssl               # HTTPS only (port 5986)
  ./winrmseek.py iplist.txt -w 20               # Fast scan (20 workers)
  
Connect to discovered hosts:
  evil-winrm -i 192.168.1.100 -u admin -p password
  evil-winrm -i 192.168.1.100 -u admin -p password -S  # HTTPS
        """
    )
    
    parser.add_argument('input_file', help='File containing IP addresses')
    parser.add_argument('-t', '--test-auth', action='store_true', help='Test authentication with provided credentials')
    parser.add_argument('-u', '--username', help='Username for authentication testing')
    parser.add_argument('-p', '--password', help='Password for authentication testing')
    parser.add_argument('--ssl-only', action='store_true', help='Only scan HTTPS port (5986)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Connection timeout (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read IPs
    ips = read_ip_list(args.input_file)
    
    if not ips:
        print(f"{RED}[!] No IPs to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting WinRM scan...{RESET}")
    print(f"{CYAN}[*] Targets: {len(ips)}{RESET}")
    print(f"{CYAN}[*] Workers: {args.workers}{RESET}")
    print(f"{CYAN}[*] Ports: {'5986 (HTTPS)' if args.ssl_only else '5985 (HTTP), 5986 (HTTPS)'}{RESET}")
    if args.test_auth:
        print(f"{CYAN}[*] Authentication testing: Enabled{RESET}")
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
                    
                    if result['winrm_http'] or result['winrm_https']:
                        services = []
                        if result['winrm_http']:
                            services.append('HTTP:5985')
                        if result['winrm_https']:
                            services.append('HTTPS:5986')
                        
                        severity = f"{GREEN}[WINRM]{RESET}"
                        msg = f"{severity} {ip} - {', '.join(services)}"
                        
                        if result['authenticated']:
                            msg += f" {GREEN}[AUTH SUCCESS]{RESET}"
                        
                        print(msg)
                    
                    elif args.verbose:
                        print(f"{BLUE}[*]{RESET} {ip} - No WinRM")
                
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
    
    winrm_hosts = len([r for r in results if r['winrm_http'] or r['winrm_https']])
    http_hosts = len([r for r in results if r['winrm_http']])
    https_hosts = len([r for r in results if r['winrm_https']])
    auth_success = len([r for r in results if r['authenticated']])
    
    print(f"WinRM hosts found: {winrm_hosts}/{len(ips)}")
    print(f"  HTTP (5985): {http_hosts}")
    print(f"  HTTPS (5986): {https_hosts}")
    if args.test_auth:
        print(f"Authentication successes: {auth_success}")
    
    # Save results
    if results:
        save_winrmlist(results)
        if auth_success > 0:
            save_access_list(results)
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
