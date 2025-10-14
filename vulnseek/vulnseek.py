#!/usr/bin/env python3
"""
VulnSeek v1.0 - Vulnerability Scanner for Internal Networks

Scans for common vulnerabilities including:
- EternalBlue (MS17-010) via Metasploit
- BlueKeep (CVE-2019-0708) 
- SMBGhost (CVE-2020-0796)
- Outdated OS versions
- Missing patches

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

# Vulnerability definitions
VULNERABILITIES = {
    'ms17-010': {
        'name': 'EternalBlue',
        'cve': 'CVE-2017-0144',
        'severity': 'CRITICAL',
        'description': 'SMBv1 Remote Code Execution',
        'ports': [445],
        'metasploit_module': 'auxiliary/scanner/smb/smb_ms17_010',
        'affected_os': ['Windows 7', 'Windows Server 2008', 'Windows 8', 'Windows Server 2012', 'Windows 10']
    },
    'bluekeep': {
        'name': 'BlueKeep',
        'cve': 'CVE-2019-0708',
        'severity': 'CRITICAL',
        'description': 'RDP Remote Code Execution',
        'ports': [3389],
        'metasploit_module': 'auxiliary/scanner/rdp/cve_2019_0708_bluekeep',
        'affected_os': ['Windows 7', 'Windows Server 2008', 'Windows Server 2008 R2']
    },
    'smbghost': {
        'name': 'SMBGhost',
        'cve': 'CVE-2020-0796',
        'severity': 'CRITICAL',
        'description': 'SMBv3 Remote Code Execution',
        'ports': [445],
        'metasploit_module': 'auxiliary/scanner/smb/smb_ms17_010',  # Generic SMB scanner
        'affected_os': ['Windows 10 1903', 'Windows 10 1909', 'Windows Server 2019']
    },
    'zerologon': {
        'name': 'Zerologon',
        'cve': 'CVE-2020-1472',
        'severity': 'CRITICAL',
        'description': 'Netlogon Elevation of Privilege',
        'ports': [445],
        'metasploit_module': 'auxiliary/scanner/dcerpc/zerologon',
        'affected_os': ['Windows Server 2008', 'Windows Server 2012', 'Windows Server 2016', 'Windows Server 2019']
    }
}

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.FAIL}╔═══════════════════════════════════════════════════════════╗
║                   VulnSeek v1.0                           ║
║          Vulnerability Scanner for Internal Networks      ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def read_ip_list(file_path: str) -> List[str]:
    """Read and parse IP addresses from file"""
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
                
                if not line or line.startswith('#'):
                    continue
                
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        ips.extend([str(ip) for ip in network.hosts()])
                    except ValueError as e:
                        print(f"{Colors.WARNING}[!] Invalid CIDR: {line} - {e}{Colors.ENDC}")
                else:
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
    """Check if a port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def get_hostname(ip: str) -> Optional[str]:
    """Get hostname via reverse DNS"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except:
        return None

def check_msfconsole() -> bool:
    """Check if Metasploit is installed"""
    try:
        result = subprocess.run(['msfconsole', '-v'], 
                              capture_output=True, 
                              timeout=5)
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def run_metasploit_module(module: str, rhosts: str, rport: int = None, 
                         timeout: int = 60) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Run a Metasploit auxiliary module
    
    Returns:
        Tuple of (vulnerable, output, error)
    """
    # Build Metasploit resource script
    commands = [
        f'use {module}',
        f'set RHOSTS {rhosts}',
        'set ExitOnSession false'
    ]
    
    if rport:
        commands.append(f'set RPORT {rport}')
    
    commands.extend([
        'run',
        'exit'
    ])
    
    rc_script = '\n'.join(commands)
    
    try:
        # Run msfconsole with resource script
        result = subprocess.run(
            ['msfconsole', '-q', '-x', rc_script],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        # Check for vulnerability indicators
        vulnerable = False
        error = None
        
        if 'vulnerable' in output.lower() or 'is likely VULNERABLE' in output:
            vulnerable = True
        elif 'not vulnerable' in output.lower() or 'does not appear' in output:
            vulnerable = False
        elif 'error' in output.lower() or 'failed' in output.lower():
            error = 'Scan error'
        elif 'timeout' in output.lower():
            error = 'Timeout'
        
        return vulnerable, output, error
        
    except subprocess.TimeoutExpired:
        return False, None, 'Timeout'
    except Exception as e:
        return False, None, str(e)

def check_eternalblue_nmap(ip: str, timeout: int = 30) -> Tuple[bool, Optional[str]]:
    """
    Check for MS17-010 (EternalBlue) using nmap script
    
    Returns:
        Tuple of (vulnerable, output)
    """
    try:
        result = subprocess.run(
            ['nmap', '-p445', '--script', 'smb-vuln-ms17-010', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        # Check for vulnerability
        if 'State: VULNERABLE' in output or 'VULNERABLE:' in output:
            return True, output
        elif 'State: NOT VULNERABLE' in output or 'not vulnerable' in output.lower():
            return False, output
        else:
            return False, 'Unable to determine'
            
    except subprocess.TimeoutExpired:
        return False, 'Timeout'
    except FileNotFoundError:
        return False, 'nmap not found'
    except Exception as e:
        return False, str(e)

def check_bluekeep_nmap(ip: str, timeout: int = 30) -> Tuple[bool, Optional[str]]:
    """Check for CVE-2019-0708 (BlueKeep) using nmap"""
    try:
        result = subprocess.run(
            ['nmap', '-p3389', '--script', 'rdp-vuln-ms12-020', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        if 'VULNERABLE' in output:
            return True, output
        else:
            return False, output
            
    except subprocess.TimeoutExpired:
        return False, 'Timeout'
    except FileNotFoundError:
        return False, 'nmap not found'
    except Exception as e:
        return False, str(e)

def get_smb_version(ip: str, timeout: int = 10) -> Optional[Dict]:
    """Get SMB version information"""
    try:
        result = subprocess.run(
            ['nmap', '-p445', '--script', 'smb-protocols', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout
        
        info = {
            'smb1': 'SMBv1' in output or 'NT LM 0.12' in output,
            'smb2': 'SMBv2' in output or '2.02' in output or '2.1' in output,
            'smb3': 'SMBv3' in output or '3.0' in output or '3.1' in output,
        }
        
        return info
        
    except Exception:
        return None

def get_os_info(ip: str, timeout: int = 20) -> Optional[Dict]:
    """Get OS information via SMB/nmap"""
    try:
        result = subprocess.run(
            ['nmap', '-O', '--osscan-guess', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout
        
        os_info = {
            'os': None,
            'version': None,
            'cpe': None
        }
        
        # Parse OS detection
        for line in output.split('\n'):
            if 'OS details:' in line or 'Running:' in line:
                os_info['os'] = line.split(':')[1].strip()
            elif 'cpe:/o:' in line:
                match = re.search(r'cpe:/o:([^:]+):([^:]+):([^:\s]+)', line)
                if match:
                    os_info['cpe'] = f"{match.group(1)}:{match.group(2)}:{match.group(3)}"
        
        return os_info if os_info['os'] else None
        
    except Exception:
        return None

def scan_host(ip: str, timeout: int = 2, use_metasploit: bool = False, 
              use_nmap: bool = True, scan_type: str = 'quick') -> Dict:
    """
    Scan a single host for vulnerabilities
    
    Args:
        ip: IP address to scan
        timeout: Connection timeout
        use_metasploit: Whether to use Metasploit modules
        use_nmap: Whether to use nmap scripts
        scan_type: 'quick' or 'full'
        
    Returns:
        Dict with scan results
    """
    result = {
        'ip': ip,
        'hostname': None,
        'vulnerabilities': [],
        'os_info': None,
        'smb_info': None,
        'ports_open': [],
        'risk_level': 'LOW',
        'error': None
    }
    
    # Get hostname
    hostname = get_hostname(ip)
    if hostname:
        result['hostname'] = hostname
    
    # Check critical ports
    critical_ports = [445, 3389, 135, 139]
    for port in critical_ports:
        if check_port(ip, port, timeout):
            result['ports_open'].append(port)
    
    if not result['ports_open']:
        result['error'] = 'No critical ports open'
        return result
    
    # Get OS info (if full scan)
    if scan_type == 'full' and use_nmap:
        os_info = get_os_info(ip, timeout=20)
        if os_info:
            result['os_info'] = os_info
    
    # Check for EternalBlue (MS17-010)
    if 445 in result['ports_open']:
        if use_nmap:
            # Check SMB version
            smb_info = get_smb_version(ip, timeout=10)
            if smb_info:
                result['smb_info'] = smb_info
                
                # SMBv1 enabled = potential EternalBlue
                if smb_info.get('smb1'):
                    print(f"    {Colors.WARNING}⚠ SMBv1 enabled{Colors.ENDC}")
            
            # Check with nmap script
            vulnerable, output = check_eternalblue_nmap(ip, timeout=30)
            if vulnerable:
                result['vulnerabilities'].append({
                    'name': 'EternalBlue',
                    'cve': 'CVE-2017-0144',
                    'severity': 'CRITICAL',
                    'description': 'MS17-010 SMBv1 RCE',
                    'confidence': 'HIGH',
                    'method': 'nmap'
                })
                result['risk_level'] = 'CRITICAL'
        
        if use_metasploit:
            # Check with Metasploit (more reliable)
            print(f"    {Colors.OKBLUE}[*] Running Metasploit check...{Colors.ENDC}")
            vulnerable, output, error = run_metasploit_module(
                'auxiliary/scanner/smb/smb_ms17_010',
                ip,
                445,
                timeout=60
            )
            if vulnerable:
                result['vulnerabilities'].append({
                    'name': 'EternalBlue',
                    'cve': 'CVE-2017-0144',
                    'severity': 'CRITICAL',
                    'description': 'MS17-010 SMBv1 RCE (Metasploit confirmed)',
                    'confidence': 'CONFIRMED',
                    'method': 'metasploit'
                })
                result['risk_level'] = 'CRITICAL'
    
    # Check for BlueKeep (CVE-2019-0708)
    if 3389 in result['ports_open'] and use_nmap:
        vulnerable, output = check_bluekeep_nmap(ip, timeout=30)
        if vulnerable:
            result['vulnerabilities'].append({
                'name': 'BlueKeep',
                'cve': 'CVE-2019-0708',
                'severity': 'CRITICAL',
                'description': 'RDP Remote Code Execution',
                'confidence': 'HIGH',
                'method': 'nmap'
            })
            if result['risk_level'] != 'CRITICAL':
                result['risk_level'] = 'CRITICAL'
    
    # Check for Zerologon (if DC port open)
    if 135 in result['ports_open'] and use_metasploit and scan_type == 'full':
        vulnerable, output, error = run_metasploit_module(
            'auxiliary/scanner/dcerpc/zerologon',
            ip,
            timeout=60
        )
        if vulnerable:
            result['vulnerabilities'].append({
                'name': 'Zerologon',
                'cve': 'CVE-2020-1472',
                'severity': 'CRITICAL',
                'description': 'Netlogon Elevation of Privilege',
                'confidence': 'HIGH',
                'method': 'metasploit'
            })
            result['risk_level'] = 'CRITICAL'
    
    # Adjust risk level
    if result['vulnerabilities']:
        severities = [v['severity'] for v in result['vulnerabilities']]
        if 'CRITICAL' in severities:
            result['risk_level'] = 'CRITICAL'
        elif 'HIGH' in severities:
            result['risk_level'] = 'HIGH'
        elif 'MEDIUM' in severities:
            result['risk_level'] = 'MEDIUM'
    
    return result

def save_vuln_list(results: List[Dict], filename: str = 'vulnlist.txt'):
    """Save list of vulnerable IPs to a file"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['vulnerabilities']:
                    f.write(f"{result['ip']}\n")
        
        print(f"\n{Colors.OKGREEN}[+] Vulnerable host list saved to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error saving vulnerable list: {e}{Colors.ENDC}")

def save_details(results: List[Dict], txt_filename: str = 'vuln_details.txt', 
                json_filename: str = 'vuln_details.json'):
    """Save detailed scan results"""
    # Save TXT format
    try:
        with open(txt_filename, 'w') as f:
            f.write("VulnSeek - Vulnerability Scan Results\n")
            f.write("=" * 70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            vuln_hosts = [r for r in results if r['vulnerabilities']]
            critical_count = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
            
            f.write(f"Total Hosts Scanned: {len(results)}\n")
            f.write(f"Vulnerable Hosts: {len(vuln_hosts)}\n")
            f.write(f"Critical Risk Hosts: {critical_count}\n")
            f.write("=" * 70 + "\n\n")
            
            for result in vuln_hosts:
                f.write(f"Host: {result['ip']}\n")
                if result['hostname']:
                    f.write(f"Hostname: {result['hostname']}\n")
                
                f.write(f"Risk Level: {result['risk_level']}\n")
                f.write(f"Open Ports: {', '.join(map(str, result['ports_open']))}\n")
                
                if result['os_info']:
                    f.write(f"OS: {result['os_info'].get('os', 'Unknown')}\n")
                
                if result['smb_info']:
                    smb_versions = []
                    if result['smb_info'].get('smb1'):
                        smb_versions.append('SMBv1')
                    if result['smb_info'].get('smb2'):
                        smb_versions.append('SMBv2')
                    if result['smb_info'].get('smb3'):
                        smb_versions.append('SMBv3')
                    f.write(f"SMB Versions: {', '.join(smb_versions)}\n")
                
                f.write(f"\nVulnerabilities Found: {len(result['vulnerabilities'])}\n")
                f.write("-" * 70 + "\n")
                
                for vuln in result['vulnerabilities']:
                    f.write(f"\n  ⚠ {vuln['name']} ({vuln['cve']})\n")
                    f.write(f"  Severity: {vuln['severity']}\n")
                    f.write(f"  Description: {vuln['description']}\n")
                    f.write(f"  Confidence: {vuln['confidence']}\n")
                    f.write(f"  Detection Method: {vuln['method']}\n")
                
                f.write("\n" + "=" * 70 + "\n\n")
        
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
        description='VulnSeek v1.0 - Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Quick nmap scan
  %(prog)s -m                           # Use Metasploit modules
  %(prog)s --full -m                    # Full scan with Metasploit
  %(prog)s -f targets.txt -v            # Verbose scan
        """
    )
    
    parser.add_argument('-f', '--file', 
                       default='iplist.txt',
                       help='Input file with IP addresses (default: iplist.txt)')
    
    parser.add_argument('-w', '--workers', 
                       type=int, 
                       default=5,
                       help='Number of concurrent workers (default: 5)')
    
    parser.add_argument('-m', '--metasploit',
                       action='store_true',
                       help='Use Metasploit modules (slower but more accurate)')
    
    parser.add_argument('--full',
                       action='store_true',
                       help='Full scan (includes OS detection)')
    
    parser.add_argument('--timeout',
                       type=int,
                       default=2,
                       help='Connection timeout in seconds (default: 2)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output (show all hosts)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check for nmap
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print(f"{Colors.FAIL}[!] Error: nmap not found. Please install: sudo apt install nmap{Colors.ENDC}")
        return 1
    
    # Check for Metasploit if requested
    if args.metasploit:
        if not check_msfconsole():
            print(f"{Colors.WARNING}[!] Warning: msfconsole not found. Install Metasploit for more accurate results{Colors.ENDC}")
            args.metasploit = False
    
    # Read IP list
    ips = read_ip_list(args.file)
    if not ips:
        print(f"{Colors.FAIL}[!] No valid IPs to scan{Colors.ENDC}")
        return 1
    
    scan_type = 'full' if args.full else 'quick'
    
    print(f"\n{Colors.OKBLUE}[*] Starting vulnerability scan...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets: {len(ips)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Workers: {args.workers}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Scan Type: {scan_type.upper()}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Metasploit: {'Yes' if args.metasploit else 'No'}{Colors.ENDC}")
    print()
    
    # Scan hosts
    results = []
    completed = 0
    vuln_found = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {
                executor.submit(scan_host, ip, args.timeout, args.metasploit, True, scan_type): ip 
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['vulnerabilities']:
                        vuln_found += 1
                        
                        # Color code by risk
                        if result['risk_level'] == 'CRITICAL':
                            risk_color = Colors.FAIL
                        elif result['risk_level'] == 'HIGH':
                            risk_color = Colors.WARNING
                        else:
                            risk_color = Colors.OKBLUE
                        
                        hostname_str = f" ({result['hostname']})" if result['hostname'] else ""
                        
                        print(f"{risk_color}[{result['risk_level']}]{Colors.ENDC} {result['ip']}{hostname_str}")
                        
                        # Show vulnerabilities
                        for vuln in result['vulnerabilities']:
                            print(f"    {Colors.FAIL}⚠ {vuln['name']} ({vuln['cve']}) - {vuln['severity']}{Colors.ENDC}")
                    
                    elif args.verbose:
                        print(f"[ ] {ip} - No vulnerabilities detected")
                    
                    # Progress
                    if completed % 5 == 0 or completed == len(ips):
                        print(f"\n{Colors.OKCYAN}[*] Progress: {completed}/{len(ips)} ({vuln_found} vulnerable){Colors.ENDC}\n")
                
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error scanning {ip}: {e}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
    
    # Summary
    print(f"\n{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Scan Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"Total Hosts Scanned: {completed}")
    print(f"Vulnerable Hosts: {vuln_found}")
    
    critical_hosts = sum(1 for r in results if r['risk_level'] == 'CRITICAL')
    high_hosts = sum(1 for r in results if r['risk_level'] == 'HIGH')
    
    print(f"Critical Risk: {critical_hosts}")
    print(f"High Risk: {high_hosts}")
    
    # Count vulnerabilities
    all_vulns = {}
    for result in results:
        for vuln in result['vulnerabilities']:
            vuln_name = vuln['name']
            all_vulns[vuln_name] = all_vulns.get(vuln_name, 0) + 1
    
    if all_vulns:
        print(f"\nVulnerability Breakdown:")
        for vuln_name, count in sorted(all_vulns.items(), key=lambda x: x[1], reverse=True):
            print(f"  {vuln_name}: {count} host(s)")
    
    # Save results
    if vuln_found > 0:
        print()
        save_vuln_list(results)
        save_details(results)
    
    return 0

if __name__ == '__main__':
    exit(main())
