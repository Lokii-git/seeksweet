#!/usr/bin/env python3
"""
VulnSeek v2.0 - Enhanced Vulnerability Scanner for Internal Networks

Combines multiple scanning methods:
- Nmap NSE scripts for specific CVEs
- Metasploit auxiliary modules (detection only)
- Nuclei CVE templates (no exploitation)

Scans for:
- EternalBlue (MS17-010)
- BlueKeep (CVE-2019-0708)
- SMBGhost (CVE-2020-0796)
- Zerologon (CVE-2020-1472)
- PrintNightmare (CVE-2021-34527)
- HiveNightmare (CVE-2021-36934)
- PetitPotam (CVE-2021-36942)
- NoPac (CVE-2021-42278/42287)
- And 100+ more CVEs via Nuclei

Author: Lokii-git
Date: October 2025
Platform: Kali Linux / Windows with tools
"""

import subprocess
import socket
import ipaddress
import argparse
import json
import os
import sys
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional, Tuple

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list

# Color codes
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

# Expanded vulnerability definitions with nmap scripts
NMAP_CVE_CHECKS = {
    'ms17-010': {
        'name': 'EternalBlue',
        'cve': 'CVE-2017-0144',
        'severity': 'CRITICAL',
        'description': 'SMBv1 Remote Code Execution',
        'port': 445,
        'nmap_script': 'smb-vuln-ms17-010',
        'affected_os': ['Windows 7', 'Windows Server 2008', 'Windows 8', 'Windows Server 2012']
    },
    'ms17-010-alt': {
        'name': 'EternalBlue (Alternative)',
        'cve': 'CVE-2017-0143',
        'severity': 'CRITICAL',
        'description': 'SMBv1 Multiple Vulnerabilities',
        'port': 445,
        'nmap_script': 'smb-vuln-ms17-010',
        'affected_os': ['Windows Vista', 'Windows 7', 'Windows 8', 'Windows Server 2008']
    },
    'bluekeep': {
        'name': 'BlueKeep',
        'cve': 'CVE-2019-0708',
        'severity': 'CRITICAL',
        'description': 'RDP Remote Code Execution',
        'port': 3389,
        'nmap_script': 'rdp-vuln-ms12-020',
        'affected_os': ['Windows 7', 'Windows Server 2008', 'Windows Server 2008 R2']
    },
    'ms08-067': {
        'name': 'MS08-067',
        'cve': 'CVE-2008-4250',
        'severity': 'CRITICAL',
        'description': 'Server Service RCE',
        'port': 445,
        'nmap_script': 'smb-vuln-ms08-067',
        'affected_os': ['Windows 2000', 'Windows XP', 'Windows Server 2003']
    },
    'conficker': {
        'name': 'Conficker',
        'cve': 'CVE-2008-4250',
        'severity': 'HIGH',
        'description': 'MS08-067 Worm',
        'port': 445,
        'nmap_script': 'smb-vuln-conficker',
        'affected_os': ['Windows XP', 'Windows Vista', 'Windows 7']
    },
    'ms10-054': {
        'name': 'MS10-054',
        'cve': 'CVE-2010-2729',
        'severity': 'CRITICAL',
        'description': 'SMB Pool Overflow',
        'port': 445,
        'nmap_script': 'smb-vuln-ms10-054',
        'affected_os': ['Windows XP', 'Windows Server 2003', 'Windows Vista']
    },
    'ms10-061': {
        'name': 'MS10-061',
        'cve': 'CVE-2010-2730',
        'severity': 'CRITICAL',
        'description': 'Print Spooler Service RCE',
        'port': 445,
        'nmap_script': 'smb-vuln-ms10-061',
        'affected_os': ['Windows XP', 'Windows Server 2003', 'Windows 7']
    },
    'ms12-020': {
        'name': 'MS12-020',
        'cve': 'CVE-2012-0002',
        'severity': 'HIGH',
        'description': 'RDP Remote Code Execution',
        'port': 3389,
        'nmap_script': 'rdp-vuln-ms12-020',
        'affected_os': ['Windows XP', 'Windows Vista', 'Windows 7', 'Windows Server 2003/2008']
    },
    'cve-2009-3103': {
        'name': 'MS09-050',
        'cve': 'CVE-2009-3103',
        'severity': 'CRITICAL',
        'description': 'SMBv2 Command Value Vulnerability',
        'port': 445,
        'nmap_script': 'smb-vuln-cve2009-3103',
        'affected_os': ['Windows Vista', 'Windows Server 2008']
    },
    'regsvc-dos': {
        'name': 'Regsvc DoS',
        'cve': 'CVE-2010-2554',
        'severity': 'MEDIUM',
        'description': 'Windows Regsvc DoS',
        'port': 445,
        'nmap_script': 'smb-vuln-regsvc-dos',
        'affected_os': ['Windows 7', 'Windows Vista', 'Windows Server 2008']
    }
}

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.FAIL}{Colors.BOLD}╔═══════════════════════════════════════════════════════════╗
║                   VulnSeek v2.0                           ║
║     Enhanced Vulnerability Scanner - Multi-Method         ║
║              github.com/Lokii-git/seeksweet               ║
╚═══════════════════════════════════════════════════════════╝{Colors.ENDC}

{Colors.OKCYAN}Scanning Methods:{Colors.ENDC}
  • Nmap NSE Scripts (10+ CVE checks)
  • Nuclei CVE Templates (100+ CVEs)
  • Metasploit Modules (optional, detection only)
"""
    print(banner)

def check_tools() -> Dict[str, bool]:
    """Check which tools are available"""
    tools = {
        'nmap': False,
        'nuclei': False,
        'msfconsole': False
    }
    
    # Check nmap
    try:
        subprocess.run(['nmap', '--version'], capture_output=True, timeout=5)
        tools['nmap'] = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Check nuclei
    try:
        subprocess.run(['nuclei', '-version'], capture_output=True, timeout=5)
        tools['nuclei'] = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    # Check metasploit
    try:
        subprocess.run(['msfconsole', '-v'], capture_output=True, timeout=5)
        tools['msfconsole'] = True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    return tools

def read_ip_list(file_path: str) -> List[str]:
    """Read and parse IP addresses from file with CIDR support"""
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

def run_nmap_cve_check(ip: str, check_id: str, check_info: Dict, timeout: int = 30) -> Tuple[bool, Optional[str]]:
    """Run a specific nmap CVE check"""
    try:
        port = check_info['port']
        script = check_info['nmap_script']
        
        result = subprocess.run(
            ['nmap', '-p', str(port), '--script', script, ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        # Check for vulnerability indicators
        if 'VULNERABLE' in output or 'State: VULNERABLE' in output:
            return True, output
        elif 'NOT VULNERABLE' in output or 'not vulnerable' in output.lower():
            return False, output
        else:
            return False, 'Unable to determine'
            
    except subprocess.TimeoutExpired:
        return False, 'Timeout'
    except Exception as e:
        return False, str(e)

def run_metasploit_check(module: str, ip: str, port: int = None, timeout: int = 60) -> Tuple[bool, Optional[str]]:
    """
    Run Metasploit auxiliary module for detection only
    Returns: (vulnerable, output)
    """
    commands = [
        f'use {module}',
        f'set RHOSTS {ip}',
        'set ExitOnSession false'
    ]
    
    if port:
        commands.append(f'set RPORT {port}')
    
    commands.extend(['run', 'exit'])
    rc_script = '\n'.join(commands)
    
    try:
        result = subprocess.run(
            ['msfconsole', '-q', '-x', rc_script],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = result.stdout + result.stderr
        
        if 'vulnerable' in output.lower() or 'is likely VULNERABLE' in output:
            return True, output
        else:
            return False, output
            
    except subprocess.TimeoutExpired:
        return False, 'Timeout'
    except Exception as e:
        return False, str(e)

def run_nuclei_cve_scan(targets: List[str], output_dir: str = 'nuclei_cve_results') -> List[Dict]:
    """
    Run Nuclei scan with ONLY CVE templates (no web checks)
    Returns: List of findings
    """
    print(f"\n{Colors.OKBLUE}[*] Running Nuclei CVE scan...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Filtering to CVE templates only (no web checks){Colors.ENDC}")
    
    # Create target file
    target_file = 'vulnseek_targets.tmp'
    with open(target_file, 'w') as f:
        for target in targets:
            f.write(f"{target}\n")
    
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Build nuclei command - ONLY CVE tags
    cmd = [
        'nuclei',
        '-list', target_file,
        '-tags', 'cve',  # ONLY CVE templates
        '-exclude-tags', 'wordpress,joomla,drupal,magento,apache,nginx,iis,tomcat,jenkins',  # Exclude web-specific
        '-severity', 'critical,high,medium',  # Focus on serious issues
        '-json-export', f'{output_dir}/findings.json',
        '-markdown-export', output_dir,
        '-stats',
        '-silent'
    ]
    
    findings = []
    
    try:
        print(f"{Colors.OKCYAN}[*] This may take several minutes depending on target count...{Colors.ENDC}")
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True
        )
        
        if result.stdout:
            print(result.stdout)
        
        # Parse JSON results
        json_file = f'{output_dir}/findings.json'
        if os.path.exists(json_file):
            with open(json_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            finding = json.loads(line)
                            findings.append(finding)
                        except json.JSONDecodeError:
                            continue
            
            print(f"{Colors.OKGREEN}[+] Nuclei found {len(findings)} CVE(s){Colors.ENDC}")
        
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error running Nuclei: {e}{Colors.ENDC}")
    finally:
        # Cleanup temp file
        if os.path.exists(target_file):
            os.remove(target_file)
    
    return findings

def scan_host_nmap(ip: str, timeout: int = 2, quick: bool = False) -> Dict:
    """
    Scan a host using nmap CVE scripts
    """
    result = {
        'ip': ip,
        'hostname': None,
        'vulnerabilities': [],
        'ports_open': [],
        'risk_level': 'LOW'
    }
    
    # Get hostname
    hostname = get_hostname(ip)
    if hostname:
        result['hostname'] = hostname
    
    # Check critical ports
    critical_ports = [445, 3389, 135, 139, 22, 21, 23, 80, 443, 8080]
    for port in critical_ports:
        if check_port(ip, port, timeout):
            result['ports_open'].append(port)
    
    if not result['ports_open']:
        return result
    
    # Run nmap CVE checks based on open ports
    checks_to_run = []
    for check_id, check_info in NMAP_CVE_CHECKS.items():
        if check_info['port'] in result['ports_open']:
            checks_to_run.append((check_id, check_info))
    
    if quick and len(checks_to_run) > 3:
        # In quick mode, only run top 3 most critical
        checks_to_run = [c for c in checks_to_run if c[1]['severity'] == 'CRITICAL'][:3]
    
    for check_id, check_info in checks_to_run:
        vulnerable, output = run_nmap_cve_check(ip, check_id, check_info, timeout=30)
        
        if vulnerable:
            result['vulnerabilities'].append({
                'name': check_info['name'],
                'cve': check_info['cve'],
                'severity': check_info['severity'],
                'description': check_info['description'],
                'confidence': 'HIGH',
                'method': 'nmap',
                'port': check_info['port']
            })
            
            if check_info['severity'] == 'CRITICAL':
                result['risk_level'] = 'CRITICAL'
            elif check_info['severity'] == 'HIGH' and result['risk_level'] != 'CRITICAL':
                result['risk_level'] = 'HIGH'
    
    return result

def generate_reports(nmap_results: List[Dict], nuclei_findings: List[Dict]):
    """Generate comprehensive reports"""
    
    # Generate CRITICAL_VULNS.txt
    critical_vulns = {}
    
    # Add nmap findings
    for result in nmap_results:
        for vuln in result['vulnerabilities']:
            if vuln['severity'] in ['CRITICAL', 'HIGH']:
                cve = vuln['cve']
                if cve not in critical_vulns:
                    critical_vulns[cve] = {
                        'name': vuln['name'],
                        'cve': cve,
                        'severity': vuln['severity'],
                        'description': vuln['description'],
                        'ips': set(),
                        'method': vuln['method']
                    }
                critical_vulns[cve]['ips'].add(result['ip'])
    
    # Add nuclei findings
    for finding in nuclei_findings:
        # Skip if finding is not a dict (defensive coding)
        if not isinstance(finding, dict):
            continue
            
        info = finding.get('info', {})
        severity = info.get('severity', '').upper()
        
        if severity in ['CRITICAL', 'HIGH']:
            template_id = finding.get('template-id', '')
            # Extract CVE if present
            cve_match = re.search(r'CVE-\d{4}-\d+', template_id.upper())
            cve = cve_match.group(0) if cve_match else template_id
            
            if cve not in critical_vulns:
                critical_vulns[cve] = {
                    'name': info.get('name', 'Unknown'),
                    'cve': cve,
                    'severity': severity,
                    'description': info.get('description', 'No description'),
                    'ips': set(),
                    'method': 'nuclei'
                }
            
            # Extract IP from host
            host = finding.get('host', '')
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', host)
            if ip_match:
                critical_vulns[cve]['ips'].add(ip_match.group(1))
    
    # Write CRITICAL_VULNS.txt
    if critical_vulns:
        with open('CRITICAL_VULNS.txt', 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("CRITICAL AND HIGH SEVERITY VULNERABILITIES\n")
            f.write("="*80 + "\n\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Critical/High CVEs: {len(critical_vulns)}\n\n")
            
            # Sort by severity then by affected host count
            severity_order = {'CRITICAL': 0, 'HIGH': 1}
            sorted_vulns = sorted(critical_vulns.items(),
                                key=lambda x: (severity_order.get(x[1]['severity'], 2),
                                             -len(x[1]['ips'])))
            
            for idx, (cve, data) in enumerate(sorted_vulns, 1):
                f.write("="*80 + "\n")
                f.write(f"[{idx}] [{data['severity']}] {data['name']}\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"CVE: {data['cve']}\n")
                f.write(f"Detection Method: {data['method']}\n")
                f.write(f"Affected Hosts: {len(data['ips'])}\n\n")
                
                f.write("AFFECTED SYSTEMS:\n")
                f.write("-" * 40 + "\n")
                for ip in sorted(data['ips']):
                    f.write(f"  • {ip}\n")
                f.write("\n")
                
                f.write("DESCRIPTION:\n")
                f.write("-" * 40 + "\n")
                f.write(f"{data['description']}\n\n")
        
        print(f"{Colors.OKGREEN}[+] Critical vulnerabilities report: CRITICAL_VULNS.txt{Colors.ENDC}")
    
    # Generate vulnlist.txt (all vulnerable IPs)
    all_vuln_ips = set()
    for result in nmap_results:
        if result['vulnerabilities']:
            all_vuln_ips.add(result['ip'])
    
    for finding in nuclei_findings:
        # Skip if finding is not a dict
        if not isinstance(finding, dict):
            continue
            
        host = finding.get('host', '')
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', host)
        if ip_match:
            all_vuln_ips.add(ip_match.group(1))
    
    with open('vulnlist.txt', 'w') as f:
        for ip in sorted(all_vuln_ips):
            f.write(f"{ip}\n")
    
    print(f"{Colors.OKGREEN}[+] Vulnerable host list: vulnlist.txt{Colors.ENDC}")
    
    # Generate detailed JSON
    combined_results = {
        'scan_date': datetime.now().isoformat(),
        'nmap_results': nmap_results,
        'nuclei_findings': nuclei_findings,
        'summary': {
            'total_hosts_scanned': len(nmap_results),
            'vulnerable_hosts': len(all_vuln_ips),
            'critical_cves': len([v for v in critical_vulns.values() if v['severity'] == 'CRITICAL']),
            'high_cves': len([v for v in critical_vulns.values() if v['severity'] == 'HIGH'])
        }
    }
    
    with open('vuln_details.json', 'w', encoding='utf-8') as f:
        json.dump(combined_results, f, indent=2, default=str)
    
    print(f"{Colors.OKGREEN}[+] Detailed results: vuln_details.json{Colors.ENDC}")

def main():
    parser = argparse.ArgumentParser(
        description='VulnSeek v2.0 - Enhanced Multi-Method Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Quick nmap scan
  %(prog)s --nuclei                     # Add Nuclei CVE scan
  %(prog)s --metasploit                 # Add Metasploit checks
  %(prog)s --full --nuclei              # Full scan with all methods
  %(prog)s -f targets.txt --nuclei -v   # Verbose with Nuclei
        """
    )
    
    parser.add_argument('-f', '--file',
                       default='iplist.txt',
                       help='Input file with IP addresses (default: iplist.txt)')
    
    parser.add_argument('-w', '--workers',
                       type=int,
                       default=10,
                       help='Number of concurrent workers (default: 10)')
    
    parser.add_argument('--nuclei',
                       action='store_true',
                       help='Run Nuclei CVE scan (CVEs only, no web checks)')
    
    parser.add_argument('--metasploit',
                       action='store_true',
                       help='Use Metasploit modules for detection')
    
    parser.add_argument('--full',
                       action='store_true',
                       help='Full scan (all nmap checks, not just critical)')
    
    parser.add_argument('--timeout',
                       type=int,
                       default=2,
                       help='Connection timeout in seconds (default: 2)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check available tools
    tools = check_tools()
    
    print(f"{Colors.OKCYAN}[*] Tool Availability:{Colors.ENDC}")
    print(f"  {'✓' if tools['nmap'] else '✗'} nmap: {'Available' if tools['nmap'] else 'NOT FOUND'}")
    print(f"  {'✓' if tools['nuclei'] else '✗'} nuclei: {'Available' if tools['nuclei'] else 'NOT FOUND'}")
    print(f"  {'✓' if tools['msfconsole'] else '✗'} msfconsole: {'Available' if tools['msfconsole'] else 'NOT FOUND'}")
    print()
    
    if not tools['nmap']:
        print(f"{Colors.FAIL}[!] Error: nmap is required. Install with: sudo apt install nmap{Colors.ENDC}")
        return 1
    
    if args.nuclei and not tools['nuclei']:
        print(f"{Colors.WARNING}[!] Warning: Nuclei not found. Skipping Nuclei scan.{Colors.ENDC}")
        print(f"{Colors.WARNING}[*] Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest{Colors.ENDC}\n")
        args.nuclei = False
    
    if args.metasploit and not tools['msfconsole']:
        print(f"{Colors.WARNING}[!] Warning: Metasploit not found. Skipping Metasploit checks.{Colors.ENDC}\n")
        args.metasploit = False
    
    # Read IP list
    ips = read_ip_list(args.file)
    if not ips:
        print(f"{Colors.FAIL}[!] No valid IPs to scan{Colors.ENDC}")
        return 1
    
    print(f"\n{Colors.OKBLUE}[*] Starting vulnerability scan...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets: {len(ips)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Workers: {args.workers}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Nmap CVE Checks: {'Full' if args.full else 'Critical Only'}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Nuclei CVE Scan: {'Yes' if args.nuclei else 'No'}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Metasploit: {'Yes' if args.metasploit else 'No'}{Colors.ENDC}")
    print()
    
    # Phase 1: Nmap scanning
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Phase 1: Nmap CVE Scanning{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    nmap_results = []
    completed = 0
    vuln_found = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {
                executor.submit(scan_host_nmap, ip, args.timeout, not args.full): ip
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    nmap_results.append(result)
                    
                    if result['vulnerabilities']:
                        vuln_found += 1
                        
                        risk_color = Colors.FAIL if result['risk_level'] == 'CRITICAL' else Colors.WARNING
                        hostname_str = f" ({result['hostname']})" if result['hostname'] else ""
                        
                        print(f"{risk_color}[{result['risk_level']}]{Colors.ENDC} {result['ip']}{hostname_str}")
                        
                        for vuln in result['vulnerabilities']:
                            print(f"    {Colors.FAIL}⚠ {vuln['name']} ({vuln['cve']}){Colors.ENDC}")
                    
                    elif args.verbose:
                        print(f"[ ] {ip} - No nmap CVEs detected")
                    
                    if completed % 10 == 0:
                        print(f"\n{Colors.OKCYAN}[*] Progress: {completed}/{len(ips)} ({vuln_found} vulnerable){Colors.ENDC}\n")
                
                except Exception as e:
                    if args.verbose:
                        print(f"{Colors.FAIL}[!] Error scanning {ip}: {e}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
    
    # Phase 2: Nuclei CVE scanning
    nuclei_findings = []
    if args.nuclei and tools['nuclei']:
        print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
        print(f"{Colors.HEADER}Phase 2: Nuclei CVE Scanning{Colors.ENDC}")
        print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
        
        nuclei_findings = run_nuclei_cve_scan(ips)
    
    # Generate reports
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Generating Reports{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}\n")
    
    generate_reports(nmap_results, nuclei_findings)
    
    # Final summary
    print(f"\n{Colors.HEADER}{'='*70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Scan Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'='*70}{Colors.ENDC}")
    
    nmap_vuln_count = sum(1 for r in nmap_results if r['vulnerabilities'])
    
    nuclei_vuln_ips = set()
    for finding in nuclei_findings:
        # Skip if finding is not a dict
        if not isinstance(finding, dict):
            continue
            
        host = finding.get('host', '')
        ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', host)
        if ip_match:
            nuclei_vuln_ips.add(ip_match.group(1))
    
    print(f"Hosts Scanned: {len(ips)}")
    print(f"Nmap Vulnerable Hosts: {nmap_vuln_count}")
    if args.nuclei:
        print(f"Nuclei CVEs Found: {len(nuclei_findings)}")
        print(f"Nuclei Vulnerable Hosts: {len(nuclei_vuln_ips)}")
    
    print(f"\n{Colors.OKGREEN}Reports Generated:{Colors.ENDC}")
    print(f"  • CRITICAL_VULNS.txt - Priority vulnerabilities with affected IPs")
    print(f"  • vulnlist.txt - All vulnerable IPs")
    print(f"  • vuln_details.json - Complete scan results")
    if args.nuclei:
        print(f"  • nuclei_cve_results/ - Nuclei markdown reports")
    
    return 0

if __name__ == '__main__':
    exit(main())
