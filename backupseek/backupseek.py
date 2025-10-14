#!/usr/bin/env python3
"""
BackupSeek v1.0 - Backup System Discovery Tool
Find and enumerate backup infrastructure

Features:
- Veeam Backup & Replication discovery
- Acronis Cyber Backup detection
- Bacula backup system enumeration
- Dell EMC Networker discovery
- IBM Spectrum Protect (TSM) detection
- Windows Server Backup detection
- Generic backup service discovery
- Backup schedule analysis

Usage:
    ./backupseek.py                        # Scan all backup systems
    ./backupseek.py --veeam                # Veeam only
    ./backupseek.py --acronis              # Acronis only
    ./backupseek.py --full                 # Full enumeration
    
Output:
    backuplist.txt      - Backup servers found
    backup_details.txt  - Detailed findings
    backup_details.json - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import argparse
import ipaddress
import requests
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

# Backup system ports
BACKUP_PORTS = {
    # Veeam
    9392: 'Veeam Backup Service',
    9393: 'Veeam Data Mover',
    9394: 'Veeam Agent',
    9395: 'Veeam Agent',
    9401: 'Veeam Cloud Connect',
    9419: 'Veeam Backup Enterprise Manager',
    6160: 'Veeam vPower NFS',
    6162: 'Veeam Mount Server',
    
    # Acronis
    9876: 'Acronis Backup',
    43234: 'Acronis Agent',
    44445: 'Acronis Management Server',
    
    # Bacula
    9101: 'Bacula Director',
    9102: 'Bacula File Daemon',
    9103: 'Bacula Storage Daemon',
    
    # Dell EMC Networker
    7937: 'Dell Networker',
    7938: 'Dell Networker NSR',
    7939: 'Dell Networker',
    
    # IBM Spectrum Protect (TSM)
    1500: 'IBM TSM/Spectrum Protect',
    1501: 'IBM TSM/Spectrum Protect',
    1581: 'IBM TSM Web Client',
    
    # CommVault
    8400: 'CommVault',
    8401: 'CommVault',
    8403: 'CommVault',
    
    # Veritas NetBackup
    1556: 'NetBackup',
    13701: 'NetBackup',
    13702: 'NetBackup',
    13720: 'NetBackup',
    13724: 'NetBackup',
    
    # Generic backup
    10000: 'Backup Exec',
    10080: 'Amanda Backup'
}

# Veeam web interfaces
VEEAM_WEB_PORTS = [9443, 9419, 9399]

# Banner - ASCII version for Windows compatibility
BANNER = f"""{CYAN}{BOLD}
=========================================================================
        BACKUPSEEK v1.0 - Backup System Discovery
=========================================================================
{RESET}
{YELLOW}Find and enumerate backup infrastructure{RESET}
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_ip_list(file_path):
    """Read IP addresses from a file (supports CIDR notation)"""
    # Use shared utility to find the file
    file_path = find_ip_list(file_path)
    
    ips = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ip_input = line.split()[0]
                    
                    # Check if CIDR notation
                    if '/' in ip_input:
                        try:
                            network = ipaddress.ip_network(ip_input, strict=False)
                            # Add all host IPs in the network
                            ips.extend([str(ip) for ip in network.hosts()])
                        except ValueError as e:
                            print(f"{YELLOW}[!] Invalid CIDR notation '{ip_input}': {e}{RESET}")
                    else:
                        ips.append(ip_input)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return ips


def check_port(ip, port, timeout=3):
    """Check if a TCP port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def detect_veeam_web(ip, timeout=5):
    """
    Detect Veeam web interface
    Returns: dict with findings
    """
    findings = []
    
    for port in VEEAM_WEB_PORTS:
        try:
            url = f'https://{ip}:{port}'
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            # Check for Veeam indicators in response
            if 'veeam' in response.text.lower() or 'backup' in response.headers.get('Server', '').lower():
                findings.append({
                    'type': 'veeam_web',
                    'url': url,
                    'port': port,
                    'status_code': response.status_code
                })
                
                # Try to identify specific Veeam component
                if 'enterprise manager' in response.text.lower():
                    findings[-1]['component'] = 'Enterprise Manager'
                elif 'cloud connect' in response.text.lower():
                    findings[-1]['component'] = 'Cloud Connect'
        except:
            continue
    
    return findings


def detect_acronis_web(ip, timeout=5):
    """
    Detect Acronis web interface
    Returns: dict with findings
    """
    findings = []
    
    acronis_ports = [9877, 44445]
    
    for port in acronis_ports:
        try:
            for protocol in ['https', 'http']:
                url = f'{protocol}://{ip}:{port}'
                response = requests.get(url, timeout=timeout, verify=False)
                
                if 'acronis' in response.text.lower():
                    findings.append({
                        'type': 'acronis_web',
                        'url': url,
                        'port': port,
                        'status_code': response.status_code
                    })
                    break
        except:
            continue
    
    return findings


def check_smb_backup_shares(ip, timeout=3):
    """
    Check for common backup share names
    Returns: list of backup shares found
    """
    backup_shares = []
    backup_share_names = ['Backup', 'Backups', 'VeeamBackup', 'BackupExec', 'Acronis']
    
    try:
        # List shares
        cmd = ['smbclient', '-L', f'//{ip}', '-N', '--timeout', str(timeout)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                for backup_name in backup_share_names:
                    if backup_name.lower() in line.lower() and 'Disk' in line:
                        parts = line.split()
                        if parts:
                            share_name = parts[0].strip()
                            backup_shares.append(share_name)
    except:
        pass
    
    return backup_shares


def identify_backup_system(open_ports):
    """
    Identify backup system based on open ports
    Returns: list of identified systems
    """
    systems = []
    
    # Veeam
    veeam_ports = [9392, 9393, 9401, 9419, 6160]
    if any(port in open_ports for port in veeam_ports):
        systems.append({
            'system': 'Veeam Backup & Replication',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in veeam_ports]
        })
    
    # Acronis
    acronis_ports = [9876, 43234, 44445]
    if any(port in open_ports for port in acronis_ports):
        systems.append({
            'system': 'Acronis Cyber Backup',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in acronis_ports]
        })
    
    # Bacula
    bacula_ports = [9101, 9102, 9103]
    if any(port in open_ports for port in bacula_ports):
        systems.append({
            'system': 'Bacula',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in bacula_ports]
        })
    
    # Dell Networker
    networker_ports = [7937, 7938, 7939]
    if any(port in open_ports for port in networker_ports):
        systems.append({
            'system': 'Dell EMC Networker',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in networker_ports]
        })
    
    # IBM Spectrum Protect
    tsm_ports = [1500, 1501, 1581]
    if any(port in open_ports for port in tsm_ports):
        systems.append({
            'system': 'IBM Spectrum Protect (TSM)',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in tsm_ports]
        })
    
    # CommVault
    commvault_ports = [8400, 8401, 8403]
    if any(port in open_ports for port in commvault_ports):
        systems.append({
            'system': 'CommVault',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in commvault_ports]
        })
    
    # NetBackup
    netbackup_ports = [1556, 13701, 13702, 13720, 13724]
    if any(port in open_ports for port in netbackup_ports):
        systems.append({
            'system': 'Veritas NetBackup',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in netbackup_ports]
        })
    
    return systems


def scan_host(ip, args):
    """
    Scan a single host for backup systems
    Returns: dict with findings
    """
    result = {
        'ip': ip,
        'open_ports': [],
        'identified_systems': [],
        'web_interfaces': [],
        'backup_shares': [],
        'status': 'no_backup'
    }
    
    try:
        # Determine which ports to scan
        ports_to_scan = []
        
        if args.veeam_only:
            ports_to_scan = [9392, 9393, 9401, 9419, 6160, 6162]
        elif args.acronis_only:
            ports_to_scan = [9876, 43234, 44445]
        elif args.full:
            ports_to_scan = list(BACKUP_PORTS.keys())
        else:
            # Common backup ports
            ports_to_scan = [
                9392, 9401,  # Veeam
                9876, 44445,  # Acronis
                9101, 9102, 9103,  # Bacula
                7937, 7938,  # Networker
                1500, 1581,  # TSM
                8400, 13701  # CommVault, NetBackup
            ]
        
        # Scan ports
        for port in ports_to_scan:
            if check_port(ip, port, timeout=args.timeout):
                result['open_ports'].append(port)
        
        if not result['open_ports']:
            return result
        
        # Identify backup systems
        result['identified_systems'] = identify_backup_system(result['open_ports'])
        
        if result['identified_systems']:
            result['status'] = 'backup_found'
        
        # Check for web interfaces
        if any('Veeam' in sys['system'] for sys in result['identified_systems']):
            veeam_web = detect_veeam_web(ip, timeout=args.timeout)
            if veeam_web:
                result['web_interfaces'].extend(veeam_web)
        
        if any('Acronis' in sys['system'] for sys in result['identified_systems']):
            acronis_web = detect_acronis_web(ip, timeout=args.timeout)
            if acronis_web:
                result['web_interfaces'].extend(acronis_web)
        
        # Check for backup shares (if SMB ports are open)
        if args.full:
            backup_shares = check_smb_backup_shares(ip, timeout=args.timeout)
            if backup_shares:
                result['backup_shares'] = backup_shares
    
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_backuplist(results, filename='backuplist.txt'):
    """Save list of backup servers"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['identified_systems']:
                    f.write(f"{result['ip']}\n")
        print(f"{GREEN}[+] Backup server list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving backup list: {e}{RESET}")


def save_details(results, filename='backup_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("BACKUPSEEK - Detailed Scan Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['identified_systems']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    # Identified systems
                    f.write(f"Backup Systems Detected:\n")
                    for system in result['identified_systems']:
                        f.write(f"  • {system['system']} (Confidence: {system['confidence']})\n")
                        f.write(f"    Ports: {', '.join(map(str, system['ports']))}\n")
                    
                    f.write(f"\n")
                    
                    # Open ports
                    if result['open_ports']:
                        f.write(f"Open Ports ({len(result['open_ports'])}):\n")
                        for port in result['open_ports']:
                            service = BACKUP_PORTS.get(port, 'Unknown')
                            f.write(f"  • {port} - {service}\n")
                        f.write(f"\n")
                    
                    # Web interfaces
                    if result['web_interfaces']:
                        f.write(f"Web Interfaces:\n")
                        for web in result['web_interfaces']:
                            component = web.get('component', 'Unknown')
                            f.write(f"  • {web['url']} - {component}\n")
                        f.write(f"\n")
                    
                    # Backup shares
                    if result['backup_shares']:
                        f.write(f"Backup Shares:\n")
                        for share in result['backup_shares']:
                            f.write(f"  • \\\\{result['ip']}\\{share}\n")
                        f.write(f"\n")
                    
                    # Exploitation notes
                    f.write(f"Exploitation Notes:\n")
                    for system in result['identified_systems']:
                        if 'Veeam' in system['system']:
                            f.write(f"  Veeam:\n")
                            f.write(f"    - Default creds: administrator/password or admin/admin\n")
                            f.write(f"    - Check Veeam database for credentials\n")
                            f.write(f"    - Backup files may contain domain credentials\n")
                        elif 'Acronis' in system['system']:
                            f.write(f"  Acronis:\n")
                            f.write(f"    - Default admin credentials may exist\n")
                            f.write(f"    - Check backup archive locations\n")
                        elif 'Bacula' in system['system']:
                            f.write(f"  Bacula:\n")
                            f.write(f"    - Check /etc/bacula/ for configuration\n")
                            f.write(f"    - Director password in bacula-dir.conf\n")
                    
                    f.write(f"\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='backup_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='BackupSeek - Backup System Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./backupseek.py iplist.txt                 # Scan common backup ports
  ./backupseek.py iplist.txt --full          # Full scan (all backup systems)
  ./backupseek.py iplist.txt --veeam         # Veeam only
  ./backupseek.py iplist.txt --acronis       # Acronis only
  ./backupseek.py iplist.txt -w 20           # Fast scan (20 workers)
  
Backup Systems Detected:
  - Veeam Backup & Replication
  - Acronis Cyber Backup
  - Bacula
  - Dell EMC Networker
  - IBM Spectrum Protect (TSM)
  - CommVault
  - Veritas NetBackup
        """
    )
    
    parser.add_argument('input_file', help='File containing IP addresses')
    parser.add_argument('--full', action='store_true', help='Full scan (all backup systems)')
    parser.add_argument('--veeam', dest='veeam_only', action='store_true', help='Scan for Veeam only')
    parser.add_argument('--acronis', dest='acronis_only', action='store_true', help='Scan for Acronis only')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read IPs
    ips = read_ip_list(args.input_file)
    
    if not ips:
        print(f"{RED}[!] No IPs to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting backup system scan...{RESET}")
    print(f"{CYAN}[*] Targets: {len(ips)}{RESET}")
    print(f"{CYAN}[*] Workers: {args.workers}{RESET}")
    mode = 'Veeam' if args.veeam_only else 'Acronis' if args.acronis_only else 'Full' if args.full else 'Common'
    print(f"{CYAN}[*] Mode: {mode}{RESET}")
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
                    
                    if result['identified_systems']:
                        systems = ', '.join([s['system'] for s in result['identified_systems']])
                        
                        severity = f"{RED}[BACKUP]{RESET}"
                        msg = f"{severity} {ip} - {systems}"
                        
                        if result['web_interfaces']:
                            msg += f" {GREEN}[WEB]{RESET}"
                        
                        if result['backup_shares']:
                            msg += f" {YELLOW}[SHARES]{RESET}"
                        
                        print(msg)
                    
                    elif args.verbose:
                        print(f"{BLUE}[*]{RESET} {ip} - No backup systems detected")
                
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
    
    backup_servers = len([r for r in results if r['identified_systems']])
    
    # Count by system type
    system_counts = {}
    for result in results:
        for system in result['identified_systems']:
            system_name = system['system']
            system_counts[system_name] = system_counts.get(system_name, 0) + 1
    
    print(f"Backup servers found: {backup_servers}/{len(ips)}")
    
    if system_counts:
        print(f"\nBreakdown by system:")
        for system, count in sorted(system_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {system}: {count}")
    
    # Save results
    if results:
        save_backuplist(results)
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")
    
    # Print exploitation tips
    if backup_servers > 0:
        print(f"\n{YELLOW}[*] Exploitation Tips:{RESET}")
        print(f"  • Backup systems often contain domain credentials")
        print(f"  • Check for default credentials on web interfaces")
        print(f"  • Veeam databases contain encrypted credentials")
        print(f"  • Backup files may have weak passwords or none at all")
        print(f"  • Look for backup shares with sensitive data")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
