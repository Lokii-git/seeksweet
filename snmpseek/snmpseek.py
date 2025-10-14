#!/usr/bin/env python3
"""
SNMPSeek v1.0 - Enhanced SNMP Enumeration Tool
Comprehensive SNMP scanning and exploitation

Features:
- SNMP port scanning (161 UDP)
- Community string bruteforce (public, private, common strings)
- MIB walking and information extraction
- Writable SNMP detection
- SNMPv3 enumeration and testing
- Device information extraction
- Network device configuration extraction

Usage:
    ./snmpseek.py                          # Basic SNMP discovery
    ./snmpseek.py --bruteforce             # Bruteforce community strings
    ./snmpseek.py --walk                   # MIB walk discovered devices
    ./snmpseek.py -c custom1,custom2       # Custom community strings
    ./snmpseek.py --writable               # Test for writable SNMP
    
Output:
    snmplist.txt        - SNMP enabled hosts
    snmp_creds.txt      - Valid community strings
    snmp_info.txt       - Extracted device information
    snmp_details.txt    - Detailed findings
    snmp_details.json   - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

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

# SNMP ports
SNMP_PORTS = {
    161: 'SNMP',
    162: 'SNMP Trap'
}

# Common community strings to test
COMMON_COMMUNITY_STRINGS = [
    'public',
    'private',
    'community',
    'snmp',
    'manager',
    'admin',
    'cisco',
    'password',
    'secret',
    'default',
    'read',
    'write',
    'monitor',
    'test',
    'guest',
    'root',
    'network',
    'switch',
    'router'
]

# Common OIDs to query
COMMON_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',        # System description
    'sysObjectID': '1.3.6.1.2.1.1.2.0',     # System object ID
    'sysUpTime': '1.3.6.1.2.1.1.3.0',       # System uptime
    'sysContact': '1.3.6.1.2.1.1.4.0',      # System contact
    'sysName': '1.3.6.1.2.1.1.5.0',         # System name
    'sysLocation': '1.3.6.1.2.1.1.6.0',     # System location
    'sysServices': '1.3.6.1.2.1.1.7.0',     # System services
    'ifNumber': '1.3.6.1.2.1.2.1.0',        # Number of interfaces
    'ifDescr': '1.3.6.1.2.1.2.2.1.2',       # Interface description
    'ipAdEntAddr': '1.3.6.1.2.1.4.20.1.1',  # IP addresses
    'ipRouteNextHop': '1.3.6.1.2.1.4.21.1.7', # Routing table
    'hrStorageDescr': '1.3.6.1.2.1.25.2.3.1.3', # Storage description
    'hrProcessorLoad': '1.3.6.1.2.1.25.3.3.1.2' # CPU load
}

# Writable OIDs to test
WRITABLE_OIDS = [
    '1.3.6.1.2.1.1.4.0',  # sysContact
    '1.3.6.1.2.1.1.5.0',  # sysName
    '1.3.6.1.2.1.1.6.0'   # sysLocation
]

# Banner
BANNER = f"""{CYAN}{BOLD}
███████╗███╗   ██╗███╗   ███╗██████╗ ███████╗███████╗███████╗██╗  ██╗
██╔════╝████╗  ██║████╗ ████║██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
███████╗██╔██╗ ██║██╔████╔██║██████╔╝███████╗█████╗  █████╗  █████╔╝ 
╚════██║██║╚██╗██║██║╚██╔╝██║██╔═══╝ ╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
███████║██║ ╚████║██║ ╚═╝ ██║██║     ███████║███████╗███████╗██║  ██╗
╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}SNMPSeek v1.0 - Enhanced SNMP Enumeration{RESET}
{BLUE}Comprehensive SNMP scanning and exploitation{RESET}
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


def check_snmp_port(ip, port=161, timeout=2):
    """
    Check if SNMP port is open (UDP)
    Returns: True if port responds
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # Send a simple SNMP GET request
        # This is a minimal SNMP v1 GET request for sysDescr
        snmp_request = bytes([
            0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62,
            0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x04, 0x00, 0x00, 0x00,
            0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30,
            0x09, 0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00
        ])
        
        sock.sendto(snmp_request, (ip, port))
        data, addr = sock.recvfrom(1024)
        sock.close()
        
        return len(data) > 0
    except:
        return False


def test_community_string(ip, community, timeout=3):
    """
    Test a community string using snmpget
    Returns: dict with result
    """
    result = {
        'community': community,
        'valid': False,
        'readable': False,
        'writable': False
    }
    
    try:
        # Test read access with sysDescr OID
        cmd = ['snmpget', '-v2c', '-c', community, '-t', str(timeout), ip, COMMON_OIDS['sysDescr']]
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if proc_result.returncode == 0 and 'Timeout' not in proc_result.stdout:
            result['valid'] = True
            result['readable'] = True
    
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        result['error'] = 'snmpget not found (install snmp package)'
    except Exception as e:
        result['error'] = str(e)
    
    return result


def snmp_get(ip, community, oid, timeout=3):
    """
    Get SNMP value for a specific OID
    Returns: value or None
    """
    try:
        cmd = ['snmpget', '-v2c', '-c', community, '-t', str(timeout), '-Oqv', ip, oid]
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if proc_result.returncode == 0:
            return proc_result.stdout.strip().strip('"')
    except:
        pass
    
    return None


def snmp_walk(ip, community, oid, timeout=5):
    """
    Perform SNMP walk on an OID
    Returns: list of (oid, value) tuples
    """
    results = []
    
    try:
        cmd = ['snmpwalk', '-v2c', '-c', community, '-t', str(timeout), '-Oq', ip, oid]
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+5)
        
        if proc_result.returncode == 0:
            for line in proc_result.stdout.split('\n'):
                if line.strip():
                    parts = line.split(' ', 1)
                    if len(parts) == 2:
                        results.append((parts[0], parts[1].strip().strip('"')))
    except:
        pass
    
    return results


def test_writable_snmp(ip, community, timeout=3):
    """
    Test if SNMP community string has write access
    Returns: True if writable
    """
    try:
        # Try to set sysContact (usually allowed if writable)
        test_value = "SNMPSEEK_TEST"
        cmd = ['snmpset', '-v2c', '-c', community, '-t', str(timeout), 
               ip, WRITABLE_OIDS[0], 's', test_value]
        
        proc_result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if proc_result.returncode == 0:
            # Restore original value if possible
            cmd_restore = ['snmpset', '-v2c', '-c', community, '-t', str(timeout),
                          ip, WRITABLE_OIDS[0], 's', '']
            subprocess.run(cmd_restore, capture_output=True, timeout=timeout+2)
            return True
    except:
        pass
    
    return False


def extract_device_info(ip, community, timeout=5):
    """
    Extract common device information via SNMP
    Returns: dict with device info
    """
    info = {}
    
    for name, oid in COMMON_OIDS.items():
        value = snmp_get(ip, community, oid, timeout=timeout)
        if value:
            info[name] = value
    
    return info


def scan_host(ip, args):
    """
    Scan a single host for SNMP
    Returns: dict with findings
    """
    result = {
        'ip': ip,
        'snmp_open': False,
        'valid_communities': [],
        'writable_communities': [],
        'device_info': {},
        'status': 'closed'
    }
    
    try:
        # Check if SNMP port is open
        if not check_snmp_port(ip, timeout=args.timeout):
            return result
        
        result['snmp_open'] = True
        result['status'] = 'open'
        
        # Build community string list
        communities = []
        
        if args.bruteforce:
            communities.extend(COMMON_COMMUNITY_STRINGS)
        else:
            communities.append('public')
            communities.append('private')
        
        if args.communities:
            communities.extend(args.communities.split(','))
        
        # Remove duplicates
        communities = list(set(communities))
        
        # Test community strings
        for community in communities:
            test_result = test_community_string(ip, community, timeout=args.timeout)
            
            if test_result['valid']:
                result['valid_communities'].append(community)
                
                # Extract device info from first valid community
                if not result['device_info']:
                    result['device_info'] = extract_device_info(ip, community, timeout=args.timeout)
                
                # Test for write access if requested
                if args.writable:
                    if test_writable_snmp(ip, community, timeout=args.timeout):
                        result['writable_communities'].append(community)
                
                # Only test first valid community unless full bruteforce
                if not args.bruteforce:
                    break
        
        # Perform MIB walk if requested and we have valid community
        if args.walk and result['valid_communities']:
            community = result['valid_communities'][0]
            
            # Walk interesting OIDs
            walk_results = {}
            for name, oid in [('interfaces', COMMON_OIDS['ifDescr']), 
                            ('ip_addresses', COMMON_OIDS['ipAdEntAddr'])]:
                walk_data = snmp_walk(ip, community, oid, timeout=args.timeout*2)
                if walk_data:
                    walk_results[name] = walk_data[:10]  # Limit output
            
            if walk_results:
                result['walk_results'] = walk_results
        
        if result['valid_communities']:
            result['status'] = 'accessible'
    
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_snmplist(results, filename='snmplist.txt'):
    """Save list of SNMP enabled hosts"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['snmp_open']:
                    f.write(f"{result['ip']}\n")
        print(f"{GREEN}[+] SNMP host list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving SNMP list: {e}{RESET}")


def save_snmp_creds(results, filename='snmp_creds.txt'):
    """Save valid community strings"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SNMPSEEK - Valid Community Strings\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['valid_communities']:
                    f.write(f"\nHost: {result['ip']}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    for community in result['valid_communities']:
                        access = 'READ/WRITE' if community in result.get('writable_communities', []) else 'READ'
                        f.write(f"  Community: {community} ({access})\n")
                    
                    f.write("\n")
        
        print(f"{GREEN}[+] Valid community strings saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving credentials: {e}{RESET}")


def save_snmp_info(results, filename='snmp_info.txt'):
    """Save extracted device information"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SNMPSEEK - Device Information\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['device_info']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    info = result['device_info']
                    
                    if 'sysDescr' in info:
                        f.write(f"Description: {info['sysDescr']}\n")
                    if 'sysName' in info:
                        f.write(f"Name: {info['sysName']}\n")
                    if 'sysLocation' in info:
                        f.write(f"Location: {info['sysLocation']}\n")
                    if 'sysContact' in info:
                        f.write(f"Contact: {info['sysContact']}\n")
                    if 'sysUpTime' in info:
                        f.write(f"Uptime: {info['sysUpTime']}\n")
                    
                    f.write("\n")
                    
                    # Walk results
                    if 'walk_results' in result:
                        for category, data in result['walk_results'].items():
                            f.write(f"{category.upper()}:\n")
                            for oid, value in data:
                                f.write(f"  {value}\n")
                            f.write("\n")
        
        print(f"{GREEN}[+] Device information saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving device info: {e}{RESET}")


def save_details(results, filename='snmp_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SNMPSEEK - Detailed Scan Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['status'] != 'closed':
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"Status: {result['status'].upper()}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    if result['valid_communities']:
                        f.write(f"Valid Communities ({len(result['valid_communities'])}):\n")
                        for community in result['valid_communities']:
                            f.write(f"  • {community}\n")
                        f.write("\n")
                    
                    if result['writable_communities']:
                        f.write(f"⚠ WRITABLE Communities ({len(result['writable_communities'])}):\n")
                        for community in result['writable_communities']:
                            f.write(f"  • {community}\n")
                        f.write("\n")
                    
                    if result['device_info']:
                        f.write("Device Information:\n")
                        for key, value in result['device_info'].items():
                            f.write(f"  {key}: {value[:100]}\n")
                        f.write("\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='snmp_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='SNMPSeek - Enhanced SNMP Enumeration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./snmpseek.py iplist.txt                       # Basic discovery (public/private)
  ./snmpseek.py iplist.txt --bruteforce          # Bruteforce community strings
  ./snmpseek.py iplist.txt --walk                # MIB walk discovered devices
  ./snmpseek.py iplist.txt -c custom1,custom2    # Custom community strings
  ./snmpseek.py iplist.txt --writable            # Test for write access
  ./snmpseek.py iplist.txt -w 20 --bruteforce    # Fast bruteforce scan
  
Manual enumeration:
  snmpwalk -v2c -c public 192.168.1.1
  snmpget -v2c -c private 192.168.1.1 1.3.6.1.2.1.1.5.0
        """
    )
    
    parser.add_argument('input_file', help='File containing IP addresses')
    parser.add_argument('--bruteforce', action='store_true', help='Bruteforce common community strings')
    parser.add_argument('--walk', action='store_true', help='Perform MIB walk on discovered devices')
    parser.add_argument('--writable', action='store_true', help='Test for writable SNMP')
    parser.add_argument('-c', '--communities', help='Comma-separated list of community strings to test')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='SNMP timeout in seconds (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read IPs
    ips = read_ip_list(args.input_file)
    
    if not ips:
        print(f"{RED}[!] No IPs to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting SNMP scan...{RESET}")
    print(f"{CYAN}[*] Targets: {len(ips)}{RESET}")
    print(f"{CYAN}[*] Workers: {args.workers}{RESET}")
    print(f"{CYAN}[*] Bruteforce: {'Yes' if args.bruteforce else 'No'}{RESET}")
    print(f"{CYAN}[*] MIB Walk: {'Yes' if args.walk else 'No'}{RESET}")
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
                    
                    if result['valid_communities']:
                        severity = f"{RED}[CRITICAL]{RESET}" if result['writable_communities'] else f"{YELLOW}[HIGH]{RESET}"
                        
                        msg = f"{severity} {ip}"
                        msg += f" - {', '.join(result['valid_communities'])}"
                        
                        if result['writable_communities']:
                            msg += f" {RED}[WRITABLE]{RESET}"
                        
                        if result['device_info'].get('sysName'):
                            msg += f" ({result['device_info']['sysName']})"
                        
                        print(msg)
                    
                    elif result['snmp_open']:
                        if args.verbose:
                            print(f"{BLUE}[*]{RESET} {ip} - SNMP open, no valid communities")
                    
                    elif args.verbose:
                        print(f"{BLUE}[*]{RESET} {ip} - SNMP closed")
                
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
    
    snmp_hosts = len([r for r in results if r['snmp_open']])
    accessible_hosts = len([r for r in results if r['valid_communities']])
    writable_hosts = len([r for r in results if r['writable_communities']])
    
    print(f"SNMP enabled hosts: {snmp_hosts}/{len(ips)}")
    print(f"Accessible hosts: {accessible_hosts}")
    print(f"Writable hosts: {writable_hosts}")
    
    # Save results
    if results:
        save_snmplist(results)
        
        if accessible_hosts > 0:
            save_snmp_creds(results)
            save_snmp_info(results)
        
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
