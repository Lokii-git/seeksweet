#!/usr/bin/env python3
"""
DCSeek - Domain Controller Discovery Tool
Reads IPs from iplist.txt and identifies potential Active Directory Domain Controllers
Can enumerate users and SMB shares using enum4linux
"""

import socket
import ipaddress
import subprocess
import sys
import argparse
import os
import re
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list

# Common DC ports
DC_PORTS = {
    53: "DNS",
    88: "Kerberos",
    389: "LDAP",
    445: "SMB",
    636: "LDAPS",
    3268: "Global Catalog",
    3269: "Global Catalog SSL"
}

# Minimum ports for DC detection (having these suggests it's likely a DC)
CRITICAL_DC_PORTS = {88, 389, 445}


def read_ip_list(filename: str) -> Set[str]:
    """Read and expand IP addresses from file"""
    ips = set()
    
    # Use shared utility to find the file
    filename = find_ip_list(filename)
    
    try:
        with open(filename, 'r') as f:
            line_number = 0
            for line in f:
                line_number += 1
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Handle CIDR notation
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        # Limit expansion for safety
                        host_count = network.num_addresses - 2  # Exclude network and broadcast
                        if host_count > 65534:
                            print(f"[!] Warning: Line {line_number}: CIDR {line} is too large (>{host_count} hosts). Skipping.")
                            continue
                        for ip in network.hosts():
                            ips.add(str(ip))
                    except ValueError as e:
                        print(f"[!] Warning: Line {line_number}: Invalid CIDR notation '{line}': {e}")
                else:
                    # Validate single IP
                    try:
                        ipaddress.ip_address(line)
                        ips.add(line)
                    except ValueError as e:
                        print(f"[!] Warning: Line {line_number}: Invalid IP address '{line}': {e}")
    except PermissionError:
        print(f"[!] Error: Permission denied reading {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading file {filename}: {e}")
        sys.exit(1)
    
    if not ips:
        print(f"[!] Error: No valid IP addresses found in {filename}")
        sys.exit(1)
    
    return ips


def check_port(ip: str, port: int, timeout: float = 1.0) -> bool:
    """Check if a port is open"""
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        return result == 0
    except socket.error as e:
        return False
    except Exception as e:
        return False
    finally:
        if sock:
            try:
                sock.close()
            except:
                pass


def get_hostname(ip: str) -> str:
    """Try to resolve hostname"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname else "N/A"
    except socket.herror:
        return "N/A"
    except socket.gaierror:
        return "N/A"
    except socket.timeout:
        return "N/A"
    except Exception as e:
        return "N/A"


def check_dns_srv_records(ip: str) -> List[str]:
    """Check for AD DNS SRV records"""
    srv_records = []
    
    # Try to query common AD SRV records
    srv_queries = [
        "_ldap._tcp.dc._msdcs",
        "_kerberos._tcp.dc._msdcs",
        "_gc._tcp"
    ]
    
    for query in srv_queries:
        try:
            result = subprocess.run(
                ['nslookup', '-type=SRV', query, ip],
                capture_output=True,
                text=True,
                timeout=3,
                stderr=subprocess.DEVNULL
            )
            if result.returncode == 0 and 'service' in result.stdout.lower():
                srv_records.append(query)
        except subprocess.TimeoutExpired:
            continue
        except FileNotFoundError:
            # nslookup not available
            break
        except Exception as e:
            continue
    
    return srv_records


def scan_host(ip: str, timeout: float = 1.0) -> Optional[dict]:
    """Scan a single host for DC indicators"""
    try:
        result = {
            'ip': ip,
            'hostname': None,
            'open_ports': {},
            'is_likely_dc': False,
            'srv_records': [],
            'error': None
        }
        
        # Validate IP
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            result['error'] = "Invalid IP address"
            return result
        
        # Get hostname
        result['hostname'] = get_hostname(ip)
        
        # Check DC ports
        open_dc_ports = set()
        for port, service in DC_PORTS.items():
            try:
                if check_port(ip, port, timeout):
                    result['open_ports'][port] = service
                    open_dc_ports.add(port)
            except Exception as e:
                continue
        
        # Check if it's likely a DC
        if CRITICAL_DC_PORTS.issubset(open_dc_ports):
            result['is_likely_dc'] = True
            # Check DNS SRV records if DNS is open
            if 53 in open_dc_ports:
                try:
                    result['srv_records'] = check_dns_srv_records(ip)
                except Exception as e:
                    pass
        
        return result
    except Exception as e:
        return {
            'ip': ip,
            'hostname': None,
            'open_ports': {},
            'is_likely_dc': False,
            'srv_records': [],
            'error': str(e)
        }


def parse_enum4linux_output(output: str, ip: str) -> Dict:
    """Parse enum4linux output for users and shares"""
    result = {
        'ip': ip,
        'users': [],
        'shares': [],
        'domain': None,
        'os_info': None,
        'groups': [],
        'password_policy': {}
    }
    
    lines = output.split('\n')
    
    # Parse domain info
    for line in lines:
        if 'Domain Name:' in line:
            match = re.search(r'Domain Name:\s*(\S+)', line)
            if match:
                result['domain'] = match.group(1)
        elif 'OS:' in line:
            result['os_info'] = line.strip()
    
    # Parse users (look for user list section)
    in_user_section = False
    for i, line in enumerate(lines):
        if 'Users on' in line or 'user:' in line.lower():
            in_user_section = True
        elif in_user_section:
            # Match patterns like: user:[username] rid:[0x...]
            user_match = re.search(r'user:\[([^\]]+)\]', line, re.IGNORECASE)
            if user_match:
                username = user_match.group(1)
                if username and username not in result['users']:
                    result['users'].append(username)
            # Exit section on empty line or new section
            elif line.strip() == '' or line.startswith('='):
                in_user_section = False
    
    # Parse shares
    in_share_section = False
    for i, line in enumerate(lines):
        if 'Share Enumeration' in line or 'Sharename' in line:
            in_share_section = True
            continue
        elif in_share_section:
            # Match share names (typically in format: Sharename   Type   Comment)
            if line.strip() and not line.startswith('=') and not line.startswith('-'):
                # Look for common share patterns
                share_match = re.match(r'\s*(\S+)\s+(Disk|IPC|Printer)', line)
                if share_match:
                    share_name = share_match.group(1)
                    share_type = share_match.group(2)
                    if share_name not in ['IPC$'] and share_name not in result['shares']:
                        result['shares'].append(share_name)
            elif 'Failed' in line or line.startswith('==='):
                in_share_section = False
    
    # Parse groups
    in_group_section = False
    for line in lines:
        if 'Group' in line and ('Members' in line or 'rid:' in line.lower()):
            in_group_section = True
        elif in_group_section:
            group_match = re.search(r'group:\[([^\]]+)\]', line, re.IGNORECASE)
            if group_match:
                group_name = group_match.group(1)
                if group_name and group_name not in result['groups']:
                    result['groups'].append(group_name)
    
    # Parse password policy
    for line in lines:
        if 'Minimum password length:' in line:
            match = re.search(r'Minimum password length:\s*(\d+)', line)
            if match:
                result['password_policy']['min_length'] = match.group(1)
        elif 'Password history length:' in line:
            match = re.search(r'Password history length:\s*(\d+)', line)
            if match:
                result['password_policy']['history_length'] = match.group(1)
        elif 'Maximum password age:' in line:
            result['password_policy']['max_age'] = line.split(':', 1)[1].strip()
        elif 'Password Complexity Flags:' in line:
            match = re.search(r'Password Complexity Flags:\s*(.+)', line)
            if match:
                result['password_policy']['complexity'] = match.group(1)
    
    return result


def run_enum4linux(ip: str, output_dir: str = "enum4linux_results") -> Optional[Dict]:
    """Run enum4linux on a target IP and parse results"""
    print(f"[*] Running enum4linux on {ip}...")
    
    # Create output directory if it doesn't exist
    try:
        os.makedirs(output_dir, exist_ok=True)
    except Exception as e:
        print(f"[!] Error creating directory {output_dir}: {e}")
        return None
    
    # Run enum4linux
    output_file = os.path.join(output_dir, f"enum4linux_{ip.replace('.', '_')}.txt")
    
    try:
        # Check if enum4linux is available
        check_cmd = subprocess.run(
            ['which', 'enum4linux'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if check_cmd.returncode != 0:
            # Try enum4linux-ng as alternative
            check_cmd = subprocess.run(
                ['which', 'enum4linux-ng'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if check_cmd.returncode != 0:
                print(f"[!] enum4linux not found. Install with: sudo apt install enum4linux")
                return None
            else:
                enum_cmd = 'enum4linux-ng'
        else:
            enum_cmd = 'enum4linux'
        
        # Run enum4linux with comprehensive options
        cmd = [enum_cmd, '-a', ip]  # -a = all simple enumeration
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        output = result.stdout + result.stderr
        
        # Save raw output
        try:
            with open(output_file, 'w') as f:
                f.write(f"Enum4linux scan of {ip}\n")
                f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*70 + "\n\n")
                f.write(output)
            print(f"[+] Enum4linux output saved to: {output_file}")
        except Exception as e:
            print(f"[!] Error saving enum4linux output: {e}")
        
        # Parse the output
        parsed = parse_enum4linux_output(output, ip)
        
        return parsed
        
    except subprocess.TimeoutExpired:
        print(f"[!] enum4linux timed out for {ip}")
        return None
    except FileNotFoundError:
        print(f"[!] enum4linux not found. Install with: sudo apt install enum4linux")
        return None
    except Exception as e:
        print(f"[!] Error running enum4linux on {ip}: {e}")
        return None


def save_dclist(domain_controllers: List[Dict], filename: str = "dclist.txt"):
    """Save discovered DCs to dclist.txt"""
    try:
        with open(filename, 'w') as f:
            for dc in domain_controllers:
                f.write(f"{dc['ip']}\n")
        print(f"[+] DC IP list saved to: {filename}")
        return True
    except Exception as e:
        print(f"[!] Error saving DC list: {e}")
        return False


def save_enum_summary(enum_results: List[Dict], filename: str = "enum4linux_summary.txt"):
    """Save parsed enum4linux results summary"""
    try:
        with open(filename, 'w') as f:
            f.write("DCSeek - Enum4linux Enumeration Summary\n")
            f.write("="*70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total DCs Enumerated: {len(enum_results)}\n")
            f.write("="*70 + "\n\n")
            
            for result in enum_results:
                f.write(f"\nTarget: {result['ip']}\n")
                f.write("-"*70 + "\n")
                
                if result.get('domain'):
                    f.write(f"Domain: {result['domain']}\n")
                if result.get('os_info'):
                    f.write(f"OS Info: {result['os_info']}\n")
                
                f.write(f"\nUsers Found ({len(result['users'])}):\n")
                if result['users']:
                    for user in result['users']:
                        f.write(f"  - {user}\n")
                else:
                    f.write("  (none)\n")
                
                f.write(f"\nSMB Shares Found ({len(result['shares'])}):\n")
                if result['shares']:
                    for share in result['shares']:
                        f.write(f"  - {share}\n")
                else:
                    f.write("  (none)\n")
                
                if result.get('groups'):
                    f.write(f"\nGroups Found ({len(result['groups'])}):\n")
                    for group in result['groups']:
                        f.write(f"  - {group}\n")
                
                if result.get('password_policy'):
                    f.write("\nPassword Policy:\n")
                    for key, value in result['password_policy'].items():
                        f.write(f"  {key}: {value}\n")
                
                f.write("\n" + "="*70 + "\n")
        
        print(f"[+] Enum4linux summary saved to: {filename}")
        
        # Also save JSON for easy parsing
        json_file = filename.replace('.txt', '.json')
        try:
            with open(json_file, 'w') as f:
                json.dump(enum_results, f, indent=2)
            print(f"[+] JSON summary saved to: {json_file}")
        except Exception as e:
            print(f"[!] Error saving JSON summary: {e}")
        
        return True
    except Exception as e:
        print(f"[!] Error saving enum summary: {e}")
        return False


def print_banner():
    """Print DCSeek banner"""
    banner = """
================================================================
                    DCSeek v1.1
          Domain Controller Discovery Tool
            with Enum4linux Integration
================================================================
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='DCSeek - Find Domain Controllers from IP list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default iplist.txt
  %(prog)s -f targets.txt               # Custom input file
  %(prog)s -w 20 -t 2 -v                # 20 workers, 2s timeout, verbose
  %(prog)s -f ips.txt -o results.txt    # Custom output file
  %(prog)s --enum                       # Run enum4linux on found DCs
  %(prog)s --enum --enum-only           # Only enumerate (skip DC discovery)
        """
    )
    parser.add_argument('-f', '--file', default='iplist.txt', help='Input file with IPs (default: iplist.txt)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-o', '--output', default='domain_controllers.txt', help='Output file (default: domain_controllers.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all scanned hosts')
    parser.add_argument('--enum', action='store_true', help='Run enum4linux on discovered DCs')
    parser.add_argument('--enum-only', action='store_true', help='Only run enum4linux on IPs from dclist.txt (skip discovery)')
    parser.add_argument('--dclist', default='dclist.txt', help='DC list file (default: dclist.txt)')
    parser.add_argument('--enum-dir', default='enum4linux_results', help='Directory for enum4linux results (default: enum4linux_results)')
    
    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit(1)
    
    # Validate arguments
    if args.timeout <= 0:
        print("[!] Error: Timeout must be greater than 0")
        sys.exit(1)
    
    if args.workers <= 0 or args.workers > 100:
        print("[!] Error: Workers must be between 1 and 100")
        sys.exit(1)
    
    print_banner()
    
    domain_controllers = []
    completed = 0
    errors = 0
    
    # Handle enum-only mode
    if args.enum_only:
        print(f"[*] Enum-only mode: Reading DCs from {args.dclist}")
        if not os.path.exists(args.dclist):
            print(f"[!] Error: {args.dclist} not found. Run discovery first without --enum-only")
            sys.exit(1)
        
        try:
            with open(args.dclist, 'r') as f:
                dc_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            for ip in dc_ips:
                domain_controllers.append({'ip': ip, 'hostname': 'N/A', 'open_ports': {}})
            
            print(f"[*] Loaded {len(domain_controllers)} DCs from {args.dclist}")
        except Exception as e:
            print(f"[!] Error reading {args.dclist}: {e}")
            sys.exit(1)
    else:
        # Normal discovery mode
        print(f"[*] Reading IPs from: {args.file}")
        
        try:
            ips = read_ip_list(args.file)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            sys.exit(1)
        
        print(f"[*] Found {len(ips)} IP addresses to scan")
        print(f"[*] Starting scan with {args.workers} workers (timeout: {args.timeout}s)...\n")
        
        all_results = []
        errors = 0
        completed = 0
        
        try:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {executor.submit(scan_host, ip, args.timeout): ip for ip in ips}
                
                for future in as_completed(futures):
                    completed += 1
                    try:
                        result = future.result()
                        if not result or result is None:
                            errors += 1
                            if args.verbose:
                                print(f"[!] {futures[future]}: Scan returned no result")
                            continue
                        
                        all_results.append(result)
                        
                        if result.get('error'):
                            errors += 1
                            if args.verbose:
                                print(f"[!] {result['ip']}: {result['error']}")
                            continue
                        
                        if result['is_likely_dc']:
                            domain_controllers.append(result)
                            print(f"[+] DOMAIN CONTROLLER FOUND: {result['ip']}")
                            if result['hostname'] != "N/A":
                                print(f"    Hostname: {result['hostname']}")
                            print(f"    Open DC Ports: {', '.join([f'{p} ({s})' for p, s in result['open_ports'].items()])}")
                            if result['srv_records']:
                                print(f"    DNS SRV Records: {', '.join(result['srv_records'])}")
                            print()
                        elif args.verbose and result['open_ports']:
                            print(f"[-] {result['ip']}: Open ports {list(result['open_ports'].keys())} (not a DC)")
                        
                        if completed % 50 == 0:
                            print(f"[*] Progress: {completed}/{len(ips)} hosts scanned")
                    except KeyboardInterrupt:
                        raise
                    except Exception as e:
                        errors += 1
                        if args.verbose:
                            print(f"[!] Error scanning {futures[future]}: {e}")
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            print(f"[*] Scanned {completed}/{len(ips)} hosts before interruption")
    
    # Summary
    print("\n" + "="*70)
    print("SCAN SUMMARY")
    print("="*70)
    if not args.enum_only:
        print(f"Total IPs scanned: {completed}")
    print(f"Domain Controllers found: {len(domain_controllers)}")
    if not args.enum_only and errors > 0:
        print(f"Errors encountered: {errors}")
    
    if domain_controllers:
        print("\nDOMAIN CONTROLLERS:")
        print("-"*70)
        for dc in domain_controllers:
            print(f"  {dc['ip']:<15} | {dc['hostname']}")
    else:
        print("\n[!] No Domain Controllers detected")
    
    # Save DC list to dclist.txt
    if domain_controllers and not args.enum_only:
        save_dclist(domain_controllers, args.dclist)
    
    # Save detailed results
    if domain_controllers and not args.enum_only:
        try:
            with open(args.output, 'w') as f:
                f.write("DCSeek - Domain Controllers Found\n")
                f.write("="*70 + "\n")
                f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                if completed > 0:
                    f.write(f"Total IPs Scanned: {completed}\n")
                f.write(f"Domain Controllers Found: {len(domain_controllers)}\n")
                f.write("="*70 + "\n\n")
                
                for dc in domain_controllers:
                    f.write(f"IP: {dc['ip']}\n")
                    f.write(f"Hostname: {dc.get('hostname', 'N/A')}\n")
                    if dc.get('open_ports'):
                        f.write(f"Open Ports: {', '.join([f'{p} ({s})' for p, s in dc['open_ports'].items()])}\n")
                    if dc.get('srv_records'):
                        f.write(f"DNS SRV Records: {', '.join(dc['srv_records'])}\n")
                    f.write("\n" + "-"*70 + "\n\n")
            print(f"\n[*] Results saved to: {args.output}")
        except PermissionError:
            print(f"\n[!] Error: Permission denied writing to {args.output}")
        except Exception as e:
            print(f"\n[!] Error saving results: {e}")
    
    # Run enum4linux if requested
    if args.enum or args.enum_only:
        if not domain_controllers:
            print("\n[!] No Domain Controllers to enumerate")
            sys.exit(0)
        
        print("\n" + "="*70)
        print("ENUM4LINUX ENUMERATION")
        print("="*70)
        print(f"[*] Starting enum4linux on {len(domain_controllers)} Domain Controllers...")
        print(f"[*] Results will be saved to: {args.enum_dir}/\n")
        
        enum_results = []
        
        for i, dc in enumerate(domain_controllers, 1):
            print(f"\n[{i}/{len(domain_controllers)}] Enumerating {dc['ip']}...")
            
            try:
                parsed = run_enum4linux(dc['ip'], args.enum_dir)
                
                if parsed:
                    enum_results.append(parsed)
                    
                    # Print summary
                    print(f"[+] Enumeration complete for {dc['ip']}")
                    if parsed.get('domain'):
                        print(f"    Domain: {parsed['domain']}")
                    print(f"    Users found: {len(parsed['users'])}")
                    print(f"    Shares found: {len(parsed['shares'])}")
                    
                    if parsed['users']:
                        print(f"    Sample users: {', '.join(parsed['users'][:5])}")
                    if parsed['shares']:
                        print(f"    Shares: {', '.join(parsed['shares'])}")
                else:
                    print(f"[-] No results from enum4linux for {dc['ip']}")
            
            except KeyboardInterrupt:
                print("\n[!] Enum4linux enumeration interrupted by user")
                break
            except Exception as e:
                print(f"[!] Error enumerating {dc['ip']}: {e}")
        
        # Save enum summary
        if enum_results:
            print("\n" + "="*70)
            print("ENUMERATION SUMMARY")
            print("="*70)
            
            total_users = sum(len(r['users']) for r in enum_results)
            total_shares = sum(len(r['shares']) for r in enum_results)
            
            print(f"DCs enumerated: {len(enum_results)}")
            print(f"Total unique users found: {total_users}")
            print(f"Total shares found: {total_shares}")
            
            save_enum_summary(enum_results, "enum4linux_summary.txt")
    
    sys.exit(0)


if __name__ == "__main__":
    main()
