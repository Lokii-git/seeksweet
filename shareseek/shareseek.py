#!/usr/bin/env python3
"""
ShareSeek v1.0 - Network Share Discovery Tool

Discovers network file shares including:
- NFS shares (Network File System)
- FTP servers (File Transfer Protocol)
- WebDAV (Web-based Distributed Authoring and Versioning)
- TFTP (Trivial FTP)
- rsync servers

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

# Share service ports
SHARE_PORTS = {
    21: 'FTP',
    69: 'TFTP',
    873: 'rsync',
    2049: 'NFS',
    80: 'HTTP/WebDAV',
    443: 'HTTPS/WebDAV',
    8080: 'HTTP-Alt/WebDAV'
}

# WebDAV detection paths
WEBDAV_PATHS = ['/', '/webdav', '/dav', '/remote.php/webdav', '/servlet/webdav']

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════╗
║                   ShareSeek v1.0                          ║
║             Network Share Discovery Tool                  ║
║              github.com/Lokii-git/seeksweet               ║
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

def check_ftp(ip: str, timeout: int = 10) -> Dict:
    """
    Check FTP server and test for anonymous access
    
    Returns:
        Dict with FTP information
    """
    result = {
        'enabled': False,
        'banner': None,
        'anonymous': False,
        'error': None
    }
    
    try:
        # Try to connect and get banner
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, 21))
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        result['banner'] = banner
        result['enabled'] = True
        
        # Test anonymous login
        sock.send(b'USER anonymous\r\n')
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        
        if '331' in response or '230' in response:
            sock.send(b'PASS anonymous@\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '230' in response:
                result['anonymous'] = True
        
        sock.close()
        
    except socket.timeout:
        result['error'] = 'Timeout'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_nfs(ip: str, timeout: int = 10) -> Dict:
    """
    Check for NFS shares using showmount
    
    Returns:
        Dict with NFS information
    """
    result = {
        'enabled': False,
        'exports': [],
        'error': None
    }
    
    try:
        # Run showmount -e
        proc = subprocess.run(
            ['showmount', '-e', ip],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout
        
        if proc.returncode == 0 and output:
            result['enabled'] = True
            
            # Parse exports
            for line in output.split('\n')[1:]:  # Skip header
                line = line.strip()
                if line:
                    parts = line.split()
                    if parts:
                        export_path = parts[0]
                        clients = ' '.join(parts[1:]) if len(parts) > 1 else '*'
                        result['exports'].append({
                            'path': export_path,
                            'clients': clients
                        })
        else:
            result['error'] = 'No exports or access denied'
            
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'showmount not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_webdav(ip: str, port: int = 80, timeout: int = 10) -> Dict:
    """
    Check for WebDAV using OPTIONS request
    
    Returns:
        Dict with WebDAV information
    """
    result = {
        'enabled': False,
        'methods': [],
        'paths': [],
        'error': None
    }
    
    import http.client
    import ssl
    
    for path in WEBDAV_PATHS:
        try:
            # Create connection
            if port in [443, 8443]:
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(ip, port, timeout=timeout)
            
            # Send OPTIONS request
            conn.request('OPTIONS', path)
            response = conn.getresponse()
            
            # Check for WebDAV methods
            allow_header = response.getheader('Allow')
            dav_header = response.getheader('DAV')
            
            if allow_header or dav_header:
                webdav_methods = ['PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK']
                
                if allow_header and any(method in allow_header.upper() for method in webdav_methods):
                    result['enabled'] = True
                    result['methods'] = allow_header.split(',')
                    result['paths'].append(path)
                
                if dav_header:
                    result['enabled'] = True
                    if path not in result['paths']:
                        result['paths'].append(path)
            
            conn.close()
            
            if result['enabled']:
                break  # Found WebDAV, no need to check other paths
                
        except Exception as e:
            continue
    
    if not result['enabled'] and not result['paths']:
        result['error'] = 'Not detected'
    
    return result

def check_rsync(ip: str, timeout: int = 10) -> Dict:
    """
    Check for rsync shares
    
    Returns:
        Dict with rsync information
    """
    result = {
        'enabled': False,
        'modules': [],
        'error': None
    }
    
    try:
        # Run rsync list modules
        proc = subprocess.run(
            ['rsync', f'rsync://{ip}/'],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        output = proc.stdout
        
        if output and 'MOTD' not in output and '@ERROR' not in output:
            result['enabled'] = True
            
            # Parse modules
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    if parts:
                        module_name = parts[0]
                        comment = ' '.join(parts[1:]) if len(parts) > 1 else ''
                        result['modules'].append({
                            'name': module_name,
                            'comment': comment
                        })
        else:
            result['error'] = 'No modules or access denied'
            
    except subprocess.TimeoutExpired:
        result['error'] = 'Timeout'
    except FileNotFoundError:
        result['error'] = 'rsync not found'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def check_tftp(ip: str, timeout: int = 5) -> Dict:
    """
    Check for TFTP server (UDP)
    
    Returns:
        Dict with TFTP information
    """
    result = {
        'enabled': False,
        'error': None
    }
    
    try:
        # TFTP uses UDP, try to send a read request for a non-existent file
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        
        # TFTP RRQ packet for a test file
        request = b'\x00\x01' + b'test.txt' + b'\x00' + b'octet' + b'\x00'
        
        sock.sendto(request, (ip, 69))
        
        # Wait for response
        response, addr = sock.recvfrom(1024)
        
        # Any response means TFTP is running
        if response:
            result['enabled'] = True
        
        sock.close()
        
    except socket.timeout:
        result['error'] = 'Timeout (may not be running)'
    except Exception as e:
        result['error'] = str(e)
    
    return result

def scan_host(ip: str, timeout: int = 2, test_access: bool = False) -> Dict:
    """
    Scan a single host for network shares
    
    Args:
        ip: IP address to scan
        timeout: Connection timeout
        test_access: Whether to test share access
        
    Returns:
        Dict with scan results
    """
    result = {
        'ip': ip,
        'hostname': None,
        'shares_found': False,
        'services': {},
        'accessible_shares': [],
        'anonymous_access': False,
        'error': None
    }
    
    # Get hostname
    hostname = get_hostname(ip)
    if hostname:
        result['hostname'] = hostname
    
    # Check all share ports
    open_ports = []
    for port, service in SHARE_PORTS.items():
        if check_port(ip, port, timeout):
            open_ports.append({'port': port, 'service': service})
    
    if not open_ports:
        result['error'] = 'No share ports open'
        return result
    
    # Check each service
    for port_info in open_ports:
        port = port_info['port']
        service = port_info['service']
        
        if port == 21:  # FTP
            ftp_info = check_ftp(ip, timeout=10)
            if ftp_info['enabled']:
                result['services']['FTP'] = ftp_info
                result['shares_found'] = True
                if ftp_info['anonymous']:
                    result['anonymous_access'] = True
                    result['accessible_shares'].append({
                        'type': 'FTP',
                        'path': f'ftp://{ip}',
                        'anonymous': True
                    })
        
        elif port == 2049:  # NFS
            nfs_info = check_nfs(ip, timeout=10)
            if nfs_info['enabled']:
                result['services']['NFS'] = nfs_info
                result['shares_found'] = True
                for export in nfs_info['exports']:
                    result['accessible_shares'].append({
                        'type': 'NFS',
                        'path': f'{ip}:{export["path"]}',
                        'clients': export['clients']
                    })
        
        elif port == 873:  # rsync
            rsync_info = check_rsync(ip, timeout=10)
            if rsync_info['enabled']:
                result['services']['rsync'] = rsync_info
                result['shares_found'] = True
                for module in rsync_info['modules']:
                    result['accessible_shares'].append({
                        'type': 'rsync',
                        'path': f'rsync://{ip}/{module["name"]}',
                        'comment': module['comment']
                    })
        
        elif port == 69:  # TFTP
            tftp_info = check_tftp(ip, timeout=5)
            if tftp_info['enabled']:
                result['services']['TFTP'] = tftp_info
                result['shares_found'] = True
                result['accessible_shares'].append({
                    'type': 'TFTP',
                    'path': f'tftp://{ip}',
                    'note': 'UDP service'
                })
        
        elif port in [80, 443, 8080]:  # WebDAV
            webdav_info = check_webdav(ip, port, timeout=10)
            if webdav_info['enabled']:
                result['services'][f'WebDAV:{port}'] = webdav_info
                result['shares_found'] = True
                for path in webdav_info['paths']:
                    protocol = 'https' if port in [443, 8443] else 'http'
                    result['accessible_shares'].append({
                        'type': 'WebDAV',
                        'path': f'{protocol}://{ip}:{port}{path}',
                        'methods': webdav_info['methods']
                    })
    
    return result

def save_share_list(results: List[Dict], filename: str = 'sharelist.txt'):
    """Save list of share URLs/paths to a file"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['accessible_shares']:
                    for share in result['accessible_shares']:
                        f.write(f"{share['path']}\n")
        
        print(f"\n{Colors.OKGREEN}[+] Share list saved to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error saving share list: {e}{Colors.ENDC}")

def save_details(results: List[Dict], txt_filename: str = 'share_details.txt', 
                json_filename: str = 'share_details.json'):
    """Save detailed scan results"""
    # Save TXT format
    try:
        with open(txt_filename, 'w') as f:
            f.write("ShareSeek - Network Share Discovery Results\n")
            f.write("=" * 70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            share_hosts = [r for r in results if r['shares_found']]
            
            f.write(f"Total Hosts with Shares: {len(share_hosts)}\n")
            f.write("=" * 70 + "\n\n")
            
            for result in share_hosts:
                f.write(f"Host: {result['ip']}\n")
                if result['hostname']:
                    f.write(f"Hostname: {result['hostname']}\n")
                
                if result['anonymous_access']:
                    f.write("⚠ ANONYMOUS ACCESS ALLOWED\n")
                
                f.write(f"Services Found: {', '.join(result['services'].keys())}\n")
                f.write("-" * 70 + "\n")
                
                for service_name, service_info in result['services'].items():
                    f.write(f"\n  Service: {service_name}\n")
                    
                    if service_name == 'FTP':
                        if service_info.get('banner'):
                            f.write(f"  Banner: {service_info['banner']}\n")
                        if service_info.get('anonymous'):
                            f.write(f"  Anonymous Access: YES\n")
                    
                    elif service_name == 'NFS':
                        if service_info.get('exports'):
                            f.write(f"  Exports:\n")
                            for export in service_info['exports']:
                                f.write(f"    {export['path']} ({export['clients']})\n")
                    
                    elif service_name == 'rsync':
                        if service_info.get('modules'):
                            f.write(f"  Modules:\n")
                            for module in service_info['modules']:
                                f.write(f"    {module['name']}")
                                if module['comment']:
                                    f.write(f" - {module['comment']}")
                                f.write("\n")
                    
                    elif service_name.startswith('WebDAV'):
                        if service_info.get('paths'):
                            f.write(f"  Paths: {', '.join(service_info['paths'])}\n")
                        if service_info.get('methods'):
                            f.write(f"  Methods: {', '.join(service_info['methods'])}\n")
                
                f.write("\n")
                
                if result['accessible_shares']:
                    f.write(f"Accessible Shares ({len(result['accessible_shares'])}):\n")
                    for share in result['accessible_shares']:
                        f.write(f"  ✓ {share['path']}\n")
                
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
        description='ShareSeek v1.0 - Network Share Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Basic scan
  %(prog)s -v                           # Verbose output
  %(prog)s -f targets.txt -v            # Custom file, verbose
  %(prog)s -w 20                        # 20 concurrent workers
        """
    )
    
    parser.add_argument('-f', '--file', 
                       default='iplist.txt',
                       help='Input file with IP addresses (default: iplist.txt)')
    
    parser.add_argument('-w', '--workers', 
                       type=int, 
                       default=10,
                       help='Number of concurrent workers (default: 10)')
    
    parser.add_argument('--timeout',
                       type=int,
                       default=2,
                       help='Connection timeout in seconds (default: 2)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output (show all hosts)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check for required tools
    tools = ['showmount', 'rsync']
    missing_tools = []
    for tool in tools:
        try:
            subprocess.run([tool, '--version'], capture_output=True, timeout=2)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Colors.WARNING}[!] Warning: Missing tools: {', '.join(missing_tools)}{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Install with: sudo apt install nfs-common rsync{Colors.ENDC}\n")
    
    # Read IP list
    ips = read_ip_list(args.file)
    if not ips:
        print(f"{Colors.FAIL}[!] No valid IPs to scan{Colors.ENDC}")
        return 1
    
    print(f"\n{Colors.OKBLUE}[*] Starting share discovery...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets: {len(ips)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Workers: {args.workers}{Colors.ENDC}")
    print()
    
    # Scan hosts
    results = []
    completed = 0
    shares_found = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {
                executor.submit(scan_host, ip, args.timeout, False): ip 
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['shares_found']:
                        shares_found += 1
                        
                        confidence = f"{Colors.OKGREEN}[HIGH]{Colors.ENDC}" if result['accessible_shares'] else f"{Colors.OKBLUE}[MEDIUM]{Colors.ENDC}"
                        
                        hostname_str = f" ({result['hostname']})" if result['hostname'] else ""
                        services_str = ', '.join(result['services'].keys())
                        
                        anon_str = f" {Colors.WARNING}[ANONYMOUS]{Colors.ENDC}" if result['anonymous_access'] else ""
                        
                        print(f"{confidence} {result['ip']}{hostname_str} - {services_str}{anon_str}")
                        
                        # Show accessible shares
                        if result['accessible_shares']:
                            for share in result['accessible_shares'][:3]:  # Show first 3
                                print(f"    ✓ {share['path']}")
                            if len(result['accessible_shares']) > 3:
                                print(f"    ... and {len(result['accessible_shares']) - 3} more")
                    
                    elif args.verbose:
                        print(f"[ ] {ip} - No shares found")
                    
                    # Progress
                    if completed % 10 == 0 or completed == len(ips):
                        print(f"\n{Colors.OKCYAN}[*] Progress: {completed}/{len(ips)} ({shares_found} with shares){Colors.ENDC}\n")
                
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error scanning {ip}: {e}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
    
    # Summary
    print(f"\n{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Scan Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"Total Hosts Scanned: {completed}")
    print(f"Hosts with Shares: {shares_found}")
    
    # Count services
    service_counts = {}
    for result in results:
        for service in result['services'].keys():
            service_counts[service] = service_counts.get(service, 0) + 1
    
    if service_counts:
        print(f"\nService Breakdown:")
        for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {service}: {count} host(s)")
    
    # Save results
    if shares_found > 0:
        print()
        save_share_list(results)
        save_details(results)
    
    return 0

if __name__ == '__main__':
    exit(main())
