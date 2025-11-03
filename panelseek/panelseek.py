#!/usr/bin/env python3
"""
PanelSeek - Exposed Admin Panel Discovery Tool
Discovers web-based admin interfaces (routers, firewalls, switches, management panels)
"""

import socket
import ipaddress
import subprocess
import sys
import argparse
import os

# Import shared utilities
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list
import re
import json
import urllib3
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict
import http.client
import ssl

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Common admin panel ports
ADMIN_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    8000: "HTTP Dev",
    8888: "HTTP Management",
    9090: "Management Console",
    10000: "Webmin",
    3000: "Grafana/Web UI",
    5000: "Flask/Web UI",
    4443: "Alt HTTPS"
}

# Admin panel signatures
PANEL_SIGNATURES = {
    # Network Devices
    'cisco': ['Cisco', 'cisco', 'CISCO'],
    'juniper': ['Juniper', 'JUNOS', 'juniper'],
    'pfsense': ['pfSense', 'pfsense'],
    'fortinet': ['FortiGate', 'Fortinet', 'FortiOS'],
    'palo_alto': ['Palo Alto', 'PAN-OS', 'GlobalProtect'],
    'sonicwall': ['SonicWall', 'SonicOS'],
    'watchguard': ['WatchGuard', 'Firebox'],
    'netgear': ['NETGEAR', 'Netgear'],
    'tp_link': ['TP-Link', 'TP-LINK'],
    'ubiquiti': ['Ubiquiti', 'UniFi', 'EdgeOS'],
    'mikrotik': ['MikroTik', 'RouterOS'],
    'dd_wrt': ['DD-WRT', 'ddwrt'],
    'openwrt': ['OpenWrt', 'LuCI'],
    'tomato': ['Tomato', 'tomato'],
    
    # Management Interfaces
    'vmware': ['VMware', 'vSphere', 'ESXi', 'vCenter'],
    'idrac': ['iDRAC', 'Dell Remote Access'],
    'ilo': ['iLO', 'HP iLO', 'Integrated Lights-Out'],
    'ipmi': ['IPMI', 'Intelligent Platform Management'],
    'webmin': ['Webmin', 'Usermin'],
    'cpanel': ['cPanel', 'WHM'],
    'plesk': ['Plesk', 'plesk'],
    'proxmox': ['Proxmox', 'PVE'],
    
    # Applications
    'jenkins': ['Jenkins', 'jenkins'],
    'grafana': ['Grafana', 'grafana'],
    'kibana': ['Kibana', 'kibana'],
    'prometheus': ['Prometheus', 'prometheus'],
    'portainer': ['Portainer', 'portainer'],
    'rancher': ['Rancher', 'rancher'],
    'kubernetes': ['Kubernetes Dashboard', 'k8s'],
    'docker': ['Docker', 'Moby'],
    
    # Databases
    'phpmyadmin': ['phpMyAdmin', 'phpmyadmin'],
    'adminer': ['Adminer', 'adminer'],
    'mongodb': ['MongoDB', 'mongo-express'],
    
    # Generic
    'admin': ['Admin Panel', 'Administration', 'admin login', 'Dashboard'],
    'login': ['Login', 'Sign In', 'Authentication Required']
}

# Common admin paths to check
ADMIN_PATHS = [
    '/',
    '/admin',
    '/login',
    '/admin.php',
    '/administrator',
    '/wp-admin',
    '/admin/login',
    '/user/login',
    '/console',
    '/dashboard',
    '/management',
    '/config',
    '/system',
    '/setup',
    '/cgi-bin',
    '/web',
    '/ui',
    '/portal',
    '/api',
    '/manager/html',
    '/phpmyadmin',
    '/adminer.php',
    '/webmin',
    '/cpanel',
    '/plesk',
    '/admin/index.php',
    '/login.php',
    '/signin'
]


def read_ip_list(filename: str) -> Set[str]:
    """Read and expand IP addresses from file"""
    # Use shared utility to find the file
    filename = find_ip_list(filename)
    
    ips = set()
    
    if not os.path.exists(filename):
        print(f"[!] Error: File not found: {filename}")
        sys.exit(1)
    
    if not os.path.isfile(filename):
        print(f"[!] Error: {filename} is not a file")
        sys.exit(1)
    
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
                        host_count = network.num_addresses - 2
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
    except socket.error:
        return False
    except Exception:
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
    except:
        return "N/A"


def fetch_web_page(ip: str, port: int, path: str = "/", timeout: int = 5) -> Optional[Dict]:
    """Fetch web page and extract information"""
    try:
        # Determine protocol
        use_https = port in [443, 8443, 4443] or port == 10000
        
        if use_https:
            # Create unverified SSL context for self-signed certs
            context = ssl._create_unverified_context()
            conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=context)
        else:
            conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
        
        # Send request with common headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'close'
        }
        
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        
        result = {
            'status_code': response.status,
            'headers': dict(response.getheaders()),
            'body': '',
            'redirects_to': None
        }
        
        # Handle redirects
        if response.status in [301, 302, 303, 307, 308]:
            location = response.getheader('Location')
            if location:
                result['redirects_to'] = location
        
        # Read response body
        try:
            body = response.read()
            result['body'] = body.decode('utf-8', errors='ignore')[:50000]  # Limit size
        except:
            result['body'] = ''
        
        conn.close()
        return result
        
    except ssl.SSLError as e:
        return {'error': f'SSL Error: {str(e)}', 'status_code': 0}
    except http.client.HTTPException as e:
        return {'error': f'HTTP Error: {str(e)}', 'status_code': 0}
    except socket.timeout:
        return {'error': 'Timeout', 'status_code': 0}
    except ConnectionRefusedError:
        return {'error': 'Connection Refused', 'status_code': 0}
    except Exception as e:
        return {'error': str(e), 'status_code': 0}


def identify_panel(html: str, headers: Dict, url: str) -> Dict:
    """Identify admin panel type from HTML and headers"""
    identification = {
        'panel_type': 'unknown',
        'vendor': None,
        'title': None,
        'auth_required': False,
        'default_creds_likely': False,
        'confidence': 'low',
        'indicators': []
    }
    
    # Extract title
    title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
    if title_match:
        title = title_match.group(1).strip()
        title = re.sub(r'\s+', ' ', title)
        identification['title'] = title[:200]
    
    # Check for authentication indicators
    auth_keywords = ['login', 'password', 'username', 'sign in', 'authenticate', 'credentials']
    html_lower = html.lower()
    if any(keyword in html_lower for keyword in auth_keywords):
        identification['auth_required'] = True
    
    # Check for password input
    if 'type="password"' in html_lower or 'type=\'password\'' in html_lower:
        identification['auth_required'] = True
    
    # Check WWW-Authenticate header
    if 'www-authenticate' in [h.lower() for h in headers.keys()]:
        identification['auth_required'] = True
    
    # Identify panel type by signatures
    matched_types = []
    for panel_type, signatures in PANEL_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in html_lower or (identification['title'] and sig.lower() in identification['title'].lower()):
                matched_types.append(panel_type)
                identification['indicators'].append(sig)
                break
    
    # Set panel type and confidence
    if matched_types:
        identification['panel_type'] = matched_types[0]
        identification['vendor'] = matched_types[0].replace('_', ' ').title()
        identification['confidence'] = 'high'
        
        # Check for default credentials likelihood
        default_creds_panels = ['netgear', 'tp_link', 'ubiquiti', 'mikrotik', 'dd_wrt', 
                               'jenkins', 'tomato', 'webmin', 'admin']
        if identification['panel_type'] in default_creds_panels:
            identification['default_creds_likely'] = True
    elif identification['auth_required']:
        identification['panel_type'] = 'admin_login'
        identification['confidence'] = 'medium'
    
    # Check Server header for additional info
    server_header = headers.get('Server', headers.get('server', ''))
    if server_header:
        identification['indicators'].append(f"Server: {server_header}")
        if not identification['vendor']:
            for vendor_key, vendor_sigs in PANEL_SIGNATURES.items():
                if any(sig.lower() in server_header.lower() for sig in vendor_sigs):
                    identification['vendor'] = vendor_key.replace('_', ' ').title()
                    break
    
    return identification


def scan_host(ip: str, ports: List[int], paths: List[str], timeout: float = 2.0) -> Optional[Dict]:
    """Scan a single host for admin panels"""
    try:
        result = {
            'ip': ip,
            'hostname': None,
            'panels': [],
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
        
        # Check each port
        for port in ports:
            if not check_port(ip, port, timeout):
                continue
            
            # Port is open, check paths
            for path in paths:
                try:
                    web_result = fetch_web_page(ip, port, path, timeout=5)
                    
                    if not web_result or web_result.get('error'):
                        continue
                    
                    # Skip if not successful response
                    if web_result['status_code'] not in [200, 301, 302, 401, 403]:
                        continue
                    
                    # Identify panel
                    identification = identify_panel(
                        web_result.get('body', ''),
                        web_result.get('headers', {}),
                        f"{'https' if port in [443, 8443, 4443] else 'http'}://{ip}:{port}{path}"
                    )
                    
                    # Only record if it looks like an admin panel
                    if identification['auth_required'] or identification['panel_type'] != 'unknown':
                        panel_info = {
                            'port': port,
                            'path': path,
                            'protocol': 'https' if port in [443, 8443, 4443, 10000] else 'http',
                            'url': f"{'https' if port in [443, 8443, 4443, 10000] else 'http'}://{ip}:{port}{path}",
                            'status_code': web_result['status_code'],
                            'panel_type': identification['panel_type'],
                            'vendor': identification['vendor'],
                            'title': identification['title'],
                            'auth_required': identification['auth_required'],
                            'default_creds_likely': identification['default_creds_likely'],
                            'confidence': identification['confidence'],
                            'indicators': identification['indicators'],
                            'redirects_to': web_result.get('redirects_to')
                        }
                        result['panels'].append(panel_info)
                        
                        # If we found something on this port, skip other paths
                        if identification['confidence'] == 'high':
                            break
                        
                except Exception as e:
                    continue
        
        return result
        
    except Exception as e:
        return {
            'ip': ip,
            'hostname': None,
            'panels': [],
            'error': str(e)
        }


def save_panel_list(panels: List[Dict], filename: str = "panellist.txt") -> bool:
    """Save discovered panels to panellist.txt (URLs)"""
    try:
        with open(filename, 'w') as f:
            for panel in panels:
                for panel_info in panel.get('panels', []):
                    f.write(f"{panel_info['url']}\n")
        print(f"[+] Panel URL list saved to: {filename}")
        return True
    except Exception as e:
        print(f"[!] Error saving panel list: {e}")
        return False


def save_panel_details(panels: List[Dict], filename: str = "panel_details.txt") -> bool:
    """Save detailed panel information"""
    try:
        with open(filename, 'w') as f:
            f.write("PanelSeek - Exposed Admin Panels Found\n")
            f.write("="*70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Hosts with Panels: {len(panels)}\n")
            total_panels = sum(len(p.get('panels', [])) for p in panels)
            f.write(f"Total Panels Found: {total_panels}\n")
            f.write("="*70 + "\n\n")
            
            for host in panels:
                f.write(f"Host: {host['ip']}\n")
                if host.get('hostname') and host['hostname'] != 'N/A':
                    f.write(f"Hostname: {host['hostname']}\n")
                f.write(f"Panels Found: {len(host.get('panels', []))}\n")
                f.write("-"*70 + "\n")
                
                for panel in host.get('panels', []):
                    f.write(f"\n  URL: {panel['url']}\n")
                    f.write(f"  Status: {panel['status_code']}\n")
                    f.write(f"  Panel Type: {panel['panel_type'].replace('_', ' ').title()}\n")
                    f.write(f"  Confidence: {panel['confidence'].upper()}\n")
                    
                    if panel.get('vendor'):
                        f.write(f"  Vendor: {panel['vendor']}\n")
                    if panel.get('title'):
                        f.write(f"  Title: {panel['title']}\n")
                    
                    f.write(f"  Auth Required: {'Yes' if panel['auth_required'] else 'No'}\n")
                    
                    if panel.get('default_creds_likely'):
                        f.write(f"  ⚠ DEFAULT CREDENTIALS LIKELY - Try common passwords\n")
                    
                    if panel.get('indicators'):
                        f.write(f"  Indicators: {', '.join(panel['indicators'][:3])}\n")
                    
                    if panel.get('redirects_to'):
                        f.write(f"  Redirects To: {panel['redirects_to']}\n")
                    
                    f.write("\n")
                
                f.write("="*70 + "\n\n")
        
        print(f"[+] Detailed results saved to: {filename}")
        
        # Also save JSON
        json_file = filename.replace('.txt', '.json')
        try:
            with open(json_file, 'w') as f:
                json.dump(panels, f, indent=2)
            print(f"[+] JSON results saved to: {json_file}")
        except Exception as e:
            print(f"[!] Error saving JSON: {e}")
        
        return True
    except Exception as e:
        print(f"[!] Error saving panel details: {e}")
        return False


def check_go_installed():
    """Check if Go is installed and in PATH"""
    try:
        result = subprocess.run(['go', 'version'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"[+] Go found: {version}")
            return True
        else:
            print("[!] Go not found in PATH")
            return False
    except FileNotFoundError:
        print("[!] Go not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        print("[!] Go version check timed out")
        return False
    except Exception as e:
        print(f"[!] Error checking Go installation: {e}")
        return False


def check_gowitness_installed():
    """Check if gowitness is installed"""
    try:
        result = subprocess.run(['gowitness', '--version'], 
                              capture_output=True, 
                              text=True,
                              timeout=10)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"[+] gowitness found: {version}")
            return True
        else:
            return False
    except FileNotFoundError:
        return False
    except subprocess.TimeoutExpired:
        print("[!] gowitness version check timed out")
        return False
    except Exception as e:
        print(f"[!] Error checking gowitness: {e}")
        return False


def install_gowitness():
    """Install gowitness using go install"""
    print("[*] Installing gowitness...")
    try:
        result = subprocess.run([
            'go', 'install', 'github.com/sensepost/gowitness@latest'
        ], capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print("[+] gowitness installed successfully")
            return True
        else:
            print(f"[!] Error installing gowitness: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print("[!] gowitness installation timed out")
        return False
    except Exception as e:
        print(f"[!] Error installing gowitness: {e}")
        return False


def run_gowitness_screenshots(panellist_file, delay=15):
    """Run gowitness to capture screenshots of admin panels"""
    if not os.path.exists(panellist_file):
        print(f"[!] Panel list file not found: {panellist_file}")
        return False
    
    # Check if file has content
    with open(panellist_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]
    
    if not urls:
        print("[!] No URLs found in panel list file")
        return False
    
    print(f"\n[*] Capturing screenshots of {len(urls)} admin panels with gowitness...")
    print(f"[*] Using delay of {delay} seconds for slower systems...")
    
    # Create screenshots directory
    screenshots_dir = "screenshots"
    os.makedirs(screenshots_dir, exist_ok=True)
    
    try:
        # Run gowitness with file input and delay
        cmd = [
            'gowitness', 'file',
            '--source', panellist_file,
            '--destination', screenshots_dir,
            '--delay', str(delay),
            '--timeout', '30',
            '--threads', '5'
        ]
        
        print(f"[*] Running: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=False, text=True, timeout=600)
        
        if result.returncode == 0:
            print(f"[+] Screenshots captured successfully in '{screenshots_dir}' directory")
            
            # Count captured screenshots
            screenshot_files = [f for f in os.listdir(screenshots_dir) if f.endswith(('.png', '.jpg', '.jpeg'))]
            print(f"[+] Total screenshots captured: {len(screenshot_files)}")
            
            # List some examples
            if screenshot_files:
                print("\n[+] Screenshot examples:")
                for i, screenshot in enumerate(screenshot_files[:5]):
                    print(f"    - {screenshot}")
                if len(screenshot_files) > 5:
                    print(f"    ... and {len(screenshot_files) - 5} more")
            
            return True
        else:
            print(f"[!] gowitness failed with exit code {result.returncode}")
            return False
            
    except subprocess.TimeoutExpired:
        print("[!] gowitness screenshot capture timed out")
        return False
    except Exception as e:
        print(f"[!] Error running gowitness: {e}")
        return False


def print_banner():
    """Print PanelSeek banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                     PanelSeek v2.0                       ║
║        Admin Panel Discovery + Screenshot Capture        ║
║              github.com/Lokii-git/seeksweet              ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='PanelSeek - Find exposed admin panels from IP list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default iplist.txt
  %(prog)s -f targets.txt               # Custom input file
  %(prog)s -w 20 -t 2 -v                # 20 workers, 2s timeout, verbose
  %(prog)s --quick                      # Quick scan (fewer paths)
  %(prog)s --full                       # Full scan (all paths)
  %(prog)s --delay 10                   # Use 10 second delay for gowitness (faster systems)
  %(prog)s --no-screenshots             # Skip screenshot capture
        """
    )
    parser.add_argument('-f', '--file', default='iplist.txt', help='Input file with IPs (default: iplist.txt)')
    parser.add_argument('-t', '--timeout', type=float, default=2.0, help='Connection timeout in seconds (default: 2.0)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-o', '--output', default='panel_details.txt', help='Output file (default: panel_details.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all scanned hosts')
    parser.add_argument('--ports', nargs='+', type=int, help=f'Custom ports to scan (default: {list(ADMIN_PORTS.keys())})')
    parser.add_argument('--quick', action='store_true', help='Quick scan (check only / and /admin)')
    parser.add_argument('--full', action='store_true', help='Full scan (check all paths)')
    parser.add_argument('--panellist', default='panellist.txt', help='Panel list file (default: panellist.txt)')
    parser.add_argument('--screenshots', action='store_true', help='Capture screenshots of admin panels using gowitness')
    parser.add_argument('--delay', type=int, default=15, help='Delay between requests for gowitness (default: 15 seconds)')
    parser.add_argument('--no-screenshots', action='store_true', help='Skip screenshot capture even if gowitness is available')
    
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
    
    # Determine ports and paths to check
    ports_to_check = args.ports if args.ports else list(ADMIN_PORTS.keys())
    
    if args.quick:
        paths_to_check = ['/', '/admin', '/login']
    elif args.full:
        paths_to_check = ADMIN_PATHS
    else:
        # Default: balanced
        paths_to_check = ['/', '/admin', '/login', '/admin.php', '/administrator', '/console', '/dashboard']
    
    print_banner()
    print(f"[*] Reading IPs from: {args.file}")
    print(f"[*] Ports to check: {ports_to_check}")
    print(f"[*] Paths per port: {len(paths_to_check)}")
    
    try:
        ips = read_ip_list(args.file)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    
    print(f"[*] Found {len(ips)} IP addresses to scan")
    print(f"[*] Starting scan with {args.workers} workers (timeout: {args.timeout}s)...\n")
    
    hosts_with_panels = []
    all_results = []
    completed = 0
    errors = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            futures = {executor.submit(scan_host, ip, ports_to_check, paths_to_check, args.timeout): ip for ip in ips}
            
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
                    
                    if result.get('panels'):
                        hosts_with_panels.append(result)
                        
                        for panel in result['panels']:
                            confidence_icon = "[+++]" if panel['confidence'] == 'high' else "[++]" if panel['confidence'] == 'medium' else "[+]"
                            
                            print(f"{confidence_icon} ADMIN PANEL FOUND: {panel['url']}")
                            if result['hostname'] != "N/A":
                                print(f"    Hostname: {result['hostname']}")
                            
                            panel_type_display = panel['panel_type'].replace('_', ' ').title()
                            if panel['vendor']:
                                print(f"    Type: {panel['vendor']} ({panel_type_display})")
                            else:
                                print(f"    Type: {panel_type_display}")
                            
                            if panel.get('title'):
                                print(f"    Title: {panel['title'][:80]}")
                            
                            print(f"    Status: {panel['status_code']} | Auth: {'Yes' if panel['auth_required'] else 'No'}")
                            
                            if panel.get('default_creds_likely'):
                                print(f"    ⚠ DEFAULT CREDS LIKELY - Test common passwords!")
                            
                            print()
                    
                    elif args.verbose:
                        print(f"[-] {result['ip']}: No panels found")
                    
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
    print(f"Total IPs scanned: {completed}")
    print(f"Hosts with admin panels: {len(hosts_with_panels)}")
    total_panels = sum(len(h.get('panels', [])) for h in hosts_with_panels)
    print(f"Total panels found: {total_panels}")
    if errors > 0:
        print(f"Errors encountered: {errors}")
    
    if hosts_with_panels:
        print("\nADMIN PANELS BY TYPE:")
        print("-"*70)
        
        # Group by panel type
        panel_types = {}
        for host in hosts_with_panels:
            for panel in host.get('panels', []):
                # Safely get panel type with proper fallback
                panel_type_raw = panel.get('vendor') or panel.get('panel_type') or 'Unknown'
                panel_type = panel_type_raw.replace('_', ' ').title()
                if panel_type not in panel_types:
                    panel_types[panel_type] = []
                panel_types[panel_type].append(f"{host['ip']}:{panel['port']}")
        
        for panel_type, locations in sorted(panel_types.items()):
            print(f"\n{panel_type}: {len(locations)}")
            for loc in locations[:5]:  # Show first 5
                print(f"  - {loc}")
            if len(locations) > 5:
                print(f"  ... and {len(locations) - 5} more")
    else:
        print("\n[!] No admin panels detected")
    
    # Save results
    if hosts_with_panels:
        save_panel_list(hosts_with_panels, args.panellist)
        save_panel_details(hosts_with_panels, args.output)
        
        # Screenshot capture with gowitness
        if not args.no_screenshots:
            print("\n" + "="*70)
            print("GOWITNESS SCREENSHOT CAPTURE")
            print("="*70)
            
            # Check if Go is installed
            if not check_go_installed():
                print("[!] Go is required for gowitness. Please install Go and add it to your PATH.")
                print("[!] Download Go from: https://golang.org/dl/")
                print("[!] Skipping screenshot capture...")
            else:
                # Check if gowitness is installed
                if not check_gowitness_installed():
                    print("[*] gowitness not found. Attempting to install...")
                    if install_gowitness():
                        # Try to run gowitness after installation
                        run_gowitness_screenshots(args.panellist, args.delay)
                    else:
                        print("[!] Failed to install gowitness. Skipping screenshot capture...")
                        print("[!] You can manually install with: go install github.com/sensepost/gowitness@latest")
                else:
                    # gowitness is available, run screenshot capture
                    run_gowitness_screenshots(args.panellist, args.delay)
        else:
            print("\n[*] Screenshot capture disabled with --no-screenshots")
    
    sys.exit(0)


if __name__ == "__main__":
    main()
