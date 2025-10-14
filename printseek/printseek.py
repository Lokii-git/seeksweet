#!/usr/bin/env python3
"""
PrintSeek - Network Printer Discovery and Enumeration Tool
Discovers network printers and extracts configuration information
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
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Optional, Dict

# Common printer ports
PRINTER_PORTS = {
    9100: "HP JetDirect",
    515: "LPD/LPR",
    631: "IPP/CUPS",
    161: "SNMP",
    80: "Web Interface",
    443: "HTTPS Web Interface",
    8080: "Alt Web",
    21: "FTP"
}

# Critical printer ports (having these suggests it's a printer)
CRITICAL_PRINTER_PORTS = {9100, 631}  # JetDirect or IPP
LIKELY_PRINTER_PORTS = {9100, 515, 631, 161}  # Any 2 of these


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
                        # Limit expansion for safety
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
    except socket.herror:
        return "N/A"
    except socket.gaierror:
        return "N/A"
    except socket.timeout:
        return "N/A"
    except Exception:
        return "N/A"


def snmp_get(ip: str, oid: str, community: str = "public", timeout: int = 2) -> Optional[str]:
    """Get SNMP value using snmpget"""
    try:
        # Check if snmpget is available
        result = subprocess.run(
            ['snmpget', '-v', '2c', '-c', community, '-t', str(timeout), ip, oid],
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )
        
        if result.returncode == 0 and result.stdout:
            # Parse output: typically "OID = TYPE: value"
            if '=' in result.stdout:
                value = result.stdout.split('=', 1)[1].strip()
                # Remove TYPE: prefix if present
                if ':' in value:
                    value = value.split(':', 1)[1].strip()
                # Remove quotes
                value = value.strip('"').strip()
                return value if value else None
        return None
    except subprocess.TimeoutExpired:
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def enumerate_snmp(ip: str, community: str = "public") -> Dict:
    """Enumerate printer via SNMP"""
    info: Dict[str, Optional[str]] = {
        'model': None,
        'serial': None,
        'location': None,
        'contact': None,
        'description': None,
        'uptime': None,
        'page_count': None,
        'name': None
    }
    
    # Standard SNMP OIDs
    oids = {
        'description': '1.3.6.1.2.1.1.1.0',      # sysDescr
        'name': '1.3.6.1.2.1.1.5.0',             # sysName
        'location': '1.3.6.1.2.1.1.6.0',         # sysLocation
        'contact': '1.3.6.1.2.1.1.4.0',          # sysContact
        'uptime': '1.3.6.1.2.1.1.3.0',           # sysUpTime
        # Printer-specific MIB OIDs
        'model': '1.3.6.1.2.1.25.3.2.1.3.1',     # hrDeviceDescr
        'serial': '1.3.6.1.2.1.43.5.1.1.17.1',   # prtGeneralSerialNumber
        'page_count': '1.3.6.1.2.1.43.10.2.1.4.1.1'  # prtMarkerLifeCount
    }
    
    for key, oid in oids.items():
        value = snmp_get(ip, oid, community)
        if value:
            info[key] = value
    
    return info


def grab_web_title(ip: str, port: int = 80, timeout: int = 3) -> Optional[str]:
    """Try to grab title from web interface"""
    try:
        import http.client
        
        if port == 443:
            conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
        
        conn.request("GET", "/")
        response = conn.getresponse()
        html = response.read().decode('utf-8', errors='ignore')
        conn.close()
        
        # Extract title
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()
            # Clean up
            title = re.sub(r'\s+', ' ', title)
            return title[:100]  # Limit length
        
        # Check for common printer strings
        if any(keyword in html.lower() for keyword in ['printer', 'hp', 'canon', 'epson', 'xerox', 'brother', 'ricoh', 'kyocera', 'lexmark']):
            return "Printer Web Interface"
        
        return None
    except Exception:
        return None


def scan_host(ip: str, timeout: float = 1.0, snmp_community: str = "public") -> Optional[Dict]:
    """Scan a single host for printer indicators"""
    try:
        result = {
            'ip': ip,
            'hostname': None,
            'open_ports': {},
            'is_likely_printer': False,
            'confidence': 'low',
            'snmp_info': {},
            'web_title': None,
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
        
        # Check printer ports
        open_printer_ports = set()
        for port, service in PRINTER_PORTS.items():
            try:
                if check_port(ip, port, timeout):
                    result['open_ports'][port] = service
                    open_printer_ports.add(port)
            except Exception:
                continue
        
        # Determine if it's likely a printer
        if CRITICAL_PRINTER_PORTS & open_printer_ports:
            result['is_likely_printer'] = True
            result['confidence'] = 'high'
        elif len(LIKELY_PRINTER_PORTS & open_printer_ports) >= 2:
            result['is_likely_printer'] = True
            result['confidence'] = 'medium'
        elif 161 in open_printer_ports:  # SNMP only
            # Check if hostname suggests printer
            hostname_lower = result['hostname'].lower()
            if any(word in hostname_lower for word in ['print', 'printer', 'hp', 'canon', 'epson', 'xerox', 'brother']):
                result['is_likely_printer'] = True
                result['confidence'] = 'medium'
        
        # If likely printer, gather more info
        if result['is_likely_printer']:
            # Try SNMP enumeration
            if 161 in open_printer_ports:
                try:
                    snmp_info = enumerate_snmp(ip, snmp_community)
                    if any(snmp_info.values()):
                        result['snmp_info'] = snmp_info
                        result['confidence'] = 'high'
                except Exception:
                    pass
            
            # Try web interface
            if 80 in open_printer_ports:
                web_title = grab_web_title(ip, 80)
                if web_title:
                    result['web_title'] = web_title
            elif 443 in open_printer_ports:
                web_title = grab_web_title(ip, 443)
                if web_title:
                    result['web_title'] = web_title
        
        return result
    except Exception as e:
        return {
            'ip': ip,
            'hostname': None,
            'open_ports': {},
            'is_likely_printer': False,
            'confidence': 'low',
            'snmp_info': {},
            'web_title': None,
            'error': str(e)
        }


def save_printer_list(printers: List[Dict], filename: str = "printerlist.txt") -> bool:
    """Save discovered printers to printerlist.txt"""
    try:
        with open(filename, 'w') as f:
            for printer in printers:
                f.write(f"{printer['ip']}\n")
        print(f"[+] Printer IP list saved to: {filename}")
        return True
    except Exception as e:
        print(f"[!] Error saving printer list: {e}")
        return False


def save_printer_details(printers: List[Dict], filename: str = "printer_details.txt") -> bool:
    """Save detailed printer information"""
    try:
        with open(filename, 'w') as f:
            f.write("PrintSeek - Network Printers Found\n")
            f.write("="*70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Printers Found: {len(printers)}\n")
            f.write("="*70 + "\n\n")
            
            for printer in printers:
                f.write(f"IP: {printer['ip']}\n")
                f.write(f"Hostname: {printer.get('hostname', 'N/A')}\n")
                f.write(f"Confidence: {printer.get('confidence', 'unknown').upper()}\n")
                
                if printer.get('open_ports'):
                    f.write(f"Open Ports: {', '.join([f'{p} ({s})' for p, s in printer['open_ports'].items()])}\n")
                
                if printer.get('web_title'):
                    f.write(f"Web Title: {printer['web_title']}\n")
                
                if printer.get('snmp_info'):
                    snmp = printer['snmp_info']
                    if snmp.get('name'):
                        f.write(f"Printer Name: {snmp['name']}\n")
                    if snmp.get('model'):
                        f.write(f"Model: {snmp['model']}\n")
                    if snmp.get('serial'):
                        f.write(f"Serial Number: {snmp['serial']}\n")
                    if snmp.get('location'):
                        f.write(f"Location: {snmp['location']}\n")
                    if snmp.get('contact'):
                        f.write(f"Contact: {snmp['contact']}\n")
                    if snmp.get('page_count'):
                        f.write(f"Page Count: {snmp['page_count']}\n")
                    if snmp.get('description'):
                        f.write(f"Description: {snmp['description']}\n")
                
                f.write("\n" + "-"*70 + "\n\n")
        
        print(f"[+] Detailed results saved to: {filename}")
        
        # Also save JSON
        json_file = filename.replace('.txt', '.json')
        try:
            with open(json_file, 'w') as f:
                json.dump(printers, f, indent=2)
            print(f"[+] JSON results saved to: {json_file}")
        except Exception as e:
            print(f"[!] Error saving JSON: {e}")
        
        return True
    except Exception as e:
        print(f"[!] Error saving printer details: {e}")
        return False


def print_banner():
    """Print PrintSeek banner"""
    banner = """
╔══════════════════════════════════════════════════════════╗
║                     PrintSeek v1.0                       ║
║              Network Printer Discovery Tool              ║
╚══════════════════════════════════════════════════════════╝
"""
    print(banner)


def main():
    parser = argparse.ArgumentParser(
        description='PrintSeek - Find network printers from IP list',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Use default iplist.txt
  %(prog)s -f targets.txt               # Custom input file
  %(prog)s -w 20 -t 2 -v                # 20 workers, 2s timeout, verbose
  %(prog)s -c private                   # Use 'private' SNMP community
  %(prog)s --snmp-only printerlist.txt  # Only SNMP enum (skip discovery)
        """
    )
    parser.add_argument('-f', '--file', default='iplist.txt', help='Input file with IPs (default: iplist.txt)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Connection timeout in seconds (default: 1.0)')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-o', '--output', default='printer_details.txt', help='Output file (default: printer_details.txt)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show all scanned hosts')
    parser.add_argument('-c', '--community', default='public', help='SNMP community string (default: public)')
    parser.add_argument('--snmp-only', action='store_true', help='Only run SNMP enumeration on printerlist.txt (skip discovery)')
    parser.add_argument('--printerlist', default='printerlist.txt', help='Printer list file (default: printerlist.txt)')
    
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
    
    printers = []
    completed = 0
    errors = 0
    
    # Handle SNMP-only mode
    if args.snmp_only:
        print(f"[*] SNMP-only mode: Reading printers from {args.printerlist}")
        if not os.path.exists(args.printerlist):
            print(f"[!] Error: {args.printerlist} not found. Run discovery first without --snmp-only")
            sys.exit(1)
        
        try:
            with open(args.printerlist, 'r') as f:
                printer_ips = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            print(f"[*] Loaded {len(printer_ips)} printers from {args.printerlist}")
            print(f"[*] Enumerating with SNMP community: {args.community}\n")
            
            for ip in printer_ips:
                print(f"[*] Enumerating {ip}...")
                snmp_info = enumerate_snmp(ip, args.community)
                
                if any(snmp_info.values()):
                    printer = {
                        'ip': ip,
                        'hostname': get_hostname(ip),
                        'open_ports': {161: 'SNMP'},
                        'is_likely_printer': True,
                        'confidence': 'high',
                        'snmp_info': snmp_info,
                        'web_title': None
                    }
                    printers.append(printer)
                    
                    print(f"[+] Success: {ip}")
                    if snmp_info.get('name'):
                        print(f"    Name: {snmp_info['name']}")
                    if snmp_info.get('model'):
                        print(f"    Model: {snmp_info['model']}")
                    if snmp_info.get('location'):
                        print(f"    Location: {snmp_info['location']}")
                else:
                    print(f"[-] No SNMP data from {ip}")
        
        except Exception as e:
            print(f"[!] Error reading {args.printerlist}: {e}")
            sys.exit(1)
    else:
        # Normal discovery mode
        print(f"[*] Reading IPs from: {args.file}")
        print(f"[*] SNMP community: {args.community}")
        
        try:
            ips = read_ip_list(args.file)
        except KeyboardInterrupt:
            print("\n[!] Interrupted by user")
            sys.exit(1)
        
        print(f"[*] Found {len(ips)} IP addresses to scan")
        print(f"[*] Starting scan with {args.workers} workers (timeout: {args.timeout}s)...\n")
        
        all_results = []
        
        try:
            with ThreadPoolExecutor(max_workers=args.workers) as executor:
                futures = {executor.submit(scan_host, ip, args.timeout, args.community): ip for ip in ips}
                
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
                        
                        if result['is_likely_printer']:
                            printers.append(result)
                            confidence_icon = "+++" if result['confidence'] == 'high' else "++"
                            print(f"[{confidence_icon}] PRINTER FOUND: {result['ip']} (Confidence: {result['confidence'].upper()})")
                            if result['hostname'] != "N/A":
                                print(f"    Hostname: {result['hostname']}")
                            print(f"    Open Ports: {', '.join([f'{p} ({s})' for p, s in result['open_ports'].items()])}")
                            
                            if result.get('snmp_info'):
                                snmp = result['snmp_info']
                                if snmp.get('name'):
                                    print(f"    Name: {snmp['name']}")
                                if snmp.get('model'):
                                    print(f"    Model: {snmp['model']}")
                                if snmp.get('location'):
                                    print(f"    Location: {snmp['location']}")
                            
                            if result.get('web_title'):
                                print(f"    Web: {result['web_title']}")
                            
                            print()
                        elif args.verbose and result['open_ports']:
                            print(f"[-] {result['ip']}: Open ports {list(result['open_ports'].keys())} (not a printer)")
                        
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
    if not args.snmp_only:
        print(f"Total IPs scanned: {completed}")
    print(f"Printers found: {len(printers)}")
    if not args.snmp_only and errors > 0:
        print(f"Errors encountered: {errors}")
    
    if printers:
        print("\nNETWORK PRINTERS:")
        print("-"*70)
        
        # Group by confidence
        high_conf = [p for p in printers if p.get('confidence') == 'high']
        med_conf = [p for p in printers if p.get('confidence') == 'medium']
        low_conf = [p for p in printers if p.get('confidence') == 'low']
        
        if high_conf:
            print("\nHigh Confidence:")
            for p in high_conf:
                model = p.get('snmp_info', {}).get('model', 'Unknown')
                print(f"  {p['ip']:<15} | {p['hostname']:<30} | {model}")
        
        if med_conf:
            print("\nMedium Confidence:")
            for p in med_conf:
                print(f"  {p['ip']:<15} | {p['hostname']}")
        
        if low_conf:
            print("\nLow Confidence:")
            for p in low_conf:
                print(f"  {p['ip']:<15} | {p['hostname']}")
    else:
        print("\n[!] No printers detected")
    
    # Save results
    if printers and not args.snmp_only:
        save_printer_list(printers, args.printerlist)
    
    if printers:
        save_printer_details(printers, args.output)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
