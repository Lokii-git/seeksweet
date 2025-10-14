#!/usr/bin/env python3
"""
WebSeek v1.0 - Web Vulnerability Scanner
Discover common web security issues on internal networks

Features:
- Directory listing detection
- Backup file discovery (.bak, .old, ~)
- Information disclosure (phpinfo, debug pages)
- Git repository exposure (.git/)
- Common admin paths (/admin, /backup, /config)
- Default credentials testing
- SSL/TLS analysis
- HTTP security headers analysis

Usage:
    ./webseek.py                           # Basic vulnerability scan
    ./webseek.py --full                    # Full scan (all checks)
    ./webseek.py --git                     # Git exposure only
    ./webseek.py --backup                  # Backup files only
    ./webseek.py -u admin -p admin         # Test credentials
    
Output:
    weblist.txt         - Vulnerable web servers
    findings.txt        - All findings
    git_repos.txt       - Exposed git repositories
    backup_files.txt    - Backup files found
    web_details.txt     - Detailed findings
    web_details.json    - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urljoin
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

# Web ports to scan
WEB_PORTS = [80, 443, 8000, 8080, 8443, 8888, 9090]

# Common admin/backup paths
COMMON_PATHS = [
    '/admin', '/administrator', '/admin.php', '/admin/', '/wp-admin/',
    '/phpmyadmin', '/pma', '/cpanel', '/webadmin', '/administrator.php',
    '/backup', '/backups', '/backup.zip', '/backup.tar.gz', '/db_backup',
    '/config', '/config.php', '/configuration.php', '/settings.php',
    '/.git', '/.git/config', '/.git/HEAD', '/.svn', '/.hg',
    '/phpinfo.php', '/info.php', '/test.php', '/debug.php', '/console',
    '/.env', '/config.json', '/appsettings.json', '/web.config',
    '/database.yml', '/config.yml', '/settings.yml'
]

# Backup file extensions
BACKUP_EXTENSIONS = [
    '.bak', '.backup', '.old', '.save', '.orig', '.copy',
    '.zip', '.tar.gz', '.rar', '.7z', '~', '.swp', '.tmp'
]

# Common files to check for backups
COMMON_FILES = [
    'index', 'login', 'admin', 'config', 'database', 'db',
    'setup', 'install', 'backup', 'home', 'default'
]

# Info disclosure patterns
INFO_PATTERNS = {
    'phpinfo': [
        'phpinfo()',
        'PHP Version',
        'System.*Linux',
        'Server API'
    ],
    'debug': [
        'Debug Mode',
        'Stack Trace',
        'Exception',
        'Traceback',
        'Fatal error'
    ],
    'directory_listing': [
        'Index of /',
        'Parent Directory',
        '<title>Index of',
        'Directory Listing'
    ],
    'sql_error': [
        'SQL syntax',
        'mysql_fetch',
        'pg_query',
        'ORA-[0-9]+',
        'SQLite',
        'SQLSTATE'
    ]
}

# Security headers to check
SECURITY_HEADERS = [
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Permitted-Cross-Domain-Policies'
]

# Banner
BANNER = f"""{CYAN}{BOLD}
██╗    ██╗███████╗██████╗ ███████╗███████╗███████╗██╗  ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  █████╗  █████╔╝ 
██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
╚███╔███╔╝███████╗██████╔╝███████║███████╗███████╗██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}WebSeek v1.0 - Web Vulnerability Scanner{RESET}
{BLUE}Discover common web security issues{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_ip_list(file_path):
    """Read IP addresses or URLs from a file"""
    # Use shared utility to find the file
    file_path = find_ip_list(file_path)
    
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return targets


def check_web_port(ip, port, timeout=3):
    """Check if a web port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def check_url(url, timeout=5):
    """
    Check if URL is accessible
    Returns: response object or None
    """
    try:
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return response
    except:
        return None


def check_git_exposure(base_url, timeout=5):
    """
    Check for exposed .git directory
    Returns: dict with findings
    """
    findings = []
    
    git_paths = ['/.git/', '/.git/config', '/.git/HEAD', '/.git/index']
    
    for path in git_paths:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=timeout, verify=False)
            
            if response.status_code == 200:
                findings.append({
                    'type': 'git_exposure',
                    'url': url,
                    'status_code': response.status_code,
                    'severity': 'HIGH'
                })
                
                # Check for valid git content
                if path == '/.git/HEAD' and 'ref:' in response.text:
                    findings.append({
                        'type': 'git_exposure_confirmed',
                        'url': url,
                        'content': response.text[:100],
                        'severity': 'CRITICAL'
                    })
                    break
        except:
            continue
    
    return findings


def check_backup_files(base_url, timeout=5):
    """
    Check for backup files
    Returns: list of backup files found
    """
    findings = []
    
    # Check common files with backup extensions
    for filename in COMMON_FILES[:5]:  # Limit to prevent too many requests
        for ext in BACKUP_EXTENSIONS[:5]:
            try:
                url = urljoin(base_url, f'/{filename}{ext}')
                response = requests.head(url, timeout=timeout, verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    findings.append({
                        'type': 'backup_file',
                        'url': url,
                        'status_code': response.status_code,
                        'size': response.headers.get('Content-Length', 'Unknown'),
                        'severity': 'MEDIUM'
                    })
            except:
                continue
    
    return findings


def check_info_disclosure(base_url, timeout=5):
    """
    Check for information disclosure
    Returns: list of findings
    """
    findings = []
    
    info_paths = ['/phpinfo.php', '/info.php', '/test.php', '/debug.php', '/']
    
    for path in info_paths:
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=timeout, verify=False)
            
            if response.status_code == 200:
                content = response.text[:10000]  # First 10KB
                
                # Check for patterns
                for info_type, patterns in INFO_PATTERNS.items():
                    for pattern in patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            findings.append({
                                'type': info_type,
                                'url': url,
                                'pattern': pattern,
                                'severity': 'HIGH' if info_type == 'phpinfo' else 'MEDIUM'
                            })
                            break  # One match per type is enough
        except:
            continue
    
    return findings


def check_common_paths(base_url, timeout=5):
    """
    Check common admin/config paths
    Returns: list of accessible paths
    """
    findings = []
    
    for path in COMMON_PATHS[:15]:  # Limit requests
        try:
            url = urljoin(base_url, path)
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            
            if response.status_code in [200, 301, 302, 401, 403]:
                severity = 'HIGH' if response.status_code == 200 else 'MEDIUM'
                
                # 401/403 means path exists but requires auth
                if response.status_code in [401, 403]:
                    severity = 'LOW'
                
                findings.append({
                    'type': 'common_path',
                    'url': url,
                    'status_code': response.status_code,
                    'severity': severity
                })
        except:
            continue
    
    return findings


def check_security_headers(base_url, timeout=5):
    """
    Check for missing security headers
    Returns: dict with header status
    """
    missing_headers = []
    
    try:
        response = requests.get(base_url, timeout=timeout, verify=False)
        
        for header in SECURITY_HEADERS:
            if header not in response.headers:
                missing_headers.append(header)
        
        if missing_headers:
            return {
                'type': 'missing_security_headers',
                'url': base_url,
                'missing_headers': missing_headers,
                'severity': 'LOW'
            }
    except:
        pass
    
    return None


def test_default_credentials(base_url, username, password, timeout=5):
    """
    Test default credentials on common login paths
    Returns: list of successful logins
    """
    findings = []
    
    login_paths = [
        '/login', '/admin/login', '/wp-login.php', '/administrator',
        '/admin.php', '/user/login'
    ]
    
    for path in login_paths:
        try:
            url = urljoin(base_url, path)
            
            # Try POST request with credentials
            data = {
                'username': username,
                'password': password,
                'user': username,
                'pass': password,
                'login': 'Login'
            }
            
            response = requests.post(url, data=data, timeout=timeout, verify=False, allow_redirects=False)
            
            # Check for successful login indicators
            if response.status_code in [200, 302, 303]:
                # Look for success indicators
                if 'dashboard' in response.text.lower() or 'logout' in response.text.lower():
                    findings.append({
                        'type': 'default_credentials',
                        'url': url,
                        'username': username,
                        'password': password,
                        'severity': 'CRITICAL'
                    })
        except:
            continue
    
    return findings


def scan_web_server(target, args):
    """
    Scan a single web server
    Returns: dict with findings
    """
    result = {
        'target': target,
        'accessible_urls': [],
        'findings': [],
        'status': 'unreachable'
    }
    
    try:
        # Determine if target is IP or URL
        if target.startswith('http://') or target.startswith('https://'):
            urls_to_check = [target]
        else:
            # Check common ports
            urls_to_check = []
            for port in WEB_PORTS:
                if check_web_port(target, port, timeout=args.timeout):
                    protocol = 'https' if port in [443, 8443] else 'http'
                    port_suffix = '' if port in [80, 443] else f':{port}'
                    urls_to_check.append(f'{protocol}://{target}{port_suffix}')
        
        # Scan each accessible URL
        for url in urls_to_check:
            response = check_url(url, timeout=args.timeout)
            
            if response:
                result['accessible_urls'].append(url)
                result['status'] = 'accessible'
                
                # Run checks
                if args.full or args.git:
                    git_findings = check_git_exposure(url, timeout=args.timeout)
                    result['findings'].extend(git_findings)
                
                if args.full or args.backup:
                    backup_findings = check_backup_files(url, timeout=args.timeout)
                    result['findings'].extend(backup_findings)
                
                if args.full or not (args.git or args.backup):
                    info_findings = check_info_disclosure(url, timeout=args.timeout)
                    result['findings'].extend(info_findings)
                    
                    path_findings = check_common_paths(url, timeout=args.timeout)
                    result['findings'].extend(path_findings)
                    
                    header_check = check_security_headers(url, timeout=args.timeout)
                    if header_check:
                        result['findings'].append(header_check)
                
                # Test credentials if provided
                if args.username and args.password:
                    cred_findings = test_default_credentials(url, args.username, args.password, timeout=args.timeout)
                    result['findings'].extend(cred_findings)
    
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_weblist(results, filename='weblist.txt'):
    """Save list of vulnerable web servers"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['findings']:
                    for url in result['accessible_urls']:
                        f.write(f"{url}\n")
        print(f"{GREEN}[+] Vulnerable web servers saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving web list: {e}{RESET}")


def save_findings(results, filename='findings.txt'):
    """Save all findings"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEBSEEK - Web Vulnerability Findings\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['findings']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Target: {result['target']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    # Group by severity
                    critical = [f for f in result['findings'] if f.get('severity') == 'CRITICAL']
                    high = [f for f in result['findings'] if f.get('severity') == 'HIGH']
                    medium = [f for f in result['findings'] if f.get('severity') == 'MEDIUM']
                    low = [f for f in result['findings'] if f.get('severity') == 'LOW']
                    
                    if critical:
                        f.write("CRITICAL Findings:\n")
                        for finding in critical:
                            f.write(f"  🔴 {finding['type']}: {finding.get('url', 'N/A')}\n")
                            if 'username' in finding:
                                f.write(f"     Credentials: {finding['username']}:{finding['password']}\n")
                        f.write("\n")
                    
                    if high:
                        f.write("HIGH Findings:\n")
                        for finding in high:
                            f.write(f"  🟠 {finding['type']}: {finding.get('url', 'N/A')}\n")
                        f.write("\n")
                    
                    if medium:
                        f.write("MEDIUM Findings:\n")
                        for finding in medium[:10]:  # Limit output
                            f.write(f"  🟡 {finding['type']}: {finding.get('url', 'N/A')}\n")
                        if len(medium) > 10:
                            f.write(f"  ... and {len(medium) - 10} more\n")
                        f.write("\n")
                    
                    if low:
                        f.write(f"LOW Findings: {len(low)}\n\n")
        
        print(f"{GREEN}[+] Findings saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving findings: {e}{RESET}")


def save_git_repos(results, filename='git_repos.txt'):
    """Save exposed git repositories"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEBSEEK - Exposed Git Repositories\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            f.write("Use git-dumper to download:\n")
            f.write("  git-dumper http://target/.git/ output_dir\n\n")
            
            for result in results:
                git_findings = [f for f in result['findings'] if 'git' in f.get('type', '')]
                if git_findings:
                    for finding in git_findings:
                        f.write(f"{finding['url']}\n")
        
        print(f"{GREEN}[+] Git repositories saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving git repos: {e}{RESET}")


def save_backup_files(results, filename='backup_files.txt'):
    """Save backup files found"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEBSEEK - Backup Files Found\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                backup_findings = [f for f in result['findings'] if f.get('type') == 'backup_file']
                if backup_findings:
                    f.write(f"\nTarget: {result['target']}\n")
                    f.write(f"{'=' * 80}\n")
                    for finding in backup_findings:
                        f.write(f"  {finding['url']} (Size: {finding.get('size', 'Unknown')})\n")
        
        print(f"{GREEN}[+] Backup files saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving backup files: {e}{RESET}")


def save_details(results, filename='web_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("WEBSEEK - Detailed Scan Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['status'] == 'accessible':
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Target: {result['target']}\n")
                    f.write(f"Accessible URLs: {len(result['accessible_urls'])}\n")
                    for url in result['accessible_urls']:
                        f.write(f"  • {url}\n")
                    f.write(f"Findings: {len(result['findings'])}\n")
                    f.write(f"{'=' * 80}\n")
                    
                    # Count by severity
                    critical = len([f for f in result['findings'] if f.get('severity') == 'CRITICAL'])
                    high = len([f for f in result['findings'] if f.get('severity') == 'HIGH'])
                    medium = len([f for f in result['findings'] if f.get('severity') == 'MEDIUM'])
                    low = len([f for f in result['findings'] if f.get('severity') == 'LOW'])
                    
                    f.write(f"Severity breakdown:\n")
                    f.write(f"  CRITICAL: {critical}\n")
                    f.write(f"  HIGH: {high}\n")
                    f.write(f"  MEDIUM: {medium}\n")
                    f.write(f"  LOW: {low}\n\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='web_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='WebSeek - Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./webseek.py iplist.txt                        # Basic scan
  ./webseek.py iplist.txt --full                 # Full scan (all checks)
  ./webseek.py iplist.txt --git                  # Git exposure only
  ./webseek.py iplist.txt --backup               # Backup files only
  ./webseek.py iplist.txt -u admin -p admin      # Test default credentials
  ./webseek.py urls.txt -w 20                    # Fast scan (20 workers)
        """
    )
    
    parser.add_argument('input_file', help='File containing IPs or URLs')
    parser.add_argument('--full', action='store_true', help='Full scan (all checks)')
    parser.add_argument('--git', action='store_true', help='Check for .git exposure only')
    parser.add_argument('--backup', action='store_true', help='Check for backup files only')
    parser.add_argument('-u', '--username', help='Username for credential testing')
    parser.add_argument('-p', '--password', help='Password for credential testing')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('--timeout', type=int, default=5, help='Request timeout (default: 5)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read targets
    targets = read_ip_list(args.input_file)
    
    if not targets:
        print(f"{RED}[!] No targets to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting web vulnerability scan...{RESET}")
    print(f"{CYAN}[*] Targets: {len(targets)}{RESET}")
    print(f"{CYAN}[*] Workers: {args.workers}{RESET}")
    print(f"{CYAN}[*] Mode: {'Full' if args.full else 'Git only' if args.git else 'Backup only' if args.backup else 'Standard'}{RESET}")
    print()
    
    results = []
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_target = {executor.submit(scan_web_server, target, args): target for target in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['findings']:
                        critical = len([f for f in result['findings'] if f.get('severity') == 'CRITICAL'])
                        high = len([f for f in result['findings'] if f.get('severity') == 'HIGH'])
                        
                        severity_label = f"{RED}[CRITICAL]{RESET}" if critical > 0 else f"{YELLOW}[HIGH]{RESET}" if high > 0 else f"{BLUE}[VULN]{RESET}"
                        
                        msg = f"{severity_label} {target}"
                        if critical > 0:
                            msg += f" - {critical} CRITICAL"
                        if high > 0:
                            msg += f" - {high} HIGH"
                        
                        print(msg)
                    
                    elif args.verbose:
                        print(f"{BLUE}[*]{RESET} {target} - No findings")
                
                except KeyboardInterrupt:
                    print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
                    executor.shutdown(wait=False, cancel_futures=True)
                    break
                except Exception as e:
                    if args.verbose:
                        print(f"{RED}[!]{RESET} {target} - Error: {e}")
    
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
    
    # Print summary
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    print(f"{CYAN}Scan Complete{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}")
    
    vuln_servers = len([r for r in results if r['findings']])
    total_findings = sum(len(r['findings']) for r in results)
    critical_findings = sum(len([f for f in r['findings'] if f.get('severity') == 'CRITICAL']) for r in results)
    high_findings = sum(len([f for f in r['findings'] if f.get('severity') == 'HIGH']) for r in results)
    
    print(f"Vulnerable servers: {vuln_servers}/{len(targets)}")
    print(f"Total findings: {total_findings}")
    print(f"  CRITICAL: {critical_findings}")
    print(f"  HIGH: {high_findings}")
    
    # Save results
    if results:
        save_weblist(results)
        if total_findings > 0:
            save_findings(results)
        
        # Save specific findings
        git_count = sum(len([f for f in r['findings'] if 'git' in f.get('type', '')]) for r in results)
        backup_count = sum(len([f for f in r['findings'] if f.get('type') == 'backup_file']) for r in results)
        
        if git_count > 0:
            save_git_repos(results)
        if backup_count > 0:
            save_backup_files(results)
        
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
