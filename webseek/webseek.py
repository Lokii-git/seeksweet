#!/usr/bin/env python3
"""
WebSeek v2.0 - Nuclei-Powered Web Vulnerability Scanner
Leverage Nuclei's extensive template library for comprehensive web security scanning

Features:
- 5000+ Nuclei vulnerability templates
- CVE detection and exploitation
- Information disclosure
- Misconfigurations
- Exposed panels and services
- Default credentials
- Git/SVN exposure
- Backup file discovery
- SSL/TLS vulnerabilities
- Security headers analysis
- Automatic template updates
- Markdown report generation with organized results
- Intelligent filtering to exclude noisy/informational findings
- Categorized notable findings report (CVE, Auth, SSL/TLS, etc.)

Usage:
    ./webseek-v2.py                        # Full Nuclei scan (all templates)
    ./webseek-v2.py --severity critical    # Critical issues only
    ./webseek-v2.py --severity high,critical # High and critical only
    ./webseek-v2.py --tags cve,exposure    # Specific tags only
    ./webseek-v2.py --templates custom/    # Custom template directory
    ./webseek-v2.py --update               # Update Nuclei templates
    
Output:
    webseek_report/         - Markdown reports organized by template
    findings.json           - JSON export of all findings
    findings.txt            - Human-readable findings summary
    vulnerable_hosts.txt    - List of vulnerable hosts
    NOTABLE_FINDINGS.txt    - Filtered, categorized actionable findings (NEW!)
    CRITICAL_FINDINGS.txt   - High/Critical priority vulnerabilities
    IP_TO_VULNS.txt         - Vulnerabilities organized by IP
"""

import subprocess
import sys
import json
import os
import argparse
import ipaddress
from pathlib import Path
from datetime import datetime
import shutil

# Import shared utilities
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

# Banner
BANNER = f"""{CYAN}{BOLD}
██╗    ██╗███████╗██████╗ ███████╗███████╗███████╗██╗  ██╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  █████╗  █████╔╝ 
██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
╚███╔███╔╝███████╗██████╔╝███████║███████╗███████╗██║  ██╗
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}WebSeek v2.0 - Nuclei-Powered Web Vulnerability Scanner{RESET}
{BLUE}Smart reporting • 5000+ templates • Report-ready outputs{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""

# Severity colors
SEVERITY_COLORS = {
    'info': BLUE,
    'low': CYAN,
    'medium': YELLOW,
    'high': MAGENTA,
    'critical': RED
}

# Findings to exclude (too noisy/informational for pentest reports)
EXCLUDE_FINDINGS = {
    'addeventlistener-detect',
    'apache-detect',
    'aspnet-version-detect',
    'cookies-without-httponly',
    'cookies-without-httponly-secure',  
    'cookies-without-secure',
    'default-windows-server-page',
    'email-extractor',
    'favicon-detect',
    'fingerprinthub-web-fingerprints',
    'form-detection',
    'index.md',
    'microsoft-iis-version',
    'missing-cookie-samesite-strict',
    'missing-sri',
    'mixed-passive-content',
    'old-copyright',
    'openssh-detect',
    'options-method',
    'robots-txt',
    'robots-txt-endpoint',
    'ssl-dns-names',
    'ssl-issuer',
    'tech-detect',
    'tls-version',
    'tomcat-detect',
    'waf-detect',
    'xss-fuzz',  # Usually false positives
}



def print_banner():
    """Print the tool banner"""
    print(BANNER)


def check_nuclei():
    """Check if Nuclei is installed"""
    try:
        result = subprocess.run(['nuclei', '-version'], 
                              capture_output=True, 
                              text=True,
                              timeout=5)
        if result.returncode == 0:
            version = result.stdout.strip()
            print(f"{GREEN}[+] Nuclei found: {version}{RESET}")
            return True
    except FileNotFoundError:
        print(f"{RED}[!] Nuclei not found!{RESET}")
        print(f"{YELLOW}[*] Install with: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[!] Error checking Nuclei: {e}{RESET}")
        return False


def update_nuclei_templates():
    """Update Nuclei templates"""
    print(f"{YELLOW}[*] Updating Nuclei templates...{RESET}")
    try:
        result = subprocess.run(['nuclei', '-update-templates'],
                              capture_output=True,
                              text=True,
                              timeout=300)
        if result.returncode == 0:
            print(f"{GREEN}[+] Templates updated successfully{RESET}")
            print(result.stdout)
            return True
        else:
            print(f"{RED}[!] Template update failed{RESET}")
            print(result.stderr)
            return False
    except Exception as e:
        print(f"{RED}[!] Error updating templates: {e}{RESET}")
        return False


def read_ip_list(file_path):
    """Read IP addresses or URLs from a file. Supports CIDR notation."""
    file_path = find_ip_list(file_path)
    
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Check if it's CIDR notation
                    if '/' in line and not line.startswith('http'):
                        try:
                            network = ipaddress.ip_network(line, strict=False)
                            for ip in network.hosts():
                                targets.append(str(ip))
                        except ValueError:
                            # Not valid CIDR, treat as URL
                            targets.append(line)
                    else:
                        targets.append(line)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return targets


def prepare_target_file(ip_file):
    """Prepare target file for Nuclei (expand CIDR if needed)"""
    targets = read_ip_list(ip_file)
    
    # Create temporary target file
    temp_file = 'webseek_targets.tmp'
    with open(temp_file, 'w') as f:
        for target in targets:
            # If target doesn't have protocol, add http://
            if not target.startswith('http'):
                f.write(f"http://{target}\n")
                # Also add https version for common ports
                f.write(f"https://{target}\n")
            else:
                f.write(f"{target}\n")
    
    print(f"{GREEN}[+] Prepared {len(targets)} targets for scanning{RESET}")
    return temp_file, len(targets)


def run_nuclei_scan(target_file, args):
    """Run Nuclei scan with specified parameters"""
    
    # Create output directory
    report_dir = 'webseek_report'
    os.makedirs(report_dir, exist_ok=True)
    
    # Build Nuclei command
    cmd = [
        'nuclei',
        '-list', target_file,
        '-markdown-export', report_dir,
        '-json-export', 'findings.json',
        '-stats',
        '-silent'
    ]
    
    # Add severity filter
    if args.severity:
        cmd.extend(['-severity', args.severity])
    
    # Add tags filter
    if args.tags:
        cmd.extend(['-tags', args.tags])
    
    # Add custom templates
    if args.templates:
        cmd.extend(['-templates', args.templates])
    
    # Add rate limit to be nice to internal networks
    if args.rate_limit:
        cmd.extend(['-rate-limit', str(args.rate_limit)])
    
    # Add concurrency
    if args.concurrency:
        cmd.extend(['-concurrency', str(args.concurrency)])
    
    # Add timeout
    if args.timeout:
        cmd.extend(['-timeout', str(args.timeout)])
    
    # Set environment variable for markdown sorting
    env = os.environ.copy()
    env['MARKDOWN_EXPORT_SORT_MODE'] = 'template'
    
    print(f"{YELLOW}[*] Starting Nuclei scan...{RESET}")
    print(f"{BLUE}[*] Command: {' '.join(cmd)}{RESET}")
    print(f"{CYAN}[*] This may take a while depending on target count and template selection{RESET}")
    
    if args.max_scan_time > 0:
        print(f"{CYAN}[*] Maximum scan time: {args.max_scan_time} seconds ({args.max_scan_time//60} minutes){RESET}")
    else:
        print(f"{CYAN}[*] No timeout set - scan will run until completion{RESET}")
    print()
    
    try:
        # Run Nuclei scan with optional timeout
        if args.max_scan_time > 0:
            result = subprocess.run(cmd,
                                  env=env,
                                  capture_output=True,
                                  text=True,
                                  timeout=args.max_scan_time)
        else:
            # No timeout - let it run as long as needed
            result = subprocess.run(cmd,
                                  env=env,
                                  capture_output=True,
                                  text=True)
        
        # Print output
        if result.stdout:
            print(result.stdout)
        
        if result.returncode == 0:
            print(f"\n{GREEN}[+] Scan completed successfully{RESET}")
            return True
        else:
            print(f"\n{YELLOW}[!] Scan completed with warnings{RESET}")
            if result.stderr:
                print(result.stderr)
            return True  # Still process results even with warnings
            
    except subprocess.TimeoutExpired:
        print(f"\n{RED}[!] Scan timed out after {args.max_scan_time} seconds{RESET}")
        print(f"{YELLOW}[*] For large subnets, consider using --max-scan-time 0 for unlimited time{RESET}")
        return False
    except Exception as e:
        print(f"\n{RED}[!] Error running Nuclei: {e}{RESET}")
        return False


def parse_json_results(json_file):
    """Parse Nuclei JSON output and generate summary"""
    if not os.path.exists(json_file):
        print(f"{YELLOW}[!] No JSON results found at {json_file}{RESET}")
        return None
    
    findings = []
    try:
        with open(json_file, 'r') as f:
            for line in f:
                if line.strip():
                    finding = json.loads(line)
                    findings.append(finding)
    except Exception as e:
        print(f"{RED}[!] Error parsing JSON results: {e}{RESET}")
        return None
    
    return findings


def extract_ip(host):
    """Extract IP address from host URL"""
    import re
    # Try to extract IP from URL
    ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', host)
    if ip_match:
        return ip_match.group(1)
    return host


def group_findings_by_vuln(findings):
    """
    Group findings by vulnerability type with affected IPs
    Returns dict: {template_id: {info: ..., ips: [...], findings: [...]}}
    """
    vuln_groups = {}
    
    for finding in findings:
        template_id = finding.get('template-id', 'unknown')
        host = finding.get('host', '')
        ip = extract_ip(host)
        
        if template_id not in vuln_groups:
            vuln_groups[template_id] = {
                'info': finding.get('info', {}),
                'ips': set(),
                'findings': []
            }
        
        vuln_groups[template_id]['ips'].add(ip)
        vuln_groups[template_id]['findings'].append(finding)
    
    # Convert sets to sorted lists
    for template_id in vuln_groups:
        vuln_groups[template_id]['ips'] = sorted(list(vuln_groups[template_id]['ips']))
    
    return vuln_groups


def generate_critical_report(vuln_groups, output_file='CRITICAL_FINDINGS.txt'):
    """Generate report for critical and high severity findings only"""
    critical_vulns = {k: v for k, v in vuln_groups.items() 
                     if v['info'].get('severity', '').lower() in ['critical', 'high']}
    
    if not critical_vulns:
        print(f"{GREEN}[+] No critical or high severity findings!{RESET}")
        return
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("CRITICAL AND HIGH SEVERITY FINDINGS - PRIORITY FOR REPORT\n")
        f.write("="*80 + "\n\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Critical/High Vulnerabilities: {len(critical_vulns)}\n\n")
        
        # Sort by severity (critical first) then by number of affected hosts
        severity_order = {'critical': 0, 'high': 1}
        sorted_vulns = sorted(critical_vulns.items(), 
                            key=lambda x: (
                                severity_order.get(x[1]['info'].get('severity', 'high').lower(), 2),
                                -len(x[1]['ips'])  # More hosts first
                            ))
        
        for idx, (template_id, data) in enumerate(sorted_vulns, 1):
            info = data['info']
            severity = info.get('severity', 'unknown').upper()
            name = info.get('name', 'Unknown Vulnerability')
            description = info.get('description', 'No description available')
            ips = data['ips']
            
            f.write("="*80 + "\n")
            f.write(f"[{idx}] [{severity}] {name}\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Template ID: {template_id}\n")
            f.write(f"Affected Hosts: {len(ips)}\n\n")
            
            # Write IP list
            f.write("AFFECTED SYSTEMS:\n")
            f.write("-" * 40 + "\n")
            for ip in ips:
                f.write(f"  • {ip}\n")
            f.write("\n")
            
            # Description
            f.write("DESCRIPTION:\n")
            f.write("-" * 40 + "\n")
            f.write(f"{description}\n\n")
            
            # CVE/CWE if available
            if 'cve-id' in info:
                f.write(f"CVE ID: {info['cve-id']}\n")
            if 'cwe-id' in info:
                cwe_id = info['cwe-id']
                if isinstance(cwe_id, list):
                    cwe_id = ', '.join(cwe_id)
                f.write(f"CWE ID: {cwe_id}\n")
            
            # CVSS Score
            if 'cvss-score' in info:
                f.write(f"CVSS Score: {info['cvss-score']}\n")
            
            # References
            references = info.get('reference', [])
            if references:
                f.write("\nREFERENCES:\n")
                f.write("-" * 40 + "\n")
                if isinstance(references, list):
                    for ref in references:
                        f.write(f"  • {ref}\n")
                else:
                    f.write(f"  • {references}\n")
            
            f.write("\n\n")
    
    print(f"{GREEN}[+] Critical findings report saved to: {output_file}{RESET}")


def generate_vuln_summary_by_severity(vuln_groups):
    """Generate individual files for each severity level with grouped vulnerabilities"""
    
    severity_files = {
        'critical': 'CRITICAL_VULNS.txt',
        'high': 'HIGH_VULNS.txt', 
        'medium': 'MEDIUM_VULNS.txt',
        'low': 'LOW_VULNS.txt',
        'info': 'INFO_VULNS.txt'
    }
    
    for severity, filename in severity_files.items():
        severity_vulns = {k: v for k, v in vuln_groups.items() 
                         if v['info'].get('severity', '').lower() == severity}
        
        if not severity_vulns:
            continue
        
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write(f"{severity.upper()} SEVERITY FINDINGS\n")
            f.write("="*80 + "\n\n")
            f.write(f"Total {severity.upper()} vulnerabilities: {len(severity_vulns)}\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Sort by number of affected hosts (most affected first)
            sorted_vulns = sorted(severity_vulns.items(), 
                                key=lambda x: -len(x[1]['ips']))
            
            for idx, (template_id, data) in enumerate(sorted_vulns, 1):
                info = data['info']
                name = info.get('name', 'Unknown')
                ips = data['ips']
                
                f.write(f"[{idx}] {name}\n")
                f.write("-" * 80 + "\n")
                f.write(f"Template: {template_id}\n")
                f.write(f"Affected Hosts ({len(ips)}): {', '.join(ips)}\n")
                f.write("\n")
        
        print(f"{CYAN}[+] {severity.upper()} findings saved to: {filename}{RESET}")


def generate_ip_to_vuln_report(vuln_groups, output_file='IP_TO_VULNS.txt'):
    """Generate report showing vulnerabilities per IP address"""
    
    # Invert the mapping: IP -> list of vulnerabilities
    ip_to_vulns = {}
    
    for template_id, data in vuln_groups.items():
        info = data['info']
        severity = info.get('severity', 'unknown').lower()
        name = info.get('name', 'Unknown')
        
        for ip in data['ips']:
            if ip not in ip_to_vulns:
                ip_to_vulns[ip] = []
            ip_to_vulns[ip].append({
                'template_id': template_id,
                'name': name,
                'severity': severity
            })
    
    # Sort IPs by number of vulnerabilities (most vulnerable first)
    sorted_ips = sorted(ip_to_vulns.items(), key=lambda x: -len(x[1]))
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("="*80 + "\n")
        f.write("VULNERABILITIES BY IP ADDRESS\n")
        f.write("="*80 + "\n\n")
        f.write(f"Total Vulnerable Hosts: {len(ip_to_vulns)}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        for ip, vulns in sorted_ips:
            # Count by severity
            severity_counts = {}
            for v in vulns:
                sev = v['severity']
                severity_counts[sev] = severity_counts.get(sev, 0) + 1
            
            f.write("="*80 + "\n")
            f.write(f"HOST: {ip}\n")
            f.write("="*80 + "\n")
            f.write(f"Total Vulnerabilities: {len(vulns)}\n")
            
            # Show severity breakdown
            f.write("Severity Breakdown: ")
            sev_parts = []
            for sev in ['critical', 'high', 'medium', 'low', 'info']:
                if sev in severity_counts:
                    sev_parts.append(f"{sev.upper()}: {severity_counts[sev]}")
            f.write(", ".join(sev_parts) + "\n\n")
            
            # Sort vulnerabilities by severity
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_vulns = sorted(vulns, key=lambda x: severity_order.get(x['severity'], 5))
            
            f.write("VULNERABILITIES:\n")
            f.write("-" * 80 + "\n")
            for idx, vuln in enumerate(sorted_vulns, 1):
                f.write(f"{idx:3d}. [{vuln['severity'].upper()}] {vuln['name']}\n")
                f.write(f"     Template: {vuln['template_id']}\n")
            f.write("\n")
    
    print(f"{CYAN}[+] IP-to-vulnerability mapping saved to: {output_file}{RESET}")


def generate_notable_findings_report(vuln_groups, output_file='NOTABLE_FINDINGS.txt'):
    """Generate filtered report excluding noisy/informational findings
    
    This report focuses on actionable findings for pentest reports by:
    - Excluding version detection and fingerprinting
    - Removing informational cookie/header flags  
    - Filtering out common tech detection
    - Categorizing findings by type (CVE, Auth, SSL/TLS, etc.)
    """
    
    # Filter out excluded findings
    notable_vulns = {k: v for k, v in vuln_groups.items() 
                     if k not in EXCLUDE_FINDINGS}
    
    if not notable_vulns:
        print(f"{YELLOW}[!] No notable findings after filtering{RESET}")
        return
    
    # Categorize findings
    categorized = {
        'CVE': {},
        'Authentication': {},
        'SSL/TLS': {},
        'Configuration': {},
        'Information Disclosure': {},
        'Network Services': {},
    }
    
    for template_id, data in notable_vulns.items():
        # Categorize based on template ID patterns
        if template_id.startswith('CVE-'):
            categorized['CVE'][template_id] = data
        elif any(x in template_id for x in ['login', 'auth', 'password', 'credential']):
            categorized['Authentication'][template_id] = data
        elif any(x in template_id for x in ['ssl', 'tls', 'cert', 'cipher']):
            categorized['SSL/TLS'][template_id] = data
        elif any(x in template_id for x in ['smb', 'ssh', 'rdp', 'snmp', 'ldap', 'mysql', 'pgsql', 'smtp', 'nfs', 'msmq']):
            categorized['Network Services'][template_id] = data
        elif any(x in template_id for x in ['disclosure', 'leak', 'trace', 'stacktrace', 'exposure']):
            categorized['Information Disclosure'][template_id] = data
        else:
            categorized['Configuration'][template_id] = data
    
    # Calculate stats
    total_notable = sum(len(category) for category in categorized.values())
    total_ips = set()
    for category in categorized.values():
        for data in category.values():
            total_ips.update(data['ips'])
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("="*100 + "\n")
        f.write("NOTABLE NUCLEI FINDINGS - FILTERED REPORT\n")
        f.write("Excludes: Informational/Detection findings, Version detection, Cookie flags, etc.\n")
        f.write("="*100 + "\n\n")
        
        f.write(f"Total Notable Findings: {total_notable}\n")
        f.write(f"Affected IPs: {len(total_ips)}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Write categorized findings
        for category_name, category_findings in categorized.items():
            if not category_findings:
                continue
            
            f.write("\n" + "="*100 + "\n")
            f.write(f"{category_name.upper()}\n")
            f.write("="*100 + "\n\n")
            
            # Sort by severity and number of affected hosts
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
            sorted_findings = sorted(category_findings.items(), 
                                   key=lambda x: (severity_order.get(x[1]['info'].get('severity', 'info').lower(), 5), 
                                                 -len(x[1]['ips'])))
            
            for template_id, data in sorted_findings:
                info = data['info']
                severity = info.get('severity', 'unknown').upper()
                name = info.get('name', 'Unknown')
                description = info.get('description', 'No description available')
                ips = sorted(data['ips'])
                
                f.write(f"[{template_id}]\n")
                f.write(f"  Name: {name}\n")
                f.write(f"  Severity: {severity}\n")
                f.write(f"  Count: {len(ips)}\n")
                f.write(f"  Affected IPs: {', '.join(ips)}\n")
                
                # Truncate description if too long
                if description:
                    desc_clean = description.replace('\n', ' ').strip()[:300]
                    f.write(f"  Description: {desc_clean}\n")
                
                # Add references if available
                references = info.get('reference', [])
                if references:
                    if isinstance(references, list):
                        f.write(f"  References: {references[0]}\n")
                    else:
                        f.write(f"  References: {references}\n")
                
                f.write("\n")
    
    print(f"{GREEN}[+] Notable findings report saved to: {output_file}{RESET}")
    print(f"{GREEN}    (Filtered from {len(vuln_groups)} to {total_notable} actionable findings){RESET}")


def generate_summary(findings):

    """Generate human-readable summary of findings"""
    if not findings:
        print(f"{GREEN}[+] No vulnerabilities found!{RESET}")
        return
    
    # Count by severity
    severity_counts = {}
    vulnerable_hosts = set()
    templates_triggered = set()
    
    for finding in findings:
        severity = finding.get('info', {}).get('severity', 'unknown').lower()
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        host = finding.get('host', '')
        if host:
            ip = extract_ip(host)
            vulnerable_hosts.add(ip)
        
        template_id = finding.get('template-id', '')
        if template_id:
            templates_triggered.add(template_id)
    
    # Group findings by vulnerability
    vuln_groups = group_findings_by_vuln(findings)
    
    # Print summary
    print(f"\n{BOLD}{CYAN}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}SCAN SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}{'='*60}{RESET}\n")
    
    print(f"{BOLD}Total Findings:{RESET} {len(findings)}")
    print(f"{BOLD}Unique Vulnerabilities:{RESET} {len(vuln_groups)}")
    print(f"{BOLD}Vulnerable Hosts:{RESET} {len(vulnerable_hosts)}")
    print(f"{BOLD}Templates Triggered:{RESET} {len(templates_triggered)}\n")
    
    print(f"{BOLD}Findings by Severity:{RESET}")
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        count = severity_counts.get(severity, 0)
        if count > 0:
            color = SEVERITY_COLORS.get(severity, RESET)
            print(f"  {color}[{severity.upper()}]{RESET} {count}")
    
    # Generate smart reports
    print(f"\n{YELLOW}[*] Generating smart reports for pentest documentation...{RESET}")
    
    # Critical/High priority report
    generate_critical_report(vuln_groups)
    
    # Severity-based reports
    generate_vuln_summary_by_severity(vuln_groups)
    
    # IP-to-vulnerability mapping
    generate_ip_to_vuln_report(vuln_groups)
    
    # Notable findings (filtered, categorized)
    generate_notable_findings_report(vuln_groups)
    
    # Write findings summary (legacy format)
    with open('findings.txt', 'w', encoding='utf-8') as f:
        f.write("="*60 + "\n")
        f.write("WEBSEEK V2 SCAN RESULTS\n")
        f.write("="*60 + "\n\n")
        f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total Findings: {len(findings)}\n")
        f.write(f"Vulnerable Hosts: {len(vulnerable_hosts)}\n\n")
        
        f.write("Findings by Severity:\n")
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                f.write(f"  [{severity.upper()}] {count}\n")
        
        f.write("\n" + "="*60 + "\n")
        f.write("DETAILED FINDINGS\n")
        f.write("="*60 + "\n\n")
        
        # Sort findings by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(findings, 
                                key=lambda x: severity_order.get(
                                    x.get('info', {}).get('severity', 'info').lower(), 5))
        
        for finding in sorted_findings:
            info = finding.get('info', {})
            severity = info.get('severity', 'unknown').upper()
            name = info.get('name', 'Unknown')
            template_id = finding.get('template-id', '')
            host = finding.get('host', '')
            matched_at = finding.get('matched-at', '')
            
            f.write(f"[{severity}] {name}\n")
            f.write(f"  Template: {template_id}\n")
            f.write(f"  Host: {host}\n")
            if matched_at:
                f.write(f"  URL: {matched_at}\n")
            
            # Add description if available
            description = info.get('description', '')
            if description:
                f.write(f"  Description: {description}\n")
            
            # Add reference if available
            reference = info.get('reference', [])
            if reference:
                f.write(f"  References: {', '.join(reference) if isinstance(reference, list) else reference}\n")
            
            f.write("\n")
    
    # Write vulnerable hosts list
    with open('vulnerable_hosts.txt', 'w', encoding='utf-8') as f:
        for host in sorted(vulnerable_hosts):
            f.write(f"{host}\n")
    
    print(f"\n{BOLD}{GREEN}{'='*60}{RESET}")
    print(f"{BOLD}{GREEN}REPORT FILES GENERATED{RESET}")
    print(f"{BOLD}{GREEN}{'='*60}{RESET}")
    print(f"\n{CYAN}📋 For Report Writing:{RESET}")
    print(f"  {RED}• CRITICAL_FINDINGS.txt{RESET}     - Priority vulnerabilities with affected IPs")
    print(f"  {MAGENTA}• HIGH_VULNS.txt{RESET}             - High severity issues grouped")
    print(f"  {YELLOW}• MEDIUM_VULNS.txt{RESET}           - Medium severity issues grouped")
    
    print(f"\n{CYAN}🔍 Detailed Analysis:{RESET}")
    print(f"  • IP_TO_VULNS.txt           - Vulnerabilities per host (most vulnerable first)")
    print(f"  • LOW_VULNS.txt             - Low severity findings")
    print(f"  • INFO_VULNS.txt            - Informational findings")
    
    print(f"\n{CYAN}📊 Standard Output:{RESET}")
    print(f"  • findings.txt              - Complete findings list")
    print(f"  • findings.json             - JSON export")
    print(f"  • vulnerable_hosts.txt      - Simple IP list")
    print(f"  • webseek_report/           - Nuclei markdown reports (organized by template)")
    
    print(f"\n{YELLOW}💡 Tip: Start with CRITICAL_FINDINGS.txt for your pentest report!{RESET}\n")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='WebSeek v2.0 - Nuclei-Powered Web Vulnerability Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                              # Full scan with all templates
  %(prog)s --severity critical,high     # Only critical and high severity
  %(prog)s --tags cve,exposure          # Only CVEs and exposures
  %(prog)s --templates custom/          # Use custom template directory
  %(prog)s --update                     # Update Nuclei templates
  %(prog)s --rate-limit 150             # Limit to 150 requests/second
        """
    )
    
    parser.add_argument('ip_file', nargs='?', default='iplist.txt',
                       help='File containing IP addresses or URLs (supports CIDR)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (compatibility flag, always verbose)')
    parser.add_argument('--severity', '-s', 
                       help='Filter by severity (critical,high,medium,low,info)')
    parser.add_argument('--tags', '-t',
                       help='Filter by tags (cve,exposure,panel,default-login,etc)')
    parser.add_argument('--templates', '-tp',
                       help='Custom template directory or file')
    parser.add_argument('--rate-limit', '-rl', type=int, default=150,
                       help='Rate limit (requests per second, default: 150)')
    parser.add_argument('--concurrency', '-c', type=int, default=25,
                       help='Concurrency level (default: 25)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Timeout per request in seconds (default: 10)')
    parser.add_argument('--max-scan-time', type=int, default=0,
                       help='Maximum scan time in seconds (default: 0 = unlimited)')
    parser.add_argument('--update', '-u', action='store_true',
                       help='Update Nuclei templates before scanning')
    parser.add_argument('--skip-update', action='store_true',
                       help='Skip automatic template update check')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check if Nuclei is installed
    if not check_nuclei():
        sys.exit(1)
    
    # Update templates if requested
    if args.update:
        if not update_nuclei_templates():
            print(f"{YELLOW}[!] Template update failed, continuing anyway...{RESET}")
    elif not args.skip_update:
        print(f"{BLUE}[*] Tip: Use --update to update Nuclei templates{RESET}")
    
    # Prepare target file
    try:
        target_file, target_count = prepare_target_file(args.ip_file)
    except Exception as e:
        print(f"{RED}[!] Error preparing targets: {e}{RESET}")
        sys.exit(1)
    
    # Run scan
    try:
        success = run_nuclei_scan(target_file, args)
        
        if success:
            # Parse and summarize results
            findings = parse_json_results('findings.json')
            if findings is not None:
                generate_summary(findings)
        
    finally:
        # Cleanup temp file
        if os.path.exists(target_file):
            os.remove(target_file)
    
    print(f"\n{CYAN}{'='*60}{RESET}")
    print(f"{GREEN}[+] WebSeek v2 scan complete!{RESET}")
    print(f"{CYAN}{'='*60}{RESET}\n")


if __name__ == '__main__':
    main()
