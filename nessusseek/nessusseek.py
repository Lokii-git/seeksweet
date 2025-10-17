#!/usr/bin/env python3
"""
NessusSeek v1.0 - Nessus Vulnerability Scanner Integration
Automate Nessus scans and parse results for internal pentests

Features:
- Launch Nessus scans via REST API
- Monitor scan progress in real-time
- Download and parse results (CSV/JSON)
- Categorize findings by severity
- Generate comprehensive vulnerability reports
- Integration with SeekSweet workflow

Usage:
    ./nessusseek.py                                      # Interactive mode (prompts for credentials)
    ./nessusseek.py --activation-code XXXX-XXXX-XXXX     # Activate Nessus Essentials/Pro
    ./nessusseek.py -t targets.txt                       # Launch scan from IP list
    ./nessusseek.py -t targets.txt -n "My Scan"          # Custom scan name
    ./nessusseek.py --list                               # List existing scans
    ./nessusseek.py --download SCAN_ID                   # Download results from existing scan
    
Output:
    nessuslist.txt          - List of vulnerable hosts
    nessus_findings.txt     - Detailed vulnerability report by severity
    nessus_results.csv      - Full CSV export from Nessus
    nessus_results.json     - Full JSON export from Nessus
    NESSUS_GUIDE.txt        - Remediation guidance

Requirements:
    pip install requests urllib3
    
Note:
    - Requires Nessus Professional or Essentials
    - Nessus must be running (default: https://localhost:8834)
    - API keys can be generated in Nessus UI: Settings → API Keys
"""

import argparse
import requests
import urllib3
import json
import time
import sys
import os
from datetime import datetime
from pathlib import Path
import csv

# Disable SSL warnings for self-signed Nessus certificate
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
{'='*80}
NessusSeek v1.0 - Nessus Vulnerability Scanner Integration
Part of the SeekSweet Framework
{'='*80}
{RESET}"""


class NessusAPI:
    """Nessus API Client"""
    
    def __init__(self, url, access_key, secret_key, verify_ssl=False):
        self.url = url.rstrip('/')
        self.access_key = access_key
        self.secret_key = secret_key
        self.verify_ssl = verify_ssl
        self.headers = {
            'X-ApiKeys': f'accessKey={access_key}; secretKey={secret_key}',
            'Content-Type': 'application/json'
        }
    
    def register_nessus(self, activation_code):
        """Register Nessus with activation code (Essentials/Professional)"""
        try:
            # First check if already registered
            response = requests.get(
                f'{self.url}/server/properties',
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )
            
            if response.status_code == 200:
                props = response.json()
                if props.get('license', {}).get('type') in ['PV', 'VS', 'SC']:
                    print(f"{YELLOW}[*] Nessus already registered with {props['license']['type']} license{RESET}")
                    return True, "Already registered"
            
            # Register with activation code
            print(f"{CYAN}[*] Registering Nessus with activation code...{RESET}")
            register_data = {
                'code': activation_code
            }
            
            response = requests.post(
                f'{self.url}/plugins/plugin-sets/register',
                headers=self.headers,
                json=register_data,
                verify=self.verify_ssl,
                timeout=30
            )
            
            if response.status_code == 200:
                print(f"{GREEN}[+] Nessus registered successfully!{RESET}")
                return True, "Registration successful"
            else:
                return False, f"HTTP {response.status_code}: {response.text}"
                
        except Exception as e:
            return False, str(e)
    
    def test_connection(self):
        """Test connection to Nessus"""
        try:
            response = requests.get(
                f'{self.url}/server/status',
                headers=self.headers,
                verify=self.verify_ssl,
                timeout=10
            )
            if response.status_code == 200:
                data = response.json()
                return True, data
            else:
                return False, f"HTTP {response.status_code}"
        except Exception as e:
            return False, str(e)
    
    def list_scans(self):
        """List all scans"""
        try:
            response = requests.get(
                f'{self.url}/scans',
                headers=self.headers,
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                return response.json().get('scans', [])
            return []
        except Exception as e:
            print(f"{RED}[!] Error listing scans: {e}{RESET}")
            return []
    
    def list_policies(self):
        """List available scan policies/templates"""
        try:
            response = requests.get(
                f'{self.url}/editor/policy/templates',
                headers=self.headers,
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                return response.json().get('templates', [])
            return []
        except Exception as e:
            print(f"{RED}[!] Error listing policies: {e}{RESET}")
            return []
    
    def create_scan(self, name, targets, policy_uuid='731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65'):
        """
        Create a new scan
        Default policy: Basic Network Scan
        """
        try:
            # Get policy details
            response = requests.get(
                f'{self.url}/editor/policy/templates',
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            # Try to find "Basic Network Scan" or "Advanced Scan"
            templates = response.json().get('templates', [])
            template_uuid = None
            
            for template in templates:
                if 'basic' in template.get('title', '').lower() or 'advanced' in template.get('title', '').lower():
                    template_uuid = template.get('uuid')
                    break
            
            if not template_uuid and templates:
                # Use first available template
                template_uuid = templates[0].get('uuid')
            
            if not template_uuid:
                return None, "No scan templates available"
            
            scan_data = {
                'uuid': template_uuid,
                'settings': {
                    'name': name,
                    'enabled': True,
                    'text_targets': targets,
                    'description': f'SeekSweet scan created at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
                }
            }
            
            response = requests.post(
                f'{self.url}/scans',
                headers=self.headers,
                json=scan_data,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                scan_id = response.json()['scan']['id']
                return scan_id, None
            else:
                return None, f"HTTP {response.status_code}: {response.text}"
                
        except Exception as e:
            return None, str(e)
    
    def launch_scan(self, scan_id):
        """Launch a scan"""
        try:
            response = requests.post(
                f'{self.url}/scans/{scan_id}/launch',
                headers=self.headers,
                verify=self.verify_ssl
            )
            return response.status_code == 200
        except Exception as e:
            print(f"{RED}[!] Error launching scan: {e}{RESET}")
            return False
    
    def get_scan_status(self, scan_id):
        """Get scan status and progress"""
        try:
            response = requests.get(
                f'{self.url}/scans/{scan_id}',
                headers=self.headers,
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                data = response.json()
                info = data.get('info', {})
                return {
                    'status': info.get('status'),
                    'progress': info.get('scanner_progress', 0),
                    'hosts': info.get('hostcount', 0),
                    'vulnerabilities': data.get('vulnerabilities', {})
                }
            return None
        except Exception as e:
            print(f"{RED}[!] Error getting scan status: {e}{RESET}")
            return None
    
    def export_scan(self, scan_id, format='csv'):
        """
        Export scan results
        format: 'csv' or 'nessus' (JSON)
        """
        try:
            # Request export
            export_data = {'format': format}
            response = requests.post(
                f'{self.url}/scans/{scan_id}/export',
                headers=self.headers,
                json=export_data,
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                return None, f"Export request failed: HTTP {response.status_code}"
            
            file_id = response.json()['file']
            
            # Wait for export to be ready
            print(f"{YELLOW}[*] Preparing export...{RESET}")
            max_wait = 300  # 5 minutes
            waited = 0
            
            while waited < max_wait:
                status_response = requests.get(
                    f'{self.url}/scans/{scan_id}/export/{file_id}/status',
                    headers=self.headers,
                    verify=self.verify_ssl
                )
                
                if status_response.status_code == 200:
                    status = status_response.json()['status']
                    if status == 'ready':
                        break
                
                time.sleep(5)
                waited += 5
                print(f"{YELLOW}[*] Waiting for export... ({waited}s){RESET}")
            
            if waited >= max_wait:
                return None, "Export timeout"
            
            # Download export
            download_response = requests.get(
                f'{self.url}/scans/{scan_id}/export/{file_id}/download',
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if download_response.status_code == 200:
                return download_response.content, None
            else:
                return None, f"Download failed: HTTP {download_response.status_code}"
                
        except Exception as e:
            return None, str(e)


def parse_csv_results(csv_content):
    """Parse CSV results from Nessus"""
    results = {
        'critical': [],
        'high': [],
        'medium': [],
        'low': [],
        'info': []
    }
    
    hosts_summary = {}
    
    try:
        # Parse CSV
        lines = csv_content.decode('utf-8').splitlines()
        reader = csv.DictReader(lines)
        
        for row in reader:
            host = row.get('Host', 'Unknown')
            plugin_name = row.get('Name', row.get('Plugin Name', 'Unknown'))
            severity = row.get('Risk', row.get('Severity', 'Unknown')).lower()
            port = row.get('Port', 'N/A')
            protocol = row.get('Protocol', 'N/A')
            cve = row.get('CVE', 'N/A')
            description = row.get('Description', row.get('Synopsis', 'No description'))
            
            vuln = {
                'host': host,
                'name': plugin_name,
                'port': port,
                'protocol': protocol,
                'cve': cve,
                'description': description[:200] + '...' if len(description) > 200 else description
            }
            
            # Categorize by severity
            if severity == 'critical':
                results['critical'].append(vuln)
            elif severity == 'high':
                results['high'].append(vuln)
            elif severity == 'medium':
                results['medium'].append(vuln)
            elif severity == 'low':
                results['low'].append(vuln)
            else:
                results['info'].append(vuln)
            
            # Track hosts
            if host not in hosts_summary:
                hosts_summary[host] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
            hosts_summary[host][severity] = hosts_summary[host].get(severity, 0) + 1
        
    except Exception as e:
        print(f"{RED}[!] Error parsing CSV: {e}{RESET}")
    
    return results, hosts_summary


def save_nessuslist(hosts_summary, filename='nessuslist.txt'):
    """Save list of vulnerable hosts"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("NESSUS SCAN - VULNERABLE HOSTS\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Sort by severity (most critical first)
            sorted_hosts = sorted(hosts_summary.items(),
                                key=lambda x: (x[1]['critical'], x[1]['high'], x[1]['medium']),
                                reverse=True)
            
            for host, counts in sorted_hosts:
                if counts['critical'] > 0 or counts['high'] > 0:
                    f.write(f"{host}\n")
                    f.write(f"  Critical: {counts['critical']}, High: {counts['high']}, ")
                    f.write(f"Medium: {counts['medium']}, Low: {counts['low']}\n\n")
        
        print(f"{GREEN}[+] Host list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving host list: {e}{RESET}")


def save_findings_report(results, filename='nessus_findings.txt'):
    """Save detailed findings report"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("NESSUS VULNERABILITY SCAN - DETAILED FINDINGS\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            # Summary
            f.write("SEVERITY SUMMARY:\n")
            f.write("-" * 40 + "\n")
            f.write(f"Critical: {len(results['critical'])}\n")
            f.write(f"High:     {len(results['high'])}\n")
            f.write(f"Medium:   {len(results['medium'])}\n")
            f.write(f"Low:      {len(results['low'])}\n")
            f.write(f"Info:     {len(results['info'])}\n\n")
            
            # Critical findings
            if results['critical']:
                f.write("=" * 80 + "\n")
                f.write("CRITICAL VULNERABILITIES\n")
                f.write("=" * 80 + "\n\n")
                for i, vuln in enumerate(results['critical'], 1):
                    f.write(f"[{i}] {vuln['name']}\n")
                    f.write(f"Host: {vuln['host']}\n")
                    f.write(f"Port: {vuln['port']}/{vuln['protocol']}\n")
                    if vuln['cve'] != 'N/A':
                        f.write(f"CVE: {vuln['cve']}\n")
                    f.write(f"Description: {vuln['description']}\n")
                    f.write("\n" + "-" * 80 + "\n\n")
            
            # High findings
            if results['high']:
                f.write("=" * 80 + "\n")
                f.write("HIGH VULNERABILITIES\n")
                f.write("=" * 80 + "\n\n")
                for i, vuln in enumerate(results['high'], 1):
                    f.write(f"[{i}] {vuln['name']}\n")
                    f.write(f"Host: {vuln['host']}\n")
                    f.write(f"Port: {vuln['port']}/{vuln['protocol']}\n")
                    if vuln['cve'] != 'N/A':
                        f.write(f"CVE: {vuln['cve']}\n")
                    f.write(f"Description: {vuln['description']}\n")
                    f.write("\n" + "-" * 80 + "\n\n")
            
            # Medium findings (summary only)
            if results['medium']:
                f.write("=" * 80 + "\n")
                f.write(f"MEDIUM VULNERABILITIES ({len(results['medium'])} findings)\n")
                f.write("=" * 80 + "\n")
                f.write("See nessus_results.csv for full details\n\n")
        
        print(f"{GREEN}[+] Findings report saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving findings report: {e}{RESET}")


def save_nessus_guide(filename='NESSUS_GUIDE.txt'):
    """Generate Nessus remediation guide"""
    guide_content = """================================================================================
NESSUS VULNERABILITY SCAN - REMEDIATION GUIDE
================================================================================

This guide provides next steps for addressing vulnerabilities found by Nessus.

================================================================================
CRITICAL VULNERABILITIES - IMMEDIATE ACTION REQUIRED
================================================================================

Critical vulnerabilities pose an immediate risk and should be addressed within
24-48 hours. Common critical findings include:

1. REMOTE CODE EXECUTION (RCE)
   - Patch immediately
   - If patching not possible, isolate system from network
   - Consider using WAF or IPS rules as temporary mitigation

2. AUTHENTICATION BYPASS
   - Disable affected service until patched
   - Review access logs for signs of exploitation
   - Implement additional authentication layers if possible

3. KNOWN EXPLOITED VULNERABILITIES (KEVs)
   - Check CISA KEV catalog: https://www.cisa.gov/known-exploited-vulnerabilities
   - Prioritize based on active exploitation in the wild
   - Apply patches immediately

4. DEFAULT CREDENTIALS
   - Change all default passwords immediately
   - Implement strong password policy
   - Enable MFA where possible

================================================================================
HIGH VULNERABILITIES - ACTION REQUIRED WITHIN 7 DAYS
================================================================================

High severity vulnerabilities should be addressed within one week:

1. MISSING SECURITY PATCHES
   - Schedule maintenance window for patching
   - Test patches in dev/staging before production
   - Document all changes

2. WEAK ENCRYPTION/SSL/TLS
   - Disable SSLv2, SSLv3, TLS 1.0, TLS 1.1
   - Implement TLS 1.2 or higher
   - Use strong cipher suites only

3. INFORMATION DISCLOSURE
   - Review what information is being exposed
   - Disable banner grabbing where possible
   - Remove version information from headers

4. PRIVILEGE ESCALATION
   - Review user permissions
   - Implement principle of least privilege
   - Enable auditing and monitoring

================================================================================
MEDIUM/LOW VULNERABILITIES - SCHEDULE FOR REMEDIATION
================================================================================

Address within 30-90 days based on business risk:

1. Configuration Issues
2. End-of-Life Software
3. Informational Findings
4. Best Practice Violations

================================================================================
REMEDIATION WORKFLOW
================================================================================

1. TRIAGE
   - Review all critical and high findings
   - Verify false positives
   - Assess business impact

2. PRIORITIZE
   - Internet-facing systems first
   - Systems with sensitive data second
   - Internal systems third

3. REMEDIATE
   - Patch systems
   - Implement configuration changes
   - Deploy compensating controls if needed

4. VALIDATE
   - Re-scan after remediation
   - Verify fixes are effective
   - Document all changes

5. REPORT
   - Update stakeholders
   - Track remediation metrics
   - Schedule follow-up scans

================================================================================
COMMON CVE RESOURCES
================================================================================

• NIST NVD: https://nvd.nist.gov/
• CVE Details: https://www.cvedetails.com/
• Exploit-DB: https://www.exploit-db.com/
• CISA Alerts: https://www.cisa.gov/news-events/cybersecurity-advisories

================================================================================
NESSUS BEST PRACTICES
================================================================================

1. REGULAR SCANNING
   - Weekly for critical systems
   - Monthly for all systems
   - After any infrastructure changes

2. CREDENTIALED SCANS
   - Provide credentials for deeper scanning
   - Detects missing patches more accurately
   - Finds configuration issues

3. CONTINUOUS MONITORING
   - Integrate with SIEM
   - Set up automated alerting
   - Track metrics over time

4. VULNERABILITY MANAGEMENT PROGRAM
   - Define SLAs for remediation
   - Assign ownership for findings
   - Regular reporting to management

================================================================================
NESSUS SCAN TYPES
================================================================================

• Basic Network Scan: Standard vulnerability scan
• Web Application Tests: OWASP Top 10, SQLi, XSS
• Credentialed Patch Audit: Deep system analysis
• Policy Compliance: CIS benchmarks, PCI DSS
• Malware Scan: Detect malicious software
• Advanced Scan: Comprehensive assessment

================================================================================
INTEGRATION WITH OTHER TOOLS
================================================================================

1. VULNERABILITY VALIDATION
   - Use Metasploit to verify exploitability
   - Test in isolated environment first

2. PATCH MANAGEMENT
   - WSUS for Windows
   - Ansible/Chef/Puppet for automation
   - Track patch deployment

3. ASSET MANAGEMENT
   - Correlate findings with asset inventory
   - Track system owners
   - Map to business criticality

================================================================================
REPORTING
================================================================================

1. EXECUTIVE SUMMARY
   - High-level metrics
   - Risk scoring
   - Trend analysis

2. TECHNICAL DETAILS
   - Full finding list
   - Remediation steps
   - Validation evidence

3. COMPLIANCE MAPPING
   - PCI DSS requirements
   - HIPAA controls
   - ISO 27001 standards

================================================================================
CREATED BY: NessusSeek v1.0 (SeekSweet Framework)
================================================================================
"""
    
    try:
        with open(filename, 'w') as f:
            f.write(guide_content)
        print(f"{GREEN}[+] Remediation guide saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving guide: {e}{RESET}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='NessusSeek v1.0 - Nessus Vulnerability Scanner Integration',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                      # Interactive mode
  %(prog)s --activation-code XXXX-XXXX-XXXX     # Activate Nessus (fresh vRPA)
  %(prog)s -t iplist.txt                        # Launch scan from IP list
  %(prog)s -t iplist.txt -n "My Scan"           # Custom scan name
  %(prog)s --list                               # List existing scans
  %(prog)s --download 42                        # Download results from scan ID 42
        """
    )
    
    parser.add_argument('-t', '--targets', 
                       help='Target IP list file')
    parser.add_argument('-n', '--name', 
                       help='Scan name (default: SeekSweet-TIMESTAMP)')
    parser.add_argument('--url', default='https://localhost:8834',
                       help='Nessus URL (default: https://localhost:8834)')
    parser.add_argument('--access-key',
                       help='Nessus API access key')
    parser.add_argument('--secret-key',
                       help='Nessus API secret key')
    parser.add_argument('--activation-code',
                       help='Nessus activation code (for fresh installations)')
    parser.add_argument('--list', action='store_true',
                       help='List existing scans')
    parser.add_argument('--download', type=int, metavar='SCAN_ID',
                       help='Download results from existing scan')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    print(BANNER)
    
    # Try to get API keys from environment variables first
    if not args.access_key:
        args.access_key = os.environ.get('NESSUS_ACCESS_KEY', '')
    
    if not args.secret_key:
        args.secret_key = os.environ.get('NESSUS_SECRET_KEY', '')
    
    if not args.url or args.url == 'https://localhost:8834':
        env_url = os.environ.get('NESSUS_URL', '')
        if env_url:
            args.url = env_url
    
    # Prompt for API keys if still not provided
    if not args.access_key:
        print(f"{YELLOW}[*] Nessus API keys can be generated in: Settings → API Keys{RESET}")
        print(f"{YELLOW}[*] Or load from file: source ~/.nessus_keys{RESET}\n")
        args.access_key = input(f"{CYAN}Enter Nessus Access Key: {RESET}").strip()
    
    if not args.secret_key:
        args.secret_key = input(f"{CYAN}Enter Nessus Secret Key: {RESET}").strip()
    
    if not args.access_key or not args.secret_key:
        print(f"{RED}[!] API keys are required{RESET}")
        print(f"{YELLOW}[*] Set environment variables or use --access-key and --secret-key{RESET}")
        return
    
    # Initialize Nessus API
    nessus = NessusAPI(args.url, args.access_key, args.secret_key)
    
    # Handle activation code if provided
    if args.activation_code:
        print(f"\n{BLUE}[*] Registering Nessus with activation code...{RESET}")
        success, message = nessus.register_nessus(args.activation_code)
        if not success:
            print(f"{RED}[!] Registration failed: {message}{RESET}")
            print(f"{YELLOW}[*] Note: You may need to complete setup first via Web UI{RESET}")
            return
        print(f"{GREEN}[+] {message}{RESET}")
    
    # Test connection
    print(f"\n{BLUE}[*] Testing connection to Nessus...{RESET}")
    success, result = nessus.test_connection()
    
    if not success:
        print(f"{RED}[!] Connection failed: {result}{RESET}")
        print(f"{YELLOW}[*] Make sure Nessus is running: sudo systemctl start nessusd{RESET}")
        return
    
    print(f"{GREEN}[+] Connected to Nessus{RESET}")
    if args.verbose and isinstance(result, dict):
        print(f"{BLUE}[*] Server: {result.get('server_version', 'Unknown')}{RESET}")
    
    # List scans mode
    if args.list:
        print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
        print(f"{CYAN}{BOLD}EXISTING SCANS{RESET}")
        print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
        
        scans = nessus.list_scans()
        if not scans:
            print(f"{YELLOW}[*] No scans found{RESET}")
            return
        
        for scan in scans:
            status_color = GREEN if scan.get('status') == 'completed' else YELLOW
            print(f"ID: {scan.get('id')}")
            print(f"  Name: {scan.get('name')}")
            print(f"  Status: {status_color}{scan.get('status')}{RESET}")
            print(f"  Created: {scan.get('creation_date', 'Unknown')}")
            print()
        
        return
    
    # Download results mode
    if args.download:
        scan_id = args.download
        
        print(f"\n{BLUE}[*] Downloading results from scan ID: {scan_id}{RESET}")
        
        # Export as CSV
        csv_content, error = nessus.export_scan(scan_id, format='csv')
        if error:
            print(f"{RED}[!] Error exporting CSV: {error}{RESET}")
            return
        
        # Save CSV
        csv_filename = 'nessus_results.csv'
        with open(csv_filename, 'wb') as f:
            f.write(csv_content)
        print(f"{GREEN}[+] CSV results saved to: {csv_filename}{RESET}")
        
        # Parse results
        print(f"\n{BLUE}[*] Parsing results...{RESET}")
        results, hosts_summary = parse_csv_results(csv_content)
        
        # Print summary
        print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
        print(f"{CYAN}{BOLD}SCAN SUMMARY{RESET}")
        print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
        print(f"{RED}Critical: {len(results['critical'])}{RESET}")
        print(f"{YELLOW}High:     {len(results['high'])}{RESET}")
        print(f"Medium:   {len(results['medium'])}")
        print(f"Low:      {len(results['low'])}")
        print(f"Info:     {len(results['info'])}\n")
        print(f"Hosts scanned: {len(hosts_summary)}\n")
        
        # Save outputs
        save_nessuslist(hosts_summary)
        save_findings_report(results)
        save_nessus_guide()
        
        print(f"\n{GREEN}[+] Results processed successfully!{RESET}")
        return
    
    # Launch new scan mode
    if not args.targets:
        print(f"{RED}[!] Target file required for new scan{RESET}")
        print(f"{YELLOW}[*] Use --targets iplist.txt or --list to view existing scans{RESET}")
        return
    
    # Load targets
    try:
        target_file = find_ip_list(args.targets)
        with open(target_file, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        if not targets:
            print(f"{RED}[!] No targets found in file{RESET}")
            return
        
        target_string = ', '.join(targets)
        print(f"{GREEN}[+] Loaded {len(targets)} target(s){RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error loading targets: {e}{RESET}")
        return
    
    # Generate scan name
    if not args.name:
        args.name = f"SeekSweet-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    # Create scan
    print(f"\n{BLUE}[*] Creating scan: {args.name}{RESET}")
    scan_id, error = nessus.create_scan(args.name, target_string)
    
    if error:
        print(f"{RED}[!] Error creating scan: {error}{RESET}")
        return
    
    print(f"{GREEN}[+] Scan created (ID: {scan_id}){RESET}")
    
    # Launch scan
    print(f"{BLUE}[*] Launching scan...{RESET}")
    if not nessus.launch_scan(scan_id):
        print(f"{RED}[!] Failed to launch scan{RESET}")
        return
    
    print(f"{GREEN}[+] Scan launched successfully!{RESET}")
    
    # Monitor progress
    print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}SCAN PROGRESS{RESET}")
    print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
    
    last_progress = -1
    
    while True:
        status_info = nessus.get_scan_status(scan_id)
        
        if not status_info:
            time.sleep(10)
            continue
        
        status = status_info['status']
        progress = status_info['progress']
        
        if progress != last_progress:
            print(f"{YELLOW}[*] Status: {status} - Progress: {progress}%{RESET}")
            last_progress = progress
        
        if status in ['completed', 'canceled', 'aborted']:
            break
        
        time.sleep(15)
    
    if status == 'completed':
        print(f"\n{GREEN}[+] Scan completed!{RESET}")
        
        # Auto-download results
        print(f"\n{BLUE}[*] Downloading results...{RESET}")
        csv_content, error = nessus.export_scan(scan_id, format='csv')
        
        if error:
            print(f"{RED}[!] Error downloading results: {error}{RESET}")
            print(f"{YELLOW}[*] Use: ./nessusseek.py --download {scan_id}{RESET}")
            return
        
        # Save and parse
        csv_filename = 'nessus_results.csv'
        with open(csv_filename, 'wb') as f:
            f.write(csv_content)
        print(f"{GREEN}[+] CSV results saved to: {csv_filename}{RESET}")
        
        print(f"\n{BLUE}[*] Parsing results...{RESET}")
        results, hosts_summary = parse_csv_results(csv_content)
        
        # Print summary
        print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
        print(f"{CYAN}{BOLD}SCAN SUMMARY{RESET}")
        print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
        print(f"{RED}Critical: {len(results['critical'])}{RESET}")
        print(f"{YELLOW}High:     {len(results['high'])}{RESET}")
        print(f"Medium:   {len(results['medium'])}")
        print(f"Low:      {len(results['low'])}")
        print(f"Info:     {len(results['info'])}\n")
        print(f"Hosts scanned: {len(hosts_summary)}\n")
        
        # Save outputs
        save_nessuslist(hosts_summary)
        save_findings_report(results)
        save_nessus_guide()
        
        print(f"\n{GREEN}[+] All results saved!{RESET}")
    else:
        print(f"\n{YELLOW}[!] Scan ended with status: {status}{RESET}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
