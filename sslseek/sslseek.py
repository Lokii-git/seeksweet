#!/usr/bin/env python3
"""
SSLSeek - SSL/TLS Security Scanner Wrapper
Part of the SeekSweet reconnaissance framework

This tool wraps testssl.sh to identify SSL/TLS vulnerabilities and misconfigurations.
Generates comprehensive SSL_ATTACK_GUIDE.txt with exploitation strategies.

Usage:
    python sslseek.py target.com
    python sslseek.py -f targets.txt
    python sslseek.py 10.10.10.10:443 --full
    python sslseek.py target.com --guide-only

Philosophy: We identify SSL/TLS weaknesses and provide guidance, not exploitation.
"""

import subprocess
import argparse
import sys
import os
import json
from pathlib import Path
from datetime import datetime

# Import seek_utils for finding IP list files
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
    from seek_utils import find_ip_list
except ImportError:
    # Fallback if seek_utils not available
    def find_ip_list(filename):
        if os.path.exists(filename):
            return os.path.abspath(filename)
        raise SystemExit(f"Error: Could not find file '{filename}'")

# Color codes for output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_banner():
    """Print the SSLSeek banner"""
    banner = f"""{CYAN}{BOLD}
    ================================================================
                        SSLSeek v1.0
              SSL/TLS Security Scanner Wrapper
                  github.com/Lokii-git/seeksweet
    ================================================================
    {RESET}"""
    print(banner)

def check_testssl():
    """Check if testssl.sh is available, auto-install if missing"""
    print(f"{CYAN}[*] Checking for testssl.sh...{RESET}")
    
    # Common locations for testssl.sh
    testssl_paths = [
        '/usr/bin/testssl.sh',
        '/usr/local/bin/testssl.sh',
        '/opt/testssl.sh/testssl.sh',
        './testssl.sh/testssl.sh',
        './testssl.sh',
        'testssl.sh'
    ]
    
    for path in testssl_paths:
        if os.path.exists(path):
            # Make sure it's executable
            try:
                os.chmod(path, 0o755)
            except:
                pass
            print(f"{GREEN}[+] Found testssl.sh at: {path}{RESET}")
            return path
    
    # Try which/where command
    try:
        result = subprocess.run(['which', 'testssl.sh'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            path = result.stdout.strip()
            # Make sure it's executable
            try:
                os.chmod(path, 0o755)
            except:
                pass
            print(f"{GREEN}[+] Found testssl.sh at: {path}{RESET}")
            return path
    except:
        pass
    
    # testssl.sh not found - offer to install
    print(f"{YELLOW}[!] testssl.sh not found!{RESET}")
    print(f"{CYAN}[*] Would you like to auto-install testssl.sh? (y/n){RESET}")
    
    try:
        response = input().strip().lower()
        if response in ['y', 'yes']:
            return install_testssl()
        else:
            print(f"{YELLOW}[*] Manual installation instructions:{RESET}")
            print(f"{YELLOW}    git clone --depth 1 https://github.com/drwetter/testssl.sh.git{RESET}")
            print(f"{YELLOW}    Or download from: https://testssl.sh/{RESET}")
            return None
    except (KeyboardInterrupt, EOFError):
        print(f"\n{YELLOW}[!] Installation cancelled{RESET}")
        return None

def install_testssl():
    """Auto-install testssl.sh from GitHub"""
    print(f"{CYAN}[*] Installing testssl.sh from GitHub...{RESET}")
    
    try:
        # Clone testssl.sh repository
        cmd = ['git', 'clone', '--depth', '1', 'https://github.com/drwetter/testssl.sh.git']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        if result.returncode != 0:
            print(f"{RED}[!] Failed to clone testssl.sh repository{RESET}")
            print(f"{RED}    Error: {result.stderr}{RESET}")
            return None
        
        # Verify installation
        testssl_path = './testssl.sh/testssl.sh'
        if os.path.exists(testssl_path):
            # Make it executable
            os.chmod(testssl_path, 0o755)
            print(f"{GREEN}[+] Successfully installed testssl.sh at: {testssl_path}{RESET}")
            return testssl_path
        else:
            print(f"{RED}[!] Installation failed - testssl.sh not found after clone{RESET}")
            return None
            
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Installation timed out{RESET}")
        return None
    except FileNotFoundError:
        print(f"{RED}[!] git command not found - please install git first{RESET}")
        return None
    except Exception as e:
        print(f"{RED}[!] Installation failed: {e}{RESET}")
        return None

def generate_testssl_command(target, testssl_path, full_scan=False, output_file=None):
    """Generate testssl.sh command"""
    cmd = [testssl_path]
    
    if full_scan:
        # Full comprehensive scan
        cmd.extend([
            '--warnings', 'off',
            '--openssl-timeout', '10',
            '--sneaky',  # Slower but more stealthy
        ])
    else:
        # Quick scan (most important checks)
        cmd.extend([
            '--warnings', 'off',
            '--openssl-timeout', '5',
            '--fast',
        ])
    
    # JSON output for parsing
    if output_file:
        cmd.extend(['--jsonfile', output_file])
    
    # Target
    cmd.append(target)
    
    return cmd

def parse_testssl_output(json_file, target):
    """
    Parse testssl.sh JSON output and extract vulnerability findings.
    Returns dict with vulnerability categories and certificate info.
    """
    findings = {
        'target': target,
        'vulnerabilities': {},
        'cert_expired': False,
        'cert_expiring_soon': False,
        'cert_info': {},
        'weak_ciphers': [],
        'protocol_issues': []
    }
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Extract actual target from JSON if available
        # Prioritize IP over hostname (to avoid reverse DNS issues where multiple IPs resolve to same hostname)
        if data and len(data) > 0 and isinstance(data[0], dict):
            json_ip = data[0].get('ip', '')
            json_host = data[0].get('targetHost', '')
            
            # Use IP if available, otherwise use targetHost, but filter out placeholder
            if json_ip and json_ip != 'target.com':
                findings['target'] = json_ip
            elif json_host and json_host != 'target.com':
                findings['target'] = json_host
        
        for item in data:
            if not isinstance(item, dict):
                continue
                
            severity = item.get('severity', '').upper()
            finding = item.get('finding', '')
            id_name = item.get('id', '')
            
            # Certificate expiration checks
            if 'cert_expirationStatus' in id_name or 'cert_notAfter' in id_name:
                if 'expired' in finding.lower():
                    findings['cert_expired'] = True
                    findings['cert_info']['status'] = 'EXPIRED'
                elif 'expires' in finding.lower():
                    # Check if expiring within 30 days
                    findings['cert_info']['expiry'] = finding
                    if any(word in finding.lower() for word in ['soon', 'day', 'week']):
                        findings['cert_expiring_soon'] = True
            
            # Certificate details
            if 'cert_' in id_name:
                findings['cert_info'][id_name] = finding
            
            # Vulnerability detection - specific CVEs and attacks
            vuln_patterns = {
                'Heartbleed': ['heartbleed', 'CVE-2014-0160'],
                'CCS_Injection': ['ccs', 'ccs injection', 'CVE-2014-0224'],
                'Ticketbleed': ['ticketbleed', 'CVE-2016-9244'],
                'ROBOT': ['robot', 'return of bleichenbacher'],
                'Secure_Renegotiation': ['secure_renego', 'renegotiation'],
                'CRIME': ['crime', 'CVE-2012-4929'],
                'BREACH': ['breach', 'CVE-2013-3587'],
                'POODLE_SSL': ['poodle', 'CVE-2014-3566'],
                'Sweet32': ['sweet32', 'CVE-2016-2183', 'birthday'],
                'FREAK': ['freak', 'CVE-2015-0204'],
                'DROWN': ['drown', 'CVE-2016-0800'],
                'Logjam': ['logjam', 'CVE-2015-4000'],
                'BEAST': ['beast', 'CVE-2011-3389'],
                'Lucky13': ['lucky13', 'lucky 13', 'CVE-2013-0169'],
                'RC4': ['rc4', 'arcfour'],
                'SSLv2': ['sslv2', 'ssl v2'],
                'SSLv3': ['sslv3', 'ssl v3'],
                'TLS_FALLBACK_SCSV': ['fallback', 'scsv'],
                'TLS1.0': ['tls 1.0', 'tls1.0'],
                'TLS1.1': ['tls 1.1', 'tls1.1']
            }
            
            # Check if vulnerable
            if severity in ['CRITICAL', 'HIGH', 'MEDIUM'] or 'vulnerable' in finding.lower():
                for vuln_name, patterns in vuln_patterns.items():
                    if any(pattern in id_name.lower() or pattern in finding.lower() for pattern in patterns):
                        if 'not vulnerable' not in finding.lower() and 'no ' not in finding.lower():
                            if vuln_name not in findings['vulnerabilities']:
                                findings['vulnerabilities'][vuln_name] = []
                            findings['vulnerabilities'][vuln_name].append({
                                'severity': severity,
                                'finding': finding,
                                'id': id_name
                            })
            
            # Weak cipher detection
            if 'cipher' in id_name.lower() and any(word in finding.lower() for word in ['weak', 'null', 'export', 'anon']):
                findings['weak_ciphers'].append(finding)
        
        return findings
    
    except Exception as e:
        print(f"{YELLOW}[!] Could not parse JSON output: {e}{RESET}")
        return findings


def organize_findings_by_vulnerability(all_results, output_base='sslseek_results'):
    """
    Organize scan results by vulnerability type into folders.
    Creates vulnerability-specific folders and copies relevant files.
    """
    print(f"\n{CYAN}[*] Organizing findings by vulnerability type...{RESET}")
    
    # Create base output directory
    if not os.path.exists(output_base):
        os.makedirs(output_base)
    
    # Track which IPs have which vulnerabilities
    vuln_to_targets = {}
    expired_certs = []
    expiring_soon_certs = []
    
    for result in all_results:
        target = result['target']
        
        # Handle certificate expiration
        if result['cert_expired']:
            expired_certs.append(target)
        if result['cert_expiring_soon']:
            expiring_soon_certs.append(target)
        
        # Organize by vulnerability
        for vuln_name, vuln_findings in result['vulnerabilities'].items():
            if vuln_name not in vuln_to_targets:
                vuln_to_targets[vuln_name] = []
            vuln_to_targets[vuln_name].append({
                'target': target,
                'findings': vuln_findings
            })
    
    # Create vulnerability-specific folders and copy files
    for vuln_name, targets in vuln_to_targets.items():
        vuln_dir = os.path.join(output_base, vuln_name)
        os.makedirs(vuln_dir, exist_ok=True)
        
        # Create summary file for this vulnerability
        summary_file = os.path.join(vuln_dir, f'{vuln_name}_summary.txt')
        with open(summary_file, 'w') as f:
            f.write(f"{'=' * 80}\n")
            f.write(f"{vuln_name} - Affected Targets\n")
            f.write(f"{'=' * 80}\n\n")
            f.write(f"Total Affected: {len(targets)}\n\n")
            
            for target_info in targets:
                f.write(f"\nTarget: {target_info['target']}\n")
                f.write(f"{'-' * 80}\n")
                for finding in target_info['findings']:
                    f.write(f"  Severity: {finding['severity']}\n")
                    f.write(f"  Finding: {finding['finding']}\n")
                    f.write(f"  ID: {finding['id']}\n\n")
        
        # Copy JSON files for affected targets
        for target_info in targets:
            target = target_info['target']
            json_file = f"testssl_{target.replace(':', '_').replace('/', '_')}.json"
            if os.path.exists(json_file):
                import shutil
                dest = os.path.join(vuln_dir, os.path.basename(json_file))
                shutil.copy(json_file, dest)
        
        print(f"{GREEN}[+] {vuln_name}: {len(targets)} affected targets{RESET}")
    
    # Handle expired certificates
    if expired_certs or expiring_soon_certs:
        cert_dir = os.path.join(output_base, 'Certificate_Issues')
        os.makedirs(cert_dir, exist_ok=True)
        
        cert_report = os.path.join(cert_dir, 'certificate_report.txt')
        with open(cert_report, 'w') as f:
            f.write(f"{'=' * 80}\n")
            f.write("SSL/TLS Certificate Issues Report\n")
            f.write(f"{'=' * 80}\n\n")
            
            if expired_certs:
                f.write(f"EXPIRED CERTIFICATES ({len(expired_certs)}):\n")
                f.write(f"{'-' * 80}\n")
                for target in sorted(expired_certs):
                    f.write(f"  {target}\n")
                f.write("\n")
            
            if expiring_soon_certs:
                f.write(f"EXPIRING SOON ({len(expiring_soon_certs)}):\n")
                f.write(f"{'-' * 80}\n")
                for target in sorted(expiring_soon_certs):
                    f.write(f"  {target}\n")
        
        print(f"{YELLOW}[!] Expired certificates: {len(expired_certs)}{RESET}")
        print(f"{YELLOW}[!] Expiring soon: {len(expiring_soon_certs)}{RESET}")
    
    return vuln_to_targets, expired_certs, expiring_soon_certs


def generate_master_summary(all_results, output_file='ssllist.txt'):
    """
    Generate master summary file with bite-sized information per IP.
    Only includes IPs with findings.
    """
    print(f"\n{CYAN}[*] Generating master summary...{RESET}")
    
    with open(output_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("SSLSeek - SSL/TLS Security Summary\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        # Count total findings
        total_with_findings = 0
        
        for result in all_results:
            target = result['target']
            
            # Check if target has any findings
            has_findings = (
                result['vulnerabilities'] or 
                result['cert_expired'] or 
                result['cert_expiring_soon'] or
                result['weak_ciphers']
            )
            
            if not has_findings:
                continue  # Skip targets with no findings
            
            total_with_findings += 1
            
            f.write(f"\n{'=' * 80}\n")
            f.write(f"Target: {target}\n")
            f.write(f"{'=' * 80}\n")
            
            # Certificate status
            if result['cert_expired']:
                f.write(f"  [CRITICAL] Certificate EXPIRED\n")
            elif result['cert_expiring_soon']:
                f.write(f"  [WARNING] Certificate expiring soon\n")
            
            # Vulnerabilities
            if result['vulnerabilities']:
                f.write(f"\n  Vulnerabilities Found ({len(result['vulnerabilities'])}):\n")
                for vuln_name, findings in result['vulnerabilities'].items():
                    severity = findings[0]['severity'] if findings else 'UNKNOWN'
                    f.write(f"    [{severity}] {vuln_name}\n")
            
            # Weak ciphers
            if result['weak_ciphers']:
                f.write(f"\n  Weak Ciphers: {len(result['weak_ciphers'])} found\n")
            
            f.write("\n")
        
        f.write("\n" + "=" * 80 + "\n")
        f.write(f"Total targets with findings: {total_with_findings}\n")
        f.write("=" * 80 + "\n")
    
    print(f"{GREEN}[+] Master summary saved to: {output_file}{RESET}")
    print(f"{CYAN}[*] Targets with findings: {total_with_findings}{RESET}")
    return output_file

def run_testssl_scan(target, testssl_path, full_scan=False, verbose=False):
    """Run testssl.sh scan and return parsed findings"""
    output_file = f"testssl_{target.replace(':', '_').replace('/', '_')}.json"
    
    # Ensure testssl.sh is executable before running
    try:
        if os.path.exists(testssl_path):
            os.chmod(testssl_path, 0o755)
    except Exception as e:
        print(f"{YELLOW}[!] Warning: Could not set executable permissions: {e}{RESET}")
    
    cmd = generate_testssl_command(target, testssl_path, full_scan, output_file)
    
    print(f"\n{CYAN}[*] Scanning SSL/TLS: {target}{RESET}")
    if verbose:
        print(f"{CYAN}[*] Command: {' '.join(cmd)}{RESET}\n")
    
    try:
        if verbose:
            # Show full output
            result = subprocess.run(cmd)
            success = (result.returncode == 0)
        else:
            # Capture output
            result = subprocess.run(cmd, capture_output=True, text=True)
            success = (result.returncode == 0)
        
        if success:
            print(f"{GREEN}[+] Scan completed successfully{RESET}")
            
            # Parse findings if JSON exists
            if os.path.exists(output_file):
                findings = parse_testssl_output(output_file, target)
                
                # Display quick summary
                vuln_count = len(findings['vulnerabilities'])
                if vuln_count > 0:
                    print(f"{RED}[!] Found {vuln_count} vulnerability types{RESET}")
                    for vuln_name in list(findings['vulnerabilities'].keys())[:5]:
                        print(f"    - {vuln_name}")
                    if vuln_count > 5:
                        print(f"    ... and {vuln_count - 5} more")
                
                if findings['cert_expired']:
                    print(f"{RED}[!!!] Certificate EXPIRED{RESET}")
                elif findings['cert_expiring_soon']:
                    print(f"{YELLOW}[!] Certificate expiring soon{RESET}")
                
                return findings
            else:
                print(f"{YELLOW}[!] JSON output not found - scan may have failed to complete{RESET}")
                return None
        else:
            # More verbose failure message
            print(f"{RED}[!] testssl.sh scan failed for {target} (exit code: {result.returncode}){RESET}")
            print(f"{YELLOW}[*] This could be due to:{RESET}")
            print(f"{YELLOW}    - Target not responding on SSL/TLS port{RESET}")
            print(f"{YELLOW}    - Connection timeout or network issue{RESET}")
            print(f"{YELLOW}    - SSL/TLS handshake failure{RESET}")
            print(f"{YELLOW}    - testssl.sh compatibility issue{RESET}")
            
            if not verbose and result.stderr:
                print(f"{YELLOW}[*] Error details:{RESET}")
                print(f"{RED}{result.stderr[:500]}{RESET}")
            elif not verbose and result.stdout:
                # Show last few lines of output for context
                stdout_lines = result.stdout.strip().split('\n')
                if len(stdout_lines) > 5:
                    print(f"{YELLOW}[*] Last output lines:{RESET}")
                    for line in stdout_lines[-5:]:
                        print(f"    {line}")
            
            return None
    
    except Exception as e:
        print(f"{RED}[!] Error running testssl.sh: {e}{RESET}")
        print(f"{YELLOW}[*] This is an SSLSeek execution error, not a scan failure{RESET}")
        return None

def save_ssl_guide():
    """Generate comprehensive SSL/TLS attack guide"""
    guide_file = "SSL_ATTACK_GUIDE.txt"
    
    guide_content = """
================================================================================
                    SSL/TLS ATTACK GUIDE - SSLSeek v1.0
           Comprehensive Guide to SSL/TLS Vulnerability Exploitation
================================================================================

This guide provides detailed information on SSL/TLS vulnerabilities, attack
methodologies, and remediation strategies. Use responsibly and ethically.

================================================================================
                            TABLE OF CONTENTS
================================================================================

1. TESTSSL.SH USAGE
2. CRITICAL SSL/TLS VULNERABILITIES
3. CIPHER SUITE ATTACKS
4. CERTIFICATE ATTACKS
5. PROTOCOL VULNERABILITIES
6. CONFIGURATION WEAKNESSES
7. EXPLOITATION TOOLS
8. MITIGATION STRATEGIES
9. OPSEC CONSIDERATIONS
10. TROUBLESHOOTING

================================================================================
                        1. TESTSSL.SH USAGE
================================================================================

BASIC SCANS
-----------
# Quick scan (most important checks)
testssl.sh target.com

# Full comprehensive scan
testssl.sh --warnings off --openssl-timeout 10 target.com

# Scan specific port
testssl.sh target.com:8443

# Scan from file
cat targets.txt | while read target; do testssl.sh "$target"; done

# Stealthy scan (slower, less noisy)
testssl.sh --sneaky target.com

# JSON output for parsing
testssl.sh --jsonfile output.json target.com

FOCUSED SCANS
-------------
# Check only vulnerabilities
testssl.sh -U target.com

# Check only cipher suites
testssl.sh -E target.com

# Check only protocols
testssl.sh -p target.com

# Check only certificate
testssl.sh -S target.com

# Check for specific vulnerability
testssl.sh -H target.com  # Heartbleed

ADVANCED OPTIONS
----------------
# Skip DNS lookups (faster)
testssl.sh --ip target.com

# Use specific OpenSSL binary
testssl.sh --openssl=/path/to/openssl target.com

# Parallel scanning (be careful!)
cat targets.txt | parallel -j5 testssl.sh {}

# Save all output formats
testssl.sh --jsonfile out.json --htmlfile out.html --csvfile out.csv target.com

================================================================================
                    2. CRITICAL SSL/TLS VULNERABILITIES
================================================================================

HEARTBLEED (CVE-2014-0160)
--------------------------
Description: Memory disclosure in OpenSSL TLS heartbeat extension
Impact: Allows reading 64KB of server memory per request (keys, passwords, data)
Affected: OpenSSL 1.0.1 through 1.0.1f

Detection:
  testssl.sh -H target.com
  nmap --script ssl-heartbleed target.com

Exploitation:
  # Metasploit
  use auxiliary/scanner/ssl/openssl_heartbleed
  set RHOSTS target.com
  set RPORT 443
  set VERBOSE true
  run

  # Python script
  python heartbleed-poc.py target.com

  # Extract multiple times to get keys
  for i in {1..1000}; do python heartbleed-poc.py target.com >> dump.txt; done
  grep -a "BEGIN RSA PRIVATE KEY" dump.txt

Remediation:
  - Update OpenSSL to 1.0.1g or later
  - Regenerate SSL certificates and keys
  - Revoke old certificates

POODLE (CVE-2014-3566)
----------------------
Description: Padding Oracle On Downgraded Legacy Encryption
Impact: Decrypts SSLv3 traffic through padding oracle attack
Affected: SSLv3 protocol

Detection:
  testssl.sh --poodle target.com
  nmap --script ssl-poodle target.com

Exploitation:
  # Requires MITM position
  # Force SSLv3 downgrade, then exploit padding oracle
  
  # POODLE attack tools
  git clone https://github.com/mpgn/poodle-PoC
  python poodle.py --target target.com

Remediation:
  - Disable SSLv3 completely
  - Use TLS 1.2+ only

DROWN (CVE-2016-0800)
---------------------
Description: Decrypting RSA with Obsolete and Weakened eNcryption
Impact: Breaks TLS by attacking SSLv2 RSA key exchange
Affected: Servers supporting SSLv2 or sharing keys with SSLv2 servers

Detection:
  testssl.sh --drown target.com
  nmap --script ssl-drown target.com

Exploitation:
  # Requires ~1000 TLS connections and SSLv2 oracle
  # Complex attack, limited practical exploitation
  
Remediation:
  - Disable SSLv2 on all servers
  - Don't share keys between servers
  - Regenerate keys if exposed

FREAK (CVE-2015-0204)
---------------------
Description: Factoring RSA Export Keys
Impact: MITM can downgrade to weak 512-bit export-grade encryption
Affected: Servers supporting export cipher suites

Detection:
  testssl.sh --freak target.com

Exploitation:
  # Requires MITM position
  # Force export cipher negotiation
  # Factor 512-bit RSA key (hours/days)
  
Remediation:
  - Disable export cipher suites
  - Use strong cipher suites only

LOGJAM (CVE-2015-4000)
----------------------
Description: Diffie-Hellman downgrade attack
Impact: MITM can downgrade to 512-bit DH and break encryption
Affected: Servers supporting weak DH parameters

Detection:
  testssl.sh --logjam target.com

Exploitation:
  # Pre-compute DH discrete log for common primes
  # MITM downgrade to 512-bit DH
  # Decrypt traffic
  
Remediation:
  - Use DH parameters >= 2048 bits
  - Prefer ECDHE over DHE

ROBOT (Return Of Bleichenbacher's Oracle Threat)
-------------------------------------------------
Description: RSA padding oracle attack on TLS
Impact: Decrypt RSA ciphertext or sign messages
Affected: Servers with vulnerable RSA PKCS#1 v1.5 implementation

Detection:
  testssl.sh --robot target.com
  python robot-detect.py target.com

Exploitation:
  # Requires many oracle queries
  # Can decrypt RSA session keys
  
Remediation:
  - Patch TLS implementation
  - Prefer ECDHE cipher suites (forward secrecy)

SWEET32 (CVE-2016-2183)
-----------------------
Description: Birthday attacks on 64-bit block ciphers
Impact: Recover plaintext after ~32GB of data
Affected: 3DES and Blowfish cipher suites

Detection:
  testssl.sh --sweet32 target.com

Exploitation:
  # Requires long-lived TLS connections
  # Capture ~32GB encrypted traffic
  # Birthday attack to recover blocks
  
Remediation:
  - Disable 3DES and Blowfish
  - Use AES cipher suites

================================================================================
                        3. CIPHER SUITE ATTACKS
================================================================================

RC4 CIPHER ATTACKS
------------------
Description: Statistical biases in RC4 keystream
Impact: Recover plaintext with enough ciphertext samples

Detection:
  testssl.sh -E target.com | grep RC4

Exploitation:
  # Capture many TLS sessions using RC4
  # Statistical analysis to recover session cookies
  
  # RC4 NOMORE attack
  # Requires ~2^26 encryptions of same plaintext
  
Remediation:
  - Disable RC4 cipher suites completely
  - Use AES-GCM or ChaCha20-Poly1305

NULL CIPHER SUITES
------------------
Description: Cipher suites with no encryption
Impact: Plaintext communication

Detection:
  testssl.sh -E target.com | grep NULL

Exploitation:
  # Simply capture traffic - it's unencrypted!
  tcpdump -i eth0 -w capture.pcap host target.com
  wireshark capture.pcap

Remediation:
  - Disable NULL cipher suites immediately

WEAK CIPHER SUITES (DES, 3DES, EXPORT)
---------------------------------------
Detection:
  testssl.sh -E target.com | grep -E "DES|EXPORT"

Exploitation:
  # Force weak cipher negotiation (MITM required)
  # Brute force or cryptanalysis

Remediation:
  - Disable all weak ciphers
  - Use only strong cipher suites:
    * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    * TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

CIPHER SUITE PREFERENCE
------------------------
# Test cipher suite order
testssl.sh --cipher-per-proto target.com

# Force specific cipher
openssl s_client -cipher 'DES-CBC3-SHA' -connect target.com:443

Ideal Configuration:
1. Server cipher preference (not client)
2. Forward secrecy (ECDHE/DHE)
3. Authenticated encryption (GCM/CCM/Poly1305)
4. Strong key exchange (ECDH P-256+, DH 2048+)

================================================================================
                        4. CERTIFICATE ATTACKS
================================================================================

SELF-SIGNED CERTIFICATES
------------------------
Detection:
  testssl.sh -S target.com
  openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -issuer -subject

Impact:
  - MITM attacks (user may accept warning)
  - Phishing opportunities
  - Trust issues

Exploitation:
  # MITM with self-signed cert
  mitmproxy --mode transparent
  # Victims see certificate warning

EXPIRED CERTIFICATES
--------------------
Detection:
  testssl.sh -S target.com | grep -i expired
  openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -dates

Impact: Trust issues, potential MITM

WEAK SIGNATURE ALGORITHMS
--------------------------
Detection:
  testssl.sh -S target.com | grep -i "Signature Algorithm"
  
Weak algorithms: MD5, SHA1

Remediation:
  - Use SHA256 or SHA384
  - Reissue certificates with strong signatures

CERTIFICATE CHAIN ISSUES
-------------------------
Detection:
  testssl.sh -S target.com | grep -i chain
  openssl s_client -connect target.com:443 -showcerts

Issues to check:
  - Incomplete chain (missing intermediates)
  - Expired intermediates
  - Untrusted root CA

COMMON NAME / SAN MISMATCH
---------------------------
Detection:
  testssl.sh -S target.com
  openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 "Subject Alternative Name"

Impact: Certificate warnings, MITM opportunities

WILDCARD CERTIFICATES
---------------------
Detection:
  openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -subject | grep '*'

Risks:
  - If private key compromised, all subdomains affected
  - Broader attack surface

================================================================================
                    5. PROTOCOL VULNERABILITIES
================================================================================

SSLV2 / SSLV3 (DEPRECATED)
---------------------------
Detection:
  testssl.sh -p target.com | grep -E "SSLv2|SSLv3"
  nmap --script ssl-enum-ciphers target.com

Impact:
  - Multiple known vulnerabilities
  - POODLE, DROWN, etc.

Remediation:
  - Disable SSLv2 and SSLv3 completely
  - Use TLS 1.2+ only

TLS 1.0 / 1.1 (DEPRECATED)
---------------------------
Detection:
  testssl.sh -p target.com
  
Status: Deprecated by major browsers (2020)

Vulnerabilities:
  - BEAST attack
  - Weak cipher suites support
  - No modern AEAD ciphers

Remediation:
  - Use TLS 1.2 and TLS 1.3
  - Disable TLS 1.0/1.1

TLS COMPRESSION (CRIME)
-----------------------
Detection:
  testssl.sh --crime target.com

Impact: Side-channel attack to recover session cookies

Remediation:
  - Disable TLS compression

RENEGOTIATION ATTACKS
----------------------
Detection:
  testssl.sh -R target.com

Types:
  - Insecure renegotiation (CVE-2009-3555)
  - Client-initiated renegotiation (DoS)

Remediation:
  - Require secure renegotiation
  - Disable client-initiated renegotiation

================================================================================
                    6. CONFIGURATION WEAKNESSES
================================================================================

HTTP ON SSL PORT
----------------
Detection:
  testssl.sh target.com:443 | grep -i "doesn't seem to be a TLS/SSL"
  curl -k http://target.com:443

Impact: Service confusion, potential vulnerabilities

HSTS NOT ENABLED
----------------
Detection:
  testssl.sh -h target.com
  curl -I https://target.com | grep -i strict-transport-security

Impact: Vulnerable to SSL stripping attacks

Remediation:
  # Add HSTS header
  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

SSL STRIPPING ATTACK
--------------------
Tools:
  # sslstrip (MITM required)
  sslstrip -l 8080
  iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080

Prevention: HSTS header

PERFECT FORWARD SECRECY (PFS)
------------------------------
Detection:
  testssl.sh -E target.com | grep -E "ECDHE|DHE"

Importance: Protects past sessions if keys compromised

Remediation:
  - Prefer ECDHE cipher suites
  - Disable non-PFS ciphers

================================================================================
                        7. EXPLOITATION TOOLS
================================================================================

TESTSSL.SH
----------
# Most comprehensive SSL/TLS scanner
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh target.com

NMAP SSL SCRIPTS
----------------
# Comprehensive SSL check
nmap --script ssl-enum-ciphers target.com

# Specific vulnerability checks
nmap --script ssl-heartbleed target.com
nmap --script ssl-poodle target.com
nmap --script ssl-drown target.com
nmap --script ssl-cert target.com

SSLSCAN
-------
# Fast cipher enumeration
sslscan target.com
sslscan --no-failed target.com

SSLYZE
------
# Fast Python-based scanner
pip install sslyze
sslyze --regular target.com
sslyze --heartbleed --robot target.com

O-SAFT
------
# OWASP SSL Advanced Forensic Tool
git clone https://github.com/OWASP/O-Saft.git
./o-saft.pl +check target.com

OPENSSL S_CLIENT
----------------
# Manual testing
openssl s_client -connect target.com:443

# Test specific protocol
openssl s_client -tls1_2 -connect target.com:443

# Test specific cipher
openssl s_client -cipher 'ECDHE-RSA-AES256-GCM-SHA384' -connect target.com:443

# Show certificate
openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -text

METASPLOIT MODULES
------------------
use auxiliary/scanner/ssl/openssl_heartbleed
use auxiliary/scanner/ssl/ssl_version
use auxiliary/scanner/http/ssl_version

PYTHON TOOLS
------------
# ssl-checker
git clone https://github.com/narbeh/ssl-checker
python ssl-checker.py -H target.com

# Custom Python scanning
import ssl, socket
context = ssl.create_default_context()
with socket.create_connection(('target.com', 443)) as sock:
    with context.wrap_socket(sock, server_hostname='target.com') as ssock:
        print(ssock.version())
        print(ssock.cipher())

================================================================================
                    8. MITIGATION STRATEGIES
================================================================================

SERVER CONFIGURATION (NGINX)
-----------------------------
# Strong SSL configuration
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers on;
ssl_session_timeout 10m;
ssl_session_cache shared:SSL:10m;
ssl_stapling on;
ssl_stapling_verify on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

SERVER CONFIGURATION (APACHE)
------------------------------
# Strong SSL configuration
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305
SSLHonorCipherOrder on
SSLCompression off
SSLUseStapling on
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

RECOMMENDED CIPHER SUITES (2025)
--------------------------------
1. TLS_AES_256_GCM_SHA384 (TLS 1.3)
2. TLS_AES_128_GCM_SHA256 (TLS 1.3)
3. TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)
4. TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
5. TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256

CERTIFICATE BEST PRACTICES
---------------------------
- Use 2048-bit RSA or 256-bit ECDSA keys
- SHA256 or SHA384 signatures
- Include complete certificate chain
- Enable OCSP stapling
- Use Certificate Transparency
- Short certificate lifetime (90 days recommended)
- Automated renewal (Let's Encrypt)

MONITORING AND MAINTENANCE
---------------------------
# Regular scanning
0 0 * * 0 /path/to/testssl.sh target.com --jsonfile /var/log/ssl-scan.json

# Certificate expiry monitoring
openssl s_client -connect target.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -enddate

# Automated alerts
certwatch --email admin@example.com --days 30 target.com

================================================================================
                    9. OPSEC CONSIDERATIONS
================================================================================

DETECTION RISKS
---------------
1. SSL/TLS scanners are easily detected:
   - Unusual handshake patterns
   - Rapid connection attempts
   - Protocol/cipher probing
   - Connection without data transfer

2. Logged at multiple layers:
   - Firewall logs
   - IDS/IPS signatures
   - Web server access logs
   - TLS inspection appliances

3. Common signatures:
   - testssl.sh user agent
   - Multiple failed handshakes
   - Unsupported protocol attempts
   - Suspicious cipher requests

STEALTH TECHNIQUES
------------------
# Slower scanning (less noisy)
testssl.sh --sneaky target.com

# Scan through proxy
testssl.sh --proxy proxy.com:8080 target.com

# Rate limiting
for target in $(cat targets.txt); do
    testssl.sh "$target"
    sleep 300  # 5-minute delay
done

# Distributed scanning
# Use multiple source IPs
# Scan from cloud providers
# Use Tor (not recommended for speed)

LEGAL CONSIDERATIONS
--------------------
- Only scan systems you own or have permission to test
- Be aware of jurisdictional laws
- Document authorization
- Follow rules of engagement
- Respect privacy and data protection laws

================================================================================
                    10. TROUBLESHOOTING
================================================================================

TESTSSL.SH ISSUES
-----------------
Problem: "OpenSSL too old"
Solution: 
  # Use testssl.sh bundled OpenSSL
  ./testssl.sh --openssl-timeout 10 target.com
  
  # Or compile newer OpenSSL
  wget https://www.openssl.org/source/openssl-1.1.1.tar.gz
  tar -xf openssl-1.1.1.tar.gz
  cd openssl-1.1.1
  ./config
  make
  ./testssl.sh --openssl=/path/to/openssl target.com

Problem: "Timeout errors"
Solution:
  # Increase timeout
  testssl.sh --openssl-timeout 30 target.com
  
  # Check network connectivity
  nc -zv target.com 443

Problem: "Could not determine the protocol"
Solution:
  # Verify port is correct
  nmap -p 443 target.com
  
  # Check if service is HTTPS
  curl -k https://target.com

CONNECTION ISSUES
-----------------
# Test basic connectivity
telnet target.com 443
nc -zv target.com 443

# Check firewall
iptables -L -n | grep 443
netstat -an | grep 443

# Verify DNS
dig target.com
nslookup target.com

# Test with curl
curl -kvI https://target.com

FALSE POSITIVES
---------------
- Always verify findings manually
- Check OpenSSL version on server
- Test with multiple tools
- Review server logs
- Consider testing environment differences

================================================================================
                            RESOURCES
================================================================================

Official Documentation:
- testssl.sh: https://github.com/drwetter/testssl.sh
- SSL Labs: https://www.ssllabs.com/
- Mozilla SSL Config: https://ssl-config.mozilla.org/

Security Standards:
- PCI DSS SSL/TLS Guidelines
- NIST SP 800-52 Rev. 2
- RFC 8446 (TLS 1.3)
- RFC 5246 (TLS 1.2)

Tools:
- https://github.com/rbsec/sslscan
- https://github.com/nabla-c0d3/sslyze
- https://github.com/OWASP/O-Saft

Vulnerability Databases:
- CVE Database: https://cve.mitre.org/
- NVD: https://nvd.nist.gov/

================================================================================
                            FINAL NOTES
================================================================================

This guide is for authorized security testing only. Always:
- Obtain proper authorization before testing
- Follow ethical hacking guidelines
- Respect privacy and confidentiality
- Document findings professionally
- Provide actionable remediation advice

Remember: The goal is to improve security, not exploit vulnerabilities.

================================================================================
                    Generated by SSLSeek v1.0
                    github.com/Lokii-git/seeksweet
================================================================================
"""
    
    try:
        with open(guide_file, 'w') as f:
            f.write(guide_content)
        
        print(f"{GREEN}[+] SSL/TLS attack guide saved to: {guide_file}{RESET}")
        return guide_file
    
    except Exception as e:
        print(f"{RED}[!] Error saving guide: {e}{RESET}")
        return None

def main():
    parser = argparse.ArgumentParser(
        description='SSLSeek - SSL/TLS Security Scanner Wrapper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python sslseek.py target.com
  python sslseek.py -f targets.txt --full
  python sslseek.py 10.10.10.10:443 -v
  python sslseek.py --guide-only
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target domain or IP:port')
    parser.add_argument('-f', '--file', help='File containing targets (one per line)')
    parser.add_argument('--full', action='store_true', help='Full comprehensive scan (slower)')
    parser.add_argument('--guide-only', action='store_true', help='Generate guide only, skip scanning')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Generate guide if requested
    if args.guide_only:
        print(f"{CYAN}[*] Generating SSL/TLS attack guide...{RESET}")
        save_ssl_guide()
        return
    
    # Check for target
    if not args.target and not args.file:
        print(f"{RED}[!] Error: Please provide a target or file{RESET}")
        parser.print_help()
        sys.exit(1)
    
    # Check for testssl.sh
    testssl_path = check_testssl()
    if not testssl_path:
        print(f"\n{YELLOW}[*] Generating SSL/TLS attack guide anyway...{RESET}")
        save_ssl_guide()
        sys.exit(1)
    
    # Get targets
    targets = []
    if args.file:
        try:
            # Use seek_utils to find the IP list file
            ip_list_path = find_ip_list(args.file)
            print(f"{CYAN}[*] Using IP list: {ip_list_path}{RESET}")
            
            with open(ip_list_path, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"{GREEN}[+] Loaded {len(targets)} targets from file{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error reading file: {e}{RESET}")
            sys.exit(1)
    else:
        targets = [args.target]
    
    # Scan targets
    all_results = []
    completed = 0
    for target in targets:
        completed += 1
        print(f"\n{CYAN}[*] Scanning {completed}/{len(targets)}: {target}{RESET}")
        findings = run_testssl_scan(target, testssl_path, args.full, args.verbose)
        
        if findings:
            all_results.append(findings)
        
        # Progress indicator (after each target completes)
        if completed < len(targets):
            print(f"\n{CYAN}[*] Progress: {completed}/{len(targets)} targets completed{RESET}\n")
    
    # Organize findings by vulnerability type
    if all_results:
        print(f"\n{CYAN}[*] Organizing findings by vulnerability type...{RESET}")
        organize_findings_by_vulnerability(all_results)
        
        print(f"\n{CYAN}[*] Generating master summary...{RESET}")
        generate_master_summary(all_results)
    else:
        print(f"\n{YELLOW}[!] No results to organize{RESET}")
    
    # Generate guide
    print(f"\n{CYAN}[*] Generating SSL/TLS attack guide...{RESET}")
    save_ssl_guide()
    
    # Final summary
    print(f"\n{GREEN}{BOLD}[+] SSLSeek scan complete!{RESET}")
    print(f"{CYAN}[*] Master summary: ssllist.txt{RESET}")
    print(f"{CYAN}[*] Attack guide: SSL_ATTACK_GUIDE.txt{RESET}")
    print(f"{CYAN}[*] Organized findings in vulnerability-specific folders{RESET}")
    
    # Count critical findings
    if all_results:
        total_critical = sum(
            sum(1 for f in findings for sev in f.get('severity', '') if sev == 'CRITICAL')
            for result in all_results
            for findings in result.get('vulnerabilities', {}).values()
        )
        
        total_vulns = sum(len(r.get('vulnerabilities', {})) for r in all_results)
        
        if total_critical > 0:
            print(f"\n{RED}{BOLD}[!!!] {total_critical} CRITICAL FINDINGS!{RESET}")
        
        print(f"{YELLOW}[*] Total unique vulnerability types: {total_vulns}{RESET}")
        print(f"{YELLOW}[*] Targets with findings: {len(all_results)}{RESET}")

if __name__ == '__main__':
    main()
