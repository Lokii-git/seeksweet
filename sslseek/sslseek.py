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
    """Check if testssl.sh is available"""
    print(f"{CYAN}[*] Checking for testssl.sh...{RESET}")
    
    # Common locations for testssl.sh
    testssl_paths = [
        '/usr/bin/testssl.sh',
        '/usr/local/bin/testssl.sh',
        '/opt/testssl.sh/testssl.sh',
        './testssl.sh',
        'testssl.sh'
    ]
    
    for path in testssl_paths:
        if os.path.exists(path):
            print(f"{GREEN}[+] Found testssl.sh at: {path}{RESET}")
            return path
    
    # Try which/where command
    try:
        result = subprocess.run(['which', 'testssl.sh'], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            path = result.stdout.strip()
            print(f"{GREEN}[+] Found testssl.sh at: {path}{RESET}")
            return path
    except:
        pass
    
    print(f"{RED}[!] testssl.sh not found!{RESET}")
    print(f"{YELLOW}[*] Install with: git clone --depth 1 https://github.com/drwetter/testssl.sh.git{RESET}")
    print(f"{YELLOW}[*] Or download from: https://testssl.sh/{RESET}")
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

def parse_testssl_output(json_file):
    """Parse testssl.sh JSON output for critical findings"""
    critical_findings = []
    high_findings = []
    medium_findings = []
    
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
        
        # Look for critical vulnerabilities
        critical_vulns = [
            'heartbleed', 'ccs', 'ticketbleed', 'robot', 'secure_renego',
            'secure_client_renego', 'crime', 'breach', 'poodle_ssl',
            'fallback_scsv', 'sweet32', 'freak', 'drown', 'logjam',
            'beast', 'rc4'
        ]
        
        for item in data:
            if isinstance(item, dict):
                severity = item.get('severity', '').upper()
                finding = item.get('finding', '')
                id_name = item.get('id', '')
                
                if severity == 'CRITICAL' or id_name in critical_vulns:
                    critical_findings.append({
                        'id': id_name,
                        'finding': finding,
                        'severity': 'CRITICAL'
                    })
                elif severity == 'HIGH':
                    high_findings.append({
                        'id': id_name,
                        'finding': finding,
                        'severity': 'HIGH'
                    })
                elif severity == 'MEDIUM':
                    medium_findings.append({
                        'id': id_name,
                        'finding': finding,
                        'severity': 'MEDIUM'
                    })
        
        return critical_findings, high_findings, medium_findings
    
    except Exception as e:
        print(f"{YELLOW}[!] Could not parse JSON output: {e}{RESET}")
        return [], [], []

def run_testssl_scan(target, testssl_path, full_scan=False, verbose=False):
    """Run testssl.sh scan"""
    output_file = f"testssl_{target.replace(':', '_').replace('/', '_')}.json"
    
    cmd = generate_testssl_command(target, testssl_path, full_scan, output_file)
    
    print(f"\n{CYAN}[*] Scanning SSL/TLS: {target}{RESET}")
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
            
            if result.stdout:
                print(result.stdout)
        
        if success:
            print(f"{GREEN}[+] Scan completed successfully{RESET}")
            
            # Parse findings if JSON exists
            if os.path.exists(output_file):
                critical, high, medium = parse_testssl_output(output_file)
                
                if critical:
                    print(f"\n{RED}{BOLD}[!!!] CRITICAL VULNERABILITIES FOUND: {len(critical)}{RESET}")
                    for finding in critical[:5]:  # Show top 5
                        print(f"  {RED}- {finding['id']}: {finding['finding'][:80]}{RESET}")
                
                if high:
                    print(f"\n{YELLOW}[!] HIGH SEVERITY FINDINGS: {len(high)}{RESET}")
                    for finding in high[:3]:
                        print(f"  {YELLOW}- {finding['id']}: {finding['finding'][:80]}{RESET}")
                
                return True, critical, high, medium
        else:
            print(f"{RED}[!] Scan failed{RESET}")
            if not verbose and result.stderr:
                print(f"{RED}{result.stderr}{RESET}")
            return False, [], [], []
    
    except Exception as e:
        print(f"{RED}[!] Error running testssl: {e}{RESET}")
        return False, [], [], []

def save_ssllist(targets, results):
    """Save SSL scan summary to ssllist.txt"""
    output_file = "ssllist.txt"
    
    try:
        with open(output_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("SSLSeek - SSL/TLS Security Scan Summary\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for target, result in zip(targets, results):
                success, critical, high, medium = result
                f.write(f"\nTarget: {target}\n")
                f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n")
                
                if critical:
                    f.write(f"CRITICAL Findings: {len(critical)}\n")
                    for finding in critical:
                        f.write(f"  - {finding['id']}: {finding['finding']}\n")
                
                if high:
                    f.write(f"HIGH Findings: {len(high)}\n")
                
                if medium:
                    f.write(f"MEDIUM Findings: {len(medium)}\n")
                
                f.write("\n" + "-" * 80 + "\n")
        
        print(f"{GREEN}[+] Summary saved to: {output_file}{RESET}")
        return output_file
    
    except Exception as e:
        print(f"{RED}[!] Error saving summary: {e}{RESET}")
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
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            print(f"{GREEN}[+] Loaded {len(targets)} targets from file{RESET}")
        except Exception as e:
            print(f"{RED}[!] Error reading file: {e}{RESET}")
            sys.exit(1)
    else:
        targets = [args.target]
    
    # Scan targets
    results = []
    completed = 0
    for target in targets:
        completed += 1
        print(f"\n{CYAN}[*] Scanning {completed}/{len(targets)}: {target}{RESET}")
        result = run_testssl_scan(target, testssl_path, args.full, args.verbose)
        results.append(result)
        
        # Progress indicator (after each target completes)
        if completed < len(targets):
            print(f"\n{CYAN}[*] Progress: {completed}/{len(targets)} targets completed{RESET}\n")
    
    # Save summary
    print(f"\n{CYAN}[*] Generating summary and guide...{RESET}")
    save_ssllist(targets, results)
    save_ssl_guide()
    
    # Final summary
    print(f"\n{GREEN}{BOLD}[+] SSLSeek scan complete!{RESET}")
    print(f"{CYAN}[*] Results saved to: ssllist.txt{RESET}")
    print(f"{CYAN}[*] Attack guide saved to: SSL_ATTACK_GUIDE.txt{RESET}")
    
    # Check for critical findings
    total_critical = sum(len(r[1]) for r in results if r[0])
    if total_critical > 0:
        print(f"\n{RED}{BOLD}[!!!] {total_critical} CRITICAL VULNERABILITIES FOUND!{RESET}")
        print(f"{YELLOW}[*] Review ssllist.txt and testssl JSON output for details{RESET}")

if __name__ == '__main__':
    main()
