#!/usr/bin/env python3
"""
BackupSeek v1.1 - Backup System Discovery Tool
Find and enumerate backup infrastructure

Features:
- Veeam Backup & Replication discovery
- Acronis Cyber Backup detection
- Bacula backup system enumeration
- Dell EMC Networker discovery
- IBM Spectrum Protect (TSM) detection
- Windows Server Backup detection
- NAS Backup Systems (NEW!):
  * Synology DSM
  * QNAP QTS
  * TrueNAS/FreeNAS
  * Netgear ReadyNAS
  * Buffalo TeraStation/LinkStation
- Generic backup service discovery
- Backup schedule analysis

Usage:
    ./backupseek.py                        # Scan all backup systems (including NAS)
    ./backupseek.py --veeam                # Veeam only
    ./backupseek.py --acronis              # Acronis only
    ./backupseek.py --full                 # Full enumeration with SMB shares
    
Output:
    backuplist.txt      - Backup servers found
    backup_details.txt  - Detailed findings
    backup_details.json - JSON export
"""

import socket
import subprocess
import sys
import json
import re
import argparse
import ipaddress
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning

# Import shared utilities
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from seek_utils import find_ip_list


# Disable SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Device fingerprinting patterns
DEVICE_FINGERPRINTS = {
    'backup_nas': {
        'synology': {
            'headers': ['x-synology-server', 'server'],
            'content': ['synology', 'dsm', 'diskstation'],
            'titles': ['synology diskstation', 'dsm'],
            'paths': ['/', '/webman/', '/webapi/']
        },
        'qnap': {
            'headers': ['server', 'x-qnap-id'],
            'content': ['qnap', 'qts', 'nas'],
            'titles': ['qnap turbo nas', 'qts'],
            'paths': ['/', '/cgi-bin/', '/indexnas.cgi']
        },
        'truenas': {
            'headers': ['server'],
            'content': ['truenas', 'freenas', 'middleware'],
            'titles': ['truenas', 'freenas'],
            'paths': ['/', '/ui/', '/api/']
        },
        'netgear': {
            'headers': ['server'],
            'content': ['netgear', 'readynas', 'readycloud'],
            'titles': ['netgear', 'readynas'],
            'paths': ['/', '/admin/', '/api/']
        },
        'drobo': {
            'headers': ['server'],
            'content': ['drobo', 'droboshare'],
            'titles': ['drobo dashboard', 'droboshare'],
            'paths': ['/', '/dashboard/']
        },
        'buffalo': {
            'headers': ['server'],
            'content': ['buffalo', 'terastation', 'linkstation'],
            'titles': ['terastation', 'linkstation', 'buffalo nas'],
            'paths': ['/', '/admin/']
        }
    },
    'backup_software': {
        'veeam': {
            'headers': ['server'],
            'content': ['veeam', 'backup', 'enterprise manager'],
            'titles': ['veeam backup', 'enterprise manager'],
            'paths': ['/', '/em/', '/console/']
        },
        'acronis': {
            'headers': ['server'],
            'content': ['acronis', 'cyber backup'],
            'titles': ['acronis', 'cyber backup'],
            'paths': ['/', '/management/', '/console/']
        }
    },
    'exclude_devices': {
        'printers': {
            'headers': ['server'],
            'content': ['hp ', 'canon', 'epson', 'brother', 'lexmark', 'xerox', 'kyocera', 'ricoh', 'printer', 'print server', 'cups'],
            'titles': ['hp ', 'canon', 'epson', 'brother', 'lexmark', 'printer', 'embedded web server'],
            'paths': ['/']
        },
        'switches': {
            'headers': ['server'],
            'content': ['cisco', 'netgear switch', 'tp-link', 'dlink', 'switch', 'managed switch'],
            'titles': ['cisco', 'switch management', 'web management'],
            'paths': ['/']
        },
        'routers': {
            'headers': ['server'],
            'content': ['router', 'gateway', 'openwrt', 'dd-wrt', 'pfsense'],
            'titles': ['router', 'gateway', 'openwrt', 'pfsense'],
            'paths': ['/']
        }
    }
}

# Color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Backup system ports
BACKUP_PORTS = {
    # Veeam
    9392: 'Veeam Backup Service',
    9393: 'Veeam Data Mover',
    9394: 'Veeam Agent',
    9395: 'Veeam Agent',
    9401: 'Veeam Cloud Connect',
    9419: 'Veeam Backup Enterprise Manager',
    6160: 'Veeam vPower NFS',
    6162: 'Veeam Mount Server',
    
    # Acronis
    9876: 'Acronis Backup',
    43234: 'Acronis Agent',
    44445: 'Acronis Management Server',
    
    # Bacula
    9101: 'Bacula Director',
    9102: 'Bacula File Daemon',
    9103: 'Bacula Storage Daemon',
    
    # Dell EMC Networker
    7937: 'Dell Networker',
    7938: 'Dell Networker NSR',
    7939: 'Dell Networker',
    
    # IBM Spectrum Protect (TSM)
    1500: 'IBM TSM/Spectrum Protect',
    1501: 'IBM TSM/Spectrum Protect',
    1581: 'IBM TSM Web Client',
    
    # CommVault
    8400: 'CommVault',
    8401: 'CommVault',
    8403: 'CommVault',
    
    # Veritas NetBackup
    1556: 'NetBackup',
    13701: 'NetBackup',
    13702: 'NetBackup',
    13720: 'NetBackup',
    13724: 'NetBackup',
    
    # Generic backup
    10000: 'Backup Exec',
    10080: 'Amanda Backup',
    
    # NAS Backup Systems
    5000: 'Synology DSM',
    5001: 'Synology DSM (HTTPS)',
    8080: 'QNAP NAS (HTTP)',
    8443: 'QNAP NAS (HTTPS)',
    443: 'TrueNAS/FreeNAS Web',
    80: 'TrueNAS/FreeNAS Web',
    6789: 'Ceph Storage',
    3260: 'iSCSI Target (NAS)',
    2049: 'NFS (NAS Backup Share)',
    
    # Cloud Backup Gateways
    3128: 'Backup Proxy',
    8888: 'Backup Gateway'
}

# Veeam web interfaces
VEEAM_WEB_PORTS = [9443, 9419, 9399]

# NAS system detection
NAS_SYSTEMS = {
    'synology': {
        'ports': [5000, 5001],
        'paths': ['/webman/index.cgi', '/webapi/query.cgi'],
        'headers': ['Server'],
        'identifiers': ['Synology', 'DiskStation']
    },
    'qnap': {
        'ports': [8080, 8443],
        'paths': ['/cgi-bin/index.cgi', '/'],
        'headers': ['Server', 'X-Powered-By'],
        'identifiers': ['QNAP', 'QTS']
    },
    'truenas': {
        'ports': [80, 443],
        'paths': ['/ui/', '/api/v2.0/'],
        'headers': ['Server'],
        'identifiers': ['TrueNAS', 'FreeNAS', 'nginx']
    },
    'netgear': {
        'ports': [443, 80],
        'paths': ['/admin/', '/'],
        'headers': ['Server'],
        'identifiers': ['ReadyNAS']
    },
    'buffalo': {
        'ports': [80, 443],
        'paths': ['/'],
        'headers': ['Server'],
        'identifiers': ['Buffalo', 'TeraStation', 'LinkStation']
    }
}

# Default credentials for common backup/NAS systems
DEFAULT_CREDS = {
    'synology': [
        ('admin', ''),
        ('admin', 'admin'),
        ('admin', 'password'),
    ],
    'qnap': [
        ('admin', 'admin'),
        ('admin', ''),
        ('admin', 'password'),
    ],
    'truenas': [
        ('root', 'freenas'),
        ('root', 'truenas'),
        ('admin', 'admin'),
    ],
    'netgear': [
        ('admin', 'password'),
        ('admin', 'netgear1'),
        ('admin', ''),
    ],
    'buffalo': [
        ('admin', 'password'),
        ('admin', ''),
    ],
    'smb_backup': [
        ('backup', 'backup'),
        ('backup', ''),
        ('administrator', 'backup'),
        ('backupuser', 'backup'),
        ('veeam', 'veeam'),
    ]
}

# Banner - ASCII version for Windows compatibility
BANNER = f"""{CYAN}{BOLD}
=========================================================================
        BACKUPSEEK v1.0 - Backup System Discovery
=========================================================================
{RESET}
{YELLOW}Find and enumerate backup infrastructure{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def read_ip_list(file_path):
    """Read IP addresses from a file (supports CIDR notation)"""
    # Use shared utility to find the file
    file_path = find_ip_list(file_path)
    
    ips = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ip_input = line.split()[0]
                    
                    # Check if CIDR notation
                    if '/' in ip_input:
                        try:
                            network = ipaddress.ip_network(ip_input, strict=False)
                            # Add all host IPs in the network
                            ips.extend([str(ip) for ip in network.hosts()])
                        except ValueError as e:
                            print(f"{YELLOW}[!] Invalid CIDR notation '{ip_input}': {e}{RESET}")
                    else:
                        ips.append(ip_input)
    except Exception as e:
        print(f"{RED}[!] Error reading file {file_path}: {e}{RESET}")
    return ips


def check_port(ip, port, timeout=3):
    """Check if a TCP port is open"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False


def detect_veeam_web(ip, timeout=5):
    """
    Detect Veeam Backup Enterprise Manager
    Returns: (found, version, port) tuple
    """
    for port in VEEAM_WEB_PORTS:
        try:
            for protocol in ['https', 'http']:
                url = f"{protocol}://{ip}:{port}/api/"
                
                response = requests.get(url, timeout=timeout, verify=False)
                if response.status_code == 200 and 'veeam' in response.text.lower():
                    # Try to extract version
                    version_match = re.search(r'version["\s:]+([0-9.]+)', response.text, re.IGNORECASE)
                    version = version_match.group(1) if version_match else 'Unknown'
                    return True, version, port
        except:
            continue
    return False, '', 0

def detect_acronis_web(ip, timeout=5):
    """
    Detect Acronis Cyber Backup web interface
    Returns: (found, version, port) tuple
    """
    acronis_ports = [9877, 44445, 80, 443]
    
    for port in acronis_ports:
        try:
            for protocol in ['https', 'http']:
                for path in ['/', '/api/', '/login']:
                    url = f"{protocol}://{ip}:{port}{path}"
                    
                    response = requests.get(url, timeout=timeout, verify=False)
                    
                    # Check for Acronis indicators
                    if any(term in response.text.lower() for term in ['acronis', 'cyber backup', 'cyber protect']):
                        version_match = re.search(r'version["\s:]+([0-9.]+)', response.text, re.IGNORECASE)
                        version = version_match.group(1) if version_match else 'Unknown'
                        return True, version, port
        except:
            continue
    return False, '', 0

def grab_http_banner(ip, port, timeout=5):
    """
    Grab HTTP banner and page content for analysis
    Returns: dict with server, title, content, headers
    """
    result = {
        'server': '',
        'title': '',
        'content': '',
        'headers': {},
        'status_code': 0
    }
    
    for protocol in ['https', 'http']:
        try:
            url = f"{protocol}://{ip}:{port}/"
            response = requests.get(
                url,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            )
            
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['server'] = response.headers.get('Server', '')
            result['content'] = response.text[:10000]  # First 10KB
            
            # Extract title
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
            if title_match:
                result['title'] = title_match.group(1).strip()
            
            return result
            
        except Exception:
            continue
    
    return result

def is_backup_system(banner_info, ip, port):
    """
    Analyze banner info to determine if this is actually a backup system
    Returns: (is_backup, system_type, confidence_score)
    """
    
    # Anti-patterns (things that are NOT backup systems)
    anti_patterns = [
        r'printer.*web.*server',
        r'cups.*\d+',
        r'hp.*web.*jetadmin',
        r'canon.*imagerunner',
        r'lexmark.*management',
        r'brother.*control.*center',
        r'xerox.*centreware',
        r'router.*admin',
        r'switch.*management',
        r'firewall.*management',
        r'camera.*web.*interface',
        r'ip.*camera',
        r'surveillance.*system',
        r'generic.*login.*page',
        r'web.*server.*test.*page',
        r'apache.*default.*page',
        r'nginx.*default.*page',
        r'iis.*welcome.*page'
    ]
    
    # Backup-specific indicators with confidence scoring
    backup_indicators = {
        'veeam': {
            'patterns': [
                r'veeam.*backup',
                r'backup.*enterprise.*manager',
                r'veeam.*one',
                r'vbr\d+',
                r'backup.*replication'
            ],
            'ports': [9443, 9419, 9399],
            'confidence': 95
        },
        'acronis': {
            'patterns': [
                r'acronis.*backup',
                r'cyber.*backup',
                r'acronis.*cyber.*protect'
            ],
            'ports': [9877, 44445],
            'confidence': 95
        },
        'synology_backup': {
            'patterns': [
                r'synology.*dsm',
                r'diskstation.*manager',
                r'synology.*backup',
                r'cloud.*station.*backup'
            ],
            'ports': [5000, 5001],
            'confidence': 85
        },
        'qnap_backup': {
            'patterns': [
                r'qnap.*qts',
                r'hybrid.*backup.*sync',
                r'qnap.*backup'
            ],
            'ports': [8080, 8443],
            'confidence': 85
        },
        'truenas_backup': {
            'patterns': [
                r'truenas.*core',
                r'freenas',
                r'truenas.*scale'
            ],
            'ports': [80, 443],
            'confidence': 80
        }
    }
    
    # Combine all text for analysis
    analysis_text = ' '.join([
        banner_info.get('server', ''),
        banner_info.get('title', ''),
        banner_info.get('content', '')
    ]).lower()
    
    # Check anti-patterns first (eliminate false positives)
    for pattern in anti_patterns:
        if re.search(pattern, analysis_text, re.IGNORECASE):
            return False, 'excluded', 0
    
    # Check backup system patterns
    best_match = None
    best_confidence = 0
    
    for system_type, config in backup_indicators.items():
        confidence = 0
        
        # Check patterns
        for pattern in config['patterns']:
            if re.search(pattern, analysis_text, re.IGNORECASE):
                confidence += config['confidence']
                break
        
        # Port bonus
        if port in config.get('ports', []):
            confidence += 10
        
        # Update best match
        if confidence > best_confidence:
            best_confidence = confidence
            best_match = system_type
    
    # Require minimum confidence threshold
    if best_confidence >= 70:
        return True, best_match, best_confidence
    
    return False, 'unknown', best_confidence


def enhanced_credential_test(ip, port, username, password, system_type, timeout=10):
    """
    Enhanced credential testing with better validation
    Returns: (success, evidence, error_msg)
    """
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    system_specific_tests = {
        'synology_backup': {
            'login_path': '/webapi/auth.cgi',
            'method': 'GET',
            'params': {
                'api': 'SYNO.API.Auth',
                'version': '2',
                'method': 'login',
                'account': username,
                'passwd': password,
                'session': 'FileStation',
                'format': 'cookie'
            },
            'success_indicators': ['success":true', '"sid":', 'success: true'],
            'failure_indicators': ['error', 'password', 'invalid', 'denied']
        },
        'qnap_backup': {
            'login_path': '/cgi-bin/authLogin.cgi',
            'method': 'POST',
            'data': {
                'user': username,
                'pwd': password
            },
            'success_indicators': ['QTS_LOGGED', 'authPassed', 'success'],
            'failure_indicators': ['authFailed', 'invalid', 'error']
        },
        'veeam': {
            'login_path': '/api/sessionMngr/',
            'method': 'POST',
            'headers': {'Content-Type': 'application/json'},
            'data': {
                'username': username,
                'password': password
            },
            'success_indicators': ['X-RestSvcSessionId', 'sessionId', 'token'],
            'failure_indicators': ['unauthorized', 'invalid', 'error']
        }
    }
    
    if system_type not in system_specific_tests:
        return False, 'No specific test available', 'Generic auth not implemented'
    
    test_config = system_specific_tests[system_type]
    
    try:
        for protocol in ['https', 'http']:
            url = f"{protocol}://{ip}:{port}{test_config['login_path']}"
            
            if test_config['method'] == 'POST':
                response = requests.post(
                    url,
                    data=test_config.get('data', {}),
                    json=test_config.get('json', None),
                    headers=test_config.get('headers', {}),
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
            else:
                response = requests.get(
                    url,
                    params=test_config.get('params', {}),
                    headers=test_config.get('headers', {}),
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
            
            response_text = response.text.lower()
            
            # Check for success indicators
            for indicator in test_config['success_indicators']:
                if indicator.lower() in response_text:
                    # Double-check it's not a failure
                    is_failure = any(fail_ind.lower() in response_text 
                                   for fail_ind in test_config['failure_indicators'])
                    if not is_failure:
                        return True, f'Found: {indicator}', ''
            
            # Check for explicit failure indicators
            for indicator in test_config['failure_indicators']:
                if indicator.lower() in response_text:
                    return False, f'Failed: {indicator}', response.status_code
    
    except Exception as e:
        return False, 'Connection failed', str(e)
    
    return False, 'Auth result unclear', 'No clear success/failure indicators found'


def detect_veeam_web(ip, timeout=5):
    """
    Detect Veeam web interface
    Returns: dict with findings
    """
    findings = []
    
    for port in VEEAM_WEB_PORTS:
        try:
            url = f'https://{ip}:{port}'
            response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
            
            # Check for Veeam indicators in response
            if 'veeam' in response.text.lower() or 'backup' in response.headers.get('Server', '').lower():
                findings.append({
                    'type': 'veeam_web',
                    'url': url,
                    'port': port,
                    'status_code': response.status_code
                })
                
                # Try to identify specific Veeam component
                if 'enterprise manager' in response.text.lower():
                    findings[-1]['component'] = 'Enterprise Manager'
                elif 'cloud connect' in response.text.lower():
                    findings[-1]['component'] = 'Cloud Connect'
        except:
            continue
    
    return findings


def detect_acronis_web(ip, timeout=5):
    """
    Detect Acronis web interface
    Returns: dict with findings
    """
    findings = []
    
    acronis_ports = [9877, 44445]
    
    for port in acronis_ports:
        try:
            for protocol in ['https', 'http']:
                url = f'{protocol}://{ip}:{port}'
                response = requests.get(url, timeout=timeout, verify=False)
                
                if 'acronis' in response.text.lower():
                    findings.append({
                        'type': 'acronis_web',
                        'url': url,
                        'port': port,
                        'status_code': response.status_code
                    })
                    break
        except:
            continue
    
    return findings


def check_smb_backup_shares(ip, timeout=3):
    """
    Check for common backup share names
    Returns: list of backup shares found
    """
    backup_shares = []
    backup_share_names = ['Backup', 'Backups', 'VeeamBackup', 'BackupExec', 'Acronis']
    
    try:
        # List shares
        cmd = ['smbclient', '-L', f'//{ip}', '-N', '--timeout', str(timeout)]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                for backup_name in backup_share_names:
                    if backup_name.lower() in line.lower() and 'Disk' in line:
                        parts = line.split()
                        if parts:
                            share_name = parts[0].strip()
                            backup_shares.append(share_name)
    except:
        pass
    
    return backup_shares


def grab_http_banner(ip, port, timeout=5):
    """
    Grab HTTP banner and classify device type using fingerprinting patterns.
    Returns (device_type, banner_info) tuple.
    """
    import requests
    import ssl
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    device_type = "unknown"
    banner_info = {}
    
    # Try HTTPS first, then HTTP
    protocols = [('https', port), ('http', port)]
    if port == 80:
        protocols = [('http', port)]
    elif port == 443:
        protocols = [('https', port)]
    
    for protocol, p in protocols:
        try:
            url = f"{protocol}://{ip}:{p}"
            
            # Make request with common backup device paths
            paths = ['/', '/admin', '/api/v1/status', '/login', '/setup', '/cgi-bin/luci']
            
            for path in paths:
                try:
                    response = requests.get(
                        f"{url}{path}",
                        timeout=timeout,
                        verify=False,
                        allow_redirects=True,
                        headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                    )
                    
                    # Extract banner information
                    banner_info.update({
                        'status_code': response.status_code,
                        'headers': dict(response.headers),
                        'title': '',
                        'content_snippet': response.text[:2000].lower(),
                        'url': response.url
                    })
                    
                    # Extract title
                    import re
                    title_match = re.search(r'<title[^>]*>([^<]+)</title>', response.text, re.IGNORECASE)
                    if title_match:
                        banner_info['title'] = title_match.group(1).strip()
                    
                    # Check device fingerprints
                    device_type = classify_device(banner_info)
                    
                    if device_type != "unknown":
                        return device_type, banner_info
                        
                except requests.exceptions.RequestException:
                    continue
                    
            # If we got any response but no classification, return what we have
            if banner_info:
                return device_type, banner_info
                
        except Exception:
            continue
    
    return device_type, banner_info


def classify_device(banner_info):
    """
    Classify device type based on banner information using DEVICE_FINGERPRINTS.
    Returns device category: backup_nas, backup_software, exclude_devices, or unknown.
    """
    content = banner_info.get('content_snippet', '').lower()
    title = banner_info.get('title', '').lower()
    headers = banner_info.get('headers', {})
    url_path = banner_info.get('url', '').lower()
    
    # Convert headers to lowercase for easier matching
    headers_str = ' '.join([f"{k}: {v}" for k, v in headers.items()]).lower()
    
    # Check exclusions first (printers, switches, routers) - highest priority
    if 'exclude_devices' in DEVICE_FINGERPRINTS:
        for device_name, patterns in DEVICE_FINGERPRINTS['exclude_devices'].items():
            # Check content patterns
            if 'content' in patterns:
                for pattern in patterns['content']:
                    if pattern.lower() in content:
                        return 'exclude_devices'
            
            # Check title patterns  
            if 'titles' in patterns:
                for pattern in patterns['titles']:
                    if pattern.lower() in title:
                        return 'exclude_devices'
            
            # Check header patterns
            if 'headers' in patterns:
                for header_name in patterns['headers']:
                    if header_name.lower() in headers_str:
                        # Only match if we actually have server header content indicating excluded device
                        if any(pattern.lower() in headers_str for pattern in patterns.get('content', [])):
                            return 'exclude_devices'
    
    # Check for backup/NAS devices
    if 'backup_nas' in DEVICE_FINGERPRINTS:
        for device_name, patterns in DEVICE_FINGERPRINTS['backup_nas'].items():
            # Check content patterns
            if 'content' in patterns:
                for pattern in patterns['content']:
                    if pattern.lower() in content:
                        return 'backup_nas'
            
            # Check title patterns
            if 'titles' in patterns:
                for pattern in patterns['titles']:
                    if pattern.lower() in title:
                        return 'backup_nas'
    
    # Check for backup software
    if 'backup_software' in DEVICE_FINGERPRINTS:
        for device_name, patterns in DEVICE_FINGERPRINTS['backup_software'].items():
            # Check content patterns
            if 'content' in patterns:
                for pattern in patterns['content']:
                    if pattern.lower() in content:
                        return 'backup_software'
            
            # Check title patterns
            if 'titles' in patterns:
                for pattern in patterns['titles']:
                    if pattern.lower() in title:
                        return 'backup_software'
    
    return 'unknown'


def test_smb_credentials(ip, share, username, password, timeout=3):
    """
    Test SMB credentials on a share
    Returns: (success, file_list) tuple
    """
    try:
        # Build smbclient command
        if password:
            cmd = ['smbclient', f'//{ip}/{share}', password, '-U', username, '-c', 'ls', '--timeout', str(timeout)]
        else:
            cmd = ['smbclient', f'//{ip}/{share}', '-U', f'{username}%', '-c', 'ls', '--timeout', str(timeout)]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        
        if result.returncode == 0 and 'NT_STATUS' not in result.stdout:
            # Extract first few files/folders
            files = []
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith('.') and ('D' in line or '<DIR>' in line or 'A' in line):
                    parts = line.split()
                    if parts:
                        files.append(parts[0])
                if len(files) >= 5:  # Limit to first 5 items
                    break
            return True, files
        return False, []
    except:
        return False, []


def test_nas_web_login(ip, port, username, password, nas_type, timeout=5):
    """
    Test web login for NAS systems with improved validation
    Returns: (success, details) tuple
    """
    import requests
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    
    try:
        # First, classify the device to ensure it's actually a backup/NAS device
        device_type, banner_info = grab_http_banner(ip, port, timeout)
        
        # Skip credential testing on excluded devices (printers, switches, etc.)
        if device_type == 'exclude_devices':
            return False, f"Skipped - Device classified as {device_type} (not a backup system)"
        
        # If device type is unknown, proceed with caution
        if device_type == 'unknown':
            # Check if it has basic backup/NAS indicators
            content = banner_info.get('content_snippet', '').lower()
            title = banner_info.get('title', '').lower()
            
            # Basic backup/storage indicators
            backup_indicators = [
                'storage', 'backup', 'nas', 'file server', 'disk station',
                'share', 'volume', 'raid', 'dashboard', 'admin panel'
            ]
            
            has_backup_indicators = any(indicator in content or indicator in title 
                                     for indicator in backup_indicators)
            
            if not has_backup_indicators:
                return False, "Skipped - No backup/storage indicators found"
        
        # Test specific NAS types with proper API validation
        if nas_type == 'synology':
            success, details = test_synology_login(ip, port, username, password, timeout)
            if success:
                return success, details
                
        elif nas_type == 'qnap':
            success, details = test_qnap_login(ip, port, username, password, timeout)
            if success:
                return success, details
        
        # Enhanced generic authentication testing
        return test_generic_web_auth(ip, port, username, password, timeout, banner_info)
        
    except Exception as e:
        return False, f"Error during authentication test: {str(e)}"


def test_synology_login(ip, port, username, password, timeout=5):
    """Test Synology DSM API login with proper validation"""
    try:
        # Try both HTTP and HTTPS
        for protocol in ['https', 'http']:
            try:
                url = f'{protocol}://{ip}:{port}/webapi/auth.cgi'
                data = {
                    'api': 'SYNO.API.Auth',
                    'version': '3',
                    'method': 'login',
                    'account': username,
                    'passwd': password,
                    'session': 'FileStation',
                    'format': 'cookie'
                }
                
                response = requests.get(url, params=data, timeout=timeout, verify=False)
                
                if response.status_code == 200:
                    try:
                        result = response.json()
                        if result.get('success') == True:
                            # Verify we actually got a session by checking info
                            info_url = f'{protocol}://{ip}:{port}/webapi/entry.cgi'
                            info_params = {
                                'api': 'SYNO.API.Info',
                                'version': '1',
                                'method': 'query'
                            }
                            info_response = requests.get(info_url, params=info_params, 
                                                       cookies=response.cookies, timeout=timeout, verify=False)
                            
                            if info_response.status_code == 200:
                                return True, f"Synology DSM - Successfully authenticated and verified session"
                                
                    except ValueError:
                        # Not JSON response
                        continue
                        
            except requests.exceptions.RequestException:
                continue
                
        return False, None
        
    except Exception:
        return False, None


def test_qnap_login(ip, port, username, password, timeout=5):
    """Test QNAP QTS login with proper validation"""
    try:
        for protocol in ['https', 'http']:
            try:
                # Try QTS login endpoint
                url = f'{protocol}://{ip}:{port}/cgi-bin/authLogin.cgi'
                data = {
                    'user': username,
                    'pwd': password
                }
                
                response = requests.post(url, data=data, timeout=timeout, verify=False)
                
                # Check for successful login indicators
                if (response.status_code == 200 and 
                    ('authPassed' in response.text or 'QID' in response.text)):
                    
                    # Verify by trying to access admin interface
                    admin_url = f'{protocol}://{ip}:{port}/cgi-bin/management/manaRequest.cgi'
                    admin_response = requests.get(admin_url, cookies=response.cookies, 
                                                timeout=timeout, verify=False)
                    
                    if admin_response.status_code in [200, 302]:
                        return True, f"QNAP QTS - Successfully authenticated and verified access"
                        
            except requests.exceptions.RequestException:
                continue
                
        return False, None
        
    except Exception:
        return False, None


def test_generic_web_auth(ip, port, username, password, timeout, banner_info):
    """Enhanced generic web authentication testing with proper validation"""
    try:
        # Test various authentication methods
        auth_methods = [
            ('basic_auth', None),
            ('form_login', ['/login', '/admin/login', '/api/login']),
            ('digest_auth', None)
        ]
        
        for protocol in ['https', 'http']:
            for auth_method, paths in auth_methods:
                
                if auth_method == 'basic_auth':
                    # Test HTTP Basic Authentication
                    for path in ['/', '/admin', '/api']:
                        try:
                            url = f'{protocol}://{ip}:{port}{path}'
                            
                            # First check without auth
                            no_auth_response = requests.get(url, timeout=timeout, verify=False)
                            
                            # Try with auth
                            auth_response = requests.get(url, auth=(username, password), 
                                                       timeout=timeout, verify=False)
                            
                            # Validate successful authentication
                            if (auth_response.status_code == 200 and 
                                no_auth_response.status_code in [401, 403] and
                                len(auth_response.text) > len(no_auth_response.text)):
                                
                                # Additional validation - check for admin content
                                content = auth_response.text.lower()
                                admin_indicators = [
                                    'dashboard', 'logout', 'admin', 'settings', 
                                    'configuration', 'users', 'system', 'status'
                                ]
                                
                                if any(indicator in content for indicator in admin_indicators):
                                    return True, f"HTTP Basic Auth successful - Admin interface accessible"
                                    
                        except requests.exceptions.RequestException:
                            continue
                
                elif auth_method == 'form_login' and paths:
                    # Test form-based login
                    for path in paths:
                        try:
                            url = f'{protocol}://{ip}:{port}{path}'
                            
                            # Get login form
                            form_response = requests.get(url, timeout=timeout, verify=False)
                            
                            if form_response.status_code == 200:
                                # Extract form details and attempt login
                                success = attempt_form_login(url, username, password, 
                                                           form_response.text, timeout)
                                if success:
                                    return True, f"Form-based login successful at {path}"
                                    
                        except requests.exceptions.RequestException:
                            continue
        
        return False, None
        
    except Exception:
        return False, None


def attempt_form_login(login_url, username, password, form_html, timeout):
    """Attempt to login using form-based authentication"""
    try:
        import re
        from urllib.parse import urljoin
        
        # Extract form action and input fields
        form_match = re.search(r'<form[^>]*action=[\'"](.*?)[\'"][^>]*>(.*?)</form>', 
                              form_html, re.DOTALL | re.IGNORECASE)
        
        if not form_match:
            return False
            
        action = form_match.group(1)
        form_content = form_match.group(2)
        
        # Find input fields
        inputs = re.findall(r'<input[^>]*name=[\'"](.*?)[\'"][^>]*(?:value=[\'"](.*?)[\'"])?[^>]*>', 
                           form_content, re.IGNORECASE)
        
        # Build form data
        form_data = {}
        username_fields = ['username', 'user', 'login', 'email', 'account']
        password_fields = ['password', 'passwd', 'pass', 'pwd']
        
        for input_name, input_value in inputs:
            if input_name.lower() in username_fields:
                form_data[input_name] = username
            elif input_name.lower() in password_fields:
                form_data[input_name] = password
            elif input_value:  # Hidden fields with values
                form_data[input_name] = input_value
        
        # Submit form
        if action.startswith('http'):
            submit_url = action
        else:
            submit_url = urljoin(login_url, action)
            
        response = requests.post(submit_url, data=form_data, timeout=timeout, 
                               verify=False, allow_redirects=True)
        
        # Check for successful login indicators
        if response.status_code == 200:
            content = response.text.lower()
            success_indicators = ['dashboard', 'welcome', 'logout', 'admin panel']
            failure_indicators = ['invalid', 'error', 'failed', 'incorrect']
            
            has_success = any(indicator in content for indicator in success_indicators)
            has_failure = any(indicator in content for indicator in failure_indicators)
            
            return has_success and not has_failure
            
        return False
        
    except Exception:
        return False


def identify_backup_system(open_ports):
    """
    Identify backup system based on open ports
    Returns: list of identified systems
    """
    systems = []
    
    # Veeam
    veeam_ports = [9392, 9393, 9401, 9419, 6160]
    if any(port in open_ports for port in veeam_ports):
        systems.append({
            'system': 'Veeam Backup & Replication',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in veeam_ports]
        })
    
    # Acronis
    acronis_ports = [9876, 43234, 44445]
    if any(port in open_ports for port in acronis_ports):
        systems.append({
            'system': 'Acronis Cyber Backup',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in acronis_ports]
        })
    
    # Bacula
    bacula_ports = [9101, 9102, 9103]
    if any(port in open_ports for port in bacula_ports):
        systems.append({
            'system': 'Bacula',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in bacula_ports]
        })
    
    # Dell Networker
    networker_ports = [7937, 7938, 7939]
    if any(port in open_ports for port in networker_ports):
        systems.append({
            'system': 'Dell EMC Networker',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in networker_ports]
        })
    
    # IBM Spectrum Protect
    tsm_ports = [1500, 1501, 1581]
    if any(port in open_ports for port in tsm_ports):
        systems.append({
            'system': 'IBM Spectrum Protect (TSM)',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in tsm_ports]
        })
    
    # CommVault
    commvault_ports = [8400, 8401, 8403]
    if any(port in open_ports for port in commvault_ports):
        systems.append({
            'system': 'CommVault',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in commvault_ports]
        })
    
    # NetBackup
    netbackup_ports = [1556, 13701, 13702, 13720, 13724]
    if any(port in open_ports for port in netbackup_ports):
        systems.append({
            'system': 'Veritas NetBackup',
            'confidence': 'high',
            'ports': [p for p in open_ports if p in netbackup_ports]
        })
    
    return systems


def is_backup_system(banner, headers, title, url):
    """
    Enhanced backup system detection with anti-patterns
    Returns: (is_backup, confidence, system_type)
    """
    combined_text = f"{banner} {headers} {title} {url}".lower()
    
    # Anti-patterns for printer and generic admin interfaces
    printer_patterns = [
        'printer', 'canon', 'xerox', 'hp laserjet', 'epson',
        'brother printer', 'toner', 'cartridge', 'print queue',
        'ricoh', 'kyocera', 'sharp printer', 'konica minolta',
        'web jetadmin', 'printer management', 'supply levels'
    ]
    
    # Generic admin interface patterns (low confidence)
    generic_patterns = [
        'admin panel', 'control panel', 'web interface',
        'management console', 'configuration', 'settings',
        'dashboard', 'login page'
    ]
    
    # Check for printer indicators (immediate rejection)
    if any(pattern in combined_text for pattern in printer_patterns):
        return False, 0, 'Printer/Print Server'
    
    # Backup system patterns with confidence scoring
    backup_patterns = {
        'veeam': 95,
        'acronis': 95,
        'commvault': 95,
        'veritas netbackup': 95,
        'symantec backup': 95,
        'backup exec': 95,
        'bacula': 90,
        'amanda backup': 90,
        'duplicati': 85,
        'urbackup': 85,
        'synology': 85,  # Often used for backups
        'qnap': 85,      # Often used for backups
        'drobo': 80,
        'freenas': 80,
        'truenas': 80,
        'openfiler': 75,
        'backup software': 70,
        'backup server': 70,
        'backup management': 70,
        'backup console': 70,
        'disaster recovery': 65,
        'data protection': 60
    }
    
    max_confidence = 0
    detected_system = 'Unknown Backup System'
    
    for pattern, confidence in backup_patterns.items():
        if pattern in combined_text:
            if confidence > max_confidence:
                max_confidence = confidence
                detected_system = pattern.title()
    
    # Check for generic patterns only if no specific backup patterns found
    if max_confidence == 0:
        if any(pattern in combined_text for pattern in generic_patterns):
            # Very low confidence for generic interfaces
            return True, 15, 'Generic Interface'
    
    return max_confidence > 0, max_confidence, detected_system


def enhanced_web_detection(ip, open_ports, timeout=5):
    """
    Enhanced web-based backup system detection
    Returns: list of detected systems with confidence scores
    """
    detected_systems = []
    web_ports = [port for port in open_ports if port in [80, 443, 8080, 8443, 9443, 8081, 8082, 9000, 9001]]
    
    for port in web_ports:
        banner = grab_http_banner(ip, port, timeout)
        if banner:
            is_backup, confidence, system_type = is_backup_system(
                banner.get('banner', ''),
                str(banner.get('headers', {})),
                banner.get('title', ''),
                f"http://{ip}:{port}"
            )
            
            if is_backup and confidence >= 50:  # Only report medium+ confidence
                detected_systems.append({
                    'system': system_type,
                    'confidence': f'medium ({confidence}%)',
                    'ports': [port],
                    'details': f"Web interface detected via banner analysis"
                })
    
    return detected_systems

def detect_nas_systems(ip, open_ports, timeout=5):
    """
    Detect NAS backup systems with smart device classification to avoid false positives
    Returns: list of detected NAS systems
    """
    detected = []
    
    # Common web ports for device detection
    web_ports = [port for port in open_ports if port in [80, 443, 8080, 8443, 5000, 5001, 9000]]
    
    # First, try device classification on web ports
    for port in web_ports:
        device_type, banner_info = grab_http_banner(ip, port, timeout)
        
        # Skip excluded devices (printers, switches, routers)
        if device_type == 'exclude_devices':
            try:
                verbose_mode = False  # Set to False by default for now
            except:
                verbose_mode = False
                
            if verbose_mode:
                print(f"{YELLOW}[!] Skipping {ip}:{port} - Detected as excluded device type{RESET}")
            continue
            
        # Handle confirmed backup/NAS devices
        if device_type in ['backup_nas', 'backup_software']:
            confidence = 'high' if device_type == 'backup_nas' else 'medium'
            
            # Try to identify specific NAS type
            title = banner_info.get('title', '').lower()
            content = banner_info.get('content_snippet', '').lower()
            headers = banner_info.get('headers', {})
            
            # Specific NAS system detection
            nas_type = identify_specific_nas_type(title, content, headers)
            
            detected.append({
                'system': nas_type if nas_type else f'NAS System ({device_type})',
                'confidence': confidence,
                'ports': [port],
                'url': banner_info.get('url', f'http://{ip}:{port}'),
                'identifiers': extract_device_identifiers(banner_info),
                'version': headers.get('Server', 'Unknown'),
                'device_type': device_type
            })
    
    # Fallback to traditional NAS detection for systems without web interfaces
    for nas_name, nas_config in NAS_SYSTEMS.items():
        for port in nas_config['ports']:
            if port not in open_ports:
                continue
                
            # Skip if we already detected this port as a web interface
            if port in web_ports:
                continue
                
            # Try HTTP/HTTPS detection for non-standard ports
            for protocol in ['https', 'http']:
                try:
                    for path in nas_config['paths']:
                        url = f"{protocol}://{ip}:{port}{path}"
                        
                        response = requests.get(
                            url,
                            timeout=timeout,
                            verify=False,
                            allow_redirects=True,
                            headers={'User-Agent': 'Mozilla/5.0'}
                        )
                        
                        # Check headers for identifiers
                        found_identifiers = []
                        for header_name in nas_config['headers']:
                            header_value = response.headers.get(header_name, '')
                            for identifier in nas_config['identifiers']:
                                if identifier.lower() in header_value.lower():
                                    found_identifiers.append(identifier)
                        
                        # Check response body for identifiers
                        response_text = response.text[:5000]  # First 5KB
                        for identifier in nas_config['identifiers']:
                            if identifier.lower() in response_text.lower():
                                if identifier not in found_identifiers:
                                    found_identifiers.append(identifier)
                        
                        if found_identifiers:
                            detected.append({
                                'system': f'{nas_name.upper()} NAS',
                                'confidence': 'high',
                                'ports': [port],
                                'url': url,
                                'identifiers': found_identifiers,
                                'version': response.headers.get('Server', 'Unknown'),
                                'device_type': 'backup_nas'
                            })
                            break  # Found it, move to next NAS type
                        
                except requests.exceptions.RequestException:
                    continue
                except Exception as e:
                    try:
                        verbose_mode = False  # Set to False by default for now
                    except:
                        verbose_mode = False
                        
                    if verbose_mode:
                        print(f"{YELLOW}[!] NAS detection error for {ip}:{port} - {e}{RESET}")
                    continue
    
    # Protocol-based NAS detection (non-HTTP services)
    nas_service_ports = {
        3260: 'iSCSI Target',
        2049: 'NFS Share', 
        6789: 'Ceph Storage',
        111: 'RPC Portmapper (NFS)',
        2000: 'Cisco SCCP (Storage)',
        8200: 'VMware vSphere'
    }
    
    for port, service in nas_service_ports.items():
        if port in open_ports and port not in [d['ports'][0] for d in detected]:
            detected.append({
                'system': f'Storage Service ({service})',
                'confidence': 'medium',
                'ports': [port],
                'identifiers': [f'Port {port} ({service})'],
                'device_type': 'backup_service'
            })
    
    return detected


def identify_specific_nas_type(title, content, headers):
    """Identify specific NAS system type from banner information"""
    server_header = headers.get('Server', '').lower()
    
    # Synology detection
    if any(term in title for term in ['synology', 'diskstation', 'dsm']):
        return 'Synology DiskStation'
    if any(term in content for term in ['synology', 'diskstation', 'syno']):
        return 'Synology NAS'
    
    # QNAP detection  
    if any(term in title for term in ['qnap', 'turbonas']):
        return 'QNAP TurboNAS'
    if any(term in content for term in ['qnap', 'qts', 'turbonas']):
        return 'QNAP NAS'
    
    # FreeNAS/TrueNAS detection
    if any(term in title for term in ['freenas', 'truenas']):
        return 'TrueNAS/FreeNAS'
    if any(term in content for term in ['freenas', 'truenas', 'freebsd']):
        return 'TrueNAS System'
    
    # Buffalo detection
    if any(term in title for term in ['buffalo', 'terastation']):
        return 'Buffalo TeraStation'
    
    # Drobo detection
    if any(term in title for term in ['drobo']):
        return 'Drobo Storage'
    
    # Generic web-based storage
    if any(term in content for term in ['web administration', 'storage management']):
        return 'Web-based Storage System'
        
    return None


def extract_device_identifiers(banner_info):
    """Extract identifying information from banner data"""
    identifiers = []
    
    title = banner_info.get('title', '')
    if title:
        identifiers.append(f"Title: {title}")
    
    headers = banner_info.get('headers', {})
    server = headers.get('Server')
    if server:
        identifiers.append(f"Server: {server}")
    
    content = banner_info.get('content_snippet', '')
    # Look for version info in content
    import re
    version_match = re.search(r'version\s*[:=]\s*([0-9\.]+)', content, re.IGNORECASE)
    if version_match:
        identifiers.append(f"Version: {version_match.group(1)}")
    
    return identifiers if identifiers else ['HTTP response']


def scan_host(ip, args):
    """
    Scan a single host for backup systems
    Returns: dict with findings
    """
    result = {
        'ip': ip,
        'open_ports': [],
        'identified_systems': [],
        'web_interfaces': [],
        'backup_shares': [],
        'status': 'no_backup'
    }
    
    try:
        # Determine which ports to scan
        ports_to_scan = []
        
        if args.veeam_only:
            ports_to_scan = [9392, 9393, 9401, 9419, 6160, 6162]
        elif args.acronis_only:
            ports_to_scan = [9876, 43234, 44445]
        elif args.full:
            ports_to_scan = list(BACKUP_PORTS.keys())
        else:
            # Common backup ports (including NAS systems)
            ports_to_scan = [
                9392, 9401,  # Veeam
                9876, 44445,  # Acronis
                9101, 9102, 9103,  # Bacula
                7937, 7938,  # Networker
                1500, 1581,  # TSM
                8400, 13701,  # CommVault, NetBackup
                5000, 5001,  # Synology DSM
                8080, 8443,  # QNAP
                443, 80,     # TrueNAS/Generic NAS Web
                3260, 2049   # iSCSI, NFS (NAS backup shares)
            ]
        
        # Scan ports
        for port in ports_to_scan:
            if check_port(ip, port, timeout=args.timeout):
                result['open_ports'].append(port)
        
        if not result['open_ports']:
            return result
        
        # Identify backup systems
        result['identified_systems'] = identify_backup_system(result['open_ports'])
        
        # Enhanced web-based detection for additional confidence
        enhanced_systems = enhanced_web_detection(ip, result['open_ports'], timeout=args.timeout)
        if enhanced_systems:
            # Merge with existing systems or add new ones
            for enhanced in enhanced_systems:
                # Check if we already detected this system type via port detection
                existing = next((s for s in result['identified_systems'] 
                               if enhanced['system'].lower() in s['system'].lower()), None)
                if existing:
                    # Enhance existing detection with web evidence
                    existing['confidence'] = 'high (port + web confirmed)'
                    existing['details'] = f"Port detection confirmed by web interface analysis"
                else:
                    # Add new system detected only via web interface
                    result['identified_systems'].append(enhanced)
        
        # Detect NAS systems (Synology, QNAP, TrueNAS, etc.) with smart filtering
        nas_systems = detect_nas_systems(ip, result['open_ports'], timeout=args.timeout)
        if nas_systems:
            # Apply backup-only filtering if enabled and classification is enabled
            if args.backup_only and not args.skip_classification:
                # Only keep systems classified as backup/NAS devices
                filtered_systems = []
                for system in nas_systems:
                    device_type = system.get('device_type', 'unknown')
                    if device_type in ['backup_nas', 'backup_software', 'backup_service']:
                        filtered_systems.append(system)
                    elif args.verbose:
                        print(f"{YELLOW}[!] Filtered out {ip}: {system.get('system', 'Unknown')} (device_type: {device_type}){RESET}")
                
                nas_systems = filtered_systems
            
            result['identified_systems'].extend(nas_systems)
        
        if result['identified_systems']:
            result['status'] = 'backup_found'
        
        # Check for web interfaces
        if any('Veeam' in sys['system'] for sys in result['identified_systems']):
            veeam_web = detect_veeam_web(ip, timeout=args.timeout)
            if veeam_web:
                result['web_interfaces'].extend(veeam_web)
        
        if any('Acronis' in sys['system'] for sys in result['identified_systems']):
            acronis_web = detect_acronis_web(ip, timeout=args.timeout)
            if acronis_web:
                result['web_interfaces'].extend(acronis_web)
        
        # Check for backup shares (if SMB ports are open)
        if args.full or args.test_creds:
            backup_shares = check_smb_backup_shares(ip, timeout=args.timeout)
            if backup_shares:
                result['backup_shares'] = backup_shares
        
        # Test default credentials if enabled and not in classify-only mode
        if args.test_creds and not args.classify_only:
            result['cred_results'] = []
            
            # Test SMB shares with default creds
            if result['backup_shares']:
                print(f"{YELLOW}[*] Testing default credentials on SMB shares...{RESET}")
                for share in result['backup_shares']:
                    for username, password in DEFAULT_CREDS['smb_backup']:
                        success, files = test_smb_credentials(ip, share, username, password, timeout=args.timeout)
                        if success:
                            pwd_display = password if password else '[blank]'
                            result['cred_results'].append({
                                'type': 'smb',
                                'share': share,
                                'username': username,
                                'password': pwd_display,
                                'files': files
                            })
                            print(f"{GREEN}[+] SMB {share} - Success: {username}:{pwd_display}{RESET}")
                            break  # Found working creds, move to next share
            
            # Test NAS web interfaces with default creds
            for system in result['identified_systems']:
                system_name = system.get('system', '').lower()
                nas_type = None
                enhanced_type = None  # For enhanced credential testing
                
                # Determine NAS type and map to enhanced test type
                if 'synology' in system_name:
                    nas_type = 'synology'
                    enhanced_type = 'synology_backup'
                    creds = DEFAULT_CREDS['synology']
                elif 'qnap' in system_name:
                    nas_type = 'qnap'
                    enhanced_type = 'qnap_backup'
                    creds = DEFAULT_CREDS['qnap']
                elif 'veeam' in system_name:
                    nas_type = 'veeam'
                    enhanced_type = 'veeam'
                    creds = DEFAULT_CREDS.get('veeam', [])
                elif 'truenas' in system_name or 'freenas' in system_name:
                    nas_type = 'truenas'
                    creds = DEFAULT_CREDS['truenas']
                elif 'netgear' in system_name or 'readynas' in system_name:
                    nas_type = 'netgear'
                    creds = DEFAULT_CREDS['netgear']
                elif 'buffalo' in system_name or 'terastation' in system_name:
                    nas_type = 'buffalo'
                    creds = DEFAULT_CREDS['buffalo']
                else:
                    continue
                
                print(f"{YELLOW}[*] Testing {nas_type.upper()} default credentials...{RESET}")
                ports = system.get('ports', [])
                for port in ports:
                    for username, password in creds:
                        # Try enhanced credential test first for supported systems
                        if enhanced_type:
                            try:
                                success, evidence, error = enhanced_credential_test(
                                    ip, port, username, password, enhanced_type, timeout=args.timeout
                                )
                                if success:
                                    pwd_display = password if password else '[blank]'
                                    result['cred_results'].append({
                                        'type': 'nas_web',
                                        'nas_type': nas_type,
                                        'port': port,
                                        'username': username,
                                        'password': pwd_display,
                                        'details': f"Enhanced test: {evidence}"
                                    })
                                    print(f"{GREEN}[+] {nas_type.upper()} Web - Success: {username}:{pwd_display} ({evidence}){RESET}")
                                    break
                            except Exception:
                                # Fall back to standard test
                                pass
                        
                        # Standard credential test fallback
                        success, details = test_nas_web_login(ip, port, username, password, nas_type, timeout=args.timeout)
                        if success:
                            pwd_display = password if password else '[blank]'
                            result['cred_results'].append({
                                'type': 'nas_web',
                                'nas_type': nas_type,
                                'port': port,
                                'username': username,
                                'password': pwd_display,
                                'details': details
                            })
                            print(f"{GREEN}[+] {nas_type.upper()} Web - Success: {username}:{pwd_display}{RESET}")
                            break  # Found working creds
                    if result.get('cred_results') and result['cred_results'][-1].get('nas_type') == nas_type:
                        break  # Found working creds, don't test other ports
    
    except KeyboardInterrupt:
        raise
    except Exception as e:
        result['error'] = str(e)
    
    return result


def save_backuplist(results, filename='backuplist.txt'):
    """Save list of backup servers"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['identified_systems']:
                    f.write(f"{result['ip']}\n")
        print(f"{GREEN}[+] Backup server list saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving backup list: {e}{RESET}")


def save_details(results, filename='backup_details.txt'):
    """Save detailed scan results"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("BACKUPSEEK - Detailed Scan Results\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['identified_systems']:
                    f.write(f"\n{'=' * 80}\n")
                    f.write(f"Host: {result['ip']}\n")
                    f.write(f"{'=' * 80}\n\n")
                    
                    # Identified systems
                    f.write(f"Backup Systems Detected:\n")
                    for system in result['identified_systems']:
                        f.write(f"  • {system['system']} (Confidence: {system['confidence']})\n")
                        f.write(f"    Ports: {', '.join(map(str, system['ports']))}\n")
                    
                    f.write(f"\n")
                    
                    # Open ports
                    if result['open_ports']:
                        f.write(f"Open Ports ({len(result['open_ports'])}):\n")
                        for port in result['open_ports']:
                            service = BACKUP_PORTS.get(port, 'Unknown')
                            f.write(f"  • {port} - {service}\n")
                        f.write(f"\n")
                    
                    # Web interfaces
                    if result['web_interfaces']:
                        f.write(f"Web Interfaces:\n")
                        for web in result['web_interfaces']:
                            component = web.get('component', 'Unknown')
                            f.write(f"  • {web['url']} - {component}\n")
                        f.write(f"\n")
                    
                    # Backup shares
                    if result['backup_shares']:
                        f.write(f"Backup Shares:\n")
                        for share in result['backup_shares']:
                            f.write(f"  • \\\\{result['ip']}\\{share}\n")
                        f.write(f"\n")
                    
                    # Credential test results
                    if result.get('cred_results'):
                        f.write(f"{'-' * 80}\n")
                        f.write(f"DEFAULT CREDENTIAL TEST RESULTS:\n")
                        f.write(f"{'-' * 80}\n\n")
                        
                        for cred in result['cred_results']:
                            if cred['type'] == 'smb':
                                f.write(f"✓ SMB SHARE ACCESS:\n")
                                f.write(f"  Share: \\\\{result['ip']}\\{cred['share']}\n")
                                f.write(f"  Username: {cred['username']}\n")
                                f.write(f"  Password: {cred['password']}\n")
                                if cred['files']:
                                    f.write(f"  Sample files/folders:\n")
                                    for file in cred['files']:
                                        f.write(f"    - {file}\n")
                                f.write(f"\n")
                            
                            elif cred['type'] == 'nas_web':
                                f.write(f"✓ NAS WEB LOGIN:\n")
                                f.write(f"  System: {cred['nas_type'].upper()}\n")
                                f.write(f"  URL: http://{result['ip']}:{cred['port']}\n")
                                f.write(f"  Username: {cred['username']}\n")
                                f.write(f"  Password: {cred['password']}\n")
                                f.write(f"  Details: {cred['details']}\n")
                                f.write(f"\n")
                        
                        f.write(f"NOTE: Use these credentials to explore the system further!\n")
                        f.write(f"      For SMB: smbclient //{result['ip']}/share -U username\n")
                        f.write(f"      For NAS Web: Navigate to URL in browser\n")
                        f.write(f"\n")
                    
                    # Exploitation notes
                    f.write(f"Exploitation Notes:\n")
                    for system in result['identified_systems']:
                        if 'Veeam' in system['system']:
                            f.write(f"  Veeam:\n")
                            f.write(f"    - Default creds: administrator/password or admin/admin\n")
                            f.write(f"    - Check Veeam database for credentials\n")
                            f.write(f"    - Backup files may contain domain credentials\n")
                        elif 'Acronis' in system['system']:
                            f.write(f"  Acronis:\n")
                            f.write(f"    - Default admin credentials may exist\n")
                            f.write(f"    - Check backup archive locations\n")
                        elif 'Bacula' in system['system']:
                            f.write(f"  Bacula:\n")
                            f.write(f"    - Check /etc/bacula/ for configuration\n")
                            f.write(f"    - Director password in bacula-dir.conf\n")
                    
                    f.write(f"\n")
        
        print(f"{GREEN}[+] Detailed results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving details: {e}{RESET}")


def save_json(results, filename='backup_details.json'):
    """Save results as JSON"""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"{GREEN}[+] JSON results saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving JSON: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(
        description='BackupSeek - Backup System Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./backupseek.py iplist.txt                 # Scan common backup ports
  ./backupseek.py iplist.txt --full          # Full scan (all backup systems)
  ./backupseek.py iplist.txt --veeam         # Veeam only
  ./backupseek.py iplist.txt --acronis       # Acronis only
  ./backupseek.py iplist.txt -w 20           # Fast scan (20 workers)
  
Backup Systems Detected:
  - Veeam Backup & Replication
  - Acronis Cyber Backup
  - Bacula
  - Dell EMC Networker
  - IBM Spectrum Protect (TSM)
  - CommVault
  - Veritas NetBackup
        """
    )
    
    parser.add_argument('input_file', help='File containing IP addresses')
    parser.add_argument('--full', action='store_true', help='Full scan (all backup systems)')
    parser.add_argument('--test-creds', action='store_true', help='Test default credentials on found systems')
    parser.add_argument('--veeam', dest='veeam_only', action='store_true', help='Scan for Veeam only')
    parser.add_argument('--acronis', dest='acronis_only', action='store_true', help='Scan for Acronis only')
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of concurrent workers (default: 10)')
    parser.add_argument('-t', '--timeout', type=int, default=3, help='Connection timeout (default: 3)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--backup-only', action='store_true', help='Only scan confirmed backup/NAS devices (skip printers, switches)')
    parser.add_argument('--skip-classification', action='store_true', help='Skip device classification (legacy mode)')
    parser.add_argument('--classify-only', action='store_true', help='Only classify devices, do not test credentials')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read IPs
    ips = read_ip_list(args.input_file)
    
    if not ips:
        print(f"{RED}[!] No IPs to scan{RESET}")
        sys.exit(1)
    
    print(f"{CYAN}[*] Starting backup system scan...{RESET}")
    print(f"{CYAN}[*] Targets: {len(ips)}{RESET}")
    print(f"{CYAN}[*] Workers: {args.workers}{RESET}")
    mode = 'Veeam' if args.veeam_only else 'Acronis' if args.acronis_only else 'Full' if args.full else 'Common'
    print(f"{CYAN}[*] Mode: {mode}{RESET}")
    
    # Display filtering options
    if args.backup_only:
        print(f"{CYAN}[*] Filter: Backup devices only (excluding printers/switches){RESET}")
    if args.classify_only:
        print(f"{CYAN}[*] Classification mode: Device identification only{RESET}")
    if args.skip_classification:
        print(f"{CYAN}[*] Classification: Disabled (legacy mode){RESET}")
    
    print()
    
    results = []
    completed = 0
    backup_found = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {executor.submit(scan_host, ip, args): ip for ip in ips}
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    if result['identified_systems']:
                        backup_found += 1
                        systems = ', '.join([s['system'] for s in result['identified_systems']])
                        
                        severity = f"{RED}[BACKUP]{RESET}"
                        msg = f"{severity} {ip} - {systems}"
                        
                        if result['web_interfaces']:
                            msg += f" {GREEN}[WEB]{RESET}"
                        
                        if result['backup_shares']:
                            msg += f" {YELLOW}[SHARES]{RESET}"
                        
                        print(msg)
                    
                    elif args.verbose:
                        print(f"{BLUE}[*]{RESET} {ip} - No backup systems detected")
                    
                    # Progress indicator
                    if completed % 10 == 0 or completed == len(ips):
                        print(f"\n{CYAN}[*] Progress: {completed}/{len(ips)} ({backup_found} backup systems){RESET}\n")
                
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
    
    backup_servers = len([r for r in results if r['identified_systems']])
    
    # Count by system type
    system_counts = {}
    for result in results:
        for system in result['identified_systems']:
            system_name = system['system']
            system_counts[system_name] = system_counts.get(system_name, 0) + 1
    
    print(f"Backup servers found: {backup_servers}/{len(ips)}")
    
    if system_counts:
        print(f"\nBreakdown by system:")
        for system, count in sorted(system_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {system}: {count}")
    
    # Save results
    if results:
        save_backuplist(results)
        save_details(results)
        save_json(results)
    
    print(f"\n{GREEN}[+] Scan complete!{RESET}")
    
    # Print exploitation tips
    if backup_servers > 0:
        print(f"\n{YELLOW}[*] Exploitation Tips:{RESET}")
        print(f"  • Backup systems often contain domain credentials")
        print(f"  • Check for default credentials on web interfaces")
        print(f"  • Veeam databases contain encrypted credentials")
        print(f"  • Backup files may have weak passwords or none at all")
        print(f"  • Look for backup shares with sensitive data")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
