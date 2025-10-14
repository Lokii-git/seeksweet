#!/usr/bin/env python3
"""
DbSeek v1.0 - Database Server Discovery Tool

Discovers database servers and tests for common misconfigurations:
- MySQL/MariaDB (3306)
- PostgreSQL (5432)
- Microsoft SQL Server (1433)
- MongoDB (27017)
- Redis (6379)
- Oracle (1521, 1522)
- Elasticsearch (9200, 9300)
- Cassandra (9042)

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

# Database ports and services
DB_PORTS = {
    3306: 'MySQL/MariaDB',
    5432: 'PostgreSQL',
    1433: 'MSSQL',
    27017: 'MongoDB',
    6379: 'Redis',
    1521: 'Oracle',
    1522: 'Oracle-Alt',
    9200: 'Elasticsearch-HTTP',
    9300: 'Elasticsearch-Transport',
    9042: 'Cassandra',
    5984: 'CouchDB',
    7000: 'Cassandra-Cluster',
    7001: 'Cassandra-SSL'
}

# Default credentials to test
DEFAULT_CREDS = {
    'MySQL': [
        ('root', ''),
        ('root', 'root'),
        ('root', 'password'),
        ('root', 'toor'),
        ('admin', 'admin'),
        ('mysql', 'mysql')
    ],
    'PostgreSQL': [
        ('postgres', ''),
        ('postgres', 'postgres'),
        ('postgres', 'password'),
        ('admin', 'admin')
    ],
    'MSSQL': [
        ('sa', ''),
        ('sa', 'sa'),
        ('sa', 'password'),
        ('sa', 'Password123'),
        ('admin', 'admin')
    ],
    'MongoDB': [
        ('admin', ''),
        ('root', ''),
        ('admin', 'admin'),
        ('root', 'root')
    ],
    'Redis': [
        ('', ''),  # No auth
        ('', 'redis'),
        ('', 'password')
    ],
    'Oracle': [
        ('sys', 'sys'),
        ('system', 'manager'),
        ('scott', 'tiger'),
        ('admin', 'admin')
    ]
}

def print_banner():
    """Print tool banner"""
    banner = f"""
{Colors.OKCYAN}╔═══════════════════════════════════════════════════════════╗
║                   DbSeek v1.0                             ║
║            Database Server Discovery Tool                 ║
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

def get_mysql_banner(ip: str, port: int = 3306, timeout: int = 5) -> Optional[str]:
    """Get MySQL banner"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Receive initial handshake packet
        data = sock.recv(1024)
        
        if len(data) > 5:
            # Parse version string (after protocol version byte)
            version = data[5:].split(b'\x00')[0].decode('utf-8', errors='ignore')
            sock.close()
            return version
        
        sock.close()
    except:
        pass
    
    return None

def test_mysql_access(ip: str, port: int = 3306, username: str = 'root', 
                     password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """Test MySQL access with credentials"""
    try:
        import pymysql
        
        conn = pymysql.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT VERSION()")
        version = cursor.fetchone()[0]
        
        conn.close()
        return True, version
        
    except ImportError:
        # Try with mysql command
        try:
            if password:
                cmd = f"mysql -h {ip} -P {port} -u {username} -p{password} -e 'SELECT VERSION();' 2>&1"
            else:
                cmd = f"mysql -h {ip} -P {port} -u {username} -e 'SELECT VERSION();' 2>&1"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0 and 'VERSION()' in result.stdout:
                return True, 'Connected'
            
        except:
            pass
        
        return False, 'Authentication failed'
    
    except Exception as e:
        return False, str(e)

def test_postgresql_access(ip: str, port: int = 5432, username: str = 'postgres', 
                          password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """Test PostgreSQL access with credentials"""
    try:
        import psycopg2
        
        conn = psycopg2.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT version()")
        version = cursor.fetchone()[0]
        
        conn.close()
        return True, version
        
    except ImportError:
        # Try with psql command
        try:
            if password:
                env = os.environ.copy()
                env['PGPASSWORD'] = password
                cmd = ['psql', '-h', ip, '-p', str(port), '-U', username, '-c', 'SELECT version();']
            else:
                cmd = ['psql', '-h', ip, '-p', str(port), '-U', username, '-w', '-c', 'SELECT version();']
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env if password else None
            )
            
            if result.returncode == 0 and 'PostgreSQL' in result.stdout:
                return True, 'Connected'
            
        except:
            pass
        
        return False, 'Authentication failed'
    
    except Exception as e:
        return False, str(e)

def test_mssql_access(ip: str, port: int = 1433, username: str = 'sa', 
                     password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """Test MSSQL access with credentials"""
    try:
        import pymssql
        
        conn = pymssql.connect(
            server=ip,
            port=port,
            user=username,
            password=password,
            timeout=timeout
        )
        
        cursor = conn.cursor()
        cursor.execute("SELECT @@VERSION")
        version = cursor.fetchone()[0]
        
        conn.close()
        return True, version
        
    except ImportError:
        # No pymssql, return unknown
        return False, 'pymssql not installed'
    
    except Exception as e:
        return False, str(e)

def test_mongodb_access(ip: str, port: int = 27017, username: str = '', 
                       password: str = '', timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """Test MongoDB access"""
    try:
        import pymongo
        
        if username and password:
            client = pymongo.MongoClient(
                ip,
                port,
                username=username,
                password=password,
                serverSelectionTimeoutMS=timeout * 1000
            )
        else:
            client = pymongo.MongoClient(
                ip,
                port,
                serverSelectionTimeoutMS=timeout * 1000
            )
        
        # Try to get server info
        info = client.server_info()
        version = info.get('version', 'Unknown')
        
        client.close()
        return True, version
        
    except ImportError:
        # Try with mongo command
        try:
            if username and password:
                cmd = f"mongo --host {ip} --port {port} -u {username} -p {password} --eval 'db.version()' --quiet 2>&1"
            else:
                cmd = f"mongo --host {ip} --port {port} --eval 'db.version()' --quiet 2>&1"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode == 0:
                version = result.stdout.strip()
                return True, version if version else 'Connected'
            
        except:
            pass
        
        return False, 'Authentication failed'
    
    except Exception as e:
        return False, str(e)

def test_redis_access(ip: str, port: int = 6379, password: str = '', 
                     timeout: int = 10) -> Tuple[bool, Optional[str]]:
    """Test Redis access"""
    try:
        import redis
        
        if password:
            r = redis.Redis(host=ip, port=port, password=password, 
                          socket_connect_timeout=timeout, decode_responses=True)
        else:
            r = redis.Redis(host=ip, port=port, socket_connect_timeout=timeout, 
                          decode_responses=True)
        
        info = r.info()
        version = info.get('redis_version', 'Unknown')
        
        return True, version
        
    except ImportError:
        # Try with redis-cli
        try:
            if password:
                cmd = f"redis-cli -h {ip} -p {port} -a {password} INFO server 2>&1 | grep redis_version"
            else:
                cmd = f"redis-cli -h {ip} -p {port} INFO server 2>&1 | grep redis_version"
            
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if 'redis_version' in result.stdout:
                version = result.stdout.split(':')[1].strip()
                return True, version
            
        except:
            pass
        
        return False, 'Authentication failed'
    
    except Exception as e:
        if 'NOAUTH' in str(e) or 'Authentication required' in str(e):
            return False, 'Authentication required'
        return False, str(e)

def check_elasticsearch(ip: str, port: int = 9200, timeout: int = 10) -> Dict:
    """Check Elasticsearch HTTP API"""
    result = {
        'accessible': False,
        'version': None,
        'cluster_name': None,
        'no_auth': False,
        'error': None
    }
    
    try:
        import http.client
        
        conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request('GET', '/')
        response = conn.getresponse()
        
        if response.status == 200:
            data = json.loads(response.read().decode())
            result['accessible'] = True
            result['no_auth'] = True
            result['version'] = data.get('version', {}).get('number')
            result['cluster_name'] = data.get('cluster_name')
        
        conn.close()
        
    except Exception as e:
        result['error'] = str(e)
    
    return result

def enumerate_mysql_databases(ip: str, port: int, username: str, password: str, timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in MySQL (READ-ONLY operation)
    Returns list of database names
    """
    databases = []
    try:
        import pymysql
        
        conn = pymysql.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        # SAFE: SHOW DATABASES is read-only
        cursor.execute("SHOW DATABASES")
        databases = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
    except ImportError:
        # Try with mysql command
        try:
            if password:
                cmd = f"mysql -h {ip} -P {port} -u {username} -p{password} -e 'SHOW DATABASES;' 2>&1"
            else:
                cmd = f"mysql -h {ip} -P {port} -u {username} -e 'SHOW DATABASES;' 2>&1"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
            
            if result.returncode == 0:
                # Parse output
                lines = result.stdout.split('\n')
                for line in lines[1:]:  # Skip header
                    line = line.strip()
                    if line and line != 'Database':
                        databases.append(line)
        except:
            pass
    except:
        pass
    
    return databases

def enumerate_postgresql_databases(ip: str, port: int, username: str, password: str, timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in PostgreSQL (READ-ONLY operation)
    Returns list of database names
    """
    databases = []
    try:
        import psycopg2
        
        conn = psycopg2.connect(
            host=ip,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout
        )
        
        cursor = conn.cursor()
        # SAFE: Query system catalog (read-only)
        cursor.execute("SELECT datname FROM pg_database WHERE datistemplate = false")
        databases = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
    except ImportError:
        # Try with psql command
        try:
            env = os.environ.copy()
            if password:
                env['PGPASSWORD'] = password
            
            cmd = ['psql', '-h', ip, '-p', str(port), '-U', username, '-l', '-t']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
            
            if result.returncode == 0:
                # Parse output
                lines = result.stdout.split('\n')
                for line in lines:
                    parts = line.split('|')
                    if parts and parts[0].strip():
                        db_name = parts[0].strip()
                        if db_name not in ['template0', 'template1']:
                            databases.append(db_name)
        except:
            pass
    except:
        pass
    
    return databases

def enumerate_mssql_databases(ip: str, port: int, username: str, password: str, timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in MSSQL (READ-ONLY operation)
    Returns list of database names
    """
    databases = []
    try:
        import pymssql
        
        conn = pymssql.connect(
            server=ip,
            port=port,
            user=username,
            password=password,
            timeout=timeout
        )
        
        cursor = conn.cursor()
        # SAFE: Query system view (read-only)
        cursor.execute("SELECT name FROM sys.databases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb')")
        databases = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        
    except:
        pass
    
    return databases

def enumerate_mongodb_databases(ip: str, port: int, username: str, password: str, timeout: int = 10) -> List[str]:
    """
    SAFE: List databases in MongoDB (READ-ONLY operation)
    Returns list of database names
    """
    databases = []
    try:
        import pymongo
        
        if username and password:
            client = pymongo.MongoClient(
                ip, 
                port, 
                username=username, 
                password=password,
                serverSelectionTimeoutMS=timeout * 1000
            )
        else:
            client = pymongo.MongoClient(ip, port, serverSelectionTimeoutMS=timeout * 1000)
        
        # SAFE: List databases (read-only)
        databases = client.list_database_names()
        
        client.close()
        
    except:
        pass
    
    return databases

def scan_host(ip: str, timeout: int = 2, test_creds: bool = False, 
              custom_username: Optional[str] = None, custom_password: Optional[str] = None,
              enumerate_dbs: bool = False) -> Dict:
    """
    Scan a single host for database services
    
    Args:
        ip: IP address to scan
        timeout: Connection timeout
        test_creds: Whether to test default credentials
        custom_username: Custom username to test (e.g., from Responder)
        custom_password: Custom password to test (e.g., from Responder)
        enumerate_dbs: Whether to enumerate databases (SAFE: read-only)
        
    Returns:
        Dict with scan results
    """
    result = {
        'ip': ip,
        'hostname': None,
        'databases_found': False,
        'services': {},
        'vulnerable': [],
        'default_creds': [],
        'error': None
    }
    
    # Get hostname
    hostname = get_hostname(ip)
    if hostname:
        result['hostname'] = hostname
    
    # Check all database ports
    open_ports = []
    for port, service in DB_PORTS.items():
        if check_port(ip, port, timeout):
            open_ports.append({'port': port, 'service': service})
    
    if not open_ports:
        result['error'] = 'No database ports open'
        return result
    
    result['databases_found'] = True
    
    # Check each database service
    for port_info in open_ports:
        port = port_info['port']
        service = port_info['service']
        
        service_info = {
            'port': port,
            'accessible': False,
            'version': None,
            'auth_required': True,
            'default_creds_work': False,
            'working_creds': None
        }
        
        # MySQL/MariaDB
        if port == 3306:
            banner = get_mysql_banner(ip, port, timeout)
            if banner:
                service_info['version'] = banner
                service_info['accessible'] = True
            
            if test_creds or (custom_username and custom_password):
                # Try custom credentials first if provided
                if custom_username and custom_password:
                    success, info = test_mysql_access(ip, port, custom_username, custom_password, timeout)
                    if success:
                        service_info['default_creds_work'] = True
                        service_info['working_creds'] = {'username': custom_username, 'password': custom_password}
                        service_info['auth_required'] = True
                        result['default_creds'].append({
                            'service': 'MySQL',
                            'username': custom_username,
                            'password': custom_password,
                            'source': 'custom'
                        })
                        result['vulnerable'].append(f"MySQL custom credentials work: {custom_username}/{custom_password}")
                        
                        # SAFE: Enumerate databases if requested (read-only)
                        if enumerate_dbs:
                            databases = enumerate_mysql_databases(ip, port, custom_username, custom_password, timeout)
                            if databases:
                                service_info['databases'] = databases
                
                # Try default credentials if custom didn't work or wasn't provided
                if test_creds and not service_info['default_creds_work']:
                    for username, password in DEFAULT_CREDS.get('MySQL', []):
                        success, info = test_mysql_access(ip, port, username, password, timeout)
                        if success:
                            service_info['default_creds_work'] = True
                            service_info['working_creds'] = {'username': username, 'password': password}
                            service_info['auth_required'] = False if not password else True
                            result['default_creds'].append({
                                'service': 'MySQL',
                                'username': username,
                                'password': password
                            })
                            if not password or password in ['root', 'password']:
                                result['vulnerable'].append(f"MySQL weak credentials: {username}/{password or '(blank)'}")
                            
                            # SAFE: Enumerate databases if requested (read-only)
                            if enumerate_dbs:
                                databases = enumerate_mysql_databases(ip, port, username, password, timeout)
                                if databases:
                                    service_info['databases'] = databases
                            break
        
        # PostgreSQL
        elif port == 5432:
            service_info['accessible'] = True
            
            if test_creds or (custom_username and custom_password):
                # Try custom credentials first if provided
                if custom_username and custom_password:
                    success, info = test_postgresql_access(ip, port, custom_username, custom_password, timeout)
                    if success:
                        service_info['default_creds_work'] = True
                        service_info['working_creds'] = {'username': custom_username, 'password': custom_password}
                        service_info['auth_required'] = True
                        service_info['version'] = info if info else None
                        result['default_creds'].append({
                            'service': 'PostgreSQL',
                            'username': custom_username,
                            'password': custom_password,
                            'source': 'custom'
                        })
                        result['vulnerable'].append(f"PostgreSQL custom credentials work: {custom_username}/{custom_password}")
                        
                        # SAFE: Enumerate databases if requested (read-only)
                        if enumerate_dbs:
                            databases = enumerate_postgresql_databases(ip, port, custom_username, custom_password, timeout)
                            if databases:
                                service_info['databases'] = databases
                
                # Try default credentials if custom didn't work or wasn't provided
                if test_creds and not service_info['default_creds_work']:
                    for username, password in DEFAULT_CREDS.get('PostgreSQL', []):
                        success, info = test_postgresql_access(ip, port, username, password, timeout)
                        if success:
                            service_info['default_creds_work'] = True
                            service_info['working_creds'] = {'username': username, 'password': password}
                            service_info['auth_required'] = False if not password else True
                            service_info['version'] = info if info else None
                            result['default_creds'].append({
                                'service': 'PostgreSQL',
                                'username': username,
                                'password': password
                            })
                            if not password:
                                result['vulnerable'].append(f"PostgreSQL weak credentials: {username}/(blank)")
                            
                            # SAFE: Enumerate databases if requested (read-only)
                            if enumerate_dbs:
                                databases = enumerate_postgresql_databases(ip, port, username, password, timeout)
                                if databases:
                                    service_info['databases'] = databases
                            break
        
        # MSSQL
        elif port == 1433:
            service_info['accessible'] = True
            
            if test_creds or (custom_username and custom_password):
                # Try custom credentials first if provided
                if custom_username and custom_password:
                    success, info = test_mssql_access(ip, port, custom_username, custom_password, timeout)
                    if success:
                        service_info['default_creds_work'] = True
                        service_info['working_creds'] = {'username': custom_username, 'password': custom_password}
                        service_info['version'] = info if info else None
                        result['default_creds'].append({
                            'service': 'MSSQL',
                            'username': custom_username,
                            'password': custom_password,
                            'source': 'custom'
                        })
                        result['vulnerable'].append(f"MSSQL custom credentials work: {custom_username}/{custom_password}")
                        
                        # SAFE: Enumerate databases if requested (read-only)
                        if enumerate_dbs:
                            databases = enumerate_mssql_databases(ip, port, custom_username, custom_password, timeout)
                            if databases:
                                service_info['databases'] = databases
                
                # Try default credentials if custom didn't work or wasn't provided
                if test_creds and not service_info['default_creds_work']:
                    for username, password in DEFAULT_CREDS.get('MSSQL', []):
                        success, info = test_mssql_access(ip, port, username, password, timeout)
                        if success:
                            service_info['default_creds_work'] = True
                            service_info['working_creds'] = {'username': username, 'password': password}
                            service_info['version'] = info if info else None
                            result['default_creds'].append({
                                'service': 'MSSQL',
                                'username': username,
                                'password': password
                            })
                            if not password or password in ['sa', 'password']:
                                result['vulnerable'].append(f"MSSQL weak credentials: {username}/{password or '(blank)'}")
                            
                            # SAFE: Enumerate databases if requested (read-only)
                            if enumerate_dbs:
                                databases = enumerate_mssql_databases(ip, port, username, password, timeout)
                                if databases:
                                    service_info['databases'] = databases
                            break
        
        # MongoDB
        elif port == 27017:
            service_info['accessible'] = True
            
            # Test no auth first
            success, info = test_mongodb_access(ip, port, '', '', timeout)
            if success:
                service_info['default_creds_work'] = True
                service_info['auth_required'] = False
                service_info['version'] = info if info else None
                result['vulnerable'].append("MongoDB no authentication required")
                
                # SAFE: Enumerate databases if requested (read-only)
                if enumerate_dbs:
                    databases = enumerate_mongodb_databases(ip, port, '', '', timeout)
                    if databases:
                        service_info['databases'] = databases
            elif test_creds or (custom_username and custom_password):
                # Try custom credentials first if provided
                if custom_username and custom_password:
                    success, info = test_mongodb_access(ip, port, custom_username, custom_password, timeout)
                    if success:
                        service_info['default_creds_work'] = True
                        service_info['working_creds'] = {'username': custom_username, 'password': custom_password}
                        service_info['version'] = info if info else None
                        result['default_creds'].append({
                            'service': 'MongoDB',
                            'username': custom_username,
                            'password': custom_password,
                            'source': 'custom'
                        })
                        result['vulnerable'].append(f"MongoDB custom credentials work: {custom_username}/{custom_password}")
                        
                        # SAFE: Enumerate databases if requested (read-only)
                        if enumerate_dbs:
                            databases = enumerate_mongodb_databases(ip, port, custom_username, custom_password, timeout)
                            if databases:
                                service_info['databases'] = databases
                
                # Try default credentials if custom didn't work or wasn't provided
                if test_creds and not service_info['default_creds_work']:
                    for username, password in DEFAULT_CREDS.get('MongoDB', []):
                        success, info = test_mongodb_access(ip, port, username, password, timeout)
                        if success:
                            service_info['default_creds_work'] = True
                            service_info['working_creds'] = {'username': username, 'password': password}
                            service_info['version'] = info if info else None
                            result['default_creds'].append({
                                'service': 'MongoDB',
                                'username': username,
                                'password': password
                            })
                            
                            # SAFE: Enumerate databases if requested (read-only)
                            if enumerate_dbs:
                                databases = enumerate_mongodb_databases(ip, port, username, password, timeout)
                                if databases:
                                    service_info['databases'] = databases
                            break
        
        # Redis
        elif port == 6379:
            service_info['accessible'] = True
            
            # Test no auth first
            success, info = test_redis_access(ip, port, '', timeout)
            if success:
                service_info['default_creds_work'] = True
                service_info['auth_required'] = False
                service_info['version'] = info if info else None
                result['vulnerable'].append("Redis no authentication required")
            elif (test_creds or custom_password) and 'Authentication required' in str(info):
                # Try custom password first if provided (Redis uses password-only auth)
                if custom_password:
                    success, info = test_redis_access(ip, port, custom_password, timeout)
                    if success:
                        service_info['default_creds_work'] = True
                        service_info['working_creds'] = {'password': custom_password}
                        service_info['version'] = info if info else None
                        result['default_creds'].append({
                            'service': 'Redis',
                            'password': custom_password,
                            'source': 'custom'
                        })
                        result['vulnerable'].append(f"Redis custom password works: {custom_password}")
                
                # Try default passwords if custom didn't work or wasn't provided
                if test_creds and not service_info['default_creds_work']:
                    for _, password in DEFAULT_CREDS.get('Redis', []):
                        if not password:
                            continue
                        success, info = test_redis_access(ip, port, password, timeout)
                        if success:
                            service_info['default_creds_work'] = True
                            service_info['working_creds'] = {'password': password}
                            service_info['version'] = info if info else None
                            result['default_creds'].append({
                                'service': 'Redis',
                                'password': password
                            })
                            break
        
        # Elasticsearch
        elif port == 9200:
            es_info = check_elasticsearch(ip, port, timeout)
            service_info['accessible'] = es_info['accessible']
            service_info['version'] = es_info['version']
            
            if es_info['no_auth']:
                service_info['auth_required'] = False
                service_info['default_creds_work'] = True
                result['vulnerable'].append("Elasticsearch no authentication required")
        
        # Oracle (just mark as accessible if port is open)
        elif port in [1521, 1522]:
            service_info['accessible'] = True
        
        # Add service info
        if service_info['accessible']:
            result['services'][service] = service_info
    
    return result

def save_db_list(results: List[Dict], filename: str = 'dblist.txt'):
    """Save list of database server IPs to a file"""
    try:
        with open(filename, 'w') as f:
            for result in results:
                if result['databases_found']:
                    f.write(f"{result['ip']}\n")
        
        print(f"\n{Colors.OKGREEN}[+] Database server list saved to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"\n{Colors.FAIL}[!] Error saving database list: {e}{Colors.ENDC}")

def save_creds_list(results: List[Dict], filename: str = 'db_creds.txt'):
    """Save working credentials to a file"""
    try:
        with open(filename, 'w') as f:
            f.write("# Database Credentials Found\n")
            f.write("# Format: IP | Service | Username | Password\n\n")
            
            for result in results:
                if result['default_creds']:
                    for cred in result['default_creds']:
                        username = cred.get('username', '')
                        password = cred.get('password', '')
                        f.write(f"{result['ip']} | {cred['service']} | {username} | {password}\n")
        
        print(f"{Colors.OKGREEN}[+] Credentials saved to: {filename}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.FAIL}[!] Error saving credentials: {e}{Colors.ENDC}")

def save_details(results: List[Dict], txt_filename: str = 'db_details.txt', 
                json_filename: str = 'db_details.json'):
    """Save detailed scan results"""
    # Save TXT format
    try:
        with open(txt_filename, 'w') as f:
            f.write("DbSeek - Database Server Discovery Results\n")
            f.write("=" * 70 + "\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            
            db_hosts = [r for r in results if r['databases_found']]
            vuln_count = sum(1 for r in results if r['vulnerable'])
            creds_count = sum(1 for r in results if r['default_creds'])
            
            f.write(f"Total Database Servers: {len(db_hosts)}\n")
            f.write(f"Servers with Vulnerabilities: {vuln_count}\n")
            f.write(f"Servers with Default Credentials: {creds_count}\n")
            f.write("=" * 70 + "\n\n")
            
            for result in db_hosts:
                f.write(f"Host: {result['ip']}\n")
                if result['hostname']:
                    f.write(f"Hostname: {result['hostname']}\n")
                
                f.write(f"Services Found: {len(result['services'])}\n")
                f.write("-" * 70 + "\n")
                
                for service_name, service_info in result['services'].items():
                    f.write(f"\n  Service: {service_name} (Port {service_info['port']})\n")
                    
                    if service_info.get('version'):
                        f.write(f"  Version: {service_info['version']}\n")
                    
                    if not service_info.get('auth_required'):
                        f.write(f"  ⚠ NO AUTHENTICATION REQUIRED\n")
                    
                    if service_info.get('default_creds_work'):
                        creds = service_info.get('working_creds', {})
                        username = creds.get('username', '')
                        password = creds.get('password', '(blank)')
                        f.write(f"  ⚠ DEFAULT CREDENTIALS WORK: {username}:{password}\n")
                
                if result['vulnerable']:
                    f.write(f"\nVulnerabilities:\n")
                    for vuln in result['vulnerable']:
                        f.write(f"  ⚠ {vuln}\n")
                
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
        description='DbSeek v1.0 - Database Server Discovery',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                        # Basic scan
  %(prog)s -t                                     # Test default credentials
  %(prog)s -u admin -p Password123                # Test custom credentials (e.g., from Responder)
  %(prog)s -t -u admin -p Password123 -e          # Test creds + enumerate databases (SAFE)
  %(prog)s -e -u admin -p Password123             # Enumerate databases with custom creds
  %(prog)s -f targets.txt -t -v                   # Full scan with cred testing
  %(prog)s -w 20                                  # 20 concurrent workers
        """
    )
    
    parser.add_argument('-f', '--file', 
                       default='iplist.txt',
                       help='Input file with IP addresses (default: iplist.txt)')
    
    parser.add_argument('-w', '--workers', 
                       type=int, 
                       default=10,
                       help='Number of concurrent workers (default: 10)')
    
    parser.add_argument('-t', '--test-creds',
                       action='store_true',
                       help='Test default credentials (slower)')
    
    parser.add_argument('-u', '--username',
                       help='Username to test (e.g., from Responder)')
    
    parser.add_argument('-p', '--password',
                       help='Password to test (e.g., from Responder)')
    
    parser.add_argument('-e', '--enumerate',
                       action='store_true',
                       help='Enumerate databases on successful authentication (SAFE: read-only)')
    
    parser.add_argument('--timeout',
                       type=int,
                       default=2,
                       help='Connection timeout in seconds (default: 2)')
    
    parser.add_argument('-v', '--verbose',
                       action='store_true',
                       help='Verbose output (show all hosts)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Read IP list
    ips = read_ip_list(args.file)
    if not ips:
        print(f"{Colors.FAIL}[!] No valid IPs to scan{Colors.ENDC}")
        return 1
    
    print(f"\n{Colors.OKBLUE}[*] Starting database discovery...{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Targets: {len(ips)}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Workers: {args.workers}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}[*] Test Credentials: {'Yes' if args.test_creds else 'No'}{Colors.ENDC}")
    if args.username and args.password:
        print(f"{Colors.WARNING}[*] Custom Credentials: {args.username}:{args.password}{Colors.ENDC}")
    elif args.username or args.password:
        print(f"{Colors.WARNING}[!] Warning: Both username and password required for custom testing{Colors.ENDC}")
    if args.enumerate:
        print(f"{Colors.OKCYAN}[*] Enumerate Databases: Yes (SAFE: read-only queries){Colors.ENDC}")
    print()
    
    # Scan hosts
    results = []
    completed = 0
    db_found = 0
    
    try:
        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_to_ip = {
                executor.submit(scan_host, ip, args.timeout, args.test_creds, 
                              args.username, args.password, args.enumerate): ip 
                for ip in ips
            }
            
            for future in as_completed(future_to_ip):
                ip = future_to_ip[future]
                completed += 1
                
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['databases_found']:
                        db_found += 1
                        
                        # Determine confidence
                        if result['vulnerable'] or result['default_creds']:
                            confidence = f"{Colors.FAIL}[CRITICAL]{Colors.ENDC}"
                        elif result['services']:
                            confidence = f"{Colors.WARNING}[HIGH]{Colors.ENDC}"
                        else:
                            confidence = f"{Colors.OKBLUE}[MEDIUM]{Colors.ENDC}"
                        
                        hostname_str = f" ({result['hostname']})" if result['hostname'] else ""
                        services_str = ', '.join(result['services'].keys())
                        
                        print(f"{confidence} {result['ip']}{hostname_str} - {services_str}")
                        
                        # Show vulnerabilities
                        if result['vulnerable']:
                            for vuln in result['vulnerable']:
                                print(f"    {Colors.FAIL}⚠ {vuln}{Colors.ENDC}")
                        
                        # Show working credentials
                        if result['default_creds']:
                            for cred in result['default_creds']:
                                username = cred.get('username', '')
                                password = cred.get('password', '(blank)')
                                print(f"    {Colors.WARNING}✓ {cred['service']}: {username}:{password}{Colors.ENDC}")
                        
                        # Show enumerated databases (if requested)
                        if args.enumerate:
                            for service_name, service_info in result['services'].items():
                                if service_info.get('databases'):
                                    db_list = ', '.join(service_info['databases'][:5])  # Show first 5
                                    total_dbs = len(service_info['databases'])
                                    if total_dbs > 5:
                                        db_list += f", ... ({total_dbs} total)"
                                    print(f"    {Colors.OKCYAN}📊 {service_name} Databases: {db_list}{Colors.ENDC}")
                    
                    elif args.verbose:
                        print(f"[ ] {ip} - No databases found")
                    
                    # Progress
                    if completed % 10 == 0 or completed == len(ips):
                        print(f"\n{Colors.OKCYAN}[*] Progress: {completed}/{len(ips)} ({db_found} with databases){Colors.ENDC}\n")
                
                except Exception as e:
                    print(f"{Colors.FAIL}[!] Error scanning {ip}: {e}{Colors.ENDC}")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}[!] Scan interrupted by user{Colors.ENDC}")
    
    # Summary
    print(f"\n{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"{Colors.HEADER}Scan Complete{Colors.ENDC}")
    print(f"{Colors.HEADER}{'=' * 70}{Colors.ENDC}")
    print(f"Total Hosts Scanned: {completed}")
    print(f"Database Servers Found: {db_found}")
    
    vuln_hosts = sum(1 for r in results if r['vulnerable'])
    creds_hosts = sum(1 for r in results if r['default_creds'])
    
    print(f"Servers with Vulnerabilities: {vuln_hosts}")
    print(f"Servers with Default Credentials: {creds_hosts}")
    
    # Count services
    service_counts = {}
    for result in results:
        for service in result['services'].keys():
            service_counts[service] = service_counts.get(service, 0) + 1
    
    if service_counts:
        print(f"\nDatabase Types Found:")
        for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {service}: {count} server(s)")
    
    # Save results
    if db_found > 0:
        print()
        save_db_list(results)
        if creds_hosts > 0:
            save_creds_list(results)
        save_details(results)
    
    return 0

if __name__ == '__main__':
    exit(main())
