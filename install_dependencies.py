#!/usr/bin/env python3
"""
SeekSweet Dependency Installer
Automated installation script for all SeekSweet dependencies

This script will:
1. Detect your operating system
2. Install required system tools
3. Install Python packages
4. Verify all installations
5. Provide troubleshooting guidance

Usage:
    python3 install_dependencies.py [options]

Options:
    --minimal       Install only critical dependencies
    --full          Install all dependencies (default)
    --check-only    Only check current installation status
    --help          Show this help message
"""

import os
import sys
import subprocess
import platform
import argparse
import json
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Color codes for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    ENDC = '\033[0m'

def print_banner():
    """Print installation banner"""
    banner = f"""
{Colors.CYAN}{'='*70}
{Colors.BOLD}              SeekSweet Dependency Installer{Colors.ENDC}
{Colors.CYAN}         Automated setup for all SeekSweet tools
           github.com/Lokii-git/seeksweet
{'='*70}{Colors.ENDC}
"""
    print(banner)

def detect_os() -> Dict[str, str]:
    """Detect operating system and package manager"""
    system = platform.system().lower()
    dist_info = {}
    
    if system == "linux":
        # Try to detect Linux distribution
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if '=' in line:
                        key, value = line.strip().split('=', 1)
                        dist_info[key] = value.strip('"')
        except FileNotFoundError:
            pass
        
        # Determine package manager
        if os.path.exists('/usr/bin/apt-get'):
            package_manager = 'apt'
        elif os.path.exists('/usr/bin/yum'):
            package_manager = 'yum'
        elif os.path.exists('/usr/bin/dnf'):
            package_manager = 'dnf'
        elif os.path.exists('/usr/bin/pacman'):
            package_manager = 'pacman'
        else:
            package_manager = 'unknown'
    
    elif system == "darwin":
        package_manager = 'brew'
    elif system == "windows":
        package_manager = 'choco'
    else:
        package_manager = 'unknown'
    
    return {
        'system': system,
        'package_manager': package_manager,
        'dist_name': dist_info.get('NAME', 'Unknown'),
        'dist_id': dist_info.get('ID', 'unknown')
    }

def run_command(cmd: List[str], check: bool = True, timeout: int = 300) -> Tuple[int, str, str]:
    """Run a system command and return result"""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", f"Command timed out after {timeout} seconds"
    except FileNotFoundError:
        return 1, "", f"Command not found: {cmd[0]}"
    except Exception as e:
        return 1, "", f"Error running command: {e}"

def check_tool_exists(tool: str) -> bool:
    """Check if a system tool exists"""
    code, _, _ = run_command(['which', tool], check=False, timeout=5)
    if code != 0:
        # Try 'where' command for Windows compatibility
        code, _, _ = run_command(['where', tool], check=False, timeout=5)
    return code == 0

def check_python_package(package: str) -> bool:
    """Check if a Python package is installed"""
    try:
        __import__(package)
        return True
    except ImportError:
        return False

def install_system_tools(os_info: Dict[str, str], tools: List[str], minimal: bool = False) -> Dict[str, bool]:
    """Install system tools based on OS"""
    results = {}
    pm = os_info['package_manager']
    
    if pm == 'apt':
        # Update package list first
        print(f"{Colors.BLUE}[*] Updating package list...{Colors.ENDC}")
        code, _, stderr = run_command(['sudo', 'apt-get', 'update'])
        if code != 0:
            print(f"{Colors.YELLOW}[!] Warning: Failed to update package list: {stderr}{Colors.ENDC}")
        
        # Install tools
        for tool in tools:
            print(f"{Colors.BLUE}[*] Installing {tool}...{Colors.ENDC}")
            
            # Map tools to package names
            package_map = {
                'enum4linux': 'enum4linux',
                'ldapsearch': 'ldap-utils',
                'smbclient': 'smbclient',
                'nmap': 'nmap',
                'snmpwalk': 'snmp',
                'snmpget': 'snmp',
                'snmp-mibs': 'snmp-mibs-downloader',
                'GetUserSPNs.py': 'impacket-scripts',
                'GetNPUsers.py': 'impacket-scripts',
                'crackmapexec': 'crackmapexec',
                'rpcclient': 'samba-common-bin',
                'nikto': 'nikto'
            }
            
            package = package_map.get(tool, tool)
            code, stdout, stderr = run_command(['sudo', 'apt-get', 'install', '-y', package])
            
            if code == 0:
                results[tool] = True
                print(f"{Colors.GREEN}[+] {tool} installed successfully{Colors.ENDC}")
            else:
                results[tool] = False
                print(f"{Colors.RED}[!] Failed to install {tool}: {stderr}{Colors.ENDC}")
    
    elif pm == 'yum' or pm == 'dnf':
        cmd_base = ['sudo', pm, 'install', '-y']
        package_map = {
            'ldapsearch': 'openldap-clients',
            'smbclient': 'samba-client',
            'nmap': 'nmap',
            'snmpwalk': 'net-snmp-utils'
        }
        
        for tool in tools:
            package = package_map.get(tool, tool)
            print(f"{Colors.BLUE}[*] Installing {package}...{Colors.ENDC}")
            code, _, stderr = run_command(cmd_base + [package])
            results[tool] = code == 0
            
            if code == 0:
                print(f"{Colors.GREEN}[+] {tool} installed successfully{Colors.ENDC}")
            else:
                print(f"{Colors.RED}[!] Failed to install {tool}: {stderr}{Colors.ENDC}")
    
    elif pm == 'brew':
        for tool in tools:
            package_map = {
                'ldapsearch': 'openldap',
                'smbclient': 'samba',
                'snmpwalk': 'net-snmp'
            }
            
            package = package_map.get(tool, tool)
            print(f"{Colors.BLUE}[*] Installing {package}...{Colors.ENDC}")
            code, _, stderr = run_command(['brew', 'install', package])
            results[tool] = code == 0
            
            if code == 0:
                print(f"{Colors.GREEN}[+] {tool} installed successfully{Colors.ENDC}")
            else:
                print(f"{Colors.RED}[!] Failed to install {tool}: {stderr}{Colors.ENDC}")
    
    else:
        print(f"{Colors.RED}[!] Unsupported package manager: {pm}{Colors.ENDC}")
        print(f"{Colors.YELLOW}[*] Please install tools manually:{Colors.ENDC}")
        for tool in tools:
            print(f"    - {tool}")
            results[tool] = False
    
    return results

def install_python_packages(packages: List[str]) -> Dict[str, bool]:
    """Install Python packages"""
    results = {}
    
    # Upgrade pip first
    print(f"{Colors.BLUE}[*] Upgrading pip...{Colors.ENDC}")
    code, _, stderr = run_command([sys.executable, '-m', 'pip', 'install', '--upgrade', 'pip'])
    
    if code != 0:
        print(f"{Colors.YELLOW}[!] Warning: Failed to upgrade pip: {stderr}{Colors.ENDC}")
    
    # Install packages
    for package in packages:
        print(f"{Colors.BLUE}[*] Installing Python package: {package}...{Colors.ENDC}")
        code, _, stderr = run_command([sys.executable, '-m', 'pip', 'install', package])
        
        if code == 0:
            results[package] = True
            print(f"{Colors.GREEN}[+] {package} installed successfully{Colors.ENDC}")
        else:
            results[package] = False
            print(f"{Colors.RED}[!] Failed to install {package}: {stderr}{Colors.ENDC}")
    
    return results

def install_netexec() -> bool:
    """Install NetExec (modern crackmapexec replacement)"""
    print(f"{Colors.BLUE}[*] Installing NetExec (modern crackmapexec replacement)...{Colors.ENDC}")
    
    # Try pipx first (recommended)
    if check_tool_exists('pipx'):
        code, _, stderr = run_command(['pipx', 'install', 'netexec'])
        if code == 0:
            print(f"{Colors.GREEN}[+] NetExec installed via pipx{Colors.ENDC}")
            return True
    
    # Fall back to pip
    code, _, stderr = run_command([sys.executable, '-m', 'pip', 'install', 'netexec'])
    if code == 0:
        print(f"{Colors.GREEN}[+] NetExec installed via pip{Colors.ENDC}")
        return True
    else:
        print(f"{Colors.RED}[!] Failed to install NetExec: {stderr}{Colors.ENDC}")
        return False

def verify_installation() -> Dict[str, Dict[str, bool]]:
    """Verify all installations"""
    print(f"\\n{Colors.CYAN}{'='*70}")
    print(f"{Colors.BOLD}INSTALLATION VERIFICATION{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    
    results = {
        'critical_tools': {},
        'optional_tools': {},
        'python_packages': {}
    }
    
    # Critical system tools
    critical_tools = [
        'enum4linux', 'ldapsearch', 'smbclient', 'nmap', 
        'snmpwalk', 'snmpget', 'GetUserSPNs.py', 'GetNPUsers.py'
    ]
    
    print(f"\\n{Colors.BOLD}Critical System Tools:{Colors.ENDC}")
    for tool in critical_tools:
        exists = check_tool_exists(tool)
        results['critical_tools'][tool] = exists
        
        if exists:
            print(f"  {Colors.GREEN}✓ {tool}{Colors.ENDC}")
        else:
            print(f"  {Colors.RED}✗ {tool} (MISSING - CRITICAL){Colors.ENDC}")
    
    # Optional system tools
    optional_tools = ['netexec', 'crackmapexec', 'rpcclient', 'nikto', 'nuclei']
    
    print(f"\\n{Colors.BOLD}Optional System Tools:{Colors.ENDC}")
    for tool in optional_tools:
        exists = check_tool_exists(tool)
        results['optional_tools'][tool] = exists
        
        if exists:
            print(f"  {Colors.GREEN}✓ {tool}{Colors.ENDC}")
        else:
            print(f"  {Colors.YELLOW}- {tool} (not found - optional){Colors.ENDC}")
    
    # Python packages
    critical_packages = ['requests', 'urllib3']
    optional_packages = ['PyMySQL', 'psycopg2', 'pymssql', 'pymongo', 'redis', 'pywinrm']
    
    print(f"\\n{Colors.BOLD}Python Packages:{Colors.ENDC}")
    print(f"{Colors.UNDERLINE}Required:{Colors.ENDC}")
    for package in critical_packages:
        exists = check_python_package(package)
        results['python_packages'][package] = exists
        
        if exists:
            print(f"  {Colors.GREEN}✓ {package}{Colors.ENDC}")
        else:
            print(f"  {Colors.RED}✗ {package} (MISSING - CRITICAL){Colors.ENDC}")
    
    print(f"{Colors.UNDERLINE}Optional:{Colors.ENDC}")
    for package in optional_packages:
        exists = check_python_package(package)
        results['python_packages'][package] = exists
        
        if exists:
            print(f"  {Colors.GREEN}✓ {package}{Colors.ENDC}")
        else:
            print(f"  {Colors.YELLOW}- {package} (not found - optional){Colors.ENDC}")
    
    return results

def generate_summary(results: Dict) -> None:
    """Generate installation summary"""
    print(f"\\n{Colors.CYAN}{'='*70}")
    print(f"{Colors.BOLD}INSTALLATION SUMMARY{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    
    # Count successes/failures
    critical_tools = results.get('critical_tools', {})
    optional_tools = results.get('optional_tools', {})
    python_packages = results.get('python_packages', {})
    
    critical_success = sum(1 for v in critical_tools.values() if v)
    critical_total = len(critical_tools)
    
    optional_success = sum(1 for v in optional_tools.values() if v)
    optional_total = len(optional_tools)
    
    python_success = sum(1 for v in python_packages.values() if v)
    python_total = len(python_packages)
    
    print(f"Critical Tools: {Colors.GREEN}{critical_success}/{critical_total}{Colors.ENDC}")
    print(f"Optional Tools: {Colors.YELLOW}{optional_success}/{optional_total}{Colors.ENDC}")
    print(f"Python Packages: {Colors.GREEN}{python_success}/{python_total}{Colors.ENDC}")
    
    # Check if all critical components are installed
    missing_critical = [k for k, v in critical_tools.items() if not v]
    missing_python = [k for k, v in python_packages.items() if not v and k in ['requests', 'urllib3']]
    
    if not missing_critical and not missing_python:
        print(f"\\n{Colors.GREEN}{Colors.BOLD}🎉 SUCCESS: All critical dependencies installed!{Colors.ENDC}")
        print(f"{Colors.GREEN}SeekSweet is ready to use.{Colors.ENDC}")
    else:
        print(f"\\n{Colors.RED}{Colors.BOLD}⚠️  INCOMPLETE: Missing critical dependencies{Colors.ENDC}")
        if missing_critical:
            print(f"{Colors.RED}Missing tools: {', '.join(missing_critical)}{Colors.ENDC}")
        if missing_python:
            print(f"{Colors.RED}Missing Python packages: {', '.join(missing_python)}{Colors.ENDC}")
        
        print(f"\\n{Colors.YELLOW}Please install missing dependencies manually or run with --full{Colors.ENDC}")

def provide_troubleshooting(results: Dict) -> None:
    """Provide troubleshooting guidance for failed installations"""
    missing_tools = []
    missing_packages = []
    
    # Find missing critical components
    for tool, installed in results.get('critical_tools', {}).items():
        if not installed:
            missing_tools.append(tool)
    
    for package, installed in results.get('python_packages', {}).items():
        if not installed and package in ['requests', 'urllib3']:
            missing_packages.append(package)
    
    if missing_tools or missing_packages:
        print(f"\\n{Colors.CYAN}{'='*70}")
        print(f"{Colors.BOLD}TROUBLESHOOTING GUIDE{Colors.ENDC}")
        print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
        
        if missing_tools:
            print(f"\\n{Colors.BOLD}Missing System Tools:{Colors.ENDC}")
            for tool in missing_tools:
                print(f"\\n{Colors.YELLOW}• {tool}:{Colors.ENDC}")
                
                if tool == 'enum4linux':
                    print("  sudo apt-get install enum4linux")
                    print("  # Or try: sudo apt-get install enum4linux-ng")
                
                elif tool == 'ldapsearch':
                    print("  sudo apt-get install ldap-utils")
                
                elif tool == 'smbclient':
                    print("  sudo apt-get install smbclient")
                
                elif tool == 'nmap':
                    print("  sudo apt-get install nmap")
                
                elif tool in ['snmpwalk', 'snmpget']:
                    print("  sudo apt-get install snmp snmp-mibs-downloader")
                    print("  sudo download-mibs")
                
                elif tool in ['GetUserSPNs.py', 'GetNPUsers.py']:
                    print("  sudo apt-get install impacket-scripts")
                    print("  # Verify with: find /usr -name 'GetUserSPNs.py' 2>/dev/null")
        
        if missing_packages:
            print(f"\\n{Colors.BOLD}Missing Python Packages:{Colors.ENDC}")
            print("  python3 -m pip install --upgrade pip")
            print(f"  python3 -m pip install {' '.join(missing_packages)}")
            
            if 'psycopg2' in missing_packages:
                print("\\n  # For psycopg2 issues:")
                print("  sudo apt-get install python3-dev libpq-dev")
                print("  python3 -m pip install psycopg2-binary")

def main():
    """Main installation function"""
    parser = argparse.ArgumentParser(
        description='SeekSweet Dependency Installer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 install_dependencies.py                # Full installation
  python3 install_dependencies.py --minimal      # Critical tools only
  python3 install_dependencies.py --check-only   # Check status only
        """
    )
    
    parser.add_argument('--minimal', action='store_true',
                       help='Install only critical dependencies')
    parser.add_argument('--full', action='store_true', default=True,
                       help='Install all dependencies (default)')
    parser.add_argument('--check-only', action='store_true',
                       help='Only check current installation status')
    
    try:
        args = parser.parse_args()
    except SystemExit:
        sys.exit(1)
    
    print_banner()
    
    # Detect OS
    os_info = detect_os()
    print(f"{Colors.BLUE}[*] Detected OS: {os_info['dist_name']} ({os_info['system']}){Colors.ENDC}")
    print(f"{Colors.BLUE}[*] Package Manager: {os_info['package_manager']}{Colors.ENDC}")
    
    if args.check_only:
        print(f"{Colors.BLUE}[*] Checking current installation status...{Colors.ENDC}")
        results = verify_installation()
        generate_summary(results)
        provide_troubleshooting(results)
        return
    
    # Confirm installation
    mode = "minimal" if args.minimal else "full"
    print(f"\\n{Colors.YELLOW}[?] Installing SeekSweet dependencies ({mode} mode){Colors.ENDC}")
    print(f"{Colors.YELLOW}[?] This will install system packages and may require sudo access.{Colors.ENDC}")
    
    try:
        confirm = input(f"{Colors.YELLOW}Continue? [Y/n]: {Colors.ENDC}").strip().lower()
        if confirm in ['n', 'no']:
            print(f"{Colors.YELLOW}[*] Installation cancelled{Colors.ENDC}")
            return
    except KeyboardInterrupt:
        print(f"\\n{Colors.YELLOW}[*] Installation cancelled{Colors.ENDC}")
        return
    
    # Install system tools
    print(f"\\n{Colors.CYAN}{'='*70}")
    print(f"{Colors.BOLD}INSTALLING SYSTEM TOOLS{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    
    critical_tools = [
        'enum4linux', 'ldapsearch', 'smbclient', 'nmap',
        'snmpwalk', 'snmp-mibs', 'GetUserSPNs.py'
    ]
    
    optional_tools = ['crackmapexec', 'rpcclient', 'nikto'] if not args.minimal else []
    
    all_tools = critical_tools + optional_tools
    
    install_results = install_system_tools(os_info, all_tools, args.minimal)
    
    # Install NetExec if not minimal
    if not args.minimal:
        print(f"\\n{Colors.BLUE}[*] Installing enhanced tools...{Colors.ENDC}")
        netexec_success = install_netexec()
        install_results['netexec'] = netexec_success
    
    # Install Python packages
    print(f"\\n{Colors.CYAN}{'='*70}")
    print(f"{Colors.BOLD}INSTALLING PYTHON PACKAGES{Colors.ENDC}")
    print(f"{Colors.CYAN}{'='*70}{Colors.ENDC}")
    
    critical_packages = ['requests>=2.31.0', 'urllib3>=2.0.0']
    optional_packages = [
        'PyMySQL>=1.1.0', 'psycopg2-binary>=2.9.9', 'pymssql>=2.2.11',
        'pymongo>=4.6.0', 'redis>=5.0.0', 'pywinrm>=0.4.3'
    ] if not args.minimal else []
    
    all_packages = critical_packages + optional_packages
    
    python_results = install_python_packages(all_packages)
    
    # Download SNMP MIBs if snmp was installed
    if install_results.get('snmp-mibs', False):
        print(f"\\n{Colors.BLUE}[*] Downloading SNMP MIBs...{Colors.ENDC}")
        code, _, stderr = run_command(['sudo', 'download-mibs'], timeout=60)
        if code == 0:
            print(f"{Colors.GREEN}[+] SNMP MIBs downloaded successfully{Colors.ENDC}")
        else:
            print(f"{Colors.YELLOW}[!] Warning: Failed to download MIBs: {stderr}{Colors.ENDC}")
    
    # Final verification
    results = verify_installation()
    generate_summary(results)
    provide_troubleshooting(results)
    
    # Save results to file
    results_file = Path('installation_results.json')
    try:
        with open(results_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\\n{Colors.BLUE}[*] Installation results saved to: {results_file}{Colors.ENDC}")
    except Exception as e:
        print(f"{Colors.YELLOW}[!] Warning: Could not save results: {e}{Colors.ENDC}")
    
    print(f"\\n{Colors.CYAN}Installation complete! Check the summary above for any issues.{Colors.ENDC}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\\n{Colors.YELLOW}[*] Installation interrupted by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\\n{Colors.RED}[!] Unexpected error: {e}{Colors.ENDC}")
        sys.exit(1)