#!/usr/bin/env python3
"""
BloodSeek v1.0 - BloodHound Collection Wrapper
Simplified BloodHound data collection with guided commands

Features:
- Wrapper for bloodhound-python (Linux) and SharpHound (Windows)
- Auto-generates collection commands
- Multiple collection methods (All, DCOnly, SessionLoop, etc.)
- Comprehensive usage guide generation
- Integration with Neo4j and BloodHound UI

Usage:
    ./bloodseek.py -d DOMAIN -u username -p password -dc DC-IP
    ./bloodseek.py -d DOMAIN -u username -p password -dc DC-IP --method All
    ./bloodseek.py -d DOMAIN -u username -p password -dc DC-IP --method DCOnly
    ./bloodseek.py --guide-only  # Generate guide without collecting
    
Output:
    bloodlist.txt           - Collection summary
    BLOODHOUND_GUIDE.txt    - Comprehensive BloodHound guide
    *.json                  - BloodHound data files (from bloodhound-python)
    *.zip                   - SharpHound collection archive (if using SharpHound)
"""

import socket
import subprocess
import sys
import json
import argparse
import os
from datetime import datetime
from pathlib import Path

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
██████╗ ██╗      ██████╗  ██████╗ ██████╗ ███████╗███████╗███████╗██╗  ██╗
██╔══██╗██║     ██╔═══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██║ ██╔╝
██████╔╝██║     ██║   ██║██║   ██║██║  ██║███████╗█████╗  █████╗  █████╔╝ 
██╔══██╗██║     ██║   ██║██║   ██║██║  ██║╚════██║██╔══╝  ██╔══╝  ██╔═██╗ 
██████╔╝███████╗╚██████╔╝╚██████╔╝██████╔╝███████║███████╗███████╗██║  ██╗
╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
{RESET}
{YELLOW}BloodSeek v1.0 - BloodHound Collection Wrapper{RESET}
{BLUE}Simplified BloodHound data collection with guided commands{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""

# BloodHound collection methods
COLLECTION_METHODS = {
    'All': 'Collects everything (default)',
    'DCOnly': 'Domain Controllers only (fast, limited data)',
    'Session': 'User sessions only',
    'SessionLoop': 'Continuous session collection (useful for timing attacks)',
    'LoggedOn': 'Logged on users',
    'Group': 'Group memberships',
    'ACL': 'ACLs and permissions',
    'Trusts': 'Domain trusts',
    'Default': 'Default collection (groups, sessions, trusts)',
    'Container': 'Container properties',
    'DcOnly': 'Same as DCOnly (alternate spelling)'
}


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def check_bloodhound_python():
    """Check if bloodhound-python is installed"""
    try:
        result = subprocess.run(['bloodhound-python', '--help'], 
                               capture_output=True, text=True, timeout=5)
        return result.returncode == 0
    except FileNotFoundError:
        return False
    except Exception:
        return False


def generate_bloodhound_command(domain, username, password, dc_ip, method='All', ns=None):
    """Generate bloodhound-python collection command"""
    cmd_parts = [
        'bloodhound-python',
        '-d', domain,
        '-u', username,
        '-p', password,
        '-dc', dc_ip,
        '-c', method
    ]
    
    if ns:
        cmd_parts.extend(['-ns', ns])
    
    return ' '.join(cmd_parts)


def run_bloodhound_collection(domain, username, password, dc_ip, method='All', ns=None):
    """Run bloodhound-python collection"""
    cmd = [
        'bloodhound-python',
        '-d', domain,
        '-u', username,
        '-p', password,
        '-dc', dc_ip,
        '-c', method
    ]
    
    if ns:
        cmd.extend(['-ns', ns])
    
    print(f"{CYAN}[*] Running BloodHound collection...{RESET}")
    print(f"{YELLOW}Command:{RESET} {' '.join(cmd)}")
    print()
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            print(f"{GREEN}[+] Collection successful!{RESET}")
            print(result.stdout)
            return True, result.stdout
        else:
            print(f"{RED}[!] Collection failed{RESET}")
            print(result.stderr)
            return False, result.stderr
    
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] Collection timed out (5 minutes){RESET}")
        return False, "Timeout"
    except Exception as e:
        print(f"{RED}[!] Error running collection: {e}{RESET}")
        return False, str(e)


def save_bloodlist(domain, method, success, filename='bloodlist.txt'):
    """Save collection summary"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("BLOODSEEK - BloodHound Collection Summary\n")
            f.write(f"Collection Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"Domain: {domain}\n")
            f.write(f"Collection Method: {method}\n")
            f.write(f"Status: {'SUCCESS' if success else 'FAILED'}\n\n")
            
            if success:
                # List generated JSON files
                json_files = list(Path('.').glob('*.json'))
                if json_files:
                    f.write(f"Generated Files ({len(json_files)}):\n")
                    for jf in json_files:
                        f.write(f"  • {jf.name}\n")
                    f.write("\n")
            
            f.write("Next Steps:\n")
            f.write("1. Start Neo4j database (neo4j console)\n")
            f.write("2. Open BloodHound UI\n")
            f.write("3. Import data files (drag and drop JSON files)\n")
            f.write("4. Run queries to find attack paths\n\n")
        
        print(f"{GREEN}[+] Collection summary saved to: {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error saving summary: {e}{RESET}")


def save_bloodhound_guide(domain=None, dc_ip=None, filename='BLOODHOUND_GUIDE.txt'):
    """Generate comprehensive BloodHound guide"""
    try:
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("BLOODHOUND COLLECTION AND ANALYSIS GUIDE\n")
            f.write("=" * 80 + "\n\n")
            
            if domain and dc_ip:
                f.write(f"Target Domain: {domain}\n")
                f.write(f"Domain Controller: {dc_ip}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("METHOD 1: BloodHound-Python (Linux/Kali - Recommended)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Installation:\n")
            f.write("-" * 80 + "\n")
            f.write("pip3 install bloodhound\n")
            f.write("# OR\n")
            f.write("apt install bloodhound.py\n\n")
            
            f.write("Collection Commands:\n")
            f.write("-" * 80 + "\n")
            
            if domain and dc_ip:
                f.write(f"# All data (recommended for full assessment)\n")
                f.write(f"bloodhound-python -d {domain} -u USERNAME -p PASSWORD -dc {dc_ip} -c All\n\n")
                
                f.write(f"# DC Only (fast, minimal data)\n")
                f.write(f"bloodhound-python -d {domain} -u USERNAME -p PASSWORD -dc {dc_ip} -c DCOnly\n\n")
                
                f.write(f"# Session loop (collect sessions every 10 minutes)\n")
                f.write(f"bloodhound-python -d {domain} -u USERNAME -p PASSWORD -dc {dc_ip} -c SessionLoop\n\n")
            else:
                f.write("# All data (recommended)\n")
                f.write("bloodhound-python -d DOMAIN -u USERNAME -p PASSWORD -dc DC-IP -c All\n\n")
                
                f.write("# DC Only (fast)\n")
                f.write("bloodhound-python -d DOMAIN -u USERNAME -p PASSWORD -dc DC-IP -c DCOnly\n\n")
                
                f.write("# Session loop\n")
                f.write("bloodhound-python -d DOMAIN -u USERNAME -p PASSWORD -dc DC-IP -c SessionLoop\n\n")
            
            f.write("Collection Method Options:\n")
            f.write("-" * 80 + "\n")
            for method, desc in COLLECTION_METHODS.items():
                f.write(f"  • {method:<15} - {desc}\n")
            f.write("\n")
            
            f.write("Advanced Options:\n")
            f.write("-" * 80 + "\n")
            f.write("# Specify custom nameserver\n")
            f.write("bloodhound-python -d DOMAIN -u USER -p PASS -dc DC-IP -ns 8.8.8.8 -c All\n\n")
            
            f.write("# Use Kerberos authentication\n")
            f.write("bloodhound-python -d DOMAIN -u USER -k -dc DC-IP -c All\n\n")
            
            f.write("# Disable Kerberos (force NTLM)\n")
            f.write("bloodhound-python -d DOMAIN -u USER -p PASS -dc DC-IP --disable-authn-check -c All\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("METHOD 2: SharpHound (Windows - Alternative)\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Download:\n")
            f.write("-" * 80 + "\n")
            f.write("https://github.com/BloodHoundAD/SharpHound/releases\n\n")
            
            f.write("Collection Commands (PowerShell):\n")
            f.write("-" * 80 + "\n")
            f.write("# All data\n")
            f.write(".\\SharpHound.exe -c All\n\n")
            
            f.write("# DC Only\n")
            f.write(".\\SharpHound.exe -c DCOnly\n\n")
            
            f.write("# Session loop (every 10 minutes, 12 iterations = 2 hours)\n")
            f.write(".\\SharpHound.exe -c SessionLoop --Loop --LoopDuration 02:00:00\n\n")
            
            f.write("# With credentials\n")
            f.write(".\\SharpHound.exe -c All --Domain DOMAIN --LdapUsername USER --LdapPassword PASS\n\n")
            
            f.write("Advanced Options:\n")
            f.write("-" * 80 + "\n")
            f.write("# Stealth mode (slower, less detectable)\n")
            f.write(".\\SharpHound.exe -c All --Stealth\n\n")
            
            f.write("# Output to specific directory\n")
            f.write(".\\SharpHound.exe -c All --OutputDirectory C:\\Temp\\BH\n\n")
            
            f.write("# Exclude specific domain controllers\n")
            f.write(".\\SharpHound.exe -c All --ExcludeDCs DC01.domain.local\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("NEO4J DATABASE SETUP\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Installation (Linux):\n")
            f.write("-" * 80 + "\n")
            f.write("apt install neo4j\n")
            f.write("neo4j console\n")
            f.write("# Access: http://localhost:7474\n")
            f.write("# Default creds: neo4j/neo4j (will prompt to change)\n\n")
            
            f.write("Installation (Windows):\n")
            f.write("-" * 80 + "\n")
            f.write("Download: https://neo4j.com/download-center/\n")
            f.write("Run: neo4j.bat console\n")
            f.write("Access: http://localhost:7474\n\n")
            
            f.write("Installation (Docker - Easiest):\n")
            f.write("-" * 80 + "\n")
            f.write("docker run -p 7474:7474 -p 7687:7687 neo4j:4.4\n")
            f.write("# Access: http://localhost:7474\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("BLOODHOUND UI SETUP\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Installation (Linux):\n")
            f.write("-" * 80 + "\n")
            f.write("apt install bloodhound\n")
            f.write("bloodhound\n\n")
            
            f.write("Installation (Windows/Mac):\n")
            f.write("-" * 80 + "\n")
            f.write("Download: https://github.com/BloodHoundAD/BloodHound/releases\n")
            f.write("Extract and run BloodHound executable\n\n")
            
            f.write("First Time Setup:\n")
            f.write("-" * 80 + "\n")
            f.write("1. Start Neo4j database\n")
            f.write("2. Launch BloodHound\n")
            f.write("3. Connect to database (bolt://localhost:7687)\n")
            f.write("4. Login with Neo4j credentials\n")
            f.write("5. Drag and drop JSON files into BloodHound UI\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("IMPORTING DATA\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Method 1: BloodHound UI (Easiest)\n")
            f.write("-" * 80 + "\n")
            f.write("1. Open BloodHound\n")
            f.write("2. Click 'Upload Data' button (top right)\n")
            f.write("3. Select all .json files\n")
            f.write("4. Wait for import to complete\n")
            f.write("5. Check 'Database Info' tab for statistics\n\n")
            
            f.write("Method 2: Command Line\n")
            f.write("-" * 80 + "\n")
            f.write("# Using BloodHound's built-in import\n")
            f.write("bloodhound-python --import-json *.json\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("BLOODHOUND QUERIES - QUICK WINS\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Pre-Built Queries (Click 'Queries' tab):\n")
            f.write("-" * 80 + "\n")
            f.write("🔥 HIGH-VALUE TARGETS:\n")
            f.write("  • Find all Domain Admins\n")
            f.write("  • Find Shortest Paths to Domain Admins\n")
            f.write("  • Find Computers where Domain Users are Local Admin\n")
            f.write("  • Find Computers where Domain Users can RDP\n\n")
            
            f.write("🎯 PRIVILEGE ESCALATION:\n")
            f.write("  • Shortest Paths to High Value Targets\n")
            f.write("  • Shortest Paths from Owned Principals\n")
            f.write("  • Shortest Paths to Domain Admins from Kerberoastable Users\n\n")
            
            f.write("⚠️ MISCONFIGURATIONS:\n")
            f.write("  • Find Kerberoastable Members of High Value Groups\n")
            f.write("  • Find AS-REP Roastable Users (Domain Users)\n")
            f.write("  • Find Computers with Unconstrained Delegation\n")
            f.write("  • Find Principals with DCSync Rights\n\n")
            
            f.write("🔍 RECONNAISSANCE:\n")
            f.write("  • List all Kerberoastable Accounts\n")
            f.write("  • Find All Paths from Domain Users to High Value Targets\n")
            f.write("  • Find Workstations where Domain Users can RDP\n")
            f.write("  • Find Servers where Domain Users can RDP\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("CUSTOM CYPHER QUERIES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Find shortest path from user to Domain Admins:\n")
            f.write("-" * 80 + "\n")
            f.write("MATCH (u:User {name:'USERNAME@DOMAIN.LOCAL'}),\n")
            f.write("      (g:Group {name:'DOMAIN ADMINS@DOMAIN.LOCAL'}),\n")
            f.write("      p=shortestPath((u)-[*1..]->(g))\n")
            f.write("RETURN p\n\n")
            
            f.write("Find all computers with unconstrained delegation:\n")
            f.write("-" * 80 + "\n")
            f.write("MATCH (c:Computer {unconstraineddelegation:true})\n")
            f.write("RETURN c.name\n\n")
            
            f.write("Find users with DCSync rights:\n")
            f.write("-" * 80 + "\n")
            f.write("MATCH p=(u:User)-[:DCSync|AllExtendedRights]->(d:Domain)\n")
            f.write("RETURN u.name, d.name\n\n")
            
            f.write("Find computers where a specific user has admin rights:\n")
            f.write("-" * 80 + "\n")
            f.write("MATCH (u:User {name:'USERNAME@DOMAIN.LOCAL'})\n")
            f.write("MATCH (c:Computer)\n")
            f.write("MATCH p=(u)-[:AdminTo|MemberOf*1..]->(c)\n")
            f.write("RETURN p\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("ANALYSIS WORKFLOW\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Step 1: Mark Owned Principals\n")
            f.write("-" * 80 + "\n")
            f.write("1. Right-click on user/computer node\n")
            f.write("2. Select 'Mark User as Owned'\n")
            f.write("3. Run 'Shortest Paths from Owned Principals'\n\n")
            
            f.write("Step 2: Identify High-Value Targets\n")
            f.write("-" * 80 + "\n")
            f.write("1. Run 'Find all Domain Admins'\n")
            f.write("2. Run 'Find Computers with Unconstrained Delegation'\n")
            f.write("3. Run 'Find Principals with DCSync Rights'\n\n")
            
            f.write("Step 3: Find Attack Paths\n")
            f.write("-" * 80 + "\n")
            f.write("1. Run 'Shortest Paths to Domain Admins'\n")
            f.write("2. Run 'Shortest Paths to High Value Targets'\n")
            f.write("3. Analyze edges (relationships) for exploitation\n\n")
            
            f.write("Step 4: Look for Quick Wins\n")
            f.write("-" * 80 + "\n")
            f.write("1. Check for Kerberoastable users in sensitive groups\n")
            f.write("2. Look for AS-REP roastable accounts\n")
            f.write("3. Find users with GenericAll/GenericWrite/WriteDacl\n")
            f.write("4. Identify computers where you can RDP/PSRemote\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("EDGE TYPES AND EXPLOITATION\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("AdminTo:\n")
            f.write("  Attack: PSExec, WMI, DCOM, or service creation\n")
            f.write("  Tools: crackmapexec, psexec.py, wmiexec.py\n\n")
            
            f.write("MemberOf:\n")
            f.write("  Attack: Inherit group permissions\n")
            f.write("  Check: What can this group do?\n\n")
            
            f.write("HasSession:\n")
            f.write("  Attack: Token impersonation if you have admin rights\n")
            f.write("  Tools: Mimikatz, Rubeus\n\n")
            
            f.write("ForceChangePassword:\n")
            f.write("  Attack: Change target user's password\n")
            f.write("  Tools: PowerView, net user\n\n")
            
            f.write("GenericAll:\n")
            f.write("  Attack: Full control - reset password, add to groups\n")
            f.write("  Tools: PowerView, ADSI, ldapmodify\n\n")
            
            f.write("GenericWrite:\n")
            f.write("  Attack: Modify object properties\n")
            f.write("  Abuse: Add SPN for Kerberoasting, modify logon scripts\n\n")
            
            f.write("WriteDacl:\n")
            f.write("  Attack: Grant yourself GenericAll/DCSync rights\n")
            f.write("  Tools: PowerView, ADSI\n\n")
            
            f.write("WriteOwner:\n")
            f.write("  Attack: Change object owner to yourself\n")
            f.write("  Then: Modify DACL to grant GenericAll\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("OPERATIONAL SECURITY\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("🔍 Detection Risks:\n")
            f.write("-" * 80 + "\n")
            f.write("• BloodHound creates LDAP queries (logged in Event ID 1644)\n")
            f.write("• Large number of LDAP queries in short time = suspicious\n")
            f.write("• NetSessionEnum queries for session data (noisy)\n")
            f.write("• Modern EDR can detect BloodHound patterns\n\n")
            
            f.write("✓ Stealth Options:\n")
            f.write("-" * 80 + "\n")
            f.write("• Use --Stealth flag with SharpHound (slower collection)\n")
            f.write("• Collect during business hours (blend with normal traffic)\n")
            f.write("• Use DCOnly first (minimal queries)\n")
            f.write("• Spread collection over multiple days\n")
            f.write("• Use compromised service account (less suspicious)\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("TROUBLESHOOTING\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Collection fails with 'Access Denied':\n")
            f.write("  → Need valid domain user credentials\n")
            f.write("  → Check username format: DOMAIN\\user or user@domain.local\n\n")
            
            f.write("No data appears in BloodHound:\n")
            f.write("  → Verify JSON files were generated\n")
            f.write("  → Check Neo4j is running (http://localhost:7474)\n")
            f.write("  → Re-import data files\n")
            f.write("  → Check 'Database Info' for import errors\n\n")
            
            f.write("'Cannot connect to database':\n")
            f.write("  → Start Neo4j: neo4j console\n")
            f.write("  → Check bolt://localhost:7687 is accessible\n")
            f.write("  → Verify firewall allows connection\n\n")
            
            f.write("Collection is very slow:\n")
            f.write("  → Large domains take time (30+ min for 10k+ users)\n")
            f.write("  → Use DCOnly for quick assessment\n")
            f.write("  → Check network latency to DC\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("RESOURCES\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("Official Resources:\n")
            f.write("  • BloodHound GitHub: https://github.com/BloodHoundAD/BloodHound\n")
            f.write("  • BloodHound Docs: https://bloodhound.readthedocs.io/\n")
            f.write("  • SharpHound: https://github.com/BloodHoundAD/SharpHound\n\n")
            
            f.write("Tutorials:\n")
            f.write("  • BloodHound Introduction: https://blog.riccardoancarani.it/bloodhound-tips-and-tricks/\n")
            f.write("  • Custom Queries: https://hausec.com/2019/09/09/bloodhound-cypher-cheatsheet/\n")
            f.write("  • Attack Paths: https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-with-bloodhound-on-kali-linux\n\n")
            
            f.write("Community Queries:\n")
            f.write("  • https://github.com/hausec/Bloodhound-Custom-Queries\n")
            f.write("  • https://github.com/CompassSecurity/BloodHoundQueries\n\n")
        
        print(f"{GREEN}[+] BloodHound guide saved to: {filename}{RESET}")
        
    except Exception as e:
        print(f"{RED}[!] Error saving BloodHound guide: {e}{RESET}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='BloodSeek - BloodHound Collection Wrapper',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./bloodseek.py -d CORP.LOCAL -u john -p Password123 -dc 192.168.1.10
  ./bloodseek.py -d CORP.LOCAL -u john -p Password123 -dc 192.168.1.10 --method All
  ./bloodseek.py -d CORP.LOCAL -u john -p Password123 -dc 192.168.1.10 --method DCOnly
  ./bloodseek.py --guide-only
        """
    )
    
    parser.add_argument('-d', '--domain', help='Target domain (e.g., CORP.LOCAL)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-dc', '--dc-ip', dest='dc_ip', help='Domain Controller IP address')
    parser.add_argument('--method', choices=list(COLLECTION_METHODS.keys()), 
                       default='All', help='Collection method (default: All)')
    parser.add_argument('--ns', help='Custom nameserver IP')
    parser.add_argument('--guide-only', action='store_true', 
                       help='Generate guide only, no collection')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Guide-only mode
    if args.guide_only:
        print(f"{CYAN}[*] Generating BloodHound guide...{RESET}\n")
        save_bloodhound_guide()
        print(f"\n{GREEN}[+] Guide generated!{RESET}")
        print(f"{YELLOW}[*] Review BLOODHOUND_GUIDE.txt for complete instructions{RESET}\n")
        return
    
    # Validate required arguments
    if not all([args.domain, args.username, args.password, args.dc_ip]):
        print(f"{RED}[!] Missing required arguments{RESET}")
        print(f"{YELLOW}Required: -d DOMAIN -u USERNAME -p PASSWORD -dc DC-IP{RESET}")
        print(f"{YELLOW}Or use: --guide-only to generate guide without collection{RESET}\n")
        parser.print_help()
        sys.exit(1)
    
    # Check if bloodhound-python is installed
    if not check_bloodhound_python():
        print(f"{RED}[!] bloodhound-python not found{RESET}")
        print(f"{YELLOW}[*] Install with: pip3 install bloodhound{RESET}")
        print(f"{YELLOW}[*] Or: apt install bloodhound.py{RESET}\n")
        print(f"{CYAN}[*] Generating guide instead...{RESET}\n")
        save_bloodhound_guide(args.domain, args.dc_ip)
        print(f"\n{YELLOW}[*] Review BLOODHOUND_GUIDE.txt for installation and usage{RESET}\n")
        sys.exit(1)
    
    # Display collection info
    print(f"{CYAN}{'=' * 80}{RESET}")
    print(f"{CYAN}{BOLD}BloodHound Collection{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}")
    print(f"{YELLOW}Domain:{RESET} {args.domain}")
    print(f"{YELLOW}DC IP:{RESET} {args.dc_ip}")
    print(f"{YELLOW}Username:{RESET} {args.username}")
    print(f"{YELLOW}Method:{RESET} {args.method} - {COLLECTION_METHODS[args.method]}")
    print(f"{CYAN}{'=' * 80}{RESET}\n")
    
    # Generate and display command
    cmd = generate_bloodhound_command(args.domain, args.username, args.password, 
                                      args.dc_ip, args.method, args.ns)
    print(f"{YELLOW}Command (for reference):{RESET}")
    print(f"{cmd.replace(args.password, '********')}\n")
    
    # Run collection
    success, output = run_bloodhound_collection(args.domain, args.username, args.password,
                                                 args.dc_ip, args.method, args.ns)
    
    # Save summary and guide
    save_bloodlist(args.domain, args.method, success)
    save_bloodhound_guide(args.domain, args.dc_ip)
    
    # Final output
    print(f"\n{CYAN}{'=' * 80}{RESET}")
    if success:
        print(f"{GREEN}{BOLD}[+] Collection Complete!{RESET}")
        print(f"{YELLOW}[*] Next steps:{RESET}")
        print(f"    1. Start Neo4j: neo4j console")
        print(f"    2. Open BloodHound UI")
        print(f"    3. Import JSON files (drag and drop)")
        print(f"    4. Review BLOODHOUND_GUIDE.txt for analysis queries")
    else:
        print(f"{RED}{BOLD}[!] Collection Failed{RESET}")
        print(f"{YELLOW}[*] Review BLOODHOUND_GUIDE.txt for troubleshooting{RESET}")
    print(f"{CYAN}{'=' * 80}{RESET}\n")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Interrupted by user{RESET}")
        sys.exit(0)
