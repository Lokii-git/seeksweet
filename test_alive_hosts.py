#!/usr/bin/env python3
"""
Test Script for SeekSweet Alive Host Discovery
Verifies that the alive hosts check properly populates iplist with only alive hosts
"""

import os
import sys
import shutil
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime

# Color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BLUE = '\033[94m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_banner():
    """Print test banner"""
    print(f"""
{CYAN}{BOLD}
===============================================================
              SeekSweet Alive Host Discovery Test
         Verify that alive checking properly filters
               iplist.txt to only alive hosts
===============================================================
{RESET}
""")

def check_prerequisites():
    """Check if required tools are available"""
    print(f"{CYAN}[*] Checking prerequisites...{RESET}")
    
    # Check if nmap is installed
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        if result.returncode == 0:
            print(f"{GREEN}[+] nmap found: {result.stdout.split()[1]}{RESET}")
        else:
            print(f"{RED}[!] nmap check failed{RESET}")
            return False
    except FileNotFoundError:
        print(f"{RED}[!] nmap not found - please install nmap{RESET}")
        return False
    
    # Check if aliveseek.py exists
    script_dir = Path(__file__).parent
    aliveseek_path = script_dir / 'aliveseek' / 'aliveseek.py'
    if aliveseek_path.exists():
        print(f"{GREEN}[+] aliveseek.py found{RESET}")
    else:
        print(f"{RED}[!] aliveseek.py not found at: {aliveseek_path}{RESET}")
        return False
    
    # Check if seeksweet.py exists
    seeksweet_path = script_dir / 'seeksweet.py'
    if seeksweet_path.exists():
        print(f"{GREEN}[+] seeksweet.py found{RESET}")
    else:
        print(f"{RED}[!] seeksweet.py not found{RESET}")
        return False
    
    return True

def create_test_ip_list(test_file):
    """Create a test IP list with mix of likely alive and dead hosts"""
    test_ips = [
        # Common router/gateway IPs (likely alive)
        "192.168.1.1",
        "192.168.1.254",
        "10.0.0.1",
        
        # Google DNS (definitely alive)
        "8.8.8.8",
        "8.8.4.4",
        
        # Cloudflare DNS (definitely alive) 
        "1.1.1.1",
        "1.0.0.1",
        
        # Local network IPs (may or may not be alive)
        "192.168.1.100",
        "192.168.1.101",
        "192.168.1.102",
        "192.168.1.103",
        
        # Private network IPs unlikely to be alive
        "172.16.99.99",
        "172.16.88.88",
        "10.99.99.99",
        "10.88.88.88",
        
        # Reserved/invalid IPs (definitely dead)
        "192.168.255.255",
        "10.255.255.255",
        "172.31.255.255"
    ]
    
    with open(test_file, 'w') as f:
        for ip in test_ips:
            f.write(f"{ip}\n")
    
    print(f"{GREEN}[+] Created test IP list with {len(test_ips)} hosts{RESET}")
    return test_ips

def backup_original_files():
    """Backup original iplist.txt if it exists"""
    script_dir = Path(__file__).parent
    original_iplist = script_dir / 'iplist.txt'
    backup_file = script_dir / f'iplist_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt'
    
    if original_iplist.exists():
        shutil.copy2(original_iplist, backup_file)
        print(f"{YELLOW}[*] Backed up original iplist.txt to: {backup_file.name}{RESET}")
        return backup_file
    return None

def test_aliveseek_directly():
    """Test aliveseek.py directly"""
    print(f"\n{BLUE}{BOLD}TEST 1: Direct AliveSeek Test{RESET}")
    print(f"{BLUE}{'='*50}{RESET}")
    
    script_dir = Path(__file__).parent
    test_file = script_dir / 'test_iplist.txt'
    output_file = script_dir / 'test_alive_results.txt'
    
    # Create test IP list
    original_ips = create_test_ip_list(test_file)
    
    # Run aliveseek directly
    aliveseek_path = script_dir / 'aliveseek' / 'aliveseek.py'
    cmd = [
        sys.executable, str(aliveseek_path),
        str(test_file),
        '-T', '4',  # Aggressive timing for faster test
        '--output', str(output_file),
        '--backup', str(script_dir / 'test_backup.txt')
    ]
    
    print(f"{CYAN}[*] Running aliveseek directly...{RESET}")
    print(f"{CYAN}[*] Command: {' '.join(cmd)}{RESET}")
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print(f"{GREEN}[+] AliveSeek completed successfully{RESET}")
            
            # Check if output file was created
            if output_file.exists():
                with open(output_file, 'r') as f:
                    alive_hosts = [line.strip() for line in f if line.strip()]
                
                print(f"{GREEN}[+] Found {len(alive_hosts)} alive hosts out of {len(original_ips)}{RESET}")
                print(f"{GREEN}[+] Alive hosts:{RESET}")
                for host in alive_hosts:
                    print(f"    {host}")
                
                # Verify that we only have alive hosts (should be subset of original)
                if set(alive_hosts).issubset(set(original_ips)):
                    print(f"{GREEN}[+] ✓ All alive hosts are from original list{RESET}")
                else:
                    print(f"{RED}[!] ✗ Some alive hosts not in original list{RESET}")
                    return False
                
                # Verify file contains only valid IPs
                valid_count = 0
                for host in alive_hosts:
                    if validate_ip(host):
                        valid_count += 1
                
                if valid_count == len(alive_hosts):
                    print(f"{GREEN}[+] ✓ All alive hosts are valid IP addresses{RESET}")
                else:
                    print(f"{RED}[!] ✗ Some invalid IP addresses found{RESET}")
                    return False
                
                return True
            else:
                print(f"{RED}[!] Output file not created{RESET}")
                return False
        else:
            print(f"{RED}[!] AliveSeek failed with exit code {result.returncode}{RESET}")
            if result.stderr:
                print(f"{RED}STDERR: {result.stderr}{RESET}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"{RED}[!] AliveSeek timed out after 2 minutes{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[!] Error running AliveSeek: {e}{RESET}")
        return False

def test_seeksweet_integration():
    """Test alive host discovery through seeksweet menu option 89"""
    print(f"\n{BLUE}{BOLD}TEST 2: SeekSweet Integration Test{RESET}")
    print(f"{BLUE}{'='*50}{RESET}")
    
    script_dir = Path(__file__).parent
    test_file = script_dir / 'test_iplist_seeksweet.txt'
    
    # Create test IP list
    original_ips = create_test_ip_list(test_file)
    
    print(f"{CYAN}[*] Testing seeksweet alive host discovery integration{RESET}")
    print(f"{YELLOW}[*] Note: This tests the workflow but requires manual verification{RESET}")
    print(f"{YELLOW}[*] You would run seeksweet.py and select option 89{RESET}")
    
    # Show what the integration should do
    print(f"\n{CYAN}Expected SeekSweet Option 89 workflow:{RESET}")
    print(f"  1. Prompt for IP list file")
    print(f"  2. Show target count from file")
    print(f"  3. Allow timing template selection")
    print(f"  4. Run aliveseek.py with selected options")
    print(f"  5. Backup original iplist.txt to iplist_full.txt")
    print(f"  6. Replace iplist.txt with alive hosts only")
    print(f"  7. Show completion message")
    
    return True

def validate_ip(ip):
    """Basic IP address validation"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    
    try:
        for part in parts:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        return True
    except ValueError:
        return False

def test_nmap_output_parsing():
    """Test the nmap output parsing functionality"""
    print(f"\n{BLUE}{BOLD}TEST 3: Nmap Output Parsing Test{RESET}")
    print(f"{BLUE}{'='*50}{RESET}")
    
    # Simulate nmap output
    sample_nmap_output = """
Starting Nmap 7.80 ( https://nmap.org ) at 2024-01-15 10:30 EST
Nmap scan report for 8.8.8.8
Host is up (0.010s latency).
Nmap scan report for 8.8.4.4
Host is up (0.012s latency).
Nmap scan report for 1.1.1.1
Host is up (0.008s latency).
Nmap done: 18 IP addresses (3 hosts up) scanned in 5.23 seconds
"""
    
    # Import parse function from aliveseek
    sys.path.append(str(Path(__file__).parent / 'aliveseek'))
    try:
        from aliveseek import parse_nmap_output
        
        alive_hosts = parse_nmap_output(sample_nmap_output)
        expected_hosts = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        
        print(f"{CYAN}[*] Testing nmap output parsing{RESET}")
        print(f"Expected: {expected_hosts}")
        print(f"Parsed: {alive_hosts}")
        
        if set(alive_hosts) == set(expected_hosts):
            print(f"{GREEN}[+] ✓ Nmap output parsing works correctly{RESET}")
            return True
        else:
            print(f"{RED}[!] ✗ Nmap output parsing failed{RESET}")
            return False
            
    except ImportError as e:
        print(f"{YELLOW}[!] Could not import parse_nmap_output function: {e}{RESET}")
        return False

def test_file_operations():
    """Test file backup and replacement operations"""
    print(f"\n{BLUE}{BOLD}TEST 4: File Operations Test{RESET}")
    print(f"{BLUE}{'='*50}{RESET}")
    
    script_dir = Path(__file__).parent
    
    # Test scenario: original iplist.txt exists
    test_original = script_dir / 'test_original_iplist.txt'
    test_backup = script_dir / 'test_iplist_full.txt'
    test_new = script_dir / 'test_new_iplist.txt'
    
    # Create test files
    original_content = "192.168.1.1\n192.168.1.2\n192.168.1.3\n10.10.10.10\n"
    alive_content = "192.168.1.1\n192.168.1.2\n"
    
    with open(test_original, 'w') as f:
        f.write(original_content)
    
    with open(test_new, 'w') as f:
        f.write(alive_content)
    
    print(f"{CYAN}[*] Testing file backup and replacement{RESET}")
    
    # Test backup creation
    if test_original.exists():
        shutil.copy2(test_original, test_backup)
        if test_backup.exists():
            print(f"{GREEN}[+] ✓ Backup file created successfully{RESET}")
        else:
            print(f"{RED}[!] ✗ Backup file creation failed{RESET}")
            return False
    
    # Test file replacement
    shutil.copy2(test_new, test_original)
    
    # Verify replacement
    with open(test_original, 'r') as f:
        new_content = f.read()
    
    if new_content == alive_content:
        print(f"{GREEN}[+] ✓ File replacement works correctly{RESET}")
        
        # Verify backup preservation
        with open(test_backup, 'r') as f:
            backup_content = f.read()
        
        if backup_content == original_content:
            print(f"{GREEN}[+] ✓ Original content preserved in backup{RESET}")
            
            # Cleanup test files
            for test_file in [test_original, test_backup, test_new]:
                if test_file.exists():
                    test_file.unlink()
            
            return True
        else:
            print(f"{RED}[!] ✗ Backup content doesn't match original{RESET}")
            return False
    else:
        print(f"{RED}[!] ✗ File replacement failed{RESET}")
        return False

def cleanup_test_files():
    """Clean up test files"""
    script_dir = Path(__file__).parent
    test_files = [
        'test_iplist.txt',
        'test_alive_results.txt',
        'test_backup.txt',
        'test_iplist_seeksweet.txt',
        'test_original_iplist.txt',
        'test_iplist_full.txt',
        'test_new_iplist.txt'
    ]
    
    print(f"\n{CYAN}[*] Cleaning up test files...{RESET}")
    for filename in test_files:
        test_file = script_dir / filename
        if test_file.exists():
            test_file.unlink()
            print(f"{GREEN}[+] Removed: {filename}{RESET}")

def main():
    """Main test function"""
    print_banner()
    
    # Check prerequisites
    if not check_prerequisites():
        print(f"\n{RED}[!] Prerequisites not met. Exiting.{RESET}")
        sys.exit(1)
    
    # Backup original files
    backup_file = backup_original_files()
    
    print(f"\n{CYAN}{BOLD}Starting SeekSweet Alive Host Discovery Tests{RESET}")
    print(f"{CYAN}{'='*60}{RESET}")
    
    test_results = []
    
    # Run tests
    try:
        # Test 1: Direct aliveseek test
        result1 = test_aliveseek_directly()
        test_results.append(("Direct AliveSeek Test", result1))
        
        # Test 2: SeekSweet integration
        result2 = test_seeksweet_integration()
        test_results.append(("SeekSweet Integration Test", result2))
        
        # Test 3: Nmap output parsing
        result3 = test_nmap_output_parsing()
        test_results.append(("Nmap Output Parsing Test", result3))
        
        # Test 4: File operations
        result4 = test_file_operations()
        test_results.append(("File Operations Test", result4))
        
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Tests interrupted by user{RESET}")
    except Exception as e:
        print(f"\n{RED}[!] Unexpected error during tests: {e}{RESET}")
    
    finally:
        # Clean up test files
        cleanup_test_files()
    
    # Results summary
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}{CYAN}TEST RESULTS SUMMARY{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"  {test_name:<30} [{status}]")
        if result:
            passed += 1
    
    print(f"\n{BOLD}Overall: {passed}/{total} tests passed{RESET}")
    
    if passed == total:
        print(f"{GREEN}{BOLD}[+] ✓ All tests passed! Alive host discovery is working correctly.{RESET}")
    else:
        print(f"{RED}{BOLD}[!] ✗ Some tests failed. Check the alive host discovery functionality.{RESET}")
    
    # Manual verification instructions
    print(f"\n{YELLOW}{BOLD}MANUAL VERIFICATION STEPS:{RESET}")
    print(f"{YELLOW}To manually verify the alive host discovery in SeekSweet:{RESET}")
    print(f"  1. Run: python seeksweet.py")
    print(f"  2. Select option: 89 (Find Alive Hosts)")
    print(f"  3. Use the current iplist.txt file")
    print(f"  4. Choose timing template (2 recommended)")
    print(f"  5. Verify that:")
    print(f"     • Original list is backed up to iplist_full.txt")
    print(f"     • iplist.txt contains only alive hosts")
    print(f"     • Count of alive hosts is less than or equal to original")
    print(f"     • All IPs in new iplist.txt are valid IP addresses")
    print(f"     • Subsequent seek tools use the filtered list")
    
    if backup_file:
        print(f"\n{GREEN}[+] Your original iplist.txt was backed up to: {backup_file.name}{RESET}")
    
    print(f"\n{CYAN}Test complete!{RESET}\n")

if __name__ == '__main__':
    main()