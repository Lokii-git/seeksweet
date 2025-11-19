#!/usr/bin/env python3
"""
Simple Test Script for ThoughtLeadershipSeek
Verifies basic functionality of the thought leadership discovery tool
"""

import os
import sys
import subprocess
from pathlib import Path

# Color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

def print_banner():
    """Print test banner"""
    print(f"""
{CYAN}{BOLD}
===============================================================
        ThoughtLeadershipSeek Validation Test
     Verify basic functionality of the OSINT tool
===============================================================
{RESET}
""")

def test_help():
    """Test that --help works"""
    print(f"{CYAN}[*] Test 1: Testing --help flag{RESET}")
    script_path = Path(__file__).parent / 'thoughtleadershipseek.py'
    
    try:
        result = subprocess.run(
            ['python3', str(script_path), '--help'],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode == 0 and 'ThoughtLeadershipSeek' in result.stdout:
            print(f"{GREEN}[+] --help flag works correctly{RESET}")
            return True
        else:
            print(f"{RED}[!] --help flag failed{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[!] Exception during --help test: {e}{RESET}")
        return False

def test_guide_generation():
    """Test guide-only mode"""
    print(f"\n{CYAN}[*] Test 2: Testing --guide-only flag{RESET}")
    script_path = Path(__file__).parent / 'thoughtleadershipseek.py'
    test_dir = Path(__file__).parent / 'test_output'
    
    # Create test directory
    test_dir.mkdir(exist_ok=True)
    
    try:
        result = subprocess.run(
            ['python3', str(script_path), '--guide-only', '-o', str(test_dir)],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        guide_file = test_dir / 'THOUGHT_LEADERSHIP_GUIDE.txt'
        
        if result.returncode == 0 and guide_file.exists():
            file_size = guide_file.stat().st_size
            print(f"{GREEN}[+] Guide generated successfully ({file_size} bytes){RESET}")
            
            # Clean up
            guide_file.unlink()
            test_dir.rmdir()
            return True
        else:
            print(f"{RED}[!] Guide generation failed{RESET}")
            if test_dir.exists():
                # Clean up
                for f in test_dir.glob('*'):
                    f.unlink()
                test_dir.rmdir()
            return False
    except Exception as e:
        print(f"{RED}[!] Exception during guide generation test: {e}{RESET}")
        # Clean up
        if test_dir.exists():
            for f in test_dir.glob('*'):
                try:
                    f.unlink()
                except:
                    pass
            try:
                test_dir.rmdir()
            except:
                pass
        return False

def test_import():
    """Test that the script can be imported"""
    print(f"\n{CYAN}[*] Test 3: Testing module import{RESET}")
    
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        # Try importing key functions
        import thoughtleadershipseek
        
        # Check for key functions
        if (hasattr(thoughtleadershipseek, 'discover_thought_leadership') and
            hasattr(thoughtleadershipseek, 'generate_guide') and
            hasattr(thoughtleadershipseek, 'save_results')):
            print(f"{GREEN}[+] Module imports correctly with required functions{RESET}")
            return True
        else:
            print(f"{YELLOW}[!] Module imports but missing some functions{RESET}")
            return False
    except Exception as e:
        print(f"{RED}[!] Import test failed: {e}{RESET}")
        return False

def main():
    """Run all tests"""
    print_banner()
    
    results = []
    
    # Run tests
    results.append(("Help flag test", test_help()))
    results.append(("Guide generation test", test_guide_generation()))
    results.append(("Module import test", test_import()))
    
    # Print summary
    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}Test Summary{RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}")
    
    passed = 0
    failed = 0
    
    for test_name, result in results:
        status = f"{GREEN}PASS{RESET}" if result else f"{RED}FAIL{RESET}"
        print(f"{test_name}: {status}")
        if result:
            passed += 1
        else:
            failed += 1
    
    print(f"\n{BOLD}Total: {passed} passed, {failed} failed{RESET}")
    
    if failed == 0:
        print(f"\n{GREEN}{BOLD}All tests passed! ✓{RESET}")
        return 0
    else:
        print(f"\n{YELLOW}{BOLD}Some tests failed!{RESET}")
        return 1

if __name__ == '__main__':
    sys.exit(main())
