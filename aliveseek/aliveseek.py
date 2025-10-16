#!/usr/bin/env python3
"""
AliveSeek - Fast Host Discovery
Quickly identify alive hosts from an IP list using Nmap
"""

import argparse
import subprocess
import sys
import os
import re
from pathlib import Path

# Color codes
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
CYAN = '\033[96m'
BOLD = '\033[1m'
RESET = '\033[0m'

def check_nmap_installed():
    """Check if nmap is installed"""
    try:
        result = subprocess.run(['nmap', '--version'], capture_output=True, text=True)
        return result.returncode == 0
    except FileNotFoundError:
        return False

def parse_nmap_output(output):
    """Parse nmap output to extract alive hosts"""
    alive_hosts = []
    
    # Look for "Nmap scan report for" lines
    for line in output.split('\n'):
        if 'Nmap scan report for' in line:
            # Extract IP address
            match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
            if match:
                ip = match.group(1)
                alive_hosts.append(ip)
    
    return alive_hosts

def load_targets(file_path):
    """Load target IPs from file"""
    targets = []
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    targets.append(line)
        return targets
    except FileNotFoundError:
        print(f"{RED}[!] Error: File not found: {file_path}{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[!] Error reading file: {e}{RESET}")
        sys.exit(1)

def main():
    banner = f"""
{CYAN}{BOLD}
    ╔═══════════════════════════════════════╗
    ║         AliveSeek - Host Discovery    ║
    ║      Fast Alive Host Identification   ║
    ╚═══════════════════════════════════════╝
{RESET}
"""
    print(banner)
    
    parser = argparse.ArgumentParser(
        description='Fast host discovery using Nmap - identify alive hosts',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('targets', help='Target IP list file')
    parser.add_argument('-T', '--timing', choices=['0', '1', '2', '3', '4', '5'], 
                       default='2', help='Nmap timing template (default: 2/Polite)')
    parser.add_argument('-Pn', '--no-ping', action='store_true',
                       help='Skip host discovery, treat all hosts as online')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose nmap output')
    parser.add_argument('-o', '--output', default='iplist.txt',
                       help='Output file for alive hosts (default: iplist.txt)')
    parser.add_argument('--backup', default='iplist_full.txt',
                       help='Backup file for original list (default: iplist_full.txt)')
    
    args = parser.parse_args()
    
    # Check if nmap is installed
    if not check_nmap_installed():
        print(f"{RED}[!] Error: nmap is not installed or not in PATH{RESET}")
        print(f"{YELLOW}[*] Install nmap: https://nmap.org/download.html{RESET}")
        sys.exit(1)
    
    # Load targets
    print(f"{CYAN}[*] Loading targets from: {args.targets}{RESET}")
    targets = load_targets(args.targets)
    total = len(targets)
    print(f"{GREEN}[+] Loaded {total} target(s){RESET}\n")
    
    # Check if we should backup the original file
    if args.targets == args.output and args.backup:
        print(f"{YELLOW}[*] Backing up original list to: {args.backup}{RESET}")
        try:
            with open(args.targets, 'r') as src:
                with open(args.backup, 'w') as dst:
                    dst.write(src.read())
            print(f"{GREEN}[+] Backup created{RESET}\n")
        except Exception as e:
            print(f"{RED}[!] Error creating backup: {e}{RESET}")
            sys.exit(1)
    
    # Build nmap command
    timing_names = {'0': 'Paranoid', '1': 'Sneaky', '2': 'Polite', '3': 'Normal', '4': 'Aggressive', '5': 'Insane'}
    print(f"{CYAN}[*] Running nmap host discovery{RESET}")
    print(f"{CYAN}[*] Timing: T{args.timing} ({timing_names[args.timing]}){RESET}")
    print(f"{CYAN}[*] This may take a few minutes...{RESET}\n")
    
    cmd = ['nmap', '-sn', f'-T{args.timing}', '-iL', args.targets]
    
    if args.no_ping:
        cmd.append('-Pn')
    
    if args.verbose:
        cmd.append('-v')
    
    # Run nmap
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print(f"{RED}[!] Nmap scan failed{RESET}")
            if result.stderr:
                print(f"{RED}{result.stderr}{RESET}")
            sys.exit(1)
        
        # Parse output for alive hosts
        alive_hosts = parse_nmap_output(result.stdout)
        
        # Show nmap output if verbose
        if args.verbose:
            print(result.stdout)
    
    except FileNotFoundError:
        print(f"{RED}[!] Error: nmap not found{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[!] Error running nmap: {e}{RESET}")
        sys.exit(1)
    
    # Results summary
    print(f"\n{'='*60}")
    print(f"{GREEN}{BOLD}[+] Scan Complete!{RESET}")
    print(f"{'='*60}")
    print(f"{GREEN}[+] Alive hosts: {len(alive_hosts)}/{total}{RESET}")
    print(f"{RED}[-] Down hosts: {total - len(alive_hosts)}/{total}{RESET}")
    
    if alive_hosts:
        # Save alive hosts
        print(f"\n{CYAN}[*] Saving alive hosts to: {args.output}{RESET}")
        try:
            with open(args.output, 'w') as f:
                for ip in sorted(alive_hosts):
                    f.write(f"{ip}\n")
            print(f"{GREEN}[+] Alive hosts saved to: {args.output}{RESET}")
            
            # Show first few alive hosts
            print(f"\n{GREEN}[+] Sample alive hosts:{RESET}")
            for ip in sorted(alive_hosts)[:10]:
                print(f"    {ip}")
            if len(alive_hosts) > 10:
                print(f"    ... and {len(alive_hosts) - 10} more")
                
        except Exception as e:
            print(f"{RED}[!] Error saving results: {e}{RESET}")
            sys.exit(1)
    else:
        print(f"\n{RED}[!] No alive hosts found{RESET}")
        print(f"{YELLOW}[*] Tips:{RESET}")
        print(f"    - Try different method: --method both")
        print(f"    - Increase timeout: --timeout 2")
        print(f"    - Check if targets are correct")
    
    print(f"\n{GREEN}[+] AliveSeek complete!{RESET}\n")

if __name__ == '__main__':
    main()
