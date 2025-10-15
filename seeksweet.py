#!/usr/bin/env python3
"""
SeekSweet - Orchestration Menu for Seek Tools Suite
A sweet suite of network reconnaissance tools with guided workflow
"""

import os
import sys
import subprocess
import json
from datetime import datetime
from pathlib import Path

# Color codes for terminal output
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
BLUE = '\033[94m'
MAGENTA = '\033[95m'
CYAN = '\033[96m'
WHITE = '\033[97m'
BOLD = '\033[1m'
RESET = '\033[0m'

# Track completed scans
completed_scans = {}
scan_outputs = {}

# Status file for persistent tracking
STATUS_FILE = Path(__file__).parent / '.seeksweet_status.json'

def load_status():
    """Load completion status from file"""
    global completed_scans, scan_outputs
    if STATUS_FILE.exists():
        try:
            with open(STATUS_FILE, 'r') as f:
                data = json.load(f)
                completed_scans = {int(k): v for k, v in data.get('completed_scans', {}).items()}
                scan_outputs = {int(k): v for k, v in data.get('scan_outputs', {}).items()}
        except Exception as e:
            print(f"{YELLOW}[!] Warning: Could not load status file: {e}{RESET}")

def save_status():
    """Save completion status to file"""
    try:
        data = {
            'completed_scans': completed_scans,
            'scan_outputs': scan_outputs,
            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        with open(STATUS_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"{YELLOW}[!] Warning: Could not save status file: {e}{RESET}")

def reset_status():
    """Clear all completion status"""
    global completed_scans, scan_outputs
    completed_scans = {}
    scan_outputs = {}
    if STATUS_FILE.exists():
        STATUS_FILE.unlink()
    print(f"{GREEN}[+] All completion status cleared{RESET}")

# Define the Seek tools in recommended execution order
SEEK_TOOLS = [
    {
        'id': 1,
        'name': 'DCSeek',
        'script': 'dcseek/dcseek.py',
        'priority': 'CRITICAL',
        'phase': 'Discovery',
        'description': 'Find Domain Controllers and enumerate domain info',
        'why': 'Start here - identifies the domain infrastructure',
        'outputs': ['dclist.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 2,
        'name': 'LDAPSeek',
        'script': 'ldapseek/ldapseek.py',
        'priority': 'CRITICAL',
        'phase': 'Discovery',
        'description': 'Enumerate users, groups, and AD objects via LDAP',
        'why': 'Essential for finding user accounts and domain structure',
        'outputs': ['ldaplist.txt', 'ldap_details.txt', 'ldap_details.json'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 3,
        'name': 'SMBSeek',
        'script': 'smbseek/smbseek.py',
        'priority': 'CRITICAL',
        'phase': 'Discovery',
        'description': 'Find SMB shares and enumerate accessible resources',
        'why': 'Critical for finding accessible file shares and sensitive data',
        'outputs': ['smblist.txt', 'sharelist.txt', 'smb_details.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 4,
        'name': 'ShareSeek',
        'script': 'shareseek/shareseek.py',
        'priority': 'HIGH',
        'phase': 'Discovery',
        'description': 'Deep enumeration of network shares and permissions',
        'why': 'Detailed share analysis for privilege escalation paths',
        'outputs': ['sharelist.txt', 'share_details.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 5,
        'name': 'KerbSeek',
        'script': 'kerbseek/kerbseek.py',
        'priority': 'HIGH',
        'phase': 'Authentication',
        'description': 'Find Kerberos services and enumerate SPNs',
        'why': 'Identify Kerberoastable accounts and service principals',
        'outputs': ['kerblist.txt', 'kerb_details.txt', 'kerb_details.json'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 6,
        'name': 'CredSeek',
        'script': 'credseek/credseek.py',
        'priority': 'HIGH',
        'phase': 'Authentication',
        'description': 'Find credential stores and password vaults',
        'why': 'Locate stored credentials and password managers',
        'outputs': ['credlist.txt', 'cred_details.txt', 'cred_details.json'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 7,
        'name': 'WinRMSeek',
        'script': 'winrmseek/winrmseek.py',
        'priority': 'MEDIUM',
        'phase': 'Access',
        'description': 'Find Windows Remote Management endpoints',
        'why': 'Identify remote administration access points',
        'outputs': ['winrmlist.txt', 'winrm_details.txt', 'winrm_details.json'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 8,
        'name': 'WebSeek',
        'script': 'webseek/webseek.py',
        'priority': 'HIGH',
        'phase': 'Web',
        'description': 'Nuclei-powered web vulnerability scanner with 5000+ templates',
        'why': 'Comprehensive web security scanning with smart reporting',
        'outputs': ['CRITICAL_FINDINGS.txt', 'findings.json', 'webseek_report/', 'IP_TO_VULNS.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 9,
        'name': 'PanelSeek',
        'script': 'panelseek/panelseek.py',
        'priority': 'MEDIUM',
        'phase': 'Web',
        'description': 'Find admin panels and management interfaces',
        'why': 'Locate administrative web interfaces',
        'outputs': ['panellist.txt', 'panel_details.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 10,
        'name': 'DbSeek',
        'script': 'dbseek/dbseek.py',
        'priority': 'MEDIUM',
        'phase': 'Services',
        'description': 'Find database servers and enumerate instances',
        'why': 'Identify database servers for potential data extraction',
        'outputs': ['dblist.txt', 'db_creds.txt', 'db_details.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 11,
        'name': 'BackupSeek',
        'script': 'backupseek/backupseek.py',
        'priority': 'MEDIUM',
        'phase': 'Services',
        'description': 'Find backup systems and infrastructure',
        'why': 'Locate backup servers - often contain full system images',
        'outputs': ['backuplist.txt', 'backup_details.txt', 'backup_details.json'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 12,
        'name': 'PrintSeek',
        'script': 'printseek/printseek.py',
        'priority': 'LOW',
        'phase': 'Services',
        'description': 'Find print servers and enumerate printers',
        'why': 'Identify print infrastructure - useful for network mapping',
        'outputs': ['printerlist.txt', 'printer_details.txt'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 13,
        'name': 'SNMPSeek',
        'script': 'snmpseek/snmpseek.py',
        'priority': 'LOW',
        'phase': 'Services',
        'description': 'Find SNMP services and enumerate devices',
        'why': 'Identify network devices and extract SNMP information',
        'outputs': ['snmplist.txt', 'snmp_details.txt', 'snmp_details.json'],
        'typical_args': 'iplist.txt -v'
    },
    {
        'id': 14,
        'name': 'VulnSeek',
        'script': 'vulnseek/vulnseek.py',
        'priority': 'HIGH',
        'phase': 'Assessment',
        'description': 'Multi-method vulnerability scanner (Nmap + Nuclei CVEs + Metasploit detection)',
        'why': 'Final assessment - comprehensive CVE detection with 10+ nmap checks and Nuclei CVE templates',
        'outputs': ['CRITICAL_VULNS.txt', 'vulnlist.txt', 'vuln_details.json', 'nuclei_cve_results/'],
        'typical_args': '-f iplist.txt --full --nuclei -v'
    }
]


def print_banner():
    """Print the SeekSweet banner"""
    banner = f"""{CYAN}{BOLD}
    ========================================================================
                    SEEKSWEET v1.0 - Seek Tools Suite
              Orchestrated Network Reconnaissance Framework
                   github.com/Lokii-git/seeksweet
    ========================================================================
    {RESET}"""
    print(banner)


def get_priority_color(priority):
    """Get color for priority level"""
    colors = {
        'CRITICAL': RED,
        'HIGH': YELLOW,
        'MEDIUM': BLUE,
        'LOW': WHITE
    }
    return colors.get(priority, WHITE)


def get_phase_color(phase):
    """Get color for phase"""
    colors = {
        'Discovery': MAGENTA,
        'Authentication': CYAN,
        'Access': YELLOW,
        'Web': BLUE,
        'Services': GREEN,
        'Assessment': RED
    }
    return colors.get(phase, WHITE)


def strip_ansi(text):
    """Remove ANSI color codes for length calculation"""
    import re
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def pad_with_ansi(text, width):
    """Pad text to width, accounting for ANSI codes"""
    visible_len = len(strip_ansi(text))
    padding_needed = width - visible_len
    return text + (' ' * padding_needed) if padding_needed > 0 else text


def format_tool_lines(tool, show_details):
    """Format a tool's display lines"""
    lines = []
    status = f" {GREEN}✓ {BOLD}COMPLETE{RESET}" if tool['id'] in completed_scans else ""
    priority_color = get_priority_color(tool['priority'])
    
    # Main line
    lines.append(f"  {BOLD}{tool['id']:2d}.{RESET} {BOLD}{tool['name']}{RESET} {priority_color}[{tool['priority']}]{RESET}{status}")
    lines.append(f"      {tool['description'][:48]}")
    
    # Optional details
    if show_details:
        lines.append(f"      {YELLOW}Why:{RESET} {tool['why'][:48]}")
    
    # Output location if completed
    if tool['id'] in completed_scans and tool['id'] in scan_outputs:
        lines.append(f"      {GREEN}Output:{RESET} {scan_outputs[tool['id']][:46]}")
    
    return lines


def print_menu(show_details=False):
    """Print the main menu with two-column layout - phases in columns"""
    print(f"\n{BOLD}{'='*120}{RESET}")
    print(f"{BOLD}{CYAN}SEEKSWEET MENU - Select a Tool to Run{RESET}")
    print(f"{BOLD}{'='*120}{RESET}\n")
    
    # Group by phase
    phases = {}
    for tool in SEEK_TOOLS:
        phase = tool['phase']
        if phase not in phases:
            phases[phase] = []
        phases[phase].append(tool)
    
    # Split phases into two columns
    left_phases = ['Discovery', 'Authentication', 'Access']
    right_phases = ['Web', 'Services', 'Assessment']
    
    # Build display lines for each column
    left_lines = []
    right_lines = []
    
    # Build left column
    for phase in left_phases:
        if phase in phases:
            left_lines.append(f"{get_phase_color(phase)}{BOLD}═══ {phase.upper()} PHASE ═══{RESET}")
            for tool in phases[phase]:
                tool_lines = format_tool_lines(tool, show_details)
                left_lines.extend(tool_lines)
                left_lines.append("")  # Spacing between tools
    
    # Build right column
    for phase in right_phases:
        if phase in phases:
            right_lines.append(f"{get_phase_color(phase)}{BOLD}═══ {phase.upper()} PHASE ═══{RESET}")
            for tool in phases[phase]:
                tool_lines = format_tool_lines(tool, show_details)
                right_lines.extend(tool_lines)
                right_lines.append("")  # Spacing between tools
    
    # Make both columns same length
    max_lines = max(len(left_lines), len(right_lines))
    while len(left_lines) < max_lines:
        left_lines.append("")
    while len(right_lines) < max_lines:
        right_lines.append("")
    
    # Print both columns side by side
    for left_line, right_line in zip(left_lines, right_lines):
        print(f"{pad_with_ansi(left_line, 58)}  {right_line}")
    
    print(f"\n{BOLD}═══ SPECIAL OPTIONS ═══{RESET}")
    print(f"  {BOLD}90.{RESET} {BOLD}Run All (Sequential){RESET} - Execute all tools one after another")
    print(f"  {BOLD}91.{RESET} {BOLD}Run All (Parallel){RESET} - Execute all tools simultaneously")
    print(f"  {BOLD}92.{RESET} {BOLD}Run Recommended Sequence{RESET} - Run critical tools in optimal order")
    print(f"  {BOLD}93.{RESET} {BOLD}Toggle Details{RESET} - Show/hide detailed tool information")
    print(f"  {BOLD}94.{RESET} {BOLD}View Results Summary{RESET} - Show all completed scans and outputs")
    print(f"  {BOLD}95.{RESET} {BOLD}Reset Completion Status{RESET} - Clear all completion markers")
    print(f"  {BOLD} 0.{RESET} {BOLD}Exit{RESET}")
    
    print(f"\n{BOLD}{'='*80}{RESET}")


def run_seek_tool(tool, target_file=None):
    """Run a specific seek tool"""
    script_path = Path(__file__).parent / tool['script']
    
    if not script_path.exists():
        print(f"{RED}[!] Error: {tool['name']} script not found at {script_path}{RESET}")
        return False
    
    print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}Running: {tool['name']}{RESET}")
    print(f"{CYAN}{BOLD}{'='*80}{RESET}")
    print(f"{YELLOW}Description:{RESET} {tool['description']}")
    print(f"{YELLOW}Why Run This:{RESET} {tool['why']}")
    print(f"{YELLOW}Expected Outputs:{RESET} {', '.join(tool['outputs'])}")
    print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
    
    # Prompt for target file if not provided
    if not target_file:
        # Extract default from typical_args (handle both "file" and "-f file" formats)
        default_file = 'iplist.txt'
        args_parts = tool['typical_args'].split()
        for i, part in enumerate(args_parts):
            if not part.startswith('-') and i == 0:
                default_file = part
                break
            elif part in ['-f', '--file'] and i + 1 < len(args_parts):
                default_file = args_parts[i + 1]
                break
        
        target_file = input(f"Enter target IP list file [{default_file}]: ").strip()
        if not target_file:
            target_file = default_file
    
    # Check if target file exists (will be found by seek_utils.find_ip_list in the tool)
    target_path = Path(target_file)
    parent_path = Path(__file__).parent / target_file
    if not target_path.exists() and not parent_path.exists():
        print(f"{YELLOW}[!] Warning: Target file '{target_file}' not found locally{RESET}")
        print(f"{YELLOW}[*] Tool will search in standard locations...{RESET}\n")
    
    # Build command - check if tool uses -f flag or positional argument
    cmd = [sys.executable, str(script_path)]
    
    # Tools that use -f flag
    if tool['name'] in ['DCSeek', 'PrintSeek', 'ShareSeek', 'PanelSeek', 'DbSeek', 'SMBSeek']:
        cmd.extend(['-f', target_file, '-v'])
    elif tool['name'] == 'VulnSeek':
        # VulnSeek v2 with full scan and Nuclei CVE scanning
        cmd.extend(['-f', target_file, '--full', '--nuclei', '-v'])
    else:
        # Tools that use positional argument
        cmd.extend([target_file, '-v'])
    
    print(f"{BLUE}[*] Executing: {' '.join(cmd)}{RESET}\n")
    
    start_time = datetime.now()
    
    try:
        # Run the tool
        result = subprocess.run(cmd, cwd=script_path.parent, capture_output=False, text=True)
        
        end_time = datetime.now()
        duration = (end_time - start_time).total_seconds()
        
        print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
        if result.returncode == 0:
            print(f"{GREEN}[+] {tool['name']} completed successfully in {duration:.2f} seconds{RESET}")
            completed_scans[tool['id']] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            # Find output files
            output_dir = script_path.parent
            found_outputs = []
            for output in tool['outputs']:
                output_path = output_dir / output
                if output_path.exists():
                    found_outputs.append(str(output_path))
            
            if found_outputs:
                scan_outputs[tool['id']] = ', '.join(found_outputs)
                print(f"{GREEN}[+] Output files:{RESET}")
                for output in found_outputs:
                    print(f"    {output}")
            
            # Save status to disk
            save_status()
            
            return True
        else:
            print(f"{RED}[!] {tool['name']} failed with exit code {result.returncode}{RESET}")
            return False
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        return False
    except Exception as e:
        print(f"{RED}[!] Error running {tool['name']}: {str(e)}{RESET}")
        return False
    finally:
        print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")


def run_all_sequential(target_file=None):
    """Run all tools sequentially"""
    print(f"\n{CYAN}{BOLD}Running all tools in sequential mode...{RESET}\n")
    
    if not target_file:
        target_file = input(f"Enter target IP list file [iplist.txt]: ").strip()
        if not target_file:
            target_file = "iplist.txt"
    
    success_count = 0
    fail_count = 0
    
    for tool in SEEK_TOOLS:
        if run_seek_tool(tool, target_file):
            success_count += 1
        else:
            fail_count += 1
        
        if tool != SEEK_TOOLS[-1]:  # Not the last tool
            input(f"\n{YELLOW}Press Enter to continue to next tool...{RESET}")
    
    print(f"\n{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}Sequential Scan Complete{RESET}")
    print(f"{GREEN}Successful: {success_count}{RESET}")
    print(f"{RED}Failed: {fail_count}{RESET}")
    print(f"{BOLD}{'='*80}{RESET}\n")


def run_all_parallel(target_file=None):
    """Run all tools in parallel"""
    print(f"\n{CYAN}{BOLD}Running all tools in parallel mode...{RESET}\n")
    print(f"{YELLOW}Warning: This will execute all 14 tools simultaneously!{RESET}")
    print(f"{YELLOW}This may consume significant system resources.{RESET}\n")
    
    confirm = input("Are you sure you want to continue? (yes/no): ").strip().lower()
    if confirm != 'yes':
        print(f"{YELLOW}Parallel execution cancelled.{RESET}")
        return
    
    if not target_file:
        target_file = input(f"Enter target IP list file [iplist.txt]: ").strip()
        if not target_file:
            target_file = "iplist.txt"
    
    processes = []
    
    print(f"\n{BLUE}[*] Starting all tools in parallel...{RESET}\n")
    
    for tool in SEEK_TOOLS:
        script_path = Path(__file__).parent / tool['script']
        if script_path.exists():
            cmd = [sys.executable, str(script_path), target_file, '-v']
            print(f"{BLUE}[*] Starting: {tool['name']}{RESET}")
            try:
                proc = subprocess.Popen(cmd, cwd=script_path.parent)
                processes.append((tool, proc))
            except Exception as e:
                print(f"{RED}[!] Failed to start {tool['name']}: {str(e)}{RESET}")
    
    print(f"\n{CYAN}[*] All tools started. Waiting for completion...{RESET}\n")
    
    # Wait for all processes to complete
    success_count = 0
    fail_count = 0
    
    for tool, proc in processes:
        proc.wait()
        if proc.returncode == 0:
            print(f"{GREEN}[+] {tool['name']} completed successfully{RESET}")
            completed_scans[tool['id']] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            success_count += 1
        else:
            print(f"{RED}[!] {tool['name']} failed{RESET}")
            fail_count += 1
    
    print(f"\n{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}Parallel Scan Complete{RESET}")
    print(f"{GREEN}Successful: {success_count}{RESET}")
    print(f"{RED}Failed: {fail_count}{RESET}")
    print(f"{BOLD}{'='*80}{RESET}\n")


def run_recommended_sequence(target_file=None):
    """Run recommended critical tools in optimal order"""
    recommended = [tool for tool in SEEK_TOOLS if tool['priority'] in ['CRITICAL', 'HIGH']]
    
    print(f"\n{CYAN}{BOLD}Running recommended sequence (Critical & High priority tools)...{RESET}\n")
    print(f"{YELLOW}This will run {len(recommended)} tools in optimal order:{RESET}")
    for tool in recommended:
        priority_color = get_priority_color(tool['priority'])
        print(f"  {tool['id']}. {tool['name']} {priority_color}[{tool['priority']}]{RESET}")
    print()
    
    if not target_file:
        target_file = input(f"Enter target IP list file [iplist.txt]: ").strip()
        if not target_file:
            target_file = "iplist.txt"
    
    success_count = 0
    fail_count = 0
    
    for tool in recommended:
        if run_seek_tool(tool, target_file):
            success_count += 1
        else:
            fail_count += 1
        
        if tool != recommended[-1]:
            input(f"\n{YELLOW}Press Enter to continue to next tool...{RESET}")
    
    print(f"\n{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}Recommended Sequence Complete{RESET}")
    print(f"{GREEN}Successful: {success_count}{RESET}")
    print(f"{RED}Failed: {fail_count}{RESET}")
    print(f"{BOLD}{'='*80}{RESET}\n")


def view_results_summary():
    """Display summary of completed scans"""
    print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}RESULTS SUMMARY{RESET}")
    print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
    
    if not completed_scans:
        print(f"{YELLOW}No scans completed yet.{RESET}\n")
        return
    
    print(f"{GREEN}Completed Scans: {len(completed_scans)}/{len(SEEK_TOOLS)}{RESET}\n")
    
    for tool in SEEK_TOOLS:
        if tool['id'] in completed_scans:
            print(f"{GREEN}[✓]{RESET} {BOLD}{tool['name']}{RESET}")
            print(f"    Completed: {completed_scans[tool['id']]}")
            if tool['id'] in scan_outputs:
                print(f"    Output: {scan_outputs[tool['id']]}")
            print()
    
    print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")


def reset_completion_status():
    """Reset all completion markers"""
    if not completed_scans:
        print(f"\n{YELLOW}No completion status to reset.{RESET}\n")
        return
    
    print(f"\n{YELLOW}This will clear completion status for {len(completed_scans)} scans.{RESET}")
    confirm = input("Are you sure? (yes/no): ").strip().lower()
    
    if confirm == 'yes':
        reset_status()
        print(f"{GREEN}[+] Status file deleted and memory cleared.{RESET}\n")
    else:
        print(f"{YELLOW}Reset cancelled.{RESET}\n")


def main():
    """Main menu loop"""
    show_details = False
    
    # Load previous status
    load_status()
    
    print_banner()
    
    print(f"\n{CYAN}{BOLD}Welcome to SeekSweet!{RESET}")
    print(f"{WHITE}This orchestration tool guides you through the Seek Tools suite.{RESET}")
    print(f"{WHITE}Tools are organized by phase and priority for optimal workflow.{RESET}")
    
    if completed_scans:
        print(f"{GREEN}[+] Loaded {len(completed_scans)} completed scans from previous session{RESET}")
    
    print()
    
    while True:
        print_menu(show_details)
        
        try:
            choice = input(f"\n{BOLD}Select an option: {RESET}").strip()
            
            if not choice:
                continue
            
            if choice == '0':
                print(f"\n{CYAN}Thanks for using SeekSweet! Happy hunting! 🎯{RESET}\n")
                break
            
            choice_num = int(choice)
            
            if choice_num == 90:
                run_all_sequential()
            elif choice_num == 91:
                run_all_parallel()
            elif choice_num == 92:
                run_recommended_sequence()
            elif choice_num == 93:
                show_details = not show_details
                status = "enabled" if show_details else "disabled"
                print(f"\n{GREEN}[+] Detailed information {status}{RESET}\n")
            elif choice_num == 94:
                view_results_summary()
            elif choice_num == 95:
                reset_completion_status()
            elif 1 <= choice_num <= len(SEEK_TOOLS):
                tool = SEEK_TOOLS[choice_num - 1]
                run_seek_tool(tool)
                input(f"\n{YELLOW}Press Enter to return to menu...{RESET}")
            else:
                print(f"\n{RED}[!] Invalid option. Please try again.{RESET}\n")
        
        except ValueError:
            print(f"\n{RED}[!] Invalid input. Please enter a number.{RESET}\n")
        except KeyboardInterrupt:
            print(f"\n\n{YELLOW}[!] Interrupted by user. Exiting...{RESET}\n")
            break
        except Exception as e:
            print(f"\n{RED}[!] Error: {str(e)}{RESET}\n")


if __name__ == '__main__':
    main()
