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
ORANGE = '\033[38;5;208m'       # Bright orange for [NEW!]
BRIGHT_CYAN = '\033[38;5;51m'   # Brighter cyan for Access phase
PURPLE = '\033[38;5;141m'       # Purple for Assessment phase
LIGHT_BLUE = '\033[38;5;117m'   # Light blue for Web phase
BOLD = '\033[1m'
RESET = '\033[0m'

# Track completed scans
completed_scans = {}
scan_outputs = {}

# Status file for persistent tracking
STATUS_FILE = Path(__file__).parent / '.seeksweet_status.json'

# Centralized logs folder
LOGS_DIR = Path(__file__).parent / 'seekerlogs'

def ensure_logs_dir():
    """Create seekerlogs directory if it doesn't exist"""
    LOGS_DIR.mkdir(exist_ok=True)
    return LOGS_DIR

def copy_outputs_to_logs(tool, tool_dir):
    """Copy tool outputs to centralized seekerlogs folder"""
    try:
        logs_dir = ensure_logs_dir()
        copied_files = []
        
        for output in tool['outputs']:
            source = tool_dir / output
            if source.exists():
                dest = logs_dir / output
                # Copy file
                import shutil
                shutil.copy2(source, dest)
                copied_files.append(output)
        
        if copied_files:
            print(f"{GREEN}[+] Copied {len(copied_files)} file(s) to seekerlogs/{RESET}")
            for f in copied_files:
                print(f"    {GREEN}→{RESET} seekerlogs/{f}")
        
        return True
    except Exception as e:
        print(f"{YELLOW}[!] Warning: Could not copy outputs to logs: {e}{RESET}")
        return False

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
        'description': 'Find Domain Controllers + DC SMB Signing vulnerabilities',
        'why': 'Start here - identifies DCs and critical relay vulnerabilities',
        'outputs': ['dclist.txt', 'dc_smb_status.txt'],
        'typical_args': 'iplist.txt -v',
        'new_features': 'DC SMB signing detection (CRITICAL vulnerability check)'
    },
    {
        'id': 2,
        'name': 'LDAPSeek',
        'script': 'ldapseek/ldapseek.py',
        'priority': 'CRITICAL',
        'phase': 'Discovery',
        'description': 'Enumerate AD users, admins, LAPS passwords, delegation trusts, and password policies',
        'why': 'Essential for users, LAPS passwords, delegation, weak policies',
        'outputs': ['ldaplist.txt', 'users.txt', 'laps_readable.txt', 'delegation_targets.txt', 'password_policy.txt', 'LAPS_ATTACK_GUIDE.txt', 'DELEGATION_ATTACK_GUIDE.txt', 'USERS_ATTACK_GUIDE.txt'],
        'typical_args': 'iplist.txt --full -v',
        'optional_creds': True,
        'new_features': 'LAPS detection, enhanced delegation, password policy'
    },
    {
        'id': 3,
        'name': 'SMBSeek',
        'script': 'smbseek/smbseek.py',
        'priority': 'CRITICAL',
        'phase': 'Discovery',
        'description': 'Find SMB shares + SMB Relay vulnerabilities',
        'why': 'Critical for shares, sensitive data, and SMB relay attacks',
        'outputs': ['smblist.txt', 'sharelist.txt', 'smb_relay_targets.txt', 'SMB_ATTACK_GUIDE.txt'],
        'typical_args': 'iplist.txt -v',
        'new_features': 'SMB signing detection, relay target identification'
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
        'description': 'Kerberoasting + ASREPRoasting with cracking guide',
        'why': 'Extract hashes, get comprehensive cracking strategies',
        'outputs': ['kerblist.txt', 'tgs_hashes.txt', 'asrep_hashes.txt', 'KERBEROS_ATTACK_GUIDE.txt'],
        'typical_args': 'iplist.txt -v',
        'needs_creds': True,
        'new_features': 'Comprehensive hash cracking guide with GPU time estimates'
    },
    {
        'id': 6,
        'name': 'CredSeek',
        'script': 'credseek/credseek.py',
        'priority': 'HIGH',
        'phase': 'Authentication',
        'description': 'Find credential stores, password vaults, and GPP passwords',
        'why': 'Locate stored credentials, password managers, and exploit MS14-025 GPP vulnerability',
        'outputs': ['credlist.txt', 'cred_details.txt', 'cred_details.json', 'GPP_ATTACK_GUIDE.txt'],
        'typical_args': 'iplist.txt --deep -v (or --gpp dclist.txt for GPP extraction)',
        'new_features': 'GPP password extraction with comprehensive attack guide'
    },
    {
        'id': 7,
        'name': 'WinRMSeek',
        'script': 'winrmseek/winrmseek.py',
        'priority': 'MEDIUM',
        'phase': 'Access',
        'description': 'Find WinRM endpoints, validate credentials, and test remote command execution',
        'why': 'Identify remote administration access points with connection validation',
        'outputs': ['winrmlist.txt', 'winrm_access.txt', 'winrm_details.txt', 'winrm_details.json', 'WINRM_ATTACK_GUIDE.txt'],
        'typical_args': 'iplist.txt -t -u user -p pass -v',
        'new_features': 'Real connection testing + command execution + attack guide',
        'optional_creds': True
    },
    {
        'id': 8,
        'name': 'WebSeek',
        'script': 'webseek/webseek.py',
        'priority': 'HIGH',
        'phase': 'Web',
        'description': 'Nuclei web vuln scanner (5000+ templates)',
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
        'description': 'Find database servers (optional: test creds)',
        'why': 'Identify database servers for potential data extraction',
        'outputs': ['dblist.txt', 'db_creds.txt', 'db_details.txt'],
        'typical_args': 'iplist.txt -v',
        'optional_creds': True
    },
    {
        'id': 11,
        'name': 'BackupSeek',
        'script': 'backupseek/backupseek.py',
        'priority': 'MEDIUM',
        'phase': 'Services',
        'description': 'Find backup systems and NAS infrastructure',
        'why': 'Locate backup servers and NAS devices - often contain full system images and backups',
        'outputs': ['backuplist.txt', 'backup_details.txt', 'backup_details.json'],
        'typical_args': 'iplist.txt -v',
        'new_features': 'NAS detection (Synology, QNAP, TrueNAS, Netgear, Buffalo)'
    },
    {
        'id': 12,
        'name': 'PrintSeek',
        'script': 'printseek/printseek.py',
        'priority': 'MEDIUM',
        'phase': 'Services',
        'description': 'Find print servers and enumerate printers - Remember: Check address books for user enumeration and test default admin passwords',
        'why': 'Printer address books contain user lists, and default admin credentials are a common medium finding',
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
        'description': 'Scan for critical CVEs: EternalBlue, BlueKeep, SMBGhost, Zerologon, and 100+ more',
        'why': 'Final assessment - comprehensive CVE detection with 10+ nmap checks and Nuclei CVE templates',
        'outputs': ['CRITICAL_VULNS.txt', 'vulnlist.txt', 'vuln_details.json', 'nuclei_cve_results/'],
        'typical_args': '-f iplist.txt --full --nuclei -v'
    },
    {
        'id': 15,
        'name': 'BloodSeek',
        'script': 'bloodseek/bloodseek.py',
        'priority': 'CRITICAL',
        'phase': 'Assessment',
        'description': 'Collect AD data with BloodHound to find paths to Domain Admin and identify privilege escalation routes',
        'why': 'Essential for Active Directory attack path analysis and privilege escalation mapping',
        'outputs': ['bloodlist.txt', 'BLOODHOUND_GUIDE.txt', '*.json (BloodHound data)'],
        'typical_args': '-d DOMAIN.LOCAL -u user -p password -dc 10.10.10.10 --method All',
        'needs_creds': True,
        'new_features': 'BloodHound wrapper with 11 collection methods + attack guide'
    },
    {
        'id': 16,
        'name': 'SSLSeek',
        'script': 'sslseek/sslseek.py',
        'priority': 'HIGH',
        'phase': 'Services',
        'description': 'SSL/TLS security scanner wrapper with comprehensive vulnerability guide',
        'why': 'Identify SSL/TLS misconfigurations, weak ciphers, and critical vulnerabilities (Heartbleed, POODLE, etc.)',
        'outputs': ['ssllist.txt', 'SSL_ATTACK_GUIDE.txt', 'testssl_*.json'],
        'typical_args': 'target.com --full',
        'new_features': 'testssl.sh wrapper with 10+ CVE checks + attack guide'
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
        'Access': BRIGHT_CYAN,
        'Web': LIGHT_BLUE,
        'Services': GREEN,
        'Assessment': PURPLE
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


def wrap_text(text, width, indent="      "):
    """Wrap text to fit within specified width, preserving indent"""
    words = text.split()
    lines = []
    current_line = []
    current_length = 0
    
    for word in words:
        # Account for space between words
        word_length = len(word) + (1 if current_line else 0)
        
        if current_length + word_length <= width:
            current_line.append(word)
            current_length += word_length
        else:
            # Finish current line and start new one
            if current_line:
                lines.append(indent + ' '.join(current_line))
            current_line = [word]
            current_length = len(word)
    
    # Add remaining words
    if current_line:
        lines.append(indent + ' '.join(current_line))
    
    return lines


def format_tool_lines(tool, show_details):
    """Format a tool's display lines"""
    lines = []
    status = f" {GREEN}✓ {BOLD}COMPLETE{RESET}" if tool['id'] in completed_scans else ""
    priority_color = get_priority_color(tool['priority'])
    
    # NEW indicator for enhanced tools
    new_indicator = f" {ORANGE}[NEW!]{RESET}" if tool.get('new_features') else ""
    
    # Credential indicator
    cred_indicator = " 🔑" if tool.get('needs_creds') or tool.get('optional_creds') else ""
    
    # Main line
    lines.append(f"  {BOLD}{tool['id']:2d}.{RESET} {BOLD}{tool['name']}{cred_indicator}{RESET} {priority_color}[{tool['priority']}]{RESET}{new_indicator}{status}")
    
    # Description - wrap if longer than 52 chars (column width)
    desc = tool['description']
    if len(desc) <= 52:
        lines.append(f"      {desc}")
    else:
        wrapped = wrap_text(desc, 52, "      ")
        lines.extend(wrapped)
    
    # New features - wrap if longer than 50 chars (leaving room for "✨ NEW: ")
    if tool.get('new_features'):
        new_feat = tool['new_features']
        if len(new_feat) <= 44:  # 52 - 8 for "✨ NEW: "
            lines.append(f"      {ORANGE}✨ NEW:{RESET} {new_feat}")
        else:
            # First line with label
            words = new_feat.split()
            first_line = []
            first_length = 0
            remaining_words = []
            
            for i, word in enumerate(words):
                word_length = len(word) + (1 if first_line else 0)
                if first_length + word_length <= 44:
                    first_line.append(word)
                    first_length += word_length
                else:
                    remaining_words = words[i:]
                    break
            
            lines.append(f"      {ORANGE}✨ NEW:{RESET} {' '.join(first_line)}")
            
            # Remaining lines (indented further)
            if remaining_words:
                wrapped = wrap_text(' '.join(remaining_words), 46, "             ")
                lines.extend(wrapped)
    
    # Optional details
    if show_details:
        why = tool['why']
        if len(why) <= 46:  # 52 - 6 for "Why: "
            lines.append(f"      {YELLOW}Why:{RESET} {why}")
        else:
            wrapped = wrap_text(why, 46, "           ")
            lines.append(f"      {YELLOW}Why:{RESET} {wrapped[0][11:]}")  # First line with label
            lines.extend(wrapped[1:])  # Remaining lines
    
    # Output location if completed
    if tool['id'] in completed_scans and tool['id'] in scan_outputs:
        output = scan_outputs[tool['id']]
        if len(output) <= 45:  # 52 - 7 for "Output: "
            lines.append(f"      {GREEN}Output:{RESET} {output}")
        else:
            wrapped = wrap_text(output, 45, "             ")
            lines.append(f"      {GREEN}Output:{RESET} {wrapped[0][13:]}")
            lines.extend(wrapped[1:])
    
    return lines


def print_menu(show_details=False):
    """Print the main menu with two-column layout - phases in columns"""
    print(f"\n{BOLD}{'='*120}{RESET}")
    print(f"{BOLD}{CYAN}SEEKSWEET MENU - Select a Tool to Run{RESET}")
    print(f"{BOLD}{'='*120}{RESET}")
    
    # Legend
    print(f"{CYAN}Legend:{RESET} 🔑 = Supports/requires credentials for enhanced enumeration  |  {ORANGE}[NEW!]{RESET} = Recently enhanced with new features\n")
    
    # Highlight new features
    print(f"{ORANGE}{BOLD}✨ NEW FEATURES ADDED:{RESET} SMB Relay Detection, LAPS Enumeration, Enhanced Delegation, Password Policy, Kerberos Cracking Guide")
    print(f"{ORANGE}   Tools enhanced: DCSeek, SMBSeek, LDAPSeek, KerbSeek{RESET}\n")
    
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
        print(f"{pad_with_ansi(left_line, 62)}  {right_line}")
    
    print(f"\n{BOLD}═══ SPECIAL OPTIONS ═══{RESET}")
    print(f"  {BOLD}89.{RESET} {BOLD}Find Alive Hosts{RESET} - Quick discovery to identify live targets (updates iplist.txt)")
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
    
    # Check if tool needs or supports credentials
    username = None
    password = None
    if tool.get('needs_creds'):
        print(f"{YELLOW}[!] {tool['name']} requires domain credentials for authenticated attacks{RESET}")
        username = input(f"{CYAN}Enter username (user@domain or DOMAIN\\user): {RESET}").strip()
        if username:
            password = input(f"{CYAN}Enter password: {RESET}").strip()
            print(f"{GREEN}[+] Credentials captured{RESET}")
        else:
            print(f"{RED}[!] Credentials required. Exiting.{RESET}")
            return False
    elif tool.get('optional_creds'):
        print(f"{YELLOW}[?] {tool['name']} supports optional credentials for authentication testing{RESET}")
        sys.stdout.flush()
        use_creds = input(f"{CYAN}Test with credentials? [y/N]: {RESET}").strip().lower()
        if use_creds in ['y', 'yes']:
            print()  # Add blank line for clarity
            username = input(f"{CYAN}Enter username: {RESET}").strip()
            if username:
                password = input(f"{CYAN}Enter password: {RESET}").strip()
                print(f"{GREEN}[+] Credentials captured (username: {username}){RESET}")
    
    # Build command - check if tool uses -f flag or positional argument
    cmd = [sys.executable, str(script_path)]
    
    # Tools that use -f flag
    if tool['name'] in ['DCSeek', 'PrintSeek', 'ShareSeek', 'PanelSeek', 'DbSeek', 'SMBSeek']:
        cmd.extend(['-f', target_file, '-v'])
        # Add credentials if provided
        if username and password:
            cmd.extend(['-u', username, '-p', password])
    elif tool['name'] == 'BackupSeek':
        # BackupSeek with full scan and credential testing
        cmd.extend([target_file, '--full', '--test-creds', '-v'])
    elif tool['name'] == 'VulnSeek':
        # VulnSeek v2 with full scan and Nuclei CVE scanning
        cmd.extend(['-f', target_file, '--full', '--nuclei', '-v'])
    elif tool['name'] == 'KerbSeek':
        # KerbSeek requires credentials and uses positional arg
        cmd.extend([target_file, '-v'])
        if username and password:
            cmd.extend(['-u', username, '-p', password])
    elif tool['name'] in ['LDAPSeek', 'WinRMSeek']:
        # LDAPSeek and WinRMSeek with optional credentials (positional arg)
        cmd.extend([target_file, '-v'])
        
        # For WinRMSeek, prompt for credentials if not provided
        if tool['name'] == 'WinRMSeek':
            if not username or not password:
                print(f"{YELLOW}[*] WinRMSeek can test connections with credentials{RESET}")
                sys.stdout.flush()
                test_creds = input(f"{CYAN}Do you want to test WinRM connections? (y/n): {RESET}").strip().lower()
                
                if test_creds == 'y':
                    if not username:
                        username = input(f"{CYAN}Username: {RESET}").strip()
                    if not password:
                        password = input(f"{CYAN}Password: {RESET}").strip()
                    
                    if username and password:
                        cmd.extend(['-t', '-u', username, '-p', password])
                        print(f"{GREEN}[+] Will test connections with credentials (username: {username}){RESET}")
            else:
                # Credentials already provided, add connection testing flag
                cmd.extend(['-t', '-u', username, '-p', password])
        else:
            # LDAPSeek
            if username and password:
                cmd.extend(['-u', username, '-p', password])
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
                
                # Copy outputs to centralized logs folder
                print()
                copy_outputs_to_logs(tool, output_dir)
            
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


def run_alive_check():
    """Run alive host discovery and update iplist.txt"""
    print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD}ALIVE HOST DISCOVERY{RESET}")
    print(f"{CYAN}{BOLD}{'='*80}{RESET}\n")
    
    print(f"{YELLOW}This will:{RESET}")
    print(f"  1. Scan your IP list for alive hosts")
    print(f"  2. Backup original list to iplist_full.txt")
    print(f"  3. Replace iplist.txt with only alive hosts")
    print(f"  4. All other tools will then only scan alive hosts\n")
    
    target_file = input(f"{CYAN}Enter IP list file to scan [iplist.txt]: {RESET}").strip()
    if not target_file:
        target_file = "iplist.txt"
    
    if not os.path.exists(target_file):
        print(f"{RED}[!] Error: File not found: {target_file}{RESET}\n")
        return
    
    # Count targets
    with open(target_file, 'r') as f:
        target_count = len([line for line in f if line.strip() and not line.startswith('#')])
    
    print(f"{GREEN}[+] Found {target_count} target(s) in {target_file}{RESET}\n")
    
    # Ask for scan options
    print(f"{CYAN}[?] Nmap timing template:{RESET}")
    print(f"  0. Paranoid (slowest, most stealthy)")
    print(f"  1. Sneaky")
    print(f"  2. Polite (recommended - good balance)")
    print(f"  3. Normal")
    print(f"  4. Aggressive (faster)")
    print(f"  5. Insane (fastest, least accurate)")
    
    timing = input(f"{CYAN}Choose timing [0-5, default: 2]: {RESET}").strip()
    if timing not in ['0', '1', '2', '3', '4', '5']:
        timing = '2'
    
    verbose_choice = input(f"{CYAN}Show verbose nmap output? [y/N]: {RESET}").strip().lower()
    
    print(f"\n{CYAN}[*] Starting nmap host discovery (this may take a few minutes)...{RESET}\n")
    
    # Run aliveseek.py
    script_path = Path(__file__).parent / 'aliveseek' / 'aliveseek.py'
    
    try:
        cmd = [
            sys.executable,
            str(script_path),
            target_file,
            '-T', timing,
            '--output', 'iplist.txt',
            '--backup', 'iplist_full.txt'
        ]
        
        if verbose_choice == 'y':
            cmd.append('-v')
        
        result = subprocess.run(cmd)
        
        if result.returncode == 0:
            print(f"\n{GREEN}{BOLD}[+] Alive host discovery complete!{RESET}")
            print(f"{GREEN}[+] iplist.txt now contains only alive hosts{RESET}")
            print(f"{GREEN}[+] Original list backed up to iplist_full.txt{RESET}\n")
        else:
            print(f"\n{RED}[!] Error during alive host discovery{RESET}\n")
    
    except Exception as e:
        print(f"{RED}[!] Error running alive check: {e}{RESET}\n")
    
    input(f"{YELLOW}Press Enter to return to menu...{RESET}")


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
            new_indicator = f" {MAGENTA}[ENHANCED!]{RESET}" if tool.get('new_features') else ""
            print(f"{GREEN}[✓]{RESET} {BOLD}{tool['name']}{RESET}{new_indicator}")
            print(f"    Completed: {completed_scans[tool['id']]}")
            if tool['id'] in scan_outputs:
                print(f"    Output: {scan_outputs[tool['id']]}")
            
            # List expected output files (including new ones)
            if tool.get('outputs'):
                print(f"    Expected Files: {', '.join(tool['outputs'][:5])}")
                if len(tool['outputs']) > 5:
                    print(f"                    {', '.join(tool['outputs'][5:])}")
            
            # Highlight new features
            if tool.get('new_features'):
                print(f"    {MAGENTA}✨ New:{RESET} {tool['new_features']}")
            
            print()
    
    # Show new attack guides available
    new_guides = []
    for tool in SEEK_TOOLS:
        if tool['id'] in completed_scans and tool.get('new_features'):
            for output in tool.get('outputs', []):
                if 'GUIDE' in output.upper():
                    new_guides.append(output)
    
    if new_guides:
        print(f"{MAGENTA}{BOLD}✨ NEW ATTACK GUIDES GENERATED:{RESET}")
        for guide in set(new_guides):
            print(f"   • {guide}")
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
    
    # Ensure seekerlogs directory exists
    ensure_logs_dir()
    
    print_banner()
    
    print(f"\n{CYAN}{BOLD}Welcome to SeekSweet!{RESET}")
    print(f"{WHITE}This orchestration tool guides you through the Seek Tools suite.{RESET}")
    print(f"{WHITE}Tools are organized by phase and priority for optimal workflow.{RESET}")
    print(f"{GREEN}[+] All scan results will be copied to: seekerlogs/{RESET}")
    
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
            
            if choice_num == 89:
                run_alive_check()
            elif choice_num == 90:
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
