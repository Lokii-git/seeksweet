"""
Shared utilities for SeekSweet tools
"""
import os
import sys


def find_ip_list(filename: str) -> str:
    """
    Find IP list file in multiple locations:
    1. Exact path if provided (absolute or relative to CWD)
    2. Current directory
    3. Parent directory (seeksweet root)
    4. Two levels up (for tools in subfolders)
    
    Args:
        filename: The IP list filename or path
        
    Returns:
        Absolute path to the IP list file
        
    Raises:
        SystemExit: If file cannot be found
    """
    # If it's an absolute path or exists as-is, use it
    if os.path.isabs(filename) or os.path.exists(filename):
        if os.path.exists(filename):
            return os.path.abspath(filename)
    
    # Get the script's directory
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    
    # Search locations
    search_paths = [
        filename,  # Current working directory
        os.path.join(script_dir, filename),  # Script's directory
        os.path.join(script_dir, '..', filename),  # Parent directory (seeksweet root)
        os.path.join(script_dir, '..', '..', filename),  # Two levels up
        os.path.join(os.getcwd(), filename),  # Explicit CWD
    ]
    
    # Try each location
    for path in search_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path) and os.path.isfile(abs_path):
            return abs_path
    
    # If not found, show helpful error
    print(f"[!] Error: Could not find IP list file: {filename}")
    print(f"[*] Searched in:")
    for path in search_paths:
        print(f"    - {os.path.abspath(path)}")
    print(f"\n[*] Current working directory: {os.getcwd()}")
    print(f"[*] Script directory: {script_dir}")
    sys.exit(1)
