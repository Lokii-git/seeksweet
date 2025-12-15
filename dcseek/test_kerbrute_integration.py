#!/usr/bin/env python3
"""
Test script for DCSeek Kerbrute integration
Demonstrates the new username generation functionality
"""

import sys
import os

# Add the dcseek directory to path
sys.path.insert(0, os.path.dirname(__file__))

from dcseek import (
    generate_usernames, 
    load_names_from_file,
    save_usernames,
    get_username_format
)

def test_username_generation():
    """Test username generation functionality"""
    
    print("="*60)
    print("DCSeek Kerbrute Integration Test")
    print("="*60)
    
    # Create sample name files for testing
    sample_first_names = ["john", "jane", "bob", "alice", "mike"]
    sample_last_names = ["smith", "doe", "johnson", "brown", "wilson"]
    
    print(f"Sample first names: {sample_first_names}")
    print(f"Sample last names: {sample_last_names}")
    print()
    
    # Test different formats
    formats = [
        ('{f}{last}', 'flast'),
        ('{f}.{last}', 'f.last'), 
        ('{first}.{last}', 'first.last'),
        ('{first}{last}', 'firstlast'),
        ('{last}{f}', 'lastf'),
        ('{first}_{last}', 'first_last')
    ]
    
    for format_string, desc in formats:
        print(f"Testing format: {format_string} ({desc})")
        usernames = generate_usernames(sample_first_names, sample_last_names, format_string, 50)
        print(f"Generated {len(usernames)} usernames:")
        print(f"  Examples: {', '.join(usernames[:5])}")
        
        if usernames:
            # Test saving
            filename = save_usernames(usernames, "test", desc)
            if filename:
                print(f"  Saved to: {filename}")
                # Clean up test file
                try:
                    os.remove(filename)
                    print(f"  Cleaned up test file")
                except:
                    pass
        print()
    
    print("Username generation test completed!")

def create_sample_name_files():
    """Create sample name files for testing"""
    
    sample_first_names = [
        "john", "jane", "bob", "alice", "mike", "sarah", "david", "mary",
        "james", "jennifer", "robert", "lisa", "william", "karen", "richard"
    ]
    
    sample_last_names = [
        "smith", "doe", "johnson", "brown", "wilson", "moore", "taylor", 
        "anderson", "thomas", "jackson", "white", "harris", "martin", "thompson"
    ]
    
    # Create sample names.txt
    with open("names.txt", "w") as f:
        for name in sample_first_names:
            f.write(f"{name}\n")
    
    # Create sample familynames file
    with open("familynames-usa-top1000.txt", "w") as f:
        for name in sample_last_names:
            f.write(f"{name}\n")
    
    print("Created sample name files:")
    print("  - names.txt (15 first names)")
    print("  - familynames-usa-top1000.txt (14 last names)")
    print("  - Total possible combinations: 210")
    
    return "names.txt", "familynames-usa-top1000.txt"

def test_file_loading():
    """Test loading names from files"""
    
    print("\n" + "="*60)
    print("Testing file loading functionality")  
    print("="*60)
    
    # Create sample files
    first_file, last_file = create_sample_name_files()
    
    # Test loading
    first_names = load_names_from_file(first_file)
    last_names = load_names_from_file(last_file)
    
    print(f"Loaded {len(first_names)} first names from {first_file}")
    print(f"Loaded {len(last_names)} last names from {last_file}")
    
    if first_names and last_names:
        print("File loading test: PASSED")
        
        # Test username generation with loaded files
        print(f"\nGenerating usernames with {f}{last} format...")
        usernames = generate_usernames(first_names, last_names, '{f}{last}', 100)
        print(f"Generated {len(usernames)} usernames")
        print(f"Sample usernames: {', '.join(usernames[:10])}")
        
        # Save test file
        filename = save_usernames(usernames, "testdomain", "flast")
        print(f"Saved to: {filename}")
        
        return filename
    else:
        print("File loading test: FAILED")
        return None

def main():
    """Main test function"""
    
    try:
        # Test 1: Username generation
        test_username_generation()
        
        # Test 2: File loading and real generation
        saved_file = test_file_loading()
        
        print("\n" + "="*60)
        print("DCSeek Kerbrute Integration - All Tests Completed!")
        print("="*60)
        
        if saved_file:
            print(f"Sample username file created: {saved_file}")
            print("You can now use this file for testing with Kerbrute:")
            print(f"  kerbrute userenum --dc <DC_IP> -d <DOMAIN> {saved_file}")
        
        print("\nTo test the full DCSeek integration:")
        print("  python dcseek.py --help")
        print("  python dcseek.py -f iplist.txt --kerbrute --domain test.local")
        
    except Exception as e:
        print(f"Test failed with error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()