#!/usr/bin/env python3
"""
ThoughtLeadershipSeek v1.0 - Thought Leadership Content Discovery
Identify thought leadership resources and industry insights on target domains

Features:
- Discover blogs, whitepapers, and research publications
- Identify conference presentations and webinars
- Track industry thought leaders and subject matter experts
- Monitor technical documentation and knowledge bases
- Social media presence analysis
- Patent and research paper discovery

Usage:
    ./thoughtleadershipseek.py -f iplist.txt -v
    ./thoughtleadershipseek.py -d example.com --full
    ./thoughtleadershipseek.py --domains domains.txt -o output/
    
Output:
    thoughtleadershiplist.txt       - Discovered thought leadership resources
    thought_leadership_details.txt  - Detailed findings
    thought_leadership_details.json - JSON formatted results
    THOUGHT_LEADERSHIP_GUIDE.txt    - Comprehensive analysis guide
"""

import socket
import subprocess
import sys
import json
import argparse
import os
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import re

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
████████╗██╗  ██╗ ██████╗ ██╗   ██╗ ██████╗ ██╗  ██╗████████╗
╚══██╔══╝██║  ██║██╔═══██╗██║   ██║██╔════╝ ██║  ██║╚══██╔══╝
   ██║   ███████║██║   ██║██║   ██║██║  ███╗███████║   ██║   
   ██║   ██╔══██║██║   ██║██║   ██║██║   ██║██╔══██║   ██║   
   ██║   ██║  ██║╚██████╔╝╚██████╔╝╚██████╔╝██║  ██║   ██║   
   ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
                                                               
██╗     ███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗██╗  ██╗██╗██████╗ 
██║     ██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝██║  ██║██║██╔══██╗
██║     █████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗███████║██║██████╔╝
██║     ██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║██╔══██║██║██╔═══╝ 
███████╗███████╗██║  ██║██████╔╝███████╗██║  ██║███████║██║  ██║██║██║     
╚══════╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝     
{RESET}
{YELLOW}ThoughtLeadershipSeek v1.0 - Thought Leadership Discovery{RESET}
{BLUE}Identify thought leadership content and industry insights{RESET}
{GREEN}github.com/Lokii-git/seeksweet{RESET}
"""

# Common thought leadership paths
TL_PATHS = [
    '/blog',
    '/insights',
    '/resources',
    '/whitepapers',
    '/research',
    '/publications',
    '/news',
    '/press',
    '/media',
    '/events',
    '/webinars',
    '/case-studies',
    '/knowledge-base',
    '/documentation',
    '/articles',
    '/thought-leadership'
]

# Social media platforms
SOCIAL_PLATFORMS = [
    'linkedin.com',
    'twitter.com',
    'x.com',
    'youtube.com',
    'medium.com',
    'github.com',
    'slideshare.net'
]


def print_banner():
    """Print the tool banner"""
    print(BANNER)


def resolve_domain(domain):
    """Resolve domain to IP address"""
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror:
        return None


def check_url(url, timeout=5):
    """Check if a URL is accessible"""
    try:
        # Disable SSL warnings for self-signed certificates during reconnaissance
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        # Note: SSL verification is disabled for reconnaissance purposes to detect
        # sites with self-signed or expired certificates. In production, consider
        # adding a --verify-ssl flag to control this behavior.
        response = requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return response.status_code, response.url, len(response.content)
    except Exception as e:
        return None, None, 0


def discover_thought_leadership(domain, verbose=False):
    """Discover thought leadership resources on a domain"""
    results = {
        'domain': domain,
        'ip': None,
        'resources': [],
        'social_media': [],
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    if verbose:
        print(f"\n{CYAN}[*] Analyzing domain: {domain}{RESET}")
    
    # Resolve domain
    ip = resolve_domain(domain)
    results['ip'] = ip
    
    if ip:
        if verbose:
            print(f"{GREEN}[+] Resolved to: {ip}{RESET}")
    else:
        if verbose:
            print(f"{YELLOW}[!] Could not resolve domain{RESET}")
        return results
    
    # Check for common thought leadership paths
    if verbose:
        print(f"{CYAN}[*] Checking for thought leadership resources...{RESET}")
    
    for path in TL_PATHS:
        for scheme in ['https', 'http']:
            url = f"{scheme}://{domain}{path}"
            status, final_url, size = check_url(url)
            
            if status and status < 400:
                resource = {
                    'url': url,
                    'final_url': final_url,
                    'status': status,
                    'size': size,
                    'type': path.strip('/')
                }
                results['resources'].append(resource)
                
                if verbose:
                    print(f"{GREEN}[+] Found: {url} [{status}]{RESET}")
                break  # Found with this scheme, no need to try the other
    
    # Check for social media presence
    if verbose:
        print(f"{CYAN}[*] Checking social media presence...{RESET}")
    
    # Extract company/org name from domain
    # Handle subdomains by taking the second-to-last part for common TLDs
    domain_parts = domain.split('.')
    if len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'gov', 'edu', 'org', 'net']:
        # e.g., blog.company.co.uk -> company
        org_name = domain_parts[-3]
    elif len(domain_parts) >= 2:
        # e.g., blog.company.com -> company, or company.com -> company
        org_name = domain_parts[-2]
    else:
        # Single part domain, use as-is
        org_name = domain_parts[0]
    
    for platform in SOCIAL_PLATFORMS:
        platform_domain = platform.split('.')[0]
        for scheme in ['https', 'http']:
            url = f"{scheme}://{platform}/{org_name}"
            status, final_url, size = check_url(url)
            
            if status and status < 400:
                social = {
                    'platform': platform_domain,
                    'url': url,
                    'final_url': final_url,
                    'status': status
                }
                results['social_media'].append(social)
                
                if verbose:
                    print(f"{GREEN}[+] Social: {platform_domain} - {url}{RESET}")
                break
    
    return results


def generate_guide(output_dir):
    """Generate comprehensive thought leadership analysis guide"""
    guide_content = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                  THOUGHT LEADERSHIP ANALYSIS GUIDE                           ║
║           Comprehensive Intelligence Gathering Methodology                   ║
╚══════════════════════════════════════════════════════════════════════════════╝

═══════════════════════════════════════════════════════════════════════════════
SECTION 1: OVERVIEW
═══════════════════════════════════════════════════════════════════════════════

Thought leadership content provides valuable intelligence about:
- Technical expertise and specializations
- Industry focus and market positioning
- Key personnel and subject matter experts
- Technology stack and methodologies
- Business challenges and solutions
- Strategic partnerships and collaborations
- Future roadmaps and innovations

═══════════════════════════════════════════════════════════════════════════════
SECTION 2: RESOURCE TYPES
═══════════════════════════════════════════════════════════════════════════════

BLOGS & ARTICLES
- Technical insights and engineering practices
- Security posture and awareness
- Development methodologies
- Technology adoption patterns

WHITEPAPERS & RESEARCH
- Deep technical analysis
- Security implementations
- Architecture decisions
- Best practices and standards

WEBINARS & PRESENTATIONS
- Live demonstrations and POCs
- Technology showcases
- Industry event participation
- Educational content

CASE STUDIES
- Client success stories
- Implementation details
- Problem-solving approaches
- Technology integrations

═══════════════════════════════════════════════════════════════════════════════
SECTION 3: SOCIAL MEDIA ANALYSIS
═══════════════════════════════════════════════════════════════════════════════

LINKEDIN
- Employee profiles and roles
- Company updates and announcements
- Technical articles and posts
- Network connections and partnerships

GITHUB
- Public repositories
- Code samples and tools
- Development activity
- Technology stack indicators

TWITTER/X
- Industry engagement
- Real-time updates
- Thought leaders and influencers
- Event participation

YOUTUBE
- Technical demonstrations
- Conference talks
- Product showcases
- Educational content

═══════════════════════════════════════════════════════════════════════════════
SECTION 4: INTELLIGENCE GATHERING METHODOLOGY
═══════════════════════════════════════════════════════════════════════════════

STEP 1: CONTENT DISCOVERY
1. Identify all thought leadership resources
2. Catalog content types and topics
3. Map key authors and contributors
4. Track publication frequency

STEP 2: TECHNICAL ANALYSIS
1. Extract technology mentions
2. Identify security discussions
3. Document architecture patterns
4. Note compliance references

STEP 3: PERSONNEL MAPPING
1. Identify key personnel
2. Map expertise areas
3. Track social media presence
4. Document speaking engagements

STEP 4: COMPETITIVE INTELLIGENCE
1. Industry positioning
2. Market focus areas
3. Strategic partnerships
4. Technology differentiators

═══════════════════════════════════════════════════════════════════════════════
SECTION 5: RECONNAISSANCE APPLICATIONS
═══════════════════════════════════════════════════════════════════════════════

SOCIAL ENGINEERING
- Employee targeting based on expertise
- Phishing campaigns using relevant topics
- Pretexting with industry knowledge
- Authority exploitation through role identification

TECHNICAL RECON
- Technology stack enumeration
- Security posture assessment
- Vulnerability research vectors
- API and integration discovery

OSINT CORRELATION
- Cross-reference with other sources
- Personnel background checks
- Company relationship mapping
- Supply chain analysis

═══════════════════════════════════════════════════════════════════════════════
SECTION 6: TOOLS & TECHNIQUES
═══════════════════════════════════════════════════════════════════════════════

WEB SCRAPING
# Using wget to mirror thought leadership content
wget --mirror --convert-links --adjust-extension \\
     --page-requisites --no-parent \\
     https://example.com/blog/

CONTENT ANALYSIS
# Extract metadata from PDFs
exiftool whitepaper.pdf

# Extract emails and names from content
grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}" content.txt

SOCIAL MEDIA ENUMERATION
# LinkedIn company enumeration
# Twitter account discovery
# GitHub organization repositories

AUTOMATED MONITORING
# Set up RSS feeds for blog updates
# Configure alerts for new publications
# Track social media activity

═══════════════════════════════════════════════════════════════════════════════
SECTION 7: REPORTING & DOCUMENTATION
═══════════════════════════════════════════════════════════════════════════════

Create comprehensive intelligence reports including:

1. EXECUTIVE SUMMARY
   - Organization overview
   - Key findings
   - Strategic recommendations

2. TECHNICAL INTELLIGENCE
   - Technology stack
   - Security posture indicators
   - Development practices
   - Infrastructure insights

3. PERSONNEL INTELLIGENCE
   - Key decision makers
   - Technical experts
   - Contact information
   - Areas of expertise

4. COMPETITIVE ANALYSIS
   - Market positioning
   - Differentiators
   - Partnerships
   - Industry influence

═══════════════════════════════════════════════════════════════════════════════
SECTION 8: OPERATIONAL SECURITY
═══════════════════════════════════════════════════════════════════════════════

OPSEC CONSIDERATIONS
- Use VPNs or proxies for reconnaissance
- Avoid detection through rate limiting
- Respect robots.txt and terms of service (for authorized testing)
- Document all intelligence gathering activities
- Maintain chain of custody for evidence

LEGAL & ETHICAL
- Obtain proper authorization for assessment
- Follow rules of engagement
- Respect privacy laws and regulations
- Use gathered intelligence responsibly
- Report findings through proper channels

═══════════════════════════════════════════════════════════════════════════════
SECTION 9: REFERENCES
═══════════════════════════════════════════════════════════════════════════════

OSINT FRAMEWORKS
- OSINT Framework (osintframework.com)
- Maltego
- theHarvester
- Shodan
- SpiderFoot

SOCIAL MEDIA TOOLS
- Social-Analyzer
- Twint (Twitter)
- LinkedIn Intelligence
- GitHarvester

CONTENT ANALYSIS
- Metagoofil (metadata extraction)
- FOCA (fingerprinting)
- ExifTool
- Wayback Machine (archive.org)

═══════════════════════════════════════════════════════════════════════════════

Generated by ThoughtLeadershipSeek v1.0
Part of the SeekSweet reconnaissance suite
https://github.com/Lokii-git/seeksweet

Remember: Always obtain proper authorization before conducting reconnaissance!

═══════════════════════════════════════════════════════════════════════════════
"""
    
    guide_path = output_dir / 'THOUGHT_LEADERSHIP_GUIDE.txt'
    with open(guide_path, 'w') as f:
        f.write(guide_content)
    
    return guide_path


def save_results(all_results, output_dir):
    """Save results to output files"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save simple list
    list_file = output_dir / 'thoughtleadershiplist.txt'
    with open(list_file, 'w') as f:
        f.write(f"Thought Leadership Discovery Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        for result in all_results:
            if result['resources'] or result['social_media']:
                f.write(f"Domain: {result['domain']}\n")
                f.write(f"IP: {result['ip']}\n")
                f.write(f"Resources found: {len(result['resources'])}\n")
                f.write(f"Social media: {len(result['social_media'])}\n")
                f.write("-" * 80 + "\n")
    
    # Save detailed results
    details_file = output_dir / 'thought_leadership_details.txt'
    with open(details_file, 'w') as f:
        f.write(f"Thought Leadership Discovery - Detailed Results\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        for result in all_results:
            f.write(f"\nDOMAIN: {result['domain']}\n")
            f.write(f"IP: {result['ip']}\n")
            f.write(f"Timestamp: {result['timestamp']}\n")
            f.write("-" * 80 + "\n")
            
            if result['resources']:
                f.write("\nTHOUGHT LEADERSHIP RESOURCES:\n")
                for resource in result['resources']:
                    f.write(f"  Type: {resource['type']}\n")
                    f.write(f"  URL: {resource['url']}\n")
                    f.write(f"  Status: {resource['status']}\n")
                    f.write(f"  Size: {resource['size']} bytes\n")
                    if resource['final_url'] != resource['url']:
                        f.write(f"  Redirected to: {resource['final_url']}\n")
                    f.write("\n")
            
            if result['social_media']:
                f.write("\nSOCIAL MEDIA PRESENCE:\n")
                for social in result['social_media']:
                    f.write(f"  Platform: {social['platform']}\n")
                    f.write(f"  URL: {social['url']}\n")
                    f.write(f"  Status: {social['status']}\n")
                    f.write("\n")
            
            f.write("=" * 80 + "\n")
    
    # Save JSON results
    json_file = output_dir / 'thought_leadership_details.json'
    with open(json_file, 'w') as f:
        json.dump(all_results, f, indent=2)
    
    print(f"\n{GREEN}[+] Results saved to:{RESET}")
    print(f"    {list_file}")
    print(f"    {details_file}")
    print(f"    {json_file}")
    
    return list_file, details_file, json_file


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='ThoughtLeadershipSeek - Discover thought leadership content and resources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -f iplist.txt -v
  %(prog)s -d example.com --full
  %(prog)s --domains domains.txt -o output/
  %(prog)s --guide-only

Output Files:
  thoughtleadershiplist.txt       - Simple list of discovered resources
  thought_leadership_details.txt  - Detailed findings
  thought_leadership_details.json - JSON formatted results
  THOUGHT_LEADERSHIP_GUIDE.txt    - Comprehensive analysis guide
        """
    )
    
    parser.add_argument('-f', '--file', help='File containing IP addresses or domains')
    parser.add_argument('-d', '--domain', help='Single domain to analyze')
    parser.add_argument('--domains', help='File containing domains (one per line)')
    parser.add_argument('-o', '--output', default='.', help='Output directory (default: current directory)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--full', action='store_true', help='Full analysis (includes all checks)')
    parser.add_argument('--guide-only', action='store_true', help='Generate guide only (no scanning)')
    
    args = parser.parse_args()
    
    print_banner()
    
    output_dir = Path(args.output)
    
    # Generate guide if requested
    if args.guide_only:
        print(f"\n{CYAN}[*] Generating comprehensive analysis guide...{RESET}")
        guide_path = generate_guide(output_dir)
        print(f"{GREEN}[+] Guide generated: {guide_path}{RESET}")
        return 0
    
    # Collect domains to analyze
    domains = []
    
    if args.domain:
        domains.append(args.domain)
    
    if args.file:
        ip_list_path = find_ip_list(args.file)
        if ip_list_path and os.path.exists(ip_list_path):
            with open(ip_list_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Could be IP or domain
                        domains.append(line)
        else:
            print(f"{RED}[!] Could not find IP list file{RESET}")
            return 1
    
    if args.domains:
        if os.path.exists(args.domains):
            with open(args.domains, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domains.append(line)
        else:
            print(f"{RED}[!] Domain file not found: {args.domains}{RESET}")
            return 1
    
    if not domains:
        print(f"{YELLOW}[!] No domains specified. Use -d, -f, or --domains{RESET}")
        parser.print_help()
        return 1
    
    print(f"\n{CYAN}[*] Analyzing {len(domains)} domain(s)...{RESET}")
    
    # Analyze each domain
    all_results = []
    for domain in domains:
        # Skip if it looks like a CIDR range
        if '/' in domain:
            if args.verbose:
                print(f"{YELLOW}[!] Skipping CIDR range: {domain}{RESET}")
            continue
        
        results = discover_thought_leadership(domain, verbose=args.verbose)
        all_results.append(results)
    
    # Save results
    if all_results:
        save_results(all_results, output_dir)
        
        # Generate guide
        print(f"\n{CYAN}[*] Generating analysis guide...{RESET}")
        guide_path = generate_guide(output_dir)
        print(f"{GREEN}[+] Guide generated: {guide_path}{RESET}")
    
    # Summary
    total_resources = sum(len(r['resources']) for r in all_results)
    total_social = sum(len(r['social_media']) for r in all_results)
    
    print(f"\n{CYAN}[*] Scan Summary:{RESET}")
    print(f"{GREEN}[+] Domains analyzed: {len(all_results)}{RESET}")
    print(f"{GREEN}[+] Resources found: {total_resources}{RESET}")
    print(f"{GREEN}[+] Social media accounts: {total_social}{RESET}")
    
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}[!] Error: {e}{RESET}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
