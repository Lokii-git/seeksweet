# ThoughtLeadershipSeek

**Thought Leadership Content Discovery Tool**

ThoughtLeadershipSeek is a reconnaissance tool designed to discover and catalog thought leadership content, industry insights, and public-facing resources from target organizations. This tool helps security assessors understand an organization's public presence, technical expertise, and key personnel.

## Features

- 🔍 **Content Discovery** - Automatically discover blogs, whitepapers, research, and publications
- 📱 **Social Media Enumeration** - Identify organization presence on LinkedIn, Twitter, GitHub, YouTube
- 👥 **Personnel Mapping** - Identify key personnel and subject matter experts
- 📊 **Intelligence Gathering** - Extract valuable OSINT for security assessments
- 📝 **Comprehensive Guide** - Auto-generates detailed analysis methodology guide
- 🎯 **Multi-format Output** - TXT, JSON outputs for easy integration

## Installation

ThoughtLeadershipSeek is part of the SeekSweet suite. To use it:

```bash
cd seeksweet/thought-leadership
python3 thoughtleadershipseek.py --help
```

### Requirements

```bash
pip install requests urllib3
```

## Usage

### Basic Usage

```bash
# Analyze a single domain
python3 thoughtleadershipseek.py -d example.com -v

# Analyze multiple domains from file
python3 thoughtleadershipseek.py -f domains.txt -v

# Full analysis with all checks
python3 thoughtleadershipseek.py -d example.com --full -v

# Generate guide only (no scanning)
python3 thoughtleadershipseek.py --guide-only
```

### Advanced Usage

```bash
# Specify output directory
python3 thoughtleadershipseek.py -d example.com -o /path/to/output -v

# Use with SeekSweet iplist.txt
python3 thoughtleadershipseek.py -f ../iplist.txt -v

# Analyze domains from custom file
python3 thoughtleadershipseek.py --domains targets.txt -v
```

## Output Files

ThoughtLeadershipSeek generates four main output files:

### 1. thoughtleadershiplist.txt
Simple summary of discovered resources per domain:
```
Thought Leadership Discovery Results - 2025-10-31 12:00:00
================================================================================

Domain: example.com
IP: 93.184.216.34
Resources found: 5
Social media: 3
--------------------------------------------------------------------------------
```

### 2. thought_leadership_details.txt
Detailed findings including:
- Full resource URLs and types
- HTTP status codes
- Content sizes
- Redirect chains
- Social media profiles
- Discovery timestamps

### 3. thought_leadership_details.json
Machine-readable JSON format containing all discovered data for integration with other tools.

### 4. THOUGHT_LEADERSHIP_GUIDE.txt
Comprehensive 400+ line guide covering:
- Intelligence gathering methodology
- Resource type analysis
- Social media reconnaissance
- OSINT correlation techniques
- Tools and automation
- Reporting best practices

## What Gets Discovered

### Content Resources
- `/blog` - Company blogs and technical articles
- `/insights` - Industry insights and analysis
- `/resources` - Resource centers and downloads
- `/whitepapers` - Technical whitepapers and research
- `/research` - Research publications and papers
- `/publications` - Academic and industry publications
- `/news` - News and press releases
- `/webinars` - Webinar archives and recordings
- `/case-studies` - Customer case studies
- `/documentation` - Technical documentation

### Social Media Presence
- LinkedIn company pages
- Twitter/X accounts
- GitHub organizations
- YouTube channels
- Medium publications
- SlideShare profiles

## Use Cases

### Security Assessment
- **Reconnaissance Phase** - Gather public intelligence about target organization
- **Personnel Enumeration** - Identify key decision makers and technical experts
- **Technology Stack Discovery** - Learn about technologies and tools used
- **Social Engineering Prep** - Understand communication style and topics

### Competitive Intelligence
- Market positioning analysis
- Technical capabilities assessment
- Industry influence measurement
- Partnership identification

### OSINT Operations
- Cross-reference with other intelligence sources
- Build comprehensive organization profiles
- Track technology adoption and trends
- Monitor security awareness and posture

## Intelligence Value

Thought leadership content reveals:

1. **Technical Expertise**
   - Technology stack indicators
   - Development methodologies
   - Security practices and awareness
   - Architecture patterns

2. **Personnel Intelligence**
   - Key decision makers
   - Technical subject matter experts
   - Areas of specialization
   - Contact information

3. **Business Context**
   - Industry focus and vertical markets
   - Strategic partnerships
   - Client types and use cases
   - Competitive positioning

4. **Security Indicators**
   - Security awareness level
   - Compliance frameworks
   - Incident response capability
   - Privacy practices

## Integration with SeekSweet

ThoughtLeadershipSeek integrates seamlessly with the SeekSweet orchestration framework:

```bash
# From SeekSweet root
python seeksweet.py
# Select ThoughtLeadershipSeek from menu
```

Outputs automatically copied to `seekerlogs/` directory for centralized access.

## Operational Security

When conducting thought leadership reconnaissance:

- ✅ Use VPN or proxy for anonymity
- ✅ Respect rate limits to avoid detection
- ✅ Follow robots.txt guidelines (for authorized testing)
- ✅ Document all intelligence gathering activities
- ✅ Obtain proper authorization before assessment
- ✅ Use gathered intelligence responsibly
- ✅ Report findings through proper channels

## Examples

### Example 1: Basic Domain Analysis
```bash
$ python3 thoughtleadershipseek.py -d acme.com -v

[*] Analyzing domain: acme.com
[+] Resolved to: 203.0.113.10
[*] Checking for thought leadership resources...
[+] Found: https://acme.com/blog [200]
[+] Found: https://acme.com/insights [200]
[+] Found: https://acme.com/whitepapers [200]
[*] Checking social media presence...
[+] Social: linkedin - https://linkedin.com/acme
[+] Social: twitter - https://twitter.com/acme
[+] Social: github - https://github.com/acme

[*] Scan Summary:
[+] Domains analyzed: 1
[+] Resources found: 3
[+] Social media accounts: 3
```

### Example 2: Multiple Domains
```bash
$ python3 thoughtleadershipseek.py -f domains.txt -v

[*] Analyzing 5 domain(s)...

[*] Analyzing domain: company1.com
[+] Found: https://company1.com/blog [200]
...

[+] Results saved to:
    thoughtleadershiplist.txt
    thought_leadership_details.txt
    thought_leadership_details.json
```

## Tips for Effective Analysis

1. **Start with Known Domains** - Use corporate domains, not IP addresses
2. **Review JSON Output** - Parse JSON for automated processing
3. **Check Redirects** - Note final URLs for additional discovery
4. **Cross-Reference** - Combine with DNS enumeration for subdomains
5. **Read the Guide** - Review THOUGHT_LEADERSHIP_GUIDE.txt for methodology
6. **Monitor Over Time** - Track changes to identify new content
7. **Extract Metadata** - Download PDFs/documents for metadata analysis

## Limitations

- Requires domain names (not just IP addresses)
- May miss content behind authentication
- Subject to rate limiting on public sites
- Some social media platforms may block automated access
- Content discovery depends on common path patterns

## Legal & Ethical Considerations

⚠️ **IMPORTANT**: This tool is designed for authorized security assessments and OSINT research only.

- Always obtain proper authorization before reconnaissance
- Follow applicable laws and regulations (CFAA, GDPR, etc.)
- Respect website terms of service
- Use gathered intelligence ethically and responsibly
- Report any discovered vulnerabilities through proper channels

## Contributing

Contributions welcome! To improve ThoughtLeadershipSeek:

1. Add new content paths to `TL_PATHS` array
2. Add social media platforms to `SOCIAL_PLATFORMS`
3. Enhance intelligence extraction logic
4. Improve reporting and output formats
5. Add integration with other OSINT tools

## Version History

### v1.0 (2025-10-31)
- Initial release
- Core content discovery functionality
- Social media enumeration
- Multi-format output (TXT, JSON)
- Comprehensive analysis guide
- SeekSweet integration

## Support

- Issues: [GitHub Issues](https://github.com/Lokii-git/seeksweet/issues)
- Discussions: [GitHub Discussions](https://github.com/Lokii-git/seeksweet/discussions)

## License

MIT License - Part of the SeekSweet suite

---

**Created with ❤️ for the security research community**

**Remember: Always get authorization before reconnaissance!** 🔒
