#!/usr/bin/env python3
"""
Test script to demonstrate smart reporting features using example Nuclei data
"""
import json
import sys
import os

# Import the functions from webseek-v2
sys.path.insert(0, os.path.dirname(__file__))

# Read example findings.json if available
example_findings = [
    {
        "template-id": "hp-printer-default-login",
        "info": {
            "name": "Hewlett Packard LaserJet Printer - Default Login",
            "severity": "high",
            "description": "HP printers often allow administrative access without requiring a password by default.",
            "tags": ["hp", "printer", "default-login"]
        },
        "host": "http://10.64.51.23",
        "matched-at": "https://10.64.51.23/hp/device/DeviceStatus/Index"
    },
    {
        "template-id": "hp-printer-default-login",
        "info": {
            "name": "Hewlett Packard LaserJet Printer - Default Login",
            "severity": "high",
            "description": "HP printers often allow administrative access without requiring a password by default."
        },
        "host": "http://10.64.51.14",
        "matched-at": "https://10.64.51.14/hp/device/DeviceStatus/Index"
    },
    {
        "template-id": "hp-printer-default-login",
        "info": {
            "name": "Hewlett Packard LaserJet Printer - Default Login",
            "severity": "high",
            "description": "HP printers often allow administrative access without requiring a password by default."
        },
        "host": "http://10.65.51.138",
        "matched-at": "https://10.65.51.138/hp/device/DeviceStatus/Index"
    },
    {
        "template-id": "CVE-2025-41393",
        "info": {
            "name": "Ricoh Web Image Monitor - Reflected XSS",
            "severity": "medium",
            "description": "A reflected cross-site scripting vulnerability exists in Ricoh Web Image Monitor.",
            "cve-id": "CVE-2025-41393",
            "cvss-score": "6.10",
            "tags": ["cve", "cve2025", "ricoh", "xss"]
        },
        "host": "http://10.64.102.122",
        "matched-at": "http://10.64.102.122/?profile=</script><script>alert(document.domain)</script>"
    },
    {
        "template-id": "CVE-2025-41393",
        "info": {
            "name": "Ricoh Web Image Monitor - Reflected XSS",
            "severity": "medium",
            "description": "A reflected cross-site scripting vulnerability exists in Ricoh Web Image Monitor.",
            "cve-id": "CVE-2025-41393",
            "cvss-score": "6.10"
        },
        "host": "http://10.65.51.4"
    },
    {
        "template-id": "ricoh-default-login",
        "info": {
            "name": "Ricoh Printer - Default Login",
            "severity": "high",
            "description": "Ricoh printer accessible with default credentials"
        },
        "host": "http://10.64.102.122"
    },
    {
        "template-id": "expired-ssl",
        "info": {
            "name": "Expired SSL Certificate",
            "severity": "info",
            "description": "SSL certificate has expired"
        },
        "host": "https://10.64.21.125"
    },
    {
        "template-id": "http-trace",
        "info": {
            "name": "HTTP TRACE Method Enabled",
            "severity": "info",
            "description": "HTTP TRACE method is enabled"
        },
        "host": "http://10.64.21.125"
    }
]

# Import functions - need to use importlib since the filename has a dash
import importlib.util
spec = importlib.util.spec_from_file_location("webseek_v2", "webseek-v2.py")
webseek_v2 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(webseek_v2)

group_findings_by_vuln = webseek_v2.group_findings_by_vuln
generate_critical_report = webseek_v2.generate_critical_report
generate_vuln_summary_by_severity = webseek_v2.generate_vuln_summary_by_severity
generate_ip_to_vuln_report = webseek_v2.generate_ip_to_vuln_report

print("Testing Smart Report Generation...")
print("="*80)

# Group findings
vuln_groups = group_findings_by_vuln(example_findings)

print(f"\nFound {len(vuln_groups)} unique vulnerabilities:")
for template_id, data in vuln_groups.items():
    severity = data['info'].get('severity', 'unknown')
    name = data['info'].get('name', 'Unknown')
    ip_count = len(data['ips'])
    print(f"  [{severity.upper()}] {name} ({ip_count} hosts)")

print("\n" + "="*80)
print("Generating reports...\n")

# Generate reports
generate_critical_report(vuln_groups, 'test_CRITICAL_FINDINGS.txt')
generate_vuln_summary_by_severity(vuln_groups)
generate_ip_to_vuln_report(vuln_groups, 'test_IP_TO_VULNS.txt')

print("\n" + "="*80)
print("✅ Test reports generated successfully!")
print("\nGenerated files:")
print("  - test_CRITICAL_FINDINGS.txt")
print("  - test_HIGH_VULNS.txt")
print("  - test_MEDIUM_VULNS.txt")
print("  - test_INFO_VULNS.txt")
print("  - test_IP_TO_VULNS.txt")
