# NessusSeek v1.0 - Nessus Integration for SeekSweet

Professional vulnerability scanning integration using Tenable Nessus.

## Features

- 🚀 **Launch Nessus Scans** - Create and launch scans via REST API
- 📊 **Real-time Monitoring** - Track scan progress and status
- 📥 **Automated Downloads** - Export and parse results automatically
- 🎯 **Severity Categorization** - Critical/High/Medium/Low/Info classification
- 📝 **Comprehensive Reports** - Detailed findings with remediation guidance
- 🔄 **SeekSweet Integration** - Results saved to `seekerlogs/`

## Requirements

```bash
# Python packages
pip install requests urllib3

# Nessus Professional or Essentials
# Running on default port: https://localhost:8834
sudo systemctl start nessusd
```

## Setup

### 1. Generate Nessus API Keys

1. Log into Nessus web interface (https://localhost:8834)
2. Go to **Settings** → **API Keys**
3. Click **Generate** to create new API key pair
4. Save **Access Key** and **Secret Key**

### 2. Run NessusSeek

```bash
# Interactive mode (prompts for API keys)
./nessusseek.py -t iplist.txt

# With API keys provided
./nessusseek.py -t iplist.txt --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY

# Custom scan name
./nessusseek.py -t iplist.txt -n "Production Network Scan"

# List existing scans
./nessusseek.py --list --access-key KEY --secret-key KEY

# Download results from existing scan
./nessusseek.py --download 42 --access-key KEY --secret-key KEY
```

## Usage Examples

### Quick Scan
```bash
./nessusseek.py -t iplist.txt
# Will prompt for API keys interactively
```

### Full Workflow
```bash
# 1. Launch scan
./nessusseek.py -t targets.txt -n "Q4-2024-Scan"

# 2. Monitor progress (automatic)
# Shows: Status: running - Progress: 45%

# 3. Results auto-downloaded when complete
# Creates: nessuslist.txt, nessus_findings.txt, nessus_results.csv
```

### Check Existing Scans
```bash
# List all scans
./nessusseek.py --list --access-key YOUR_KEY --secret-key YOUR_KEY

# Download from specific scan
./nessusseek.py --download 123 --access-key YOUR_KEY --secret-key YOUR_KEY
```

## Output Files

| File | Description |
|------|-------------|
| `nessuslist.txt` | List of vulnerable hosts with severity counts |
| `nessus_findings.txt` | Detailed Critical/High findings with descriptions |
| `nessus_results.csv` | Full CSV export from Nessus (all findings) |
| `NESSUS_GUIDE.txt` | Remediation guidance and best practices |

## Scan Process

```
1. CREATE SCAN
   ├─ Loads targets from file
   ├─ Creates scan in Nessus
   └─ Returns Scan ID

2. LAUNCH SCAN
   ├─ Starts vulnerability assessment
   └─ Begins host discovery

3. MONITOR PROGRESS
   ├─ Polls scan status every 15 seconds
   ├─ Shows progress percentage
   └─ Waits for completion

4. DOWNLOAD RESULTS
   ├─ Exports CSV format
   ├─ Waits for export to be ready
   └─ Downloads to local file

5. PARSE & REPORT
   ├─ Categorizes by severity
   ├─ Generates host summary
   └─ Creates detailed reports
```

## Nessus Scan Types

NessusSeek uses the **Basic Network Scan** template by default, which includes:

- Port scanning
- Service detection
- Version identification
- Vulnerability checks
- Configuration audits
- Compliance checks

### Advanced Scanning

For more comprehensive scans, you can:

1. **Create scan in Nessus UI** with advanced template
2. **Launch from UI** or use `./nessusseek.py --download SCAN_ID`
3. **Parse results** with NessusSeek

## API Key Security

⚠️ **Important**: API keys provide full access to Nessus

**Best Practices:**
- Store keys in environment variables
- Use `.bashrc` or `.zshrc` for persistent storage
- Never commit keys to git
- Rotate keys regularly
- Use read-only keys if available

```bash
# Add to ~/.bashrc
export NESSUS_ACCESS_KEY="your_access_key"
export NESSUS_SECRET_KEY="your_secret_key"

# Use in script
./nessusseek.py -t iplist.txt --access-key $NESSUS_ACCESS_KEY --secret-key $NESSUS_SECRET_KEY
```

## Troubleshooting

### Connection Failed

```bash
# Check if Nessus is running
sudo systemctl status nessusd

# Start Nessus
sudo systemctl start nessusd

# Check web interface
curl -k https://localhost:8834
```

### SSL Certificate Errors

NessusSeek disables SSL warnings by default for self-signed certificates. If you need strict SSL:

Edit `nessusseek.py`:
```python
nessus = NessusAPI(args.url, args.access_key, args.secret_key, verify_ssl=True)
```

### Scan Not Starting

- Verify API keys are correct
- Check Nessus license is active
- Ensure targets are reachable
- Review Nessus scanner status in UI

### Export Timeout

Large scans may take time to export. Increase timeout in code:
```python
max_wait = 600  # 10 minutes instead of 5
```

## Integration with SeekSweet

Run from SeekSweet menu:
```bash
./seeksweet.py
# Select option 17: NessusSeek
```

All results automatically copied to `seekerlogs/` folder.

## Nessus vs VulnSeek

| Feature | NessusSeek | VulnSeek |
|---------|-----------|----------|
| Checks | 100,000+ plugins | 15+ targeted CVEs + Nuclei |
| Speed | Slower (comprehensive) | Faster (targeted) |
| Credentials | Optional (credentialed scan) | None required |
| Compliance | Yes (PCI, HIPAA, etc.) | No |
| Best For | Full assessments | Quick enumeration |

**Recommendation**: Use both!
- **VulnSeek** for initial enumeration
- **NessusSeek** for comprehensive assessment

## Common Nessus CVEs Detected

- **MS17-010** (EternalBlue)
- **CVE-2020-0601** (CurveBall)
- **CVE-2019-0708** (BlueKeep)
- **Log4Shell** (CVE-2021-44228)
- **ProxyLogon** (CVE-2021-26855)
- **SMBGhost** (CVE-2020-0796)
- And 100,000+ more...

## Compliance Scanning

Nessus includes templates for:
- PCI DSS
- HIPAA
- CIS Benchmarks
- NIST
- GDPR
- ISO 27001

Configure in Nessus UI before scanning.

## Credits

- **Tenable Nessus** - https://www.tenable.com/products/nessus
- **SeekSweet Framework** - https://github.com/Lokii-git/seeksweet
- **NessusSeek** - Integration wrapper by SeekSweet team

## License

Part of the SeekSweet framework. For educational and authorized testing only.
