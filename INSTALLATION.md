# SeekSweet Installation Guide

## Quick Start

### Automated Installation (Recommended)

```bash
# Download or clone SeekSweet
git clone https://github.com/Lokii-git/seeksweet.git
cd seeksweet

# Run automated installer
python3 install_dependencies.py

# Verify installation
python3 install_dependencies.py --check-only
```

### Manual Installation

```bash
# Install critical system tools
sudo apt-get update
sudo apt-get install -y enum4linux ldap-utils smbclient nmap snmp snmp-mibs-downloader impacket-scripts

# Install Python dependencies
pip install requests urllib3

# Download SNMP MIBs
sudo download-mibs
```

---

## Installation Methods

### Method 1: Automated Installer (Recommended)

The `install_dependencies.py` script provides intelligent, OS-aware installation:

#### Full Installation (All Dependencies)
```bash
python3 install_dependencies.py
# or
python3 install_dependencies.py --full
```

#### Minimal Installation (Critical Only)
```bash
python3 install_dependencies.py --minimal
```

#### Check Current Status
```bash
python3 install_dependencies.py --check-only
```

#### Features:
- ✅ **OS Detection**: Automatically detects Linux distribution and package manager
- ✅ **Dependency Verification**: Checks all tools before and after installation
- ✅ **Error Handling**: Provides specific troubleshooting for failed installations
- ✅ **Progress Reporting**: Clear visual feedback during installation
- ✅ **Rollback Safe**: Only installs missing components
- ✅ **Cross-Platform**: Supports Debian/Ubuntu, RHEL/CentOS, macOS

### Method 2: Manual Installation

#### For Kali Linux / Debian / Ubuntu:

```bash
# Update package list
sudo apt-get update

# Critical tools (required for core functionality)
sudo apt-get install -y enum4linux ldap-utils smbclient nmap snmp snmp-mibs-downloader impacket-scripts

# Optional tools (enhanced features)
sudo apt-get install -y crackmapexec samba-common-bin nikto

# Modern alternatives
sudo apt-get install pipx
pipx install netexec  # Modern crackmapexec replacement

# Python packages (required)
pip install requests>=2.31.0 urllib3>=2.0.0

# Optional Python packages (database testing)
pip install PyMySQL psycopg2-binary pymssql pymongo redis pywinrm

# Download SNMP MIBs
sudo download-mibs
```

#### For RHEL / CentOS / Fedora:

```bash
# Install available tools
sudo yum install -y smbclient openldap-clients nmap net-snmp-utils

# Python packages
pip install requests urllib3

# Note: Some tools like enum4linux may need manual installation
```

#### For macOS:

```bash
# Install Homebrew if not present
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install samba openldap nmap net-snmp

# Python packages
pip install requests urllib3
```

---

## Verification

### Automated Verification

The installer includes comprehensive verification:

```bash
python3 install_dependencies.py --check-only
```

**Sample Output:**
```
======================================================================
INSTALLATION VERIFICATION
======================================================================

Critical System Tools:
  ✓ enum4linux
  ✓ ldapsearch
  ✓ smbclient
  ✓ nmap
  ✓ snmpwalk
  ✓ snmpget
  ✓ GetUserSPNs.py
  ✓ GetNPUsers.py

Optional System Tools:
  ✓ netexec
  - crackmapexec (not found - optional)
  ✓ rpcclient
  ✓ nikto
  - nuclei (not found - optional)

Python Packages:
Required:
  ✓ requests
  ✓ urllib3
Optional:
  - PyMySQL (not found - optional)
  - psycopg2 (not found - optional)

======================================================================
INSTALLATION SUMMARY
======================================================================
Critical Tools: 8/8
Optional Tools: 3/5
Python Packages: 2/8

🎉 SUCCESS: All critical dependencies installed!
SeekSweet is ready to use.
```

### Manual Verification

Create a verification script:

```bash
#!/bin/bash
# verify_installation.sh

echo "=== SeekSweet Installation Verification ==="

# Critical tools
for tool in enum4linux ldapsearch smbclient nmap snmpwalk snmpget GetUserSPNs.py GetNPUsers.py; do
    if command -v "$tool" &> /dev/null; then
        echo "✓ $tool found"
    else
        echo "✗ $tool MISSING (CRITICAL)"
    fi
done

# Python packages
python3 -c "
import sys
try:
    import requests, urllib3
    print('✓ Python packages: requests, urllib3')
except ImportError as e:
    print(f'✗ Python packages missing: {e}')
"

echo "=== Verification Complete ==="
```

---

## Troubleshooting

### Common Issues

#### 1. "enum4linux not found"

**Symptoms:**
```
✗ enum4linux (MISSING - CRITICAL)
```

**Solutions:**
```bash
# Standard installation
sudo apt-get install enum4linux

# Alternative: newer version
sudo apt-get install enum4linux-ng

# Verify installation
enum4linux --help
```

#### 2. "GetUserSPNs.py not found" 

**Symptoms:**
```
✗ GetUserSPNs.py (MISSING - CRITICAL)
✗ GetNPUsers.py (MISSING - CRITICAL)
```

**Solutions:**
```bash
# Install impacket scripts
sudo apt-get install impacket-scripts

# Verify installation
find /usr -name "GetUserSPNs.py" 2>/dev/null
GetUserSPNs.py -h

# Alternative: pip installation
pip install impacket
```

#### 3. SNMP tools not working

**Symptoms:**
```
✗ snmpwalk (MISSING - CRITICAL)
✗ snmpget (MISSING - CRITICAL)
```

**Solutions:**
```bash
# Install SNMP tools
sudo apt-get install snmp snmp-mibs-downloader

# Download MIB files (important!)
sudo download-mibs

# Edit SNMP configuration
sudo nano /etc/snmp/snmp.conf
# Comment out: mibs :

# Test installation
snmpwalk -v2c -c public 127.0.0.1 1.3.6.1.2.1.1.5.0
```

#### 4. Python packages not installing

**Symptoms:**
```
✗ requests (MISSING - CRITICAL)
✗ urllib3 (MISSING - CRITICAL)
```

**Solutions:**
```bash
# Update pip first
python3 -m pip install --upgrade pip

# Install with explicit Python version
python3 -m pip install requests urllib3

# For database packages on Debian/Ubuntu
sudo apt-get install python3-dev libpq-dev
python3 -m pip install psycopg2-binary

# Use virtual environment (recommended)
python3 -m venv seeksweet-env
source seeksweet-env/bin/activate
pip install -r requirements.txt
```

#### 5. NetExec vs CrackMapExec

**Issue:** NetExec is the modern replacement for CrackMapExec

**Solutions:**
```bash
# Preferred: Install NetExec
pipx install netexec

# Or via pip
pip install netexec

# Legacy: CrackMapExec (if NetExec unavailable)
sudo apt-get install crackmapexec

# Verify installation
netexec --version
# or
crackmapexec --version
```

### Permission Issues

#### "Permission denied" during installation

**Solutions:**
```bash
# Ensure sudo access
sudo -v

# Fix pip permissions
python3 -m pip install --user requests urllib3

# Use virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Platform-Specific Issues

#### Windows/WSL

**Issue:** Most tools designed for Linux

**Solutions:**
```bash
# Use WSL2 (Windows Subsystem for Linux)
wsl --install

# Install Kali Linux in WSL
wsl --install -d kali-linux

# Run SeekSweet from within WSL
wsl
cd /mnt/c/path/to/seeksweet
python3 install_dependencies.py
```

#### macOS

**Issue:** Some tools not available via Homebrew

**Solutions:**
```bash
# Install available tools
brew install samba openldap nmap net-snmp

# Manual compilation for missing tools
git clone https://github.com/CiscoCXSecurity/enum4linux-ng.git
cd enum4linux-ng
pip install -r requirements.txt
```

---

## Advanced Installation

### Container Installation

#### Docker

```dockerfile
FROM kalilinux/kali-rolling

# Install dependencies
RUN apt-get update && apt-get install -y \
    enum4linux ldap-utils smbclient nmap snmp \
    snmp-mibs-downloader impacket-scripts python3-pip

# Install Python packages
RUN pip3 install requests urllib3

# Download SNMP MIBs
RUN download-mibs

# Copy SeekSweet
COPY . /seeksweet
WORKDIR /seeksweet

# Verify installation
RUN python3 install_dependencies.py --check-only
```

#### Build and run:
```bash
docker build -t seeksweet .
docker run -it -v $(pwd)/results:/seeksweet/results seeksweet
```

### Virtual Environment Installation

```bash
# Create isolated environment
python3 -m venv seeksweet-env
source seeksweet-env/bin/activate

# Install Python dependencies
pip install -r requirements.txt

# Install system tools (still requires system-level installation)
sudo apt-get install enum4linux ldap-utils smbclient nmap snmp impacket-scripts
```

### Development Installation

```bash
# Clone with development features
git clone --recursive https://github.com/Lokii-git/seeksweet.git
cd seeksweet

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/
```

---

## Post-Installation

### Configuration

1. **Update IP Lists:**
   ```bash
   # Edit default IP list
   nano iplist.txt
   
   # Or specify custom lists
   python3 seeksweet.py -f custom_targets.txt
   ```

2. **Configure SNMP:**
   ```bash
   # Edit SNMP configuration
   sudo nano /etc/snmp/snmp.conf
   # Comment out: mibs :
   ```

3. **Set up Logging:**
   ```bash
   # Create logs directory
   mkdir -p logs
   
   # Set permissions
   chmod 755 logs
   ```

### Performance Tuning

```bash
# Increase file descriptor limits
ulimit -n 4096

# For large networks, adjust timeout values in individual tools
# Edit seek modules and modify timeout parameters
```

### Security Considerations

⚠️ **Important:** These tools perform active network reconnaissance

**Recommendations:**
- Use only on authorized networks
- Test in isolated lab environments first
- Monitor network traffic for detection signatures
- Follow responsible disclosure practices

### Updates

```bash
# Update SeekSweet
git pull origin main

# Update dependencies
python3 install_dependencies.py --check-only
python3 -m pip install --upgrade -r requirements.txt

# Update system tools
sudo apt-get update && sudo apt-get upgrade
```

---

## Support

### Getting Help

1. **Check Documentation:**
   - `DEPENDENCIES.md` - Detailed dependency information
   - Individual module `README.md` files
   - `--help` options for each tool

2. **Verify Installation:**
   ```bash
   python3 install_dependencies.py --check-only
   ```

3. **Check Logs:**
   ```bash
   # Check recent installer logs
   cat installation_results.json
   
   # Check tool-specific logs
   ls -la logs/
   ```

4. **Debug Mode:**
   ```bash
   # Run with verbose output
   python3 seeksweet.py -v
   
   # Enable debug logging
   export DEBUG=1
   python3 seeksweet.py
   ```

### Common Commands

```bash
# Quick health check
python3 install_dependencies.py --check-only

# Reinstall missing dependencies
python3 install_dependencies.py --minimal

# Full reinstall
python3 install_dependencies.py --full

# Check individual tool versions
enum4linux --version
nmap --version
GetUserSPNs.py -h
```

---

## Conclusion

The SeekSweet dependency system is designed to be:
- **Automated**: One-command installation
- **Intelligent**: OS-aware and adaptive
- **Reliable**: Comprehensive verification and error handling
- **Maintainable**: Clear documentation and troubleshooting guides

For most users, the automated installer will handle everything:

```bash
python3 install_dependencies.py
```

For advanced users or specific environments, manual installation and configuration options provide full flexibility.

**Next Steps:**
1. Verify installation with `--check-only`
2. Configure `iplist.txt` with your target networks
3. Start with individual seek modules (e.g., `python3 dcseek/dcseek.py`)
4. Use the main interface: `python3 seeksweet.py`

Happy hunting! 🎯