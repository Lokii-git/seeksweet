# WinRMSeek Technical Summary

## Overview
WinRMSeek is a network reconnaissance tool specialized in discovering and testing Windows Remote Management (WinRM) services. It identifies PowerShell Remoting-enabled hosts and validates credentials for lateral movement opportunities.

## Architecture

### Core Components
1. **Port Scanner**: TCP connect scan for ports 5985 (HTTP) and 5986 (HTTPS)
2. **Service Detector**: HTTP/HTTPS probes to verify WinRM service
3. **Authentication Tester**: Validates credentials via multiple methods
4. **Result Processor**: Formats and exports findings

### Protocol Stack
```
Application Layer:    PowerShell Remoting
                     ↓
WS-Management:       SOAP over HTTP/HTTPS
                     ↓
Transport Layer:     HTTP (5985) or HTTPS (5986)
                     ↓
Network Layer:       TCP/IP
```

## WinRM Protocol Details

### WS-Management Protocol
WinRM implements the **WS-Management** (Web Services Management) protocol, which is SOAP-based and uses HTTP/HTTPS as transport.

**Specification**: DMTF DSP0226 (WS-Management)

**Endpoint**: `/wsman`

**Example Request**:
```http
POST /wsman HTTP/1.1
Host: target.corp.local:5985
Content-Type: application/soap+xml;charset=UTF-8
User-Agent: Microsoft WinRM Client

<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing">
    <s:Header>
        <wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action>
        <wsa:To>http://target:5985/wsman</wsa:To>
    </s:Header>
    <s:Body>
        <!-- SOAP body -->
    </s:Body>
</s:Envelope>
```

### Authentication Flow

#### NTLM Authentication
```
Client                              Server
  |                                   |
  |-- GET /wsman ------------------>  |
  |                                   |
  |<- 401 + WWW-Authenticate: NTLM --|
  |                                   |
  |-- NTLM Type 1 Message ----------> |
  |   (Negotiate)                     |
  |                                   |
  |<- 401 + NTLM Type 2 Message ----- |
  |   (Challenge)                     |
  |                                   |
  |-- NTLM Type 3 Message ----------> |
  |   (Authenticate)                  |
  |                                   |
  |<- 200 OK + Session ---------------|
```

**Type 1 (Negotiate)**:
- Client capabilities
- Workstation name
- Domain name

**Type 2 (Challenge)**:
- Server challenge (8 bytes)
- Target information
- Server capabilities

**Type 3 (Authenticate)**:
- Username
- Domain
- Challenge response (NTLMv1/NTLMv2)
- Session key

#### Kerberos Authentication
```
Client                  KDC                     Server
  |                      |                        |
  |-- AS-REQ ----------->|                        |
  |<- AS-REP ------------|                        |
  |   (TGT)              |                        |
  |                      |                        |
  |-- TGS-REQ ---------->|                        |
  |   (TGT + SPN)        |                        |
  |<- TGS-REP -----------|                        |
  |   (Service Ticket)   |                        |
  |                                               |
  |-- AP-REQ (Ticket) --------------------------> |
  |                                               |
  |<- AP-REP (Session Key) ---------------------- |
  |                                               |
  |-- WinRM Request ----------------------------> |
```

**SPN Format**: `WSMAN/hostname.domain.com`

## Implementation Details

### Port Scanning
```python
def check_port(ip, port, timeout=3):
    # TCP connect scan
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((ip, port))
    sock.close()
    return result == 0  # 0 = success (port open)
```

**Performance**:
- Non-blocking sockets
- Configurable timeout (default: 3s)
- Concurrent scanning with ThreadPoolExecutor
- Default: 10 workers, configurable up to 100+

### Service Detection (HTTP)
```python
def detect_winrm_http(ip, timeout=5):
    url = f'http://{ip}:5985/wsman'
    response = requests.get(url, timeout=timeout, verify=False)
    
    # WinRM signatures:
    # - 401 Unauthorized (auth required)
    # - 405 Method Not Allowed (POST required)
    # - XML response with wsman namespace
    
    return (response.status_code in [401, 405] or 
            'wsman' in response.text.lower())
```

**HTTP Status Codes**:
- **401**: Authentication required (WinRM present)
- **405**: Method not allowed (GET not supported, WinRM present)
- **404**: Not found (no WinRM or wrong endpoint)
- **500**: Server error (WinRM present but misconfigured)

**XML Namespace Detection**:
```xml
<!-- WinRM response contains -->
xmlns:wsman="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"
```

### Service Detection (HTTPS)
```python
def detect_winrm_https(ip, timeout=5):
    url = f'https://{ip}:5986/wsman'
    response = requests.get(url, timeout=timeout, verify=False)
    
    # Same detection as HTTP
    # verify=False: Ignore self-signed certificates
    
    return (response.status_code in [401, 405] or 
            'wsman' in response.text.lower())
```

**SSL/TLS Considerations**:
- Self-signed certificates common
- Certificate validation disabled (pentesting context)
- SSLError often indicates service present but cert issues

### Authentication Testing Methods

#### Method 1: pywinrm (Python Library)
```python
def test_winrm_auth_pywinrm(ip, port, username, password, timeout=10):
    from winrm.protocol import Protocol
    
    protocol = 'https' if port == 5986 else 'http'
    endpoint = f'{protocol}://{ip}:{port}/wsman'
    
    p = Protocol(
        endpoint=endpoint,
        transport='ntlm',  # or 'kerberos', 'basic'
        username=username,
        password=password,
        server_cert_validation='ignore'
    )
    
    # Attempt to open shell
    shell_id = p.open_shell(timeout=timeout)
    
    if shell_id:
        p.close_shell(shell_id)
        return {'authenticated': True}
    
    return {'authenticated': False}
```

**Advantages**:
- Pure Python implementation
- Cross-platform (Linux, Windows, macOS)
- No external dependencies beyond pywinrm

**Disadvantages**:
- Requires pip install pywinrm
- May not support all auth methods

#### Method 2: PowerShell (Windows Only)
```python
def test_winrm_auth_powershell(ip, port, username, password, timeout=10):
    ps_cmd = f'''
$password = ConvertTo-SecureString '{password}' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential(
    '{username}', $password)
$session = New-PSSession -ComputerName {ip} -Port {port} 
                         -Credential $cred -ErrorAction Stop
if ($session) {{
    Remove-PSSession $session
    Write-Output "SUCCESS"
}}
'''
    
    result = subprocess.run(
        ['powershell.exe', '-Command', ps_cmd],
        capture_output=True, text=True, timeout=timeout
    )
    
    return {'authenticated': 'SUCCESS' in result.stdout}
```

**Advantages**:
- Native Windows functionality
- Supports all Windows auth methods
- Uses OS credential cache (Kerberos)

**Disadvantages**:
- Windows only
- Requires PowerShell installed
- May trigger more logging

#### Method 3: evil-winrm (Linux)
```python
def test_winrm_auth_evil_winrm(ip, username, password, ssl=False, timeout=10):
    cmd = ['evil-winrm', '-i', ip, '-u', username, '-p', password]
    
    if ssl:
        cmd.append('-S')
    
    # Try to execute simple command
    cmd.extend(['-e', 'whoami'])
    
    result = subprocess.run(cmd, capture_output=True, 
                          text=True, timeout=timeout)
    
    return {'authenticated': result.returncode == 0}
```

**Advantages**:
- Purpose-built for pentesting
- Excellent for exploitation after discovery
- Many built-in features (upload, download, etc.)

**Disadvantages**:
- Ruby dependency (gem install)
- Linux/Unix focused
- Slower for bulk testing

### Concurrent Scanning
```python
with ThreadPoolExecutor(max_workers=args.workers) as executor:
    futures = {
        executor.submit(scan_host, ip, args): ip 
        for ip in targets
    }
    
    for future in as_completed(futures):
        ip = futures[future]
        try:
            result = future.result(timeout=args.timeout * 2)
            # Process result
        except Exception as e:
            # Handle errors gracefully
            pass
```

**Threading Model**:
- ThreadPoolExecutor from concurrent.futures
- Default: 10 workers
- Configurable: 1-100+ workers
- Each thread handles one host scan
- Results collected as completed (non-blocking)

**Thread Safety**:
- Shared data structures protected
- Print statements synchronized
- File writes buffered and flushed

## Output Formats

### winrmlist.txt (Discovery)
```
192.168.1.10:5985 (HTTP)
192.168.1.11:5986 (HTTPS)
192.168.1.12:5985,5986 (HTTP,HTTPS)
```

**Format**: `IP:PORT (PROTOCOL)`

### winrm_access.txt (Authenticated)
```
192.168.1.10:5985 - Access Found (CORP\administrator)
192.168.1.11:5986 - Access Found (admin@corp.local)
```

**Format**: `IP:PORT - Access Found (USERNAME)`

### winrm_details.json (Structured)
```json
{
  "scan_time": "2025-10-13T14:30:00.123Z",
  "scan_parameters": {
    "workers": 10,
    "timeout": 3,
    "test_auth": true,
    "username": "CORP\\administrator"
  },
  "statistics": {
    "total_hosts": 254,
    "winrm_found": 45,
    "http_only": 20,
    "https_only": 15,
    "both_protocols": 10,
    "authenticated": 12
  },
  "results": [
    {
      "ip": "192.168.1.10",
      "ports": {
        "5985": {
          "open": true,
          "protocol": "http",
          "service": "WinRM",
          "authenticated": true,
          "username": "CORP\\administrator",
          "method": "pywinrm"
        },
        "5986": {
          "open": false
        }
      },
      "timestamp": "2025-10-13T14:30:05.456Z"
    }
  ]
}
```

## Performance Characteristics

### Timing Analysis
- **Port scan**: ~100ms per host per port (local network)
- **Service detection**: ~500ms per port (HTTP request + response)
- **Authentication test**: ~1-3 seconds (includes auth negotiation)
- **Full scan (per host)**: ~2-5 seconds average

### Scalability
**Network Size vs Time** (10 workers):
- /24 (254 hosts): ~10-15 minutes
- /16 (65,536 hosts): ~18-24 hours
- Single host: ~2-5 seconds

**Worker Optimization**:
- 10 workers: Balanced, low detection risk
- 50 workers: Fast, medium detection risk
- 100 workers: Very fast, high detection risk

### Resource Usage
- **Memory**: ~50-100 MB baseline
- **CPU**: Low (I/O bound, not CPU bound)
- **Network**: Minimal bandwidth (<10 KB per host)
- **Disk**: Output files typically <1 MB

## Security Considerations

### Operational Security

**Detection Vectors**:
1. **Network IDS/IPS**:
   - Pattern: Multiple connections to ports 5985/5986
   - Signature: HTTP requests to /wsman endpoint
   - Anomaly: Connections from unusual source IPs

2. **Host-Based Detection**:
   - Event ID 4624: Network logon attempts
   - Event ID 4625: Failed logon attempts
   - Event ID 91: WinRM connection accepted
   - Event ID 142: New PowerShell session

3. **Behavioral Analytics**:
   - Multiple auth attempts from single source
   - Auth attempts outside business hours
   - Successful auth from non-admin workstation

**Evasion Techniques**:
- **Rate limiting**: Use fewer workers (`-w 5`)
- **Timing**: Scan during business hours
- **Source IP**: Scan from compromised internal host
- **Valid credentials**: Successful auth less suspicious

### Defense Mechanisms

#### Network Level
```powershell
# Firewall rule to restrict WinRM access
New-NetFirewallRule -Name "WinRM-Restrict" `
    -DisplayName "WinRM Restricted Access" `
    -Direction Inbound `
    -Protocol TCP `
    -LocalPort 5985,5986 `
    -RemoteAddress 10.0.0.0/24 `
    -Action Allow

# Block all other sources
Set-NetFirewallRule -Name "WINRM-HTTP-In-TCP" -Enabled False
```

#### Service Level
```powershell
# Disable HTTP, require HTTPS
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $false

# Limit authentication methods
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $false
Set-Item WSMan:\localhost\Service\Auth\Kerberos -Value $true

# Require certificate authentication
Set-Item WSMan:\localhost\Service\Auth\Certificate -Value $true
```

#### Logging and Monitoring
```powershell
# Enable detailed logging
wevtutil sl Microsoft-Windows-WinRM/Operational /e:true /rt:true

# Enable PowerShell logging
$basePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

# Module logging
New-ItemProperty -Path "$basePath\ModuleLogging" `
    -Name EnableModuleLogging -Value 1 -Force

# Script block logging
New-ItemProperty -Path "$basePath\ScriptBlockLogging" `
    -Name EnableScriptBlockLogging -Value 1 -Force

# Transcription
New-ItemProperty -Path "$basePath\Transcription" `
    -Name EnableTranscripting -Value 1 -Force
```

## Detection Rules

### Sigma Rule (Multiple WinRM Connections)
```yaml
title: Multiple WinRM Connection Attempts
status: experimental
description: Detects multiple WinRM connection attempts from single source
logsource:
  product: windows
  service: winrm
detection:
  selection:
    EventID: 91
  timeframe: 5m
  condition: selection | count() > 10
falsepositives:
  - Legitimate administrative scripts
  - Monitoring systems
level: medium
```

### Splunk Query
```spl
index=windows EventCode=91 
| stats count by src_ip 
| where count > 10 
| sort -count
```

### ELK Query
```json
{
  "query": {
    "bool": {
      "must": [
        { "match": { "event.code": "91" }},
        { "range": { "@timestamp": { "gte": "now-5m" }}}
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip", "size": 100 }
    }
  }
}
```

## Common Misconfigurations

### 1. Unencrypted WinRM
```powershell
# Vulnerable config
AllowUnencrypted = true  # ❌ Credentials sent in cleartext
```

### 2. Overly Permissive Firewall
```powershell
# Vulnerable config
RemoteAddress = Any  # ❌ Allows connections from anywhere
```

### 3. Weak Authentication
```powershell
# Vulnerable config
Auth\Basic = true        # ❌ Base64-encoded passwords
Auth\Kerberos = false    # ❌ Forces NTLM
```

### 4. No Logging
```powershell
# Vulnerable config
# WinRM/Operational log disabled  # ❌ No audit trail
```

### 5. Default TrustedHosts
```powershell
# Vulnerable config
TrustedHosts = *  # ❌ Trusts all hosts (MITM risk)
```

## Error Handling

### Common Errors
```python
# Connection refused
errno 111 (Linux) / 10061 (Windows)
→ Port closed or firewall blocking

# Timeout
socket.timeout
→ Slow network or host unreachable

# Authentication failure
HTTP 401 Unauthorized
→ Invalid credentials

# SSL/TLS error
requests.exceptions.SSLError
→ Certificate issues (often indicates WinRM present)

# Connection reset
errno 104 (Linux) / 10054 (Windows)
→ Firewall RST or service crash
```

### Exception Handling Strategy
```python
try:
    result = scan_host(ip, args)
except socket.timeout:
    # Timeout: log and skip
    log_error(f"Timeout: {ip}")
except ConnectionRefusedError:
    # Port closed: mark as closed, continue
    result = {'status': 'closed'}
except Exception as e:
    # Unexpected error: log and continue
    log_error(f"Error scanning {ip}: {e}")
    result = {'status': 'error', 'error': str(e)}
```

## Dependencies

### Required
- Python 3.6+
- `socket` (standard library)
- `subprocess` (standard library)
- `requests` (HTTP client)
- `urllib3` (HTTPS handling)

### Optional
- **pywinrm**: Python WinRM client library
  ```bash
  pip install pywinrm
  ```

- **evil-winrm**: Ruby-based WinRM exploitation tool
  ```bash
  gem install evil-winrm
  ```

- **PowerShell**: Native Windows remoting (Windows only)
  ```powershell
  # Usually pre-installed on Windows
  Get-Command Enter-PSSession
  ```

## Integration with Attack Frameworks

### Metasploit
```ruby
# modules/auxiliary/scanner/winrm/winrm_scanner.rb
use auxiliary/scanner/winrm/winrm_login
set RHOSTS file:/path/to/winrmlist.txt
set USERNAME administrator
set PASSWORD Password123
run
```

### Cobalt Strike
```csharp
// Beacon command
powershell Invoke-Command -ComputerName TARGET -Credential $cred -ScriptBlock {whoami}
```

### Empire/Starkiller
```powershell
# Use discovered hosts for lateral movement
usemodule lateral_movement/invoke_psremoting
set ComputerName TARGET
set Listener http
execute
```

## Use Cases

### 1. Penetration Testing
- **Initial reconnaissance**: Identify WinRM-enabled hosts
- **Credential validation**: Test compromised credentials
- **Lateral movement**: Find accessible hosts for pivoting

### 2. Red Team Operations
- **Infrastructure mapping**: Understand remote admin capabilities
- **Persistence hunting**: Find always-accessible admin ports
- **Command and control**: Use WinRM for C2 channel

### 3. Security Auditing
- **Configuration review**: Identify insecure WinRM configs
- **Access control testing**: Verify firewall rules
- **Compliance checking**: Ensure HTTPS-only policy

### 4. Purple Team Exercises
- **Detection testing**: Trigger alerts and test SIEM rules
- **Response validation**: Test incident response to WinRM scans
- **Log analysis**: Verify logging is working correctly

## Limitations

### Technical Limitations
- Cannot bypass firewalls or network ACLs
- Requires network connectivity to target ports
- Authentication testing requires valid credentials
- SSL/TLS certificate validation issues may cause false negatives

### Scope Limitations
- Windows-specific (WinRM is Windows-only)
- Does not test PowerShell remoting capabilities in depth
- No automatic privilege escalation
- No built-in credential brute-forcing

### Detection Risk
- Network scanning is noisy
- Multiple authentication attempts trigger alerts
- Source IP easily identified in logs
- Cannot evade host-based EDR/AV

## Future Enhancements
- Native WinRM protocol implementation (remove dependencies)
- Integrated credential brute-forcing
- Automatic privilege escalation checks
- Certificate-based authentication support
- Kerberos ticket integration
- Obfuscated HTTP/HTTPS requests
- IPv6 support
- Multi-domain forest enumeration

## References
- **DMTF DSP0226**: WS-Management Protocol Specification
- **Microsoft Docs**: Windows Remote Management (WinRM)
- **MITRE ATT&CK**: T1021.006 (Remote Services: Windows Remote Management)
- **CIS Benchmarks**: Windows Server WinRM hardening
- **NIST**: Secure PowerShell Remoting guidelines
- **evil-winrm**: https://github.com/Hackplayers/evil-winrm
- **pywinrm**: https://github.com/diyan/pywinrm
