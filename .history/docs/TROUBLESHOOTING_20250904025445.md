# Troubleshooting Guide - WSL SSL Inspector

This guide helps resolve common issues when using the WSL SSL Inspector.

## Common Issues and Solutions

### 1. WSL Not Available

#### Error Message
```
WSL is not available or properly configured
```

#### Solutions
```powershell
# Check if WSL is installed
wsl --version

# Install WSL if not available
wsl --install

# List available distributions
wsl -l -v

# Install Ubuntu if no distributions exist
wsl --install -d Ubuntu
```

### 2. No Corporate Certificates Found

#### Error Message
```
No corporate certificates found matching the criteria
```

#### Solutions
```powershell
# Try broader search patterns
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("CA", "Root", "Certificate") -Verbose

# Check certificate stores manually
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*CA*" }
Get-ChildItem -Path Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*Corporate*" }

# Include more specific company patterns
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("YourCompanyName", "Internal", "Corporate") -Verbose
```

### 3. Permission Denied in WSL

#### Error Message
```
Permission denied when accessing /usr/local/share/ca-certificates/
```

#### Solutions
```bash
# In WSL, check current user
whoami

# Ensure script runs with root privileges (it should automatically use -u root)
# If manual intervention needed:
sudo mkdir -p /usr/local/share/ca-certificates/
sudo chmod 755 /usr/local/share/ca-certificates/
```

```powershell
# Ensure PowerShell is running as Administrator
# Right-click PowerShell -> "Run as Administrator"
```

### 4. SSL Tests Still Failing After Installation

#### Error Message
```
SSL certificate problem: unable to get local issuer certificate
```

#### Solutions
```powershell
# Install all effective certificates, not just the first one
.\Install-CorporateSSL-WSL.ps1 -RequireAllCerts -Verbose

# Look for intermediate certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("CA", "Intermediate", "Chain") -RequireAllCerts

# Clean install to remove conflicts
.\Install-CorporateSSL-WSL.ps1 -CleanInstall -RequireAllCerts -Verbose
```

#### Manual Verification in WSL
```bash
# Check installed certificates
ls -la /usr/local/share/ca-certificates/

# Update certificate store manually
sudo update-ca-certificates --verbose

# Test specific domain
curl -v https://google.com

# Check certificate chain
openssl s_client -connect google.com:443 -servername google.com
```

### 5. Unsupported WSL Distribution

#### Error Message
```
WSL distribution 'MyDistro' is not supported
```

#### Solutions
```powershell
# List supported distributions
Get-Content .\Install-CorporateSSL-WSL.ps1 | Select-String "WSLDistros.*="

# Use a supported distribution
.\Install-CorporateSSL-WSL.ps1 -WSLDistro "Ubuntu-22.04"

# Or try auto-detection
.\Install-CorporateSSL-WSL.ps1
```

### 6. Export Directory Access Denied

#### Error Message
```
Access denied when creating export directory
```

#### Solutions
```powershell
# Use a different export path
.\Install-CorporateSSL-WSL.ps1 -CertificateExportPath "$env:TEMP\certificates"

# Or create directory manually
New-Item -ItemType Directory -Path "$env:UserProfile\certificates" -Force

# Check permissions
Get-Acl "$env:UserProfile\certificates"
```

### 7. Curl Not Available in WSL

#### Error Message
```
curl is not available in the target WSL distribution
```

#### Solutions
The script should automatically install curl, but if it fails:

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y curl ca-certificates

# RHEL/CentOS/Fedora
sudo yum install -y curl ca-certificates
# or
sudo dnf install -y curl ca-certificates

# SUSE
sudo zypper install -y curl ca-certificates

# Arch
sudo pacman -Sy curl ca-certificates
```

### 8. Certificate Export Fails

#### Error Message
```
Failed to export certificate to file
```

#### Solutions
```powershell
# Check if export directory exists and is writable
Test-Path "$env:UserProfile\certificates"
New-Item -ItemType Directory -Path "$env:UserProfile\certificates" -Force

# Try different export path
.\Install-CorporateSSL-WSL.ps1 -CertificateExportPath "C:\Temp\certs"

# Run as Administrator
```

### 9. Script Execution Policy Issues

#### Error Message
```
Execution of scripts is disabled on this system
```

#### Solutions
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set execution policy (run as Administrator)
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser

# Or bypass for single execution
PowerShell -ExecutionPolicy Bypass -File ".\Install-CorporateSSL-WSL.ps1"
```

### 10. Network Connectivity Issues

#### Error Message
```
Timeout when testing SSL connectivity
```

#### Solutions
```powershell
# Increase timeout
.\Install-CorporateSSL-WSL.ps1 -TestTimeout 60

# Test with fewer domains
.\Install-CorporateSSL-WSL.ps1 -TestDomains @("https://google.com") -TestTimeout 45

# Check proxy settings in WSL
```

```bash
# In WSL, check proxy settings
env | grep -i proxy

# Test basic connectivity
ping google.com
wget --spider https://google.com
```

## Advanced Troubleshooting

### Debug Mode

Enable maximum verbosity for troubleshooting:

```powershell
.\Install-CorporateSSL-WSL.ps1 -Verbose -DryRun -ExportFormat Both
```

### Manual Certificate Verification

1. **Check Windows Certificate Stores:**
```powershell
# List all certificates with "CA" in name
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*CA*" } | Select-Object Subject, Thumbprint, NotAfter

# Check specific certificate
Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq "YOUR_THUMBPRINT" } | Format-List *
```

2. **Verify Certificate Export:**
```powershell
# Check exported certificate format
Get-Content "$env:UserProfile\certificates\YourCert.crt"

# Verify PEM format
$cert = Get-Content "$env:UserProfile\certificates\YourCert.crt" -Raw
$cert -match "-----BEGIN CERTIFICATE-----" -and $cert -match "-----END CERTIFICATE-----"
```

3. **Test WSL Certificate Installation:**
```bash
# Check certificate is copied
ls -la /usr/local/share/ca-certificates/

# Verify certificate content
cat /usr/local/share/ca-certificates/YourCert.crt

# Update certificates manually
sudo update-ca-certificates --verbose

# Check certificate store
ls -la /etc/ssl/certs/ | grep -i your_cert
```

### Log Analysis

The script creates detailed logs in the `logs` directory. Check these for detailed error information:

```powershell
# View latest log
Get-ChildItem .\logs\*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1 | Get-Content

# Search for errors in logs
Select-String -Path ".\logs\*.log" -Pattern "ERROR" -Context 2

# Search for specific certificate
Select-String -Path ".\logs\*.log" -Pattern "YourCompany" -Context 1
```

### Environment Validation

Run the test suite to validate your environment:

```powershell
.\tests\Test-WSLSSLInspector.ps1 -Verbose

# Skip WSL tests if WSL is not available
.\tests\Test-WSLSSLInspector.ps1 -SkipWSLTests -Verbose
```

## Known Limitations

### 1. Multiple SSL Inspection Layers
Some corporate environments have multiple SSL inspection layers. You may need to install certificates from multiple vendors:

```powershell
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("YourCompany", "BlueCoat", "Forcepoint", "McAfee") -RequireAllCerts
```

### 2. Intermediate Certificate Chains
Some applications require the complete certificate chain:

```powershell
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("CA", "Intermediate", "Root") -RequireAllCerts
```

### 3. Application-Specific Certificates
Some applications may require additional configuration beyond system certificates:

```bash
# Node.js
export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt

# Python
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# Git
git config --global http.sslCAInfo /etc/ssl/certs/ca-certificates.crt
```

## Getting Help

### 1. Enable Detailed Logging
Always use `-Verbose` and check log files:

```powershell
.\Install-CorporateSSL-WSL.ps1 -Verbose -ExportFormat Both
```

### 2. Run Dry Run First
Use `-DryRun` to see what the script would do:

```powershell
.\Install-CorporateSSL-WSL.ps1 -DryRun -Verbose
```

### 3. Export Analysis Results
Export detailed analysis for review:

```powershell
.\Install-CorporateSSL-WSL.ps1 -DryRun -ExportFormat Both -CertificateExportPath "C:\Analysis"
```

### 4. Check System Requirements
- Windows 10/11 with WSL2
- PowerShell 5.1 or higher
- Administrator privileges
- WSL distribution with curl support

### 5. Collect Diagnostic Information

Create a diagnostic report:

```powershell
# System information
Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, TotalPhysicalMemory

# WSL information
wsl --version
wsl -l -v

# PowerShell version
$PSVersionTable

# Certificate store summary
@("LocalMachine\Root", "LocalMachine\CA", "CurrentUser\Root", "CurrentUser\CA") | ForEach-Object {
    $count = (Get-ChildItem "Cert:\$_" -ErrorAction SilentlyContinue).Count
    "$_: $count certificates"
}
```

If you continue to experience issues, provide this diagnostic information along with:
- The complete error message
- The command you ran
- The relevant log file content
- Your WSL distribution and version
