# Usage Guide

## Overview

This guide provides detailed instructions for using the Corporate SSL Certificate Manager in various scenarios.

## Prerequisites

### System Requirements
- **Windows 10/11** or Windows Server 2019/2022
- **PowerShell 5.1+** (PowerShell Core 7+ recommended)
- **Administrator privileges** for certificate store access

### Environment-Specific Requirements

#### For WSL
- **WSL 2** installed and configured
- **Linux distribution** installed (Ubuntu, Debian, Fedora, etc.)
- **Root access** in WSL distribution

#### For Node.js
- **Node.js 14+** installed
- **npm** or **yarn** (for package management)

## Basic Usage

### WSL Certificate Installation

#### Automatic Installation (Recommended)
```powershell
# Run with verbose output for detailed progress
.\Install-CorporateSSL-WSL.ps1 -Verbose
```

#### Dry Run (Analysis Only)
```powershell
# Analyze certificates without installing
.\Install-CorporateSSL-WSL.ps1 -DryRun -Verbose
```

#### Clean Installation
```powershell
# Remove existing certificates and install fresh
.\Install-CorporateSSL-WSL.ps1 -CleanInstall -Verbose
```

### Node.js Certificate Configuration

#### Complete Bundle Installation
```powershell
# Install all effective certificates as a bundle
.\Install-CorporateSSL-Node.ps1 -BundleAllCerts -Verbose
```

#### Individual Certificate Testing
```powershell
# Test each certificate individually
.\Install-CorporateSSL-Node.ps1 -RequireAllCerts -Verbose
```

## Advanced Usage

### Custom Search Patterns

#### Corporate-Specific Patterns
```powershell
# Search for company-specific certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("CA", "YourCompany", "Internal") -Verbose
```

#### SSL Inspection Focus
```powershell
# Focus on SSL inspection certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("SSL", "TLS", "Proxy", "Inspection") -Verbose
```

### Multi-Distribution Support

#### Specific WSL Distribution
```powershell
# Target specific WSL distribution
.\Install-CorporateSSL-WSL.ps1 -WSLDistro "Ubuntu-22.04" -Verbose
```

#### List Available Distributions
```powershell
# Check available WSL distributions
wsl -l -v
```

### Custom Test Domains

#### Internal Corporate Domains
```powershell
# Test against internal corporate domains
.\Install-CorporateSSL-WSL.ps1 -TestDomains @("https://internal.company.com", "https://app.company.com") -Verbose
```

#### Specific Problematic Domains
```powershell
# Test against domains that are failing
.\Install-CorporateSSL-WSL.ps1 -TestDomains @("https://problematic-site.com") -Verbose
```

## Testing and Verification

### WSL Testing

#### Manual SSL Test
```bash
# In WSL, test SSL connectivity
curl -v https://google.com
curl -I https://github.com
```

#### Certificate Verification
```bash
# Check installed certificates
ls -la /usr/local/share/ca-certificates/

# Update certificate store manually
sudo update-ca-certificates --verbose

# Check certificate details
openssl x509 -in /usr/local/share/ca-certificates/certificate.crt -text -noout
```

### Node.js Testing

#### Environment Variables
```powershell
# Check current Node.js environment
Get-ChildItem env:NODE*
```

#### SSL Connectivity Test
```bash
# Test with the provided script
node test-ssl-connectivity.js

# Test specific certificate
node test-ssl-connectivity.js --cert "C:\certificates\certificate.crt"

# Test specific domains
node test-ssl-connectivity.js --domains "https://google.com,https://github.com"
```

#### Programmatic Testing
```javascript
// Test in Node.js application
const https = require('https');

https.get('https://google.com', (res) => {
    console.log('Status Code:', res.statusCode);
    console.log('SSL Working:', res.statusCode >= 200 && res.statusCode < 400);
}).on('error', (err) => {
    console.log('SSL Error:', err.message);
});
```

## Output Files

### Generated Files
```
%USERPROFILE%\certificates\
├── Corporate_CA_Bundle.crt           # Node.js certificate bundle
├── Server_CA_ABC123.crt              # Individual certificates
├── Root_CA_DEF456.crt
├── Certificate_Analysis_TIMESTAMP.csv # Analysis results
└── Certificate_Analysis_TIMESTAMP.json

.\logs\
├── WSL_SSL_Installation_TIMESTAMP.log    # WSL installation log
└── Node_SSL_Installation_TIMESTAMP.log   # Node.js installation log
```

### CSV Analysis Format
```csv
Thumbprint,Subject,Issuer,IsValid,Store,SuccessRate,Status,ExportedFile
ABC123...,CN=Corporate Root CA,CN=Corporate Root CA,True,LocalMachine\Root,100,Installed,C:\certificates\...
```

### JSON Analysis Format
```json
{
  "Thumbprint": "ABC123...",
  "Subject": "CN=Corporate Root CA",
  "Issuer": "CN=Corporate Root CA", 
  "IsValid": true,
  "Store": "LocalMachine\\Root",
  "TestResult": {
    "SuccessCount": 6,
    "SuccessRate": 100,
    "IsEffective": true
  },
  "Status": "Installed"
}
```

## Environment Configuration

### WSL Environment Variables
```bash
# No environment variables needed - certificates installed in system store
```

### Node.js Environment Variables
```powershell
# Set automatically by the script
$env:NODE_EXTRA_CA_CERTS = "C:\certificates\Corporate_CA_Bundle.crt"
$env:NODE_TLS_REJECT_UNAUTHORIZED = "1"  # Enable proper SSL validation
$env:NODE_NO_WARNINGS = "1"             # Suppress Node.js warnings
```

## Performance Optimization

### WSL Optimization
- **Minimal certificates**: Install only the most effective certificate
- **Fast testing**: Use `-RequireAllCerts $false` to stop after first success
- **Targeted search**: Use specific `-SearchPatterns` to reduce search time

### Node.js Optimization  
- **Bundle approach**: Single file with all certificates reduces I/O
- **Environment caching**: Variables persist across Node.js processes
- **Timeout tuning**: Adjust `-TestTimeout` based on network conditions

## Best Practices

### Security
1. **Run as Administrator** for certificate store access
2. **Use `-DryRun` first** to understand what will be changed
3. **Review logs** for audit trail
4. **Test in development** before production deployment

### Performance
1. **Use minimal certificate sets** when possible
2. **Cache results** by saving effective certificate lists
3. **Target specific domains** if you know which ones are problematic
4. **Use bundles for Node.js** to reduce file system overhead

### Maintenance
1. **Re-run periodically** as corporate certificates may change
2. **Monitor logs** for certificate expiration warnings
3. **Update test domains** based on your application needs
4. **Keep backups** of working configurations

## Integration Examples

### CI/CD Pipeline
```powershell
# In build script
if (Test-Path ".\Install-CorporateSSL-WSL.ps1") {
    .\Install-CorporateSSL-WSL.ps1 -DryRun -Verbose
    if ($LASTEXITCODE -eq 0) {
        .\Install-CorporateSSL-WSL.ps1 -Verbose
    }
}
```

### Docker Integration
```dockerfile
# In Dockerfile for WSL-based containers
COPY certificates/ /usr/local/share/ca-certificates/
RUN update-ca-certificates
```

### Node.js Application
```javascript
// In Node.js application startup
if (process.env.NODE_EXTRA_CA_CERTS) {
    console.log('Using corporate certificates:', process.env.NODE_EXTRA_CA_CERTS);
}
```

## Next Steps

1. **Run the appropriate installer** for your environment
2. **Verify SSL connectivity** using the test scripts
3. **Review the analysis report** (CORPORATE-CERTIFICATE-ANALYSIS.md)
4. **Configure your applications** to use the installed certificates
5. **Monitor and maintain** the certificate configuration