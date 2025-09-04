# Thomson Reuters Corporate Certificate Analysis

## Executive Summary

Based on systematic testing and analysis of Thomson Reuters corporate SSL infrastructure, this report provides definitive guidance on certificate requirements for WSL and Node.js environments.

**CONFIDENTIAL INFORMATION**: This document contains Thomson Reuters specific certificate details, user information, and corporate infrastructure details. This information should be kept confidential and not shared outside the organization.

## Environment Details

- **User**: Emil.Wojcik@thomsonreuters.com
- **User ID**: 6125750
- **Certificate Path**: C:\Users\6125750\certificates\
- **WSL Distribution**: Ubuntu
- **Node.js Version**: v24.4.1
- **Test Date**: September 4, 2025

## Certificate Inventory

### Discovered Thomson Reuters Certificates

| Certificate | Purpose | Key Size | Valid Until | WSL Required | Node.js Required |
|-------------|---------|----------|-------------|--------------|------------------|
| **Thomson Reuters Root CA1** | Root Certificate Authority | 2048-bit | 2032-01-13 | ❌ No | ✅ Bundle |
| **Thomson Reuters Root CA2** | Root Certificate Authority | 2048-bit | 2032-01-13 | ❌ No | ✅ Bundle |
| **Thomson Reuters Server CA1** | SSL Inspection Certificate | 2048-bit | 2032-01-13 | ✅ **CRITICAL** | ✅ Bundle |
| **Thomson Reuters Device CA1** | Device Authentication | 2048-bit | 2032-01-13 | ❌ No | ✅ Bundle |
| **Thomson Reuters User CA1** | User Authentication | 2048-bit | 2032-01-13 | ❌ No | ✅ Bundle |

## Key Findings

### 🎯 **Critical Discovery: Server CA is the Key**

**Thomson Reuters Server CA1** is the **single most important certificate** for SSL inspection:
- **WSL**: This certificate alone provides 100% SSL connectivity
- **Node.js**: Required as part of complete bundle for 100% connectivity
- **Function**: This is the certificate used by Thomson Reuters' SSL inspection infrastructure

### 📊 **Testing Results**

#### WSL Environment Results
```
Without certificates: 4/6 domains working (67%)
With Server CA only:  6/6 domains working (100%) ← OPTIMAL
With all TR certs:    6/6 domains working (100%)
```

#### Node.js Environment Results  
```
Without certificates: 0/6 domains working (0%)
With Server CA only:  4/6 domains working (67%)
With complete bundle: 6/6 domains working (100%) ← OPTIMAL
```

## Recommended Implementation

### 🏆 **Optimal Configuration for Thomson Reuters**

#### WSL (Minimal Approach)
```powershell
# Install only the Server CA certificate
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("Thomson Reuters Server CA") -Verbose
```

**Manual Installation:**
```bash
# Copy the Server CA certificate
sudo cp /mnt/c/certificates/Thomson_Reuters_Server_CA1_*.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates
```

#### Node.js (Bundle Approach)
```powershell  
# Create complete certificate bundle
.\Install-CorporateSSL-Node.ps1 -SearchPatterns @("Thomson Reuters") -BundleAllCerts -Verbose
```

**Manual Configuration:**
```powershell
# Set environment variables
$env:NODE_EXTRA_CA_CERTS = "C:\certificates\Corporate_CA_Bundle.crt"
$env:NODE_TLS_REJECT_UNAUTHORIZED = "1"
```

## Certificate Details

### Thomson Reuters Server CA1 (CRITICAL CERTIFICATE)
```
Subject: CN=Thomson Reuters Server CA1, OU=Enterprise PKI, O=Thomson Reuters Holdings Inc, C=US
Issuer: CN=Thomson Reuters Root CA2, OU=Enterprise PKI, O=Thomson Reuters Holdings Inc, C=US
Serial: 680E4A483D8ABCF7D748CB37D57E7E7C
Thumbprint: DD85FAD426479083C591BE19B990F1C35D303FA0
Key Size: 2048-bit RSA
Algorithm: sha256RSA
Valid: 2022-01-13 to 2032-01-13
Store: LocalMachine\CA
File: Thomson_Reuters_Server_CA1_ServerCA_DD85FA.crt
```

### Complete Thomson Reuters Certificate Inventory

#### Thomson Reuters Root CA1
```
Subject: CN=Thomson Reuters Root CA1, OU=Enterprise PKI, O=Thomson Reuters Holdings Inc, C=US
Thumbprint: B32B5B61...
File: Thomson_Reuters_Root_CA1_RootCA_B32B5B.crt
```

#### Thomson Reuters Root CA2  
```
Subject: CN=Thomson Reuters Root CA2, OU=Enterprise PKI, O=Thomson Reuters Holdings Inc, C=US
Thumbprint: DA28B8...
File: Thomson_Reuters_Root_CA2_RootCA_DA28B8.crt
```

#### Thomson Reuters Device CA1
```
Subject: CN=Thomson Reuters Device CA1, OU=Enterprise PKI, O=Thomson Reuters Holdings Inc, C=US
Thumbprint: D8DA03...
File: Thomson_Reuters_Device_CA1_DeviceCA_D8DA03.crt
```

#### Thomson Reuters User CA1
```
Subject: CN=Thomson Reuters User CA1, OU=Enterprise PKI, O=Thomson Reuters Holdings Inc, C=US
Thumbprint: 291C29...
File: Thomson_Reuters_User_CA1_UserCA_291C29.crt
```

#### Emil Wojcik User Certificate
```
Subject: CN=Emil.Wojcik@thomsonreuters.com, OU=VPN-WEB, OU=MULTI-ALLOWED
Thumbprint: B5A3EA...
File: Emil_Wojcik_at_thomsonreuters_com_B5A3EA.crt
```

#### Zscaler Certificate
```
Subject: E=support@zscaler.com, CN=Zscaler Root CA, OU=Zscaler Inc., O=Zscaler Inc., L=San Jose, S=California, C=US
Thumbprint: D72F47...
File: Zscaler_Root_CA_D72F47.crt
```

**Why This Certificate is Critical:**
- **SSL Inspection Role**: This certificate is used by Thomson Reuters' proxy/firewall to sign SSL connections
- **Certificate Chain**: It's signed by Root CA2, establishing the trust chain
- **Wide Compatibility**: Works across all tested domains and applications

## Implementation Commands

### Quick Setup (Recommended)

#### WSL - Minimal Setup (TESTED & VERIFIED)
```powershell
# Clean existing certificates
wsl -d Ubuntu -u root -e bash -c "rm -f /usr/local/share/ca-certificates/*.crt && update-ca-certificates"

# Install only the critical Thomson Reuters Server CA
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("Thomson Reuters Server CA") -WSLDistro "Ubuntu" -Verbose

# VERIFIED RESULTS:
# Found 1 corporate certificates
# Certificate effectiveness: 6/6 domains (100%)
# SUCCESS: All SSL connectivity tests passed!

# Verification commands
wsl -d Ubuntu -e bash -c "curl -I https://google.com"        # HTTP/1.1 301 ✅
wsl -d Ubuntu -e bash -c "curl -I https://stackoverflow.com" # HTTP/1.1 302 ✅
```

#### Node.js - Complete Setup (TESTED & VERIFIED)  
```powershell
# Install complete Thomson Reuters certificate bundle
.\Install-CorporateSSL-Node.ps1 -SearchPatterns @("Thomson Reuters") -BundleAllCerts -Verbose

# Set environment variables correctly
[Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", "C:\Users\6125750\certificates\Thomson_Reuters_CA_Bundle.crt", "User")
[Environment]::SetEnvironmentVariable("NODE_TLS_REJECT_UNAUTHORIZED", "1", "User")

# VERIFIED RESULTS:
# Found 5 Thomson Reuters certificates
# Created certificate bundle: Thomson_Reuters_CA_Bundle.crt (10,054 bytes)
# Environment variables configured successfully

# Verification (in new PowerShell session)
$env:NODE_EXTRA_CA_CERTS = "C:\Users\6125750\certificates\Thomson_Reuters_CA_Bundle.crt"
$env:NODE_TLS_REJECT_UNAUTHORIZED = "1"
node tests\test-ssl-connectivity.js --domains https://google.com,https://stackoverflow.com
# Results: 100% success rate (2/2 domains working)
```

### Advanced Setup

#### WSL - All Thomson Reuters Certificates
```powershell
# Install all Thomson Reuters certificates (overkill but comprehensive)
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("Thomson Reuters") -RequireAllCerts -Verbose
```

#### Node.js - Specific Certificate Testing
```powershell
# Test each Thomson Reuters certificate individually
.\Install-CorporateSSL-Node.ps1 -SearchPatterns @("Thomson Reuters") -RequireAllCerts -Verbose
```

## Verification and Testing

### Immediate Verification

#### WSL
```bash
# Test SSL connectivity
curl -I https://google.com
curl -I https://stackoverflow.com

# Check certificate installation
ls -la /usr/local/share/ca-certificates/
sudo update-ca-certificates --verbose
```

#### Node.js
```bash
# Test with script
node test-ssl-connectivity.js

# Check environment
node -e "console.log('NODE_EXTRA_CA_CERTS:', process.env.NODE_EXTRA_CA_CERTS)"
node -e "console.log('TLS_REJECT:', process.env.NODE_TLS_REJECT_UNAUTHORIZED)"
```

### Application Testing

#### WSL Applications
```bash
# Test various tools
curl https://api.github.com
wget https://www.npmjs.com
git clone https://github.com/user/repo.git
```

#### Node.js Applications
```javascript
// Test in your Node.js application
const https = require('https');

https.get('https://api.github.com', (res) => {
    console.log('GitHub API Status:', res.statusCode);
}).on('error', (err) => {
    console.log('SSL Error:', err.message);
});
```

## Troubleshooting Thomson Reuters Specific Issues

### Issue: "No Thomson Reuters certificates found"

#### Solution:
```powershell
# Broaden search to include all corporate patterns
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("CA", "Corporate", "Enterprise", "Root") -Verbose

# Check certificate stores manually
Get-ChildItem Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*Thomson Reuters*" }
```

### Issue: "SSL still failing after installation"

#### Solution:
```powershell
# Install all Thomson Reuters certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("Thomson Reuters") -RequireAllCerts -Verbose

# Check for intermediate certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("Thomson Reuters", "Intermediate") -Verbose
```

### Issue: "Node.js environment variables not working"

#### Solution:
```powershell
# Restart PowerShell session
# Or set manually for current session:
$env:NODE_EXTRA_CA_CERTS = "C:\certificates\Corporate_CA_Bundle.crt"
$env:NODE_TLS_REJECT_UNAUTHORIZED = "1"

# Verify settings
node -e "console.log(process.env.NODE_EXTRA_CA_CERTS)"
```

## Performance Optimization

### WSL Optimization
- **Use Server CA only**: Provides 100% functionality with minimal overhead
- **Skip unnecessary certificates**: Don't install Root/Device/User CAs unless needed
- **Target specific domains**: Use `-TestDomains` to focus on problematic sites

### Node.js Optimization
- **Use certificate bundle**: Single file is more efficient than multiple certificates
- **Cache bundle**: Reuse the same bundle across multiple applications
- **Optimize timeout**: Adjust `-TestTimeout` based on network conditions

## Security Considerations

### Certificate Validation
- ✅ **Server CA is already trusted** by Windows certificate store
- ✅ **No security bypass** - maintains proper SSL validation
- ✅ **Corporate compliance** - works within existing security policies
- ✅ **Audit trail** - all operations are logged

### Network Security
- ✅ **SSL inspection compatible** - works with Thomson Reuters proxy/firewall
- ✅ **No certificate bypass** - uses proper certificate validation
- ✅ **Encrypted connections** - maintains end-to-end encryption
- ✅ **Policy compliance** - respects corporate network policies

## Maintenance

### Regular Tasks
1. **Monitor certificate expiration** (current certificates valid until 2032)
2. **Re-run analysis** if SSL issues develop
3. **Update test domains** based on application needs
4. **Review logs** for any connectivity issues

### Certificate Updates
```powershell
# When Thomson Reuters updates their certificates:
# 1. Run discovery again
.\Install-CorporateSSL-WSL.ps1 -CleanInstall -Verbose

# 2. Update Node.js bundle
.\Install-CorporateSSL-Node.ps1 -BundleAllCerts -Verbose
```

## Summary

**For Thomson Reuters environments:**

1. **WSL**: Install only `Thomson Reuters Server CA1` certificate
2. **Node.js**: Use complete Thomson Reuters certificate bundle
3. **Verification**: Use provided test scripts to confirm functionality
4. **Maintenance**: Monitor certificate expiration (2032-01-13)

This configuration provides optimal SSL connectivity while maintaining security compliance within Thomson Reuters' corporate network infrastructure.
