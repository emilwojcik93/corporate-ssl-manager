# Installation Guide

## Prerequisites

### System Requirements
- **Windows 10/11** with PowerShell 5.1+
- **WSL 2** with Ubuntu (or compatible distribution)
- **Docker** installed in WSL (optional, for Docker script)
- **Node.js** 14+ (optional, for Node.js script)
- **Administrator privileges** for PowerShell execution

### WSL Setup
```powershell
# Enable WSL and install Ubuntu
wsl --install Ubuntu
```

### Docker Setup (Optional)
```bash
# In WSL Ubuntu
sudo apt update
sudo apt install docker.io
sudo systemctl enable docker
sudo systemctl start docker
sudo usermod -aG docker $USER
```

## Step-by-Step Installation

### 1. WSL SSL Certificate Setup

**Purpose**: Configure WSL to work with corporate SSL inspection

**Script**: `Install-CorporateSSL-WSL.ps1`

**Steps**:
```powershell
# Basic installation (auto-detect corporate certificates)
.\Install-CorporateSSL-WSL.ps1 -Verbose

# Target specific corporate certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("YourCompany", "Corporate CA") -Verbose

# Dry run to see what would be installed
.\Install-CorporateSSL-WSL.ps1 -DryRun -Verbose

# Clean installation (remove existing first)
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("YourCompany") -RequireAllCerts -Verbose
```

**What it does**:
1. Scans Windows certificate stores for corporate certificates
2. Excludes public CAs (DigiCert, Let's Encrypt, etc.)
3. Tests each certificate against multiple domains
4. Installs only effective certificates in WSL
5. Updates WSL certificate store

**Expected Result**: 
- WSL can access HTTPS sites through corporate proxy
- `curl https://google.com` works without SSL errors

### 2. Node.js SSL Certificate Setup

**Purpose**: Configure Node.js applications to work with corporate SSL inspection

**Script**: `Install-CorporateSSL-Node.ps1`

**Steps**:
```powershell
# Basic installation with certificate bundle
.\Install-CorporateSSL-Node.ps1 -SearchPatterns @("YourCompany") -BundleAllCerts -Verbose

# Test specific certificate effectiveness
.\Install-CorporateSSL-Node.ps1 -SearchPatterns @("Corporate", "CA") -RequireAllCerts -Verbose

# Create certificate bundle only
.\Install-CorporateSSL-Node.ps1 -BundleAllCerts -DryRun -Verbose
```

**What it does**:
1. Finds corporate certificates from Windows stores
2. Creates comprehensive certificate bundle
3. Sets Node.js environment variables:
   - `NODE_EXTRA_CA_CERTS`
   - `NODE_TLS_REJECT_UNAUTHORIZED`
4. Tests Node.js SSL connectivity

**Expected Result**:
- Node.js applications can access HTTPS APIs
- `node test-ssl-connectivity.js` shows 100% success rate

### 3. Docker SSL Certificate Setup

**Purpose**: Configure Docker containers to work with corporate SSL inspection globally

**Script**: `Install-CorporateSSL-Docker.ps1`

**Steps**:
```powershell
# Complete Docker setup with cleanup
.\Install-CorporateSSL-Docker.ps1 -SearchPatterns @("YourCompany") -CleanInstall -Verbose

# Basic installation
.\Install-CorporateSSL-Docker.ps1 -SearchPatterns @("Corporate", "CA") -Verbose

# Dry run to see configuration
.\Install-CorporateSSL-Docker.ps1 -DryRun -Verbose
```

**What it does**:
1. Creates Docker CA bundle with corporate certificates
2. Configures Docker registry certificates for pull/push operations
3. Installs system-wide CA certificates
4. Creates `docker-corp` wrapper command
5. Sets up Docker environment and aliases

**Expected Result**:
- Standard `docker pull` commands work
- `docker-corp run` containers can access HTTPS sites
- All containers automatically use corporate certificates

## Installation Order

**Recommended installation order**:

1. **WSL First**: `.\Install-CorporateSSL-WSL.ps1`
2. **Node.js Second**: `.\Install-CorporateSSL-Node.ps1` 
3. **Docker Last**: `.\Install-CorporateSSL-Docker.ps1`

**Why this order**:
- WSL provides the foundation for other environments
- Node.js setup is independent and can be done separately
- Docker setup builds on WSL certificate configuration

## Common Installation Patterns

### Pattern 1: Auto-Discovery
```powershell
# Let scripts auto-detect corporate certificates
.\Install-CorporateSSL-WSL.ps1 -Verbose
.\Install-CorporateSSL-Node.ps1 -BundleAllCerts -Verbose
.\Install-CorporateSSL-Docker.ps1 -CleanInstall -Verbose
```

### Pattern 2: Company-Specific
```powershell
# Target specific company certificates
$patterns = @("YourCompany", "Corporate CA", "Enterprise PKI")

.\Install-CorporateSSL-WSL.ps1 -SearchPatterns $patterns -Verbose
.\Install-CorporateSSL-Node.ps1 -SearchPatterns $patterns -BundleAllCerts -Verbose
.\Install-CorporateSSL-Docker.ps1 -SearchPatterns $patterns -CleanInstall -Verbose
```

### Pattern 3: Comprehensive
```powershell
# Install all effective certificates
.\Install-CorporateSSL-WSL.ps1 -RequireAllCerts -Verbose
.\Install-CorporateSSL-Node.ps1 -RequireAllCerts -BundleAllCerts -Verbose
.\Install-CorporateSSL-Docker.ps1 -CleanInstall -Verbose
```

## Verification

### WSL Verification
```bash
# Test SSL connectivity
curl -I https://google.com
curl -I https://github.com

# Check installed certificates
ls -la /usr/local/share/ca-certificates/
sudo update-ca-certificates --verbose
```

### Node.js Verification
```bash
# Check environment variables
echo $NODE_EXTRA_CA_CERTS
echo $NODE_TLS_REJECT_UNAUTHORIZED

# Test SSL connectivity
node tests/test-ssl-connectivity.js
```

### Docker Verification
```bash
# Test standard Docker operations
docker pull hello-world

# Test HTTPS in containers
docker-corp run --rm curlimages/curl:latest curl https://google.com
docker-corp run --rm curlimages/curl:latest curl https://github.com

# Quick tests (after restarting terminal)
docker-test-google
docker-test-github
```

## Troubleshooting Installation

### Issue: "No certificates found"
```powershell
# Broaden search patterns
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("CA", "Root", "Corporate", "Enterprise") -Verbose

# Check certificate stores manually
Get-ChildItem Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*Corporate*" }
```

### Issue: "SSL tests still failing"
```powershell
# Install all effective certificates
.\Install-CorporateSSL-WSL.ps1 -RequireAllCerts -Verbose

# Check for intermediate certificates
.\Install-CorporateSSL-WSL.ps1 -SearchPatterns @("Intermediate", "Issuing") -Verbose
```

### Issue: "Docker containers still failing"
```bash
# Test docker-corp directly
/usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -v https://google.com

# Check certificate mounting
docker-corp run --rm ubuntu ls -la /etc/ssl/certs/ca-certificates.crt
```

## Next Steps

After successful installation:

1. **Restart terminals** to load new environment variables
2. **Test applications** that previously had SSL issues
3. **Update development workflows** to use new commands
4. **Monitor certificate expiration** dates
5. **Re-run scripts** if corporate certificates are updated
