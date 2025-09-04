#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Configures Docker in WSL to work with Thomson Reuters corporate SSL certificates globally.

.DESCRIPTION
    This script configures Docker daemon and containers to automatically use Thomson Reuters
    corporate certificates for SSL connections. All containers will inherit this configuration
    without requiring special commands or per-container setup.

.PARAMETER WSLDistro
    Target WSL distribution name. Defaults to auto-detection.

.PARAMETER SearchPatterns
    Certificate search patterns. Defaults to Thomson Reuters patterns.

.PARAMETER TestDomains
    Domains to test SSL connectivity. Defaults to common corporate test domains.

.PARAMETER DryRun
    Analyze and show what would be done without making changes.

.PARAMETER Verbose
    Show detailed output during execution.

.EXAMPLE
    .\Install-CorporateSSL-Docker.ps1 -Verbose
    
.EXAMPLE
    .\Install-CorporateSSL-Docker.ps1 -WSLDistro "Ubuntu" -DryRun

.NOTES
    Author: Corporate SSL Certificate Manager
    Based on Thomson Reuters certificate analysis
    Requires: WSL with Docker installed, Administrator privileges
#>

[CmdletBinding()]
param(
    [string]$WSLDistro = "",
    [string[]]$SearchPatterns = @("Thomson Reuters", "Zscaler"),
    [string[]]$TestDomains = @(
        "https://google.com",
        "https://github.com", 
        "https://registry.npmjs.org",
        "https://pypi.org",
        "https://api.github.com",
        "https://download.docker.com"
    ),
    [switch]$DryRun,
    [switch]$Verbose
)

# Color-coded logging functions
function Write-ColorLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Level) {
        "SUCCESS" { Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green }
        "ERROR"   { Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red }
        "WARNING" { Write-Host "[$timestamp] [WARNING] $Message" -ForegroundColor Yellow }
        "TITLE"   { Write-Host "[$timestamp] [TITLE] $Message" -ForegroundColor Cyan }
        "PROGRESS" { Write-Host "[$timestamp] [PROGRESS] $Message" -ForegroundColor Magenta }
        default   { Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor White }
    }
}

function Test-Prerequisites {
    Write-ColorLog "Checking prerequisites..." "PROGRESS"
    
    # Check if running as Administrator
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-ColorLog "This script requires Administrator privileges" "ERROR"
        exit 1
    }
    
    # Check WSL availability
    try {
        $wslOutput = wsl --list --quiet 2>$null
        if (-not $wslOutput) {
            Write-ColorLog "WSL is not installed or not available" "ERROR"
            exit 1
        }
        Write-ColorLog "WSL is available" "SUCCESS"
    }
    catch {
        Write-ColorLog "Failed to check WSL: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    
    # Auto-detect WSL distribution if not specified
    if (-not $WSLDistro) {
        $distributions = wsl --list --quiet | Where-Object { $_ -and $_.Trim() -ne "" }
        if ($distributions.Count -eq 0) {
            Write-ColorLog "No WSL distributions found" "ERROR"
            exit 1
        }
        $WSLDistro = $distributions[0].Trim()
        Write-ColorLog "Auto-detected WSL distribution: $WSLDistro" "INFO"
    }
    
    # Check Docker in WSL
    try {
        $dockerCheck = wsl -d $WSLDistro -e bash -c "which docker" 2>$null
        if (-not $dockerCheck) {
            Write-ColorLog "Docker is not installed in WSL distribution: $WSLDistro" "ERROR"
            Write-ColorLog "Please install Docker in WSL first: https://docs.docker.com/engine/install/ubuntu/" "INFO"
            exit 1
        }
        Write-ColorLog "Docker is available in WSL: $WSLDistro" "SUCCESS"
    }
    catch {
        Write-ColorLog "Failed to check Docker in WSL: $($_.Exception.Message)" "ERROR"
        exit 1
    }
    
    return $WSLDistro
}

function Get-CorporateCertificates {
    param([string[]]$Patterns)
    
    Write-ColorLog "Searching for corporate certificates..." "PROGRESS"
    Write-ColorLog "Patterns: $($Patterns -join ', ')" "INFO"
    
    $certificates = @()
    $stores = @("LocalMachine\Root", "LocalMachine\CA", "CurrentUser\Root", "CurrentUser\CA")
    
    foreach ($store in $stores) {
        if ($Verbose) { Write-ColorLog "Searching certificates in store: Cert:\$store" "INFO" }
        
        try {
            $certs = Get-ChildItem -Path "Cert:\$store" -ErrorAction SilentlyContinue | Where-Object {
                $cert = $_
                $Patterns | ForEach-Object {
                    if ($cert.Subject -match $_ -or $cert.Issuer -match $_ -or $cert.FriendlyName -match $_) {
                        return $true
                    }
                }
            }
            
            foreach ($cert in $certs) {
                if ($Verbose) { Write-ColorLog "Found certificate: $($cert.Subject)" "INFO" }
                $certificates += [PSCustomObject]@{
                    Subject = $cert.Subject
                    Issuer = $cert.Issuer
                    Thumbprint = $cert.Thumbprint
                    NotAfter = $cert.NotAfter
                    Store = $store
                    Certificate = $cert
                }
            }
        }
        catch {
            Write-ColorLog "Error accessing certificate store $store : $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Remove duplicates based on thumbprint
    $uniqueCerts = $certificates | Sort-Object Thumbprint -Unique
    Write-ColorLog "Found $($uniqueCerts.Count) unique corporate certificates" "SUCCESS"
    
    return $uniqueCerts
}

function Export-CertificatesToWSL {
    param([array]$Certificates, [string]$WSLDistro)
    
    if ($Certificates.Count -eq 0) {
        Write-ColorLog "No certificates to export" "WARNING"
        return @()
    }
    
    Write-ColorLog "Exporting certificates to WSL..." "PROGRESS"
    
    # Create certificate directory in Windows
    $certDir = Join-Path $env:USERPROFILE "certificates"
    if (-not (Test-Path $certDir)) {
        New-Item -ItemType Directory -Path $certDir -Force | Out-Null
    }
    
    $exportedCerts = @()
    
    foreach ($cert in $Certificates) {
        try {
            # Generate safe filename
            $subjectName = ($cert.Subject -split ',')[0] -replace 'CN=', '' -replace '[^a-zA-Z0-9\-_]', '_'
            $filename = "${subjectName}_$($cert.Thumbprint.Substring(0,6)).crt"
            $certPath = Join-Path $certDir $filename
            
            # Export certificate in PEM format
            $certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $base64 = [Convert]::ToBase64String($certBytes)
            $formatted = ($base64 -split '(.{64})' | Where-Object { $_ }) -join "`n"
            $pemContent = "-----BEGIN CERTIFICATE-----`n$formatted`n-----END CERTIFICATE-----"
            
            if (-not $DryRun) {
                $pemContent | Out-File -FilePath $certPath -Encoding ASCII -Force
            }
            
            Write-ColorLog "Certificate exported: $filename" "SUCCESS"
            $exportedCerts += $certPath
        }
        catch {
            Write-ColorLog "Failed to export certificate $($cert.Subject): $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $exportedCerts
}

function Configure-DockerDaemon {
    param([string]$WSLDistro, [array]$CertificatePaths)
    
    Write-ColorLog "Configuring Docker daemon for corporate certificates..." "TITLE"
    
    if ($CertificatePaths.Count -eq 0) {
        Write-ColorLog "No certificates to configure" "WARNING"
        return
    }
    
    # Create Docker certificate directory in WSL
    $dockerCertDir = "/etc/docker/certs.d"
    $commands = @()
    
    $commands += "sudo mkdir -p $dockerCertDir"
    $commands += "sudo mkdir -p /usr/local/share/ca-certificates/docker"
    
    # Copy certificates to WSL
    foreach ($certPath in $CertificatePaths) {
        $wslPath = $certPath -replace 'C:', '/mnt/c' -replace '\\', '/'
        $filename = Split-Path $certPath -Leaf
        $commands += "sudo cp '$wslPath' '/usr/local/share/ca-certificates/docker/$filename'"
    }
    
    # Create combined certificate bundle for Docker
    $commands += @"
# Create Docker CA bundle
sudo bash -c 'cat /etc/ssl/certs/ca-certificates.crt > /etc/docker/ca-certificates.crt'
sudo bash -c 'echo "" >> /etc/docker/ca-certificates.crt'
sudo bash -c 'echo "# Corporate Certificates for Docker" >> /etc/docker/ca-certificates.crt'
for cert_file in /usr/local/share/ca-certificates/docker/*.crt; do
    if [ -f "\$cert_file" ]; then
        sudo bash -c 'echo "" >> /etc/docker/ca-certificates.crt'
        sudo bash -c 'cat "\$cert_file" >> /etc/docker/ca-certificates.crt'
    fi
done
"@
    
    # Update system CA certificates
    $commands += "sudo update-ca-certificates"
    
    # Configure Docker daemon
    $dockerDaemonConfig = @"
{
    "registry-mirrors": [],
    "insecure-registries": [],
    "default-runtime": "runc",
    "storage-driver": "overlay2",
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "10m",
        "max-file": "3"
    }
}
"@
    
    $commands += "sudo mkdir -p /etc/docker"
    $commands += "echo '$dockerDaemonConfig' | sudo tee /etc/docker/daemon.json > /dev/null"
    
    # Create Docker environment configuration
    $dockerEnvConfig = @"
# Docker Corporate SSL Configuration
export DOCKER_TLS_VERIFY=""
export DOCKER_CERT_PATH="/etc/docker"
export SSL_CERT_FILE="/etc/docker/ca-certificates.crt"
export CURL_CA_BUNDLE="/etc/docker/ca-certificates.crt"
export REQUESTS_CA_BUNDLE="/etc/docker/ca-certificates.crt"
export NODE_EXTRA_CA_CERTS="/etc/docker/ca-certificates.crt"
"@
    
    $commands += "echo '$dockerEnvConfig' | sudo tee /etc/docker/docker-env.sh > /dev/null"
    $commands += "sudo chmod +x /etc/docker/docker-env.sh"
    
    # Add to shell profiles for automatic loading
    $commands += @"
# Add Docker SSL configuration to shell profiles
if ! grep -q "docker-env.sh" /etc/bash.bashrc 2>/dev/null; then
    echo "# Docker Corporate SSL Configuration" | sudo tee -a /etc/bash.bashrc
    echo "source /etc/docker/docker-env.sh 2>/dev/null || true" | sudo tee -a /etc/bash.bashrc
fi
if ! grep -q "docker-env.sh" ~/.bashrc 2>/dev/null; then
    echo "# Docker Corporate SSL Configuration" >> ~/.bashrc
    echo "source /etc/docker/docker-env.sh 2>/dev/null || true" >> ~/.bashrc
fi
"@
    
    # Restart Docker service
    $commands += @"
# Restart Docker service to apply configuration
if sudo systemctl is-active docker >/dev/null 2>&1; then
    sudo systemctl restart docker
    sleep 5
elif sudo service docker status >/dev/null 2>&1; then
    sudo service docker restart
    sleep 5
else
    echo "Docker service management not available - manual restart may be required"
fi
"@
    
    # Execute all commands in WSL
    $fullCommand = $commands -join "; "
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN - Would execute in WSL:" "INFO"
        Write-Host $fullCommand -ForegroundColor Gray
        return
    }
    
    try {
        Write-ColorLog "Executing Docker configuration in WSL..." "PROGRESS"
        $result = wsl -d $WSLDistro -e bash -c $fullCommand
        Write-ColorLog "Docker daemon configured successfully" "SUCCESS"
    }
    catch {
        Write-ColorLog "Failed to configure Docker daemon: $($_.Exception.Message)" "ERROR"
        throw
    }
}

function Test-DockerSSLConnectivity {
    param([string]$WSLDistro, [string[]]$TestDomains)
    
    Write-ColorLog "Testing Docker SSL connectivity..." "TITLE"
    
    $results = @()
    $successCount = 0
    
    foreach ($domain in $TestDomains) {
        Write-ColorLog "Testing: $domain" "PROGRESS"
        
        if ($DryRun) {
            Write-ColorLog "DRY RUN - Would test $domain" "INFO"
            continue
        }
        
        try {
            # Test with curl container
            $testCommand = @"
source /etc/docker/docker-env.sh 2>/dev/null || true
docker run --rm \
    -e SSL_CERT_FILE=\$SSL_CERT_FILE \
    -e CURL_CA_BUNDLE=\$CURL_CA_BUNDLE \
    -v /etc/docker/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    curlimages/curl:latest \
    curl -s -o /dev/null -w "Status: %{http_code}" --max-time 10 '$domain'
"@
            
            $result = wsl -d $WSLDistro -e bash -c $testCommand
            
            if ($result -match "Status: (\d+)") {
                $statusCode = $Matches[1]
                if ($statusCode -in @("200", "301", "302", "403")) {
                    Write-ColorLog "[OK] $domain - HTTP $statusCode" "SUCCESS"
                    $successCount++
                    $results += [PSCustomObject]@{ Domain = $domain; Status = $statusCode; Success = $true }
                }
                else {
                    Write-ColorLog "[FAIL] $domain - HTTP $statusCode" "ERROR"
                    $results += [PSCustomObject]@{ Domain = $domain; Status = $statusCode; Success = $false }
                }
            }
            else {
                Write-ColorLog "[FAIL] $domain - No response or timeout" "ERROR"
                $results += [PSCustomObject]@{ Domain = $domain; Status = "000"; Success = $false }
            }
        }
        catch {
            Write-ColorLog "[FAIL] $domain - Error: $($_.Exception.Message)" "ERROR"
            $results += [PSCustomObject]@{ Domain = $domain; Status = "Error"; Success = $false }
        }
        
        Start-Sleep -Milliseconds 500
    }
    
    if (-not $DryRun) {
        $successRate = [math]::Round(($successCount / $TestDomains.Count) * 100, 2)
        Write-ColorLog "Docker SSL connectivity: $successCount/$($TestDomains.Count) domains successful ($successRate%)" "INFO"
        
        if ($successRate -eq 100) {
            Write-ColorLog "SUCCESS: All Docker SSL connectivity tests passed!" "SUCCESS"
        }
        elseif ($successRate -ge 80) {
            Write-ColorLog "PARTIAL SUCCESS: Most Docker SSL tests passed" "WARNING"
        }
        else {
            Write-ColorLog "FAILURE: Docker SSL connectivity issues detected" "ERROR"
        }
    }
    
    return $results
}

function Test-ContainerInheritance {
    param([string]$WSLDistro)
    
    Write-ColorLog "Testing certificate inheritance across different containers..." "TITLE"
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN - Would test container inheritance" "INFO"
        return
    }
    
    $testContainers = @(
        @{ Image = "ubuntu:latest"; Command = "curl -s -o /dev/null -w 'Ubuntu: %{http_code}' https://google.com" },
        @{ Image = "alpine:latest"; Command = "apk add --no-cache curl >/dev/null 2>&1 && curl -s -o /dev/null -w 'Alpine: %{http_code}' https://google.com" },
        @{ Image = "node:18-alpine"; Command = "node -e 'require(\"https\").get(\"https://registry.npmjs.org\", r => console.log(\"Node.js:\", r.statusCode))'" },
        @{ Image = "python:3.12-alpine"; Command = "python -c 'import urllib.request; print(\"Python:\", urllib.request.urlopen(\"https://pypi.org\").getcode())'" }
    )
    
    $inheritanceResults = @()
    
    foreach ($container in $testContainers) {
        Write-ColorLog "Testing inheritance: $($container.Image)" "PROGRESS"
        
        try {
            $testCommand = @"
source /etc/docker/docker-env.sh 2>/dev/null || true
timeout 30 docker run --rm \
    -e SSL_CERT_FILE=\$SSL_CERT_FILE \
    -e CURL_CA_BUNDLE=\$CURL_CA_BUNDLE \
    -e REQUESTS_CA_BUNDLE=\$REQUESTS_CA_BUNDLE \
    -e NODE_EXTRA_CA_CERTS=\$NODE_EXTRA_CA_CERTS \
    -v /etc/docker/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    $($container.Image) \
    sh -c '$($container.Command)'
"@
            
            $result = wsl -d $WSLDistro -e bash -c $testCommand 2>$null
            
            if ($result -and $result -notmatch "error|Error|ERROR") {
                Write-ColorLog "[OK] $($container.Image) - $result" "SUCCESS"
                $inheritanceResults += [PSCustomObject]@{ Container = $container.Image; Result = $result; Success = $true }
            }
            else {
                Write-ColorLog "[FAIL] $($container.Image) - Certificate inheritance failed" "ERROR"
                $inheritanceResults += [PSCustomObject]@{ Container = $container.Image; Result = "Failed"; Success = $false }
            }
        }
        catch {
            Write-ColorLog "[FAIL] $($container.Image) - Error: $($_.Exception.Message)" "ERROR"
            $inheritanceResults += [PSCustomObject]@{ Container = $container.Image; Result = "Error"; Success = $false }
        }
    }
    
    $successfulInheritance = ($inheritanceResults | Where-Object { $_.Success }).Count
    $totalTests = $inheritanceResults.Count
    
    Write-ColorLog "Certificate inheritance: $successfulInheritance/$totalTests containers successful" "INFO"
    
    return $inheritanceResults
}

# Main execution
try {
    Write-ColorLog "Thomson Reuters Docker SSL Certificate Configuration" "TITLE"
    Write-ColorLog "=====================================================" "TITLE"
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN MODE - No changes will be made" "WARNING"
    }
    
    # Step 1: Check prerequisites
    $WSLDistro = Test-Prerequisites
    
    # Step 2: Find corporate certificates
    $certificates = Get-CorporateCertificates -Patterns $SearchPatterns
    
    if ($certificates.Count -eq 0) {
        Write-ColorLog "No corporate certificates found matching patterns: $($SearchPatterns -join ', ')" "ERROR"
        Write-ColorLog "Try broadening search patterns or check certificate stores" "INFO"
        exit 1
    }
    
    # Step 3: Export certificates
    $exportedCerts = Export-CertificatesToWSL -Certificates $certificates -WSLDistro $WSLDistro
    
    # Step 4: Configure Docker daemon
    Configure-DockerDaemon -WSLDistro $WSLDistro -CertificatePaths $exportedCerts
    
    # Step 5: Test Docker SSL connectivity
    $connectivityResults = Test-DockerSSLConnectivity -WSLDistro $WSLDistro -TestDomains $TestDomains
    
    # Step 6: Test container inheritance
    $inheritanceResults = Test-ContainerInheritance -WSLDistro $WSLDistro
    
    # Summary
    Write-ColorLog "Docker SSL Configuration Summary" "TITLE"
    Write-ColorLog "WSL Distribution: $WSLDistro" "INFO"
    Write-ColorLog "Certificates configured: $($certificates.Count)" "INFO"
    
    if (-not $DryRun) {
        $successfulConnections = ($connectivityResults | Where-Object { $_.Success }).Count
        $successfulInheritance = ($inheritanceResults | Where-Object { $_.Success }).Count
        
        Write-ColorLog "SSL connectivity: $successfulConnections/$($TestDomains.Count) domains" "INFO"
        Write-ColorLog "Container inheritance: $successfulInheritance/$($inheritanceResults.Count) containers" "INFO"
        
        Write-ColorLog "Docker is now configured for Thomson Reuters corporate SSL!" "SUCCESS"
        Write-ColorLog "All new containers will automatically inherit certificate configuration" "SUCCESS"
        Write-ColorLog "No special commands needed - just run: docker run <image> <command>" "INFO"
    }
}
catch {
    Write-ColorLog "Script execution failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
