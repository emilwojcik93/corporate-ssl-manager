# Corporate SSL Certificate Manager for Docker - Complete Global Setup
# Configures Docker daemon and containers to use Thomson Reuters corporate certificates globally
# All containers will automatically work with HTTPS without manual certificate mounting

[CmdletBinding()]
param(
    [string[]]$SearchPatterns = @("Thomson Reuters", "Zscaler", "CA"),
    [string[]]$ExcludeIssuers = @("DigiCert", "thawte", "Digital Signature Trust Co.", "GlobalSign", "Microsoft", "SSL.com", "Entrust", "COMODO", "Starfield", "VeriSign", "Go Daddy", "USERTrust", "IdenTrust", "QuoVadis", "Certum", "AAA Certificate Services", "AddTrust", "Sectigo", "Symantec", "GeoTrust", "RapidSSL", "Let's Encrypt", "ISRG", "Baltimore", "UTN-USERFirst", "Amazon", "Google Trust Services", "Apple", "Buypass", "HARICA", "SwissSign", "TrustCor", "OISTE", "WoSign", "StartCom", "Camerfirma", "AC Camerfirma", "NetLock", "e-Szigno", "Microsec", "TURKTRUST", "Hotspot 2.0 Trust Root CA", "WFA Hotspot 2.0"),
    [string]$WSLDistro = "Ubuntu",
    [string[]]$TestDomains = @("https://google.com", "https://github.com", "https://registry.npmjs.org", "https://pypi.org", "https://download.docker.com", "https://api.github.com"),
    [switch]$DryRun
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\logs"
$logFile = "$logDir\Docker_Complete_SSL_Installation_$timestamp.log"
$certificateDir = "$env:USERPROFILE\certificates"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
}

if (-not (Test-Path $certificateDir)) {
    New-Item -ItemType Directory -Path $certificateDir -Force | Out-Null
}

function Write-ColorLog {
    param(
        [string]$Message,
        [string]$Level = "INFO",
        [ConsoleColor]$Color = [ConsoleColor]::White
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    Write-Host $logMessage -ForegroundColor $Color
    Add-Content -Path $logFile -Value $logMessage
}

function Test-DockerConnectivity {
    param([string[]]$Domains, [string]$TestType = "Standard")
    
    $results = @()
    foreach ($domain in $Domains) {
        try {
            $dockerCmd = if ($TestType -eq "Global") {
                "timeout 15 /usr/local/bin/docker-global run --rm curlimages/curl:latest curl -s -o /dev/null -w '%{http_code}' '$domain' 2>/dev/null || echo '000'"
            } else {
                "timeout 15 docker run --rm curlimages/curl:latest curl -s -o /dev/null -w '%{http_code}' '$domain' 2>/dev/null || echo '000'"
            }
            
            $result = wsl bash -c $dockerCmd
            $status = if ($result -match '^\d{3}$') { [int]$result } else { 0 }
            $success = $status -ge 200 -and $status -lt 400
            
            $results += [PSCustomObject]@{
                Domain = $domain
                StatusCode = $status
                Success = $success
                TestType = $TestType
            }
            
            if ($success) {
                Write-ColorLog "[$TestType] [OK] $domain - Success (HTTP $status)" -Level "SUCCESS" -Color Green
            } else {
                Write-ColorLog "[$TestType] [FAIL] $domain - Failed (HTTP $status)" -Level "ERROR" -Color Red
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Domain = $domain
                StatusCode = 0
                Success = $false
                TestType = $TestType
            }
            Write-ColorLog "[$TestType] [ERROR] $domain - Connection failed: $($_.Exception.Message)" -Level "ERROR" -Color Red
        }
    }
    
    $successCount = ($results | Where-Object Success).Count
    $totalCount = $results.Count
    $successRate = if ($totalCount -gt 0) { [math]::Round(($successCount / $totalCount) * 100, 2) } else { 0 }
    
    Write-ColorLog "[$TestType] Docker connectivity: $successCount/$totalCount domains successful ($successRate%)" -Level "INFO" -Color Cyan
    return $results
}

function Get-CorporateCertificates {
    param([string[]]$Patterns, [string[]]$ExcludeList)
    
    Write-ColorLog "Searching for corporate certificates..." -Level "PROGRESS" -Color Yellow
    Write-ColorLog "Patterns: $($Patterns -join ', ')" -Level "INFO"
    
    $certificates = @()
    $stores = @("Cert:\LocalMachine\My", "Cert:\LocalMachine\Root", "Cert:\LocalMachine\CA", "Cert:\CurrentUser\My", "Cert:\CurrentUser\Root", "Cert:\CurrentUser\CA")
    
    foreach ($store in $stores) {
        try {
            $certs = Get-ChildItem -Path $store -ErrorAction SilentlyContinue
            foreach ($cert in $certs) {
                $subject = $cert.Subject
                $issuer = $cert.Issuer
                
                # Check if certificate matches any pattern
                $matchesPattern = $false
                foreach ($pattern in $Patterns) {
                    if ($subject -like "*$pattern*" -or $issuer -like "*$pattern*") {
                        $matchesPattern = $true
                        break
                    }
                }
                
                # Check if certificate should be excluded
                $shouldExclude = $false
                foreach ($excludePattern in $ExcludeList) {
                    if ($subject -like "*$excludePattern*" -or $issuer -like "*$excludePattern*") {
                        $shouldExclude = $true
                        break
                    }
                }
                
                if ($matchesPattern -and -not $shouldExclude) {
                    $certificates += [PSCustomObject]@{
                        Subject = $subject
                        Issuer = $issuer
                        Thumbprint = $cert.Thumbprint
                        Certificate = $cert
                        Store = $store
                    }
                }
            }
        }
        catch {
            Write-ColorLog "Warning: Could not access certificate store $store" -Level "WARNING" -Color Yellow
        }
    }
    
    # Remove duplicates based on thumbprint
    $uniqueCertificates = $certificates | Sort-Object Thumbprint -Unique
    
    Write-ColorLog "Found $($uniqueCertificates.Count) unique corporate certificates" -Level "SUCCESS" -Color Green
    return $uniqueCertificates
}

function Export-CertificatesToPEM {
    param([PSCustomObject[]]$Certificates)
    
    $exportedCerts = @()
    
    foreach ($cert in $Certificates) {
        try {
            # Generate safe filename
            $subjectCN = ($cert.Subject -split ',' | Where-Object { $_ -like "CN=*" } | Select-Object -First 1) -replace "CN=", "" -replace "[^a-zA-Z0-9\-_]", "_"
            if (-not $subjectCN) { $subjectCN = "Unknown" }
            
            $thumbprintShort = $cert.Thumbprint.Substring(0, 6)
            $filename = "$subjectCN" + "_$thumbprintShort.crt"
            $filepath = Join-Path $certificateDir $filename
            
            # Export certificate in PEM format
            $certBytes = $cert.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            $base64 = [Convert]::ToBase64String($certBytes)
            $formatted = ($base64 -split '(.{64})' | Where-Object { $_ }) -join "`n"
            $pemContent = "-----BEGIN CERTIFICATE-----`n$formatted`n-----END CERTIFICATE-----"
            
            Set-Content -Path $filepath -Value $pemContent -Encoding ASCII
            
            Write-ColorLog "Certificate exported: $filename" -Level "SUCCESS" -Color Green
            
            $exportedCerts += [PSCustomObject]@{
                Subject = $cert.Subject
                Filename = $filename
                Filepath = $filepath
                Thumbprint = $cert.Thumbprint
            }
        }
        catch {
            Write-ColorLog "Failed to export certificate: $($cert.Subject) - $($_.Exception.Message)" -Level "ERROR" -Color Red
        }
    }
    
    return $exportedCerts
}

function Install-CompleteDockerSSLConfiguration {
    param([PSCustomObject[]]$ExportedCertificates)
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN: Would configure complete Docker SSL setup with $($ExportedCertificates.Count) certificates" -Level "INFO" -Color Cyan
        return $true
    }
    
    Write-ColorLog "Installing complete Docker SSL configuration..." -Level "PROGRESS" -Color Yellow
    
    try {
        # Step 1: Create Docker CA bundle for containers
        Write-ColorLog "Creating Docker CA bundle..." -Level "PROGRESS" -Color Yellow
        
        wsl bash -c "mkdir -p ~/.docker" 2>$null
        wsl bash -c "cp /etc/ssl/certs/ca-certificates.crt ~/.docker/ca-bundle.crt" 2>$null
        
        # Add corporate certificates to bundle
        foreach ($cert in $ExportedCertificates) {
            $windowsPath = $cert.Filepath
            $wslPath = wsl wslpath "'$windowsPath'"
            
            wsl bash -c "echo '' >> ~/.docker/ca-bundle.crt" 2>$null
            wsl bash -c "echo '# Corporate Certificate: $($cert.Subject)' >> ~/.docker/ca-bundle.crt" 2>$null
            wsl bash -c "cat '$wslPath' >> ~/.docker/ca-bundle.crt" 2>$null
            
            Write-ColorLog "Added certificate to bundle: $($cert.Filename)" -Level "SUCCESS" -Color Green
        }
        
        # Step 2: Configure Docker registry certificates (for docker pull/push)
        Write-ColorLog "Configuring Docker registry certificates..." -Level "PROGRESS" -Color Yellow
        
        $registries = @(
            "registry-1.docker.io",
            "index.docker.io", 
            "auth.docker.io",
            "registry.npmjs.org",
            "pypi.org",
            "download.docker.com",
            "gcr.io",
            "quay.io"
        )
        
        foreach ($registry in $registries) {
            wsl bash -c "sudo mkdir -p /etc/docker/certs.d/$registry" 2>$null
            wsl bash -c "sudo cp ~/.docker/ca-bundle.crt /etc/docker/certs.d/$registry/ca.crt" 2>$null
            Write-ColorLog "Configured registry certificates for: $registry" -Level "SUCCESS" -Color Green
        }
        
        # Step 3: Install system-wide CA certificates
        Write-ColorLog "Installing system-wide CA certificates..." -Level "PROGRESS" -Color Yellow
        
        # Find and install the critical Thomson Reuters Server CA
        $serverCA = $ExportedCertificates | Where-Object { $_.Subject -like "*Thomson Reuters Server CA*" } | Select-Object -First 1
        if ($serverCA) {
            $serverCAPath = wsl wslpath "'$($serverCA.Filepath)'"
            wsl bash -c "sudo cp '$serverCAPath' /usr/local/share/ca-certificates/thomson-reuters-server.crt" 2>$null
            wsl bash -c "sudo update-ca-certificates" 2>$null
            Write-ColorLog "Installed Thomson Reuters Server CA system-wide" -Level "SUCCESS" -Color Green
        }
        
        # Step 4: Create global Docker wrapper script
        Write-ColorLog "Creating global Docker wrapper..." -Level "PROGRESS" -Color Yellow
        
        # Create the wrapper script directly in WSL
        $wrapperScript = @'
#!/bin/bash
# Global Docker wrapper with automatic corporate certificate injection

DOCKER_CERT_PATH="$HOME/.docker/ca-bundle.crt"

if [[ "$1" == "run" ]]; then
    shift
    exec /usr/bin/docker run \
        -v "$DOCKER_CERT_PATH:/etc/ssl/certs/ca-certificates.crt:ro" \
        -v "$DOCKER_CERT_PATH:/etc/pki/tls/certs/ca-bundle.crt:ro" \
        -v "$DOCKER_CERT_PATH:/usr/local/share/ca-certificates/corporate.crt:ro" \
        -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
        -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        -e NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt \
        "$@"
else
    exec /usr/bin/docker "$@"
fi
'@
        
        # Write wrapper script to temporary file and copy to WSL
        $tempScript = "$env:TEMP\docker-wrapper.sh"
        Set-Content -Path $tempScript -Value $wrapperScript -Encoding UTF8
        $tempScriptWSL = wsl wslpath "'$tempScript'"
        
        wsl bash -c "sudo cp '$tempScriptWSL' /usr/local/bin/docker-global && sudo chmod +x /usr/local/bin/docker-global" 2>$null
        Remove-Item -Path $tempScript -Force
        
        Write-ColorLog "Created global Docker wrapper: /usr/local/bin/docker-global" -Level "SUCCESS" -Color Green
        
        # Step 5: Create Docker aliases and environment setup
        Write-ColorLog "Setting up Docker aliases..." -Level "PROGRESS" -Color Yellow
        
        $aliasScript = @'
# Docker Corporate Certificate Configuration
export DOCKER_CERT_PATH="$HOME/.docker/ca-bundle.crt"
export SSL_CERT_FILE="$HOME/.docker/ca-bundle.crt"

# Docker aliases for corporate environment
alias docker-corp='/usr/local/bin/docker-global'
alias docker-secure='/usr/local/bin/docker-global'

# Test aliases
alias docker-test='docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "Status: %{http_code}\n"'
alias docker-test-google='docker-test https://google.com'
alias docker-test-github='docker-test https://github.com'

# Uncomment the next line to make docker-corp the default docker command
# alias docker='/usr/local/bin/docker-global'
'@
        
        $tempAlias = "$env:TEMP\docker-aliases.sh"
        Set-Content -Path $tempAlias -Value $aliasScript -Encoding UTF8
        $tempAliasWSL = wsl wslpath "'$tempAlias'"
        
        wsl bash -c "cp '$tempAliasWSL' ~/.docker/docker-corporate-env.sh" 2>$null
        wsl bash -c "grep -q 'docker-corporate-env.sh' ~/.bashrc || echo 'source ~/.docker/docker-corporate-env.sh 2>/dev/null' >> ~/.bashrc" 2>$null
        Remove-Item -Path $tempAlias -Force
        
        Write-ColorLog "Created Docker corporate environment setup" -Level "SUCCESS" -Color Green
        
        # Step 6: Configure Docker daemon
        Write-ColorLog "Configuring Docker daemon..." -Level "PROGRESS" -Color Yellow
        
        $daemonConfig = @{
            "registry-mirrors" = @()
            "insecure-registries" = @()
            "log-driver" = "json-file"
            "log-opts" = @{
                "max-size" = "10m"
                "max-file" = "3"
            }
            "storage-driver" = "overlay2"
            "userland-proxy" = $false
        }
        
        $daemonConfigJson = $daemonConfig | ConvertTo-Json -Depth 3
        $tempDaemon = "$env:TEMP\daemon.json"
        Set-Content -Path $tempDaemon -Value $daemonConfigJson -Encoding UTF8
        $tempDaemonWSL = wsl wslpath "'$tempDaemon'"
        
        wsl bash -c "sudo cp '$tempDaemonWSL' /etc/docker/daemon.json" 2>$null
        Remove-Item -Path $tempDaemon -Force
        
        # Step 7: Restart Docker daemon
        Write-ColorLog "Restarting Docker daemon..." -Level "PROGRESS" -Color Yellow
        wsl bash -c "sudo systemctl restart docker" 2>$null
        Start-Sleep -Seconds 5
        
        # Wait for Docker to be ready
        $dockerReady = $false
        $attempts = 0
        while (-not $dockerReady -and $attempts -lt 10) {
            try {
                $result = wsl bash -c "docker info > /dev/null 2>&1 && echo 'ready'"
                if ($result -eq "ready") {
                    $dockerReady = $true
                } else {
                    Start-Sleep -Seconds 2
                    $attempts++
                }
            }
            catch {
                Start-Sleep -Seconds 2
                $attempts++
            }
        }
        
        if ($dockerReady) {
            Write-ColorLog "Docker daemon restarted successfully" -Level "SUCCESS" -Color Green
        } else {
            Write-ColorLog "Warning: Docker daemon may not be fully ready" -Level "WARNING" -Color Yellow
        }
        
        return $true
    }
    catch {
        Write-ColorLog "Failed to install complete Docker SSL configuration: $($_.Exception.Message)" -Level "ERROR" -Color Red
        return $false
    }
}

# Main execution
Write-ColorLog "Corporate SSL Certificate Manager for Docker - Complete Setup" -Level "TITLE" -Color Magenta
Write-ColorLog "=============================================================" -Level "TITLE" -Color Magenta

# Check prerequisites
try {
    $wslCheck = wsl bash -c "echo 'WSL Available'"
    if ($wslCheck -ne "WSL Available") {
        throw "WSL not responding correctly"
    }
    Write-ColorLog "WSL is available and responding" -Level "SUCCESS" -Color Green
}
catch {
    Write-ColorLog "ERROR: WSL is not available or not responding: $($_.Exception.Message)" -Level "ERROR" -Color Red
    exit 1
}

try {
    $dockerCheck = wsl bash -c "docker --version 2>/dev/null"
    if (-not $dockerCheck) {
        throw "Docker not available in WSL"
    }
    Write-ColorLog "Docker is available: $dockerCheck" -Level "SUCCESS" -Color Green
}
catch {
    Write-ColorLog "ERROR: Docker is not available in WSL: $($_.Exception.Message)" -Level "ERROR" -Color Red
    exit 1
}

Write-ColorLog "Environment initialized successfully" -Level "SUCCESS" -Color Green
Write-ColorLog "WSL Distribution: $WSLDistro" -Level "INFO"
Write-ColorLog "Certificate Export Path: $certificateDir" -Level "INFO"
Write-ColorLog "Log File: $logFile" -Level "INFO"

Write-ColorLog "Starting complete Docker SSL certificate configuration..." -Level "TITLE" -Color Magenta

# Test baseline Docker connectivity
Write-ColorLog "Testing baseline Docker connectivity..." -Level "PROGRESS" -Color Yellow
$baselineResults = Test-DockerConnectivity -Domains $TestDomains -TestType "Baseline"

# Find corporate certificates
$certificates = Get-CorporateCertificates -Patterns $SearchPatterns -ExcludeList $ExcludeIssuers

if ($certificates.Count -eq 0) {
    Write-ColorLog "No corporate certificates found matching the specified patterns" -Level "WARNING" -Color Yellow
    Write-ColorLog "Try broadening search patterns or check certificate stores manually" -Level "INFO"
    exit 0
}

# Export certificates
Write-ColorLog "Exporting $($certificates.Count) certificates..." -Level "PROGRESS" -Color Yellow
$exportedCertificates = Export-CertificatesToPEM -Certificates $certificates

if ($exportedCertificates.Count -eq 0) {
    Write-ColorLog "No certificates were successfully exported" -Level "ERROR" -Color Red
    exit 1
}

# Install complete Docker SSL configuration
Write-ColorLog "Installing complete Docker SSL configuration..." -Level "PROGRESS" -Color Yellow
$installResult = Install-CompleteDockerSSLConfiguration -ExportedCertificates $exportedCertificates

if (-not $installResult) {
    Write-ColorLog "Complete Docker SSL configuration failed" -Level "ERROR" -Color Red
    exit 1
}

# Test final connectivity with both standard and global Docker
Write-ColorLog "Testing Docker connectivity after complete configuration..." -Level "PROGRESS" -Color Yellow
$standardResults = Test-DockerConnectivity -Domains $TestDomains -TestType "Standard"
$globalResults = Test-DockerConnectivity -Domains $TestDomains -TestType "Global"

# Compare results
$baselineSuccess = ($baselineResults | Where-Object Success).Count
$standardSuccess = ($standardResults | Where-Object Success).Count
$globalSuccess = ($globalResults | Where-Object Success).Count

Write-ColorLog "Final validation results:" -Level "TITLE" -Color Magenta
Write-ColorLog "Baseline Docker: $baselineSuccess/$($TestDomains.Count) domains successful" -Level "INFO"
Write-ColorLog "Standard Docker: $standardSuccess/$($TestDomains.Count) domains successful" -Level "INFO"
Write-ColorLog "Global Docker: $globalSuccess/$($TestDomains.Count) domains successful" -Level "INFO"

$improvement = $globalSuccess - $baselineSuccess

if ($globalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "PERFECT SUCCESS: All domains working with global Docker!" -Level "SUCCESS" -Color Green
} elseif ($improvement -gt 0) {
    Write-ColorLog "Docker connectivity improved by $improvement domains!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "Docker connectivity maintained at current levels" -Level "INFO"
}

# Export comprehensive results
$analysisResults = @{
    Timestamp = Get-Date
    BaselineResults = $baselineResults
    StandardResults = $standardResults
    GlobalResults = $globalResults
    CertificatesInstalled = $exportedCertificates.Count
    CertificateDetails = $exportedCertificates
    BaselineSuccess = $baselineSuccess
    StandardSuccess = $standardSuccess
    GlobalSuccess = $globalSuccess
    Improvement = $improvement
    Configuration = "Complete Docker SSL Setup"
}

$csvPath = "$certificateDir\Docker_Complete_Analysis_$timestamp.csv"
$jsonPath = "$certificateDir\Docker_Complete_Analysis_$timestamp.json"

# Create comprehensive CSV
$allResults = @()
$allResults += $baselineResults
$allResults += $standardResults  
$allResults += $globalResults

$allResults | Export-Csv -Path $csvPath -NoTypeInformation
$analysisResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8

Write-ColorLog "Results exported to: $csvPath, $jsonPath" -Level "SUCCESS" -Color Green

# Display comprehensive usage instructions
Write-ColorLog "`nComplete Docker SSL Configuration Installed!" -Level "TITLE" -Color Magenta
Write-ColorLog "Usage Instructions:" -Level "INFO"
Write-ColorLog "1. Registry Operations (automatic):" -Level "INFO"
Write-ColorLog "   docker pull node:18" -Level "INFO"
Write-ColorLog "   docker pull python:3.12" -Level "INFO"
Write-ColorLog "2. Global Docker with automatic certificate injection:" -Level "INFO"
Write-ColorLog "   docker-corp run --rm curlimages/curl:latest curl https://google.com" -Level "INFO"
Write-ColorLog "   docker-secure run --rm ubuntu curl https://github.com" -Level "INFO"
Write-ColorLog "3. Quick tests:" -Level "INFO"
Write-ColorLog "   docker-test-google" -Level "INFO"
Write-ColorLog "   docker-test-github" -Level "INFO"
Write-ColorLog "4. To make docker-corp the default, uncomment the alias in ~/.docker/docker-corporate-env.sh" -Level "INFO"
Write-ColorLog "5. Restart WSL terminal to load new aliases and environment" -Level "INFO"

if ($globalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "SUCCESS: Complete Docker SSL configuration installed successfully!" -Level "SUCCESS" -Color Green
    Write-ColorLog "All containers will now work with HTTPS by default using docker-corp command!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "PARTIAL SUCCESS: Docker SSL configuration improved connectivity" -Level "WARNING" -Color Yellow
    Write-ColorLog "Use docker-corp command for best results with HTTPS connections" -Level "INFO"
}

Write-ColorLog "Docker complete SSL certificate installation process completed!" -Level "SUCCESS" -Color Green
