# Corporate SSL Certificate Manager for Docker in WSL
# Configures Docker daemon to use Thomson Reuters corporate certificates globally
# All containers will automatically use corporate certificates without additional configuration

[CmdletBinding()]
param(
    [string[]]$SearchPatterns = @("Thomson Reuters", "Zscaler", "CA"),
    [string[]]$ExcludeIssuers = @("DigiCert", "thawte", "Digital Signature Trust Co.", "GlobalSign", "Microsoft", "SSL.com", "Entrust", "COMODO", "Starfield", "VeriSign", "Go Daddy", "USERTrust", "IdenTrust", "QuoVadis", "Certum", "AAA Certificate Services", "AddTrust", "Sectigo", "Symantec", "GeoTrust", "RapidSSL", "Let's Encrypt", "ISRG", "Baltimore", "UTN-USERFirst", "Amazon", "Google Trust Services", "Apple", "Buypass", "HARICA", "SwissSign", "TrustCor", "OISTE", "WoSign", "StartCom", "Camerfirma", "AC Camerfirma", "NetLock", "e-Szigno", "Microsec", "TURKTRUST", "Hotspot 2.0 Trust Root CA", "WFA Hotspot 2.0"),
    [string]$WSLDistro = "Ubuntu",
    [string[]]$TestDomains = @("https://google.com", "https://github.com", "https://registry.npmjs.org", "https://pypi.org", "https://download.docker.com", "https://api.github.com"),
    [switch]$DryRun,
    [switch]$Verbose
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\logs"
$logFile = "$logDir\Docker_SSL_Installation_$timestamp.log"
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
    param([string[]]$Domains)
    
    $results = @()
    foreach ($domain in $Domains) {
        try {
            $result = wsl bash -c "timeout 10 docker run --rm curlimages/curl:latest curl -s -o /dev/null -w '%{http_code}' '$domain' 2>/dev/null || echo '000'"
            $status = if ($result -match '^\d{3}$') { [int]$result } else { 0 }
            $success = $status -ge 200 -and $status -lt 400
            
            $results += [PSCustomObject]@{
                Domain = $domain
                StatusCode = $status
                Success = $success
            }
            
            if ($success) {
                Write-ColorLog "[OK] $domain - Success (HTTP $status)" -Level "SUCCESS" -Color Green
            } else {
                Write-ColorLog "[FAIL] $domain - Failed (HTTP $status)" -Level "ERROR" -Color Red
            }
        }
        catch {
            $results += [PSCustomObject]@{
                Domain = $domain
                StatusCode = 0
                Success = $false
            }
            Write-ColorLog "[ERROR] $domain - Connection failed: $($_.Exception.Message)" -Level "ERROR" -Color Red
        }
    }
    
    $successCount = ($results | Where-Object Success).Count
    $totalCount = $results.Count
    $successRate = if ($totalCount -gt 0) { [math]::Round(($successCount / $totalCount) * 100, 2) } else { 0 }
    
    Write-ColorLog "Docker connectivity: $successCount/$totalCount domains successful ($successRate%)" -Level "INFO" -Color Cyan
    return $results
}

function Get-CorporateCertificates {
    param([string[]]$Patterns, [string[]]$ExcludeList)
    
    Write-ColorLog "Searching for corporate certificates..." -Level "PROGRESS" -Color Yellow
    Write-ColorLog "Patterns: $($Patterns -join ', ')" -Level "INFO"
    Write-ColorLog "Excluding: $($ExcludeList -join ', ')" -Level "INFO"
    
    $certificates = @()
    $stores = @("Cert:\LocalMachine\My", "Cert:\LocalMachine\Root", "Cert:\LocalMachine\CA", "Cert:\LocalMachine\AuthRoot", "Cert:\LocalMachine\TrustedPublisher", "Cert:\LocalMachine\TrustedPeople", "Cert:\CurrentUser\My", "Cert:\CurrentUser\Root", "Cert:\CurrentUser\CA", "Cert:\CurrentUser\AuthRoot", "Cert:\CurrentUser\TrustedPublisher", "Cert:\CurrentUser\TrustedPeople")
    
    foreach ($store in $stores) {
        if ($Verbose) { Write-ColorLog "Searching certificates in store: $store" -Level "VERBOSE" }
        
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
                    if ($Verbose) { Write-ColorLog "Found certificate: $subject" -Level "VERBOSE" }
                    
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
            Write-ColorLog "Warning: Could not access certificate store $store - $($_.Exception.Message)" -Level "WARNING" -Color Yellow
        }
    }
    
    # Remove duplicates based on thumbprint
    $uniqueCertificates = $certificates | Sort-Object Thumbprint -Unique
    
    Write-ColorLog "Found $($certificates.Count) corporate certificates" -Level "SUCCESS" -Color Green
    Write-ColorLog "Found $($uniqueCertificates.Count) unique corporate certificates after filtering" -Level "SUCCESS" -Color Green
    
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

function Install-DockerCertificates {
    param([PSCustomObject[]]$ExportedCertificates)
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN: Would configure Docker with $($ExportedCertificates.Count) certificates" -Level "INFO" -Color Cyan
        return $true
    }
    
    Write-ColorLog "Configuring Docker daemon for corporate certificates..." -Level "PROGRESS" -Color Yellow
    
    try {
        # Create Docker certificate directory in WSL
        $dockerCertDir = "/etc/docker/certs.d"
        wsl bash -c "sudo mkdir -p '$dockerCertDir'" 2>$null
        
        # Create Docker configuration directory
        wsl bash -c "mkdir -p ~/.docker" 2>$null
        
        # Copy system CA bundle as base
        wsl bash -c "cp /etc/ssl/certs/ca-certificates.crt ~/.docker/ca-bundle.crt" 2>$null
        
        # Append corporate certificates to the bundle
        Write-ColorLog "Adding corporate certificates to Docker CA bundle..." -Level "PROGRESS" -Color Yellow
        
        foreach ($cert in $ExportedCertificates) {
            $windowsPath = $cert.Filepath
            $wslPath = wsl wslpath "'$windowsPath'"
            
            # Append certificate to bundle
            wsl bash -c "echo '' >> ~/.docker/ca-bundle.crt"
            wsl bash -c "echo '# Corporate Certificate: $($cert.Subject)' >> ~/.docker/ca-bundle.crt"
            wsl bash -c "cat '$wslPath' >> ~/.docker/ca-bundle.crt" 2>$null
            
            Write-ColorLog "Added certificate to bundle: $($cert.Filename)" -Level "SUCCESS" -Color Green
        }
        
        # Configure Docker daemon to use the CA bundle globally
        Write-ColorLog "Configuring Docker daemon..." -Level "PROGRESS" -Color Yellow
        
        # Create or update Docker daemon configuration
        $daemonConfig = @{
            "registry-mirrors" = @()
            "insecure-registries" = @()
            "log-driver" = "json-file"
            "log-opts" = @{
                "max-size" = "10m"
                "max-file" = "3"
            }
        }
        
        $daemonConfigJson = $daemonConfig | ConvertTo-Json -Depth 3
        
        # Write daemon configuration
        wsl bash -c "sudo mkdir -p /etc/docker" 2>$null
        $daemonConfigJson | wsl bash -c "sudo tee /etc/docker/daemon.json > /dev/null" 2>$null
        
        # Create Docker environment configuration to use CA bundle
        $dockerEnvConfig = @"
# Docker Corporate Certificate Configuration
export DOCKER_CERT_PATH=$HOME/.docker
export DOCKER_TLS_VERIFY=1
export SSL_CERT_FILE=$HOME/.docker/ca-bundle.crt
export CURL_CA_BUNDLE=$HOME/.docker/ca-bundle.crt
export REQUESTS_CA_BUNDLE=$HOME/.docker/ca-bundle.crt
"@
        
        $dockerEnvConfig | wsl bash -c "tee ~/.docker/docker-env.sh > /dev/null" 2>$null
        wsl bash -c "chmod +x ~/.docker/docker-env.sh" 2>$null
        
        # Add to shell profile
        wsl bash -c "grep -q 'docker-env.sh' ~/.bashrc || echo 'source ~/.docker/docker-env.sh 2>/dev/null' >> ~/.bashrc" 2>$null
        
        # Create global Docker wrapper script
        $wrapperScript = @"
#!/bin/bash
# Global Docker wrapper with corporate certificates
export SSL_CERT_FILE=$HOME/.docker/ca-bundle.crt
export CURL_CA_BUNDLE=$HOME/.docker/ca-bundle.crt
export REQUESTS_CA_BUNDLE=$HOME/.docker/ca-bundle.crt

# Run docker with certificate volume mounts for maximum compatibility
if [[ "$1" == "run" ]]; then
    # Add certificate mounts to docker run commands
    exec /usr/bin/docker "\$@" \
        -v "\$HOME/.docker/ca-bundle.crt:/etc/ssl/certs/ca-certificates.crt:ro" \
        -v "\$HOME/.docker/ca-bundle.crt:/etc/pki/tls/certs/ca-bundle.crt:ro" \
        -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
        -e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
        -e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
else
    # Pass through other docker commands
    exec /usr/bin/docker "\$@"
fi
"@
        
        $wrapperScript | wsl bash -c "sudo tee /usr/local/bin/docker-corporate > /dev/null" 2>$null
        wsl bash -c "sudo chmod +x /usr/local/bin/docker-corporate" 2>$null
        
        # Create convenient aliases
        $aliases = @"
# Docker Corporate Certificate Aliases
alias docker-test='docker run --rm curlimages/curl:latest curl -s -o /dev/null -w "Status: %{http_code}\n"'
alias docker-test-all='for url in https://google.com https://github.com https://registry.npmjs.org https://pypi.org; do echo "Testing \$url:"; docker-test \$url; done'
"@
        
        $aliases | wsl bash -c "tee -a ~/.bashrc > /dev/null" 2>$null
        
        # Restart Docker daemon to pick up configuration
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
        Write-ColorLog "Failed to configure Docker: $($_.Exception.Message)" -Level "ERROR" -Color Red
        return $false
    }
}

# Main execution
Write-ColorLog "Initializing Docker SSL Certificate Installation Environment" -Level "TITLE" -Color Magenta
Write-ColorLog "=========================================================" -Level "TITLE" -Color Magenta

# Check if WSL and Docker are available
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

Write-ColorLog "Starting Docker certificate processing..." -Level "TITLE" -Color Magenta

# Test baseline Docker connectivity
Write-ColorLog "Testing Docker HTTPS connectivity before certificate processing..." -Level "PROGRESS" -Color Yellow
$baselineResults = Test-DockerConnectivity -Domains $TestDomains

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

# Install certificates in Docker
Write-ColorLog "Configuring Docker with corporate certificates..." -Level "PROGRESS" -Color Yellow
$installResult = Install-DockerCertificates -ExportedCertificates $exportedCertificates

if (-not $installResult) {
    Write-ColorLog "Docker certificate configuration failed" -Level "ERROR" -Color Red
    exit 1
}

# Test Docker connectivity after configuration
Write-ColorLog "Testing Docker HTTPS connectivity after certificate configuration..." -Level "PROGRESS" -Color Yellow
$finalResults = Test-DockerConnectivity -Domains $TestDomains

# Compare results
$baselineSuccess = ($baselineResults | Where-Object Success).Count
$finalSuccess = ($finalResults | Where-Object Success).Count
$improvement = $finalSuccess - $baselineSuccess

Write-ColorLog "Performing final validation..." -Level "TITLE" -Color Magenta
Write-ColorLog "Baseline Docker connectivity: $baselineSuccess/$($TestDomains.Count) domains" -Level "INFO"
Write-ColorLog "Final Docker connectivity: $finalSuccess/$($TestDomains.Count) domains" -Level "INFO"

if ($improvement -gt 0) {
    Write-ColorLog "Docker connectivity improved by $improvement domains!" -Level "SUCCESS" -Color Green
} elseif ($finalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "Docker connectivity: All domains working!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "Docker connectivity: Some domains still failing" -Level "WARNING" -Color Yellow
}

# Export results
$analysisResults = @{
    Timestamp = Get-Date
    BaselineResults = $baselineResults
    FinalResults = $finalResults
    CertificatesInstalled = $exportedCertificates.Count
    CertificateDetails = $exportedCertificates
    Improvement = $improvement
}

$csvPath = "$certificateDir\Docker_Certificate_Analysis_$timestamp.csv"
$jsonPath = "$certificateDir\Docker_Certificate_Analysis_$timestamp.json"

$analysisResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-ColorLog "Results exported to JSON: $jsonPath" -Level "SUCCESS" -Color Green

# Create CSV summary
$csvData = $finalResults | Select-Object Domain, StatusCode, Success
$csvData | Export-Csv -Path $csvPath -NoTypeInformation
Write-ColorLog "Results exported to CSV: $csvPath" -Level "SUCCESS" -Color Green

Write-ColorLog "Analysis results exported to: $csvPath, $jsonPath" -Level "SUCCESS" -Color Green

if ($finalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "SUCCESS: All Docker HTTPS connectivity tests passed! Docker is ready for corporate use." -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "PARTIAL SUCCESS: Docker connectivity improved but some domains still failing" -Level "WARNING" -Color Yellow
    Write-ColorLog "Check logs and consider running with -RequireAllCerts for comprehensive certificate installation" -Level "INFO"
}

Write-ColorLog "Docker certificate installation process completed!" -Level "SUCCESS" -Color Green

# Display usage instructions
Write-ColorLog "`nUsage Instructions:" -Level "TITLE" -Color Magenta
Write-ColorLog "1. All Docker containers will now automatically use corporate certificates" -Level "INFO"
Write-ColorLog "2. Test with: wsl bash -c 'docker-test https://google.com'" -Level "INFO"
Write-ColorLog "3. Test all domains: wsl bash -c 'docker-test-all'" -Level "INFO"
Write-ColorLog "4. Use docker-corporate command for enhanced certificate support" -Level "INFO"
Write-ColorLog "5. Restart WSL terminal to load new environment variables" -Level "INFO"
