# Corporate SSL Certificate Manager for Docker - Final Working Version
# Properly configures Docker daemon and containers to use Thomson Reuters corporate certificates globally
# Fixes all identified issues: PowerShell parsing, Docker daemon readiness, line endings

[CmdletBinding()]
param(
    [string[]]$SearchPatterns = @("Thomson Reuters", "Zscaler", "CA"),
    [string[]]$ExcludeIssuers = @("DigiCert", "thawte", "Digital Signature Trust Co.", "GlobalSign", "Microsoft", "SSL.com", "Entrust", "COMODO", "Starfield", "VeriSign", "Go Daddy", "USERTrust", "IdenTrust", "QuoVadis", "Certum", "AAA Certificate Services", "AddTrust", "Sectigo", "Symantec", "GeoTrust", "RapidSSL", "Let's Encrypt", "ISRG", "Baltimore", "UTN-USERFirst", "Amazon", "Google Trust Services", "Apple", "Buypass", "HARICA", "SwissSign", "TrustCor", "OISTE", "WoSign", "StartCom", "Camerfirma", "AC Camerfirma", "NetLock", "e-Szigno", "Microsec", "TURKTRUST", "Hotspot 2.0 Trust Root CA", "WFA Hotspot 2.0"),
    [string]$WSLDistro = "Ubuntu",
    [string[]]$TestDomains = @("https://google.com", "https://github.com", "https://registry.npmjs.org", "https://pypi.org", "https://download.docker.com", "https://api.github.com"),
    [switch]$DryRun,
    [switch]$CleanInstall
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\logs"
$logFile = "$logDir\Docker_Final_SSL_Installation_$timestamp.log"
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

function Wait-ForDockerReady {
    param([int]$MaxAttempts = 15, [int]$WaitSeconds = 2)
    
    Write-ColorLog "Waiting for Docker daemon to be fully ready..." -Level "PROGRESS" -Color Yellow
    
    $attempts = 0
    while ($attempts -lt $MaxAttempts) {
        try {
            $dockerStatus = wsl bash -c "systemctl is-active docker 2>/dev/null"
            $dockerInfo = wsl bash -c "timeout 10 docker info > /dev/null 2>&1 && echo 'ready'"
            
            if ($dockerStatus -eq "active" -and $dockerInfo -eq "ready") {
                Write-ColorLog "Docker daemon is fully ready and responding" -Level "SUCCESS" -Color Green
                return $true
            }
            
            Write-ColorLog "Docker not ready yet (attempt $($attempts + 1)/$MaxAttempts)..." -Level "INFO"
            Start-Sleep -Seconds $WaitSeconds
            $attempts++
        }
        catch {
            Write-ColorLog "Docker readiness check failed (attempt $($attempts + 1)/$MaxAttempts): $($_.Exception.Message)" -Level "WARNING" -Color Yellow
            Start-Sleep -Seconds $WaitSeconds
            $attempts++
        }
    }
    
    Write-ColorLog "Warning: Docker may not be fully ready after $MaxAttempts attempts" -Level "WARNING" -Color Yellow
    return $false
}

function Test-DockerConnectivity {
    param([string[]]$Domains, [string]$TestType = "Standard")
    
    # Ensure Docker is ready before testing
    if (-not (Wait-ForDockerReady -MaxAttempts 5 -WaitSeconds 3)) {
        Write-ColorLog "Skipping connectivity test - Docker not ready" -Level "WARNING" -Color Yellow
        return @()
    }
    
    $results = @()
    foreach ($domain in $Domains) {
        try {
            $dockerCmd = if ($TestType -eq "Global") {
                "timeout 20 /usr/local/bin/docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w '%{http_code}' '$domain' 2>/dev/null || echo '000'"
            } else {
                "timeout 20 docker run --rm curlimages/curl:latest curl -s -o /dev/null -w '%{http_code}' '$domain' 2>/dev/null || echo '000'"
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

function Clear-DockerConfiguration {
    Write-ColorLog "Cleaning up existing Docker configuration..." -Level "PROGRESS" -Color Yellow
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN: Would clean Docker configuration" -Level "INFO" -Color Cyan
        return
    }
    
    try {
        # Remove existing Docker certificate directories
        wsl bash -c "sudo rm -rf /etc/docker/certs.d/*" 2>$null
        
        # Remove existing Docker wrapper scripts
        wsl bash -c "sudo rm -f /usr/local/bin/docker-global /usr/local/bin/docker-corp" 2>$null
        
        # Clean up Docker configuration files
        wsl bash -c "rm -f ~/.docker/docker-*.sh" 2>$null
        
        # Reset Docker daemon configuration
        wsl bash -c "sudo rm -f /etc/docker/daemon.json" 2>$null
        
        # Remove aliases from bashrc
        wsl bash -c "sed -i '/docker-corp/d; /docker-secure/d; /docker-test/d; /docker-corporate-env/d' ~/.bashrc" 2>$null
        
        Write-ColorLog "Docker configuration cleaned successfully" -Level "SUCCESS" -Color Green
    }
    catch {
        Write-ColorLog "Warning: Some cleanup operations failed: $($_.Exception.Message)" -Level "WARNING" -Color Yellow
    }
}

function Install-DockerSSLConfiguration {
    param([PSCustomObject[]]$ExportedCertificates)
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN: Would configure Docker SSL with $($ExportedCertificates.Count) certificates" -Level "INFO" -Color Cyan
        return $true
    }
    
    Write-ColorLog "Installing Docker SSL configuration..." -Level "PROGRESS" -Color Yellow
    
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
            "download.docker.com"
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
        
        # Step 4: Copy Docker wrapper script from repository file
        Write-ColorLog "Installing Docker wrapper script..." -Level "PROGRESS" -Color Yellow
        
        # Use file copy method to avoid PowerShell parsing issues and ensure proper line endings
        $dockerCorpScript = Join-Path $PSScriptRoot "docker-corp.sh"
        if (-not (Test-Path $dockerCorpScript)) {
            Write-ColorLog "ERROR: docker-corp.sh not found in script directory" -Level "ERROR" -Color Red
            return $false
        }
        
        $dockerCorpWSLPath = wsl wslpath "'$dockerCorpScript'"
        wsl bash -c "sudo cp '$dockerCorpWSLPath' /usr/local/bin/docker-corp && sudo chmod +x /usr/local/bin/docker-corp" 2>$null
        
        Write-ColorLog "Created Docker wrapper: /usr/local/bin/docker-corp" -Level "SUCCESS" -Color Green
        
        # Step 5: Create Docker environment and aliases
        Write-ColorLog "Setting up Docker environment..." -Level "PROGRESS" -Color Yellow
        
        wsl bash -c @"
cat > ~/.docker/docker-corporate-env.sh << 'ENV_SCRIPT_EOF'
# Docker Corporate Certificate Environment
export DOCKER_CERT_PATH="`$HOME/.docker/ca-bundle.crt"

# Docker aliases
alias docker-corp='/usr/local/bin/docker-corp'
alias docker-test='docker-corp run --rm curlimages/curl:latest curl -s -o /dev/null -w "Status: %{http_code}\n"'
alias docker-test-google='docker-test https://google.com'
alias docker-test-github='docker-test https://github.com'

echo "Docker Corporate SSL Environment Loaded"
echo "Use 'docker-corp' for containers with automatic certificate injection"
echo "Use 'docker-test-google' and 'docker-test-github' for quick tests"
ENV_SCRIPT_EOF

chmod +x ~/.docker/docker-corporate-env.sh
"@ 2>$null
        
        # Add to bashrc
        wsl bash -c "grep -q 'docker-corporate-env.sh' ~/.bashrc || echo 'source ~/.docker/docker-corporate-env.sh 2>/dev/null' >> ~/.bashrc" 2>$null
        
        Write-ColorLog "Created Docker environment setup" -Level "SUCCESS" -Color Green
        
        # Step 6: Restart Docker daemon
        Write-ColorLog "Restarting Docker daemon..." -Level "PROGRESS" -Color Yellow
        wsl bash -c "sudo systemctl restart docker" 2>$null
        
        # Wait for Docker to be fully ready
        $dockerReady = Wait-ForDockerReady -MaxAttempts 15 -WaitSeconds 3
        
        if ($dockerReady) {
            Write-ColorLog "Docker daemon restarted and is fully ready" -Level "SUCCESS" -Color Green
        } else {
            Write-ColorLog "Warning: Docker daemon may not be fully ready, but continuing..." -Level "WARNING" -Color Yellow
        }
        
        return $true
    }
    catch {
        Write-ColorLog "Failed to install Docker SSL configuration: $($_.Exception.Message)" -Level "ERROR" -Color Red
        return $false
    }
}

# Main execution
Write-ColorLog "Corporate SSL Certificate Manager for Docker - Final Working Version" -Level "TITLE" -Color Magenta
Write-ColorLog "=================================================================" -Level "TITLE" -Color Magenta

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

# Clean existing configuration if requested
if ($CleanInstall) {
    Clear-DockerConfiguration
}

Write-ColorLog "Starting Docker SSL certificate configuration..." -Level "TITLE" -Color Magenta

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

# Install Docker SSL configuration
Write-ColorLog "Installing Docker SSL configuration..." -Level "PROGRESS" -Color Yellow
$installResult = Install-DockerSSLConfiguration -ExportedCertificates $exportedCertificates

if (-not $installResult) {
    Write-ColorLog "Docker SSL configuration failed" -Level "ERROR" -Color Red
    exit 1
}

# Test final connectivity with proper Docker readiness check
Write-ColorLog "Testing Docker connectivity after configuration..." -Level "PROGRESS" -Color Yellow
$finalResults = Test-DockerConnectivity -Domains $TestDomains -TestType "Global"

# Compare results
$baselineSuccess = ($baselineResults | Where-Object Success).Count
$finalSuccess = ($finalResults | Where-Object Success).Count
$improvement = $finalSuccess - $baselineSuccess

Write-ColorLog "Final validation results:" -Level "TITLE" -Color Magenta
Write-ColorLog "Baseline Docker: $baselineSuccess/$($TestDomains.Count) domains successful" -Level "INFO"
Write-ColorLog "Final Docker: $finalSuccess/$($TestDomains.Count) domains successful" -Level "INFO"

if ($finalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "PERFECT SUCCESS: All domains working with docker-corp!" -Level "SUCCESS" -Color Green
} elseif ($improvement -gt 0) {
    Write-ColorLog "Docker connectivity improved by $improvement domains!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "Docker connectivity: Use docker-corp for best results" -Level "INFO"
}

# Export results
$analysisResults = @{
    Timestamp = Get-Date
    BaselineResults = $baselineResults
    FinalResults = $finalResults
    CertificatesInstalled = $exportedCertificates.Count
    CertificateDetails = $exportedCertificates
    BaselineSuccess = $baselineSuccess
    FinalSuccess = $finalSuccess
    Improvement = $improvement
    Configuration = "Final Working Docker SSL Setup"
}

$jsonPath = "$certificateDir\Docker_Final_Analysis_$timestamp.json"
$analysisResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-ColorLog "Results exported to: $jsonPath" -Level "SUCCESS" -Color Green

# Display usage instructions
Write-ColorLog "`nFinal Docker SSL Configuration Complete!" -Level "TITLE" -Color Magenta
Write-ColorLog "Usage Instructions:" -Level "INFO"
Write-ColorLog "1. Standard Docker registry operations work automatically:" -Level "INFO"
Write-ColorLog "   docker pull node:18" -Level "INFO"
Write-ColorLog "   docker pull python:3.12" -Level "INFO"
Write-ColorLog "2. For HTTPS inside containers, use docker-corp:" -Level "INFO"
Write-ColorLog "   docker-corp run --rm curlimages/curl:latest curl https://google.com" -Level "INFO"
Write-ColorLog "   docker-corp run --rm ubuntu curl https://github.com" -Level "INFO"
Write-ColorLog "3. Quick tests (after restarting WSL terminal):" -Level "INFO"
Write-ColorLog "   docker-test-google" -Level "INFO"
Write-ColorLog "   docker-test-github" -Level "INFO"
Write-ColorLog "4. Restart WSL terminal to load new environment" -Level "INFO"

if ($finalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "SUCCESS: Docker SSL configuration working perfectly!" -Level "SUCCESS" -Color Green
    Write-ColorLog "All containers work with HTTPS using docker-corp command!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "Configuration completed - use docker-corp for HTTPS connections" -Level "INFO"
}

Write-ColorLog "Docker SSL certificate installation completed!" -Level "SUCCESS" -Color Green
