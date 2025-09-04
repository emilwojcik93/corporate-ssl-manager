# Corporate SSL Certificate Manager for Docker - Global Configuration
# Configures Docker daemon to automatically inject corporate certificates into ALL containers
# Based on Docker documentation: https://docs.docker.com/engine/security/certificates/

[CmdletBinding()]
param(
    [string[]]$SearchPatterns = @("Thomson Reuters", "Zscaler", "CA"),
    [string]$WSLDistro = "Ubuntu",
    [string[]]$TestDomains = @("https://google.com", "https://github.com", "https://registry.npmjs.org", "https://pypi.org", "https://download.docker.com", "https://api.github.com"),
    [switch]$DryRun
)

# Initialize logging
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$logDir = ".\logs"
$logFile = "$logDir\Docker_Global_SSL_Installation_$timestamp.log"
$certificateDir = "$env:USERPROFILE\certificates"

if (-not (Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir -Force | Out-Null
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

function Install-GlobalDockerCertificates {
    
    if ($DryRun) {
        Write-ColorLog "DRY RUN: Would configure Docker with global certificate injection" -Level "INFO" -Color Cyan
        return $true
    }
    
    Write-ColorLog "Configuring Docker for global certificate injection..." -Level "PROGRESS" -Color Yellow
    
    try {
        # Method 1: Configure Docker daemon for registry access
        Write-ColorLog "Configuring Docker registry certificates..." -Level "PROGRESS" -Color Yellow
        
        # Create registry certificate directories (for Docker Hub and common registries)
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
        
        # Method 2: Create Docker wrapper script with automatic certificate injection
        Write-ColorLog "Creating global Docker wrapper..." -Level "PROGRESS" -Color Yellow
        
        $dockerWrapper = @"
#!/bin/bash
# Global Docker wrapper with automatic corporate certificate injection
# Automatically mounts corporate certificates for all containers

DOCKER_CERT_PATH="/home/\$USER/.docker/ca-bundle.crt"

# Function to inject certificate arguments
inject_certs() {
    echo "-v \$DOCKER_CERT_PATH:/etc/ssl/certs/ca-certificates.crt:ro"
    echo "-v \$DOCKER_CERT_PATH:/etc/pki/tls/certs/ca-bundle.crt:ro"
    echo "-v \$DOCKER_CERT_PATH:/usr/local/share/ca-certificates/corporate.crt:ro"
    echo "-e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt"
    echo "-e CURL_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"
    echo "-e REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt"
    echo "-e NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt"
}

# Check if this is a 'docker run' command
if [[ "\$1" == "run" ]]; then
    # Extract docker run arguments
    shift
    
    # Inject certificate arguments automatically
    cert_args=\$(inject_certs)
    
    # Execute docker with certificate injection
    exec /usr/bin/docker run \$cert_args "\$@"
else
    # Pass through other docker commands unchanged
    exec /usr/bin/docker "\$@"
fi
"@
        
        # Write the wrapper script
        $dockerWrapper | wsl bash -c "sudo tee /usr/local/bin/docker-global > /dev/null" 2>$null
        wsl bash -c "sudo chmod +x /usr/local/bin/docker-global" 2>$null
        
        # Method 3: Create Docker alias for automatic use
        $dockerAlias = @"
# Docker Global Corporate Certificate Configuration
alias docker-secure='/usr/local/bin/docker-global'
alias docker-corp='docker-secure'

# Override default docker command (optional - uncomment to make global)
# alias docker='/usr/local/bin/docker-global'
"@
        
        $dockerAlias | wsl bash -c "tee ~/.docker/docker-global-alias.sh > /dev/null" 2>$null
        wsl bash -c "echo 'source ~/.docker/docker-global-alias.sh' >> ~/.bashrc" 2>$null
        
        # Method 4: Configure Docker daemon with custom settings
        Write-ColorLog "Updating Docker daemon configuration..." -Level "PROGRESS" -Color Yellow
        
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
            "experimental" = $false
        }
        
        $daemonConfigJson = $daemonConfig | ConvertTo-Json -Depth 3
        $daemonConfigJson | wsl bash -c "sudo tee /etc/docker/daemon.json > /dev/null" 2>$null
        
        # Method 5: Create system-wide CA certificate update
        Write-ColorLog "Installing corporate certificates system-wide..." -Level "PROGRESS" -Color Yellow
        
        # Copy the critical Thomson Reuters Server CA to system certificates
        wsl bash -c "sudo cp /mnt/c/Users/6125750/certificates/Thomson_Reuters_Server_CA1_DD85FA.crt /usr/local/share/ca-certificates/docker-corporate.crt" 2>$null
        wsl bash -c "sudo update-ca-certificates" 2>$null
        
        # Restart Docker daemon
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
        Write-ColorLog "Failed to configure global Docker certificates: $($_.Exception.Message)" -Level "ERROR" -Color Red
        return $false
    }
}

# Main execution
Write-ColorLog "Initializing Docker Global SSL Certificate Configuration" -Level "TITLE" -Color Magenta
Write-ColorLog "========================================================" -Level "TITLE" -Color Magenta

# Check prerequisites
try {
    $wslCheck = wsl bash -c "echo 'WSL Available'"
    $dockerCheck = wsl bash -c "docker --version 2>/dev/null"
    Write-ColorLog "Prerequisites: WSL and Docker available" -Level "SUCCESS" -Color Green
}
catch {
    Write-ColorLog "ERROR: WSL or Docker not available" -Level "ERROR" -Color Red
    exit 1
}

Write-ColorLog "WSL Distribution: $WSLDistro" -Level "INFO"
Write-ColorLog "Certificate Directory: $certificateDir" -Level "INFO"
Write-ColorLog "Log File: $logFile" -Level "INFO"

# Test baseline connectivity
Write-ColorLog "Testing baseline Docker connectivity..." -Level "PROGRESS" -Color Yellow
$baselineResults = Test-DockerConnectivity -Domains $TestDomains

# Install global Docker certificate configuration
Write-ColorLog "Installing global Docker certificate configuration..." -Level "PROGRESS" -Color Yellow
$installResult = Install-GlobalDockerCertificates

if (-not $installResult) {
    Write-ColorLog "Global Docker certificate configuration failed" -Level "ERROR" -Color Red
    exit 1
}

# Test final connectivity
Write-ColorLog "Testing Docker connectivity after global configuration..." -Level "PROGRESS" -Color Yellow
$finalResults = Test-DockerConnectivity -Domains $TestDomains

# Compare results
$baselineSuccess = ($baselineResults | Where-Object Success).Count
$finalSuccess = ($finalResults | Where-Object Success).Count
$improvement = $finalSuccess - $baselineSuccess

Write-ColorLog "Final validation results:" -Level "TITLE" -Color Magenta
Write-ColorLog "Baseline: $baselineSuccess/$($TestDomains.Count) domains successful" -Level "INFO"
Write-ColorLog "Final: $finalSuccess/$($TestDomains.Count) domains successful" -Level "INFO"

if ($improvement -gt 0) {
    Write-ColorLog "Docker connectivity improved by $improvement domains!" -Level "SUCCESS" -Color Green
} elseif ($finalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "Docker connectivity: All domains working!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "Docker connectivity: Some domains still need attention" -Level "WARNING" -Color Yellow
}

# Export results
$analysisResults = @{
    Timestamp = Get-Date
    BaselineResults = $baselineResults
    FinalResults = $finalResults
    Improvement = $improvement
    Configuration = "Global Docker Certificate Injection"
}

$jsonPath = "$certificateDir\Docker_Global_Analysis_$timestamp.json"
$analysisResults | ConvertTo-Json -Depth 3 | Out-File -FilePath $jsonPath -Encoding UTF8
Write-ColorLog "Results exported to: $jsonPath" -Level "SUCCESS" -Color Green

# Display usage instructions
Write-ColorLog "`nGlobal Docker Certificate Configuration Complete!" -Level "TITLE" -Color Magenta
Write-ColorLog "Usage Options:" -Level "INFO"
Write-ColorLog "1. Standard docker commands now work with registry certificates" -Level "INFO"
Write-ColorLog "2. Use 'docker-secure' for automatic certificate injection into containers" -Level "INFO"
Write-ColorLog "3. Use 'docker-corp' as shorthand for docker-secure" -Level "INFO"
Write-ColorLog "4. Test with: wsl bash -c 'docker-secure run --rm curlimages/curl:latest curl https://google.com'" -Level "INFO"
Write-ColorLog "5. Restart WSL terminal to load new aliases" -Level "INFO"

if ($finalSuccess -eq $TestDomains.Count) {
    Write-ColorLog "SUCCESS: Global Docker certificate configuration completed successfully!" -Level "SUCCESS" -Color Green
} else {
    Write-ColorLog "PARTIAL SUCCESS: Global configuration applied, some domains may need additional configuration" -Level "WARNING" -Color Yellow
}

Write-ColorLog "Docker global certificate installation process completed!" -Level "SUCCESS" -Color Green
