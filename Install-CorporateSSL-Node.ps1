#Requires -Version 5.1
<#
.SYNOPSIS
    Corporate SSL Certificate Installer for Node.js

.DESCRIPTION
    Automatically identifies, tests, and configures corporate SSL certificates for Node.js
    applications in corporate environments with SSL inspection.

.PARAMETER SearchPatterns
    Array of patterns to search for in certificate subjects/issuers.

.PARAMETER TestDomains
    Array of domains to test SSL connectivity against.

.PARAMETER CertificateExportPath
    Path to export certificate files. Default: $env:UserProfile\certificates

.PARAMETER BundleAllCerts
    If true, creates a single bundle file with all effective certificates.

.EXAMPLE
    .\Install-CorporateSSL-Node.ps1 -SearchPatterns @("YourCompany") -BundleAllCerts -Verbose
#>

[CmdletBinding()]
param(
    [string[]]$SearchPatterns = @("CA", "Corporate", "Enterprise", "Root", "Intermediate", "SSL", "TLS", "Proxy", "Gateway", "Security", "Inspection"),
    [string[]]$TestDomains = @("https://google.com", "https://github.com", "https://microsoft.com", "https://stackoverflow.com", "https://www.npmjs.com", "https://registry.npmjs.org"),
    [string]$CertificateExportPath = "$env:UserProfile\certificates",
    [switch]$BundleAllCerts
)

if (-not (Test-Path $CertificateExportPath)) {
    New-Item -Path $CertificateExportPath -ItemType Directory -Force | Out-Null
}

$script:LogFilePath = Join-Path ".\logs" "Node_SSL_Installation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (-not (Test-Path ".\logs")) {
    New-Item -Path ".\logs" -ItemType Directory -Force | Out-Null
}

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "TITLE" { Write-Host $logEntry -ForegroundColor Cyan }
        "PROGRESS" { Write-Host $logEntry -ForegroundColor Magenta }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    Add-Content -Path $script:LogFilePath -Value $logEntry
}

# Search for certificates
Write-Log "Node.js SSL Certificate Installer for Corporate Environments" "TITLE"
Write-Log "Searching for corporate certificates..." "PROGRESS"

$allCertificates = @()
foreach ($pattern in $SearchPatterns) {
    $allCertificates += Get-ChildItem Cert:\LocalMachine\CA | Where-Object { $_.Subject -like "*$pattern*" }
    $allCertificates += Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -like "*$pattern*" }
}

# Remove duplicates
$allCertificates = $allCertificates | Sort-Object Thumbprint -Unique

if ($allCertificates.Count -eq 0) {
    Write-Log "No corporate certificates found matching patterns: $($SearchPatterns -join ', ')" "ERROR"
    return
}

Write-Log "Found $($allCertificates.Count) corporate certificates" "SUCCESS"

# Export certificates
$exportedCerts = @()
foreach ($cert in $allCertificates) {
    $safeName = ($cert.Subject -replace "CN=", "" -replace ",.*", "" -replace "[^a-zA-Z0-9]", "_").Trim("_")
    $certFileName = "${safeName}_$($cert.Thumbprint.Substring(0,6)).crt"
    $certFilePath = Join-Path $CertificateExportPath $certFileName
    
    try {
        $certBytes = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $base64Content = [Convert]::ToBase64String($certBytes)
        $formattedContent = ($base64Content -split "(.{64})" | Where-Object { $_ -ne "" }) -join "`n"
        
        $pemContent = @"
-----BEGIN CERTIFICATE-----
$formattedContent
-----END CERTIFICATE-----
"@
        
        Set-Content -Path $certFilePath -Value $pemContent -Encoding UTF8
        Write-Log "Exported: $certFileName" "SUCCESS"
        $exportedCerts += $certFilePath
    }
    catch {
        Write-Log "Failed to export: $($cert.Subject)" "ERROR"
    }
}

    # Create bundle
    if ($BundleAllCerts -and $exportedCerts.Count -gt 0) {
        $bundlePath = Join-Path $CertificateExportPath "Corporate_CA_Bundle.crt"
    $bundleContent = @()
    
    foreach ($certFile in $exportedCerts) {
        $certContent = Get-Content $certFile -Raw
        $bundleContent += $certContent.Trim()
        $bundleContent += ""
    }
    
    $bundleContent = $bundleContent -join "`n"
    Set-Content -Path $bundlePath -Value $bundleContent -Encoding UTF8
    
    Write-Log "Created certificate bundle: $bundlePath" "SUCCESS"
    
    # Set environment variables
    [Environment]::SetEnvironmentVariable("NODE_EXTRA_CA_CERTS", $bundlePath, "User")
    [Environment]::SetEnvironmentVariable("NODE_TLS_REJECT_UNAUTHORIZED", "1", "User")
    
    Write-Log "Set NODE_EXTRA_CA_CERTS=$bundlePath" "SUCCESS"
    Write-Log "Set NODE_TLS_REJECT_UNAUTHORIZED=1" "SUCCESS"
    Write-Log "Restart PowerShell to use new environment variables" "WARNING"
}

Write-Log "Corporate certificate installation completed!" "SUCCESS"
