#Requires -Version 5.1
<#
.SYNOPSIS
    Corporate SSL Certificate Installer for WSL

.DESCRIPTION
    Automatically identifies, tests, and installs corporate SSL certificates in WSL environments
    to resolve SSL inspection issues. Supports 25+ Linux distributions with intelligent
    certificate discovery and systematic testing.

.PARAMETER SearchPatterns
    Array of patterns to search for in certificate subjects/issuers.
    Default: @("CA", "Corporate", "Enterprise", "Root", "Intermediate", "SSL", "TLS", "Proxy", "Gateway", "Security", "Inspection")

.PARAMETER ExcludeIssuers
    Array of issuer names to exclude from results (common public CAs).

.PARAMETER WSLDistro
    WSL distribution to install certificates in. Auto-detected if not specified.

.PARAMETER TestDomains
    Array of domains to test SSL connectivity against.
    Default: @("https://google.com", "https://github.com", "https://microsoft.com", "https://stackoverflow.com", "https://www.npmjs.com", "https://registry.npmjs.org")

.PARAMETER CertificateExportPath
    Path to export certificate files. Default: $env:UserProfile\certificates

.PARAMETER ExportFormat
    Export certificate details format: CSV, JSON, or Both. Default: Both

.PARAMETER LogPath
    Path for log files. Default: .\logs

.PARAMETER RequireAllCerts
    If true, installs all successful certificates. If false, stops after first success.

.PARAMETER DryRun
    If true, performs analysis without installing certificates.

.PARAMETER CleanInstall
    If true, removes all existing corporate certificates before installation.

.PARAMETER TestTimeout
    Timeout for each curl test in seconds. Default: 30

.EXAMPLE
    .\Install-CorporateSSL-WSL.ps1 -Verbose

.EXAMPLE
    .\Install-CorporateSSL-WSL.ps1 -WSLDistro "Ubuntu-22.04" -RequireAllCerts -ExportFormat Both

.EXAMPLE
    .\Install-CorporateSSL-WSL.ps1 -DryRun -SearchPatterns @("CA", "YourCompany") -Verbose

.NOTES
    Version: 3.0
    Requires: PowerShell 5.1+, WSL 2, Administrator privileges
    
    This script helps resolve SSL certificate issues in corporate environments
    where SSL inspection is used (e.g., proxy servers, security appliances).
#>

[CmdletBinding()]
param(
    [string[]]$SearchPatterns = @("CA", "Corporate", "Enterprise", "Root", "Intermediate", "SSL", "TLS", "Proxy", "Gateway", "Security", "Inspection"),
    [string[]]$ExcludeIssuers = @("DigiCert", "thawte", "Digital Signature Trust Co.", "GlobalSign", "Microsoft", "SSL.com", "Entrust", "COMODO", "Starfield", "VeriSign", "Go Daddy", "USERTrust", "IdenTrust", "QuoVadis", "Certum", "AAA Certificate Services", "AddTrust", "Sectigo", "Symantec", "GeoTrust", "RapidSSL", "Let's Encrypt", "ISRG", "Baltimore", "UTN-USERFirst", "Amazon", "Google Trust Services", "Apple", "Buypass", "HARICA", "SwissSign", "TrustCor", "OISTE", "WoSign", "StartCom", "Camerfirma", "AC Camerfirma", "NetLock", "e-Szigno", "Microsec", "TURKTRUST", "Hotspot 2.0 Trust Root CA", "WFA Hotspot 2.0"),
    [string]$WSLDistro,
    [string[]]$TestDomains = @("https://google.com", "https://github.com", "https://microsoft.com", "https://stackoverflow.com", "https://www.npmjs.com", "https://registry.npmjs.org"),
    [string]$CertificateExportPath = "$env:UserProfile\certificates",
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both",
    [string]$LogPath = ".\logs",
    [switch]$RequireAllCerts,
    [switch]$DryRun,
    [switch]$CleanInstall,
    [int]$TestTimeout = 30
)

# Set verbose preference from CmdletBinding
if ($PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters['Verbose']) {
    $VerbosePreference = "Continue"
}

#region Initialization

# Ensure required directories exist
@($CertificateExportPath, $LogPath) | ForEach-Object {
    if (-not (Test-Path $_)) {
        New-Item -Path $_ -ItemType Directory -Force | Out-Null
    }
}

# Initialize logging
$script:LogFilePath = Join-Path $LogPath "WSL_SSL_Installation_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Color coding for console output
    switch ($Level) {
        "SUCCESS" { Write-Host $logEntry -ForegroundColor Green }
        "WARNING" { Write-Host $logEntry -ForegroundColor Yellow }
        "ERROR" { Write-Host $logEntry -ForegroundColor Red }
        "TITLE" { Write-Host $logEntry -ForegroundColor Cyan }
        "PROGRESS" { Write-Host $logEntry -ForegroundColor Magenta }
        default { Write-Host $logEntry -ForegroundColor White }
    }
    
    # Also write to log file
    Add-Content -Path $script:LogFilePath -Value $logEntry
}

# WSL distribution configurations
$script:WSLDistros = @{
    # Ubuntu Family
    "Ubuntu" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    "Ubuntu-18.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    "Ubuntu-20.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    "Ubuntu-22.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    "Ubuntu-24.04" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    "Debian" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    "kali-linux" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    
    # RHEL Family
    "FedoraLinux-39" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "FedoraLinux-40" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "FedoraLinux-41" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "AlmaLinux-8" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "AlmaLinux-9" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "Rocky-8" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "Rocky-9" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "CentOS-7" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "RHEL-8" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    "RHEL-9" = @{ Path = "/etc/pki/ca-trust/source/anchors/"; Command = "update-ca-trust extract" }
    
    # SUSE Family
    "openSUSE-Tumbleweed" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates" }
    "openSUSE-Leap-15.5" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates" }
    "openSUSE-Leap-15.6" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates" }
    "SUSE-Linux-Enterprise-15-SP5" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates" }
    "SUSE-Linux-Enterprise-15-SP6" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates" }
    "SUSE-Linux-Enterprise-15-SP7" = @{ Path = "/etc/pki/trust/anchors/"; Command = "update-ca-certificates" }
    
    # Arch Family
    "archlinux" = @{ Path = "/etc/ca-certificates/trust-source/anchors/"; Command = "trust extract-compat" }
    "Arch" = @{ Path = "/etc/ca-certificates/trust-source/anchors/"; Command = "trust extract-compat" }
    "ManjaroLinux" = @{ Path = "/etc/ca-certificates/trust-source/anchors/"; Command = "trust extract-compat" }
    
    # Other
    "Alpine" = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
}

#endregion

#region Core Functions

function Test-WSLAvailability {
    Write-Log "Checking WSL availability..." "PROGRESS"
    
    if (-not (Get-Command wsl -ErrorAction SilentlyContinue)) {
        throw "WSL is not installed or not available in PATH"
    }
    
    try {
        $wslOutput = wsl -l -q 2>$null
        if ($wslOutput) {
            $wslList = $wslOutput | Where-Object { $_ -and $_.ToString().Trim() -ne "" } | ForEach-Object { $_.ToString().Trim() }
            if ($wslList) {
                Write-Log "Available WSL distributions: $($wslList -join ', ')" "INFO"
                return $wslList
            }
        }
        
        throw "No WSL distributions found"
    }
    catch {
        throw "Failed to list WSL distributions: $($_.Exception.Message)"
    }
}

function Get-DefaultWSLDistro {
    param([string[]]$AvailableDistros)
    
    Write-Log "Detecting default WSL distribution..." "PROGRESS"
    
    # Try to get the default distribution
    try {
        $wslOutput = wsl -l -q 2>$null
        if ($wslOutput) {
            $wslList = $wslOutput | Where-Object { $_ -and $_.ToString().Trim() -ne "" }
            if ($wslList) {
                $defaultDistro = $wslList[0].ToString().Trim()
                Write-Log "Default WSL distribution detected: $defaultDistro" "SUCCESS"
                return $defaultDistro
            }
        }
    }
    catch {
        Write-Log "Could not detect default WSL distribution" "WARNING"
    }
    
    # Fallback to first available distribution
    if ($AvailableDistros) {
        $fallback = $AvailableDistros[0].ToString().Trim()
        Write-Log "Using first available distribution: $fallback" "INFO"
        return $fallback
    }
    
    throw "No WSL distributions available"
}

function Test-WSLDistroSupport {
    param([string]$DistroName)
    
    Write-Log "Checking WSL distribution support for: $DistroName" "PROGRESS"
    
    if ($script:WSLDistros.ContainsKey($DistroName)) {
        Write-Log "WSL distribution supported: $DistroName" "SUCCESS"
        return $true
    }
    
    # Try family-based detection
    $familyMap = @{
        "Ubuntu" = @("ubuntu", "debian", "kali")
        "RHEL" = @("fedora", "centos", "rhel", "alma", "rocky")
        "SUSE" = @("suse", "opensuse")
        "Arch" = @("arch", "manjaro")
        "Alpine" = @("alpine")
    }
    
    foreach ($family in $familyMap.Keys) {
        foreach ($pattern in $familyMap[$family]) {
            if ($DistroName -like "*$pattern*") {
                Write-Log "Distribution $DistroName detected as $family family" "INFO"
                $script:WSLDistros[$DistroName] = $script:WSLDistros[$family]
                return $true
            }
        }
    }
    
    Write-Log "Unsupported WSL distribution: $DistroName" "WARNING"
    Write-Log "Attempting to use Ubuntu defaults..." "INFO"
    $script:WSLDistros[$DistroName] = @{ Path = "/usr/local/share/ca-certificates/"; Command = "update-ca-certificates" }
    return $true
}

function Test-WSLPrerequisites {
    param([string]$DistroName)
    
    Write-Log "Checking WSL prerequisites for: $DistroName" "PROGRESS"
    
    # Check if curl is available
    Write-Log "Checking if curl is available..." "PROGRESS"
    $curlCheck = wsl -d $DistroName -e bash -c "command -v curl >/dev/null 2>&1 && echo 'available' || echo 'missing'"
    
    if ($curlCheck -ne "available") {
        Write-Log "curl is not available in WSL. Attempting to install..." "WARNING"
        
        # Try to install curl based on distribution family
        $installCommands = @{
            "Ubuntu" = "apt-get update && apt-get install -y curl ca-certificates"
            "RHEL" = "yum install -y curl ca-certificates || dnf install -y curl ca-certificates"
            "SUSE" = "zypper install -y curl ca-certificates"
            "Arch" = "pacman -Sy --noconfirm curl ca-certificates"
            "Alpine" = "apk add --no-cache curl ca-certificates"
        }
        
        # Detect family and install
        $installed = $false
        foreach ($family in $installCommands.Keys) {
            if ($script:WSLDistros[$DistroName] -eq $script:WSLDistros[$family]) {
                try {
                    wsl -d $DistroName -u root -e bash -c $installCommands[$family]
                    $installed = $true
                    break
                }
                catch {
                    continue
                }
            }
        }
        
        if (-not $installed) {
            throw "Failed to install required packages in WSL distribution: $DistroName"
        }
    }
    
    Write-Log "All prerequisites are available" "SUCCESS"
}

function Search-CorporateCertificates {
    param(
        [string[]]$Patterns,
        [string[]]$ExcludeList
    )
    
    Write-Log "Searching for corporate certificates..." "PROGRESS"
    Write-Log "Patterns: $($Patterns -join ', ')" "INFO"
    Write-Log "Excluding: $($ExcludeList -join ', ')" "INFO"
    
    $storeLocations = @("LocalMachine", "CurrentUser")
    $storeNames = @("My", "Root", "CA", "AuthRoot", "TrustedPublisher", "TrustedPeople")
    
    $results = [System.Collections.ArrayList]::new()
    $processedThumbprints = @{}
    
    foreach ($storeLocation in $storeLocations) {
        foreach ($storeName in $storeNames) {
            $storePath = "Cert:\$storeLocation\$storeName"
            Write-Verbose "Searching certificates in store: $storePath"
            
            try {
                $certificates = Get-ChildItem -Path $storePath -ErrorAction SilentlyContinue
                
                foreach ($cert in $certificates) {
                    # Skip duplicates
                    if ($processedThumbprints.ContainsKey($cert.Thumbprint)) {
                        continue
                    }
                    
                    # Check if certificate matches any pattern
                    $matchesPattern = $false
                    $matchedPattern = ""
                    foreach ($pattern in $Patterns) {
                        if ($cert.Subject -like "*$pattern*" -or $cert.Issuer -like "*$pattern*") {
                            $matchesPattern = $true
                            $matchedPattern = $pattern
                            break
                        }
                    }
                    
                    if ($matchesPattern) {
                        # Check if it should be excluded
                        $shouldExclude = $false
                        foreach ($excludePattern in $ExcludeList) {
                            if ($cert.Issuer -like "*$excludePattern*" -or $cert.Subject -like "*$excludePattern*") {
                                $shouldExclude = $true
                                Write-Verbose "Excluding certificate: $excludePattern"
                                break
                            }
                        }
                        
                        if (-not $shouldExclude) {
                            Write-Verbose "Found certificate: $($cert.Subject)"
                            
                            $certInfo = @{
                                Certificate = $cert
                                Thumbprint = $cert.Thumbprint
                                Subject = $cert.Subject
                                Issuer = $cert.Issuer
                                SerialNumber = $cert.SerialNumber
                                NotBefore = $cert.NotBefore
                                NotAfter = $cert.NotAfter
                                IsValid = ($cert.NotBefore -le (Get-Date) -and $cert.NotAfter -gt (Get-Date))
                                Store = "$storeLocation\$storeName"
                                MatchedPattern = $matchedPattern
                                KeySize = if ($cert.PublicKey.Key.KeySize) { $cert.PublicKey.Key.KeySize } else { 0 }
                                SignatureAlgorithm = $cert.SignatureAlgorithm.FriendlyName
                                IsSelfSigned = ($cert.Subject -eq $cert.Issuer)
                            }
                            
                            $results.Add($certInfo) | Out-Null
                            $processedThumbprints[$cert.Thumbprint] = $true
                        }
                    }
                }
            }
            catch {
                Write-Log "Error accessing certificate store ${storePath}: $($_.Exception.Message)" "WARNING"
            }
        }
    }
    
    Write-Log "Found $($results.Count) corporate certificates" "SUCCESS"
    return $results.ToArray()
}

function Export-CertificateToFile {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [string]$FilePath
    )
    
    # Handle null certificate
    if ($null -eq $Certificate) {
        Write-Log "Cannot export null certificate to ${FilePath}" "ERROR"
        return $false
    }
    
    try {
        Write-Verbose "Exporting certificate to: $FilePath"
        
        $certBytes = $Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
        $base64Content = [Convert]::ToBase64String($certBytes)
        
        # Format with line breaks every 64 characters
        $formattedContent = ($base64Content -split "(.{64})" | Where-Object { $_ -ne "" }) -join "`n"
        
        $pemContent = @"
-----BEGIN CERTIFICATE-----
$formattedContent
-----END CERTIFICATE-----
"@
        
        Set-Content -Path $FilePath -Value $pemContent -Encoding UTF8
        Write-Log "Certificate exported: $(Split-Path -Leaf $FilePath)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to export certificate to ${FilePath}: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-SafeCertificateFileName {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )
    
    if ($null -eq $Certificate) {
        return "NullCertificate_$(Get-Date -Format 'HHmmss').crt"
    }
    
    try {
        # Try to extract meaningful name from subject
        $subjectName = ""
        
        # First try CN (Common Name)
        if ($Certificate.Subject -match "CN=([^,]+)") {
            $subjectName = $Matches[1].Trim()
        }
        # If no CN, try O (Organization)
        elseif ($Certificate.Subject -match "O=([^,]+)") {
            $subjectName = $Matches[1].Trim()
        }
        # If no O, try OU (Organizational Unit)
        elseif ($Certificate.Subject -match "OU=([^,]+)") {
            $subjectName = $Matches[1].Trim()
        }
        # Fallback to generic name
        else {
            $subjectName = "Certificate"
        }
        
        # Clean the name for Unix/Linux filesystem compatibility
        $safeName = $subjectName
        
        # Remove problematic characters and replace with safe alternatives
        $safeName = $safeName -replace '[<>:"/\\|?*]', '_'  # Windows forbidden chars
        $safeName = $safeName -replace '[@#$%^&*()+=\[\]{}|;''",.<>?/\\]', '_'  # Special chars
        $safeName = $safeName -replace '\s+', '_'  # Multiple spaces to single underscore
        $safeName = $safeName -replace '_+', '_'   # Multiple underscores to single
        $safeName = $safeName.Trim('_')            # Remove leading/trailing underscores
        
        # Handle email addresses specifically (common in certificates)
        if ($safeName -match '^(.+)_(.+)_(.+)$' -and $subjectName -like "*@*") {
            # Convert email format: user@domain.com -> user_at_domain_com
            $safeName = $subjectName -replace '@', '_at_' -replace '\.', '_'
        }
        
        # Ensure reasonable length (Unix filename limit consideration)
        if ($safeName.Length -gt 40) {
            $safeName = $safeName.Substring(0, 40)
        }
        
        # Handle empty or invalid names
        if ([string]::IsNullOrWhiteSpace($safeName) -or $safeName -eq '_') {
            $safeName = "Certificate"
        }
        
        # Add meaningful suffix based on certificate type
        $certType = ""
        if ($Certificate.Subject -like "*Root CA*") {
            $certType = "RootCA"
        }
        elseif ($Certificate.Subject -like "*Server CA*") {
            $certType = "ServerCA"
        }
        elseif ($Certificate.Subject -like "*Device CA*") {
            $certType = "DeviceCA"
        }
        elseif ($Certificate.Subject -like "*User CA*") {
            $certType = "UserCA"
        }
        elseif ($Certificate.Subject -like "*CA*") {
            $certType = "CA"
        }
        
        # Build final filename
        $finalName = $safeName
        if ($certType -and -not $safeName.Contains($certType)) {
            $finalName = "${safeName}_${certType}"
        }
        
        # Add short thumbprint for uniqueness
        $thumbprintSuffix = $Certificate.Thumbprint.Substring(0, 6)
        $finalName = "${finalName}_${thumbprintSuffix}"
        
        # Ensure .crt extension
        return "${finalName}.crt"
    }
    catch {
        # Fallback naming scheme
        $thumbprintSuffix = $Certificate.Thumbprint.Substring(0, 8)
        return "Certificate_${thumbprintSuffix}.crt"
    }
}

function Test-SSLConnectivity {
    param(
        [string]$DistroName,
        [string]$Domain,
        [int]$TimeoutSeconds = 30
    )
    
    Write-Verbose "Testing SSL connectivity to: $Domain"
    
    try {
        # Test with curl and capture both exit code and output
        $curlCommand = "timeout $TimeoutSeconds curl -s -o /dev/null -w '%{http_code}' '$Domain' 2>/dev/null || echo 'ERROR'"
        $result = wsl -d $DistroName -u root -e bash -c $curlCommand
        
        Write-Verbose "Curl result for ${Domain}: $result"
        
        # Parse result
        if ($result -eq "ERROR" -or $result -eq "" -or $result -eq "000") {
            return @{
                Success = $false
                StatusCode = "000"
                Error = "SSL certificate problem or connection failed"
            }
        }
        elseif ($result -match "^\d{3}$" -and [int]$result -ge 200 -and [int]$result -lt 400) {
            return @{
                Success = $true
                StatusCode = $result
                Error = $null
            }
        }
        else {
            return @{
                Success = $false
                StatusCode = $result
                Error = "Unexpected response"
            }
        }
    }
    catch {
        Write-Log "Error testing SSL connectivity to ${Domain}: $($_.Exception.Message)" "ERROR"
        return @{
            Success = $false
            StatusCode = "ERROR"
            Error = $_.Exception.Message
        }
    }
}

function Install-CertificateInWSL {
    param(
        [string]$CertificateFilePath,
        [string]$DistroName
    )
    
    $certFileName = Split-Path -Leaf $CertificateFilePath
    Write-Log "Installing certificate in WSL: $certFileName" "PROGRESS"
    
    try {
        $distroConfig = $script:WSLDistros[$DistroName]
        $certPath = $distroConfig.Path
        $updateCommand = $distroConfig.Command
        
        # Convert Windows path to WSL path format
        # Handle both C:\ and c:\ formats, and ensure proper WSL mount path
        $normalizedPath = $CertificateFilePath -replace '\\', '/'
        if ($normalizedPath -match '^([A-Za-z]):') {
            $driveLetter = $matches[1].ToLower()
            $pathWithoutDrive = $normalizedPath -replace '^[A-Za-z]:', ''
            $wslPath = "/mnt/$driveLetter$pathWithoutDrive"
        } else {
            $wslPath = $normalizedPath
        }
        Write-Verbose "Converted Windows path '$CertificateFilePath' to WSL path '$wslPath'"
        
        # Copy certificate to WSL
        $copyCommand = "cp '$wslPath' '$certPath$certFileName'"
        wsl -d $DistroName -u root -e bash -c $copyCommand
        
        # Verify copy
        $verifyCommand = "test -f '$certPath$certFileName' && echo 'exists' || echo 'missing'"
        $verifyResult = wsl -d $DistroName -u root -e bash -c $verifyCommand
        
        if ($verifyResult -ne "exists") {
            throw "Failed to copy certificate to WSL"
        }
        
        Write-Log "Certificate copied to WSL: $certPath$certFileName" "SUCCESS"
        
        # Update certificate store
        wsl -d $DistroName -u root -e bash -c $updateCommand
        
        Write-Log "Certificate installed and store updated" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to install certificate in WSL: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Remove-CertificateFromWSL {
    param(
        [string]$CertificateFileName,
        [string]$DistroName
    )
    
    Write-Log "Removing certificate from WSL: $CertificateFileName" "PROGRESS"
    
    try {
        $distroConfig = $script:WSLDistros[$DistroName]
        $certPath = $distroConfig.Path
        $updateCommand = $distroConfig.Command
        
        # Remove certificate file
        $removeCommand = "rm -f '$certPath$CertificateFileName'"
        wsl -d $DistroName -u root -e bash -c $removeCommand
        
        # Update certificate store
        wsl -d $DistroName -u root -e bash -c $updateCommand
        
        Write-Log "Certificate removed from WSL: $CertificateFileName" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to remove certificate from WSL: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Test-CertificateEffectiveness {
    param(
        [string]$DistroName,
        [string[]]$TestDomains,
        [string]$CertificateName,
        [array]$BaselineResults
    )
    
    Write-Log "Testing certificate effectiveness: $CertificateName" "PROGRESS"
    
    $results = @()
    $successCount = 0
    $improvementCount = 0
    
    foreach ($domain in $TestDomains) {
        $testResult = Test-SSLConnectivity -DistroName $DistroName -Domain $domain -TimeoutSeconds $TestTimeout
        
        # Find baseline result for this domain
        $baselineResult = $BaselineResults | Where-Object { $_.Domain -eq $domain } | Select-Object -First 1
        $wasWorking = $baselineResult -and $baselineResult.Success
        $nowWorking = $testResult.Success
        
        $domainResult = @{
            Domain = $domain
            Success = $testResult.Success
            StatusCode = $testResult.StatusCode
            Error = $testResult.Error
            BaselineSuccess = $wasWorking
            Improved = (-not $wasWorking -and $nowWorking)
            Degraded = ($wasWorking -and -not $nowWorking)
        }
        
        $results += $domainResult
        
        if ($testResult.Success) {
            $successCount++
            Write-Log "[OK] $domain - Success (HTTP $($testResult.StatusCode))" "SUCCESS"
            
            # Check if this is an improvement
            if (-not $wasWorking) {
                $improvementCount++
                Write-Log "[IMPROVEMENT] $domain - Now working (was failing)" "SUCCESS"
            }
        } else {
            Write-Log "[FAIL] $domain - Failed ($($testResult.StatusCode): $($testResult.Error))" "WARNING"
            
            # Check if this is a degradation
            if ($wasWorking) {
                Write-Log "[DEGRADATION] $domain - Now failing (was working)" "ERROR"
            }
        }
    }
    
    $successRate = [Math]::Round(($successCount / $TestDomains.Count) * 100, 2)
    Write-Log "Certificate effectiveness: $successCount/$($TestDomains.Count) domains ($successRate%)" "INFO"
    
    if ($improvementCount -gt 0) {
        Write-Log "Certificate improved connectivity for $improvementCount domains" "SUCCESS"
    }
    
    return @{
        CertificateName = $CertificateName
        SuccessCount = $successCount
        TotalTests = $TestDomains.Count
        SuccessRate = $successRate
        ImprovementCount = $improvementCount
        Results = $results
        IsEffective = ($improvementCount -gt 0)  # Only effective if it actually improves something
    }
}

function Export-Results {
    param(
        [array]$Results,
        [string]$ExportPath,
        [string]$Format
    )
    
    Write-Log "Exporting certificate analysis results..." "PROGRESS"
    
    $exportedFiles = @()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    
    if ($Format -eq "CSV" -or $Format -eq "Both") {
        try {
            $csvPath = Join-Path $ExportPath "Certificate_Analysis_$timestamp.csv"
            $Results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
            Write-Log "Results exported to CSV: $csvPath" "SUCCESS"
            $exportedFiles += $csvPath
        }
        catch {
            Write-Log "Failed to export CSV: $($_.Exception.Message)" "ERROR"
        }
    }
    
    if ($Format -eq "JSON" -or $Format -eq "Both") {
        try {
            $jsonPath = Join-Path $ExportPath "Certificate_Analysis_$timestamp.json"
            
            # Convert to JSON with proper formatting
            $jsonData = $Results | ForEach-Object {
                @{
                    Thumbprint = $_.Thumbprint
                    Subject = $_.Subject
                    Issuer = $_.Issuer
                    SerialNumber = $_.SerialNumber
                    NotBefore = $_.NotBefore
                    NotAfter = $_.NotAfter
                    IsValid = $_.IsValid
                    Store = $_.Store
                    MatchedPattern = $_.MatchedPattern
                    KeySize = $_.KeySize
                    SignatureAlgorithm = $_.SignatureAlgorithm
                    IsSelfSigned = $_.IsSelfSigned
                    TestResult = if ($_.TestResult) { 
                        @{
                            SuccessCount = $_.TestResult.SuccessCount
                            SuccessRate = $_.TestResult.SuccessRate
                            ImprovementCount = $_.TestResult.ImprovementCount
                            IsEffective = $_.TestResult.IsEffective
                        }
                    } else { $null }
                    Status = $_.Status
                    ExportedFile = $_.ExportedFile
                }
            }
            
            $jsonData | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonPath -Encoding UTF8
            Write-Log "Results exported to JSON: $jsonPath" "SUCCESS"
            $exportedFiles += $jsonPath
        }
        catch {
            Write-Log "Failed to export JSON: $($_.Exception.Message)" "ERROR"
        }
    }
    
    return $exportedFiles
}

#endregion

#region Main Processing

function Initialize-Environment {
    Write-Log "Initializing WSL SSL Certificate Installation Environment" "TITLE"
    Write-Log "=========================================================" "TITLE"
    Write-Log "Logging initialized: $script:LogFilePath" "INFO"
    
    # Test WSL availability
    $availableDistros = Test-WSLAvailability
    
    # Determine WSL distribution to use
    if (-not $WSLDistro) {
        $WSLDistro = Get-DefaultWSLDistro -AvailableDistros $availableDistros
    }
    
    # Test distribution support
    Test-WSLDistroSupport -DistroName $WSLDistro | Out-Null
    
    # Test prerequisites
    Test-WSLPrerequisites -DistroName $WSLDistro
    
    Write-Log "Environment initialized successfully" "SUCCESS"
    Write-Log "WSL Distribution: $WSLDistro" "INFO"
    Write-Log "Certificate Export Path: $CertificateExportPath" "INFO"
    Write-Log "Log File: $script:LogFilePath" "INFO"
    
    return $WSLDistro
}

function Test-ExistingSSLConnectivity {
    param(
        [string]$DistroName,
        [string[]]$TestDomains
    )
    
    Write-Log "Testing existing SSL connectivity before certificate processing..." "PROGRESS"
    
    $results = @()
    $successCount = 0
    
    foreach ($domain in $TestDomains) {
        $testResult = Test-SSLConnectivity -DistroName $DistroName -Domain $domain
        $results += @{
            Domain = $domain
            Success = $testResult.Success
            StatusCode = $testResult.StatusCode
        }
        
        if ($testResult.Success) {
            $successCount++
        }
    }
    
    $successRate = [Math]::Round(($successCount / $TestDomains.Count) * 100, 2)
    Write-Log "Initial connectivity: $successCount/$($TestDomains.Count) domains successful ($successRate%)" "INFO"
    
    return @{
        SuccessCount = $successCount
        TotalCount = $TestDomains.Count
        SuccessRate = $successRate
        Results = $results
        AllSuccessful = ($successCount -eq $TestDomains.Count)
    }
}

function Backup-ExistingCertificates {
    param([string]$DistroName)
    
    Write-Log "Creating backup of existing certificates..." "PROGRESS"
    
    try {
        # Create backup directory in WSL home
        $backupDir = "/home/backup_certificates_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        $createBackupCmd = "mkdir -p '$backupDir'"
        wsl -d $DistroName -u root -e bash -c $createBackupCmd
        
        # Check if there are any certificates to backup
        $checkCertsCmd = "ls -la /usr/local/share/ca-certificates/*.crt 2>/dev/null | wc -l"
        $certCount = wsl -d $DistroName -u root -e bash -c $checkCertsCmd
        
        if ([int]$certCount -gt 0) {
            # Move existing certificates to backup
            $backupCmd = "mv /usr/local/share/ca-certificates/*.crt '$backupDir/' 2>/dev/null || true"
            wsl -d $DistroName -u root -e bash -c $backupCmd
            
            # Update CA certificates after removal
            $updateCmd = "update-ca-certificates"
            wsl -d $DistroName -u root -e bash -c $updateCmd
            
            Write-Log "Backed up $certCount certificates to: $backupDir" "SUCCESS"
            return $backupDir
        } else {
            Write-Log "No existing certificates found to backup" "INFO"
            # Remove empty backup directory
            wsl -d $DistroName -u root -e bash -c "rmdir '$backupDir'"
            return $null
        }
    }
    catch {
        Write-Log "Failed to backup existing certificates: $($_.Exception.Message)" "ERROR"
        return $null
    }
}

function Restore-BackupCertificates {
    param(
        [string]$DistroName,
        [string]$BackupPath
    )
    
    if (-not $BackupPath) {
        Write-Log "No backup path provided - nothing to restore" "INFO"
        return $true
    }
    
    Write-Log "Restoring certificates from backup: $BackupPath" "PROGRESS"
    
    try {
        # Restore certificates from backup
        $restoreCmd = "mv '$BackupPath'/*.crt /usr/local/share/ca-certificates/ 2>/dev/null || true"
        wsl -d $DistroName -u root -e bash -c $restoreCmd
        
        # Update CA certificates
        $updateCmd = "update-ca-certificates"
        wsl -d $DistroName -u root -e bash -c $updateCmd
        
        # Remove backup directory
        $cleanupCmd = "rmdir '$BackupPath'"
        wsl -d $DistroName -u root -e bash -c $cleanupCmd
        
        Write-Log "Successfully restored certificates from backup" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "Failed to restore certificates from backup: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Invoke-CertificateProcessing {
    param([string]$DistroName)
    
    Write-Log "Starting certificate processing..." "TITLE"
    
    # Test existing SSL connectivity FIRST before any processing
    $initialConnectivity = Test-ExistingSSLConnectivity -DistroName $DistroName -TestDomains $TestDomains
    
    if ($initialConnectivity.AllSuccessful) {
        Write-Log "All domains are already working successfully!" "SUCCESS"
        Write-Log "Attempting to identify which certificates are responsible..." "PROGRESS"
        
        # Backup existing certificates and test again
        $backupPath = Backup-ExistingCertificates -DistroName $DistroName
        
        # Test connectivity after removing certificates
        Write-Log "Testing connectivity after removing existing certificates..." "PROGRESS"
        $connectivityAfterRemoval = Test-ExistingSSLConnectivity -DistroName $DistroName -TestDomains $TestDomains
        
        if ($connectivityAfterRemoval.AllSuccessful) {
            # Still working without certificates - restore backup and exit
            Restore-BackupCertificates -DistroName $DistroName -BackupPath $backupPath
            
            Write-Log "SSL connectivity remains successful even without custom certificates." "WARNING"
            Write-Log "This indicates that:" "INFO"
            Write-Log "  - WSL may be using system certificates that are already working" "INFO"
            Write-Log "  - Corporate SSL inspection may not be active for these domains" "INFO"
            Write-Log "  - Network configuration allows direct SSL connections" "INFO"
            Write-Log "Script cannot identify specific certificates needed in this environment." "WARNING"
            Write-Log "If you experience SSL issues with other domains, re-run the script with those domains." "INFO"
            
            return @()
        } else {
            # Connectivity failed after removing certificates - they were needed
            Write-Log "SSL connectivity failed after removing certificates - they are required!" "SUCCESS"
            Write-Log "Proceeding to analyze which specific certificates are needed..." "PROGRESS"
            
            # Restore certificates temporarily for analysis
            Restore-BackupCertificates -DistroName $DistroName -BackupPath $backupPath
        }
    }
    
    # Clean install if requested (after initial connectivity test)
    if ($CleanInstall) {
        Write-Log "Clean install requested - clearing existing certificates..." "WARNING"
        Clear-WSLCertificates -DistroName $DistroName
    }
    
    # Search for corporate certificates
    $allCertificates = Search-CorporateCertificates -Patterns $SearchPatterns -ExcludeList $ExcludeIssuers
    
    # Filter out null entries - use array approach to avoid Where-Object issues
    $certificates = @()
    foreach ($cert in $allCertificates) {
        if ($null -ne $cert -and $null -ne $cert.Certificate) {
            $certificates += $cert
        }
    }
    
    if ($certificates.Count -eq 0) {
        Write-Log "No corporate certificates found matching the criteria" "WARNING"
        return @()
    }
    
    Write-Log "Found $($certificates.Count) valid corporate certificates after filtering" "SUCCESS"
    
    # Test initial connectivity (before any certificate installation)
    Write-Log "Testing initial SSL connectivity (baseline)..." "PROGRESS"
    $baselineResults = @()
    foreach ($domain in $TestDomains) {
        $baselineTest = Test-SSLConnectivity -DistroName $DistroName -Domain $domain
        $baselineResults += @{
            Domain = $domain
            Success = $baselineTest.Success
            StatusCode = $baselineTest.StatusCode
        }
    }
    
    $baselineSuccesses = ($baselineResults | Where-Object { $_.Success }).Count
    Write-Log "Baseline connectivity: $baselineSuccesses/$($TestDomains.Count) domains successful" "INFO"
    
    # Process certificates
    $processedCertificates = @()
    $successfulCertificates = @()
    
    Write-Log "Processing $($certificates.Count) certificates..." "PROGRESS"
    
    for ($i = 0; $i -lt $certificates.Count; $i++) {
        $cert = $certificates[$i]
        $certNumber = $i + 1
        
        # Handle null or invalid certificate objects
        if ($null -eq $cert -or $null -eq $cert.Certificate) {
            Write-Log "[$certNumber/$($certificates.Count)] Skipping null certificate" "WARNING"
            continue
        }
        
        Write-Log "[$certNumber/$($certificates.Count)] Processing: $($cert.Subject)" "TITLE"
        
        # Export certificate
        $certFileName = Get-SafeCertificateFileName -Certificate $cert.Certificate
        $certFilePath = Join-Path $CertificateExportPath $certFileName
        
        $exportSuccess = Export-CertificateToFile -Certificate $cert.Certificate -FilePath $certFilePath
        if (-not $exportSuccess) {
            $cert.Status = "Export Failed"
            $cert.ExportedFile = $null
            $processedCertificates += $cert
            continue
        }
        
        $cert.ExportedFile = $certFilePath
        
        if ($DryRun) {
            Write-Log "Dry run mode - skipping installation" "INFO"
            $cert.Status = "Dry Run"
            $processedCertificates += $cert
            continue
        }
        
        # Install certificate in WSL
        $installSuccess = Install-CertificateInWSL -CertificateFilePath $certFilePath -DistroName $DistroName
        if (-not $installSuccess) {
            $cert.Status = "Installation Failed"
            $processedCertificates += $cert
            continue
        }
        
        # Test certificate effectiveness by comparing with baseline
        $testResult = Test-CertificateEffectiveness -DistroName $DistroName -TestDomains $TestDomains -CertificateName $certFileName -BaselineResults $baselineResults
        $cert.TestResult = $testResult
        
        if ($testResult.IsEffective) {
            Write-Log "Certificate is effective! Improved connectivity for $($testResult.ImprovementCount) domains" "SUCCESS"
            $cert.Status = "Effective"
            $successfulCertificates += $cert
            
            if (-not $RequireAllCerts) {
                Write-Log "First effective certificate found. Use -RequireAllCerts to test all certificates." "INFO"
                $cert.Status = "Installed"
                $processedCertificates += $cert
                break
            } else {
                $cert.Status = "Installed"
            }
        } else {
            Write-Log "Certificate provides no improvement. Removing from WSL..." "WARNING"
            Remove-CertificateFromWSL -CertificateFileName $certFileName -DistroName $DistroName
            $cert.Status = "Ineffective"
        }
        
        $processedCertificates += $cert
    }
    
    return $processedCertificates
}

function Invoke-FinalValidation {
    param(
        [string]$DistroName,
        [array]$ProcessedCertificates
    )
    
    Write-Log "Performing final validation..." "TITLE"
    
    $installedCerts = $ProcessedCertificates | Where-Object { $_.Status -eq "Installed" -or $_.Status -eq "Effective" }
    
    if ($installedCerts.Count -eq 0) {
        Write-Log "No certificates were successfully installed" "WARNING"
        return
    }
    
    Write-Log "Installed certificates: $($installedCerts.Count)" "SUCCESS"
    foreach ($cert in $installedCerts) {
        Write-Log "  - $($cert.Subject)" "INFO"
    }
    
    # Final connectivity test
    Write-Log "Performing final connectivity test..." "PROGRESS"
    $finalResults = @()
    
    foreach ($domain in $TestDomains) {
        $finalTest = Test-SSLConnectivity -DistroName $DistroName -Domain $domain
        $finalResults += @{
            Domain = $domain
            Success = $finalTest.Success
            StatusCode = $finalTest.StatusCode
        }
        
        if ($finalTest.Success) {
            Write-Log "[OK] $domain - Success (HTTP $($finalTest.StatusCode))" "SUCCESS"
        } else {
            Write-Log "[FAIL] $domain - Failed ($($finalTest.StatusCode))" "ERROR"
        }
    }
    
    $finalSuccesses = ($finalResults | Where-Object { $_.Success }).Count
    Write-Log "Final connectivity: $finalSuccesses/$($TestDomains.Count) domains successful" "SUCCESS"
    
    if ($finalSuccesses -eq $TestDomains.Count) {
        Write-Log "SUCCESS: All SSL connectivity tests passed! WSL is ready for corporate use." "SUCCESS"
    } elseif ($finalSuccesses -gt 0) {
        Write-Log "WARNING: Partial success. Some domains may still have SSL issues." "WARNING"
    } else {
        Write-Log "ERROR: SSL connectivity issues persist. Manual intervention may be required." "ERROR"
    }
}

function Invoke-MainProcess {
    try {
        # Initialize environment
        $distroName = Initialize-Environment
        
        # Process certificates
        $processedCertificates = Invoke-CertificateProcessing -DistroName $distroName
        
        # Export results
        if ($processedCertificates.Count -gt 0) {
            $exportedFiles = Export-Results -Results $processedCertificates -ExportPath $CertificateExportPath -Format $ExportFormat
            Write-Log "Analysis results exported to: $($exportedFiles -join ', ')" "SUCCESS"
        }
        
        # Final validation
        if (-not $DryRun) {
            Invoke-FinalValidation -DistroName $distroName -ProcessedCertificates $processedCertificates
        }
        
        Write-Log "Certificate installation process completed!" "SUCCESS"
        Write-Log "Log file: $script:LogFilePath" "INFO"
        
    }
    catch {
        Write-Log "Critical error: $($_.Exception.Message)" "ERROR"
        Write-Log "Stack trace: $($_.ScriptStackTrace)" "ERROR"
        throw
    }
}

#endregion

# Execute main process
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-MainProcess
}
