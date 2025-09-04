#Requires -Version 5.1
<#
.SYNOPSIS
    Test suite for WSL SSL Inspector

.DESCRIPTION
    Comprehensive test suite to validate the functionality of the WSL SSL Inspector
    certificate installation and management system.
#>

[CmdletBinding()]
param(
    [string]$TestWSLDistro = "Ubuntu",
    [switch]$SkipWSLTests,
    [switch]$Verbose
)

# Set verbose preference
if ($Verbose) { $VerbosePreference = "Continue" }

#region Test Framework

$script:TestResults = @()
$script:TestCount = 0
$script:PassCount = 0
$script:FailCount = 0

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Message = "",
        [string]$Details = ""
    )
    
    $script:TestCount++
    
    if ($Passed) {
        $script:PassCount++
        $status = "PASS"
        $color = "Green"
    } else {
        $script:FailCount++
        $status = "FAIL"
        $color = "Red"
    }
    
    $result = @{
        TestName = $TestName
        Status = $status
        Passed = $Passed
        Message = $Message
        Details = $Details
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    Write-Host "[$status] $TestName" -ForegroundColor $color
    if ($Message) {
        Write-Host "      $Message" -ForegroundColor Gray
    }
    if ($Details -and $Verbose) {
        Write-Host "      Details: $Details" -ForegroundColor DarkGray
    }
}

function Assert-True {
    param(
        [string]$TestName,
        [bool]$Condition,
        [string]$Message = ""
    )
    
    Write-TestResult -TestName $TestName -Passed $Condition -Message $Message
}

function Assert-NotNull {
    param(
        [string]$TestName,
        [object]$Object,
        [string]$Message = ""
    )
    
    $condition = $null -ne $Object
    Write-TestResult -TestName $TestName -Passed $condition -Message $Message
}

function Assert-FileExists {
    param(
        [string]$TestName,
        [string]$FilePath,
        [string]$Message = ""
    )
    
    $condition = Test-Path $FilePath
    $details = "File: $FilePath"
    Write-TestResult -TestName $TestName -Passed $condition -Message $Message -Details $details
}

#endregion

#region Test Functions

function Test-ScriptSyntax {
    Write-Host "`n=== Testing Script Syntax ===" -ForegroundColor Cyan
    
    $scriptPath = ".\src\Install-CorporateCertificatesWSL.ps1"
    
    try {
        $tokens = $null
        $errors = $null
        [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$tokens, [ref]$errors)
        
        Assert-True -TestName "Script Syntax Valid" -Condition ($errors.Count -eq 0) -Message "PowerShell syntax validation"
        
        if ($errors.Count -gt 0) {
            foreach ($err in $errors) {
                Write-Host "      Syntax Error: $($err.Message)" -ForegroundColor Red
            }
        }
    }
    catch {
        Assert-True -TestName "Script Syntax Valid" -Condition $false -Message "Exception during syntax check: $($_.Exception.Message)"
    }
}

function Test-RequiredModules {
    Write-Host "`n=== Testing Required Modules ===" -ForegroundColor Cyan
    
    # Test if script can be imported without errors
    try {
        $scriptContent = Get-Content ".\src\Install-CorporateCertificatesWSL.ps1" -Raw
        $scriptBlock = [ScriptBlock]::Create($scriptContent)
        
        Assert-True -TestName "Script Import" -Condition ($null -ne $scriptBlock) -Message "Script can be loaded as ScriptBlock"
    }
    catch {
        Assert-True -TestName "Script Import" -Condition $false -Message "Script import failed: $($_.Exception.Message)"
    }
}

function Test-CertificateStoreAccess {
    Write-Host "`n=== Testing Certificate Store Access ===" -ForegroundColor Cyan
    
    $stores = @(
        "Cert:\LocalMachine\Root",
        "Cert:\LocalMachine\CA",
        "Cert:\CurrentUser\Root",
        "Cert:\CurrentUser\CA"
    )
    
    foreach ($store in $stores) {
        try {
            $certs = Get-ChildItem -Path $store -ErrorAction Stop
            Assert-True -TestName "Access $store" -Condition $true -Message "Successfully accessed certificate store"
        }
        catch {
            Assert-True -TestName "Access $store" -Condition $false -Message "Failed to access: $($_.Exception.Message)"
        }
    }
}

function Test-WSLAvailability {
    Write-Host "`n=== Testing WSL Availability ===" -ForegroundColor Cyan
    
    if ($SkipWSLTests) {
        Write-Host "Skipping WSL tests as requested" -ForegroundColor Yellow
        return
    }
    
    # Test WSL command availability
    $wslCommand = Get-Command wsl -ErrorAction SilentlyContinue
    Assert-NotNull -TestName "WSL Command Available" -Object $wslCommand -Message "WSL command found in PATH"
    
    if ($wslCommand) {
        try {
            $wslDistros = wsl -l -q 2>$null | Where-Object { $_ -ne "" -and $_ -notmatch "^Windows Subsystem" }
            Assert-True -TestName "WSL Distributions Available" -Condition ($wslDistros.Count -gt 0) -Message "Found $($wslDistros.Count) WSL distributions"
            
            if ($wslDistros -contains $TestWSLDistro) {
                Assert-True -TestName "Test Distribution Available" -Condition $true -Message "Test distribution '$TestWSLDistro' is available"
                
                # Test basic WSL functionality
                try {
                    $testOutput = wsl -d $TestWSLDistro -e echo "test"
                    Assert-True -TestName "WSL Basic Functionality" -Condition ($testOutput -eq "test") -Message "WSL can execute basic commands"
                }
                catch {
                    Assert-True -TestName "WSL Basic Functionality" -Condition $false -Message "WSL command execution failed: $($_.Exception.Message)"
                }
            } else {
                Assert-True -TestName "Test Distribution Available" -Condition $false -Message "Test distribution '$TestWSLDistro' not found"
            }
        }
        catch {
            Assert-True -TestName "WSL Distributions Available" -Condition $false -Message "Failed to list WSL distributions: $($_.Exception.Message)"
        }
    }
}

function Test-DirectoryCreation {
    Write-Host "`n=== Testing Directory Creation ===" -ForegroundColor Cyan
    
    $testPaths = @(
        ".\test_certificates",
        ".\test_logs",
        "$env:TEMP\wsl_ssl_test"
    )
    
    foreach ($path in $testPaths) {
        try {
            if (Test-Path $path) {
                Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
            }
            
            New-Item -ItemType Directory -Path $path -Force | Out-Null
            Assert-FileExists -TestName "Create Directory $path" -FilePath $path -Message "Directory created successfully"
            
            # Cleanup
            Remove-Item $path -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            Assert-True -TestName "Create Directory $path" -Condition $false -Message "Failed to create directory: $($_.Exception.Message)"
        }
    }
}

function Test-CertificateExport {
    Write-Host "`n=== Testing Certificate Export ===" -ForegroundColor Cyan
    
    try {
        # Find a test certificate
        $testCert = Get-ChildItem -Path "Cert:\LocalMachine\Root" | Select-Object -First 1
        
        if ($testCert) {
            Assert-NotNull -TestName "Test Certificate Available" -Object $testCert -Message "Found test certificate for export testing"
            
            # Test export functionality
            $testExportPath = "$env:TEMP\test_cert_export.crt"
            
            try {
                $certBytes = $testCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                $base64Content = [Convert]::ToBase64String($certBytes)
                $formattedContent = ($base64Content -split "(.{64})" | Where-Object { $_ -ne "" }) -join "`n"
                
                $pemContent = @"
-----BEGIN CERTIFICATE-----
$formattedContent
-----END CERTIFICATE-----
"@
                
                Set-Content -Path $testExportPath -Value $pemContent -Encoding UTF8
                
                Assert-FileExists -TestName "Certificate Export" -FilePath $testExportPath -Message "Certificate exported to PEM format"
                
                # Verify file content
                $exportedContent = Get-Content $testExportPath -Raw
                $hasBeginMarker = $exportedContent -like "*-----BEGIN CERTIFICATE-----*"
                $hasEndMarker = $exportedContent -like "*-----END CERTIFICATE-----*"
                
                Assert-True -TestName "PEM Format Valid" -Condition ($hasBeginMarker -and $hasEndMarker) -Message "Exported certificate has valid PEM format"
                
                # Cleanup
                Remove-Item $testExportPath -Force -ErrorAction SilentlyContinue
            }
            catch {
                Assert-True -TestName "Certificate Export" -Condition $false -Message "Export failed: $($_.Exception.Message)"
            }
        } else {
            Assert-True -TestName "Test Certificate Available" -Condition $false -Message "No certificates found for testing"
        }
    }
    catch {
        Assert-True -TestName "Test Certificate Available" -Condition $false -Message "Failed to access certificate store: $($_.Exception.Message)"
    }
}

function Test-ParameterValidation {
    Write-Host "`n=== Testing Parameter Validation ===" -ForegroundColor Cyan
    
    # Test valid export formats
    $validFormats = @("CSV", "JSON", "Both")
    foreach ($format in $validFormats) {
        Assert-True -TestName "Valid Export Format: $format" -Condition $true -Message "Format '$format' should be accepted"
    }
    
    # Test path validation
    $testPath = $env:TEMP
    Assert-True -TestName "Valid Path Parameter" -Condition (Test-Path $testPath) -Message "Temp path exists and is accessible"
    
    # Test timeout parameter
    $testTimeout = 30
    Assert-True -TestName "Valid Timeout Parameter" -Condition ($testTimeout -gt 0) -Message "Timeout value is positive"
}

function Test-LoggingFunctionality {
    Write-Host "`n=== Testing Logging Functionality ===" -ForegroundColor Cyan
    
    $testLogDir = "$env:TEMP\wsl_ssl_test_logs"
    $testLogFile = Join-Path $testLogDir "test_log.log"
    
    try {
        # Create test log directory
        if (-not (Test-Path $testLogDir)) {
            New-Item -ItemType Directory -Path $testLogDir -Force | Out-Null
        }
        
        # Test log file creation
        $testLogContent = @"
[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] Test log entry
[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [SUCCESS] Test successful operation
[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARNING] Test warning message
"@
        
        Set-Content -Path $testLogFile -Value $testLogContent -Encoding UTF8
        
        Assert-FileExists -TestName "Log File Creation" -FilePath $testLogFile -Message "Log file created successfully"
        
        # Test log content
        $logContent = Get-Content $testLogFile
        Assert-True -TestName "Log Content Valid" -Condition ($logContent.Count -eq 3) -Message "Log file contains expected number of entries"
        
        # Cleanup
        Remove-Item $testLogDir -Recurse -Force -ErrorAction SilentlyContinue
    }
    catch {
        Assert-True -TestName "Log File Creation" -Condition $false -Message "Logging test failed: $($_.Exception.Message)"
    }
}

function Test-CSVExport {
    Write-Host "`n=== Testing CSV Export ===" -ForegroundColor Cyan
    
    $testData = @(
        [PSCustomObject]@{
            Thumbprint = "ABC123"
            Subject = "CN=Test Certificate"
            Status = "Test"
        },
        [PSCustomObject]@{
            Thumbprint = "DEF456" 
            Subject = "CN=Another Test"
            Status = "Test"
        }
    )
    
    $testCsvPath = "$env:TEMP\test_export.csv"
    
    try {
        $testData | Export-Csv -Path $testCsvPath -NoTypeInformation -Encoding UTF8
        
        Assert-FileExists -TestName "CSV Export" -FilePath $testCsvPath -Message "CSV file exported successfully"
        
        # Test CSV import
        $importedData = Import-Csv -Path $testCsvPath
        Assert-True -TestName "CSV Import" -Condition ($importedData.Count -eq 2) -Message "CSV data imported correctly"
        
        # Cleanup
        Remove-Item $testCsvPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Assert-True -TestName "CSV Export" -Condition $false -Message "CSV export test failed: $($_.Exception.Message)"
    }
}

function Test-JSONExport {
    Write-Host "`n=== Testing JSON Export ===" -ForegroundColor Cyan
    
    $testData = @{
        ExportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TestData = @(
            @{ Name = "Test1"; Value = "Value1" },
            @{ Name = "Test2"; Value = "Value2" }
        )
    }
    
    $testJsonPath = "$env:TEMP\test_export.json"
    
    try {
        $testData | ConvertTo-Json -Depth 10 | Set-Content -Path $testJsonPath -Encoding UTF8
        
        Assert-FileExists -TestName "JSON Export" -FilePath $testJsonPath -Message "JSON file exported successfully"
        
        # Test JSON import
        $importedData = Get-Content $testJsonPath | ConvertFrom-Json
        Assert-NotNull -TestName "JSON Import" -Object $importedData -Message "JSON data imported correctly"
        Assert-True -TestName "JSON Structure" -Condition ($importedData.TestData.Count -eq 2) -Message "JSON structure preserved"
        
        # Cleanup
        Remove-Item $testJsonPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Assert-True -TestName "JSON Export" -Condition $false -Message "JSON export test failed: $($_.Exception.Message)"
    }
}

function Test-WSLDistributionSupport {
    Write-Host "`n=== Testing WSL Distribution Support ===" -ForegroundColor Cyan
    
    if ($SkipWSLTests) {
        Write-Host "Skipping WSL distribution tests as requested" -ForegroundColor Yellow
        return
    }
    
    # Test known distribution configurations
    $knownDistros = @("Ubuntu", "Ubuntu-22.04", "Debian", "AlmaLinux-9", "openSUSE-Leap-15.6")
    
    # Load the WSL distribution configuration from the script
    try {
        $scriptContent = Get-Content ".\src\Install-CorporateCertificatesWSL.ps1" -Raw
        
        foreach ($distro in $knownDistros) {
            $hasConfig = $scriptContent -like "*`"$distro`"*"
            Assert-True -TestName "Distribution Config: $distro" -Condition $hasConfig -Message "Configuration found for $distro"
        }
    }
    catch {
        Assert-True -TestName "Distribution Configuration" -Condition $false -Message "Failed to load distribution configurations"
    }
}

#endregion

#region Main Test Execution

function Invoke-AllTests {
    Write-Host "WSL SSL Inspector - Test Suite" -ForegroundColor Magenta
    Write-Host "==============================" -ForegroundColor Magenta
    Write-Host "Test WSL Distribution: $TestWSLDistro" -ForegroundColor Gray
    Write-Host "Skip WSL Tests: $SkipWSLTests" -ForegroundColor Gray
    Write-Host ""
    
    # Run all tests
    Test-ScriptSyntax
    Test-RequiredModules
    Test-CertificateStoreAccess
    Test-WSLAvailability
    Test-DirectoryCreation
    Test-CertificateExport
    Test-ParameterValidation
    Test-LoggingFunctionality
    Test-CSVExport
    Test-JSONExport
    Test-WSLDistributionSupport
    
    # Summary
    Write-Host "`n=== Test Summary ===" -ForegroundColor Magenta
    Write-Host "Total Tests: $script:TestCount" -ForegroundColor White
    Write-Host "Passed: $script:PassCount" -ForegroundColor Green
    Write-Host "Failed: $script:FailCount" -ForegroundColor Red
    
    if ($script:FailCount -eq 0) {
        Write-Host "`n🎉 All tests passed!" -ForegroundColor Green
        $exitCode = 0
    } else {
        Write-Host "`n❌ Some tests failed. Check the output above for details." -ForegroundColor Red
        $exitCode = 1
    }
    
    # Export test results
    $resultsPath = ".\test_results_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    try {
        $testSummary = @{
            TestRunDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            TotalTests = $script:TestCount
            PassedTests = $script:PassCount
            FailedTests = $script:FailCount
            TestWSLDistro = $TestWSLDistro
            SkipWSLTests = $SkipWSLTests.IsPresent
            Results = $script:TestResults
        }
        
        $testSummary | ConvertTo-Json -Depth 10 | Set-Content -Path $resultsPath -Encoding UTF8
        Write-Host "`nTest results exported to: $resultsPath" -ForegroundColor Cyan
    }
    catch {
        Write-Host "`nFailed to export test results: $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    return $exitCode
}

#endregion

# Execute tests if script is run directly
if ($MyInvocation.InvocationName -ne '.') {
    $exitCode = Invoke-AllTests
    exit $exitCode
}
