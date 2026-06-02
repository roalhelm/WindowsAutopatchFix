<#
.SYNOPSIS
    Test script for Windows Update Fix detection and remediation scripts.
    Validates functionality and simulates various scenarios locally.

.DESCRIPTION
    This script helps validate the detection and remediation scripts before deploying
    to Intune. It can test various scenarios and verify script behavior.

.NOTES
    File Name     : Test-WindowsUpdateFix.ps1
    Author        : Ronny Alhelm
    Version       : 1.0
    Creation Date : 2026-06-02

.EXAMPLE
    .\Test-WindowsUpdateFix.ps1
    # Runs all validation tests

.EXAMPLE
    .\Test-WindowsUpdateFix.ps1 -TestDetectionOnly
    # Only tests detection script

.EXAMPLE
    .\Test-WindowsUpdateFix.ps1 -TestRemediationOnly
    # Only tests remediation script
#>

param (
    [switch]$TestDetectionOnly,
    [switch]$TestRemediationOnly,
    [switch]$Verbose
)

$ErrorActionPreference = "Continue"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Windows Update Fix - Test Suite v1.0" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

# Test Results Tracking
$script:TestResults = @{
    Passed = 0
    Failed = 0
    Warnings = 0
    Tests = @()
}

function Write-TestResult {
    param (
        [string]$TestName,
        [string]$Status,  # Pass, Fail, Warning
        [string]$Message
    )
    
    $color = switch ($Status) {
        "Pass" { "Green"; $script:TestResults.Passed++ }
        "Fail" { "Red"; $script:TestResults.Failed++ }
        "Warning" { "Yellow"; $script:TestResults.Warnings++ }
    }
    
    $statusSymbol = switch ($Status) {
        "Pass" { "[✓]" }
        "Fail" { "[✗]" }
        "Warning" { "[!]" }
    }
    
    Write-Host "$statusSymbol $TestName" -ForegroundColor $color
    if ($Message) {
        Write-Host "    $Message" -ForegroundColor Gray
    }
    
    $script:TestResults.Tests += @{
        Name = $TestName
        Status = $Status
        Message = $Message
    }
}

# Test 1: Check if scripts exist
function Test-ScriptExistence {
    Write-Host "`n--- Testing Script Existence ---" -ForegroundColor Yellow
    
    $detectionPath = Join-Path $scriptPath "detection.ps1"
    $remediationPath = Join-Path $scriptPath "remediation.ps1"
    
    if (Test-Path $detectionPath) {
        Write-TestResult "Detection Script Exists" "Pass" $detectionPath
    } else {
        Write-TestResult "Detection Script Exists" "Fail" "Not found at $detectionPath"
    }
    
    if (Test-Path $remediationPath) {
        Write-TestResult "Remediation Script Exists" "Pass" $remediationPath
    } else {
        Write-TestResult "Remediation Script Exists" "Fail" "Not found at $remediationPath"
    }
}

# Test 2: Validate PowerShell syntax
function Test-ScriptSyntax {
    Write-Host "`n--- Testing PowerShell Syntax ---" -ForegroundColor Yellow
    
    $detectionPath = Join-Path $scriptPath "detection.ps1"
    $remediationPath = Join-Path $scriptPath "remediation.ps1"
    
    # Test detection.ps1
    if (Test-Path $detectionPath) {
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $detectionPath -Raw), [ref]$errors)
        if ($errors.Count -eq 0) {
            Write-TestResult "Detection Script Syntax" "Pass" "No syntax errors"
        } else {
            Write-TestResult "Detection Script Syntax" "Fail" "$($errors.Count) syntax error(s) found"
            foreach ($error in $errors) {
                Write-Host "      Line $($error.Token.StartLine): $($error.Message)" -ForegroundColor Red
            }
        }
    }
    
    # Test remediation.ps1
    if (Test-Path $remediationPath) {
        $errors = $null
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $remediationPath -Raw), [ref]$errors)
        if ($errors.Count -eq 0) {
            Write-TestResult "Remediation Script Syntax" "Pass" "No syntax errors"
        } else {
            Write-TestResult "Remediation Script Syntax" "Fail" "$($errors.Count) syntax error(s) found"
            foreach ($error in $errors) {
                Write-Host "      Line $($error.Token.StartLine): $($error.Message)" -ForegroundColor Red
            }
        }
    }
}

# Test 3: Check for required functions
function Test-RequiredFunctions {
    Write-Host "`n--- Testing Required Functions ---" -ForegroundColor Yellow
    
    $detectionPath = Join-Path $scriptPath "detection.ps1"
    $remediationPath = Join-Path $scriptPath "remediation.ps1"
    
    # Detection script required functions
    $detectionContent = Get-Content $detectionPath -Raw
    $detectionFunctions = @("Write-Log", "Invoke-LogRotation", "Get-ErrorCodeDescription")
    
    foreach ($func in $detectionFunctions) {
        if ($detectionContent -match "function $func") {
            Write-TestResult "Detection: Function $func" "Pass" "Found"
        } else {
            Write-TestResult "Detection: Function $func" "Fail" "Not found"
        }
    }
    
    # Remediation script required functions
    $remediationContent = Get-Content $remediationPath -Raw
    $remediationFunctions = @("Write-Log", "Invoke-LogRotation", "Start-ServiceWithRetry", "Test-WUComponentsNeedReset", "Test-ServicesNeedRestart")
    
    foreach ($func in $remediationFunctions) {
        if ($remediationContent -match "function $func") {
            Write-TestResult "Remediation: Function $func" "Pass" "Found"
        } else {
            Write-TestResult "Remediation: Function $func" "Fail" "Not found"
        }
    }
}

# Test 4: Validate configuration variables
function Test-ConfigurationVariables {
    Write-Host "`n--- Testing Configuration Variables ---" -ForegroundColor Yellow
    
    $detectionPath = Join-Path $scriptPath "detection.ps1"
    $remediationPath = Join-Path $scriptPath "remediation.ps1"
    
    # Detection script config variables
    $detectionContent = Get-Content $detectionPath -Raw
    $detectionVars = @("maxEventLogEntries", "minDiskSpaceGB", "maxSoftwareDistFiles", "dllMinYear")
    
    foreach ($var in $detectionVars) {
        if ($detectionContent -match "\`$$var\s*=") {
            Write-TestResult "Detection: Variable `$$var" "Pass" "Defined"
        } else {
            Write-TestResult "Detection: Variable `$$var" "Fail" "Not defined"
        }
    }
    
    # Remediation script config variables
    $remediationContent = Get-Content $remediationPath -Raw
    $remediationVars = @("fullRepair", "resetWUComponents", "cleanupRegistry", "serviceRetryCount")
    
    foreach ($var in $remediationVars) {
        if ($remediationContent -match "\`$$var\s*=") {
            Write-TestResult "Remediation: Variable `$$var" "Pass" "Defined"
        } else {
            Write-TestResult "Remediation: Variable `$$var" "Fail" "Not defined"
        }
    }
}

# Test 5: Check system prerequisites
function Test-SystemPrerequisites {
    Write-Host "`n--- Testing System Prerequisites ---" -ForegroundColor Yellow
    
    # Check if running as Administrator
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($isAdmin) {
        Write-TestResult "Running as Administrator" "Pass" "Required for full testing"
    } else {
        Write-TestResult "Running as Administrator" "Warning" "Some tests may fail without admin rights"
    }
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -ge 5) {
        Write-TestResult "PowerShell Version" "Pass" "Version $($PSVersionTable.PSVersion) is supported"
    } else {
        Write-TestResult "PowerShell Version" "Fail" "Version $($PSVersionTable.PSVersion) is too old (requires 5.1+)"
    }
    
    # Check critical services exist
    $criticalServices = @('wuauserv', 'BITS', 'CryptSvc', 'IntuneManagementExtension')
    foreach ($svc in $criticalServices) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service) {
            Write-TestResult "Service: $svc" "Pass" "Status: $($service.Status)"
        } else {
            if ($svc -eq 'IntuneManagementExtension') {
                Write-TestResult "Service: $svc" "Warning" "Not found (may not be Intune-managed)"
            } else {
                Write-TestResult "Service: $svc" "Fail" "Service not found"
            }
        }
    }
}

# Test 6: Dry run detection script
function Test-DetectionDryRun {
    Write-Host "`n--- Testing Detection Script (Dry Run) ---" -ForegroundColor Yellow
    
    $detectionPath = Join-Path $scriptPath "detection.ps1"
    
    if (-not (Test-Path $detectionPath)) {
        Write-TestResult "Detection Dry Run" "Fail" "Script not found"
        return
    }
    
    try {
        Write-Host "    Running detection script..." -ForegroundColor Gray
        $result = & $detectionPath -ErrorAction Stop
        $exitCode = $LASTEXITCODE
        
        if ($null -eq $exitCode) {
            Write-TestResult "Detection Execution" "Warning" "No exit code returned"
        } elseif ($exitCode -eq 0) {
            Write-TestResult "Detection Execution" "Pass" "Exit code 0 (No issues detected)"
        } elseif ($exitCode -eq 1) {
            Write-TestResult "Detection Execution" "Pass" "Exit code 1 (Issues detected - remediation triggered)"
        } else {
            Write-TestResult "Detection Execution" "Warning" "Exit code $exitCode (unexpected)"
        }
        
        # Check if log was created
        $logPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_detection.log"
        if (Test-Path $logPath) {
            $logSize = (Get-Item $logPath).Length
            Write-TestResult "Detection Log Created" "Pass" "Log size: $logSize bytes"
        } else {
            Write-TestResult "Detection Log Created" "Fail" "Log not found at $logPath"
        }
    }
    catch {
        Write-TestResult "Detection Execution" "Fail" "Error: $($_.Exception.Message)"
    }
}

# Test 7: Check remediation script configuration
function Test-RemediationConfiguration {
    Write-Host "`n--- Testing Remediation Configuration ---" -ForegroundColor Yellow
    
    $remediationPath = Join-Path $scriptPath "remediation.ps1"
    
    if (-not (Test-Path $remediationPath)) {
        Write-TestResult "Remediation Configuration" "Fail" "Script not found"
        return
    }
    
    $content = Get-Content $remediationPath -Raw
    
    # Check parameter support
    if ($content -match 'param\s*\(') {
        Write-TestResult "Parameter Support" "Pass" "Parameters are defined"
    } else {
        Write-TestResult "Parameter Support" "Warning" "No parameters found"
    }
    
    # Check configuration flags
    $configFlags = @('fullRepair', 'resetWUComponents', 'cleanupRegistry', 'reregisterDLLs', 
                     'restartIntune', 'checkAutopatch', 'clearRebootFlags', 'verifyCriticalServices')
    
    $flagsFound = 0
    foreach ($flag in $configFlags) {
        if ($content -match "\`$$flag\s*=\s*[01]") {
            $flagsFound++
        }
    }
    
    if ($flagsFound -eq $configFlags.Count) {
        Write-TestResult "Configuration Flags" "Pass" "All $flagsFound flags defined"
    } else {
        Write-TestResult "Configuration Flags" "Warning" "Only $flagsFound of $($configFlags.Count) flags found"
    }
}

# Main Test Execution
Write-Host "Starting validation tests..." -ForegroundColor Cyan
Write-Host "Script Path: $scriptPath" -ForegroundColor Gray
Write-Host ""

# Run tests based on parameters
if (-not $TestRemediationOnly) {
    Test-ScriptExistence
    Test-ScriptSyntax
    Test-RequiredFunctions
    Test-ConfigurationVariables
    Test-SystemPrerequisites
}

if (-not $TestRemediationOnly) {
    Test-DetectionDryRun
}

if (-not $TestDetectionOnly) {
    Test-RemediationConfiguration
}

# Summary
Write-Host "`n======================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($script:TestResults.Tests.Count)" -ForegroundColor White
Write-Host "Passed:      $($script:TestResults.Passed)" -ForegroundColor Green
Write-Host "Failed:      $($script:TestResults.Failed)" -ForegroundColor Red
Write-Host "Warnings:    $($script:TestResults.Warnings)" -ForegroundColor Yellow
Write-Host ""

if ($script:TestResults.Failed -gt 0) {
    Write-Host "Status: FAILED - Review failed tests above" -ForegroundColor Red
    exit 1
} elseif ($script:TestResults.Warnings -gt 0) {
    Write-Host "Status: PASSED WITH WARNINGS - Review warnings above" -ForegroundColor Yellow
    exit 0
} else {
    Write-Host "Status: ALL TESTS PASSED" -ForegroundColor Green
    exit 0
}
