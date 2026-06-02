#region PowerShell Help
<#
.SYNOPSIS
    Intelligent remediation script for Windows Update issues with configurable repair steps.
    Only executes repairs when problems are detected, minimizing unnecessary system changes.
    Features robust validation, race condition prevention, and comprehensive operation verification.

    GitHub Repository: https://github.com/roalhelm/WindowsAutopatchFix

.DESCRIPTION
    This script remediates common Windows Update failures on Intune-managed devices with intelligent
    detection and configurable repair steps. Each repair action is only executed when necessary:
    
    Configurable Repair Steps:
    - Windows Update component reset (SoftwareDistribution, catroot2)
    - Service verification and restart (BITS, wuauserv, CryptSvc, AppReadiness)
    - DISM and SFC system repair (optional, resource-intensive)
    - Intune Management Extension restart
    - Windows Autopatch configuration check and repair
    - Registry policy cleanup (WSUS, GPO conflicts)
    - DLL re-registration (Windows Update DLLs)
    - Pending reboot flags cleanup
    - Critical services verification
    - Disk cleanup (when < 20 GB free space)
    - Windows Update policy blocks removal
    - Windows Update Agent reset
    - Primary Refresh Token refresh (for Intune-only devices)
    - Windows Update policy refresh
    
    Addresses errors including: 0x80070002, 0x8007000E, 0x80240034, 0x8024402F, 0x80070643,
    0x800F0922, 0xC1900200, 0x80070490, 0x800F0831, and many others.

.NOTES
    File Name     : remediation.ps1
    Author        : Ronny Alhelm
    Version       : 3.3
    Creation Date : 2024-09-19
    Last Updated  : 2026-06-02

.CHANGES
    3.3 - Enhanced reliability: Service start with retry logic (3 attempts, exponential backoff)
          Extended validation: DLL version checks after registration, enhanced reboot flag cleanup
          Better configuration: All repair flags as parameters, configurable thresholds
          Improved logging: Log rotation (10 MB limit), detailed validation results
          Extended cleanup: Additional reboot flag locations (PackagesPending, RebootRequired)
    3.2 - Enhanced reliability and validation: Fixed race conditions in service restarts with proper timing
          Added comprehensive validation for all critical operations (DLL registration, service states)
          Improved operation verification with detailed status logging and error detection
    3.1 - Optimized for Intune-only devices: Replaced gpupdate with dsregcmd /refreshprt for PRT refresh
          Updated registry cleanup to focus on WSUS/GPO conflicts, improved Intune-only client support
    3.0 - Added intelligent detection (repairs only when needed) and configurable repair steps
    2.0 - Expanded to fix all common Windows Update errors, added comprehensive repair actions
    1.0 - Initial version (focused on 0Xc1900200)

.VERSION
    3.3

.PARAMETER fullRepair
    Set to 1 to enable DISM + SFC system repair (resource intensive). Default: 0

.PARAMETER resetWUComponents
    Set to 1 to enable Windows Update component reset. Default: 1

.PARAMETER cleanupRegistry
    Set to 1 to enable registry cleanup. Default: 1

.PARAMETER reregisterDLLs
    Set to 1 to enable DLL re-registration. Default: 1

.PARAMETER restartIntune
    Set to 1 to enable Intune Management Extension restart. Default: 1

.PARAMETER checkAutopatch
    Set to 1 to enable Windows Autopatch configuration check. Default: 1

.PARAMETER clearRebootFlags
    Set to 1 to enable pending reboot flags cleanup. Default: 1

.PARAMETER verifyCriticalServices
    Set to 1 to enable critical services verification. Default: 1

.PARAMETER configureAppReadiness
    Set to 1 to enable App Readiness Service configuration. Default: 1

.PARAMETER runDiskCleanup
    Set to 1 to enable disk cleanup (only runs if < 20 GB free). Default: 1

.PARAMETER removePolicyBlocks
    Set to 1 to enable Windows Update policy blocks removal. Default: 1

.PARAMETER resetWUAgent
    Set to 1 to enable Windows Update Agent reset. Default: 1

.PARAMETER refreshPRT
    Set to 1 to enable Primary Refresh Token refresh (for Intune-only devices). Default: 1

.PARAMETER refreshWUPolicies
    Set to 1 to enable Windows Update policy refresh. Default: 1

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1
    # Runs with default configuration (all steps enabled except fullRepair)

.EXAMPLE
    # Edit the script to set $fullRepair = 1 for deep system repair
    powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1

.EXAMPLE
    # Edit the script to disable specific steps (e.g., set $checkAutopatch = 0)
    powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1
#>
#endregion

# PowerShell Remediation Script for All Windows Update Issues

#region Parameters
param (
    [string]$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_remediation.log",
    [int]$fullRepair = 0,
    [int]$resetWUComponents = 1,
    [int]$cleanupRegistry = 1,
    [int]$reregisterDLLs = 1,
    [int]$restartIntune = 1,
    [int]$checkAutopatch = 1,
    [int]$clearRebootFlags = 1,
    [int]$verifyCriticalServices = 1,
    [int]$configureAppReadiness = 1,
    [int]$runDiskCleanup = 0,
    [int]$removePolicyBlocks = 1,
    [int]$resetWUAgent = 1,
    [int]$refreshPRT = 1,
    [int]$refreshWUPolicies = 1,
    [switch]$Verbose
)
#endregion

#region Configuration - Enable/Disable Repair Steps & Thresholds
# Configuration can be set via parameters or by editing values below

# Repair Step Flags (if not provided via parameters)
if (-not $PSBoundParameters.ContainsKey('fullRepair')) { $fullRepair = 0 }
if (-not $PSBoundParameters.ContainsKey('resetWUComponents')) { $resetWUComponents = 1 }
if (-not $PSBoundParameters.ContainsKey('cleanupRegistry')) { $cleanupRegistry = 1 }
if (-not $PSBoundParameters.ContainsKey('reregisterDLLs')) { $reregisterDLLs = 1 }
if (-not $PSBoundParameters.ContainsKey('restartIntune')) { $restartIntune = 1 }
if (-not $PSBoundParameters.ContainsKey('checkAutopatch')) { $checkAutopatch = 1 }
if (-not $PSBoundParameters.ContainsKey('clearRebootFlags')) { $clearRebootFlags = 1 }
if (-not $PSBoundParameters.ContainsKey('verifyCriticalServices')) { $verifyCriticalServices = 1 }
if (-not $PSBoundParameters.ContainsKey('configureAppReadiness')) { $configureAppReadiness = 1 }
if (-not $PSBoundParameters.ContainsKey('runDiskCleanup')) { $runDiskCleanup = 0 }
if (-not $PSBoundParameters.ContainsKey('removePolicyBlocks')) { $removePolicyBlocks = 1 }
if (-not $PSBoundParameters.ContainsKey('resetWUAgent')) { $resetWUAgent = 1 }
if (-not $PSBoundParameters.ContainsKey('refreshPRT')) { $refreshPRT = 1 }
if (-not $PSBoundParameters.ContainsKey('refreshWUPolicies')) { $refreshWUPolicies = 1 }

# Thresholds and Limits
$maxSoftwareDistFiles = 75      # Max files in SoftwareDistribution/Download for reset
$minDiskSpaceGB = 20            # Minimum free disk space for cleanup trigger
$serviceRetryCount = 3          # Number of retry attempts for service starts
$serviceRetryDelayMs = 500      # Base delay for retry (exponential backoff)
$logRotationSizeMB = 10         # Log rotation size threshold
$maxLogFiles = 5                # Number of log files to keep
$dllMinYear = 2020              # Minimum year for DLL versions

#endregion

# Function to log output to file and console
$global:LogPath = $LogPath
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$timestamp - $message"
    Write-Output $logLine
    Add-Content -Path $global:LogPath -Value $logLine
}

# Function to rotate log files
function Invoke-LogRotation {
    try {
        if (Test-Path $global:LogPath) {
            $logSize = (Get-Item $global:LogPath).Length / 1MB
            if ($logSize -gt $logRotationSizeMB) {
                Write-Output "Log rotation: Current log size $([math]::Round($logSize, 2)) MB exceeds limit"
                
                # Delete oldest log if max count reached
                $oldestLog = "$global:LogPath.$maxLogFiles"
                if (Test-Path $oldestLog) {
                    Remove-Item $oldestLog -Force -ErrorAction SilentlyContinue
                }
                
                # Rotate existing logs
                for ($i = $maxLogFiles - 1; $i -ge 1; $i--) {
                    $currentLog = "$global:LogPath.$i"
                    $nextLog = "$global:LogPath.$($i + 1)"
                    if (Test-Path $currentLog) {
                        Move-Item $currentLog $nextLog -Force -ErrorAction SilentlyContinue
                    }
                }
                
                # Rotate current log to .1
                Move-Item $global:LogPath "$global:LogPath.1" -Force -ErrorAction SilentlyContinue
                Write-Output "Log rotation completed successfully"
            }
        }
        
        # Clean up old logs (older than 30 days)
        $logDir = Split-Path $global:LogPath -Parent
        if (Test-Path $logDir) {
            Get-ChildItem -Path $logDir -Filter "WindowsUpdateFix_*.log*" -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-30) } | 
                Remove-Item -Force -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Output "Log rotation warning: $($_.Exception.Message)"
    }
}

# Function to start service with retry logic
function Start-ServiceWithRetry {
    param (
        [string]$ServiceName,
        [string]$DisplayName,
        [int]$MaxRetries = $serviceRetryCount,
        [int]$BaseDelayMs = $serviceRetryDelayMs
    )
    
    $attempt = 0
    $success = $false
    
    while ($attempt -lt $MaxRetries -and -not $success) {
        $attempt++
        try {
            Start-Service -Name $ServiceName -ErrorAction Stop
            
            # Wait with exponential backoff
            $delay = $BaseDelayMs * [Math]::Pow(2, $attempt - 1)
            Start-Sleep -Milliseconds $delay
            
            # Verify service is running
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq 'Running') {
                Write-Log "Successfully started $DisplayName on attempt $attempt (Status: Running)"
                $success = $true
                return $true
            }
            else {
                Write-Log "Attempt $attempt failed: $DisplayName status is $($service.Status)"
            }
        }
        catch {
            Write-Log "Attempt $attempt failed to start ${DisplayName}: $($_.Exception.Message)"
            if ($attempt -lt $MaxRetries) {
                $delay = $BaseDelayMs * [Math]::Pow(2, $attempt - 1)
                Start-Sleep -Milliseconds $delay
            }
        }
    }
    
    if (-not $success) {
        Write-Log "ERROR: Failed to start $DisplayName after $MaxRetries attempts"
        return $false
    }
}

# Perform log rotation
Invoke-LogRotation

Write-Log "Starting comprehensive Windows Update remediation for all common issues (v3.3)"

# Check for TPM
$tpmStatus = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
if ($tpmStatus -and $tpmStatus.IsActivated_InitialValue -eq $true) {
    Write-Log "TPM is activated"
} else {
    Write-Log "TPM is not activated or not present"
}

# Check Secure Boot status
$secureBoot = Confirm-SecureBootUEFI
if ($secureBoot) {
    Write-Log "Secure Boot is enabled"
} else {
    Write-Log "Secure Boot is not enabled"
}

# Check free disk space on system drive
$sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
$freeSpaceGB = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
Write-Log "Free disk space on C: drive: $freeSpaceGB GB"
if ($freeSpaceGB -lt 20) {
    Write-Log "Warning: Low disk space. Minimum 20 GB recommended for upgrade."
}

# Function to check if Windows Update components need reset
function Test-WUComponentsNeedReset {
    $needsReset = $false
    
    # Check if SoftwareDistribution has too many stuck files
    $downloadFolder = "C:\Windows\SoftwareDistribution\Download"
    if (Test-Path $downloadFolder) {
        $downloadFiles = Get-ChildItem $downloadFolder -ErrorAction SilentlyContinue
        if ($downloadFiles.Count -gt $maxSoftwareDistFiles) {
            Write-Log "SoftwareDistribution has $($downloadFiles.Count) files - reset needed (threshold: $maxSoftwareDistFiles)"
            $needsReset = $true
        }
    }
    
    # Check if catroot2 is missing or corrupted
    if (-not (Test-Path "C:\Windows\System32\catroot2")) {
        Write-Log "catroot2 folder is missing - reset needed"
        $needsReset = $true
    }
    
    return $needsReset
}

# Function to check if services are not running
function Test-ServicesNeedRestart {
    $servicesNeedingRestart = @()
    $servicesToCheck = @('BITS', 'wuauserv', 'CryptSvc', 'msiserver')
    
    foreach ($svc in $servicesToCheck) {
        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne "Running") {
            $servicesNeedingRestart += $svc
        }
    }
    
    return $servicesNeedingRestart
}

# Check if services need to be restarted
$servicesNeedingRestart = Test-ServicesNeedRestart
if ($servicesNeedingRestart.Count -gt 0) {
    Write-Log "Services not running: $($servicesNeedingRestart -join ', ') - Stopping and restarting..."
    $servicesToStop = @('BITS', 'wuauserv', 'CryptSvc', 'msiserver')
    foreach ($svc in $servicesToStop) {
        try {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
            Write-Log "Stopped service: $svc"
        } catch {
            Write-Log "Could not stop service $svc`: $($_.Exception.Message)"
        }
    }
} else {
    Write-Log "All Windows Update services are running - skipping service restart"
}

# Optional: Run DISM health scan and repair (only if $fullRepair = 1)
if ($fullRepair -eq 1) {
    Write-Log "Full repair mode enabled - Running DISM health scan and repair (this may take several minutes)..."
    try {
        $dismScan = & DISM.exe /Online /Cleanup-Image /ScanHealth 2>&1
        Write-Log "DISM ScanHealth completed"
        
        $dismRestore = & DISM.exe /Online /Cleanup-Image /RestoreHealth 2>&1
        Write-Log "DISM RestoreHealth completed"
        
        # Additional DISM cleanup
        $dismCleanup = & DISM.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase 2>&1
        Write-Log "DISM Component Cleanup completed"
    } catch {
        Write-Log "Error running DISM: $($_.Exception.Message)"
    }

    # Run System File Checker
    Write-Log "Running System File Checker (SFC)..."
    try {
        $sfcResult = & sfc.exe /scannow 2>&1
        Write-Log "SFC scan completed"
    } catch {
        Write-Log "Error running SFC: $($_.Exception.Message)"
    }
} else {
    Write-Log "Full repair mode disabled (set `$fullRepair = 1 to enable DISM and SFC scans)"
}

# Reset Windows Update components only if needed
if ($resetWUComponents -eq 1) {
    if (Test-WUComponentsNeedReset) {
        Write-Log "Resetting Windows Update components..."
        Stop-Service -Name BITS -Force -Verbose -ErrorAction SilentlyContinue
        Stop-Service -Name wuauserv -Force -Verbose -ErrorAction SilentlyContinue
        
        Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "C:\Windows\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Windows Update components reset completed"
    } else {
        Write-Log "Windows Update components are healthy - skipping reset"
    }
} else {
    Write-Log "Windows Update component reset disabled in configuration - skipping"
}

# Check if registry keys exist before attempting deletion (removes WSUS/GPO conflicts)
if ($cleanupRegistry -eq 1) {
    $registryKeysDeleted = 0
    # These keys are typically set by WSUS/GPO and can conflict with Intune-managed updates
    $registryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX"
    )

    foreach ($key in $registryKeys) {
        if (Test-Path $key) {
            try {
                Remove-Item -Path $key -Recurse -Force -ErrorAction Stop
                Write-Log "Successfully deleted: $key"
                $registryKeysDeleted++
            } catch {
                Write-Log "Error deleting $key`: $($_.Exception.Message)"
            }
        }
    }

    if ($registryKeysDeleted -eq 0) {
        Write-Log "No problematic registry keys found - skipping registry cleanup"
    } else {
        Write-Log "Deleted $registryKeysDeleted problematic registry keys"
    }
} else {
    Write-Log "Registry cleanup disabled in configuration - skipping"
}

# Restart services only if they were stopped
if ($servicesNeedingRestart.Count -gt 0) {
    $servicesToRestart = @(
        @{Name = 'BITS'; Display = 'Background Intelligent Transfer Service'},
        @{Name = 'wuauserv'; Display = 'Windows Update'},
        @{Name = 'CryptSvc'; Display = 'Cryptographic Services'},
        @{Name = 'msiserver'; Display = 'Windows Installer'}
    )
    
    foreach ($svc in $servicesToRestart) {
        $result = Start-ServiceWithRetry -ServiceName $svc.Name -DisplayName $svc.Display
        if (-not $result) {
            Write-Log "WARNING: Service $($svc.Display) may require manual intervention"
        }
    }
    Write-Log "Windows Update services restart sequence completed"
}

# Re-register Windows Update DLLs only if Windows Update COM interface is not accessible
if ($reregisterDLLs -eq 1) {
    $needDllReregistration = $false
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
        if (-not $updateSession) {
            $needDllReregistration = $true
            Write-Log "Windows Update COM interface not accessible - DLL re-registration needed"
        } else {
            Write-Log "Windows Update COM interface is accessible - skipping DLL re-registration"
        }
    } catch {
        $needDllReregistration = $true
        Write-Log "Windows Update COM test failed - DLL re-registration needed"
    }

    if ($needDllReregistration) {
        Write-Log "Re-registering Windows Update DLLs..."
$dlls = @(
    "atl.dll", "urlmon.dll", "mshtml.dll", "shdocvw.dll", "browseui.dll",
    "jscript.dll", "vbscript.dll", "scrrun.dll", "msxml.dll", "msxml3.dll",
    "msxml6.dll", "actxprxy.dll", "softpub.dll", "wintrust.dll", "dssenh.dll",
    "rsaenh.dll", "gpkcsp.dll", "sccbase.dll", "slbcsp.dll", "cryptdlg.dll",
    "oleaut32.dll", "ole32.dll", "shell32.dll", "initpki.dll", "wuapi.dll",
    "wuaueng.dll", "wuaueng1.dll", "wucltui.dll", "wups.dll", "wups2.dll",
    "wuweb.dll", "qmgr.dll", "qmgrprxy.dll", "wucltux.dll", "muweb.dll", "wuwebv.dll"
)

    $registeredCount = 0
    $failedCount = 0
    foreach ($dll in $dlls) {
        try {
            $dllPath = "$env:SystemRoot\System32\$dll"
            if (Test-Path $dllPath) {
                $process = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s", $dll -Wait -PassThru -NoNewWindow -ErrorAction Stop
                if ($process.ExitCode -eq 0) {
                    $registeredCount++
                } else {
                    Write-Log "Warning: Failed to register $dll (Exit code: $($process.ExitCode))"
                    $failedCount++
                }
            }
        } catch {
            Write-Log "Error registering ${dll}: $($_.Exception.Message)"
            $failedCount++
        }
    }
    Write-Log "DLL re-registration completed: $registeredCount succeeded, $failedCount failed/skipped"
        
        # Validate DLL registration by checking versions and COM interface
        Write-Log "Validating DLL registration..."
        $validationPassed = $true
        
        # Check critical Windows Update DLL versions
        $criticalDLLs = @("wuapi.dll", "wuaueng.dll", "wups2.dll")
        foreach ($dllName in $criticalDLLs) {
            $dllPath = "$env:SystemRoot\System32\$dllName"
            if (Test-Path $dllPath) {
                $dllInfo = Get-Item $dllPath -ErrorAction SilentlyContinue
                if ($dllInfo) {
                    $dllDate = $dllInfo.LastWriteTime
                    if ($dllDate.Year -lt $dllMinYear) {
                        Write-Log "WARNING: $dllName is outdated (Date: $($dllDate.ToString('yyyy-MM-dd')))"
                        $validationPassed = $false
                    }
                    else {
                        Write-Log "Validation passed: $dllName (Date: $($dllDate.ToString('yyyy-MM-dd')))"
                    }
                }
            }
        }
        
        # Re-test COM interface after registration
        try {
            $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
            Write-Log "COM interface validation passed: $($searchResult.Updates.Count) updates available"
        }
        catch {
            Write-Log "WARNING: COM interface validation failed: $($_.Exception.Message)"
            $validationPassed = $false
        }
        
        if ($validationPassed) {
            Write-Log "DLL registration validation completed successfully"
        }
        else {
            Write-Log "WARNING: DLL registration validation found issues - manual review may be needed"
        }
    }
} else {
    Write-Log "DLL re-registration disabled in configuration - skipping"
}

# Restart Intune Management Extension service only if not running
if ($restartIntune -eq 1) {
    Write-Log "Checking Intune Management Extension service..."
    try {
        $intuneService = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
        if ($intuneService -and $intuneService.Status -ne "Running") {
            Write-Log "Intune Management Extension service is not running - restarting..."
            Restart-Service -Name IntuneManagementExtension -Force -ErrorAction Stop
            Start-Sleep -Seconds 2
            
            # Verify service is running after restart
            $intuneService = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
            if ($intuneService -and $intuneService.Status -eq "Running") {
                Write-Log "Intune Management Extension service restarted successfully (Status: Running)"
            } else {
                Write-Log "Warning: Intune Management Extension service may not have started correctly (Status: $($intuneService.Status))"
            }
        } else {
            Write-Log "Intune Management Extension service is already running - skipping restart"
        }
    } catch {
        Write-Log "Failed to restart Intune Management Extension: $($_.Exception.Message)"
    }
} else {
    Write-Log "Intune Management Extension restart disabled in configuration - skipping"
}

# Trigger Intune policy sync
Write-Log "Triggering Intune device sync..."
try {
    $omaDMPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts\*"
    $accounts = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts" -ErrorAction SilentlyContinue
    
    foreach ($account in $accounts) {
        # Trigger sync by updating registry
        $sessionIdPath = Join-Path $account.PSPath "Protected\ConnInfo"
        if (Test-Path $sessionIdPath) {
            Write-Log "Found Intune account: $($account.PSChildName)"
        }
    }
    
    # Alternative method: Use deviceenroller.exe to trigger sync
    if (Test-Path "$env:windir\System32\deviceenroller.exe") {
        Start-Process -FilePath "$env:windir\System32\deviceenroller.exe" -ArgumentList "/c /AutoEnrollMDM" -Wait -NoNewWindow -ErrorAction SilentlyContinue
        Write-Log "Device enrollment sync triggered"
    }
    
    # Use IME sync method
    $IMEExe = "$env:ProgramFiles\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"
    if (Test-Path $IMEExe) {
        Write-Log "Triggering Intune Management Extension sync"
        # IME will sync automatically after service restart
    }
    
} catch {
    Write-Log "Error triggering Intune sync: $($_.Exception.Message)"
}

# Check and refresh Windows Autopatch configuration
if ($checkAutopatch -eq 1) {
    Write-Log "Checking Windows Autopatch configuration..."
    try {
    $autopatchRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Autopatch"
    
    if (Test-Path $autopatchRegPath) {
        $autopatchEnabled = (Get-ItemProperty -Path $autopatchRegPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
        
        if ($autopatchEnabled -eq 1) {
            Write-Log "Windows Autopatch is enabled - Checking Client Broker..."
            
            # Check if Windows Autopatch Client Broker is installed
            $autopatchBrokerInstalled = $false
            $autopatchBrokerPath = $null
            $autopatchBrokerPaths = @(
                "C:\Program Files\Microsoft Windows Autopatch\WindowsAutopatchClientBroker.exe",
                "C:\Program Files (x86)\Microsoft Windows Autopatch\WindowsAutopatchClientBroker.exe"
            )
            
            foreach ($path in $autopatchBrokerPaths) {
                if (Test-Path $path) {
                    $autopatchBrokerInstalled = $true
                    $autopatchBrokerPath = $path
                    Write-Log "Windows Autopatch Client Broker found at: $path"
                    break
                }
            }
            
            # Check via registry if not found by path
            if (-not $autopatchBrokerInstalled) {
                $autopatchApp = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                    Where-Object { $_.DisplayName -like "*Windows Autopatch*" -or $_.DisplayName -like "*Autopatch Client Broker*" }
                
                if (-not $autopatchApp) {
                    $autopatchApp = Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                        Where-Object { $_.DisplayName -like "*Windows Autopatch*" -or $_.DisplayName -like "*Autopatch Client Broker*" }
                }
                
                if ($autopatchApp) {
                    $autopatchBrokerInstalled = $true
                    Write-Log "Windows Autopatch Client Broker is installed (Version: $($autopatchApp.DisplayVersion))"
                }
            }
            
            # If Client Broker is not installed, trigger installation via Intune sync
            if (-not $autopatchBrokerInstalled) {
                Write-Log "Windows Autopatch Client Broker NOT found - Triggering installation..."
                
                # The Client Broker is deployed via Intune when device is enrolled in Autopatch
                # Trigger Intune sync to install it
                try {
                    # Restart Intune Management Extension to trigger app sync
                    Write-Log "Restarting Intune Management Extension to trigger app deployment..."
                    Restart-Service -Name IntuneManagementExtension -Force -ErrorAction Stop
                    Start-Sleep -Seconds 3
                    
                    # Trigger device sync via deviceenroller
                    if (Test-Path "$env:windir\System32\deviceenroller.exe") {
                        Start-Process -FilePath "$env:windir\System32\deviceenroller.exe" -ArgumentList "/c /AutoEnrollMDM" -Wait -NoNewWindow -ErrorAction SilentlyContinue
                        Write-Log "Device enrollment sync triggered for Autopatch Client Broker installation"
                    }
                    
                    # Trigger Company Portal sync (alternative method)
                    $IMEExe = "$env:ProgramFiles\Microsoft Intune Management Extension\Microsoft.Management.Services.IntuneWindowsAgent.exe"
                    if (Test-Path $IMEExe) {
                        Write-Log "Intune Management Extension will check for required apps on next sync cycle"
                    }
                    
                    Write-Log "Installation trigger completed. Client Broker should install within 30-60 minutes"
                    Write-Log "Manual verification recommended: Check Intune > Devices > Apps to confirm deployment"
                } catch {
                    Write-Log "Error triggering Client Broker installation: $($_.Exception.Message)"
                }
            } else {
                # Client Broker is installed - verify it's functioning
                Write-Log "Verifying Windows Autopatch Client Broker functionality..."
                
                try {
                    # Check if broker process is running
                    $brokerProcess = Get-Process -Name "WindowsAutopatchClientBroker" -ErrorAction SilentlyContinue
                    if ($brokerProcess) {
                        Write-Log "Windows Autopatch Client Broker process is running (PID: $($brokerProcess.Id))"
                    } else {
                        Write-Log "Windows Autopatch Client Broker process is not running - Attempting to start..."
                        
                        if ($autopatchBrokerPath) {
                            Start-Process -FilePath $autopatchBrokerPath -ErrorAction Stop
                            Start-Sleep -Seconds 2
                            
                            $brokerProcess = Get-Process -Name "WindowsAutopatchClientBroker" -ErrorAction SilentlyContinue
                            if ($brokerProcess) {
                                Write-Log "Windows Autopatch Client Broker started successfully"
                            } else {
                                Write-Log "Failed to start Windows Autopatch Client Broker - May require manual intervention"
                            }
                        }
                    }
                    
                    # Check broker service (if it has one)
                    $brokerService = Get-Service -Name "WindowsAutopatch*" -ErrorAction SilentlyContinue
                    if ($brokerService) {
                        foreach ($svc in $brokerService) {
                            Write-Log "Autopatch Service: $($svc.Name) - Status: $($svc.Status)"
                            if ($svc.Status -ne "Running" -and $svc.StartType -ne "Disabled") {
                                try {
                                    Start-Service -Name $svc.Name -ErrorAction Stop
                                    Write-Log "Started Autopatch service: $($svc.Name)"
                                } catch {
                                    Write-Log "Could not start $($svc.Name): $($_.Exception.Message)"
                                }
                            }
                        }
                    }
                } catch {
                    Write-Log "Error verifying Client Broker functionality: $($_.Exception.Message)"
                }
            }
            
            # Trigger Autopatch policy refresh by restarting related services
            Write-Log "Refreshing Autopatch update services..."
            $autopatchServices = @('wuauserv', 'UsoSvc')
            foreach ($svc in $autopatchServices) {
                try {
                    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq "Running") {
                        Restart-Service -Name $svc -Force -ErrorAction Stop
                        Start-Sleep -Seconds 1
                        
                        # Verify service restarted successfully
                        $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
                        if ($service -and $service.Status -eq "Running") {
                            Write-Log "Successfully restarted $svc for Autopatch refresh (Status: Running)"
                        } else {
                            Write-Log "Warning: $svc may not have restarted correctly (Status: $($service.Status))"
                        }
                    }
                } catch {
                    Write-Log "Could not restart $svc`: $($_.Exception.Message)"
                }
            }
            
            Write-Log "Autopatch configuration refresh completed"
        } elseif ($autopatchEnabled -eq 0) {
            Write-Log "Windows Autopatch is configured but disabled (Enabled = 0)"
        } else {
            Write-Log "Windows Autopatch Enabled value not set - Attempting to enable..."
            Set-ItemProperty -Path $autopatchRegPath -Name Enabled -Value 1 -Type DWord -ErrorAction Stop
            Write-Log "Set Autopatch Enabled registry value to 1"
        }
    } else {
        Write-Log "Windows Autopatch registry not found (device may not be enrolled in Autopatch)"
    }
    } catch {
        Write-Log "Error checking/refreshing Autopatch configuration: $($_.Exception.Message)"
    }
} else {
    Write-Log "Windows Autopatch check disabled in configuration - skipping"
}

# Refresh Primary Refresh Token for Intune-only devices (replaces gpupdate for cloud-only devices)
if ($refreshPRT -eq 1) {
    Write-Log "Refreshing Primary Refresh Token for Intune policy sync..."
    try {
        $dsregOutput = & dsregcmd /refreshprt 2>&1
        Write-Log "Primary Refresh Token refreshed: $dsregOutput"
    } catch {
        Write-Log "Error running dsregcmd: $($_.Exception.Message)"
    }
} else {
    Write-Log "Primary Refresh Token refresh disabled in configuration - skipping"
}

# Trigger Windows Update policy refresh
if ($refreshWUPolicies -eq 1) {
    Write-Log "Refreshing Windows Update policies..."
    try {
        # Reset Windows Update policy cache
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results" -Recurse -Force -ErrorAction SilentlyContinue
        
        # Use USOClient to check for updates and refresh policies
        if (Test-Path "$env:windir\System32\UsoClient.exe") {
            Start-Process -FilePath "$env:windir\System32\UsoClient.exe" -ArgumentList "ScanInstallWait" -NoNewWindow -ErrorAction SilentlyContinue
            Write-Log "Windows Update scan triggered via UsoClient"
        }
        
        # Alternative: Use wuauclt if available (legacy)
        Start-Process -FilePath "wuauclt.exe" -ArgumentList "/detectnow", "/updatenow" -NoNewWindow -ErrorAction SilentlyContinue
        Write-Log "Windows Update detection triggered"
        
    } catch {
        Write-Log "Error refreshing Windows Update policies: $($_.Exception.Message)"
    }

    # Clear Windows Update cache to force re-evaluation
    Write-Log "Clearing Windows Update cache..."
    try {
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\DataStore\DataStore.edb" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\SoftwareDistribution\DataStore\Logs\*.log" -Force -ErrorAction SilentlyContinue
        Write-Log "Windows Update cache cleared"
    } catch {
        Write-Log "Error clearing Windows Update cache: $($_.Exception.Message)"
    }
} else {
    Write-Log "Windows Update policy refresh disabled in configuration - skipping"
}

# Clear pending reboot flags only if they exist (safe flags only, not Setup-related)
if ($clearRebootFlags -eq 1) {
    Write-Log "Checking for pending reboot flags..."
    $rebootFlagsCleared = 0
    
    try {
        # Safe reboot flags that can be cleared
        $safeRebootFlags = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        
        foreach ($flagPath in $safeRebootFlags) {
            if (Test-Path $flagPath) {
                try {
                    Remove-Item -Path $flagPath -Recurse -Force -ErrorAction Stop
                    Write-Log "Cleared reboot flag: $flagPath"
                    $rebootFlagsCleared++
                }
                catch {
                    Write-Log "Could not clear $flagPath`: $($_.Exception.Message)"
                }
            }
        }
        
        # Check PendingFileRenameOperations (only log, don't clear - may be critical)
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            Write-Log "INFO: PendingFileRenameOperations detected - Not clearing (may be critical system files)"
        }
        
        # Check PendingFileRenameOperations2 (rarely used, but check for completeness)
        $pendingFileRename2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations2 -ErrorAction SilentlyContinue
        if ($pendingFileRename2) {
            Write-Log "INFO: PendingFileRenameOperations2 detected - Not clearing (may be critical system files)"
        }
        
        if ($rebootFlagsCleared -eq 0) {
            Write-Log "No safe reboot flags found to clear"
        }
        else {
            Write-Log "Cleared $rebootFlagsCleared reboot flag(s)"
        }
    } catch {
        Write-Log "Error checking reboot flags: $($_.Exception.Message)"
    }
} else {
    Write-Log "Pending reboot flags cleanup disabled in configuration - skipping"
}

# Verify and start critical services only if they are not running
if ($verifyCriticalServices -eq 1) {
    Write-Log "Verifying critical services..."
    $servicesFixed = 0
    $criticalServices = @{
    'wuauserv' = 'Windows Update'
    'BITS' = 'Background Intelligent Transfer Service'
    'CryptSvc' = 'Cryptographic Services'
    'TrustedInstaller' = 'Windows Modules Installer'
    'IntuneManagementExtension' = 'Intune Management Extension'
}

foreach ($svcName in $criticalServices.Keys) {
    try {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service) {
            if ($service.Status -ne "Running") {
                Write-Log "Service $($criticalServices[$svcName]) is not running - Starting with retry logic..."
                $result = Start-ServiceWithRetry -ServiceName $svcName -DisplayName $criticalServices[$svcName]
                if ($result) {
                    $servicesFixed++
                }
                else {
                    Write-Log "WARNING: Failed to start $($criticalServices[$svcName]) after retries"
                }
            }
            
            # Ensure service is set to automatic start (except TrustedInstaller which is Manual)
            if ($svcName -ne 'TrustedInstaller') {
                $startupType = (Get-Service -Name $svcName).StartType
                if ($startupType -ne 'Automatic') {
                    Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
                    
                    # Verify startup type was changed
                    $verifyStartupType = (Get-Service -Name $svcName -ErrorAction SilentlyContinue).StartType
                    if ($verifyStartupType -eq 'Automatic') {
                        Write-Log "Set $($criticalServices[$svcName]) to Automatic startup - Verified"
                        $servicesFixed++
                    } else {
                        Write-Log "Warning: Could not verify startup type for $($criticalServices[$svcName])"
                    }
                }
            }
        } else {
            Write-Log "Warning: Service $svcName not found on this system"
        }
    } catch {
        Write-Log "Error managing service $($criticalServices[$svcName]): $($_.Exception.Message)"
    }
}

    if ($servicesFixed -eq 0) {
        Write-Log "All critical services are running and properly configured - skipping"
    }
} else {
    Write-Log "Critical services verification disabled in configuration - skipping"
}

# Enable App Readiness Service only if it's disabled
if ($configureAppReadiness -eq 1) {
    Write-Log "Checking App Readiness Service..."
    try {
        $appReadiness = Get-Service -Name AppReadiness -ErrorAction SilentlyContinue
        if ($appReadiness) {
            if ($appReadiness.StartType -eq "Disabled") {
                Write-Log "App Readiness Service is disabled - Enabling..."
                Set-Service -Name AppReadiness -StartupType Manual -ErrorAction Stop
                
                # Verify the startup type was changed
                $appReadiness = Get-Service -Name AppReadiness -ErrorAction SilentlyContinue
                if ($appReadiness -and $appReadiness.StartType -eq "Manual") {
                    Write-Log "App Readiness Service enabled (set to Manual) - Verified"
                } else {
                    Write-Log "Warning: App Readiness Service startup type may not have been changed correctly"
                }
            } else {
                Write-Log "App Readiness Service is properly configured ($($appReadiness.StartType)) - skipping"
            }
        }
    } catch {
        Write-Log "Error configuring App Readiness Service: $($_.Exception.Message)"
    }
} else {
    Write-Log "App Readiness Service configuration disabled in configuration - skipping"
}

# Cleanup disk space only if free space is low (< 20 GB)
if ($runDiskCleanup -eq 1) {
    Write-Log "Checking disk space..."
    try {
    $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGBBefore = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
    Write-Log "Free disk space: $freeSpaceGBBefore GB"
    
    if ($freeSpaceGBBefore -lt 20) {
        Write-Log "Low disk space detected - Running cleanup..."
        
        # Run Disk Cleanup to remove old Windows Update files
        if (Test-Path "$env:SystemRoot\System32\cleanmgr.exe") {
            Write-Log "Running Disk Cleanup for Windows Update files..."
            
            # Set registry keys for automated cleanup
            $volumeCaches = @(
                "Update Cleanup",
                "Windows Update Cleanup",
                "Temporary Setup Files"
            )
            
            foreach ($cache in $volumeCaches) {
                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$cache"
                if (Test-Path $regPath) {
                    Set-ItemProperty -Path $regPath -Name StateFlags0100 -Value 2 -Type DWord -ErrorAction SilentlyContinue
                }
            }
            
            # Run cleanmgr with automated settings in hidden mode
            Start-Process -FilePath "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList "/sagerun:100" -Wait -NoNewWindow -WindowStyle Hidden -ErrorAction SilentlyContinue
            Write-Log "Disk Cleanup completed"
            
            # Check free space after cleanup
            $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
            $freeSpaceGBAfter = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
            $freedSpace = $freeSpaceGBAfter - $freeSpaceGBBefore
            Write-Log "Free disk space after cleanup: $freeSpaceGBAfter GB (freed: $([math]::Round($freedSpace, 2)) GB)"
        }
    } else {
        Write-Log "Sufficient disk space available - skipping cleanup"
    }
    } catch {
        Write-Log "Error during disk space check/cleanup: $($_.Exception.Message)"
    }
} else {
    Write-Log "Disk cleanup disabled in configuration - skipping"
}

# Remove WSUS policy blocks that prevent Intune-managed updates
if ($removePolicyBlocks -eq 1) {
    Write-Log "Checking for WSUS policy blocks (conflicts with Intune)..."
    try {
    # These policies force the device to use WSUS instead of Windows Update/Intune
    $policyBlocks = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DoNotConnectToWindowsUpdateInternetLocations"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "WUServer"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "UseWUServer"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"}
    )
    
    $blocksRemoved = 0
    foreach ($block in $policyBlocks) {
        if (Test-Path $block.Path) {
            $value = Get-ItemProperty -Path $block.Path -Name $block.Name -ErrorAction SilentlyContinue
            if ($value) {
                Remove-ItemProperty -Path $block.Path -Name $block.Name -Force -ErrorAction SilentlyContinue
                Write-Log "Removed policy block: $($block.Path)\$($block.Name)"
                $blocksRemoved++
            }
        }
    }
    
    if ($blocksRemoved -eq 0) {
        Write-Log "No Windows Update policy blocks found - skipping"
    } else {
        Write-Log "Removed $blocksRemoved policy blocks"
    }
    } catch {
        Write-Log "Error removing policy blocks: $($_.Exception.Message)"
    }
} else {
    Write-Log "Windows Update policy blocks removal disabled in configuration - skipping"
}

# Reset Windows Update Agent only if COM interface is not accessible
if ($resetWUAgent -eq 1) {
    Write-Log "Checking Windows Update Agent health..."
    try {
    $needsReset = $false
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    
    if (-not $updateSession) {
        $needsReset = $true
    } else {
        try {
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            $null = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        } catch {
            $needsReset = $true
        }
    }
    
    if ($needsReset) {
        Write-Log "Windows Update Agent needs reset - resetting..."
        # Stop Windows Update service
        Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        
        # Remove Windows Update registry keys to force re-initialization
        $regRemoved = $false
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate") {
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
            $regRemoved = $true
        }
        
        # Restart Windows Update service (will recreate registry keys)
        Start-Service -Name wuauserv -ErrorAction Stop
        Start-Sleep -Seconds 2
        
        # Verify service is running and registry was recreated
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        $regRecreated = Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate"
        
        if ($wuService -and $wuService.Status -eq "Running" -and $regRecreated) {
            Write-Log "Windows Update Agent reset completed successfully (Service: Running, Registry: Recreated)"
        } elseif ($regRemoved -and -not $regRecreated) {
            Write-Log "Warning: Registry keys were removed but may not have been recreated yet"
        } else {
            Write-Log "Windows Update Agent reset completed with potential issues"
        }
    } else {
        Write-Log "Windows Update Agent is healthy - skipping reset"
    }
    } catch {
        Write-Log "Error checking/resetting Windows Update Agent: $($_.Exception.Message)"
    }
} else {
    Write-Log "Windows Update Agent reset disabled in configuration - skipping"
}

# Verify Windows Update client health
Write-Log "Verifying Windows Update client health..."
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($updateSession) {
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        Write-Log "Windows Update client is functional - $($searchResult.Updates.Count) updates available"
    } else {
        Write-Log "Warning: Windows Update COM interface not accessible after remediation"
    }
} catch {
    Write-Log "Warning: Windows Update client health verification failed: $($_.Exception.Message)"
}

# Final service status report
Write-Log "Final service status check..."
foreach ($svcName in $criticalServices.Keys) {
    try {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service) {
            Write-Log "$($criticalServices[$svcName]): $($service.Status)"
        }
    } catch {
        Write-Log "Could not check $($criticalServices[$svcName])"
    }
}

Write-Log "Remediation script completed successfully"
Write-Log "NOTE: If issues persist, a system reboot may be required"
