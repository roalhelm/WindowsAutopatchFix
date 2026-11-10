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
    - Pending reboot flags report (flags are never cleared)
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
    Version       : 3.5
    Creation Date : 2024-09-19
    Last Updated  : 2026-11-10

.CHANGES
    3.5 - Safety: component reset renames instead of deleting; no service is stopped or forced to Automatic without need;
          WSUS values are kept on co-managed devices; WindowsUpdate registry key and update database are no longer deleted;
          exit code 1 when a step failed
    3.4 - Safety: Intune PolicyManager Update key is no longer deleted; pending reboot flags are reported, never cleared
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
    Set to 1 to report pending reboot flags. Flags are never cleared (since 3.4). Default: 1

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
$global:RemediationErrors = 0
function Write-Log {
    param ([string]$message)
    # Lines that start with "Error", "ERROR:" or "Failed" mark a failed step and decide the exit code.
    if ($message -cmatch '^(ERROR|Error|Failed)\b') { $global:RemediationErrors++ }
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

Write-Log "Starting comprehensive Windows Update remediation for all common issues (v3.5)"

# Check for TPM
$tpmStatus = Get-CimInstance -Namespace "Root\CIMv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction SilentlyContinue
if ($tpmStatus -and $tpmStatus.IsActivated_InitialValue -eq $true) {
    Write-Log "TPM is activated"
} else {
    Write-Log "TPM is not activated or not present"
}

# Check Secure Boot status
# Confirm-SecureBootUEFI throws on legacy BIOS systems and when not elevated
$secureBoot = $false
try { $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop } catch { Write-Log "Secure Boot state could not be read: $($_.Exception.Message)" }
if ($secureBoot) {
    Write-Log "Secure Boot is enabled"
} else {
    Write-Log "Secure Boot is not enabled"
}

# Check free disk space on system drive
$sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
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

# Report the state of the update services. Nothing is stopped here.
# wuauserv, BITS and msiserver are demand-start services: "Stopped" is their normal idle state.
# Stopping msiserver could abort a running installation, so this script never touches it.
$componentsReset = $false
foreach ($svc in @('BITS', 'wuauserv', 'CryptSvc')) {
    $service = Get-Service -Name $svc -ErrorAction SilentlyContinue
    if ($service) {
        Write-Log "Service $svc`: Status $($service.Status), StartType $($service.StartType)"
    } else {
        Write-Log "Service $svc not found"
    }
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
        # No /ResetBase: it would make every installed update impossible to uninstall.
        $dismCleanup = & DISM.exe /Online /Cleanup-Image /StartComponentCleanup 2>&1
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
        # CryptSvc holds catroot2 open, so it has to be stopped as well.
        foreach ($svc in @('BITS', 'wuauserv', 'CryptSvc')) {
            Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        }

        # Rename instead of delete: Windows rebuilds both folders, and the old content stays available for rollback.
        # Backups from an earlier run of this script are removed first so they cannot fill the disk.
        $stamp = Get-Date -Format "yyyyMMddHHmmss"
        $resetTargets = @(
            @{Parent = "C:\Windows"; Name = "SoftwareDistribution"},
            @{Parent = "C:\Windows\System32"; Name = "catroot2"}
        )
        foreach ($target in $resetTargets) {
            $folder = Join-Path $target.Parent $target.Name
            Get-ChildItem -Path $target.Parent -Directory -Filter "$($target.Name).wufix-old-*" -ErrorAction SilentlyContinue |
                Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path $folder) {
                try {
                    Rename-Item -Path $folder -NewName "$($target.Name).wufix-old-$stamp" -ErrorAction Stop
                    Write-Log "Renamed $folder to $($target.Name).wufix-old-$stamp"
                } catch {
                    Write-Log "Error renaming $folder`: $($_.Exception.Message)"
                }
            }
        }
        $componentsReset = $true
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
    # NOTE: HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update is NOT in this list.
    # It holds the Intune (MDM) update ring policies and must never be deleted.
    # NOTE: HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection is NOT in this list either.
    # It holds the diagnostic data (telemetry) policy that Autopatch and Windows Update reports depend on.
    $registryKeys = @(
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

# Start the services again only if the component reset stopped them
if ($componentsReset) {
    $servicesToRestart = @(
        @{Name = 'CryptSvc'; Display = 'Cryptographic Services'},
        @{Name = 'BITS'; Display = 'Background Intelligent Transfer Service'},
        @{Name = 'wuauserv'; Display = 'Windows Update'}
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
                                Write-Log "Warning: Could not start Windows Autopatch Client Broker - May require manual intervention"
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
        # Ask the update orchestrator for a scan. Nothing is deleted here: the scan history
        # (Auto Update\Results) and the update database (DataStore.edb) stay in place. The database is only
        # rebuilt by the component reset step above, when that step finds a reason for it.
        # Installation stays with the update policy (update rings, Autopatch).
        $usoClient = "$env:windir\System32\UsoClient.exe"
        if (Test-Path $usoClient) {
            Start-Process -FilePath $usoClient -ArgumentList "StartScan" -NoNewWindow -ErrorAction Stop
            Write-Log "Windows Update scan triggered via UsoClient"
        } else {
            Write-Log "UsoClient.exe not found - scan not triggered"
        }
    } catch {
        Write-Log "Error refreshing Windows Update policies: $($_.Exception.Message)"
    }
} else {
    Write-Log "Windows Update policy refresh disabled in configuration - skipping"
}

# Pending reboot flags are reported but NEVER cleared.
# Deleting RebootPending / PackagesPending / RebootRequired leaves servicing operations
# unfinished and can corrupt the component store. The only safe fix is a restart.
# The $clearRebootFlags parameter is kept for compatibility and now only controls this report.
if ($clearRebootFlags -eq 1) {
    Write-Log "Checking for pending reboot flags (report only)..."
    try {
        $rebootFlags = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
        )
        $rebootFlagsFound = 0
        foreach ($flagPath in $rebootFlags) {
            if (Test-Path $flagPath) {
                Write-Log "INFO: Pending reboot flag present (not cleared): $flagPath"
                $rebootFlagsFound++
            }
        }

        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            Write-Log "INFO: PendingFileRenameOperations detected (not cleared)"
            $rebootFlagsFound++
        }

        $pendingFileRename2 = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations2 -ErrorAction SilentlyContinue
        if ($pendingFileRename2) {
            Write-Log "INFO: PendingFileRenameOperations2 detected (not cleared)"
            $rebootFlagsFound++
        }

        if ($rebootFlagsFound -eq 0) {
            Write-Log "No pending reboot flags found"
        }
        else {
            Write-Log "WARNING: A restart is pending - restart the device to finish servicing operations"
        }
    } catch {
        Write-Log "Error checking reboot flags: $($_.Exception.Message)"
    }
} else {
    Write-Log "Pending reboot flag check disabled in configuration - skipping"
}

# Verify critical services: repair a disabled service and start the ones that have to run all the time.
# Default start types are restored, never forced to Automatic: wuauserv, BITS and TrustedInstaller are
# demand-start services and are normally stopped when idle.
$criticalServices = [ordered]@{
    'wuauserv'                  = @{Display = 'Windows Update'; DefaultStart = 'Manual'; AlwaysRunning = $false}
    'BITS'                      = @{Display = 'Background Intelligent Transfer Service'; DefaultStart = 'Manual'; AlwaysRunning = $false}
    'TrustedInstaller'          = @{Display = 'Windows Modules Installer'; DefaultStart = 'Manual'; AlwaysRunning = $false}
    'CryptSvc'                  = @{Display = 'Cryptographic Services'; DefaultStart = 'Automatic'; AlwaysRunning = $true}
    'IntuneManagementExtension' = @{Display = 'Intune Management Extension'; DefaultStart = 'Automatic'; AlwaysRunning = $true}
}
if ($verifyCriticalServices -eq 1) {
    Write-Log "Verifying critical services..."
    $servicesFixed = 0

    foreach ($svcName in $criticalServices.Keys) {
        $svcInfo = $criticalServices[$svcName]
        try {
            $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
            if (-not $service) {
                Write-Log "Warning: Service $svcName not found on this system"
                continue
            }

            if ($service.StartType -eq 'Disabled') {
                Write-Log "Service $($svcInfo.Display) is disabled - restoring default start type $($svcInfo.DefaultStart)..."
                Set-Service -Name $svcName -StartupType $svcInfo.DefaultStart -ErrorAction Stop
                $verifyStartupType = (Get-Service -Name $svcName -ErrorAction SilentlyContinue).StartType
                if ($verifyStartupType -ne 'Disabled') {
                    Write-Log "Set $($svcInfo.Display) to $verifyStartupType startup - Verified"
                    $servicesFixed++
                } else {
                    Write-Log "Error: $($svcInfo.Display) is still disabled (a policy may enforce this)"
                }
            }

            if ($svcInfo.AlwaysRunning -and $service.Status -ne "Running") {
                Write-Log "Service $($svcInfo.Display) is not running - Starting with retry logic..."
                $result = Start-ServiceWithRetry -ServiceName $svcName -DisplayName $svcInfo.Display
                if ($result) {
                    $servicesFixed++
                }
            }
        } catch {
            Write-Log "Error managing service $($svcInfo.Display): $($_.Exception.Message)"
        }
    }

    if ($servicesFixed -eq 0) {
        Write-Log "All critical services are properly configured - skipping"
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
    $sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
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
            Start-Process -FilePath "$env:SystemRoot\System32\cleanmgr.exe" -ArgumentList "/sagerun:100" -Wait -WindowStyle Hidden -ErrorAction SilentlyContinue
            Write-Log "Disk Cleanup completed"
            
            # Check free space after cleanup
            $sysDrive = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
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
    # A Configuration Manager client sets the WSUS values on purpose (software update point).
    # On co-managed devices they must stay unless the Windows Update workload was moved to Intune,
    # and Configuration Manager removes them itself in that case.
    $configMgrClient = Get-Service -Name CcmExec -ErrorAction SilentlyContinue
    if ($configMgrClient) {
        Write-Log "Configuration Manager client found (CcmExec) - WSUS policy values are left unchanged"
    } else {
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
                Write-Log "Removed policy block: $($block.Path)\$($block.Name) (was: $($value.$($block.Name)))"
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
    }
} else {
    Write-Log "Windows Update policy blocks removal disabled in configuration - skipping"
}

# Restart the Windows Update Agent only if its COM interface does not answer
if ($resetWUAgent -eq 1) {
    Write-Log "Checking Windows Update Agent health..."
    try {
        # Offline search: tests the agent and its database without depending on the network.
        function Test-WUAgentResponds {
            try {
                $session = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
                $searcher = $session.CreateUpdateSearcher()
                $searcher.Online = $false
                $null = $searcher.Search("IsInstalled=0 and IsHidden=0")
                return $true
            } catch {
                return $false
            }
        }

        if (Test-WUAgentResponds) {
            Write-Log "Windows Update Agent is healthy - skipping reset"
        } else {
            Write-Log "Windows Update Agent does not respond - restarting the service..."
            # The registry key HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate is NOT deleted.
            # It holds the device's update client ID and orchestrator state, and Windows does not fully recreate it.
            Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
            Start-Service -Name wuauserv -ErrorAction Stop
            Start-Sleep -Seconds 2

            if (Test-WUAgentResponds) {
                Write-Log "Windows Update Agent responds again after the service restart"
            } else {
                Write-Log "Error: Windows Update Agent still does not respond. Next step: component reset (resetWUComponents) or DISM/SFC (fullRepair)"
            }
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
            Write-Log "$($criticalServices[$svcName].Display): $($service.Status) (StartType: $($service.StartType))"
        }
    } catch {
        Write-Log "Could not check $($criticalServices[$svcName].Display)"
    }
}

Write-Log "NOTE: If issues persist, a system reboot may be required"

# Exit code: 0 = all steps ran without error, 1 = at least one step failed (Intune then shows the remediation as failed)
if ($global:RemediationErrors -gt 0) {
    Write-Log "Remediation script completed with $($global:RemediationErrors) failed step(s) - see the lines starting with 'Error' or 'Failed' above"
    exit 1
}
Write-Log "Remediation script completed successfully"
exit 0
