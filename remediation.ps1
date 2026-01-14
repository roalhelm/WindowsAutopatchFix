#region PowerShell Help
<#
.SYNOPSIS
    Intelligent remediation script for Windows Update issues with configurable repair steps.
    Only executes repairs when problems are detected, minimizing unnecessary system changes.

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
    - Group Policy update
    - Windows Update policy refresh
    
    Addresses errors including: 0x80070002, 0x8007000E, 0x80240034, 0x8024402F, 0x80070643,
    0x800F0922, 0xC1900200, 0x80070490, 0x800F0831, and many others.

.NOTES
    File Name     : remediation.ps1
    Author        : Ronny Alhelm
    Version       : 3.0
    Creation Date : 2024-09-19
    Last Updated  : 2025-12-11

.CHANGES
    3.0 - Added intelligent detection (repairs only when needed) and configurable repair steps
    2.0 - Expanded to fix all common Windows Update errors, added comprehensive repair actions
    1.0 - Initial version (focused on 0Xc1900200)

.VERSION
    3.0

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

.PARAMETER updateGroupPolicy
    Set to 1 to enable Group Policy update. Default: 1

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

#region Configuration - Enable/Disable Repair Steps
# Set to 1 to enable, 0 to skip individual repair steps

# Full system repair (DISM + SFC) - Resource intensive, takes several minutes
$fullRepair = 0

# Windows Update component reset (SoftwareDistribution, catroot2)
$resetWUComponents = 1

# Registry cleanup (remove problematic policy keys)
$cleanupRegistry = 1

# DLL re-registration (Windows Update DLLs)
$reregisterDLLs = 1

# Intune Management Extension restart
$restartIntune = 1

# Windows Autopatch configuration check and repair
$checkAutopatch = 1

# Pending reboot flags cleanup
$clearRebootFlags = 1

# Critical services verification and restart
$verifyCriticalServices = 1

# App Readiness Service configuration
$configureAppReadiness = 1

# Disk cleanup (only runs if < 20 GB free space)
$runDiskCleanup = 1

# Windows Update policy blocks removal
$removePolicyBlocks = 1

# Windows Update Agent reset
$resetWUAgent = 1

# Group Policy update
$updateGroupPolicy = 1

# Windows Update policy refresh
$refreshWUPolicies = 1

#endregion

# Function to log output to file and console
$global:LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_remediation.log"
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$timestamp - $message"
    Write-Output $logLine
    Add-Content -Path $global:LogPath -Value $logLine
}

Write-Log "Starting comprehensive Windows Update remediation for all common issues"

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
        if ($downloadFiles.Count -gt 50) {
            Write-Log "SoftwareDistribution has $($downloadFiles.Count) files - reset needed"
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

# Check if registry keys exist before attempting deletion
if ($cleanupRegistry -eq 1) {
    $registryKeysDeleted = 0
    $registryKeys = @(
        "HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
        "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Appraiser\GWX",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\DisableWindowsUpdateAccess",
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\NoAutoUpdate"
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
    Start-Service -Name BITS -Verbose -ErrorAction SilentlyContinue
    Start-Service -Name wuauserv -Verbose -ErrorAction SilentlyContinue
    Start-Service -Name CryptSvc -Verbose -ErrorAction SilentlyContinue
    Start-Service -Name msiserver -Verbose -ErrorAction SilentlyContinue
    Write-Log "Windows Update services restarted"
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

    foreach ($dll in $dlls) {
        try {
            $regResult = & regsvr32.exe /s $dll 2>&1
        } catch {
            # Some DLLs may not exist on all systems, continue
        }
    }
    Write-Log "DLL re-registration completed"
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
            Write-Log "Intune Management Extension service restarted successfully"
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
                        Write-Log "Restarted $svc for Autopatch refresh"
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

# Force Group Policy update to apply any Intune-delivered policies
if ($updateGroupPolicy -eq 1) {
    Write-Log "Forcing Group Policy update..."
    try {
        $gpUpdateOutput = & gpupdate.exe /force 2>&1
        Write-Log "Group Policy updated: $gpUpdateOutput"
    } catch {
        Write-Log "Error running gpupdate: $($_.Exception.Message)"
    }
} else {
    Write-Log "Group Policy update disabled in configuration - skipping"
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

# Clear pending reboot flags only if they exist
if ($clearRebootFlags -eq 1) {
    Write-Log "Checking for pending reboot flags..."
    $rebootFlagsCleared = $false
    try {
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -Force -ErrorAction SilentlyContinue
            Write-Log "Cleared Component Based Servicing RebootPending flag"
            $rebootFlagsCleared = $true
        }
        
        if (-not $rebootFlagsCleared) {
            Write-Log "No safe reboot flags found - skipping"
        }
    } catch {
        Write-Log "Error clearing reboot flags: $($_.Exception.Message)"
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
                Write-Log "Service $($criticalServices[$svcName]) is not running - Starting..."
                Start-Service -Name $svcName -ErrorAction Stop
                Write-Log "Successfully started $($criticalServices[$svcName])"
                $servicesFixed++
            }
            
            # Ensure service is set to automatic start (except TrustedInstaller which is Manual)
            if ($svcName -ne 'TrustedInstaller') {
                $startupType = (Get-Service -Name $svcName).StartType
                if ($startupType -ne 'Automatic') {
                    Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
                    Write-Log "Set $($criticalServices[$svcName]) to Automatic startup"
                    $servicesFixed++
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
                Write-Log "App Readiness Service enabled (set to Manual)"
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

# Remove Windows Update policy blocks only if they exist
if ($removePolicyBlocks -eq 1) {
    Write-Log "Checking for Windows Update policy blocks..."
    try {
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
        
        # Remove Windows Update registry keys to force re-initialization
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
        
        # Restart Windows Update service (will recreate registry keys)
        Start-Service -Name wuauserv -ErrorAction SilentlyContinue
        Write-Log "Windows Update Agent reset completed"
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
