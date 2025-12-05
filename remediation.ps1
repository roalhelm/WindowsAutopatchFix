#region PowerShell Help
<#
.SYNOPSIS
    Remediation script for all Windows Update issues, repairing system components and services.

    GitHub Repository: https://github.com/roalhelm/

.DESCRIPTION
    This script remediates common Windows Update failures on Intune-managed devices. It performs:
    - Windows Update component reset (SoftwareDistribution, catroot2)
    - Service restart (BITS, wuauserv, CryptSvc, AppReadiness)
    - DISM and SFC system repair
    - Intune policy re-sync and configuration refresh
    - Windows Update database cleanup
    - Registry policy cleanup
    Addresses errors including: 0x80070002, 0x8007000E, 0x80240034, 0x8024402F, 0x80070643,
    0x800F0922, 0xC1900200, 0x80070490, 0x800F0831, and many others.

.NOTES
    File Name     : remediation.ps1
    Author        : Ronny Alhelm
    Version       : 2.0
    Creation Date : 2024-09-19

.CHANGES
    2.0 - Expanded to fix all common Windows Update errors, added comprehensive repair actions
    1.0 - Initial version (focused on 0Xc1900200)

.VERSION
    2.0

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1
    # Runs the remediation script to repair all Windows Update issues and log results.
#>
#endregion

# PowerShell Remediation Script for All Windows Update Issues

# Configuration: Set to 1 to enable full system repair (DISM + SFC), set to 0 to skip
$fullRepair = 0

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

# Stop all Windows Update related services
Write-Log "Stopping Windows Update services..."
$servicesToStop = @('BITS', 'wuauserv', 'CryptSvc', 'msiserver')
foreach ($svc in $servicesToStop) {
    try {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Write-Log "Stopped service: $svc"
    } catch {
        Write-Log "Could not stop service $svc`: $($_.Exception.Message)"
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

# Reset Windows Update components
Write-Log "Resetting Windows Update components..."
Stop-Service -Name BITS -Force -Verbose -ErrorAction SilentlyContinue
Stop-Service -Name wuauserv -Force -Verbose -ErrorAction SilentlyContinue
#net stop appidsvc
#net stop cryptsvc

Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\System32\catroot2" -Recurse -Force -ErrorAction SilentlyContinue

# List of registry keys to be deleted
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
        } catch {
            Write-Log "Error deleting $key`: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Key not found: $key"
    }
}

Start-Service -Name BITS -Verbose -ErrorAction SilentlyContinue
Start-Service -Name wuauserv -Verbose -ErrorAction SilentlyContinue
Start-Service -Name CryptSvc -Verbose -ErrorAction SilentlyContinue
Start-Service -Name msiserver -Verbose -ErrorAction SilentlyContinue
Write-Log "Windows Update services restarted"

# Re-register Windows Update DLLs
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

# Restart Intune Management Extension service to trigger policy sync
Write-Log "Restarting Intune Management Extension service..."
try {
    Restart-Service -Name IntuneManagementExtension -Force -ErrorAction Stop
    Write-Log "Intune Management Extension service restarted successfully"
} catch {
    Write-Log "Failed to restart Intune Management Extension: $($_.Exception.Message)"
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
Write-Log "Checking Windows Autopatch configuration..."
try {
    $autopatchRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Autopatch"
    
    if (Test-Path $autopatchRegPath) {
        $autopatchEnabled = (Get-ItemProperty -Path $autopatchRegPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
        
        if ($autopatchEnabled -eq 1) {
            Write-Log "Windows Autopatch is enabled - Refreshing configuration..."
            
            # Trigger Autopatch policy refresh by restarting related services
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

# Force Group Policy update to apply any Intune-delivered policies
Write-Log "Forcing Group Policy update..."
try {
    $gpUpdateOutput = & gpupdate.exe /force 2>&1
    Write-Log "Group Policy updated: $gpUpdateOutput"
} catch {
    Write-Log "Error running gpupdate: $($_.Exception.Message)"
}

# Trigger Windows Update policy refresh
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

# Check and remove setup registry block
Write-Log "Checking for setup registry blocks..."
try {
    $setupBlock = Get-ItemProperty -Path "HKLM:\SYSTEM\Setup" -ErrorAction SilentlyContinue
    if ($setupBlock -and $setupBlock.SetupType -and $setupBlock.SetupType -ne 0) {
        Write-Log "Setup registry block detected: SetupType = $($setupBlock.SetupType) - Attempting to remove..."
        Remove-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SetupType" -Force -ErrorAction Stop
        Write-Log "Successfully removed SetupType registry block"
    } else {
        Write-Log "No SetupType registry block found"
    }
} catch {
    Write-Log "Error removing setup registry block: $($_.Exception.Message)"
}

# Clear pending reboot flags (where safe to do so)
Write-Log "Checking and clearing safe reboot flags..."
try {
    # Remove Component Based Servicing RebootPending flag if it exists
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
        Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -Force -ErrorAction SilentlyContinue
        Write-Log "Cleared Component Based Servicing RebootPending flag"
    }
    
    # Note: We do NOT remove Windows Update RebootRequired as this could cause issues
    # Note: We do NOT remove PendingFileRenameOperations as this could break system stability
    Write-Log "Reboot flag cleanup completed (safe flags only)"
} catch {
    Write-Log "Error clearing reboot flags: $($_.Exception.Message)"
}

# Verify and start critical services
Write-Log "Verifying all critical services are running..."
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
            } else {
                Write-Log "Service $($criticalServices[$svcName]) is already running"
            }
            
            # Ensure service is set to automatic start (except TrustedInstaller which is Manual)
            if ($svcName -ne 'TrustedInstaller') {
                $startupType = (Get-Service -Name $svcName).StartType
                if ($startupType -ne 'Automatic') {
                    Set-Service -Name $svcName -StartupType Automatic -ErrorAction SilentlyContinue
                    Write-Log "Set $($criticalServices[$svcName]) to Automatic startup"
                }
            }
        } else {
            Write-Log "Warning: Service $svcName not found on this system"
        }
    } catch {
        Write-Log "Error managing service $($criticalServices[$svcName]): $($_.Exception.Message)"
    }
}

# Enable App Readiness Service if disabled
Write-Log "Checking App Readiness Service..."
try {
    $appReadiness = Get-Service -Name AppReadiness -ErrorAction SilentlyContinue
    if ($appReadiness) {
        if ($appReadiness.StartType -eq "Disabled") {
            Write-Log "App Readiness Service is disabled - Enabling..."
            Set-Service -Name AppReadiness -StartupType Manual -ErrorAction Stop
            Write-Log "App Readiness Service enabled (set to Manual)"
        } else {
            Write-Log "App Readiness Service startup type: $($appReadiness.StartType)"
        }
    }
} catch {
    Write-Log "Error configuring App Readiness Service: $($_.Exception.Message)"
}

# Cleanup disk space - Remove old Windows Update files
Write-Log "Cleaning up disk space..."
try {
    $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"
    $freeSpaceGBBefore = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
    Write-Log "Free disk space before cleanup: $freeSpaceGBBefore GB"
    
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
} catch {
    Write-Log "Error during disk cleanup: $($_.Exception.Message)"
}

# Remove Windows Update policy blocks
Write-Log "Removing Windows Update policy blocks..."
try {
    $policyBlocks = @(
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DoNotConnectToWindowsUpdateInternetLocations"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"; Name = "DisableWindowsUpdateAccess"},
        @{Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Name = "NoAutoUpdate"}
    )
    
    foreach ($block in $policyBlocks) {
        if (Test-Path $block.Path) {
            $value = Get-ItemProperty -Path $block.Path -Name $block.Name -ErrorAction SilentlyContinue
            if ($value) {
                Remove-ItemProperty -Path $block.Path -Name $block.Name -Force -ErrorAction SilentlyContinue
                Write-Log "Removed policy block: $($block.Path)\$($block.Name)"
            }
        }
    }
} catch {
    Write-Log "Error removing policy blocks: $($_.Exception.Message)"
}

# Reset Windows Update Agent
Write-Log "Resetting Windows Update Agent..."
try {
    # Stop Windows Update service
    Stop-Service -Name wuauserv -Force -ErrorAction SilentlyContinue
    
    # Remove Windows Update registry keys to force re-initialization
    Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -Recurse -Force -ErrorAction SilentlyContinue
    
    # Restart Windows Update service (will recreate registry keys)
    Start-Service -Name wuauserv -ErrorAction SilentlyContinue
    Write-Log "Windows Update Agent reset completed"
} catch {
    Write-Log "Error resetting Windows Update Agent: $($_.Exception.Message)"
}

# Verify Windows Update client health
Write-Log "Verifying Windows Update client health..."
try {
    $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
    if ($updateSession) {
        Write-Log "Windows Update COM interface is accessible"
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $searchResult = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        Write-Log "Windows Update client test search completed successfully - $($searchResult.Updates.Count) updates found"
    } else {
        Write-Log "Warning: Windows Update COM interface not accessible"
    }
} catch {
    Write-Log "Warning: Windows Update client health check failed: $($_.Exception.Message)"
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
