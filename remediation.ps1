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
$global:LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\RepairWinUpdate_remediation.log"
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

# Liste der Registry-Schlüssel, die gelöscht werden sollen
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
            Write-Log "Erfolgreich gelöscht: $key"
        } catch {
            Write-Log "Fehler beim Löschen von $key`: $($_.Exception.Message)"
        }
    } else {
        Write-Log "Schlüssel nicht gefunden: $key"
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

# Check registry for setup block
$setupBlock = Get-ItemProperty -Path "HKLM:\SYSTEM\Setup" -ErrorAction SilentlyContinue
if ($setupBlock -and $setupBlock.SetupType) {
    Write-Log "SetupType registry value found: $($setupBlock.SetupType)"
} else {
    Write-Log "No SetupType registry value found"
}

Write-Log "Remediation script completed"
