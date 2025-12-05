#region PowerShell Help
<#
.SYNOPSIS
    Detection script for Windows Update issues, checking system requirements and service health.

    GitHub Repository: https://github.com/roalhelm/

.DESCRIPTION
    This script detects conditions that may cause Windows Update failures on Intune-managed devices.
    It checks for common issues including: corrupted update components, service failures, disk space,
    TPM/Secure Boot status, Intune enrollment, policy sync issues, and Windows Update client health.
    Addresses errors like: 0x80070002, 0x8007000E, 0x80240034, 0x8024402F, 0x80070643, 0x800F0922,
    0xC1900200, 0x80070490, 0x800F0831, and many others. If issues are detected, remediation is triggered.

.NOTES
    File Name     : detection.ps1
    Author        : Ronny Alhelm
    Version       : 2.0
    Creation Date : 2024-09-30

.CHANGES
    2.0 - Expanded to detect all common Windows Update errors, added Intune/Autopatch checks
    1.0 - Initial version (focused on 0Xc1900200)

.VERSION
    2.0

.EXAMPLE
    powershell.exe -ExecutionPolicy Bypass -File .\detection.ps1
    # Runs the detection script to check for all common Windows Update issues.
#>
#endregion

# PowerShell Detection Script for Windows Update Issues

# Function to log output to file and console
$global:LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_detection.log"
function Write-Log {
    param ([string]$message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "$timestamp - $message"
    Write-Output $logLine
    Add-Content -Path $global:LogPath -Value $logLine -ErrorAction SilentlyContinue
}

try {
    $exitCode = 0
    $issues = @()
    
    Write-Log "Starting Windows Update health detection for all common issues"
    
    # Check for TPM activation
    try {
        $tpmStatus = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm -ErrorAction SilentlyContinue
        if (-not $tpmStatus -or $tpmStatus.IsActivated_InitialValue -ne $true) {
            $issues += "TPM is not activated or not present"
        }
    }
    catch {
        $issues += "Unable to check TPM status: $($_.Exception.Message)"
    }
    
    # Check Secure Boot status
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        if (-not $secureBoot) {
            $issues += "Secure Boot is not enabled"
        }
    }
    catch {
        $issues += "Unable to verify Secure Boot status (may not be supported on this system)"
    }
    
    # Check free disk space on system drive (minimum 20 GB required)
    try {
        $sysDrive = Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'" -ErrorAction SilentlyContinue
        if ($sysDrive) {
            $freeSpaceGB = [math]::Round($sysDrive.FreeSpace / 1GB, 2)
            if ($freeSpaceGB -lt 20) {
                $issues += "Insufficient disk space: $freeSpaceGB GB available (minimum 20 GB required)"
            }
        }
        else {
            $issues += "Unable to check disk space on system drive"
        }
    }
    catch {
        $issues += "Error checking disk space: $($_.Exception.Message)"
    }
    
    # Check Windows Update service status
    try {
        $wuauserv = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if (-not $wuauserv -or $wuauserv.Status -ne "Running") {
            $issues += "Windows Update service is not running: $($wuauserv.Status)"
        }
    }
    catch {
        $issues += "Error checking Windows Update service: $($_.Exception.Message)"
    }
    
    # Check Intune Management Extension service
    try {
        $intuneService = Get-Service -Name IntuneManagementExtension -ErrorAction SilentlyContinue
        if (-not $intuneService -or $intuneService.Status -ne "Running") {
            $issues += "Intune Management Extension service is not running: $($intuneService.Status)"
        }
    }
    catch {
        $issues += "Error checking Intune Management Extension service: $($_.Exception.Message)"
    }
    
    # Check BITS service status
    try {
        $bits = Get-Service -Name BITS -ErrorAction SilentlyContinue
        if (-not $bits -or $bits.Status -ne "Running") {
            $issues += "BITS service is not running: $($bits.Status)"
        }
    }
    catch {
        $issues += "Error checking BITS service: $($_.Exception.Message)"
    }
    
    # Check for corrupted Windows Update components
    try {
        $softwareDistPath = "$Env:Windir\SoftwareDistribution"
        $catroot2Path = "$Env:Windir\System32\catroot2"
        
        # Check if SoftwareDistribution folder is accessible and not corrupted
        if (Test-Path $softwareDistPath) {
            $downloadFolder = "$softwareDistPath\Download"
            if (Test-Path $downloadFolder) {
                $downloadFiles = Get-ChildItem $downloadFolder -ErrorAction SilentlyContinue
                # If there are many stuck download files, it might indicate corruption
                if ($downloadFiles.Count -gt 50) {
                    $issues += "SoftwareDistribution folder may be corrupted: $($downloadFiles.Count) files in Download folder"
                }
            }
        }
        
        # Check catroot2 folder accessibility
        if (-not (Test-Path $catroot2Path)) {
            $issues += "catroot2 folder is missing or inaccessible"
        }
    }
    catch {
        $issues += "Error checking Windows Update component folders: $($_.Exception.Message)"
    }
    
    # Check for problematic registry entries that could block setup
    try {
        $setupBlock = Get-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SetupType" -ErrorAction SilentlyContinue
        if ($setupBlock -and $setupBlock.SetupType -ne 0) {
            $issues += "Setup registry block detected: SetupType = $($setupBlock.SetupType)"
        }
    }
    catch {
        # Registry check failed, but this shouldn't cause detection to fail
    }
    
    # Check for recent Windows Update failures in Event Log
    try {
        $recentUpdateErrors = Get-WinEvent -FilterHashtable @{
            LogName='System'
            ID=16,20,24,25,31,34,35
            StartTime=(Get-Date).AddDays(-7)
        } -MaxEvents 10 -ErrorAction SilentlyContinue
        
        if ($recentUpdateErrors.Count -gt 5) {
            $issues += "Multiple Windows Update errors in Event Log: $($recentUpdateErrors.Count) errors in last 7 days"
        }
    }
    catch {
        # Event log access might fail, but this shouldn't cause detection to fail
    }
    
    # Check Windows Update client health
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction SilentlyContinue
        if ($updateSession) {
            $updateSearcher = $updateSession.CreateUpdateSearcher()
            # Try a simple search to test Windows Update functionality
            $null = $updateSearcher.Search("IsInstalled=0 and IsHidden=0")
        }
        else {
            $issues += "Windows Update COM interface is not accessible"
        }
    }
    catch {
        $issues += "Windows Update client appears to be corrupted: $($_.Exception.Message)"
    }
    
    # Check Intune Enrollment status
    try {
        $enrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
        $enrollments = Get-ChildItem -Path $enrollmentPath -ErrorAction SilentlyContinue
        if (-not $enrollments) {
            $issues += "Device does not appear to be enrolled in Intune"
        }
        else {
            # Check if enrolled device is active
            $activeEnrollment = $false
            foreach ($enrollment in $enrollments) {
                $enrollmentType = (Get-ItemProperty -Path $enrollment.PSPath -Name EnrollmentType -ErrorAction SilentlyContinue).EnrollmentType
                if ($enrollmentType) {
                    $activeEnrollment = $true
                    break
                }
            }
            if (-not $activeEnrollment) {
                $issues += "No active Intune enrollment found"
            }
        }
    }
    catch {
        $issues += "Error checking Intune enrollment: $($_.Exception.Message)"
    }
    
    # Check Windows Autopatch registration
    try {
        $autopatchRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\Autopatch"
        if (Test-Path $autopatchRegPath) {
            $autopatchEnabled = (Get-ItemProperty -Path $autopatchRegPath -Name Enabled -ErrorAction SilentlyContinue).Enabled
            if ($autopatchEnabled -ne 1) {
                $issues += "Windows Autopatch is not properly enabled"
            }
        }
        else {
            # Autopatch registry may not exist if not configured, this is informational
            Write-Log "Windows Autopatch registry not found (may not be configured)"
        }
    }
    catch {
        # Non-critical, Autopatch registry check is informational
    }
    
    # Check for stale Intune policies (last sync time)
    try {
        $omaDMPath = "HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts"
        if (Test-Path $omaDMPath) {
            $accounts = Get-ChildItem -Path $omaDMPath -ErrorAction SilentlyContinue
            foreach ($account in $accounts) {
                $lastSync = (Get-ItemProperty -Path $account.PSPath -Name LastSuccessfulSync -ErrorAction SilentlyContinue).LastSuccessfulSync
                if ($lastSync) {
                    $lastSyncDate = [DateTime]::FromFileTime($lastSync)
                    $daysSinceSync = (New-TimeSpan -Start $lastSyncDate -End (Get-Date)).TotalDays
                    if ($daysSinceSync -gt 7) {
                        $issues += "Intune policy not synced for $([math]::Round($daysSinceSync, 1)) days (last sync: $($lastSyncDate.ToString('yyyy-MM-dd HH:mm')))"
                    }
                }
            }
        }
    }
    catch {
        $issues += "Error checking Intune policy sync status: $($_.Exception.Message)"
    }
    
    # Check for Windows Update for Business configuration
    try {
        $wufbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        if (Test-Path $wufbPath) {
            $doNotConnectToWindowsUpdateInternetLocations = (Get-ItemProperty -Path $wufbPath -Name DoNotConnectToWindowsUpdateInternetLocations -ErrorAction SilentlyContinue).DoNotConnectToWindowsUpdateInternetLocations
            if ($doNotConnectToWindowsUpdateInternetLocations -eq 1) {
                $issues += "Windows Update is blocked from connecting to Internet locations (policy conflict)"
            }
            
            # Check for WSUS Server configuration (blocks Autopatch)
            $wuServer = (Get-ItemProperty -Path $wufbPath -Name WUServer -ErrorAction SilentlyContinue).WUServer
            if ($wuServer) {
                $issues += "WSUS Server configured: $wuServer (conflicts with Windows Autopatch/Cloud Updates)"
            }
        }
        
        # Check if UseWUServer is enabled (forces WSUS instead of Windows Update)
        $wuAUPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        if (Test-Path $wuAUPath) {
            $useWUServer = (Get-ItemProperty -Path $wuAUPath -Name UseWUServer -ErrorAction SilentlyContinue).UseWUServer
            if ($useWUServer -eq 1) {
                $issues += "UseWUServer is enabled (forces WSUS, blocks Windows Autopatch)"
            }
        }
    }
    catch {
        # Registry check is informational
    }
    
    # Check Windows Update Database integrity
    try {
        $dataStorePath = "$Env:SystemRoot\SoftwareDistribution\DataStore\DataStore.edb"
        if (Test-Path $dataStorePath) {
            $dataStoreSize = (Get-Item $dataStorePath).Length / 1MB
            # If DataStore.edb is unusually large (>500MB), it may be corrupted
            if ($dataStoreSize -gt 500) {
                $issues += "Windows Update database may be corrupted: DataStore.edb is $([math]::Round($dataStoreSize, 2)) MB"
            }
        }
    }
    catch {
        $issues += "Error checking Windows Update database: $($_.Exception.Message)"
    }
    
    # Check Cryptographic Services
    try {
        $cryptSvc = Get-Service -Name CryptSvc -ErrorAction SilentlyContinue
        if (-not $cryptSvc -or $cryptSvc.Status -ne "Running") {
            $issues += "Cryptographic Services not running: $($cryptSvc.Status) (causes 0x80070643, 0x800F0922)"
        }
    }
    catch {
        $issues += "Error checking Cryptographic Services: $($_.Exception.Message)"
    }
    
    # Check App Readiness Service
    try {
        $appReadiness = Get-Service -Name AppReadiness -ErrorAction SilentlyContinue
        if ($appReadiness -and $appReadiness.StartType -eq "Disabled") {
            $issues += "App Readiness Service is disabled (may cause Store/UWP app update failures)"
        }
    }
    catch {
        # Service check is informational
    }
    
    # Check for pending reboot
    try {
        $rebootPending = $false
        
        # Check Component Based Servicing
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending") {
            $rebootPending = $true
        }
        
        # Check Windows Update
        if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired") {
            $rebootPending = $true
        }
        
        # Check PendingFileRenameOperations
        $pendingFileRename = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($pendingFileRename) {
            $rebootPending = $true
        }
        
        if ($rebootPending) {
            $issues += "System reboot is pending (may block new updates)"
        }
    }
    catch {
        # Reboot check is informational
    }
    
    # Check System File integrity (SFC scan needed)
    try {
        # Check if CBS.log shows corruption (common indicator)
        $cbsLogPath = "$Env:SystemRoot\Logs\CBS\CBS.log"
        if (Test-Path $cbsLogPath) {
            $cbsLog = Get-Content $cbsLogPath -Tail 100 -ErrorAction SilentlyContinue
            if ($cbsLog -match "corrupt|failed|error") {
                $issues += "CBS log indicates potential system file corruption (0x800F0922, 0x800F0831)"
            }
        }
    }
    catch {
        # Log check is optional
    }
    
    # Check Windows Update Agent version
    try {
        $wuAgent = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate" -ErrorAction SilentlyContinue
        if (-not $wuAgent) {
            $issues += "Windows Update Agent registry keys missing or corrupted"
        }
    }
    catch {
        $issues += "Error checking Windows Update Agent: $($_.Exception.Message)"
    }
    
    # Check for specific error codes in WindowsUpdate.log or Event Viewer
    try {
        $updateErrors = Get-WinEvent -FilterHashtable @{
            LogName='System'
            ProviderName='Microsoft-Windows-WindowsUpdateClient'
            Level=2,3
            StartTime=(Get-Date).AddDays(-3)
        } -MaxEvents 20 -ErrorAction SilentlyContinue
        
        if ($updateErrors) {
            $errorCodes = @()
            foreach ($updateError in $updateErrors) {
                if ($updateError.Message -match '0x[0-9A-Fa-f]{8}') {
                    $errorCodes += $matches[0]
                }
            }
            
            if ($errorCodes.Count -gt 0) {
                $uniqueErrors = $errorCodes | Select-Object -Unique
                $issues += "Recent Windows Update errors found: $($uniqueErrors -join ', ')"
            }
        }
    }
    catch {
        # Event log parsing is informational
    }
    
    # Check network connectivity to Windows Update servers
    try {
        $updateServers = @(
            "update.microsoft.com",
            "windowsupdate.microsoft.com"
        )
        
        foreach ($server in $updateServers) {
            $testConnection = Test-NetConnection -ComputerName $server -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
            if (-not $testConnection) {
                $issues += "Cannot reach Windows Update server: $server (network/firewall issue, causes 0x8024402F)"
                break
            }
        }
    }
    catch {
        # Network check is informational
    }
    
    # Evaluate results and determine exit code
    if ($issues.Count -gt 0) {
        # Create detailed output for Pre-remediation detection
        # Use comma separation instead of line breaks for better Intune display
        $detectionOutput = "ISSUES DETECTED: $($issues.Count), "
        
        $issueNumber = 1
        foreach ($issue in $issues) {
            $detectionOutput += "[$issueNumber] $issue"
            if ($issueNumber -lt $issues.Count) {
                $detectionOutput += ", "
            }
            $issueNumber++
        }
        
        $detectionOutput += " | STATUS: Remediation required"
        
        # Output as single line with comma separation
        Write-Output $detectionOutput
        Write-Log $detectionOutput
        
        $exitCode = 1
    }
    else {
        $statusMessage = "STATUS: No issues detected, System appears healthy"
        Write-Output $statusMessage
        Write-Log $statusMessage
        $exitCode = 0
    }
    
    Write-Log "Detection completed with exit code: $exitCode"
    Exit $exitCode
}
catch {
    $errorMessage = "Detection script encountered an unexpected error: $($_.Exception.Message)"
    Write-Error $errorMessage
    Write-Log $errorMessage
    # Exit 1 to trigger remediation if detection script fails
    Exit 1
}