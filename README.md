# Windows Update Fix - Intune Proactive Remediation

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Intune](https://img.shields.io/badge/Microsoft-Intune-0078D4.svg)](https://intune.microsoft.com)

Automated detection and remediation scripts for common Windows Update failures on Microsoft Intune-managed devices. Diagnoses and repairs over 20 different Windows Update error conditions including service failures, corrupted components, registry blocks, and policy conflicts.

## 🎯 Purpose

This Intune Proactive Remediation package automatically detects and resolves Windows Update issues that commonly prevent devices from receiving updates, including:

- Service failures (Windows Update, BITS, Cryptographic Services)
- Corrupted Windows Update components (SoftwareDistribution, catroot2)
- Registry blocks and policy conflicts
- WSUS configuration conflicts (WUServer, UseWUServer)
- Legacy ConfigMgr/WSUS artifacts blocking Autopatch
- Intune Management Extension sync issues
- Windows Autopatch configuration problems
- Low disk space and pending reboots
- Windows Update database corruption

## 🔍 Supported Error Codes

Addresses the following common Windows Update error codes:

- `0x80070002` - File not found
- `0x8007000E` - Out of memory
- `0x80240034` - Update not applicable
- `0x8024402F` - Network/connectivity issues
- `0x80070643` - Installation failure
- `0x800F0922` - System file corruption
- `0xC1900200` - Upgrade requirements not met
- `0x80070490` - Component store corruption
- `0x800F0831` - CBS corruption

And many more...

## 📋 Requirements

- **Platform:** Windows 10/11
- **Management:** Microsoft Intune
- **PowerShell:** 5.1 or later
- **Permissions:** System/Administrator level (runs as SYSTEM in Intune)

## 🚀 Deployment

### Intune Portal Configuration

1. Navigate to **Devices** > **Scripts and remediations** > **Proactive remediations**
2. Click **+ Create** to add a new script package
3. Configure the following settings:

#### Basic Information
- **Name:** Windows Update Fix
- **Description:** Detects and repairs Windows Update issues: service failures, corrupted components, registry blocks, policy conflicts, Intune/Autopatch sync problems. Addresses errors 0x80070002, 0x8007000E, 0x80240034, 0x8024402F, 0x80070643, 0x800F0922, 0xC1900200, 0x80070490, 0x800F0831.

#### Settings
- **Detection script:** `detection.ps1`
- **Remediation script:** `remediation.ps1`
- **Run this script using the logged-on credentials:** **No**
- **Enforce script signature check:** **No**
- **Run script in 64-bit PowerShell:** **Yes**

#### Assignments
- Assign to appropriate device groups (e.g., All Windows devices)

#### Schedule
- **Run script every:** 1 day (recommended)
- Or configure as needed based on your environment

## 📁 Files

### `detection.ps1`
Comprehensive health check that detects:
- TPM and Secure Boot status
- Disk space availability (minimum 20 GB)
- Service status (Windows Update, BITS, Cryptographic Services, Intune Management Extension)
- Windows Update component integrity
- Registry blocks and policy conflicts
- WSUS Server configuration (WUServer, UseWUServer)
- Legacy ConfigMgr/WSUS remnants
- Intune enrollment and policy sync status
- Windows Autopatch configuration
- Pending reboots and system file corruption
- Network connectivity to Windows Update servers

**Exit Codes:**
- `0` - No issues detected, system healthy
- `1` - Issues detected, triggers remediation

### `remediation.ps1`
Automated repair actions including:
- Service restart and startup type configuration
- Windows Update component reset (SoftwareDistribution, catroot2)
- Registry cleanup (policy blocks, setup blocks, WSUS configuration)
- WSUS artifact removal (WUServer, UseWUServer)
- DLL re-registration (Windows Update components)
- Intune Management Extension service restart and sync trigger
- Windows Autopatch configuration refresh
- Group Policy and Windows Update policy refresh
- Disk cleanup (old Windows Update files)
- Windows Update Agent reset
- Pending reboot flag cleanup (safe flags only)
- System health verification

**Configuration Options:**
- `$fullRepair = 0` - Set to `1` to enable DISM and SFC scans (takes longer)

## 📊 Logging

Both scripts log detailed information to:

```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\
├── WindowsUpdateFix_detection.log
└── WindowsUpdateFix_remediation.log
```

Logs include:
- Timestamps for all actions
- Detection results and issue counts
- Remediation steps performed
- Service status changes
- Error messages and warnings
- Disk space before/after cleanup
- Final system health status

## 🔧 Manual Execution

For testing or troubleshooting, you can run the scripts manually:

```powershell
# Detection only
powershell.exe -ExecutionPolicy Bypass -File .\detection.ps1

# Remediation
powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1
```

**Note:** Scripts require elevated privileges (Run as Administrator).

## 🛠️ Customization

### Enable Full System Repair (DISM + SFC)

Edit `remediation.ps1` and change:
```powershell
$fullRepair = 1
```

This enables:
- DISM ScanHealth
- DISM RestoreHealth
- DISM StartComponentCleanup
- SFC /scannow

**Warning:** Full repair mode significantly increases execution time (10-30 minutes).

### Adjust Disk Space Threshold

Edit `detection.ps1` line 79:
```powershell
if ($freeSpaceGB -lt 20) {  # Change 20 to your desired minimum GB
```

## 📈 Monitoring

Monitor remediation effectiveness through:

1. **Intune Portal:**
   - Devices > Scripts and remediations > Proactive remediations
   - View device status, detection results, and remediation success rates

2. **Log Files:**
   - Review `WindowsUpdateFix_*.log` files on devices
   - Check for specific errors or repeated failures

3. **Windows Update Settings:**
   - Verify devices can check for updates successfully
   - Confirm update installation proceeds normally

## ⚠️ Limitations

The remediation script **cannot** automatically fix:

- **Hardware issues:** TPM not present, Secure Boot unavailable
- **Insufficient disk space:** Only cleans temporary files, may not free enough space
- **Intune enrollment:** Cannot re-enroll devices automatically
- **Network/firewall blocks:** Cannot modify network infrastructure
- **Active system reboot requirement:** Does not force restart (by design)

These issues require manual intervention or different remediation approaches.

## 🔄 ConfigMgr/WSUS Migration Support

This solution specifically addresses common issues when migrating from Configuration Manager or WSUS to Intune and Windows Autopatch:

### Detected WSUS Artifacts
- **WUServer** - WSUS server URL that redirects updates away from cloud services
- **UseWUServer** - Registry value that forces use of WSUS instead of Windows Update

### Common Migration Scenarios
1. **Co-Management enabled** but Software Update client settings still active in ConfigMgr
2. **Control slider moved to Intune** but registry artifacts remain
3. **GPO remnants** from previous WSUS deployments
4. **Hybrid environments** with mixed update sources

### Best Practices
- Ensure ConfigMgr Software Update client settings are disabled for Autopatch devices
- Target Autopatch devices with client settings that disable Windows and Office updates
- Run this remediation regularly to catch configuration drift
- Monitor log files for recurring WSUS configuration detections

For more information, see [Microsoft's Conflicting Configurations Documentation](https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/references/windows-autopatch-conflicting-configurations).

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Ronny Alhelm**
- GitHub: [@roalhelm](https://github.com/roalhelm)

## 🔄 Version History

### Version 2.0 (Current)
- Expanded detection to cover all common Windows Update errors
- Added comprehensive remediation actions
- Implemented Intune/Autopatch sync checks and fixes
- Added WSUS configuration detection and removal (WUServer, UseWUServer)
- Support for ConfigMgr/WSUS to Intune migration scenarios
- Enhanced logging to IntuneManagementExtension directory
- Added disk cleanup functionality
- Registry policy block removal
- Windows Update Agent reset
- Service startup type configuration
- Pending reboot flag cleanup

### Version 1.0
- Initial release (focused on error 0xC1900200)
- Basic service restart functionality
- Component folder reset

## 🙏 Acknowledgments

- Microsoft Intune documentation and community
- Windows Update troubleshooting guides
- PowerShell community contributions
- [Ken Goossens](https://kengoossens.com/) for Windows Autopatch remediation insights

---

**Need Help?** Check the log files first, then open an issue on GitHub with relevant log entries.
