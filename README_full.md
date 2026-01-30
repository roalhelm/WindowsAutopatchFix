# Windows Update Fix - Intune Proactive Remediation

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Intune](https://img.shields.io/badge/Microsoft-Intune-0078D4.svg)](https://intune.microsoft.com)
[![Version](https://img.shields.io/badge/Version-3.0-brightgreen.svg)](https://github.com/roalhelm/WindowsAutopatchFix)

Intelligent detection and remediation scripts for Windows Update failures on Microsoft Intune-managed devices. Features configurable repair steps that only execute when problems are detected, minimizing unnecessary system changes while addressing over 20 different error conditions.

## 🎯 Purpose

Intelligent, targeted repair of Windows Update issues for Intune-managed devices. Only performs repairs when problems are detected.

**Key Features:**
- **Smart Detection** - Only fixes what's broken
- **Fully Configurable** - 15 independent repair steps
- **Minimal Impact** - Skips unnecessary operations
- **20+ Error Codes** - Comprehensive coverage

**Addresses:** Service failures, corrupted components, registry/policy conflicts, WSUS artifacts, Autopatch issues, disk space, and database corruption.

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

**Intune Portal:** Devices > Scripts and remediations > Proactive remediations > + Create

**Settings:**
- Detection: `detection.ps1` | Remediation: `remediation.ps1`
- Run as: **System** (not logged-on credentials)
- 64-bit PowerShell: **Yes** | Signature check: **No**
- Schedule: **Daily** (recommended)
- Assign to: All Windows devices or target groups

## 📁 Files

### `detection.ps1`
Checks: TPM/Secure Boot, disk space (20 GB min), services, WU components, registry/WSUS config, Intune/Autopatch status, pending reboots.

**Exit:** `0` = healthy | `1` = issues detected (triggers remediation)

### `remediation.ps1`
Intelligent automated repair with configurable steps. Each action is only executed when necessary based on detection results.

**Repair Actions:**
- Service restart and startup type configuration (only if services are stopped)
- Windows Update component reset (only if corrupted/stuck)
- Registry cleanup (only if problematic keys exist)
- WSUS artifact removal (only if WUServer/UseWUServer detected)
- DLL re-registration (only if COM interface fails)
- Intune Management Extension service restart (only if not running)
- Windows Autopatch configuration refresh (only if enabled)
- Windows Autopatch Client Broker installation trigger and verification
- Client Broker process and service health checks
- Primary Refresh Token refresh for Intune policy sync (Intune-only devices)
- Windows Update policy refresh
- Disk cleanup (only if < 20 GB free space)
- Windows Update Agent reset (only if COM interface broken)
- Pending reboot flag cleanup (safe flags only)
- System health verification

**Configuration Variables (all customizable):**
```powershell
$fullRepair = 0              # DISM + SFC (resource intensive)
$resetWUComponents = 1       # Windows Update component reset
$cleanupRegistry = 1         # Registry cleanup
$reregisterDLLs = 1          # DLL re-registration
$restartIntune = 1           # Intune Management Extension restart
$checkAutopatch = 1          # Windows Autopatch configuration check
$removeSetupBlocks = 1       # Setup registry block removal
$clearRebootFlags = 1        # Pending reboot flags cleanup
$verifyCriticalServices = 1  # Critical services verification
$configureAppReadiness = 1   # App Readiness Service configuration
$runDiskCleanup = 1          # Disk cleanup (< 20 GB)
$removePolicyBlocks = 1      # WSUS policy blocks removal
$resetWUAgent = 1            # Windows Update Agent reset
$refreshPRT = 1              # Primary Refresh Token refresh (Intune-only)
$refreshWUPolicies = 1       # Windows Update policy refresh
```

Set any variable to `0` to disable that specific repair step.

## 📊 Logging

Location: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_*.log`

**Includes:** Timestamps, detection results, remediation actions, "skipping" messages for healthy components, config settings, errors/warnings.

**Example:**
```
10:15:23 - All services running - skipping restart
10:15:24 - WU components healthy - skipping reset
10:15:26 - COM interface broken - DLL re-registration needed
10:15:45 - DLL re-registration completed
```

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

### Configure Repair Steps

Edit configuration section at the top of `remediation.ps1` - 15 individual options available:

```powershell
$fullRepair = 0              # DISM + SFC (10-30 min)
$resetWUComponents = 1       # Component reset
$cleanupRegistry = 1         # Registry cleanup
$reregisterDLLs = 1          # DLL re-registration
# ... 11 more options
```

**Quick Configs:**
- **Minimal:** Only `$resetWUComponents`, `$verifyCriticalServices`, `$removePolicyBlocks` = 1
- **Deep Repair:** Set `$fullRepair = 1` (enables DISM/SFC - increases runtime)
- **Intune-only/Autopatch:** Focus on `$checkAutopatch`, `$removePolicyBlocks`, `$refreshPRT`, `$restartIntune`

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
- **Disabled configuration steps:** Repairs set to `0` in configuration are skipped

These issues require manual intervention or different remediation approaches.

**Note:** The script intelligently skips repairs when components are already healthy, so execution time varies based on actual problems detected.

## 🔄 ConfigMgr/WSUS Migration Support

Addresses migration issues from ConfigMgr/WSUS to Intune/Autopatch:

**Auto-Detects & Fixes:**
- WSUS artifacts (WUServer, UseWUServer)
- GPO remnants and registry conflicts
- Autopatch Client Broker issues (installation, process/service status)
- Co-management misconfigurations

**Best Practices:** Disable ConfigMgr Software Update settings, run remediation daily, monitor logs for drift.

[Microsoft Docs](https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/references/windows-autopatch-conflicting-configurations)

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Ronny Alhelm**
- GitHub: [@roalhelm](https://github.com/roalhelm)

## 🔄 Version History

### Version 3.0 (Current - 2025-12-11)
- **Intelligent Detection** - Only repairs components that are actually broken
- **Configurable Repair Steps** - 15 individual configuration options
- **Conditional Execution** - Each step checks if repair is needed before executing
- **Enhanced Logging** - Clear "skipping" messages for healthy components
- **Optimized Performance** - Reduced execution time by skipping unnecessary operations
- **Granular Control** - Enable/disable specific repair actions as needed

### Version 2.0 (2024-09-19)
- Expanded detection to cover all common Windows Update errors
- Added comprehensive remediation actions
- Implemented Intune/Autopatch sync checks and fixes
- Added WSUS configuration detection and removal (WUServer, UseWUServer)
- Support for ConfigMgr/WSUS to Intune migration scenarios
- Windows Autopatch Client Broker detection and installation trigger
- Client Broker process and service health verification
- Enhanced logging to IntuneManagementExtension directory
- Added disk cleanup functionality
- Registry policy block removal
- Windows Update Agent reset
- Service startup type configuration
- Pending reboot flag cleanup

### Version 1.0 (2024-09-19)
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
