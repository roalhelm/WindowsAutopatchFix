# Windows Update Fix - Intune Proactive Remediation

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Intune](https://img.shields.io/badge/Microsoft-Intune-0078D4.svg)](https://intune.microsoft.com)
[![Version](https://img.shields.io/badge/Version-3.3%20%2F%202.2-brightgreen.svg)](https://github.com/roalhelm/WindowsAutopatchFix)

Intelligent detection and remediation for Windows Update failures. Configurable repair steps that only execute when needed, minimizing system impact.

## 🎯 Purpose

Smart, targeted Windows Update repair for Intune-managed devices.

**Key Features:**
- **Smart Detection** - Only fixes what's broken, with enhanced diagnostics (DLL versions, BitLocker, service dependencies)
- **Fully Configurable** - 15 independent repair steps with parameter support
- **Robust Reliability** - Service start retry logic (3 attempts, exponential backoff)
- **Minimal Impact** - Skips unnecessary operations, intelligent thresholds
- **Enhanced Validation** - DLL version checks, extended reboot flag cleanup, error code descriptions
- **Auto Log Rotation** - 10 MB limit, keeps last 5 logs
- **20+ Error Codes** - Comprehensive coverage with error code dictionary

**Addresses:** Service failures, corrupted components, registry/policy conflicts, WSUS artifacts, Autopatch issues, disk space, database corruption.

## 🔍 Supported Error Codes

`0x80070002` `0x8007000E` `0x80240034` `0x8024402F` `0x80070643` `0x800F0922` `0xC1900200` `0x80070490` `0x800F0831` and more

## 📋 Requirements

Windows 10/11 | Microsoft Intune | PowerShell 5.1+ | System/Admin permissions

## 🚀 Deployment

**Intune:** Devices > Scripts and remediations > Proactive remediations > + Create

**Settings:**
- Detection: `detection.ps1` | Remediation: `remediation.ps1`
- Run as: **System** | 64-bit PS: **Yes** | Signature: **No**
- Schedule: **Daily** | Assign: All Windows devices or groups

## 📁 Files

**`detection.ps1`** (v2.2) - Enhanced diagnostics with BitLocker check, DLL version validation, service dependencies, extended network tests, error code dictionary  
Exit: `0` = healthy | `1` = issues (triggers remediation)

**`remediation.ps1`** (v3.3) - Intelligent repair with 15 configurable steps, service retry logic, DLL validation, extended reboot flag cleanup

**`Test-WindowsUpdateFix.ps1`** - Local validation script for testing before Intune deployment

## 🆕 What's New (v3.3 / v2.2)

**detection.ps1 v2.2:**
- ✅ **BitLocker Status Check** - Warns if enabled (may block feature updates)
- ✅ **DLL Version Validation** - Detects outdated Windows Update DLLs (main cause of 0xC1900200)
- ✅ **Service Dependencies** - Checks RpcSs, DcomLaunch, UsoSvc prerequisites
- ✅ **Extended Event Log Analysis** - Configurable limit (default 50), with error code descriptions
- ✅ **Enhanced Network Tests** - HTTP connectivity, DNS resolution, proxy detection
- ✅ **Error Code Dictionary** - Descriptions for 13 common error codes
- ✅ **Log Rotation** - Automatic rotation at 10 MB, keeps last 5 logs
- ✅ **Parameter Support** - `-LogPath`, `-Verbose` for flexible deployment

**remediation.ps1 v3.3:**
- ✅ **Service Retry Logic** - 3 attempts with exponential backoff (500ms → 1s → 2s)
- ✅ **DLL Validation** - Version checks and COM interface testing after re-registration
- ✅ **Extended Reboot Flags** - Cleans PackagesPending, RebootRequired, CBS RebootPending
- ✅ **Parameter Support** - All 15 repair flags configurable via parameters
- ✅ **Enhanced Validation** - Post-operation verification for all critical actions
- ✅ **Configurable Thresholds** - SoftwareDistribution limit (75 files), retry settings

## 📊 Logging

Location: `C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_*.log`

Includes timestamps, actions, "skipping" messages, config, errors/warnings.

## 🛠️ Configuration

Edit `remediation.ps1` configuration section - 15 options (set to `0` to disable):

```powershell
$fullRepair = 0              # DISM + SFC (10-30 min)
$resetWUComponents = 1       # Component reset
$cleanupRegistry = 1         # Registry cleanup
$reregisterDLLs = 1          # DLL re-registration
$restartIntune = 1           # Intune restart
$checkAutopatch = 1          # Autopatch check
$removeSetupBlocks = 1       # Setup blocks
$clearRebootFlags = 1        # Reboot flags
$verifyCriticalServices = 1  # Services
$configureAppReadiness = 1   # App Readiness
$runDiskCleanup = 1          # Disk cleanup (<20GB)
$removePolicyBlocks = 1      # Policy blocks (WSUS)
$resetWUAgent = 1            # WU Agent
$refreshPRT = 1              # PRT refresh (Intune-only)
$refreshWUPolicies = 1       # WU Policies
```

**Quick Configs:**
- **Minimal:** Only `$resetWUComponents`, `$verifyCriticalServices`, `$removePolicyBlocks` = 1
- **Deep Repair:** `$fullRepair = 1` (DISM/SFC)
- **Intune-only/Autopatch:** `$checkAutopatch`, `$removePolicyBlocks`, `$refreshPRT`, `$restartIntune`

## 🔧 Manual Testing

**Local Validation (before Intune deployment):**
```powershell
# Run test suite
.\Test-WindowsUpdateFix.ps1

# Test detection only
.\Test-WindowsUpdateFix.ps1 -TestDetectionOnly

# Test remediation only
.\Test-WindowsUpdateFix.ps1 -TestRemediationOnly
```

**Run scripts manually:**
```powershell
# Detection
powershell.exe -ExecutionPolicy Bypass -File .\detection.ps1

# Remediation (requires Admin)
powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1

# With parameters
.\remediation.ps1 -fullRepair 1 -Verbose
```

## 📈 Monitoring

- **Intune:** Scripts and remediations > View status/rates
- **Logs:** `WindowsUpdateFix_*.log` for errors
- **Validation:** Test Windows Update

## ⚠️ Limitations

Cannot auto-fix: Hardware (TPM/Secure Boot), severe disk space issues, Intune enrollment, network/firewall blocks, forced reboots.

**Note:** Execution time varies - skips healthy components.

## 🔄 ConfigMgr/WSUS Migration

Auto-detects & fixes: WSUS artifacts, GPO remnants, Autopatch Client Broker, co-management issues.

**Best Practice:** Disable ConfigMgr updates for Autopatch devices, run daily.

[Docs](https://learn.microsoft.com/en-us/windows/deployment/windows-autopatch/references/windows-autopatch-conflicting-configurations)

## 👤 Author

**Ronny Alhelm** - [@roalhelm](https://github.com/roalhelm)

## 🔄 Version History

**3.2 (2026-03-03)** - Enhanced reliability: Fixed race conditions with proper timing, comprehensive validation for all operations, status verification logging  
**3.1 (2026-01-30)** - Intune-only optimization: dsregcmd PRT refresh, WSUS/GPO cleanup focus  
**3.0 (2025-12-11)** - Intelligent detection, 15 configurable steps, conditional execution, optimized performance  
**2.1 (2026-03-03)** - Detection script enhancements: Improved error handling, performance optimizations, better logging  
**2.0 (2024-09-19)** - Comprehensive coverage, Autopatch support, WSUS cleanup  
**1.0 (2024-09-19)** - Initial release

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

**Need Help?** Check logs, then open an issue on GitHub.
