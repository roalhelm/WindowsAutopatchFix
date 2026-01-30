# Windows Update Fix - Intune Proactive Remediation

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Intune](https://img.shields.io/badge/Microsoft-Intune-0078D4.svg)](https://intune.microsoft.com)
[![Version](https://img.shields.io/badge/Version-3.0-brightgreen.svg)](https://github.com/roalhelm/WindowsAutopatchFix)

Intelligent detection and remediation for Windows Update failures. Configurable repair steps that only execute when needed, minimizing system impact.

## 🎯 Purpose

Smart, targeted Windows Update repair for Intune-managed devices.

**Key Features:**
- **Smart Detection** - Only fixes what's broken
- **Fully Configurable** - 15 independent repair steps
- **Minimal Impact** - Skips unnecessary operations
- **20+ Error Codes** - Comprehensive coverage

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

**`detection.ps1`** - Checks TPM/Secure Boot, disk space, services, components, registry/WSUS, Intune/Autopatch, reboots  
Exit: `0` = healthy | `1` = issues (triggers remediation)

**`remediation.ps1`** - Intelligent repair with 15 configurable steps (see Configuration below)

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

`powershell.exe -ExecutionPolicy Bypass -File .\remediation.ps1` (requires Admin)

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

**3.0 (2025-12-11)** - Intelligent detection, 15 configurable steps, conditional execution, optimized performance  
**2.0 (2024-09-19)** - Comprehensive coverage, Autopatch support, WSUS cleanup  
**1.0 (2024-09-19)** - Initial release

## 📄 License

MIT License - see [LICENSE](LICENSE)

---

**Need Help?** Check logs, then open an issue on GitHub.
