# CHANGELOG - Windows Update Fix

All notable changes to this project will be documented in this file.

## [3.5 / 2.4] - 2026-11-10

### Changed - remediation.ps1 v3.5 (safer repair steps)

- **Component reset**: `SoftwareDistribution` and `catroot2` are renamed (`*.wufix-old-<timestamp>`) instead of deleted, and `CryptSvc` is stopped first so `catroot2` can actually be moved. The backup from an earlier run is removed before a new one is created.
- **Services**: No service is stopped just because it is idle. `msiserver` is never touched (stopping it can abort a running installation). A disabled service gets its default start type back; nothing is forced to `Automatic`. Only `CryptSvc` and the Intune Management Extension are started when stopped.
- **Update agent reset**: The registry key `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate` is no longer deleted. The step restarts `wuauserv` and tests again, using an offline search so a network outage does not look like a broken agent.
- **Policy refresh**: Triggers `UsoClient StartScan` only. `DataStore.edb`, its logs and the `Auto Update\Results` key are no longer deleted on every run, and the legacy `wuauclt` call is gone.
- **Registry cleanup**: `HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection` (diagnostic data policy) is no longer deleted.
- **WSUS values**: Left unchanged on devices with a Configuration Manager client (`CcmExec`).
- **Full repair**: `DISM /StartComponentCleanup` runs without `/ResetBase`, so installed updates can still be uninstalled.
- **Exit code**: `1` when at least one step failed, `0` otherwise. Before, the script always returned `0`.
- **Robustness**: Secure Boot check no longer fails on legacy BIOS devices; the final service report works when service verification is disabled; Disk Cleanup start parameters fixed.

### Changed - detection.ps1 v2.4

- **Update agent test** uses an offline search.
- **WSUS values** are not reported as an issue on devices with a Configuration Manager client.

## [3.4 / 2.3] - 2026-11-10

### Fixed - detection.ps1 v2.3 (false positives)

- **Intune policy key**: `HKLM:\SOFTWARE\Microsoft\PolicyManager\current\device\Update` is no longer reported as an issue. The key holds the Intune update ring policies and exists on every managed device.
- **wuauserv and BITS**: A stopped service is no longer an issue. Both are demand-start services and are normally stopped when idle. Only a missing or disabled service is reported.
- **CBS.log**: The check now matches real corruption markers (`[SR] Cannot repair`, `CBS_E_STORE_CORRUPTION`, `0x80073712`, `0x800f0831`, ...) instead of the generic words `corrupt|failed|error`.
- **Pending reboot**: Logged as information and no longer triggers remediation, because remediation cannot (and must not) resolve it.

### Changed - both scripts

- **WMI access**: `Get-WmiObject` replaced with `Get-CimInstance` (TPM status, free disk space). `Get-WmiObject` does not exist in PowerShell 7. `wmic.exe` was never used.

### Fixed - remediation.ps1 v3.4 (destructive steps removed)

- **Intune policy key**: `PolicyManager\current\device\Update` is no longer deleted by the registry cleanup step.
- **Pending reboot flags**: `RebootPending`, `PackagesPending` and `RebootRequired` are no longer deleted. Clearing them leaves servicing operations unfinished and can corrupt the component store. The `clearRebootFlags` parameter is kept for compatibility and now only reports the flags.

## [3.3 / 2.2] - 2026-06-02

### ✨ Added - detection.ps1 v2.2

#### Enhanced Diagnostics
- **BitLocker Status Check**: Detects if BitLocker is enabled on C: drive (informational - may block feature updates)
- **DLL Version Validation**: Checks Windows Update DLL versions (wuapi.dll, wuaueng.dll, wups2.dll) against minimum year (2020)
  - Identifies outdated DLLs that cause error 0xC1900200
- **Service Dependency Check**: Validates prerequisite services (RpcSs, DcomLaunch, UsoSvc) are running
- **Error Code Dictionary**: Built-in descriptions for 13 common Windows Update error codes
  - Provides context in detection output (e.g., "0x8024402F - Network/connectivity - WSUS/GPO conflicts")

#### Extended Network Testing
- **HTTP Connectivity**: Tests actual HTTP connectivity to update.microsoft.com (not just ping)
- **DNS Resolution**: Separate DNS resolution testing for Windows Update servers
- **Proxy Detection**: Identifies if proxy is configured and logs settings

#### Enhanced Client Broker Health Check
- **Version Information**: Logs Client Broker file version and date
- **Process Status**: Checks if WindowsAutopatchClientBroker.exe is running
- **Age Warning**: Warns if Client Broker is older than 1 year

#### Improved Event Log Analysis
- **Configurable Limit**: MaxEvents increased from 10/15 to 50 (configurable via `$maxEventLogEntries`)
- **Error Code Extraction**: Automatically extracts and describes error codes from event log messages
- **Better Filtering**: More targeted event filtering with proper severity levels

#### Configuration & Usability
- **Parameter Support**: `-LogPath`, `-Verbose` for flexible deployment
- **Configuration Variables**: Centralized thresholds at script top:
  - `$maxEventLogEntries = 50` (was hardcoded 10/15)
  - `$maxSoftwareDistFiles = 75` (was hardcoded 50)
  - `$dllMinYear = 2020` (new)
  - `$maxEventLogDays = 7` (was hardcoded)
  - `$networkTestTimeout = 5` (new)
- **Log Rotation**: Automatic rotation at 10 MB, keeps last 5 logs, deletes logs older than 30 days

### ✨ Added - remediation.ps1 v3.3

#### Reliability Improvements
- **Service Retry Logic**: New `Start-ServiceWithRetry` function
  - 3 retry attempts with exponential backoff (500ms, 1s, 2s)
  - Proper service state verification after each attempt
  - Detailed logging of retry attempts and failures
- **DLL Validation**: Post-registration validation
  - Checks DLL versions after re-registration
  - Tests COM interface functionality with update count
  - Warns if DLLs are still outdated after registration

#### Extended Cleanup
- **Enhanced Reboot Flag Cleanup**: Now cleans 3 registry locations (was 1):
  - `Component Based Servicing\RebootPending`
  - `Component Based Servicing\PackagesPending` (new)
  - `WindowsUpdate\Auto Update\RebootRequired` (new)
  - Logs but doesn't clear PendingFileRenameOperations (safety measure)

#### Configuration & Usability
- **Full Parameter Support**: All 15 repair flags now available as parameters
  - Enables Intune parameter passing without script editing
  - Parameters: `-fullRepair`, `-resetWUComponents`, `-cleanupRegistry`, etc.
- **Configuration Variables**: Centralized thresholds:
  - `$maxSoftwareDistFiles = 75` (was hardcoded 50)
  - `$serviceRetryCount = 3` (new)
  - `$serviceRetryDelayMs = 500` (new)
  - `$dllMinYear = 2020` (new)
- **Log Rotation**: Automatic rotation at 10 MB, keeps last 5 logs

### 🔧 Changed

#### detection.ps1
- Updated disk space logging to include threshold value
- SoftwareDistribution file count threshold increased from 50 to 75 (reduces false positives)
- Event log analysis now processes up to 50 events (was 10/15)
- Network check now includes both TCP and DNS testing
- Version updated to 2.2

#### remediation.ps1
- All service start operations now use retry logic (was single attempt)
- Critical services verification now uses `Start-ServiceWithRetry` function
- Windows Update service restart now uses `Start-ServiceWithRetry` function
- Version updated to 3.3

### 📊 Performance

#### detection.ps1
- Event log query limit increase may add 1-2 seconds to execution time
- Network tests add ~2 seconds per server (DNS + HTTP)
- Overall execution time expected: 30-60 seconds (was 20-40 seconds)

#### remediation.ps1
- Service retry logic adds up to 7 seconds per failed service (3 retries with backoff)
- DLL validation adds ~5 seconds after re-registration
- Extended reboot flag cleanup adds ~1 second
- Overall execution time expected: 2-5 minutes excluding DISM/SFC (unchanged for healthy systems)

### 📝 Documentation

#### New Files
- **Test-WindowsUpdateFix.ps1**: Automated test suite for local validation
  - Tests script syntax, required functions, configuration variables
  - Validates system prerequisites
  - Dry-run execution of detection script
  - 7 test categories, detailed pass/fail/warning reporting

#### Updated Files
- **README.md**: Added "What's New" section, updated version badges, enhanced feature list
- **CHANGELOG.md**: This file - comprehensive change documentation

### 🔬 Testing

Recommended testing procedure:
1. Run `Test-WindowsUpdateFix.ps1` to validate script integrity
2. Execute `detection.ps1` on test device to verify detection logic
3. Review log output for new diagnostic information
4. Execute `remediation.ps1` with specific flags to test retry logic
5. Verify log rotation after running multiple times

### 📋 Migration Notes

**From v3.2 / v2.1:**
- No breaking changes
- Scripts are backward compatible
- Configuration variables have sensible defaults
- Log files maintain same format and location
- Existing Intune deployments can be updated in-place

**Configuration Migration:**
- Old scripts: Edit values in script body
- New scripts: Can still edit values OR use parameters
- Intune deployment: No changes required (parameters optional)

### 🚀 Deployment Checklist

Before deploying to production:
- [ ] Run `Test-WindowsUpdateFix.ps1` locally (requires admin)
- [ ] Test on 5-10 pilot devices
- [ ] Review detection logs for false positives
- [ ] Verify remediation success rate > 80%
- [ ] Check log rotation is working (test with small `$logRotationSizeMB = 1`)
- [ ] Confirm no performance degradation on older hardware
- [ ] Update Intune assignment group to include production devices

### 🔗 Related Issues

**Fixes:**
- DLL version detection addresses root cause of 0xC1900200 errors
- Service retry logic solves intermittent service start failures
- Extended reboot flags cleanup reduces stuck update states
- Enhanced network tests identify firewall/proxy issues earlier

**Known Limitations:**
- BitLocker check is informational only (no auto-suspend)
- DLL version check requires files dated 2020+ (may need adjustment for older Windows 10 builds)
- Service retry logic cannot fix services with corrupted binaries
- Reboot flag cleanup doesn't clear Setup-related flags (by design)

---

## [3.2 / 2.1] - 2026-03-03

### Enhanced reliability and validation
- Fixed race conditions in service restarts with proper timing
- Added comprehensive validation for all critical operations
- Improved operation verification with detailed status logging

---

## [3.1] - Previous Release

### Optimized for Intune-only devices
- Replaced gpupdate with dsregcmd /refreshprt for PRT refresh
- Updated registry cleanup to focus on WSUS/GPO conflicts

---

## [3.0] - Previous Release

### Added intelligent detection
- Repairs only when needed
- Configurable repair steps

---

## [2.0] - Previous Release

### Expanded error coverage
- Support for all common Windows Update errors
- Comprehensive repair actions

---

## [1.0] - Initial Release

### Basic functionality
- Focused on 0xC1900200 error
- Core detection and remediation
