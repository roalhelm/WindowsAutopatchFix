# Windows Update & Autopatch - Checkliste für Support

## Übersicht
Diese Checkliste hilft dabei, Windows Update und Autopatch-Probleme systematisch zu erkennen und zu beheben. Sie enthält kritische Settings, deren Sollwerte und potenzielle Problemkombinationen.

---

## HARDWARE & FIRMWARE-VORAUSSETZUNGEN

### 1. TPM (Trusted Platform Module)
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **TPM-Status** | Geräte-Manager oder `Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm` | TPM muss aktiviert sein (`IsActivated_InitialValue = $true`) | TPM deaktiviert oder nicht vorhanden → Windows 11 Upgrade blockt |
| | Systemeinstellungen > Sicherheit > Gerätesicherheit | TPM 2.0 vorhanden | TPM 1.2 (zu alt) oder TPM 0.0 (nicht vorhanden) |

**Problemkombinationen:**
- TPM deaktiviert + Windows 11 Update geplant = **Fehler 0xC1900200**
- Unsicheres TPM (externe TPM ohne UEFI) + Secure Boot = Instabilität

---

### 2. Secure Boot
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Secure Boot Status** | UEFI-Setup (F2/Del beim Boot) oder PowerShell: `Confirm-SecureBootUEFI` | Enabled | Deaktiviert → Sicherheitsrisiken, Update-Blocken |
| **UEFI Firmware** | UEFI-Setup > Info | Aktuell | Veraltetes BIOS/UEFI → Inkompatibilität mit neuen Windows-Updates |

**Problemkombinationen:**
- Secure Boot aus + TPM aus = **Update mit 0x80070002 oder 0x80070643 scheitert**
- BIOS < 2 Jahre alt + Insider Builds = CPU Microcode-Probleme

---

## DISK & SPEICHER

### 3. Festplattenplatz
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Freier Platz C:\ Drive** | `Get-WmiObject Win32_LogicalDisk -Filter "DeviceID='C:'"` oder Datei-Explorer | ≥ 20 GB | < 20 GB → Installation scheitert |
| | Systemeinstellungen > System > Speicher | Mindestens 35 GB für sicheren Puffer | < 10 GB = **Fehler 0x8007000E** (Speicher voll) |
| **SoftwareDistribution Ordner Größe** | `C:\Windows\SoftwareDistribution\Download` | < 500 MB | > 1 GB = zu viele hängen-gebliebene Update-Dateien |
| **Anzahl Dateien in Download** | `(Get-ChildItem C:\Windows\SoftwareDistribution\Download).Count` | < 50 Dateien | > 50 Dateien = **Fehler 0x80240034** (korrupte Downloads) |

**Problemkombinationen:**
- < 15 GB freier Platz + DISM/SFC Repair geplant = **DISM schlägt fehl**
- > 50 Dateien in SoftwareDistribution + antiker WU-Cache = **0x80240034**
- Temp-Ordner auf anderer Partition + zu wenig Platz auf C: = Installation blockiert

---

## KRITISCHE WINDOWS SERVICES

### 4. Automatische Updates (wuauserv)
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Status** | Services.msc → "Windows Update" oder `Get-Service wuauserv` | Status = **Running**, Startup = **Automatic** | Status = Stopped, Startup = Manual/Disabled |
| **Starttyp** | Services.msc (Properties) oder `Get-Service wuauserv \| Select StartType` | Automatic | Disabled/Manual → Updates laufen nicht automatisch |
| **Fehler im Event Log** | Event Viewer > Windows Logs > System (IDs 16, 20, 24, 25) | Keine Fehler in letzten 7 Tagen | > 5 Fehler in 7 Tagen = **0x8024402F** (Kommunikationsfehler) |

**Problemkombinationen:**
- wuauserv Stopped + BITS nicht läuft = **Updates blockiert komplett**
- wuauserv läuft + alte DLLs = **0xC1900200**

---

### 5. BITS (Background Intelligent Transfer Service)
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Status** | Services.msc → "Background Intelligent Transfer Service" | Status = **Running**, Startup = **Manual** (ok) oder **Automatic** | Status = Stopped, Startup = Disabled |
| **Abhängigkeiten** | Services.msc > BITS > Dependencies | Hängt von RpcSs, DcomLaunch ab | Abhängigkeits-Services nicht laufen |

---

### 6. Cryptographic Services (CryptSvc)
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Status** | Services.msc → "Cryptographic Services" | Status = **Running** | Status = Stopped |
| **Signatur-Validierung** | Event Log prüfen auf Zertifikats-Fehler | Keine Fehler | Zertifikats-Fehler = **0x80070643** |

---

### 7. Intune Management Extension
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Status** | Services.msc → "IntuneManagementExtension" oder `Get-Service IntuneManagementExtension` | Status = **Running** | Status = Stopped/Not Found |
| **Intune Enrollment** | HKLM:\SOFTWARE\Microsoft\Enrollments | Einträge müssen vorhanden sein | Keine Enrollments = Device nicht bei Intune registriert |

**Problemkombinationen:**
- IntuneManagementExtension Stopped + Autopatch aktiv = **Kein Remediation möglich**

---

### 8. App Readiness Service (AppReadiness)
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Status** | Services.msc → "App Readiness" | Status = Running (für W11) | Nicht erreichbar/fehlt = **W11 Update-Probleme** |
| **Startup Typ** | Services.msc Properties | Manual (Windows 11: Automatic) | Disabled = App-Launch-Probleme |

---

## REGISTRY & LEGACY POLICIES (WSUS/GPO Konflikte)

### 9. WSUS/GPO Konflikte (Legacy Policies)
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-------------|
| **WSUS Server konfiguriert** | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate` - Wert: `WUServer` | Sollte LEER sein (Intune-only = direkt von Windows Update) | WSUS konfiguriert (z.B. http://wsus.company.local:8530) = **Blockiert Intune Updates** |
| **UseWUServer Policy** | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` - `UseWUServer` | Sollte nicht existieren | = 1 (zwingt WSUS-Nutzung) = **Intune komplett blockiert** |
| **Auto Update Policy** | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` - `NoAutoUpdate` | Sollte nicht existieren oder = 0 | = 1 (Auto Updates deaktiviert) |
| **Installationshora** | `HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU` - `ScheduledInstallDay` | = 0 (every day) | = spezifisches Datum (kann Konflikte erzeugen) |

**Problemkombinationen:**
- WSUS konfiguriert + ConfigMgr Remnants im Registry = **Double-Management-Konflikt**
- GPO WSUS + Intune Updates = **0x8024402F** (Mixed-Policy-Fehler) - Intune komplett blockiert
- `UseWUServer = 1` ohne erreichbaren WSUS-Server = **Totaler Update-Block**
- `NoAutoUpdate = 1` + Intune Remediation = **Kann Remediation blockieren**

---

### 10. Setup & Installation Registry
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **SetupType** | `HKLM:\SYSTEM\Setup` - Wert: `SetupType` | Sollte nicht existieren oder = 0 | = 1 oder höher (Setup läuft noch) = **Fehler 0xC1900200** |
| **Registry-Locks** | `HKLM:\SYSTEM\Setup` - `SystemSetupInProgress` | Sollte nicht existieren | = 1 (altes Setup nicht abgeschlossen) |

---

## WINDOWS UPDATE & AUTOPATCH

### 11. Windows Update Komponenten Status
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **SoftwareDistribution Ordner** | `C:\Windows\SoftwareDistribution` | Vorhanden, < 1 GB, < 50 Dateien | Fehlend, > 1 GB, > 50 Dateien = korrupt |
| **catroot2 Ordner** | `C:\Windows\System32\catroot2` | Vorhanden, ~100-500 MB | Fehlend oder > 2 GB = Zertifikats-Cache korrupt |
| **WU DLL Registrierung** | PowerShell: `regsvr32 wuapi.dll` (Test) | DLL lädt ohne Fehler | DLL-Fehler = **0x80070643** |
| **Windows Update COM Interface** | PowerShell: `New-Object -ComObject Microsoft.Update.Session` | Erstellt erfolgreich Objekt | COM-Error = WU völlig defekt |

**Problemkombinationen:**
- SoftwareDistribution > 1 GB + > 50 Dateien + DLL-Fehler = **Total Neustart von WU nötig**
- catroot2 > 2 GB + alte Zertifikate = **0x80070643** (Signaturvalidierung fehlgeschlagen)

---

### 12. Autopatch Konfiguration
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Autopatch Agent Status** | Services.msc oder Check-Registry: `HKLM:\SOFTWARE\Microsoft\Autopatch` | Service läuft, Agent Version aktuell | Service gestoppt, Agent alte Version |
| **Autopatch Device Registration** | `HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\Autopatch` | Einträge vorhanden (DeviceId, etc.) | Keine Einträge = Device nicht registriert in Autopatch |
| **Autopatch Policies** | Event Log: "Autopatch" suchen | Keine Fehler beim Policy-Abruf | Fehler 429 (Rate Limit), 403 (Zugriff verweigert) = **Policy-Sync blockiert** |

**Problemkombinationen:**
- Autopatch Agent aktiv + WSUS konfiguriert + Intune = **Triple-Konflikt → 0x8024402F**
- Autopatch Device nicht registriert + fehlende Policies = **Keine automatischen Updates**

---

## NETZWERK & INTUNE VERBINDUNG

### 13. Intune Connectivity
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Intune Enrollment Status** | Settings > Accounts > Access work or school | Enrolled und Connected | "Not Configured" oder "Error" |
| **Device Compliance** | Intune Portal > Device Compliance | Compliant | Non-Compliant → Block möglich |
| **Certificate Chain** | Event Log > Application | Keine Zertifikats-Fehler | Zertifikats-Chain nicht vertraut = **403 Errors** |

---

## SYSTEMKONFIGURATION

### 14. Pending Reboot Status
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Reboot Flag** | Registry: `HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager` - `PendingFileRenameOperations` | Sollte nicht existieren | Existiert (alte Reboot pending) = **Neue Updates blockiert** |
| | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` | Leer | Hat Einträge (verhindert neuen Reboot) |
| **Component-Based Servicing (CBS)** | `HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Reboot Required` | Sollte nicht existieren | Existiert = **Reboot erforderlich** |

**Problemkombinationen:**
- PendingFileRenameOperations existiert + neue Update = **Fehler 0x800F0922**
- Mehrere alte Pending Reboot Flags = **Reboot wird nie durchgeführt**

---

## SICHERHEIT & UPDATES

### 15. Defender & Security Status
| Prüfung | Wo zu prüfen | Sollwert | Problem bei |
|---------|-------------|---------|-----------|
| **Windows Defender Definition Updates** | Windows Defender > Virus & Threat Protection | Definitions aktuell (< 24h) | > 7 Tage alt = **Könnte Update blocken** |
| **Tamper Protection** | Windows Defender > Virus & Threat Protection > Manage Settings | Enabled oder Disabled (konsistent) | Konflikt zwischen GPO und Defender = **Remediation blockiert** |

---

## SCHNELLCHECKLISTE - PROBLEMDIAGNOSE

### Fehler: **0xC1900200**
```
Prüfe:
  1. TPM aktiviert? (MUSS sein)
  2. Secure Boot enabled? (MUSS sein)
  3. SetupType im Registry = 0 oder existiert nicht?
  4. Keine PendingFileRenameOperations?
  5. > 20 GB freier Speicher?
  
Lösung: remediation.ps1 mit $fullRepair = 1
```

### Fehler: **0x8024402F**
```
Prüfe:
  1. WSUS konfiguriert? (MUSS leer sein für Intune-only)
  2. UseWUServer = 1 im Registry? (BLOCKIERT Intune komplett!)
  3. Autopatch + WSUS gleichzeitig? (KONFLIKT!)
  4. BITS Service läuft?
  5. wuauserv Service läuft?
  6. Event Log > 5 Fehler in 7 Tagen?
  
Lösung: WSUS-Policies entfernen (remediation.ps1) + PRT refresh
```

### Fehler: **0x80240034**
```
Prüfe:
  1. > 50 Dateien in C:\Windows\SoftwareDistribution\Download?
  2. Antivirus blockt Download?
  3. Proxy/Firewall blockt Updates?
  
Lösung: SoftwareDistribution zurücksetzen (remediation.ps1)
```

### Fehler: **0x80070643**
```
Prüfe:
  1. Zertifikate gültig? (CryptSvc läuft?)
  2. catroot2 > 2 GB?
  3. DLL wuapi.dll registriert?
  
Lösung: catroot2 löschen + DLL neu registrieren
```

### Fehler: **0x80070490** (Device not ready)
```
Prüfe:
  1. TPM 2.0 vorhanden?
  2. Secure Boot für ältere Hardware aktiv?
  3. App Readiness Service läuft?
  
Lösung: TPM/UEFI-Firmware prüfen
```

### Kein Autopatch/Windows Update
```
Prüfe:
  1. Intune Enrollment ok?
  2. IntuneManagementExtension läuft?
  3. WSUS-Konflikt vorhanden?
  4. Device registriert in Autopatch?
  5. Policies synced (Event Log)?
  
Lösung: Intune Re-Enrollment (falls nötig)
```

---

## REMEDIATION KONFIGURATION

### Schnelle Fixes (Minimal Config)
```powershell
# Nur diese auf 1 setzen in remediation.ps1:
$resetWUComponents = 1       # WU Komponenten zurücksetzen
$verifyCriticalServices = 1  # Services prüfen und starten
$removePolicyBlocks = 1      # WSUS/GPO Policy-Konflikte entfernen
```

### Tiefe Reparatur (Deep Repair)
```powershell
# Wenn minimale Fixes nicht helfen:
$fullRepair = 1             # DISM + SFC (dauert 10-30 Min!)
# + alle anderen auf 1 setzen
```

### Autopatch-Probleme (Intune-only Clients)
```powershell
# Für Autopatch/Intune-Konflikte:
$checkAutopatch = 1       # Autopatch-Status prüfen
$removePolicyBlocks = 1   # WSUS/GPO Policies entfernen
$refreshPRT = 1           # Primary Refresh Token aktualisieren
$restartIntune = 1        # Intune Management Extension neustarten
$cleanupRegistry = 1      # Legacy-Registry-Keys bereinigen
```

---

## SUPPORT ESKALATION

### Wann ist Escalation nötig?
- **Hardware-Fehler**: TPM, Secure Boot können nicht aktiviert werden → OEM Support
- **Netzwerk-Fehler**: Device kann sich nicht mit Intune verbinden → Networking Team
- **Enrollment-Fehler**: Device nicht enrollable → Identity/Intune Admins
- **Persistent nach Remediation**: Mehrmaliges Ausführen ohne Erfolg → Microsoft Support (ProDirect)

### Logs für Support
Immer diese sammeln:
```
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\WindowsUpdateFix_*.log
C:\Windows\Logs\CBS\CBS.log (für DISM Fehler)
Event Viewer > System (Windows Update Fehler)
Event Viewer > Application (COM/Service Fehler)
```

---

## WARTUNGSPLAN

| Task | Frequenz | Wenn |
|------|----------|-----|
| Disk Space prüfen | Wöchentlich | < 25 GB = Cleanup starten |
| Service Status prüfen | Täglich (Intune) | Automatisch via Proactive Remediation |
| WSUS Remnants cleanup | Monatlich | Nach ConfigMgr → Autopatch Migration |
| Update History Review | Monatlich | Fehlerquoten analysieren |
| TPM/Secure Boot Audit | Quartal | Hardware-Audit für neue Devices |

---

**Letzte Aktualisierung**: Januar 2026 | Version: 3.0
