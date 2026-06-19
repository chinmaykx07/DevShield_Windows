# DevShield · कवच-यन्त्र
## Master Development Plan, Progress Report & TODO
**Document version:** 2026-06-18  
**Project version target:** v0.1.0 → v0.5.0 → v1.0.0  
**Status:** Code complete with known gaps. Build blocked by 3 missing artifacts.

---

## Table of Contents
1. [Project Overview](#1-project-overview)
2. [Architecture Summary](#2-architecture-summary)
3. [Complete File Inventory](#3-complete-file-inventory)
4. [Session Bug Fixes](#4-session-bug-fixes)
5. [Phase 0 — Ship Blockers](#5-phase-0--ship-blockers)
6. [Phase 1 — v0.1 Production Release](#6-phase-1--v01-production-release)
7. [Phase 2 — v0.5 Feature Release](#7-phase-2--v05-feature-release)
8. [Phase 3 — v1.0 Rust Rewrite](#8-phase-3--v10-rust-rewrite)
9. [Mid-2026 Landscape Backlog](#9-mid-2026-landscape-backlog)
10. [Build Instructions](#10-build-instructions)
11. [Pre-Release Testing Checklist](#11-pre-release-testing-checklist)
12. [Release Checklist](#12-release-checklist)
13. [Architecture Decisions](#13-architecture-decisions--constraints)

---

## 1. Project Overview

DevShield is a Windows developer tool combining three capabilities no single existing
tool provides together:

| Pillar | What it does | Why others fail |
|---|---|---|
| **Thermal** | Silent Summer / Gaming Gear / Dev Mode with measured before/after sensor delta | Other tools toggle, never verify |
| **Privacy** | Telemetry sinkhole + registry + service hardening with full rollback | Other tools have no undo |
| **Network** | Per-process guardian with developer-aware allowlist | Generic firewalls have no concept of your dev stack |

**The moat:** Verification-first (NASA 8-step pattern applied to consumer Windows tooling),
rollback by audit ID, SQLite trail, bilingual EN+Sanskrit UI, cross-process shared-JSON IPC,
and cryptographically verifiable releases via Sigstore + GitHub Attestation.

**Target user:** Developer on Ryzen 9 / RTX-class machine, Windows 11, running
VS Code / Docker / Node — who wants their system silent in summer, fast for gaming,
private always, and able to undo everything.

---

## 2. Architecture Summary

```
devshield.exe  (Go tray — UI, state management, audit)
    |
    +-- Reads  ~/.devshield/config.json    language, auto-switch
    +-- Reads  ~/.devshield/state.json     current thermal mode, guardian state
    +-- Writes ~/.devshield/events/        JSON event queue → SQLite every 2s
    +-- Reads  ~/.devshield/audit.db       SQLite WAL mode — all events + alerts
    |
    +-- Triggers via Task Scheduler (RunLevel=Highest, registered once at first run)
            |
            +-- scripts/core/00_core.ps1              shared foundation, bilingual engine
            +-- scripts/core/01_first_run.ps1         hardware detection, LHM, tasks
            +-- scripts/core/02_lhm_bridge.ps1        sensor reading via LHM WMI
            +-- scripts/profiles/silent_summer.ps1
            +-- scripts/profiles/gaming_gear.ps1
            +-- scripts/profiles/dev_mode.ps1
            +-- scripts/profiles/profile_manager.ps1
            +-- scripts/monitor/hardware_dashboard.ps1
            +-- scripts/monitor/network_guardian.ps1
            +-- scripts/hardening/privacy_enforcer.ps1
            +-- scripts/hardening/tor_hardening.ps1
            +-- scripts/hardening/rollback.ps1

Key design decisions:
  PS scripts NEVER touch SQLite — write JSON to events/ folder, Go reads them
  Go tray NEVER runs PS directly — always via Task Scheduler for elevation
  config.json + state.json are the complete IPC layer between Go and PS
  lang.watchConfigFile polls every 3s — PS-side language change updates tray live
  Every destructive action: backup BEFORE change, verify AFTER, fault-safe on fail
```

---

## 3. Complete File Inventory

### 3a. Go Source — repo root

| # | File | Lines | Status | Source |
|---|---|---|---|---|
| 1 | `main.go` | 90 | PATCHED | file_20 + session fix |
| 2 | `tray.go` | 359 | ready | file_19 |
| 3 | `thermal.go` | 289 | ready | file_16 |
| 4 | `watchdog.go` | 168 | ready | file_17 |
| 5 | `context.go` | 278 | ready | file_18_context.go (clean, no suffix) |
| 6 | `audit.go` | 359 | ready | file_13 |
| 7 | `ps_bridge.go` | 348 | PATCHED | file_14_psbridge__1_ + session fix |
| 8 | `ps_bridge_windows.go` | 33 | NEW | session created |
| 9 | `lang.go` | 309 | NEW | session created (replaces go_language_toggle.go) |
| 10 | `icon.go` | 32 | PATCHED | file_22 + session fix (moved to root) |
| 11 | `go.mod` | 20 | needs module path update | file_21 |
| 12 | `go.sum` | — | MISSING — run go mod tidy | generated |

### 3b. Assets — assets/

| File | Status | Action required |
|---|---|---|
| `assets/devshield.ico` | MISSING — build fails without it | favicon.io, 2 minutes |
| `assets/placeholder.ico` | MISSING — build.bat pre-flight fails | copy of devshield.ico |

### 3c. PowerShell Scripts — scripts/

| # | File | Lines | Status | Notes |
|---|---|---|---|---|
| 1 | `core/00_core.ps1` | 530 | ready | file_01 |
| 2 | `core/01_first_run.ps1` | 667 | ready | file_02 |
| 3 | `core/02_lhm_bridge.ps1` | 581 | ready | file_03 |
| 4 | `profiles/silent_summer.ps1` | 403 | needs 24H2 fix | file_04 (both versions identical) |
| 5 | `profiles/gaming_gear.ps1` | 483 | needs 24H2 fix | file_05 |
| 6 | `profiles/dev_mode.ps1` | 564 | needs 24H2 fix | file_06 |
| 7 | `profiles/profile_manager.ps1` | 416 | ready | file_07 |
| 8 | `monitor/hardware_dashboard.ps1` | 523 | ready | file_08 |
| 9 | `monitor/network_guardian.ps1` | 542 | needs WSL2 + toast + URL fix | file_09 |
| 10 | `hardening/privacy_enforcer.ps1` | 616 | needs Recall/Copilot domains | file_10 |
| 11 | `hardening/tor_hardening.ps1` | 559 | ready | file_11 |
| 12 | `hardening/rollback.ps1` | 542 | ready | file_12 |

### 3d. Data files — scripts/monitor/

| File | Status | Notes |
|---|---|---|
| `monitor/blocklist_bundled.json` | MISSING | Installer references it. Guardian writes it at runtime from PS var but needs to exist as real file for offline install path. See Phase 1.2 for full content. |

### 3e. CI / Build / Install

| File | Status | Source |
|---|---|---|
| `.github/workflows/build.yml` | ready | file_23 |
| `build.bat` | ready | file_24 |
| `installer/devshield.iss` | ready | file_25 |
| `.gitignore` | ready | file_26 |
| `README.md` | winget install line not live yet | file_27 |
| `LICENSE` | ready — Apache 2.0 | file_28 |

### 3f. Distribution — not yet created

| File | Status | Notes |
|---|---|---|
| `winget/manifests/d/DevShield/DevShield/0.1.0/DevShield.yaml` | TODO | Version manifest |
| `winget/manifests/d/DevShield/DevShield/0.1.0/DevShield.installer.yaml` | TODO | Installer manifest |
| `winget/manifests/d/DevShield/DevShield/0.1.0/DevShield.locale.en-US.yaml` | TODO | Locale manifest |

### 3g. Duplicate files — canonical versions to use

| Discard | Use instead | Reason |
|---|---|---|
| `file_14_psbridge.go` | `ps_bridge.go` (session output) | Inline syscall without build tag |
| `file_18_context__1_.go` | `file_18_context.go` (no suffix) | Has invalid import_() inside function |
| `file_18_context__2_.go` | `file_18_context.go` (no suffix) | Missing package-level imports entirely |
| `file_22_icon.go` in assets/ | `icon.go` (session output, root) | Wrong directory + wrong embed path |
| `file_20_main.go` | `main.go` (session output) | Uses reserved compiler name runtime_KeepAlive |
| `go_language_toggle.go` | `lang.go` (session output) | Contains tray excerpt causing duplicate declarations |
| `language_toggle_system.txt` | Reference only | PS side already correctly in 00_core.ps1 |

---

## 4. Session Bug Fixes

Seven compile-blocking or data-corrupting bugs found and fixed.

### BUG 1 — ps_bridge_windows.go missing (compile fail)
ps_bridge.go called setHideWindow() and getNewWindowAttr() declared as
"implemented in ps_bridge_windows.go" — that file never existed.
FIX: Created ps_bridge_windows.go with correct Windows syscall implementations.

### BUG 2 — newWindowAttr() wrong return type (compile fail)
ps_bridge.go declared newWindowAttr() interface{} but assigned result to
cmd.SysProcAttr which is *syscall.SysProcAttr — type mismatch.
FIX: Changed return type to *syscall.SysProcAttr, added syscall import,
added //go:build windows to ps_bridge.go.

### BUG 3 — runtime_KeepAlive reserved compiler name (undefined behaviour)
main.go defined a user function named runtime_KeepAlive — a name the Go
compiler reserves internally.
FIX: Replaced with var _instanceMutex uintptr package-level variable.

### BUG 4 — TFmt had import "fmt" inside function body (compile fail)
go_language_toggle.go had import "fmt" as a statement inside the TFmt()
function body. Not valid Go — imports must be package-level.
FIX: Moved "fmt" to package-level imports in new lang.go.

### BUG 5 — lang.go tray excerpt caused duplicate declarations (compile fail)
go_language_toggle.go included tray functions (onTrayReady, buildTrayMenu etc.)
already defined in tray.go — duplicate symbol compile errors.
FIX: Created clean lang.go containing only language management. watchConfigFile
fires lang.OnChange callbacks (which reach updateMenuLabels in tray.go)
instead of calling rebuildTrayMenu directly.

### BUG 6 — icon.go in wrong directory with wrong embed path (compile fail)
file_22_icon.go placed in assets/ subdirectory with package main — all
package main files must share one directory. Embed path also wrong.
FIX: Moved icon.go to repo root, corrected path to //go:embed assets/devshield.ico.

### BUG 7 — writeToDisk silently dropped config keys (data loss)
Original writeToDisk used a dsConfig struct with only 4 known fields. Any
key written by context.go (e.g. auto_switch) would be silently dropped on
the next language change write-back.
FIX: Replaced struct with map[string]interface{} round-trip to preserve all keys.

---

## 5. Phase 0 — Ship Blockers

Nothing compiles or runs until these are done.

### 0.1 — assets/devshield.ico (CRITICAL — go build fails without it)
The //go:embed directive is enforced at compile time.
Action:
  1. Go to https://favicon.io/favicon-generator/
  2. Type DS, download zip, extract favicon.ico
  3. Rename to devshield.ico, place at assets/devshield.ico
  Or with ImageMagick: magick convert icon.png -define icon:auto-resize=256,64,48,32,16 assets\devshield.ico

### 0.2 — assets/placeholder.ico (CRITICAL — build.bat pre-flight fails)
Action: Copy-Item assets\devshield.ico assets\placeholder.ico

### 0.3 — go.sum (CRITICAL — no reproducible build)
Action: go mod tidy
(Run after updating the module path in go.mod)

### 0.4 — Update go.mod module path (CRITICAL — must match your GitHub repo)
Edit go.mod line 1: module github.com/YOUR_USERNAME/devshield
Edit build.bat line 7: set MODULE=github.com/YOUR_USERNAME/devshield

### 0.5 — scripts/monitor/blocklist_bundled.json (HIGH)
Installer references it via skipifsourcedoesntexist. Guardian writes it
at runtime from the PS $BUNDLED_TELEMETRY var, but it should exist as a
committed file for offline installs. Content in Phase 1.2.

---

## 6. Phase 1 — v0.1 Production Release

### 1.1 — Update privacy_enforcer.ps1 with 2026 AI/Recall domains
Current domain count: 32 (2025 dataset)
Missing — add to $TELEMETRY_DOMAINS:

  "recall.microsoft.com",            # Windows Recall — screenshots everything
  "prod.recall.microsoft.com",
  "copilot.microsoft.com",           # Copilot Runtime (ships in 24H2)
  "sydney.bing.com",                 # Copilot backend
  "edgeservices.bing.com",           # Edge Copilot
  "assistantservices.microsoft.com",
  "aiassistant.microsoft.com",
  "v10.events.data.microsoft.com",   # ARIA telemetry (massively expanded 24H2)
  "v20.events.data.microsoft.com",
  "browser.pipe.aria.microsoft.com",
  "experimentation.microsoft.com",   # A/B testing for all AI features
  "activity.microsoft.com",          # Activity History — feeds Recall
  "activityhistory.microsoft.com",
  "api.msn.com",                     # MSN / Start AI recommendations
  "ntp.msn.com",
  "aiplatform.microsoft.com",        # Windows AI Studio telemetry
  "telemetry.asusvivo.com",          # ASUS AI Suite (added 2025)
  "rog.telemetry.asus.com",
  "dc.services.amd.com"

Add to $REGISTRY_TWEAKS:
  Disable Windows Recall: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI
    DisableAIDataAnalysis = 1 (DWord)
  Disable Copilot: HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot
    TurnOffWindowsCopilot = 1 (DWord)
  Disable AI Start recommendations: HKCU:\...\Explorer\Advanced
    Start_IrisRecommendations = 0 (DWord)

### 1.2 — Create scripts/monitor/blocklist_bundled.json
Full content (save as this file in the repo):

{
  "version": "2026-06-18",
  "source": "bundled",
  "domains": [
    "telemetry.microsoft.com", "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com", "watson.microsoft.com",
    "df.telemetry.microsoft.com", "sqm.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com", "settings-win.data.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com", "statsfe1.ws.microsoft.com",
    "statsfe2.ws.microsoft.com", "choice.microsoft.com",
    "feedback.microsoft-hohm.com", "pipe.aria.microsoft.com",
    "v10.events.data.microsoft.com", "v20.events.data.microsoft.com",
    "browser.pipe.aria.microsoft.com", "experimentation.microsoft.com",
    "recall.microsoft.com", "prod.recall.microsoft.com",
    "copilot.microsoft.com", "sydney.bing.com", "edgeservices.bing.com",
    "assistantservices.microsoft.com", "aiassistant.microsoft.com",
    "activity.microsoft.com", "activityhistory.microsoft.com",
    "api.msn.com", "ntp.msn.com", "aiplatform.microsoft.com",
    "ads.msn.com", "adnexus.net", "c.msn.com", "bingapis.com",
    "telemetry.asus.com", "auep.amd.com", "dc.telemetry.amd.com",
    "events.gfe.nvidia.com", "telemetry.nvidia.com", "gfe.geforce.com",
    "telemetry.intel.com", "registrationapi.intel.com"
  ],
  "ip_prefixes": [
    "13.107.4.", "13.107.5.", "52.114.", "52.184.",
    "20.42.", "20.189.", "157.56.9", "65.52.100", "65.55.252", "51.104.", "51.105."
  ],
  "telemetry_procs": [
    "CompatTelRunner", "DiagTrackRunner", "DeviceCensus",
    "WerFault", "WerFaultSecure", "musnotification", "usocoreworker",
    "AIXHost", "AiAssistant"
  ]
}

### 1.3 — Fix network_guardian.ps1 — WSL2 false positives
Add to $ALLOWED_PROCESSES:
  "wslhost","wslservice","wslrelay","vmmemWSL","vmmem","LxssManager"

Add to categorisation logic before the UNKNOWN check:
  if ($remoteIP -match "^172\.(1[6-9]|2[0-9]|3[01])\.") {
      $category = "WSL2_INTERNAL"  # Never alert on WSL2 internal traffic
  }

### 1.4 — Fix network_guardian.ps1 — WindowsSpyBlocker URL stale
Windows 10 EOL was October 2025. The win10 path may 404.
Current: "$base/hosts/win10/spy.txt"
Replace with:
  $BLOCKLIST_URLS = @(
      "$base/hosts/win11/spy.txt",
      "$base/hosts/win10/spy.txt",
      "$base/hosts/spy.txt"
  )
  Try each in order, use first that returns HTTP 200.

### 1.5 — Add Windows Toast Notifications to network_guardian.ps1
Add this helper (WinRT, zero dependencies, PS7 only):

  function Send-DSToast {
      param([string]$Title, [string]$Message)
      try {
          $xml = "<toast><visual><binding template='ToastGeneric'>" +
                 "<text>$Title</text><text>$Message</text>" +
                 "</binding></visual></toast>"
          [Windows.UI.Notifications.ToastNotificationManager,
           Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null
          $doc = [Windows.Data.Xml.Dom.XmlDocument]::new()
          $doc.LoadXml($xml)
          $toast = [Windows.UI.Notifications.ToastNotification]::new($doc)
          [Windows.UI.Notifications.ToastNotificationManager]::
              CreateToastNotifier("DevShield").Show($toast)
      } catch {}
  }

Call it after writing a GUARDIAN_TELEMETRY_ALERT event.

### 1.6 — Thermal profiles: Windows 11 24H2 compatibility
In silent_summer.ps1, gaming_gear.ps1, dev_mode.ps1 — add after applying power plan:

  # 24H2 added processor efficiency class — set it explicitly
  powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCESSOREFFICIENCYCLASSCODE 0

  # Detect and warn if Energy Saver is overriding our plan
  $es = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power" `
      -Name "EnergySaverStatus" -ErrorAction SilentlyContinue
  if ($es.EnergySaverStatus -eq 1) {
      Write-DS -EN "Warning: Windows Energy Saver active — may override fan control." `
               -SA "चेतावनी: Windows ऊर्जा-बचत सक्रिय है।" -Level WARN
  }

### 1.7 — WinGet manifests (3 YAML files)
Create at winget/manifests/d/DevShield/DevShield/0.1.0/

DevShield.yaml:
  PackageIdentifier: DevShield.DevShield
  PackageVersion: 0.1.0
  DefaultLocale: en-US
  ManifestType: version
  ManifestVersion: 1.6.0

DevShield.locale.en-US.yaml:
  PackageIdentifier: DevShield.DevShield
  PackageVersion: 0.1.0
  PackageLocale: en-US
  Publisher: DevShield Project
  PublisherUrl: https://github.com/YOUR_USERNAME/devshield
  PackageName: DevShield
  License: Apache-2.0
  ShortDescription: Privacy · Thermal · Network Intelligence for Windows developers
  ManifestType: locale
  ManifestVersion: 1.6.0

DevShield.installer.yaml:
  PackageIdentifier: DevShield.DevShield
  PackageVersion: 0.1.0
  MinimumOSVersion: 10.0.17763.0
  InstallerType: inno
  Scope: machine
  Installers:
    - Architecture: x64
      InstallerUrl: https://github.com/YOUR_USERNAME/devshield/releases/download/v0.1.0/DevShield-v0.1.0-Setup.exe
      InstallerSha256: <SHA256_AFTER_BUILD>
      InstallerSwitches:
        Silent: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART
  ManifestType: installer
  ManifestVersion: 1.6.0

Submission: Fork microsoft/winget-pkgs, add these files, open a PR.
Review takes 1-3 weeks.

### 1.8 — Microsoft Trusted Signing
Cost: $9.99/month
Steps:
  1. portal.azure.com → Marketplace → Trusted Signing → create account
  2. Create Certificate Profile (Public Trust)
  3. Add to build.yml: uses: azure/trusted-signing-action@v0.5
  4. Uncomment in installer/devshield.iss: SignTool=MicrosoftTrustedSigning $f
Alternative: continue with Sigstore + build SmartScreen rep organically.

### 1.9 — Landing page
Minimum viable: single page at devshield.dev or github.io
Must contain: what it does, dashboard screenshot, install command, verify/trust section.

---

## 7. Phase 2 — v0.5 Feature Release

### 2.1 — updater.go (auto-update checker)
New file at repo root. Polls GitHub Releases API on startup and every 24h.
Compares semver against dsVersion constant. Shows tray notification when
update available — never auto-installs. Clicking notification opens
GitHub releases page in browser.
Tray change: add "Update available: vX.X.X" menu item, visible only when
an update exists.

### 2.2 — GPU thermal management
Silent Summer: nvidia-smi -pl 80 (80W limit — RTX 4070 at 200W TDP goes silent)
Gaming Gear: nvidia-smi -pl 200 (full power restored)
Dev Mode: nvidia-smi -pl 120 (balanced)
AMD: equivalent via amdgpu power cap sysfs (via LHM or direct WMI)
Add GPU power readings to dashboard alongside CPU.

### 2.3 — Profile export/import (dotfiles for security)
JSON schema: devshield-profile.json
Fields: name, author, hardware, silent_summer overrides, gaming_gear overrides,
privacy custom_domains, guardian extra_allowed/extra_blocked.
CLI: devshield-profile export > my-profile.json
     devshield-profile import my-profile.json
Community profiles shareable on GitHub like dotfiles.

### 2.4 — ARM64 proper build
Remove continue-on-error: true from CI ARM64 step.
Add ARM64 TDM-GCC or LLVM toolchain.
Validate LHM ARM64 sensor namespaces (Snapdragon X uses different WMI paths).
Adjust thermal profile frequency caps for Snapdragon efficiency curves.

### 2.5 — Scoop bucket
Create bucket repo: github.com/YOUR_USERNAME/scoop-devshield
Manifest: devshield.json with version, url, hash, bin fields.

---

## 8. Phase 3 — v1.0 Rust Rewrite

### 3.1 — Rust crate decisions (lock now)
System tray:   fyne.io/systray  ->  tray-icon (tauri-apps)
Process list:  gopsutil/v3      ->  sysinfo crate
SQLite:        modernc.org/sqlite -> rusqlite
JSON:          encoding/json    ->  serde_json
HTTP:          net/http         ->  reqwest
Config:        manual map       ->  config crate

### 3.2 — Compatibility contract (must not break)
The v1.0 Rust binary must read the same config.json schema,
read the same state.json schema, write to the same events/ folder,
and support the same Task Scheduler task names.
Any schema change requires a migration step in 01_first_run.ps1.

### 3.3 — Migration path
v0.5: Write schema_version: 1 into state.json
v1.0: Read schema_version, run migration if needed
v1.0 installer must handle upgrade from Go v0.x binary gracefully.

---

## 9. Mid-2026 Landscape Backlog

| Item | Impact | Effort | Target Phase |
|---|---|---|---|
| Windows Recall telemetry not blocked | Privacy tool has biggest 2026 gap | Low — add domains | 1.1 |
| Windows 11 24H2 powercfg changes | Thermal profiles may silently no-op | Medium — test + fix | 1.6 |
| WindowsSpyBlocker win10 path stale | Live update silently fails post-Win10 EOL | Low — add fallback URLs | 1.4 |
| WSL2 triggers guardian false positives | Guardian unusable for WSL-heavy devs | Low — extend allowlist | 1.3 |
| No toast notifications | Security alerts invisible to user | Low — 10 lines PS | 1.5 |
| No WinGet manifest | README install command fails | Medium — 3 YAML files + PR | 1.7 |
| SmartScreen warning blocks installs | Kills adoption outside developer circle | Medium — $9.99/mo | 1.8 |
| No auto-update | Users run stale versions | Medium — new Go file | 2.1 |
| No GPU thermal control | Silent Summer doesn't fully silence fans | High — nvidia-smi | 2.2 |
| ARM64 build broken | Copilot+ PC users get wrong binary | High — CI rework | 2.4 |
| No landing page | No credibility, no organic discovery | Low — single HTML | 1.9 |

---

## 10. Build Instructions

### Prerequisites
  winget install GoLang.Go           # Go 1.22+
  choco install tdm-gcc --yes        # GCC for CGO (fyne-io/systray)
  winget install Microsoft.PowerShell  # PS7 for scripts
  go version && gcc --version && pwsh --version   # verify all three

### First build
  git clone https://github.com/YOUR_USERNAME/devshield
  cd devshield
  # 1. Update go.mod module path (line 1)
  # 2. Place assets/devshield.ico
  Copy-Item assets\devshield.ico assets\placeholder.ico
  # 3. Generate go.sum
  go mod tidy
  # 4. Dev build (console visible)
  build.bat dev
  # 5. Release build
  build.bat
  # 6. Launch
  build.bat run

### CI build
  git tag v0.1.0 && git push origin v0.1.0
  GitHub Actions triggers build.yml:
    build x64 + arm64, SHA256, Sigstore sign, create GitHub Release

---

## 11. Pre-Release Testing Checklist

### First run
  [ ] Tray icon appears within 3 seconds
  [ ] First-run UAC fires exactly once
  [ ] 01_first_run.ps1 completes — LHM downloaded, 6 tasks registered
  [ ] ~/.devshield/config.json created with language: "BOTH"
  [ ] ~/.devshield/state.json created
  [ ] ~/.devshield/audit.db created with TRAY_STARTED event

### Thermal profiles
  [ ] Silent Summer applies — state.json shows thermal_mode: "silent"
  [ ] Silent Summer — audit log shows before/after CPU temp delta
  [ ] Silent Summer — fans audibly quieter within 60 seconds
  [ ] Gaming Gear — CPU boost re-enabled, pre-flight fires if temp > 85C
  [ ] Dev Mode — applies, 90% frequency cap confirmed
  [ ] All three profiles survive Windows restart
  [ ] rollback.ps1 -Last restores previous power plan exactly

### Language toggle
  [ ] Tray shows bilingual labels by default (BOTH mode)
  [ ] Language > English only — all labels switch
  [ ] Language > Sanskrit only — all labels switch to Devanagari
  [ ] devshield-lang SA in terminal — tray updates within 3 seconds
  [ ] Language preference persists across restart

### Privacy enforcer
  [ ] Runs — domains added to hosts file
  [ ] vortex.data.microsoft.com resolves to 0.0.0.0 after applying
  [ ] Windows Update still works (whitelist verified)
  [ ] Rollback restores original hosts file exactly

### Network guardian
  [ ] Starts as background job
  [ ] VS Code, Chrome, node — no alerts
  [ ] CompatTelRunner — triggers TELEMETRY alert
  [ ] Alert count appears in tray badge
  [ ] Stop/start via tray works

### Dashboard
  [ ] Opens in new terminal window
  [ ] CPU per-core temps visible with real values
  [ ] GPU temps visible
  [ ] L key toggles language, Q closes cleanly
  [ ] Refreshes every 2 seconds without flicker

### Rollback
  [ ] rollback.ps1 -DryRun -All — lists everything, changes nothing
  [ ] rollback.ps1 -All — undoes all actions
  [ ] System matches pre-DevShield state after full rollback

---

## 12. Release Checklist

### v0.1.0 go/no-go
  [ ] Phase 0 complete — all 5 ship blockers resolved
  [ ] Phase 1.1 — Recall/Copilot domains added
  [ ] Phase 1.2 — blocklist_bundled.json exists and committed
  [ ] Phase 1.3 + 1.4 — WSL2 fix + URL fallback added
  [ ] Phase 1.5 — toast notifications added
  [ ] Phase 1.6 — 24H2 thermal verified on real hardware
  [ ] Full pre-release testing passed on clean Windows 11 VM
  [ ] go.sum committed
  [ ] go.mod module path updated to real repo
  [ ] README.md winget install line commented out until WinGet PR merges
  [ ] SHA256 of installer generated, in release notes

### Within 2 weeks of v0.1.0
  [ ] WinGet manifest PR submitted (Phase 1.7)
  [ ] Microsoft Trusted Signing account created (Phase 1.8)
  [ ] Landing page live (Phase 1.9)
  [ ] v0.1.1 signed binary patch release

---

## 13. Architecture Decisions & Constraints

### Why Task Scheduler instead of COM elevation per operation
UAC on every profile change is unacceptable UX. Task Scheduler with
RunLevel=Highest registered once at first run means the tray triggers
admin operations silently forever after. One UAC prompt, never again.

### Why PS scripts write JSON events instead of touching SQLite directly
SQLite from PowerShell requires a third-party module or COM interop.
File-based queue (write JSON → Go reads and inserts) means PS scripts
have zero dependencies for logging. Standalone scripts still work without
the Go tray running — events queue up and are picked up on next launch.

### Why modernc.org/sqlite instead of mattn/go-sqlite3
mattn/go-sqlite3 requires CGO. modernc.org/sqlite is pure Go — no CGO
for SQLite. This keeps the CGO requirement isolated to fyne.io/systray
(which genuinely needs it for the Windows tray API).

### Why bilingual and not an i18n framework
The custom T(LabelKey) function with a static map is ~100 lines with zero
dependencies. The Sanskrit integration is a design identity feature, not
an internationalisation exercise. A full i18n framework would add complexity
without adding capability relevant to this specific two-language use case.

### Why SQLite WAL mode
WAL allows concurrent readers during writes. watchdog.go reads for alert
counts every 30s while audit.go may be inserting events from the PS queue.
Without WAL, reads block writes — visible latency in tray UI.

### What DevShield will never touch (hard safety constraints)
  Boot configuration (no bcdedit)
  Driver stack (no .sys files)
  WinPE or Recovery partition
  Windows Update infrastructure (explicit whitelist in privacy_enforcer)
  Anything requiring kernel mode

### Canonical file versions for each duplicate pair
  main.go              session output (patched from file_20)
  ps_bridge.go         session output (patched from file_14__1_)
  ps_bridge_windows.go session output (new)
  lang.go              session output (new)
  icon.go              session output (patched from file_22, moved to root)
  context.go           file_18_context.go (clean, no suffix)
  silent_summer.ps1    file_04_silent_summer.txt (both versions identical)
  all other Go files   use the non-duplicated version directly

---

Document maintained by: DevShield development session
Last updated: 2026-06-18
