# 🛡 DevShield · कवच-यन्त्र

**Privacy · Thermal · Network Intelligence — for Windows developers**

DevShield lives in your system tray and does three things no other tool combines:
- **Thermal profiles** — Silent Summer, Gaming Gear, Dev Mode with real before/after sensor verification
- **Privacy hardening** — Telemetry sinkhole, registry tweaks, Tor kill-switch
- **Network watchdog** — Background per-process monitor, alerts on unexpected connections

Built in Go. Scripts in PowerShell 7. Sensor data via LibreHardwareMonitor.  
Bilingual interface: **English + Sanskrit (द्विभाषिक)**.

> ⚠️ Experimental / intermediate-stage warning
> DevShield is currently in an intermediate development stage and has not yet been validated through rigorous, broad real-world testing. The project may contain bugs, incomplete features, or behavior that could affect system stability, privacy settings, or network access. Anyone installing, downloading, or forking this repository should treat it as experimental software and use it at their own risk. We strongly recommend testing it on a disposable or non-critical Windows system, creating a restore point or backup first, and reviewing the scripts before execution.

---

## Project status and credits

- This project is still experimental and not yet rigorously tested.
- For a record of the third-party libraries, SDKs, tools, and upstream projects used by DevShield, see [docs/CREDITS.md](docs/CREDITS.md).

## Install

### Via WinGet (recommended — zero SmartScreen warning)
> **Not yet live.** The WinGet manifest has been submitted but is pending
> Microsoft's review (typically 1–3 weeks). Use Direct download below until
> this command works:
```powershell
# winget install DevShield.DevShield
```

### Direct download
Download `devshield.exe` from [Releases](../../releases).

> **Windows will show "Unknown Publisher"** — click **More Info → Run Anyway**.  
> This is expected for new apps building SmartScreen reputation. See [Trust](#trust) below.

### Requirements
- Windows 10 (build 17763) or Windows 11
- PowerShell 7 — `winget install Microsoft.PowerShell`
- Internet connection (first run only, for LibreHardwareMonitor download)

---

## What it does

### System tray
Click the shield icon in your taskbar. One click applies any profile.

```
🛡 DevShield · कवच-यन्त्र
● Status: 🔇 Silent Summer · मौन-ग्रीष्म
─────────────────────────────────
🔇 Silent Summer · मौन-ग्रीष्म
🎮 Gaming Gear · क्रीडा-आवृत्ति
💻 Dev Mode · विकास-अवस्था
─────────────────────────────────
🔒 Privacy · गोपनीयता
🌐 Network Guardian · जाल-रक्षक
📋 Open Dashboard
↩  Rollback…
🌐 Language: English + Sanskrit
⚙  Auto-switch: OFF
✕  Quit · विराम
```

### Thermal profiles

| Profile | Boost | Frequency | Fans | Best for |
|---|---|---|---|---|
| 🔇 Silent Summer | OFF | 2800 MHz cap | Quiet | Writing, calls, summer heat |
| 🎮 Gaming Gear | Aggressive | Unlimited | Turbo | Games, benchmarks, rendering |
| 💻 Dev Mode | Efficient | 90% cap | Balanced | Coding, compiling, Docker |

Every profile reads sensor data **before and after** applying, shows you the delta, and verifies the change actually worked. If it fails midway, it automatically rolls back.

### Hardware dashboard
```powershell
# Or click "Open Dashboard" from tray
pwsh -File scripts\monitor\hardware_dashboard.ps1
```

Live HWiNFO-style terminal dashboard. Updates every 2 seconds. Press `L` to toggle language, `Q` to quit.

### Privacy enforcer
Blocks 40+ telemetry domains at DNS level via hosts file sinkhole.  
Disables DiagTrack service. Applies registry privacy tweaks.  
**Never blocks Windows Update** — explicitly preserved.

```powershell
# Apply
pwsh -File scripts\hardening\privacy_enforcer.ps1

# Remove (full rollback)
pwsh -File scripts\hardening\privacy_enforcer.ps1 -Rollback
```

### Network guardian
Monitors all TCP connections, categorises traffic, alerts on telemetry or unknown processes.

```powershell
pwsh -File scripts\monitor\network_guardian.ps1 -Start    # start background job
pwsh -File scripts\monitor\network_guardian.ps1 -Status   # check status
pwsh -File scripts\monitor\network_guardian.ps1 -Alerts   # view recent alerts
pwsh -File scripts\monitor\network_guardian.ps1 -Stop     # stop
```

### Rollback — undo anything
Every destructive action saves a backup. Rollback restores your exact pre-DevShield state.

```powershell
pwsh -File scripts\hardening\rollback.ps1          # interactive list
pwsh -File scripts\hardening\rollback.ps1 -Last    # undo most recent
pwsh -File scripts\hardening\rollback.ps1 -All     # undo everything
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All  # preview only
```

### Language toggle
Switch between English, Sanskrit, or both from the tray or terminal at any time.

```powershell
# In any terminal session
devshield-lang          # show current
devshield-lang EN       # English only
devshield-lang SA       # संस्कृत केवलम्
devshield-lang BOTH     # द्विभाषिक (default)
devshield-lang toggle   # cycle to next
```

---

## First run

On first launch, DevShield automatically:

1. Scans your hardware (CPU, GPU, motherboard, RAM, storage, NICs)
2. Saves a hardware profile to `~/.devshield/hardware_profile.json`
3. Registers admin tasks in Task Scheduler (one UAC prompt, never again)
4. Offers to download LibreHardwareMonitor for full sensor access

---

## Trust

DevShield is designed to be **verifiable**, not just trusted.

### Every release includes:
| File | What it proves |
|---|---|
| `checksums.txt` | SHA256 hash of every binary |
| `devshield.exe.sig` | Sigstore keyless signature |
| `devshield.exe.pem` | Sigstore certificate |
| GitHub Attestation | Cryptographic proof this binary came from this repo's CI |

### Verify a release
```powershell
# Option 1 — GitHub Attestation (requires gh CLI)
gh attestation verify devshield.exe --repo chinmaykx07/DevShield_Windows

# Option 2 — Sigstore signature
cosign verify-blob devshield.exe `
  --signature devshield.exe.sig `
  --certificate devshield.exe.pem

# Option 3 — Manual SHA256
(Get-FileHash devshield.exe -Algorithm SHA256).Hash
# Compare against checksums.txt
```

### Why the SmartScreen warning?
Windows shows "Unknown Publisher" on any new app until it accumulates enough downloads to build **SmartScreen reputation**. This takes roughly 500–2000 installs. The warning is a soft gate (click More Info → Run Anyway), not a hard block. The presence of a Sigstore signature and GitHub attestation is actually stronger proof of integrity than a paid certificate — anyone can verify it independently.

---

## How it works

```
devshield.exe  (Go — system tray, state management)
    │
    ├── Reads ~/.devshield/state.json    (current thermal mode)
    ├── Reads ~/.devshield/config.json   (language, auto-switch pref)
    ├── Reads ~/.devshield/audit.db      (SQLite — all events + alerts)
    │
    └── Triggers via Task Scheduler (RunLevel=Highest, no UAC)
            │
            ├── scripts/profiles/silent_summer.ps1
            ├── scripts/profiles/gaming_gear.ps1
            ├── scripts/profiles/dev_mode.ps1
            ├── scripts/hardening/privacy_enforcer.ps1
            ├── scripts/hardening/tor_hardening.ps1
            ├── scripts/monitor/network_guardian.ps1
            └── scripts/hardening/rollback.ps1
                    │
                    └── LibreHardwareMonitor  (sensor backend)
```

PS scripts write events to `~/.devshield/events/`. The Go tray app watches that folder and inserts events into `audit.db` every 2 seconds. PS scripts never touch SQLite directly.

---

## Building from source

### Requirements
- Go 1.22+
- TDM-GCC (for CGO): https://jmeubank.github.io/tdm-gcc/
- PowerShell 7

```powershell
# Clone
git clone https://github.com/chinmaykx07/DevShield_Windows
cd DevShield_Windows

# Add your icon (see assets/icon.go for instructions)
# assets/devshield.ico must exist before building

# Build
build.bat               # release build → dist\devshield.exe
build.bat dev           # dev build (console visible)
build.bat run           # build + launch immediately
build.bat clean         # remove dist\
```

### Build the installer (optional)
Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php):
```powershell
iscc installer\devshield.iss
# Output: installer\Output\DevShield-v0.1.0-Setup.exe
```

---

## File structure

```
devshield/
├── *.go                    Go source (tray app)
├── assets/icon.go          Embedded tray icon
├── scripts/
│   ├── core/               Shared PS functions, hardware detection, LHM bridge
│   ├── profiles/           Thermal profiles + profile manager
│   ├── monitor/            Hardware dashboard + network guardian
│   └── hardening/          Privacy enforcer, Tor hardening, rollback
├── installer/devshield.iss Inno Setup installer
├── build.bat               Local build script
└── .github/workflows/      CI: build + sign + release
```

---

## Roadmap

- **v0.5** WinGet catalog submission (zero SmartScreen), Scoop bucket, auto-update checker, JSON profile export ("dotfiles for security")
- **v1.0** Rewrite core in Rust for memory-safe, zero-overhead binary. Microsoft Trusted Signing ($9.99/mo) for mainstream users.

---

## Contributing

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-change`
3. Test your PS scripts manually before committing
4. Run `build.bat` to verify the Go layer compiles
5. Open a PR — describe what you tested

Script contributions welcome. Please follow the NASA 8-step operation pattern (Pre-flight → Assert → Backup → Act → Verify → Report → Log → Fault-safe) used throughout.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

LibreHardwareMonitor is MPL 2.0 — see https://github.com/LibreHardwareMonitor/LibreHardwareMonitor.

---

*DevShield — Privacy · गोपनीयता &nbsp;·&nbsp; Thermal · तापनियंत्रण &nbsp;·&nbsp; Network · जाल-निरीक्षण*
