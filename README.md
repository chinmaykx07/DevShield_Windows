# 🛡 DevShield · कवच-यन्त्र

**Privacy · Thermal · Network · AI-agent control — the owner decides what runs and what leaves the machine**

DevShield aims to keep a developer's machine under its owner's control: it watches for AI agents (including undocumented, rogue ones), controls what may leave the machine, blocks telemetry and manages thermal profiles.

There are two variants, at different stages:
- **Linux**: a root daemon plus a CLI (`devshield …`), written in Go. This is where development is focused now. See [docs/USER_MANUAL.md](docs/USER_MANUAL.md) section 2b.
- **Windows**: a tray app (Go) that runs PowerShell 7 scripts, with sensors via LibreHardwareMonitor and a bilingual interface (**English + Sanskrit, द्विभाषिक**). **Several of its core features are known to be broken** (below). It will be fixed after Linux.

## What works today (honest status)

| Feature | Linux | Windows |
|---|---|---|
| AI agent detection (Agent Watch) | ✅ unit-tested; live-tested in namespaces (a catalogued agent, and an uncatalogued program found by behaviour alone: listening on a model port) | ⚠ compiles, **never run on Windows** |
| Block one agent's network / lockdown (tunnel, Tor, chosen users) | ✅ live-tested against the real kernel in namespaces (`test/linux-live/`); not yet with a real VPN/Tor or under systemd | — not implemented |
| Telemetry sinkhole (hosts file) | ✅ unit-tested; restore checked live on a simulated tree | ⚠ script exists, not tested on Windows |
| LAN privacy (LLMNR/mDNS, MAC randomisation) | ⚠ tested on a simulated system only | ⚠ in `tor_hardening.ps1`, not tested |
| Thermal profiles | ⚠ tested on simulated kernel layouts, **not on real hardware** | ⚠ scripts exist, not tested on Windows |
| Network monitor | ✅ live-tested in a namespace (TCP only) | ❌ crashes in its main loop; unknown-process alerts never fire (C5) |
| Undo everything | ✅ `devshield restore-all`, live-tested: thermal, hosts and LAN privacy on a simulated tree; lockdown and allowed/blocked agents on the real kernel in namespaces | ❌ rollback restores nothing and still reports success (C4) |
| Tor kill switch | ⚠ `lockdown on --tor` = lockdown that lets only the Tor daemon's account out; the account lookup is unit-tested and per-user lockdown is live-tested, but never with a real Tor daemon | ❌ creates only *allow* rules, so it blocks nothing (C6) |
| One-time admin setup | — (systemd unit, not yet run under systemd) | ❌ task registration always fails (C1), first run can't run unattended (C2), tray actions stop at a prompt (C3) |

C1–C8 refer to [docs/REVIEW_NOTES_2026-10-20.md](docs/REVIEW_NOTES_2026-10-20.md). DevShield sends no data anywhere and checks for updates only when you click "Check for updates". It does make **DNS lookups on its own**, through your normal resolver: the LLM API host names in its catalog every 15 minutes (Linux daemon and Windows tray, to recognise agent connections), and on Linux the telemetry domains every 30 minutes (for the network monitor). Your DNS server sees these names being looked up.

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

## What it does (Windows tray: read the status table above first)

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

Every profile is designed to read sensor data **before and after** applying and show you the delta. None of this has been tested on a real Windows machine yet, and automatic rollback depends on `rollback.ps1`, which is currently broken (C4).

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

# Remove the hosts-file block ONLY: DiagTrack and the registry tweaks stay
# changed, and rollback.ps1 is currently broken (C4)
pwsh -File scripts\hardening\privacy_enforcer.ps1 -Rollback
```

### Network guardian
Designed to monitor TCP connections, categorise traffic and alert on telemetry or unknown processes. **Currently broken:** the main loop crashes on the first unknown process, so those alerts never fire, and the tray's Stop cannot stop it (C5).

```powershell
pwsh -File scripts\monitor\network_guardian.ps1 -Start    # start background job
pwsh -File scripts\monitor\network_guardian.ps1 -Status   # check status
pwsh -File scripts\monitor\network_guardian.ps1 -Alerts   # view recent alerts
pwsh -File scripts\monitor\network_guardian.ps1 -Stop     # stop
```

### Rollback
Every destructive action saves a backup. **Currently broken:** rollback reads the backup wrongly, restores nothing and still reports success (C4). Until it's fixed, make a Windows restore point before using DevShield.

```powershell
pwsh -File scripts\hardening\rollback.ps1          # interactive list
pwsh -File scripts\hardening\rollback.ps1 -Last    # undo most recent
pwsh -File scripts\hardening\rollback.ps1 -All     # undo everything
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All  # preview only
```

### Language toggle
Switch between English, Sanskrit, or both from the tray menu. There is no `devshield-lang` command (earlier docs described one that was never written); from PowerShell the setting can be changed with the functions in `scripts/core/00_core.ps1`:

```powershell
. scripts\core\00_core.ps1
Get-DSLanguage            # show current
Set-DSLanguage -Lang EN   # EN | SA | BOTH (default)
Switch-DSLanguage         # cycle BOTH → EN → SA
```

Not tested on Windows.

---

## First run

The intended first run scans your hardware, saves a hardware profile to `~/.devshield/hardware_profile.json`, registers admin tasks in Task Scheduler (one UAC prompt) and offers to download LibreHardwareMonitor. **Today this does not work:** the tray never starts first-run setup, task registration always fails, and first run stops at an interactive prompt (C1, C2).

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
- Go as named in `go.mod` (it fetches the patched toolchain itself)
- PowerShell 7 (Windows variant only)
- `build.bat` currently insists on GCC (TDM-GCC) because it sets CGO. That isn't actually needed: the Windows build compiles with `CGO_ENABLED=0` (checked by cross-compiling). This will be simplified when the Windows variant is fixed.

On Linux: `go build -o devshield .`, then follow the install steps in the user manual (section 2b). The network controls need `nftables`.

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

See [docs/ROADMAP_LINUX_FIRST_AND_X402.md](docs/ROADMAP_LINUX_FIRST_AND_X402.md): Linux first (daemon, tray, .deb/.rpm), then fix and test the Windows variant (C1–C8), then macOS.

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
