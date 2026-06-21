# Installing DevShield

This guide covers everything from "what do I need first" to "how do I know it actually installed correctly." If you hit a problem partway through, check [TROUBLESHOOTING.md](TROUBLESHOOTING.md) — most install issues have a known fix there.

> ⚠️ Warning
> This project is still experimental and not yet rigorously tested. The installer and PowerShell scripts may change without notice and can make system-level changes. Do not install on mission-critical or production systems unless you understand the risks and have backups or a restore point.

---

## 1. Before you install

### System requirements
- Windows 10, build 17763 (version 1809) or later, or Windows 11
- PowerShell 7 — DevShield's scripts require it; Windows' built-in PowerShell 5.1 will not work
- Administrator access (needed once, at first run)
- Internet connection for first run only (downloads LibreHardwareMonitor)

### Install PowerShell 7 first, if you don't have it
```powershell
winget install Microsoft.PowerShell
```
Verify it worked:
```powershell
pwsh --version
```
Should print `PowerShell 7.x.x`. If `pwsh` isn't found after installing, close and reopen your terminal — PATH changes do not apply to already-open windows.

---

## 2. Choose an install method

### Option A — WinGet (not yet available)
```powershell
# winget install DevShield.DevShield
```
This line is intentionally commented out. The WinGet manifest has been submitted to Microsoft's package repository but is still in review. Once it is live, this becomes the recommended path — it installs with zero SmartScreen warning. Until then, use Option B.

### Option B — Direct download (use this for now)
1. Go to the [Releases page](../../releases) of this repository
2. Download `DevShield-v0.1.0-Setup.exe` from the latest release
3. Before running it, verify it is genuine — see Section 3 below
4. Run the installer

---

## 3. Verify the installer before running it

DevShield's releases are cryptographically signed and attested. This step is optional but strongly recommended, especially the first time you install from a new release.

```powershell
# Option 1 — GitHub Attestation
gh attestation verify DevShield-v0.1.0-Setup.exe --repo chinmaykx07/DevShield_Windows

# Option 2 — Sigstore signature
cosign verify-blob DevShield-v0.1.0-Setup.exe `
  --signature DevShield-v0.1.0-Setup.exe.sig `
  --certificate DevShield-v0.1.0-Setup.exe.pem

# Option 3 — Manual SHA256 comparison
(Get-FileHash DevShield-v0.1.0-Setup.exe -Algorithm SHA256).Hash
# Compare the output against checksums.txt from the same release
```

If any of these fail on an official release, do not run the installer and report it — see [SECURITY.md](SECURITY.md).

---

## 4. The SmartScreen warning (expected, here's why)

When you run the installer, Windows will likely show:

> Windows protected your PC
> Microsoft Defender SmartScreen prevented an unrecognized app from starting.

This is expected and not a sign of a problem. Click **More info** and then **Run anyway**.

---

## 5. Running the installer

The Inno Setup installer will:
- Ask for administrator privileges (required)
- Check for PowerShell 7 and warn you if it is missing
- Let you choose Desktop and Start Menu shortcuts
- Install to `Program Files\DevShield` by default

At the end, it offers to launch DevShield immediately. You can uncheck this and launch later from the Start Menu.

---

## 6. What happens on first run

The first time `devshield.exe` runs, it automatically:

1. Shows the tray icon within a few seconds
2. Triggers `01_first_run.ps1`, which:
   - Scans your hardware
   - Saves the result to `%USERPROFILE%\.devshield\hardware_profile.json`
   - Shows exactly one UAC prompt to register Task Scheduler tasks
   - Registers six Task Scheduler tasks under a `DevShield` folder
   - Offers to download LibreHardwareMonitor
3. Creates the DevShield home folder at `%USERPROFILE%\.devshield\` containing `config.json`, `state.json`, and an empty `audit.db`

---

## 7. Verifying the install worked

Check each of these:

```powershell
# 1. The home folder exists
Test-Path "$env:USERPROFILE\.devshield\config.json"
Test-Path "$env:USERPROFILE\.devshield\state.json"

# 2. Task Scheduler tasks are registered
schtasks /Query /TN "DevShield\DS_SilentSummer" /FO LIST

# 3. The tray icon is running
Get-Process devshield -ErrorAction SilentlyContinue
```

If any of these fail, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) → "First run didn't complete correctly."

---

## 8. Uninstalling

1. Settings → Apps → DevShield → Uninstall (or via the Start Menu shortcut)
2. The uninstaller will ask whether to remove your DevShield data folder (`~/.devshield/`) — this contains your hardware profile, audit logs, and backup files used by rollback
3. After uninstalling, verify the Task Scheduler tasks are gone:
   ```powershell
   schtasks /Query /TN "DevShield\DS_SilentSummer" /FO LIST
   ```

---

## Next steps

Once installed, read [USER_MANUAL.md](USER_MANUAL.md) — specifically the Safe Use section — before applying any thermal profile or privacy hardening for the first time.
