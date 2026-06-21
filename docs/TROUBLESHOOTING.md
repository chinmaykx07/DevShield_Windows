# Troubleshooting

Find your symptom below. Each entry has a likely cause and a concrete fix. If nothing here matches, see [SECURITY.md](../SECURITY.md) for how to report a problem that might be a real bug or safety issue.

---

## Installation issues

### Windows protected your PC / SmartScreen warning
This is expected, not a bug. See [INSTALL.md](INSTALL.md) Section 4. Click **More info → Run anyway**.

### Installer says PowerShell 7 is missing
```powershell
winget install Microsoft.PowerShell
```
Then close and reopen your terminal and re-run the installer or launch `devshield.exe` directly.

### `gh attestation verify` or `cosign verify-blob` fails
Do not run the installer. This means the binary does not match what the official CI built and signed. See [SECURITY.md](../SECURITY.md).

---

## First-run issues

### Tray icon never appears
1. Check Task Manager for a `devshield.exe` process.
2. If the process is running but no icon shows, click the **^** arrow in the taskbar to show hidden icons.
3. If the app crashed, run it from a terminal to see the error output.

### UAC prompt never appears / first run seems stuck
The first-run script needs that one UAC prompt to register Task Scheduler tasks. If it is not appearing, try running first-run manually:
```powershell
pwsh -File "C:\Program Files\DevShield\scripts\core\01_first_run.ps1"
```

### `~/.devshield/` folder was never created
Run the first-run script manually and read the console output.

---

## Thermal profile issues

### Profile applies but I don't see or feel any difference
1. Open the dashboard and check whether sensors show real values or blank/zero.
2. Some changes take 10–15 seconds to become visible under load.
3. If LibreHardwareMonitor is missing, reinstall or re-run first-run.

### Sensors show 0 / blank in the dashboard
LibreHardwareMonitor either is not installed or is not running.

### Profile says applying for a long time
If it is stuck past ~90 seconds, run rollback for the most recent action and try again.

---

## Privacy enforcer issues

### Windows Update stopped working after applying
This should not happen; Windows Update domains are explicitly whitelisted. If it does, run rollback for privacy changes.

### A website I need stopped working
Use rollback for privacy changes or review the hosts file manually.

---

## Network guardian issues

### Constant alerts for WSL2 / Docker / a tool I use
Review the allowlist in the network guardian script and add trusted entries if needed.

### Toast notifications aren't appearing
Toast notifications are best-effort. The alert is still logged in the audit trail even if the toast does not appear.

---

## Language toggle issues

### Tray and terminal show different languages
The tray polls `config.json` for changes every few seconds. If they are out of sync, check the config file directly.

---

## Rollback issues

### Rollback says it succeeded but the change is still visible
Some settings take a moment to reflect. If it still persists, inspect the audit log and the backup files in `.devshield/backups`.

### Rollback itself fails / reports an error
Use the backup files directly or review the relevant rollback documentation in the user manual.

---

## Update checker issues

### Update available notification won't go away
Click the menu item once — it dismisses that specific version and opens the release page.
