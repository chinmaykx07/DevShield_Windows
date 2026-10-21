# DevShield — Full Code Review Notes

Review date: 2026-10-20
Scope: every file in the repo, read in full: 15 Go files, 12 PowerShell scripts, the CI workflow, `build.bat`, the Inno Setup installer, the winget manifests and the docs.

## How this was checked

| Check | Result |
|---|---|
| `go vet ./...` (Linux) | Clean |
| `GOOS=windows go vet ./...` and `go build` | Clean. Builds with `CGO_ENABLED=0`, so GCC is not actually needed. |
| PowerShell 7.4 AST parse of all 12 scripts | 0 parse errors |
| PSScriptAnalyzer 1.22 | Mostly style warnings. 3 real hits (`$profile` automatic var), plus unused variables listed below. |
| Runtime simulations in pwsh (Linux) | Confirmed: rollback data mismatch, guardian loop crash, `(if …)` runtime error, `-StartWhenAvailable $true` binding error |
| Not possible here | Anything Windows-only: Task Scheduler, powercfg, LHM WMI, firewall, registry. Findings for these come from reading the code and Microsoft docs, and are marked **(verify on Windows)** where there is doubt. |

---

## 1. How the system actually fits together

```
devshield.exe (Go tray)
 ├─ schtasks /Run "DevShield\DS_*" ──► pwsh -NonInteractive -File <script>.ps1    (elevated task)
 │      └─ fallback: Start-Process pwsh -Verb RunAs ... -NoConfirm                 (UAC)
 ├─ polls ~/.devshield/state.json every 5s   ◄── written by scripts (Set-DSStateKey)
 ├─ ingests ~/.devshield/events/evt_*.json every 2s → audit.db (SQLite), then DELETES the file
 ├─ reads/writes ~/.devshield/config.json (language, auto_switch)  ◄── also written by scripts
 └─ checks GitHub releases every 24h

scripts/core/00_core.ps1     shared helpers (Write-DS, state/config, backups, audit events)
scripts/core/01_first_run.ps1  hardware discovery + task registration + LHM download
scripts/core/02_lhm_bridge.ps1 sensor reads via LibreHardwareMonitor WMI (root\LibreHardwareMonitor)
profiles/*                   powercfg changes (AC values only) + before/after sensor reads
hardening/*                  hosts sinkhole + registry, Tor/LLMNR/NetBIOS/MAC/firewall, rollback
monitor/*                    background guardian (Start-Job), live dashboard
```

The design is sensible. Almost all the serious problems sit where two parts meet: Go↔PowerShell arguments, script↔script data formats, and job/process lifetimes.

---

## 2. Critical: core features that cannot work as written

### C1. Scheduled tasks never get registered
Three independent failures, any one of which is enough:
- `01_first_run.ps1:404`: `New-ScheduledTaskSettingsSet ... -StartWhenAvailable $true`. `-StartWhenAvailable` is a switch, and the cmdlet has no positional parameters, so `$true` raises *"A positional parameter cannot be found that accepts argument 'True'"*. The `try` catches it, so **every task fails to register**, even when running as admin. (Reproduced. The parameter definition was confirmed in Microsoft Learn docs.)
- `01_first_run.ps1:372`: when not admin, the script relaunches itself elevated with `-SetupTasksOnly`. The file has no `param()` block and no top-level code, so the elevated process only defines functions and exits.
- `00_core.ps1:33`: `$DS_SCRIPTS = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent` resolves to the **install root**, not `…\scripts`. Task actions are then built as `<root>\profiles\silent_summer.ps1`, a path that doesn't exist (`01_first_run.ps1:390`).

### C2. Nothing runs first-run setup, and first-run can't run unattended
- The Go app never triggers `01_first_run.ps1`. It only runs inside `Initialize-DevShield` when some script runs and `hardware_profile.json` is missing.
- That first script is usually started hidden with `-NonInteractive` (a task or the UAC fallback), and first-run calls `Read-Host` (`01_first_run.ps1:446`), which throws in that mode.

### C3. Tray actions run scripts without `-NoConfirm`
- Task actions are `-NonInteractive -WindowStyle Hidden -File <script>` (`01_first_run.ps1:393`). Every profile, privacy and Tor script calls `Read-Host` unless `-NoConfirm` is passed (`silent_summer.ps1:117`, `gaming_gear.ps1:322`, `dev_mode.ps1:391`, `privacy_enforcer.ps1:550`, `tor_hardening.ps1:303`). Under `-NonInteractive` this throws, so **every tray-triggered change fails** at the confirmation step.
- `DS_Guardian` runs `network_guardian.ps1` with no `-Start`, which only prints status.
- `ps_bridge.go:180` (UAC fallback) adds `-NoConfirm` to every script, including `rollback.ps1` and `network_guardian.ps1`, which don't have that parameter. That is a binding error.

### C4. Rollback restores nothing, then reports success
- `New-DSBackup` saves `{ type, timestamp, file, data: { …actual values… } }` (`00_core.ps1:457`).
- `rollback.ps1:74` reads the file and passes the **outer** object as `Data`, so `$d.scheme_guid`, `$d.boost_mode`, `$d.hosts_content`, `$d.registry_before`, `$d.adapters` and so on are all `$null`. (Reproduced.)
- What happens as a result:
  - **powercfg**: 0 settings restored, reported as SUCCESS.
  - **privacy**: hosts, registry and DiagTrack are skipped.
  - **Tor**: firewall rules are removed, LLMNR is forced to 1, NetBIOS and MAC are skipped.
- Each "successful" restore then **renames the backup to `*.restored.json`** (`rollback.ps1:414`). The listing glob `*.json` (`rollback.ps1:68`) still matches those, so restored backups reappear in the list and `-All` replays them. `tor_mac_*.json` files also show up as an unknown type `tor_mac` and count as failures.

### C5. Network guardian
- **Crash in the main loop** (`network_guardian.ps1:407-410`, added in the last commit "Integrate uploaded PowerShell fixes"):
  - A toast call was pasted after the telemetry `continue`. It uses undefined `$procName`/`$remoteIP` and calls `Send-DSToast` and `Write-DS -PassThru`. Neither function exists inside the `Start-Job` process, and `Write-DS` has no `-PassThru` anyway.
  - Result: the first unknown process throws, the `catch` writes `GUARDIAN_POLL_ERROR`, and the rest of that poll is skipped. **`GUARDIAN_UNKNOWN_PROCESS` alerts can never fire, and the log fills with a poll error every 10s.** (Reproduced.)
- **Job lifetime**: `Start-Job` jobs belong to the PowerShell process that started them, so the guardian dies when the task's `pwsh` exits.
  - `-Stop` runs in a new process and never finds the job.
  - `state.json` is left with `guardian_running = true`.
- **Detection**: the domain list is passed to the job but never used, because there is no DNS or remote-name lookup. "Watching N domains" is misleading. IP prefixes such as `20.42.`, `52.114.` and `20.189.` cover very large shared Azure ranges.

### C6. Tor "kill-switch" doesn't block anything
`tor_hardening.ps1:418-462` only creates **Allow** rules (plus a disabled sentinel). Windows Firewall's default outbound action is Allow, so all non-Tor traffic still flows. The CHANGELOG, README and script header all describe a "Tor-only outbound" kill-switch. This is a safety claim users may rely on.

### C7. App hangs on Quit (FIXED alongside Agent Watch, regression test in `audit_test.go`)
`audit.go:132` `closeAudit` holds `auditMu.Lock()` and calls `writeAuditDirect`, which calls `auditMu.RLock()`. `sync.RWMutex` is not re-entrant, so this deadlocks on every Quit.

### C8. Tray opens scripts the wrong way
- `ps_bridge.go:228`: Windows Terminal is launched with `powershell.exe` (5.1), but every script has `#Requires -Version 7.0`. So the dashboard and rollback windows fail whenever WT is installed (default on Win 11).
- Both launch paths also pass `-NonInteractive`, which breaks the rollback menu and the dashboard key handling.
- These windows are **not elevated**, so "Remove Sinkhole (Rollback)" and any restore from the rollback window fail at `Assert-DSAdmin`.

---

## 3. High: wrong behaviour or silent failures

### Thermal profiles (`profiles/*.ps1`)
- **AC only.** Every change uses `powercfg -setacvalueindex`. On a laptop running on battery, none of the profiles change anything.
- **Unrecorded side change.** After verification, all three profiles run `powercfg /setacvalueindex|/setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCESSOREFFICIENCYCLASSCODE 0` (`silent_summer.ps1:230`, `gaming_gear.ps1:422`, `dev_mode.ps1:504`).
  - It isn't backed up and isn't rolled back.
  - It writes DC values too.
  - Gaming Gear sets "prefer efficiency".
  - The alias likely doesn't exist **(verify on Windows)**. `try/catch` can't catch a native exe's failure, so errors just print.
- **Display timeout is never restored.** Dev Mode sets the display timeout to "never". Switching to Silent or Gaming afterwards doesn't restore it; only a rollback of that specific backup would, and rollback is broken (C4).
- **Dev Mode's 90% max processor state** disables turbo on most Intel/AMD systems, which contradicts "compile fast" and makes the boost-mode setting irrelevant.
- **Dev environment scan is always empty.** `dev_mode.ps1:348` runs `Get-DevContext` in `Start-Job`, where the function and `$DEV_PROCESS_MAP` don't exist. Separately, `"notepad++"` used as a regex (`dev_mode.ps1:177`) is invalid and would throw if the job did run.
- **Verification is weak when LHM is missing.**
  - Silent: `$actualFreq = 0` makes `$freqVerified` always true.
  - Gaming: CPU temp reads as 0, so the projected temp is +20°C and always "SAFE". It should say "no sensor data".
- **Vendor fan control is probably a no-op.** The `root\WMI ASUSManagement` class with a `SetFanMode` method most likely doesn't exist **(verify on Windows)**. Gaming also changes the fan mode without backing up the previous one.

### Privacy enforcer (`hardening/privacy_enforcer.ps1`)
- **Tamper Protection check looks inverted.** `:234` treats registry values 4 and 5 as "enabled", but Defender uses 5 = on and 4 = off **(verify on Windows)**. With TP off, the hosts step would be skipped. The fallback reads `Get-MpPreference.DisableTamperProtection`, which isn't a real property; the real one is `(Get-MpComputerStatus).IsTamperProtected`.
- **Re-applying can drop domains.** When the domain list grows, the new block contains only the *new* domains and replaces the old block, so previously blocked domains are dropped (`:307-345`).
- **Verification counts failures as passes.** Any DNS exception, including having no network, counts as "blocked" (`:376`).
- **Rollback is incomplete.** `-Rollback` only removes the hosts block; registry and DiagTrack stay changed. `rollback.ps1` restores only 5 of the 10 registry tweaks (the 24H2 AI keys are missing).
- **Risks worth documenting:**
  - Some listed hosts are used by Edge, Teams or Office features (`config.edge.skype.com`, `settings-win.data.microsoft.com`, `api.msn.com`, `edgeservices.bing.com`).
  - Defender may flag hosts entries that block Microsoft telemetry, which can revert the change.
  - `AllowTelemetry=0` is only honoured on Enterprise/Education editions.
- **Line endings.** The hosts file is rewritten with LF line endings, which Windows tolerates.

### Tor hardening rollback
- `tor_hardening.ps1:209` and `rollback.ps1:314` set the LLMNR *policy* value to 1 instead of deleting it when no policy existed before.
- **Bad MAC backups:**
  - The MAC backup file name only goes down to the second (`tor_mac_<yyyyMMddHHmmss>.json`), so with two Wi-Fi adapters one backup overwrites the other.
  - Applying twice saves the *randomised* MAC as the "original".
- Restore writes the hardware MAC as an override instead of removing `NetworkAddress`.

### LHM / sensors (`02_lhm_bridge.ps1`, `01_first_run.ps1`)
- **The "SHA256 verified" claim doesn't hold.** It only checks if the release notes contain a hash, and LHM release notes don't, so in practice nothing is verified.
- **Unknown launch flag.** `--no-gui` is not a documented LHM switch **(verify on Windows)**.
- **Admin required.** LHM's WMI provider and driver need admin, so the non-elevated dashboard falls back to limited WMI.
- **Repeated startup attempts.** `Get-DSAllSensors` calls `Start-DSLHM` every time; the dashboard does this every 2s. When LHM is missing, each tick prints warnings over the dashboard and can wait up to 4s.

### Shared output helpers
- **`-Level HEADER` is not a valid level.** It appears **25 times** but isn't in `Write-DS`'s `ValidateSet`, so every section heading prints a parameter error instead.
- **`(if …)` is a runtime error** ("The term 'if' is not recognized"):
  - `00_core.ps1:289`: `Write-DSTable` when a row has `Delta`.
  - `hardware_dashboard.ps1:344`: every tick when drive data exists.
  - Fix: use `$(if …)`.
- **`return if (…)`** at `01_first_run.ps1:261` fails the same way, for GPUs that reach the fallback branch (e.g. Intel Arc, iGPUs reporting ≥2 GB).
- **Broken string concatenation.** `01_first_run.ps1:468,470` pass `+ " " * 20 +` to `Write-Host` as separate arguments, which prints garbled box lines.

### Events are deleted before PowerShell reads them
The Go tray deletes `evt_*.json` within about 2s of ingesting them. Several scripts read history or alerts *from that folder*, so they show nothing while the tray is running:
- `profile_manager.ps1:210` (history)
- `network_guardian.ps1:517,537` (status and alerts)
- `hardware_dashboard.ps1:379` (event tail)

### Go side
- **Auto-switch almost always picks Dev mode.** `context.go:179-195` uses `strings.Contains` on short names (`go`, `code`, `atom`, `origin`, `node`), so `logonui`, `GoogleUpdate` and others match Dev. It also falls back to Dev outside quiet hours.
- **Timeouts are reported as success.** `ps_bridge.go:139-148`: `RunTaskAndWait` returns no error on timeout, so `thermal.go` logs `PROFILE_APPLY_DONE ok`. When the target mode is already active, the poll returns immediately.
- **Tray status can stick.** `tray.go:271`: re-applying the current mode leaves the status at "Applying…", because the mode-change callback never fires.
- **Guardian menu items never update.** Start/Stop items don't refresh (`watchdog.go` only fires callbacks on alert count changes), and `updateGuardianItems` runs before the state changes.
- **Audit timestamps sort wrongly.** PowerShell writes local time with an offset, Go writes UTC `Z`, and `ORDER BY timestamp` compares the strings. `GetAlertCount` also ignores `GUARDIAN_UNKNOWN_PROCESS` and uses the UTC day.
- **`config.json` can lose settings.** Go (`lang.go`, `context.go`) and the scripts all rewrite the whole file with no locking. `SetDSConfigKey` also fails silently if `~/.devshield` doesn't exist yet.
- **Version stamping does nothing.** `-X main.dsVersion=…` in `build.bat` and CI has no effect because `dsVersion` is a **const** (`main.go:19`). The updater always believes the version is 0.1.0.

### Dashboard
- `hardware_dashboard.ps1:488`: `[P]` opens `$PSScriptRoot\profile_manager.ps1`, but the dashboard is in `monitor\` and the profile manager is in `profiles\`.
- `$gpu.type` doesn't exist in sensor data (it's only in the hardware profile), so the label renders as `[NVIDIA · ]`.
- The connection count shows 0 on two of every three ticks.

### Installer / release
- **Data folder isn't removed on uninstall.** The uninstaller looks in `{userappdata}\.devshield` (`AppData\Roaming`), but data lives in `%USERPROFILE%\.devshield`.
- **Uninstall leaves system changes behind.** It doesn't remove the `\DevShield\` scheduled tasks, the hosts block, the firewall rules or the LHM process. `docs/INSTALL.md` says the tasks are removed.
- **The tray runs as admin after install.** `PrivilegesRequired=admin` plus a postinstall launch without `runasoriginaluser` starts the tray elevated.
- `[Tasks] ... Flags: checked`: `checked` is likely not a valid Inno flag **(verify with `iscc`)**.
- **No installer in CI.** CI never builds the installer, so `DevShield-v0.1.0-Setup.exe` (referenced by winget) is never produced. The arm64 setup in the winget manifest doesn't exist anywhere.
- **ARM64 build always fails.** CI cross-compiles with `CGO_ENABLED=1` and no ARM64 toolchain. `CGO_ENABLED=0` would let both architectures build, and the TDM-GCC steps could then be removed.
- **Signing on PRs.** CI runs cosign and attestation on PRs; fork PRs will fail without an OIDC token.

---

## 4. Medium / low
- `instance_windows.go:31`: the `err.(syscall.Errno)` type assertion is fine in practice, but `errors.Is(err, windows.ERROR_ALREADY_EXISTS)` is safer.
- `updater.go`: dismissing an update isn't saved, so it re-notifies after a restart.
- `audit.go:375`: IDs are made from nanosecond timestamps, combined with `INSERT OR REPLACE`. A collision would silently overwrite an event.
- `lang.go:watchConfigFile`: fires a second refresh after every tray-side change (harmless).
- `main_stub.go` is an empty file and can be deleted.
- `profile_manager.ps1:87` and `01_first_run.ps1:35,609` assign to `$profile` (an automatic variable). It works, but should be renamed.
- `privacy_enforcer.ps1:341`: `Lines[0..(BlockStart-1)]` with `BlockStart = 0` yields `[0, -1]`. This is an edge case and only happens if the block is at the top of the file.
- Unused variables (from PSScriptAnalyzer): `dev_mode.ps1:195,340`, `hardware_dashboard.ps1:227,357,358`, `tor_hardening.ps1:59,78`, `network_guardian.ps1:501`.
- `network_guardian.ps1` `Update-DSBlocklist` says "SHA256-verified", but it only computes and logs the hash.
- `scripts/monitor/blocklist_bundled.json` is shipped but **never read** by any script. Both scripts use inline lists. `docs/USER_MANUAL.md:116` tells users to edit it.
- `build.bat` requires GCC, which isn't needed. Dev builds get version `0.1.0-dev-dev`.
- `tor_hardening.ps1` and `profile_manager.ps1` have no tray menu entries. That's fine, but `DS_TorHarden` is counted in `AreTasksRegistered`.

## 5. Docs drift
- **CHANGELOG** still lists `INSTALL/USER_MANUAL/TROUBLESHOOTING` and `go.sum` as missing; all of them exist.
- **CHANGELOG/README** describe a Tor "kill-switch", "automatic rollback on failure" and "SHA256 verified" LHM. See C4, C6 and the LHM notes above.
- **INSTALL.md** says six tasks are registered (the code defines eight) and that uninstall removes them (it doesn't).
- **`SECURITY.md`** exists both at the repo root and in `docs/` with identical content; the commit message said it was moved.
- **`SESSION_STATUS.md` / `SESSION_HANDOFF.md`** are accurate that no Windows runtime testing has happened. These notes confirm that the first such run would hit C1 to C3 immediately.

---

## 6. Suggested fix order
1. **Make the basic flow work:** C1 (task registration), C2 (first-run trigger and non-interactive mode), C3 (`-NoConfirm`, `-Start`, fallback args), C8 (pwsh, elevation), C7 (deadlock).
2. **Make undo trustworthy:** C4 (read `.data`, exclude `*.restored.json` and `tor_mac_*`, restore all registry keys and display timeout). Do this before anyone runs the hardening scripts on a real machine.
3. **Fix or rename safety features:** C6 (implement real blocking, or stop calling it a kill-switch), and the Tamper Protection mapping.
4. **Guardian:** remove the misplaced toast block (C5), and run the guardian as a long-lived process (or a task that stays running) instead of `Start-Job`.
5. **Shared PowerShell helpers:** add `HEADER` to `Write-DS`, fix the `(if …)` and `return if` cases, and move history/alert reads to the SQLite DB (or stop deleting events).
6. **Profiles:** set DC values too, drop or back up the `PROCESSOREFFICIENCYCLASSCODE` block, restore the display timeout when switching, and say "no sensor data" instead of reporting a pass.
7. **Release:** make `dsVersion` a `var`, use `CGO_ENABLED=0`, build the installer in CI, and fix uninstall cleanup.
8. Update the docs to match.

---

## 7. Added by the 2026-10-21 audit (independent re-review)

**Status of C1–C8 in the current code:** C7 is fixed. C1–C6 and C8 are **still unfixed**: the scripts have not changed since commit `15989a8`.

**New Windows-side findings** (Go tray; read, not run, since pwsh is not available here):
- **W1. The UAC fallback can't start any script** (`ps_bridge.go:169-171`). The `-File \"%s\"` sits inside a PowerShell single-quoted string, so pwsh receives backslash+quote and the path is cut at the first space (or keeps literal quotes). Today schtasks always fails (C1), so this fallback is the only path left, and it doesn't work either.
- **W2. A profile apply that times out is logged as success** (`ps_bridge.go:139-145` with `thermal.go:111-124`). `RunTaskAndWait` returns the old state with a nil error on timeout, and the tray logs `PROFILE_APPLY_DONE … ok`. The status line also stays at "Applying…" whenever the mode doesn't change.
- **W3. Tray buttons fail silently** (`tray.go:234-260`). Privacy Apply ignores the `RunTask` error and resets its label at once. Guardian Start lacks `-Start` (C3). Guardian Stop starts a new non-elevated process that can't see the `Start-Job` job (C5).
- **W4. Sanction can approve the wrong agent** (`tray_agents.go:62-69`). A menu slot can be refilled with a different agent between reading and clicking. The click should carry the agent's fingerprint, not the slot number.
- **W5. Event files can collide or get stuck** (`audit.go:199-203, 382-385`). IDs are timestamps written with `INSERT OR REPLACE`, so a collision overwrites an event. An unparseable `evt_*.json` is retried every 2 s forever instead of being quarantined.

**Fixed in this audit on the Windows side:** the tray no longer contacts GitHub on its own: update checks are manual, from the tray menu. `dsVersion` is now a `var`, so `-X` stamping works (verified with a Linux build). The Windows build compiles with `CGO_ENABLED=0` (verified by cross-compiling); `build.bat` and CI still set CGO and install TDM-GCC, which can be dropped (item 7 above).
