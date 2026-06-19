# DevShield — Path to Shipped v0.1.0
## Complete Step-by-Step Plan: Code → Tested → Documented → GitHub

**Core principle of this document:** every phase that touches the registry, hosts
file, power plan, firewall, or services has a **safety gate** before the next
phase is allowed to start. No phase is skipped because code "looks correct."
Bricking risk is treated as the primary constraint, not an afterthought.

---

## How to use this document

Work top to bottom. Each phase has a **GATE** — a pass/fail condition.
Do not proceed past a GATE that fails. If a GATE fails, fix the issue,
re-run the phase, re-check the gate.

---

## PHASE A — Code Finalization (mechanical, zero system risk)

Nothing in this phase touches a real system. Pure text editing.

| Step | Action | File(s) |
|---|---|---|
| A.1 | Replace `YOUR_USERNAME` with your real GitHub username | `go.mod`, `build.bat`, `updater.go`, both winget YAML files |
| A.2 | Wire `updater.go` into `tray.go` (5 additions — struct field, menu item, callback, click handler, shutdown call) | `tray.go` |
| A.3 | Confirm `context.go` (no suffix) is the one in the repo — discard `_1_` and `_2_` versions | `context.go` |
| A.4 | Confirm `ps_bridge.go` is the session-patched version with `//go:build windows` | `ps_bridge.go` |
| A.5 | Confirm `icon.go` is at repo root (not `assets/`) | `icon.go` |
| A.6 | Place `assets/devshield.ico` and `assets/placeholder.ico` (already generated this session) | `assets/` |

**GATE A:** `grep -r "YOUR_USERNAME" .` returns zero results. No duplicate
file suffixes (`_1_`, `_2_`) remain anywhere in the repo tree.

---

## PHASE B — Local Build Verification (no admin rights used)

This phase proves the code compiles. It does **not** run any DevShield
script that touches the system.

| Step | Action |
|---|---|
| B.1 | Install Go 1.22+, TDM-GCC, PowerShell 7 (see Build Instructions in master plan) |
| B.2 | `go mod tidy` — generates `go.sum`, downloads all dependencies |
| B.3 | `go vet ./...` — static analysis, catches type errors before build |
| B.4 | `build.bat dev` — dev build, console visible |
| B.5 | Launch `dist\devshield.exe` — confirm tray icon appears |
| B.6 | Right-click tray icon — confirm every menu label renders (no blank/garbled text) |
| B.7 | Toggle language EN → SA → BOTH — confirm labels update live |
| B.8 | Quit via tray — confirm process exits cleanly (check Task Manager) |

**GATE B:** Tray icon appears, all menu items have readable labels in all
3 language modes, process exits cleanly with no orphaned `devshield.exe`
in Task Manager. **Do not proceed to Phase C if any profile/privacy/guardian
script has been triggered yet** — Phase B is UI-only verification.

---

## PHASE C — Isolated VM Safety Testing (CRITICAL GATE — bricking risk lives here)

**This is the most important phase in this document.** Every script that
writes to the registry, hosts file, power plan, or firewall is tested here
first, on a disposable VM, with snapshots before and after every single
destructive action. Nothing in this phase touches your real machine.

### C.0 — VM setup
- Fresh Windows 11 24H2 VM (VMware, VirtualBox, or Hyper-V — any hypervisor with snapshot support)
- Install PowerShell 7 inside the VM
- **Take a snapshot named `clean-baseline` before installing DevShield**
- Install DevShield via `build.bat run` copied into the VM, or the Inno installer

### C.1 — Bricking Risk Matrix
For each item below: snapshot → run action → verify → run rollback →
verify state matches `clean-baseline` → restore snapshot if anything is wrong.

| Risk | Script | What could theoretically go wrong | Test |
|---|---|---|---|
| Power plan corruption | `silent_summer.ps1`, `gaming_gear.ps1`, `dev_mode.ps1` | `powercfg` leaves system in an unrecoverable power state, machine won't wake from sleep | Apply profile → sleep/wake cycle → apply rollback → confirm `powercfg /getactivescheme` matches pre-test default |
| Boot failure from registry edit | `privacy_enforcer.ps1` | A registry key write affects a service required at boot | Apply privacy enforcer → **full VM restart** → confirm Windows boots normally → confirm DiagTrack/services still controllable |
| Hosts file lockout | `privacy_enforcer.ps1` | Hosts file edit blocks a domain needed for Windows Update or network functions | Apply → run `winget upgrade` or check for Windows Update → confirm it still works → rollback → confirm hosts file byte-identical to backup |
| Firewall self-lockout | `tor_hardening.ps1` | Kill-switch firewall rule blocks all traffic, including non-Tor apps, permanently | Apply → confirm normal browser traffic still works → confirm rule only fires when Tor process exits → rollback → confirm firewall rules fully removed |
| Task Scheduler privilege escalation gone wrong | `01_first_run.ps1` | A `RunLevel=Highest` task is mis-scoped and runs with unintended persistence | Inspect registered tasks in Task Scheduler GUI — confirm exactly the expected 6-8 DevShield tasks exist, nothing else |
| Service disable causing instability | `privacy_enforcer.ps1` (DiagTrack) | Disabling a service breaks an unrelated Windows feature | Disable → use Windows normally for 30 min (Settings, Store, Update) → confirm no errors |
| SQLite corruption on crash | `audit.go` | Killing the process mid-write corrupts `audit.db` | Force-kill `devshield.exe` via Task Manager mid-profile-apply → relaunch → confirm tray starts, audit.db still readable |
| Rollback failure compounding the issue | `rollback.ps1` | Rollback itself fails partway, leaving system in a worse state than either before or after | Apply privacy enforcer → manually corrupt the backup file → run rollback → confirm script reports the failure clearly and does NOT silently claim success |

### C.2 — Full rollback verification (run this regardless of individual test results above)
```powershell
# After running every profile, privacy, and tor script at least once:
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All   # review the plan
pwsh -File scripts\hardening\rollback.ps1 -All            # execute
# Then compare full system state against clean-baseline:
#   - powercfg /getactivescheme  → matches baseline
#   - hosts file                  → byte-identical to baseline
#   - firewall rules               → DevShield rules absent
#   - registry keys touched        → reverted to baseline values
#   - services (DiagTrack etc.)    → original start type restored
```

### C.3 — Crash resilience
- Kill `devshield.exe` via Task Manager **while a profile is mid-apply**
  (between backup and verify steps) → relaunch → confirm no half-applied
  state, confirm audit log shows the interrupted action as `status: "fail"`
  or correctly resumes
- Pull VM network cable mid–privacy-enforcer run (during the live blocklist
  fetch) → confirm script falls back to bundled `blocklist_bundled.json`
  without hanging or corrupting the hosts file

**GATE C (hard gate — do not proceed without 100% pass):**
- [ ] VM boots normally after every registry-writing script
- [ ] Hosts file is byte-identical to pre-test state after full rollback
- [ ] Firewall has zero DevShield rules after full rollback
- [ ] Power plan matches baseline GUID after full rollback
- [ ] No test produced a VM that failed to boot
- [ ] Forced process kill mid-operation never leaves an unverifiable state
- [ ] Rollback failure (intentionally triggered) is reported, not silently swallowed

**If GATE C fails on any item:** do not proceed to Phase D or E. Fix the
specific script, re-snapshot, re-run that test in isolation.

---

## PHASE D — Real Hardware Compatibility Testing

Only after Phase C passes completely. Use a real but **non-critical**
physical machine — not your primary workstation.

| Step | Action |
|---|---|
| D.1 | Install on real hardware (AMD + NVIDIA combo if available, matching the target persona) |
| D.2 | Confirm LibreHardwareMonitor actually reads real sensors (VM sensors are often fake/zero) |
| D.3 | Confirm Silent Summer produces an actually measurable temperature drop and audible fan change |
| D.4 | Confirm Gaming Gear pre-flight check correctly reads real CPU temp and blocks if too hot |
| D.5 | Test with WSL2 actively running (`wsl` + some `apt`/`curl` traffic) — confirm guardian doesn't false-positive |
| D.6 | Test on a machine with ASUS/MSI/Gigabyte fan control software already installed — confirm no conflict |
| D.7 | Full restart test — confirm Task Scheduler tasks survive reboot and profile re-applies correctly if needed |

**GATE D:** Real sensor data is read correctly (not zeros/placeholders),
no fan-control software conflict observed, WSL2 produces zero false alerts
over a 30-minute idle-with-traffic period.

---

## PHASE E — Documentation Completion

Write these in parallel with Phase D if you want to save time — they don't
depend on test results, only on final script behavior being locked.

| Document | Purpose | Status |
|---|---|---|
| `README.md` | Already written — update with real screenshots after Phase D | needs update |
| `INSTALL.md` | Step-by-step install guide, plain language, screenshots of SmartScreen click-through | **to write** |
| `USER_MANUAL.md` | Full safe-use + pro-use manual (see structure below) | **to write** |
| `SECURITY.md` | Vulnerability disclosure policy | **to write** |
| `TROUBLESHOOTING.md` | Common issues + fixes, especially "tray icon doesn't appear" and "profile didn't apply" | **to write** |
| `CHANGELOG.md` | v0.1.0 entry | **to write** |

### USER_MANUAL.md required structure
```
1. Before You Start
   - What DevShield changes on your system (full transparency list)
   - What DevShield will never touch (hard safety boundaries)
   - How to fully uninstall and verify removal

2. Safe Use (every user should read this)
   - First-run walkthrough with screenshots
   - How to read the audit log
   - How to use rollback.ps1 -DryRun before any real rollback
   - What to do if a profile doesn't apply
   - What to do if you see a guardian alert you don't understand

3. Pro Use (advanced users)
   - CLI reference for every script + flag
   - Editing the bundled blocklist
   - Adding custom guardian allowlist entries
   - Auto-switch configuration and override behavior
   - Reading state.json / config.json directly
   - Task Scheduler manual inspection/repair

4. Emergency Recovery
   - If DevShield is suspected of causing an issue: exact rollback command
   - If rollback itself fails: manual restore steps using backup files directly
     (exact file paths in ~/.devshield/backups/, what each file is, how to
     restore each type of change by hand — registry .reg import, hosts file
     copy, powercfg import)
   - How to fully disable DevShield without uninstalling (stop all tasks)
```

**GATE E:** All 6 documents exist and are internally consistent (commands
in USER_MANUAL.md actually match script flag names in the real scripts).

---

## PHASE F — Repo Assembly

| Step | Action |
|---|---|
| F.1 | Create the exact directory structure from the master plan's file inventory |
| F.2 | Place every file in its correct location (use the canonical-version table — no duplicates) |
| F.3 | Run `git init`, add `.gitignore` first (before anything else, so secrets/binaries never get staged) |
| F.4 | `git add .` then `git status` — manually review the full file list before first commit |
| F.5 | Confirm no `~/.devshield/` runtime files, no `.exe`, no `go.sum`-less commit |

**GATE F:** `git status` shows only source files — no binaries, no
generated runtime data, no `_1_`/`_2_` duplicates.

---

## PHASE G — GitHub Push & CI Validation

| Step | Action |
|---|---|
| G.1 | Create the GitHub repo (public, Apache 2.0 license auto-detected from LICENSE file) |
| G.2 | Push `main` branch |
| G.3 | Confirm `.github/workflows/build.yml` runs automatically on push (PR-build mode, no release yet) |
| G.4 | Watch the Actions tab — confirm the Windows runner builds successfully, TDM-GCC installs, `go build` succeeds |
| G.5 | If CI fails: fix locally, re-push, re-watch — do not tag a release until CI is green on a normal push |

**GATE G:** A plain push to `main` (no tag) produces a green CI run that
builds both x64 and produces checksums, without creating a release.

---

## PHASE H — Release Tagging & v0.1.0 Ship

| Step | Action |
|---|---|
| H.1 | `git tag v0.1.0 && git push origin v0.1.0` |
| H.2 | CI builds, signs with Sigstore, attests provenance, creates GitHub Release automatically |
| H.3 | Download the released `devshield.exe` fresh from GitHub (not your local build) |
| H.4 | Verify it on a clean machine: `gh attestation verify devshield.exe --repo YOUR_USERNAME/devshield` |
| H.5 | Verify Sigstore signature independently |
| H.6 | Run the **entire Phase C safety matrix again** on this exact released binary — local builds and CI builds can differ |
| H.7 | Only after H.6 passes: announce / share the release |

**GATE H (final gate):** The binary downloaded from the public GitHub
Release page — not your dev machine — passes the full Phase C bricking
risk matrix. This is the binary real users will run; it's the only one
that matters for the final safety sign-off.

---

## PHASE I — Post-Release (ongoing)

| Step | Action |
|---|---|
| I.1 | Monitor GitHub Issues for any bricking/instability report — treat as P0 |
| I.2 | Submit WinGet manifest PR (1-3 week review) |
| I.3 | Apply for Microsoft Trusted Signing if budget allows ($9.99/mo) |
| I.4 | Keep `blocklist_bundled.json` updated as Microsoft adds new telemetry endpoints |
| I.5 | Re-run Phase C matrix against any future Windows feature update (24H2 → 25H1 etc.) before claiming compatibility |

---

## Quick-reference: what NOT to do

- Do not skip Phase C because Phase B (UI-only) passed — UI working tells
  you nothing about registry/hosts/firewall safety
- Do not test destructive scripts on your primary machine before Phase C
  passes on a VM
- Do not tag a release before Phase G's plain-push CI is confirmed green
- Do not treat a local `build.bat` binary as equivalent to the CI-built,
  signed release binary — re-verify the actual release artifact (Phase H.6)
- Do not silently swallow a rollback failure — if `rollback.ps1` can't
  restore something, it must say so loudly, in the audit log and on screen

---

*This plan assumes the code from the master plan document is the final
source of truth for file inventory and canonical-version decisions.*
