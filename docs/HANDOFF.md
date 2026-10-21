# DevShield — handoff for the next session

Last updated 2026-10-21. Branch: `claude/beautiful-dirac-gw6vzv`, last
commit before this file: `5aa5c30`. This file replaces
`docs/SESSION_HANDOFF.md` and `docs/SESSION_STATUS.md` (June 2026, now
historical).

**Read this first, then `docs/USER_MANUAL.md` §2b (what the Linux side
does and its stated limits) and `docs/REVIEW_NOTES_2026-10-20.md`
(Windows findings C1–C8, W1–W6).** Don't re-read the whole repository:
the sections below say where each piece lives.

---

## 1. Goal and decisions already taken (don't re-open them)

- **Goal:** the owner is the sole sovereign of the machine. Nothing runs
  or leaves without the owner's permission. Roadmap step names: Block →
  Allow → Charge (Charge = x402 gateway, later; see
  `docs/ROADMAP_LINUX_FIRST_AND_X402.md` §8).
- **Order: Linux → Windows → macOS.** Linux v1 = full feature parity
  before release (daemon + CLI + tray + .deb/.rpm). Windows keeps its
  PowerShell scripts and gets them fixed in place. The repo keeps its
  name.
- **Honesty rule (the owner's explicit, repeated requirement):** every
  claim in code messages, docs and commit messages must be true and
  verified. Say "not tested on X" wherever that applies. A test only
  counts if it fails without its fix (mutation-check it, §5). Never
  report a check as passed when it was skipped or couldn't run.

## 2. Where things stand

### Linux (the focus): built and tested
Go module `github.com/chinmaykx07/DevShield_Windows`, toolchain go1.27.3
(fetched automatically via `go.mod`). One binary: `devshield daemon`
(root service) plus the CLI (`devshield help` lists every command;
`cliUsage` in `cli.go` is the single source).

| Package | What it does |
|---|---|
| `internal/agentwatch` | AI-agent detection (catalog identity + behaviour), verdicts, sanctions (SQLite), exec-event handling |
| `internal/procevents` | kernel exec events (netlink proc connector, own reader) |
| `internal/egress` | nftables table `inet devshield`: per-agent block/allow (cgroup v2), lockdown, `--inbound`, `block-doh`, tamper check |
| `internal/daemon` | the root daemon: IPC handlers, authorization, reconcile loops, restore-all |
| `internal/ipc` | Unix socket protocol, peer credentials (SO_PEERCRED) |
| `internal/auditlog` | hash-chained, tamper-evident audit log |
| `internal/hosts` | telemetry sinkhole in /etc/hosts |
| `internal/lanprivacy` | LLMNR/mDNS off, Wi-Fi MAC randomisation, IPv6 privacy |
| `internal/thermal`, `internal/sensors` | thermal profiles via sysfs; hwmon sensors |
| `internal/netwatch` | `devshield net`: who talks to whom |
| `packaging/linux/*.service` | hardened daemon unit + early-boot egress unit |
| `test/linux-live/` | live suite (real kernel, nftables, daemon, in namespaces) |

**Verified state at `5aa5c30`:**
- Tests: 138 unit-test functions, all pass with the race detector; vet
  passes on Linux and Windows.
- govulncheck: clean at the last check.
- Live suite: 214 passed, 0 failed, 4 skipped (2 per cgroup layout, see
  §4).
- Both systemd units pass `systemd-analyze verify`, which checks syntax
  and references only.

**CI has never run successfully on this code.** The workflow was invalid
(duplicate `push:` key) until `4cb9670`; since then it triggers only on
`main`, tags, PRs into `main`, or by hand ("Run workflow" in the Actions
tab, added after `222f667`). So the tests have never run natively on
Windows, and the CI live-test job has never run on GitHub's runners.
**First CI run (by hand, run 39549081862 on `86a1414`): all three jobs
failed.**

| Job | What failed |
|---|---|
| Windows tests | Only `TestBaselineFileIsRootOnly`, which checks Unix file modes (now skipped on Windows, after `86a1414`); every other package passed natively. |
| Linux tests on GitHub's runner | One package failed; it wasn't identified (read the full log). It likely assumes root or this dev container. |
| Live suite on GitHub's runner | Some checks failed; read the full log for which ones. |

govulncheck didn't run, because it is skipped after a failure.
**First step of the next session:** open that run's logs (Actions tab),
fix, and re-run by hand until green.

Unit-test coverage (`go test -cover`):

| Package | Coverage |
|---|---|
| cli (main) | 2.9% |
| daemon | 50% |
| agentwatch | 65% |
| ipc | 72% |
| egress | 73% |
| all others | 78–96% |

### Linux: never tested (say so in any claim)
- Under systemd on a real distribution: the units' hardening, and the
  early-boot ordering of `devshield-egress.service` before the network.
- On real hardware: thermal profiles, sensors, Wi-Fi MAC randomisation.
- With a real WireGuard/OpenVPN/Tor (including `--tor`), real
  systemd-resolved, and real NetworkManager.
- nft rule comparison: checked against nft 1.0.9 only. Another version
  may show "UNVERIFIED"; change detection still works then.

### Windows: known broken, not run on Windows
C1–C6 and C8, plus W1–W6, are open; details in
`docs/REVIEW_NOTES_2026-10-20.md` (§3, §7). Summary:
- task registration fails;
- first run can't run unattended;
- tray actions stop at prompts;
- rollback restores nothing yet reports success;
- the network guardian crashes;
- the "Tor kill switch" only adds allow rules;
- the UAC fallback can't start scripts;
- timeouts are logged as success;
- sanction can hit the wrong menu slot;
- event-file collisions;
- auto-switch logs success early.

The PowerShell scripts haven't changed since `15989a8`.

## 3. What to build next, in order

Each item: build → unit tests (mutation-checked) → docs (manual,
CHANGELOG, README status table if affected) → one live run at the end →
commit + push. Sizes are rough.

1. **Run agents under their own account (L). Biggest remaining hole.**
   Today a blocked agent can get work done through a helper that is
   already running outside its cgroup (`systemd-run --user`, `at`, tmux,
   the Docker daemon).
   - Idea (Tails' Tor-only model): launch agents as a dedicated user and
     match `meta skuid` in nft.
   - Whatever such helpers start then still runs as that user.
   - Don't give that user the `docker` group or the docker socket.
   - Needs: a launcher (`devshield run --as-agent <cmd>`?), how the
     account is created and shared files are reached (group, ACLs), and
     how sanctions map to it.
   - Write the design in the manual before coding; ask the owner if
     unclear.
2. **Manage the nft table with `google/nftables` (M, Apache-2.0).**
   - Use change notifications instead of the 10 s poll.
   - Use the table "owner" flag so other programs can't change it
     (kernel 5.12+, unverified).
   - Use "persist" if available (secondary source says 6.9).
   - Keep `nft -j` (JSON) as a fallback; it removes the version-dependent
     text comparison.
   - Keep the current behaviour and messages.
3. **Integrity beyond one file (M).** An approval should cover:
   - the exe, read via `/proc/pid/exe` so a replaced file is caught;
   - the script;
   - the executable mappings in `/proc/pid/maps`, cached by
     (dev, inode, size, ctime);
   - memfd or deleted executables, which should be flagged;
   - IMA hashes when the system has IMA enabled.
4. **Seal the audit log against root (S–M).**
   - Use a forward-secure HMAC chain (journald FSS idea; systemd is
     LGPL, ideas only).
   - The first key is shown once for the owner to keep off the machine;
     each epoch's key is derived from the previous one, which is then
     deleted.
   - Add `devshield verify-log --key …`.
   - State the limit: the current epoch can still be rewritten.
5. **Thermal coexistence (S–M).**
   - If power-profiles-daemon owns `org.freedesktop.UPower.PowerProfiles`,
     delegate to it.
   - If TLP, auto-cpufreq, tuned, system76-power or thinkfan is active,
     go read-only and warn.
6. **Network monitor (M).**
   - Domain names via systemd-resolved's `io.systemd.Resolve.Monitor`.
   - UDP via conntrack events (today TCP only, labels by IP).
7. **Linux tray (M).** `fyne.io/systray` (Apache-2.0).
   - It needs cgo; GNOME needs the AppIndicator extension.
   - It talks to the daemon over the existing socket: read-only, with
     policy changes still requiring root.
8. **Packages (M).** `.deb`/`.rpm` with `nfpm` (MIT).
   - Units go in `/usr/lib/systemd/system`.
   - postinst runs `daemon-reload`, then `enable --now` only if
     `/run/systemd/system` exists; prerm stops and disables.
   - Add `systemd-analyze security --offline=yes` as a CI gate.
9. **One real-machine pass.** A VM is fine for systemd and the VPN; a
   laptop is needed for thermal and Wi-Fi. Cover:
   - install from the package;
   - boot ordering;
   - a lockdown through real WireGuard and Tor;
   - resolved and NetworkManager with LAN privacy;
   - thermal profiles;
   - `restore-all`.

   Then update every "not tested" line that this pass covers.
10. **Windows phase:** fix C1–C8 and W1–W6 in place (suggested order in
    `REVIEW_NOTES` §6), then run it on a real Windows VM.
11. macOS later (the tray library needs cgo there).

Also worth doing whenever a related file is touched:
- unit tests for `cli.go` (2.9% coverage);
- the daemon's `verify` IPC op is unused by the CLI (harmless; remove it
  or use it).

## 4. Current caveats and limits (all documented in the manual; keep them true)

**Agent Watch**
- A catalog name removes only the "undocumented" sign: an impostor named
  `claude` shows ⚠ unsanctioned, not 🚨.
- Recon tools are recognised by name only.
- The "detached" signal is weak: a double fork avoids it.
- The approval hash covers one file: a swapped `python3` or a changed
  library is not noticed (§3.3).
- Very short commands: kernel exec events catch about 99% (296–300 of
  300 `/bin/true` runs). Windows samples every 0.5 s.

**Exec events**
- Exist only in the initial network namespace. The live suite runs in a
  namespace, so its two "caught within ~2 s" checks print SKIP.
- `TestBlockedProgramIsCaughtAtExec` (run as root) tests this end to end
  in the host namespace: 11–12 ms measured.

**Network controls**
- Helper-mediated escape (§3.1).
- A program running as root can answer on port 22 if nothing else
  listens there.
- Data hidden inside allowed traffic.
- Intel AMT/vPro (below the OS).
- Malware with root (rules are restored within 10 s and logged, but root
  is root).
- Blocking an agent inside an editor cuts the editor.
- Arbitrary-program allow and ask-on-connect are not built.

**`block-doh`**
- Covers only the well-known resolvers (list in `internal/egress/doh.go`).
  Those addresses come from memory of the providers' published lists and
  were not re-checked against the providers' pages this session; do
  that.
- DoH can run on any HTTPS server.

**State and logs**
- Corrupt egress state fails closed only until reboot.
- `egress.json` fsync isn't unit-testable.
- The audit log's sync-failure rollback path isn't directly tested.
- Root can rewrite the whole audit log consistently (§3.4).

**Restore and cleanup**
- `restore-all` can't recover originals DevShield never recorded.
- Randomised Wi-Fi addresses already used stay seen.

**Tests**
- Mutating the MCP naming in `agentName` isn't caught by the fingerprint
  consistency test: scan and single-process paths share that function by
  design.

**Known bugs:** none open on Linux. All 13 findings from the second
audit and the exec-identity bug are fixed with tests (see CHANGELOG).
Windows: everything in §2.

## 5. How to work (environment and checks)

```bash
# fast checks, every change
gofmt -l . ; go vet ./... && GOOS=windows go vet ./...
go test -race -count=1 ./...
# vulnerabilities (before pushing a dependency change)
GOTOOLCHAIN=go1.27.3 go run golang.org/x/vuln/cmd/govulncheck@latest ./...
# does a regression test catch its bug?
test/mutate.sh FILE 'OLD' 'NEW' TestRegex ./internal/pkg/
# live suite: root, nft, unshare, python3, /dev/net/tun, cgroup v2;
# ~10–12 min. Run ALONE (shared cgroup hierarchy).
go build -o /tmp/ds . && timeout 1800 test/linux-live/run.sh /tmp/ds > /tmp/live.tmp 2>&1; mv /tmp/live.tmp /tmp/live.out
grep "FAIL\|SKIP\|^==" /tmp/live.out
```

Lessons from this project; repeat none of them:
- **Stale results.** Write live output to a temp file and rename it at
  the end. A watcher once read the previous run's "exit 0" and reported
  a false pass.
- **Editing a running suite.** Don't edit `run.sh` or `restore_all.sh`
  while a run is in progress: `sh` reads them as it goes. Committing is
  fine.
- **Self-matching harness.** The fake agent's name is assembled at run
  time so the harness never matches itself (`fixtures.py`).
- **Python edits.** When a Python script edits Go files, assert each old
  string occurs exactly once.
- **Docs follow code.** Docs must say what the code does now. Grep the
  manual and README for the feature you changed, and test-count lines
  (README, roadmap, `test/linux-live/README.md`) after adding checks.
- **Mutant rejects.** An "INVALID" mutant proves nothing; pick another.
  A probabilistic race test is not proof; use a hook to make the race
  deterministic.

Git and repo rules:
- Branch `claude/beautiful-dirac-gw6vzv`; push with
  `git push -u origin claude/beautiful-dirac-gw6vzv`.
- No PR unless the owner asks.
- Every commit ends with the session's `Co-Authored-By` and
  `Claude-Session` trailers.
- No model names in commits or code.
- Licences: DevShield is Apache-2.0. GPL/AGPL/EUPL projects (OpenSnitch,
  Portmaster, Mullvad, Proton, simplewall, Pi-hole, auto-cpufreq, TLP,
  systemd) are ideas only, never copied. MIT/BSD/Apache code may be
  reused with attribution in `docs/CREDITS.md`.

## 6. How the next session should run (to keep cost down)

1. Start a **fresh session**. Read this file and only the files the
   chosen item touches. Get CI green first (§2).
2. Take **one item from §3**, starting with §3.1. If its design has open
   questions (§3.1 does: the account model), write a short design note
   and ask the owner before coding.
3. Use unit tests and `test/mutate.sh` while building. Run the **live
   suite once, at the end**, unless the item changes rules or processes
   in a way only the live suite can check.
4. Update the docs, commit, push, and **update this file**: move the item
   to "done", record new caveats and the new commit hash.
5. Report to the owner: what's done, what's tested and how, and what
   isn't. Check real spend after the item to plan the next one.
