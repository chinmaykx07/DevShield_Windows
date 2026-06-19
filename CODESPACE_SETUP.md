# Codespace Setup — Read This First

This repo was assembled offline and is missing two things that **require**
real network access to generate. Do these two steps first, in order, inside
your Codespace terminal.

## 1. Generate `go.sum`

```bash
go mod tidy
```

This downloads every dependency listed in `go.mod` and writes the
cryptographic lock file. It was not possible to generate this offline.
**Do not skip this** — CI and local builds will fail without it.

## 2. Confirm the placeholder username

Every reference to the repo's GitHub location currently uses the placeholder
`the_abstract_creator`. Once you know the real org/username this repo will
live under, run:

```bash
grep -rl "the_abstract_creator" . --include="*.go" --include="*.mod" --include="*.bat" --include="*.yaml"
```

Then replace it everywhere that command lists (5 files: `go.mod`,
`build.bat`, `updater.go`, and the two WinGet manifest YAMLs under
`winget/manifests/`).

## 3. Then follow the real plan

This repo's actual development roadmap, safety testing protocol, and file
inventory live in:

- **`docs/MASTER_PLAN.md`** — full architecture, file inventory, every
  known bug already fixed, the 2026-landscape backlog
- **`docs/SHIP_PLAN.md`** — the phase-by-phase plan from here to a shipped
  v0.1.0, including the mandatory VM-based safety testing gate (Phase C)
  before any script touches a real machine

**Important:** This Codespace is a Linux container. You can run
`go mod tidy`, `go vet ./...`, and even `go build` for syntax checking here,
but the actual binary is Windows-only (it uses `fyne.io/systray` with CGO
for the Windows tray API, and PowerShell 7 scripts for system operations).
Real build and test verification (Phase B onward in `docs/SHIP_PLAN.md`)
requires a Windows environment — a VM, not this Codespace.

## What's deliberately not in this zip yet

Per the ship plan, these come later and are not blocking:
- `docs/INSTALL.md`, `docs/USER_MANUAL.md`, `docs/TROUBLESHOOTING.md`
- Final WinGet PR submission (manifests are ready, just not submitted)
- Microsoft Trusted Signing setup

See `CHANGELOG.md` → `[Unreleased]` for the complete pending list.
