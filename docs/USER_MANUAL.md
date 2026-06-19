# DevShield User Manual

## 1. Before You Start

DevShield changes several system areas, including:
- power plans
- hosts file entries
- privacy-related registry settings
- firewall and Tor-related rules

It does not modify the boot loader, driver stack, or Windows Update itself.

## 2. Safe Use

- Use the tray menu to switch profiles.
- Review rollback options before applying destructive changes.
- Use the dashboard to inspect current state.

## 3. Pro Use

- Use the PowerShell scripts directly for advanced debugging.
- Review state and config files in the user profile under .devshield.

## 4. Emergency Recovery

If you need to undo everything, run:

```powershell
pwsh -File scripts\hardening\rollback.ps1 -All
```

Use the dry-run mode first if you want to preview changes:

```powershell
pwsh -File scripts\hardening\rollback.ps1 -DryRun -All
```
