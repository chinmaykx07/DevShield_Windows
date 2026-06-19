# Security Policy

## Why this matters more than usual

DevShield runs with elevated (admin) privileges via Task Scheduler and
modifies your registry, hosts file, power plan, and firewall rules. A
vulnerability here is not a typical software bug — it could mean privilege
escalation, persistence, or system instability. We treat every report
seriously and ask that you do too.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x (latest) | ✅ |
| < 0.1.0 (pre-release / dev builds) | ❌ |

## Reporting a vulnerability

**Do not open a public GitHub Issue for security vulnerabilities.**
Public issues are scanned by automated tools and bad actors before a fix
ships.

Instead:

1. Use **GitHub's private vulnerability reporting**: go to the repo's
   **Security** tab → **Report a vulnerability**. This creates a private
   advisory visible only to maintainers.
2. If that's unavailable, email the maintainer directly (see repo profile)
   with the subject line `[DevShield Security]`.

### What to include
- DevShield version (`devshield.exe` → tray menu shows version, or check
  `~/.devshield/state.json`)
- Windows version (`winver`)
- Exact steps to reproduce
- What you expected vs. what happened
- Whether the issue involves privilege escalation, persistence, data
  exposure, or system instability (bricking/boot failure) — flag this
  explicitly, it changes our response priority

## Response expectations

| Severity | Examples | Response target |
|---|---|---|
| Critical | Privilege escalation, boot failure, unintended persistence | Acknowledgement within 24h, patch prioritized over all other work |
| High | Registry/hosts/firewall changes that don't roll back correctly | Acknowledgement within 48h |
| Medium | Incorrect sensor readings, false guardian alerts, language bugs | Acknowledgement within 1 week |
| Low | Cosmetic, documentation | Best effort |

We will credit reporters in the release notes unless you ask to remain
anonymous.

## Our safety commitments

DevShield's design includes specific guarantees relevant to security
reports — see [docs/SHIP_PLAN.md](docs/SHIP_PLAN.md) Phase C for the full
testing matrix. In short:

- Every destructive action backs up state **before** changing it
- Every change is verified **after** applying it
- `rollback.ps1 -All` can fully undo every DevShield action
- DevShield never touches boot configuration, the driver stack, or WinPE
- Windows Update domains are explicitly whitelisted and never blocked

If you find a case where any of these guarantees fail, that **is** a
security report under this policy, even if it doesn't look like a
traditional vulnerability.

## Verifying release integrity

Every release is signed and attested. Before reporting "this binary looks
suspicious," verify it first:

```powershell
gh attestation verify devshield.exe --repo the_abstract_creator/devshield
cosign verify-blob devshield.exe --signature devshield.exe.sig --certificate devshield.exe.pem
```

If verification fails on an official release artifact, that is itself a
critical-severity report — it would mean the supply chain has been
compromised.
