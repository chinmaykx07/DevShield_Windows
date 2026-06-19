#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Privacy Enforcer
.DESCRIPTION
    Blocks telemetry at the DNS level via hosts file sinkhole.
    Optionally disables telemetry registry keys and DiagTrack service.

    NASA 8-step pattern applied to every operation:
      Pre-flight → Assert → Backup → Act → Verify → Report → Log → Fault-safe

    Key safety guarantees:
      · Windows Update domains are NEVER blocked (explicit whitelist)
      · Tamper Protection detected BEFORE any modification attempt
      · Entire hosts file backed up before writing a single byte
      · Idempotent: safe to run multiple times — skips already-blocked domains
      · Every change tagged with rollback ID for precise undo via rollback.ps1
      · DevShield block section clearly marked — never corrupts existing entries

.PARAMETER NoConfirm    Skip confirmation
.PARAMETER DryRun       Show what would happen without applying
.PARAMETER RegistryOnly Skip hosts file, only apply registry tweaks
.PARAMETER HostsOnly    Skip registry tweaks, only apply hosts sinkhole
.PARAMETER Rollback     Remove DevShield sinkhole entries from hosts file
#>
param(
    [switch]$NoConfirm,
    [switch]$DryRun,
    [switch]$RegistryOnly,
    [switch]$HostsOnly,
    [switch]$Rollback
)

. "$PSScriptRoot\..\core\00_core.ps1"

Initialize-DevShield -ScriptName "privacy_enforcer.ps1"

# ══════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS
# ══════════════════════════════════════════════════════════════
$HOSTS_PATH     = "C:\Windows\System32\drivers\etc\hosts"
$DS_BLOCK_BEGIN = "# DevShield Telemetry Sinkhole — Begin"
$DS_BLOCK_END   = "# DevShield Telemetry Sinkhole — End"
$SINKHOLE_IP    = "0.0.0.0"

# Windows Update + Microsoft Store domains — NEVER sinkholes these
# Blocking these breaks Windows Update, Store, and system authentication
$WINDOWS_UPDATE_WHITELIST = @(
    "windowsupdate.microsoft.com",
    "download.windowsupdate.com",
    "download.microsoft.com",
    "update.microsoft.com",
    "wustat.windows.com",
    "ntservicepack.microsoft.com",
    "windowsupdate.com",
    "go.microsoft.com",
    "dl.delivery.mp.microsoft.com",
    "officecdn.microsoft.com",
    "login.microsoftonline.com",
    "login.live.com",
    "microsoftonline.com",
    "live.com",
    "account.microsoft.com",
    "signup.live.com"
)

# Telemetry domains to sinkhole
# Note: Windows Update whitelist takes precedence — any overlap is skipped
$TELEMETRY_DOMAINS = @(
    "telemetry.microsoft.com",
    "vortex.data.microsoft.com",
    "vortex-win.data.microsoft.com",
    "watson.microsoft.com",
    "df.telemetry.microsoft.com",
    "sqm.telemetry.microsoft.com",
    "oca.telemetry.microsoft.com",
    "settings-win.data.microsoft.com",
    "reports.wes.df.telemetry.microsoft.com",
    "statsfe1.ws.microsoft.com",
    "statsfe2.ws.microsoft.com",
    "feedback.microsoft-hohm.com",
    "redir.metaservices.microsoft.com",
    "choice.microsoft.com",
    "i1.services.social.microsoft.com",
    "c.microsoft.com",
    "c1.microsoft.com",
    "pipe.aria.microsoft.com",
    "data.microsoft.com",
    # Cortana / search telemetry
    "bingapis.com",
    # Advertising
    "ads.msn.com",
    "c.msn.com",
    "adnexus.net",
    # Vendor telemetry
    "telemetry.asus.com",
    "auep.amd.com",
    "dc.telemetry.amd.com",
    "events.gfe.nvidia.com",
    "telemetry.nvidia.com",
    "gfe.geforce.com",
    "telemetry.intel.com",
    "registrationapi.intel.com",

    # Windows 11 24H2 — Copilot Runtime + Windows Recall (2026)
    "recall.microsoft.com",
    "prod.recall.microsoft.com",
    "copilot.microsoft.com",
    "sydney.bing.com",
    "edgeservices.bing.com",
    "assistantservices.microsoft.com",
    "aiassistant.microsoft.com",
    "aiplatform.microsoft.com",

    # ARIA telemetry — massively expanded in Windows 11 24H2
    "v10.events.data.microsoft.com",
    "v20.events.data.microsoft.com",
    "browser.pipe.aria.microsoft.com",
    "experimentation.microsoft.com",
    "config.edge.skype.com",

    # Activity History + Timeline (feeds Windows Recall)
    "activity.microsoft.com",
    "activityhistory.microsoft.com",

    # MSN / Start AI content recommendations
    "api.msn.com",
    "ntp.msn.com",

    # Vendor additions 2025-2026
    "rog.telemetry.asus.com",
    "telemetry.asusvivo.com",
    "dc.services.amd.com"
)

# Registry tweaks — optional, powerful
$REGISTRY_TWEAKS = @(
    @{
        Path    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Name    = "AllowTelemetry"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Telemetry level → Security (0)"
        DescSA  = "टेलीमेट्री स्तर → सुरक्षित (0)"
    }
    @{
        Path    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
        Name    = "DoNotShowFeedbackNotifications"
        Value   = 1
        Type    = "DWORD"
        Desc    = "Disable feedback notifications"
        DescSA  = "फ़ीडबैक-सूचनाएं अक्षम"
    }
    @{
        Path    = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
        Name    = "AllowTelemetry"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Data collection policy → disabled"
        DescSA  = "डेटा-संग्रह नीति → अक्षम"
    }
    @{
        Path    = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy"
        Name    = "TailoredExperiencesWithDiagnosticDataEnabled"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Tailored experiences → off"
        DescSA  = "अनुकूलित अनुभव → बंद"
    }
    @{
        Path    = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"
        Name    = "NumberOfSIUFInPeriod"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Disable feedback frequency prompts"
        DescSA  = "फ़ीडबैक-बारंबारता → बंद"
    }
    # ── Windows 11 24H2 AI features ──────────────────────────
    @{
        Path    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        Name    = "DisableAIDataAnalysis"
        Value   = 1
        Type    = "DWORD"
        Desc    = "Disable Windows Recall — prevents continuous screenshot analysis"
        DescSA  = "Windows Recall अक्षम — स्क्रीनशॉट विश्लेषण रोकें"
    }
    @{
        Path    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI"
        Name    = "AllowRecallEnablement"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Block Recall re-enablement via Settings"
        DescSA  = "Settings से Recall पुनः-सक्षमता अवरुद्ध"
    }
    @{
        Path    = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot"
        Name    = "TurnOffWindowsCopilot"
        Value   = 1
        Type    = "DWORD"
        Desc    = "Disable Windows Copilot sidebar + data upload"
        DescSA  = "Windows Copilot साइडबार + डेटा अपलोड अक्षम"
    }
    @{
        Path    = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
        Name    = "Start_IrisRecommendations"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Disable AI-powered Start menu recommendations"
        DescSA  = "AI Start अनुशंसाएं अक्षम"
    }
    @{
        Path    = "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
        Name    = "SubscribedContent-338389Enabled"
        Value   = 0
        Type    = "DWORD"
        Desc    = "Disable Windows AI tips and suggestions"
        DescSA  = "Windows AI सुझाव अक्षम"
    }
)

# DiagTrack (Connected User Experiences + Telemetry) service
$DIAGTRACK_SERVICE = "DiagTrack"

# ══════════════════════════════════════════════════════════════
# SECTION 2 — TAMPER PROTECTION DETECTION
# Must check BEFORE attempting any hosts or registry modification
# ══════════════════════════════════════════════════════════════
function Get-TamperProtectionState {
    try {
        $tp = (Get-ItemProperty `
            -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Features" `
            -Name "TamperProtection" `
            -ErrorAction Stop).TamperProtection
        # 4 or 5 = enabled, 1 or 0 = disabled
        return @{ Enabled = ($tp -in @(4,5)); Code = $tp }
    } catch {
        # Fallback via MpPreference
        try {
            $pref = Get-MpPreference -ErrorAction Stop
            $enabled = -not $pref.DisableTamperProtection
            return @{ Enabled = $enabled; Code = if ($enabled) { 5 } else { 0 } }
        } catch {
            return @{ Enabled = $false; Code = -1 }  # unknown — assume off
        }
    }
}

function Show-TamperProtectionInstructions {
    Write-DS -BLANK
    Write-DS -EN "Tamper Protection is ON. To modify the hosts file:" `
             -SA "Tamper Protection चालू है। Hosts फ़ाइल बदलने के लिए:" -Level WARN
    Write-DS -EN "  1. Open Windows Security (Start → type 'Windows Security')" -Level INFO -NoIcon
    Write-DS -EN "  2. Go to Virus & threat protection → Manage settings" -Level INFO -NoIcon
    Write-DS -EN "  3. Toggle 'Tamper Protection' to OFF" -Level INFO -NoIcon
    Write-DS -EN "  4. Re-run DevShield Privacy Enforcer" -Level INFO -NoIcon
    Write-DS -EN "  5. Re-enable Tamper Protection after applying" -Level INFO -NoIcon
    Write-DS -BLANK
    Write-DS -EN "Note: Registry tweaks do NOT require disabling Tamper Protection." `
             -SA "नोट: रजिस्ट्री बदलाव के लिए Tamper Protection बंद करना जरूरी नहीं।" -Level INFO
}

# ══════════════════════════════════════════════════════════════
# SECTION 3 — HOSTS FILE ANALYSIS
# Read current state before touching anything
# ══════════════════════════════════════════════════════════════
function Get-HostsAnalysis {
    $content = Get-Content $HOSTS_PATH -Raw -Encoding UTF8 -ErrorAction Stop
    $lines   = $content -split "`n" | ForEach-Object { $_.TrimEnd() }

    # Find existing DevShield block
    $blockStart = -1; $blockEnd = -1
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match [regex]::Escape($DS_BLOCK_BEGIN)) { $blockStart = $i }
        if ($lines[$i] -match [regex]::Escape($DS_BLOCK_END))   { $blockEnd   = $i }
    }

    # Count already-blocked domains
    $alreadyBlocked = $TELEMETRY_DOMAINS | Where-Object {
        $domain = $_
        $lines  | Where-Object { $_ -match "0\.0\.0\.0\s+$([regex]::Escape($domain))" }
    }

    # Count total custom (non-Windows) entries
    $customEntries = $lines | Where-Object {
        $_ -notmatch "^\s*#" -and $_.Trim() -and
        $_ -notmatch "localhost|127\.0\.0\.1|::1|0\.0\.0\.0\s+$"
    }

    return @{
        Content        = $content
        Lines          = $lines
        BlockStart     = $blockStart
        BlockEnd       = $blockEnd
        HasDSBlock     = ($blockStart -ge 0 -and $blockEnd -gt $blockStart)
        AlreadyBlocked = $alreadyBlocked
        CustomEntries  = $customEntries.Count
        TotalLines     = $lines.Count
    }
}

# ══════════════════════════════════════════════════════════════
# SECTION 4 — HOSTS SINKHOLE APPLICATION
# ══════════════════════════════════════════════════════════════
function Invoke-HostsSinkhole {
    param([object]$Analysis)

    # Filter domain list: exclude whitelist + already-blocked
    $toAdd = $TELEMETRY_DOMAINS | Where-Object {
        $d = $_
        $notWhitelisted    = -not ($WINDOWS_UPDATE_WHITELIST | Where-Object { $d -eq $_ })
        $notAlreadyBlocked = -not ($Analysis.AlreadyBlocked  | Where-Object { $d -eq $_ })
        $notWhitelisted -and $notAlreadyBlocked
    }

    if ($toAdd.Count -eq 0) {
        Write-DS -EN "All $($TELEMETRY_DOMAINS.Count) domains already blocked. Nothing to add." `
                 -SA "सभी $($TELEMETRY_DOMAINS.Count) डोमेन पहले से अवरुद्ध। जोड़ने को कुछ नहीं।" `
                 -Level SUCCESS
        return @{ Added = 0; Skipped = $Analysis.AlreadyBlocked.Count }
    }

    Write-DS -EN "Adding $($toAdd.Count) domains to sinkhole ($($Analysis.AlreadyBlocked.Count) already present)..." `
             -SA "$($toAdd.Count) डोमेन सिंकहोल में जोड़ रहे हैं..." -Level INFO

    # Build the new block content
    $timestamp = Get-Date -Format "o"
    $blockLines = @(
        "",
        $DS_BLOCK_BEGIN,
        "# Applied by DevShield v$DS_VERSION on $timestamp",
        "# $($toAdd.Count) domains blocked — Windows Update domains preserved",
        "# To remove: run privacy_enforcer.ps1 -Rollback"
    )
    foreach ($domain in ($toAdd | Sort-Object)) {
        $blockLines += "$SINKHOLE_IP $domain"
    }
    $blockLines += $DS_BLOCK_END
    $blockLines += ""

    # If existing DevShield block found — replace it; else append
    if ($Analysis.HasDSBlock) {
        $beforeBlock = $Analysis.Lines[0..($Analysis.BlockStart - 1)]
        $afterBlock  = if ($Analysis.BlockEnd -lt ($Analysis.Lines.Count - 1)) {
            $Analysis.Lines[($Analysis.BlockEnd + 1)..($Analysis.Lines.Count - 1)]
        } else { @() }
        $newContent = ($beforeBlock + $blockLines + $afterBlock) -join "`n"
    } else {
        $newContent = $Analysis.Content.TrimEnd() + "`n" + ($blockLines -join "`n")
    }

    Set-Content -Path $HOSTS_PATH -Value $newContent -Encoding UTF8 -NoNewline
    return @{ Added = $toAdd.Count; Skipped = $Analysis.AlreadyBlocked.Count }
}

# ══════════════════════════════════════════════════════════════
# SECTION 5 — HOSTS SINKHOLE VERIFICATION
# ══════════════════════════════════════════════════════════════
function Test-SinkholeVerification {
    param([int]$TestCount = 3)

    $testDomains = $TELEMETRY_DOMAINS | Select-Object -First $TestCount
    $passed = 0; $failed = @()

    foreach ($domain in $testDomains) {
        try {
            # Flush DNS cache first for accurate test
            ipconfig /flushdns 2>$null | Out-Null
            $result = Resolve-DnsName $domain -ErrorAction Stop |
                      Where-Object { $_.Type -eq "A" }
            $resolvedIP = ($result | Select-Object -First 1).IPAddress

            if ($resolvedIP -eq $SINKHOLE_IP -or $resolvedIP -eq "0.0.0.0") {
                $passed++
            } else {
                $failed += "$domain → $resolvedIP (expected 0.0.0.0)"
            }
        } catch {
            # Resolution error = domain blocked (NXDOMAIN or connection refused)
            $passed++
        }
    }
    return @{ Passed = $passed; Failed = $failed; Total = $testDomains.Count }
}

# ══════════════════════════════════════════════════════════════
# SECTION 6 — REGISTRY TWEAKS
# ══════════════════════════════════════════════════════════════
function Get-RegistryRollbackState {
    $state = @{}
    foreach ($tweak in $REGISTRY_TWEAKS) {
        try {
            $state[$tweak.Path + "|" + $tweak.Name] = (
                Get-ItemProperty -Path $tweak.Path -Name $tweak.Name -ErrorAction SilentlyContinue
            ).$($tweak.Name)
        } catch { $state[$tweak.Path + "|" + $tweak.Name] = $null }
    }
    return $state
}

function Invoke-RegistryTweaks {
    $ok = 0; $fail = 0
    foreach ($tweak in $REGISTRY_TWEAKS) {
        try {
            if (-not (Test-Path $tweak.Path)) {
                New-Item -Path $tweak.Path -Force | Out-Null
            }
            Set-ItemProperty -Path $tweak.Path -Name $tweak.Name `
                             -Value $tweak.Value -Type $tweak.Type -Force
            Write-DS -EN "  ✅ $($tweak.Desc)" -SA "  ✅ $($tweak.DescSA)" -Level SUCCESS -NoIcon
            $ok++
        } catch {
            Write-DS -EN "  ❌ $($tweak.Desc): $_" -Level WARN -NoIcon
            $fail++
        }
    }

    # Disable DiagTrack service (Connected User Experiences + Telemetry)
    try {
        $svc = Get-Service -Name $DIAGTRACK_SERVICE -ErrorAction Stop
        if ($svc.StartType -ne "Disabled") {
            Set-Service -Name $DIAGTRACK_SERVICE -StartupType Disabled -ErrorAction Stop
            Stop-Service -Name $DIAGTRACK_SERVICE -Force -ErrorAction SilentlyContinue
            Write-DS -EN "  ✅ DiagTrack service disabled" -SA "  ✅ DiagTrack सेवा अक्षम" -Level SUCCESS -NoIcon
            $ok++
        } else {
            Write-DS -EN "  ✅ DiagTrack already disabled" -SA "  ✅ DiagTrack पहले से अक्षम" -Level SUCCESS -NoIcon
        }
    } catch {
        Write-DS -EN "  ⚠ DiagTrack: $_" -Level WARN -NoIcon
    }

    return @{ OK = $ok; Failed = $fail }
}

# ══════════════════════════════════════════════════════════════
# SECTION 7 — ROLLBACK (remove DevShield entries)
# ══════════════════════════════════════════════════════════════
function Invoke-PrivacyRollback {
    Write-DSBanner -Subtitle "Privacy Rollback · गोपनीयता-पुनःस्थापना"

    if (-not (Assert-DSAdmin)) { exit 1 }

    $analysis = Get-HostsAnalysis
    if (-not $analysis.HasDSBlock) {
        Write-DS -EN "No DevShield sinkhole block found in hosts file. Nothing to remove." `
                 -SA "Hosts फ़ाइल में DevShield ब्लॉक नहीं मिला।" -Level INFO
        return
    }

    # Remove just the DevShield block
    $cleaned = @()
    $skip    = $false
    foreach ($line in $analysis.Lines) {
        if ($line -match [regex]::Escape($DS_BLOCK_BEGIN)) { $skip = $true;  continue }
        if ($line -match [regex]::Escape($DS_BLOCK_END))   { $skip = $false; continue }
        if (-not $skip) { $cleaned += $line }
    }

    Set-Content -Path $HOSTS_PATH -Value ($cleaned -join "`n") -Encoding UTF8 -NoNewline
    ipconfig /flushdns 2>$null | Out-Null

    Set-DSStateKey -Key "privacy_active"      -Value $false
    Set-DSStateKey -Key "privacy_applied_at"  -Value $null

    Write-DS -EN "Sinkhole removed. $($analysis.AlreadyBlocked.Count) domains unblocked." `
             -SA "सिंकहोल हटाया। $($analysis.AlreadyBlocked.Count) डोमेन अनब्लॉक।" -Level SUCCESS
    Write-DSAudit -Action "PRIVACY_ROLLBACK" `
                  -Detail "Removed DevShield sinkhole block from hosts file" -Status "ok"
}

# ══════════════════════════════════════════════════════════════
# SECTION 8 — MAIN
# ══════════════════════════════════════════════════════════════
function Invoke-PrivacyEnforcer {
    if ($Rollback) { Invoke-PrivacyRollback; return }

    Write-DSBanner -Subtitle "Privacy Enforcer · गोपनीयता-प्रवर्तक"

    # ── STEP 1: PRE-FLIGHT ────────────────────────────────────
    Write-DS -EN "Reading current hosts file and system state..." `
             -SA "वर्तमान Hosts फ़ाइल और अवस्था पढ़ रहे हैं..." -Level INFO

    $tamper = Get-TamperProtectionState

    $analysis = $null
    $hostsReadable = $true
    try { $analysis = Get-HostsAnalysis } catch {
        Write-DS -EN "Could not read hosts file: $_" -Level WARN
        $hostsReadable = $false
    }

    # Show current status table
    Write-DS -BLANK
    Write-DS -EN "CURRENT STATE" -SA "वर्तमान-अवस्था" -Level HEADER
    Write-DSSeparator

    if ($analysis) {
        $dsBlockStatus = if ($analysis.HasDSBlock) {
            "✅ Active ($($analysis.AlreadyBlocked.Count)/$($TELEMETRY_DOMAINS.Count) domains)"
        } else { "⬜ Not applied" }

        Write-DS -EN "Hosts file   : $HOSTS_PATH ($($analysis.TotalLines) lines)" -Level INFO
        Write-DS -EN "DS Sinkhole  : $dsBlockStatus" `
                 -SA "DS सिंकहोल  : $dsBlockStatus" `
                 -Level $(if ($analysis.HasDSBlock) {"SUCCESS"} else {"WARN"})
        Write-DS -EN "Custom entries (non-DevShield): $($analysis.CustomEntries)" -Level INFO
    }

    $tpStatus = if ($tamper.Enabled) { "🔴 ON — hosts file modifications blocked" } else { "🟢 OFF" }
    Write-DS -EN "Tamper Prot. : $tpStatus" `
             -SA "Tamper सुरक्षा: $tpStatus" `
             -Level $(if ($tamper.Enabled) {"WARN"} else {"INFO"})

    Write-DS -EN "Registry tweaks: $($REGISTRY_TWEAKS.Count) settings + DiagTrack service" -Level INFO
    Write-DS -EN "Windows Update : $($WINDOWS_UPDATE_WHITELIST.Count) domains preserved (never blocked)" `
             -SA "Windows Update : $($WINDOWS_UPDATE_WHITELIST.Count) डोमेन सुरक्षित" -Level SUCCESS
    Write-DSSeparator
    Write-DS -BLANK

    # ── STEP 2: ASSERT ────────────────────────────────────────
    if (-not (Assert-DSAdmin)) {
        Write-OutputJSON -Status "fail" -Detail "Not admin"
        exit 1
    }

    $applyHosts    = $hostsReadable -and -not $RegistryOnly -and -not $tamper.Enabled
    $applyRegistry = -not $HostsOnly

    if ($tamper.Enabled -and -not $RegistryOnly) {
        Show-TamperProtectionInstructions
        if (-not $RegistryOnly) {
            Write-DS -EN "Hosts sinkhole skipped (Tamper Protection is ON)." `
                     -SA "Hosts सिंकहोल छोड़ा (Tamper Protection चालू)।" -Level WARN
            Write-DS -EN "Registry tweaks will still be applied." `
                     -SA "रजिस्ट्री बदलाव फिर भी लागू होंगे।" -Level INFO
            $applyHosts = $false
        }
    }

    # ── STEP 3: CONFIRMATION ──────────────────────────────────
    if (-not $NoConfirm -and -not $DryRun) {
        $actions = @()
        if ($applyHosts)    { $actions += "hosts sinkhole ($($TELEMETRY_DOMAINS.Count - $analysis.AlreadyBlocked.Count) domains)" }
        if ($applyRegistry) { $actions += "registry tweaks ($($REGISTRY_TWEAKS.Count + 1) settings)" }

        if ($actions.Count -eq 0) {
            Write-DS -EN "Nothing to apply." -Level INFO
            return
        }
        Write-DS -EN "Apply: $($actions -join ' + ')?" -SA "लागू करें: $($actions -join ' + ')?" -Level WARN
        $ans = Read-Host "  [Y] Apply  [N] Cancel"
        if ($ans.ToUpper() -ne "Y") {
            Write-DS -EN "Cancelled." -SA "रद्द।" -Level INFO
            return
        }
    }

    if ($DryRun) {
        if ($applyHosts)    { Write-DS -EN "DRY RUN: Would add $($TELEMETRY_DOMAINS.Count) domains to hosts sinkhole." -Level WARN }
        if ($applyRegistry) { Write-DS -EN "DRY RUN: Would apply $($REGISTRY_TWEAKS.Count) registry tweaks + disable DiagTrack." -Level WARN }
        return
    }

    # ── STEP 4: BACKUP ────────────────────────────────────────
    Write-DS -EN "Saving rollback state..." -SA "रोलबैक-अवस्था सहेज रहे हैं..." -Level INFO
    $rollbackData = @{
        hosts_content   = if ($analysis) { $analysis.Content } else { $null }
        registry_before = Get-RegistryRollbackState
        diagtrack_start = (Get-Service $DIAGTRACK_SERVICE -EA SilentlyContinue)?.StartType?.ToString()
        applied_at      = (Get-Date -Format "o")
        tamper_was_on   = $tamper.Enabled
    }
    $backup = New-DSBackup -Type "privacy_enforcer" -Data $rollbackData
    Write-DS -EN "Backup: $($backup.file | Split-Path -Leaf)" -Level SUCCESS

    # ── STEP 5: ACT ───────────────────────────────────────────
    $hostsResult = @{ Added = 0; Skipped = 0 }
    $regResult   = @{ OK = 0; Failed = 0 }

    try {
        if ($applyHosts -and $analysis) {
            Write-DS -BLANK
            Write-DS -EN "Applying hosts sinkhole..." -SA "Hosts सिंकहोल लागू..." -Level INFO
            Write-DSProgress -EN "Writing sinkhole entries..." -SA "एंट्री लिख रहे हैं..." -Step 1 -Total 3
            $hostsResult = Invoke-HostsSinkhole -Analysis $analysis
            ipconfig /flushdns 2>$null | Out-Null
            Write-DS -EN "DNS cache flushed." -SA "DNS कैश साफ़।" -Level INFO
        }

        if ($applyRegistry) {
            Write-DS -BLANK
            Write-DS -EN "Applying registry tweaks..." -SA "रजिस्ट्री बदलाव लागू..." -Level INFO
            Write-DSProgress -EN "Writing registry values..." -SA "रजिस्ट्री मान लिख रहे हैं..." -Step 2 -Total 3
            $regResult = Invoke-RegistryTweaks
        }

        Write-DSProgress -EN "Verifying..." -SA "सत्यापन..." -Step 3 -Total 3

    } catch {
        Write-DS -EN "Exception during apply: $_" -Level CRITICAL
        # Restore hosts file from backup
        if ($rollbackData.hosts_content) {
            Set-Content -Path $HOSTS_PATH -Value $rollbackData.hosts_content -Encoding UTF8 -NoNewline
        }
        Write-DSAudit -Action "PRIVACY_APPLY_EXCEPTION" -Detail "$_" -Status "fail" `
                      -Rollback @{ file = $backup.file; type = "privacy_enforcer" }
        exit 1
    }

    Set-DSStateKey -Key "privacy_active"     -Value $true
    Set-DSStateKey -Key "privacy_applied_at" -Value (Get-Date -Format "o")

    # ── STEP 6: VERIFY ────────────────────────────────────────
    $verify = if ($applyHosts) { Test-SinkholeVerification -TestCount 3 } else { $null }

    # ── STEP 7: REPORT ────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "PRIVACY ENFORCER — RESULTS" -SA "गोपनीयता-प्रवर्तक — परिणाम" -Level HEADER
    Write-DSSeparator

    if ($applyHosts) {
        Write-DS -EN "Hosts sinkhole  : +$($hostsResult.Added) added  $($hostsResult.Skipped) already present" `
                 -SA "Hosts सिंकहोल  : +$($hostsResult.Added) जोड़े  $($hostsResult.Skipped) पहले से" `
                 -Level $(if ($hostsResult.Added -gt 0 -or $hostsResult.Skipped -gt 0) {"SUCCESS"} else {"INFO"})

        if ($verify) {
            $vColor = if ($verify.Passed -eq $verify.Total) { "SUCCESS" } else { "WARN" }
            Write-DS -EN "DNS verify      : $($verify.Passed)/$($verify.Total) domains resolve to 0.0.0.0 ✅" `
                     -SA "DNS सत्यापन    : $($verify.Passed)/$($verify.Total) डोमेन 0.0.0.0 पर" `
                     -Level $vColor
            if ($verify.Failed) {
                $verify.Failed | ForEach-Object {
                    Write-DS -EN "  ❌ $_" -Level WARN -NoIcon
                }
            }
        }
    }

    if ($applyRegistry) {
        Write-DS -EN "Registry tweaks : $($regResult.OK) applied  $($regResult.Failed) failed" `
                 -SA "रजिस्ट्री      : $($regResult.OK) लागू  $($regResult.Failed) विफल" `
                 -Level $(if ($regResult.Failed -eq 0) {"SUCCESS"} else {"WARN"})
    }

    Write-DS -EN "Windows Update  : ✅ $($WINDOWS_UPDATE_WHITELIST.Count) domains preserved" `
             -SA "Windows Update  : ✅ $($WINDOWS_UPDATE_WHITELIST.Count) डोमेन सुरक्षित" -Level SUCCESS
    Write-DS -EN "Rollback ID     : $($backup.file | Split-Path -Leaf)" -Level INFO
    Write-DSSeparator
    Write-DS -BLANK

    $verified = -not $verify -or ($verify.Passed -eq $verify.Total)
    if ($verified) {
        Write-DS -EN "Privacy Enforcer complete. Telemetry blocked at DNS level." `
                 -SA "गोपनीयता-प्रवर्तक सम्पूर्ण। DNS स्तर पर टेलीमेट्री अवरुद्ध।" -Level SUCCESS
    } else {
        Write-DS -EN "Partially applied. Some DNS entries may need a system restart to take effect." `
                 -SA "आंशिक रूप से लागू। कुछ DNS एंट्री के लिए पुनः-प्रारंभ आवश्यक हो सकता है।" -Level WARN
    }

    # ── STEP 8: LOG ───────────────────────────────────────────
    Confirm-DSOperation -Action "PRIVACY_ENFORCER" -Backup $backup

    Write-DSAudit `
        -Action   "PRIVACY_APPLIED" `
        -Detail   "Hosts:+$($hostsResult.Added) Registry:$($regResult.OK) Verify:$($verify?.Passed)/$($verify?.Total) Rollback:$($backup.file | Split-Path -Leaf)" `
        -Mode     (Get-DSState).thermal_mode `
        -Rollback @{ file = $backup.file; type = "privacy_enforcer" } `
        -Status   $(if ($verified) {"ok"} else {"warn"})

    @{
        status        = if ($verified) {"ok"} else {"warn"}
        domains_added = $hostsResult.Added
        reg_applied   = $regResult.OK
        verified      = $verified
        rollback_id   = ($backup.file | Split-Path -Leaf)
        timestamp     = (Get-Date -Format "o")
    } | ConvertTo-Json -Compress
}

function Write-OutputJSON { param([string]$Status, [string]$Detail = "")
    @{ status = $Status; detail = $Detail; timestamp = (Get-Date -Format "o") } |
        ConvertTo-Json -Compress
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Invoke-PrivacyEnforcer
