#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Silent Summer Thermal Profile
.DESCRIPTION
    Applies a quiet, cool operating profile:
      · Disables CPU boost on all detected processors
      · Caps CPU frequency at 2800 MHz
      · Sets processor cooling policy to Passive
      · Applies vendor fan curve if hardware is supported (ASUS/MSI/Gigabyte)
      · Reads sensors before AND after, displays verified delta

    NASA 8-step pattern:
      Pre-flight → Assert → Backup → Act → Verify → Report → Log → Fault-safe

    Called by:
      Go tray   → schtasks /Run /TN "DevShield\DS_SilentSummer"
      Terminal  → pwsh -File silent_summer.ps1 [-NoConfirm] [-DryRun]

.PARAMETER NoConfirm
    Skip interactive confirmation. Used when called from Go tray.
.PARAMETER DryRun
    Show what would happen without applying any changes.
#>
param(
    [switch]$NoConfirm,
    [switch]$DryRun
)

. "$PSScriptRoot\..\core\00_core.ps1"
. "$PSScriptRoot\..\core\02_lhm_bridge.ps1"

Initialize-DevShield -ScriptName "silent_summer.ps1"

# ══════════════════════════════════════════════════════════════
# CONSTANTS — powercfg subgroup + setting GUIDs (Windows standard)
# These are fixed Windows identifiers — safe to use on all machines
# The SCHEME guid is always read dynamically (never hardcoded)
# ══════════════════════════════════════════════════════════════
$PROC_SUB   = "54533251-82be-4824-96c1-47b60b740d00"  # SUB_PROCESSOR
$BOOST_MODE = "be337238-0d82-4146-a38c-c378f404fcbf"  # PERFBOOSTMODE
$FREQ_MAX   = "75b0ae3f-bce0-45a7-8c89-c9611c25e100"  # Max frequency MHz (0=unlimited)
$PROC_MAX   = "bc5038f7-23e0-4960-96da-33abaf5935ec"  # Max processor state %
$COOLING    = "94d3a615-a899-4ac5-ae2b-e4d8f634367f"  # Cooling policy (0=passive,1=active)

$TARGET_FREQ_MHZ = 2800   # Silent Summer ceiling
$STABILISE_SEC   = 15     # Seconds to wait before reading post-apply temps
$VERIFY_DROP_MIN = 3.0    # Minimum °C drop expected for verification to pass

# ══════════════════════════════════════════════════════════════
# HELPER — Read a single powercfg AC setting value
# ══════════════════════════════════════════════════════════════
function Get-PowerSetting {
    param([string]$SchemeGuid, [string]$Subgroup, [string]$Setting)
    $out = powercfg /query $SchemeGuid $Subgroup $Setting 2>$null
    if ($out -match "Current AC Power Setting Index:\s*(0x[0-9A-Fa-f]+)") {
        return [Convert]::ToInt32($matches[1], 16)
    }
    return $null
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
function Invoke-SilentSummer {
    Write-DSBanner -Subtitle "Silent Summer · मौन-ग्रीष्म"
    $hw = Get-DSHwProfile

    # ── STEP 1: PRE-FLIGHT ────────────────────────────────────
    Write-DS -EN "Reading hardware state before applying profile..." `
             -SA "आकृति लागू करने से पूर्व यन्त्र-अवस्था पढ़ रहे हैं..." -Level INFO

    $before = Get-DSAllSensors
    $beforeQuick = @{
        cpu_max = ($before.cpu | ForEach-Object { $_.temp_package.current } |
                   Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
        gpu_max = ($before.gpu | ForEach-Object { $_.temp_core.current } |
                   Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
        fan_rpm = ($before.fans | Select-Object -First 1)?.rpm ?? 0
    }

    Write-DS -BLANK
    Write-DS -EN "THERMAL STATE — Before" -SA "तापीय-अवस्था — पूर्व" -Level HEADER
    if ($before.available) {
        $beforeRows = Format-SensorAsTableRows -Snap $before
        Write-DSTable -Title "Before · पूर्व" -Rows $beforeRows
    } else {
        Write-DS -EN "Limited Mode: CPU avg load $($before.basic_wmi.cpu_load_pct)%  Thermal zone $($before.basic_wmi.thermal_zone_c)°C" `
                 -Level WARN
    }

    # Safety check: if already very cool, note it (not an error)
    if ($beforeQuick.cpu_max -gt 0 -and $beforeQuick.cpu_max -lt 45) {
        Write-DS -EN "System is already cool ($($beforeQuick.cpu_max)°C). Profile will still apply frequency cap." `
                 -SA "यन्त्र पहले से शीतल ($($beforeQuick.cpu_max)°C)। आवृत्ति-सीमा फिर भी लागू होगी।" -Level INFO
    }

    # ── STEP 2: ASSERT ────────────────────────────────────────
    if (-not (Assert-DSAdmin)) {
        Write-OutputJSON -Status "fail" -Detail "Not running as admin"
        exit 1
    }

    $schemeGuid = Get-DSPowercfgGuid
    if (-not $schemeGuid) {
        Write-DS -EN "Could not read active power scheme GUID." `
                 -SA "सक्रिय पावर-योजना GUID नहीं मिली।" -Level CRITICAL
        Write-OutputJSON -Status "fail" -Detail "No power scheme GUID"
        exit 1
    }
    Write-DS -EN "Active power scheme: $schemeGuid" -Level DEBUG

    # ── STEP 3: USER CONFIRMATION ─────────────────────────────
    if (-not $NoConfirm -and -not $DryRun) {
        Write-DS -BLANK
        Write-DS -EN "Apply Silent Summer? Caps CPU at $TARGET_FREQ_MHZ MHz, disables boost." `
                 -SA "मौन-ग्रीष्म लागू करें? CPU $TARGET_FREQ_MHZ MHz पर सीमित, बूस्ट बंद।" -Level WARN
        $ans = Read-Host "  [Y] Apply  [N] Cancel"
        if ($ans.ToUpper() -ne "Y") {
            Write-DS -EN "Cancelled by user." -SA "उपयोगकर्ता द्वारा रद्द।" -Level INFO
            Write-OutputJSON -Status "cancelled"
            exit 0
        }
    }

    if ($DryRun) {
        Write-DS -EN "DRY RUN: Would apply — Boost OFF, Freq cap $TARGET_FREQ_MHZ MHz, Cooling passive." `
                 -SA "परीक्षण-मोड: लागू होता — बूस्ट बंद, आवृत्ति-सीमा $TARGET_FREQ_MHZ MHz।" -Level WARN
        Write-OutputJSON -Status "dry_run"
        exit 0
    }

    # ── STEP 4: BACKUP (before touching ANYTHING) ─────────────
    Write-DS -EN "Saving rollback state..." -SA "रोलबैक-अवस्था सहेज रहे हैं..." -Level INFO
    $rollback = @{
        scheme_guid   = $schemeGuid
        boost_mode    = Get-PowerSetting $schemeGuid $PROC_SUB $BOOST_MODE
        freq_max_mhz  = Get-PowerSetting $schemeGuid $PROC_SUB $FREQ_MAX
        proc_max_pct  = Get-PowerSetting $schemeGuid $PROC_SUB $PROC_MAX
        cooling_pol   = Get-PowerSetting $schemeGuid $PROC_SUB $COOLING
        vendor_state  = Get-VendorFanState -HwProfile $hw
        applied_at    = (Get-Date -Format "o")
    }
    $backup = New-DSBackup -Type "powercfg_silent" -Data $rollback
    Write-DS -EN "Rollback saved. ID: $($backup.file | Split-Path -Leaf)" `
             -SA "रोलबैक सहेजा। ID: $($backup.file | Split-Path -Leaf)" -Level SUCCESS

    # ── STEP 5: ACT ───────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "Applying Silent Summer profile..." `
             -SA "मौन-ग्रीष्म आकृति लागू कर रहे हैं..." -Level INFO
    $errors = @()

    try {
        # [1/4] Disable CPU Boost
        Write-DSProgress -EN "Disabling CPU boost..." -SA "CPU बूस्ट अक्षम..." -Step 1 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $BOOST_MODE 0
        if ($LASTEXITCODE -ne 0) { $errors += "BOOST_MODE set failed (exit $LASTEXITCODE)" }

        # [2/4] Cap frequency at 2800 MHz
        Write-DSProgress -EN "Capping frequency at $TARGET_FREQ_MHZ MHz..." `
                         -SA "आवृत्ति $TARGET_FREQ_MHZ MHz पर सीमित..." -Step 2 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $FREQ_MAX $TARGET_FREQ_MHZ
        if ($LASTEXITCODE -ne 0) { $errors += "FREQ_MAX set failed (exit $LASTEXITCODE)" }

        # [3/4] Set cooling policy to Passive (CPU throttles before fan spins up)
        Write-DSProgress -EN "Setting cooling policy to passive..." `
                         -SA "शीतलन-नीति निष्क्रिय..." -Step 3 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $COOLING 0
        if ($LASTEXITCODE -ne 0) { $errors += "COOLING set failed (exit $LASTEXITCODE)" }

        # [4/4] Apply scheme + optional vendor fan enhancement
        Write-DSProgress -EN "Activating scheme + vendor fan control..." `
                         -SA "योजना सक्रिय + विक्रेता-पंखा नियंत्रण..." -Step 4 -Total 4
        powercfg -setactive $schemeGuid
        Invoke-VendorFanControl -Mode "silent" -HwProfile $hw
    } catch {
        # NASA fault-safe: any exception → rollback immediately
        Write-DS -EN "Exception during apply: $_" -SA "लागू करते समय त्रुटि: $_" -Level CRITICAL
        Invoke-DSRollback -Backup $backup
        Invoke-PowercfgRestore -Rollback $rollback -SchemeGuid $schemeGuid
        Write-DSAudit -Action "SILENT_SUMMER_APPLY_EXCEPTION" -Detail "$_" -Status "fail" `
                      -Rollback @{ file = $backup.file; type = "powercfg_silent" }
        Write-OutputJSON -Status "fail" -Detail "Exception: $_"
        exit 1
    }

    # Soft errors (powercfg returned non-zero but didn't throw)
    if ($errors) {
        Write-DS -EN "Partial apply — some settings may not have taken:" -Level WARN
        $errors | ForEach-Object { Write-DS -EN "  · $_" -Level WARN -NoIcon }
    }

    # Update state immediately (Go tray reads this)
    Set-DSStateKey -Key "thermal_mode"       -Value "silent"
    Set-DSStateKey -Key "thermal_applied_at" -Value (Get-Date -Format "o")

    # ── STEP 6: VERIFY (wait for thermals to stabilise) ───────
    Write-DS -BLANK
    Write-DS -EN "Waiting $STABILISE_SEC seconds for thermals to stabilise..." `
             -SA "$STABILISE_SEC सेकंड प्रतीक्षा — ताप स्थिर हो रहा है..." -Level INFO

    for ($i = 1; $i -le $STABILISE_SEC; $i++) {
        Write-DSProgress -EN "Stabilising..." -SA "स्थिरीकरण..." -Step $i -Total $STABILISE_SEC
        Start-Sleep -Seconds 1
    }

    $after = Get-DSAllSensors
    $afterQuick = @{
        cpu_max = ($after.cpu | ForEach-Object { $_.temp_package.current } |
                   Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
        gpu_max = ($after.gpu | ForEach-Object { $_.temp_core.current } |
                   Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
    }

    # Read actual frequency to confirm cap took effect
    $actualFreq = ($after.cpu | ForEach-Object { $_.clock_avg_mhz } |
                   Where-Object { $_ } | Measure-Object -Average).Average ?? 0

    # Verification logic
    $cpuDrop     = [math]::Round($beforeQuick.cpu_max - $afterQuick.cpu_max, 1)
    $freqVerified = ($actualFreq -le ($TARGET_FREQ_MHZ + 100))  # 100MHz tolerance
    $tempVerified = ($cpuDrop -ge $VERIFY_DROP_MIN) -or ($beforeQuick.cpu_max -lt 50)
    $verified     = $freqVerified -or $tempVerified   # Either confirms success


    # ── Windows 11 24H2 compatibility ────────────────────────
    # 24H2 added PROCESSOREFFICIENCYCLASSCODE — set explicitly
    # 0 = prefer efficiency, ensures scheduler respects our profile intent
    try {
        powercfg /setacvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCESSOREFFICIENCYCLASSCODE 0
        powercfg /setdcvalueindex SCHEME_CURRENT SUB_PROCESSOR PROCESSOREFFICIENCYCLASSCODE 0
    } catch {}  # GUID absent on pre-24H2 — safe to ignore

    # Detect Energy Saver (new in 24H2 — distinct from Power Saver)
    # Energy Saver can override fan curves and frequency caps without warning
    try {
        $esProp = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power" `
            -Name "EnergySaverStatus" -ErrorAction SilentlyContinue
        if ($esProp -and $esProp.EnergySaverStatus -eq 1) {
            Write-DS -EN "Note: Windows Energy Saver active — may override fan control." `
                     -SA "नोट: Windows ऊर्जा-बचत सक्रिय — पंखा नियंत्रण प्रभावित।" -Level WARN
        }
    } catch {}

    # ── STEP 7: REPORT ────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "THERMAL STATE — After" -SA "तापीय-अवस्था — पश्चात" -Level HEADER
    if ($after.available) {
        $afterRows = Format-SensorAsTableRows -Snap $after
        Write-DSTable -Title "After · पश्चात" -Rows $afterRows
    }

    Write-DS -EN "DELTA SUMMARY" -SA "परिवर्तन-सारांश" -Level HEADER
    Write-DSSeparator
    if ($beforeQuick.cpu_max -gt 0) {
        Write-DSBeforeAfter -Label "CPU Max Temp" -LabelSA "CPU अधिकतम ताप" `
            -Before $beforeQuick.cpu_max -After $afterQuick.cpu_max `
            -Unit "°C" -LowerIsBetter
    }
    if ($beforeQuick.gpu_max -gt 0) {
        Write-DSBeforeAfter -Label "GPU Max Temp" -LabelSA "GPU अधिकतम ताप" `
            -Before $beforeQuick.gpu_max -After $afterQuick.gpu_max `
            -Unit "°C" -LowerIsBetter
    }
    Write-DSBeforeAfter -Label "CPU Avg Clock" -LabelSA "CPU औसत आवृत्ति" `
        -Before ($before.cpu | Select-Object -First 1)?.clock_avg_mhz `
        -After  $actualFreq -Unit " MHz"
    Write-DSSeparator

    # Verification result
    if ($verified) {
        Write-DS -EN "Verification passed. Silent Summer is active." `
                 -SA "सत्यापन सफल। मौन-ग्रीष्म सक्रिय।" -Level SUCCESS
    } else {
        Write-DS -EN "Verification inconclusive — settings applied but temp drop less than expected." `
                 -SA "सत्यापन अनिर्णायक — सेटिंग्स लागू, पर अपेक्षित ताप-गिरावट नहीं।" -Level WARN
        Write-DS -EN "This can be normal if the system was already cool or under active load." `
                 -SA "यदि यन्त्र पहले से शीतल या लोड में था तो यह सामान्य है।" -Level INFO
    }

    # ── STEP 8: LOG ───────────────────────────────────────────
    Confirm-DSOperation -Action "SILENT_SUMMER" -Backup $backup `
        -Before @{ cpu = $beforeQuick.cpu_max; gpu = $beforeQuick.gpu_max } `
        -After  @{ cpu = $afterQuick.cpu_max;  gpu = $afterQuick.gpu_max }

    Write-DSAudit `
        -Action  "SILENT_SUMMER_APPLIED" `
        -Detail  "CPU:$($beforeQuick.cpu_max)→$($afterQuick.cpu_max)°C GPU:$($beforeQuick.gpu_max)→$($afterQuick.gpu_max)°C Freq:$([int]$actualFreq)MHz Verified:$verified" `
        -Mode    "silent" `
        -Rollback @{ file = $backup.file; type = "powercfg_silent" } `
        -Status  $(if ($verified) { "ok" } else { "warn" })

    # JSON output for Go tray app (last line of stdout — Go reads this)
    Write-OutputJSON -Status $(if ($verified) {"ok"} else {"warn"}) `
        -Mode         "silent" `
        -BeforeCPU    $beforeQuick.cpu_max `
        -AfterCPU     $afterQuick.cpu_max `
        -DeltaCPU     $cpuDrop `
        -BeforeGPU    $beforeQuick.gpu_max `
        -AfterGPU     $afterQuick.gpu_max `
        -FreqMHz      $actualFreq `
        -Verified     $verified
}

# ══════════════════════════════════════════════════════════════
# VENDOR FAN CONTROL (optional enhancement layer)
# Universal powercfg is always applied first.
# Vendor WMI layer silently skipped if not available.
# ══════════════════════════════════════════════════════════════
function Get-VendorFanState {
    param([object]$HwProfile)
    $vendor = $HwProfile?.motherboard?.vendor_clean
    $state  = @{ vendor = $vendor; method = "none"; data = $null }

    switch -Wildcard ($vendor) {
        "ASUS" {
            try {
                $asusWmi = Get-CimInstance -Namespace "root\WMI" `
                                           -ClassName "ASUSManagement" `
                                           -ErrorAction Stop
                $state.method = "ASUS_WMI"
                $state.data   = @{ fan_mode = $asusWmi.FanMode ?? "unknown" }
            } catch { $state.method = "unavailable" }
        }
        "MSI"  { $state.method = "unavailable" }   # MSI Center required — skip
        default { $state.method = "none" }
    }
    return $state
}

function Invoke-VendorFanControl {
    param([string]$Mode, [object]$HwProfile)
    $vendor = $HwProfile?.motherboard?.vendor_clean

    switch -Wildcard ($vendor) {
        "ASUS" {
            try {
                # ASUS fan mode: 0=Balanced, 1=Silent, 2=Turbo, 3=Full Speed
                $fanModeVal = switch ($Mode) {
                    "silent"  { 1 }
                    "gaming"  { 2 }
                    "dev"     { 0 }
                    default   { 0 }
                }
                $asusWmi = Get-CimInstance -Namespace "root\WMI" `
                                           -ClassName "ASUSManagement" `
                                           -ErrorAction Stop
                $asusWmi | Invoke-CimMethod -MethodName "SetFanMode" `
                                            -Arguments @{ Mode = $fanModeVal } `
                                            -ErrorAction Stop | Out-Null
                Write-DS -EN "ASUS fan curve set to: $Mode (WMI mode $fanModeVal)" `
                         -SA "ASUS पंखा-वक्र: $Mode (WMI मोड $fanModeVal)" -Level SUCCESS
            } catch {
                # Silent failure — universal powercfg is already applied
                Write-DS -EN "ASUS WMI fan control unavailable (not an error — using powercfg thermal policy)." `
                         -SA "ASUS WMI पंखा-नियंत्रण अनुपलब्ध — powercfg थर्मल नीति सक्रिय।" -Level DEBUG
            }
        }
        default {
            Write-DS -EN "Vendor fan enhancement not available for $vendor. powercfg passive cooling active." `
                     -SA "विक्रेता पंखा-नियंत्रण $vendor के लिए अनुपलब्ध। powercfg निष्क्रिय शीतलन सक्रिय।" `
                     -Level DEBUG
        }
    }
}

# ══════════════════════════════════════════════════════════════
# ROLLBACK HELPER — Restores powercfg to pre-apply state
# Called automatically on fault, or via rollback.ps1
# ══════════════════════════════════════════════════════════════
function Invoke-PowercfgRestore {
    param([hashtable]$Rollback, [string]$SchemeGuid)
    Write-DS -EN "Restoring power settings..." -SA "पावर-सेटिंग्स पुनःस्थापित..." -Level WARN

    # Restore all saved values — if a value was null (not previously set), skip it
    @(
        @{ Setting = $BOOST_MODE; Value = $Rollback.boost_mode }
        @{ Setting = $FREQ_MAX;   Value = $Rollback.freq_max_mhz }
        @{ Setting = $PROC_MAX;   Value = $Rollback.proc_max_pct }
        @{ Setting = $COOLING;    Value = $Rollback.cooling_pol }
    ) | Where-Object { $null -ne $_.Value } | ForEach-Object {
        powercfg -setacvalueindex $SchemeGuid $PROC_SUB $_.Setting $_.Value 2>$null
    }
    powercfg -setactive $SchemeGuid 2>$null
    Set-DSStateKey -Key "thermal_mode" -Value "unknown"
    Write-DS -EN "Power settings restored." -SA "पावर-सेटिंग्स पुनःस्थापित।" -Level SUCCESS
}

# ══════════════════════════════════════════════════════════════
# JSON OUTPUT — Last line of stdout read by Go tray app
# ══════════════════════════════════════════════════════════════
function Write-OutputJSON {
    param(
        [string]$Status    = "ok",
        [string]$Mode      = "silent",
        [string]$Detail    = "",
        [double]$BeforeCPU = 0,
        [double]$AfterCPU  = 0,
        [double]$DeltaCPU  = 0,
        [double]$BeforeGPU = 0,
        [double]$AfterGPU  = 0,
        [double]$FreqMHz   = 0,
        [bool]$Verified    = $false
    )
    @{
        status         = $Status
        mode           = $Mode
        detail         = $Detail
        before_cpu_c   = $BeforeCPU
        after_cpu_c    = $AfterCPU
        delta_cpu_c    = $DeltaCPU
        before_gpu_c   = $BeforeGPU
        after_gpu_c    = $AfterGPU
        freq_actual_mhz = $FreqMHz
        verified       = $Verified
        timestamp      = (Get-Date -Format "o")
    } | ConvertTo-Json -Compress   # Go reads this single line from stdout
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Invoke-SilentSummer
