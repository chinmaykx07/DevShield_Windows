#Requires -Version 7.0
<#
.SYNOPSIS  DevShield — Gaming Gear Thermal Profile
.DESCRIPTION
    Applies a high-performance gaming profile:
      · Re-enables CPU boost (Aggressive mode)
      · Removes frequency ceiling (0 = unlimited)
      · Sets processor cooling policy to Active (fan first)
      · Applies vendor Turbo fan curve where supported

    Unique feature — THERMAL HEADROOM PRE-FLIGHT:
      Reads current temps and calculates projected peak under gaming load.
      If projected peak exceeds danger threshold, refuses to apply (or warns).
      This prevents boosting into an already-hot system.

    NASA 8-step pattern:
      Pre-flight → Assert → Backup → Act → Verify → Report → Log → Fault-safe

.PARAMETER NoConfirm  Skip user confirmation (called from Go tray via Task Scheduler)
.PARAMETER DryRun     Show what would happen without applying
.PARAMETER Force      Override thermal headroom safety check (use with caution)
#>
param(
    [switch]$NoConfirm,
    [switch]$DryRun,
    [switch]$Force
)

. "$PSScriptRoot\..\core\00_core.ps1"
. "$PSScriptRoot\..\core\02_lhm_bridge.ps1"

Initialize-DevShield -ScriptName "gaming_gear.ps1"

# ══════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════
$PROC_SUB   = "54533251-82be-4824-96c1-47b60b740d00"
$BOOST_MODE = "be337238-0d82-4146-a38c-c378f404fcbf"
$FREQ_MAX   = "75b0ae3f-bce0-45a7-8c89-c9611c25e100"
$PROC_MAX   = "bc5038f7-23e0-4960-96da-33abaf5935ec"
$COOLING    = "94d3a615-a899-4ac5-ae2b-e4d8f634367f"

# Gaming Gear target values
$BOOST_AGGRESSIVE = 2     # 0=off 1=enabled 2=aggressive 4=efficient-aggressive
$FREQ_UNLIMITED   = 0     # 0 = no cap — let the CPU boost freely
$PROC_MAX_FULL    = 100   # 100% max processor state
$COOLING_ACTIVE   = 1     # 1 = Active (spin fan before throttling)

# Thermal headroom model
# Expected temperature rise from idle → full gaming load
$CPU_GAMING_OVERHEAD_C = 20   # conservative estimate for most desktops/laptops
$GPU_GAMING_OVERHEAD_C = 25
$CPU_SAFE_CEILING_C    = 85   # warn above this projected peak
$CPU_DANGER_CEILING_C  = 92   # refuse unless -Force above this
$GPU_HOTSPOT_CEILING_C = 100  # GPU hotspot danger ceiling

$VERIFY_WAIT_SEC = 5    # Settings verification (not thermal — gaming gear raises temps)

# ══════════════════════════════════════════════════════════════
# SHARED PROFILE HELPERS
# Note: these mirror the helpers in silent_summer.ps1.
# If the codebase grows, extract to profiles/shared.ps1.
# ══════════════════════════════════════════════════════════════
function Get-PowerSetting {
    param([string]$SchemeGuid, [string]$Subgroup, [string]$Setting)
    $out = powercfg /query $SchemeGuid $Subgroup $Setting 2>$null
    if ($out -match "Current AC Power Setting Index:\s*(0x[0-9A-Fa-f]+)") {
        return [Convert]::ToInt32($matches[1], 16)
    }
    return $null
}

function Write-OutputJSON {
    param(
        [string]$Status   = "ok",
        [string]$Mode     = "gaming",
        [string]$Detail   = "",
        [double]$CpuTemp  = 0,
        [double]$GpuTemp  = 0,
        [bool]$BoostOn    = $false,
        [int]$FreqCap     = 0,
        [bool]$Verified   = $false
    )
    @{
        status       = $Status
        mode         = $Mode
        detail       = $Detail
        cpu_temp_c   = $CpuTemp
        gpu_temp_c   = $GpuTemp
        boost_active = $BoostOn
        freq_cap_mhz = $FreqCap
        verified     = $Verified
        timestamp    = (Get-Date -Format "o")
    } | ConvertTo-Json -Compress
}

function Invoke-PowercfgRestore {
    param([hashtable]$Rollback, [string]$SchemeGuid)
    Write-DS -EN "Restoring power settings to pre-gaming state..." `
             -SA "पावर-सेटिंग्स पूर्व-अवस्था में लौटा रहे हैं..." -Level WARN
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

function Invoke-VendorTurboFan {
    param([object]$HwProfile)
    $vendor = $HwProfile?.motherboard?.vendor_clean
    switch -Wildcard ($vendor) {
        "ASUS" {
            try {
                # ASUS fan mode 2 = Turbo
                $asusWmi = Get-CimInstance -Namespace "root\WMI" `
                                           -ClassName "ASUSManagement" -ErrorAction Stop
                $asusWmi | Invoke-CimMethod -MethodName "SetFanMode" `
                                            -Arguments @{ Mode = 2 } -ErrorAction Stop | Out-Null
                Write-DS -EN "ASUS fan curve set to: Turbo" -SA "ASUS पंखा: टर्बो" -Level SUCCESS
            } catch {
                Write-DS -EN "ASUS WMI fan control unavailable — powercfg Active cooling applied." `
                         -SA "ASUS WMI अनुपलब्ध — powercfg सक्रिय शीतलन लागू।" -Level DEBUG
            }
        }
        default {
            Write-DS -EN "Vendor fan turbo not available for $vendor — Active cooling policy set via powercfg." `
                     -SA "विक्रेता टर्बो $vendor के लिए अनुपलब्ध — सक्रिय शीतलन नीति सक्रिय।" -Level DEBUG
        }
    }
}

# ══════════════════════════════════════════════════════════════
# THE PRE-FLIGHT THERMAL HEADROOM ENGINE
# Unique to Gaming Gear — Silent Summer never needs this
# because lowering power always makes things safer.
# Here we are RAISING power, so we must verify headroom exists.
# ══════════════════════════════════════════════════════════════
function Invoke-ThermalHeadroomCheck {
    param([hashtable]$Sensors)

    Write-DS -EN "THERMAL HEADROOM PRE-FLIGHT" -SA "तापीय-रिक्तता पूर्व-परीक्षण" -Level HEADER
    Write-DSSeparator

    $cpuCurrent  = ($Sensors.cpu | ForEach-Object { $_.temp_package.current } |
                    Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
    $gpuCurrent  = ($Sensors.gpu | ForEach-Object { $_.temp_core.current } |
                    Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
    $gpuHotspot  = ($Sensors.gpu | ForEach-Object { $_.temp_hotspot.current } |
                    Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0

    $cpuProjected = $cpuCurrent + $CPU_GAMING_OVERHEAD_C
    $gpuProjected = $gpuCurrent + $GPU_GAMING_OVERHEAD_C
    $hotProjected = ($gpuHotspot -gt 0) ? ($gpuHotspot + $GPU_GAMING_OVERHEAD_C) : 0

    # CPU row
    $cpuHeadroom  = $CPU_SAFE_CEILING_C - $cpuProjected
    $cpuStatus    = if ($cpuProjected -lt $CPU_SAFE_CEILING_C) { "SAFE" }
                    elseif ($cpuProjected -lt $CPU_DANGER_CEILING_C) { "WARM" }
                    else { "DANGER" }

    # GPU row
    $gpuHeadroom  = $GPU_HOTSPOT_CEILING_C - $hotProjected
    $gpuStatus    = if ($hotProjected -lt 90)  { "SAFE" }
                    elseif ($hotProjected -lt $GPU_HOTSPOT_CEILING_C) { "WARM" }
                    else { "DANGER" }

    # Display the pre-flight table
    $rows = @(
        @{
            Sensor  = "CPU current"
            Value   = "$cpuCurrent°C"
            Icon    = Get-TempIcon $cpuCurrent
            Extra   = "at idle/light load"
            RawTemp = $cpuCurrent
        }
        @{
            Sensor  = "CPU projected (gaming)"
            Value   = "~$cpuProjected°C"
            Icon    = Get-TempIcon $cpuProjected
            Extra   = "+${CPU_GAMING_OVERHEAD_C}°C est. overhead"
            RawTemp = $cpuProjected
        }
        @{
            Sensor  = "CPU headroom"
            Value   = "${cpuHeadroom}°C"
            Icon    = if ($cpuHeadroom -gt 15) {"🟢"} elseif ($cpuHeadroom -gt 5) {"🟡"} else {"🔴"}
            Extra   = "before $CPU_SAFE_CEILING_C°C threshold · $cpuStatus"
            RawTemp = 0
        }
        @{ Divider = $true }
        @{
            Sensor  = "GPU core current"
            Value   = "$gpuCurrent°C"
            Icon    = Get-TempIcon $gpuCurrent
            Extra   = "at idle/light load"
            RawTemp = $gpuCurrent
        }
        @{
            Sensor  = "GPU projected (gaming)"
            Value   = "~$gpuProjected°C"
            Icon    = Get-TempIcon $gpuProjected
            Extra   = "+${GPU_GAMING_OVERHEAD_C}°C est. overhead"
            RawTemp = $gpuProjected
        }
        @{
            Sensor  = "GPU hotspot projected"
            Value   = if ($hotProjected -gt 0) {"~$hotProjected°C"} else {"N/A"}
            Icon    = if ($hotProjected -gt 0) {Get-TempIcon $hotProjected} else {"⬜"}
            Extra   = "limit $GPU_HOTSPOT_CEILING_C°C · $gpuStatus"
            RawTemp = $hotProjected
        }
    )
    Write-DSTable -Title "Headroom Check · रिक्तता-जाँच" `
                  -Headers @("Component","Projected","Notes") -Rows $rows

    # Decision logic
    $cpuDanger = ($cpuProjected -ge $CPU_DANGER_CEILING_C)
    $gpuDanger = ($hotProjected -ge $GPU_HOTSPOT_CEILING_C -and $hotProjected -gt 0)
    $cpuWarm   = ($cpuProjected -ge $CPU_SAFE_CEILING_C)
    $gpuWarm   = ($hotProjected -ge 90 -and $hotProjected -gt 0)

    if ($cpuDanger -or $gpuDanger) {
        Write-DS -EN "DANGER: Projected gaming temps exceed safety limits." `
                 -SA "खतरा: अनुमानित गेमिंग ताप सुरक्षा-सीमा पार करेगा।" -Level CRITICAL
        if ($cpuDanger) {
            Write-DS -EN "  CPU projected $cpuProjected°C — limit $CPU_DANGER_CEILING_C°C" -Level CRITICAL -NoIcon
        }
        if ($gpuDanger) {
            Write-DS -EN "  GPU hotspot projected $hotProjected°C — limit $GPU_HOTSPOT_CEILING_C°C" -Level CRITICAL -NoIcon
        }
        Write-DS -EN "Recommendation: clean dust filters, reapply thermal paste, ensure case airflow." `
                 -SA "सुझाव: धूल फ़िल्टर साफ़ करें, थर्मल पेस्ट लगाएं, केस वायुप्रवाह सुनिश्चित करें।" -Level WARN
        if (-not $Force) {
            Write-DS -EN "Apply cancelled for safety. Use -Force to override." `
                     -SA "सुरक्षा हेतु रद्द। -Force से ओवरराइड करें।" -Level CRITICAL
            return @{ safe = $false; warn = $false; cpu = $cpuProjected; gpu = $gpuProjected }
        }
        Write-DS -EN "-Force flag set. Applying despite danger reading. Monitor temps closely." `
                 -SA "-Force सक्रिय। खतरनाक रीडिंग के बावजूद लागू। ताप ध्यान से देखें।" -Level WARN
    } elseif ($cpuWarm -or $gpuWarm) {
        Write-DS -EN "WARNING: Projected temps are high but within operating range." `
                 -SA "चेतावनी: अनुमानित ताप अधिक पर संचालन-सीमा में।" -Level WARN
        Write-DS -EN "Monitor temperatures during gaming. Apply Silent Summer if throttling occurs." `
                 -SA "गेमिंग के दौरान ताप देखें। थ्रॉटलिंग पर मौन-ग्रीष्म लागू करें।" -Level WARN
        return @{ safe = $true; warn = $true; cpu = $cpuProjected; gpu = $gpuProjected }
    } else {
        Write-DS -EN "Pre-flight passed. CPU $cpuHeadroom°C headroom. GPU $gpuHeadroom°C headroom." `
                 -SA "पूर्व-परीक्षण सफल। CPU $cpuHeadroom°C रिक्तता। GPU $gpuHeadroom°C रिक्तता।" `
                 -Level SUCCESS
    }
    return @{ safe = $true; warn = $false; cpu = $cpuProjected; gpu = $gpuProjected }
}

# ══════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════
function Invoke-GamingGear {
    Write-DSBanner -Subtitle "Gaming Gear · क्रीडा-आवृत्ति"
    $hw = Get-DSHwProfile

    # ── STEP 1: PRE-FLIGHT ────────────────────────────────────
    Write-DS -EN "Reading hardware state and calculating thermal headroom..." `
             -SA "यन्त्र-अवस्था पढ़ रहे हैं और तापीय-रिक्तता गणना..." -Level INFO

    $before = Get-DSAllSensors
    $beforeQuick = @{
        cpu = ($before.cpu | ForEach-Object { $_.temp_package.current } |
               Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
        gpu = ($before.gpu | ForEach-Object { $_.temp_core.current } |
               Where-Object { $_ } | Measure-Object -Maximum).Maximum ?? 0
        clock = ($before.cpu | Select-Object -First 1)?.clock_avg_mhz ?? 0
        fan   = ($before.fans | Select-Object -First 1)?.rpm ?? 0
    }

    # Show current state
    Write-DS -BLANK
    Write-DS -EN "CURRENT STATE — Before Gaming Gear" `
             -SA "वर्तमान-अवस्था — क्रीडा-आवृत्ति पूर्व" -Level HEADER
    if ($before.available) {
        Write-DSTable -Title "Before · पूर्व" `
                      -Rows (Format-SensorAsTableRows -Snap $before)
    } else {
        Write-DS -EN "Limited Mode: CPU load $($before.basic_wmi.cpu_load_pct)%" -Level WARN
    }

    # Thermal headroom check
    Write-DS -BLANK
    $headroom = Invoke-ThermalHeadroomCheck -Sensors $before
    if (-not $headroom.safe) {
        Write-OutputJSON -Status "fail" -Detail "Thermal headroom check failed" `
                         -CpuTemp $headroom.cpu -GpuTemp $headroom.gpu
        exit 1
    }

    # ── STEP 2: ASSERT ────────────────────────────────────────
    if (-not (Assert-DSAdmin)) {
        Write-OutputJSON -Status "fail" -Detail "Not running as admin"
        exit 1
    }
    $schemeGuid = Get-DSPowercfgGuid
    if (-not $schemeGuid) {
        Write-DS -EN "Could not read active power scheme GUID." -Level CRITICAL
        Write-OutputJSON -Status "fail" -Detail "No power scheme GUID"
        exit 1
    }

    # ── STEP 3: USER CONFIRMATION ─────────────────────────────
    if (-not $NoConfirm -and -not $DryRun) {
        Write-DS -BLANK
        Write-DS -EN "Apply Gaming Gear? Enables boost, removes frequency cap." `
                 -SA "क्रीडा-आवृत्ति लागू करें? बूस्ट सक्षम, आवृत्ति-सीमा हटाएं।" -Level WARN
        if ($headroom.warn) {
            Write-DS -EN "Note: Projected temps are elevated. Watch thermals during heavy load." `
                     -SA "नोट: अनुमानित ताप अधिक। भारी लोड में ताप देखें।" -Level WARN
        }
        $ans = Read-Host "  [Y] Apply  [N] Cancel"
        if ($ans.ToUpper() -ne "Y") {
            Write-DS -EN "Cancelled." -SA "रद्द।" -Level INFO
            Write-OutputJSON -Status "cancelled"
            exit 0
        }
    }

    if ($DryRun) {
        Write-DS -EN "DRY RUN: Would apply — Boost AGGRESSIVE, Freq UNLIMITED, Cooling ACTIVE." `
                 -SA "परीक्षण-मोड: बूस्ट आक्रामक, आवृत्ति असीमित, सक्रिय शीतलन।" -Level WARN
        Write-OutputJSON -Status "dry_run"
        exit 0
    }

    # ── STEP 4: BACKUP ────────────────────────────────────────
    Write-DS -EN "Saving rollback state..." -SA "रोलबैक-अवस्था सहेज रहे हैं..." -Level INFO
    $rollback = @{
        scheme_guid  = $schemeGuid
        boost_mode   = Get-PowerSetting $schemeGuid $PROC_SUB $BOOST_MODE
        freq_max_mhz = Get-PowerSetting $schemeGuid $PROC_SUB $FREQ_MAX
        proc_max_pct = Get-PowerSetting $schemeGuid $PROC_SUB $PROC_MAX
        cooling_pol  = Get-PowerSetting $schemeGuid $PROC_SUB $COOLING
        applied_at   = (Get-Date -Format "o")
    }
    $backup = New-DSBackup -Type "powercfg_gaming" -Data $rollback
    Write-DS -EN "Rollback saved. ID: $($backup.file | Split-Path -Leaf)" `
             -SA "रोलबैक सहेजा। ID: $($backup.file | Split-Path -Leaf)" -Level SUCCESS

    # ── STEP 5: ACT ───────────────────────────────────────────
    Write-DS -BLANK
    Write-DS -EN "Applying Gaming Gear profile..." `
             -SA "क्रीडा-आवृत्ति आकृति लागू कर रहे हैं..." -Level INFO
    $errors = @()

    try {
        # [1/4] Enable boost (Aggressive)
        Write-DSProgress -EN "Enabling CPU boost (Aggressive)..." `
                         -SA "CPU बूस्ट सक्षम (आक्रामक)..." -Step 1 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $BOOST_MODE $BOOST_AGGRESSIVE
        if ($LASTEXITCODE -ne 0) { $errors += "BOOST_MODE set failed" }

        # [2/4] Remove frequency cap
        Write-DSProgress -EN "Removing frequency ceiling (unlimited)..." `
                         -SA "आवृत्ति-सीमा हटा रहे हैं (असीमित)..." -Step 2 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $FREQ_MAX $FREQ_UNLIMITED
        if ($LASTEXITCODE -ne 0) { $errors += "FREQ_MAX set failed" }

        # [3/4] Max processor state + Active cooling
        Write-DSProgress -EN "Setting max processor state + active cooling..." `
                         -SA "अधिकतम संसाधक-अवस्था + सक्रिय शीतलन..." -Step 3 -Total 4
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $PROC_MAX $PROC_MAX_FULL
        powercfg -setacvalueindex $schemeGuid $PROC_SUB $COOLING   $COOLING_ACTIVE
        if ($LASTEXITCODE -ne 0) { $errors += "COOLING set failed" }

        # [4/4] Activate scheme + vendor turbo fan
        Write-DSProgress -EN "Activating scheme + vendor turbo fan..." `
                         -SA "योजना सक्रिय + विक्रेता टर्बो पंखा..." -Step 4 -Total 4
        powercfg -setactive $schemeGuid
        Invoke-VendorTurboFan -HwProfile $hw

    } catch {
        Write-DS -EN "Exception during apply: $_" -Level CRITICAL
        Invoke-PowercfgRestore -Rollback $rollback -SchemeGuid $schemeGuid
        Write-DSAudit -Action "GAMING_GEAR_APPLY_EXCEPTION" -Detail "$_" -Status "fail" `
                      -Rollback @{ file = $backup.file; type = "powercfg_gaming" }
        Write-OutputJSON -Status "fail" -Detail "Exception: $_"
        exit 1
    }

    if ($errors) {
        Write-DS -EN "Partial apply:" -Level WARN
        $errors | ForEach-Object { Write-DS -EN "  · $_" -Level WARN -NoIcon }
    }

    Set-DSStateKey -Key "thermal_mode"       -Value "gaming"
    Set-DSStateKey -Key "thermal_applied_at" -Value (Get-Date -Format "o")

    # ── STEP 6: VERIFY — confirm settings took effect ─────────
    Write-DS -BLANK
    Write-DS -EN "Verifying settings applied (${VERIFY_WAIT_SEC}s)..." `
             -SA "सेटिंग्स सत्यापन (${VERIFY_WAIT_SEC}s)..." -Level INFO
    Start-Sleep -Seconds $VERIFY_WAIT_SEC

    $newBoost   = Get-PowerSetting $schemeGuid $PROC_SUB $BOOST_MODE
    $newFreqCap = Get-PowerSetting $schemeGuid $PROC_SUB $FREQ_MAX
    $newCooling = Get-PowerSetting $schemeGuid $PROC_SUB $COOLING
    $after      = Get-DSAllSensors
    $afterClock = ($after.cpu | Select-Object -First 1)?.clock_avg_mhz ?? 0

    $boostVerified   = ($newBoost   -gt 0)               # any non-zero = boost on
    $freqVerified    = ($newFreqCap -eq $FREQ_UNLIMITED)  # 0 = unlimited
    $coolingVerified = ($newCooling -eq $COOLING_ACTIVE)
    $verified        = $boostVerified -and $freqVerified


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
    Write-DS -EN "GAMING GEAR — VERIFICATION REPORT" `
             -SA "क्रीडा-आवृत्ति — सत्यापन-रिपोर्ट" -Level HEADER
    Write-DSSeparator

    Write-DS -EN "CPU Boost Mode  : $(if($boostVerified){'✅ ENABLED (Aggressive)'}else{'❌ Failed'})" `
             -SA "CPU बूस्ट       : $(if($boostVerified){'✅ सक्षम (आक्रामक)'}else{'❌ विफल'})" `
             -Level $(if ($boostVerified) {"SUCCESS"} else {"CRITICAL"})

    Write-DS -EN "Frequency Cap   : $(if($freqVerified){'✅ REMOVED (unlimited)'}else{"❌ Still capped at $newFreqCap MHz"})" `
             -SA "आवृत्ति-सीमा    : $(if($freqVerified){'✅ हटाई (असीमित)'}else{"❌ $newFreqCap MHz पर सीमित"})" `
             -Level $(if ($freqVerified) {"SUCCESS"} else {"CRITICAL"})

    Write-DS -EN "Cooling Policy  : $(if($coolingVerified){'✅ ACTIVE (fan first)'}else{'⚠ Not confirmed'})" `
             -Level $(if ($coolingVerified) {"SUCCESS"} else {"WARN"})

    if ($afterClock -gt 0) {
        Write-DS -EN "Current CPU Avg : $([int]$afterClock) MHz $(if($afterClock -gt 3000){'(boosting ✅)'}else{'(under light load — will boost under game load)'})" `
                 -Level INFO
    }

    Write-DSSeparator
    Write-DS -BLANK

    # Thermal projection reminder
    if ($headroom.warn) {
        Write-DS -EN "⚠  Reminder: Temps were elevated before applying. Monitor with [DevShield Dashboard]." `
                 -SA "⚠  स्मरण: लागू करने से पूर्व ताप अधिक था। Dashboard से निरीक्षण करें।" -Level WARN
    } else {
        Write-DS -EN "System has $([int]($CPU_SAFE_CEILING_C - $beforeQuick.cpu))°C headroom before thermal limit." `
                 -SA "तापीय-सीमा से $([int]($CPU_SAFE_CEILING_C - $beforeQuick.cpu))°C पहले यन्त्र सुरक्षित।" `
                 -Level SUCCESS
    }

    if ($verified) {
        Write-DS -EN "Gaming Gear is active. Enjoy your game." `
                 -SA "क्रीडा-आवृत्ति सक्रिय। खेल का आनंद लें।" -Level SUCCESS
    } else {
        Write-DS -EN "Settings partially applied. Rerun or check power plan manually." `
                 -SA "सेटिंग्स आंशिक रूप से लागू। पुनः चलाएं या पावर प्लान जाँचें।" -Level WARN
    }

    # ── STEP 8: LOG ───────────────────────────────────────────
    Confirm-DSOperation -Action "GAMING_GEAR" -Backup $backup

    Write-DSAudit `
        -Action   "GAMING_GEAR_APPLIED" `
        -Detail   "BoostMode:$newBoost FreqCap:$newFreqCap Cooling:$newCooling Clock:$([int]$afterClock)MHz Verified:$verified Headroom:$(if($headroom.warn){'WARN'}else{'SAFE'})" `
        -Mode     "gaming" `
        -Rollback @{ file = $backup.file; type = "powercfg_gaming" } `
        -Status   $(if ($verified) {"ok"} else {"warn"})

    Write-OutputJSON `
        -Status   $(if ($verified) {"ok"} else {"warn"}) `
        -Mode     "gaming" `
        -CpuTemp  $beforeQuick.cpu `
        -GpuTemp  $beforeQuick.gpu `
        -BoostOn  $boostVerified `
        -FreqCap  $newFreqCap `
        -Verified $verified
}

# ══════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════
Invoke-GamingGear
