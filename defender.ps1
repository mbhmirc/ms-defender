#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Defender performance audit, security configuration check, and
    exclusion advisor with risk-tiered recommendations.

.DESCRIPTION
    Best used during a real workload or performance issue, especially on
    servers where exclusions should be avoided unless the evidence clearly
    supports a narrow Microsoft Defender Antivirus tuning action.

    1. Validates exclusion discovery methods (optional, -ValidateExclusions).
    2. Discovers current exclusions via three fallback methods (Get-MpPreference,
       registry direct-read, MpCmdRun -GetFiles CAB extraction).
    3. Extracts diagnostic intelligence from MpSupportFiles.cab (effective config,
       scan skips, detection history, filter drivers, IFEO hijack check,
       network protection, device control, product health, WSC state, MDE hints).
    4. Audits Defender security configuration against best practices.
    5. Captures a live performance trace using New-MpPerformanceRecording.
    6. Optionally generates synthetic workload during recording (-ValidateLoad).
    7. Analyses the recording with Get-MpPerformanceReport (-Raw).
    8. Generates risk-tiered exclusion suggestions (BLOCKED/CAUTION/SAFE).
    9. Outputs colour-coded console report, JSON report, and HTML dashboard.

.PARAMETER RecordingSeconds
    How many seconds to capture the performance trace. Default: 600 (10 min).
    Longer recordings produce more representative results under real workloads.

.PARAMETER TopN
    Number of top items to show in each impact category. Default: 25.

.PARAMETER ReportPath
    Directory where reports are saved. Defaults to the script directory.

.PARAMETER StartAt
    Exact future date and time to begin the run. Use this when you want a
    one-off scheduled start such as 2026-04-03 23:30.

.PARAMETER StartAtTime
    Daily time-of-day to begin the run in the local time zone, using the next
    occurrence of that time. Example: 23:30 starts tonight if still in the
    future, otherwise tomorrow night.

.PARAMETER StrictCAB
    Generate and bind the report to one fresh MpSupportFiles.cab snapshot for
    this run. If a fresh CAB cannot be produced, the script stops instead of
    silently falling back to an older CAB.

.PARAMETER ValidateLoad
    Generate synthetic file/process workload during the recording period to
    produce meaningful scan data for testing or baseline analysis. For real
    troubleshooting, prefer running during the actual workload issue instead.

.PARAMETER SyntheticWorkloadMode
    Select the synthetic workload type used with -ValidateLoad:
    Mixed (default), PowerShell, or NativeExe.

.PARAMETER ValidateExclusions
    Add a temporary test exclusion and verify each discovery method can find it,
    then clean up. Tests the reliability of the exclusion discovery pipeline.

.PARAMETER VerboseCAB
    Extract and display full diagnostic details from the MpSupportFiles.cab,
    including effective config dump, full scan skip logs, MPLog analysis,
    and network protection state.

.PARAMETER NoOpenReport
    Do not automatically open the generated HTML report. Useful for looped or
    unattended validation runs.

.PARAMETER AIMode
    Generate an AI-ready export JSON and a review prompt alongside the normal
    report outputs for external analysis or second-opinion workflows.

.EXAMPLE
    .\defender.ps1
    .\defender.ps1 -RecordingSeconds 300 -TopN 30
    .\defender.ps1 -ValidateLoad -ValidateExclusions -VerboseCAB
    .\defender.ps1 -ValidateLoad -SyntheticWorkloadMode NativeExe -TopN 100
    .\defender.ps1 -RecordingSeconds 120 -ReportPath "C:\Reports"
    .\defender.ps1 -StartAtTime "23:30" -RecordingSeconds 300 -ReportPath "C:\Reports"
    .\defender.ps1 -StrictCAB -RecordingSeconds 300 -ReportPath "C:\Reports"
    .\defender.ps1 -RecordingSeconds 120 -AIMode
#>
[CmdletBinding()]
param(
    [ValidateRange(10, 900)]
    [int]$RecordingSeconds = 600,

    [ValidateRange(5, 100)]
    [int]$TopN = 25,

    [string]$ReportPath,

    [datetime]$StartAt,

    [string]$StartAtTime,

    [switch]$StrictCAB,

    [switch]$ValidateLoad,

    [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
    [string]$SyntheticWorkloadMode = 'Mixed',

    [switch]$ValidateExclusions,

    [switch]$VerboseCAB,

    [switch]$NoOpenReport,

    [switch]$AIMode
)

Set-StrictMode -Version Latest

# ═══════════════════════════════════════════════════════════════════════════════
#  RESOLVE REPORT PATH
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $ReportPath) {
    $ReportPath = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
}
if (-not (Test-Path $ReportPath)) {
    New-Item -ItemType Directory -Path $ReportPath -Force | Out-Null
}

$script:sessionId = Get-Date -Format 'yyyyMMdd_HHmmss'
$script:transcriptFile = Join-Path $ReportPath "DefenderPerf_$($script:sessionId).transcript.log"
$script:transcriptStarted = $false

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Write-Section([string]$Title) {
    $w = 66
    Write-Host ""
    Write-Host ("+" + ("=" * $w) + "+") -ForegroundColor Cyan
    Write-Host ("|  {0,-$($w - 3)}|" -f $Title) -ForegroundColor Cyan
    Write-Host ("+" + ("=" * $w) + "+") -ForegroundColor Cyan
}

function Write-OK([string]$msg) { Write-Host "  [OK]   $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-Bad([string]$msg) { Write-Host "  [FAIL] $msg" -ForegroundColor Red }
function Write-Info([string]$msg) { Write-Host "  [info] $msg" -ForegroundColor Gray }

function Close-RunTranscript {
    if (-not $script:transcriptStarted) { return }

    try { Stop-Transcript | Out-Null } catch { }
    $script:transcriptStarted = $false
}

function Exit-Script([int]$Code) {
    Close-RunTranscript
    exit $Code
}

function Write-ExceptionDetails($errorRecord) {
    if (-not $errorRecord) { return }

    $exception = $errorRecord.Exception
    if ($exception) {
        Write-Info "Exception type     : $($exception.GetType().FullName)"
        Write-Info "Exception message  : $($exception.Message)"
        if ($exception.InnerException) {
            Write-Info "Inner exception    : $($exception.InnerException.GetType().FullName): $($exception.InnerException.Message)"
        }
    }

    if ($errorRecord.FullyQualifiedErrorId) {
        Write-Info "FullyQualifiedId   : $($errorRecord.FullyQualifiedErrorId)"
    }
    if ($errorRecord.CategoryInfo) {
        Write-Info "Category           : $($errorRecord.CategoryInfo)"
    }
    if ($errorRecord.InvocationInfo -and $errorRecord.InvocationInfo.PositionMessage) {
        Write-Info "Position           : $($errorRecord.InvocationInfo.PositionMessage.Trim())"
    }
    if ($errorRecord.ScriptStackTrace) {
        Write-Info "Script stack       : $($errorRecord.ScriptStackTrace)"
    }
}

function Format-Duration([double]$ms) {
    if ($ms -lt 1) { return ("{0:N3} ms" -f $ms) }
    if ($ms -lt 1000) { return ("{0:N1} ms" -f $ms) }
    if ($ms -lt 60000) { return ("{0:N2} s" -f ($ms / 1000)) }
    return ("{0:N1} min" -f ($ms / 60000))
}

function HtmlEncode([string]$s) {
    if (-not $s) { return '' }
    return [System.Net.WebUtility]::HtmlEncode($s)
}

function Resolve-ScheduledStart {
    param(
        [Nullable[datetime]]$ExplicitStart,
        [string]$TimeOfDay,
        [bool]$ExplicitStartSpecified,
        [bool]$TimeOfDaySpecified
    )

    if ($ExplicitStartSpecified -and $TimeOfDaySpecified) {
        throw "Use either -StartAt or -StartAtTime, not both."
    }

    if ($TimeOfDaySpecified) {
        $parsedTime = [TimeSpan]::Zero
        if (-not [TimeSpan]::TryParse($TimeOfDay, [ref]$parsedTime)) {
            throw "StartAtTime must be a valid local time such as 23:30 or 23:30:00."
        }

        $now = Get-Date
        $candidate = [datetime]::Today.Add($parsedTime)
        if ($candidate -le $now.AddSeconds(5)) {
            $candidate = $candidate.AddDays(1)
        }

        return [PSCustomObject]@{
            StartAt   = $candidate
            Mode      = 'TimeOfDay'
            InputText = $TimeOfDay
        }
    }

    if ($ExplicitStartSpecified) {
        if ($ExplicitStart -le (Get-Date).AddSeconds(5)) {
            throw "StartAt must be in the future. Use -StartAtTime for the next daily occurrence."
        }

        return [PSCustomObject]@{
            StartAt   = $ExplicitStart
            Mode      = 'DateTime'
            InputText = $ExplicitStart.ToString('yyyy-MM-dd HH:mm:ss')
        }
    }

    return $null
}

function Wait-UntilScheduledStart {
    param(
        [Parameter(Mandatory)][datetime]$StartAt,
        [string]$Mode = 'DateTime',
        [string]$InputText
    )

    $waitStartedAt = Get-Date
    $remaining = $StartAt - $waitStartedAt
    if ($remaining.TotalSeconds -le 0) {
        return 0
    }

    $waitDescription = if ($remaining.TotalMinutes -ge 1) {
        "{0} minute(s)" -f [math]::Ceiling($remaining.TotalMinutes)
    }
    else {
        "{0} second(s)" -f [math]::Ceiling($remaining.TotalSeconds)
    }

    Write-Section "0 - Scheduled Start"
    Write-Info "Schedule mode   : $Mode"
    if ($InputText) {
        Write-Info "Requested input : $InputText"
    }
    Write-Info "Scheduled start : $($StartAt.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Info "Current time    : $($waitStartedAt.ToString('yyyy-MM-dd HH:mm:ss'))"
    Write-Info "Waiting         : $waitDescription"

    while ($true) {
        $remaining = $StartAt - (Get-Date)
        if ($remaining.TotalSeconds -le 0) {
            break
        }

        $sleepSeconds = [int][math]::Min([math]::Ceiling($remaining.TotalSeconds), 60)
        Start-Sleep -Seconds $sleepSeconds
    }

    return [math]::Round(((Get-Date) - $waitStartedAt).TotalSeconds, 1)
}

function Truncate([string]$s, [int]$maxLen = 55) {
    if (-not $s -or $s.Length -le $maxLen) { return $s }
    return ("..." + $s.Substring($s.Length - ($maxLen - 3)))
}

function Normalize-Extension([string]$ext) {
    if ([string]::IsNullOrWhiteSpace($ext)) { return $null }
    return $ext.Trim().TrimStart('.').ToLowerInvariant()
}

function Format-ExtensionDisplay([string]$ext) {
    $normalized = Normalize-Extension $ext
    if (-not $normalized) { return $null }
    return ".$normalized"
}

function Convert-DisabledFlagToEnabled($value) {
    if ($null -eq $value) { return $null }
    return (-not [bool]$value)
}

function Test-EligibleProcessPath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    if ($path -notmatch '^[A-Za-z]:\\') { return $false }

    $extension = [System.IO.Path]::GetExtension($path)
    if ([string]::IsNullOrWhiteSpace($extension) -or $extension.ToLowerInvariant() -ne '.exe') {
        return $false
    }

    return [bool](Test-Path -LiteralPath $path -PathType Leaf -ErrorAction SilentlyContinue)
}

function Test-VersionAtLeast([string]$versionString, [string]$minimumVersion) {
    if ([string]::IsNullOrWhiteSpace($versionString)) { return $false }
    try {
        return ([version]$versionString) -ge ([version]$minimumVersion)
    }
    catch {
        return $false
    }
}

function Format-ContextualExclusionPath([string]$path, [string]$pathType, [string]$scanTrigger, [string]$processPath) {
    $cleanPath = $path.TrimEnd('\')
    $escapedProcess = $processPath -replace '"', '\"'
    return "{0}\:{{PathType:{1},ScanTrigger:{2},Process:""{3}""}}" -f $cleanPath, $pathType, $scanTrigger, $escapedProcess
}

function Format-ExclusionProcessCommand([string]$processPath) {
    if ([string]::IsNullOrWhiteSpace($processPath)) { return $null }
    return "Add-MpPreference -ExclusionProcess '$($processPath -replace "'", "''")'"
}

function New-RankedFallback {
    param(
        [int]$TierOrder,
        [string]$Label,
        [string]$Command
    )

    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    return "Tier $TierOrder - ${Label}: $Command"
}

function Invoke-ExternalTool {
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$IgnoreExitCode
    )

    $output = & $FilePath @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE

    if (-not $IgnoreExitCode -and $exitCode -ne 0) {
        $preview = (@($output) | Select-Object -First 10) -join [Environment]::NewLine
        $name = [System.IO.Path]::GetFileName($FilePath)
        throw "$name exited with code $exitCode.$([Environment]::NewLine)$preview"
    }

    return [PSCustomObject]@{
        Output   = @($output)
        ExitCode = $exitCode
    }
}

function Invoke-WprCommand {
    param(
        [Parameter(Mandatory)][string[]]$ArgumentList,
        [switch]$IgnoreNoActiveTrace
    )

    $output = & wpr @ArgumentList 2>&1
    $exitCode = $LASTEXITCODE
    $text = (@($output) -join [Environment]::NewLine)
    $noActiveTrace = $text -match 'There are no trace profiles running' -or $text -match 'WPR is not recording'

    if ($exitCode -ne 0 -and -not ($IgnoreNoActiveTrace -and $noActiveTrace)) {
        throw "wpr $($ArgumentList -join ' ') failed with code $exitCode.$([Environment]::NewLine)$text"
    }

    return [PSCustomObject]@{
        Output        = @($output)
        ExitCode      = $exitCode
        NoActiveTrace = $noActiveTrace
    }
}

function Reset-MpPerformanceRecordingState {
    Write-Info "Resetting Defender performance recording state before capture..."

    try {
        $statusBefore = Invoke-WprCommand -ArgumentList @('-status') -IgnoreNoActiveTrace
        foreach ($line in ($statusBefore.Output | Select-Object -First 3)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$line)) {
                Write-Info "  WPR status: $line"
            }
        }
    }
    catch {
        Write-Warn "Could not query WPR status before reset: $($_.Exception.Message)"
    }

    $cleanupSteps = @(
        @{ Label = 'Defender performance instance'; Args = @('-cancel', '-instancename', 'MSFT_MpPerformanceRecording') }
        @{ Label = 'default WPR trace'; Args = @('-cancel') }
    )

    foreach ($cleanupStep in $cleanupSteps) {
        try {
            $cleanupResult = Invoke-WprCommand -ArgumentList $cleanupStep.Args -IgnoreNoActiveTrace
            if ($cleanupResult.NoActiveTrace) {
                Write-Info "  No active $($cleanupStep.Label) found"
            }
            elseif ($cleanupResult.ExitCode -eq 0) {
                Write-OK "  Cleared $($cleanupStep.Label)"
            }
        }
        catch {
            Write-Warn "  Cleanup step failed for $($cleanupStep.Label): $($_.Exception.Message)"
        }
    }

    Start-Sleep -Seconds 2

    try {
        $statusAfter = Invoke-WprCommand -ArgumentList @('-status') -IgnoreNoActiveTrace
        foreach ($line in ($statusAfter.Output | Select-Object -First 3)) {
            if (-not [string]::IsNullOrWhiteSpace([string]$line)) {
                Write-Info "  WPR post-reset: $line"
            }
        }
    }
    catch {
        Write-Warn "Could not query WPR status after reset: $($_.Exception.Message)"
    }
}

function Stop-BackgroundJob {
    param(
        $Job,
        [switch]$StopIfRunning,
        [switch]$WaitForCompletion,
        [int]$WaitTimeoutSeconds = 30
    )

    if (-not $Job) { return @() }

    if ($StopIfRunning -and $Job.State -notin @('Completed', 'Failed', 'Stopped')) {
        try { Stop-Job -Job $Job -ErrorAction SilentlyContinue | Out-Null } catch { }
    }

    if ($WaitForCompletion) {
        try { $Job | Wait-Job -Timeout $WaitTimeoutSeconds | Out-Null } catch { }
    }

    $output = @()
    try { $output = @($Job | Receive-Job -ErrorAction SilentlyContinue) } catch { }
    try { $Job | Remove-Job -Force -ErrorAction SilentlyContinue } catch { }
    return $output
}

function Read-NormalizedTextFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }

    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
    if ($null -eq $raw) { return $null }

    # Many Defender support files are UTF-16-ish dumps that surface embedded NULs.
    return ($raw -replace "`0", '')
}

function Get-NormalizedTextLines([string]$Path) {
    $content = Read-NormalizedTextFile $Path
    if ($null -eq $content) { return @() }
    return @($content -split '\r?\n')
}

function Get-MpSupportCabPath {
    param(
        [datetime]$NewerThan = [datetime]::MinValue,
        [int]$TimeoutSeconds = 15,
        [switch]$AllowStaleFallback = $true
    )

    $candidatePaths = @(
        "$env:ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab",
        (Join-Path $env:TEMP 'MpSupportFiles.cab')
    ) | Select-Object -Unique

    $timeoutSeconds = [Math]::Max(0, $TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($timeoutSeconds)

    do {
        foreach ($candidate in $candidatePaths) {
            if (-not (Test-Path -LiteralPath $candidate)) { continue }

            $item = Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue
            if ($item -and $item.LastWriteTime -ge $NewerThan) {
                return $item.FullName
            }
        }

        if ($timeoutSeconds -le 0) { break }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)

    if ($AllowStaleFallback) {
        foreach ($candidate in $candidatePaths) {
            if (Test-Path -LiteralPath $candidate) {
                return (Get-Item -LiteralPath $candidate -ErrorAction SilentlyContinue).FullName
            }
        }
    }

    return $null
}

function Get-FileSha256Hex([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path)) { return $null }

    try {
        return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash
    }
    catch {
        return $null
    }
}

function New-ReportCabSnapshot {
    param(
        [switch]$Strict,
        [string]$Purpose = 'Report'
    )

    $snapshot = [ordered]@{
        Purpose            = $Purpose
        StrictMode         = [bool]$Strict
        RequestedAt        = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        GenerateExitCode   = $null
        Path               = $null
        LastWriteTime      = $null
        FileSizeBytes      = $null
        SHA256             = $null
        Fresh              = $false
        StaleFallbackUsed  = $false
        Error              = $null
    }

    $mpCmdRun = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
    if (-not (Test-Path -LiteralPath $mpCmdRun)) {
        $mpCmdRun = "${env:ProgramW6432}\Windows Defender\MpCmdRun.exe"
    }

    if (-not (Test-Path -LiteralPath $mpCmdRun)) {
        $snapshot['Error'] = 'MpCmdRun.exe not found'
        if ($Strict) {
            throw "StrictCAB is enabled but MpCmdRun.exe was not found."
        }

        return [PSCustomObject]$snapshot
    }

    $requestedAt = Get-Date
    $snapshot['RequestedAt'] = $requestedAt.ToString('yyyy-MM-dd HH:mm:ss')

    try {
        $getFilesResult = Invoke-ExternalTool -FilePath $mpCmdRun -ArgumentList @('-GetFiles') -IgnoreExitCode
        $snapshot['GenerateExitCode'] = $getFilesResult.ExitCode
    }
    catch {
        $snapshot['Error'] = $_.Exception.Message
        if ($Strict) {
            throw "StrictCAB is enabled and MpCmdRun.exe -GetFiles failed: $($_.Exception.Message)"
        }
    }

    $cabPath = Get-MpSupportCabPath -NewerThan $requestedAt.AddSeconds(-1) -TimeoutSeconds 20 -AllowStaleFallback:(-not $Strict)
    if (-not $cabPath) {
        $snapshot['Error'] = if ($Strict) { 'No fresh CAB snapshot found' } else { 'No CAB snapshot found' }
        if ($Strict) {
            throw "StrictCAB is enabled and no fresh MpSupportFiles.cab snapshot was produced for this run."
        }

        return [PSCustomObject]$snapshot
    }

    $cabItem = Get-Item -LiteralPath $cabPath -ErrorAction SilentlyContinue
    $isFresh = [bool]($cabItem -and $cabItem.LastWriteTime -ge $requestedAt.AddSeconds(-1))

    $snapshot['Path'] = $cabPath
    $snapshot['LastWriteTime'] = if ($cabItem) { $cabItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    $snapshot['FileSizeBytes'] = if ($cabItem) { [int64]$cabItem.Length } else { $null }
    $snapshot['SHA256'] = Get-FileSha256Hex $cabPath
    $snapshot['Fresh'] = $isFresh
    $snapshot['StaleFallbackUsed'] = -not $isFresh

    if ($Strict -and -not $isFresh) {
        throw "StrictCAB is enabled and the available CAB snapshot is stale."
    }

    return [PSCustomObject]$snapshot
}

# Get duration in ms — handles TimeSpan, double, ticks, and -Raw output
function Get-DurationMs($item) {
    if ($null -eq $item) { return 0 }

    $val = $null
    if ($item.PSObject.Properties['TotalDuration']) {
        $val = $item.TotalDuration
    } elseif ($item.PSObject.Properties['Duration']) {
        $val = $item.Duration
    }

    if ($null -eq $val) { return 0 }

    if ($val -is [TimeSpan])  { return $val.TotalMilliseconds }
    if ($val -is [double])    { return $val }
    if ($val -is [int])       { return [double]$val }
    
    # UInt64/Int64 ticks from -Raw output (10,000 ticks = 1 ms)
    if ($val -is [UInt64] -or $val -is [Int64]) { 
        return ([double]$val) / 10000.0 
    }

    if ($val.PSObject -and $val.PSObject.Properties['TotalMilliseconds']) {
        return [double]$val.TotalMilliseconds
    }
    return 0
}

# Safely read a named property
function Get-Prop($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    if ($obj.PSObject.Properties[$name]) { return $obj.$name }
    return $null
}

function Get-PathDirectory([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $null }

    try {
        if (Test-Path -LiteralPath $path -PathType Container -ErrorAction SilentlyContinue) {
            return $path.TrimEnd('\')
        }
    }
    catch { }

    try {
        return [System.IO.Path]::GetDirectoryName($path)
    }
    catch {
        return $null
    }
}

function Convert-FileTimeValueToLocalText($value) {
    if ($null -eq $value) { return $null }

    try {
        return ([DateTime]::FromFileTimeUtc([int64]$value).ToLocalTime()).ToString('yyyy-MM-dd HH:mm:ss')
    }
    catch {
        return $null
    }
}

function Convert-TraceDurationValueToMs($value) {
    if ($null -eq $value) { return 0 }
    if ($value -is [TimeSpan]) { return $value.TotalMilliseconds }
    if ($value -is [double] -or $value -is [single] -or $value -is [decimal]) { return [double]$value }
    if ($value -is [byte] -or $value -is [int16] -or $value -is [int32] -or $value -is [int64] -or $value -is [uint16] -or $value -is [uint32] -or $value -is [uint64]) {
        return ([double]$value) / 10000.0
    }

    try {
        return ([double]$value) / 10000.0
    }
    catch {
        return 0
    }
}

function Parse-ScanComment([string]$comment) {
    if ([string]::IsNullOrWhiteSpace($comment)) { return $null }

    if ($comment -match '^(?<scanType>\w+)\s+(?<path>[A-Za-z]:\\.+?)\s+lasted\s+(?<duration>\d+)$') {
        $commentPath = $Matches['path']
        return [PSCustomObject]@{
            ScanType   = $Matches['scanType']
            Path       = $commentPath
            FolderPath = Get-PathDirectory $commentPath
            Extension  = Normalize-Extension ([System.IO.Path]::GetExtension($commentPath))
            DurationMs = Convert-TraceDurationValueToMs ([int64]$Matches['duration'])
        }
    }

    return $null
}

function Add-FolderAggregateObservation {
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [string]$FolderPath,
        [double]$DurationMs,
        [string]$ProcessPath,
        [string]$Image,
        [string]$ExamplePath
    )

    if ([string]::IsNullOrWhiteSpace($FolderPath)) { return }

    if (-not $Map.ContainsKey($FolderPath)) {
        $Map[$FolderPath] = [ordered]@{
            FolderPath      = $FolderPath
            TotalDurationMs = [double]0
            Count           = 0
            ProcessDurations = @{}
            ExamplePaths    = [System.Collections.Generic.List[string]]::new()
            SyntheticOnly   = $true
        }
    }

    $entry = $Map[$FolderPath]
    $entry.TotalDurationMs += $DurationMs
    $entry.Count++

    $processKey = if (-not [string]::IsNullOrWhiteSpace($ProcessPath)) { $ProcessPath } elseif (-not [string]::IsNullOrWhiteSpace($Image)) { "Image:$Image" } else { $null }
    if ($processKey) {
        if (-not $entry.ProcessDurations.ContainsKey($processKey)) {
            $entry.ProcessDurations[$processKey] = [double]0
        }
        $entry.ProcessDurations[$processKey] = [double]$entry.ProcessDurations[$processKey] + $DurationMs
    }

    if (-not [string]::IsNullOrWhiteSpace($ExamplePath) -and -not $entry.ExamplePaths.Contains($ExamplePath) -and $entry.ExamplePaths.Count -lt 3) {
        [void]$entry.ExamplePaths.Add($ExamplePath)
    }

    if (($FolderPath -notmatch 'DefenderWorkload_') -and ($ExamplePath -notmatch 'DefenderWorkload_')) {
        $entry.SyntheticOnly = $false
    }
}

function Convert-FolderAggregateMapToRows {
    param(
        [Parameter(Mandatory)][hashtable]$Map,
        [double]$ObservedDurationMs
    )

    $rows = foreach ($entry in $Map.Values) {
        $topProcessEntry = @($entry.ProcessDurations.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 1)
        $topProcessKey = if ($topProcessEntry.Count -gt 0) { [string]$topProcessEntry[0].Key } else { $null }
        $topProcessPath = if ($topProcessKey -and -not $topProcessKey.StartsWith('Image:', [System.StringComparison]::OrdinalIgnoreCase)) { $topProcessKey } else { $null }
        $topProcessImage = if ($topProcessPath) { Split-Path $topProcessPath -Leaf -ErrorAction SilentlyContinue } elseif ($topProcessKey) { $topProcessKey.Substring(6) } else { $null }
        $shareOfObserved = if ($ObservedDurationMs -gt 0) { [math]::Round(($entry.TotalDurationMs / $ObservedDurationMs) * 100, 1) } else { 0 }

        [PSCustomObject]@{
            FolderPath               = $entry.FolderPath
            TotalDurationMs          = [math]::Round($entry.TotalDurationMs, 2)
            Duration                 = Format-Duration $entry.TotalDurationMs
            Count                    = $entry.Count
            ShareOfObservedDuration  = $shareOfObserved
            TopProcessPath           = $topProcessPath
            TopProcessImage          = $topProcessImage
            ExamplePaths             = @($entry.ExamplePaths)
            SyntheticOnly            = [bool]$entry.SyntheticOnly
        }
    }

    return @($rows | Sort-Object TotalDurationMs -Descending)
}

# ── Accumulators ──────────────────────────────────────────────────────────────
$script:suggestions = [System.Collections.Generic.List[PSObject]]::new()
$script:suppressedSuggestions = [System.Collections.Generic.List[PSObject]]::new()
$script:impactTableRows = [System.Collections.Generic.List[PSObject]]::new()
$script:suggestedPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$script:suggestedContextualKeys = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$script:coveredProcessPaths = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase)
$script:extensionHotspots = @()
$script:topScanContexts = @()

function Add-Suggestion {
    param([string]$Type, [string]$Value, [string]$Reason, [string]$Impact, [string]$Command,
          [string]$Risk = 'SAFE', [string]$Advisory = '', [string]$Scope = '', [string]$Preference = '',
          [int]$TierOrder = 99, [string[]]$Fallbacks = @(), [string]$RelatedProcessPath = '',
          $RelativeSharePercent = $null, [string]$RelativeShareBasis = '',
          $ConcentrationPercent = $null, [string]$ConcentrationBasis = '')
    $script:suggestions.Add([PSCustomObject]@{
            Type = $Type; Value = $Value; Reason = $Reason; Impact = $Impact
            Command = $Command; Risk = $Risk; Advisory = $Advisory; Scope = $Scope; Preference = $Preference
            TierOrder = $TierOrder; Fallbacks = @($Fallbacks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            RelatedProcessPath = $RelatedProcessPath
            RelativeSharePercent = $RelativeSharePercent; RelativeShareBasis = $RelativeShareBasis
            ConcentrationPercent = $ConcentrationPercent; ConcentrationBasis = $ConcentrationBasis
        })
}

function Add-SuppressedSuggestion {
    param(
        [string]$Type,
        [string]$Value,
        [string]$Impact,
        [string]$Reason,
        [string]$SuppressedBecause,
        [string[]]$Commands = @(),
        [string]$Scope = '',
        [string]$Evidence = '',
        [string]$Preference = '',
        [string[]]$Fallbacks = @(),
        $RelativeSharePercent = $null, [string]$RelativeShareBasis = '',
        $ConcentrationPercent = $null, [string]$ConcentrationBasis = ''
    )

    $script:suppressedSuggestions.Add([PSCustomObject]@{
            Type              = $Type
            Value             = $Value
            Impact            = $Impact
            Reason            = $Reason
            SuppressedBecause = $SuppressedBecause
            Commands          = @($Commands | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
            Scope             = $Scope
            Evidence          = $Evidence
            Preference        = $Preference
            Fallbacks         = @($Fallbacks | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            RelativeSharePercent = $RelativeSharePercent
            RelativeShareBasis   = $RelativeShareBasis
            ConcentrationPercent = $ConcentrationPercent
            ConcentrationBasis   = $ConcentrationBasis
        })
}

function Add-ImpactRow {
    param([string]$Category, [string]$Item, [string]$Duration, [double]$DurationMs, [int]$Count, [string]$Impact)
    $script:impactTableRows.Add([PSCustomObject]@{
            Category = $Category; Item = $Item; Duration = $Duration
            DurationMs = $DurationMs; Count = $Count; Impact = $Impact
        })
}

# ── Impact classification ────────────────────────────────────────────────────
$thresholdHigh = 5000
$thresholdMedium = 1000

function Get-ImpactLevel([double]$ms) {
    if ($ms -ge $thresholdHigh) { return "HIGH" }
    if ($ms -ge $thresholdMedium) { return "MEDIUM" }
    return "LOW"
}

function Get-ImpactOrder([string]$impact) {
    switch ($impact) {
        'HIGH' { return 0 }
        'MEDIUM' { return 1 }
        'LOW' { return 2 }
        default { return 3 }
    }
}

function Get-RelativeSharePercent([double]$durationMs, [double]$totalMs) {
    if ($totalMs -le 0) { return $null }
    return [math]::Round(($durationMs / $totalMs) * 100, 1)
}

function Get-ImpactColour([string]$impact) {
    switch ($impact) { 'HIGH' { 'Red' } 'MEDIUM' { 'Yellow' } default { 'Green' } }
}

$startAtSpecified = $PSBoundParameters.ContainsKey('StartAt')
$startAtTimeSpecified = $PSBoundParameters.ContainsKey('StartAtTime')
$script:scheduleMode = 'Immediate'
$script:scheduleInput = $null
$script:scheduledStartAt = $null
$script:scheduledWaitSeconds = 0
$script:actualRunStartedAt = $null

try {
    $scheduleRequest = Resolve-ScheduledStart -ExplicitStart $StartAt -TimeOfDay $StartAtTime -ExplicitStartSpecified $startAtSpecified -TimeOfDaySpecified $startAtTimeSpecified
    if ($scheduleRequest) {
        $script:scheduleMode = $scheduleRequest.Mode
        $script:scheduleInput = $scheduleRequest.InputText
        $script:scheduledStartAt = $scheduleRequest.StartAt
    }
}
catch {
    Write-Section "0 - Scheduled Start"
    Write-Bad $_.Exception.Message
    Exit-Script 1
}

try {
    Start-Transcript -Path $script:transcriptFile -Force | Out-Null
    $script:transcriptStarted = $true
    Write-Info "Full PowerShell transcript: $script:transcriptFile"
}
catch {
    Write-Warn "Could not start transcript logging: $($_.Exception.Message)"
}

if ($script:scheduledStartAt) {
    $script:scheduledWaitSeconds = Wait-UntilScheduledStart -StartAt $script:scheduledStartAt -Mode $script:scheduleMode -InputText $script:scheduleInput
}

$script:actualRunStartedAt = Get-Date

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 1 — PRE-FLIGHT CHECKS
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "1 - Pre-flight Checks"

# Verify New-MpPerformanceRecording exists
if (-not (Get-Command New-MpPerformanceRecording -ErrorAction SilentlyContinue)) {
    Write-Bad "New-MpPerformanceRecording cmdlet not found."
    Write-Host "  Required: Defender platform version 4.18.2108.7 or later." -ForegroundColor Yellow
    Write-Host "  Run: Get-MpComputerStatus | Select AMProductVersion" -ForegroundColor Yellow
    Exit-Script 1
}

$status = Get-MpComputerStatus -ErrorAction SilentlyContinue
$prefs = Get-MpPreference     -ErrorAction SilentlyContinue

$contextualMinPlatformVersion = '4.18.2205.7'
$contextualMinEngineVersion = '1.1.19300.2'
$platformVersion = if ($status) { Get-Prop $status 'AMProductVersion' } else { $null }
$engineVersion = if ($status) { Get-Prop $status 'AMEngineVersion' } else { $null }
$contextualExclusionsSupported = Test-VersionAtLeast $platformVersion $contextualMinPlatformVersion
if ($contextualExclusionsSupported -and $engineVersion) {
    $contextualExclusionsSupported = Test-VersionAtLeast $engineVersion $contextualMinEngineVersion
}

$disableLocalAdminMerge = if ($prefs) { Get-Prop $prefs 'DisableLocalAdminMerge' } else { $null }
$exclusionGuidance = [ordered]@{
    ContextualExclusionsSupported = $contextualExclusionsSupported
    LocalAdminMergeDisabled       = $disableLocalAdminMerge
    Principles                    = @(
        'Treat exclusions as a last resort and review them regularly.'
        'Prefer exact process paths and contextual file or folder exclusions over broad folder or extension exclusions when the platform supports them.'
        'When the issue is limited to one file type in one directory, prefer a file-pattern path exclusion such as C:\App\Logs\*.log over excluding the whole folder.'
        'Folder and extension exclusions are broad and can affect real-time, scheduled, and on-demand scanning.'
        'Process exclusions only affect files opened by that process during real-time scanning; the process binary itself is still scanned, and scheduled or on-demand scans can still inspect those files.'
        'Microsoft Defender Antivirus exclusions do not automatically replace separate controls such as ASR, CFA, or Defender for Endpoint indicators.'
        'Defender for Endpoint automated investigation can still inspect items in Microsoft Defender Antivirus exclusions, so exclusions are not a substitute for investigation or containment controls.'
        'Protect excluded folders with restrictive NTFS ACLs and change control so only the intended trusted processes can write there.'
        'Enable the Disable local admin merge setting in managed environments if you do not want locally added exclusions to combine with policy-managed exclusions.'
    )
    Sources                       = @(
        'https://cloudbrothers.info/en/guide-to-defender-exclusions/'
        'https://learn.microsoft.com/en-au/defender-endpoint/configure-contextual-file-folder-exclusions-microsoft-defender-antivirus'
        'https://learn.microsoft.com/en-us/defender-endpoint/configure-extension-file-exclusions-microsoft-defender-antivirus'
        'https://learn.microsoft.com/en-us/defender-endpoint/configure-process-opened-file-exclusions-microsoft-defender-antivirus'
    )
}

if ($status) {
    Write-OK  "Defender engine           : $($status.AMProductVersion)"
    Write-OK  "Signature version         : $($status.AntivirusSignatureVersion)"
    Write-Info "Real-time protection      : $(if ($status.RealTimeProtectionEnabled) {'Enabled'} else {'DISABLED'})"
    if ($engineVersion) {
        Write-Info "Defender engine version   : $engineVersion"
    }
}
else {
    Write-Warn "Could not read MpComputerStatus -- some metadata will be unavailable."
}

if ($contextualExclusionsSupported) {
    Write-OK "Contextual exclusions     : Supported"
}
else {
    Write-Warn "Contextual exclusions     : Not confirmed from current Defender version data"
}

if ($null -ne $disableLocalAdminMerge) {
    if ($disableLocalAdminMerge) {
        Write-OK "Local admin merge         : Disabled"
    }
    else {
        Write-Warn "Local admin merge         : Enabled -- local admin exclusions can merge with managed policy"
    }
}

Write-OK "Pre-flight checks passed"

$requestedValidateExclusions = [bool]$ValidateExclusions
$exclusionValidationDetails = [ordered]@{
    Requested       = $requestedValidateExclusions
    Executed        = $false
    TemporaryPath   = $null
    Results         = [ordered]@{}
    Evidence        = [ordered]@{}
    WorkingMethods  = 0
    TotalMethods    = 0
    BestMethod      = $null
    CleanupVerified = $null
    SkippedReason   = $null
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 1b — EXCLUSION VALIDATION TEST (optional)
# ═══════════════════════════════════════════════════════════════════════════════
if ($ValidateExclusions) {
    Write-Section "1b - Validating Exclusion Discovery Methods"

    # Use a unique, obviously-test path that cannot conflict with real exclusions
    $testExclRoot = if (-not [string]::IsNullOrWhiteSpace($env:SystemDrive)) {
        $env:SystemDrive
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:SystemRoot)) {
        [System.IO.Path]::GetPathRoot($env:SystemRoot).TrimEnd('\')
    }
    else {
        [System.IO.Path]::GetPathRoot((Get-Location).Path).TrimEnd('\')
    }
    $testExclPath = Join-Path $testExclRoot "DefenderPerfTest_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    $exclusionValidationDetails['TemporaryPath'] = $testExclPath
    Write-Info "Test exclusion path: $testExclPath"

    # Add a temporary path exclusion
    try {
        Add-MpPreference -ExclusionPath $testExclPath -ErrorAction Stop
        Write-OK "Test exclusion added successfully"
    }
    catch {
        Write-Bad "Failed to add test exclusion: $_"
        Write-Warn "Exclusion validation skipped -- Tamper Protection may be blocking changes"
        $exclusionValidationDetails['SkippedReason'] = "Failed to add temporary exclusion: $($_.Exception.Message)"
        $ValidateExclusions = $false
    }

    if ($ValidateExclusions) {
        $exclusionValidationDetails['Executed'] = $true
        Start-Sleep -Seconds 2  # Allow propagation

        $validationResults = [ordered]@{}
        $validationEvidence = [ordered]@{}

        # Method 1: Get-MpPreference
        Write-Info "Testing Method 1: Get-MpPreference..."
        $m1Found = $false
        try {
            $m1Prefs = Get-MpPreference -ErrorAction Stop
            $m1Paths = @($m1Prefs.ExclusionPath | Where-Object { $_ })
            $m1Found = $m1Paths -contains $testExclPath
        }
        catch { }
        $validationResults['Get-MpPreference'] = $m1Found
        if ($m1Found) { Write-OK  "Method 1 (Get-MpPreference)    : FOUND" }
        else          { Write-Warn "Method 1 (Get-MpPreference)    : NOT VISIBLE (likely hidden)" }

        # Method 2: Direct registry read
        Write-Info "Testing Method 2: Registry direct read..."
        $m2Found = $false
        try {
            $regBase = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
            $regProps = (Get-ItemProperty "$regBase\Paths" -ErrorAction Stop).PSObject.Properties |
                Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                ForEach-Object { $_.Name }
            $m2Found = $regProps -contains $testExclPath
        }
        catch { }
        $validationResults['Registry'] = $m2Found
        if ($m2Found) { Write-OK  "Method 2 (Registry)            : FOUND" }
        else          { Write-Warn "Method 2 (Registry)            : NOT VISIBLE (access blocked)" }

        # Method 2b: Group Policy registry
        Write-Info "Testing Method 2b: GP registry..."
        $m2bFound = $false
        try {
            $gpBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
            $gpProps = (Get-ItemProperty "$gpBase\Paths" -ErrorAction Stop).PSObject.Properties |
                Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                ForEach-Object { $_.Name }
            $m2bFound = $gpProps -contains $testExclPath
        }
        catch { }
        $validationResults['GroupPolicy-Registry'] = $m2bFound
        if ($m2bFound) { Write-OK  "Method 2b (GP Registry)        : FOUND" }
        else          { Write-Info "Method 2b (GP Registry)        : NOT PRESENT (expected if not GP-managed)" }

        # Method 3: CAB extraction (expensive, so just test if MpCmdRun works)
        Write-Info "Testing Method 3: MpCmdRun CAB extraction..."
        $m3Found = $false
        $method3Evidence = [ordered]@{
            GetFilesExitCode = $null
            CabPath          = $null
            CabLastWriteTime = $null
            RegistryFileFound = $false
            MatchFound       = $false
            Error            = $null
        }
        $mpCmdRun = "$env:ProgramFiles\Windows Defender\MpCmdRun.exe"
        if (-not (Test-Path $mpCmdRun)) { $mpCmdRun = "${env:ProgramW6432}\Windows Defender\MpCmdRun.exe" }
        if (Test-Path $mpCmdRun) {
            try {
                $cabRequestedAt = Get-Date
                $getFilesResult = Invoke-ExternalTool -FilePath $mpCmdRun -ArgumentList @('-GetFiles') -IgnoreExitCode
                $method3Evidence['GetFilesExitCode'] = $getFilesResult.ExitCode
                $cabPath = Get-MpSupportCabPath -NewerThan $cabRequestedAt.AddSeconds(-1) -TimeoutSeconds 20 -AllowStaleFallback:$false
                if ($cabPath -and (Test-Path -LiteralPath $cabPath)) {
                    $cabItem = Get-Item -LiteralPath $cabPath -ErrorAction SilentlyContinue
                    $method3Evidence['CabPath'] = $cabPath
                    $method3Evidence['CabLastWriteTime'] = if ($cabItem) { $cabItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                    $method3Evidence['CabSha256'] = Get-FileSha256Hex $cabPath
                    $method3Evidence['FreshCab'] = [bool]($cabItem -and $cabItem.LastWriteTime -ge $cabRequestedAt.AddSeconds(-1))
                    $extractDir = Join-Path $env:TEMP "DefenderCAB_Validate_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
                    New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
                    Invoke-ExternalTool -FilePath 'expand.exe' -ArgumentList @($cabPath, '-F:*', $extractDir) | Out-Null

                    $mpRegFile = Get-ChildItem -Path $extractDir -Filter "MpRegistry.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($mpRegFile) {
                        $method3Evidence['RegistryFileFound'] = $true
                        $regContent = Get-Content $mpRegFile.FullName -Raw -ErrorAction SilentlyContinue
                        if ($regContent -match [regex]::Escape($testExclPath)) {
                            $m3Found = $true
                            $method3Evidence['MatchFound'] = $true
                        }
                    }
                    Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
            catch {
                $method3Evidence['Error'] = $_.Exception.Message
            }
        }
        $validationResults['CAB-MpRegistry'] = $m3Found
        $validationEvidence['CAB-MpRegistry'] = $method3Evidence
        if ($m3Found) { Write-OK  "Method 3 (CAB MpRegistry.txt)  : FOUND" }
        else          { Write-Warn "Method 3 (CAB MpRegistry.txt)  : NOT VISIBLE (may need fresh CAB)" }

        # Remove the test exclusion
        Write-Info "Removing test exclusion..."
        try {
            Remove-MpPreference -ExclusionPath $testExclPath -ErrorAction Stop
            Write-OK "Test exclusion removed"
        }
        catch {
            Write-Bad "Failed to remove test exclusion '$testExclPath': $_"
            Write-Bad "MANUAL CLEANUP NEEDED: Remove-MpPreference -ExclusionPath '$testExclPath'"
        }

        try {
            Start-Sleep -Seconds 1
            $stillPresent = $false

            try {
                $postPrefs = Get-MpPreference -ErrorAction Stop
                $stillPresent = (@($postPrefs.ExclusionPath | Where-Object { $_ }) -contains $testExclPath)
            }
            catch { }

            if (-not $stillPresent) {
                try {
                    $regProps = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths' -ErrorAction Stop).PSObject.Properties |
                        Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                        ForEach-Object { $_.Name }
                    $stillPresent = $regProps -contains $testExclPath
                }
                catch { }
            }

            $cleanupVerified = -not $stillPresent
            $exclusionValidationDetails['CleanupVerified'] = $cleanupVerified
            if ($cleanupVerified) {
                Write-OK "Cleanup verification        : Test exclusion no longer visible"
            }
            else {
                Write-Warn "Cleanup verification        : Test exclusion still visible after removal"
            }
        }
        catch {
            Write-Warn "Cleanup verification skipped: $_"
        }

        # Summary
        $workingMethods = @($validationResults.GetEnumerator() | Where-Object { $_.Value }).Count
        $totalMethods = $validationResults.Count
        foreach ($entry in $validationResults.GetEnumerator()) {
            $exclusionValidationDetails['Results'][$entry.Key] = [bool]$entry.Value
        }
        $exclusionValidationDetails['Evidence'] = $validationEvidence
        $exclusionValidationDetails['WorkingMethods'] = $workingMethods
        $exclusionValidationDetails['TotalMethods'] = $totalMethods
        Write-Host ""
        if ($workingMethods -gt 0) {
            Write-OK  "Exclusion validation: $workingMethods/$totalMethods discovery methods can detect exclusions"
            $bestMethod = ($validationResults.GetEnumerator() | Where-Object { $_.Value } | Select-Object -First 1).Key
            $exclusionValidationDetails['BestMethod'] = $bestMethod
            Write-Info "Best working method: $bestMethod"
        }
        else {
            Write-Bad "Exclusion validation: NO discovery methods could detect the test exclusion"
            Write-Warn "All exclusion data in this report may be incomplete"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 2 — PREPARE CAB SNAPSHOT
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "2 - Preparing CAB Snapshot"

$script:reportCabSnapshot = $null

try {
    $script:reportCabSnapshot = New-ReportCabSnapshot -Strict:$StrictCAB -Purpose 'Report'

    if ($script:reportCabSnapshot.Path) {
        $cabSizeMb = if ($script:reportCabSnapshot.FileSizeBytes) { [math]::Round(($script:reportCabSnapshot.FileSizeBytes / 1MB), 2) } else { $null }
        $freshnessText = if ($script:reportCabSnapshot.Fresh) { 'fresh' } else { 'stale fallback' }
        Write-OK "CAB snapshot ready: $($script:reportCabSnapshot.Path)"
        Write-Info "CAB details : $freshnessText, $cabSizeMb MB, $($script:reportCabSnapshot.LastWriteTime)"
        if ($script:reportCabSnapshot.SHA256) {
            Write-Info "CAB SHA256  : $($script:reportCabSnapshot.SHA256)"
        }
    }
    elseif ($script:reportCabSnapshot.Error) {
        Write-Warn "CAB snapshot unavailable: $($script:reportCabSnapshot.Error)"
    }
    else {
        Write-Warn "CAB snapshot unavailable for this run"
    }
}
catch {
    Write-Bad $_.Exception.Message
    Exit-Script 1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 2b — DISCOVER EXCLUSIONS (Multi-source: cmdlet -> registry -> CAB)
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "2b - Discovering Exclusions (Hidden-Exclusion Aware)"

$exclusionSource = 'none'
$discoveredExcl = [ordered]@{
    Paths      = @()
    Processes  = @()
    Extensions = @()
}

# ── Method 1: Get-MpPreference (fastest, but may be hidden) ──────────────────
Write-Info "Trying Get-MpPreference..."
if ($prefs) {
    $mpPaths = @($prefs.ExclusionPath      | Where-Object { $_ })
    $mpProcs = @($prefs.ExclusionProcess    | Where-Object { $_ })
    $mpExts = @($prefs.ExclusionExtension  | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ } | Select-Object -Unique)

    if (($mpPaths.Count + $mpProcs.Count + $mpExts.Count) -gt 0) {
        $discoveredExcl.Paths = $mpPaths
        $discoveredExcl.Processes = $mpProcs
        $discoveredExcl.Extensions = $mpExts
        $exclusionSource = 'Get-MpPreference'
        Write-OK  "Exclusions visible via Get-MpPreference ($($mpPaths.Count) paths, $($mpProcs.Count) procs, $($mpExts.Count) exts)"
    }
    else {
        Write-Warn "Get-MpPreference returned empty exclusions (likely hidden by Tamper Protection)"
    }
}

# ── Method 2: Direct registry read ───────────────────────────────────────────
if ($exclusionSource -eq 'none') {
    Write-Info "Trying direct registry read..."
    $regBase = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions'
    try {
        $regPaths = @((Get-ItemProperty "$regBase\Paths" -ErrorAction Stop).PSObject.Properties |
            Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
            ForEach-Object { $_.Name })
        $regProcs = @((Get-ItemProperty "$regBase\Processes" -ErrorAction Stop).PSObject.Properties |
            Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
            ForEach-Object { $_.Name })
        $regExts = @((Get-ItemProperty "$regBase\Extensions" -ErrorAction Stop).PSObject.Properties |
            Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
            ForEach-Object { Normalize-Extension $_.Name } |
            Where-Object { $_ } |
            Select-Object -Unique)

        if (($regPaths.Count + $regProcs.Count + $regExts.Count) -gt 0) {
            $discoveredExcl.Paths = @($regPaths | Where-Object { $_ })
            $discoveredExcl.Processes = @($regProcs | Where-Object { $_ })
            $discoveredExcl.Extensions = @($regExts | Where-Object { $_ })
            $exclusionSource = 'Registry'
            Write-OK  "Exclusions found in registry ($($regPaths.Count) paths, $($regProcs.Count) procs, $($regExts.Count) exts)"
        }
        else {
            Write-Warn "Registry exclusion keys exist but are empty"
        }
    }
    catch {
        Write-Warn "Registry keys inaccessible (access denied or not present)"
    }

    # Also check the Group Policy registry location
    if ($exclusionSource -eq 'none') {
        $gpBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions'
        try {
            $gpPaths = @((Get-ItemProperty "$gpBase\Paths" -ErrorAction Stop).PSObject.Properties |
                Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                ForEach-Object { $_.Name })
            $gpProcs = @((Get-ItemProperty "$gpBase\Processes" -ErrorAction Stop).PSObject.Properties |
                Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                ForEach-Object { $_.Name })
            $gpExts = @((Get-ItemProperty "$gpBase\Extensions" -ErrorAction Stop).PSObject.Properties |
                Where-Object { $_.Name -notin 'PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider' } |
                ForEach-Object { Normalize-Extension $_.Name } |
                Where-Object { $_ } |
                Select-Object -Unique)

            if (($gpPaths.Count + $gpProcs.Count + $gpExts.Count) -gt 0) {
                $discoveredExcl.Paths = @($gpPaths | Where-Object { $_ })
                $discoveredExcl.Processes = @($gpProcs | Where-Object { $_ })
                $discoveredExcl.Extensions = @($gpExts | Where-Object { $_ })
                $exclusionSource = 'GroupPolicy-Registry'
                Write-OK  "Exclusions found in GP registry ($($gpPaths.Count) paths, $($gpProcs.Count) procs, $($gpExts.Count) exts)"
            }
        }
        catch {
            Write-Info "No Group Policy exclusion keys found"
        }
    }
}

# ── Method 3: MpCmdRun -GetFiles CAB extraction ─────────────────────────────
if ($exclusionSource -eq 'none') {
    Write-Info "Exclusions hidden -- extracting from the report CAB snapshot..."

    $cabPath = if ($script:reportCabSnapshot) { $script:reportCabSnapshot.Path } else { $null }

    if ($cabPath -and (Test-Path -LiteralPath $cabPath)) {
        try {
            Write-OK  "Using CAB snapshot: $cabPath ($([math]::Round((Get-Item $cabPath).Length / 1MB, 1)) MB)"

            # Extract to temp directory
            $extractDir = Join-Path $env:TEMP "DefenderCAB_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            New-Item -ItemType Directory -Path $extractDir -Force | Out-Null
            Invoke-ExternalTool -FilePath 'expand.exe' -ArgumentList @($cabPath, '-F:*', $extractDir) | Out-Null
            Write-Info "Extracted CAB to: $extractDir"

                # Parse MpRegistry.txt for exclusion entries
                $mpRegFile = Get-ChildItem -Path $extractDir -Filter "MpRegistry.txt" -Recurse -ErrorAction SilentlyContinue |
                Select-Object -First 1

                if ($mpRegFile) {
                    Write-OK  "Found MpRegistry.txt -- parsing exclusions..."
                    $regContent = Get-Content $mpRegFile.FullName -Raw -ErrorAction SilentlyContinue

                    # Parse exclusion paths from the registry dump
                    # Format: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
                    #             key = value
                    $cabPaths = [System.Collections.Generic.List[string]]::new()
                    $cabProcs = [System.Collections.Generic.List[string]]::new()
                    $cabExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

                    $sections = @{
                        'Exclusions\\Paths'      = $cabPaths
                        'Exclusions\\Processes'  = $cabProcs
                        'Exclusions\\Extensions' = $cabExts
                    }

                    foreach ($sectionKey in $sections.Keys) {
                        $targetList = $sections[$sectionKey]
                        # Match the registry section and capture entries until next section
                        $pattern = [regex]::Escape($sectionKey) + '\]?\s*\r?\n([\s\S]*?)(?=\r?\n\s*\[|$)'
                        if ($regContent -match $pattern) {
                            $sectionBlock = $Matches[1]
                            # Each line: "    value_name    REG_DWORD    0x0" or similar
                            foreach ($line in ($sectionBlock -split '\r?\n')) {
                                $line = $line.Trim()
                                if (-not $line -or $line.StartsWith('[')) { break }
                                # Extract the value name (which is the exclusion path/process/ext)
                                if ($line -match '^(.+?)\s+REG_') {
                                    $val = $Matches[1].Trim()
                                    if ($val -and $val -ne '(Default)') {
                                        if ($targetList -is [System.Collections.Generic.HashSet[string]]) {
                                            $normalizedValue = Normalize-Extension $val
                                            if ($normalizedValue) { [void]$targetList.Add($normalizedValue) }
                                        }
                                        else {
                                            $targetList.Add($val)
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (($cabPaths.Count + $cabProcs.Count + $cabExts.Count) -gt 0) {
                        $discoveredExcl.Paths = @($cabPaths | Where-Object { $_ })
                        $discoveredExcl.Processes = @($cabProcs | Where-Object { $_ })
                        $discoveredExcl.Extensions = @($cabExts | Where-Object { $_ } | Sort-Object)
                        $exclusionSource = 'CAB-MpRegistry.txt'
                        Write-OK  "Extracted exclusions from CAB ($($cabPaths.Count) paths, $($cabProcs.Count) procs, $($cabExts.Count) exts)"
                    }
                    else {
                        if ($requestedValidateExclusions -and $exclusionValidationDetails.Results['CAB-MpRegistry']) {
                            Write-Info "MpRegistry.txt parsed successfully but this fresh CAB snapshot contains no persistent exclusions. CAB discovery itself was already validated earlier with the temporary test exclusion."
                        }
                        else {
                            Write-Info "MpRegistry.txt parsed successfully but contains no persistent exclusion entries in this CAB snapshot"
                        }
                    }
                }
                else {
                    Write-Warn "MpRegistry.txt not found in CAB contents"

                    # Fallback: try parsing MPLog files for exclusion evidence
                    $mpLogs = Get-ChildItem -Path $extractDir -Filter "MPLog-*.log" -Recurse -ErrorAction SilentlyContinue
                    if ($mpLogs) {
                        Write-Info "Found $($mpLogs.Count) MPLog file(s) -- scanning for exclusion references..."
                        $logExclPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                        foreach ($log in $mpLogs) {
                            $logLines = Get-Content $log.FullName -ErrorAction SilentlyContinue
                            foreach ($l in $logLines) {
                                # MPLog lines with "Exclusion" often show: ProcessExclusion:..., PathExclusion:...
                                if ($l -match 'PathExclusion:\s*(.+)') {
                                    [void]$logExclPaths.Add($Matches[1].Trim())
                                }
                            }
                        }
                        if ($logExclPaths.Count -gt 0) {
                            $discoveredExcl.Paths = @($logExclPaths)
                            $exclusionSource = 'CAB-MPLog'
                            Write-OK  "Found $($logExclPaths.Count) path exclusion(s) from MPLog analysis"
                        }
                    }
                }

                # Cleanup extracted CAB
                Remove-Item $extractDir -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Warn "CAB extraction failed: $_"
        }
    }
    else {
        Write-Warn "No report CAB snapshot is available for CAB-based exclusion discovery"
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Info "Exclusion discovery source: $exclusionSource"
Write-Info "  Paths      : $($discoveredExcl.Paths.Count)"
Write-Info "  Processes  : $($discoveredExcl.Processes.Count)"
Write-Info "  Extensions : $($discoveredExcl.Extensions.Count)"

if ($exclusionSource -eq 'none') {
    Write-Warn "Could not discover any exclusions through any method."
    Write-Warn "Exclusions may genuinely be empty, or all access methods are blocked."
}

# Check for HideExclusionsFromLocalAdmins status
$tpExcl = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Features' -Name 'TPExclusions' -ErrorAction SilentlyContinue).TPExclusions
if ($tpExcl -eq 1) {
    Write-Warn "TPExclusions=1 : Exclusions are protected by Tamper Protection"
}

# Show discovered exclusions
if ($discoveredExcl.Paths.Count -gt 0) {
    Write-Host ""
    Write-Host "  Discovered Path Exclusions:" -ForegroundColor White
    foreach ($p in $discoveredExcl.Paths) { Write-Host "    - $p" -ForegroundColor Gray }
}
if ($discoveredExcl.Processes.Count -gt 0) {
    Write-Host ""
    Write-Host "  Discovered Process Exclusions:" -ForegroundColor White
    foreach ($p in $discoveredExcl.Processes) { Write-Host "    - $p" -ForegroundColor Gray }
}
if ($discoveredExcl.Extensions.Count -gt 0) {
    Write-Host ""
    Write-Host "  Discovered Extension Exclusions:" -ForegroundColor White
    foreach ($p in $discoveredExcl.Extensions) { Write-Host "    - $(Format-ExtensionDisplay $p)" -ForegroundColor Gray }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 2c — CAB DIAGNOSTIC INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "2c - Extracting CAB Diagnostic Intelligence"

$cabIntel = [ordered]@{}

$cabPath = if ($script:reportCabSnapshot) { $script:reportCabSnapshot.Path } else { $null }
if ($cabPath -and (Test-Path -LiteralPath $cabPath)) {
    $cabExtractDir = Join-Path $env:TEMP "DefenderCAB_Intel_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    New-Item -ItemType Directory -Path $cabExtractDir -Force | Out-Null

    try {
        Invoke-ExternalTool -FilePath 'expand.exe' -ArgumentList @($cabPath, '-F:*', $cabExtractDir) | Out-Null
        Write-OK "CAB extracted for intelligence gathering"

        # ── Effective Configuration (MPSupportEffectiveConfig.json) ──────────
        $effConfigFile = Get-ChildItem -Path $cabExtractDir -Filter "MPSupportEffectiveConfig.json" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($effConfigFile) {
            try {
                $effConfig = Get-Content $effConfigFile.FullName -Raw | ConvertFrom-Json
                $disableRealtimeMonitoring = Get-Prop $effConfig 'DisableRealtimeMonitoring'
                $disableBehaviorMonitoring = Get-Prop $effConfig 'DisableBehaviorMonitoring'
                $disableIOAVProtection = Get-Prop $effConfig 'DisableIOAVProtection'
                $disableScriptScanning = Get-Prop $effConfig 'DisableScriptScanning'
                $cabIntel['EffectiveConfig'] = [ordered]@{
                    CloudProtection               = Get-Prop $effConfig 'MAPSReporting'
                    CloudBlockLevel               = Get-Prop $effConfig 'CloudBlockLevel'
                    SubmitSamplesConsent          = Get-Prop $effConfig 'SubmitSamplesConsent'
                    PUAProtection                 = Get-Prop $effConfig 'PUAProtection'
                    RealTimeProtectionEnabled     = Convert-DisabledFlagToEnabled $disableRealtimeMonitoring
                    BehaviorMonitoringEnabled     = Convert-DisabledFlagToEnabled $disableBehaviorMonitoring
                    IOAVProtectionEnabled         = Convert-DisabledFlagToEnabled $disableIOAVProtection
                    ScriptScanningEnabled         = Convert-DisabledFlagToEnabled $disableScriptScanning
                    DisableRealtimeMonitoring     = $disableRealtimeMonitoring
                    DisableBehaviorMonitoring     = $disableBehaviorMonitoring
                    DisableIOAVProtection         = $disableIOAVProtection
                    DisableScriptScanning         = $disableScriptScanning
                }
                Write-OK "Effective config: Cloud=$(Get-Prop $effConfig 'MAPSReporting'), PUA=$(Get-Prop $effConfig 'PUAProtection'), RTP Enabled=$((Convert-DisabledFlagToEnabled $disableRealtimeMonitoring))"
            }
            catch { Write-Warn "Could not parse effective config JSON: $_" }
        }

        # ── Platform Versions (FileVersions.txt) ──────────────────────────────
        $fileVersionsFile = Get-ChildItem -Path $cabExtractDir -Filter "FileVersions.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fileVersionsFile) {
            $fileVersionsContent = Read-NormalizedTextFile $fileVersionsFile.FullName
            $platformVersions = [ordered]@{}

            if ($fileVersionsContent -match 'OS Build/Branch info:\s*([^\r\n]+)') {
                $platformVersions['OSBuildBranch'] = $Matches[1].Trim()
            }
            if ($fileVersionsContent -match 'GetOsVersion\(\)\s*reports:\s*([^\r\n]+)') {
                $platformVersions['ReportedOSVersion'] = $Matches[1].Trim()
            }
            if ($fileVersionsContent -match 'Windows Defender\\Platform\\([0-9A-Za-z\.\-]+)') {
                $platformVersions['DefenderPlatformVersion'] = $Matches[1].Trim()
            }

            if ($platformVersions.Count -gt 0) {
                $cabIntel['PlatformVersions'] = $platformVersions
                Write-OK "Platform versions parsed: OS=$($platformVersions.ReportedOSVersion), DefenderPlatform=$($platformVersions.DefenderPlatformVersion)"
            }
        }

        # ── Product Health (MPStateInfo.txt) ──────────────────────────────────
        $mpStateFile = Get-ChildItem -Path $cabExtractDir -Filter "MPStateInfo.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($mpStateFile) {
            $mpStateContent = Read-NormalizedTextFile $mpStateFile.FullName
            $healthState = [ordered]@{}

            if ($mpStateContent -match 'Threat Stats\s*:\s*Threats\((\d+)\)\s*Suspicious\((\d+)\)') {
                $healthState['ThreatCount'] = [int]$Matches[1]
                $healthState['SuspiciousCount'] = [int]$Matches[2]
            }
            if ($mpStateContent -match 'Overall product status\s*:\s*(0x[0-9A-Fa-f]+)') {
                $healthState['OverallProductStatus'] = $Matches[1]
            }

            $statusPhrases = [ordered]@{
                AutoScanEnabled            = 'Auto scan enabled'
                AutoSignatureUpdateEnabled = 'Auto sigupdate enabled'
                RealtimeMonitorEnabled     = 'Realtime monitor enabled'
                OnAccessProtectionEnabled  = 'OnAccess protection enabled'
                IOAVProtectionEnabled      = 'IOAV protection enabled'
            }

            foreach ($statusEntry in $statusPhrases.GetEnumerator()) {
                $healthState[$statusEntry.Key] = $mpStateContent -match [regex]::Escape($statusEntry.Value)
            }

            if ($healthState.Count -gt 0) {
                $cabIntel['HealthState'] = $healthState
                Write-OK "Health state parsed: RTP=$($healthState.RealtimeMonitorEnabled), OnAccess=$($healthState.OnAccessProtectionEnabled), IOAV=$($healthState.IOAVProtectionEnabled)"
            }
        }

        # ── Network Protection State (NetworkProtectionState.txt) ─────────────
        $networkProtectionFile = Get-ChildItem -Path $cabExtractDir -Filter "NetworkProtectionState.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($networkProtectionFile) {
            $networkProtectionContent = Read-NormalizedTextFile $networkProtectionFile.FullName
            $networkProtection = [ordered]@{}
            $networkFlags = [ordered]@{}
            $disabledFeatures = @()

            if ($networkProtectionContent -match 'Network Protection is currently set in ([^\r\n]+?) mode') {
                $networkProtection['Mode'] = $Matches[1].Trim()
            }

            foreach ($match in [regex]::Matches($networkProtectionContent, '"([^"]+)":(true|false)')) {
                $flagName = $match.Groups[1].Value
                $flagValue = $match.Groups[2].Value -eq 'true'
                $networkFlags[$flagName] = $flagValue
                if ($flagName -like 'disable*' -and $flagValue) {
                    $disabledFeatures += $flagName
                }
            }

            if ($networkFlags.Count -gt 0) {
                $networkProtection['Flags'] = $networkFlags
                $networkProtection['DisabledFeatures'] = @($disabledFeatures)
                $networkProtection['DisabledFeatureCount'] = $disabledFeatures.Count
            }

            if ($networkProtection.Count -gt 0) {
                $cabIntel['NetworkProtection'] = $networkProtection
                if ($disabledFeatures.Count -gt 0) {
                    Write-Warn "Network protection: $($networkProtection.Mode) mode, $($disabledFeatures.Count) feature toggle(s) disabled"
                }
                else {
                    Write-OK "Network protection: $($networkProtection.Mode) mode"
                }
            }
        }

        # ── Device Control State (DeviceControlInfo.txt / MPDeviceControl*.log) ─
        $deviceControlFile = Get-ChildItem -Path $cabExtractDir -Filter "DeviceControlInfo.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($deviceControlFile) {
            $deviceControlContent = Read-NormalizedTextFile $deviceControlFile.FullName
            $deviceControl = [ordered]@{}

            if ($deviceControlContent -match 'Defender service running mode:\s*([^\r\n]+)') {
                $deviceControl['ServiceMode'] = $Matches[1].Trim()
            }
            if ($deviceControlContent -match 'PackageVersion:\s*([^\r\n]+)') {
                $deviceControl['PackageVersion'] = $Matches[1].Trim()
            }
            if ($deviceControlContent -match 'State:\s*([^\r\n]+)') {
                $deviceControl['State'] = $Matches[1].Trim()
            }
            if ($deviceControlContent -match 'DefaultEnforcement:\s*([^\r\n]+)') {
                $deviceControl['DefaultEnforcement'] = $Matches[1].Trim()
            }
            if ($deviceControlContent -match 'PoliciesLastUpdated:\s*([^\r\n]+)') {
                $deviceControl['PoliciesLastUpdated'] = $Matches[1].Trim()
            }

            $deviceControlLog = Get-ChildItem -Path $cabExtractDir -Filter "MPDeviceControl-*.log" -Recurse -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
            if ($deviceControlLog) {
                $deviceControlLogContent = Read-NormalizedTextFile $deviceControlLog.FullName
                if ($deviceControlLogContent -match 'IsAvailable\[(\d+)\]') {
                    $deviceControl['Available'] = ([int]$Matches[1] -ne 0)
                }
                if ($deviceControlLogContent -match 'fDeviceControlEnabled\[(\d+)\]') {
                    $deviceControl['EnabledByPolicy'] = ([int]$Matches[1] -ne 0)
                }
                if ($deviceControlLogContent -match 'fDeviceControlPolicyPresent\[(\d+)\]') {
                    $deviceControl['PolicyPresent'] = ([int]$Matches[1] -ne 0)
                }
            }

            if ($deviceControl.Count -gt 0) {
                $cabIntel['DeviceControl'] = $deviceControl
                Write-OK "Device control parsed: State=$($deviceControl.State), ServiceMode=$($deviceControl.ServiceMode)"
            }
        }

        # ── Cloud/Operational Events (MPOperationalEvents.txt) ────────────────
        $operationalEventsFile = Get-ChildItem -Path $cabExtractDir -Filter "MPOperationalEvents.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($operationalEventsFile) {
            $operationalEventsContent = Read-NormalizedTextFile $operationalEventsFile.FullName
            $cloudOperationalEvents = [ordered]@{}
            $cloudEventCount = [regex]::Matches($operationalEventsContent, 'used cloud protection to get additional security intelligence', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase).Count
            $recentCloudEvents = [System.Collections.Generic.List[PSObject]]::new()

            if ($cloudEventCount -gt 0) {
                $cloudOperationalEvents['CloudProtectionEventCount'] = $cloudEventCount
            }
            if ($operationalEventsContent -match 'Current security intelligence Version:\s*([^\r\n]+)') {
                $cloudOperationalEvents['LatestSecurityIntelligenceVersion'] = $Matches[1].Trim()
            }
            if ($operationalEventsContent -match 'Current Engine Version:\s*([^\r\n]+)') {
                $cloudOperationalEvents['LatestEngineVersion'] = $Matches[1].Trim()
            }

            foreach ($eventChunk in ($operationalEventsContent -split '(?=\*{20,})')) {
                if ($recentCloudEvents.Count -ge 5) { break }
                if ($eventChunk -notmatch 'used cloud protection to get additional security intelligence') { continue }

                $eventInfo = [ordered]@{}
                if ($eventChunk -match '(?m)^(?<timestamp>\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[AP]M)\s+') {
                    $eventInfo['Timestamp'] = $Matches['timestamp'].Trim()
                }
                if ($eventChunk -match 'Current security intelligence Version:\s*([^\r\n]+)') {
                    $eventInfo['SecurityIntelligenceVersion'] = $Matches[1].Trim()
                }
                if ($eventChunk -match 'Current Engine Version:\s*([^\r\n]+)') {
                    $eventInfo['EngineVersion'] = $Matches[1].Trim()
                }
                if ($eventChunk -match 'Cloud protection intelligence Type:\s*([^\r\n]+)') {
                    $eventInfo['IntelligenceType'] = $Matches[1].Trim()
                }
                if ($eventChunk -match 'Persistence Path:\s*([^\r\n]+)') {
                    $eventInfo['PersistencePath'] = $Matches[1].Trim()
                }
                if ($eventChunk -match 'Cloud protection intelligence Compilation Timestamp:\s*([^\r\n]+)') {
                    $eventInfo['CompilationTimestamp'] = $Matches[1].Trim()
                }
                if ($eventChunk -match 'Persistence Limit Type:\s*([^\r\n]+)') {
                    $eventInfo['PersistenceLimitType'] = $Matches[1].Trim()
                }
                if ($eventChunk -match 'Persistence Limit:\s*([^\r\n]+)') {
                    $eventInfo['PersistenceLimit'] = $Matches[1].Trim()
                }

                if ($eventInfo.Count -gt 0) {
                    $recentCloudEvents.Add([PSCustomObject]$eventInfo)
                }
            }

            if ($recentCloudEvents.Count -gt 0) {
                $cloudOperationalEvents['RecentCloudEvents'] = @($recentCloudEvents)
            }

            if ($cloudOperationalEvents.Count -gt 0) {
                $cabIntel['CloudOperationalEvents'] = $cloudOperationalEvents
                Write-OK "Operational events parsed: $cloudEventCount cloud intelligence event(s)"
            }
        }

        # ── Security Center Providers (WSCInfo.txt) ───────────────────────────
        $wscInfoFile = Get-ChildItem -Path $cabExtractDir -Filter "WSCInfo.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($wscInfoFile) {
            $wscLines = Get-NormalizedTextLines $wscInfoFile.FullName
            $rawProducts = [System.Collections.Generic.List[PSObject]]::new()
            $currentProduct = [ordered]@{}

            foreach ($line in $wscLines) {
                $trimmedLine = $line.Trim()

                if ($trimmedLine -match '^displayName = \[(.+)\]$') {
                    if ($currentProduct.Count -gt 0 -and $currentProduct['DisplayName']) {
                        $rawProducts.Add([PSCustomObject]$currentProduct)
                    }
                    $currentProduct = [ordered]@{ DisplayName = $Matches[1].Trim() }
                    continue
                }

                if ($trimmedLine -match '^pathToSignedProductExe = \[(.*)\]$') {
                    if ($currentProduct.Count -gt 0) {
                        $currentProduct['ProductPath'] = $Matches[1].Trim()
                    }
                    continue
                }

                if ($trimmedLine -match '^productState = \[(\d+)\]$') {
                    if ($currentProduct.Count -gt 0) {
                        $currentProduct['ProductState'] = [int]$Matches[1]
                        $rawProducts.Add([PSCustomObject]$currentProduct)
                        $currentProduct = [ordered]@{}
                    }
                }
            }

            if ($currentProduct.Count -gt 0 -and $currentProduct['DisplayName']) {
                $rawProducts.Add([PSCustomObject]$currentProduct)
            }

            $uniqueProducts = [System.Collections.Generic.List[PSObject]]::new()
            $seenProducts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($product in $rawProducts) {
                $productKey = '{0}|{1}|{2}' -f $product.DisplayName, $product.ProductPath, $product.ProductState
                if ($seenProducts.Add($productKey)) {
                    $uniqueProducts.Add($product)
                }
            }

            if ($uniqueProducts.Count -gt 0) {
                $cabIntel['SecurityCenterProducts'] = @($uniqueProducts)
                if ($uniqueProducts.Count -gt 1) {
                    Write-Warn "$($uniqueProducts.Count) products registered in Windows Security Center"
                }
                else {
                    Write-OK "Windows Security Center registration parsed"
                }
            }
        }

        # ── MDE Onboarding Hints (search extracted text for onboarding metadata) ─
        $senseSource = Get-ChildItem -Path $cabExtractDir -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Extension -in @('.txt', '.log', '.json') } |
            Select-String -Pattern 'OnboardedInfo|MdeAadTenantIdMapping' -List -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($senseSource) {
            $senseContent = Read-NormalizedTextFile $senseSource.Path
            $mdeOnboarding = [ordered]@{}

            if ($senseContent -match '"orgId":"([^"]+)"') {
                $mdeOnboarding['OrgId'] = $Matches[1]
            }
            if ($senseContent -match '"datacenter":"([^"]+)"') {
                $mdeOnboarding['Datacenter'] = $Matches[1]
            }
            if ($senseContent -match '"vortexGeoLocation":"([^"]+)"') {
                $mdeOnboarding['VortexGeoLocation'] = $Matches[1]
            }
            if ($senseContent -match '"mdeAadTenantId":"([^"]+)"') {
                $mdeOnboarding['MdeAadTenantId'] = $Matches[1]
            }
            if ($senseContent -match '"version":"([^"]+)"') {
                $mdeOnboarding['Version'] = $Matches[1]
            }

            if ($mdeOnboarding.Count -gt 0) {
                $mdeOnboarding['Onboarded'] = $true
                $cabIntel['MDEOnboarding'] = $mdeOnboarding
                Write-OK "MDE onboarding metadata parsed: OrgId=$($mdeOnboarding.OrgId)"
            }
        }

        # ── MPLog Highlights (MPLog-*.log) ───────────────────────────────────
        $mpLogFiles = @(Get-ChildItem -Path $cabExtractDir -Filter "MPLog-*.log" -Recurse -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending)
        if ($mpLogFiles) {
            $mpLogHighlights = [ordered]@{
                FileCount          = $mpLogFiles.Count
                LatestFile         = $mpLogFiles[0].Name
                LatestFileWriteTime = $mpLogFiles[0].LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
            }
            $dynamicSignatureEvents = [System.Collections.Generic.List[PSObject]]::new()
            $impactRecords = [System.Collections.Generic.List[PSObject]]::new()
            $pathExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $processExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            $extensionExclusions = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

            foreach ($mpLogFile in $mpLogFiles | Select-Object -First 3) {
                $mpLogLines = Get-NormalizedTextLines $mpLogFile.FullName
                $currentImpactRecord = $null
                $currentTimestamp = $null

                for ($i = 0; $i -lt $mpLogLines.Count; $i++) {
                    $line = $mpLogLines[$i]
                    if ([string]::IsNullOrWhiteSpace($line)) {
                        if ($currentImpactRecord -and $currentImpactRecord.Count -gt 1) {
                            $impactRecords.Add([PSCustomObject]$currentImpactRecord)
                        }
                        $currentImpactRecord = $null
                        continue
                    }

                    $trimmedLine = $line.Trim()
                    if ($trimmedLine -match '^(?<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)') {
                        $currentTimestamp = $Matches['timestamp']
                    }

                    if ($trimmedLine -match '^PathExclusion:\s*(.+)$') {
                        [void]$pathExclusions.Add($Matches[1].Trim())
                    }
                    elseif ($trimmedLine -match '^ProcessExclusion:\s*(.+)$') {
                        [void]$processExclusions.Add($Matches[1].Trim())
                    }
                    elseif ($trimmedLine -match '^ExtensionExclusion:\s*(.+)$') {
                        $normalizedExtension = Normalize-Extension $Matches[1]
                        if ($normalizedExtension) {
                            [void]$extensionExclusions.Add($normalizedExtension)
                        }
                    }

                    if ($trimmedLine -match 'Dynamic signature dropped$') {
                        $event = [ordered]@{
                            Timestamp = $currentTimestamp
                            SourceLog = $mpLogFile.Name
                        }

                        for ($j = $i + 1; $j -lt [Math]::Min($mpLogLines.Count, $i + 8); $j++) {
                            $detailLine = $mpLogLines[$j].Trim()
                            if ([string]::IsNullOrWhiteSpace($detailLine)) { break }
                            if ($detailLine -match '^\d{4}-\d{2}-\d{2}T') { break }
                            if ($detailLine -match '^Dynamic Signature Type:\s*(.+)$') {
                                $event['SignatureType'] = $Matches[1].Trim()
                            }
                            elseif ($detailLine -match '^Signature Path:\s*(.+)$') {
                                $event['SignaturePath'] = $Matches[1].Trim()
                            }
                            elseif ($detailLine -match '^Dynamic Signature Compilation Timestamp:\s*(.+)$') {
                                $event['CompilationTimestamp'] = $Matches[1].Trim()
                            }
                            elseif ($detailLine -match '^Persistence Type:\s*(.+)$') {
                                $event['PersistenceType'] = $Matches[1].Trim()
                            }
                            elseif ($detailLine -match '^Time remaining:\s*(.+)$') {
                                $event['TimeRemaining'] = $Matches[1].Trim()
                            }
                        }

                        $dynamicSignatureEvents.Add([PSCustomObject]$event)
                    }

                    if ($trimmedLine -match '^(ProcessImageName|ProcessPath|ProcessName|ImageName|EstimatedImpact|Estimated impact)\s*[:=]\s*(.+)$') {
                        if (-not $currentImpactRecord) {
                            $currentImpactRecord = [ordered]@{
                                Timestamp = $currentTimestamp
                                SourceLog  = $mpLogFile.Name
                            }
                        }

                        $fieldName = ($Matches[1] -replace '\s+', '')
                        $fieldValue = $Matches[2].Trim()
                        switch -Regex ($fieldName) {
                            '^ProcessImageName$' { $currentImpactRecord['ProcessImageName'] = $fieldValue }
                            '^ProcessPath$'      { $currentImpactRecord['ProcessPath'] = $fieldValue }
                            '^ProcessName$'      { $currentImpactRecord['ProcessName'] = $fieldValue }
                            '^ImageName$'        { $currentImpactRecord['ImageName'] = $fieldValue }
                            '^EstimatedImpact$'  { $currentImpactRecord['EstimatedImpact'] = $fieldValue }
                        }
                    }
                }

                if ($currentImpactRecord -and $currentImpactRecord.Count -gt 1) {
                    $impactRecords.Add([PSCustomObject]$currentImpactRecord)
                }
            }

            if ($dynamicSignatureEvents.Count -gt 0) {
                $mpLogHighlights['DynamicSignatureDropCount'] = $dynamicSignatureEvents.Count
                $mpLogHighlights['RecentDynamicSignatureEvents'] = @($dynamicSignatureEvents | Select-Object -First 5)
            }

            if ($pathExclusions.Count -gt 0 -or $processExclusions.Count -gt 0 -or $extensionExclusions.Count -gt 0) {
                $mpLogHighlights['ExclusionMentions'] = [ordered]@{
                    Paths      = @($pathExclusions)
                    Processes  = @($processExclusions)
                    Extensions = @($extensionExclusions | ForEach-Object { Format-ExtensionDisplay $_ })
                }
            }

            if ($impactRecords.Count -gt 0) {
                $mpLogHighlights['ImpactRecords'] = @($impactRecords | Select-Object -First 10)
            }

            if ($mpLogHighlights.Count -gt 0) {
                $cabIntel['MPLogHighlights'] = $mpLogHighlights
                Write-OK "MPLog analysis parsed: $($mpLogHighlights.FileCount) log(s), $($dynamicSignatureEvents.Count) dynamic signature event(s)"
            }
        }

        # ── Signature Update Stub (MpSigStub.log) ────────────────────────────
        $mpSigStubFile = Get-ChildItem -Path $cabExtractDir -Filter "MpSigStub.log" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($mpSigStubFile) {
            $mpSigStubContent = Read-NormalizedTextFile $mpSigStubFile.FullName
            $signatureUpdateStub = [ordered]@{}

            if ($mpSigStubContent -match 'Start time:\s*([^\r\n]+)') {
                $signatureUpdateStub['StartTime'] = $Matches[1].Trim()
            }
            if ($mpSigStubContent -match 'Command:\s*([^\r\n]+)') {
                $signatureUpdateStub['Command'] = $Matches[1].Trim()
            }
            if ($mpSigStubContent -match 'Administrator:\s*([^\r\n]+)') {
                $signatureUpdateStub['Administrator'] = $Matches[1].Trim()
            }
            if ($mpSigStubContent -match 'Version:\s*([^\r\n]+)') {
                $signatureUpdateStub['StubVersion'] = $Matches[1].Trim()
            }
            if ($mpSigStubContent -match 'Status:\s*([^\r\n]+)') {
                $signatureUpdateStub['ProductStatus'] = $Matches[1].Trim()
            }
            if ($mpSigStubContent -match 'Engine:\s*[0-9a-fA-F]+\s+([^\r\n]+)') {
                $signatureUpdateStub['ProductEngineVersion'] = $Matches[1].Trim()
            }

            if ($signatureUpdateStub.Count -gt 0) {
                $cabIntel['SignatureUpdateStub'] = $signatureUpdateStub
                Write-OK "Signature update stub log parsed: $($signatureUpdateStub.StartTime)"
            }
        }

        # ── Scan Skip Analysis (MPScanSkip-*.log) ───────────────────────────
        $scanSkipFiles = Get-ChildItem -Path $cabExtractDir -Filter "MPScanSkip-*.log" -Recurse -ErrorAction SilentlyContinue
        if ($scanSkipFiles) {
            $skipReasons = @{}
            $totalSkips = 0
            foreach ($sf in $scanSkipFiles) {
                $lines = Get-Content $sf.FullName -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line -match 'Reason\[(.+?)\]') {
                        $reason = $Matches[1]
                        if (-not $skipReasons.ContainsKey($reason)) { $skipReasons[$reason] = 0 }
                        $skipReasons[$reason] = $skipReasons[$reason] + 1
                        $totalSkips++
                    }
                }
            }
            if ($totalSkips -gt 0) {
                $cabIntel['ScanSkips'] = [ordered]@{
                    TotalSkipped = $totalSkips
                    ByReason     = $skipReasons
                }
                Write-Warn "Scan skips detected: $totalSkips total"
                foreach ($r in ($skipReasons.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5)) {
                    Write-Info "  $($r.Key): $($r.Value) skips"
                }
            }
            else {
                Write-OK "No scan skips found"
            }
        }

        # ── Detection History (MPDetection-*.log) ────────────────────────────
        $detectionFiles = Get-ChildItem -Path $cabExtractDir -Filter "MPDetection-*.log" -Recurse -ErrorAction SilentlyContinue
        if ($detectionFiles) {
            $detections = @()
            foreach ($df in $detectionFiles) {
                $lines = Get-Content $df.FullName -ErrorAction SilentlyContinue
                foreach ($line in $lines) {
                    if ($line -match 'threat|detection|quarantine' -and $line -notmatch '^[\d-]+T[\d:.]+ (Version|Service started)') {
                        $detections += $line.Trim()
                    }
                }
            }
            $cabIntel['RecentDetections'] = $detections
            if ($detections.Count -gt 0) {
                Write-Bad "$($detections.Count) detection event(s) found in logs"
            }
            else {
                Write-OK "No recent detections in logs"
            }
        }

        # ── Filter Driver Stack (FltmcInfo.txt) ─────────────────────────────
        $fltmcFile = Get-ChildItem -Path $cabExtractDir -Filter "FltmcInfo.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($fltmcFile) {
            $drivers = @()
            $lines = Get-Content $fltmcFile.FullName -ErrorAction SilentlyContinue
            foreach ($line in $lines) {
                if ($line -match '^\S+\s+\d+\s+\d+') {
                    $parts = $line.Trim() -split '\s+'
                    $drivers += [ordered]@{ Name = $parts[0]; Instances = [int]$parts[1]; Altitude = $parts[2] }
                }
            }
            if ($drivers.Count -gt 0) {
                $cabIntel['FilterDrivers'] = $drivers
                Write-OK "$($drivers.Count) filesystem filter drivers active"
                $wdFilter = $drivers | Where-Object { $_.Name -eq 'WdFilter' }
                if ($wdFilter) {
                    Write-Info "  WdFilter (Defender) at altitude $($wdFilter.Altitude) with $($wdFilter.Instances) instances"
                }
            }
        }

        # ── IFEO (Image File Execution Options) — debugger hijack check ─────
        $ifeoFile = Get-ChildItem -Path $cabExtractDir -Filter "IFEO.txt" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($ifeoFile) {
            $ifeoContent = Get-Content $ifeoFile.FullName -Raw -ErrorAction SilentlyContinue
            $debuggerHijacks = @()
            if ($ifeoContent -match 'Debugger') {
                $ifeoLines = $ifeoContent -split '\r?\n'
                for ($i = 0; $i -lt $ifeoLines.Count; $i++) {
                    if ($ifeoLines[$i] -match 'Debugger.*=.*\S') {
                        $debuggerHijacks += $ifeoLines[$i].Trim()
                    }
                }
            }
            if ($debuggerHijacks.Count -gt 0) {
                $cabIntel['IFEODebuggerHijacks'] = $debuggerHijacks
                Write-Bad "$($debuggerHijacks.Count) IFEO debugger entry/entries found (potential security concern)"
                foreach ($h in $debuggerHijacks) { Write-Info "  $h" }
            }
            else {
                Write-OK "No IFEO debugger hijacks detected"
            }
        }
    }
    catch {
        Write-Warn "CAB intelligence extraction failed: $_"
    }
    finally {
        Remove-Item $cabExtractDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
else {
    Write-Info "CAB file not available -- skipping intelligence extraction"
    Write-Info "Run 'MpCmdRun.exe -GetFiles' first to generate the CAB"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 3 — CAPTURE PERFORMANCE RECORDING
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "3 - Capturing Performance Recording ($RecordingSeconds s)"

$etlFile = Join-Path $env:TEMP "DefenderPerf_$(Get-Date -Format 'yyyyMMdd_HHmmss').etl"

Write-Info "Trace file : $etlFile"
Write-Info "Duration   : $RecordingSeconds seconds"
Write-Info "Preparing Defender performance recording..."
Write-Host ""

Reset-MpPerformanceRecordingState

$workloadJob = $null
if ($ValidateLoad) {
    $workloadScript = Join-Path (Split-Path $MyInvocation.MyCommand.Path -Parent) 'defender-workload.ps1'
    if (Test-Path $workloadScript) {
        Write-Info "Launching workload generator in background (mode: $SyntheticWorkloadMode)..."
        $workloadJob = Start-Job -ScriptBlock {
            param($script, $seconds, $mode)
            & $script -DurationSeconds $seconds -Mode $mode
        } -ArgumentList $workloadScript, $RecordingSeconds, $SyntheticWorkloadMode
        Write-OK "Workload job started (Job ID: $($workloadJob.Id))"
    }
    else {
        Write-Warn "Workload script not found at: $workloadScript"
    }
}

$workloadOutput = @()
$recordingSucceeded = $false
$recordingAttempt = 0
$maxRecordingAttempts = 2
$recordingError = $null
try {
    while (-not $recordingSucceeded -and $recordingAttempt -lt $maxRecordingAttempts) {
        $recordingAttempt++

        try {
            Write-Info "Starting recording (attempt $recordingAttempt of $maxRecordingAttempts) -- keep your normal workload running..."
            New-MpPerformanceRecording -RecordTo $etlFile -Seconds $RecordingSeconds
            $recordingSucceeded = $true
            Write-OK "Recording completed successfully"
            $etlSize = (Get-Item $etlFile -ErrorAction SilentlyContinue).Length
            if ($etlSize) { Write-Info "File size  : $([math]::Round($etlSize / 1MB, 2)) MB" }
        }
        catch {
            $recordingError = $_
            Write-Warn "Recording attempt $recordingAttempt failed: $($_.Exception.Message)"
            Write-ExceptionDetails $_

            if ($recordingAttempt -lt $maxRecordingAttempts) {
                Write-Info "Retrying after resetting Defender/WPR trace state..."
                Reset-MpPerformanceRecordingState
                Start-Sleep -Seconds 2
            }
        }
    }

    if (-not $recordingSucceeded) {
        if ($recordingError) { throw $recordingError }
        throw "New-MpPerformanceRecording failed without returning an error record."
    }
}
catch {
    Write-Bad "Failed to create performance recording: $_"
    Write-ExceptionDetails $_
    Write-Host ""
    Write-Host "  Possible causes:" -ForegroundColor Yellow
    Write-Host "    - Defender or WPR trace state is stale and needs reset" -ForegroundColor Yellow
    Write-Host "    - Defender platform too old (need 4.18.2108+)" -ForegroundColor Yellow
    Write-Host "    - Insufficient permissions" -ForegroundColor Yellow
    Write-Host "    - Another capture mechanism is blocking the recording" -ForegroundColor Yellow
    Write-Host ""
    Write-Info "Transcript log : $script:transcriptFile"
    Exit-Script 1
}
finally {
    if ($workloadJob) {
        if ($recordingSucceeded) {
            Write-Info "Waiting for workload generator to finish..."
            $workloadOutput = Stop-BackgroundJob -Job $workloadJob -WaitForCompletion -WaitTimeoutSeconds 30
            if ($workloadOutput) {
                foreach ($line in $workloadOutput) { Write-Host "  $line" -ForegroundColor DarkMagenta }
            }
            Write-OK "Workload generator completed"
        }
        else {
            $null = Stop-BackgroundJob -Job $workloadJob -StopIfRunning
            Write-Warn "Workload generator stopped after recording failure"
        }
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 4 — GENERATE PERFORMANCE REPORT FROM RECORDING
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "4 - Generating Performance Report"

try {
    $perfReport = Get-MpPerformanceReport -Path $etlFile `
        -TopFiles $TopN `
        -TopScansPerFile 3 `
        -TopProcesses $TopN `
        -TopScansPerProcess 3 `
        -TopExtensions $TopN `
        -TopScansPerExtension 3 `
        -TopScans $TopN `
        -MinDuration "100ms" `
        -Raw
    Write-OK "Performance report generated (with -Raw for clean JSON)"
}
catch {
    Write-Bad "Failed to parse performance recording: $_"
    Write-Host "  The .etl file may be corrupt or empty. Try a longer recording." -ForegroundColor Yellow
    Write-ExceptionDetails $_
    Write-Info "Transcript log : $script:transcriptFile"
    Exit-Script 1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 5 — CONVERT TO JSON
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "5 - Converting Report to JSON"

$timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$htmlFile = Join-Path $ReportPath "DefenderPerf_$runId.html"
$aiExportFile = if ($AIMode) { Join-Path $ReportPath "DefenderPerf_$runId.ai-export.json" } else { $null }
$aiPromptFile = if ($AIMode) { Join-Path $ReportPath "DefenderPerf_$runId.ai-prompt.md" } else { $null }

$jsonData = [ordered]@{
    ReportMetadata     = [ordered]@{
        GeneratedAt        = $timestamp
        ComputerName       = $env:COMPUTERNAME
        OSVersion          = [System.Environment]::OSVersion.VersionString
        RecordingFile      = $etlFile
        RecordDuration     = $RecordingSeconds
        TranscriptLog      = $script:transcriptFile
        DefenderEngine     = if ($status) { $status.AMProductVersion } else { 'N/A' }
        DefenderCoreEngine = if ($engineVersion) { $engineVersion } else { 'N/A' }
        SignatureVersion   = if ($status) { $status.AntivirusSignatureVersion } else { 'N/A' }
        RealTimeProtection = if ($status) { $status.RealTimeProtectionEnabled } else { $null }
        SyntheticWorkload  = [bool]$ValidateLoad
        SyntheticWorkloadMode = if ($ValidateLoad) { $SyntheticWorkloadMode } else { $null }
        ExclusionValidation = $requestedValidateExclusions
        AIMode             = [bool]$AIMode
        AIExportFile       = $aiExportFile
        AIPromptFile       = $aiPromptFile
        ScheduleMode       = $script:scheduleMode
        ScheduleInput      = $script:scheduleInput
        ScheduledStartAt   = if ($script:scheduledStartAt) { $script:scheduledStartAt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
        ActualRunStartedAt = if ($script:actualRunStartedAt) { $script:actualRunStartedAt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
        ScheduledWaitSeconds = $script:scheduledWaitSeconds
        StrictCAB          = [bool]$StrictCAB
        CABSnapshot        = $script:reportCabSnapshot
        ContextualExclusionsSupported = $contextualExclusionsSupported
        DisableLocalAdminMerge = $disableLocalAdminMerge
    }
    ExclusionValidationDetails = $exclusionValidationDetails
    ExclusionDiscovery = [ordered]@{
        Source     = $exclusionSource
        Paths      = $discoveredExcl.Paths
        Processes  = $discoveredExcl.Processes
        Extensions = $discoveredExcl.Extensions
    }
    ExclusionGuidance  = $exclusionGuidance
    CABIntelligence    = $cabIntel
    TopFiles           = $perfReport.TopFiles
    TopProcesses       = $perfReport.TopProcesses
    TopExtensions      = $perfReport.TopExtensions
    TopScans           = $perfReport.TopScans
}

$jsonFile = Join-Path $ReportPath "DefenderPerf_$runId.json"
Write-OK "JSON data prepared (will be saved after analysis)"

# ── Derive scan context and extension hotspot models ─────────────────────────
$script:extensionHotspots = @()
$script:topScanContexts = @()

if ($perfReport.TopScans) {
    $script:topScanContexts = @(
        foreach ($scan in $perfReport.TopScans) {
            $durationMs = Get-DurationMs $scan
            $scanPath = if (Get-Prop $scan 'Path') { $scan.Path }
            elseif (Get-Prop $scan 'File') { $scan.File }
            elseif (Get-Prop $scan 'Process') { $scan.Process }
            else { '<unresolved scan target>' }
            $processPath = if (Get-Prop $scan 'ProcessPath') { $scan.ProcessPath }
            elseif (Get-Prop $scan 'Process') { $scan.Process }
            else { $null }
            $image = if (Get-Prop $scan 'Image') { $scan.Image }
            elseif ($processPath) { Split-Path $processPath -Leaf -ErrorAction SilentlyContinue }
            else { $null }
            $relatedFolderMap = @{}
            $commentSamples = [System.Collections.Generic.List[string]]::new()

            $scanComments = @()
            foreach ($rawComment in @(Get-Prop $scan 'Comments')) {
                if (-not [string]::IsNullOrWhiteSpace($rawComment)) {
                    $scanComments += $rawComment
                }
            }

            foreach ($comment in $scanComments) {
                if (-not [string]::IsNullOrWhiteSpace($comment) -and $commentSamples.Count -lt 5) {
                    [void]$commentSamples.Add($comment)
                }

                $parsedComment = Parse-ScanComment $comment
                if ($parsedComment) {
                    Add-FolderAggregateObservation -Map $relatedFolderMap `
                        -FolderPath $parsedComment.FolderPath `
                        -DurationMs $parsedComment.DurationMs `
                        -ProcessPath $null `
                        -Image $null `
                        -ExamplePath $parsedComment.Path
                }
            }

            $relatedObservedDurationMs = 0.0
            foreach ($entry in $relatedFolderMap.Values) {
                $relatedObservedDurationMs += [double]$entry.TotalDurationMs
            }
            $relatedFolders = if ($relatedFolderMap.Count -gt 0) {
                Convert-FolderAggregateMapToRows -Map $relatedFolderMap -ObservedDurationMs $relatedObservedDurationMs | Select-Object -First 3
            }
            else {
                @()
            }

            [PSCustomObject]@{
                EstimatedImpact    = Get-ImpactLevel $durationMs
                DurationMs         = [math]::Round($durationMs, 2)
                Duration           = Format-Duration $durationMs
                StartTimeLocal     = Convert-FileTimeValueToLocalText (Get-Prop $scan 'StartTime')
                ScanType           = if (Get-Prop $scan 'ScanType') { $scan.ScanType } else { 'n/a' }
                Reason             = Get-Prop $scan 'Reason'
                SkipReason         = Get-Prop $scan 'SkipReason'
                TargetPath         = $scanPath
                ProcessPath        = $processPath
                ProcessImage       = $image
                ProcessName        = Get-Prop $scan 'ProcessName'
                RelatedFileCount   = $scanComments.Count
                RelatedFolders     = @($relatedFolders)
                CommentSamples     = @($commentSamples)
            }
        }
    )
}

if ($perfReport.TopExtensions) {
    $script:extensionHotspots = @(
        foreach ($extensionEntry in $perfReport.TopExtensions) {
            $rawExtension = Normalize-Extension (Get-Prop $extensionEntry 'Extension')
            if (-not $rawExtension) { continue }

            $folderMap = @{}
            $totalDurationMs = Get-DurationMs $extensionEntry
            $commentMatches = 0

            foreach ($scan in @(Get-Prop $extensionEntry 'Scans')) {
                $scanPath = Get-Prop $scan 'Path'
                $folderPath = Get-PathDirectory $scanPath
                Add-FolderAggregateObservation -Map $folderMap `
                    -FolderPath $folderPath `
                    -DurationMs (Get-DurationMs $scan) `
                    -ProcessPath (Get-Prop $scan 'ProcessPath') `
                    -Image (Get-Prop $scan 'Image') `
                    -ExamplePath $scanPath
            }

            foreach ($scanContext in $script:topScanContexts) {
                $hasExtensionComment = $false
                foreach ($comment in @($scanContext.CommentSamples)) {
                    $parsedComment = Parse-ScanComment $comment
                    if (-not $parsedComment -or $parsedComment.Extension -ne $rawExtension) { continue }

                    $hasExtensionComment = $true
                    $commentMatches++
                    Add-FolderAggregateObservation -Map $folderMap `
                        -FolderPath $parsedComment.FolderPath `
                        -DurationMs $parsedComment.DurationMs `
                        -ProcessPath $scanContext.ProcessPath `
                        -Image $scanContext.ProcessImage `
                        -ExamplePath $parsedComment.Path
                }

                if (-not $hasExtensionComment -and $scanContext.TargetPath) {
                    $scanContextExtension = Normalize-Extension ([System.IO.Path]::GetExtension([string]$scanContext.TargetPath))
                    if ($scanContextExtension -eq $rawExtension) {
                        Add-FolderAggregateObservation -Map $folderMap `
                            -FolderPath (Get-PathDirectory ([string]$scanContext.TargetPath)) `
                            -DurationMs ([double]$scanContext.DurationMs) `
                            -ProcessPath $scanContext.ProcessPath `
                            -Image $scanContext.ProcessImage `
                            -ExamplePath ([string]$scanContext.TargetPath)
                    }
                }
            }

            $observedDurationMs = 0.0
            foreach ($entry in $folderMap.Values) {
                $observedDurationMs += [double]$entry.TotalDurationMs
            }

            $hotspotFolders = if ($folderMap.Count -gt 0) {
                Convert-FolderAggregateMapToRows -Map $folderMap -ObservedDurationMs $observedDurationMs | Select-Object -First 5
            }
            else {
                @()
            }
            $dominantFolder = @($hotspotFolders | Select-Object -First 1)
            $observedCoveragePercent = if ($totalDurationMs -gt 0) { [math]::Round(($observedDurationMs / $totalDurationMs) * 100, 1) } else { 0 }

            [PSCustomObject]@{
                Extension                 = Format-ExtensionDisplay $rawExtension
                RawExtension              = $rawExtension
                EstimatedImpact           = Get-ImpactLevel $totalDurationMs
                TotalDurationMs           = [math]::Round($totalDurationMs, 2)
                Duration                  = Format-Duration $totalDurationMs
                Count                     = if (Get-Prop $extensionEntry 'Count') { [int]$extensionEntry.Count } else { 1 }
                ObservedDurationMs        = [math]::Round($observedDurationMs, 2)
                ObservedDuration          = Format-Duration $observedDurationMs
                ObservedCoveragePercent   = $observedCoveragePercent
                CommentMatchCount         = $commentMatches
                DominantFolderPath        = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].FolderPath } else { $null }
                DominantFolderShare       = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].ShareOfObservedDuration } else { $null }
                DominantProcessPath       = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].TopProcessPath } else { $null }
                DominantProcessImage      = if ($dominantFolder.Count -gt 0) { $dominantFolder[0].TopProcessImage } else { $null }
                HotspotFolders            = @($hotspotFolders)
            }
        }
    ) | Sort-Object TotalDurationMs -Descending
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 6 — PERFORMANCE IMPACT ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "6 - Performance Impact Analysis"

# ── Top Files ─────────────────────────────────────────────────────────────────
if ($perfReport.TopFiles) {
    Write-Host ""
    Write-Host "  +-- Top Files by Scan Time ------------------------------------------" -ForegroundColor White
    foreach ($f in $perfReport.TopFiles) {
        $durationMs = Get-DurationMs $f
        $impact = Get-ImpactLevel $durationMs
        $colour = Get-ImpactColour $impact
        $count = if (Get-Prop $f 'Count') { $f.Count } else { 1 }
        $filePath = if (Get-Prop $f 'Path') { $f.Path }
        elseif (Get-Prop $f 'File') { $f.File }
        else { '<unresolved file path>' }

        Write-Host ("  | {0,-6} {1,10}  x{2,-5}  {3}" -f $impact, (Format-Duration $durationMs), $count, (Truncate $filePath)) -ForegroundColor $colour

        Add-ImpactRow -Category "File" -Item $filePath `
            -Duration (Format-Duration $durationMs) -DurationMs $durationMs `
            -Count $count -Impact $impact
    }
    Write-Host "  +--------------------------------------------------------------------" -ForegroundColor White
}

# ── Top Processes ─────────────────────────────────────────────────────────────
if ($perfReport.TopProcesses) {
    Write-Host ""
    Write-Host "  +-- Top Processes by Scan Time --------------------------------------" -ForegroundColor White
    $skippedProcessEntries = 0
    foreach ($p in $perfReport.TopProcesses) {
        $durationMs = Get-DurationMs $p
        $impact = Get-ImpactLevel $durationMs
        $colour = Get-ImpactColour $impact
        $count = if (Get-Prop $p 'Count') { $p.Count } else { 1 }
        $procPath = if ((Get-Prop $p 'Process') -and $p.Process) { $p.Process }
        elseif ((Get-Prop $p 'ProcessPath') -and $p.ProcessPath) { $p.ProcessPath }
        else { $null }

        if (-not $procPath) {
            $skippedProcessEntries++
            continue
        }

        $procDisplay = $procPath
        Write-Host ("  | {0,-6} {1,10}  x{2,-5}  {3}" -f $impact, (Format-Duration $durationMs), $count, (Truncate $procDisplay)) -ForegroundColor $colour

        Add-ImpactRow -Category "Process" -Item $procDisplay `
            -Duration (Format-Duration $durationMs) -DurationMs $durationMs `
            -Count $count -Impact $impact
    }
    if ($skippedProcessEntries -gt 0) {
        Write-Info "Skipped $skippedProcessEntries process aggregate(s) with no resolved path"
    }
    Write-Host "  +--------------------------------------------------------------------" -ForegroundColor White
}

# ── Top Extensions ────────────────────────────────────────────────────────────
if ($perfReport.TopExtensions) {
    Write-Host ""
    Write-Host "  +-- Top Extensions by Scan Time -------------------------------------" -ForegroundColor White
    foreach ($e in $perfReport.TopExtensions) {
        $durationMs = Get-DurationMs $e
        $impact = Get-ImpactLevel $durationMs
        $colour = Get-ImpactColour $impact
        $count = if (Get-Prop $e 'Count') { $e.Count } else { 1 }
        $ext = if (Get-Prop $e 'Extension') { $e.Extension } else { '?' }
        $extDisplay = if ($ext -eq '?') { $ext } else { Format-ExtensionDisplay $ext }

        Write-Host ("  | {0,-6} {1,10}  x{2,-5}  {3}" -f $impact, (Format-Duration $durationMs), $count, $extDisplay) -ForegroundColor $colour

        Add-ImpactRow -Category "Extension" -Item $extDisplay `
            -Duration (Format-Duration $durationMs) -DurationMs $durationMs `
            -Count $count -Impact $impact
    }
    Write-Host "  +--------------------------------------------------------------------" -ForegroundColor White
}

if ($script:extensionHotspots -and $script:extensionHotspots.Count -gt 0) {
    Write-Host ""
    Write-Host "  +-- Extension Hotspots by Folder ------------------------------------" -ForegroundColor White
    foreach ($hotspot in ($script:extensionHotspots | Select-Object -First ([Math]::Min(10, $script:extensionHotspots.Count)))) {
        $impact = Get-ImpactColour $hotspot.EstimatedImpact
        $dominantFolder = if ($hotspot.DominantFolderPath) { $hotspot.DominantFolderPath } else { '<insufficient folder detail>' }
        Write-Host ("  | {0,-8} {1,10}  {2}" -f $hotspot.Extension, $hotspot.Duration, (Truncate $dominantFolder 45)) -ForegroundColor $impact

        if ($hotspot.DominantFolderPath) {
            $processLabel = if ($hotspot.DominantProcessPath) { $hotspot.DominantProcessPath } elseif ($hotspot.DominantProcessImage) { $hotspot.DominantProcessImage } else { 'n/a' }
            Write-Info ("      observed hotspot: {0}% of observed extension time | process: {1}" -f $hotspot.DominantFolderShare, $processLabel)
        }
        else {
            Write-Info ("      observed coverage: {0}% of total extension duration" -f $hotspot.ObservedCoveragePercent)
        }
    }
    Write-Host "  +--------------------------------------------------------------------" -ForegroundColor White
}

# ── Top Scans ─────────────────────────────────────────────────────────────────
if ($perfReport.TopScans) {
    Write-Host ""
    Write-Host "  +-- Top Individual Scans --------------------------------------------" -ForegroundColor White
    foreach ($s in $perfReport.TopScans) {
        $durationMs = Get-DurationMs $s
        $impact = Get-ImpactLevel $durationMs
        $colour = Get-ImpactColour $impact

        $scanType = if (Get-Prop $s 'ScanType') { $s.ScanType } else { 'n/a' }
        $scanPath = if (Get-Prop $s 'Path') { $s.Path }
        elseif (Get-Prop $s 'Process') { $s.Process }
        elseif (Get-Prop $s 'File') { $s.File }
        else { '<unresolved scan target>' }

        Write-Host ("  | {0,-6} {1,10}  [{2,-12}]  {3}" -f $impact, (Format-Duration $durationMs), $scanType, (Truncate $scanPath 45)) -ForegroundColor $colour

        Add-ImpactRow -Category "Scan" -Item "$scanType | $scanPath" `
            -Duration (Format-Duration $durationMs) -DurationMs $durationMs `
            -Count 1 -Impact $impact
    }
    Write-Host "  +--------------------------------------------------------------------" -ForegroundColor White
}

if ($script:topScanContexts -and $script:topScanContexts.Count -gt 0) {
    Write-Host ""
    Write-Host "  +-- High-Impact Scan Context ----------------------------------------" -ForegroundColor White
    foreach ($context in ($script:topScanContexts | Select-Object -First ([Math]::Min(8, $script:topScanContexts.Count)))) {
        $colour = Get-ImpactColour $context.EstimatedImpact
        Write-Host ("  | {0,-6} {1,10}  {2}" -f $context.EstimatedImpact, $context.Duration, (Truncate $context.TargetPath 45)) -ForegroundColor $colour
        $contextStart = if ($context.StartTimeLocal) { $context.StartTimeLocal } else { 'n/a' }
        $contextScanType = if ($context.ScanType) { $context.ScanType } else { 'n/a' }
        $contextReason = if ($context.Reason) { $context.Reason } else { 'n/a' }
        Write-Info ("      {0} | {1} | {2}" -f $contextStart, $contextScanType, $contextReason)
        if ($context.ProcessPath -or $context.ProcessImage) {
            $processDisplay = if ($context.ProcessPath) { $context.ProcessPath } else { $context.ProcessImage }
            Write-Info ("      process: {0}" -f $processDisplay)
        }
        if ($context.RelatedFolders -and @($context.RelatedFolders).Count -gt 0) {
            $relatedSummary = @($context.RelatedFolders | ForEach-Object { "{0} ({1})" -f $_.FolderPath, $_.Duration }) -join ' | '
            Write-Info ("      related folders: {0}" -f $relatedSummary)
        }
    }
    Write-Host "  +--------------------------------------------------------------------" -ForegroundColor White
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 7 — EXCLUSION SUGGESTIONS
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "7 - Exclusion Suggestions"

if ($ValidateLoad) {
    Write-Warn "Synthetic workload was enabled. Suggestions below may reflect the validation workload more than your normal usage."
    Write-Info "Synthetic workload mode: $SyntheticWorkloadMode"
}
if ($contextualExclusionsSupported) {
    Write-Info "Contextual exclusions are supported. The script will prefer narrower process-plus-folder recommendations when scan data allows."
}

# ── Extension risk tiers ─────────────────────────────────────────────────────
# BLOCKED: executable/scripting types — NEVER suggest global exclusion
$blockedExtensions = @(
    'exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'wsf', 'msi', 'scr',
    'com', 'hta', 'inf', 'reg', 'sys', 'cpl', 'lnk', 'pif', 'ocx', 'drv'
)

# CAUTION: common document/data types — only suggest as path-scoped, never global
# These can carry macros, embedded scripts, or are common malware delivery vehicles
$cautionExtensions = @(
    'doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptx', 'pptm',
    'pdf', 'rtf', 'html', 'htm', 'xml', 'svg', 'zip', 'rar', '7z', 'cab',
    'iso', 'img', 'vhd', 'vhdx', 'tar', 'gz', 'bz2', 'jar',
    'txt', 'csv', 'json', 'yaml', 'yml', 'ini', 'cfg', 'conf', 'log',
    'tmp', 'bak', 'dat', 'bin', 'db', 'cache'
)

# SAFE for global exclusion: development/build artefacts unlikely to carry threats
# (Still shown with advisory, but no path-scoping required)
$safeExtensions = @(
    'py', 'pyc', 'pyo', 'java', 'rb', 'go', 'rs', 'class',
    'cs', 'cpp', 'c', 'h', 'hpp', 'ts', 'tsx', 'jsx', 'vue', 'svelte',
    'css', 'scss', 'less', 'sass', 'md', 'rst', 'lock', 'sum',
    'o', 'obj', 'lib', 'a', 'so', 'pdb', 'idb', 'map',
    'wasm', 'whl', 'egg', 'gem', 'nupkg', 'crate'
)

$dangerousProcesses = @(
    'cmd.exe', 'powershell.exe', 'pwsh.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'msiexec.exe',
    'svchost.exe', 'explorer.exe', 'taskhostw.exe', 'conhost.exe',
    'dllhost.exe', 'wmic.exe', 'certutil.exe', 'bitsadmin.exe'
)
$validationOnlyProcesses = @(
    'defender-workload-helper.exe'
)
$dangerousPathPrefixes = @(
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot\Temp",
    "$env:TEMP",
    "$env:TMP"
)
$systemProcessPathPrefixes = @(
    "$env:SystemRoot",
    "$env:SystemRoot\System32",
    "$env:SystemRoot\SysWOW64",
    "$env:SystemRoot\WinSxS",
    "$env:SystemRoot\servicing"
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }

function Test-PathStartsWithAnyPrefix([string]$Path, [string[]]$Prefixes) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }

    foreach ($prefix in @($Prefixes | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        if ($Path.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            return $true
        }
    }

    return $false
}

function Test-SafeSuggestedFolderPath([string]$Path) {
    return (-not (Test-PathStartsWithAnyPrefix -Path $Path -Prefixes $dangerousPathPrefixes))
}

function Test-SafeSuggestedProcessPath([string]$Path) {
    return (-not (Test-PathStartsWithAnyPrefix -Path $Path -Prefixes $systemProcessPathPrefixes))
}

function Get-ExtensionRisk([string]$ext) {
    $e = $ext.TrimStart('.').ToLower()
    if ($blockedExtensions -contains $e) { return 'BLOCKED' }
    if ($cautionExtensions -contains $e) { return 'CAUTION' }
    if ($safeExtensions -contains $e)    { return 'SAFE' }
    return 'UNKNOWN'
}

# Lowercase existing exclusions for dedup
$existingPathsLower = $discoveredExcl.Paths      | ForEach-Object { $_.ToLower() }
$existingProcsLower = $discoveredExcl.Processes   | ForEach-Object { $_.ToLower() }
$existingExtsLower = $discoveredExcl.Extensions  | ForEach-Object { Normalize-Extension $_ } | Where-Object { $_ }
$totalTopScanMs = [double](@($perfReport.TopScans | ForEach-Object { Get-DurationMs $_ }) | Measure-Object -Sum).Sum
$totalTopProcessMs = [double](@($perfReport.TopProcesses | ForEach-Object { Get-DurationMs $_ }) | Measure-Object -Sum).Sum
$totalTopExtensionMs = [double](@($perfReport.TopExtensions | ForEach-Object { Get-DurationMs $_ }) | Measure-Object -Sum).Sum

# ── Contextual path suggestions (preferred when supported) ───────────────────
if ($contextualExclusionsSupported -and $perfReport.TopScans) {
    foreach ($s in $perfReport.TopScans) {
        $ms = Get-DurationMs $s
        if ($ms -lt $thresholdMedium) { continue }

        $scanPath = if (Get-Prop $s 'Path') { $s.Path }
        elseif (Get-Prop $s 'File') { $s.File }
        else { $null }

        $procPath = if ((Get-Prop $s 'ProcessPath') -and $s.ProcessPath) { $s.ProcessPath }
        elseif ((Get-Prop $s 'Process') -and $s.Process) { $s.Process }
        else { $null }

        if (-not $scanPath -or -not (Test-EligibleProcessPath $procPath)) { continue }

        $procName = Split-Path $procPath -Leaf -ErrorAction SilentlyContinue
        if (-not $procName) { $procName = $procPath }
        if ($dangerousProcesses -contains $procName.ToLower()) { continue }
        if (-not (Test-SafeSuggestedProcessPath $procPath)) { continue }

        $target = Split-Path $scanPath -Parent -ErrorAction SilentlyContinue
        if (-not $target) { continue }

        if (-not (Test-SafeSuggestedFolderPath $target)) { continue }
        if ($ValidateLoad -and $target -match 'DefenderWorkload_') { continue }
        if ($existingPathsLower -and ($existingPathsLower -contains $target.ToLower())) { continue }

        $contextKey = "{0}|{1}" -f $target.ToLower(), $procPath.ToLower()
        if (-not $script:suggestedContextualKeys.Add($contextKey)) { continue }
        if (-not $script:suggestedPaths.Add($target)) { continue }

        $contextualPath = Format-ContextualExclusionPath -path $target -pathType 'folder' -scanTrigger 'OnAccess' -processPath $procPath
        $processFallback = New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command (Format-ExclusionProcessCommand -processPath $procPath)
        $relativeShare = Get-RelativeSharePercent -durationMs $ms -totalMs $totalTopScanMs
        Add-Suggestion -Type "ContextualPath" -Value "$target <= $procName" `
            -Reason "On-access scans in this folder by $procName consumed $(Format-Duration $ms)" `
            -Impact (Get-ImpactLevel $ms) `
            -Command "Add-MpPreference -ExclusionPath '$($contextualPath -replace "'", "''")'" `
            -Risk 'CAUTION' `
            -Advisory "Start with this process-scoped folder exclusion before considering a broader process exclusion. Protect the excluded folder with restrictive ACLs and only trust exact process paths." `
            -Scope "MDAV on-access only for this folder and exact process path" `
            -Preference "Tier 2 - Contextual folder recommendation" `
            -TierOrder 2 `
            -Fallbacks @($processFallback) `
            -RelatedProcessPath $procPath `
            -RelativeSharePercent $relativeShare `
            -RelativeShareBasis "of observed top-scan duration in this run"
        [void]$script:coveredProcessPaths.Add($procPath)
    }
}

# ── File-path suggestions ────────────────────────────────────────────────────
if ($perfReport.TopFiles) {
    foreach ($f in $perfReport.TopFiles) {
        $ms = Get-DurationMs $f
        if ($ms -lt $thresholdMedium) { continue }

        $filePath = if (Get-Prop $f 'Path') { $f.Path }
        elseif (Get-Prop $f 'File') { $f.File }
        else { continue }

        $parentDir = Split-Path $filePath -Parent -ErrorAction SilentlyContinue
        $target = if (Test-Path $filePath -PathType Container -ErrorAction SilentlyContinue) { $filePath } else { $parentDir }
        if (-not $target) { continue }

        # Safety checks
        if (-not (Test-SafeSuggestedFolderPath $target)) { continue }

        # Skip workload-generated temp paths (they are cleaned up after recording)
        if ($ValidateLoad -and $target -match 'DefenderWorkload_') { continue }

        # Dedup
        if ($existingPathsLower -and ($existingPathsLower -contains $target.ToLower())) { continue }
        if ($existingPathsLower -and ($existingPathsLower -contains $filePath.ToLower())) { continue }
        if (-not $script:suggestedPaths.Add($target)) { continue }

        Add-Suggestion -Type "Path" -Value $target `
            -Reason "Files here consumed $(Format-Duration $ms) of scan time" `
            -Impact (Get-ImpactLevel $ms) `
            -Command "Add-MpPreference -ExclusionPath '$($target -replace "'", "''")'" `
            -Risk 'CAUTION' `
            -Advisory $(if ($contextualExclusionsSupported) { "Broad folder exclusion. This is one of the most impactful exclusion types and can affect real-time, scheduled, and on-demand scans. Contextual exclusions are supported on this device and are usually safer if one trusted process is responsible. Protect excluded folders with restrictive ACLs." } else { "Broad folder exclusion. This is one of the most impactful exclusion types and can affect real-time, scheduled, and on-demand scans. Protect excluded folders with restrictive ACLs." }) `
            -Scope "MDAV broad path exclusion across scan types"
    }
}

# ── Process suggestions ──────────────────────────────────────────────────────
if ($perfReport.TopProcesses) {
    $suggestedProcs = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase)

    foreach ($p in $perfReport.TopProcesses) {
        $ms = Get-DurationMs $p
        if ($ms -lt $thresholdMedium) { continue }

        $procPath = if ((Get-Prop $p 'Process') -and $p.Process) { $p.Process }
        elseif ((Get-Prop $p 'ProcessPath') -and $p.ProcessPath) { $p.ProcessPath }
        else { continue }

        if (-not (Test-EligibleProcessPath $procPath)) { continue }

        $procName = Split-Path $procPath -Leaf -ErrorAction SilentlyContinue
        if (-not $procName) { $procName = $procPath }

        if ($ValidateLoad -and ($validationOnlyProcesses -contains $procName.ToLowerInvariant())) { continue }
        if ($dangerousProcesses -contains $procName.ToLower()) { continue }
        if (-not (Test-SafeSuggestedProcessPath $procPath)) { continue }
        if ($existingProcsLower -and ($existingProcsLower -contains $procPath.ToLower())) { continue }
        if (-not $suggestedProcs.Add($procPath)) { continue }
        $relativeShare = Get-RelativeSharePercent -durationMs $ms -totalMs $totalTopProcessMs

        Add-Suggestion -Type "Process" -Value $procPath `
            -Reason "Process consumed $(Format-Duration $ms) of scan time" `
            -Impact (Get-ImpactLevel $ms) `
            -Command (Format-ExclusionProcessCommand -processPath $procPath) `
            -Risk 'CAUTION' `
            -Advisory "Fallback only after narrower contextual or file-pattern options have been ruled out. Files opened by this process are excluded from real-time scanning, but the process image itself is still scanned and scheduled or on-demand scans can still inspect those files." `
            -Scope "MDAV real-time opened-file exclusion for this process" `
            -Preference "Tier 4 - Exact process fallback recommendation" `
            -TierOrder 4 `
            -RelatedProcessPath $procPath `
            -RelativeSharePercent $relativeShare `
            -RelativeShareBasis "of observed top-process scan duration in this run"
    }
}

# ── Extension suggestions ────────────────────────────────────────────────────
if ($perfReport.TopExtensions) {
    foreach ($e in $perfReport.TopExtensions) {
        $ms = Get-DurationMs $e
        if ($ms -lt $thresholdMedium) { continue }

        $ext = Get-Prop $e 'Extension'
        if (-not $ext) { continue }
        $ext = $ext.TrimStart('.').ToLower()
        $extensionDisplay = Format-ExtensionDisplay $ext
        $hotspot = @($script:extensionHotspots | Where-Object { $_.RawExtension -eq $ext } | Select-Object -First 1)

        $risk = Get-ExtensionRisk $ext

        # Never suggest blocked (executable/script) extensions
        if ($risk -eq 'BLOCKED') { continue }
        if ($existingExtsLower -and ($existingExtsLower -contains $ext)) { continue }

        $recommendedFolder = $null
        $safeObservedFolders = @()
        $allObservedFolders = @()
        $hotspotIsSyntheticOnly = $false
        $allObservedPatternExamples = @()
        if ($hotspot.Count -gt 0 -and $hotspot[0].HotspotFolders) {
            $allObservedFolders = @($hotspot[0].HotspotFolders)
            $hotspotIsSyntheticOnly = (@($allObservedFolders).Count -gt 0) -and (@($allObservedFolders | Where-Object { -not $_.SyntheticOnly }).Count -eq 0)
            $allObservedPatternExamples = @($allObservedFolders | Select-Object -First 3 | ForEach-Object { Join-Path $_.FolderPath "*$extensionDisplay" })

            $safeObservedFolders = @(
                $allObservedFolders |
                Where-Object {
                    (Test-SafeSuggestedFolderPath $_.FolderPath) -and
                    -not ($ValidateLoad -and $_.FolderPath -match 'DefenderWorkload_')
                } |
                Select-Object -First 3
            )

            if ($safeObservedFolders.Count -gt 0) {
                $recommendedFolder = $safeObservedFolders[0]
            }
        }

        # Build risk-appropriate suggestion
        $advisory = ''
        $command = ''
        $suggestionType = 'Extension'
        $suggestionValue = $extensionDisplay
        $reason = "Extension scans consumed $(Format-Duration $ms)"
        $scope = "MDAV broad extension exclusion across real-time, scheduled, and on-demand scans"
        $safeObservedPatternExamples = @($safeObservedFolders | ForEach-Object { Join-Path $_.FolderPath "*$extensionDisplay" })
        $preference = ''
        $tierOrder = 90
        $fallbacks = @()
        $contextualProcessPath = $null
        $relatedProcessPath = $null
        $relativeShare = Get-RelativeSharePercent -durationMs $ms -totalMs $totalTopExtensionMs
        $concentrationPercent = $null
        $concentrationBasis = ''

        if ($recommendedFolder) {
            $folderPath = $recommendedFolder.FolderPath
            $patternPath = Join-Path $folderPath "*$extensionDisplay"
            $shareText = if ($recommendedFolder.ShareOfObservedDuration) { "$($recommendedFolder.ShareOfObservedDuration)% of observed hotspot duration" } else { 'the heaviest observed hotspot activity' }
            if ($recommendedFolder.TopProcessPath -and (Test-EligibleProcessPath $recommendedFolder.TopProcessPath) -and (Test-SafeSuggestedProcessPath $recommendedFolder.TopProcessPath)) {
                $topProcessName = Split-Path $recommendedFolder.TopProcessPath -Leaf -ErrorAction SilentlyContinue
                if ($topProcessName -and ($dangerousProcesses -notcontains $topProcessName.ToLowerInvariant())) {
                    $contextualProcessPath = $recommendedFolder.TopProcessPath
                }
            }
            $processText = if ($contextualProcessPath) { $contextualProcessPath } elseif ($recommendedFolder.TopProcessPath) { $recommendedFolder.TopProcessPath } elseif ($recommendedFolder.TopProcessImage) { $recommendedFolder.TopProcessImage } else { 'n/a' }
            $suggestionType = 'ExtensionHotspot'
            $suggestionValue = "$extensionDisplay @ $folderPath"
            $reason = "The heaviest observed $extensionDisplay scans clustered in this folder ($shareText)"
            $scope = "Prefer file-pattern scoping for this extension hotspot; broader global extension exclusions remain a fallback"
            $relatedProcessPath = $contextualProcessPath
            $concentrationPercent = if ($recommendedFolder.ShareOfObservedDuration) { [double]$recommendedFolder.ShareOfObservedDuration } else { $null }
            $concentrationBasis = 'of observed folder-attributed duration for this extension'
            $processFallbackCommand = Format-ExclusionProcessCommand -processPath $contextualProcessPath
            $contextualFolderFallbackCommand = if ($contextualProcessPath) {
                "Add-MpPreference -ExclusionPath '$((Format-ContextualExclusionPath -path $folderPath -pathType 'folder' -scanTrigger 'OnAccess' -processPath $contextualProcessPath) -replace "'", "''")'"
            } else { $null }
            $patternFallbackCommand = "Add-MpPreference -ExclusionPath '$($patternPath -replace "'", "''")'"

            if ($contextualExclusionsSupported -and $contextualProcessPath) {
                $contextualPattern = Format-ContextualExclusionPath -path $patternPath -pathType 'file' -scanTrigger 'OnAccess' -processPath $contextualProcessPath
                $command = "Add-MpPreference -ExclusionPath '$($contextualPattern -replace "'", "''")'"
                $scope = "MDAV on-access only for $extensionDisplay files in this folder and exact process path"
                $preference = 'Tier 1 - Preferred contextual file-pattern recommendation'
                $tierOrder = 1
                $fallbacks = @(
                    New-RankedFallback -TierOrder 2 -Label 'Contextual folder fallback' -Command $contextualFolderFallbackCommand
                    New-RankedFallback -TierOrder 3 -Label 'File-pattern path fallback' -Command $patternFallbackCommand
                    New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command $processFallbackCommand
                )
                [void]$script:coveredProcessPaths.Add($contextualProcessPath)
            }
            else {
                $command = $patternFallbackCommand
                $scope = "MDAV file-pattern exclusion for $extensionDisplay files in this folder across scan types"
                $preference = 'Tier 3 - Preferred file-pattern recommendation'
                $tierOrder = 3
                $fallbacks = @(
                    New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command $processFallbackCommand
                )
            }
            if ($risk -ne 'SAFE') {
                $command += "`n     # Global fallback only if truly necessary: Add-MpPreference -ExclusionExtension '$extensionDisplay'"
                $fallbacks += New-RankedFallback -TierOrder 6 -Label 'Global extension fallback only if truly necessary' -Command "Add-MpPreference -ExclusionExtension '$extensionDisplay'"
            }

            $advisory = "Start with the narrowest folder-scoped option here. Dominant observed process: $processText."
            $advisory += " Protect that folder with restrictive ACLs."
        }
        elseif ($safeObservedPatternExamples.Count -gt 0) {
            $suggestionType = 'ExtensionHotspot'
            $suggestionValue = "$extensionDisplay @ multiple folders"
            $reason = "Observed $extensionDisplay scans clustered in multiple safe folders"
            $scope = "MDAV file-pattern exclusions for $extensionDisplay files in the observed folders across scan types"
            $patternCommands = @($safeObservedPatternExamples | ForEach-Object {
                    "Add-MpPreference -ExclusionPath '$($_ -replace "'", "''")'"
                })
            $command = ($patternCommands -join "`n")
            $preference = 'Tier 3 - Preferred file-pattern recommendation'
            $tierOrder = 3
            $concentrationPercent = if ($hotspot[0].DominantFolderShare) { [double]$hotspot[0].DominantFolderShare } else { $null }
            $concentrationBasis = 'of observed folder-attributed duration for this extension'
            if ($risk -ne 'SAFE') {
                $command += "`n     # Global fallback only if truly necessary: Add-MpPreference -ExclusionExtension '$extensionDisplay'"
                $fallbacks += New-RankedFallback -TierOrder 6 -Label 'Global extension fallback only if truly necessary' -Command "Add-MpPreference -ExclusionExtension '$extensionDisplay'"
            }
            $advisory = "Prefer these concrete file-pattern exclusions over a global $extensionDisplay exclusion."
        }
        elseif ($hotspotIsSyntheticOnly) {
            $suppressedBecause = "Validation-only evidence: observed folders are synthetic workload paths and the dominant process is a Windows/system scripting engine, so this was not promoted into a live exclusion recommendation."
            $evidenceText = if ($hotspot[0].DominantProcessPath) { "Dominant process: $($hotspot[0].DominantProcessPath)" } else { "Dominant folder: $($hotspot[0].DominantFolderPath)" }
            $suppressedCommands = @()
            $suppressedType = 'ValidationOnlyPattern'
            $suppressedScope = "Validation-only file-pattern candidates for $extensionDisplay"
            $suppressedPreference = ''
            if ($contextualExclusionsSupported -and $hotspot[0].DominantProcessPath -and (Test-EligibleProcessPath $hotspot[0].DominantProcessPath) -and (Test-SafeSuggestedProcessPath $hotspot[0].DominantProcessPath)) {
                $suppressedCommands = @(
                    $allObservedFolders |
                    Select-Object -First 3 |
                    ForEach-Object {
                        $contextualSyntheticPattern = Format-ContextualExclusionPath -path (Join-Path $_.FolderPath "*$extensionDisplay") -pathType 'file' -scanTrigger 'OnAccess' -processPath $hotspot[0].DominantProcessPath
                        "Add-MpPreference -ExclusionPath '$($contextualSyntheticPattern -replace "'", "''")'"
                    }
                )
                $suppressedType = 'ValidationOnlyContextualPattern'
                $suppressedScope = "Validation-only MDAV on-access contextual file-pattern candidates for $extensionDisplay and the exact helper process"
                $suppressedPreference = 'Tier 1 - Validation-only preferred contextual file-pattern recommendation'
                $suppressedBecause = "Validation-only evidence: this contextual file-pattern candidate came from the synthetic workload, so it was captured for proof but not promoted into a live recommendation."
            }
            else {
                $suppressedCommands = @($allObservedPatternExamples | ForEach-Object {
                        "Add-MpPreference -ExclusionPath '$($_ -replace "'", "''")'"
                    })
            }
            Add-SuppressedSuggestion -Type $suppressedType `
                -Value "$extensionDisplay @ synthetic workload folders" `
                -Impact (Get-ImpactLevel $ms) `
                -Reason "Observed $extensionDisplay scans clustered in synthetic validation folders" `
                -SuppressedBecause $suppressedBecause `
                -Commands $suppressedCommands `
                -Scope $suppressedScope `
                -Evidence $evidenceText `
                -Preference $suppressedPreference `
                -RelativeSharePercent $relativeShare `
                -RelativeShareBasis "of observed extension scan duration in this run" `
                -ConcentrationPercent $(if ($hotspot[0].DominantFolderShare) { [double]$hotspot[0].DominantFolderShare } else { $null }) `
                -ConcentrationBasis "of observed folder-attributed duration for this extension"
            continue
        }

        switch ($risk) {
            'CAUTION' {
                if (-not $recommendedFolder -and $safeObservedPatternExamples.Count -eq 0) {
                    continue
                }
            }
            'UNKNOWN' {
                if (-not $recommendedFolder -and $safeObservedPatternExamples.Count -eq 0) {
                    continue
                }
            }
            default {
                if (-not $recommendedFolder -and $safeObservedPatternExamples.Count -eq 0) {
                    continue
                }
            }
        }

        if ([string]::IsNullOrWhiteSpace($command)) {
            continue
        }

        Add-Suggestion -Type $suggestionType -Value $suggestionValue `
            -Reason $reason `
            -Impact (Get-ImpactLevel $ms) `
            -Command $command -Risk $risk -Advisory $advisory `
            -Scope $scope `
            -Preference $preference `
            -TierOrder $tierOrder `
            -Fallbacks $fallbacks `
            -RelatedProcessPath $relatedProcessPath `
            -RelativeSharePercent $relativeShare `
            -RelativeShareBasis "of observed extension scan duration in this run" `
            -ConcentrationPercent $concentrationPercent `
            -ConcentrationBasis $concentrationBasis
    }
}

if ($script:suggestions.Count -gt 0) {
    foreach ($suggestion in @($script:suggestions)) {
        if ($suggestion.Type -eq 'Process') { continue }
        if ([string]::IsNullOrWhiteSpace([string]$suggestion.RelatedProcessPath)) { continue }

        $processFallback = New-RankedFallback -TierOrder 4 -Label 'Exact process fallback' -Command (Format-ExclusionProcessCommand -processPath $suggestion.RelatedProcessPath)
        if ([string]::IsNullOrWhiteSpace($processFallback)) { continue }

        $existingFallbacks = @($suggestion.Fallbacks)
        if ($existingFallbacks -notcontains $processFallback) {
            $suggestion.Fallbacks = @($existingFallbacks + $processFallback | Select-Object -Unique)
        }
    }

    $retainedSuggestions = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($suggestion in @($script:suggestions)) {
        if ($suggestion.Type -eq 'Process' -and
            -not [string]::IsNullOrWhiteSpace([string]$suggestion.RelatedProcessPath) -and
            $script:coveredProcessPaths.Contains([string]$suggestion.RelatedProcessPath)) {
            continue
        }

        $retainedSuggestions.Add($suggestion)
    }

    $script:suggestions = $retainedSuggestions
}

# ── Display suggestions ──────────────────────────────────────────────────────
if ($script:suggestions.Count -eq 0) {
    if ($script:suppressedSuggestions.Count -gt 0) {
        Write-Info "No live exclusion recommendations were promoted from this run."
        Write-Info "Validation-only exclusion candidates were captured for review below."
    }
    else {
        Write-OK "No significant exclusion candidates found -- Defender is performing well."
    }
}
else {
    $sorted = $script:suggestions | Sort-Object `
        @{ Expression = { if ($_.TierOrder) { [int]$_.TierOrder } else { 99 } } }, `
        @{ Expression = { Get-ImpactOrder $_.Impact } }, `
        @{ Expression = { if ($null -ne $_.RelativeSharePercent) { -1 * [double]$_.RelativeSharePercent } else { 0 } } }, `
        @{ Expression = { if ($null -ne $_.ConcentrationPercent) { -1 * [double]$_.ConcentrationPercent } else { 0 } } }, `
        @{ Expression = { [string]$_.Value } }

    Write-Warn "$($script:suggestions.Count) exclusion suggestion(s) to improve performance:"
    Write-Host ""

    $idx = 0
    foreach ($s in $sorted) {
        $idx++
        $colour = Get-ImpactColour $s.Impact
        $riskTag = if ($s.Risk -and $s.Risk -ne 'SAFE') { " [$($s.Risk)]" } else { '' }
        Write-Host "  $idx. [$($s.Impact)]$riskTag $($s.Type): $($s.Value)" -ForegroundColor $colour
        Write-Host "     Reason : $($s.Reason)" -ForegroundColor Gray
        if ($s.Scope) {
            Write-Host "     Scope  : $($s.Scope)" -ForegroundColor DarkGray
        }
        if ($s.Preference) {
            Write-Host "     Pref   : $($s.Preference)" -ForegroundColor Cyan
        }
        if ($null -ne $s.RelativeSharePercent) {
            Write-Host "     Share  : $($s.RelativeSharePercent)% $($s.RelativeShareBasis)" -ForegroundColor DarkGray
        }
        if ($null -ne $s.ConcentrationPercent) {
            Write-Host "     Focus  : $($s.ConcentrationPercent)% $($s.ConcentrationBasis)" -ForegroundColor DarkGray
        }
        if ($s.Advisory) {
            Write-Host "     >> $($s.Advisory)" -ForegroundColor Yellow
        }
        if (@($s.Fallbacks).Count -gt 0) {
            Write-Host "     Fallback: $($s.Fallbacks[0])" -ForegroundColor DarkYellow
            foreach ($fallback in (@($s.Fallbacks) | Select-Object -Skip 1)) {
                Write-Host "               $fallback" -ForegroundColor DarkYellow
            }
        }
        Write-Host "     Run    : $($s.Command)" -ForegroundColor DarkCyan
        Write-Host ""
    }

    Write-Host "  +============================================================+" -ForegroundColor Yellow
    Write-Host "  |  WARNING: Review each suggestion before applying.          |" -ForegroundColor Yellow
    Write-Host "  |  Excluding items reduces Defender security coverage.        |" -ForegroundColor Yellow
    Write-Host "  |  Never exclude system paths or scripting engines.           |" -ForegroundColor Yellow
    Write-Host "  +============================================================+" -ForegroundColor Yellow
}

if ($script:suppressedSuggestions.Count -gt 0) {
    $sortedSuppressed = $script:suppressedSuggestions | Sort-Object {
        switch ($_.Impact) { 'HIGH' { 0 } 'MEDIUM' { 1 } 'LOW' { 2 } default { 3 } }
    }

    Write-Host ""
    Write-Warn "$($script:suppressedSuggestions.Count) validation-only candidate(s) were intentionally suppressed from live recommendations:"
    Write-Host ""

    $idx = 0
    foreach ($s in $sortedSuppressed) {
        $idx++
        $colour = Get-ImpactColour $s.Impact
        Write-Host "  $idx. [$($s.Impact)] $($s.Type): $($s.Value)" -ForegroundColor $colour
        Write-Host "     Reason    : $($s.Reason)" -ForegroundColor Gray
        if ($s.Scope) {
            Write-Host "     Scope     : $($s.Scope)" -ForegroundColor DarkGray
        }
        if ($s.Preference) {
            Write-Host "     Pref      : $($s.Preference)" -ForegroundColor Cyan
        }
        if ($null -ne $s.RelativeSharePercent) {
            Write-Host "     Share     : $($s.RelativeSharePercent)% $($s.RelativeShareBasis)" -ForegroundColor DarkGray
        }
        if ($null -ne $s.ConcentrationPercent) {
            Write-Host "     Focus     : $($s.ConcentrationPercent)% $($s.ConcentrationBasis)" -ForegroundColor DarkGray
        }
        if ($s.Evidence) {
            Write-Host "     Evidence  : $($s.Evidence)" -ForegroundColor DarkGray
        }
        if ($s.SuppressedBecause) {
            Write-Host "     Suppressed: $($s.SuppressedBecause)" -ForegroundColor Yellow
        }
        if (@($s.Fallbacks).Count -gt 0) {
            Write-Host "     Fallbacks : $($s.Fallbacks[0])" -ForegroundColor DarkYellow
            foreach ($fallback in (@($s.Fallbacks) | Select-Object -Skip 1)) {
                Write-Host "                 $fallback" -ForegroundColor DarkYellow
            }
        }

        $commands = @($s.Commands)
        if ($commands.Count -gt 0) {
            Write-Host "     Candidate : $($commands[0])" -ForegroundColor DarkCyan
            foreach ($extraCommand in ($commands | Select-Object -Skip 1)) {
                Write-Host "                 $extraCommand" -ForegroundColor DarkCyan
            }
        }
        else {
            Write-Host "     Candidate : <none recorded>" -ForegroundColor DarkGray
        }

        Write-Host ""
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 8 — PERFORMANCE IMPACT SUMMARY TABLE
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "8 - Performance Impact Summary Table"

$highCount = @($script:impactTableRows | Where-Object { $_.Impact -eq 'HIGH' }).Count
$mediumCount = @($script:impactTableRows | Where-Object { $_.Impact -eq 'MEDIUM' }).Count
$lowCount = @($script:impactTableRows | Where-Object { $_.Impact -eq 'LOW' }).Count

if ($script:impactTableRows.Count -gt 0) {
    Write-Host ""
    Write-Host "     Impact Summary: " -NoNewline -ForegroundColor White
    Write-Host "$highCount HIGH " -NoNewline -ForegroundColor Red
    Write-Host "$mediumCount MEDIUM " -NoNewline -ForegroundColor Yellow
    Write-Host "$lowCount LOW" -ForegroundColor Green
    Write-Host ""

    $fmt = "  {0,-10} {1,-7} {2,12} {3,6}   {4}"
    Write-Host ($fmt -f "CATEGORY", "IMPACT", "DURATION", "COUNT", "ITEM") -ForegroundColor White
    Write-Host ("  " + ("-" * 78)) -ForegroundColor DarkGray

    foreach ($row in ($script:impactTableRows | Sort-Object DurationMs -Descending)) {
        $colour = Get-ImpactColour $row.Impact
        Write-Host ($fmt -f $row.Category, $row.Impact, $row.Duration, $row.Count, (Truncate $row.Item 40)) -ForegroundColor $colour
    }
    Write-Host ""
}
else {
    Write-OK "No performance impact data to display (recording may have been too short)."
}

# ═══════════════════════════════════════════════════════════════════════════════
#  STEP 9 — SAVE FINAL REPORTS (JSON + HTML)
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "9 - Generating Final Reports"

# Append analysis results to JSON
$jsonData['ExclusionSuggestions'] = @($script:suggestions | ForEach-Object {
        [ordered]@{
            Type = $_.Type; Value = $_.Value; Reason = $_.Reason
            Impact = $_.Impact; Command = $_.Command
            Risk = $_.Risk; Advisory = $_.Advisory; Scope = $_.Scope; Preference = $_.Preference
            TierOrder = $_.TierOrder; Fallbacks = @($_.Fallbacks)
            RelativeSharePercent = $_.RelativeSharePercent; RelativeShareBasis = $_.RelativeShareBasis
            ConcentrationPercent = $_.ConcentrationPercent; ConcentrationBasis = $_.ConcentrationBasis
        }
    })
$jsonData['SuppressedCandidates'] = @($script:suppressedSuggestions | ForEach-Object {
        [ordered]@{
            Type              = $_.Type
            Value             = $_.Value
            Impact            = $_.Impact
            Reason            = $_.Reason
            SuppressedBecause = $_.SuppressedBecause
            Commands          = @($_.Commands)
            Scope             = $_.Scope
            Evidence          = $_.Evidence
            Preference        = $_.Preference
            Fallbacks         = @($_.Fallbacks)
            RelativeSharePercent = $_.RelativeSharePercent
            RelativeShareBasis   = $_.RelativeShareBasis
            ConcentrationPercent = $_.ConcentrationPercent
            ConcentrationBasis   = $_.ConcentrationBasis
        }
    })
$jsonData['ExtensionHotspots'] = @($script:extensionHotspots)
$jsonData['TopScanContexts'] = @($script:topScanContexts)
$jsonData['PerformanceImpactTable'] = @($script:impactTableRows | ForEach-Object {
        [ordered]@{
            Category = $_.Category; Item = $_.Item; Duration = $_.Duration
            DurationMs = $_.DurationMs; Count = $_.Count; Impact = $_.Impact
        }
    })

$jsonData | ConvertTo-Json -Depth 15 | Out-File -FilePath $jsonFile -Encoding UTF8 -Force
Write-OK "Updated JSON report: $jsonFile"

if ($AIMode) {
    Write-Section "5b - Generating AI Handoff Artifacts"

    $aiExportData = [ordered]@{
        HandoffVersion      = 1
        Purpose             = 'Validate whether Microsoft Defender Antivirus exclusion suggestions from this run are appropriate, narrow enough, supported by real workload evidence, and aligned to MDAV performance tuning rather than broader MDE policy problems.'
        OperationalContext  = [ordered]@{
            PreferredUsage              = 'Run during a real workload or performance issue, especially on servers where exclusions should be avoided unless evidence clearly supports a narrow change.'
            NoActionIsValid             = $true
            ServerBias                  = 'Bias toward no exclusion on servers unless a narrow, defensible recommendation is strongly supported by evidence.'
            SyntheticWorkloadPresent    = [bool]$ValidateLoad
            RealWorkloadEvidencePreferred = $true
        }
        ReferenceGuidance   = [ordered]@{
            UseExclusionGuidanceSources = $true
            MicrosoftDocsPriority       = 'Use Microsoft documentation in ExclusionGuidance.Sources for syntax, platform behavior, scope, and feature support.'
            CloudbrothersPriority       = 'Use the Cloudbrothers reference in ExclusionGuidance.Sources for practical exclusion-scope guidance, caution principles, and real-world Defender tuning judgment.'
            ConflictHandling            = 'If the run evidence conflicts with the reference guidance, call out the conflict explicitly instead of smoothing it over.'
        }
        ReviewRules         = @(
            'Treat exclusions as a last resort.'
            'A valid outcome is that no Microsoft Defender Antivirus exclusion should be recommended from this run.'
            'Prefer evidence gathered during a real workload issue over synthetic validation activity.'
            'If the run contains synthetic workload evidence, do not promote synthetic-only candidates into live exclusions.'
            'On servers, bias toward avoiding exclusions unless the evidence strongly supports a narrow and defensible recommendation.'
            'Prefer exact third-party process paths over broader controls when the issue is process-specific.'
            'Prefer contextual exclusions when supported and the exact process path is trusted.'
            'When one extension in one safe folder is the issue, prefer file-pattern path exclusions such as C:\App\Cache\*.cache over excluding the whole folder.'
            'Use full folder exclusions only when multiple relevant file types in one safe folder justify that broader scope.'
            'Treat global extension exclusions as last-resort fallbacks only.'
            'Do not recommend process or contextual exclusions for Windows or other system binaries.'
            'Do not recommend exclusions based solely on Windows/system processes, system folders, temporary validation paths, or synthetic-only evidence.'
            'If the issue is really automated investigation, ASR, CFA, or indicator related, say MDAV exclusions are the wrong control.'
            'Protect excluded folders with restrictive ACLs and avoid local admin merge in managed environments.'
        )
        ReportMetadata      = $jsonData.ReportMetadata
        ExclusionValidation = $jsonData.ExclusionValidationDetails
        ExclusionDiscovery  = $jsonData.ExclusionDiscovery
        ExclusionGuidance   = $jsonData.ExclusionGuidance
        CABIntelligence     = [ordered]@{
            EffectiveConfig      = Get-Prop $cabIntel 'EffectiveConfig'
            PlatformVersions     = Get-Prop $cabIntel 'PlatformVersions'
            HealthState          = Get-Prop $cabIntel 'HealthState'
            NetworkProtection    = Get-Prop $cabIntel 'NetworkProtection'
            DeviceControl        = Get-Prop $cabIntel 'DeviceControl'
            MPLogHighlights      = Get-Prop $cabIntel 'MPLogHighlights'
            SignatureUpdateStub  = Get-Prop $cabIntel 'SignatureUpdateStub'
            ScanSkips            = Get-Prop $cabIntel 'ScanSkips'
            RecentDetections     = Get-Prop $cabIntel 'RecentDetections'
        }
        ExclusionSuggestions = $jsonData.ExclusionSuggestions
        SuppressedCandidates = $jsonData['SuppressedCandidates']
        TopScanContexts      = @($script:topScanContexts | Select-Object -First 12)
        ExtensionHotspots    = @($script:extensionHotspots | Select-Object -First 12)
        PerformanceImpact    = @($script:impactTableRows | Sort-Object DurationMs -Descending | Select-Object -First 25 | ForEach-Object {
                [ordered]@{
                    Category   = $_.Category
                    Item       = $_.Item
                    Duration   = $_.Duration
                    DurationMs = $_.DurationMs
                    Count      = $_.Count
                    Impact     = $_.Impact
                }
            })
    }

    $aiPrompt = @"
# Defender AI Review Prompt

Use the attached AI export JSON as the source of truth for this run.

Primary objective:
Validate whether each Microsoft Defender Antivirus exclusion suggestion is appropriate for the actual purpose of this tool: diagnosing Defender performance hotspots during a real workload issue and proposing the narrowest safe MDAV-compatible fix only when justified.

Review rules:
1. Treat exclusions as a last resort.
2. A valid conclusion is that no Microsoft Defender Antivirus exclusion should be recommended from this run.
3. Reject suggestions that are broader than the evidence supports.
4. Prefer exact third-party process paths, then contextual exclusions, then file-pattern path exclusions such as `C:\App\Cache\*.cache`, then full folder exclusions, and only then global extension exclusions as an explicit last resort.
5. Do not recommend process or contextual exclusions for Windows/system binaries or Windows/system folders.
6. If synthetic workload data is present, treat suppressed synthetic-only candidates as validation artifacts, not live recommendations.
7. On servers, bias toward avoiding exclusions unless the evidence strongly supports a narrow and defensible recommendation.
8. If the underlying issue is better solved by Defender for Endpoint automation exclusions, indicators, ASR configuration, CFA configuration, or some non-MDAV control, say so explicitly.
9. For every accepted MDAV exclusion, explain why the scope is narrow enough and cite the exact supporting evidence from the export.
10. If the export only supports investigation and not an exclusion, say that explicitly.

Reference guidance:
11. Use `ExclusionGuidance.Sources` from the export as review references.
12. Prioritize Microsoft documentation for syntax, platform behavior, and feature scope.
13. Use the Cloudbrothers reference for practical exclusion-scope judgment and caution principles.
14. If the export evidence conflicts with the guidance sources, say so explicitly.

Return format:
## Executive Verdict
State one of:
- No MDAV exclusion recommended
- MDAV exclusion may be justified
- Better solved by non-MDAV control

## Findings
## Validated Exclusions
## Rejected Or Unsafe Suggestions
## Better Non-MDAV Controls
## Open Questions

For each accepted or rejected suggestion, include:
- verdict
- confidence (`high`, `medium`, or `low`)
- evidence cited from the export
- whether the evidence came from real workload behavior, synthetic validation activity, or both

When proposing PowerShell:
- Use only concrete paths present in the export.
- Prefer `Add-MpPreference -ExclusionPath 'C:\Folder\*.ext'` over excluding the whole folder when the evidence is extension-specific.
- Use exact process paths only.
- Do not invent commands when the correct answer is to make no exclusion change.

Reference sources from the export:
$((@($jsonData.ExclusionGuidance.Sources) -join "`n"))

Attached export file:
$aiExportFile

Main report JSON:
$jsonFile

HTML report:
$htmlFile
"@

    try {
        $aiExportData | ConvertTo-Json -Depth 15 | Out-File -FilePath $aiExportFile -Encoding UTF8 -Force
        Write-OK "AI export saved   : $aiExportFile"
    }
    catch {
        Write-Warn "Could not save AI export: $_"
    }

    try {
        $aiPrompt | Out-File -FilePath $aiPromptFile -Encoding UTF8 -Force
        Write-OK "AI prompt saved   : $aiPromptFile"
    }
    catch {
        Write-Warn "Could not save AI prompt: $_"
    }
}

# ── Build HTML ────────────────────────────────────────────────────────────────
$htmlImpactRows = ($script:impactTableRows | Sort-Object DurationMs -Descending | ForEach-Object {
        $c = switch ($_.Impact) { 'HIGH' { '#ef4444' } 'MEDIUM' { '#f59e0b' } default { '#22c55e' } }
        $safeItem = HtmlEncode (Truncate $_.Item 70)
        $fullItem = HtmlEncode $_.Item
        "<tr><td>$(HtmlEncode $_.Category)</td><td style='color:$c;font-weight:bold'>$($_.Impact)</td><td>$($_.Duration)</td><td>$($_.Count)</td><td title='$fullItem'>$safeItem</td></tr>"
    }) -join "`n"

$htmlSuggestionRows = if ($script:suggestions.Count -gt 0) {
    ($script:suggestions | Sort-Object `
        @{ Expression = { if ($_.TierOrder) { [int]$_.TierOrder } else { 99 } } }, `
        @{ Expression = { Get-ImpactOrder $_.Impact } }, `
        @{ Expression = { if ($null -ne $_.RelativeSharePercent) { -1 * [double]$_.RelativeSharePercent } else { 0 } } }, `
        @{ Expression = { if ($null -ne $_.ConcentrationPercent) { -1 * [double]$_.ConcentrationPercent } else { 0 } } }, `
        @{ Expression = { [string]$_.Value } } | ForEach-Object {
        $c = switch ($_.Impact) { 'HIGH' { '#ef4444' } 'MEDIUM' { '#f59e0b' } default { '#22c55e' } }
        $rc = switch ($_.Risk) { 'CAUTION' { '#f59e0b' } 'UNKNOWN' { '#94a3b8' } default { '#22c55e' } }
        $scopeHtml = if ($_.Scope) { "<br><small style='color:#94a3b8'>$(HtmlEncode $_.Scope)</small>" } else { '' }
        $preferenceHtml = if ($_.Preference) { "<br><small style='color:#38bdf8;font-weight:bold'>$(HtmlEncode $_.Preference)</small>" } else { '' }
        $shareHtml = if ($null -ne $_.RelativeSharePercent) { "<br><small style='color:#cbd5e1'>Share: $(HtmlEncode ([string]$_.RelativeSharePercent))% $(HtmlEncode $_.RelativeShareBasis)</small>" } else { '' }
        $focusHtml = if ($null -ne $_.ConcentrationPercent) { "<br><small style='color:#cbd5e1'>Focus: $(HtmlEncode ([string]$_.ConcentrationPercent))% $(HtmlEncode $_.ConcentrationBasis)</small>" } else { '' }
        $advisoryHtml = if ($_.Advisory) { "<br><small style='color:#fbbf24'>$(HtmlEncode $_.Advisory)</small>" } else { '' }
        $fallbackHtml = if (@($_.Fallbacks).Count -gt 0) {
            "<br><small style='color:#facc15'>Fallbacks:</small><br>" + ((@($_.Fallbacks) | ForEach-Object { "<small style='color:#fde68a'>$(HtmlEncode $_)</small>" }) -join '<br>')
        } else { '' }
        "<tr><td style='color:$c;font-weight:bold'>$($_.Impact)</td><td style='color:$rc'>$(HtmlEncode $_.Risk)</td><td>$(HtmlEncode $_.Type)</td><td>$(HtmlEncode $_.Value)</td><td>$(HtmlEncode $_.Reason)$scopeHtml$preferenceHtml$shareHtml$focusHtml$advisoryHtml$fallbackHtml</td><td><code>$(HtmlEncode $_.Command)</code></td></tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='6' style='color:#22c55e;text-align:center;padding:20px'>No exclusion suggestions needed</td></tr>"
}

$htmlSuppressedRows = if ($script:suppressedSuggestions.Count -gt 0) {
    ($script:suppressedSuggestions | Sort-Object { switch ($_.Impact) { 'HIGH' { 0 } 'MEDIUM' { 1 } 'LOW' { 2 } default { 3 } } } | ForEach-Object {
        $c = switch ($_.Impact) { 'HIGH' { '#ef4444' } 'MEDIUM' { '#f59e0b' } default { '#22c55e' } }
        $scopeHtml = if ($_.Scope) { "<br><small style='color:#94a3b8'>$(HtmlEncode $_.Scope)</small>" } else { '' }
        $preferenceHtml = if ($_.Preference) { "<br><small style='color:#38bdf8;font-weight:bold'>$(HtmlEncode $_.Preference)</small>" } else { '' }
        $shareHtml = if ($null -ne $_.RelativeSharePercent) { "<br><small style='color:#cbd5e1'>Share: $(HtmlEncode ([string]$_.RelativeSharePercent))% $(HtmlEncode $_.RelativeShareBasis)</small>" } else { '' }
        $focusHtml = if ($null -ne $_.ConcentrationPercent) { "<br><small style='color:#cbd5e1'>Focus: $(HtmlEncode ([string]$_.ConcentrationPercent))% $(HtmlEncode $_.ConcentrationBasis)</small>" } else { '' }
        $evidenceHtml = if ($_.Evidence) { "<br><small style='color:#94a3b8'>Evidence: $(HtmlEncode $_.Evidence)</small>" } else { '' }
        $suppressedHtml = if ($_.SuppressedBecause) { "<br><small style='color:#fbbf24'>$(HtmlEncode $_.SuppressedBecause)</small>" } else { '' }
        $fallbackHtml = if (@($_.Fallbacks).Count -gt 0) {
            "<br><small style='color:#facc15'>Fallbacks:</small><br>" + ((@($_.Fallbacks) | ForEach-Object { "<small style='color:#fde68a'>$(HtmlEncode $_)</small>" }) -join '<br>')
        } else { '' }
        $commandHtml = if (@($_.Commands).Count -gt 0) {
            (@($_.Commands) | ForEach-Object { "<code>$(HtmlEncode $_)</code>" }) -join '<br>'
        }
        else {
            "<span style='color:#94a3b8'>No candidate commands recorded</span>"
        }
        "<tr><td style='color:$c;font-weight:bold'>$(HtmlEncode $_.Impact)</td><td>$(HtmlEncode $_.Type)</td><td>$(HtmlEncode $_.Value)</td><td>$(HtmlEncode $_.Reason)$scopeHtml$preferenceHtml$shareHtml$focusHtml$evidenceHtml$suppressedHtml$fallbackHtml</td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$commandHtml</td></tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='5' style='color:#94a3b8;text-align:center;padding:20px'>No validation-only candidates recorded</td></tr>"
}

$htmlExclRows = @()
foreach ($p in $discoveredExcl.Paths) { $htmlExclRows += "<tr><td>Path</td><td>$(HtmlEncode $p)</td></tr>" }
foreach ($p in $discoveredExcl.Processes) { $htmlExclRows += "<tr><td>Process</td><td>$(HtmlEncode $p)</td></tr>" }
foreach ($p in $discoveredExcl.Extensions) { $htmlExclRows += "<tr><td>Extension</td><td>$(HtmlEncode (Format-ExtensionDisplay $p))</td></tr>" }
if ($htmlExclRows.Count -eq 0) {
    $htmlExclRows = @("<tr><td colspan='2' style='color:#94a3b8'>No exclusions discovered (may be hidden)</td></tr>")
}

$osCaption = try { (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption } catch { 'N/A' }
$htmlFile = Join-Path $ReportPath "DefenderPerf_$runId.html"
$highImpactCount = $highCount
$medImpactCount = $mediumCount
$htmlGuidanceItems = ($exclusionGuidance.Principles | ForEach-Object { "<li>$(HtmlEncode $_)</li>" }) -join "`n"
$htmlGuidanceSources = ($exclusionGuidance.Sources | ForEach-Object { "<li><a href='$(HtmlEncode $_)' target='_blank' rel='noreferrer'>$(HtmlEncode $_)</a></li>" }) -join "`n"
$htmlHotspotRows = if ($script:extensionHotspots -and $script:extensionHotspots.Count -gt 0) {
    ($script:extensionHotspots | Select-Object -First 12 | ForEach-Object {
        $impactColour = switch ($_.EstimatedImpact) { 'HIGH' { '#ef4444' } 'MEDIUM' { '#f59e0b' } default { '#22c55e' } }
        $folderSummary = if ($_.HotspotFolders -and @($_.HotspotFolders).Count -gt 0) {
            @($_.HotspotFolders | ForEach-Object {
                    $proc = if ($_.TopProcessPath) { $_.TopProcessPath } elseif ($_.TopProcessImage) { $_.TopProcessImage } else { 'n/a' }
                    "{0} ({1}, {2}% of observed, process {3})" -f (HtmlEncode $_.FolderPath), (HtmlEncode $_.Duration), (HtmlEncode ([string]$_.ShareOfObservedDuration)), (HtmlEncode $proc)
                }) -join '<br>'
        }
        else {
            "<span style='color:#94a3b8'>No hotspot folders resolved</span>"
        }
        "<tr><td style='color:$impactColour;font-weight:bold'>$(HtmlEncode $_.Extension)</td><td>$(HtmlEncode $_.Duration)</td><td>$(HtmlEncode ([string]$_.Count))</td><td>$(HtmlEncode ([string]$_.ObservedCoveragePercent))%</td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$folderSummary</td></tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='5' style='color:#94a3b8;text-align:center;padding:20px'>No extension hotspot data available</td></tr>"
}
$htmlScanContextRows = if ($script:topScanContexts -and $script:topScanContexts.Count -gt 0) {
    ($script:topScanContexts | Select-Object -First 10 | ForEach-Object {
        $impactColour = switch ($_.EstimatedImpact) { 'HIGH' { '#ef4444' } 'MEDIUM' { '#f59e0b' } default { '#22c55e' } }
        $scanDetail = "{0} | Reason: {1}" -f (HtmlEncode $_.ScanType), (HtmlEncode ([string]$_.Reason))
        $processDetail = if ($_.ProcessPath) { HtmlEncode $_.ProcessPath } elseif ($_.ProcessImage) { HtmlEncode $_.ProcessImage } else { '<span style=''color:#94a3b8''>n/a</span>' }
        $relatedDetail = if ($_.RelatedFolders -and @($_.RelatedFolders).Count -gt 0) {
            @($_.RelatedFolders | ForEach-Object { "{0} ({1})" -f (HtmlEncode $_.FolderPath), (HtmlEncode $_.Duration) }) -join '<br>'
        }
        elseif ($_.CommentSamples -and @($_.CommentSamples).Count -gt 0) {
            @($_.CommentSamples | ForEach-Object { HtmlEncode $_ }) -join '<br>'
        }
        else {
            "<span style='color:#94a3b8'>No related file details</span>"
        }
        "<tr><td style='color:$impactColour;font-weight:bold'>$(HtmlEncode $_.EstimatedImpact)</td><td>$(HtmlEncode $_.Duration)</td><td>$(HtmlEncode ([string]$_.StartTimeLocal))</td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$scanDetail</td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$processDetail</td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$(HtmlEncode $_.TargetPath)</td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$relatedDetail</td></tr>"
    }) -join "`n"
}
else {
    "<tr><td colspan='7' style='color:#94a3b8;text-align:center;padding:20px'>No top scan context data available</td></tr>"
}
$htmlCabIntelRows = @()

if ($cabIntel['EffectiveConfig']) {
    $ec = $cabIntel['EffectiveConfig']
    $htmlCabIntelRows += "<tr><td>Cloud Protection</td><td>MAPSReporting: $(HtmlEncode ([string]$ec.CloudProtection)), BlockLevel: $(HtmlEncode ([string]$ec.CloudBlockLevel)), SamplesConsent: $(HtmlEncode ([string]$ec.SubmitSamplesConsent))</td></tr>"
    $htmlCabIntelRows += "<tr><td>Protection Status</td><td>PUA: $(HtmlEncode ([string]$ec.PUAProtection)), RTP Enabled: $(HtmlEncode ([string]$ec.RealTimeProtectionEnabled)), Behavior Enabled: $(HtmlEncode ([string]$ec.BehaviorMonitoringEnabled)), IOAV Enabled: $(HtmlEncode ([string]$ec.IOAVProtectionEnabled)), Script Enabled: $(HtmlEncode ([string]$ec.ScriptScanningEnabled))</td></tr>"
}

if ($cabIntel['PlatformVersions']) {
    $pv = $cabIntel['PlatformVersions']
    $htmlCabIntelRows += "<tr><td>Platform Versions</td><td>OS Build: $(HtmlEncode ([string]$pv.OSBuildBranch)), Reported OS: $(HtmlEncode ([string]$pv.ReportedOSVersion)), Defender Platform: $(HtmlEncode ([string]$pv.DefenderPlatformVersion))</td></tr>"
}

if ($cabIntel['HealthState']) {
    $hs = $cabIntel['HealthState']
    $htmlCabIntelRows += "<tr><td>Product Health</td><td>Threats: $(HtmlEncode ([string]$hs.ThreatCount)), Suspicious: $(HtmlEncode ([string]$hs.SuspiciousCount)), Overall Status: $(HtmlEncode ([string]$hs.OverallProductStatus)), RTP: $(HtmlEncode ([string]$hs.RealtimeMonitorEnabled)), OnAccess: $(HtmlEncode ([string]$hs.OnAccessProtectionEnabled)), IOAV: $(HtmlEncode ([string]$hs.IOAVProtectionEnabled))</td></tr>"
}

if ($cabIntel['NetworkProtection']) {
    $np = $cabIntel['NetworkProtection']
    $disabledFeatures = if ($np.DisabledFeatures) { @($np.DisabledFeatures | ForEach-Object { HtmlEncode $_ }) -join ', ' } else { 'none' }
    $htmlCabIntelRows += "<tr><td>Network Protection</td><td>Mode: $(HtmlEncode ([string]$np.Mode)), Disabled toggles: $(HtmlEncode ([string]$np.DisabledFeatureCount)) ($disabledFeatures)</td></tr>"
}

if ($cabIntel['DeviceControl']) {
    $dc = $cabIntel['DeviceControl']
    $htmlCabIntelRows += "<tr><td>Device Control</td><td>State: $(HtmlEncode ([string]$dc.State)), ServiceMode: $(HtmlEncode ([string]$dc.ServiceMode)), Available: $(HtmlEncode ([string]$dc.Available)), EnabledByPolicy: $(HtmlEncode ([string]$dc.EnabledByPolicy)), PolicyPresent: $(HtmlEncode ([string]$dc.PolicyPresent))</td></tr>"
}

if ($cabIntel['CloudOperationalEvents']) {
    $co = $cabIntel['CloudOperationalEvents']
    $htmlCabIntelRows += "<tr><td>Operational Events</td><td>Cloud intelligence events: $(HtmlEncode ([string]$co.CloudProtectionEventCount)), Latest SI: $(HtmlEncode ([string]$co.LatestSecurityIntelligenceVersion)), Latest Engine: $(HtmlEncode ([string]$co.LatestEngineVersion))</td></tr>"
    if ($co.RecentCloudEvents) {
        $htmlCabIntelRows += @($co.RecentCloudEvents | ForEach-Object {
                $details = @(
                    "Timestamp: $(HtmlEncode ([string]$_.Timestamp))"
                    "SI: $(HtmlEncode ([string]$_.SecurityIntelligenceVersion))"
                    "Engine: $(HtmlEncode ([string]$_.EngineVersion))"
                    "Type: $(HtmlEncode ([string]$_.IntelligenceType))"
                    "Path: $(HtmlEncode ([string]$_.PersistencePath))"
                ) -join '<br>'
                "<tr><td></td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$details</td></tr>"
            })
    }
}

if ($cabIntel['SecurityCenterProducts']) {
    $products = @($cabIntel['SecurityCenterProducts'])
    $htmlCabIntelRows += "<tr><td>Security Center</td><td>$($products.Count) product registration(s) found</td></tr>"
    foreach ($product in $products) {
        $htmlCabIntelRows += "<tr><td></td><td>$(HtmlEncode ([string]$product.DisplayName)) | State $(HtmlEncode ([string]$product.ProductState)) | $(HtmlEncode ([string]$product.ProductPath))</td></tr>"
    }
}

if ($cabIntel['MDEOnboarding']) {
    $mde = $cabIntel['MDEOnboarding']
    $htmlCabIntelRows += "<tr><td>MDE Onboarding</td><td>OrgId: $(HtmlEncode ([string]$mde.OrgId)), Datacenter: $(HtmlEncode ([string]$mde.Datacenter)), Geo: $(HtmlEncode ([string]$mde.VortexGeoLocation)), Tenant: $(HtmlEncode ([string]$mde.MdeAadTenantId))</td></tr>"
}

if ($cabIntel['MPLogHighlights']) {
    $mpLog = $cabIntel['MPLogHighlights']
    $htmlCabIntelRows += "<tr><td>MPLog Highlights</td><td>Files: $(HtmlEncode ([string]$mpLog.FileCount)), Latest: $(HtmlEncode ([string]$mpLog.LatestFile)) ($(HtmlEncode ([string]$mpLog.LatestFileWriteTime))), Dynamic signature drops: $(HtmlEncode ([string]$mpLog.DynamicSignatureDropCount))</td></tr>"

    $mpLogExclusionMentions = Get-Prop $mpLog 'ExclusionMentions'
    if ($mpLogExclusionMentions) {
        $exclusionMentionSummary = @(
            "Paths: $(@($mpLogExclusionMentions.Paths).Count)"
            "Processes: $(@($mpLogExclusionMentions.Processes).Count)"
            "Extensions: $(@($mpLogExclusionMentions.Extensions).Count)"
        ) -join ', '
        $htmlCabIntelRows += "<tr><td></td><td>$exclusionMentionSummary</td></tr>"
    }

    $mpLogDynamicEvents = Get-Prop $mpLog 'RecentDynamicSignatureEvents'
    if ($mpLogDynamicEvents) {
        $htmlCabIntelRows += @($mpLogDynamicEvents | ForEach-Object {
                $details = @(
                    "Timestamp: $(HtmlEncode ([string]$_.Timestamp))"
                    "Type: $(HtmlEncode ([string]$_.SignatureType))"
                    "Compilation: $(HtmlEncode ([string]$_.CompilationTimestamp))"
                    "Persistence: $(HtmlEncode ([string]$_.PersistenceType))"
                    "Path: $(HtmlEncode ([string]$_.SignaturePath))"
                ) -join '<br>'
                "<tr><td></td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$details</td></tr>"
            })
    }

    $mpLogImpactRecords = Get-Prop $mpLog 'ImpactRecords'
    if ($mpLogImpactRecords) {
        $htmlCabIntelRows += @($mpLogImpactRecords | ForEach-Object {
                $details = @()
                if ($_.Timestamp) { $details += "Timestamp: $(HtmlEncode ([string]$_.Timestamp))" }
                if ($_.ProcessImageName) { $details += "ProcessImageName: $(HtmlEncode ([string]$_.ProcessImageName))" }
                if ($_.ProcessPath) { $details += "ProcessPath: $(HtmlEncode ([string]$_.ProcessPath))" }
                if ($_.EstimatedImpact) { $details += "EstimatedImpact: $(HtmlEncode ([string]$_.EstimatedImpact))" }
                if ($details.Count -gt 0) {
                    "<tr><td></td><td style='white-space:normal;word-break:break-word;vertical-align:top'>$($details -join '<br>')</td></tr>"
                }
            })
    }
}

if ($cabIntel['SignatureUpdateStub']) {
    $sigStub = $cabIntel['SignatureUpdateStub']
    $htmlCabIntelRows += "<tr><td>Signature Update Stub</td><td>Start: $(HtmlEncode ([string]$sigStub.StartTime)), Administrator: $(HtmlEncode ([string]$sigStub.Administrator)), Stub: $(HtmlEncode ([string]$sigStub.StubVersion)), Product Engine: $(HtmlEncode ([string]$sigStub.ProductEngineVersion))</td></tr>"
    if ($sigStub.Command) {
        $htmlCabIntelRows += "<tr><td></td><td style='white-space:normal;word-break:break-word;vertical-align:top'>Command: $(HtmlEncode ([string]$sigStub.Command))</td></tr>"
    }
}

if ($cabIntel['ScanSkips']) {
    $ss = $cabIntel['ScanSkips']
    $htmlCabIntelRows += "<tr><td>Scan Skips</td><td style='color:#f59e0b'>$($ss.TotalSkipped) total skipped scans</td></tr>"
    $htmlCabIntelRows += @($ss.ByReason.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5 | ForEach-Object {
            "<tr><td></td><td>$(HtmlEncode $_.Key): $(HtmlEncode ([string]$_.Value))</td></tr>"
        })
}

if ($cabIntel['FilterDrivers']) {
    $htmlCabIntelRows += "<tr><td>Filter Drivers</td><td>$($cabIntel['FilterDrivers'].Count) active filesystem filters</td></tr>"
    $htmlCabIntelRows += @($cabIntel['FilterDrivers'] | ForEach-Object {
            "<tr><td></td><td>$(HtmlEncode $_.Name) (altitude $(HtmlEncode ([string]$_.Altitude)), $(HtmlEncode ([string]$_.Instances)) instances)</td></tr>"
        })
}

if ($cabIntel['IFEODebuggerHijacks'] -and $cabIntel['IFEODebuggerHijacks'].Count -gt 0) {
    $htmlCabIntelRows += "<tr><td style='color:#ef4444'>IFEO Hijacks</td><td style='color:#ef4444'>$($cabIntel['IFEODebuggerHijacks'].Count) debugger entries found</td></tr>"
    $htmlCabIntelRows += @($cabIntel['IFEODebuggerHijacks'] | ForEach-Object {
            "<tr><td></td><td>$(HtmlEncode $_)</td></tr>"
        })
}

if ($cabIntel['RecentDetections'] -and $cabIntel['RecentDetections'].Count -gt 0) {
    $htmlCabIntelRows += "<tr><td style='color:#ef4444'>Detections</td><td style='color:#ef4444'>$($cabIntel['RecentDetections'].Count) detection event(s)</td></tr>"
    $htmlCabIntelRows += @($cabIntel['RecentDetections'] | Select-Object -First 10 | ForEach-Object {
            "<tr><td></td><td>$(HtmlEncode $_)</td></tr>"
        })
}

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Defender Performance Report - $timestamp</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;padding:24px 32px;line-height:1.6}
  h1{color:#38bdf8;border-bottom:2px solid #1e3a5f;padding-bottom:10px;font-size:1.6em;margin-bottom:16px}
  h2{color:#7dd3fc;margin-top:32px;font-size:1.15em;border-left:3px solid #38bdf8;padding-left:12px;margin-bottom:8px}
  table{width:100%;border-collapse:collapse;margin-top:12px;font-size:.9em}
  th{background:#1e293b;color:#94a3b8;padding:10px 14px;text-align:left;font-weight:600;text-transform:uppercase;font-size:.75em;letter-spacing:.05em;position:sticky;top:0}
  td{padding:9px 14px;border-bottom:1px solid #1e293b;max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  tr:hover td{background:rgba(30,41,59,.5)}
  code{background:#1e293b;padding:2px 8px;border-radius:4px;font-size:.82em;color:#38bdf8;word-break:break-all;white-space:normal}
  .meta{background:#1e293b;border-left:4px solid #38bdf8;padding:14px 20px;border-radius:6px;margin:16px 0;font-size:.9em}
  .meta strong{color:#94a3b8;margin-right:6px}
  .summary-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin:20px 0}
  .stat-card{background:#1e293b;border-radius:8px;padding:18px 20px;text-align:center;border:1px solid #1e3a5f}
  .stat-card .number{font-size:2.2em;font-weight:700}
  .stat-card .label{color:#94a3b8;font-size:.85em;margin-top:4px}
  .high{color:#ef4444}.medium{color:#f59e0b}.low{color:#22c55e}.info{color:#38bdf8}
  .warning-box{background:#422006;border:1px solid #92400e;border-radius:6px;padding:12px 16px;margin:12px 0;color:#fbbf24;font-size:.9em}
  .source-badge{display:inline-block;background:#1e3a5f;color:#7dd3fc;padding:3px 10px;border-radius:12px;font-size:.8em;font-weight:600;margin-left:8px}
  ul{margin:12px 0 0 20px}
  a{color:#7dd3fc}
  footer{color:#475569;font-size:.75em;margin-top:40px;border-top:1px solid #1e293b;padding-top:12px}
</style>
</head>
<body>

<h1>Windows Defender Performance Report</h1>

<div class="meta">
  <strong>Generated:</strong> $(Get-Date -Format 'dddd d MMMM yyyy HH:mm:ss')<br>
  <strong>Host:</strong> $(HtmlEncode $env:COMPUTERNAME) |
  <strong>OS:</strong> $(HtmlEncode $osCaption)<br>
  <strong>Recording:</strong> $RecordingSeconds seconds |
  <strong>Engine:</strong> $(if($status){$status.AMProductVersion}else{'N/A'}) |
  <strong>Signatures:</strong> $(if($status){$status.AntivirusSignatureVersion}else{'N/A'}) |
  <strong>Real-time:</strong> $(if($status -and $status.RealTimeProtectionEnabled){'Enabled'}else{'DISABLED'})
  $(if($script:scheduledStartAt){"<br><strong>Scheduled start:</strong> $(HtmlEncode $script:scheduledStartAt.ToString('yyyy-MM-dd HH:mm:ss')) | <strong>Actual start:</strong> $(HtmlEncode $script:actualRunStartedAt.ToString('yyyy-MM-dd HH:mm:ss')) | <strong>Waited:</strong> $(HtmlEncode ([string]("{0:N1} min" -f ($script:scheduledWaitSeconds / 60))))"}else{''})
</div>

<div class="summary-grid">
  <div class="stat-card">
    <div class="number high">$highImpactCount</div>
    <div class="label">High Impact Items</div>
  </div>
  <div class="stat-card">
    <div class="number medium">$medImpactCount</div>
    <div class="label">Medium Impact Items</div>
  </div>
  <div class="stat-card">
    <div class="number info">$($script:suggestions.Count)</div>
    <div class="label">Exclusion Suggestions</div>
  </div>
  <div class="stat-card">
    <div class="number info">$($script:suppressedSuggestions.Count)</div>
    <div class="label">Suppressed Candidates</div>
  </div>
  <div class="stat-card">
    <div class="number low">$($script:impactTableRows.Count)</div>
    <div class="label">Total Items Analysed</div>
  </div>
</div>

<h2>Performance Impact Table</h2>
<table>
  <tr><th>Category</th><th>Impact</th><th>Duration</th><th>Count</th><th>Item</th></tr>
  $htmlImpactRows
</table>

<h2>High-Impact Scan Context</h2>
<table>
  <tr><th>Impact</th><th>Duration</th><th>Started</th><th>Scan</th><th>Process</th><th>Target</th><th>Related Folders</th></tr>
  $htmlScanContextRows
</table>

<h2>Extension Hotspots</h2>
<table>
  <tr><th>Extension</th><th>Total Duration</th><th>Count</th><th>Observed Coverage</th><th>Dominant Folder Hotspots</th></tr>
  $htmlHotspotRows
</table>

<h2>Exclusion Suggestions</h2>
<div class="warning-box">WARNING: Review each suggestion carefully before applying. Excluding items reduces Defender security coverage. Never exclude system directories, scripting engines, or executable file types.</div>
<table>
  <tr><th>Impact</th><th>Risk</th><th>Type</th><th>Value</th><th>Reason</th><th>Command</th></tr>
  $htmlSuggestionRows
</table>

<h2>Suppressed Validation-Only Candidates</h2>
<div class="warning-box">These candidates were derived from scan evidence but intentionally not promoted into live recommendations. Review them as validation-only folder-pattern examples.</div>
<table>
  <tr><th>Impact</th><th>Type</th><th>Value</th><th>Reason</th><th>Candidate Commands</th></tr>
  $htmlSuppressedRows
</table>

<h2>Exclusion Guidance</h2>
<div class="meta">
  <strong>Contextual exclusions supported:</strong> $(HtmlEncode ([string]$exclusionGuidance.ContextualExclusionsSupported))<br>
  <strong>Local admin merge disabled:</strong> $(HtmlEncode ([string]$exclusionGuidance.LocalAdminMergeDisabled))
</div>
<ul>
  $htmlGuidanceItems
</ul>
<div class="meta">
  <strong>Reference sources</strong>
  <ul>
    $htmlGuidanceSources
  </ul>
</div>

<h2>Current Exclusions <span class="source-badge">Source: $(HtmlEncode $exclusionSource)</span></h2>
<table>
  <tr><th>Type</th><th>Value</th></tr>
  $($htmlExclRows -join "`n")
</table>

$(if ($htmlCabIntelRows.Count -gt 0) {
@"
<h2>CAB Diagnostic Intelligence</h2>
<table>
  <tr><th>Category</th><th>Details</th></tr>
  $($htmlCabIntelRows -join "`n")
</table>
"@
})

<footer>
  Generated by Analyze-DefenderPerformance.ps1 | Recording: $(HtmlEncode $etlFile) | JSON: $(HtmlEncode $jsonFile)
</footer>
</body>
</html>
"@

try {
    $html | Out-File -FilePath $htmlFile -Encoding UTF8
    Write-OK "HTML report saved : $htmlFile"
}
catch {
    Write-Warn "Could not save HTML report: $_"
}

# ═══════════════════════════════════════════════════════════════════════════════
#  FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════════
Write-Section "COMPLETE"

Write-Host ""
Write-Info "Performance recording   : $etlFile"
Write-Info "JSON report             : $jsonFile"
Write-Info "HTML report             : $htmlFile"
if ($AIMode) {
    Write-Info "AI export               : $aiExportFile"
    Write-Info "AI prompt               : $aiPromptFile"
}
Write-Info "Transcript log          : $script:transcriptFile"
Write-Info "Exclusion source        : $exclusionSource"
Write-Host ""

if ($highCount -gt 0) {
    if ($script:suggestions.Count -gt 0) {
        Write-Bad  "$highCount HIGH-impact item(s) detected -- review the exclusion suggestions above."
    }
    elseif ($script:suppressedSuggestions.Count -gt 0) {
        Write-Warn "$highCount HIGH-impact item(s) detected -- live exclusions were not promoted, but validation-only candidates were captured for review."
    }
    else {
        Write-Warn "$highCount HIGH-impact item(s) detected -- investigate the high-impact scan contexts above."
    }
}
elseif ($script:suggestions.Count -gt 0) {
    Write-Warn "$($script:suggestions.Count) exclusion suggestion(s) -- minor improvements possible."
}
elseif ($script:suppressedSuggestions.Count -gt 0) {
    Write-Info "No live exclusions were promoted, but validation-only candidates were captured for review."
}
else {
    Write-OK  "Defender performance looks healthy -- no action required."
}

Write-Host ""
Write-Host "  Tip: Open the HTML report for a visual dashboard, or pipe the" -ForegroundColor DarkGray
Write-Host "       JSON into monitoring tools for automated analysis." -ForegroundColor DarkGray
Write-Host ""

# Open HTML report in default browser
if (-not $NoOpenReport) {
    try { Start-Process $htmlFile } catch {}
}

# ETL trace is kept for deeper analysis -- uncomment below to auto-clean:
# Remove-Item $etlFile -Force -ErrorAction SilentlyContinue

Close-RunTranscript
