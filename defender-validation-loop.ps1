<#
.SYNOPSIS
    Self-elevating loop harness for defender-test.ps1.

.DESCRIPTION
    Prompts for UAC elevation when needed, then runs repeated validation cycles
    against defender.ps1 through defender-test.ps1. Each cycle gets its own
    output directory, and a consolidated loop_summary.json is updated after
    every run.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 20)]
    [int]$Iterations = 2,

    [ValidateRange(10, 900)]
    [int]$RecordingSeconds = 180,

    [ValidateRange(5, 100)]
    [int]$TopN = 25,

    [ValidateRange(0, 240)]
    [int]$WaitMinutes = 15,

    [string]$OutputRoot,

    [datetime]$StartAt,

    [string]$StartAtTime,

    [switch]$StrictCAB,

    [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
    [string]$SyntheticWorkloadMode = 'Mixed',

    [switch]$StopOnFailure
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$selfPath = $MyInvocation.MyCommand.Path
$testHarness = Join-Path $scriptDir 'defender-test.ps1'

if (-not $OutputRoot) {
    $OutputRoot = Join-Path $scriptDir ("validation_loop_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}

$startAtSpecified = $PSBoundParameters.ContainsKey('StartAt')
$startAtTimeSpecified = $PSBoundParameters.ContainsKey('StartAtTime')
try {
    $scheduleRequest = Resolve-ScheduledStart -ExplicitStart $StartAt -TimeOfDay $StartAtTime -ExplicitStartSpecified $startAtSpecified -TimeOfDaySpecified $startAtTimeSpecified
}
catch {
    Write-Stage -Stage 'SCHEDULE' -Message $_.Exception.Message -Color Red
    exit 1
}
$scheduledWaitSeconds = 0

function Write-Stage {
    param(
        [string]$Stage,
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Cyan
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor DarkGray
    Write-Host "[$Stage] " -NoNewline -ForegroundColor $Color
    Write-Host $Message
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PowerShellHostExecutable {
    $currentProcess = Get-Process -Id $PID -ErrorAction SilentlyContinue
    if ($currentProcess -and $currentProcess.Path) {
        return $currentProcess.Path
    }

    $candidate = Join-Path $PSHOME 'powershell.exe'
    if (Test-Path -LiteralPath $candidate) {
        return $candidate
    }

    return 'powershell.exe'
}

function Get-SafeElevationWorkingDirectory {
    $systemDirectory = Join-Path $env:SystemRoot 'System32'
    if (Test-Path -LiteralPath $systemDirectory -PathType Container) {
        return $systemDirectory
    }

    return (Get-Location).Path
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

        $candidate = [datetime]::Today.Add($parsedTime)
        if ($candidate -le (Get-Date).AddSeconds(5)) {
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

    Write-Stage -Stage 'SCHEDULE' -Message ("Mode: {0}" -f $Mode) -Color Yellow
    if ($InputText) {
        Write-Stage -Stage 'SCHEDULE' -Message ("Requested input: {0}" -f $InputText) -Color Yellow
    }
    Write-Stage -Stage 'SCHEDULE' -Message ("Waiting until {0} ({1})" -f $StartAt.ToString('yyyy-MM-dd HH:mm:ss'), $waitDescription) -Color Yellow

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

function Get-LatestFilePath {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Filter
    )

    $item = Get-ChildItem -Path $Path -Filter $Filter -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($item) { return $item.FullName }
    return $null
}

function Save-LoopSummary {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)]$Settings,
        [Parameter(Mandatory)]$History
    )

    $payload = [ordered]@{
        GeneratedAt = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
        Settings    = $Settings
        Cycles      = @($History)
    }

    $payload | ConvertTo-Json -Depth 8 | Out-File -FilePath $Path -Encoding UTF8 -Force
}

if (-not (Test-Path $testHarness)) {
    throw "Test harness not found: $testHarness"
}

if (-not (Test-IsAdministrator)) {
    Write-Stage -Stage 'ELEVATE' -Message 'Requesting administrator approval via UAC...'
    $hostExecutable = Get-PowerShellHostExecutable
    $workingDirectory = Get-SafeElevationWorkingDirectory

    $argList = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        ('"{0}"' -f $selfPath)
        '-Iterations'
        $Iterations
        '-RecordingSeconds'
        $RecordingSeconds
        '-TopN'
        $TopN
        '-WaitMinutes'
        $WaitMinutes
        '-OutputRoot'
        ('"{0}"' -f $OutputRoot)
        '-SyntheticWorkloadMode'
        $SyntheticWorkloadMode
    )

    if ($scheduleRequest) {
        Write-Stage -Stage 'SCHEDULE' -Message ("Scheduled first cycle resolved to {0}" -f $scheduleRequest.StartAt.ToString('yyyy-MM-dd HH:mm:ss'))
        $argList += '-StartAt'
        $argList += ('"{0}"' -f $scheduleRequest.StartAt.ToString('o'))
    }
    if ($StrictCAB) {
        $argList += '-StrictCAB'
    }

    if ($StopOnFailure) {
        $argList += '-StopOnFailure'
    }

    try {
        Start-Process -FilePath $hostExecutable -Verb RunAs -WorkingDirectory $workingDirectory -ArgumentList $argList | Out-Null
        Write-Stage -Stage 'ELEVATE' -Message 'Elevated loop started in a new PowerShell window.' -Color Green
        return
    }
    catch {
        throw "Elevation was cancelled or failed: $_"
    }
}

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$summaryFile = Join-Path $OutputRoot 'loop_summary.json'
$settings = [ordered]@{
    Iterations       = $Iterations
    RecordingSeconds = $RecordingSeconds
    TopN             = $TopN
    WaitMinutes      = $WaitMinutes
    ScheduleMode     = if ($scheduleRequest) { $scheduleRequest.Mode } else { 'Immediate' }
    ScheduleInput    = if ($scheduleRequest) { $scheduleRequest.InputText } else { $null }
    ScheduledStartAt = if ($scheduleRequest) { $scheduleRequest.StartAt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    ScheduledWaitSeconds = $scheduledWaitSeconds
    StrictCAB        = [bool]$StrictCAB
    SyntheticWorkloadMode = $SyntheticWorkloadMode
    OutputRoot       = $OutputRoot
    StopOnFailure    = [bool]$StopOnFailure
}

$history = [System.Collections.Generic.List[object]]::new()

Write-Stage -Stage 'START' -Message "Output root: $OutputRoot"
Write-Stage -Stage 'START' -Message "Running $Iterations cycle(s) with a $WaitMinutes minute pause between runs."

if ($scheduleRequest) {
    $scheduledWaitSeconds = Wait-UntilScheduledStart -StartAt $scheduleRequest.StartAt -Mode $scheduleRequest.Mode -InputText $scheduleRequest.InputText
    $settings['ScheduledWaitSeconds'] = $scheduledWaitSeconds
}

for ($iteration = 1; $iteration -le $Iterations; $iteration++) {
    $cycleStartedAt = Get-Date
    $cycleDir = Join-Path $OutputRoot ("cycle_{0:00}_{1}" -f $iteration, $cycleStartedAt.ToString('yyyyMMdd_HHmmss'))
    New-Item -ItemType Directory -Path $cycleDir -Force | Out-Null

    Write-Stage -Stage 'CYCLE' -Message "Starting cycle $iteration of $Iterations" -Color Yellow

    $exceptionMessage = $null
    $exitCode = 0
    $resultData = $null

    try {
        $testArgs = @(
            '-NoProfile'
            '-ExecutionPolicy'
            'Bypass'
            '-File'
            $testHarness
            '-RecordingSeconds'
            $RecordingSeconds
            '-TopN'
            $TopN
            '-OutputRoot'
            $cycleDir
            '-SyntheticWorkloadMode'
            $SyntheticWorkloadMode
            '-NoAutoClose'
            '-NoOpenReport'
        )

        if ($StrictCAB) {
            $testArgs += '-StrictCAB'
        }

        & powershell.exe @testArgs
        $exitCode = $LASTEXITCODE
    }
    catch {
        $exceptionMessage = $_.ToString()
        $exitCode = 1
        Write-Stage -Stage 'ERROR' -Message $exceptionMessage -Color Red
    }

    $resultFile = Get-LatestFilePath -Path $cycleDir -Filter 'test_result_*.json'
    if ($resultFile) {
        try {
            $resultData = Get-Content -Path $resultFile -Raw | ConvertFrom-Json
        }
        catch {
            $parseMessage = "Could not parse result JSON '$resultFile': $_"
            $exceptionMessage = if ($exceptionMessage) { "$exceptionMessage | $parseMessage" } else { $parseMessage }
            $exitCode = 1
            Write-Stage -Stage 'ERROR' -Message $parseMessage -Color Red
        }
    }
    else {
        $missingMessage = "No test_result_*.json file found under $cycleDir"
        $exceptionMessage = if ($exceptionMessage) { "$exceptionMessage | $missingMessage" } else { $missingMessage }
        $exitCode = 1
        Write-Stage -Stage 'ERROR' -Message $missingMessage -Color Red
    }

    $historyEntry = [ordered]@{
        Cycle      = $iteration
        StartedAt  = $cycleStartedAt.ToString('yyyy-MM-dd HH:mm:ss')
        FinishedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        ExitCode   = $exitCode
        Verdict    = if ($resultData) { $resultData.Verdict } else { 'ERROR' }
        Passed     = if ($resultData) { $resultData.Passed } else { $null }
        Warned     = if ($resultData) { $resultData.Warned } else { $null }
        Failed     = if ($resultData) { $resultData.Failed } else { $null }
        ResultFile = $resultFile
        LogFile    = if ($resultData) { $resultData.LogFile } else { Get-LatestFilePath -Path $cycleDir -Filter 'test_run_*.log' }
        ReportDir  = if ($resultData) { $resultData.ReportDir } else { $null }
        Exception  = $exceptionMessage
    }

    $history.Add([PSCustomObject]$historyEntry)
    Save-LoopSummary -Path $summaryFile -Settings $settings -History $history

    if ($historyEntry.ExitCode -eq 0 -and $historyEntry.Verdict -eq 'PASS') {
        Write-Stage -Stage 'CYCLE' -Message "Cycle $iteration passed. Summary updated: $summaryFile" -Color Green
    }
    else {
        Write-Stage -Stage 'CYCLE' -Message "Cycle $iteration failed. Summary updated: $summaryFile" -Color Red
    }

    if ($StopOnFailure -and ($historyEntry.ExitCode -ne 0 -or $historyEntry.Verdict -eq 'FAIL')) {
        Write-Stage -Stage 'STOP' -Message 'Stopping early because StopOnFailure is set.' -Color Yellow
        break
    }

    if ($iteration -lt $Iterations) {
        $nextRun = (Get-Date).AddMinutes($WaitMinutes)
        Write-Stage -Stage 'WAIT' -Message "Sleeping $WaitMinutes minute(s) until $($nextRun.ToString('yyyy-MM-dd HH:mm:ss'))" -Color Yellow
        Start-Sleep -Seconds ($WaitMinutes * 60)
    }
}

$failedCycles = @($history | Where-Object { $_.ExitCode -ne 0 -or $_.Verdict -eq 'FAIL' }).Count
$warnedCycles = @($history | Where-Object { $_.Warned -gt 0 }).Count

Write-Stage -Stage 'DONE' -Message "Cycles completed: $($history.Count), failed: $failedCycles, warned: $warnedCycles"
Write-Stage -Stage 'DONE' -Message "Loop summary: $summaryFile"

exit $(if ($failedCycles -gt 0) { 1 } else { 0 })
