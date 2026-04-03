<#
.SYNOPSIS
    Self-elevating single-run launcher for defender.ps1.

.DESCRIPTION
    Prompts for UAC when needed, runs defender.ps1 once with the requested
    options, captures a UTF-8 log, and writes a small run_summary.json file
    that can be polled by external tools.
#>
[CmdletBinding()]
param(
    [ValidateRange(10, 900)]
    [int]$RecordingSeconds = 120,

    [ValidateRange(5, 100)]
    [int]$TopN = 25,

    [string]$OutputRoot,

    [datetime]$StartAt,

    [string]$StartAtTime,

    [switch]$ValidateLoad,

    [switch]$ValidateExclusions,

    [switch]$AIMode,

    [switch]$NoOpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$selfPath = $MyInvocation.MyCommand.Path
$defenderScript = Join-Path $scriptDir 'defender.ps1'

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

function Resolve-ScheduledStart {
    param(
        [datetime]$ExplicitStart,
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

if (-not (Test-Path -LiteralPath $defenderScript)) {
    throw "Main script not found: $defenderScript"
}

if (-not $OutputRoot) {
    $OutputRoot = Join-Path $scriptDir ("single_run_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
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

if (-not (Test-IsAdministrator)) {
    Write-Stage -Stage 'ELEVATE' -Message 'Requesting administrator approval via UAC...'

    $argList = @(
        '-NoProfile'
        '-ExecutionPolicy'
        'Bypass'
        '-File'
        ('"{0}"' -f $selfPath)
        '-RecordingSeconds'
        $RecordingSeconds
        '-TopN'
        $TopN
        '-OutputRoot'
        ('"{0}"' -f $OutputRoot)
    )

    if ($scheduleRequest) {
        Write-Stage -Stage 'SCHEDULE' -Message ("Scheduled start resolved to {0}" -f $scheduleRequest.StartAt.ToString('yyyy-MM-dd HH:mm:ss'))
        $argList += '-StartAt'
        $argList += ('"{0}"' -f $scheduleRequest.StartAt.ToString('o'))
    }

    if ($ValidateLoad) {
        $argList += '-ValidateLoad'
    }
    if ($ValidateExclusions) {
        $argList += '-ValidateExclusions'
    }
    if ($AIMode) {
        $argList += '-AIMode'
    }
    if ($NoOpenReport) {
        $argList += '-NoOpenReport'
    }

    try {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -WorkingDirectory $scriptDir -ArgumentList $argList | Out-Null
        Write-Stage -Stage 'ELEVATE' -Message 'Elevated run started in a new PowerShell window.' -Color Green
        return
    }
    catch {
        throw "Elevation was cancelled or failed: $_"
    }
}

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$PSDefaultParameterValues['Out-File:Encoding'] = 'utf8'
$PSDefaultParameterValues['Tee-Object:Encoding'] = 'utf8'

New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile = Join-Path $OutputRoot "single_run_$runId.log"
$summaryFile = Join-Path $OutputRoot 'run_summary.json'
$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

Write-Stage -Stage 'START' -Message "Output root: $OutputRoot"
if ($scheduleRequest) {
    Write-Stage -Stage 'SCHEDULE' -Message ("Passing scheduled start {0} into defender.ps1" -f $scheduleRequest.StartAt.ToString('yyyy-MM-dd HH:mm:ss'))
}
Write-Stage -Stage 'RUN' -Message "Launching defender.ps1 for ${RecordingSeconds}s"

$scriptError = $null
$exitCode = 0

try {
    $defenderParams = @{
        RecordingSeconds = $RecordingSeconds
        TopN             = $TopN
        ReportPath       = $OutputRoot
    }

    if ($scheduleRequest) {
        $defenderParams['StartAt'] = $scheduleRequest.StartAt
    }

    if ($ValidateLoad) {
        $defenderParams['ValidateLoad'] = $true
    }
    if ($ValidateExclusions) {
        $defenderParams['ValidateExclusions'] = $true
    }
    if ($AIMode) {
        $defenderParams['AIMode'] = $true
    }
    if ($NoOpenReport) {
        $defenderParams['NoOpenReport'] = $true
    }

    & $defenderScript @defenderParams *>&1 | Tee-Object -FilePath $logFile
    $exitCode = $LASTEXITCODE
}
catch {
    $scriptError = $_.ToString()
    $exitCode = 1
    Write-Stage -Stage 'ERROR' -Message $scriptError -Color Red
}

$stopwatch.Stop()

$result = [ordered]@{
    GeneratedAt         = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    OutputRoot          = $OutputRoot
    RecordingSeconds    = $RecordingSeconds
    ScheduleMode        = if ($scheduleRequest) { $scheduleRequest.Mode } else { 'Immediate' }
    ScheduleInput       = if ($scheduleRequest) { $scheduleRequest.InputText } else { $null }
    ScheduledStartAt    = if ($scheduleRequest) { $scheduleRequest.StartAt.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
    ValidateLoad        = [bool]$ValidateLoad
    ValidateExclusions  = [bool]$ValidateExclusions
    AIMode              = [bool]$AIMode
    ExitCode            = $exitCode
    ElapsedSeconds      = [math]::Round($stopwatch.Elapsed.TotalSeconds, 1)
    LogFile             = $logFile
    JsonReport          = (Get-ChildItem -Path $OutputRoot -Filter 'DefenderPerf_*.json' -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*.ai-export.json' } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName)
    HtmlReport          = Get-LatestFilePath -Path $OutputRoot -Filter 'DefenderPerf_*.html'
    AIExport            = Get-LatestFilePath -Path $OutputRoot -Filter 'DefenderPerf_*.ai-export.json'
    AIPrompt            = Get-LatestFilePath -Path $OutputRoot -Filter 'DefenderPerf_*.ai-prompt.md'
    Error               = $scriptError
}

$result | ConvertTo-Json -Depth 8 | Out-File -FilePath $summaryFile -Force
Write-Stage -Stage 'DONE' -Message "Summary written: $summaryFile" -Color Green

if ($exitCode -ne 0) {
    exit $exitCode
}
