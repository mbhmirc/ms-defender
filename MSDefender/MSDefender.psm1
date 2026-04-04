$script:RepositoryRoot = Split-Path -Parent $PSScriptRoot
$script:EntryScripts = @{
    Defender        = Join-Path $script:RepositoryRoot 'defender.ps1'
    SingleRun       = Join-Path $script:RepositoryRoot 'defender-single-run.ps1'
    ValidationLoop  = Join-Path $script:RepositoryRoot 'defender-validation-loop.ps1'
    Workload        = Join-Path $script:RepositoryRoot 'defender-workload.ps1'
    TestHarness     = Join-Path $script:RepositoryRoot 'defender-test.ps1'
    Compare         = Join-Path $script:RepositoryRoot 'defender-compare.ps1'
    OfflineFixtures = Join-Path $script:RepositoryRoot 'defender-offline-fixture-tests.ps1'
    ReportLib       = Join-Path $script:RepositoryRoot 'defender-report-lib.ps1'
}

foreach ($scriptPath in $script:EntryScripts.Values) {
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "MSDefender module dependency not found: $scriptPath"
    }
}

. $script:EntryScripts.ReportLib

function Invoke-MsDefenderScript {
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter()][hashtable]$Parameters = @{}
    )

    & $ScriptPath @Parameters
}

function Invoke-MsDefenderPerformanceAudit {
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

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.Defender -Parameters $PSBoundParameters
}

function Invoke-MsDefenderSingleRun {
    [CmdletBinding()]
    param(
        [ValidateRange(10, 900)]
        [int]$RecordingSeconds = 120,

        [ValidateRange(5, 100)]
        [int]$TopN = 25,

        [string]$OutputRoot,
        [datetime]$StartAt,
        [string]$StartAtTime,
        [switch]$StrictCAB,
        [switch]$ValidateLoad,
        [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
        [string]$SyntheticWorkloadMode = 'Mixed',
        [switch]$ValidateExclusions,
        [switch]$AIMode,
        [switch]$NoOpenReport
    )

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.SingleRun -Parameters $PSBoundParameters
}

function Invoke-MsDefenderValidationLoop {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 100)]
        [int]$Iterations = 3,

        [ValidateRange(10, 900)]
        [int]$RecordingSeconds = 120,

        [ValidateRange(5, 100)]
        [int]$TopN = 25,

        [ValidateRange(0, 1440)]
        [int]$WaitMinutes = 3,

        [string]$OutputRoot,
        [datetime]$StartAt,
        [string]$StartAtTime,
        [switch]$StrictCAB,
        [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
        [string]$SyntheticWorkloadMode = 'Mixed',
        [switch]$AIMode,
        [switch]$NoOpenReport,
        [switch]$NoAutoClose
    )

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.ValidationLoop -Parameters $PSBoundParameters
}

function Invoke-MsDefenderSyntheticWorkload {
    [CmdletBinding()]
    param(
        [int]$DurationSeconds = 30,
        [string]$WorkDir,
        [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
        [string]$Mode = 'Mixed'
    )

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.Workload -Parameters $PSBoundParameters
}

function Test-MsDefenderPerformanceAudit {
    [CmdletBinding()]
    param(
        [ValidateRange(10, 900)]
        [int]$RecordingSeconds = 20,

        [ValidateRange(5, 100)]
        [int]$TopN = 15,

        [string]$OutputRoot,
        [datetime]$StartAt,
        [string]$StartAtTime,
        [switch]$StrictCAB,
        [ValidateSet('Mixed', 'PowerShell', 'NativeExe')]
        [string]$SyntheticWorkloadMode = 'Mixed',
        [switch]$AIMode,
        [switch]$NoAutoClose,
        [switch]$NoOpenReport
    )

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.TestHarness -Parameters $PSBoundParameters
}

function Compare-MsDefenderPerformanceReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$BaselineReport,
        [Parameter(Mandatory)][string]$CurrentReport,
        [string]$OutputPath,
        [switch]$NoOpenReport
    )

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.Compare -Parameters $PSBoundParameters
}

function Test-MsDefenderOfflineFixtures {
    [CmdletBinding()]
    param(
        [string]$OutputRoot
    )

    Invoke-MsDefenderScript -ScriptPath $script:EntryScripts.OfflineFixtures -Parameters $PSBoundParameters
}

function Get-MsDefenderRecommendationResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$PerfReport,
        [Parameter(Mandatory)]$DiscoveredExclusions,
        [bool]$ContextualExclusionsSupported,
        [bool]$ValidateLoad,
        [double]$HighThresholdMs = 5000,
        [double]$MediumThresholdMs = 1000,
        [switch]$RequireExistingProcessPath
    )

    Get-DefenderRecommendationResult @PSBoundParameters
}

function Get-MsDefenderCabIntelligence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$ExtractedDirectory
    )

    Get-DefenderCabIntelligenceFromExtractedDirectory -ExtractedDirectory $ExtractedDirectory
}

Export-ModuleMember -Function `
    Invoke-MsDefenderPerformanceAudit, `
    Invoke-MsDefenderSingleRun, `
    Invoke-MsDefenderValidationLoop, `
    Invoke-MsDefenderSyntheticWorkload, `
    Test-MsDefenderPerformanceAudit, `
    Compare-MsDefenderPerformanceReport, `
    Test-MsDefenderOfflineFixtures, `
    Get-MsDefenderRecommendationResult, `
    Get-MsDefenderCabIntelligence
