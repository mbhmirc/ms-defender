[CmdletBinding()]
param(
    [string]$OutputRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$libPath = Join-Path $scriptDir 'defender-report-lib.ps1'
$compareScript = Join-Path $scriptDir 'defender-compare.ps1'
if (-not $OutputRoot) {
    $OutputRoot = Join-Path $scriptDir ("tests\results\offline_{0}" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
}
New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null

. $libPath

$tests = [System.Collections.Generic.List[object]]::new()
$pass = 0
$fail = 0
$contextualDemoCase = $null
$contextualDemoResult = $null

function Add-TestResult {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Details = ''
    )

    if ($Passed) {
        $script:pass++
        Write-Host "[PASS] $Name $Details" -ForegroundColor Green
    }
    else {
        $script:fail++
        Write-Host "[FAIL] $Name $Details" -ForegroundColor Red
    }

    $tests.Add([PSCustomObject]@{
            Name    = $Name
            Passed  = $Passed
            Details = $Details
        })
}

function Test-ContainsText {
    param(
        [string[]]$Haystacks,
        [string]$Needle
    )
    foreach ($haystack in @($Haystacks)) {
        $candidate = if ($null -ne $haystack) { [string]$haystack } else { '' }
        if ($candidate -like "*$Needle*") { return $true }
    }
    return $false
}

function HtmlEncode([string]$Value) {
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

Write-Host "Running offline recommendation fixtures..." -ForegroundColor Cyan
$rankingFixturePath = Join-Path $scriptDir 'tests\fixtures\recommendation-ranking\cases.json'
$rankingCases = Get-Content -LiteralPath $rankingFixturePath -Raw | ConvertFrom-Json

foreach ($case in $rankingCases) {
    $result = Get-DefenderRecommendationResult `
        -PerfReport $case.Input.PerfReport `
        -DiscoveredExclusions $case.Input.DiscoveredExclusions `
        -ContextualExclusionsSupported ([bool]$case.Input.ContextualExclusionsSupported) `
        -ValidateLoad ([bool]$case.Input.ValidateLoad)

    if ($case.Name -eq 'Trusted builder gets contextual file-pattern exclusion') {
        $contextualDemoCase = $case
        $contextualDemoResult = $result
    }

    if ($case.Expected.PSObject.Properties['SuggestionCount']) {
        Add-TestResult -Name "$($case.Name): suggestion count" -Passed (@($result.Suggestions).Count -eq [int]$case.Expected.SuggestionCount) -Details "expected=$($case.Expected.SuggestionCount) actual=$(@($result.Suggestions).Count)"
    }

    if ($case.Expected.PSObject.Properties['SuppressedCount']) {
        Add-TestResult -Name "$($case.Name): suppressed count" -Passed (@($result.SuppressedCandidates).Count -eq [int]$case.Expected.SuppressedCount) -Details "expected=$($case.Expected.SuppressedCount) actual=$(@($result.SuppressedCandidates).Count)"
    }

    if ($case.Expected.PSObject.Properties['SuppressedType']) {
        $suppressedType = if (@($result.SuppressedCandidates).Count -gt 0) { [string]$result.SuppressedCandidates[0].Type } else { '' }
        Add-TestResult -Name "$($case.Name): suppressed type" -Passed ($suppressedType -eq [string]$case.Expected.SuppressedType) -Details "actual=$suppressedType"
    }

    if ($case.Expected.PSObject.Properties['FirstSuggestionType']) {
        $firstType = if (@($result.Suggestions).Count -gt 0) { [string]$result.Suggestions[0].Type } else { '' }
        Add-TestResult -Name "$($case.Name): first suggestion type" -Passed ($firstType -eq [string]$case.Expected.FirstSuggestionType) -Details "actual=$firstType"
    }

    if ($case.Expected.PSObject.Properties['ContainsSuggestionCommand']) {
        $commands = @($result.Suggestions | ForEach-Object { [string]$_.Command })
        Add-TestResult -Name "$($case.Name): expected suggestion command" -Passed (Test-ContainsText -Haystacks $commands -Needle ([string]$case.Expected.ContainsSuggestionCommand))
    }

    if ($case.Expected.PSObject.Properties['ContainsSuggestionValue']) {
        $values = @($result.Suggestions | ForEach-Object { [string]$_.Value })
        Add-TestResult -Name "$($case.Name): expected suggestion value" -Passed (Test-ContainsText -Haystacks $values -Needle ([string]$case.Expected.ContainsSuggestionValue))
    }

    if ($case.Expected.PSObject.Properties['SuppressedCommandContains']) {
        $suppressedCommands = @($result.SuppressedCandidates | ForEach-Object { @($_.Commands) })
        foreach ($needle in @($case.Expected.SuppressedCommandContains)) {
            Add-TestResult -Name "$($case.Name): suppressed command contains $needle" -Passed (Test-ContainsText -Haystacks $suppressedCommands -Needle ([string]$needle))
        }
    }
}

if ($contextualDemoCase -and $contextualDemoResult) {
    Write-Host "Generating contextual exclusion demo artifact..." -ForegroundColor Cyan
    $demoDir = Join-Path $OutputRoot 'contextual-demo'
    New-Item -ItemType Directory -Path $demoDir -Force | Out-Null

    $contextualSuggestion = @(
        $contextualDemoResult.Suggestions |
        Where-Object { [string]$_.Command -like '*PathType:file*' } |
        Select-Object -First 1
    )
    $contextualSuggestionItem = if (@($contextualSuggestion).Count -gt 0) { $contextualSuggestion[0] } else { $null }

    $demoObject = [ordered]@{
        ScenarioName = $contextualDemoCase.Name
        Purpose      = 'Offline proof artifact showing the contextual file-pattern exclusion branch.'
        InputSummary = [ordered]@{
            Extension                    = $contextualDemoCase.Input.PerfReport.TopExtensions[0].Extension
            DominantFolder               = 'D:\Build\project\obj\Debug'
            TrustedProcessPath           = $contextualDemoCase.Input.PerfReport.TopProcesses[0].Process
            ContextualExclusionsSupported = [bool]$contextualDemoCase.Input.ContextualExclusionsSupported
            ValidateLoad                 = [bool]$contextualDemoCase.Input.ValidateLoad
        }
        OutputSummary = [ordered]@{
            SuggestionCount        = @($contextualDemoResult.Suggestions).Count
            SuppressedCount        = @($contextualDemoResult.SuppressedCandidates).Count
            ContextualSuggestion   = $contextualSuggestionItem
            AllSuggestions         = @($contextualDemoResult.Suggestions)
            TopScanContexts        = @($contextualDemoResult.TopScanContexts)
            ExtensionHotspots      = @($contextualDemoResult.ExtensionHotspots)
        }
    }

    $demoJsonFile = Join-Path $demoDir 'contextual_exclusion_demo.json'
    $demoHtmlFile = Join-Path $demoDir 'contextual_exclusion_demo.html'
    $demoObject | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $demoJsonFile -Encoding utf8

    $commandText = if ($contextualSuggestionItem) { [string]$contextualSuggestionItem.Command } else { '' }
    $valueText = if ($contextualSuggestionItem) { [string]$contextualSuggestionItem.Value } else { '' }
    $reasonText = if ($contextualSuggestionItem) { [string]$contextualSuggestionItem.Reason } else { '' }
    $scopeText = if ($contextualSuggestionItem) { [string]$contextualSuggestionItem.Scope } else { '' }
    $preferenceText = if ($contextualSuggestionItem) { [string]$contextualSuggestionItem.Preference } else { '' }
    $fallbackText = if ($contextualSuggestionItem) { (@($contextualSuggestionItem.Fallbacks) -join "`n") } else { '' }
    $relativeShareText = if ($contextualSuggestionItem) { [string]$contextualSuggestionItem.RelativeSharePercent } else { '' }

    $demoHtml = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Contextual Exclusion Demo</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; background: #0f172a; color: #e5e7eb; }
.card { background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 16px; margin-bottom: 16px; }
code, pre { color: #bfdbfe; white-space: pre-wrap; }
h1, h2 { color: #f8fafc; }
</style>
</head>
<body>
<h1>Contextual Exclusion Demo</h1>
<div class="card">
  <strong>Scenario</strong><br/>
  Trusted builder process accessing a safe build folder with contextual exclusions supported.
</div>
<div class="card">
  <strong>Recommended value</strong><br/>
  <code>$(HtmlEncode $valueText)</code>
</div>
<div class="card">
  <strong>Recommended command</strong>
  <pre>$(HtmlEncode $commandText)</pre>
</div>
<div class="card">
  <strong>Reason</strong><br/>
  $(HtmlEncode $reasonText)<br/><br/>
  <strong>Scope</strong><br/>
  $(HtmlEncode $scopeText)<br/><br/>
  <strong>Preference</strong><br/>
  $(HtmlEncode $preferenceText)<br/><br/>
  <strong>Relative share</strong><br/>
  $(HtmlEncode $relativeShareText)%<br/><br/>
  <strong>Fallbacks</strong><br/>
  <pre>$(HtmlEncode $fallbackText)</pre>
</div>
<div class="card">
  <strong>Input summary</strong><br/>
  Extension: <code>$(HtmlEncode ([string]$demoObject.InputSummary.Extension))</code><br/>
  Folder: <code>$(HtmlEncode ([string]$demoObject.InputSummary.DominantFolder))</code><br/>
  Process: <code>$(HtmlEncode ([string]$demoObject.InputSummary.TrustedProcessPath))</code>
</div>
</body>
</html>
"@
    $demoHtml | Out-File -LiteralPath $demoHtmlFile -Encoding utf8

    Add-TestResult -Name 'Contextual demo JSON created' -Passed (Test-Path -LiteralPath $demoJsonFile -PathType Leaf)
    Add-TestResult -Name 'Contextual demo HTML created' -Passed (Test-Path -LiteralPath $demoHtmlFile -PathType Leaf)
    Add-TestResult -Name 'Contextual demo command is contextual file-pattern syntax' -Passed (($commandText -like '*PathType:file*') -and ($commandText -like '*Process:"D:\Tools\builder.exe"*'))
    Add-TestResult -Name 'Contextual demo preference label present' -Passed ($preferenceText -eq 'Tier 1 - Preferred contextual file-pattern recommendation')
    Add-TestResult -Name 'Contextual demo relative share present' -Passed (-not [string]::IsNullOrWhiteSpace($relativeShareText))
    Add-TestResult -Name 'Contextual demo fallback ladder present' -Passed ($fallbackText -like '*Tier 4 - Exact process fallback*')
}

Write-Host "Running offline CAB fixture..." -ForegroundColor Cyan
$cabFixtureDir = Join-Path $scriptDir 'tests\fixtures\cab-basic'
$cabIntel = Get-DefenderCabIntelligenceFromExtractedDirectory -ExtractedDirectory $cabFixtureDir
Add-TestResult -Name 'CAB fixture: platform version parsed' -Passed ((Get-Prop (Get-Prop $cabIntel 'PlatformVersions') 'DefenderPlatformVersion') -eq '4.18.26020.6-0')
Add-TestResult -Name 'CAB fixture: network protection mode parsed' -Passed ((Get-Prop (Get-Prop $cabIntel 'NetworkProtection') 'Mode') -eq 'block')
Add-TestResult -Name 'CAB fixture: security center products parsed' -Passed (@(Get-Prop $cabIntel 'SecurityCenterProducts').Count -eq 2)
Add-TestResult -Name 'CAB fixture: MPLog exclusions parsed' -Passed (@((Get-Prop (Get-Prop $cabIntel 'MPLogHighlights') 'ExclusionMentions').Paths).Count -eq 1)
Add-TestResult -Name 'CAB fixture: impact records parsed' -Passed (@(Get-Prop (Get-Prop $cabIntel 'MPLogHighlights') 'ImpactRecords').Count -ge 1)
Add-TestResult -Name 'CAB fixture: skip reasons parsed' -Passed ((Get-Prop (Get-Prop $cabIntel 'ScanSkips') 'TotalSkipped') -eq 3)
Add-TestResult -Name 'CAB fixture: filter drivers parsed' -Passed (@(Get-Prop $cabIntel 'FilterDrivers').Count -eq 2)
Add-TestResult -Name 'CAB fixture: IFEO debugger parsed' -Passed (@(Get-Prop $cabIntel 'IFEODebuggerHijacks').Count -eq 1)

Write-Host "Running compare-mode fixture..." -ForegroundColor Cyan
$baselineReport = Join-Path $scriptDir 'tests\fixtures\report-compare\baseline.json'
$currentReport = Join-Path $scriptDir 'tests\fixtures\report-compare\current.json'
$compareOutput = Join-Path $OutputRoot 'compare'
New-Item -ItemType Directory -Path $compareOutput -Force | Out-Null
& $compareScript -BaselineReport $baselineReport -CurrentReport $currentReport -OutputPath $compareOutput -NoOpenReport

$compareJson = Get-ChildItem -Path $compareOutput -Filter 'DefenderPerfCompare_*.json' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
Add-TestResult -Name 'Compare fixture: JSON output created' -Passed ($null -ne $compareJson)
if ($compareJson) {
    $compareResult = Get-Content -LiteralPath $compareJson.FullName -Raw | ConvertFrom-Json
    Add-TestResult -Name 'Compare fixture: suggestion addition detected' -Passed (([int]$compareResult.Summary.AddedSuggestions) -ge 1)
    Add-TestResult -Name 'Compare fixture: CAB change detected' -Passed (@($compareResult.CABIntelligenceChanges | Where-Object { $_.Field -eq 'NetworkProtection.Mode' }).Count -eq 1)
    Add-TestResult -Name 'Compare fixture: hotspot change detected' -Passed (@($compareResult.ExtensionHotspotChanges | Where-Object { $_.Extension -eq '.pdb' }).Count -eq 1)
}

$result = [ordered]@{
    GeneratedAt = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    OutputRoot  = (Resolve-Path -LiteralPath $OutputRoot).Path
    Passed      = $pass
    Failed      = $fail
    Total       = $tests.Count
    Tests       = @($tests)
}
$resultFile = Join-Path $OutputRoot 'offline_fixture_test_result.json'
$result | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $resultFile -Encoding utf8

Write-Host ""
Write-Host "Offline fixture tests complete. Passed=$pass Failed=$fail" -ForegroundColor Cyan
Write-Host "Result file: $resultFile" -ForegroundColor Gray

if ($fail -gt 0) {
    exit 1
}
