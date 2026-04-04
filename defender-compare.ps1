#Requires -Version 5.1
<#
.SYNOPSIS
    Compare two Defender performance advisor JSON reports.

.DESCRIPTION
    Diffs two saved report JSON files and highlights what changed in discovered
    exclusions, recommendation output, extension hotspots, scan contexts, and
    CAB-derived intelligence. Produces both JSON and HTML comparison reports.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$BaselineReport,
    [Parameter(Mandatory)][string]$CurrentReport,
    [string]$OutputPath,
    [switch]$NoOpenReport
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$reportLib = Join-Path $scriptDir 'defender-report-lib.ps1'
if (-not (Test-Path -LiteralPath $reportLib)) {
    throw "Shared report library not found: $reportLib"
}
. $reportLib

function HtmlEncode([string]$Value) {
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function Read-ReportJson([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Report file not found: $Path"
    }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-StringSetDelta([object[]]$BaselineItems, [object[]]$CurrentItems, [ScriptBlock]$Selector) {
    $baseline = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $current = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($item in @($BaselineItems)) {
        $value = [string](& $Selector $item)
        if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$baseline.Add($value) }
    }
    foreach ($item in @($CurrentItems)) {
        $value = [string](& $Selector $item)
        if (-not [string]::IsNullOrWhiteSpace($value)) { [void]$current.Add($value) }
    }

    return [PSCustomObject]@{
        Added   = @($current | Where-Object { -not $baseline.Contains($_) } | Sort-Object)
        Removed = @($baseline | Where-Object { -not $current.Contains($_) } | Sort-Object)
    }
}

function Convert-ComparableArray([object[]]$Items) {
    if (-not $Items) { return '' }
    $values = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @($Items)) {
        if ($item -is [string] -or $item -is [ValueType]) {
            $values.Add([string]$item)
            continue
        }
        if (Get-Prop $item 'DisplayName') {
            $values.Add([string]$item.DisplayName)
            continue
        }
        if (Get-Prop $item 'Name') {
            $values.Add([string]$item.Name)
            continue
        }
        if (Get-Prop $item 'Path') {
            $values.Add([string]$item.Path)
            continue
        }
        if (Get-Prop $item 'TargetPath') {
            $values.Add([string]$item.TargetPath)
            continue
        }
        $values.Add(($item | ConvertTo-Json -Compress -Depth 6))
    }
    return (@($values | Sort-Object) -join '; ')
}

function Add-CabChangeRows {
    param(
        [System.Collections.Generic.List[object]]$Rows,
        [string]$Prefix,
        $BaselineValue,
        $CurrentValue
    )

    $baselineIsObject = $BaselineValue -and ($BaselineValue -isnot [string]) -and ($BaselineValue -isnot [ValueType]) -and ($BaselineValue -isnot [System.Array]) -and $BaselineValue.PSObject
    $currentIsObject = $CurrentValue -and ($CurrentValue -isnot [string]) -and ($CurrentValue -isnot [ValueType]) -and ($CurrentValue -isnot [System.Array]) -and $CurrentValue.PSObject

    if ($baselineIsObject -or $currentIsObject) {
        $propertyNames = @(
            @($BaselineValue.PSObject.Properties.Name)
            @($CurrentValue.PSObject.Properties.Name)
        ) | Where-Object { $_ } | Sort-Object -Unique

        foreach ($propertyName in $propertyNames) {
            Add-CabChangeRows -Rows $Rows -Prefix "$Prefix.$propertyName" -BaselineValue (Get-Prop $BaselineValue $propertyName) -CurrentValue (Get-Prop $CurrentValue $propertyName)
        }
        return
    }

    $baselineText = if ($BaselineValue -is [System.Array]) { Convert-ComparableArray $BaselineValue } else { [string]$BaselineValue }
    $currentText = if ($CurrentValue -is [System.Array]) { Convert-ComparableArray $CurrentValue } else { [string]$CurrentValue }

    $baselineComparable = if ($null -ne $baselineText) { $baselineText } else { '' }
    $currentComparable = if ($null -ne $currentText) { $currentText } else { '' }

    if ($baselineComparable -ne $currentComparable) {
        $Rows.Add([PSCustomObject]@{
                Field    = $Prefix.TrimStart('.')
                Baseline = $baselineText
                Current  = $currentText
            })
    }
}

function Get-KeyedMap([object[]]$Items, [ScriptBlock]$Selector) {
    $map = @{}
    foreach ($item in @($Items)) {
        $key = [string](& $Selector $item)
        if ([string]::IsNullOrWhiteSpace($key)) { continue }
        $map[$key] = $item
    }
    return $map
}

function Get-HotspotChanges([object[]]$BaselineHotspots, [object[]]$CurrentHotspots) {
    $rows = [System.Collections.Generic.List[object]]::new()
    $baselineMap = Get-KeyedMap -Items $BaselineHotspots -Selector { param($item) if (Get-Prop $item 'RawExtension') { $item.RawExtension } else { Normalize-Extension (Get-Prop $item 'Extension') } }
    $currentMap = Get-KeyedMap -Items $CurrentHotspots -Selector { param($item) if (Get-Prop $item 'RawExtension') { $item.RawExtension } else { Normalize-Extension (Get-Prop $item 'Extension') } }
    $keys = @($baselineMap.Keys + $currentMap.Keys | Sort-Object -Unique)

    foreach ($key in $keys) {
        $baseline = $baselineMap[$key]
        $current = $currentMap[$key]
        $baselineDuration = if ($baseline) { [double](Get-Prop $baseline 'TotalDurationMs') } else { 0 }
        $currentDuration = if ($current) { [double](Get-Prop $current 'TotalDurationMs') } else { 0 }
        $baselineCount = if ($baseline) { [int](Get-Prop $baseline 'Count') } else { 0 }
        $currentCount = if ($current) { [int](Get-Prop $current 'Count') } else { 0 }
        $baselineFolder = if ($baseline) { [string](Get-Prop $baseline 'DominantFolderPath') } else { '' }
        $currentFolder = if ($current) { [string](Get-Prop $current 'DominantFolderPath') } else { '' }

        if ($baselineDuration -ne $currentDuration -or $baselineCount -ne $currentCount -or $baselineFolder -ne $currentFolder) {
            $rows.Add([PSCustomObject]@{
                    Extension            = Format-ExtensionDisplay $key
                    BaselineDuration     = Format-Duration $baselineDuration
                    CurrentDuration      = Format-Duration $currentDuration
                    DurationDeltaMs      = [math]::Round(($currentDuration - $baselineDuration), 2)
                    BaselineCount        = $baselineCount
                    CurrentCount         = $currentCount
                    BaselineDominantFolder = $baselineFolder
                    CurrentDominantFolder  = $currentFolder
                })
        }
    }

    return @($rows | Sort-Object { [math]::Abs([double]$_.DurationDeltaMs) } -Descending)
}

function Get-ScanContextChanges([object[]]$BaselineContexts, [object[]]$CurrentContexts) {
    $selector = {
        param($item)
        '{0}|{1}|{2}' -f ([string](Get-Prop $item 'TargetPath')), ([string](Get-Prop $item 'ProcessPath')), ([string](Get-Prop $item 'ScanType'))
    }
    return Get-StringSetDelta -BaselineItems $BaselineContexts -CurrentItems $CurrentContexts -Selector $selector
}

function Get-SummaryBlock($Report, [string]$Path) {
    $metadata = Get-Prop $Report 'ReportMetadata'
    return [ordered]@{
        Path        = (Resolve-Path -LiteralPath $Path).Path
        GeneratedAt = Get-Prop $metadata 'GeneratedAt'
        Computer    = Get-Prop $metadata 'ComputerName'
        DurationSec = Get-Prop $metadata 'RecordDuration'
        StrictCAB   = Get-Prop $metadata 'StrictCAB'
    }
}

$baseline = Read-ReportJson $BaselineReport
$current = Read-ReportJson $CurrentReport

if (-not $OutputPath) {
    $OutputPath = Split-Path -Parent (Resolve-Path -LiteralPath $CurrentReport).Path
}
if (-not (Test-Path -LiteralPath $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$exclusionDiscovery = [ordered]@{
    Paths      = Get-StringSetDelta -BaselineItems @($baseline.ExclusionDiscovery.Paths) -CurrentItems @($current.ExclusionDiscovery.Paths) -Selector { param($item) $item }
    Processes  = Get-StringSetDelta -BaselineItems @($baseline.ExclusionDiscovery.Processes) -CurrentItems @($current.ExclusionDiscovery.Processes) -Selector { param($item) $item }
    Extensions = Get-StringSetDelta -BaselineItems @($baseline.ExclusionDiscovery.Extensions) -CurrentItems @($current.ExclusionDiscovery.Extensions) -Selector { param($item) (Format-ExtensionDisplay $item) }
}

$suggestionChanges = Get-StringSetDelta -BaselineItems @($baseline.ExclusionSuggestions) -CurrentItems @($current.ExclusionSuggestions) -Selector { param($item) '{0}|{1}|{2}' -f ([string]$item.Type), ([string]$item.Value), ([string]$item.Command) }
$suppressedChanges = Get-StringSetDelta -BaselineItems @($baseline.SuppressedCandidates) -CurrentItems @($current.SuppressedCandidates) -Selector { param($item) '{0}|{1}' -f ([string]$item.Type), ([string]$item.Value) }
$hotspotChanges = Get-HotspotChanges -BaselineHotspots @($baseline.ExtensionHotspots) -CurrentHotspots @($current.ExtensionHotspots)
$scanContextChanges = Get-ScanContextChanges -BaselineContexts @($baseline.TopScanContexts) -CurrentContexts @($current.TopScanContexts)
$cabRows = [System.Collections.Generic.List[object]]::new()
Add-CabChangeRows -Rows $cabRows -Prefix '' -BaselineValue $baseline.CABIntelligence -CurrentValue $current.CABIntelligence
$cabChanges = @($cabRows | Sort-Object Field)

$summary = [ordered]@{
    ComparedAt               = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    AddedDiscoveredItems     = @($exclusionDiscovery.Paths.Added + $exclusionDiscovery.Processes.Added + $exclusionDiscovery.Extensions.Added).Count
    RemovedDiscoveredItems   = @($exclusionDiscovery.Paths.Removed + $exclusionDiscovery.Processes.Removed + $exclusionDiscovery.Extensions.Removed).Count
    AddedSuggestions         = @($suggestionChanges.Added).Count
    RemovedSuggestions       = @($suggestionChanges.Removed).Count
    AddedSuppressedCandidates = @($suppressedChanges.Added).Count
    RemovedSuppressedCandidates = @($suppressedChanges.Removed).Count
    HotspotChanges           = @($hotspotChanges).Count
    ScanContextAdds          = @($scanContextChanges.Added).Count
    ScanContextRemovals      = @($scanContextChanges.Removed).Count
    CABFieldChanges          = @($cabChanges).Count
}

$compareResult = [ordered]@{
    Summary                    = $summary
    Baseline                   = Get-SummaryBlock -Report $baseline -Path $BaselineReport
    Current                    = Get-SummaryBlock -Report $current -Path $CurrentReport
    ExclusionDiscoveryChanges  = $exclusionDiscovery
    RecommendationChanges      = [ordered]@{
        Added   = @($suggestionChanges.Added)
        Removed = @($suggestionChanges.Removed)
    }
    SuppressedCandidateChanges = [ordered]@{
        Added   = @($suppressedChanges.Added)
        Removed = @($suppressedChanges.Removed)
    }
    ExtensionHotspotChanges    = @($hotspotChanges)
    ScanContextChanges         = [ordered]@{
        Added   = @($scanContextChanges.Added)
        Removed = @($scanContextChanges.Removed)
    }
    CABIntelligenceChanges     = @($cabChanges)
}

$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$jsonFile = Join-Path $OutputPath "DefenderPerfCompare_$runId.json"
$htmlFile = Join-Path $OutputPath "DefenderPerfCompare_$runId.html"
$compareResult | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonFile -Encoding utf8

$listToHtml = {
    param([object[]]$Items)
    if (-not $Items -or @($Items).Count -eq 0) { return '<p style="color:#94a3b8">No changes.</p>' }
    return (@($Items | ForEach-Object { "<li>$(HtmlEncode ([string]$_))</li>" }) -join '')
}

$hotspotRows = if ($hotspotChanges.Count -gt 0) {
    @($hotspotChanges | Select-Object -First 20 | ForEach-Object {
            "<tr><td>$(HtmlEncode $_.Extension)</td><td>$(HtmlEncode $_.BaselineDuration)</td><td>$(HtmlEncode $_.CurrentDuration)</td><td>$(HtmlEncode ([string]$_.DurationDeltaMs)) ms</td><td>$(HtmlEncode $_.BaselineDominantFolder)</td><td>$(HtmlEncode $_.CurrentDominantFolder)</td></tr>"
        }) -join ''
} else { '<tr><td colspan="6" style="color:#94a3b8">No hotspot changes.</td></tr>' }

$cabRowsHtml = if ($cabChanges.Count -gt 0) {
    @($cabChanges | Select-Object -First 40 | ForEach-Object {
            "<tr><td>$(HtmlEncode $_.Field)</td><td>$(HtmlEncode $_.Baseline)</td><td>$(HtmlEncode $_.Current)</td></tr>"
        }) -join ''
} else { '<tr><td colspan="3" style="color:#94a3b8">No CAB intelligence changes.</td></tr>' }

$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>Defender Report Compare</title>
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #e5e7eb; background: #0f172a; }
h1,h2 { color: #f8fafc; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-bottom: 24px; }
.card { background: #111827; border: 1px solid #334155; border-radius: 12px; padding: 14px; }
table { border-collapse: collapse; width: 100%; margin-top: 12px; }
th, td { border: 1px solid #334155; padding: 8px; vertical-align: top; }
th { background: #1e293b; text-align: left; }
code { color: #bfdbfe; }
</style>
</head>
<body>
<h1>Defender Report Compare</h1>
<p>Baseline: <code>$(HtmlEncode $compareResult.Baseline.Path)</code><br/>Current: <code>$(HtmlEncode $compareResult.Current.Path)</code></p>
<div class="grid">
  <div class="card"><strong>Suggestions</strong><br/>Added: $($summary.AddedSuggestions)<br/>Removed: $($summary.RemovedSuggestions)</div>
  <div class="card"><strong>Suppressed</strong><br/>Added: $($summary.AddedSuppressedCandidates)<br/>Removed: $($summary.RemovedSuppressedCandidates)</div>
  <div class="card"><strong>Hotspots</strong><br/>Changed: $($summary.HotspotChanges)</div>
  <div class="card"><strong>CAB Fields</strong><br/>Changed: $($summary.CABFieldChanges)</div>
</div>
<h2>Discovered Exclusions</h2>
<p><strong>Added</strong></p><ul>$(& $listToHtml ($exclusionDiscovery.Paths.Added + $exclusionDiscovery.Processes.Added + $exclusionDiscovery.Extensions.Added))</ul>
<p><strong>Removed</strong></p><ul>$(& $listToHtml ($exclusionDiscovery.Paths.Removed + $exclusionDiscovery.Processes.Removed + $exclusionDiscovery.Extensions.Removed))</ul>
<h2>Recommendation Output</h2>
<p><strong>Added</strong></p><ul>$(& $listToHtml $suggestionChanges.Added)</ul>
<p><strong>Removed</strong></p><ul>$(& $listToHtml $suggestionChanges.Removed)</ul>
<h2>Suppressed Validation-Only Candidates</h2>
<p><strong>Added</strong></p><ul>$(& $listToHtml $suppressedChanges.Added)</ul>
<p><strong>Removed</strong></p><ul>$(& $listToHtml $suppressedChanges.Removed)</ul>
<h2>Extension Hotspots</h2>
<table><tr><th>Extension</th><th>Baseline</th><th>Current</th><th>Delta</th><th>Baseline Folder</th><th>Current Folder</th></tr>$hotspotRows</table>
<h2>Scan Contexts</h2>
<p><strong>Added</strong></p><ul>$(& $listToHtml $scanContextChanges.Added)</ul>
<p><strong>Removed</strong></p><ul>$(& $listToHtml $scanContextChanges.Removed)</ul>
<h2>CAB Intelligence</h2>
<table><tr><th>Field</th><th>Baseline</th><th>Current</th></tr>$cabRowsHtml</table>
</body>
</html>
"@

$html | Out-File -LiteralPath $htmlFile -Encoding utf8
Write-Host "JSON compare report: $jsonFile" -ForegroundColor Green
Write-Host "HTML compare report: $htmlFile" -ForegroundColor Green

if (-not $NoOpenReport) {
    Start-Process $htmlFile
}
