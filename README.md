# ms-defender

PowerShell tooling for Microsoft Defender Antivirus performance analysis, exclusion discovery, configuration review, and validation.

The main script is [defender.ps1](./defender.ps1). It is designed to run as Administrator on Windows and helps answer four practical questions:

1. Is Defender configured and running as expected?
2. Which files, processes, extensions, and scan contexts are driving scan overhead?
3. What exclusions already exist, and can they be discovered reliably?
4. If exclusions are needed, what is the narrowest reasonable Microsoft Defender Antivirus recommendation?

The preferred use case is an active workload or performance issue on the affected machine, especially on servers where the goal is to diagnose Defender impact first and avoid exclusions unless the evidence clearly supports a narrow, justified change.

## What The Project Does

`defender.ps1` performs an end-to-end Defender audit:

1. Optionally validates exclusion discovery by creating a temporary exclusion and checking whether each discovery method can find it.
2. Discovers current exclusions from `Get-MpPreference`, direct registry reads, and `MpCmdRun.exe -GetFiles` CAB extraction.
3. Extracts useful intelligence from `MpSupportFiles.cab`, including effective config, product health, network protection, scan skips, MPLog highlights, device control state, Security Center registrations, and related diagnostics.
4. Records a Defender performance trace with `New-MpPerformanceRecording`.
5. Optionally generates synthetic load during the recording to exercise the scan pipeline.
6. Analyzes the trace with `Get-MpPerformanceReport -Raw`.
7. Produces console output plus JSON and HTML reports.
8. Generates exclusion recommendations using a narrow-first approach:
   file-pattern path exclusions before broader folder or global extension exclusions
9. Suppresses unsafe or validation-only recommendations instead of promoting them into live exclusions.

## Design Intent

This is a Defender performance advisor, not a generic exclusion wizard.

- It is intended to be run during the real workload issue when possible, not only as an offline lab exercise.
- It is especially useful on servers where clients want to avoid exclusions unless there is strong evidence for a tightly scoped exception.
- Exclusions are treated as a last resort.
- Narrow path or file-pattern exclusions are preferred over broad folder or extension exclusions.
- Process or contextual exclusions are not recommended for Windows or other system binaries.
- Synthetic validation workload results can be surfaced for review, but not promoted into live recommendations.
- The tool is intended to support Microsoft Defender Antivirus tuning, not replace controls such as ASR, CFA, indicators, or Defender for Endpoint automation exclusions.

## Best Time To Run It

For the highest-value results, run the tool while the real issue is happening:

- during a backup, restore, compile, build, package, indexing, or archive-heavy workload
- during the actual server-side performance complaint, not only after the fact
- before adding exclusions, so you capture evidence first

Use `-ValidateLoad` when you are testing the tool itself, validating the reporting pipeline, or building confidence in a lab. For production troubleshooting, real workload evidence is preferred.

## Repository Contents

- [defender.ps1](./defender.ps1): main script
- [defender-workload.ps1](./defender-workload.ps1): synthetic build/cache/log style workload generator used by `-ValidateLoad`
- [defender-test.ps1](./defender-test.ps1): automated validation harness for the main script
- [defender-single-run.ps1](./defender-single-run.ps1): self-elevating one-shot runner that captures logs and a run summary
- [defender-validation-loop.ps1](./defender-validation-loop.ps1): self-elevating repeat-run loop harness
- [extract_cab.ps1](./extract_cab.ps1): standalone `MpSupportFiles.cab` extraction and inventory helper

## Requirements

- Windows 10, Windows 11, or Windows Server with Microsoft Defender Antivirus available
- Administrator rights for the main analysis flow
- Microsoft Defender Antivirus cmdlets and support tooling available on the machine
- PowerShell 5.1 or later

## Main Usage

Run the main script from an elevated PowerShell session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\defender.ps1
```

Recommended real-world server workflow:

```powershell
# Start this while the workload issue is actually happening.
Set-ExecutionPolicy -Scope Process Bypass
.\defender.ps1 -RecordingSeconds 300 -TopN 30 -ReportPath "C:\DefenderReports"
```

Validation workflow:

```powershell
# Use this when validating the tool or testing the reporting path.
.\defender.ps1 -RecordingSeconds 180 -ValidateLoad -ValidateExclusions -NoOpenReport
```

Useful examples:

```powershell
.\defender.ps1 -RecordingSeconds 300 -TopN 30
.\defender.ps1 -ValidateLoad -ValidateExclusions -VerboseCAB
.\defender.ps1 -RecordingSeconds 120 -ReportPath "C:\Reports"
.\defender.ps1 -RecordingSeconds 120 -AIMode
.\defender.ps1 -RecordingSeconds 180 -ValidateLoad -ValidateExclusions -NoOpenReport
```

Typical console flow:

```text
+==================================================================+
|  1 - Discovering Existing Exclusions                             |
+==================================================================+
  [OK]   Exclusions discovered via Get-MpPreference

+==================================================================+
|  5 - Recording Defender Performance                              |
+==================================================================+
  [info] Recording started for 180 seconds
  [info] Waiting for live workload activity

+==================================================================+
|  COMPLETE                                                       |
+==================================================================+
  [info] JSON report             : C:\Reports\DefenderPerf_20260403_171252.json
  [info] HTML report             : C:\Reports\DefenderPerf_20260403_171252.html
  [info] Transcript log          : C:\Reports\DefenderPerf_20260403_171252.transcript.log
```

## Main Script Options

### `defender.ps1`

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-RecordingSeconds` | `int` | `600` | Length of the Defender performance recording in seconds. Valid range: `10` to `900`. |
| `-TopN` | `int` | `25` | Number of top items to show in each impact category. Valid range: `5` to `100`. |
| `-ReportPath` | `string` | script directory | Directory where JSON, HTML, transcript, and related outputs are written. |
| `-ValidateLoad` | `switch` | off | Runs the synthetic workload during the recording so the tool has meaningful test data. |
| `-ValidateExclusions` | `switch` | off | Creates a temporary exclusion, checks discovery methods, and verifies cleanup. |
| `-VerboseCAB` | `switch` | off | Includes fuller `MpSupportFiles.cab` diagnostic extraction and display. |
| `-NoOpenReport` | `switch` | off | Prevents the generated HTML report from opening automatically. |
| `-AIMode` | `switch` | off | Generates an AI export JSON and review prompt alongside the normal report outputs. |

Typical output files:

```text
DefenderPerf_20260403_171252.json
DefenderPerf_20260403_171252.html
DefenderPerf_20260403_171252.transcript.log
DefenderPerf_20260403_171252.ai-export.json
DefenderPerf_20260403_171252.ai-prompt.md
```

Example JSON fields:

```json
{
  "ReportMetadata": {
    "GeneratedAt": "2026-04-03 17:12:52",
    "RecordDuration": 180,
    "SyntheticWorkload": true,
    "ExclusionValidation": true
  },
  "ExclusionSuggestions": [],
  "SuppressedCandidates": [
    {
      "Type": "ValidationOnlyPattern",
      "Value": ".cache @ synthetic workload folders",
      "Commands": [
        "Add-MpPreference -ExclusionPath 'C:\\Users\\User\\AppData\\Local\\Temp\\DefenderWorkload_...\\logs\\*.cache'"
      ]
    }
  ]
}
```

## Helper Script Options

### `defender-single-run.ps1`

Self-elevating wrapper around `defender.ps1` that launches one run, captures a UTF-8 log, and writes a `run_summary.json`.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-RecordingSeconds` | `int` | `120` | Recording duration passed to `defender.ps1`. |
| `-TopN` | `int` | `25` | Top item count passed to `defender.ps1`. |
| `-OutputRoot` | `string` | timestamped folder under script directory | Root folder for the run log, summary, and reports. |
| `-ValidateLoad` | `switch` | off | Enables synthetic workload during the run. |
| `-ValidateExclusions` | `switch` | off | Enables structured exclusion validation during the run. |
| `-AIMode` | `switch` | off | Enables AI export and AI prompt generation. |
| `-NoOpenReport` | `switch` | off | Prevents the final HTML report from opening automatically. |

Example:

```powershell
.\defender-single-run.ps1 -RecordingSeconds 180 -ValidateLoad -ValidateExclusions
```

Typical output:

```text
[2026-04-03 17:08:47] [START] Output root: C:\Runs\single_run_20260403_170847
[2026-04-03 17:08:47] [RUN] Launching defender.ps1 for 180s
[2026-04-03 17:12:53] [DONE] Summary written: C:\Runs\single_run_20260403_170847\run_summary.json
```

Example `run_summary.json`:

```json
{
  "RecordingSeconds": 180,
  "ValidateLoad": true,
  "ValidateExclusions": true,
  "ExitCode": 0,
  "JsonReport": "C:\\Runs\\single_run_20260403_170847\\DefenderPerf_20260403_171252.json",
  "HtmlReport": "C:\\Runs\\single_run_20260403_170847\\DefenderPerf_20260403_171252.html"
}
```

### `defender-validation-loop.ps1`

Self-elevating loop harness that repeatedly calls `defender-test.ps1` and maintains a `loop_summary.json`.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-Iterations` | `int` | `2` | Number of validation cycles to run. Valid range: `1` to `20`. |
| `-RecordingSeconds` | `int` | `180` | Recording duration per cycle. |
| `-TopN` | `int` | `25` | Top item count per cycle. |
| `-WaitMinutes` | `int` | `15` | Delay between validation runs. Valid range: `0` to `240`. |
| `-OutputRoot` | `string` | timestamped loop folder | Folder where cycle subfolders and `loop_summary.json` are written. |
| `-StopOnFailure` | `switch` | off | Stops the loop after the first failed cycle. |

Example:

```powershell
.\defender-validation-loop.ps1 -Iterations 3 -RecordingSeconds 180 -WaitMinutes 3
```

Typical output:

```text
[2026-04-03 13:47:20] [START] Running 3 cycle(s) with a 3 minute pause between runs.
[2026-04-03 13:47:20] [CYCLE] Starting cycle 1 of 3
[2026-04-03 13:55:10] [CYCLE] Starting cycle 2 of 3
[2026-04-03 14:03:02] [CYCLE] Starting cycle 3 of 3
```

Example output structure:

```text
validation_loop_20260403_134720\
  loop_summary.json
  cycle_01_20260403_134723\
  cycle_02_20260403_135110\
  cycle_03_20260403_135502\
```

### `defender-test.ps1`

Automated harness that runs `defender.ps1` with validation flags enabled, then checks the generated outputs and JSON structure.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-RecordingSeconds` | `int` | `20` | Recording duration for the test run. |
| `-TopN` | `int` | `15` | Top item count for the test run. |
| `-OutputRoot` | `string` | script directory | Root folder for test logs, reports, and validation result JSON. |
| `-AIMode` | `switch` | off | Enables AI export generation during the test run. |
| `-NoAutoClose` | `switch` | off | Keeps the harness window open at the end. |
| `-NoOpenReport` | `switch` | off | Prevents the generated HTML report from opening. |

Example:

```powershell
.\defender-test.ps1 -RecordingSeconds 180 -TopN 25 -OutputRoot C:\DefenderTestRuns -NoOpenReport
```

Typical output:

```text
================================================================
  DEFENDER PERFORMANCE TEST HARNESS
================================================================
  [+] Script execution -- Completed in 246.1s
  [+] JSON report valid -- 180.4 KB
  [+] HTML report created -- 46.8 KB
  [+] Structured exclusion validation details
```

Typical generated files:

```text
test_run_20260403_171252.log
test_result_20260403_171252.json
test_reports_20260403_171252\
```

### `defender-workload.ps1`

Synthetic workload generator used to create build, cache, archive, and log churn while Defender recording is active.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-DurationSeconds` | `int` | `30` | Length of the synthetic workload run. |
| `-WorkDir` | `string` | temp folder under `%TEMP%` | Root temporary directory for generated workload files. |

Example:

```powershell
.\defender-workload.ps1 -DurationSeconds 180
```

Typical output:

```text
[workload] Started - generating Defender scan activity for 180s
[workload] WorkDir: C:\Users\<User>\AppData\Local\Temp\DefenderWorkload_20260403_170947
[workload] Phase 1: Create hot build/cache/log files
[workload] Phase 2: Re-open, append, and mirror hot files
[workload] Phase 3: Child processes writing build/cache outputs
```

### `extract_cab.ps1`

Standalone helper for extracting and inventorying `MpSupportFiles.cab`.

| Parameter | Type | Default | Purpose |
| --- | --- | --- | --- |
| `-CabPath` | `string` | `C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab` | CAB file to extract. |
| `-LogPath` | `string` | `cab_contents.log` in script directory | Output log file for the extraction report. |

Example:

```powershell
.\extract_cab.ps1
.\extract_cab.ps1 -LogPath C:\Temp\cab_contents.log
```

Typical output:

```text
=== MpSupportFiles.cab Extraction Report ===
Date: 04/03/2026 17:09:18
CAB Path: C:\ProgramData\Microsoft\Windows Defender\Support\MpSupportFiles.cab
--- Extracting to: C:\Users\<User>\AppData\Local\Temp\MpSupportFiles_Extract_20260403_170918 ---
Extraction complete.
Log saved to: C:\Temp\cab_contents.log
```

## Outputs

The main script produces some or all of the following files in the report folder:

- `DefenderPerf_<timestamp>.json`
- `DefenderPerf_<timestamp>.html`
- `DefenderPerf_<timestamp>.transcript.log`
- `DefenderPerf_<timestamp>.ai-export.json`
- `DefenderPerf_<timestamp>.ai-prompt.md`

The helper wrappers can also produce:

- `single_run_<timestamp>.log`
- `run_summary.json`
- `test_run_<timestamp>.log`
- `test_result_<timestamp>.json`
- `loop_summary.json`

Example output folder layout:

```text
powershell-work\
  defender.ps1
  defender-test.ps1
  single_run_ai_mode_20260403_163700\
    DefenderPerf_20260403_163709.json
    DefenderPerf_20260403_163709.html
    DefenderPerf_20260403_163709.ai-export.json
    DefenderPerf_20260403_163709.ai-prompt.md
    run_summary.json
```

## Report Content

Depending on the run mode and available diagnostics, the generated report can include:

- current exclusion discovery results
- exclusion validation results
- Defender performance impact tables
- top scan contexts
- extension hotspots by folder and process
- live exclusion suggestions
- suppressed validation-only candidates
- effective configuration and product health
- network protection details
- device control state
- MPLog highlights
- scan skip analysis
- Security Center product registrations

## Notes On Recommendations

- Prefer capturing real workload evidence before considering exclusions.
- On servers, use the tool to justify avoiding exclusions unless there is a strong, narrow, defensible recommendation.
- Review every suggested exclusion before applying it.
- Prefer exact path or file-pattern scoping over broader exclusions.
- Avoid excluding system directories, scripting engines, or executable file types.
- Treat synthetic workload results as validation data, not production recommendations.
- Protect excluded folders with restrictive NTFS ACLs.

## License

This project is licensed under the MIT License. See [LICENSE](./LICENSE).
