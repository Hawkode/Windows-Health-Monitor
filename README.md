# Windows Health Monitor

[![ci](https://github.com/Hawkode/Windows-Health-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/Hawkode/Windows-Health-Monitor/actions/workflows/ci.yml)

PowerShell module that checks a Windows endpoint's health **and** security posture, judges each check against thresholds, and writes the result to JSONL, CSV and the Application event log for a SIEM.

Runs on Windows PowerShell 5.1 and PowerShell 7, on Windows 10/11 and Server 2016+. Read-only apart from its own output, event source and (optionally) one scheduled task.

> **Lab first.** Run it on a test machine before you deploy it. `Register-HealthMonitorTask` creates a task that runs as SYSTEM.

## What it checks

| Check | Source | Warning | Critical | Event IDs (OK / Warn / Crit / Unknown) |
|---|---|---|---|---|
| CPU | `Win32_Processor.LoadPercentage` | 85% | 95% | 1001 / 2001 / 3001 / 4001 |
| Memory | `Win32_OperatingSystem` | 85% used | 95% used | 1002 / 2002 / 3002 / 4002 |
| Disk (per fixed volume) | `Win32_LogicalDisk`, DriveType 3 | 15% free | 5% free | 1003 / 2003 / 3003 / 4003 |
| Uptime | `LastBootUpTime` | 30 days | 60 days | 1004 / 2004 / 3004 / 4004 |
| Network | `Get-NetAdapter -Physical` | no adapter up | | 1005 / 2005 / - / 4005 |
| Defender real-time protection | `Get-MpComputerStatus` | Tamper Protection off | RTP off | 1006 / 2006 / 3006 / 4006 |
| Defender signatures | `AntivirusSignatureAge` | 2 days | 7 days | 1007 / 2007 / 3007 / 4007 |
| Firewall | `Get-NetFirewallProfile -PolicyStore ActiveStore` | | any profile off | 1008 / 2008 / 3008 / 4008 |
| Pending reboot | CBS and Windows Update registry keys | reboot pending | | 1009 / 2009 / - / 4009 |
| Patch age | `Get-HotFix`, newest install date | 35 days | 60 days | 1010 / 2010 / 3010 / 4010 |
| Event log cleared | Security 1102, System 104 | | any in 24 h | 1011 / - / 3011 / 4011 |
| BitLocker (OS drive) | `Win32_EncryptableVolume` | | protection off | 1012 / - / 3012 / 4012 |

Event ID = severity base (1000 OK, 2000 Warning, 3000 Critical, 4000 Unknown) + check number. Every run also writes a **heartbeat, EID 1000**.

**Unknown is never OK.** If a check can't run (Defender module missing, not elevated, access denied), that check reports Unknown and gives the reason. The Security log and BitLocker checks need an elevated session, so an unelevated run reports them as Unknown.

## Install
Run in an **elevated** PowerShell window:

1. Get the code:
   ```powershell
   git clone https://github.com/Hawkode/Windows-Health-Monitor.git C:\Tools\Windows-Health-Monitor
   cd C:\Tools\Windows-Health-Monitor
   ```
   No Git? Download the zip, extract it, then run `Get-ChildItem -Recurse -File | Unblock-File` in the folder. Windows marks files from a downloaded zip as internet files, and `RemoteSigned` blocks them.
2. Allow local scripts for this window only. Windows 11 defaults to `Restricted`, which blocks every `.ps1` and `.psm1`:
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
   ```
   If Group Policy enforces `AllSigned`, sign the module with your organisation's code-signing certificate rather than loosening the policy.
3. Install for all users:
   ```powershell
   .\Install.ps1
   ```
   This copies the module to `C:\Program Files\WindowsPowerShell\Modules\WindowsHealthMonitor\2.0.0\`, sets the owner to Administrators, and sets an admin-only ACL (SYSTEM and Administrators full control, Users read). See [why the ACL matters](#attack-detect-harden).
4. Run a one-off check:
   ```powershell
   Import-Module WindowsHealthMonitor
   Get-HealthSnapshot | Test-HealthSnapshot | Format-Table Check, Target, Status, Message -AutoSize
   ```

## Use

| Command | What it does |
|---|---|
| `Get-HealthSnapshot` | Collects one snapshot. Read-only. |
| `Test-HealthSnapshot` | Judges a snapshot against thresholds and returns one finding per check. Pure logic, so it also works on saved snapshots. |
| `Get-HealthThreshold` | Returns the default thresholds, or defaults merged with an override file. |
| `Start-HealthMonitor` | Collects, judges and writes output. One run by default; `-Count 0` loops until Ctrl+C. `-WhatIf` writes nothing. |
| `Register-HealthMonitorTask` | Creates a SYSTEM scheduled task that runs `Start-HealthMonitor -WriteEventLog` on an interval. |
| `Unregister-HealthMonitorTask` | Removes the task. Keeps the output. |

Show only problems:
```powershell
Get-HealthSnapshot | Test-HealthSnapshot | Where-Object Status -ne 'OK'
```

Watch a machine every 60 seconds while you troubleshoot:
```powershell
Start-HealthMonitor -Count 0 -IntervalSeconds 60 -OutputPath C:\Temp\whm -Verbose
```

Run every 15 minutes as SYSTEM, writing to the Application log:
```powershell
Register-HealthMonitorTask -IntervalMinutes 15 -WhatIf   # shows the exact command line
Register-HealthMonitorTask -IntervalMinutes 15
```
The task runs `powershell.exe -NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command "Import-Module -Name '<full path>' ..."`. It imports by full path, so a module planted earlier in `PSModulePath` cannot replace it. It uses plain `-Command` rather than `-EncodedCommand`, so the command line reads clearly in Security 4688 and Sysmon EID 1, and doesn't look like an attacker's encoded launcher.

Re-judge saved output with new thresholds:
```powershell
Get-Content C:\ProgramData\WindowsHealthMonitor\health-20261113.jsonl |
    ConvertFrom-Json |
    ForEach-Object { Test-HealthSnapshot -Snapshot $_.Snapshot -Threshold (Get-HealthThreshold -Path .\thresholds.local.psd1) }
```

## Thresholds
Defaults live in `WindowsHealthMonitor\Config\DefaultThresholds.psd1`. To change them, copy `thresholds.example.psd1` to `thresholds.local.psd1` (gitignored) and keep only the keys you change. Unknown keys throw, so a typo such as `CpuPercnt` fails instead of silently doing nothing.

For the scheduled task, install the override with the module so it gets the same admin-only ACL:
```powershell
.\Install.ps1 -ThresholdPath .\thresholds.local.psd1
Register-HealthMonitorTask -ThresholdPath 'C:\Program Files\WindowsPowerShell\Modules\WindowsHealthMonitor\thresholds.psd1'
```

| Key | Default | Notes |
|---|---|---|
| `RequireDefenderRealTime` | `$true` | Set `$false` where a third-party AV or EDR is primary and Defender runs in passive mode. Then check that product in its own console. |
| `RequireTamperProtection` | `$true` | Real-time protection on but Tamper Protection off is a Warning: a local admin can turn RTP off with `Set-MpPreference`. |
| `RequireAllFirewallProfiles` | `$true` | `$false` drops a disabled profile from Critical to Warning. |
| `RequireBitLocker` | `$true` | `$false` skips the check. |
| `IgnorePendingFileRename` | `$true` | Installers and AV updates set `PendingFileRenameOperations` all the time. Counting it makes the reboot check noisy. |
| `LogClearLookbackHours` | `24` | Match it to how often the task runs, or longer. |
| `RetentionDays` | `14` | Daily JSONL/CSV files older than this are deleted. `0` keeps everything. |

## Output
| File / log | Content |
|---|---|
| `health-yyyyMMdd.jsonl` | One line per run: full snapshot, findings, worst status. UTF-8 without BOM. |
| `health-yyyyMMdd.csv` | One summary row per run, for Excel or a trend chart. |
| Application log, source `WindowsHealthMonitor` | EID 1000 heartbeat every run, plus one entry per non-OK finding (IDs in the table above). Warning and Unknown as Warning entries, Critical as Error entries. |

Default output folder: `%LOCALAPPDATA%\WindowsHealthMonitor` for interactive runs, `C:\ProgramData\WindowsHealthMonitor` for the scheduled task. `Register-HealthMonitorTask` replaces that folder's inherited ACL, because `ProgramData` lets Users create files, which would let any user plant fake records.

### Splunk
With the Application log already forwarded by the Universal Forwarder (adjust the index to yours):

Critical findings in the last 24 hours:
```spl
index=wineventlog source="WinEventLog:Application" SourceName="WindowsHealthMonitor" EventCode>=3000 EventCode<4000 earliest=-24h
| stats latest(_time) as last_seen, values(Message) as findings by host
| convert ctime(last_seen)
```

Hosts whose monitor has gone quiet (no heartbeat in 45 minutes on a 15-minute task):
```spl
index=wineventlog source="WinEventLog:Application" SourceName="WindowsHealthMonitor" EventCode=1000 earliest=-7d
| stats latest(_time) as last_heartbeat by host
| where last_heartbeat < relative_time(now(), "-45m")
| convert ctime(last_heartbeat)
```
This only lists hosts that reported at least once in the last 7 days. To catch hosts that never reported, compare against an asset list, such as a Snipe-IT export loaded as a lookup.

## Attack, detect, harden
What an attacker on the endpoint does to the things this module watches, and what to look for.

| Technique | MITRE | What this module reports | Native evidence to correlate |
|---|---|---|---|
| Turn off Defender real-time protection | T1562.001 | DefenderRealTime Critical (3006) | Defender Operational log EID 5001 (RTP disabled), 5007 (configuration changed) |
| Turn off a firewall profile | T1562.004 | Firewall Critical (3008) | Security EID 4950 (needs MPSSVC rule-level policy change auditing) |
| Clear event logs to hide activity | T1070.001 | LogCleared Critical (3011) | Security EID 1102, System EID 104 |
| Stop, delete or break the monitor | T1562.001 | Missing heartbeat (EID 1000) | Security EID 4699 (task deleted, needs object access auditing), Task Scheduler Operational EID 141 |
| Replace the files a SYSTEM task loads | T1053.005 | `Register-HealthMonitorTask` refuses to register | Security EID 4698 / 4702 (task created / updated), file integrity monitoring on the module folder |

Hardening built in:
- **No SYSTEM task from a writable path.** `Register-HealthMonitorTask` checks the module folder, the threshold file and the PowerShell executable. It refuses to register if anyone other than SYSTEM, Administrators or TrustedInstaller has write-type rights or **owns** any of them. Owners get implicit WRITE_DAC, so a file copied by your admin account is writable by that account's *unelevated* processes. `Install.ps1` fixes both. The module loader dot-sources every `.ps1` in `Private\`, so create-file rights on the folder are enough for code execution as SYSTEM. This is the same misconfiguration class as the unquoted service path and weak service permissions in the [Windows PrivEsc lab](https://hawkode.github.io/projects/windows-privilege-escalation/).
- **Output folder ACL** replaced, so users can't plant or edit records.
- **Failures surface as Unknown**, so an attacker who breaks a collector (for example by removing the Defender module) raises a flag instead of producing a clean report.

Limits to be honest about:
- A local admin can stop the task, edit thresholds or clear the output. The heartbeat gap in the SIEM is the control for that, not anything on the host.
- The checks are point-in-time samples every N minutes. A change made and reverted between two runs is missed. Defender 5001 and Security 1102 in the SIEM catch those in real time.

## Limitations
- **CPU** is a single 1-second sample. A Critical CPU reading on its own is noise; look at the CSV trend.
- **Patch age** comes from `Get-HotFix` (CBS-installed updates). It shows whether a host is patching at all. It is not a missing-patch scan and does not prove Cyber Essentials' 14-day rule for high and critical updates. Use your patch management or vulnerability scanner for that.
- **Uptime:** with Fast Startup on (the Windows 11 default), Shut down does not reset `LastBootUpTime`; only Restart does. Laptops that are shut down every night can still show weeks of uptime.
- **Defender passive mode:** with a third-party AV or EDR as primary, Defender RTP is off by design. Set `RequireDefenderRealTime = $false` for those hosts.
- **Not an RMM or EDR.** It is a lightweight, auditable check for labs, servers outside your agent coverage, and as a cross-check on what your management tools report.

## Development
Tests run on Windows. CI runs PSScriptAnalyzer on Ubuntu, and Pester on `windows-latest` in both Windows PowerShell 5.1 and PowerShell 7.

```powershell
Install-Module Pester -RequiredVersion 5.9.1 -Scope CurrentUser -SkipPublisherCheck
Install-Module PSScriptAnalyzer -RequiredVersion 1.23.0 -Scope CurrentUser
Invoke-ScriptAnalyzer -Path . -Recurse -Settings .\PSScriptAnalyzerSettings.psd1
Invoke-Pester .\tests -Output Detailed
```
Or run `.\build\Invoke-Tests.ps1`, which installs the pinned Pester and runs the suite the same way CI does. Run Pester elevated to include the event log and ACL tests. Unelevated, they are skipped.

Unit tests use the JSON snapshots in `tests\fixtures\`, so the evaluation logic is tested without depending on the state of the test machine.

## Changes from v1
v1 was a single script pasted into this README. See [CHANGELOG.md](CHANGELOG.md) for what was fixed, including memory figures that were 1024 times too small.
