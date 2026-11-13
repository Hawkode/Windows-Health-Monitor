# Changelog

## 2.0.0 - 2026-11-13
Rebuilt as a PowerShell module. v1 existed only as a script pasted into the README.

### Fixed (v1 bugs)
- **Memory figures were 1024 times too small.** `TotalVisibleMemorySize` and `FreePhysicalMemory` are in KB; v1 divided by `1MB` and labelled the result MB, which is actually GB.
- **Disks** came from `Get-PSDrive`, so mapped network drives were included and no free percentage was calculated. Now fixed local disks only (`Win32_LogicalDisk`, DriveType 3), with free %.
- **Network** reported "Connected" if any adapter was up, including Hyper-V switches and VPN adapters. Now physical adapters only.
- **CSV** recorded no disk data. It now has one summary row per run.
- **CPU** used a localised performance counter path (`\Processor(_Total)\% Processor Time`), which fails on non-English Windows. Now `Win32_Processor.LoadPercentage`.
- **No error handling.** One failing call stopped the whole script. Each collector now fails on its own and its check reports Unknown.
- **Infinite loop, unbounded log** in Documents. Now a single run by default, `-Count` for loops, daily files and retention.

### Added
- Security posture checks: Defender real-time protection, Tamper Protection and signature age; effective firewall profiles; pending reboot; patch age; event log clearing (Security 1102, System 104); BitLocker on the OS drive.
- Thresholds with Warning / Critical bands, an override file, and rejection of unknown keys.
- JSONL (full detail) and CSV (summary) output, UTF-8.
- Application event log output with stable event IDs per check and severity, plus a heartbeat (EID 1000) for "monitor went quiet" alerting.
- `Register-HealthMonitorTask`: SYSTEM scheduled task that refuses to register from paths non-admins can write to or own; hardened output folder ACL.
- `Install.ps1`: all-users install with admin owner and admin-only ACL.
- Pester tests (fixture-driven unit tests plus Windows integration tests) and CI: PSScriptAnalyzer on Ubuntu, Pester on Windows in PowerShell 5.1 and 7.

### Removed
- The v1 screenshots, which showed the old output format.
