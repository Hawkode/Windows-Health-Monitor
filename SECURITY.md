# Security policy

## Reporting a vulnerability
Report it privately through **Security > Report a vulnerability** on this repository. Do not open a public issue.

Include what you found, how to reproduce it, and which version is affected. Do not include output from a real host (host names, process lists, security posture).

You can expect an acknowledgement within 7 days. This is a personal project maintained in spare time, so fixes are best effort.

## Supported versions
Only the latest tagged release gets fixes.

## Design notes for reviewers
- Collection is read-only. The module writes only its own output folder, its Application event log source, and (if you call `Register-HealthMonitorTask`) one scheduled task.
- No network calls. Nothing leaves the host except through your own log forwarding.
- The scheduled task runs as SYSTEM. `Register-HealthMonitorTask` refuses to register if the module folder, threshold file or PowerShell executable can be changed or is owned by anyone other than SYSTEM, Administrators or TrustedInstaller. A bypass of that check is in scope for a report.
- The task command line is plain `-Command` with full paths, not `-EncodedCommand`, so it is auditable in process creation logs.
- Threshold files are loaded with `Import-PowerShellDataFile`, which only accepts data (no commands).
