function Register-HealthMonitorTask {
    <#
    .SYNOPSIS
    Registers a scheduled task that runs Start-HealthMonitor as SYSTEM on an interval.

    .DESCRIPTION
    Must run elevated. Before registering, it refuses to continue if anyone
    other than SYSTEM, Administrators or TrustedInstaller can change or owns
    the module folder, the threshold file or the PowerShell executable. A SYSTEM task that loads user-writable code is a direct
    local privilege escalation (MITRE T1053.005 with weak file permissions).

    It then creates the output folder with an explicit ACL (SYSTEM and
    Administrators full control, Users read), registers the Application event
    log source, and registers the task.

    The task command line is plain text (-Command, not -EncodedCommand) so it
    reads clearly in process creation logs (Security 4688, Sysmon 1) and does
    not look like an attacker's encoded launcher.

    .PARAMETER IntervalMinutes
    How often the task runs.

    .PARAMETER OutputPath
    Output folder for the task. Default C:\ProgramData\WindowsHealthMonitor.

    .PARAMETER ThresholdPath
    Optional threshold override file. Must not be user-writable.

    .PARAMETER TaskName
    Scheduled task name.

    .PARAMETER UsePowerShell7
    Run the task with pwsh.exe instead of Windows PowerShell 5.1.

    .EXAMPLE
    Register-HealthMonitorTask -IntervalMinutes 15 -WhatIf

    .EXAMPLE
    Register-HealthMonitorTask -IntervalMinutes 15 -ThresholdPath 'C:\ProgramData\WindowsHealthMonitor\thresholds.psd1'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [ValidateRange(5, 1440)][int]$IntervalMinutes = 15,
        [string]$OutputPath = (Join-Path -Path ([System.Environment]::GetFolderPath('CommonApplicationData')) -ChildPath 'WindowsHealthMonitor'),
        [string]$ThresholdPath,
        [ValidatePattern('^[A-Za-z0-9 ._-]+$')][string]$TaskName = 'WindowsHealthMonitor',
        [switch]$UsePowerShell7
    )

    if (-not (Test-WhmWindowsHost)) { throw 'Register-HealthMonitorTask runs on Windows only.' }
    if (-not (Test-WhmElevated)) { throw 'Register-HealthMonitorTask must run from an elevated session.' }

    # The task runs with SYSTEM's working directory, so a relative path would land somewhere else.
    $OutputPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    $moduleRoot = $script:WhmModuleRoot
    $manifest = Join-Path -Path $moduleRoot -ChildPath 'WindowsHealthMonitor.psd1'

    $exe = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if ($UsePowerShell7) {
        $pwsh = Get-Command -Name 'pwsh.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $pwsh) { throw 'pwsh.exe not found on PATH. Install PowerShell 7 or omit -UsePowerShell7.' }
        $exe = $pwsh.Source
    }

    # Every path SYSTEM will load or execute.
    $checkPaths = @($moduleRoot, $exe)
    if ($ThresholdPath) {
        if (-not (Test-Path -LiteralPath $ThresholdPath -PathType Leaf)) { throw "Threshold file not found: $ThresholdPath" }
        $ThresholdPath = (Resolve-Path -LiteralPath $ThresholdPath).ProviderPath
        # Validate the file parses and has no unknown keys before SYSTEM uses it.
        $null = Get-HealthThreshold -Path $ThresholdPath
        $checkPaths += $ThresholdPath
    }

    $exposed = @($checkPaths | ForEach-Object { Get-WhmUntrustedWriteAccess -Path $_ })
    if ($exposed.Count -gt 0) {
        $detail = ($exposed | ForEach-Object { "  $($_.Path): $($_.Identity) has $($_.Rights)" }) -join [System.Environment]::NewLine
        throw ("Refusing to register a SYSTEM task that loads files non-admin principals can change:" + [System.Environment]::NewLine + $detail + [System.Environment]::NewLine +
            "Install the module with Install.ps1 from the repo (sets an admin-only ACL and owner) and keep the threshold file in an admin-only folder.")
    }

    # Single quotes delimit paths in the -Command string, so they cannot appear inside them.
    foreach ($p in @($manifest, $OutputPath, $ThresholdPath)) {
        if ($p -and $p.Contains("'")) { throw "Path contains a single quote, which the task command line cannot carry: $p" }
    }

    $command = "Import-Module -Name '$manifest' -Force; Start-HealthMonitor -Count 1 -OutputPath '$OutputPath' -WriteEventLog"
    if ($ThresholdPath) { $command += " -ThresholdPath '$ThresholdPath'" }
    # RemoteSigned for this process only. Group Policy (MachinePolicy) still wins.
    $arguments = "-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -Command `"$command`""

    if (-not $PSCmdlet.ShouldProcess("$TaskName (SYSTEM, every $IntervalMinutes min): $exe $arguments", 'Register scheduled task')) {
        return
    }

    # Output folder: replace the inherited ProgramData ACL, which lets Users
    # create files, with an explicit one. SIDs avoid localised group names.
    if (-not (Test-Path -LiteralPath $OutputPath -PathType Container)) {
        $null = New-Item -Path $OutputPath -ItemType Directory -Force
    }
    $null = & icacls.exe $OutputPath /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to set permissions on $OutputPath (exit code $LASTEXITCODE)." }
    $null = & icacls.exe $OutputPath /setowner '*S-1-5-32-544' /T /C /Q
    if ($LASTEXITCODE -ne 0) { throw "icacls failed to set the owner on $OutputPath (exit code $LASTEXITCODE)." }

    Register-WhmEventSource -Source $script:WhmEventSource

    $action = New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -MultipleInstances IgnoreNew -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description 'Windows Health Monitor: health and security posture checks. https://github.com/Hawkode/Windows-Health-Monitor' -Force
}
