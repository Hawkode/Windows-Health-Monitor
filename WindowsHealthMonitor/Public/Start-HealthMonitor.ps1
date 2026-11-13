function Start-HealthMonitor {
    <#
    .SYNOPSIS
    Collects and judges snapshots, then writes them to JSONL, CSV and optionally the Application event log.

    .DESCRIPTION
    Each run writes one line to health-yyyyMMdd.jsonl (full snapshot and
    findings) and one row to health-yyyyMMdd.csv (summary). Files older than
    RetentionDays are deleted.

    With -WriteEventLog, each run writes a heartbeat (Application log, source
    WindowsHealthMonitor, EID 1000) and one entry per non-OK finding. The
    event source is registered on first use, which needs an elevated session.

    The default is a single run (-Count 1), which suits a scheduled task.
    -Count 0 loops until stopped with Ctrl+C.

    -WhatIf collects and judges but writes nothing, and returns the records.

    .PARAMETER IntervalSeconds
    Pause between runs when -Count is not 1.

    .PARAMETER Count
    Number of runs. 0 runs until stopped.

    .PARAMETER OutputPath
    Folder for JSONL and CSV output. Created if missing.

    .PARAMETER ThresholdPath
    Optional threshold override file (.psd1).

    .PARAMETER WriteEventLog
    Also write a heartbeat and non-OK findings to the Application event log.

    .PARAMETER PassThru
    Return each run's record (Snapshot, Findings, WorstStatus) to the pipeline.

    .EXAMPLE
    Start-HealthMonitor -PassThru | Select-Object -ExpandProperty Findings | Format-Table Check, Target, Status, Message -AutoSize

    .EXAMPLE
    Start-HealthMonitor -Count 0 -IntervalSeconds 60 -OutputPath C:\Temp\whm
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param(
        [ValidateRange(10, 86400)][int]$IntervalSeconds = 300,
        [ValidateRange(0, 1000000)][int]$Count = 1,
        [string]$OutputPath = (Join-Path -Path ([System.Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'WindowsHealthMonitor'),
        [string]$ThresholdPath,
        [switch]$WriteEventLog,
        [switch]$PassThru
    )

    $threshold = Get-HealthThreshold -Path $ThresholdPath

    # .NET file APIs need a real filesystem path, not a PSDrive or relative path.
    $resolvedOutput = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)

    $canWrite = $PSCmdlet.ShouldProcess($resolvedOutput, 'Write health snapshots')
    if ($canWrite) {
        if (-not (Test-Path -LiteralPath $resolvedOutput -PathType Container)) {
            $null = New-Item -Path $resolvedOutput -ItemType Directory -Force
        }
        if ($WriteEventLog) { Register-WhmEventSource -Source $script:WhmEventSource }
    }

    $iteration = 0
    while ($true) {
        $iteration++

        $snapshot = Get-HealthSnapshot -LogClearLookbackHours $threshold.LogClearLookbackHours
        $findings = @(Test-HealthSnapshot -Snapshot $snapshot -Threshold $threshold)
        $record = [pscustomobject]@{
            Snapshot    = $snapshot
            Findings    = $findings
            WorstStatus = Get-WhmWorstSeverity -Finding $findings
        }

        if ($canWrite) {
            Write-WhmRecord -Record $record -OutputPath $resolvedOutput
            if ($WriteEventLog) {
                Write-WhmEvent -Finding $findings -WorstStatus $record.WorstStatus -Source $script:WhmEventSource
            }
            if ([int]$threshold.RetentionDays -gt 0) {
                $cutoff = (Get-Date).AddDays(-1 * [int]$threshold.RetentionDays)
                Get-ChildItem -LiteralPath $resolvedOutput -File -Filter 'health-*' -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt $cutoff } |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
        }

        Write-Verbose "Run $iteration on $($snapshot.ComputerName): $($record.WorstStatus)"
        if ($PassThru -or -not $canWrite) { $record }

        if ($Count -gt 0 -and $iteration -ge $Count) { break }
        Start-Sleep -Seconds $IntervalSeconds
    }
}
