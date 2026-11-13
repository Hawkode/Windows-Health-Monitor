# Default thresholds. Override any key with a .psd1 passed to -ThresholdPath;
# keys you leave out keep these values. Unknown keys are rejected, so a typo
# fails loudly instead of being ignored.
@{
    # Higher is worse.
    CpuPercent                 = @{ Warning = 85; Critical = 95 }
    MemoryUsedPercent          = @{ Warning = 85; Critical = 95 }
    UptimeDays                 = @{ Warning = 30; Critical = 60 }
    DefenderSignatureAgeDays   = @{ Warning = 2; Critical = 7 }
    PatchAgeDays               = @{ Warning = 35; Critical = 60 }

    # Lower is worse.
    DiskFreePercent            = @{ Warning = 15; Critical = 5 }

    # Policy switches. Set RequireDefenderRealTime to $false on hosts where a
    # third-party AV/EDR is primary and Defender runs in passive mode.
    RequireDefenderRealTime    = $true
    RequireTamperProtection    = $true
    RequireAllFirewallProfiles = $true
    RequireBitLocker           = $true

    # PendingFileRenameOperations is set by many installers and AV updates.
    # Ignoring it cuts false "reboot pending" warnings.
    IgnorePendingFileRename    = $true

    # How far back to look for event log clearing (EID 1102 and 104).
    LogClearLookbackHours      = 24

    # Daily output files older than this are deleted. 0 keeps everything.
    RetentionDays              = 14
}
