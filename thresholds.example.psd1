# Copy to thresholds.local.psd1 (gitignored) and keep only the keys you change.
# Install.ps1 -ThresholdPath .\thresholds.local.psd1 copies it next to the module
# under the same admin-only ACL. Unknown keys are rejected.
@{
    # Laptops shut down nightly with Fast Startup keep a long uptime. Loosen this.
    UptimeDays              = @{ Warning = 45; Critical = 90 }

    # Third-party AV/EDR is primary and Defender runs in passive mode.
    RequireDefenderRealTime = $false

    # Desktops in a locked comms room, encryption handled elsewhere.
    RequireBitLocker        = $false
}
