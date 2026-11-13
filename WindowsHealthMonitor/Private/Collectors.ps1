# Data collectors. Each one returns raw facts and throws on failure;
# Invoke-WhmCollector turns a throw into an Unknown result. Judgement
# (OK / Warning / Critical) lives in Test-HealthSnapshot, not here.

function Get-WhmCpu {
    [CmdletBinding()]
    param()
    # Win32_Processor.LoadPercentage is a 1-second average per socket. It is
    # not localised, unlike '\Processor(_Total)\% Processor Time', whose
    # counter path changes name on non-English Windows.
    $load = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            Measure-Object -Property LoadPercentage -Average).Average
    if ($null -eq $load) { throw 'Win32_Processor did not report LoadPercentage.' }
    [pscustomobject]@{ Percent = [math]::Round([double]$load, 1) }
}

function Get-WhmMemory {
    [CmdletBinding()]
    param()
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    # Both values are in KB. KB / 1MB = GB. (v1 divided by 1MB and labelled
    # the result MB, so every memory figure was 1024x too small.)
    $totalKb = [double]$os.TotalVisibleMemorySize
    $freeKb = [double]$os.FreePhysicalMemory
    if ($totalKb -le 0) { throw 'Win32_OperatingSystem reported zero total memory.' }
    [pscustomobject]@{
        TotalGB     = [math]::Round($totalKb / 1MB, 2)
        FreeGB      = [math]::Round($freeKb / 1MB, 2)
        UsedPercent = [math]::Round((($totalKb - $freeKb) / $totalKb) * 100, 1)
    }
}

function Get-WhmDisk {
    [CmdletBinding()]
    param()
    # DriveType 3 = local fixed disk. Mapped drives and removable media are out.
    $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop
    foreach ($v in $volumes) {
        if (-not $v.Size) { continue }
        [pscustomobject]@{
            Drive       = [string]$v.DeviceID
            SizeGB      = [math]::Round($v.Size / 1GB, 1)
            FreeGB      = [math]::Round($v.FreeSpace / 1GB, 1)
            FreePercent = [math]::Round(($v.FreeSpace / $v.Size) * 100, 1)
        }
    }
}

function Get-WhmUptime {
    [CmdletBinding()]
    param()
    # With Fast Startup on (the Windows 11 default), Shut down does not reset
    # LastBootUpTime. Only Restart does. Long uptime on laptops is often this.
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $boot = $os.LastBootUpTime
    $span = (Get-Date) - $boot
    [pscustomobject]@{
        LastBootUtc = ConvertTo-WhmIsoTime -Value $boot
        Days        = [math]::Round($span.TotalDays, 2)
    }
}

function Get-WhmNetwork {
    [CmdletBinding()]
    param()
    # -Physical drops Hyper-V switches, VPN and loopback adapters, which made
    # v1 report "Connected" on a machine with no real link.
    $up = @(Get-NetAdapter -Physical -ErrorAction Stop | Where-Object { [string]$_.Status -eq 'Up' })
    [pscustomobject]@{
        PhysicalUp = $up.Count
        Adapters   = @($up | ForEach-Object { [string]$_.Name })
    }
}

function Get-WhmTopProcess {
    [CmdletBinding()]
    param([ValidateRange(1, 50)][int]$Count = 5)
    Get-Process |
        Sort-Object -Property WorkingSet64 -Descending |
        Select-Object -First $Count |
        ForEach-Object {
            [pscustomobject]@{
                Name         = $_.ProcessName
                Id           = $_.Id
                WorkingSetMB = [math]::Round($_.WorkingSet64 / 1MB, 1)
            }
        }
}

function Get-WhmDefender {
    [CmdletBinding()]
    param()
    if (-not (Get-Command -Name Get-MpComputerStatus -ErrorAction SilentlyContinue)) {
        throw 'Get-MpComputerStatus is not available (Defender module missing or removed).'
    }
    $status = Get-MpComputerStatus -ErrorAction Stop
    [pscustomobject]@{
        # Normal, Passive (third-party AV is primary) or EDR Block Mode.
        RunningMode               = [string]$status.AMRunningMode
        AntivirusEnabled          = [bool]$status.AntivirusEnabled
        RealTimeProtectionEnabled = [bool]$status.RealTimeProtectionEnabled
        TamperProtected           = [bool]$status.IsTamperProtected
        SignatureAgeDays          = [int]$status.AntivirusSignatureAge
    }
}

function Get-WhmFirewall {
    [CmdletBinding()]
    param()
    # ActiveStore is the effective policy (local + GPO). The default
    # PersistentStore shows local settings only and misses GPO overrides.
    $fwProfiles = Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop
    foreach ($p in $fwProfiles) {
        [pscustomobject]@{
            Profile = [string]$p.Name
            Enabled = ([string]$p.Enabled -eq 'True')
        }
    }
}

function Get-WhmPendingReboot {
    [CmdletBinding()]
    param()
    $reasons = New-Object -TypeName 'System.Collections.Generic.List[string]'
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') {
        $reasons.Add('ComponentBasedServicing')
    }
    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') {
        $reasons.Add('WindowsUpdate')
    }
    $sessionManager = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager' -Name 'PendingFileRenameOperations' -ErrorAction SilentlyContinue
    if ($null -ne $sessionManager -and $sessionManager.PendingFileRenameOperations) {
        $reasons.Add('PendingFileRename')
    }
    [pscustomobject]@{
        Pending = ($reasons.Count -gt 0)
        Reasons = @($reasons)
    }
}

function Get-WhmPatch {
    [CmdletBinding()]
    param()
    # Get-HotFix (Win32_QuickFixEngineering) lists CBS-installed updates. It
    # is a proxy for "is this host patching at all", not a missing-patch scan.
    # Endpoint Central or Qualys is the source of truth for that.
    $latest = @(Get-HotFix -ErrorAction Stop | Where-Object { $null -ne $_.InstalledOn }) |
        Sort-Object -Property InstalledOn -Descending |
        Select-Object -First 1
    if ($null -eq $latest) { throw 'No hotfix with an install date was returned.' }
    $installed = [datetime]$latest.InstalledOn
    [pscustomobject]@{
        LatestHotFixId     = [string]$latest.HotFixID
        LatestInstalledUtc = ConvertTo-WhmIsoTime -Value $installed
        DaysSinceLastPatch = [int][math]::Floor(((Get-Date) - $installed).TotalDays)
    }
}

function Get-WhmEventCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string]$LogName,
        [Parameter(Mandatory)][int]$Id,
        [Parameter(Mandatory)][datetime]$Since
    )
    $filter = @{
        LogName      = $LogName
        ProviderName = 'Microsoft-Windows-Eventlog'
        Id           = $Id
        StartTime    = $Since
    }
    try {
        @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop).Count
    }
    catch {
        # "No events found" is a throw, not an empty result. Anything else
        # (access denied, log missing) is a real failure and must propagate,
        # or a non-admin run would report "never cleared".
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') { return 0 }
        throw
    }
}

function Get-WhmLogClear {
    [CmdletBinding()]
    param([Parameter(Mandatory)][ValidateRange(1, 720)][int]$LookbackHours)
    if (-not (Test-WhmElevated)) { throw 'Reading the Security log requires an elevated session.' }
    $since = (Get-Date).AddHours(-1 * $LookbackHours)
    # EID 1102: "The audit log was cleared" (Security log).
    $securityCleared = [int](Get-WhmEventCount -LogName 'Security' -Id 1102 -Since $since)
    # EID 104: "The <name> log file was cleared" (any other log, in System).
    $otherCleared = [int](Get-WhmEventCount -LogName 'System' -Id 104 -Since $since)
    [pscustomobject]@{
        LookbackHours      = $LookbackHours
        SecurityLogCleared = $securityCleared
        OtherLogCleared    = $otherCleared
    }
}

function Get-WhmBitLocker {
    [CmdletBinding()]
    param()
    if (-not (Test-WhmElevated)) { throw 'BitLocker status requires an elevated session.' }
    # CIM instead of Get-BitLockerVolume, so it works in PowerShell 7 without
    # the Windows PowerShell compatibility layer.
    $drive = $env:SystemDrive
    $volume = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -Filter "DriveLetter='$drive'" -ErrorAction Stop
    if ($null -eq $volume) { throw "No encryptable volume found for $drive." }
    [pscustomobject]@{
        Drive        = $drive
        # ProtectionStatus: 0 = off, 1 = on, 2 = unknown (volume locked).
        ProtectionOn = ([int]$volume.ProtectionStatus -eq 1)
    }
}
