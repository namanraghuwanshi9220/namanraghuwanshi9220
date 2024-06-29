## Copyright (c) Microsoft Corporation. All rights reserved.

<#
.SYNOPSIS
This cmdlet collects a performance recording of Microsoft Defender Antivirus
scans.

.DESCRIPTION
This cmdlet collects a performance recording of Microsoft Defender Antivirus
scans. These performance recordings contain Microsoft-Antimalware-Engine
and NT kernel process events and can be analyzed after collection using the
Get-MpPerformanceReport cmdlet.

This cmdlet requires elevated administrator privileges.

The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.

.EXAMPLE
New-MpPerformanceRecording -RecordTo:.\Defender-scans.etl

#>
function New-MpPerformanceRecording {
    [CmdletBinding(DefaultParameterSetName='Interactive')]
    param(

        # Specifies the location where to save the Microsoft Defender Antivirus
        # performance recording.
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$RecordTo,

        # Specifies the duration of the performance recording in seconds.
        [Parameter(Mandatory=$true, ParameterSetName='Timed')]
        [ValidateRange(0,2147483)]
        [int]$Seconds,

        # Specifies the PSSession object in which to create and save the Microsoft
        # Defender Antivirus performance recording. When you use this parameter,
        # the RecordTo parameter refers to the local path on the remote machine.
        [Parameter(Mandatory=$false)]
        [System.Management.Automation.Runspaces.PSSession[]]$Session,

        # Optional argument to specifiy a different tool for recording traces. Default is wpr.exe
        # When $Session parameter is used this path represents a location on the remote machine.
        [Parameter(Mandatory=$false)]
        [string]$WPRPath = $null

    )

    [bool]$interactiveMode = ($PSCmdlet.ParameterSetName -eq 'Interactive')
    [bool]$timedMode = ($PSCmdlet.ParameterSetName -eq 'Timed')

    # Hosts
    [string]$powerShellHostConsole = 'ConsoleHost'
    [string]$powerShellHostISE = 'Windows PowerShell ISE Host'
    [string]$powerShellHostRemote = 'ServerRemoteHost'

    if ($interactiveMode -and ($Host.Name -notin @($powerShellHostConsole, $powerShellHostISE, $powerShellHostRemote))) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException 'Cmdlet supported only on local PowerShell console, Windows PowerShell ISE and remote PowerShell console.'
        $category = [System.Management.Automation.ErrorCategory]::NotImplemented
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'NotImplemented',$category,$Host.Name
        $psCmdlet.WriteError($errRecord)
        return
    }

    if ($null -ne $Session) {
        [int]$RemotedSeconds = if ($timedMode) { $Seconds } else { -1 }

        Invoke-Command -Session:$session -ArgumentList:@($RecordTo, $RemotedSeconds) -ScriptBlock:{
            param(
                [Parameter(Mandatory=$true)]
                [ValidateNotNullOrEmpty()]
                [string]$RecordTo,

                [Parameter(Mandatory=$true)]
                [ValidateRange(-1,2147483)]
                [int]$RemotedSeconds
            )

            if ($RemotedSeconds -eq -1) {
                New-MpPerformanceRecording -RecordTo:$RecordTo -WPRPath:$WPRPath
            } else {
                New-MpPerformanceRecording -RecordTo:$RecordTo -Seconds:$RemotedSeconds -WPRPath:$WPRPath
            }
        }

        return
    }

    if (-not (Test-Path -LiteralPath:$RecordTo -IsValid)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot record Microsoft Defender Antivirus performance recording to path '$RecordTo' because the location does not exist."
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidPath',$category,$RecordTo
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Resolve any relative paths
    $RecordTo = $psCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($RecordTo)

    # Dependencies: WPR Profile
    [string]$wprProfile = "$PSScriptRoot\MSFT_MpPerformanceRecording.wprp"

    if (-not (Test-Path -LiteralPath:$wprProfile -PathType:Leaf)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency file '$wprProfile' because it does not exist."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprProfile
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Dependencies: WPR Version
    try 
    {
        # If user provides a valid string as $WPRPath we go with that.
        [string]$wprCommand = $WPRPath

        if (!$wprCommand) {
            $wprCommand = "wpr.exe"
            $wprs = @(Get-Command -All "wpr" 2> $null)

            if ($wprs -and ($wprs.Length -ne 0)) {
                $latestVersion = [System.Version]"0.0.0.0"

                $wprs | ForEach-Object {
                    $currentVersion = $_.Version
                    $currentFullPath = $_.Source
                    $currentVersionString = $currentVersion.ToString()
                    Write-Host "Found $currentVersionString at $currentFullPath"

                    if ($currentVersion -gt $latestVersion) {
                        $latestVersion = $currentVersion
                        $wprCommand = $currentFullPath
                    }
                }
            }
        }
    }
    catch
    {
        # Fallback to the old ways in case we encounter an error (ex: version string format change).
        [string]$wprCommand = "wpr.exe"
    }
    finally 
    {
        Write-Host "`nUsing $wprCommand version $((Get-Command $wprCommand).FileVersionInfo.FileVersion)`n"    
    }
 
    #
    # Test dependency presence
    #
    if (-not (Get-Command $wprCommand -ErrorAction:SilentlyContinue)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find dependency command '$wprCommand' because it does not exist."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$wprCommand
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Exclude versions that have known bugs or are not supported any more.
    [int]$wprFileVersion = ((Get-Command $wprCommand).Version.Major) -as [int]
    if ($wprFileVersion -le 6) {
        $ex = New-Object System.Management.Automation.PSNotSupportedException "You are using an older and unsupported version of '$wprCommand'. Please download and install Windows ADK:`r`nhttps://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install`r`nand try again."
        $category = [System.Management.Automation.ErrorCategory]::NotInstalled
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'NotSupported',$category,$wprCommand
        $psCmdlet.WriteError($errRecord)
        return
    }

    function CancelPerformanceRecording {
        Write-Host "`n`nCancelling Microsoft Defender Antivirus performance recording... " -NoNewline

        & $wprCommand -cancel -instancename MSFT_MpPerformanceRecording
        $wprCommandExitCode = $LASTEXITCODE

        switch ($wprCommandExitCode) {
            0 {}
            0xc5583000 {
                Write-Error "Cannot cancel performance recording because currently Windows Performance Recorder is not recording."
                return
            }
            default {
                Write-Error ("Cannot cancel performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "ok.`n`nRecording has been cancelled."
    }

    #
    # Ensure Ctrl-C doesn't abort the app without cleanup
    #

    # - local PowerShell consoles: use [Console]::TreatControlCAsInput; cleanup performed and output preserved
    # - PowerShell ISE: use try { ... } catch { throw } finally; cleanup performed and output preserved
    # - remote PowerShell: use try { ... } catch { throw } finally; cleanup performed but output truncated

    [bool]$canTreatControlCAsInput = $interactiveMode -and ($Host.Name -eq $powerShellHostConsole)
    $savedControlCAsInput = $null

    $shouldCancelRecordingOnTerminatingError = $false

    try
    {
        if ($canTreatControlCAsInput) {
            $savedControlCAsInput = [Console]::TreatControlCAsInput
            [Console]::TreatControlCAsInput = $true
        }

        #
        # Start recording
        #

        Write-Host "Starting Microsoft Defender Antivirus performance recording... " -NoNewline

        $shouldCancelRecordingOnTerminatingError = $true

        & $wprCommand -start "$wprProfile!Scans.Light" -filemode -instancename MSFT_MpPerformanceRecording
        $wprCommandExitCode = $LASTEXITCODE

        switch ($wprCommandExitCode) {
            0 {}
            0xc5583001 {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error "Cannot start performance recording because Windows Performance Recorder is already recording."
                return
            }
            default {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error ("Cannot start performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "ok.`n`nRecording has started." -NoNewline

        if ($timedMode) {
            Write-Host "`n`n   Recording for $Seconds seconds... " -NoNewline

            Start-Sleep -Seconds:$Seconds
            
            Write-Host "ok." -NoNewline
        } elseif ($interactiveMode) {
            $stopPrompt = "`n`n=> Reproduce the scenario that is impacting the performance on your device.`n`n   Press <ENTER> to stop and save recording or <Ctrl-C> to cancel recording"

            if ($canTreatControlCAsInput) {
                Write-Host "${stopPrompt}: "

                do {
                    $key = [Console]::ReadKey($true)
                    if (($key.Modifiers -eq [ConsoleModifiers]::Control) -and (($key.Key -eq [ConsoleKey]::C))) {

                        CancelPerformanceRecording

                        $shouldCancelRecordingOnTerminatingError = $false

                        #
                        # Restore Ctrl-C behavior
                        #

                        [Console]::TreatControlCAsInput = $savedControlCAsInput

                        return
                    }

                } while (($key.Modifiers -band ([ConsoleModifiers]::Alt -bor [ConsoleModifiers]::Control -bor [ConsoleModifiers]::Shift)) -or ($key.Key -ne [ConsoleKey]::Enter))

            } else {
                Read-Host -Prompt:$stopPrompt
            }
        }

        #
        # Stop recording
        #

        Write-Host "`n`nStopping Microsoft Defender Antivirus performance recording... "

        & $wprCommand -stop $RecordTo -instancename MSFT_MpPerformanceRecording
        $wprCommandExitCode = $LASTEXITCODE

        switch ($wprCommandExitCode) {
            0 {
                $shouldCancelRecordingOnTerminatingError = $false
            }
            0xc5583000 {
                $shouldCancelRecordingOnTerminatingError = $false
                Write-Error "Cannot stop performance recording because Windows Performance Recorder is not recording a trace."
                return
            }
            default {
                Write-Error ("Cannot stop performance recording: 0x{0:x08}." -f $wprCommandExitCode)
                return
            }
        }

        Write-Host "ok.`n`nRecording has been saved to '$RecordTo'."

        Write-Host `
'
The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.
'
Write-Host `
'
The trace you have just captured may contain personally identifiable information,
including but not necessarily limited to paths to files accessed, paths to
registry accessed and process names. Exact information depends on the events that
were logged. Please be aware of this when sharing this trace with other people.
'
    } catch {
        throw
    } finally {
        if ($shouldCancelRecordingOnTerminatingError) {
            CancelPerformanceRecording
        }

        if ($null -ne $savedControlCAsInput) {
            #
            # Restore Ctrl-C behavior
            #

            [Console]::TreatControlCAsInput = $savedControlCAsInput
        }
    }
}

function PadUserDateTime
{
    [OutputType([DateTime])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [DateTime]$UserDateTime
    )

    # Padding user input to include all events up to the start of the next second.
    if (($UserDateTime.Ticks % 10000000) -eq 0)
    {
        return $UserDateTime.AddTicks(9999999)
    }
    else
    {
        return $UserDateTime
    }
}

function ValidateTimeInterval
{
    [OutputType([PSCustomObject])]
    param(
        [DateTime]$MinStartTime = [DateTime]::MinValue,
        [DateTime]$MinEndTime = [DateTime]::MinValue,
        [DateTime]$MaxStartTime = [DateTime]::MaxValue,
        [DateTime]$MaxEndTime = [DateTime]::MaxValue
    )

    $ret = [PSCustomObject]@{
        arguments = [string[]]@()
        status = $false
    }
    
    if ($MinStartTime -gt $MaxEndTime)
    {
        $ex = New-Object System.Management.Automation.ValidationMetadataException "MinStartTime '$MinStartTime' should have been lower than MaxEndTime '$MaxEndTime'"
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Invalid time interval',$category,"'$MinStartTime' .. '$MaxEndTime'"
        $psCmdlet.WriteError($errRecord)
        return $ret
    }

    if ($MinStartTime -gt $MaxStartTime)
    {
        $ex = New-Object System.Management.Automation.ValidationMetadataException "MinStartTime '$MinStartTime' should have been lower than MaxStartTime '$MaxStartTime'"
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Invalid time interval',$category,"'$MinStartTime' .. '$MaxStartTime'"
        $psCmdlet.WriteError($errRecord)
        return $ret
    }

    if ($MinEndTime -gt $MaxEndTime)
    {
        $ex = New-Object System.Management.Automation.ValidationMetadataException "MinEndTime '$MinEndTime' should have been lower than MaxEndTime '$MaxEndTime'"
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Invalid time interval',$category,"'$MinEndTime' .. '$MaxEndTime'"
        $psCmdlet.WriteError($errRecord)
        return $ret
    }

    if ($MinStartTime -gt [DateTime]::MinValue)
    {
        try
        {
            $MinStartFileTime = $MinStartTime.ToFileTime()
        }
        catch
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MinStartTime '$MinStartTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MinStartTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret
        }

        $ret.arguments += @('-MinStartTime', $MinStartFileTime)
    }

    if ($MaxEndTime -lt [DateTime]::MaxValue)
    {
        try 
        {
            $MaxEndFileTime = $MaxEndTime.ToFileTime()
        }
        catch 
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MaxEndTime '$MaxEndTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MaxEndTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret               
        }
    
        $ret.arguments += @('-MaxEndTime', $MaxEndFileTime)
    }

    if ($MaxStartTime -lt [DateTime]::MaxValue)
    {
        try
        {
            $MaxStartFileTime = $MaxStartTime.ToFileTime()
        }
        catch
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MaxStartTime '$MaxStartTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MaxStartTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret
        }

        $ret.arguments += @('-MaxStartTime', $MaxStartFileTime)
    }

    if ($MinEndTime -gt [DateTime]::MinValue)
    {
        try 
        {
            $MinEndFileTime = $MinEndTime.ToFileTime()
        }
        catch 
        {
            $ex = New-Object System.Management.Automation.ValidationMetadataException "MinEndTime '$MinEndTime' is not a valid timestamp."
            $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
            $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'Value has to be a local DateTime between "January 1, 1601 12:00:00 AM UTC" and "December 31, 9999 11:59:59 PM UTC"',$category,"'$MinEndTime'"
            $psCmdlet.WriteError($errRecord)
            return $ret              
        }
        
        $ret.arguments += @('-MinEndTime', $MinEndFileTime)
    }

    $ret.status = $true
    return $ret
}

function ParseFriendlyDuration
{
    [OutputType([TimeSpan])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        $FriendlyDuration
    )

    if ($FriendlyDuration -match '^(\d+)(?:\.(\d+))?(sec|ms|us)$')
    {
        [string]$seconds = $Matches[1]
        [string]$decimals = $Matches[2]
        [string]$unit = $Matches[3]

        [uint32]$magnitude =
            switch ($unit)
            {
                'sec' {7}
                'ms' {4}
                'us' {1}
            }

        if ($decimals.Length -gt $magnitude)
        {
            throw [System.ArgumentException]::new("String '$FriendlyDuration' was not recognized as a valid Duration: $($decimals.Length) decimals specified for time unit '$unit'; at most $magnitude expected.")
        }

        return [timespan]::FromTicks([int64]::Parse($seconds + $decimals.PadRight($magnitude, '0')))
    }

    [timespan]$result = [timespan]::FromTicks(0)
    if ([timespan]::TryParse($FriendlyDuration, [ref]$result))
    {
        return $result
    }

    throw [System.ArgumentException]::new("String '$FriendlyDuration' was not recognized as a valid Duration; expected a value like '0.1234567sec' or '0.1234ms' or '0.1us' or a valid TimeSpan.")
}

[scriptblock]$FriendlyTimeSpanToString = { '{0:0.0000}ms' -f ($this.Ticks / 10000.0) }

function New-FriendlyTimeSpan
{
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$Ticks,

        [bool]$Raw = $false
    )

    if ($Raw) {
        return $Ticks
    }

    $result = [TimeSpan]::FromTicks($Ticks)
    $result.PsTypeNames.Insert(0, 'MpPerformanceReport.TimeSpan')
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyTimeSpanToString
    $result
}

function New-FriendlyDateTime
{
    param(
        [Parameter(Mandatory = $true)]
        [uint64]$FileTime,

        [bool]$Raw = $false
    )

    if ($Raw) {
        return $FileTime
    }

    [DateTime]::FromFileTime($FileTime)
}

function Add-DefenderCollectionType
{
    param(
        [Parameter(Mandatory = $true)]
        [ref]$CollectionRef
    )

    if ($CollectionRef.Value.Length -and ($CollectionRef.Value | Get-Member -Name:'Processes','Files','Extensions','Scans','Folder'))
    {
        $CollectionRef.Value.PSTypeNames.Insert(0, 'MpPerformanceReport.NestedCollection')
    }
}

[scriptblock]$FriendlyScanInfoToString = { 
    [PSCustomObject]@{
        ScanType = $this.ScanType
        StartTime = $this.StartTime
        EndTime = $this.EndTime
        Duration = $this.Duration
        Reason = $this.Reason
        Path = $this.Path
        ProcessPath = $this.ProcessPath
        ProcessId = $this.ProcessId
        Image = $this.Image
    }
}

function Get-ScanComments
{
    param(
        [PSCustomObject[]]$SecondaryEvents,
        [bool]$Raw = $false
    )

    $Comments = @()

    foreach ($item in @($SecondaryEvents | Sort-Object -Property:StartTime)) {
        if (($item | Get-Member -Name:'Message' -MemberType:NoteProperty).Count -eq 1) {
            if (($item | Get-Member -Name:'Duration' -MemberType:NoteProperty).Count -eq 1) {
                $Duration  = New-FriendlyTimeSpan -Ticks:$item.Duration -Raw:$Raw
                $StartTime = New-FriendlyDateTime -FileTime:$item.StartTime -Raw:$Raw

                $Comments += "Expensive operation `"{0}`" started at {1} lasted {2}" -f ($item.Message, $StartTime, $Duration.ToString())

                if (($item | Get-Member -Name:'Debug' -MemberType:NoteProperty).Count -eq 1) {
                    $item.Debug | ForEach-Object {
                        if ($_.EndsWith("is NOT trusted") -or $_.StartsWith("Not trusted, ") -or $_.ToLower().Contains("error") -or $_.Contains("Result of ValidateTrust")) {
                            $Comments += "$_"
                        }
                    }
                }
            }
            else {
                if ($item.Message.Contains("subtype=Lowfi")) {
                    $Comments += $item.Message.Replace("subtype=Lowfi", "Low-fidelity detection")
                }
                else {
                    $Comments += $item.Message
                }
            }
        }
        elseif (($item | Get-Member -Name:'ScanType' -MemberType:NoteProperty).Count -eq 1) {
            $Duration = New-FriendlyTimeSpan -Ticks:$item.Duration -Raw:$Raw
            $OpId = "Internal opertion"
            
            if (($item | Get-Member -Name:'Path' -MemberType:NoteProperty).Count -eq 1) {
                $OpId = $item.Path
            }
            elseif (($item | Get-Member -Name:'ProcessPath' -MemberType:NoteProperty).Count -eq 1) {
                $OpId = $item.ProcessPath
            }

            $Comments += "{0} {1} lasted {2}" -f ($item.ScanType, $OpId, $Duration.ToString())
        }
    }

    $Comments 
}

filter ConvertTo-DefenderScanInfo
{
    param(
        [bool]$Raw = $false
    )

    $result = [PSCustomObject]@{
        ScanType = [string]$_.ScanType
        StartTime = New-FriendlyDateTime -FileTime:$_.StartTime -Raw:$Raw
        EndTime = New-FriendlyDateTime -FileTime:$_.EndTime -Raw:$Raw
        Duration = New-FriendlyTimeSpan -Ticks:$_.Duration -Raw:$Raw
        Reason = [string]$_.Reason
        SkipReason = [string]$_.SkipReason
    }

    if (($_ | Get-Member -Name:'Path' -MemberType:NoteProperty).Count -eq 1) {
        $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:([string]$_.Path)
    }

    if (($_ | Get-Member -Name:'ProcessPath' -MemberType:NoteProperty).Count -eq 1) {
        $result | Add-Member -NotePropertyName:'ProcessPath' -NotePropertyValue:([string]$_.ProcessPath)
    }

    if (($_ | Get-Member -Name:'Image' -MemberType:NoteProperty).Count -eq 1) {
        $result | Add-Member -NotePropertyName:'Image' -NotePropertyValue:([string]$_.Image)
    }
    elseif ($_.ProcessPath -and (-not $_.ProcessPath.StartsWith("pid"))) {
        try {
            $result | Add-Member -NotePropertyName:'Image' -NotePropertyValue:([string]([System.IO.FileInfo]$_.ProcessPath).Name)
        } catch {
            # Silently ignore.
        }
    }

    $ProcessId = if ($_.ProcessId -gt 0) { [int]$_.ProcessId } elseif ($_.ScannedProcessId -gt 0) { [int]$_.ScannedProcessId } else { $null }
    if ($ProcessId) {
        $result | Add-Member -NotePropertyName:'ProcessId' -NotePropertyValue:([int]$ProcessId)
    }

    if ($result.Image -and $result.ProcessId) {
        $ProcessName = "{0} ({1})" -f $result.Image, $result.ProcessId
        $result | Add-Member -NotePropertyName:'ProcessName' -NotePropertyValue:([string]$ProcessName)
    }

    if ((($_ | Get-Member -Name:'Extra' -MemberType:NoteProperty).Count -eq 1) -and ($_.Extra.Count -gt 0)) {
        $Comments = @(Get-ScanComments -SecondaryEvents:$_.Extra -Raw:$Raw)
        $result | Add-Member -NotePropertyName:'Comments' -NotePropertyValue:$Comments
    }

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScanInfo')
    }

    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScanInfoToString
    $result
}

filter ConvertTo-DefenderScanOverview
{
    param(
        [bool]$Raw = $false
    )

    $vals = [ordered]@{}

    foreach ($entry in $_.PSObject.Properties) {
        if ($entry.Value) {
            $Key = $entry.Name.Replace("_", " ")

            if ($Key.EndsWith("Time")) {
                $vals[$Key] = New-FriendlyDateTime -FileTime:$entry.Value -Raw:$Raw
            }
            elseif ($Key.EndsWith("Duration")) {
                $vals[$Key] = New-FriendlyTimeSpan -Ticks:$entry.Value -Raw:$Raw
            }
            else {
                $vals[$Key] = $entry.Value
            }
        }
    }

    # Remove duplicates
    if (($_ | Get-Member -Name:'PerfHints' -MemberType:NoteProperty).Count -eq 1) {
        $hints = [ordered]@{}
        foreach ($hint in $_.PerfHints) {
            $hints[$hint] = $true
        }

        $vals["PerfHints"] = @($hints.Keys)
    }

    $result = New-Object PSCustomObject -Property:$vals
    $result
}

filter ConvertTo-DefenderScanStats
{
    param(
        [bool]$Raw = $false
    )

    $result = [PSCustomObject]@{
        Count = $_.Count
        TotalDuration = New-FriendlyTimeSpan -Ticks:$_.TotalDuration -Raw:$Raw
        MinDuration = New-FriendlyTimeSpan -Ticks:$_.MinDuration -Raw:$Raw
        AverageDuration = New-FriendlyTimeSpan -Ticks:$_.AverageDuration -Raw:$Raw
        MaxDuration = New-FriendlyTimeSpan -Ticks:$_.MaxDuration -Raw:$Raw
        MedianDuration = New-FriendlyTimeSpan -Ticks:$_.MedianDuration -Raw:$Raw
    }

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScanStats')
    }

    $result
}

[scriptblock]$FriendlyScannedFilePathStatsToString = {
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        Path = $this.Path
    }
}

filter ConvertTo-DefenderScannedFilePathStats
{
    param(
        [bool]$Raw = $false
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedFilePathStats')
    }
    
    $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:($_.Path)
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedFilePathStatsToString

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
        }
    }

    $result
}

[scriptblock]$FriendlyScannedPathsStatsToString = { 
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        Path = $this.Path
        Folder = $this.Folder
    }
}

filter ConvertTo-DefenderScannedPathsStats
{
    param(
        [bool]$Raw = $false
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedPathStats')
    }

    $result | Add-Member -NotePropertyName:'Path' -NotePropertyValue:($_.Path)

    if ($null -ne $_.Folder)
    {
        $result | Add-Member -NotePropertyName:'Folder' -NotePropertyValue:@(
            $_.Folder | ConvertTo-DefenderScannedPathsStats -Raw:$Raw
        )
        $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedPathsStatsToString

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Folder)
        }
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
        }
    }

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
        }
    }

    $result
}

[scriptblock]$FriendlyScannedFileExtensionStatsToString = {
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        Extension = $this.Extension
    }
}

filter ConvertTo-DefenderScannedFileExtensionStats
{
    param(
        [bool]$Raw = $false
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedFileExtensionStats')
    }

    $result | Add-Member -NotePropertyName:'Extension' -NotePropertyValue:($_.Extension)
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedFileExtensionStatsToString

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
        }
    }

    if ($null -ne $_.Processes)
    {
        $result | Add-Member -NotePropertyName:'Processes' -NotePropertyValue:@(
            $_.Processes | ConvertTo-DefenderScannedProcessStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Processes)
        }
    }


    if ($null -ne $_.Folder)
    {
        $result | Add-Member -NotePropertyName:'Folder' -NotePropertyValue:@(
            $_.Folder | ConvertTo-DefenderScannedPathsStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Folder)
        }
    }

    $result
}

[scriptblock]$FriendlyScannedProcessStatsToString = { 
    [PSCustomObject]@{
        Count = $this.Count
        TotalDuration = $this.TotalDuration
        MinDuration = $this.MinDuration
        AverageDuration = $this.AverageDuration
        MaxDuration = $this.MaxDuration
        MedianDuration = $this.MedianDuration
        ProcessPath = $this.ProcessPath
    }
}

filter ConvertTo-DefenderScannedProcessStats
{
    param(
        [bool]$Raw
    )

    $result = $_ | ConvertTo-DefenderScanStats -Raw:$Raw

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.ScannedProcessStats')
    }

    $result | Add-Member -NotePropertyName:'ProcessPath' -NotePropertyValue:($_.Process)
    $result | Add-Member -Force -MemberType:ScriptMethod -Name:'ToString' -Value:$FriendlyScannedProcessStatsToString

    if ($null -ne $_.Scans)
    {
        $result | Add-Member -NotePropertyName:'Scans' -NotePropertyValue:@(
            $_.Scans | ConvertTo-DefenderScanInfo -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Scans)
        }
    }

    if ($null -ne $_.Files)
    {
        $result | Add-Member -NotePropertyName:'Files' -NotePropertyValue:@(
            $_.Files | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Files)
        }
    }

    if ($null -ne $_.Extensions)
    {
        $result | Add-Member -NotePropertyName:'Extensions' -NotePropertyValue:@(
            $_.Extensions | ConvertTo-DefenderScannedFileExtensionStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Extensions)
        }
    }

    if ($null -ne $_.Folder)
    {
        $result | Add-Member -NotePropertyName:'Folder' -NotePropertyValue:@(
            $_.Folder | ConvertTo-DefenderScannedPathsStats -Raw:$Raw
        )

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.Folder)
        }
    }

    $result
}

<#
.SYNOPSIS
This cmdlet reports the file paths, file extensions, and processes that cause
the highest impact to Microsoft Defender Antivirus scans.

.DESCRIPTION
This cmdlet analyzes a previously collected Microsoft Defender Antivirus
performance recording and reports the file paths, file extensions and processes
that cause the highest impact to Microsoft Defender Antivirus scans.

The performance analyzer provides insight into problematic files that could
cause performance degradation of Microsoft Defender Antivirus. This tool is
provided "AS IS", and is not intended to provide suggestions on exclusions.
Exclusions can reduce the level of protection on your endpoints. Exclusions,
if any, should be defined with caution.

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopExtensions:10 -TopProcesses:10 -TopScans:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopExtensions:10 -TopProcesses:10 -TopScans:10 -Raw | ConvertTo-Json

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopScansPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopProcessesPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopFiles:10 -TopProcessesPerFile:3 -TopScansPerProcessPerFile:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopScansPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopScansPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopFilesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopFilesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopFilesPerPath:3 -TopScansPerFilePerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopFilesPerPath:3 -TopScansPerFilePerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopExtensionsPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopExtensionsPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopExtensionsPerPath:3 -TopScansPerExtensionPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopExtensionsPerPath:3 -TopScansPerExtensionPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopProcessesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopProcessesPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopPathsDepth:3 -TopProcessesPerPath:3 -TopScansPerProcessPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopPaths:10 -TopProcessesPerPath:3 -TopScansPerProcessPerPath:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopScansPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3 -TopPathsDepth:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3 -TopPathsDepth:3 -TopScansPerPathPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopPathsPerExtension:3 -TopScansPerPathPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopFilesPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopFilesPerExtension:3 -TopScansPerFilePerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopProcessesPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopExtensions:10 -TopProcessesPerExtension:3 -TopScansPerProcessPerExtension:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopScansPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopExtensionsPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopExtensionsPerProcess:3 -TopScansPerExtensionPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopFilesPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopFilesPerProcess:3 -TopScansPerFilePerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3 -TopPathsDepth:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3 -TopPathsDepth:3 -TopScansPerPathPerProcess:3

.EXAMPLE
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopProcesses:10 -TopPathsPerProcess:3 -TopScansPerPathPerProcess:3

.EXAMPLE
# Find top 10 scans with longest durations that both start and end between MinStartTime and MaxEndTime:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:01:11 AM" -MaxEndTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations between MinEndTime and MaxStartTime, possibly partially overlapping this period
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinEndTime:"5/14/2022 7:01:11 AM" -MaxStartTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations between MinStartTime and MaxStartTime, possibly partially overlapping this period
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:01:11 AM" -MaxStartTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations that start at MinStartTime or later:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations that start before or at MaxStartTime:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxStartTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations that end at MinEndTime or later:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinEndTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations that end before or at MaxEndTime:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxEndTime:"5/14/2022 7:01:11 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that did not start or end between MaxStartTime and MinEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that started between MinStartTime and MaxStartTime, and ended later than MinEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:00:00 AM" -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that started before MaxStartTime, and ended between MinEndTime and MaxEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM" -MaxEndTime:"5/14/2022 7:02:00 AM"

.EXAMPLE
# Find top 10 scans with longest durations, impacting the current interval, that started between MinStartTime and MaxStartTime, and ended between MinEndTime and MaxEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:"5/14/2022 7:00:00 AM" -MaxStartTime:"5/14/2022 7:01:11 AM" -MinEndTime:"5/14/2022 7:01:41 AM" -MaxEndTime:"5/14/2022 7:02:00 AM"

.EXAMPLE
# Find top 10 scans with longest durations that both start and end between MinStartTime and MaxEndTime, using DateTime as raw numbers in FILETIME format, e.g. from -Raw report format:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinStartTime:([DateTime]::FromFileTime(132969744714304340)) -MaxEndTime:([DateTime]::FromFileTime(132969745000971033))

.EXAMPLE
# Find top 10 scans with longest durations between MinEndTime and MaxStartTime, possibly partially overlapping this period, using DateTime as raw numbers in FILETIME format, e.g. from -Raw report format:
Get-MpPerformanceReport -Path:.\Defender-scans.etl -TopScans:10 -MinEndTime:([DateTime]::FromFileTime(132969744714304340)) -MaxStartTime:([DateTime]::FromFileTime(132969745000971033))

.EXAMPLE
# Display a summary or overview of the scans captured in the trace, in addition to the information displayed regularly through other arguments. Output is influenced by time interval arguments MinStartTime and MaxEndTime.
Get-MpPerformanceReport -Path:.\Defender-scans.etl [other arguments] -Overview

#>

function Get-MpPerformanceReport {
    [CmdletBinding()]
    param(
        # Specifies the location of Microsoft Defender Antivirus performance recording to analyze.
        [Parameter(Mandatory=$true,
                Position=0,
                ValueFromPipeline=$true,
                ValueFromPipelineByPropertyName=$true,
                HelpMessage="Location of Microsoft Defender Antivirus performance recording.")]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        # Requests a top files report and specifies how many top files to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFiles = 0,

        # Specifies how many top scans to output for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFile = 0,

        # Specifies how many top processes to output for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerFile = 0,

        # Specifies how many top scans to output for each top process for each top file, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerFile = 0,

        # Requests a top paths report and specifies how many top entries to output, sorted by "Duration". This is called recursively for each directory entry. Scans are grouped hierarchically per folder and sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopPaths = 0,

        # Specifies the maxmimum depth (path-wise) that will be used to grop scans when $TopPaths is used.
        [ValidateRange(1,1024)]
        [int]$TopPathsDepth = 0,

        # Specifies how many top scans to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerPath = 0,

        # Specifies how many top files to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerPath = 0,

        # Specifies how many top scans to output for each top file for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerPath = 0,

        # Specifies how many top extensions to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensionsPerPath = 0,
    
        # Specifies how many top scans to output for each top extension for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtensionPerPath = 0,

        # Specifies how many top processes to output for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerPath = 0,

        # Specifies how many top scans to output for each top process for each top path, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerPath = 0,

        # Requests a top extensions report and specifies how many top extensions to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensions = 0,

        # Specifies how many top scans to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtension = 0,

        # Specifies how many top paths to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopPathsPerExtension = 0,

        # Specifies how many top scans to output for each top path for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerPathPerExtension = 0,

        # Specifies how many top files to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerExtension = 0,

        # Specifies how many top scans to output for each top file for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerExtension = 0,

        # Specifies how many top processes to output for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcessesPerExtension = 0,

        # Specifies how many top scans to output for each top process for each top extension, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcessPerExtension = 0,

        # Requests a top processes report and specifies how many top processes to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopProcesses = 0,

        # Specifies how many top scans to output for each top process in the Top Processes report, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerProcess = 0,

        # Specifies how many top files to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopFilesPerProcess = 0,

        # Specifies how many top scans to output for each top file for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerFilePerProcess = 0,

        # Specifies how many top extensions to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopExtensionsPerProcess = 0,

        # Specifies how many top scans to output for each top extension for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerExtensionPerProcess = 0,

        # Specifies how many top paths to output for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopPathsPerProcess = 0,

        # Specifies how many top scans to output for each top path for each top process, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScansPerPathPerProcess = 0,

        # Requests a top scans report and specifies how many top scans to output, sorted by "Duration".
        [ValidateRange(0,([int]::MaxValue))]
        [int]$TopScans = 0,

        ## TimeSpan format: d | h:m | h:m:s | d.h:m | h:m:.f | h:m:s.f | d.h:m:s | d.h:m:.f | d.h:m:s.f => d | (d.)?h:m(:s(.f)?)? | ((d.)?h:m:.f)

        # Specifies the minimum duration of any scans or total scan durations of files, extensions and processes included in the report.
        # Accepts values like  '0.1234567sec' or '0.1234ms' or '0.1us' or a valid TimeSpan.
        [ValidatePattern('^(?:(?:(\d+)(?:\.(\d+))?(sec|ms|us))|(?:\d+)|(?:(\d+\.)?\d+:\d+(?::\d+(?:\.\d+)?)?)|(?:(\d+\.)?\d+:\d+:\.\d+))$')]
        [string]$MinDuration = '0us',

        # Specifies the minimum start time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MinStartTime = [DateTime]::MinValue,

        # Specifies the minimum end time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MinEndTime = [DateTime]::MinValue,

        # Specifies the maximum start time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MaxStartTime = [DateTime]::MaxValue,

        # Specifies the maximum end time of scans included in the report. Accepts a valid DateTime.
        [DateTime]$MaxEndTime = [DateTime]::MaxValue,

        # Adds an overview or summary of the scans captured in the trace to the regular output.
        [switch]$Overview,

        # Specifies that the output should be machine readable and readily convertible to serialization formats like JSON.
        # - Collections and elements are not be formatted.
        # - TimeSpan values are represented as number of 100-nanosecond intervals.
        # - DateTime values are represented as number of 100-nanosecond intervals since January 1, 1601 (UTC).
        [switch]$Raw
    )

    #
    # Validate performance recording presence
    #

    if (-not (Test-Path -Path:$Path -PathType:Leaf)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find path '$Path'."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$Path
        $psCmdlet.WriteError($errRecord)
        return
    }

    function ParameterValidationError {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory)]
            [string]
            $ParameterName,

            [Parameter(Mandatory)]
            [string]
            $ParentParameterName
        )

        $ex = New-Object System.Management.Automation.ValidationMetadataException "Parameter '$ParameterName' requires parameter '$ParentParameterName'."
        $category = [System.Management.Automation.ErrorCategory]::MetadataError
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidParameter',$category,$ParameterName
        $psCmdlet.WriteError($errRecord)
    }

    #
    # Additional parameter validation
    #

    if ($TopFiles -eq 0)
    {
        if ($TopScansPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFile' -ParentParameterName:'TopFiles'
        }

        if ($TopProcessesPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerFile' -ParentParameterName:'TopFiles'
        }
    }

    if ($TopProcessesPerFile -eq 0)
    {
        if ($TopScansPerProcessPerFile -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerFile' -ParentParameterName:'TopProcessesPerFile'
        }
    }

    if ($TopPathsDepth -gt 0)
    {
        if (($TopPaths -eq 0) -and ($TopPathsPerProcess -eq 0) -and ($TopPathsPerExtension -eq 0))
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopPathsDepth' -ParentParameterName:'TopPaths or TopPathsPerProcess or TopPathsPerExtension'
        }
    }

    if ($TopPaths -eq 0) 
    {
        if ($TopScansPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerPath' -ParentParameterName:'TopPaths'
        }

        if ($TopFilesPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerPath' -ParentParameterName:'TopPaths'
        }

        if ($TopExtensionsPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopExtensionsPerPath' -ParentParameterName:'TopPaths'
        }

        if ($TopProcessesPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerPath' -ParentParameterName:'TopPaths'
        }
    }

    if ($TopFilesPerPath -eq 0) 
    {
        if ($TopScansPerFilePerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerPath' -ParentParameterName:'TopFilesPerPath'
        }
    }

    if ($TopExtensionsPerPath -eq 0) 
    {
        if ($TopScansPerExtensionPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtensionPerPath' -ParentParameterName:'TopExtensionsPerPath'
        }
    }

    if ($TopProcessesPerPath -eq 0) 
    {
        if ($TopScansPerProcessPerPath -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerPath' -ParentParameterName:'TopProcessesPerPath'
        }
    }

    if ($TopExtensions -eq 0)
    {
        if ($TopScansPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopFilesPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopProcessesPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopProcessesPerExtension' -ParentParameterName:'TopExtensions'
        }

        if ($TopPathsPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopPathsPerExtension' -ParentParameterName:'TopExtensions'
        } 
    }

    if ($TopFilesPerExtension -eq 0)
    {
        if ($TopScansPerFilePerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerExtension' -ParentParameterName:'TopFilesPerExtension'
        }
    }

    if ($TopProcessesPerExtension -eq 0)
    {
        if ($TopScansPerProcessPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcessPerExtension' -ParentParameterName:'TopProcessesPerExtension'
        }
    }

    if ($TopPathsPerExtension -eq 0)
    {
        if ($TopScansPerPathPerExtension -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerPathPerExtension' -ParentParameterName:'TopPathsPerExtension'
        }
    }

    if ($TopProcesses -eq 0)
    {
        if ($TopScansPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopFilesPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopFilesPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopExtensionsPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopExtensionsPerProcess' -ParentParameterName:'TopProcesses'
        }

        if ($TopPathsPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopPathsPerProcess' -ParentParameterName:'TopProcesses'
        }
    }

    if ($TopFilesPerProcess -eq 0)
    {
        if ($TopScansPerFilePerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerFilePerProcess' -ParentParameterName:'TopFilesPerProcess'
        }
    }

    if ($TopExtensionsPerProcess -eq 0)
    {
        if ($TopScansPerExtensionPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerExtensionPerProcess' -ParentParameterName:'TopExtensionsPerProcess'
        }
    }

    if ($TopPathsPerProcess -eq 0)
    {
        if ($TopScansPerPathPerProcess -gt 0)
        {
            ParameterValidationError -ErrorAction:Stop -ParameterName:'TopScansPerPathPerProcess' -ParentParameterName:'TopPathsPerProcess'
        }
    }

    if (($TopFiles -eq 0) -and ($TopExtensions -eq 0) -and ($TopProcesses -eq 0) -and ($TopScans -eq 0) -and ($TopPaths -eq 0) -and (-not $Overview)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "At least one of the parameters 'TopFiles', 'TopPaths', 'TopExtensions', 'TopProcesses', 'TopScans' or 'Overview' must be present."
        $category = [System.Management.Automation.ErrorCategory]::InvalidArgument
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'InvalidArgument',$category,$wprProfile
        $psCmdlet.WriteError($errRecord)
        return
    }

    # Dependencies
    [string]$PlatformPath = (Get-ItemProperty -Path:'HKLM:\Software\Microsoft\Windows Defender' -Name:'InstallLocation' -ErrorAction:Stop).InstallLocation

    #
    # Test dependency presence
    #
    [string]$mpCmdRunCommand = "${PlatformPath}MpCmdRun.exe"

    if (-not (Get-Command $mpCmdRunCommand -ErrorAction:SilentlyContinue)) {
        $ex = New-Object System.Management.Automation.ItemNotFoundException "Cannot find '$mpCmdRunCommand'."
        $category = [System.Management.Automation.ErrorCategory]::ObjectNotFound
        $errRecord = New-Object System.Management.Automation.ErrorRecord $ex,'PathNotFound',$category,$mpCmdRunCommand
        $psCmdlet.WriteError($errRecord)
        return
    } 

    # assemble report arguments

    [string[]]$reportArguments = @(
        $PSBoundParameters.GetEnumerator() |
            Where-Object { $_.Key.ToString().StartsWith("Top") -and ($_.Value -gt 0) } |
            ForEach-Object { "-$($_.Key)"; "$($_.Value)"; }
        )

    [timespan]$MinDurationTimeSpan = ParseFriendlyDuration -FriendlyDuration:$MinDuration

    if ($MinDurationTimeSpan -gt [TimeSpan]::FromTicks(0))
    {
        $reportArguments += @('-MinDuration', ($MinDurationTimeSpan.Ticks))
    }

    $MaxEndTime   = PadUserDateTime -UserDateTime:$MaxEndTime
    $MaxStartTime = PadUserDateTime -UserDateTime:$MaxStartTime

    $ret = ValidateTimeInterval -MinStartTime:$MinStartTime -MaxEndTime:$MaxEndTime -MaxStartTime:$MaxStartTime -MinEndTime:$MinEndTime
    if ($false -eq $ret.status)
    {
        return
    }

    [string[]]$intervalArguments = $ret.arguments
    if (($null -ne $intervalArguments) -and ($intervalArguments.Length -gt 0))
    {
        $reportArguments += $intervalArguments
    }

    if ($Overview)
    {
        $reportArguments += "-Overview"
    }

    $report = (& $mpCmdRunCommand -PerformanceReport -RecordingPath $Path @reportArguments) | Where-Object { -not [string]::IsNullOrEmpty($_) } | ConvertFrom-Json

    $result = [PSCustomObject]@{}

    if (-not $Raw) {
        $result.PSTypeNames.Insert(0, 'MpPerformanceReport.Result')
    }

    if ($TopFiles -gt 0)
    {
        $reportTopFiles = @(if ($null -ne $report.TopFiles) { @($report.TopFiles | ConvertTo-DefenderScannedFilePathStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopFiles' -NotePropertyValue:$reportTopFiles

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopFiles)
        }
    }

    if ($TopPaths -gt 0)
    {
        $reportTopPaths = @(if ($null -ne $report.TopPaths) { @($report.TopPaths | ConvertTo-DefenderScannedPathsStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopPaths' -NotePropertyValue:$reportTopPaths
    
        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopPaths)
        }
    }

    if ($TopExtensions -gt 0)
    {
        $reportTopExtensions = @(if ($null -ne $report.TopExtensions) { @($report.TopExtensions | ConvertTo-DefenderScannedFileExtensionStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopExtensions' -NotePropertyValue:$reportTopExtensions

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopExtensions)
        }
    }

    if ($TopProcesses -gt 0)
    {
        $reportTopProcesses = @(if ($null -ne $report.TopProcesses) { @($report.TopProcesses | ConvertTo-DefenderScannedProcessStats -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopProcesses' -NotePropertyValue:$reportTopProcesses

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopProcesses)
        }
    }

    if ($TopScans -gt 0)
    {
        $reportTopScans = @(if ($null -ne $report.TopScans) { @($report.TopScans | ConvertTo-DefenderScanInfo -Raw:$Raw) } else { @() })
        $result | Add-Member -NotePropertyName:'TopScans' -NotePropertyValue:$reportTopScans

        if (-not $Raw) {
            Add-DefenderCollectionType -CollectionRef:([ref]$result.TopScans)
        }
    }

    if ($Overview)
    {
        if ($null -ne $report.Overview) {
            $reportOverview = $report.Overview | ConvertTo-DefenderScanOverview -Raw:$Raw
            $result | Add-Member -NotePropertyName:'Overview' -NotePropertyValue:$reportOverview

            if (-not $Raw) {
                $result.Overview.PSTypeNames.Insert(0, 'MpPerformanceReport.Overview')
            }
        }
    }

    $result
}

$exportModuleMemberParam = @{
    Function = @(
        'New-MpPerformanceRecording'
        'Get-MpPerformanceReport'
        )
}

Export-ModuleMember @exportModuleMemberParam

# SIG # Begin signature block
# MIIlpQYJKoZIhvcNAQcCoIIlljCCJZICAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCABOtUhuRLDSJsH
# 5LjfiBWymKYbjYNumRKF78V/LI3Gd6CCC2IwggTvMIID16ADAgECAhMzAAAK69Nl
# RIMWPjjtAAAAAArrMA0GCSqGSIb3DQEBCwUAMHkxCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xIzAhBgNVBAMTGk1pY3Jvc29mdCBXaW5kb3dzIFBD
# QSAyMDEwMB4XDTIzMTAxOTE5MTgwMloXDTI0MTAxNjE5MTgwMlowcDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEaMBgGA1UEAxMRTWljcm9zb2Z0
# IFdpbmRvd3MwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCfg+TEc3bT
# Vvq+rfw2TA/Aluhr9MvjyW4v2sVY1+wdq98kJogwk5wRwMEPNKacaRJn02l8VCT5
# eblNMpXt3iD7AcYN+cSnvC4rBDCNKAJAf1ND9AYU9kpP3eKKrxjkbNq5I5uxrIRW
# AP2K3gqGsN8peSb+7/BCINSMrmJ7Tx46PXz8asIJY3TEmq4x13zC5uXtIIb1s/d1
# PWrE9KDPyz16VZQx+ZlNEnFVXH6Cg2gw7AJMQLUHJgeLfLcBilLd/P+2j04e7dgD
# s6fc0Wrw+Bz5EA/kV77PxHLEt7apceKqp5+dNMo1unzlZuMIh5+A6HA7aXbdF9KX
# ujJ6b2MlurVnAgMBAAGjggF3MIIBczAfBgNVHSUEGDAWBgorBgEEAYI3CgMGBggr
# BgEFBQcDAzAdBgNVHQ4EFgQUU6kklw2HQNa4/ec1p2tW744uJekwVAYDVR0RBE0w
# S6RJMEcxLTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGlt
# aXRlZDEWMBQGA1UEBRMNMjMwMDI4KzUwMTcwNTAfBgNVHSMEGDAWgBTRT6mKBwjO
# 9CQYmOUA//PWeR03vDBTBgNVHR8ETDBKMEigRqBEhkJodHRwOi8vY3JsLm1pY3Jv
# c29mdC5jb20vcGtpL2NybC9wcm9kdWN0cy9NaWNXaW5QQ0FfMjAxMC0wNy0wNi5j
# cmwwVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vd3d3Lm1pY3Jv
# c29mdC5jb20vcGtpL2NlcnRzL01pY1dpblBDQV8yMDEwLTA3LTA2LmNydDAMBgNV
# HRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBks51pE8oGEEiS12JhhlAAD/Hf
# E6sdGt6b37sp62b9mymV/X3pl4YjPxzeckToiB4SBLLCuG6PCFWBWvKF3QZV7p4L
# fClCVjXz5SRXHzgZlXnEReG7r4GMXZ9i06zcSWcy/rFEINTZtPCwLYMNTEIpcW+t
# ojVpI6X4FRV5YjfFirE4qmmLYyTQioPYJO5/n2/Xz/BcNj2GFvGycjAtuITmvlPH
# g/ZTaTas8PD5loz8YKngKl/DvfTWEHDyYAdmNZcNRP2BuKf3kksHN20z6Lf/JCK1
# et2f5zMarFELgr12wrdI/8z4+hleNPf9cqU36jrEFauG+XaucS5UlnGp043TMIIG
# azCCBFOgAwIBAgIKYQxqGQAAAAAABDANBgkqhkiG9w0BAQsFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAc
# BgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0
# IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IDIwMTAwHhcNMTAwNzA2MjA0MDIz
# WhcNMjUwNzA2MjA1MDIzWjB5MQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMSMwIQYDVQQDExpNaWNyb3NvZnQgV2luZG93cyBQQ0EgMjAxMDCCASIw
# DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMB5uzqx8A+EuK1kKnUWc9C7B/Y+
# DZ0U5LGfwciUsDh8H9AzVfW6I2b1LihIU8cWg7r1Uax+rOAmfw90/FmV3MnGovdS
# cFosHZSrGb+vlX2vZqFvm2JubUu8LzVs3qRqY1pf+/MNTWHMCn4x62wK0E2XD/1/
# OEbmisdzaXZVaZZM5NjwNOu6sR/OKX7ET50TFasTG3JYYlZsioGjZHeYRmUpnYMU
# pUwIoIPXIx/zX99vLM/aFtgOcgQo2Gs++BOxfKIXeU9+3DrknXAna7/b/B7HB9jA
# vguTHijgc23SVOkoTL9rXZ//XTMSN5UlYTRqQst8nTq7iFnho0JtOlBbSNECAwEA
# AaOCAeMwggHfMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBTRT6mKBwjO9CQY
# mOUA//PWeR03vDAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMC
# AYYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBTV9lbLj+iiXGJo0T2UkFvX
# zpoYxDBWBgNVHR8ETzBNMEugSaBHhkVodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20v
# cGtpL2NybC9wcm9kdWN0cy9NaWNSb29DZXJBdXRfMjAxMC0wNi0yMy5jcmwwWgYI
# KwYBBQUHAQEETjBMMEoGCCsGAQUFBzAChj5odHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpL2NlcnRzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNydDCBnQYDVR0g
# BIGVMIGSMIGPBgkrBgEEAYI3LgMwgYEwPQYIKwYBBQUHAgEWMWh0dHA6Ly93d3cu
# bWljcm9zb2Z0LmNvbS9QS0kvZG9jcy9DUFMvZGVmYXVsdC5odG0wQAYIKwYBBQUH
# AgIwNB4yIB0ATABlAGcAYQBsAF8AUABvAGwAaQBjAHkAXwBTAHQAYQB0AGUAbQBl
# AG4AdAAuIB0wDQYJKoZIhvcNAQELBQADggIBAC5Bpoa1Bm/wgIX6O8oX6cn65DnC
# lHDDZJTD2FamkI7+5Jr0bfVvjlONWqjzrttGbL5/HVRWGzwdccRRFVR+v+6llUIz
# /Q2QJCTj+dyWyvy4rL/0wjlWuLvtc7MX3X6GUCOLViTKu6YdmocvJ4XnobYKnA0b
# jPMAYkG6SHSHgv1QyfSHKcMDqivfGil56BIkmobt0C7TQIH1B18zBlRdQLX3sWL9
# TUj3bkFHUhy7G8JXOqiZVpPUxt4mqGB1hrvsYqbwHQRF3z6nhNFbRCNjJTZ3b65b
# 3CLVFCNqQX/QQqbb7yV7BOPSljdiBq/4Gw+Oszmau4n1NQblpFvDjJ43X1PRozf9
# pE/oGw5rduS4j7DC6v119yxBt5yj4R4F/peSy39ZA22oTo1OgBfU1XL2VuRIn6Mj
# ugagwI7RiE+TIPJwX9hrcqMgSfx3DF3Fx+ECDzhCEA7bAq6aNx1QgCkepKfZxpol
# Vf1Ayq1kEOgx+RJUeRryDtjWqx4z/gLnJm1hSY/xJcKLdJnf+ZMakBzu3ZQzDkJQ
# 239Q+J9iguymghZ8ZrzsmbDBWF2osJphFJHRmS9J5D6Bmdbm78rj/T7u7AmGAwcN
# Gw186/RayZXPhxIKXezFApLNBZlyyn3xKhAYOOQxoyi05kzFUqOcasd9wHEJBA1w
# 3gI/h+5WoezrtUyFMYIZmTCCGZUCAQEwgZAweTELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEjMCEGA1UEAxMaTWljcm9zb2Z0IFdpbmRvd3MgUENB
# IDIwMTACEzMAAArr02VEgxY+OO0AAAAACuswDQYJYIZIAWUDBAIBBQCgga4wGQYJ
# KoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQB
# gjcCARUwLwYJKoZIhvcNAQkEMSIEIP1nRydeaI+1iJEMHgjg/lvzEqkxTM+0Vgz1
# fU+wYXo6MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8AcwBvAGYAdKEa
# gBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEBBQAEggEALywn
# CRgZ5Jbg9T+JXSXA/emxhO33D9HzChrgFT70wCgrW7tp1/URokTk75IG/8HGbtLX
# iL3IXSOgyFttU/ir4H3aOcQeBjCqxkq6ssZdxADkj64m94v+te26Z+9T9k8IyiKf
# t5AqbStTJwNPmNkJUhlsm5pl5IN/g/wrJRWAXz++Ljx1xx8fNNra6cECguorDdyQ
# 5B6v+1hh2DQsxis+NcroiP9zsUgnq1TDIt7BZKF3sRQfiMn2NCvx1isCSIDCnJ4o
# tPziMcJNVrXWBlNGDXdRJxIqiASkQ18u4R7PswEF2ObElDQc0qgx2fa7exbebIRh
# EXe75cdB8DQWpA+ZgqGCFygwghckBgorBgEEAYI3AwMBMYIXFDCCFxAGCSqGSIb3
# DQEHAqCCFwEwghb9AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFZBgsqhkiG9w0BCRAB
# BKCCAUgEggFEMIIBQAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFlAwQCAQUABCCi
# mZCYuTux/SyAj/Wn6eH50nA2Xh+qWnS2SofY6yKtOgIGZjOrR/tqGBMyMDI0MDUx
# MTAxMTM0Ni4zNDdaMASAAgH0oIHYpIHVMIHSMQswCQYDVQQGEwJVUzETMBEGA1UE
# CBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9z
# b2Z0IENvcnBvcmF0aW9uMS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVy
# YXRpb25zIExpbWl0ZWQxJjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOjg2REYtNEJC
# Qy05MzM1MSUwIwYDVQQDExxNaWNyb3NvZnQgVGltZS1TdGFtcCBTZXJ2aWNloIIR
# dzCCBycwggUPoAMCAQICEzMAAAHdXVcdldStqhsAAQAAAd0wDQYJKoZIhvcNAQEL
# BQAwfDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcT
# B1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UE
# AxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTAwHhcNMjMxMDEyMTkwNzA5
# WhcNMjUwMTEwMTkwNzA5WjCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hp
# bmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jw
# b3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0aW9ucyBM
# aW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMtOTMzNTEl
# MCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAKhOA5RE6i53nHURH4lnfKLp+9JvipuTtcta
# irCxMUSrPSy5CWK2DtriQP+T52HXbN2g7AktQ1pQZbTDGFzK6d03vYYNrCPuJK+P
# RsP2FPVDjBXy5mrLRFzIHHLaiAaobE5vFJuoxZ0ZWdKMCs8acjhHUmfaY+79/CR7
# uN+B4+xjJqwvdpU/mp0mAq3earyH+AKmv6lkrQN8zgrcbCgHwsqvvqT6lEFqYpi7
# uKn7MAYbSeLe0pMdatV5EW6NVnXMYOTRKuGPfyfBKdShualLo88kG7qa2mbA5l77
# +X06JAesMkoyYr4/9CgDFjHUpcHSODujlFBKMi168zRdLerdpW0bBX9EDux2zBMM
# aEK8NyxawCEuAq7++7ktFAbl3hUKtuzYC1FUZuUl2Bq6U17S4CKsqR3itLT9qNcb
# 2pAJ4jrIDdll5Tgoqef5gpv+YcvBM834bXFNwytd3ujDD24P9Dd8xfVJvumjsBQQ
# kK5T/qy3HrQJ8ud1nHSvtFVi5Sa/ubGuYEpS8gF6GDWN5/KbveFkdsoTVIPo8pkW
# hjPs0Q7nA5+uBxQB4zljEjKz5WW7BA4wpmFm24fhBmRjV4Nbp+n78cgAjvDSfTlA
# 6DYBcv2kx1JH2dIhaRnSeOXePT6hMF0Il598LMu0rw35ViUWcAQkUNUTxRnqGFxz
# 5w+ZusMDAgMBAAGjggFJMIIBRTAdBgNVHQ4EFgQUbqL1toyPUdpFyyHSDKWj0I4l
# w/EwHwYDVR0jBBgwFoAUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXwYDVR0fBFgwVjBU
# oFKgUIZOaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jcmwvTWljcm9z
# b2Z0JTIwVGltZS1TdGFtcCUyMFBDQSUyMDIwMTAoMSkuY3JsMGwGCCsGAQUFBwEB
# BGAwXjBcBggrBgEFBQcwAoZQaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9w
# cy9jZXJ0cy9NaWNyb3NvZnQlMjBUaW1lLVN0YW1wJTIwUENBJTIwMjAxMCgxKS5j
# cnQwDAYDVR0TAQH/BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDCDAOBgNVHQ8B
# Af8EBAMCB4AwDQYJKoZIhvcNAQELBQADggIBAC5U2bINLgXIHWbMcqVuf9jkUT/K
# 8zyLBvu5h8JrqYR2z/eaO2yo1Ooc9Shyvxbe9GZDu7kkUzxSyJ1IZksZZw6FDq6y
# ZNT3PEjAEnREpRBL8S+mbXg+O4VLS0LSmb8XIZiLsaqZ0fDEcv3HeA+/y/qKnCQW
# kXghpaEMwGMQzRkhGwcGdXr1zGpQ7HTxvfu57xFxZX1MkKnWFENJ6urd+4teUgXj
# 0ngIOx//l3XMK3Ht8T2+zvGJNAF+5/5qBk7nr079zICbFXvxtidNN5eoXdW+9rAI
# kS+UGD19AZdBrtt6dZ+OdAquBiDkYQ5kVfUMKS31yHQOGgmFxuCOzTpWHalrqpdI
# llsy8KNsj5U9sONiWAd9PNlyEHHbQZDmi9/BNlOYyTt0YehLbDovmZUNazk79Od/
# A917mqCdTqrExwBGUPbMP+/vdYUqaJspupBnUtjOf/76DAhVy8e/e6zR98Pkplml
# iO2brL3Q3rD6+ZCVdrGM9Rm6hUDBBkvYh+YjmGdcQ5HB6WT9Rec8+qDHmbhLhX4Z
# daard5/OXeLbgx2f7L4QQQj3KgqjqDOWInVhNE1gYtTWLHe4882d/k7Lui0K1g8E
# ZrKD7maOrsJLKPKlegceJ9FCqY1sDUKUhRa0EHUW+ZkKLlohKrS7FwjdrINWkPBg
# bQznCjdE2m47QjTbMIIHcTCCBVmgAwIBAgITMwAAABXF52ueAptJmQAAAAAAFTAN
# BgkqhkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0
# b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3Jh
# dGlvbjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9y
# aXR5IDIwMTAwHhcNMjEwOTMwMTgyMjI1WhcNMzAwOTMwMTgzMjI1WjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCC
# AgoCggIBAOThpkzntHIhC3miy9ckeb0O1YLT/e6cBwfSqWxOdcjKNVf2AX9sSuDi
# vbk+F2Az/1xPx2b3lVNxWuJ+Slr+uDZnhUYjDLWNE893MsAQGOhgfWpSg0S3po5G
# awcU88V29YZQ3MFEyHFcUTE3oAo4bo3t1w/YJlN8OWECesSq/XJprx2rrPY2vjUm
# ZNqYO7oaezOtgFt+jBAcnVL+tuhiJdxqD89d9P6OU8/W7IVWTe/dvI2k45GPsjks
# UZzpcGkNyjYtcI4xyDUoveO0hyTD4MmPfrVUj9z6BVWYbWg7mka97aSueik3rMvr
# g0XnRm7KMtXAhjBcTyziYrLNueKNiOSWrAFKu75xqRdbZ2De+JKRHh09/SDPc31B
# mkZ1zcRfNN0Sidb9pSB9fvzZnkXftnIv231fgLrbqn427DZM9ituqBJR6L8FA6PR
# c6ZNN3SUHDSCD/AQ8rdHGO2n6Jl8P0zbr17C89XYcz1DTsEzOUyOArxCaC4Q6oRR
# RuLRvWoYWmEBc8pnol7XKHYC4jMYctenIPDC+hIK12NvDMk2ZItboKaDIV1fMHSR
# lJTYuVD5C4lh8zYGNRiER9vcG9H9stQcxWv2XFJRXRLbJbqvUAV6bMURHXLvjflS
# xIUXk8A8FdsaN8cIFRg/eKtFtvUeh17aj54WcmnGrnu3tz5q4i6tAgMBAAGjggHd
# MIIB2TASBgkrBgEEAYI3FQEEBQIDAQABMCMGCSsGAQQBgjcVAgQWBBQqp1L+ZMSa
# voKRPEY1Kc8Q/y8E7jAdBgNVHQ4EFgQUn6cVXQBeYl2D9OXSZacbUzUZ6XIwXAYD
# VR0gBFUwUzBRBgwrBgEEAYI3TIN9AQEwQTA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9Eb2NzL1JlcG9zaXRvcnkuaHRtMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMIMBkGCSsGAQQBgjcUAgQMHgoAUwB1AGIAQwBBMAsGA1Ud
# DwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjR
# PZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0
# LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNy
# bDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWljcm9z
# b2Z0LmNvbS9wa2kvY2VydHMvTWljUm9vQ2VyQXV0XzIwMTAtMDYtMjMuY3J0MA0G
# CSqGSIb3DQEBCwUAA4ICAQCdVX38Kq3hLB9nATEkW+Geckv8qW/qXBS2Pk5HZHix
# BpOXPTEztTnXwnE2P9pkbHzQdTltuw8x5MKP+2zRoZQYIu7pZmc6U03dmLq2HnjY
# Ni6cqYJWAAOwBb6J6Gngugnue99qb74py27YP0h1AdkY3m2CDPVtI1TkeFN1JFe5
# 3Z/zjj3G82jfZfakVqr3lbYoVSfQJL1AoL8ZthISEV09J+BAljis9/kpicO8F7BU
# hUKz/AyeixmJ5/ALaoHCgRlCGVJ1ijbCHcNhcy4sa3tuPywJeBTpkbKpW99Jo3QM
# vOyRgNI95ko+ZjtPu4b6MhrZlvSP9pEB9s7GdP32THJvEKt1MMU0sHrYUP4KWN1A
# PMdUbZ1jdEgssU5HLcEUBHG/ZPkkvnNtyo4JvbMBV0lUZNlz138eW0QBjloZkWsN
# n6Qo3GcZKCS6OEuabvshVGtqRRFHqfG3rsjoiV5PndLQTHa1V1QJsWkBRH58oWFs
# c/4Ku+xBZj1p/cvBQUl+fpO+y/g75LcVv7TOPqUxUYS8vwLBgqJ7Fx0ViY1w/ue1
# 0CgaiQuPNtq6TPmb/wrpNPgkNWcr4A245oyZ1uEi6vAnQj0llOZ0dFtq0Z4+7X6g
# MTN9vMvpe784cETRkPHIqzqKOghif9lwY1NNje6CbaUFEMFxBmoQtB1VM1izoXBm
# 8qGCAtMwggI8AgEBMIIBAKGB2KSB1TCB0jELMAkGA1UEBhMCVVMxEzARBgNVBAgT
# Cldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29m
# dCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3BlcmF0
# aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjo4NkRGLTRCQkMt
# OTMzNTElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgU2VydmljZaIjCgEB
# MAcGBSsOAwIaAxUANiNHGWXbNaDPxnyiDbEOciSjFhCggYMwgYCkfjB8MQswCQYD
# VQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEe
# MBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3Nv
# ZnQgVGltZS1TdGFtcCBQQ0EgMjAxMDANBgkqhkiG9w0BAQUFAAIFAOnotPEwIhgP
# MjAyNDA1MTAyMzAwMDFaGA8yMDI0MDUxMTIzMDAwMVowczA5BgorBgEEAYRZCgQB
# MSswKTAKAgUA6ei08QIBADAGAgEAAgERMAcCAQACAhIcMAoCBQDp6gZxAgEAMDYG
# CisGAQQBhFkKBAIxKDAmMAwGCisGAQQBhFkKAwKgCjAIAgEAAgMHoSChCjAIAgEA
# AgMBhqAwDQYJKoZIhvcNAQEFBQADgYEAOTMOoIT6Gy7pxoCAMyDNut/vx5QeRm7C
# OPLaXm9SWoGD08gEHQ1tNmbZIig1oB5hgwrwRP//v8ze3DtN++hrduV7Ytj4Deo4
# u1jiTG77XoHNkdJWcZ2l5gNVy2axGEqKhnKgd+Xn4z1DwCXzmJ2Z57TtxrbKaRQa
# zuFx48R0GV8xggQNMIIECQIBATCBkzB8MQswCQYDVQQGEwJVUzETMBEGA1UECBMK
# V2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0
# IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQgVGltZS1TdGFtcCBQQ0Eg
# MjAxMAITMwAAAd1dVx2V1K2qGwABAAAB3TANBglghkgBZQMEAgEFAKCCAUowGgYJ
# KoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEEMC8GCSqGSIb3DQEJBDEiBCDWhppEzfJv
# k0Nmyps96Isbe7yXtaB3Ngeprx1JzkDidTCB+gYLKoZIhvcNAQkQAi8xgeowgecw
# geQwgb0EIGH/Di2aZaxPeJmce0fRWTftQI3TaVHFj5GI43rAMWNmMIGYMIGApH4w
# fDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1Jl
# ZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMd
# TWljcm9zb2Z0IFRpbWUtU3RhbXAgUENBIDIwMTACEzMAAAHdXVcdldStqhsAAQAA
# Ad0wIgQgYfrepF1BlWFaDZS0jWeTZ1wmUux9ELPbsBfbF6n5FUMwDQYJKoZIhvcN
# AQELBQAEggIAF7AFMOzf8vBvRbvU6WsXOixaunoQAqhwd8RhmXrP9veYxKpGO4Xk
# pnbY2oXkz3/tuioHvxATOjwoVitikNJe5VdSsPszlgRisltZbRqRcmHGw34X2NEE
# 1SigRMTBA2rmjh8SvanlD19kRJNk7nkRnxoZffJQJG65vhiiiIg+5lq9ukRIZSec
# UC6o3HlVzhQCAegYGxk8aarqTVzw3SgjUwYwahj5V2f9PzA11GLuYBFq62X4xQ0y
# 3DJECmXrxhj1eeBxGrw1rQ13p3tTywQkGqHS0DWxPzlNl7oAE8uNRba6mdXPs3oO
# dhfqyfwPjCEIeeD7N3+A58D74B+mkeeY+JU8Dcq4kCGHVcsWTwbn5aMTstEyWdYx
# y3BTyfo2yksiqiQEXOArT+YdlR4UvcXf4Q7W1UWJybS4ac0vSr68ad7kyUlmjDYk
# Qvr1tkwdLdv7eEPBF9SaCsdFnX+CloMlD/MuVr9N6Agddd8FWDw37AeuD1tGAxBb
# HCTnMaDR807gagVIabjmgpBdV2WhpPIwk7c2kSFVGB6Pj0iCN4cOYHcnttnmxnNR
# rFmKdQu9G+jiKpbdrQJ6mQ30KZq3vdNH0RhSYkGGVXJ0MkzJuf9UKk78AUNenS6f
# cw74idHY3pLGSWNjTqd0HXHgi4LfOCqit4HhmtWgmWQHK/u6Id+QnIA=
# SIG # End signature block
