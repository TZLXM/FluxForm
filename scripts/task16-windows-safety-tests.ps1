$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$modulePath = Join-Path $PSScriptRoot 'Task16WindowsSafety.psm1'
Import-Module -Name $modulePath -Force

function Assert-True([bool]$Value, [string]$Message) {
    if (-not $Value) { throw $Message }
}

$tempBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
$tempRoot = Join-Path $tempBase ('fluxform-task16-safety-' + [Guid]::NewGuid().ToString('N'))
$createdRoot = $false
$junctionPath = $null
try {
    [IO.Directory]::CreateDirectory($tempRoot) | Out-Null
    $createdRoot = $true
    $realDirectory = Join-Path $tempRoot 'real'
    [IO.Directory]::CreateDirectory($realDirectory) | Out-Null
    $realFile = Join-Path $realDirectory 'inside.txt'
    [IO.File]::WriteAllText($realFile, 'test fixture')

    $normalPath = Assert-Task16PathWithin -Candidate $realFile -Root $tempRoot -MustExist
    Assert-True ($normalPath.Equals([IO.Path]::GetFullPath($realFile), [StringComparison]::OrdinalIgnoreCase)) 'Normal contained path was not canonicalized.'
    $escapedPathRejected = $false
    try { Assert-Task16PathWithin -Candidate (Join-Path $env:WINDIR 'win.ini') -Root $tempRoot | Out-Null }
    catch { $escapedPathRejected = $true }
    Assert-True $escapedPathRejected 'Out-of-root path was accepted.'

    $junctionPath = Join-Path $tempRoot 'junction'
    New-Item -ItemType Junction -Path $junctionPath -Target $realDirectory | Out-Null
    $junctionRejected = $false
    try { Assert-Task16PathWithin -Candidate (Join-Path $junctionPath 'inside.txt') -Root $tempRoot -MustExist | Out-Null }
    catch { $junctionRejected = $true }
    Assert-True $junctionRejected 'Contained path traversing a junction was accepted.'

    $systemTimeout = Join-Path ([Environment]::SystemDirectory) 'timeout.exe'
    if (-not (Test-Path -LiteralPath $systemTimeout -PathType Leaf)) { throw "Windows timeout.exe is not available for the launch-lock self-test: $systemTimeout" }
    $fixtureExecutable = Join-Path $tempRoot 'timeout.exe'
    Copy-Item -LiteralPath $systemTimeout -Destination $fixtureExecutable
    $pinnedHandle = Open-Task16PinnedReadHandle -Path $fixtureExecutable
    try {
        $pinnedHash = Get-Task16PinnedSha256 -Handle $pinnedHandle
        $writeOpenRejected = $false
        try {
            $writeProbe = [IO.File]::Open($fixtureExecutable, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
            $writeProbe.Dispose()
        } catch { $writeOpenRejected = $true }
        Assert-True $writeOpenRejected 'Pinned read handle allowed another writer to open the executable.'

        $renameRejected = $false
        $renamedPath = Join-Path $tempRoot 'timeout-renamed.exe'
        try { [IO.File]::Move($fixtureExecutable, $renamedPath) }
        catch { $renameRejected = $true }
        if (-not $renameRejected) {
            [IO.File]::Move($renamedPath, $fixtureExecutable)
            throw 'Pinned read handle allowed the executable path to be renamed.'
        }

        $launchFailure = $null
        $unexpectedProcess = $null
        try {
            $wrongExpectedImagePath = Join-Path $tempRoot 'intentionally-wrong-image.exe'
            $unexpectedProcess = Start-Task16PinnedProcess -Path $fixtureExecutable -Handle $pinnedHandle -ExpectedSha256 $pinnedHash -ExpectedImagePath $wrongExpectedImagePath -ArgumentList @('/t', '20', '/nobreak') -WindowStyle Hidden
        } catch {
            $launchFailure = $_.Exception
        }
        if ($unexpectedProcess) {
            try { $unexpectedProcess.Kill(); $null = $unexpectedProcess.WaitForExit(5000) } catch { }
            throw 'Intentional post-launch image-path validation failure was not raised; test-owned child was cleaned by exact Process object.'
        }
        if ($null -eq $launchFailure) { throw 'Intentional post-launch image-path validation failure was not raised.' }
        $failedLaunchPid = [int]$launchFailure.Data['Task16ProcessId']
        $failedLaunchCleanupEstablished = [bool]$launchFailure.Data['Task16CleanupEstablished']
        $failedLaunchProcess = Get-Process -Id $failedLaunchPid -ErrorAction SilentlyContinue
        $failedLaunchChildStillPresent = $false
        if ($failedLaunchProcess) {
            $failedLaunchPath = Get-Task16ProcessImagePath -Process $failedLaunchProcess
            if ($failedLaunchPath.Equals([IO.Path]::GetFullPath($fixtureExecutable), [StringComparison]::OrdinalIgnoreCase)) {
                $failedLaunchChildStillPresent = $true
                # Test-owned emergency cleanup is exact-PID and additionally requires the unique fixture image path.
                try { $failedLaunchProcess.Kill(); $null = $failedLaunchProcess.WaitForExit(5000) } catch { }
            }
        }
        if ($failedLaunchPid -le 0) {
            $innerException = if ($launchFailure.InnerException) { $launchFailure.InnerException } else { $null }
            $diagnostic = "type=$($launchFailure.GetType().FullName); message=$($launchFailure.Message); data_count=$($launchFailure.Data.Count); inner_type=$(if($innerException){$innerException.GetType().FullName}); inner_data_count=$(if($innerException){$innerException.Data.Count})"
            throw "Post-launch validation exception did not preserve the spawned PID. $diagnostic"
        }
        Assert-True $failedLaunchCleanupEstablished 'Post-launch validation did not establish bounded exact-process cleanup.'
        Assert-True ([bool]$launchFailure.Data['Task16CleanupForced']) 'Timed test process cleanup did not record exact-process forced termination.'
        Assert-True (-not $failedLaunchChildStillPresent) 'The exact test process survived post-launch validation failure cleanup.'
        $simulatedCleanupFailure = [pscustomobject]@{
            ProcessId = $failedLaunchPid
            Established = $false
            Forced = $true
            Error = 'self-test injected bounded-cleanup failure'
        }
        $cleanupFailureException = New-Task16LaunchFailureException -ProcessId $failedLaunchPid -ValidationError 'self-test validation failure' -CleanupResult $simulatedCleanupFailure
        Assert-True (-not [bool]$cleanupFailureException.Data['Task16CleanupEstablished']) 'Cleanup-failure exception incorrectly claimed process exit was established.'
        Assert-True ([int]$cleanupFailureException.Data['Task16ProcessId'] -eq $failedLaunchPid) 'Cleanup-failure exception lost the exact spawned PID.'
        Assert-True ($cleanupFailureException.Message -like '*may still be running*' -and $cleanupFailureException.Message -like '*self-test injected bounded-cleanup failure*') 'Cleanup-failure exception did not tell the caller to retain the PID and report the cleanup error.'

    } finally {
        $pinnedHandle.Dispose()
    }

    $validObservation = Test-Task16ObservationPass -SecondLaunchPassed $true -SingleClosePassed $true -LastClosePassed $true -ProcessClosed $true -ForcedTermination $false -NoLateProcess $true
    $forcedObservation = Test-Task16ObservationPass -SecondLaunchPassed $true -SingleClosePassed $true -LastClosePassed $true -ProcessClosed $true -ForcedTermination $true -NoLateProcess $true
    $lateObservation = Test-Task16ObservationPass -SecondLaunchPassed $true -SingleClosePassed $true -LastClosePassed $true -ProcessClosed $true -ForcedTermination $false -NoLateProcess $false
    Assert-True $validObservation 'Complete safe observation should satisfy the structural gate.'
    Assert-True (-not $forcedObservation) 'Observation gate accepted forced termination.'
    Assert-True (-not $lateObservation) 'Observation gate accepted a late/restarted process.'

    $structuralPaths = Get-Task16StructuralPaths -AppDataDirectory $tempRoot -ObservationId 'task16-observation-test1'
    Assert-True ($structuralPaths.SummaryPath -notmatch '[\\/]probe-results[\\/]') 'Structural result uses the app canonical probe-results directory.'
    Assert-True ($structuralPaths.SummaryPath -match 'task16-native-observations') 'Structural result is not distinctly named as a Task16 observation.'

    [ordered]@{
        safety_self_test = 'PASS'
        write_denied_while_pinned = $writeOpenRejected
        rename_denied_while_pinned = $renameRejected
        failed_launch_pid_preserved = $failedLaunchPid
        failed_launch_cleanup_established = $failedLaunchCleanupEstablished
        failed_launch_exact_process_exited = (-not $failedLaunchChildStillPresent)
        cleanup_failure_preserves_pid_and_reports_unestablished_exit = ([int]$cleanupFailureException.Data['Task16ProcessId'] -eq $failedLaunchPid -and -not [bool]$cleanupFailureException.Data['Task16CleanupEstablished'] -and $cleanupFailureException.Message -like '*may still be running*')
        post_launch_validation_error = [string]$launchFailure.Data['Task16ValidationError']
        out_of_root_path_rejected = $escapedPathRejected
        junction_path_rejected = $junctionRejected
        forced_termination_blocks_pass = (-not $forcedObservation)
        late_process_blocks_pass = (-not $lateObservation)
        structural_result_separate_from_window_probe_result = $structuralPaths.SummaryPath
    } | ConvertTo-Json -Depth 4
} finally {
    if ($junctionPath -and (Test-Path -LiteralPath $junctionPath)) {
        [IO.Directory]::Delete($junctionPath)
    }
    if ($createdRoot -and (Test-Path -LiteralPath $tempRoot)) {
        $canonicalTempRoot = [IO.Path]::GetFullPath($tempRoot)
        if (-not $canonicalTempRoot.StartsWith($tempBase + '\', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean test path outside temp directory: $canonicalTempRoot"
        }
        Remove-Item -LiteralPath $canonicalTempRoot -Recurse -Force
    }
}
