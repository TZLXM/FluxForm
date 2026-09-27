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

        $pinnedProcess = Start-Task16PinnedProcess -Path $fixtureExecutable -Handle $pinnedHandle -ExpectedSha256 $pinnedHash -ArgumentList @('/t', '2', '/nobreak') -WindowStyle Hidden
        $actualImagePath = Get-Task16ProcessImagePath -Process $pinnedProcess
        Assert-True ($actualImagePath.Equals([IO.Path]::GetFullPath($fixtureExecutable), [StringComparison]::OrdinalIgnoreCase)) 'Started process image path did not match the locked executable.'
        $pinnedProcess.WaitForExit()
        Assert-True ($pinnedProcess.ExitCode -eq 0) "Locked test process exited with $($pinnedProcess.ExitCode)."
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
        pinned_process_image_verified = $actualImagePath
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
