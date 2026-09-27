Set-StrictMode -Version Latest

function Get-Task16CanonicalPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'A path is required.' }
    return [IO.Path]::GetFullPath($Path)
}

function Assert-Task16NoReparsePoints([string]$Path, [switch]$MustExist) {
    $fullPath = Get-Task16CanonicalPath $Path
    $volumeRoot = [IO.Path]::GetPathRoot($fullPath)
    $current = $volumeRoot
    $remainder = $fullPath.Substring($volumeRoot.Length)
    foreach ($part in ($remainder -split '[\\/]+' | Where-Object { $_ })) {
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a path containing a reparse point: $current"
            }
        } elseif ($MustExist) {
            throw "Required path does not exist: $current"
        }
    }
    return $fullPath
}

function Assert-Task16PathWithin([string]$Candidate, [string]$Root, [switch]$MustExist) {
    $candidateFull = Get-Task16CanonicalPath $Candidate
    $rootFull = (Get-Task16CanonicalPath $Root).TrimEnd('\')
    if (-not $candidateFull.Equals($rootFull, [StringComparison]::OrdinalIgnoreCase) -and
        -not $candidateFull.StartsWith($rootFull + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path escapes its required root '$rootFull': $candidateFull"
    }
    return Assert-Task16NoReparsePoints $candidateFull -MustExist:$MustExist
}

function Open-Task16PinnedReadHandle([string]$Path) {
    $fullPath = Assert-Task16NoReparsePoints $Path -MustExist
    # FILE_SHARE_READ deliberately excludes FILE_SHARE_WRITE and FILE_SHARE_DELETE. Keep this
    # handle open from hashing through CreateProcess/Start-Process and post-launch identity checks.
    $stream = [IO.File]::Open($fullPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $openedPath = Get-Task16CanonicalPath $stream.Name
    if (-not $openedPath.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) {
        $stream.Dispose()
        throw "Locked file path differs from the requested canonical path: $openedPath"
    }
    return $stream
}

function Get-Task16PinnedSha256([IO.FileStream]$Handle) {
    if ($null -eq $Handle -or -not $Handle.CanRead -or -not $Handle.CanSeek) {
        throw 'A readable, seekable pinned file handle is required.'
    }
    $savedPosition = $Handle.Position
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $Handle.Position = 0
        return ([BitConverter]::ToString($sha.ComputeHash($Handle))).Replace('-', '').ToLowerInvariant()
    } finally {
        $Handle.Position = [Math]::Min($savedPosition, $Handle.Length)
        $sha.Dispose()
    }
}

function Get-Task16ProcessImagePath([Diagnostics.Process]$Process) {
    if ($null -eq $Process) { throw 'A process object is required for image identity verification.' }
    $Process.Refresh()
    try {
        $imagePath = [string]$Process.MainModule.FileName
    } catch {
        $imagePath = $null
    }
    if ([string]::IsNullOrWhiteSpace($imagePath)) {
        try {
            $imagePath = [string](Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($Process.Id)" -ErrorAction Stop).ExecutablePath
        } catch {
            throw "Could not query the launched process image path for PID $($Process.Id): $($_.Exception.Message)"
        }
    }
    if ([string]::IsNullOrWhiteSpace($imagePath)) {
        throw "The launched process image path is unavailable for PID $($Process.Id)."
    }
    return Get-Task16CanonicalPath $imagePath
}

function Start-Task16PinnedProcess(
    [string]$Path,
    [IO.FileStream]$Handle,
    [string]$ExpectedSha256,
    [string[]]$ArgumentList = @(),
    [ValidateSet('Normal', 'Hidden', 'Minimized', 'Maximized')][string]$WindowStyle
) {
    $fullPath = Get-Task16CanonicalPath $Path
    if ($null -eq $Handle -or -not $Handle.CanRead -or
        -not (Get-Task16CanonicalPath $Handle.Name).Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The process path is not protected by the matching pinned read handle.'
    }
    if ((Get-Task16PinnedSha256 $Handle) -ne $ExpectedSha256.ToLowerInvariant()) {
        throw "Pinned executable SHA-256 changed before launch: $fullPath"
    }

    $startArguments = @{ FilePath = $fullPath; PassThru = $true }
    if ($ArgumentList.Count -gt 0) { $startArguments.ArgumentList = $ArgumentList }
    if (-not [string]::IsNullOrWhiteSpace($WindowStyle)) { $startArguments.WindowStyle = $WindowStyle }
    $process = Start-Process @startArguments
    try {
        $actualImagePath = Get-Task16ProcessImagePath $process
        if (-not $actualImagePath.Equals($fullPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Launched process image identity mismatch: expected '$fullPath', observed '$actualImagePath'."
        }
        if ((Get-Task16PinnedSha256 $Handle) -ne $ExpectedSha256.ToLowerInvariant()) {
            throw "Pinned executable SHA-256 changed across process creation: $fullPath"
        }
    } catch {
        throw "Process launch was not verified; refusing a verified-launch result. $($_.Exception.Message)"
    }
    return $process
}

function Test-Task16ObservationPass(
    [bool]$SecondLaunchPassed,
    [bool]$SingleClosePassed,
    [bool]$LastClosePassed,
    [bool]$ProcessClosed,
    [bool]$ForcedTermination,
    [bool]$NoLateProcess
) {
    return $SecondLaunchPassed -and $SingleClosePassed -and $LastClosePassed -and
        $ProcessClosed -and (-not $ForcedTermination) -and $NoLateProcess
}

function Get-Task16StructuralPaths([string]$AppDataDirectory, [string]$ObservationId) {
    if ($ObservationId -notmatch '^task16-observation-[A-Za-z0-9._-]{1,120}$') {
        throw 'ObservationId must begin with task16-observation- and contain only ASCII letters, digits, dot, underscore, or hyphen.'
    }
    $directory = Join-Path (Get-Task16CanonicalPath $AppDataDirectory) 'task16-native-observations'
    return [pscustomobject]@{
        Directory = $directory
        SummaryPath = (Join-Path $directory ("window-structure-$ObservationId.json"))
        RawPath = (Join-Path $directory ("process-observations-$ObservationId.json"))
    }
}

Export-ModuleMember -Function @(
    'Get-Task16CanonicalPath',
    'Assert-Task16NoReparsePoints',
    'Assert-Task16PathWithin',
    'Open-Task16PinnedReadHandle',
    'Get-Task16PinnedSha256',
    'Get-Task16ProcessImagePath',
    'Start-Task16PinnedProcess',
    'Test-Task16ObservationPass',
    'Get-Task16StructuralPaths'
)
