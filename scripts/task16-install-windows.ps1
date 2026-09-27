[CmdletBinding()]
param(
    [string]$InstallerPath,
    [string]$InstallId = ('task16-' + [Guid]::NewGuid().ToString('N')),
    [switch]$ResumeFinalize,
    [switch]$PathGuardSelfTest,
    [int]$ObservedInstallerExitCode = -1,
    [string]$InstallerExitEvidence
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedInstallerSha256 = '42b5ee0d33ca1b0b3379d916388f083a4844b7dde303459975e7222531d87491'
$task15StandaloneExecutableSha256 = 'd0ef712d4adc71c3a6a3ecaab7a0e7821323246cdb1c07cbef10c032f2f32b19'
$expectedExecutableName = 'fluxform-desktop-probe.exe'
$expectedUninstallerName = 'uninstall.exe'
$expectedMode = 'transparent-orb'
$approvedResumeInstallId = 'task16-d259e385be404ac78d5191891e100df8'
$approvedResumeEvidence = 'prior verifier run waited for NSIS exit, passed its nonzero-exit guard, then stopped at the post-install executable identity check'

if ([string]::IsNullOrWhiteSpace($InstallerPath)) {
    $InstallerPath = Join-Path $PSScriptRoot '..\target\release\bundle\nsis\FluxForm Desktop Probe_0.1.0_x64-setup.exe'
}

function Get-FullPath([string]$Path) {
    return [IO.Path]::GetFullPath($Path)
}

function Assert-NoReparsePoints([string]$Path, [switch]$MustExist) {
    $fullPath = Get-FullPath $Path
    $root = [IO.Path]::GetPathRoot($fullPath)
    $current = $root
    $remainder = $fullPath.Substring($root.Length)
    foreach ($part in ($remainder -split '[\\/]+' | Where-Object { $_ })) {
        $current = Join-Path $current $part
        if (Test-Path -LiteralPath $current) {
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a reparse-point path component: $current"
            }
        } elseif ($MustExist) {
            throw "Required path component does not exist: $current"
        }
    }
    return $fullPath
}

function Test-PathWithin([string]$Child, [string]$Parent) {
    $childFull = (Get-FullPath $Child).TrimEnd('\')
    $parentFull = (Get-FullPath $Parent).TrimEnd('\')
    return $childFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase) -or
        $childFull.StartsWith($parentFull + '\', [StringComparison]::OrdinalIgnoreCase)
}

function Assert-NotBuildTreePath([string]$Path, [string]$RepositoryRoot) {
    $fullPath = Get-FullPath $Path
    if (Test-PathWithin $fullPath $RepositoryRoot) {
        throw "Refusing a repository/worktree path as an installed executable: $fullPath"
    }
    if ($fullPath -match '(?i)(?:^|[\\/])(?:target|bin|obj|publish|build)(?:[\\/]|$)') {
        throw "Refusing a build-output path as an installed executable: $fullPath"
    }
}

function Write-JsonCreateNew([string]$Path, [object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 6) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

if ($InstallId -notmatch '^task16-[A-Za-z0-9._-]{1,120}$') {
    throw 'InstallId must begin with task16- and contain only ASCII letters, digits, dot, underscore, or hyphen.'
}

$repositoryRoot = Get-FullPath (Join-Path $PSScriptRoot '..')
if ($PathGuardSelfTest) {
    $buildTreeCandidate = Join-Path $repositoryRoot 'target\release\fluxform-desktop-probe.exe'
    $buildTreeRejected = $false
    try {
        Assert-NotBuildTreePath $buildTreeCandidate $repositoryRoot
    } catch {
        $buildTreeRejected = $_.Exception.Message -like '*repository/worktree path*' -or
            $_.Exception.Message -like '*build-output path*'
    }
    if (-not $buildTreeRejected) {
        throw "The build-tree path guard failed to reject $buildTreeCandidate"
    }
    $installedCandidate = Join-Path $env:LOCALAPPDATA 'Programs\FluxForm-Task16\path-guard-test\fluxform-desktop-probe.exe'
    Assert-NotBuildTreePath $installedCandidate $repositoryRoot
    [ordered]@{
        path_guard_status = 'PASS'
        rejected_build_tree_candidate = $buildTreeCandidate
        accepted_per_user_install_candidate = [IO.Path]::GetFullPath($installedCandidate)
        filesystem_changes = $false
    } | ConvertTo-Json -Depth 3
    exit 0
}

$installerFullPath = Assert-NoReparsePoints $InstallerPath -MustExist
if (-not (Test-Path -LiteralPath $installerFullPath -PathType Leaf)) {
    throw "Installer file is missing: $installerFullPath"
}
$installerHash = (Get-FileHash -LiteralPath $installerFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($installerHash -ne $expectedInstallerSha256) {
    throw "Installer SHA-256 mismatch; expected $expectedInstallerSha256, got $installerHash"
}

$programsRoot = Join-Path $env:LOCALAPPDATA 'Programs'
$taskInstallRoot = Join-Path $programsRoot 'FluxForm-Task16'
$installDirectory = Get-FullPath (Join-Path $taskInstallRoot $InstallId)
$manifestDirectory = Join-Path $env:LOCALAPPDATA 'com.fluxform.desktop-probe'
$manifestPath = Join-Path $manifestDirectory 'installed-provenance.json'
$journalPath = Join-Path $manifestDirectory ("task16-installer-journal-$InstallId.json")

$null = Assert-NoReparsePoints $env:LOCALAPPDATA -MustExist
$null = Assert-NoReparsePoints $programsRoot
$null = Assert-NoReparsePoints $taskInstallRoot
$null = Assert-NoReparsePoints $manifestDirectory
$null = Assert-NoReparsePoints $installDirectory

if (Test-Path -LiteralPath $manifestPath) {
    throw "Refusing to overwrite an existing provenance manifest: $manifestPath"
}
if (Test-Path -LiteralPath $journalPath) {
    throw "Refusing to overwrite existing installer-run evidence: $journalPath"
}

$runningProbeProcesses = @(Get-Process -Name 'fluxform-desktop-probe' -ErrorAction SilentlyContinue)
if ($runningProbeProcesses.Count -gt 0) {
    throw 'Refusing to create shared app-local provenance while another probe process is running.'
}

$installerExitCode = -1
$installerRunEvidence = ''
$installCommand = ''
$installerProcessId = $null

if ($ResumeFinalize) {
    if ($InstallId -ne $approvedResumeInstallId) {
        throw "Resume/finalize is limited to the one observed partial install: $approvedResumeInstallId"
    }
    if ($ObservedInstallerExitCode -ne 0 -or $InstallerExitEvidence -ne $approvedResumeEvidence) {
        throw 'Resume/finalize requires the exact prior-run exit evidence and observed exit code 0.'
    }
    if (-not (Test-Path -LiteralPath $installDirectory -PathType Container)) {
        throw "The exact partial install directory is missing: $installDirectory"
    }
    $installerExitCode = $ObservedInstallerExitCode
    $installerRunEvidence = $InstallerExitEvidence
    $installCommand = 'prior invocation: NSIS installer /S /D=' + $installDirectory

    $uninstallEntries = @(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -eq 'FluxForm Desktop Probe' -and $_.DisplayVersion -eq '0.1.0'
    })
    if ($uninstallEntries.Count -ne 1) {
        throw "Resume/finalize requires exactly one matching per-user uninstall registration; found $($uninstallEntries.Count)."
    }
    $registeredInstallLocation = ([string]$uninstallEntries[0].InstallLocation).Trim().Trim('"')
    if (-not $registeredInstallLocation -or -not (Get-FullPath $registeredInstallLocation).Equals($installDirectory, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The per-user uninstall registration does not point to the exact observed install directory: $registeredInstallLocation"
    }
    $registeredUninstaller = ([string]$uninstallEntries[0].UninstallString).Trim().Trim('"')
    if (-not $registeredUninstaller -or -not (Get-FullPath $registeredUninstaller).Equals((Join-Path $installDirectory $expectedUninstallerName), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The per-user uninstaller registration does not point to the expected uninstall.exe in the exact install root.'
    }
} else {
    if (Test-Path -LiteralPath $installDirectory) {
        throw "Refusing to install over an existing target directory: $installDirectory"
    }
    $matchingUninstallEntries = @(Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*' -ErrorAction SilentlyContinue | Where-Object {
        $_.DisplayName -eq 'FluxForm Desktop Probe'
    })
    if ($matchingUninstallEntries.Count -gt 0) {
        throw 'Refusing a fresh install while another FluxForm Desktop Probe per-user installation is registered.'
    }
    if (-not (Test-Path -LiteralPath $taskInstallRoot -PathType Container)) {
        [IO.Directory]::CreateDirectory($taskInstallRoot) | Out-Null
    }
    if (Test-Path -LiteralPath $installDirectory) {
        throw "Target install directory appeared before installation: $installDirectory"
    }

    # NSIS requires /D as the final option. The generated target path contains no spaces.
    $installArgument = '/D=' + $installDirectory
    $installCommand = '"' + $installerFullPath + '" /S ' + $installArgument
    $installerProcess = Start-Process -FilePath $installerFullPath -ArgumentList @('/S', $installArgument) -PassThru -WindowStyle Hidden
    $installerProcess.WaitForExit()
    $installerProcessId = $installerProcess.Id
    $installerExitCode = $installerProcess.ExitCode
    if ($installerExitCode -ne 0) {
        throw "NSIS installer exited with code $installerExitCode; any partial files are retained at $installDirectory."
    }
    if (-not (Test-Path -LiteralPath $installDirectory -PathType Container)) {
        throw "Installer exited successfully but did not create its requested directory: $installDirectory"
    }
    $installerRunEvidence = 'verifier waited for NSIS process exit and observed exit code 0'
}

$null = Assert-NoReparsePoints $installDirectory -MustExist
$canonicalInstallDirectory = (Get-Item -LiteralPath $installDirectory).FullName.TrimEnd('\')
$executables = @(Get-ChildItem -LiteralPath $installDirectory -Filter $expectedExecutableName -File -Recurse)
$uninstallers = @(Get-ChildItem -LiteralPath $installDirectory -Filter $expectedUninstallerName -File -Recurse)
if ($executables.Count -ne 1) {
    throw "Expected exactly one $expectedExecutableName under install root; found $($executables.Count)."
}
if ($uninstallers.Count -ne 1) {
    throw "Expected exactly one $expectedUninstallerName under install root; found $($uninstallers.Count)."
}

$canonicalExecutable = Assert-NoReparsePoints $executables[0].FullName -MustExist
$canonicalUninstaller = Assert-NoReparsePoints $uninstallers[0].FullName -MustExist
if (-not (Test-PathWithin $canonicalExecutable $canonicalInstallDirectory) -or
    -not (Test-PathWithin $canonicalUninstaller $canonicalInstallDirectory)) {
    throw 'The application executable or uninstaller resolves outside the requested install root.'
}
Assert-NotBuildTreePath $canonicalExecutable $repositoryRoot

$installedExecutableHash = (Get-FileHash -LiteralPath $canonicalExecutable -Algorithm SHA256).Hash.ToLowerInvariant()
$installedUninstallerHash = (Get-FileHash -LiteralPath $canonicalUninstaller -Algorithm SHA256).Hash.ToLowerInvariant()

# Recheck package identity and shared app-local state immediately before writing either record.
$finalInstallerHash = (Get-FileHash -LiteralPath $installerFullPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($finalInstallerHash -ne $expectedInstallerSha256 -or $finalInstallerHash -ne $installerHash) {
    throw 'Installer identity changed during verification; refusing to write provenance or launch.'
}
if (Test-Path -LiteralPath $manifestPath) {
    throw "Refusing to overwrite a provenance manifest created during verification: $manifestPath"
}
if (Test-Path -LiteralPath $journalPath) {
    throw "Refusing to overwrite installer-run evidence created during verification: $journalPath"
}
if (@(Get-Process -Name 'fluxform-desktop-probe' -ErrorAction SilentlyContinue).Count -gt 0) {
    throw 'A probe process appeared during verification; refusing to write shared app-local provenance or launch.'
}

if (-not (Test-Path -LiteralPath $manifestDirectory -PathType Container)) {
    [IO.Directory]::CreateDirectory($manifestDirectory) | Out-Null
}
$null = Assert-NoReparsePoints $manifestDirectory -MustExist

$journal = [ordered]@{
    schema_version = 1
    install_identity = $InstallId
    installer_path = $installerFullPath
    installer_package_sha256 = $installerHash
    installer_command = $installCommand
    installer_exit_code = $installerExitCode
    installer_process_id = $installerProcessId
    installer_exit_evidence = $installerRunEvidence
    exit_evidence_recorded_during_original_run = (-not $ResumeFinalize)
    install_directory = $canonicalInstallDirectory
    installed_executable_path = $canonicalExecutable
    installed_executable_sha256 = $installedExecutableHash
    task15_standalone_executable_sha256 = $task15StandaloneExecutableSha256
    installed_uninstaller_path = $canonicalUninstaller
    installed_uninstaller_sha256 = $installedUninstallerHash
    mode = $expectedMode
}
Write-JsonCreateNew $journalPath $journal

$manifest = [ordered]@{
    schema_version = 1
    installer_package_sha256 = $installerHash
    installed_executable_path = $canonicalExecutable
    installed_executable_sha256 = $installedExecutableHash
    probe_mode = $expectedMode
    install_identity = $InstallId
}
Write-JsonCreateNew $manifestPath $manifest

# Start only the verified installed path. The machine's WebView2 runtime/network state are not
# modified or inferred by this verifier.
$applicationProcess = Start-Process -FilePath $canonicalExecutable -PassThru

[ordered]@{
    verifier_status = 'PASS'
    install_id = $InstallId
    installer_path = $installerFullPath
    installer_sha256 = $installerHash
    installer_exit_code = $installerExitCode
    installer_process_id = $installerProcessId
    installed_directory = $canonicalInstallDirectory
    installed_executable_path = $canonicalExecutable
    installed_executable_sha256 = $installedExecutableHash
    task15_standalone_executable_sha256 = $task15StandaloneExecutableSha256
    installed_uninstaller_path = $canonicalUninstaller
    installed_uninstaller_sha256 = $installedUninstallerHash
    installer_journal_path = $journalPath
    provenance_path = $manifestPath
    provenance_create_mode = 'CreateNew'
    launched_pid = $applicationProcess.Id
    launched_path = $canonicalExecutable
    probe_mode = $expectedMode
    network_disconnected_verified = $false
    clean_offline_vm_verified = $false
    retained_created_state = @($canonicalInstallDirectory, $journalPath, $manifestPath)
} | ConvertTo-Json -Depth 5
