$ErrorActionPreference = 'Stop'
$Mode = 'Automated'
$Ffmpeg = $null
$Ffprobe = $null
$FfmpegArchive = $null
$ArtifactId = $null
$Profile = $null
$ReportPath = $null
$gateEntries = @()
for ($argumentIndex = 0; $argumentIndex -lt $args.Count; $argumentIndex++) {
    $option = [string] $args[$argumentIndex]
    if ($option -in @('-Help', '-h', '--help')) {
        Write-Host 'Usage: scripts/check-stage0.ps1 -Mode Automated|Complete [-Gate NAME ...] [-Ffmpeg PATH -Ffprobe PATH] [-FfmpegArchive PATH -ArtifactId ID -Profile PATH]'
        exit 0
    }
    if ($argumentIndex + 1 -ge $args.Count) { throw "missing value for $option." }
    $value = [string] $args[++$argumentIndex]
    switch -CaseSensitive ($option.ToLowerInvariant()) {
        '-mode' { $Mode = $value }
        '-gate' { $gateEntries += $value }
        '-ffmpeg' { $Ffmpeg = $value }
        '-ffprobe' { $Ffprobe = $value }
        '-ffmpegarchive' { $FfmpegArchive = $value }
        '-artifactid' { $ArtifactId = $value }
        '-profile' { $Profile = $value }
        '-reportpath' { $ReportPath = $value }
        default { throw "unknown argument: $option" }
    }
}
if ($Mode -notin @('Automated', 'Complete')) { throw '-Mode must be Automated or Complete.' }

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptRoot
$evidenceRoot = Join-Path $repoRoot 'target/stage0'
$runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfffZ') + '-' + [Guid]::NewGuid().ToString('N')
$runRoot = Join-Path $evidenceRoot "runs/$runId"
[System.IO.Directory]::CreateDirectory($runRoot) | Out-Null

if ([string]::IsNullOrWhiteSpace($ReportPath)) {
    $ReportPath = Join-Path $repoRoot 'docs/architecture/stage-0-gate-report.md'
}

$automatedDefaults = @(
    'format', 'clippy', 'protocol', 'contract-drift', 'capabilities',
    'ffmpeg-profile-tests', 'atomic-output', 'sandbox-unit', 'server-probe', 'desktop-probe-modes',
    'desktop-build', 'ffmpeg-profile'
)
$completeDefaults = @('ffmpeg-artifacts', 'aggregate-samples', 'report', 'public-server-linux')
$completeRequired = @($automatedDefaults + $completeDefaults)
$expectedReportEvidence = @(
    'Protocol/schema determinism',
    'Windows FFmpeg profile and license record',
    'macOS x86_64 FFmpeg profile and license record',
    'macOS aarch64 FFmpeg profile and license record',
    'Linux x86_64 FFmpeg profile and license record',
    'Exact approved/deferred capability matrix and product-owner approval',
    'Every enabled edge and rejection sample executed against all four approved native profiles',
    'Atomic reject/rename/replace, injected replacement failures, and crash recovery on each supported local filesystem',
    'Linux filesystem sandbox denial',
    'Linux OS network denial, distinct from FFmpeg protocol-policy denial',
    'Linux cgroup v2 birth placement, aggregate process/memory/CPU containment, and kill',
    'Streaming upload, reservation expansion, and early body termination',
    'Capability authorization on every concrete endpoint, Origin enforcement, and trusted-proxy IP provenance',
    'SSE reconnect, replay, resync snapshot, and expiry',
    'Real positive and negative fail-closed public-server startup',
    'Windows installed-app window, repeated-launch, close, DPI, and multi-monitor behavior',
    'Native Intel and Apple Silicon installed-app macOS window behavior',
    'Linux X11 installed-AppImage window behavior',
    'Linux Wayland installed-AppImage behavior and explicit degraded capability',
    'Windows offline WebView2 installation and first launch',
    'Signed/notarized disconnected macOS installation and first launch on both architectures',
    'Linux disconnected AppImage first launch',
    'Approved FFmpeg/FFprobe sidecar hashes and offline fixed `-version` execution per platform'
)
$requestedGates = @()
foreach ($entry in $gateEntries) {
    foreach ($item in ([string] $entry -split ',')) {
        if (-not [string]::IsNullOrWhiteSpace($item)) { $requestedGates += $item.Trim() }
    }
}
$selected = if ($requestedGates.Count -gt 0) { $requestedGates } elseif ($Mode -eq 'Complete') { $completeRequired } else { $automatedDefaults }
$knownGates = @($automatedDefaults + $completeDefaults | Select-Object -Unique)
$results = [ordered]@{}
$stopAfterFailure = $false
$previousOffline = $env:CARGO_NET_OFFLINE
$previousPythonNoBytecode = $env:PYTHONDONTWRITEBYTECODE
$env:CARGO_NET_OFFLINE = 'true'
$env:PYTHONDONTWRITEBYTECODE = '1'

function Write-Stage0Log {
    param([string] $Name, [string[]] $Lines)
    $safeName = $Name -replace '[^A-Za-z0-9_.-]', '_'
    $path = Join-Path $runRoot "$safeName.log"
    [System.IO.File]::WriteAllText($path, [string]::Join([Environment]::NewLine, $Lines) + [Environment]::NewLine)
    Write-Host "log: $path"
}

function Invoke-LoggedCommand {
    param([string] $Name, [string] $Executable, [string[]] $Arguments)
    $rendered = @("$Executable $($Arguments -join ' ')")
    Write-Host "+ $($rendered[0])"
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        # Cargo reports normal progress on stderr. Capture it without promoting it to a terminating PowerShell error.
        $ErrorActionPreference = 'Continue'
        $lines = @(& $Executable @Arguments 2>&1 | ForEach-Object { [string] $_ })
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Write-Stage0Log -Name $Name -Lines @($rendered + $lines + "exit_code=$exitCode")
    foreach ($line in $lines) { Write-Host $line }
    if ($exitCode -ne 0) {
        throw "command exited ${exitCode}: $Executable $($Arguments -join ' ')"
    }
}

function Invoke-Cargo {
    param([string] $Name, [string[]] $Arguments)
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw 'BLOCKED: cargo is not installed or is not on PATH.'
    }
    Invoke-LoggedCommand -Name $Name -Executable 'cargo' -Arguments (@('--locked', '--offline') + $Arguments)
}

function Get-ReportRows {
    param([string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "BLOCKED: gate report does not exist: $Path"
    }
    $content = [System.IO.File]::ReadAllText($Path)
    $rows = @()
    foreach ($line in ($content -split "`r?`n")) {
        if ($line -match '^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*\*\*(PASS|FAIL|BLOCKED)\*\*\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|$') {
            $rows += [pscustomobject]@{
                Number = [int] $Matches[1]
                Evidence = $Matches[2].Trim()
                Status = $Matches[3]
                ReviewerCell = $Matches[4].Trim()
                Details = $Matches[5].Trim()
            }
        }
    }
    if ($rows.Count -ne 23) {
        throw "FAIL: expected 23 uniquely numbered evidence rows, found $($rows.Count)."
    }
    $numbers = @($rows | ForEach-Object { $_.Number } | Sort-Object -Unique)
    if ($numbers.Count -ne 23 -or $numbers[0] -ne 1 -or $numbers[-1] -ne 23) {
        throw 'FAIL: report evidence rows must cover every number from 1 through 23 exactly once.'
    }
    foreach ($row in $rows) {
        if ([string]::IsNullOrWhiteSpace($row.Evidence) -or [string]::IsNullOrWhiteSpace($row.ReviewerCell) -or [string]::IsNullOrWhiteSpace($row.Details)) {
            throw "FAIL: evidence row $($row.Number) has a blank evidence cell."
        }
        if ($row.Evidence -cne $expectedReportEvidence[$row.Number - 1]) {
            throw "FAIL: evidence row $($row.Number) label does not match the required Stage 0 evidence item."
        }
        if ($row.ReviewerCell -notmatch '\b20\d{2}-\d{2}-\d{2}\b') {
            throw "FAIL: evidence row $($row.Number) has no ISO date."
        }
        if ($row.ReviewerCell -match '(?i)pending|unreviewed|placeholder|fixture|codex.*recorder') {
            throw "BLOCKED: evidence row $($row.Number) has no independent human review."
        }
        if ($row.Status -eq 'BLOCKED' -and $row.Details -notmatch '(?i)blocked|not run|not .*(verified|performed|measured|available)|no .* exists|no .* available|no .* (collected|recorded|observed|claim|evidence|result)|not available|missing|unknown|false') {
            throw "FAIL: blocked evidence row $($row.Number) does not explain its prerequisite."
        }
    }
    $summary = [regex]::Match($content, '\*\*Overall status: (PASS|FAIL|BLOCKED)\.\*\*\s*Current matrix:\s*\*\*(\d+) PASS,\s*(\d+) FAIL,\s*(\d+) BLOCKED\*\*')
    if (-not $summary.Success) {
        throw 'FAIL: gate report does not contain a canonical status summary.'
    }
    $passCount = @($rows | Where-Object Status -eq 'PASS').Count
    $failCount = @($rows | Where-Object Status -eq 'FAIL').Count
    $blockedCount = @($rows | Where-Object Status -eq 'BLOCKED').Count
    $expectedOverall = if ($failCount -gt 0) { 'FAIL' } elseif ($blockedCount -gt 0) { 'BLOCKED' } else { 'PASS' }
    if ($summary.Groups[1].Value -cne $expectedOverall -or [int] $summary.Groups[2].Value -ne $passCount -or [int] $summary.Groups[3].Value -ne $failCount -or [int] $summary.Groups[4].Value -ne $blockedCount) {
        throw 'FAIL: gate report summary does not match its evidence rows.'
    }
    [pscustomobject]@{ Rows = $rows; Pass = $passCount; Fail = $failCount; Blocked = $blockedCount }
}

function Test-ReportArtifactIdentity {
    param([string] $Details)
    $recordedHashes = @([regex]::Matches($Details, '(?i)sha-?256\s*[:=]?\s*`?([0-9a-f]{64})`?') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() })
    if ($recordedHashes.Count -eq 0) { return $false }
    $root = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $rootPrefix = $root + [System.IO.Path]::DirectorySeparatorChar
    foreach ($match in [regex]::Matches($Details, '`([^`]+)`')) {
        $token = $match.Groups[1].Value.Trim()
        if ($token.IndexOfAny([char[]] @('/', '\')) -lt 0) { continue }
        try {
            $candidate = if ([System.IO.Path]::IsPathRooted($token)) {
                [System.IO.Path]::GetFullPath($token)
            } else {
                [System.IO.Path]::GetFullPath((Join-Path $root $token))
            }
        } catch { continue }
        if (-not $candidate.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) { continue }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $item = Get-Item -LiteralPath $candidate -Force
        if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
        $stream = $null
        $sha = $null
        try {
            $stream = [System.IO.File]::Open($candidate, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            $actualHash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
            if ($recordedHashes -contains $actualHash) { return $true }
        } catch {
            continue
        } finally {
            if ($stream) { $stream.Dispose() }
            if ($sha) { $sha.Dispose() }
        }
    }
    return $false
}

function Get-WorkingPython3Command {
    foreach ($commandName in @('python3', 'python')) {
        $candidate = @(Get-Command $commandName -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1)[0]
        if (-not $candidate) { continue }
        try {
            $versionOutput = @(& $candidate.Source --version 2>&1)
            $versionExitCode = $LASTEXITCODE
            if ($versionExitCode -eq 0 -and [string]($versionOutput | Select-Object -First 1) -match '^Python 3\.') {
                return $candidate
            }
        } catch { continue }
    }
    return $null
}

function Invoke-ReviewedReportValidator {
    param([string] $Path, [string] $AggregateReportPath)
    $python = Get-WorkingPython3Command
    if (-not $python) { throw 'BLOCKED: Python 3 is required to validate reviewed per-row evidence manifests.' }
    $validator = Join-Path $scriptRoot 'validate_stage0_report.py'
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $arguments = @(
            $validator, '--repo-root', $repoRoot, '--report', $Path,
            '--attestation', (Join-Path $evidenceRoot 'reviewed-evidence-attestation.json'),
            '--aggregate-report', $AggregateReportPath
        )
        $lines = @(& $python.Source @arguments 2>&1 | ForEach-Object { [string] $_ })
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    foreach ($line in $lines) { Write-Host $line }
    if ($exitCode -eq 10) { throw 'BLOCKED: reviewed per-row evidence bundle is missing, untrusted, or invalid.' }
    if ($exitCode -ne 0) { throw 'FAIL: reviewed per-row evidence bundle or report is malformed.' }
}

function Get-SourceGitStatus {
    $lines = @(& git -C $repoRoot status --porcelain --untracked-files=all 2>&1 | ForEach-Object { [string] $_ })
    if ($LASTEXITCODE -ne 0) { throw 'BLOCKED: git status could not verify source-tree cleanliness around the desktop build.' }
    return [string]::Join("`n", $lines)
}

function Copy-ProfileEvidence {
    param([string] $SourceRoot, [string] $DestinationRoot)
    $targets = @(
        @{ Name = 'windows-x86_64'; Triple = 'x86_64-pc-windows-msvc'; File = 'ffmpeg-windows-x86_64.json' },
        @{ Name = 'macos-x86_64'; Triple = 'x86_64-apple-darwin'; File = 'ffmpeg-macos-x86_64.json' },
        @{ Name = 'macos-aarch64'; Triple = 'aarch64-apple-darwin'; File = 'ffmpeg-macos-aarch64.json' },
        @{ Name = 'linux-x86_64'; Triple = 'x86_64-unknown-linux-gnu'; File = 'ffmpeg-linux-x86_64.json' }
    )
    [System.IO.Directory]::CreateDirectory($DestinationRoot) | Out-Null
    foreach ($target in $targets) {
        $source = Join-Path $SourceRoot $target.File
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "BLOCKED: exact native profile artifact is missing: $source"
        }
        if ((Get-Item -LiteralPath $source).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "FAIL: profile artifact must not be a symlink or reparse point: $source"
        }
        try { $report = Get-Content -LiteralPath $source -Raw | ConvertFrom-Json } catch {
            throw "FAIL: invalid FFmpeg profile JSON at ${source}: $($_.Exception.Message)"
        }
        if ($report.target_triple -ne $target.Triple) {
            throw "FAIL: $source identifies $($report.target_triple), expected $($target.Triple)."
        }
        if ($report.artifact_status -ne 'approved' -or $report.distribution_gate_status -ne 'approved' -or [string]::IsNullOrWhiteSpace($report.approval_record_id) -or [string]::IsNullOrWhiteSpace($report.approval_date)) {
            throw "BLOCKED: $source does not prove an approved artifact and distribution gate."
        }
        $destination = Join-Path $DestinationRoot "$($target.Name).json"
        [System.IO.File]::Copy($source, $destination, $false)
    }
}

function Invoke-Stage0Gate {
    param([string] $Name)
    switch ($Name) {
        'format' {
            Invoke-Cargo $Name @('fmt', '--all', '--', '--check')
            return 'PASS'
        }
        'clippy' {
            Invoke-Cargo $Name @('clippy', '--workspace', '--exclude', 'fluxform-desktop-probe', '--all-targets', '--all-features', '--', '-D', 'warnings')
            Invoke-Cargo "$Name-desktop-transparent-orb" @('clippy', '-p', 'fluxform-desktop-probe', '--all-targets', '--', '-D', 'warnings')
            Invoke-Cargo "$Name-desktop-rectangular-hit-region" @('clippy', '-p', 'fluxform-desktop-probe', '--no-default-features', '--features', 'probe-transparent-window-with-rectangular-hit-region', '--all-targets', '--', '-D', 'warnings')
            Invoke-Cargo "$Name-desktop-opaque-fallback" @('clippy', '-p', 'fluxform-desktop-probe', '--no-default-features', '--features', 'probe-opaque-frameless-fallback', '--all-targets', '--', '-D', 'warnings')
            return 'PASS'
        }
        'protocol' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-protocol', '--all-targets', '--all-features')
            return 'PASS'
        }
        'contract-drift' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-protocol', '--test', 'contracts', 'committed_contracts_match_the_rust_source')
            return 'PASS'
        }
        'capabilities' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-capabilities', '--lib')
            Invoke-Cargo "$Name-manifest" @('test', '-p', 'fluxform-capabilities', '--test', 'manifest')
            Invoke-Cargo "$Name-runner" @('test', '-p', 'fluxform-capabilities', '--test', 'runner')
            return 'PASS'
        }
        'ffmpeg-profile-tests' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-ffmpeg-profile', '--all-targets', '--all-features')
            return 'PASS'
        }
        'atomic-output' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-atomic-output', '--all-targets', '--all-features')
            return 'PASS'
        }
        'sandbox-unit' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-sandbox-probe', '--lib', '--all-features')
            return 'PASS'
        }
        'server-probe' {
            Invoke-Cargo $Name @('test', '-p', 'fluxform-server-probe', '--all-targets', '--all-features')
            return 'PASS'
        }
        'desktop-probe-modes' {
            Invoke-Cargo "$Name-transparent-orb" @('test', '-p', 'fluxform-desktop-probe', '--all-targets')
            Invoke-Cargo "$Name-rectangular-hit-region" @('test', '-p', 'fluxform-desktop-probe', '--no-default-features', '--features', 'probe-transparent-window-with-rectangular-hit-region', '--all-targets')
            Invoke-Cargo "$Name-opaque-fallback" @('test', '-p', 'fluxform-desktop-probe', '--no-default-features', '--features', 'probe-opaque-frameless-fallback', '--all-targets')
            return 'PASS'
        }
        'desktop-build' {
            if (-not (Get-Command pnpm -ErrorAction SilentlyContinue)) { Write-Host 'SKIPPED: pnpm is unavailable; no package was installed.'; return 'SKIPPED' }
            $pnpmVersionOutput = @(& pnpm --version 2>$null)
            $pnpmVersionExitCode = $LASTEXITCODE
            if ($pnpmVersionExitCode -ne 0) { throw 'BLOCKED: could not read the installed pnpm version.' }
            $pnpmVersion = [string]($pnpmVersionOutput | Select-Object -First 1)
            if ($pnpmVersion -ne '11.19.0') { Write-Host "SKIPPED: expected pinned pnpm 11.19.0, found $pnpmVersion; no package was installed."; return 'SKIPPED' }
            $sourceStatusBefore = Get-SourceGitStatus
            $sourceSnapshot = Join-Path $runRoot 'desktop-source'
            $python = Get-WorkingPython3Command
            if (-not $python) { throw 'BLOCKED: Python 3 is required to make an isolated desktop source snapshot.' }
            try {
                Invoke-LoggedCommand -Name "$Name-snapshot" -Executable $python.Source -Arguments @((Join-Path $scriptRoot 'prepare_stage0_desktop_source.py'), '--repo-root', $repoRoot, '--destination', $sourceSnapshot)
                try {
                    Invoke-LoggedCommand -Name "$Name-pnpm-install" -Executable 'pnpm' -Arguments @('--dir', (Join-Path $sourceSnapshot 'apps/desktop-probe'), 'install', '--offline', '--frozen-lockfile')
                } catch {
                    throw "BLOCKED: offline frozen pnpm install failed; no download was attempted. $($_.Exception.Message)"
                }
                Invoke-LoggedCommand -Name $Name -Executable 'pnpm' -Arguments @('--dir', (Join-Path $sourceSnapshot 'apps/desktop-probe'), 'run', 'tauri:build', '--no-bundle')
            } finally {
                if (Test-Path -LiteralPath $sourceSnapshot -PathType Container) {
                    Invoke-LoggedCommand -Name "$Name-snapshot-cleanup" -Executable $python.Source -Arguments @((Join-Path $scriptRoot 'prepare_stage0_desktop_source.py'), '--repo-root', $repoRoot, '--destination', $sourceSnapshot, '--cleanup')
                }
                $sourceStatusAfter = Get-SourceGitStatus
                if ($sourceStatusAfter -cne $sourceStatusBefore) {
                    throw 'FAIL: desktop build changed the source Git status; build outputs must stay in target/stage0.'
                }
            }
            return 'PASS'
        }
        'ffmpeg-profile' {
            $hasLegacy = -not [string]::IsNullOrWhiteSpace($Ffmpeg) -or -not [string]::IsNullOrWhiteSpace($Ffprobe)
            $hasArchive = -not [string]::IsNullOrWhiteSpace($FfmpegArchive) -or -not [string]::IsNullOrWhiteSpace($ArtifactId) -or -not [string]::IsNullOrWhiteSpace($Profile)
            if ($hasLegacy) { throw 'BLOCKED: direct executable path verification was retired by the Task3 hardened archive review; supplied binaries were not executed.' }
            if (-not $hasArchive) { Write-Host 'SKIPPED: no explicit immutable archive verifier inputs were supplied.'; return 'SKIPPED' }
            if ([string]::IsNullOrWhiteSpace($FfmpegArchive) -or [string]::IsNullOrWhiteSpace($ArtifactId) -or [string]::IsNullOrWhiteSpace($Profile)) {
                throw 'BLOCKED: provide -FfmpegArchive, -ArtifactId, and -Profile together.'
            }
            if (-not (Test-Path -LiteralPath $FfmpegArchive -PathType Leaf) -or -not (Test-Path -LiteralPath $Profile -PathType Leaf)) {
                throw 'BLOCKED: archive/profile input does not exist; no dependency will be downloaded.'
            }
            $out = Join-Path $runRoot 'ffmpeg-profile-verification.json'
            Invoke-Cargo $Name @('run', '-p', 'fluxform-ffmpeg-profile', '--', 'verify', '--profile', $Profile, '--artifact-id', $ArtifactId, '--archive', $FfmpegArchive, '--out', $out)
            if (-not (Test-Path -LiteralPath $out -PathType Leaf)) { throw 'BLOCKED: verifier did not produce a report.' }
            $report = Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
            if ($report.artifact_status -ne 'approved' -or $report.distribution_gate_status -ne 'approved') { throw 'BLOCKED: the verifier report is only a candidate or the distribution gate is not approved.' }
            return 'PASS'
        }
        'public-server-linux' {
            $isLinuxHost = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Linux)
            if (-not $isLinuxHost) { Write-Host 'SKIPPED: native Linux sandbox evidence is not applicable on this host.'; return 'SKIPPED' }
            if ($env:FLUXFORM_STAGE0_LINUX_CGROUPV2_DELEGATED -ne '1') { throw 'BLOCKED: public Linux gate requires the registered native linux-cgroupv2-delegated runner.' }
            if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'self-hosted') { throw 'BLOCKED: public Linux gate only accepts the registered self-hosted native runner.' }
            $architecture = (& uname -m 2>$null | Select-Object -First 1)
            if ($architecture -ne 'x86_64') { throw "BLOCKED: Linux public gate requires native x86_64, found $architecture." }
            $cgroupRoot = $env:FLUXFORM_TEST_CGROUP_ROOT
            if ([string]::IsNullOrWhiteSpace($cgroupRoot)) { throw 'BLOCKED: FLUXFORM_TEST_CGROUP_ROOT must name the runner delegated cgroup v2 subtree.' }
            if (-not (Test-Path -LiteralPath (Join-Path $cgroupRoot 'cgroup.controllers')) -or -not (Test-Path -LiteralPath (Join-Path $cgroupRoot 'cgroup.subtree_control'))) {
                throw 'BLOCKED: delegated cgroup v2 controllers are unavailable.'
            }
            $controllers = [System.IO.File]::ReadAllText((Join-Path $cgroupRoot 'cgroup.controllers'))
            $enabledControllers = [System.IO.File]::ReadAllText((Join-Path $cgroupRoot 'cgroup.subtree_control'))
            foreach ($controller in @('cpu', 'memory', 'pids')) {
                if ($controllers -notmatch "(^|\s)$controller(\s|$)" -or $enabledControllers -notmatch "(^|\s)$controller(\s|$)") {
                    throw "BLOCKED: delegated cgroup v2 controller '$controller' is unavailable or disabled."
                }
            }
            Invoke-Cargo $Name @('test', '-p', 'fluxform-sandbox-probe', '--all-targets', '--all-features')
            Invoke-Cargo "$Name-startup-negative" @('test', '-p', 'fluxform-server-probe', '--test', 'public_startup', '--all-features')
            Invoke-Cargo "$Name-startup-positive" @('test', '-p', 'fluxform-server-probe', '--test', 'public_startup', 'delegated_linux_process_binds_public_mode_and_serves_protected_status', '--all-features', '--', '--ignored', '--exact')
            return 'PASS'
        }
        'report' {
            $gateReport = Get-ReportRows $ReportPath
            if ($gateReport.Fail -gt 0) { Write-Host "FAIL: $($gateReport.Fail) gate report row(s) are FAIL."; return 'FAIL' }
            if ($gateReport.Blocked -gt 0) { Write-Host "BLOCKED: $($gateReport.Blocked) gate report row(s) are BLOCKED."; return 'BLOCKED' }
            if ($gateReport.Pass -ne 23) { throw 'FAIL: every one of the 23 gate report rows must be PASS.' }
            Invoke-ReviewedReportValidator -Path $ReportPath -AggregateReportPath (Join-Path $runRoot 'aggregate-sample-report.json')
            Write-Host 'PASS: all 23 report rows have strict per-kind raw-result semantics and same-run reviewed attestation.'
            return 'PASS'
        }
        'ffmpeg-artifacts' {
            $profiles = Join-Path $runRoot 'profiles'
            Copy-ProfileEvidence -SourceRoot $evidenceRoot -DestinationRoot $profiles
            Invoke-Cargo $Name @('run', '-p', 'fluxform-capabilities', '--bin', 'verify_manifest', '--', 'verify-manifest', '--manifest', 'config/capabilities-v1.toml', '--reports', $profiles)
            return 'PASS'
        }
        'aggregate-samples' {
            $collected = Join-Path $evidenceRoot 'collected'
            if (-not (Test-Path -LiteralPath $collected -PathType Container)) { throw 'BLOCKED: target/stage0/collected is missing; four native artifacts are required.' }
            $directories = @(Get-ChildItem -LiteralPath $collected -Directory)
            if ($directories.Count -ne 4) { throw "BLOCKED: expected four target/stage0/collected target directories, found $($directories.Count)." }
            $digests = @()
            foreach ($directory in $directories) {
                $samplePath = Join-Path $directory.FullName 'sample-report.json'
                if (-not (Test-Path -LiteralPath $samplePath -PathType Leaf)) { throw "BLOCKED: missing sample evidence $samplePath." }
                $sample = Get-Content -LiteralPath $samplePath -Raw | ConvertFrom-Json
                if ($sample.evidence_input_digest -notmatch '^[0-9a-f]{64}$') { throw "BLOCKED: invalid evidence-input digest in $samplePath." }
                $digests += $sample.evidence_input_digest
            }
            $uniqueDigests = @($digests | Select-Object -Unique)
            if ($uniqueDigests.Count -ne 1) { throw 'BLOCKED: native sample evidence has mismatched evidence-input digests.' }
            $digest = $uniqueDigests[0]
            $out = Join-Path $runRoot 'aggregate-sample-report.json'
            Invoke-Cargo $Name @('run', '-p', 'fluxform-capabilities', '--bin', 'collect_sample_reports', '--', '--input', 'target/stage0/collected', '--manifest', 'config/capabilities-v1.toml', '--samples', 'testdata/media/v1/samples.toml', '--expected-input-digest', $digest, '--out', $out)
            $profiles = Join-Path $runRoot 'collected-profiles'
            [System.IO.Directory]::CreateDirectory($profiles) | Out-Null
            foreach ($directory in $directories) {
                $profileReport = Join-Path $directory.FullName 'ffmpeg-profile-report.json'
                if (-not (Test-Path -LiteralPath $profileReport -PathType Leaf)) { throw "BLOCKED: missing exact profile report $profileReport." }
                [System.IO.File]::Copy($profileReport, (Join-Path $profiles "$($directory.Name).json"), $false)
            }
            Invoke-Cargo "$Name-manifest" @('run', '-p', 'fluxform-capabilities', '--bin', 'verify_manifest', '--', 'verify-manifest', '--manifest', 'config/capabilities-v1.toml', '--reports', $profiles)
            Invoke-Cargo "$Name-cross-platform" @('test', '-p', 'fluxform-capabilities', '--test', 'cross_platform_samples')
            return 'PASS'
        }
        default { throw "unknown gate selector: $Name" }
    }
}

try {
    if (@($selected | Select-Object -Unique).Count -ne $selected.Count) {
        throw 'duplicate -Gate selectors are not allowed.'
    }
    foreach ($name in $selected) {
        if ($stopAfterFailure) { $results[$name] = 'NOT_RUN'; continue }
        if ($name -notin $knownGates) {
            $results[$name] = 'FAIL'
            Write-Host "gate $name=FAIL (unknown selector)"
            $stopAfterFailure = $true
            continue
        }
        Write-Host "gate ${name}: running"
        try {
            $status = Invoke-Stage0Gate $name
            $results[$name] = $status
            Write-Host "gate $name=$status"
            if ($status -in @('FAIL', 'BLOCKED')) { $stopAfterFailure = $true }
        } catch {
            $message = $_.Exception.Message
            $status = if ($message -match '^BLOCKED:') { 'BLOCKED' } else { 'FAIL' }
            $results[$name] = $status
            Write-Host "gate $name=$status ($message)"
            $stopAfterFailure = $true
        }
    }
} finally {
    if ($null -eq $previousOffline) { Remove-Item Env:CARGO_NET_OFFLINE -ErrorAction SilentlyContinue } else { $env:CARGO_NET_OFFLINE = $previousOffline }
    if ($null -eq $previousPythonNoBytecode) { Remove-Item Env:PYTHONDONTWRITEBYTECODE -ErrorAction SilentlyContinue } else { $env:PYTHONDONTWRITEBYTECODE = $previousPythonNoBytecode }
}

Write-Host 'Stage 0 gate summary:'
foreach ($name in $selected) { Write-Host "$name=$($results[$name])" }
$completeAttempt = $Mode -eq 'Complete' -and $selected.Count -eq $completeRequired.Count
$completeSelectionMatches = $completeAttempt
if ($completeSelectionMatches) {
    for ($index = 0; $index -lt $completeRequired.Count; $index++) {
        if ($selected[$index] -cne $completeRequired[$index]) { $completeSelectionMatches = $false; break }
    }
}
$complete = $completeSelectionMatches -and @($results.Values | Where-Object { $_ -ne 'PASS' }).Count -eq 0
Write-Host "stage0_complete=$($complete.ToString().ToLowerInvariant())"
if (@($results.Values | Where-Object { $_ -in @('FAIL', 'BLOCKED') }).Count -gt 0 -or ($completeAttempt -and -not $complete)) { exit 1 }
exit 0
