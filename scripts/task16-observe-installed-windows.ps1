[CmdletBinding()]
param(
    [int]$ExpectedProcessId = 40800,
    [string]$InstallId = 'task16-d259e385be404ac78d5191891e100df8',
    [string]$ObservationId = ('task16-observation-' + [Guid]::NewGuid().ToString('N')),
    [switch]$InventoryOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module -Name (Join-Path $PSScriptRoot 'Task16WindowsSafety.psm1') -Force

$expectedInstallerSha256 = '42b5ee0d33ca1b0b3379d916388f083a4844b7dde303459975e7222531d87491'
$expectedExecutableSha256 = 'b82553e959fe44adfa158839a80da1a3f924998bf0e8fa1286f56707f6dc9949'
$expectedExecutableName = 'fluxform-desktop-probe.exe'
$expectedMode = 'transparent-orb'
$closeMessage = 0x0010

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace FluxFormTask16 {
    public sealed class NativeWindowInfo {
        public long Handle { get; set; }
        public uint ProcessId { get; set; }
        public string Title { get; set; }
        public bool Visible { get; set; }
        public int RegionResult { get; set; }
        public uint RegionDataType { get; set; }
        public uint RegionRectangleCount { get; set; }
        public int RegionLeft { get; set; }
        public int RegionTop { get; set; }
        public int RegionRight { get; set; }
        public int RegionBottom { get; set; }
    }

    public static class Native {
        private delegate bool EnumWindowsCallback(IntPtr hwnd, IntPtr lParam);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT { public int Left, Top, Right, Bottom; }

        [DllImport("user32.dll")]
        private static extern bool EnumWindows(EnumWindowsCallback callback, IntPtr lParam);
        [DllImport("user32.dll")]
        private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint processId);
        [DllImport("user32.dll")]
        private static extern bool IsWindowVisible(IntPtr hwnd);
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern int GetWindowText(IntPtr hwnd, StringBuilder text, int maxCount);
        [DllImport("user32.dll")]
        private static extern int GetWindowTextLength(IntPtr hwnd);
        [DllImport("user32.dll")]
        private static extern int GetWindowRgn(IntPtr hwnd, IntPtr region);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool GetWindowRect(IntPtr hwnd, out RECT rect);
        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool PostMessage(IntPtr hwnd, uint message, IntPtr wParam, IntPtr lParam);
        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateRectRgn(int left, int top, int right, int bottom);
        [DllImport("gdi32.dll")]
        private static extern bool DeleteObject(IntPtr obj);
        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern uint GetRegionData(IntPtr region, uint byteCount, IntPtr data);

        public static NativeWindowInfo[] GetWindowsForProcess(uint expectedProcessId) {
            var windows = new List<NativeWindowInfo>();
            EnumWindows((hwnd, _) => {
                uint ownerProcessId;
                GetWindowThreadProcessId(hwnd, out ownerProcessId);
                if (ownerProcessId != expectedProcessId) return true;

                int titleLength = GetWindowTextLength(hwnd);
                var title = new StringBuilder(Math.Max(titleLength + 1, 2));
                GetWindowText(hwnd, title, title.Capacity);

                var item = new NativeWindowInfo {
                    Handle = hwnd.ToInt64(),
                    ProcessId = ownerProcessId,
                    Title = title.ToString(),
                    Visible = IsWindowVisible(hwnd)
                };

                IntPtr region = CreateRectRgn(0, 0, 0, 0);
                try {
                    item.RegionResult = GetWindowRgn(hwnd, region);
                    uint dataSize = GetRegionData(region, 0, IntPtr.Zero);
                    if (dataSize >= 32 && dataSize <= 1024 * 1024) {
                        IntPtr data = Marshal.AllocHGlobal((int)dataSize);
                        try {
                            if (GetRegionData(region, dataSize, data) >= 32) {
                                item.RegionDataType = unchecked((uint)Marshal.ReadInt32(data, 4));
                                item.RegionRectangleCount = unchecked((uint)Marshal.ReadInt32(data, 8));
                                item.RegionLeft = Marshal.ReadInt32(data, 16);
                                item.RegionTop = Marshal.ReadInt32(data, 20);
                                item.RegionRight = Marshal.ReadInt32(data, 24);
                                item.RegionBottom = Marshal.ReadInt32(data, 28);
                            }
                        } finally { Marshal.FreeHGlobal(data); }
                    }
                } finally { DeleteObject(region); }

                RECT bounds;
                if (GetWindowRect(hwnd, out bounds)) {
                    // Region bounds remain in window coordinates; screen bounds are not substituted.
                }
                windows.Add(item);
                return true;
            }, IntPtr.Zero);
            return windows.ToArray();
        }

        public static bool PostClose(long handle) {
            return PostMessage(new IntPtr(handle), 0x0010, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
'@

function Write-JsonCreateNew([string]$Path, [object]$Value) {
    $json = ($Value | ConvertTo-Json -Depth 10) + "`n"
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($json)
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    } finally {
        $stream.Dispose()
    }
}

function Get-Canonical([string]$Path) {
    return Get-Task16CanonicalPath $Path
}

function Get-InstalledProbeProcesses([string]$ExpectedPath) {
    $matches = [Collections.Generic.List[Diagnostics.Process]]::new()
    foreach ($candidate in @(Get-Process -Name 'fluxform-desktop-probe' -ErrorAction SilentlyContinue)) {
        $imagePath = Get-Task16ProcessImagePath -Process $candidate
        if ($imagePath.Equals($ExpectedPath, [StringComparison]::OrdinalIgnoreCase)) {
            $matches.Add($candidate)
        }
    }
    return @($matches)
}

function Get-ProcessSnapshot([int]$RootProcessId, [string]$ExpectedPath) {
    $processes = @(Get-CimInstance -ClassName Win32_Process)
    $root = @($processes | Where-Object { $_.ProcessId -eq $RootProcessId })
    $descendantIds = [Collections.Generic.HashSet[int]]::new()
    $queue = [Collections.Generic.Queue[int]]::new()
    $queue.Enqueue($RootProcessId)
    while ($queue.Count -gt 0) {
        $parentId = $queue.Dequeue()
        foreach ($child in $processes | Where-Object { $_.ParentProcessId -eq $parentId }) {
            if ($descendantIds.Add([int]$child.ProcessId)) {
                $queue.Enqueue([int]$child.ProcessId)
            }
        }
    }
    $webview = @($processes | Where-Object {
        $_.Name -ieq 'msedgewebview2.exe' -and $descendantIds.Contains([int]$_.ProcessId)
    } | Select-Object ProcessId, ParentProcessId, Name, ExecutablePath)
    $backend = @(Get-InstalledProbeProcesses $ExpectedPath)
    [pscustomobject]@{
        exact_installed_process_count = $backend.Count
        exact_installed_process_ids = @($backend | ForEach-Object { $_.Id })
        root_process_present = ($root.Count -eq 1 -and ([string]$root[0].ExecutablePath).Equals($ExpectedPath, [StringComparison]::OrdinalIgnoreCase))
        webview_helper_process_count = $webview.Count
        webview_helper_processes = $webview
    }
}

function Get-TopLevelWindows([int]$ProcessId) {
    return @([FluxFormTask16.Native]::GetWindowsForProcess([uint32]$ProcessId) | ForEach-Object {
        [pscustomobject]@{
            hwnd = ('0x{0:X}' -f $_.Handle)
            handle_value = [long]$_.Handle
            process_id = [uint32]$_.ProcessId
            title = [string]$_.Title
            visible = [bool]$_.Visible
            get_window_rgn_result = [int]$_.RegionResult
            region_data_type = [uint32]$_.RegionDataType
            region_rectangle_count = [uint32]$_.RegionRectangleCount
            region_bounds = @([int]$_.RegionLeft, [int]$_.RegionTop, [int]$_.RegionRight, [int]$_.RegionBottom)
        }
    })
}

function Get-ProbeWindows([int]$ProcessId) {
    return @(Get-TopLevelWindows $ProcessId | Where-Object { $_.title -match '^FluxForm Probe [12]$' })
}

function Wait-ForCondition([scriptblock]$Condition, [int]$TimeoutSeconds = 10) {
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        if (& $Condition) { return $true }
        Start-Sleep -Milliseconds 250
    }
    return (& $Condition)
}

function Wait-ForNoLateInstalledProcess([string]$ExpectedPath, [int]$WindowSeconds = 5) {
    $deadline = [DateTime]::UtcNow.AddSeconds($WindowSeconds)
    $pollCount = 0
    $lateProcesses = [Collections.Generic.List[object]]::new()
    while ([DateTime]::UtcNow -lt $deadline) {
        $current = @(Get-InstalledProbeProcesses $ExpectedPath)
        $pollCount++
        if ($current.Count -gt 0) {
            foreach ($process in $current) {
                $lateProcesses.Add([pscustomobject]@{ pid = $process.Id; path = Get-Task16ProcessImagePath $process })
            }
            return [pscustomobject]@{ passed = $false; poll_count = $pollCount; observed_processes = @($lateProcesses) }
        }
        Start-Sleep -Milliseconds 250
    }
    return [pscustomobject]@{ passed = $true; poll_count = $pollCount; observed_processes = @() }
}

if ($InstallId -ne 'task16-d259e385be404ac78d5191891e100df8') {
    throw 'This observation helper is limited to the exact Task16-created install identity.'
}

$localAppData = Assert-Task16NoReparsePoints -Path $env:LOCALAPPDATA -MustExist
$installDirectory = Assert-Task16PathWithin -Candidate (Join-Path $localAppData ("Programs\FluxForm-Task16\$InstallId")) -Root $localAppData -MustExist
$executablePath = Assert-Task16PathWithin -Candidate (Join-Path $installDirectory $expectedExecutableName) -Root $installDirectory -MustExist
$appDataDirectory = Assert-Task16PathWithin -Candidate (Join-Path $localAppData 'com.fluxform.desktop-probe') -Root $localAppData -MustExist
$manifestPath = Assert-Task16PathWithin -Candidate (Join-Path $appDataDirectory 'installed-provenance.json') -Root $appDataDirectory -MustExist
$manifest = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
$repositoryRoot = Get-Canonical (Join-Path $PSScriptRoot '..')
$installerPath = Assert-Task16NoReparsePoints -Path (Join-Path $repositoryRoot 'target\release\bundle\nsis\FluxForm Desktop Probe_0.1.0_x64-setup.exe') -MustExist
$installerPath = Assert-Task16PathWithin -Candidate $installerPath -Root $repositoryRoot -MustExist
$installerHandle = Open-Task16PinnedReadHandle -Path $installerPath
$installerHash = Get-Task16PinnedSha256 -Handle $installerHandle
if ($installerHash -ne $expectedInstallerSha256) {
    $installerHandle.Dispose()
    throw 'Installed package identity changed after provenance creation.'
}
if ($manifest.installer_package_sha256 -ne $expectedInstallerSha256 -or
    -not ([string]$manifest.installed_executable_path).Equals($executablePath, [StringComparison]::OrdinalIgnoreCase) -or
    $manifest.install_identity -ne $InstallId) {
    $installerHandle.Dispose()
    throw 'The fixed provenance manifest no longer matches the exact Task16 install identity.'
}
$executableHandle = Open-Task16PinnedReadHandle -Path $executablePath
$executableHash = Get-Task16PinnedSha256 -Handle $executableHandle
if ($executableHash -ne $expectedExecutableSha256) {
    $executableHandle.Dispose()
    $installerHandle.Dispose()
    throw 'Installed executable identity changed after provenance creation.'
}
if ($manifest.installer_package_sha256 -ne $expectedInstallerSha256 -or
    $manifest.installed_executable_sha256 -ne $expectedExecutableSha256 -or
    $manifest.installed_executable_sha256 -ne $executableHash) {
    $executableHandle.Dispose()
    $installerHandle.Dispose()
    throw 'The fixed provenance manifest no longer matches the exact Task16 install identity.'
}
$process = Get-Process -Id $ExpectedProcessId -ErrorAction Stop
if (-not (Get-Task16ProcessImagePath -Process $process).Equals($executablePath, [StringComparison]::OrdinalIgnoreCase)) {
    $executableHandle.Dispose()
    $installerHandle.Dispose()
    throw 'The supplied PID does not resolve to the exact installed executable path.'
}
$initialProcesses = @(Get-InstalledProbeProcesses $executablePath)
if ($initialProcesses.Count -ne 1 -or $initialProcesses[0].Id -ne $ExpectedProcessId) {
    $executableHandle.Dispose()
    $installerHandle.Dispose()
    throw "Expected exactly the one task-created installed PID $ExpectedProcessId before observation."
}
if ($InventoryOnly) {
    [ordered]@{
        observation_status = 'READ_ONLY_INVENTORY'
        process_snapshot = Get-ProcessSnapshot $ExpectedProcessId $executablePath
        top_level_windows = Get-TopLevelWindows $ExpectedProcessId
    } | ConvertTo-Json -Depth 8
    $executableHandle.Dispose()
    $installerHandle.Dispose()
    exit 0
}

$resultPaths = Get-Task16StructuralPaths -AppDataDirectory $appDataDirectory -ObservationId $ObservationId
$resultDirectory = Assert-Task16PathWithin -Candidate $resultPaths.Directory -Root $appDataDirectory
$resultPath = Assert-Task16PathWithin -Candidate $resultPaths.SummaryPath -Root $resultDirectory
$observationPath = Assert-Task16PathWithin -Candidate $resultPaths.RawPath -Root $resultDirectory
if (Test-Path -LiteralPath $resultPath) { throw "Refusing to overwrite an existing probe result: $resultPath" }
if (Test-Path -LiteralPath $observationPath) { throw "Refusing to overwrite existing native observations: $observationPath" }

$startUtc = [DateTime]::UtcNow.ToString('o')
$steps = [Collections.Generic.List[object]]::new()
$notes = [Collections.Generic.List[string]]::new()
$secondProcessId = $null
$repeatLaunchPassed = $false
$singleClosePassed = $false
$lastClosePassed = $false
$forcedTermination = $false
$noBackendRestartOrLateProcessAfterClose = $false
$lateProcessMonitor = [pscustomobject]@{ passed = $false; poll_count = 0; observed_processes = @() }
$lastProcessSnapshot = $null
$secondProcessSnapshot = $null
$lastProbeWindowCount = 0
$regionObservations = @()
$failure = $null
$finalCleanup = [Collections.Generic.List[object]]::new()

try {
    $baselineWindows = Get-TopLevelWindows $ExpectedProcessId
    $baselineProbeWindows = @(Get-ProbeWindows $ExpectedProcessId)
    $baselineProcesses = Get-ProcessSnapshot $ExpectedProcessId $executablePath
    $steps.Add([pscustomobject]@{ action = 'baseline'; windows = $baselineWindows; process_snapshot = $baselineProcesses })
    $regionObservations += @($baselineProbeWindows | Select-Object title,hwnd,visible,get_window_rgn_result,region_data_type,region_rectangle_count,region_bounds)
    if ($baselineProbeWindows.Count -ne 1) {
        throw "Expected one top-level probe window before second launch; observed $($baselineProbeWindows.Count)."
    }

    $secondProcess = Start-Task16PinnedProcess -Path $executablePath -Handle $executableHandle -ExpectedSha256 $executableHash
    $secondProcessId = $secondProcess.Id
    $repeatLaunchPassed = Wait-ForCondition {
        $probeWindows = @(Get-ProbeWindows $ExpectedProcessId)
        $processesNow = @(Get-InstalledProbeProcesses $executablePath)
        $probeWindows.Count -eq 2 -and $processesNow.Count -eq 1 -and $processesNow[0].Id -eq $ExpectedProcessId
    } 15
    $secondWindows = Get-TopLevelWindows $ExpectedProcessId
    $secondProbeWindows = @(Get-ProbeWindows $ExpectedProcessId)
    $secondProcessSnapshot = Get-ProcessSnapshot $ExpectedProcessId $executablePath
    $steps.Add([pscustomobject]@{
        action = 'second_launch'
        launched_pid = $secondProcessId
        launched_path = $executablePath
        second_launch_created_second_probe_window = $repeatLaunchPassed
        windows = $secondWindows
        process_snapshot = $secondProcessSnapshot
    })
    $regionObservations += @($secondProbeWindows | Select-Object title,hwnd,visible,get_window_rgn_result,region_data_type,region_rectangle_count,region_bounds)
    if (-not $repeatLaunchPassed) {
        $notes.Add('Second launch did not produce exactly two top-level probe windows under one exact installed backend PID within 15 seconds.')
    }

    if ($secondProbeWindows.Count -ge 2) {
        $secondaryWindow = @($secondProbeWindows | Where-Object { $_.title -eq 'FluxForm Probe 2' })
        if ($secondaryWindow.Count -eq 1 -and [FluxFormTask16.Native]::PostClose([long]$secondaryWindow[0].handle_value)) {
            $singleClosePassed = Wait-ForCondition {
                $probeWindows = @(Get-ProbeWindows $ExpectedProcessId)
                $processesNow = @(Get-InstalledProbeProcesses $executablePath)
                $probeWindows.Count -eq 1 -and $processesNow.Count -eq 1 -and $processesNow[0].Id -eq $ExpectedProcessId
            } 10
        }
    }
    $afterSingleCloseWindows = Get-TopLevelWindows $ExpectedProcessId
    $afterSingleCloseProcesses = Get-ProcessSnapshot $ExpectedProcessId $executablePath
    $steps.Add([pscustomobject]@{ action = 'wm_close_non_last_probe'; windows = $afterSingleCloseWindows; process_snapshot = $afterSingleCloseProcesses; passed = $singleClosePassed })
    if (-not $singleClosePassed) {
        $notes.Add('Non-last-window WM_CLOSE did not leave exactly one probe window and the same backend process alive.')
    }

    $remainingProbeWindows = @(Get-ProbeWindows $ExpectedProcessId)
    if ($remainingProbeWindows.Count -eq 1 -and [FluxFormTask16.Native]::PostClose([long]$remainingProbeWindows[0].handle_value)) {
        $lastClosePassed = Wait-ForCondition {
            @(Get-InstalledProbeProcesses $executablePath).Count -eq 0
        } 15
    }
    if ($lastClosePassed) {
        $lateProcessMonitor = Wait-ForNoLateInstalledProcess -ExpectedPath $executablePath -WindowSeconds 5
        $noBackendRestartOrLateProcessAfterClose = [bool]$lateProcessMonitor.passed
    }
    $steps.Add([pscustomobject]@{
        action = 'wm_close_last_probe'
        closed_window = if ($remainingProbeWindows.Count -eq 1) { $remainingProbeWindows[0] } else { $null }
        backend_process_exited = $lastClosePassed
        no_backend_restart_or_late_process_for_5_seconds = $noBackendRestartOrLateProcessAfterClose
        late_process_monitor = $lateProcessMonitor
        remaining_probe_processes = @(Get-InstalledProbeProcesses $executablePath | ForEach-Object { [pscustomobject]@{ pid = $_.Id; path = $_.Path } })
    })
    if (-not $lastClosePassed) {
        $notes.Add('The backend did not exit within 15 seconds after WM_CLOSE to the last probe window.')
    }
} catch {
    $failure = $_.Exception.Message
    $notes.Add("Safe native observation stopped: $failure")
} finally {
    # Graceful cleanup is restricted to this exact installed path and task-created process ID(s).
    foreach ($candidateId in @($ExpectedProcessId, $secondProcessId) | Where-Object { $_ }) {
        $candidate = Get-Process -Id ([int]$candidateId) -ErrorAction SilentlyContinue
        $candidatePath = $null
        if ($candidate) {
            try { $candidatePath = Get-Task16ProcessImagePath -Process $candidate }
            catch { $finalCleanup.Add([pscustomobject]@{ pid = $candidate.Id; method = 'WM_CLOSE skipped'; reason = 'could not verify process image path' }) }
        }
        if ($candidate -and $candidatePath -and $candidatePath.Equals($executablePath, [StringComparison]::OrdinalIgnoreCase)) {
            $windows = @([FluxFormTask16.Native]::GetWindowsForProcess([uint32]$candidate.Id))
            foreach ($window in $windows) {
                if ([FluxFormTask16.Native]::PostClose([long]$window.Handle)) {
                    $finalCleanup.Add([pscustomobject]@{ pid = $candidate.Id; hwnd = ('0x{0:X}' -f $window.Handle); method = 'WM_CLOSE'; title = $window.Title })
                }
            }
        }
    }
    $allTaskProcesses = @(Get-InstalledProbeProcesses $executablePath)
    foreach ($candidate in $allTaskProcesses) {
        try { $null = $candidate.WaitForExit(5000) } catch { }
    }
    $allTaskProcesses = @(Get-InstalledProbeProcesses $executablePath)
    foreach ($candidate in $allTaskProcesses) {
        $candidatePath = $null
        try { $candidatePath = Get-Task16ProcessImagePath -Process $candidate } catch { }
        if ($candidate.Id -in @($ExpectedProcessId, $secondProcessId) -and $candidatePath -and $candidatePath.Equals($executablePath, [StringComparison]::OrdinalIgnoreCase)) {
            Stop-Process -Id $candidate.Id -Force
            $forcedTermination = $true
            $finalCleanup.Add([pscustomobject]@{ pid = $candidate.Id; method = 'Stop-Process -Force'; exact_path_reverified = $true })
        }
    }
}

$remainingProcesses = @(Get-InstalledProbeProcesses $executablePath)
$lastProbeWindowCount = @(Get-ProbeWindows $ExpectedProcessId).Count
if ($remainingProcesses.Count -gt 0) {
    $notes.Add('Task-created installed process remained after cleanup attempts; verify exact PID/path before any further action.')
}
if ($forcedTermination) {
    $notes.Add('A task-created process required exact-PID forced termination after graceful WM_CLOSE cleanup; see raw observations.')
}
if (-not $noBackendRestartOrLateProcessAfterClose) {
    $notes.Add('No post-close stability interval proved absence of an exact installed backend restart or late process; structural observation PASS is disabled.')
}

$lastProcessSnapshot = [pscustomobject]@{
    exact_installed_process_count = $remainingProcesses.Count
    exact_installed_process_ids = @($remainingProcesses | ForEach-Object { $_.Id })
    process_closed_after_observation = ($remainingProcesses.Count -eq 0)
    forced_termination_used = $forcedTermination
    no_backend_restart_or_late_process_after_close = $noBackendRestartOrLateProcessAfterClose
    post_close_monitor_window_seconds = 5
    post_close_monitor_poll_count = [int]$lateProcessMonitor.poll_count
    post_close_process_observations = @($lateProcessMonitor.observed_processes)
    cleanup_actions = @($finalCleanup)
}
$nativeRegionPresent = @($regionObservations | Where-Object { $_.get_window_rgn_result -gt 0 }).Count -gt 0
if ($nativeRegionPresent) {
    $notes.Add('GetWindowRgn observed a region on at least one probe HWND; this structural observation does not establish visual transparency, click-through behavior, or a correct circular shape.')
} else {
    $notes.Add('No native region presence was confirmed through GetWindowRgn.')
}
$notes.Add('CUA exposed no native app/window inventory in this session; no screenshot or visual/manual checklist item was observed.')
$notes.Add('The host had WebView2 Runtime 141.0.3537.71 before installation. Network disconnection and a clean no-runtime VM were not verified.')
$notes.Add('The installed path/process and provenance hashes were checked externally; the probe UI provenance status was not directly observed.')
$notes.Add('Unobserved fields remain false; idle CPU/GPU values are 0.0 placeholders because the result schema requires numbers, not measurements.')

$observationPassed = Test-Task16ObservationPass -SecondLaunchPassed $repeatLaunchPassed -SingleClosePassed $singleClosePassed -LastClosePassed $lastClosePassed -ProcessClosed ($remainingProcesses.Count -eq 0) -ForcedTermination $forcedTermination -NoLateProcess $noBackendRestartOrLateProcessAfterClose
$observationResult = [ordered]@{
    schema_version = 1
    evidence_type = 'task16.windows.structural-observation'
    observation_id = $ObservationId
    probe_mode = $expectedMode
    platform = 'windows-x64'
    observed_at_utc = $startUtc
    installed_artifact_sha256 = $expectedInstallerSha256
    installed_executable_path = $executablePath
    installed_executable_sha256 = $executableHash
    install_identity = $InstallId
    repeated_launch_created_second_window = $repeatLaunchPassed
    one_backend_after_second_launch = if ($secondProcessSnapshot) { $secondProcessSnapshot.exact_installed_process_count -eq 1 } else { $false }
    non_last_window_close_left_backend_alive = $singleClosePassed
    last_window_close_exited_backend = $lastClosePassed -and ($remainingProcesses.Count -eq 0)
    no_backend_restart_or_late_process_after_close = $noBackendRestartOrLateProcessAfterClose
    post_close_monitor_window_seconds = 5
    post_close_monitor_poll_count = [int]$lateProcessMonitor.poll_count
    forced_termination_used = $forcedTermination
    process_closed_after_observation = ($remainingProcesses.Count -eq 0)
    native_region_observations = @($regionObservations)
    app_window_probe_result_written = $false
    observation_passed = $observationPassed
    notes = 'Structural evidence only; visual transparency/input/focus/DPI/multi-monitor/idle-resource and clean offline first launch are not asserted. This journal is not the canonical WindowProbeResult.'
}

if (-not (Test-Path -LiteralPath $resultDirectory -PathType Container)) {
    [IO.Directory]::CreateDirectory($resultDirectory) | Out-Null
}
$null = Assert-Task16PathWithin -Candidate $resultDirectory -Root $appDataDirectory -MustExist
$null = Assert-Task16PathWithin -Candidate $resultPath -Root $resultDirectory
$null = Assert-Task16PathWithin -Candidate $observationPath -Root $resultDirectory
$rawObservations = [ordered]@{
    schema_version = 1
    evidence_type = 'task16.windows.process-observations'
    observation_id = $ObservationId
    observed_at_utc = $startUtc
    install_identity = $InstallId
    installer_path = $installerPath
    installer_package_sha256 = $installerHash
    installed_executable_path = $executablePath
    installed_executable_sha256 = $executableHash
    initial_pid = $ExpectedProcessId
    second_launch_pid = $secondProcessId
    second_launch_backend_count_and_window_check_passed = $repeatLaunchPassed
    non_last_wm_close_passed = $singleClosePassed
    last_wm_close_passed = $lastClosePassed -and ($remainingProcesses.Count -eq 0)
    no_backend_restart_or_late_process_after_close = $noBackendRestartOrLateProcessAfterClose
    post_close_monitor = $lateProcessMonitor
    forced_termination_used = $forcedTermination
    native_region_observations = @($regionObservations)
    steps = @($steps)
    cleanup = $lastProcessSnapshot
    failure = $failure
    prohibited_inferences = @('visual transparency', 'transparent-pixel click-through', 'drag/drop delivery', 'focus/keyboard', 'DPI/multi-monitor', '60-second idle CPU/GPU', 'network-disconnected first launch')
}
Write-JsonCreateNew $observationPath $rawObservations
$null = Assert-Task16PathWithin -Candidate $observationPath -Root $resultDirectory -MustExist
$null = Assert-Task16PathWithin -Candidate $resultPath -Root $resultDirectory
Write-JsonCreateNew $resultPath $observationResult
$null = Assert-Task16PathWithin -Candidate $resultPath -Root $resultDirectory -MustExist

$resultHashHandle = Open-Task16PinnedReadHandle -Path $resultPath
$resultHash = Get-Task16PinnedSha256 -Handle $resultHashHandle
$resultHashHandle.Dispose()
$observationsHashHandle = Open-Task16PinnedReadHandle -Path $observationPath
$observationsHash = Get-Task16PinnedSha256 -Handle $observationsHashHandle
$observationsHashHandle.Dispose()
$executableHandle.Dispose()
$installerHandle.Dispose()
$observationPassed = Test-Task16ObservationPass -SecondLaunchPassed $repeatLaunchPassed -SingleClosePassed $singleClosePassed -LastClosePassed $lastClosePassed -ProcessClosed ($remainingProcesses.Count -eq 0) -ForcedTermination $forcedTermination -NoLateProcess $noBackendRestartOrLateProcessAfterClose
[ordered]@{
    observation_status = if ($failure) { 'BLOCKED' } elseif ($observationPassed) { 'PASS' } else { 'FAIL' }
    app_window_probe_result_status = 'NOT_WRITTEN'
    passed = $false
    observation_passed = $observationPassed
    expected_process_id = $ExpectedProcessId
    installed_executable_path = $executablePath
    installed_executable_sha256 = $executableHash
    second_launch_created_second_window = $repeatLaunchPassed
    one_backend_after_second_launch = if ($secondProcessSnapshot) { $secondProcessSnapshot.exact_installed_process_count -eq 1 } else { $false }
    non_last_window_close_left_backend_alive = $singleClosePassed
    last_window_close_exited_backend = $lastClosePassed
    no_backend_restart_or_late_process_after_close = $noBackendRestartOrLateProcessAfterClose
    post_close_monitor_window_seconds = 5
    post_close_monitor_poll_count = [int]$lateProcessMonitor.poll_count
    process_closed_after_observation = ($remainingProcesses.Count -eq 0)
    forced_termination_used = $forcedTermination
    region_observation_count = @($regionObservations).Count
    webview_helper_process_count = if ($secondProcessSnapshot) { $secondProcessSnapshot.webview_helper_process_count } else { 0 }
    observation_id = $ObservationId
    structural_result_path = $resultPath
    structural_result_sha256 = $resultHash
    raw_observations_path = $observationPath
    raw_observations_sha256 = $observationsHash
} | ConvertTo-Json -Depth 5
