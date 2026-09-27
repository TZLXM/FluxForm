use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

const REPORT_EVIDENCE_LABELS: [&str; 23] = [
    "Protocol/schema determinism",
    "Windows FFmpeg profile and license record",
    "macOS x86_64 FFmpeg profile and license record",
    "macOS aarch64 FFmpeg profile and license record",
    "Linux x86_64 FFmpeg profile and license record",
    "Exact approved/deferred capability matrix and product-owner approval",
    "Every enabled edge and rejection sample executed against all four approved native profiles",
    "Atomic reject/rename/replace, injected replacement failures, and crash recovery on each supported local filesystem",
    "Linux filesystem sandbox denial",
    "Linux OS network denial, distinct from FFmpeg protocol-policy denial",
    "Linux cgroup v2 birth placement, aggregate process/memory/CPU containment, and kill",
    "Streaming upload, reservation expansion, and early body termination",
    "Capability authorization on every concrete endpoint, Origin enforcement, and trusted-proxy IP provenance",
    "SSE reconnect, replay, resync snapshot, and expiry",
    "Real positive and negative fail-closed public-server startup",
    "Windows installed-app window, repeated-launch, close, DPI, and multi-monitor behavior",
    "Native Intel and Apple Silicon installed-app macOS window behavior",
    "Linux X11 installed-AppImage window behavior",
    "Linux Wayland installed-AppImage behavior and explicit degraded capability",
    "Windows offline WebView2 installation and first launch",
    "Signed/notarized disconnected macOS installation and first launch on both architectures",
    "Linux disconnected AppImage first launch",
    "Approved FFmpeg/FFprobe sidecar hashes and offline fixed `-version` execution per platform",
];

const REPORT_EVIDENCE_KINDS: [&str; 23] = [
    "protocol-contract",
    "windows-ffmpeg-profile",
    "macos-x86_64-ffmpeg-profile",
    "macos-aarch64-ffmpeg-profile",
    "linux-x86_64-ffmpeg-profile",
    "approved-capability-matrix",
    "native-sample-aggregate",
    "native-atomic-output",
    "linux-filesystem-sandbox",
    "linux-network-sandbox",
    "linux-cgroup-containment",
    "streaming-upload-reservation",
    "capability-auth-origin-proxy",
    "sse-reconnect-replay",
    "linux-public-server-startup",
    "windows-installed-window",
    "macos-installed-window",
    "linux-x11-installed-window",
    "linux-wayland-installed-window",
    "windows-offline-webview2-install",
    "macos-offline-install",
    "linux-offline-appimage-install",
    "approved-ffmpeg-sidecars",
];

const REPORT_PAYLOAD_FIELDS: [&[&str]; 23] = [
    &["command", "passed_tests", "failed_tests", "contract_sha256"],
    &[
        "target_triple",
        "profile_id",
        "archive_sha256",
        "ffmpeg_sha256",
        "ffprobe_sha256",
        "license_sha256",
        "distribution_approval",
    ],
    &[
        "target_triple",
        "profile_id",
        "archive_sha256",
        "ffmpeg_sha256",
        "ffprobe_sha256",
        "license_sha256",
        "distribution_approval",
    ],
    &[
        "target_triple",
        "profile_id",
        "archive_sha256",
        "ffmpeg_sha256",
        "ffprobe_sha256",
        "license_sha256",
        "distribution_approval",
    ],
    &[
        "target_triple",
        "profile_id",
        "archive_sha256",
        "ffmpeg_sha256",
        "ffprobe_sha256",
        "license_sha256",
        "distribution_approval",
    ],
    &[
        "approval_text",
        "enabled_edge_count",
        "deferred_edge_count",
        "matrix_sha256",
    ],
    &[
        "target_profiles",
        "enabled_edge_results",
        "rejection_results",
        "aggregate_sha256",
    ],
    &[
        "filesystem_set",
        "replace_rejection",
        "injected_failures",
        "crash_recovery",
    ],
    &["native_platform", "filesystem_denials", "result_sha256"],
    &[
        "native_platform",
        "connect_denials",
        "ffmpeg_policy_distinctness",
    ],
    &[
        "native_platform",
        "controllers",
        "birth_placement",
        "cpu_limits",
        "memory_limits",
        "pids_limits",
        "kill_result",
    ],
    &[
        "stream_sha256",
        "reservation_expansion",
        "early_body_termination",
    ],
    &[
        "endpoint_matrix_sha256",
        "origin_results",
        "trusted_proxy_results",
    ],
    &["reconnect", "replay", "resync_snapshot", "expiry"],
    &[
        "native_runner",
        "positive_startup",
        "negative_startup",
        "listener_state",
    ],
    &[
        "installed_app_sha256",
        "repeated_launch",
        "close_behavior",
        "transparency",
        "click_through",
        "drag_drop",
        "dpi",
        "multi_monitor",
        "idle_cpu_gpu",
    ],
    &[
        "installed_app_sha256",
        "architectures",
        "visual_behavior",
        "input_behavior",
        "focus_behavior",
        "close_behavior",
        "dpi",
        "multi_monitor",
        "idle_cpu_gpu",
    ],
    &[
        "appimage_sha256",
        "display_server",
        "window_behavior",
        "input_behavior",
        "degraded_capability",
    ],
    &[
        "appimage_sha256",
        "display_server",
        "window_behavior",
        "degraded_capability",
    ],
    &[
        "installer_sha256",
        "network_state",
        "webview_runtime_precondition",
        "first_launch",
    ],
    &[
        "installer_sha256_intel",
        "installer_sha256_arm64",
        "network_state",
        "signature",
        "notarization",
        "first_launch",
    ],
    &["appimage_sha256", "network_state", "first_launch"],
    &[
        "windows_x86_64_sha256",
        "macos_x86_64_sha256",
        "macos_aarch64_sha256",
        "linux_x86_64_sha256",
        "version_execution",
    ],
];

const REPORT_PLATFORMS: [&str; 23] = [
    "windows-x86_64",
    "windows-x86_64",
    "macos-x86_64",
    "macos-aarch64",
    "linux-x86_64",
    "product-scope",
    "native-cross-platform",
    "native-filesystem-matrix",
    "linux-native",
    "linux-native",
    "linux-cgroupv2-delegated",
    "server-integration",
    "server-integration",
    "server-integration",
    "linux-cgroupv2-delegated",
    "windows-x86_64",
    "macos-native",
    "linux-x11",
    "linux-wayland",
    "windows-offline-vm",
    "macos-offline-native",
    "linux-offline-appimage",
    "four-native-platforms",
];

struct FixtureReport {
    path: PathBuf,
    _evidence: TempDir,
}

fn workspace_root() -> PathBuf {
    let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn fixture_report(directory: &Path, blocked_row: Option<usize>) -> FixtureReport {
    let root = workspace_root();
    let evidence_root = root.join("target/stage0/reviewed-evidence");
    fs::create_dir_all(&evidence_root).unwrap();
    let evidence = tempfile::Builder::new()
        .prefix("report-fixture-")
        .tempdir_in(evidence_root)
        .unwrap();
    let summary = if blocked_row.is_some() {
        "**Overall status: BLOCKED.** Current matrix: **22 PASS, 0 FAIL, 1 BLOCKED**."
    } else {
        "**Overall status: PASS.** Current matrix: **23 PASS, 0 FAIL, 0 BLOCKED**."
    };
    let mut report = format!(
        "# Stage 0 Gate Report\n\n{summary}\n\n| # | Required evidence | Status | Platform / date / reviewer | Command or procedure, result identity, and blocker |\n| ---: | --- | --- | --- | --- |\n"
    );
    for (index, evidence_label) in REPORT_EVIDENCE_LABELS.iter().enumerate() {
        let row = index + 1;
        let status = if blocked_row == Some(row) {
            "BLOCKED"
        } else {
            "PASS"
        };
        let platform = REPORT_PLATFORMS[index];
        let reviewer = "independent human reviewer";
        let result = if status == "BLOCKED" {
            "blocked: native evidence is not present".to_owned()
        } else {
            let kind = REPORT_EVIDENCE_KINDS[index];
            let schema = format!("fluxform.stage0.{kind}.v1");
            let mut payload = serde_json::json!({
                "schema": schema,
                "row_id": row,
                "label": evidence_label,
                "evidence_kind": kind,
                "result": "PASS",
            });
            for field in REPORT_PAYLOAD_FIELDS[index] {
                let value = if field.ends_with("_sha256") {
                    format!(
                        "{:x}",
                        Sha256::digest(format!("row-{row}-{field}").as_bytes())
                    )
                } else {
                    match (row, *field) {
                        (20, "network_state") | (21, "network_state") | (22, "network_state") => {
                            "disconnected".to_owned()
                        }
                        (20, "webview_runtime_precondition") => {
                            "WebView2 runtime installed before disconnect".to_owned()
                        }
                        (20, "first_launch") | (21, "first_launch") | (22, "first_launch") => {
                            "PASS".to_owned()
                        }
                        (21, "signature") => "valid".to_owned(),
                        (21, "notarization") => "accepted".to_owned(),
                        _ => format!("reviewed observation for row {row}: {field}"),
                    }
                };
                payload[field] = serde_json::Value::String(value);
            }
            let payload_bytes = serde_json::to_vec_pretty(&payload).unwrap();
            let payload_path = evidence.path().join(format!("row-{row:02}.payload.json"));
            fs::write(&payload_path, &payload_bytes).unwrap();
            let payload_relative = payload_path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let payload_sha = format!("{:x}", Sha256::digest(&payload_bytes));
            let bundle_id = evidence.path().file_name().unwrap().to_string_lossy();
            let manifest = serde_json::json!({
                "schema": "fluxform.stage0.reviewed-row-manifest.v1",
                "bundle_id": bundle_id,
                "row_id": row,
                "label": evidence_label,
                "status": "PASS",
                "evidence_kind": kind,
                "platform": platform,
                "date": "2026-09-28",
                "reviewer": {
                    "identity": reviewer,
                    "reviewed_at": "2026-09-28T12:00:00Z",
                },
                "review_state": "reviewed",
                "payload": {
                    "path": payload_relative,
                    "sha256": payload_sha,
                    "type": "application/json",
                    "schema": schema,
                },
            });
            let manifest_bytes = serde_json::to_vec_pretty(&manifest).unwrap();
            let manifest_path = evidence.path().join(format!("row-{row:02}.manifest.json"));
            fs::write(&manifest_path, &manifest_bytes).unwrap();
            let manifest_relative = manifest_path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let manifest_sha = format!("{:x}", Sha256::digest(&manifest_bytes));
            format!("Reviewed evidence manifest: `{manifest_relative}` SHA-256 `{manifest_sha}`")
        };
        report.push_str(&format!(
            "| {row} | {evidence_label} | **{status}** | {platform}; 2026-09-28; {reviewer} | {result} |\n"
        ));
    }

    let path = directory.join("stage-0-gate-report.md");
    fs::write(&path, report).unwrap();
    FixtureReport {
        path,
        _evidence: evidence,
    }
}

fn rewrite_report_details(report: &Path, mut update: impl FnMut(usize, &str) -> String) {
    let content = fs::read_to_string(report).unwrap();
    let mut rewritten = Vec::new();
    for line in content.lines() {
        let mut cells: Vec<_> = line.split('|').map(str::to_owned).collect();
        if cells.len() == 7
            && let Ok(row) = cells[1].trim().parse::<usize>()
            && cells[3].trim() == "**PASS**"
        {
            cells[5] = update(row, cells[5].trim());
            rewritten.push(cells.join("|"));
            continue;
        }
        rewritten.push(line.to_owned());
    }
    fs::write(report, rewritten.join("\n") + "\n").unwrap();
}

fn manifest_path_from_report(report: &Path, row: usize) -> PathBuf {
    let content = fs::read_to_string(report).unwrap();
    let line = content
        .lines()
        .find(|line| line.starts_with(&format!("| {row} |")))
        .unwrap();
    let manifest_relative = line
        .split("Reviewed evidence manifest: `")
        .nth(1)
        .unwrap()
        .split('`')
        .next()
        .unwrap();
    workspace_root().join(manifest_relative)
}

fn rewrite_manifest_and_report_hash(report: &Path, row: usize, manifest: &serde_json::Value) {
    let manifest_path = manifest_path_from_report(report, row);
    let bytes = serde_json::to_vec_pretty(manifest).unwrap();
    fs::write(&manifest_path, &bytes).unwrap();
    let manifest_relative = manifest_path
        .strip_prefix(workspace_root())
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/");
    let digest = format!("{:x}", Sha256::digest(&bytes));
    rewrite_report_details(report, |current_row, details| {
        if current_row == row {
            format!("Reviewed evidence manifest: `{manifest_relative}` SHA-256 `{digest}`")
        } else {
            details.to_owned()
        }
    });
}

#[cfg(windows)]
fn cargo_shim(directory: &Path) -> (PathBuf, PathBuf) {
    let bin = directory.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let log = directory.join("cargo-commands.log");
    fs::write(
        bin.join("cargo.cmd"),
        "@echo off\r\n>>\"%FLUXFORM_STAGE0_TEST_LOG%\" echo cargo %*\r\n>&2 echo shim stderr diagnostic\r\nexit /b %FLUXFORM_STAGE0_TEST_EXIT%\r\n",
    )
    .unwrap();
    (bin, log)
}

#[cfg(windows)]
fn pnpm_shim(directory: &Path) -> (PathBuf, PathBuf) {
    let bin = directory.join("pnpm-bin");
    fs::create_dir_all(&bin).unwrap();
    let log = directory.join("pnpm-commands.log");
    fs::write(
        bin.join("pnpm.cmd"),
        "@echo off\r\nif \"%~1\"==\"--version\" (echo 11.19.0& exit /b 0)\r\n>>\"%FLUXFORM_STAGE0_TEST_PNPM_LOG%\" echo pnpm %*\r\nexit /b 0\r\n",
    )
    .unwrap();
    (bin, log)
}

#[cfg(windows)]
fn invoke_desktop_build_with_pnpm_shim(bin: &Path, log: &Path) -> Output {
    let root = workspace_root();
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(root.join("scripts/check-stage0.ps1"))
        .args(["-Mode", "Automated", "-Gate", "desktop-build"]);
    let mut path = std::ffi::OsString::from(bin.as_os_str());
    path.push(";");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    command
        .env("PATH", path)
        .env("FLUXFORM_STAGE0_TEST_PNPM_LOG", log)
        .current_dir(root)
        .output()
        .unwrap()
}

#[cfg(windows)]
fn invoke_gate(
    mode: &str,
    gates: &[&str],
    report: Option<&Path>,
    shim: Option<(&Path, u8, &Path)>,
) -> Output {
    invoke_gate_with_verifier(mode, gates, report, shim, None, None)
}

#[cfg(windows)]
fn invoke_gate_with_verifier(
    mode: &str,
    gates: &[&str],
    report: Option<&Path>,
    shim: Option<(&Path, u8, &Path)>,
    legacy_binaries: Option<(&Path, &Path)>,
    archive: Option<(&Path, &str, &Path)>,
) -> Output {
    let root = workspace_root();
    let mut command = Command::new("powershell.exe");
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
        ])
        .arg(root.join("scripts/check-stage0.ps1"))
        .args(["-Mode", mode]);
    for gate in gates {
        command.arg("-Gate").arg(gate);
    }
    if let Some(report) = report {
        command.arg("-ReportPath").arg(report);
    }
    if let Some((ffmpeg, ffprobe)) = legacy_binaries {
        command
            .arg("-Ffmpeg")
            .arg(ffmpeg)
            .arg("-Ffprobe")
            .arg(ffprobe);
    }
    if let Some((archive, artifact_id, profile)) = archive {
        command
            .arg("-FfmpegArchive")
            .arg(archive)
            .arg("-ArtifactId")
            .arg(artifact_id)
            .arg("-Profile")
            .arg(profile);
    }
    if let Some((bin, exit_code, log)) = shim {
        let mut path = std::ffi::OsString::from(bin.as_os_str());
        path.push(";");
        path.push(std::env::var_os("PATH").unwrap_or_default());
        command
            .env("PATH", path)
            .env("FLUXFORM_STAGE0_TEST_LOG", log)
            .env("FLUXFORM_STAGE0_TEST_EXIT", exit_code.to_string());
    }
    command.current_dir(root).output().unwrap()
}

#[cfg(unix)]
fn cargo_shim(directory: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let bin = directory.join("bin");
    fs::create_dir_all(&bin).unwrap();
    let log = directory.join("cargo-commands.log");
    let shim = bin.join("cargo");
    fs::write(
        &shim,
        "#!/bin/sh\nprintf '%s\\n' \"cargo $*\" >> \"$FLUXFORM_STAGE0_TEST_LOG\"\nprintf '%s\\n' 'shim stderr diagnostic' >&2\nexit \"$FLUXFORM_STAGE0_TEST_EXIT\"\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&shim).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&shim, permissions).unwrap();
    (bin, log)
}

#[cfg(unix)]
fn pnpm_shim(directory: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let bin = directory.join("pnpm-bin");
    fs::create_dir_all(&bin).unwrap();
    let log = directory.join("pnpm-commands.log");
    let shim = bin.join("pnpm");
    fs::write(
        &shim,
        "#!/bin/sh\nif [ \"$1\" = '--version' ]; then printf '%s\\n' '11.19.0'; exit 0; fi\nprintf '%s\\n' \"pnpm $*\" >> \"$FLUXFORM_STAGE0_TEST_PNPM_LOG\"\nexit 0\n",
    )
    .unwrap();
    let mut permissions = fs::metadata(&shim).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&shim, permissions).unwrap();
    (bin, log)
}

#[cfg(unix)]
fn invoke_desktop_build_with_pnpm_shim(bin: &Path, log: &Path) -> Output {
    let root = workspace_root();
    let mut command = Command::new("bash");
    command.arg(root.join("scripts/check-stage0.sh")).args([
        "--mode",
        "automated",
        "--gate",
        "desktop-build",
    ]);
    let mut path = std::ffi::OsString::from(bin.as_os_str());
    path.push(":");
    path.push(std::env::var_os("PATH").unwrap_or_default());
    command
        .env("PATH", path)
        .env("FLUXFORM_STAGE0_TEST_PNPM_LOG", log)
        .current_dir(root)
        .output()
        .unwrap()
}

#[cfg(unix)]
fn invoke_gate(
    mode: &str,
    gates: &[&str],
    report: Option<&Path>,
    shim: Option<(&Path, u8, &Path)>,
) -> Output {
    invoke_gate_with_verifier(mode, gates, report, shim, None, None)
}

#[cfg(unix)]
fn invoke_gate_with_verifier(
    mode: &str,
    gates: &[&str],
    report: Option<&Path>,
    shim: Option<(&Path, u8, &Path)>,
    legacy_binaries: Option<(&Path, &Path)>,
    archive: Option<(&Path, &str, &Path)>,
) -> Output {
    let root = workspace_root();
    let mut command = Command::new("bash");
    command
        .arg(root.join("scripts/check-stage0.sh"))
        .args(["--mode", mode]);
    for gate in gates {
        command.args(["--gate", gate]);
    }
    if let Some(report) = report {
        command.args(["--report-path", report.to_str().unwrap()]);
    }
    if let Some((ffmpeg, ffprobe)) = legacy_binaries {
        command
            .args(["--ffmpeg", ffmpeg.to_str().unwrap(), "--ffprobe"])
            .arg(ffprobe);
    }
    if let Some((archive, artifact_id, profile)) = archive {
        command
            .args([
                "--ffmpeg-archive",
                archive.to_str().unwrap(),
                "--artifact-id",
                artifact_id,
                "--profile",
            ])
            .arg(profile);
    }
    if let Some((bin, exit_code, log)) = shim {
        let mut path = std::ffi::OsString::from(bin.as_os_str());
        path.push(":");
        path.push(std::env::var_os("PATH").unwrap_or_default());
        command
            .env("PATH", path)
            .env("FLUXFORM_STAGE0_TEST_LOG", log)
            .env("FLUXFORM_STAGE0_TEST_EXIT", exit_code.to_string());
    }
    command.current_dir(root).output().unwrap()
}

fn output_text(output: &Output) -> String {
    format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn git_status_text() -> String {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=all"])
        .current_dir(workspace_root())
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

#[cfg(any(windows, unix))]
#[test]
fn selected_gate_failure_stops_and_summarizes_unrun_gates() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = cargo_shim(directory.path());
    let output = invoke_gate(
        "Automated",
        &["protocol", "contract-drift"],
        None,
        Some((&bin, 23, &log)),
    );
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("protocol=FAIL"), "{text}");
    assert!(text.contains("contract-drift=NOT_RUN"), "{text}");
    assert!(
        !fs::read_to_string(log)
            .unwrap_or_default()
            .contains("contract-drift")
    );
}

#[cfg(any(windows, unix))]
#[test]
fn successful_protocol_gate_runs_contract_drift_verification() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = cargo_shim(directory.path());
    let output = invoke_gate(
        "Automated",
        &["protocol", "contract-drift"],
        None,
        Some((&bin, 0, &log)),
    );
    let text = output_text(&output);
    let commands = fs::read_to_string(log).unwrap_or_default();

    assert!(output.status.success(), "{text}");
    assert!(text.contains("protocol=PASS"), "{text}");
    assert!(text.contains("contract-drift=PASS"), "{text}");
    assert!(text.contains("stage0_complete=false"), "{text}");
    assert!(
        text.contains("shim stderr diagnostic"),
        "native stderr was lost: {text}"
    );
    assert!(
        commands.contains(
            "test -p fluxform-protocol --test contracts committed_contracts_match_the_rust_source"
        ),
        "expected the real contract drift test to run; commands: {commands}"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn lint_and_tests_cover_each_legal_desktop_mode_without_combining_features() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = cargo_shim(directory.path());
    let output = invoke_gate(
        "Automated",
        &["clippy", "desktop-probe-modes", "server-probe"],
        None,
        Some((&bin, 0, &log)),
    );
    let text = output_text(&output);
    let commands = fs::read_to_string(log).unwrap_or_default();

    assert!(output.status.success(), "{text}");
    assert!(text.contains("clippy=PASS"), "{text}");
    assert!(text.contains("desktop-probe-modes=PASS"), "{text}");
    assert!(text.contains("server-probe=PASS"), "{text}");
    for expected in [
        "clippy --workspace --exclude fluxform-desktop-probe --all-targets --all-features",
        "clippy -p fluxform-desktop-probe --all-targets",
        "clippy -p fluxform-desktop-probe --no-default-features --features probe-transparent-window-with-rectangular-hit-region --all-targets",
        "clippy -p fluxform-desktop-probe --no-default-features --features probe-opaque-frameless-fallback --all-targets",
        "test -p fluxform-desktop-probe --all-targets",
        "test -p fluxform-desktop-probe --no-default-features --features probe-transparent-window-with-rectangular-hit-region --all-targets",
        "test -p fluxform-desktop-probe --no-default-features --features probe-opaque-frameless-fallback --all-targets",
        "test -p fluxform-server-probe --all-targets --all-features",
    ] {
        assert!(
            commands.contains(expected),
            "missing `{expected}` in: {commands}"
        );
    }
    for command in commands.lines() {
        assert!(
            !(command.contains("probe-transparent-window-with-rectangular-hit-region")
                && command.contains("probe-opaque-frameless-fallback")),
            "mutually exclusive features were combined: {command}"
        );
    }
}

#[cfg(any(windows, unix))]
#[test]
fn complete_mode_keeps_the_committed_blocked_report_nonzero() {
    let output = invoke_gate("Complete", &["report"], None, None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(text.contains("stage0_complete=false"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_mode_runs_all_automated_gates_before_complete_gates() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = cargo_shim(directory.path());
    let output = invoke_gate("Complete", &[], None, Some((&bin, 23, &log)));
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("format=FAIL"), "{text}");
    for not_run in [
        "clippy=NOT_RUN",
        "protocol=NOT_RUN",
        "contract-drift=NOT_RUN",
        "capabilities=NOT_RUN",
        "ffmpeg-profile-tests=NOT_RUN",
        "atomic-output=NOT_RUN",
        "sandbox-unit=NOT_RUN",
        "server-probe=NOT_RUN",
        "desktop-probe-modes=NOT_RUN",
        "desktop-build=NOT_RUN",
        "ffmpeg-profile=NOT_RUN",
        "public-server-linux=NOT_RUN",
        "report=NOT_RUN",
        "ffmpeg-artifacts=NOT_RUN",
        "aggregate-samples=NOT_RUN",
        "stage0_complete=false",
    ] {
        assert!(text.contains(not_run), "missing `{not_run}` in: {text}");
    }
    let commands = fs::read_to_string(log).unwrap_or_default();
    assert!(commands.contains("cargo --locked --offline fmt --all -- --check"));
    assert!(!commands.contains("ffmpeg-artifacts"));
}

#[cfg(any(windows, unix))]
#[test]
fn native_provenance_workflow_step_uses_a_cross_shell_python_file() {
    let workflow =
        fs::read_to_string(workspace_root().join(".github/workflows/stage0-gates.yml")).unwrap();
    let native_job = workflow
        .split("  native-profile-samples:")
        .nth(1)
        .unwrap()
        .split("  aggregate-evidence:")
        .next()
        .unwrap();
    let provenance_step = native_job
        .split("      - id: provenance")
        .nth(1)
        .unwrap()
        .split("      - name: Upload exact native reports")
        .next()
        .unwrap();

    assert!(
        provenance_step.contains("python scripts/bind_stage0_native_provenance.py"),
        "provenance step must call a checked-in, cross-shell Python script: {provenance_step}"
    );
    assert!(
        !provenance_step.contains("<<'PY'") && !provenance_step.contains("<<PY"),
        "PowerShell's default shell cannot parse a Bash heredoc: {provenance_step}"
    );
    for (job_start, next_job) in [
        ("  windows:", "  macos:"),
        ("  macos:", "  ubuntu:"),
        ("  ubuntu:", "  public-server-hosted-status:"),
        ("  native-profile-samples:", "  aggregate-evidence:"),
        ("  aggregate-evidence:", "  complete:"),
    ] {
        let job = workflow
            .split(job_start)
            .nth(1)
            .unwrap()
            .split(next_job)
            .next()
            .unwrap();
        assert!(
            job.contains("actions/setup-python@v5") && job.contains("python-version: '3.12'"),
            "job {job_start} must provision the pinned Python runtime needed by gate helpers"
        );
    }
    let complete_job = workflow.split("  complete:").nth(1).unwrap();
    assert!(
        complete_job.contains("actions/setup-python@v5")
            && complete_job.contains("python-version: '3.12'"),
        "Complete job must provision the pinned Python runtime needed by report validation"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn desktop_build_uses_a_target_snapshot_and_preserves_source_status() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = pnpm_shim(directory.path());
    let status_before = git_status_text();
    let output = invoke_desktop_build_with_pnpm_shim(&bin, &log);
    let text = output_text(&output);
    let commands = fs::read_to_string(log).unwrap_or_default();
    let status_after = git_status_text();

    assert!(output.status.success(), "{text}");
    assert!(text.contains("desktop-build=PASS"), "{text}");
    assert!(
        text.contains("target/stage0") || text.contains("target\\stage0"),
        "build did not use the isolated target snapshot: {text}"
    );
    assert!(
        commands.contains("install --offline --frozen-lockfile"),
        "{commands}"
    );
    assert!(
        commands.contains("run tauri:build --no-bundle"),
        "{commands}"
    );
    assert_eq!(
        status_before, status_after,
        "desktop gate changed source Git status"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn complete_mode_rejects_a_blocked_report_row() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), Some(8));
    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_passes_only_with_all_reviewed_pass_rows() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(output.status.success(), "{text}");
    assert!(text.contains("report=PASS"), "{text}");
    assert!(text.contains("stage0_complete=false"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_a_fabricated_evidence_label() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let content = fs::read_to_string(&report.path).unwrap();
    let fabricated = content.replace(
        "| 1 | Protocol/schema determinism |",
        "| 1 | Fabricated evidence label |",
    );
    fs::write(&report.path, fabricated).unwrap();

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=FAIL"), "{text}");
    assert!(
        text.contains("does not match the required Stage 0 evidence item"),
        "{text}"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_a_nonexistent_or_mismatched_evidence_identity() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let content = fs::read_to_string(&report.path).unwrap();
    let stale_path = content.replace(
        "target/stage0/reviewed-evidence/report-fixture-",
        "target/stage0/reviewed-evidence/nonexistent-report-fixture-",
    );
    fs::write(&report.path, stale_path).unwrap();

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(
        text.contains("no existing in-repository artifact"),
        "{text}"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_an_overall_status_that_disagrees_with_rows() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let content = fs::read_to_string(&report.path).unwrap();
    fs::write(
        &report.path,
        content.replace("Overall status: PASS", "Overall status: BLOCKED"),
    )
    .unwrap();

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=FAIL"), "{text}");
    assert!(text.contains("summary"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_requires_a_reviewed_row_manifest_bundle() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    rewrite_report_details(&report.path, |_, details| {
        details.replace("Reviewed evidence manifest:", "Evidence artifact:")
    });
    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(text.contains("reviewed evidence manifest"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_one_cargo_lock_reused_for_every_row() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let cargo_lock = workspace_root().join("Cargo.lock");
    let bytes = fs::read(&cargo_lock).unwrap();
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let mut content = fs::read_to_string(&report.path).unwrap();
    let shared_identity = format!("Evidence artifact: `./Cargo.lock`; SHA-256 `{digest}`");
    let mut rewritten = Vec::new();
    for line in content.lines() {
        let mut cells: Vec<_> = line.split('|').collect();
        if cells.len() == 7 && cells[3].trim() == "**PASS**" {
            cells[5] = &shared_identity;
            rewritten.push(cells.join("|"));
        } else {
            rewritten.push(line.to_owned());
        }
    }
    content = rewritten.join("\n") + "\n";
    fs::write(&report.path, content).unwrap();

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(text.contains("reviewed evidence manifest"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_a_reused_row_manifest() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let first = fs::read_to_string(&report.path)
        .unwrap()
        .lines()
        .find(|line| line.starts_with("| 1 |"))
        .unwrap()
        .split('|')
        .nth(5)
        .unwrap()
        .trim()
        .to_owned();
    rewrite_report_details(&report.path, |_, _| first.clone());

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(
        text.contains("manifest is reused across report rows"),
        "{text}"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_requires_manual_window_observation_payload_not_a_lockfile() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let manifest_path = manifest_path_from_report(&report.path, 16);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let lock_path = workspace_root().join("Cargo.lock");
    let lock_sha = format!("{:x}", Sha256::digest(fs::read(&lock_path).unwrap()));
    manifest["payload"]["path"] = serde_json::Value::String("./Cargo.lock".to_owned());
    manifest["payload"]["sha256"] = serde_json::Value::String(lock_sha);
    rewrite_manifest_and_report_hash(&report.path, 16, &manifest);

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(
        text.contains("evidence payload escaped its reviewed bundle"),
        "{text}"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_payload_reuse_between_row_manifests() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let first_path = manifest_path_from_report(&report.path, 1);
    let first: serde_json::Value = serde_json::from_slice(&fs::read(first_path).unwrap()).unwrap();
    let shared_payload = first["payload"].clone();
    for row in 2..=23 {
        let path = manifest_path_from_report(&report.path, row);
        let mut manifest: serde_json::Value =
            serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        manifest["payload"] = shared_payload.clone();
        rewrite_manifest_and_report_hash(&report.path, row, &manifest);
    }

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(
        text.contains("payload is reused across report rows"),
        "{text}"
    );
}

#[cfg(unix)]
#[test]
fn complete_report_gate_rejects_payload_symlinks_outside_the_bundle() {
    use std::os::unix::fs::symlink;

    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let manifest_path = manifest_path_from_report(&report.path, 16);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let evidence_dir = manifest_path.parent().unwrap();
    let external = workspace_root().join("Cargo.lock");
    let alias = evidence_dir.join("row-16-external.payload.json");
    symlink(&external, &alias).unwrap();
    let external_bytes = fs::read(&external).unwrap();
    manifest["payload"]["path"] = serde_json::Value::String(
        alias
            .strip_prefix(workspace_root())
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/"),
    );
    manifest["payload"]["sha256"] =
        serde_json::Value::String(format!("{:x}", Sha256::digest(external_bytes)));
    rewrite_manifest_and_report_hash(&report.path, 16, &manifest);

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(text.contains("symlink or reparse point"), "{text}");
}

#[cfg(any(windows, unix))]
#[test]
fn complete_report_gate_rejects_a_row_kind_that_does_not_match_its_label() {
    let directory = TempDir::new().unwrap();
    let report = fixture_report(directory.path(), None);
    let manifest_path = manifest_path_from_report(&report.path, 16);
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    manifest["evidence_kind"] = serde_json::Value::String("protocol-contract".to_owned());
    rewrite_manifest_and_report_hash(&report.path, 16, &manifest);

    let output = invoke_gate("Complete", &["report"], Some(&report.path), None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(
        text.contains("evidence kind does not match required row"),
        "{text}"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn legacy_executable_paths_are_blocked_without_invoking_tools() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = cargo_shim(directory.path());
    let ffmpeg = directory.path().join("ffmpeg.exe");
    let ffprobe = directory.path().join("ffprobe.exe");
    let output = invoke_gate_with_verifier(
        "Automated",
        &["ffmpeg-profile"],
        None,
        Some((&bin, 0, &log)),
        Some((&ffmpeg, &ffprobe)),
        None,
    );
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("ffmpeg-profile=BLOCKED"), "{text}");
    assert!(
        fs::read_to_string(log).unwrap_or_default().is_empty(),
        "legacy direct executable paths must not invoke cargo or the supplied files"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn archive_profile_inputs_invoke_the_hardened_verifier() {
    let directory = TempDir::new().unwrap();
    let (bin, log) = cargo_shim(directory.path());
    let archive = directory.path().join("ffmpeg-candidate.zip");
    let profile = directory.path().join("ffmpeg-profile.toml");
    fs::write(&archive, b"test archive bytes").unwrap();
    fs::write(&profile, "profile_id = \"test\"\n").unwrap();
    let output = invoke_gate_with_verifier(
        "Automated",
        &["ffmpeg-profile"],
        None,
        Some((&bin, 0, &log)),
        None,
        Some((&archive, "candidate-id", &profile)),
    );
    let text = output_text(&output);
    let commands = fs::read_to_string(log).unwrap_or_default();

    assert!(
        !output.status.success(),
        "a stub verifier cannot produce approved evidence: {text}"
    );
    assert!(
        commands.contains("cargo --locked --offline run -p fluxform-ffmpeg-profile -- verify"),
        "{commands}"
    );
    assert!(
        commands.contains("--artifact-id candidate-id"),
        "{commands}"
    );
    assert!(commands.contains("--archive "), "{commands}");
    assert!(text.contains("ffmpeg-profile=BLOCKED"), "{text}");
}
