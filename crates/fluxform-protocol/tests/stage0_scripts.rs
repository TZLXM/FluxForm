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
    let evidence_root = root.join("target/stage0");
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
        let result = if status == "BLOCKED" {
            "blocked: native evidence is not present".to_owned()
        } else {
            let bytes = format!("verified fixture evidence for report row {row}");
            let artifact = evidence.path().join(format!("row-{row}.json"));
            fs::write(&artifact, &bytes).unwrap();
            let relative = artifact
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let digest = format!("{:x}", Sha256::digest(bytes.as_bytes()));
            format!("Evidence artifact: `{relative}`; SHA-256 `{digest}`")
        };
        report.push_str(&format!(
            "| {row} | {evidence_label} | **{status}** | test-platform; 2026-09-28; independent human reviewer | {result} |\n"
        ));
    }

    let path = directory.join("stage-0-gate-report.md");
    fs::write(&path, report).unwrap();
    FixtureReport {
        path,
        _evidence: evidence,
    }
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
    let output = invoke_gate("Complete", &[], None, None);
    let text = output_text(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains("report=BLOCKED"), "{text}");
    assert!(text.contains("ffmpeg-artifacts=NOT_RUN"), "{text}");
    assert!(text.contains("aggregate-samples=NOT_RUN"), "{text}");
    assert!(text.contains("public-server-linux=NOT_RUN"), "{text}");
    assert!(text.contains("stage0_complete=false"), "{text}");
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
        "target/stage0/report-fixture-",
        "target/stage0/nonexistent-report-fixture-",
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
