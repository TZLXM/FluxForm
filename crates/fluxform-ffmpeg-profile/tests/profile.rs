use std::fs;
use std::path::PathBuf;
use std::process::Command;

use fluxform_ffmpeg_profile::{
    ApprovedArtifact, ArtifactStatus, BuildProfile, CapturedProbeOutputs, ProbeReport,
};
use tempfile::TempDir;

const FFMPEG_VERSION: &str = r#"ffmpeg version 8.1.1-essentials_build-www.gyan.dev Copyright (c) 2000-2026 the FFmpeg developers
built with gcc 15.2.0
configuration: --enable-gpl --disable-debug --enable-libx264
libavutil      60. 20.100 / 60. 20.100
"#;

const FFPROBE_VERSION: &str = r#"ffprobe version 8.1.1-essentials_build-www.gyan.dev Copyright (c) 2007-2026 the FFmpeg developers
built with gcc 15.2.0
configuration: --enable-gpl --disable-debug --enable-libx264
libavutil      60. 20.100 / 60. 20.100
"#;

fn valid_profile() -> String {
    r#"
profile_id = "fluxform-ffmpeg-v1"
license_declaration = "GPL-3.0-or-later"
declared_codecs = ["aac", "h264"]
protocol_whitelist = ["file", "pipe"]

[required]
muxers = ["mp4"]
demuxers = ["mov"]
protocols = ["file", "pipe"]

[[required.encoders]]
name = "aac"
codec = "aac"

[[required.encoders]]
name = "libx264"
codec = "h264"

[[required.decoders]]
name = "aac"
codec = "aac"

[[required.decoders]]
name = "h264"
codec = "h264"

[[artifacts]]
artifact_id = "windows-x86_64-8.1.1"
status = "approved"
target_triple = "x86_64-pc-windows-msvc"
archive_format = "zip32"
artifact_uri = "https://artifacts.example.invalid/ffmpeg.zip"
artifact_sha256 = "1111111111111111111111111111111111111111111111111111111111111111"
artifact_size_bytes = 1024
ffmpeg_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ffmpeg_size_bytes = 2048
ffprobe_sha256 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
ffprobe_size_bytes = 2048
license = "GPL-3.0-or-later"
license_text_path = "LICENSE.txt"
license_text_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
license_text_size_bytes = 2048
source_revision = "239f2c733d"
source_offer_url = "https://artifacts.example.invalid/ffmpeg-source.tar.xz"
# Test-only identity fixture; this is not product-owner or legal approval.
approval_record_id = "TEST-ONLY-IDENTITY-FIXTURE"
approval_date = "2000-01-01"
"#
    .to_owned()
}

const STAGE0_TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
];

fn approved_gate_profile(
    required_targets: &[&str],
    artifact_targets: &[&str],
    include_owner_approval: bool,
    include_legal_approval: bool,
) -> String {
    let mut profile = valid_profile();
    let artifact_template = profile
        .split_once("[[artifacts]]\n")
        .expect("artifact fixture")
        .1
        .to_owned();

    for target in artifact_targets
        .iter()
        .copied()
        .filter(|target| *target != STAGE0_TARGETS[0])
    {
        let id = format!("test-only-{target}");
        let row = artifact_template
            .replace("windows-x86_64-8.1.1", &id)
            .replace(STAGE0_TARGETS[0], target)
            .replace(
                "https://artifacts.example.invalid/ffmpeg.zip",
                &format!("https://artifacts.example.invalid/{id}.zip"),
            )
            .replace("TEST-ONLY-IDENTITY-FIXTURE", &format!("TEST-ONLY-{target}"));
        profile.push_str("\n[[artifacts]]\n");
        profile.push_str(&row);
    }

    let targets = required_targets
        .iter()
        .map(|target| format!("\"{target}\""))
        .collect::<Vec<_>>()
        .join(", ");
    profile.push_str("\n[distribution_gate]\nstatus = \"approved\"\n");
    profile.push_str(&format!("required_target_triples = [{targets}]\n"));
    profile.push_str("owner_legal_approval_required = true\n");
    if include_owner_approval {
        profile.push_str("owner_approval_record_id = \"TEST-OWNER-APPROVAL\"\n");
        profile.push_str("owner_approval_date = \"2000-01-01\"\n");
    }
    if include_legal_approval {
        profile.push_str("legal_approval_record_id = \"TEST-LEGAL-APPROVAL\"\n");
        profile.push_str("legal_approval_date = \"2000-01-01\"\n");
    }
    profile
}

fn outputs() -> CapturedProbeOutputs {
    CapturedProbeOutputs {
        ffmpeg_version: FFMPEG_VERSION.to_owned(),
        ffprobe_version: FFPROBE_VERSION.to_owned(),
        protocols: "Supported file protocols:\nInput:\n  file\n  pipe\nOutput:\n  file\n  pipe\n"
            .to_owned(),
        demuxers: "Demuxers:\n D  mov             QuickTime / MOV\n".to_owned(),
        muxers: "Muxers:\n E  mp4             MP4\n".to_owned(),
        decoders: "Decoders:\n V....D h264 H.264\n A....D aac AAC\n".to_owned(),
        encoders: "Encoders:\n V..... libx264 H.264\n A..... aac AAC\n".to_owned(),
    }
}

fn load(text: &str) -> (TempDir, BuildProfile) {
    let (temp, path) = write_profile(text);
    let profile = BuildProfile::load(&path).expect("load valid profile");
    (temp, profile)
}

fn write_profile(text: &str) -> (TempDir, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("profile.toml");
    fs::write(&path, text).expect("write profile");
    (temp, path)
}

fn valid_report() -> (TempDir, BuildProfile, ProbeReport) {
    let (temp, profile) = load(&valid_profile());
    let artifact = profile.artifacts().first().expect("artifact fixture");
    let report = ProbeReport::from_captured(&profile, artifact, outputs()).expect("parse outputs");
    (temp, profile, report)
}

#[test]
fn rejects_different_ffmpeg_and_ffprobe_versions() {
    let (_temp, profile) = load(&valid_profile());
    let artifact = &profile.artifacts()[0];
    let mut captured = outputs();
    captured.ffprobe_version = captured.ffprobe_version.replace("8.1.1", "8.1.0");

    assert!(ProbeReport::from_captured(&profile, artifact, captured).is_err());
}

#[test]
fn rejects_different_ffmpeg_and_ffprobe_configurations() {
    let (_temp, profile) = load(&valid_profile());
    let artifact = &profile.artifacts()[0];
    let mut captured = outputs();
    captured.ffprobe_version = captured.ffprobe_version.replace(" --enable-libx264", "");

    assert!(ProbeReport::from_captured(&profile, artifact, captured).is_err());
}

#[test]
fn expands_comma_separated_ffmpeg_capability_aliases() {
    let (_temp, profile) = load(&valid_profile());
    let artifact = &profile.artifacts()[0];
    let mut captured = outputs();
    captured.demuxers = "Demuxers:\n D  mov,mp4,m4a,3gp,3g2,mj2  QuickTime / MOV\n".to_owned();

    let report = ProbeReport::from_captured(&profile, artifact, captured).expect("parse aliases");
    assert!(report.demuxers.contains(&"mov".to_owned()));
    assert!(report.demuxers.contains(&"mp4".to_owned()));
}

#[test]
fn rejects_each_missing_required_capability_kind() {
    for kind in ["muxers", "demuxers", "encoders", "decoders", "protocols"] {
        let (_temp, profile, mut report) = valid_report();
        match kind {
            "muxers" => report.muxers.clear(),
            "demuxers" => report.demuxers.clear(),
            "encoders" => report.encoders.clear(),
            "decoders" => report.decoders.clear(),
            "protocols" => report.protocols.clear(),
            _ => unreachable!(),
        }
        assert!(
            report.validate(&profile).is_err(),
            "missing {kind} must fail"
        );
    }
}

#[test]
fn rejects_required_codec_capability_that_is_not_declared() {
    let invalid = valid_profile().replace(
        "declared_codecs = [\"aac\", \"h264\"]",
        "declared_codecs = [\"h264\"]",
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("profile.toml");
    fs::write(&path, invalid).expect("write profile");

    assert!(BuildProfile::load(&path).is_err());
}

#[test]
fn rejects_distribution_records_with_mandatory_identity_fields_omitted() {
    for field_prefix in [
        "license = ",
        "source_revision = ",
        "source_offer_url = ",
        "artifact_sha256 = ",
        "artifact_size_bytes = ",
        "ffmpeg_sha256 = ",
        "ffmpeg_size_bytes = ",
        "ffprobe_sha256 = ",
        "ffprobe_size_bytes = ",
        "target_triple = ",
        "archive_format = ",
        "artifact_uri = ",
        "license_text_path = ",
        "license_text_sha256 = ",
        "license_text_size_bytes = ",
    ] {
        let invalid = valid_profile()
            .lines()
            .filter(|line| !line.trim_start().starts_with(field_prefix))
            .collect::<Vec<_>>()
            .join("\n");
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("profile.toml");
        fs::write(&path, invalid).expect("write profile");
        assert!(
            BuildProfile::load(&path).is_err(),
            "omitting {field_prefix} must fail"
        );
    }
}

#[test]
fn rejects_network_or_nested_protocols_in_invocation_whitelist() {
    for forbidden in ["http", "https", "tcp", "udp", "srt", "ftp", "ssh", "crypto"] {
        let invalid = valid_profile().replace(
            "protocol_whitelist = [\"file\", \"pipe\"]",
            &format!("protocol_whitelist = [\"file\", \"pipe\", \"{forbidden}\"]"),
        );
        let temp = tempfile::tempdir().expect("tempdir");
        let path = temp.path().join("profile.toml");
        fs::write(&path, invalid).expect("write profile");
        assert!(
            BuildProfile::load(&path).is_err(),
            "{forbidden} must fail closed"
        );
    }
}

#[test]
fn captured_report_is_normalized_sorted_and_validates() {
    let (_temp, profile, mut report) = valid_report();

    report.validate(&profile).expect("valid report");
    assert_eq!(report.version, "8.1.1-essentials_build-www.gyan.dev");
    assert_eq!(report.encoders, vec!["aac", "libx264"]);
    assert_eq!(report.decoders, vec!["aac", "h264"]);
    assert_eq!(
        report.build_configuration,
        "--enable-gpl --disable-debug --enable-libx264"
    );
}

#[test]
fn exact_approved_identity_is_required() {
    let (_temp, profile, report) = valid_report();
    let approved = profile
        .approved_artifact("windows-x86_64-8.1.1")
        .expect("test-only approved identity fixture");
    report.verify_identity(&approved).expect("exact identity");

    assert_identity_mutation_is_rejected(&report, &approved, "profile_id", |r| {
        r.profile_id = "different-profile".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "profile_digest", |r| {
        r.profile_digest = "e".repeat(64);
    });
    assert_identity_mutation_is_rejected(&report, &approved, "distribution_gate_status", |r| {
        r.distribution_gate_status = "approved".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "artifact_id", |r| {
        r.artifact_id = "different-artifact".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "artifact_status", |r| {
        r.artifact_status = ArtifactStatus::Candidate;
    });
    assert_identity_mutation_is_rejected(&report, &approved, "artifact_uri", |r| {
        r.artifact_uri = "https://artifacts.example.invalid/other.zip".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "source_offer_url", |r| {
        r.source_offer_url = "https://artifacts.example.invalid/different-source".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "artifact_sha256", |r| {
        r.artifact_sha256 = "f".repeat(64);
    });
    assert_identity_mutation_is_rejected(&report, &approved, "artifact_size_bytes", |r| {
        r.artifact_size_bytes += 1;
    });
    assert_identity_mutation_is_rejected(&report, &approved, "target_triple", |r| {
        r.target_triple = "aarch64-apple-darwin".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "ffmpeg_sha256", |r| {
        r.ffmpeg_sha256 = "c".repeat(64);
    });
    assert_identity_mutation_is_rejected(&report, &approved, "ffmpeg_size_bytes", |r| {
        r.ffmpeg_size_bytes += 1;
    });
    assert_identity_mutation_is_rejected(&report, &approved, "ffprobe_sha256", |r| {
        r.ffprobe_sha256 = "d".repeat(64);
    });
    assert_identity_mutation_is_rejected(&report, &approved, "ffprobe_size_bytes", |r| {
        r.ffprobe_size_bytes += 1;
    });
    assert_identity_mutation_is_rejected(&report, &approved, "source_revision", |r| {
        r.source_revision = "different-source".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "reported_source_revision", |r| {
        r.source_revision_reported_by_binary = Some("different-source".to_owned());
    });
    assert_identity_mutation_is_rejected(&report, &approved, "license_declaration", |r| {
        r.license_declaration = "different-license".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "license_text_path", |r| {
        r.license_text_path = "OTHER-LICENSE".to_owned();
    });
    assert_identity_mutation_is_rejected(&report, &approved, "license_text_sha256", |r| {
        r.license_text_sha256 = "3".repeat(64);
    });
    assert_identity_mutation_is_rejected(&report, &approved, "license_text_size_bytes", |r| {
        r.license_text_size_bytes += 1;
    });
    assert_identity_mutation_is_rejected(&report, &approved, "approval_record_id", |r| {
        r.approval_record_id = Some("TEST-OTHER-IDENTITY".to_owned());
    });
    assert_identity_mutation_is_rejected(&report, &approved, "approval_date", |r| {
        r.approval_date = Some("2001-01-01".to_owned());
    });
}

#[test]
fn report_validation_rejects_unmeasured_archive_and_license_identity() {
    for field in [
        "artifact_sha256",
        "artifact_size_bytes",
        "license_text_sha256",
        "license_text_size_bytes",
    ] {
        let (_temp, profile, mut report) = valid_report();
        match field {
            "artifact_sha256" => report.artifact_sha256 = "c".repeat(64),
            "artifact_size_bytes" => report.artifact_size_bytes += 1,
            "license_text_sha256" => report.license_text_sha256 = "d".repeat(64),
            "license_text_size_bytes" => report.license_text_size_bytes += 1,
            _ => unreachable!(),
        }
        assert!(
            report.validate(&profile).is_err(),
            "changed observed {field} must not be replaced from the manifest"
        );
    }
}

fn assert_identity_mutation_is_rejected(
    report: &ProbeReport,
    approved: &ApprovedArtifact,
    field: &str,
    mutate: impl FnOnce(&mut ProbeReport),
) {
    let mut changed = report.clone();
    mutate(&mut changed);
    assert!(
        changed.verify_identity(approved).is_err(),
        "mutated {field} must not match the immutable artifact row"
    );
}

#[test]
fn approved_gate_requires_owner_and_legal_approval_records() {
    let text = approved_gate_profile(STAGE0_TARGETS, STAGE0_TARGETS, false, true);
    let (_temp, path) = write_profile(&text);
    assert!(
        BuildProfile::load(path).is_err(),
        "owner approval is required"
    );

    let text = approved_gate_profile(STAGE0_TARGETS, STAGE0_TARGETS, true, false);
    let (_temp, path) = write_profile(&text);
    assert!(
        BuildProfile::load(path).is_err(),
        "legal approval is required"
    );

    for field in ["owner_approval_date", "legal_approval_date"] {
        for invalid_date in ["invalid", "2026-13-40", "2025-02-29"] {
            let text = approved_gate_profile(STAGE0_TARGETS, STAGE0_TARGETS, true, true).replace(
                &format!("{field} = \"2000-01-01\""),
                &format!("{field} = \"{invalid_date}\""),
            );
            let (_temp, path) = write_profile(&text);
            assert!(
                BuildProfile::load(path).is_err(),
                "invalid {field} {invalid_date} must fail"
            );
        }
    }
}

#[test]
fn approved_gate_requires_exact_stage0_target_set() {
    let reduced = &STAGE0_TARGETS[..1];
    for targets in [&[][..], reduced] {
        let text = approved_gate_profile(targets, STAGE0_TARGETS, true, true);
        let (_temp, path) = write_profile(&text);
        assert!(
            BuildProfile::load(path).is_err(),
            "empty or reduced target set must not approve distribution"
        );
    }
}

#[test]
fn approved_gate_requires_an_approved_row_for_every_native_target() {
    let text = approved_gate_profile(STAGE0_TARGETS, &[STAGE0_TARGETS[0]], true, true);
    let (_temp, path) = write_profile(&text);
    assert!(
        BuildProfile::load(path).is_err(),
        "missing native rows must fail"
    );
}

#[test]
fn complete_approved_gate_has_all_four_approved_target_rows() {
    // Synthetic structure only; these IDs and rows do not represent real approvals.
    let text = approved_gate_profile(STAGE0_TARGETS, STAGE0_TARGETS, true, true);
    let (_temp, path) = write_profile(&text);
    let profile = BuildProfile::load(path).expect("complete synthetic approval fixture");
    assert!(profile.gate_is_approved());
}

#[test]
fn archive_verification_rejects_wrong_archive_identity_before_extraction() {
    let (_profile_temp, profile) = load(&valid_profile());
    let archive_temp = tempfile::tempdir().expect("archive tempdir");
    let archive = archive_temp.path().join("candidate.zip");
    fs::write(&archive, b"not the immutable candidate archive").expect("write archive");

    let error = ProbeReport::collect_from_archive(&profile, "windows-x86_64-8.1.1", &archive)
        .expect_err("archive with wrong size/hash must fail before extraction");
    assert!(error.to_string().contains("archive identity mismatch"));
}

#[test]
fn cli_no_longer_accepts_unverified_executable_paths() {
    let output = Command::new(env!("CARGO_BIN_EXE_fluxform-ffmpeg-profile"))
        .args([
            "verify",
            "--profile",
            "missing-profile.toml",
            "--ffmpeg",
            "untrusted-ffmpeg.exe",
            "--ffprobe",
            "untrusted-ffprobe.exe",
            "--out",
            "ignored.json",
        ])
        .output()
        .expect("start verifier CLI");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown option --ffmpeg"), "{stderr}");
}

#[test]
fn candidate_artifact_cannot_be_treated_as_approved() {
    let candidate = valid_profile()
        .replace("status = \"approved\"", "status = \"candidate\"")
        .lines()
        .filter(|line| {
            !line.starts_with("approval_record_id") && !line.starts_with("approval_date")
        })
        .collect::<Vec<_>>()
        .join("\n");
    let (_temp, profile) = load(&candidate);

    assert!(profile.approved_artifact("windows-x86_64-8.1.1").is_err());
}

#[test]
fn checked_in_windows_profile_is_a_blocked_candidate_without_approval() {
    let profile_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("config/ffmpeg-profile.toml");
    let profile = BuildProfile::load(profile_path).expect("load checked-in profile");

    assert_eq!(profile.artifacts().len(), 1);
    assert_eq!(profile.artifacts()[0].status(), ArtifactStatus::Candidate);
    assert!(!profile.gate_is_approved());
    assert!(
        profile
            .approved_artifact("windows-x86_64-gyan-8.1.1-essentials")
            .is_err()
    );
}

#[test]
fn normalized_profile_digest_ignores_declared_list_order() {
    let (_first_temp, first) = load(&valid_profile());
    let reordered = valid_profile()
        .replace(
            "declared_codecs = [\"aac\", \"h264\"]",
            "declared_codecs = [\"h264\", \"aac\"]",
        )
        .replace(
            "protocol_whitelist = [\"file\", \"pipe\"]",
            "protocol_whitelist = [\"pipe\", \"file\"]",
        );
    let (_second_temp, second) = load(&reordered);

    assert_eq!(first.profile_digest(), second.profile_digest());
}
