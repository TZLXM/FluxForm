use std::fs;

use fluxform_ffmpeg_profile::{ArtifactStatus, BuildProfile, CapturedProbeOutputs, ProbeReport};
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
    let temp = tempfile::tempdir().expect("tempdir");
    let path = temp.path().join("profile.toml");
    fs::write(&path, text).expect("write profile");
    let profile = BuildProfile::load(&path).expect("load valid profile");
    (temp, profile)
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

    let mut changed = report.clone();
    changed.target_triple = "aarch64-apple-darwin".to_owned();
    assert!(changed.verify_identity(&approved).is_err());
    let mut changed = report.clone();
    changed.ffmpeg_sha256 =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_owned();
    assert!(changed.verify_identity(&approved).is_err());
    let mut changed = report.clone();
    changed.ffprobe_sha256 =
        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".to_owned();
    assert!(changed.verify_identity(&approved).is_err());
    let mut changed = report.clone();
    changed.profile_digest =
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_owned();
    assert!(changed.verify_identity(&approved).is_err());
    let mut changed = report;
    changed.approval_record_id = Some("TEST-OTHER-IDENTITY".to_owned());
    assert!(changed.verify_identity(&approved).is_err());
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
