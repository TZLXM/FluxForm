use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fluxform_capabilities::{
    CapabilityManifestV1, ConversionCategory, InputProbeV1, ManifestError, TargetTriple,
};
use fluxform_ffmpeg_profile::{ArtifactStatus, BuildProfile, CapturedProbeOutputs, ProbeReport};
use tempfile::TempDir;

const VALID_MANIFEST: &str = r#"manifest_version = "v1"

[[edges]]
id = "image.jpeg-to-png"
category = "image"
input_extensions = ["jpg", "jpeg"]
input_demuxers = ["image2"]
input_codecs = ["mjpeg"]
input_topology = "single_video_frame"
output_format = "png"
output_muxer = "image2"
video_codec = "png"
stream_map = ["0:v:0"]
alpha_policy = "preserve_if_present"
orientation_policy = "apply_to_pixels"
metadata_policy = "safe_image_metadata"
profile_ids = ["windows-x86_64", "macos-aarch64", "macos-x86_64", "linux-x86_64"]
valid_samples = ["jpeg-baseline-rgb"]
invalid_samples = ["jpeg-truncated", "jpeg-multi-stream"]

[edges.options.quality]
minimum = 0
maximum = 100
default = 90
"#;

const STAGE0_TARGETS: &[(&str, &str)] = &[
    ("windows-x86_64", "x86_64-pc-windows-msvc"),
    ("macos-aarch64", "aarch64-apple-darwin"),
    ("macos-x86_64", "x86_64-apple-darwin"),
    ("linux-x86_64", "x86_64-unknown-linux-gnu"),
];

fn profile_fixture() -> String {
    let mut profile = String::from(
        r#"profile_id = "test-only-capability-profile"
license_declaration = "GPL v3"
declared_codecs = ["mjpeg", "png"]
protocol_whitelist = ["file"]

[required]
muxers = []
demuxers = []
protocols = ["file"]
encoders = []
decoders = []
"#,
    );

    for (index, (profile_id, target)) in STAGE0_TARGETS.iter().enumerate() {
        let digit = char::from_digit(index as u32 + 10, 16).expect("hex fixture digit");
        let ffmpeg_hash = digit.to_string().repeat(64);
        let ffprobe_hash = char::from_digit(index as u32 + 1, 16)
            .expect("hex fixture digit")
            .to_string()
            .repeat(64);
        let artifact_hash = char::from_digit(index as u32 + 5, 16)
            .expect("hex fixture digit")
            .to_string()
            .repeat(64);
        profile.push_str(&format!(
            r#"
[[artifacts]]
artifact_id = "TEST-ONLY-{profile_id}"
status = "approved"
target_triple = "{target}"
archive_format = "zip32"
artifact_uri = "https://artifacts.example.invalid/{profile_id}.zip"
artifact_sha256 = "{artifact_hash}"
artifact_size_bytes = 1024
ffmpeg_sha256 = "{ffmpeg_hash}"
ffmpeg_size_bytes = 2048
ffprobe_sha256 = "{ffprobe_hash}"
ffprobe_size_bytes = 2048
license = "GPL v3"
license_text_path = "LICENSE.txt"
license_text_sha256 = "2222222222222222222222222222222222222222222222222222222222222222"
license_text_size_bytes = 64
source_revision = "test-only-source-revision"
source_offer_url = "https://artifacts.example.invalid/source"
approval_record_id = "TEST-ONLY-ARTIFACT-APPROVAL-{profile_id}"
approval_date = "2000-01-01"
"#
        ));
    }

    profile.push_str(
        r#"
[distribution_gate]
status = "approved"
required_target_triples = ["x86_64-pc-windows-msvc", "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-unknown-linux-gnu"]
owner_legal_approval_required = true
owner_approval_record_id = "TEST-ONLY-OWNER-APPROVAL"
owner_approval_date = "2000-01-01"
legal_approval_record_id = "TEST-ONLY-LEGAL-APPROVAL"
legal_approval_date = "2000-01-01"
"#,
    );
    profile
}

fn outputs() -> CapturedProbeOutputs {
    CapturedProbeOutputs {
        ffmpeg_version: "ffmpeg version 8.1.1-test\nconfiguration: --enable-gpl\n".to_owned(),
        ffprobe_version: "ffprobe version 8.1.1-test\nconfiguration: --enable-gpl\n".to_owned(),
        protocols: "Supported file protocols:\nInput:\n  file\nOutput:\n  file\n".to_owned(),
        demuxers: "Demuxers:\n D  image2          image2 sequence\n".to_owned(),
        muxers: "Muxers:\n E  image2          image2 sequence\n".to_owned(),
        decoders: "Decoders:\n V....D mjpeg          Motion JPEG\n".to_owned(),
        encoders: "Encoders:\n V..... png             PNG image\n".to_owned(),
    }
}

fn write_file(directory: &Path, filename: &str, contents: &str) -> std::path::PathBuf {
    let path = directory.join(filename);
    fs::write(&path, contents).expect("write fixture");
    path
}

fn load_fixture(
    manifest_text: &str,
) -> (
    TempDir,
    CapabilityManifestV1,
    BTreeMap<TargetTriple, ProbeReport>,
) {
    let temporary = tempfile::tempdir().expect("temporary fixture directory");
    let manifest_path = write_file(temporary.path(), "capabilities-v1.toml", manifest_text);
    write_file(temporary.path(), "ffmpeg-profile.toml", &profile_fixture());
    let manifest = CapabilityManifestV1::load(&manifest_path).expect("valid manifest fixture");
    let profile_path = temporary.path().join("ffmpeg-profile.toml");
    let profile = BuildProfile::load(&profile_path).expect("synthetic approved test profile");
    let reports = profile
        .artifacts()
        .iter()
        .map(|artifact| {
            let report = ProbeReport::from_captured(&profile, artifact, outputs())
                .expect("synthetic probe report");
            (report.target_triple.clone(), report)
        })
        .collect();
    (temporary, manifest, reports)
}

fn assert_manifest_rejected(manifest_text: &str) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let manifest_path = write_file(temporary.path(), "capabilities-v1.toml", manifest_text);
    assert!(
        CapabilityManifestV1::load(manifest_path).is_err(),
        "manifest should have been rejected:\n{manifest_text}"
    );
}

fn mutate_report(
    reports: &BTreeMap<TargetTriple, ProbeReport>,
    target: &str,
    mutate: impl FnOnce(&mut ProbeReport),
) -> BTreeMap<TargetTriple, ProbeReport> {
    let mut changed = reports.clone();
    mutate(changed.get_mut(target).expect("target report"));
    changed
}

fn assert_identity_mutation_is_rejected(
    manifest: &CapabilityManifestV1,
    reports: &BTreeMap<TargetTriple, ProbeReport>,
    identity: &str,
    mutate: impl FnOnce(&mut ProbeReport),
) {
    let changed = mutate_report(reports, "x86_64-pc-windows-msvc", mutate);
    assert!(
        manifest.validate_profiles(&changed).is_err(),
        "substituted {identity} must be rejected with unchanged capability lists"
    );
}

#[test]
fn complete_manifest_matches_only_a_fully_probed_directed_edge() {
    let (_temporary, manifest, reports) = load_fixture(VALID_MANIFEST);
    manifest
        .validate_profiles(&reports)
        .expect("all four synthetic test reports match their test-only approval rows");

    let edge = manifest
        .find_edge(
            ConversionCategory::Image,
            &InputProbeV1 {
                extension: ".JPEG".to_owned(),
                demuxer: "image2".to_owned(),
                codec: "mjpeg".to_owned(),
                topology: "single_video_frame".to_owned(),
            },
            "png",
        )
        .expect("fully matching directed edge");
    assert_eq!(edge.id, "image.jpeg-to-png");
    assert_eq!(edge.input_extensions, ["jpg", "jpeg"]);
    assert!(
        manifest
            .find_edge(
                ConversionCategory::Image,
                &InputProbeV1 {
                    extension: "jpeg".to_owned(),
                    demuxer: "image2".to_owned(),
                    codec: "png".to_owned(),
                    topology: "single_video_frame".to_owned(),
                },
                "png",
            )
            .is_none()
    );
}

#[test]
fn rejects_duplicate_edge_ids_and_wildcard_or_extension_only_matching() {
    let duplicate = format!(
        "{VALID_MANIFEST}\n{}",
        &VALID_MANIFEST[VALID_MANIFEST.find("[[edges]]").unwrap()..]
    );
    assert_manifest_rejected(&duplicate);

    assert_manifest_rejected(
        &VALID_MANIFEST.replace("input_codecs = [\"mjpeg\"]", "input_codecs = [\"*\"]"),
    );

    let extension_only = VALID_MANIFEST
        .replace("input_demuxers = [\"image2\"]", "input_demuxers = []")
        .replace("input_codecs = [\"mjpeg\"]", "input_codecs = []");
    assert_manifest_rejected(&extension_only);
}

#[test]
fn rejects_multiple_demuxers_that_would_create_input_cross_products() {
    assert_manifest_rejected(&VALID_MANIFEST.replace(
        "input_demuxers = [\"image2\"]",
        "input_demuxers = [\"image2\", \"rawvideo\"]",
    ));
}

#[test]
fn rejects_multiple_codecs_that_would_create_input_cross_products() {
    assert_manifest_rejected(&VALID_MANIFEST.replace(
        "input_codecs = [\"mjpeg\"]",
        "input_codecs = [\"mjpeg\", \"png\"]",
    ));
}

#[test]
fn rejects_wildcards_in_demuxer_selectors() {
    assert_manifest_rejected(
        &VALID_MANIFEST.replace("input_demuxers = [\"image2\"]", "input_demuxers = [\"*\"]"),
    );
}

#[test]
fn rejects_wildcards_in_output_format_selectors() {
    assert_manifest_rejected(
        &VALID_MANIFEST.replace("output_format = \"png\"", "output_format = \"?\""),
    );
}

#[test]
fn rejects_empty_toml_array_elements() {
    assert_manifest_rejected(&VALID_MANIFEST.replace(
        "input_extensions = [\"jpg\", \"jpeg\"]",
        "input_extensions = [\"jpg\",, \"jpeg\"]",
    ));
}

#[test]
fn rejects_json_null_as_a_toml_value() {
    assert_manifest_rejected(&VALID_MANIFEST.replace(
        "video_codec = \"png\"",
        "video_codec = \"png\"\naudio_codec = null",
    ));
}

#[test]
fn rejects_json_only_escape_in_toml_string() {
    assert_manifest_rejected(&VALID_MANIFEST.replace("image.jpeg-to-png", r#"image\/jpeg-to-png"#));
}

#[test]
fn rejects_lone_high_surrogate_escape() {
    assert_manifest_rejected(
        &VALID_MANIFEST.replace("image.jpeg-to-png", r#"image.\uD83D-to-png"#),
    );
}

#[test]
fn rejects_lone_low_surrogate_escape() {
    assert_manifest_rejected(
        &VALID_MANIFEST.replace("image.jpeg-to-png", r#"image.\uDE00-to-png"#),
    );
}

#[test]
fn rejects_surrogate_pair_escapes() {
    assert_manifest_rejected(
        &VALID_MANIFEST.replace("image.jpeg-to-png", r#"image.\uD83D\uDE00-to-png"#),
    );
}

#[test]
fn accepts_unicode_scalar_escape() {
    let manifest_text = VALID_MANIFEST.replace("image.jpeg-to-png", r#"image.\u00E9-to-png"#);
    let (_temporary, manifest, _) = load_fixture(&manifest_text);
    let edge = manifest
        .find_edge(
            ConversionCategory::Image,
            &InputProbeV1 {
                extension: "jpeg".to_owned(),
                demuxer: "image2".to_owned(),
                codec: "mjpeg".to_owned(),
                topology: "single_video_frame".to_owned(),
            },
            "png",
        )
        .expect("manifest with valid Unicode scalar escape loads");
    assert_eq!(edge.id, "image.é-to-png");
}

#[test]
fn rejects_missing_bounds_stream_mapping_policies_and_sample_ids() {
    for (field, replacement) in [
        ("minimum = 0\n", ""),
        ("maximum = 100\n", ""),
        ("default = 90\n", ""),
        ("stream_map = [\"0:v:0\"]\n", ""),
        ("alpha_policy = \"preserve_if_present\"\n", ""),
        ("orientation_policy = \"apply_to_pixels\"\n", ""),
        ("metadata_policy = \"safe_image_metadata\"\n", ""),
        ("valid_samples = [\"jpeg-baseline-rgb\"]\n", ""),
        (
            "invalid_samples = [\"jpeg-truncated\", \"jpeg-multi-stream\"]\n",
            "",
        ),
    ] {
        let changed = VALID_MANIFEST.replacen(field, replacement, 1);
        assert_ne!(
            changed, VALID_MANIFEST,
            "fixture field should exist: {field}"
        );
        assert_manifest_rejected(&changed);
    }
}

#[test]
fn rejects_unknown_fields_and_non_exact_policy_values_at_every_schema_level() {
    let unknown_edge = VALID_MANIFEST.replace(
        "id = \"image.jpeg-to-png\"",
        "id = \"image.jpeg-to-png\"\nexperimental = true",
    );
    assert_manifest_rejected(&unknown_edge);

    let unknown_parameter = VALID_MANIFEST.replace("default = 90", "default = 90\nextra = 1");
    assert_manifest_rejected(&unknown_parameter);

    let unknown_root = VALID_MANIFEST.replace(
        "manifest_version = \"v1\"",
        "manifest_version = \"v1\"\nextra = true",
    );
    assert_manifest_rejected(&unknown_root);

    assert_manifest_rejected(&VALID_MANIFEST.replace(
        "alpha_policy = \"preserve_if_present\"",
        "alpha_policy = \"preserve\"",
    ));
}

#[test]
fn rejects_absent_input_decoder_or_demuxer_from_a_bound_platform_profile() {
    let (_temporary, manifest, reports) = load_fixture(VALID_MANIFEST);
    let no_decoder = mutate_report(&reports, "x86_64-pc-windows-msvc", |report| {
        report.decoders.clear();
    });
    assert!(manifest.validate_profiles(&no_decoder).is_err());

    let no_demuxer = mutate_report(&reports, "x86_64-pc-windows-msvc", |report| {
        report.demuxers.clear();
    });
    assert!(manifest.validate_profiles(&no_demuxer).is_err());
}

#[test]
fn rejects_output_codec_or_muxer_missing_from_any_bound_platform_profile() {
    let (_temporary, manifest, reports) = load_fixture(VALID_MANIFEST);
    let no_encoder = mutate_report(&reports, "x86_64-pc-windows-msvc", |report| {
        report.encoders.clear();
    });
    assert!(manifest.validate_profiles(&no_encoder).is_err());

    let no_muxer = mutate_report(&reports, "x86_64-pc-windows-msvc", |report| {
        report.muxers.clear();
    });
    assert!(manifest.validate_profiles(&no_muxer).is_err());

    let mut missing_report = reports.clone();
    missing_report.remove("x86_64-pc-windows-msvc");
    assert!(manifest.validate_profiles(&missing_report).is_err());
}

#[test]
fn rejects_substituted_executable_target_profile_or_approval_identity() {
    let (_temporary, manifest, reports) = load_fixture(VALID_MANIFEST);
    assert_identity_mutation_is_rejected(&manifest, &reports, "executable hash", |report| {
        report.ffmpeg_sha256 = "f".repeat(64);
    });
    assert_identity_mutation_is_rejected(&manifest, &reports, "target triple", |report| {
        report.target_triple = "aarch64-apple-darwin".to_owned();
    });
    assert_identity_mutation_is_rejected(&manifest, &reports, "profile digest", |report| {
        report.profile_digest = "f".repeat(64);
    });
    assert_identity_mutation_is_rejected(
        &manifest,
        &reports,
        "artifact approval status",
        |report| report.artifact_status = ArtifactStatus::Candidate,
    );
    assert_identity_mutation_is_rejected(&manifest, &reports, "approval ID", |report| {
        report.approval_record_id = Some("SUBSTITUTED-TEST-ID".to_owned());
    });
    assert_identity_mutation_is_rejected(&manifest, &reports, "approval date", |report| {
        report.approval_date = Some("2001-01-01".to_owned());
    });
}

#[test]
fn checked_in_distribution_profile_keeps_manifest_validation_blocked() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let manifest_path = write_file(temporary.path(), "capabilities-v1.toml", VALID_MANIFEST);
    write_file(
        temporary.path(),
        "ffmpeg-profile.toml",
        include_str!("../../../config/ffmpeg-profile.toml"),
    );
    let manifest = CapabilityManifestV1::load(manifest_path).expect("valid manifest fixture");

    assert!(matches!(
        manifest.validate_profiles(&BTreeMap::new()),
        Err(ManifestError::DistributionGateBlocked)
    ));
}

#[test]
fn extension_normalization_does_not_turn_unknown_extensions_into_matches() {
    let normalized = VALID_MANIFEST.replace(
        "input_extensions = [\"jpg\", \"jpeg\"]",
        "input_extensions = [\".JPG\", \"JPEG\"]",
    );
    let (_temporary, manifest, _reports) = load_fixture(&normalized);
    let edge = manifest
        .find_edge(
            ConversionCategory::Image,
            &InputProbeV1 {
                extension: "jpeg".to_owned(),
                demuxer: "image2".to_owned(),
                codec: "mjpeg".to_owned(),
                topology: "single_video_frame".to_owned(),
            },
            "png",
        )
        .expect("normalized extension matches");
    assert_eq!(edge.input_extensions, ["jpg", "jpeg"]);
    assert!(
        manifest
            .find_edge(
                ConversionCategory::Image,
                &InputProbeV1 {
                    extension: "gif".to_owned(),
                    demuxer: "image2".to_owned(),
                    codec: "mjpeg".to_owned(),
                    topology: "single_video_frame".to_owned(),
                },
                "png",
            )
            .is_none()
    );
}
