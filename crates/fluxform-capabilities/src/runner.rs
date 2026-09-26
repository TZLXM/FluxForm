use crate::evidence::compute_evidence_input_digest;
use crate::samples::{SampleCatalogV1, SampleRecordV1};
use crate::{
    AlphaPolicy, CapabilityManifestV1, ConversionCategory, ConversionEdgeV1, InputTopology,
    MetadataPolicy, OrientationPolicy, ParameterBounds,
};
use fluxform_ffmpeg_profile::{BuildProfile, ProbeReport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub const RUN_REPORT_SCHEMA_V1: &str = "fluxform.sample-run.v1";
const ANIMATED_SAMPLE_IDS: &[&str] = &[
    "image-gif-animated-v1",
    "image-webp-animated-v1",
    "image-tiff-multipage-v1",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleRunReportV1 {
    pub schema: String,
    pub status: String,
    pub evidence_input_digest: String,
    pub manifest_digest: String,
    pub sample_catalog_digest: String,
    pub git_commit: String,
    pub runner_os: String,
    pub runner_arch: String,
    pub profile_id: String,
    pub target_profile_id: String,
    pub target_triple: String,
    pub artifact_id: String,
    pub profile_digest: String,
    pub ffmpeg_sha256: String,
    pub ffprobe_sha256: String,
    pub blockers: Vec<String>,
    pub results: Vec<SampleResultV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleResultV1 {
    pub edge_id: String,
    pub edge_spec_digest: String,
    pub sample_id: String,
    pub sample_sha256: String,
    pub expected_outcome: String,
    pub expected_error_code: String,
    pub status: String,
    pub actual_error_code: String,
    pub diagnostic: String,
    pub ffprobe_arguments: Vec<String>,
    pub ffmpeg_arguments: Vec<String>,
    pub ffmpeg_invoked: bool,
    pub output_expectations: OutputExpectationsV1,
    pub output_expectations_digest: String,
    pub observed_input: Option<ObservedMediaV1>,
    pub observed_output: Option<ObservedMediaV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutputExpectationsV1 {
    pub container: String,
    pub codecs: Vec<String>,
    pub stream_topology: String,
    pub width: u32,
    pub height: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub max_duration_ms: u64,
    pub alpha_policy: String,
    pub orientation_policy: String,
    pub metadata_policy: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedMediaV1 {
    pub format_name: String,
    pub codecs: Vec<String>,
    pub stream_topology: String,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub alpha_present: bool,
    pub orientation_present: bool,
    pub metadata_keys: Vec<String>,
    pub frame_count: u64,
}

pub struct RunSampleOptions<'a> {
    pub repository_root: &'a Path,
    pub manifest_path: &'a Path,
    pub samples_path: &'a Path,
    pub profile_report_path: &'a Path,
    pub ffmpeg_path: &'a Path,
    pub ffprobe_path: &'a Path,
}

pub fn edge_specification_digest(edge: &ConversionEdgeV1) -> Result<String, String> {
    let bytes = serde_json::to_vec(edge)
        .map_err(|error| format!("could not normalize edge {}: {error}", edge.id))?;
    Ok(sha256(&bytes))
}

pub fn output_expectations_digest(expectations: &OutputExpectationsV1) -> Result<String, String> {
    let bytes = serde_json::to_vec(expectations)
        .map_err(|error| format!("could not normalize output expectations: {error}"))?;
    Ok(sha256(&bytes))
}

pub fn build_ffmpeg_arguments(edge: &ConversionEdgeV1, input: &str, output: &str) -> Vec<String> {
    let mut arguments = vec![
        "-hide_banner".to_owned(),
        "-nostdin".to_owned(),
        "-v".to_owned(),
        "error".to_owned(),
        "-y".to_owned(),
    ];
    if edge.category != ConversionCategory::Audio {
        arguments.push(match edge.orientation_policy {
            OrientationPolicy::ApplyToPixels => "-autorotate".to_owned(),
            OrientationPolicy::PreserveTag | OrientationPolicy::Ignore => {
                "-noautorotate".to_owned()
            }
        });
    }
    arguments.extend(["-i".to_owned(), input.to_owned()]);
    for mapping in &edge.stream_map {
        arguments.extend(["-map".to_owned(), mapping.clone()]);
    }
    if edge.category == ConversionCategory::Image {
        arguments.extend(["-frames:v".to_owned(), "1".to_owned()]);
    }
    arguments.extend([
        "-map_metadata".to_owned(),
        match edge.metadata_policy {
            MetadataPolicy::Preserve => "0",
            MetadataPolicy::Strip | MetadataPolicy::SafeImageMetadata => "-1",
        }
        .to_owned(),
    ]);
    if let Some(codec) = &edge.video_codec {
        arguments.extend(["-c:v".to_owned(), codec.clone()]);
        if edge.category == ConversionCategory::Video
            && let Some(bounds) = edge.options.get("crf")
        {
            arguments.extend(["-crf".to_owned(), bounds.default.to_string()]);
        }
        if edge.category == ConversionCategory::Image
            && let Some(bounds) = edge.options.get("compression_level")
        {
            arguments.extend(["-compression_level".to_owned(), bounds.default.to_string()]);
        }
    }
    if let Some(codec) = &edge.audio_codec {
        arguments.extend(["-c:a".to_owned(), codec.clone()]);
        if let Some(bounds) = edge.options.get("bitrate_kbps") {
            arguments.extend(["-b:a".to_owned(), format!("{}k", bounds.default)]);
        }
    }
    match edge.category {
        ConversionCategory::Video | ConversionCategory::Image => arguments.push("-an".to_owned()),
        ConversionCategory::Audio => arguments.push("-vn".to_owned()),
    }
    arguments.extend([
        "-f".to_owned(),
        edge.output_muxer.clone(),
        output.to_owned(),
    ]);
    arguments
}

pub fn expected_output(edge: &ConversionEdgeV1, sample: &SampleRecordV1) -> OutputExpectationsV1 {
    let mut codecs = Vec::new();
    if let Some(codec) = &edge.video_codec {
        codecs.push(output_codec_name(codec));
    }
    if let Some(codec) = &edge.audio_codec {
        codecs.push(output_codec_name(codec));
    }
    let width_bound = default_option(&edge.options, "max_width", 4096) as u32;
    let height_bound = default_option(&edge.options, "max_height", 4096) as u32;
    let duration_bound =
        (default_option(&edge.options, "max_duration_seconds", 3600) as u64).saturating_mul(1000);
    OutputExpectationsV1 {
        container: edge.output_format.clone(),
        codecs,
        stream_topology: topology_for_category(edge.category).to_owned(),
        width: sample.width,
        height: sample.height,
        max_width: width_bound,
        max_height: height_bound,
        max_duration_ms: duration_bound.min(sample.duration_ms.saturating_add(1500).max(1000)),
        alpha_policy: policy_name(edge.alpha_policy).to_owned(),
        orientation_policy: orientation_name(edge.orientation_policy).to_owned(),
        metadata_policy: metadata_name(edge.metadata_policy).to_owned(),
    }
}

pub fn run_manifest_samples(options: RunSampleOptions<'_>) -> Result<SampleRunReportV1, String> {
    let root = options
        .repository_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let manifest_path = resolve_path(&root, options.manifest_path);
    let samples_path = resolve_path(&root, options.samples_path);
    let profile_path = root.join("config/ffmpeg-profile.toml");
    let profile_report_path = resolve_path(&root, options.profile_report_path);
    let ffmpeg_path = resolve_path(&root, options.ffmpeg_path);
    let ffprobe_path = resolve_path(&root, options.ffprobe_path);

    let manifest = CapabilityManifestV1::load(&manifest_path).map_err(|error| error.to_string())?;
    let catalog = SampleCatalogV1::load(&samples_path).map_err(|error| error.to_string())?;
    catalog
        .validate_manifest_samples(&manifest)
        .map_err(|error| error.to_string())?;
    let evidence = compute_evidence_input_digest(&root).map_err(|error| error.to_string())?;
    let manifest_digest = digest_file(&manifest_path)?;
    let sample_catalog_digest = digest_file(&samples_path)?;
    let git_commit = current_git_commit(&root)?;
    let profile_bytes = fs::read(&profile_report_path).map_err(|error| {
        format!("BLOCKED: required native FFmpeg profile report is missing or unreadable: {error}")
    })?;
    let profile_value: Value = serde_json::from_slice(&profile_bytes)
        .map_err(|error| format!("BLOCKED: profile report JSON is invalid: {error}"))?;
    let parsed_probe_report = serde_json::from_value::<ProbeReport>(profile_value.clone());
    let schema_error = parsed_probe_report.as_ref().err().map(ToString::to_string);
    let probe_report = parsed_probe_report.ok();
    let profile_report_value = |key: &str| {
        profile_value[key]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| "unverified".to_owned())
    };
    let target_triple = profile_report_value("target_triple");
    let target_profile_id = profile_id_for_triple(&target_triple);
    let artifact_status = profile_report_value("artifact_status");
    let distribution_gate_status = profile_report_value("distribution_gate_status");
    let profile_id = profile_report_value("profile_id");
    let profile_digest = profile_report_value("profile_digest");
    let artifact_id = profile_report_value("artifact_id");
    let ffmpeg_sha256 = profile_report_value("ffmpeg_sha256");
    let ffprobe_sha256 = profile_report_value("ffprobe_sha256");
    let profile = BuildProfile::load(&profile_path).map_err(|error| error.to_string())?;

    let mut blockers = Vec::new();
    if let Some(error) = schema_error {
        blockers.push(format!(
            "profile report does not match the Task 3 ProbeReport schema: {error}"
        ));
    }
    if !profile.gate_is_approved() || distribution_gate_status != "approved" {
        blockers.push("FFmpeg redistribution/legal distribution gate is not approved".to_owned());
    }
    if artifact_status != "approved" {
        blockers.push("profile report does not identify an approved artifact row".to_owned());
    }
    if profile_id != profile.profile_id() || profile_digest != profile.profile_digest() {
        blockers.push(
            "profile report identity is stale or does not match the checked-in profile".to_owned(),
        );
    }
    if target_profile_id == "unknown" {
        blockers.push(format!("unsupported native target triple {target_triple}"));
    }
    if profile.gate_is_approved() {
        if let Some(probe_report) = &probe_report {
            match profile
                .approved_artifact(&probe_report.artifact_id)
                .and_then(|approved| probe_report.verify_identity(&approved))
            {
                Ok(()) => {}
                Err(error) => {
                    blockers.push(format!("profile report identity is not approved: {error}"))
                }
            }
            if let Err(error) = verify_executable_identity(
                &ffmpeg_path,
                &probe_report.ffmpeg_sha256,
                probe_report.ffmpeg_size_bytes,
            ) {
                blockers.push(format!("FFmpeg executable identity mismatch: {error}"));
            }
            if let Err(error) = verify_executable_identity(
                &ffprobe_path,
                &probe_report.ffprobe_sha256,
                probe_report.ffprobe_size_bytes,
            ) {
                blockers.push(format!("FFprobe executable identity mismatch: {error}"));
            }
        } else {
            blockers
                .push("profile report cannot be bound to an approved artifact identity".to_owned());
        }
    }
    if !target_matches_runner(&target_triple) {
        blockers.push("profile report target is not the native runner OS/architecture".to_owned());
    }
    if manifest
        .edges()
        .iter()
        .any(|edge| !edge.profile_ids.iter().any(|id| id == target_profile_id))
    {
        blockers.push(format!(
            "manifest does not bind all edges to native profile {target_profile_id}"
        ));
    }

    let mut results = Vec::new();
    for edge in manifest.edges() {
        for sample_id in edge.valid_samples.iter().chain(&edge.invalid_samples) {
            let sample = catalog
                .find(sample_id)
                .ok_or_else(|| format!("sample {sample_id} is absent from catalog"))?;
            results.push(build_result(edge, sample, &root, target_profile_id)?);
        }
    }
    if blockers.is_empty() {
        for result in &mut results {
            let edge = manifest
                .edges()
                .iter()
                .find(|edge| edge.id == result.edge_id)
                .ok_or_else(|| "edge disappeared during run".to_owned())?;
            let sample = catalog
                .find(&result.sample_id)
                .ok_or_else(|| "sample disappeared during run".to_owned())?;
            let (status, error_code, diagnostic, invoked, observed_input, observed_output) =
                execute_one(
                    edge,
                    sample,
                    &root,
                    &ffmpeg_path,
                    &ffprobe_path,
                    &result.ffmpeg_arguments,
                    &result.ffprobe_arguments,
                );
            result.status = status.to_owned();
            result.actual_error_code = error_code.to_owned();
            result.diagnostic = diagnostic.to_owned();
            result.ffmpeg_invoked = invoked;
            result.observed_input = observed_input;
            result.observed_output = observed_output;
        }
    }
    results.sort_by(|left, right| {
        (&left.edge_id, &left.sample_id).cmp(&(&right.edge_id, &right.sample_id))
    });
    let status = if !blockers.is_empty() {
        "blocked"
    } else if results.iter().any(|result| result.status != "passed") {
        "failed"
    } else {
        "passed"
    };
    Ok(SampleRunReportV1 {
        schema: RUN_REPORT_SCHEMA_V1.to_owned(),
        status: status.to_owned(),
        evidence_input_digest: evidence.digest,
        manifest_digest,
        sample_catalog_digest,
        git_commit,
        runner_os: std::env::consts::OS.to_owned(),
        runner_arch: std::env::consts::ARCH.to_owned(),
        profile_id,
        target_profile_id: target_profile_id.to_owned(),
        target_triple,
        artifact_id,
        profile_digest,
        ffmpeg_sha256,
        ffprobe_sha256,
        blockers,
        results,
    })
}

pub fn validate_run_report_inputs(
    report: &SampleRunReportV1,
    manifest: &CapabilityManifestV1,
    catalog: &SampleCatalogV1,
    repository_root: &Path,
) -> Result<(), String> {
    if report.schema != RUN_REPORT_SCHEMA_V1
        || report.status != "passed"
        || !report.blockers.is_empty()
    {
        return Err("BLOCKED: sample report is not a passing native report".to_owned());
    }
    let mut expected = BTreeSet::new();
    for edge in manifest.edges() {
        for sample_id in edge.valid_samples.iter().chain(&edge.invalid_samples) {
            expected.insert((edge.id.as_str(), sample_id.as_str()));
        }
    }
    let actual = report
        .results
        .iter()
        .map(|result| (result.edge_id.as_str(), result.sample_id.as_str()))
        .collect::<BTreeSet<_>>();
    let ordered = report
        .results
        .iter()
        .map(|result| (result.edge_id.as_str(), result.sample_id.as_str()))
        .collect::<Vec<_>>();
    if actual != expected
        || report.results.len() != expected.len()
        || !ordered.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err(
            "BLOCKED: sample report result set does not equal the manifest/sample cross-product"
                .to_owned(),
        );
    }
    for result in &report.results {
        let edge = manifest
            .edges()
            .iter()
            .find(|edge| edge.id == result.edge_id)
            .ok_or_else(|| "report contains an unknown edge".to_owned())?;
        let sample = catalog
            .find(&result.sample_id)
            .ok_or_else(|| "report contains an unknown sample".to_owned())?;
        if result.status != "passed"
            || result.edge_spec_digest != edge_specification_digest(edge)?
            || result.sample_sha256 != sample.sha256
            || result.expected_outcome != sample.expected_outcome
            || result.expected_error_code != sample.expected_error_code
            || result.output_expectations != expected_output(edge, sample)
            || result.output_expectations_digest
                != output_expectations_digest(&expected_output(edge, sample))?
            || (sample.expected_outcome == "success"
                && (!result.actual_error_code.is_empty()
                    || !result.ffmpeg_invoked
                    || result.observed_output.is_none()))
            || (sample.expected_outcome == "error"
                && (result.actual_error_code != sample.expected_error_code
                    || result.ffmpeg_invoked
                    || result.observed_output.is_some()))
            || result.observed_input.is_none()
        {
            return Err(format!(
                "BLOCKED: stale or mismatched result for {} / {}",
                edge.id, sample.id
            ));
        }
        let input = root_relative_path(
            repository_root,
            &catalog
                .sample_path(&sample.id)
                .ok_or_else(|| "sample path is unavailable".to_owned())?,
        )?;
        let output = output_path(&report.target_profile_id, edge, sample);
        if result.ffprobe_arguments != ffprobe_arguments(&input)
            || result.ffmpeg_arguments != build_ffmpeg_arguments(edge, &input, &output)
        {
            return Err(format!(
                "BLOCKED: stale argument vector for {} / {}",
                edge.id, sample.id
            ));
        }
    }
    Ok(())
}

fn build_result(
    edge: &ConversionEdgeV1,
    sample: &SampleRecordV1,
    root: &Path,
    target_profile_id: &str,
) -> Result<SampleResultV1, String> {
    let input = root_relative_path(root, &root.join("testdata/media/v1").join(&sample.path))?;
    let output = output_path(target_profile_id, edge, sample);
    let expectations = expected_output(edge, sample);
    Ok(SampleResultV1 {
        edge_id: edge.id.clone(),
        edge_spec_digest: edge_specification_digest(edge)?,
        sample_id: sample.id.clone(),
        sample_sha256: sample.sha256.clone(),
        expected_outcome: sample.expected_outcome.clone(),
        expected_error_code: sample.expected_error_code.clone(),
        status: "blocked".to_owned(),
        actual_error_code: String::new(),
        diagnostic: "not_run_blocked".to_owned(),
        ffprobe_arguments: ffprobe_arguments(&input),
        ffmpeg_arguments: build_ffmpeg_arguments(edge, &input, &output),
        ffmpeg_invoked: false,
        output_expectations_digest: output_expectations_digest(&expectations)?,
        output_expectations: expectations,
        observed_input: None,
        observed_output: None,
    })
}

fn execute_one(
    edge: &ConversionEdgeV1,
    sample: &SampleRecordV1,
    root: &Path,
    ffmpeg: &Path,
    ffprobe: &Path,
    ffmpeg_args: &[String],
    ffprobe_args: &[String],
) -> (
    &'static str,
    &'static str,
    String,
    bool,
    Option<ObservedMediaV1>,
    Option<ObservedMediaV1>,
) {
    let input_path = root.join("testdata/media/v1").join(&sample.path);
    let input_probe = match execute_probe(ffprobe, root, ffprobe_args) {
        Ok(probe) => probe,
        Err(error) => return ("failed", "ffprobe_failed", error, false, None, None),
    };
    let mut observed_input = match observed_media(&input_probe) {
        Ok(observed) => observed,
        Err(error) => {
            return (
                "failed",
                "sample_validation_failed",
                error,
                false,
                None,
                None,
            );
        }
    };
    if let Err(error) = augment_multiframe_observation(sample, &input_path, &mut observed_input) {
        return (
            "failed",
            "sample_validation_failed",
            error,
            false,
            Some(observed_input),
            None,
        );
    }
    if let Err(error) = validate_sample_input(sample, edge, &observed_input) {
        return (
            "failed",
            "sample_validation_failed",
            error,
            false,
            Some(observed_input),
            None,
        );
    }
    if sample.expected_outcome == "error" {
        let actual_error = classify_invalid_sample(sample, edge, &input_path, &observed_input);
        match actual_error {
            Ok(code) if code == sample.expected_error_code => {
                let stable_code = stable_error_code(&code).unwrap_or("sample_validation_failed");
                return (
                    "passed",
                    stable_code,
                    "stable invalid-input policy matched".to_owned(),
                    false,
                    Some(observed_input),
                    None,
                );
            }
            Ok(code) => {
                return (
                    "failed",
                    "error_code_mismatch",
                    format!("expected {}, observed {code}", sample.expected_error_code),
                    false,
                    Some(observed_input),
                    None,
                );
            }
            Err(error) => {
                return (
                    "failed",
                    "sample_validation_failed",
                    error,
                    false,
                    Some(observed_input),
                    None,
                );
            }
        }
    }
    let output_arg = match ffmpeg_args.last() {
        Some(path) => root.join(path),
        None => {
            return (
                "failed",
                "runner_arguments_invalid",
                "FFmpeg argument vector has no output path".to_owned(),
                false,
                Some(observed_input),
                None,
            );
        }
    };
    if let Some(parent) = output_arg.parent()
        && let Err(error) = fs::create_dir_all(parent)
    {
        return (
            "failed",
            "output_create_failed",
            error.to_string(),
            false,
            Some(observed_input),
            None,
        );
    }
    let output = match Command::new(ffmpeg)
        .current_dir(root)
        .args(ffmpeg_args)
        .output()
    {
        Ok(output) => output,
        Err(error) => {
            return (
                "failed",
                "ffmpeg_spawn_failed",
                error.to_string(),
                true,
                Some(observed_input),
                None,
            );
        }
    };
    if !output.status.success() {
        return (
            "failed",
            "ffmpeg_conversion_failed",
            format!("FFmpeg exited {}", output.status),
            true,
            Some(observed_input),
            None,
        );
    }
    let output_probe_args =
        ffprobe_arguments(&root_relative_path(root, &output_arg).unwrap_or_default());
    let output_probe = match execute_probe(ffprobe, root, &output_probe_args) {
        Ok(probe) => probe,
        Err(error) => {
            return (
                "failed",
                "ffprobe_output_failed",
                error,
                true,
                Some(observed_input),
                None,
            );
        }
    };
    let observed_output = match observed_media(&output_probe) {
        Ok(observed) => observed,
        Err(error) => {
            return (
                "failed",
                "output_validation_failed",
                error,
                true,
                Some(observed_input),
                None,
            );
        }
    };
    let expectations = expected_output(edge, sample);
    if let Err(error) = validate_output(&expectations, &observed_output, sample) {
        return (
            "failed",
            "output_validation_failed",
            error,
            true,
            Some(observed_input),
            Some(observed_output),
        );
    }
    (
        "passed",
        "",
        "conversion and output validation passed".to_owned(),
        true,
        Some(observed_input),
        Some(observed_output),
    )
}

fn execute_probe(ffprobe: &Path, root: &Path, arguments: &[String]) -> Result<Value, String> {
    let output = Command::new(ffprobe)
        .current_dir(root)
        .args(arguments)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(format!("FFprobe exited {}", output.status));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| format!("FFprobe output is invalid JSON: {error}"))
}

fn validate_sample_input(
    sample: &SampleRecordV1,
    edge: &ConversionEdgeV1,
    observed: &ObservedMediaV1,
) -> Result<(), String> {
    if !container_matches(&sample.container, &observed.format_name) {
        return Err(format!(
            "sample container mismatch: expected {}, observed {}",
            sample.container, observed.format_name
        ));
    }
    if !ANIMATED_SAMPLE_IDS.contains(&sample.id.as_str())
        && !edge
            .input_demuxers
            .iter()
            .any(|demuxer| format_matches_demuxer(demuxer, &observed.format_name))
    {
        return Err(format!(
            "sample demuxer mismatch: expected {:?}, observed {}",
            edge.input_demuxers, observed.format_name
        ));
    }
    for codec in &sample.codecs {
        if !(observed
            .codecs
            .iter()
            .any(|actual| actual.eq_ignore_ascii_case(codec))
            || (sample.id == "image-webp-animated-v1" && observed.codecs.is_empty()))
        {
            return Err(format!(
                "sample codec mismatch: expected {codec}, observed {:?}",
                observed.codecs
            ));
        }
    }
    if sample.expected_outcome == "success" {
        let expected_topology = topology_for_input(edge.input_topology);
        if observed.stream_topology != expected_topology
            || observed.width != sample.width
            || observed.height != sample.height
        {
            return Err(format!(
                "sample topology or dimensions mismatch: observed {} {}x{}",
                observed.stream_topology, observed.width, observed.height
            ));
        }
    }
    Ok(())
}

fn classify_invalid_sample(
    sample: &SampleRecordV1,
    edge: &ConversionEdgeV1,
    input_path: &Path,
    observed: &ObservedMediaV1,
) -> Result<String, String> {
    match sample.expected_error_code.as_str() {
        "unsupported_input" => {
            if sample.codecs.iter().any(|codec| {
                !edge
                    .input_codecs
                    .iter()
                    .any(|supported| supported.eq_ignore_ascii_case(codec))
            }) {
                Ok("unsupported_input".to_owned())
            } else {
                Err("unsupported_input sample still uses a manifest-supported codec".to_owned())
            }
        }
        "invalid_input" => {
            if sample.container == "jpeg" {
                let bytes = fs::read(input_path).map_err(|error| error.to_string())?;
                let has_end_marker = bytes.ends_with(&[0xff, 0xd9]);
                if !has_end_marker || observed.width == 0 || observed.height == 0 {
                    Ok("invalid_input".to_owned())
                } else {
                    Err(
                        "truncated JPEG is still structurally decodable and has its EOI marker"
                            .to_owned(),
                    )
                }
            } else {
                Err("no v1 invalid-input classifier exists for this sample".to_owned())
            }
        }
        "unsupported_conversion" => {
            let actual = observed.frame_count >= 2;
            if ANIMATED_SAMPLE_IDS.contains(&sample.id.as_str()) && actual {
                Ok("unsupported_conversion".to_owned())
            } else {
                Err(
                    "animated/multipage structure was not observed in the real sample bytes"
                        .to_owned(),
                )
            }
        }
        other => Err(format!("unsupported stable error code {other}")),
    }
}

fn observed_media(probe: &Value) -> Result<ObservedMediaV1, String> {
    let streams = probe["streams"]
        .as_array()
        .ok_or_else(|| "FFprobe has no streams array".to_owned())?;
    let mut codecs = streams
        .iter()
        .filter_map(|stream| stream["codec_name"].as_str().map(str::to_owned))
        .collect::<Vec<_>>();
    codecs.sort();
    let video_streams = streams
        .iter()
        .filter(|stream| stream["codec_type"].as_str() == Some("video"))
        .collect::<Vec<_>>();
    let audio_streams = streams
        .iter()
        .filter(|stream| stream["codec_type"].as_str() == Some("audio"))
        .count();
    let (width, height, alpha_present, orientation_present) =
        if let Some(video) = video_streams.first() {
            let pixel_format = video["pix_fmt"].as_str().unwrap_or_default();
            let side_data = video["side_data_list"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let rotate = video["tags"]["rotate"].as_str().is_some();
            (
                value_u32(&video["width"]),
                value_u32(&video["height"]),
                pixel_format.contains('a'),
                rotate
                    || side_data
                        .iter()
                        .any(|entry| entry["side_data_type"].as_str() == Some("Display Matrix")),
            )
        } else {
            (0, 0, false, false)
        };
    let format = &probe["format"];
    let duration_ms = format["duration"]
        .as_str()
        .and_then(|value| value.parse::<f64>().ok())
        .map(|seconds| (seconds.max(0.0) * 1000.0).round() as u64)
        .unwrap_or_default();
    let mut metadata_keys = BTreeSet::new();
    if let Some(tags) = format["tags"].as_object() {
        metadata_keys.extend(
            tags.keys()
                .filter(|key| !key.eq_ignore_ascii_case("encoder"))
                .cloned(),
        );
    }
    for stream in streams {
        if let Some(tags) = stream["tags"].as_object() {
            metadata_keys.extend(
                tags.keys()
                    .filter(|key| !key.eq_ignore_ascii_case("encoder"))
                    .cloned(),
            );
        }
    }
    let frame_count = streams
        .iter()
        .filter_map(|stream| stream["nb_read_frames"].as_str()?.parse::<u64>().ok())
        .sum::<u64>();
    let format_name = probe["format"]["format_name"].as_str().unwrap_or_default();
    let still_image_format = [
        "image2",
        "jpeg_pipe",
        "png_pipe",
        "webp_pipe",
        "tiff_pipe",
        "gif",
    ]
    .iter()
    .any(|candidate| {
        format_name
            .split(',')
            .any(|actual| actual.eq_ignore_ascii_case(candidate))
    });
    let stream_topology = if audio_streams > 0 && !video_streams.is_empty() {
        "single_video_and_audio"
    } else if audio_streams > 1 {
        "multiple_audio_streams"
    } else if audio_streams == 1 {
        "single_audio_stream"
    } else if video_streams.len() > 1 {
        "multiple_video_streams"
    } else if frame_count > 1 {
        "multiple_video_frames"
    } else if still_image_format {
        "single_video_frame"
    } else {
        "single_video_stream"
    };
    Ok(ObservedMediaV1 {
        format_name: format_name.to_owned(),
        codecs,
        stream_topology: stream_topology.to_owned(),
        width,
        height,
        duration_ms,
        alpha_present,
        orientation_present,
        metadata_keys: metadata_keys.into_iter().collect(),
        frame_count,
    })
}

fn validate_output(
    expected: &OutputExpectationsV1,
    observed: &ObservedMediaV1,
    sample: &SampleRecordV1,
) -> Result<(), String> {
    if !container_matches(&expected.container, &observed.format_name) {
        return Err(format!(
            "output container mismatch: expected {}, observed {}",
            expected.container, observed.format_name
        ));
    }
    for codec in &expected.codecs {
        if !observed
            .codecs
            .iter()
            .any(|actual| actual.eq_ignore_ascii_case(codec))
        {
            return Err(format!(
                "output codec {codec} is absent from {:?}",
                observed.codecs
            ));
        }
    }
    if observed.stream_topology != expected.stream_topology {
        return Err(format!(
            "output topology mismatch: expected {}, observed {}",
            expected.stream_topology, observed.stream_topology
        ));
    }
    if expected.width > 0
        && (observed.width != expected.width || observed.height != expected.height)
    {
        return Err(format!(
            "output dimensions mismatch: expected {}x{}, observed {}x{}",
            expected.width, expected.height, observed.width, observed.height
        ));
    }
    if observed.width > expected.max_width || observed.height > expected.max_height {
        return Err(format!(
            "output dimensions exceed {}x{} bound",
            expected.max_width, expected.max_height
        ));
    }
    if sample.duration_ms > 0 && observed.duration_ms > expected.max_duration_ms {
        return Err(format!(
            "output duration {} ms exceeds {} ms bound",
            observed.duration_ms, expected.max_duration_ms
        ));
    }
    if expected.alpha_policy == "preserve_if_present"
        && sample.alpha == "present"
        && !observed.alpha_present
    {
        return Err("alpha policy requires preserving present alpha".to_owned());
    }
    if expected.orientation_policy == "apply_to_pixels" && observed.orientation_present {
        return Err("orientation display metadata remains after apply-to-pixels policy".to_owned());
    }
    if expected.metadata_policy == "strip" && !observed.metadata_keys.is_empty() {
        return Err(format!(
            "metadata stripping left tags {:?}",
            observed.metadata_keys
        ));
    }
    if expected.metadata_policy == "safe_image_metadata"
        && observed
            .metadata_keys
            .iter()
            .any(|key| !safe_image_metadata_key(key))
    {
        return Err(format!(
            "unsafe image metadata tags remain: {:?}",
            observed.metadata_keys
        ));
    }
    Ok(())
}

fn ffprobe_arguments(input: &str) -> Vec<String> {
    [
        "-v",
        "error",
        "-count_frames",
        "-show_format",
        "-show_streams",
        "-of",
        "json",
        input,
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn augment_multiframe_observation(
    sample: &SampleRecordV1,
    path: &Path,
    observed: &mut ObservedMediaV1,
) -> Result<(), String> {
    let frames = match sample.id.as_str() {
        "image-gif-animated-v1" => gif_frame_count(path)?,
        "image-webp-animated-v1" => webp_animation_frame_count(path)?,
        "image-tiff-multipage-v1" => tiff_page_count(path)?,
        _ => return Ok(()),
    };
    observed.frame_count = frames as u64;
    observed.stream_topology = if frames > 1 {
        "multiple_video_frames".to_owned()
    } else {
        "single_video_frame".to_owned()
    };
    Ok(())
}

fn gif_frame_count(path: &Path) -> Result<usize, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() < 13 || !matches!(&bytes[..6], b"GIF87a" | b"GIF89a") {
        return Err("invalid GIF header".to_owned());
    }
    let mut offset = 13usize;
    let packed = bytes[10];
    if packed & 0x80 != 0 {
        offset = offset
            .checked_add(3usize << (usize::from(packed & 0x07) + 1))
            .ok_or_else(|| "GIF global color table offset overflow".to_owned())?;
    }
    let mut frame_count = 0;
    while offset < bytes.len() {
        match bytes[offset] {
            0x3b => return Ok(frame_count),
            0x21 => {
                offset += 2;
                skip_gif_sub_blocks(&bytes, &mut offset)?;
            }
            0x2c => {
                if offset + 10 > bytes.len() {
                    return Err("truncated GIF image descriptor".to_owned());
                }
                let image_packed = bytes[offset + 9];
                offset += 10;
                if image_packed & 0x80 != 0 {
                    offset = offset
                        .checked_add(3usize << (usize::from(image_packed & 0x07) + 1))
                        .ok_or_else(|| "GIF local color table offset overflow".to_owned())?;
                }
                if offset >= bytes.len() {
                    return Err("truncated GIF image data".to_owned());
                }
                offset += 1; // LZW minimum code size
                skip_gif_sub_blocks(&bytes, &mut offset)?;
                frame_count += 1;
            }
            marker => return Err(format!("unexpected GIF block marker 0x{marker:02x}")),
        }
    }
    Err("GIF trailer is missing".to_owned())
}

fn skip_gif_sub_blocks(bytes: &[u8], offset: &mut usize) -> Result<(), String> {
    loop {
        let length = *bytes
            .get(*offset)
            .ok_or_else(|| "truncated GIF sub-block".to_owned())? as usize;
        *offset += 1;
        if length == 0 {
            return Ok(());
        }
        *offset = offset
            .checked_add(length)
            .ok_or_else(|| "GIF sub-block offset overflow".to_owned())?;
        if *offset > bytes.len() {
            return Err("GIF sub-block exceeds sample length".to_owned());
        }
    }
}

fn tiff_page_count(path: &Path) -> Result<usize, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() < 8 {
        return Err("TIFF header is too short".to_owned());
    }
    let little = match &bytes[..2] {
        b"II" => true,
        b"MM" => false,
        _ => return Err("invalid TIFF byte-order marker".to_owned()),
    };
    let read_u16 = |offset: usize| -> Option<u16> {
        let data: [u8; 2] = bytes.get(offset..offset + 2)?.try_into().ok()?;
        Some(if little {
            u16::from_le_bytes(data)
        } else {
            u16::from_be_bytes(data)
        })
    };
    let read_u32 = |offset: usize| -> Option<u32> {
        let data: [u8; 4] = bytes.get(offset..offset + 4)?.try_into().ok()?;
        Some(if little {
            u32::from_le_bytes(data)
        } else {
            u32::from_be_bytes(data)
        })
    };
    if read_u16(2) != Some(42) {
        return Err("invalid TIFF version marker".to_owned());
    }
    let mut ifd = read_u32(4).ok_or_else(|| "missing TIFF first-IFD offset".to_owned())? as usize;
    let mut seen = BTreeSet::new();
    while ifd != 0 && seen.len() < 32 {
        if !seen.insert(ifd) {
            return Err("TIFF IFD chain contains a loop".to_owned());
        }
        let count = read_u16(ifd).ok_or_else(|| "invalid TIFF IFD".to_owned())? as usize;
        let next_offset = ifd
            .checked_add(2)
            .and_then(|start| start.checked_add(count.checked_mul(12)?))
            .ok_or_else(|| "TIFF IFD offset overflow".to_owned())?;
        if next_offset + 4 > bytes.len() {
            return Err("TIFF IFD exceeds the sample length".to_owned());
        }
        ifd = read_u32(next_offset).ok_or_else(|| "missing next TIFF IFD".to_owned())? as usize;
    }
    if ifd != 0 {
        return Err("TIFF page count exceeds the v1 sample limit".to_owned());
    }
    Ok(seen.len())
}

fn webp_animation_frame_count(path: &Path) -> Result<usize, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() < 12 || &bytes[..4] != b"RIFF" || &bytes[8..12] != b"WEBP" {
        return Err("invalid WebP RIFF header".to_owned());
    }
    let declared_size = u32::from_le_bytes(
        bytes[4..8]
            .try_into()
            .map_err(|_| "invalid WebP RIFF size")?,
    ) as usize;
    let limit = declared_size
        .checked_add(8)
        .ok_or_else(|| "WebP RIFF size overflow".to_owned())?;
    if limit > bytes.len() || limit < 12 {
        return Err("WebP RIFF size exceeds sample length".to_owned());
    }
    let mut offset = 12usize;
    let mut frame_count = 0;
    while offset + 8 <= limit {
        let chunk = &bytes[offset..offset + 4];
        let length = u32::from_le_bytes(
            bytes[offset + 4..offset + 8]
                .try_into()
                .map_err(|_| "invalid WebP chunk length")?,
        ) as usize;
        let data_start = offset + 8;
        let end = data_start
            .checked_add(length)
            .ok_or_else(|| "WebP chunk offset overflow".to_owned())?;
        if end > limit {
            return Err("WebP chunk exceeds RIFF length".to_owned());
        }
        if chunk == b"ANMF" {
            frame_count += 1;
        }
        offset = end + (length & 1);
    }
    if offset != limit {
        return Err("WebP chunk alignment does not equal RIFF length".to_owned());
    }
    Ok(frame_count)
}

fn verify_executable_identity(
    path: &Path,
    expected_hash: &str,
    expected_size: u64,
) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() != expected_size {
        return Err("file size differs from approved report".to_owned());
    }
    let actual_hash = digest_file(path).map_err(|error| error.to_string())?;
    if actual_hash != expected_hash {
        return Err("SHA-256 differs from approved report".to_owned());
    }
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    Ok(sha256(&bytes))
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn output_codec_name(encoder: &str) -> String {
    match encoder.to_ascii_lowercase().as_str() {
        "libx264" | "h264" => "h264".to_owned(),
        "libx265" | "hevc" => "hevc".to_owned(),
        "libmp3lame" => "mp3".to_owned(),
        "libwebp" | "libwebp_anim" => "webp".to_owned(),
        other => other.to_owned(),
    }
}

fn stable_error_code(value: &str) -> Option<&'static str> {
    match value {
        "unsupported_input" => Some("unsupported_input"),
        "invalid_input" => Some("invalid_input"),
        "unsupported_conversion" => Some("unsupported_conversion"),
        _ => None,
    }
}

fn default_option(
    options: &std::collections::BTreeMap<String, ParameterBounds>,
    name: &str,
    fallback: i64,
) -> i64 {
    options
        .get(name)
        .map(|bounds| bounds.default)
        .unwrap_or(fallback)
}

fn topology_for_category(category: ConversionCategory) -> &'static str {
    match category {
        ConversionCategory::Audio => "single_audio_stream",
        ConversionCategory::Image => "single_video_frame",
        ConversionCategory::Video => "single_video_stream",
    }
}

fn topology_for_input(topology: InputTopology) -> &'static str {
    match topology {
        InputTopology::SingleVideoFrame => "single_video_frame",
        InputTopology::SingleVideoStream => "single_video_stream",
        InputTopology::SingleAudioStream => "single_audio_stream",
        InputTopology::SingleVideoAndAudio => "single_video_and_audio",
    }
}

fn policy_name(policy: AlphaPolicy) -> &'static str {
    match policy {
        AlphaPolicy::PreserveIfPresent => "preserve_if_present",
        AlphaPolicy::Composite => "composite",
        AlphaPolicy::Discard => "discard",
    }
}

fn orientation_name(policy: OrientationPolicy) -> &'static str {
    match policy {
        OrientationPolicy::ApplyToPixels => "apply_to_pixels",
        OrientationPolicy::PreserveTag => "preserve_tag",
        OrientationPolicy::Ignore => "ignore",
    }
}

fn metadata_name(policy: MetadataPolicy) -> &'static str {
    match policy {
        MetadataPolicy::SafeImageMetadata => "safe_image_metadata",
        MetadataPolicy::Preserve => "preserve",
        MetadataPolicy::Strip => "strip",
    }
}

fn container_matches(expected: &str, actual: &str) -> bool {
    let names = actual
        .split(',')
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    match expected.to_ascii_lowercase().as_str() {
        "m4a" => names
            .iter()
            .any(|name| ["m4a", "mp4", "mov"].contains(&name.as_str())),
        "mp4" => names
            .iter()
            .any(|name| ["mp4", "mov"].contains(&name.as_str())),
        "jpeg" | "jpg" => names
            .iter()
            .any(|name| ["jpeg_pipe", "image2", "jpeg"].contains(&name.as_str())),
        "png" => names
            .iter()
            .any(|name| ["png_pipe", "image2", "png"].contains(&name.as_str())),
        "webp" => names
            .iter()
            .any(|name| ["webp_pipe", "webp"].contains(&name.as_str())),
        "tiff" | "tif" => names
            .iter()
            .any(|name| ["tiff_pipe", "tiff"].contains(&name.as_str())),
        "gif" => names.contains("gif"),
        _ => names.contains(&expected.to_ascii_lowercase()),
    }
}

fn format_matches_demuxer(expected: &str, actual: &str) -> bool {
    actual
        .split(',')
        .any(|candidate| candidate.eq_ignore_ascii_case(expected))
}

fn value_u32(value: &Value) -> u32 {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .unwrap_or_default()
}

fn safe_image_metadata_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "orientation" | "icc_profile"
    )
}

fn profile_id_for_triple(triple: &str) -> &'static str {
    match triple {
        "x86_64-pc-windows-msvc" => "windows-x86_64",
        "aarch64-apple-darwin" => "macos-aarch64",
        "x86_64-apple-darwin" => "macos-x86_64",
        "x86_64-unknown-linux-gnu" => "linux-x86_64",
        _ => "unknown",
    }
}

fn target_matches_runner(triple: &str) -> bool {
    matches!(
        (std::env::consts::OS, std::env::consts::ARCH, triple),
        ("windows", "x86_64", "x86_64-pc-windows-msvc")
            | ("macos", "aarch64", "aarch64-apple-darwin")
            | ("macos", "x86_64", "x86_64-apple-darwin")
            | ("linux", "x86_64", "x86_64-unknown-linux-gnu")
    )
}

fn current_git_commit(root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|error| format!("could not query current git commit: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "could not query current git commit: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn output_path(
    target_profile_id: &str,
    edge: &ConversionEdgeV1,
    sample: &SampleRecordV1,
) -> String {
    format!(
        "target/stage0/sample-output/{target_profile_id}/{}-{}.{}",
        edge.id, sample.id, edge.output_format
    )
}

fn root_relative_path(root: &Path, path: &Path) -> Result<String, String> {
    path.strip_prefix(root)
        .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        .map_err(|_| format!("path escapes repository root: {}", path.display()))
}

fn resolve_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::{gif_frame_count, tiff_page_count, webp_animation_frame_count};
    use std::path::Path;

    #[test]
    fn checked_in_animated_images_and_tiff_are_real_multiframe_inputs() {
        let corpus = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("testdata/media/v1/files");
        assert_eq!(
            gif_frame_count(&corpus.join("image-gif-animated-v1.gif")).unwrap(),
            2
        );
        assert_eq!(
            webp_animation_frame_count(&corpus.join("image-webp-animated-v1.webp")).unwrap(),
            2
        );
        assert_eq!(
            tiff_page_count(&corpus.join("image-tiff-multipage-v1.tiff")).unwrap(),
            2
        );
    }
}
