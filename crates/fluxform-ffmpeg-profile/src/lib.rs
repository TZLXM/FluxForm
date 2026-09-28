mod archive;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use thiserror::Error;

const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
const PROBE_TIMEOUT: Duration = Duration::from_secs(20);
const REQUIRED_STAGE0_TARGETS: &[&str] = &[
    "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
    "x86_64-unknown-linux-gnu",
];
const PROBES: &[&[&str]] = &[
    &["-hide_banner", "-version"],
    &["-hide_banner", "-protocols"],
    &["-hide_banner", "-demuxers"],
    &["-hide_banner", "-muxers"],
    &["-hide_banner", "-decoders"],
    &["-hide_banner", "-encoders"],
];

#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("could not read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid FFmpeg profile: {0}")]
    InvalidProfile(String),
    #[error("invalid FFmpeg probe output: {0}")]
    InvalidOutput(String),
    #[error(
        "FFmpeg probe failed for {program} with fixed arguments {arguments:?} (status {status})"
    )]
    ProcessFailed {
        program: PathBuf,
        arguments: Vec<&'static str>,
        status: String,
    },
    #[error("FFmpeg probe timed out for {0}")]
    Timeout(PathBuf),
    #[error("FFmpeg probe output exceeded the capture limit")]
    OutputLimit,
    #[error(
        "required {kind} is missing: {capability} (parsed {available_count} entries: {available_preview})"
    )]
    MissingCapability {
        kind: &'static str,
        capability: String,
        available_count: usize,
        available_preview: String,
    },
    #[error("the report does not match an immutable profile artifact row")]
    IdentityMismatch,
    #[error(
        "archive identity mismatch: measured size or SHA-256 differs from the immutable profile row"
    )]
    ArchiveIdentityMismatch,
    #[error("unsafe or unsupported FFmpeg archive: {0}")]
    UnsafeArchive(String),
    #[error("report JSON could not be encoded: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileDocument {
    profile_id: String,
    license_declaration: String,
    declared_codecs: Vec<String>,
    protocol_whitelist: Vec<String>,
    required: RequiredCapabilities,
    artifacts: Vec<ArtifactRecord>,
    #[serde(default)]
    distribution_gate: DistributionGate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredCapabilities {
    muxers: Vec<String>,
    demuxers: Vec<String>,
    encoders: Vec<CodecCapability>,
    decoders: Vec<CodecCapability>,
    protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CodecCapability {
    name: String,
    codec: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactStatus {
    Candidate,
    Approved,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveFormat {
    Zip32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRecord {
    artifact_id: String,
    status: ArtifactStatus,
    target_triple: String,
    archive_format: ArchiveFormat,
    artifact_uri: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    ffmpeg_sha256: String,
    ffmpeg_size_bytes: u64,
    ffprobe_sha256: String,
    ffprobe_size_bytes: u64,
    license: String,
    license_text_path: String,
    license_text_sha256: String,
    license_text_size_bytes: u64,
    source_revision: String,
    source_offer_url: String,
    #[serde(default)]
    approval_record_id: Option<String>,
    #[serde(default)]
    approval_date: Option<String>,
}

impl ArtifactRecord {
    pub fn status(&self) -> ArtifactStatus {
        self.status
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum GateStatus {
    Blocked,
    Approved,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DistributionGate {
    #[serde(default = "blocked_gate")]
    status: GateStatus,
    #[serde(default)]
    required_target_triples: Vec<String>,
    #[serde(default = "required_owner_legal_review")]
    owner_legal_approval_required: bool,
    #[serde(default)]
    owner_approval_record_id: Option<String>,
    #[serde(default)]
    owner_approval_date: Option<String>,
    #[serde(default)]
    legal_approval_record_id: Option<String>,
    #[serde(default)]
    legal_approval_date: Option<String>,
}

impl Default for DistributionGate {
    fn default() -> Self {
        Self {
            status: GateStatus::Blocked,
            required_target_triples: Vec::new(),
            owner_legal_approval_required: true,
            owner_approval_record_id: None,
            owner_approval_date: None,
            legal_approval_record_id: None,
            legal_approval_date: None,
        }
    }
}

fn blocked_gate() -> GateStatus {
    GateStatus::Blocked
}

fn required_owner_legal_review() -> bool {
    true
}

#[derive(Debug, Clone)]
pub struct BuildProfile {
    document: ProfileDocument,
    profile_digest: String,
}

#[derive(Debug, Clone)]
pub struct ApprovedArtifact {
    artifact: ArtifactRecord,
    profile_id: String,
    profile_digest: String,
    distribution_gate_status: GateStatus,
}

#[derive(Debug, Clone, Default)]
pub struct CapturedProbeOutputs {
    pub ffmpeg_version: String,
    pub ffprobe_version: String,
    pub protocols: String,
    pub demuxers: String,
    pub muxers: String,
    pub decoders: String,
    pub encoders: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeReport {
    pub profile_id: String,
    pub profile_digest: String,
    pub distribution_gate_status: String,
    pub artifact_id: String,
    pub artifact_status: ArtifactStatus,
    pub archive_format: ArchiveFormat,
    pub artifact_uri: String,
    pub artifact_sha256: String,
    pub artifact_size_bytes: u64,
    pub target_triple: String,
    pub ffmpeg_sha256: String,
    pub ffmpeg_size_bytes: u64,
    pub ffprobe_sha256: String,
    pub ffprobe_size_bytes: u64,
    pub version: String,
    pub ffprobe_version: String,
    pub source_revision: String,
    pub source_offer_url: String,
    pub source_revision_reported_by_binary: Option<String>,
    pub build_configuration: String,
    pub license_declaration: String,
    pub license_text_path: String,
    pub license_text_sha256: String,
    pub license_text_size_bytes: u64,
    pub approval_record_id: Option<String>,
    pub approval_date: Option<String>,
    pub protocols: Vec<String>,
    pub demuxers: Vec<String>,
    pub muxers: Vec<String>,
    pub decoders: Vec<String>,
    pub encoders: Vec<String>,
}

impl BuildProfile {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| ProfileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let value = parse_toml_subset(&text)?;
        let document: ProfileDocument = serde_json::from_value(value)
            .map_err(|error| ProfileError::InvalidProfile(error.to_string()))?;
        validate_document(&document)?;
        let profile_digest = normalized_digest(&document)?;

        Ok(Self {
            document,
            profile_digest,
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.document.profile_id
    }

    pub fn profile_digest(&self) -> &str {
        &self.profile_digest
    }

    pub fn artifacts(&self) -> &[ArtifactRecord] {
        &self.document.artifacts
    }

    pub fn gate_is_approved(&self) -> bool {
        self.document.distribution_gate.status == GateStatus::Approved
    }

    pub fn approved_artifact(&self, artifact_id: &str) -> Result<ApprovedArtifact, ProfileError> {
        self.ensure_unchanged()?;
        let artifact = self
            .document
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == artifact_id)
            .ok_or(ProfileError::IdentityMismatch)?;
        if artifact.status != ArtifactStatus::Approved
            || artifact.approval_record_id.is_none()
            || artifact.approval_date.is_none()
        {
            return Err(ProfileError::IdentityMismatch);
        }

        Ok(ApprovedArtifact {
            artifact: artifact.clone(),
            profile_id: self.document.profile_id.clone(),
            profile_digest: self.profile_digest.clone(),
            distribution_gate_status: self.document.distribution_gate.status,
        })
    }

    fn ensure_unchanged(&self) -> Result<(), ProfileError> {
        if normalized_digest(&self.document)? != self.profile_digest {
            return Err(ProfileError::IdentityMismatch);
        }
        Ok(())
    }

    fn artifact_for_report<'a>(
        &'a self,
        report: &ProbeReport,
    ) -> Result<&'a ArtifactRecord, ProfileError> {
        self.ensure_unchanged()?;
        let matches = self.document.artifacts.iter().filter(|artifact| {
            artifact.target_triple == report.target_triple
                && artifact.ffmpeg_sha256 == report.ffmpeg_sha256
                && artifact.ffprobe_sha256 == report.ffprobe_sha256
                && artifact.ffmpeg_size_bytes == report.ffmpeg_size_bytes
                && artifact.ffprobe_size_bytes == report.ffprobe_size_bytes
        });
        let mut matches = matches;
        let artifact = matches.next().ok_or(ProfileError::IdentityMismatch)?;
        if matches.next().is_some() {
            return Err(ProfileError::IdentityMismatch);
        }
        Ok(artifact)
    }
}

impl ProbeReport {
    fn collect(ffmpeg: impl AsRef<Path>, ffprobe: impl AsRef<Path>) -> Result<Self, ProfileError> {
        let ffmpeg = ffmpeg.as_ref();
        let ffprobe = ffprobe.as_ref();
        let mut captured = CapturedProbeOutputs {
            ffmpeg_version: run_probe(ffmpeg, PROBES[0])?,
            ffprobe_version: run_probe(ffprobe, PROBES[0])?,
            ..CapturedProbeOutputs::default()
        };
        captured.protocols = run_probe(ffmpeg, PROBES[1])?;
        captured.demuxers = run_probe(ffmpeg, PROBES[2])?;
        captured.muxers = run_probe(ffmpeg, PROBES[3])?;
        captured.decoders = run_probe(ffmpeg, PROBES[4])?;
        captured.encoders = run_probe(ffmpeg, PROBES[5])?;

        let (ffmpeg_sha256, ffmpeg_size_bytes) = fingerprint(ffmpeg)?;
        let (ffprobe_sha256, ffprobe_size_bytes) = fingerprint(ffprobe)?;
        Self::parse_outputs(
            captured,
            ffmpeg_sha256,
            ffmpeg_size_bytes,
            ffprobe_sha256,
            ffprobe_size_bytes,
            current_target_triple(),
        )
    }

    pub fn collect_from_archive(
        profile: &BuildProfile,
        artifact_id: &str,
        archive_path: impl AsRef<Path>,
    ) -> Result<Self, ProfileError> {
        profile.ensure_unchanged()?;
        let artifact = profile
            .document
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == artifact_id)
            .ok_or(ProfileError::IdentityMismatch)?;
        archive::verify_archive_identity(artifact, archive_path.as_ref())?;
        let native_target = current_target_triple();
        if artifact.target_triple != native_target {
            return Err(ProfileError::UnsafeArchive(format!(
                "refusing to execute {} artifact on native target {native_target}",
                artifact.target_triple
            )));
        }
        let verified = archive::extract_and_verify(artifact, archive_path.as_ref())?;
        let report_result = (|| {
            let mut report = Self::collect(&verified.ffmpeg_path, &verified.ffprobe_path)?;
            if report.ffmpeg_sha256 != verified.ffmpeg_sha256
                || report.ffmpeg_size_bytes != verified.ffmpeg_size_bytes
                || report.ffprobe_sha256 != verified.ffprobe_sha256
                || report.ffprobe_size_bytes != verified.ffprobe_size_bytes
            {
                return Err(ProfileError::IdentityMismatch);
            }
            report.artifact_sha256 = verified.artifact_sha256.clone();
            report.artifact_size_bytes = verified.artifact_size_bytes;
            report.license_text_sha256 = verified.license_text_sha256.clone();
            report.license_text_size_bytes = verified.license_text_size_bytes;
            report.apply_profile(profile, artifact);
            report.validate(profile)?;
            Ok(report)
        })();
        match (report_result, verified.close()) {
            (Ok(report), Ok(())) => Ok(report),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Err(error), Err(cleanup_error)) => Err(ProfileError::UnsafeArchive(format!(
                "{error}; temporary archive cleanup also failed: {cleanup_error}"
            ))),
        }
    }

    pub fn from_captured(
        profile: &BuildProfile,
        artifact: &ArtifactRecord,
        captured: CapturedProbeOutputs,
    ) -> Result<Self, ProfileError> {
        profile.ensure_unchanged()?;
        if !profile
            .document
            .artifacts
            .iter()
            .any(|candidate| candidate == artifact)
        {
            return Err(ProfileError::IdentityMismatch);
        }
        let mut report = Self::parse_outputs(
            captured,
            artifact.ffmpeg_sha256.clone(),
            artifact.ffmpeg_size_bytes,
            artifact.ffprobe_sha256.clone(),
            artifact.ffprobe_size_bytes,
            artifact.target_triple.clone(),
        )?;
        // This constructor accepts caller-captured data for deterministic test fixtures; the
        // production CLI uses collect_from_archive and supplies independently measured values.
        report.artifact_sha256 = artifact.artifact_sha256.clone();
        report.artifact_size_bytes = artifact.artifact_size_bytes;
        report.license_text_sha256 = artifact.license_text_sha256.clone();
        report.license_text_size_bytes = artifact.license_text_size_bytes;
        report.apply_profile(profile, artifact);
        Ok(report)
    }

    pub fn validate(&mut self, profile: &BuildProfile) -> Result<(), ProfileError> {
        profile.ensure_unchanged()?;
        if !self.profile_id.is_empty() && self.profile_id != profile.document.profile_id {
            return Err(ProfileError::IdentityMismatch);
        }
        if !self.profile_digest.is_empty() && self.profile_digest != profile.profile_digest {
            return Err(ProfileError::IdentityMismatch);
        }

        let artifact = profile.artifact_for_report(self)?.clone();
        if !self.artifact_id.is_empty() && self.artifact_id != artifact.artifact_id {
            return Err(ProfileError::IdentityMismatch);
        }
        if self.artifact_sha256 != artifact.artifact_sha256
            || self.artifact_size_bytes != artifact.artifact_size_bytes
            || self.license_text_sha256 != artifact.license_text_sha256
            || self.license_text_size_bytes != artifact.license_text_size_bytes
        {
            return Err(ProfileError::IdentityMismatch);
        }
        if self.version != self.ffprobe_version {
            return Err(ProfileError::InvalidOutput(
                "ffmpeg and ffprobe versions differ".to_owned(),
            ));
        }
        if let Some(reported) = &self.source_revision_reported_by_binary
            && reported != &artifact.source_revision
        {
            return Err(ProfileError::InvalidOutput(
                "binary-reported source revision differs from the profile".to_owned(),
            ));
        }

        require_capabilities("muxer", &profile.document.required.muxers, &self.muxers)?;
        require_capabilities(
            "demuxer",
            &profile.document.required.demuxers,
            &self.demuxers,
        )?;
        require_capabilities(
            "encoder",
            &profile
                .document
                .required
                .encoders
                .iter()
                .map(|item| item.name.clone())
                .collect::<Vec<_>>(),
            &self.encoders,
        )?;
        require_capabilities(
            "decoder",
            &profile
                .document
                .required
                .decoders
                .iter()
                .map(|item| item.name.clone())
                .collect::<Vec<_>>(),
            &self.decoders,
        )?;
        require_capabilities(
            "protocol",
            &profile.document.required.protocols,
            &self.protocols,
        )?;

        self.apply_profile(profile, &artifact);
        Ok(())
    }

    pub fn verify_identity(&self, approved: &ApprovedArtifact) -> Result<(), ProfileError> {
        let artifact = &approved.artifact;
        let gate_status = match approved.distribution_gate_status {
            GateStatus::Blocked => "blocked",
            GateStatus::Approved => "approved",
        };
        if artifact.status != ArtifactStatus::Approved
            || self.profile_id != approved.profile_id
            || self.profile_digest != approved.profile_digest
            || self.distribution_gate_status != gate_status
            || self.artifact_id != artifact.artifact_id
            || self.artifact_status != artifact.status
            || self.archive_format != artifact.archive_format
            || self.target_triple != artifact.target_triple
            || self.artifact_uri != artifact.artifact_uri
            || self.artifact_sha256 != artifact.artifact_sha256
            || self.artifact_size_bytes != artifact.artifact_size_bytes
            || self.ffmpeg_sha256 != artifact.ffmpeg_sha256
            || self.ffmpeg_size_bytes != artifact.ffmpeg_size_bytes
            || self.ffprobe_sha256 != artifact.ffprobe_sha256
            || self.ffprobe_size_bytes != artifact.ffprobe_size_bytes
            || self.source_revision != artifact.source_revision
            || self.source_offer_url != artifact.source_offer_url
            || self
                .source_revision_reported_by_binary
                .as_deref()
                .is_some_and(|revision| revision != artifact.source_revision)
            || self.license_declaration != artifact.license
            || self.license_text_path != artifact.license_text_path
            || self.license_text_sha256 != artifact.license_text_sha256
            || self.license_text_size_bytes != artifact.license_text_size_bytes
            || self.approval_record_id != artifact.approval_record_id
            || self.approval_date != artifact.approval_date
        {
            return Err(ProfileError::IdentityMismatch);
        }
        Ok(())
    }

    fn parse_outputs(
        captured: CapturedProbeOutputs,
        ffmpeg_sha256: String,
        ffmpeg_size_bytes: u64,
        ffprobe_sha256: String,
        ffprobe_size_bytes: u64,
        target_triple: String,
    ) -> Result<Self, ProfileError> {
        let ffmpeg_info = parse_version_output(&captured.ffmpeg_version, "ffmpeg")?;
        let ffprobe_info = parse_version_output(&captured.ffprobe_version, "ffprobe")?;
        if ffmpeg_info.version != ffprobe_info.version {
            return Err(ProfileError::InvalidOutput(
                "ffmpeg and ffprobe do not share the same version".to_owned(),
            ));
        }
        if ffmpeg_info.configuration != ffprobe_info.configuration {
            return Err(ProfileError::InvalidOutput(
                "ffmpeg and ffprobe do not share the same build configuration".to_owned(),
            ));
        }
        if let (Some(ffmpeg_revision), Some(ffprobe_revision)) =
            (&ffmpeg_info.source_revision, &ffprobe_info.source_revision)
            && ffmpeg_revision != ffprobe_revision
        {
            return Err(ProfileError::InvalidOutput(
                "ffmpeg and ffprobe report different source revisions".to_owned(),
            ));
        }

        Ok(Self {
            profile_id: String::new(),
            profile_digest: String::new(),
            distribution_gate_status: "blocked".to_owned(),
            artifact_id: String::new(),
            artifact_status: ArtifactStatus::Candidate,
            archive_format: ArchiveFormat::Zip32,
            artifact_uri: String::new(),
            artifact_sha256: String::new(),
            artifact_size_bytes: 0,
            target_triple,
            ffmpeg_sha256,
            ffmpeg_size_bytes,
            ffprobe_sha256,
            ffprobe_size_bytes,
            version: ffmpeg_info.version,
            ffprobe_version: ffprobe_info.version,
            source_revision: String::new(),
            source_offer_url: String::new(),
            source_revision_reported_by_binary: ffmpeg_info
                .source_revision
                .or(ffprobe_info.source_revision),
            build_configuration: ffmpeg_info.configuration,
            license_declaration: String::new(),
            license_text_path: String::new(),
            license_text_sha256: String::new(),
            license_text_size_bytes: 0,
            approval_record_id: None,
            approval_date: None,
            protocols: parse_protocols(&captured.protocols),
            demuxers: parse_flagged_list(&captured.demuxers),
            muxers: parse_flagged_list(&captured.muxers),
            decoders: parse_flagged_list(&captured.decoders),
            encoders: parse_flagged_list(&captured.encoders),
        })
    }

    fn apply_profile(&mut self, profile: &BuildProfile, artifact: &ArtifactRecord) {
        self.profile_id = profile.document.profile_id.clone();
        self.profile_digest = profile.profile_digest.clone();
        self.distribution_gate_status = match profile.document.distribution_gate.status {
            GateStatus::Blocked => "blocked".to_owned(),
            GateStatus::Approved => "approved".to_owned(),
        };
        self.artifact_id = artifact.artifact_id.clone();
        self.artifact_status = artifact.status;
        self.archive_format = artifact.archive_format;
        self.artifact_uri = artifact.artifact_uri.clone();
        self.target_triple = artifact.target_triple.clone();
        self.source_revision = artifact.source_revision.clone();
        self.source_offer_url = artifact.source_offer_url.clone();
        self.license_declaration = profile.document.license_declaration.clone();
        self.license_text_path = artifact.license_text_path.clone();
        self.approval_record_id = artifact.approval_record_id.clone();
        self.approval_date = artifact.approval_date.clone();
    }
}

struct VersionInfo {
    version: String,
    configuration: String,
    source_revision: Option<String>,
}

fn parse_version_output(output: &str, program: &str) -> Result<VersionInfo, ProfileError> {
    let version_prefix = format!("{program} version ");
    let mut version = None;
    let mut configuration = None;
    let mut source_revision = None;
    for line in output.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix(&version_prefix) {
            version = rest.split_whitespace().next().map(str::to_owned);
        } else if let Some(rest) = line.strip_prefix("configuration:") {
            configuration = Some(rest.trim().to_owned());
        } else if let Some(rest) = line
            .strip_prefix("source revision:")
            .or_else(|| line.strip_prefix("git commit:"))
        {
            let value = rest.trim();
            if !value.is_empty() {
                source_revision = Some(value.to_owned());
            }
        }
    }
    let version = version
        .ok_or_else(|| ProfileError::InvalidOutput(format!("missing {program} version line")))?;
    let configuration = configuration.ok_or_else(|| {
        ProfileError::InvalidOutput(format!("missing {program} build configuration"))
    })?;
    if configuration.is_empty() {
        return Err(ProfileError::InvalidOutput(format!(
            "empty {program} build configuration"
        )));
    }
    Ok(VersionInfo {
        version,
        configuration,
        source_revision,
    })
}

fn parse_protocols(output: &str) -> Vec<String> {
    let mut in_protocol_list = false;
    let mut values = Vec::new();
    for line in output.lines().map(str::trim) {
        if line.eq_ignore_ascii_case("supported file protocols:") {
            in_protocol_list = true;
            continue;
        }
        if !in_protocol_list || line.is_empty() || line.ends_with(':') {
            continue;
        }
        values.extend(line.split_whitespace().filter_map(normalize_capability));
    }
    sort_unique(&mut values);
    values
}

fn parse_flagged_list(output: &str) -> Vec<String> {
    let mut values = Vec::new();
    for line in output.lines() {
        let mut fields = line.split_whitespace();
        let Some(flags) = fields.next() else {
            continue;
        };
        let Some(name) = fields.next() else {
            continue;
        };
        let valid_flags = flags
            .chars()
            .next()
            .is_some_and(|first| "VASED".contains(first))
            && flags
                .chars()
                .all(|character| "VASEDFX.+".contains(character));
        if valid_flags {
            for alias in name.split(',') {
                if let Some(name) = normalize_capability(alias) {
                    values.push(name);
                }
            }
        }
    }
    sort_unique(&mut values);
    values
}

fn normalize_capability(value: &str) -> Option<String> {
    if !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
    {
        Some(value.to_ascii_lowercase())
    } else {
        None
    }
}

fn sort_unique(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn require_capabilities(
    kind: &'static str,
    required: &[String],
    available: &[String],
) -> Result<(), ProfileError> {
    for capability in required {
        if available.binary_search(capability).is_err() {
            return Err(ProfileError::MissingCapability {
                kind,
                capability: capability.clone(),
                available_count: available.len(),
                available_preview: available
                    .iter()
                    .take(12)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        }
    }
    Ok(())
}

fn validate_document(document: &ProfileDocument) -> Result<(), ProfileError> {
    require_nonempty("profile_id", &document.profile_id)?;
    require_nonempty("license_declaration", &document.license_declaration)?;
    validate_unique("declared_codecs", &document.declared_codecs)?;
    validate_unique("protocol_whitelist", &document.protocol_whitelist)?;
    validate_unique("required.muxers", &document.required.muxers)?;
    validate_unique("required.demuxers", &document.required.demuxers)?;
    validate_unique("required.protocols", &document.required.protocols)?;

    const FORBIDDEN_PROTOCOLS: &[&str] =
        &["http", "https", "tcp", "udp", "srt", "ftp", "ssh", "crypto"];
    for protocol in &document.protocol_whitelist {
        require_nonempty("protocol_whitelist entry", protocol)?;
        if FORBIDDEN_PROTOCOLS
            .iter()
            .any(|forbidden| forbidden.eq_ignore_ascii_case(protocol))
        {
            return Err(ProfileError::InvalidProfile(format!(
                "protocol_whitelist must not include {protocol}"
            )));
        }
    }

    for (kind, capabilities) in [
        ("required.encoders", &document.required.encoders),
        ("required.decoders", &document.required.decoders),
    ] {
        let mut names = BTreeSet::new();
        for capability in capabilities {
            require_nonempty(kind, &capability.name)?;
            require_nonempty("capability codec", &capability.codec)?;
            if !names.insert(&capability.name) {
                return Err(ProfileError::InvalidProfile(format!(
                    "{kind} contains duplicate capability {}",
                    capability.name
                )));
            }
            if !document.declared_codecs.contains(&capability.codec) {
                return Err(ProfileError::InvalidProfile(format!(
                    "{kind} capability {} references undeclared codec {}",
                    capability.name, capability.codec
                )));
            }
        }
    }

    let mut artifact_ids = BTreeSet::new();
    for artifact in &document.artifacts {
        if !artifact_ids.insert(&artifact.artifact_id) {
            return Err(ProfileError::InvalidProfile(format!(
                "duplicate artifact_id {}",
                artifact.artifact_id
            )));
        }
        validate_artifact(artifact, &document.license_declaration)?;
    }
    validate_unique(
        "distribution_gate.required_target_triples",
        &document.distribution_gate.required_target_triples,
    )?;
    if document.distribution_gate.status == GateStatus::Approved {
        if !document.distribution_gate.owner_legal_approval_required {
            return Err(ProfileError::InvalidProfile(
                "an approved distribution gate must retain the owner/legal approval requirement"
                    .to_owned(),
            ));
        }
        let required_targets = document
            .distribution_gate
            .required_target_triples
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let stage0_targets = REQUIRED_STAGE0_TARGETS
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        if required_targets != stage0_targets {
            return Err(ProfileError::InvalidProfile(
                "approved distribution gate must require the exact four Stage 0 target triples"
                    .to_owned(),
            ));
        }
        for (id_field, date_field, id, date) in [
            (
                "owner_approval_record_id",
                "owner_approval_date",
                document
                    .distribution_gate
                    .owner_approval_record_id
                    .as_deref()
                    .unwrap_or_default(),
                document
                    .distribution_gate
                    .owner_approval_date
                    .as_deref()
                    .unwrap_or_default(),
            ),
            (
                "legal_approval_record_id",
                "legal_approval_date",
                document
                    .distribution_gate
                    .legal_approval_record_id
                    .as_deref()
                    .unwrap_or_default(),
                document
                    .distribution_gate
                    .legal_approval_date
                    .as_deref()
                    .unwrap_or_default(),
            ),
        ] {
            require_nonempty(id_field, id)?;
            if !valid_date(date) {
                return Err(ProfileError::InvalidProfile(format!(
                    "approved distribution gate requires a valid {date_field}"
                )));
            }
        }
        for target in &document.distribution_gate.required_target_triples {
            let approved = document.artifacts.iter().any(|artifact| {
                artifact.target_triple == *target && artifact.status == ArtifactStatus::Approved
            });
            if !approved {
                return Err(ProfileError::InvalidProfile(format!(
                    "approved distribution gate is missing an approved artifact for {target}"
                )));
            }
        }
    }
    Ok(())
}

fn validate_artifact(artifact: &ArtifactRecord, profile_license: &str) -> Result<(), ProfileError> {
    for (field, value) in [
        ("artifact_id", artifact.artifact_id.as_str()),
        ("target_triple", artifact.target_triple.as_str()),
        ("artifact_uri", artifact.artifact_uri.as_str()),
        ("license", artifact.license.as_str()),
        ("license_text_path", artifact.license_text_path.as_str()),
        ("source_revision", artifact.source_revision.as_str()),
        ("source_offer_url", artifact.source_offer_url.as_str()),
    ] {
        require_nonempty(field, value)?;
    }
    for (field, hash) in [
        ("artifact_sha256", &artifact.artifact_sha256),
        ("ffmpeg_sha256", &artifact.ffmpeg_sha256),
        ("ffprobe_sha256", &artifact.ffprobe_sha256),
        ("license_text_sha256", &artifact.license_text_sha256),
    ] {
        if !is_sha256(hash) {
            return Err(ProfileError::InvalidProfile(format!(
                "{field} must contain exactly 64 hexadecimal characters"
            )));
        }
    }
    for (field, size) in [
        ("artifact_size_bytes", artifact.artifact_size_bytes),
        ("ffmpeg_size_bytes", artifact.ffmpeg_size_bytes),
        ("ffprobe_size_bytes", artifact.ffprobe_size_bytes),
        ("license_text_size_bytes", artifact.license_text_size_bytes),
    ] {
        if size == 0 {
            return Err(ProfileError::InvalidProfile(format!(
                "{field} must be greater than zero"
            )));
        }
    }
    if artifact.license != profile_license {
        return Err(ProfileError::InvalidProfile(
            "artifact license differs from profile license declaration".to_owned(),
        ));
    }
    if !artifact.source_offer_url.starts_with("https://") {
        return Err(ProfileError::InvalidProfile(
            "source_offer_url must be an HTTPS URL".to_owned(),
        ));
    }
    match artifact.status {
        ArtifactStatus::Candidate => {
            if artifact.approval_record_id.is_some() || artifact.approval_date.is_some() {
                return Err(ProfileError::InvalidProfile(
                    "candidate artifacts must not carry approval fields".to_owned(),
                ));
            }
        }
        ArtifactStatus::Approved => {
            let record_id = artifact.approval_record_id.as_deref().unwrap_or_default();
            let date = artifact.approval_date.as_deref().unwrap_or_default();
            require_nonempty("approval_record_id", record_id)?;
            if !valid_date(date) {
                return Err(ProfileError::InvalidProfile(
                    "approved artifacts require an ISO YYYY-MM-DD approval_date".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ProfileError> {
    if value.trim().is_empty() {
        return Err(ProfileError::InvalidProfile(format!(
            "{field} must not be empty"
        )));
    }
    Ok(())
}

fn validate_unique(field: &str, values: &[String]) -> Result<(), ProfileError> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(ProfileError::InvalidProfile(format!(
            "{field} contains duplicate values"
        )));
    }
    for value in values {
        require_nonempty(field, value)?;
    }
    Ok(())
}

fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| index == 4 || index == 7 || byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[0..4].parse::<u32>().ok();
    let month = value[5..7].parse::<u32>().ok();
    let day = value[8..10].parse::<u32>().ok();
    let (Some(year), Some(month), Some(day)) = (year, month, day) else {
        return false;
    };
    if year == 0 || !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let leap_year = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        2 if leap_year => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    day <= days_in_month
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalized_digest(document: &ProfileDocument) -> Result<String, ProfileError> {
    let mut normalized = document.clone();
    normalized.declared_codecs.sort();
    normalized
        .protocol_whitelist
        .sort_by_key(|item| item.to_ascii_lowercase());
    normalized.required.muxers.sort();
    normalized.required.demuxers.sort();
    normalized.required.protocols.sort();
    normalized
        .required
        .encoders
        .sort_by(|left, right| left.name.cmp(&right.name));
    normalized
        .required
        .decoders
        .sort_by(|left, right| left.name.cmp(&right.name));
    normalized.distribution_gate.required_target_triples.sort();
    normalized
        .artifacts
        .sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));

    let serialized = serde_json::to_vec(&normalized)?;
    Ok(hex_digest(&serialized))
}

#[cfg(test)]
mod zip_inventory_tests {
    use super::*;
    use crate::archive::{ZipEntry, inspect_zip_archive};
    use std::io::Cursor;

    #[derive(Clone)]
    struct TestEntry {
        central_name: Vec<u8>,
        local_name: Vec<u8>,
        flags: u16,
        method: u16,
        disk_start: u16,
        external_attributes: u32,
        central_extra: Vec<u8>,
        payload: Vec<u8>,
        uncompressed_size_override: Option<u32>,
    }

    impl TestEntry {
        fn regular(name: &str) -> Self {
            Self {
                central_name: name.as_bytes().to_vec(),
                local_name: name.as_bytes().to_vec(),
                flags: 0,
                method: 0,
                disk_start: 0,
                external_attributes: 0x81a4_0000,
                central_extra: Vec::new(),
                payload: Vec::new(),
                uncompressed_size_override: None,
            }
        }

        fn with_payload(name: &str, payload: &[u8]) -> Self {
            let mut entry = Self::regular(name);
            entry.payload = payload.to_vec();
            entry
        }

        fn directory(name: &str) -> Self {
            let mut entry = Self::regular(name);
            entry.external_attributes = 0x41ed_0010;
            entry
        }
    }

    fn push_u16(bytes: &mut Vec<u8>, value: u16) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(bytes: &mut Vec<u8>, value: u32) {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn crc32(bytes: &[u8]) -> u32 {
        let mut crc = u32::MAX;
        for byte in bytes {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xedb8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    fn test_zip(entries: &[TestEntry], eocd_disk: u16) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut offsets = Vec::new();
        for entry in entries {
            offsets.push(bytes.len() as u32);
            let size = entry.payload.len() as u32;
            let uncompressed_size = entry.uncompressed_size_override.unwrap_or(size);
            let checksum = crc32(&entry.payload);
            push_u32(&mut bytes, 0x0403_4b50);
            push_u16(&mut bytes, 20);
            push_u16(&mut bytes, entry.flags);
            push_u16(&mut bytes, entry.method);
            push_u16(&mut bytes, 0);
            push_u16(&mut bytes, 0);
            push_u32(&mut bytes, checksum);
            push_u32(&mut bytes, size);
            push_u32(&mut bytes, uncompressed_size);
            push_u16(&mut bytes, entry.local_name.len() as u16);
            push_u16(&mut bytes, 0);
            bytes.extend_from_slice(&entry.local_name);
            bytes.extend_from_slice(&entry.payload);
        }

        let central_offset = bytes.len() as u32;
        for (entry, local_offset) in entries.iter().zip(offsets) {
            let size = entry.payload.len() as u32;
            let uncompressed_size = entry.uncompressed_size_override.unwrap_or(size);
            let checksum = crc32(&entry.payload);
            push_u32(&mut bytes, 0x0201_4b50);
            push_u16(&mut bytes, 0x0314);
            push_u16(&mut bytes, 20);
            push_u16(&mut bytes, entry.flags);
            push_u16(&mut bytes, entry.method);
            push_u16(&mut bytes, 0);
            push_u16(&mut bytes, 0);
            push_u32(&mut bytes, checksum);
            push_u32(&mut bytes, size);
            push_u32(&mut bytes, uncompressed_size);
            push_u16(&mut bytes, entry.central_name.len() as u16);
            push_u16(&mut bytes, entry.central_extra.len() as u16);
            push_u16(&mut bytes, 0);
            push_u16(&mut bytes, entry.disk_start);
            push_u16(&mut bytes, 0);
            push_u32(&mut bytes, entry.external_attributes);
            push_u32(&mut bytes, local_offset);
            bytes.extend_from_slice(&entry.central_name);
            bytes.extend_from_slice(&entry.central_extra);
        }
        let central_size = bytes.len() as u32 - central_offset;
        push_u32(&mut bytes, 0x0605_4b50);
        push_u16(&mut bytes, eocd_disk);
        push_u16(&mut bytes, eocd_disk);
        push_u16(&mut bytes, entries.len() as u16);
        push_u16(&mut bytes, entries.len() as u16);
        push_u32(&mut bytes, central_size);
        push_u32(&mut bytes, central_offset);
        push_u16(&mut bytes, 0);
        bytes
    }

    fn inspect(bytes: &[u8]) -> Result<Vec<ZipEntry>, ProfileError> {
        inspect_zip_archive(&mut Cursor::new(bytes), bytes.len() as u64)
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn test_artifact(
        bytes: &[u8],
        ffmpeg: &[u8],
        ffprobe: &[u8],
        license: &[u8],
    ) -> ArtifactRecord {
        ArtifactRecord {
            artifact_id: "test-windows-candidate".to_owned(),
            status: ArtifactStatus::Candidate,
            target_triple: current_target_triple(),
            archive_format: ArchiveFormat::Zip32,
            artifact_uri: "https://artifacts.example.invalid/test.zip".to_owned(),
            artifact_sha256: hex_digest(bytes),
            artifact_size_bytes: bytes.len() as u64,
            ffmpeg_sha256: hex_digest(ffmpeg),
            ffmpeg_size_bytes: ffmpeg.len() as u64,
            ffprobe_sha256: hex_digest(ffprobe),
            ffprobe_size_bytes: ffprobe.len() as u64,
            license: "MIT".to_owned(),
            license_text_path: "bundle/LICENSE.txt".to_owned(),
            license_text_sha256: hex_digest(license),
            license_text_size_bytes: license.len() as u64,
            source_revision: "test-revision".to_owned(),
            source_offer_url: "https://artifacts.example.invalid/source".to_owned(),
            approval_record_id: None,
            approval_date: None,
        }
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    fn small_candidate_zip(ffmpeg: &[u8], ffprobe: &[u8], license: &[u8]) -> Vec<u8> {
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        test_zip(
            &[
                TestEntry::directory("bundle/"),
                TestEntry::directory("bundle/bin/"),
                TestEntry::with_payload(&format!("bundle/bin/ffmpeg{suffix}"), ffmpeg),
                TestEntry::with_payload(&format!("bundle/bin/ffprobe{suffix}"), ffprobe),
                TestEntry::with_payload("bundle/LICENSE.txt", license),
            ],
            0,
        )
    }

    #[test]
    fn accepts_regular_safe_zip_entries() {
        let bytes = test_zip(
            &[
                TestEntry::directory("bundle/"),
                TestEntry::with_payload("bundle/bin/ffmpeg.exe", b"safe fixture"),
            ],
            0,
        );
        let entries = inspect(&bytes).expect("safe archive");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].name, "bundle/bin/ffmpeg.exe");
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    #[test]
    fn verified_extraction_measures_archive_executables_and_license_then_cleans_temp() {
        let ffmpeg = b"non-executable ffmpeg fixture";
        let ffprobe = b"non-executable ffprobe fixture";
        let license = b"license fixture";
        let bytes = small_candidate_zip(ffmpeg, ffprobe, license);
        let artifact = test_artifact(&bytes, ffmpeg, ffprobe, license);
        let archive_directory = tempfile::tempdir().expect("archive fixture directory");
        let archive_path = archive_directory.path().join("candidate.zip");
        fs::write(&archive_path, &bytes).expect("write archive fixture");

        let verified =
            archive::extract_and_verify(&artifact, &archive_path).expect("verified extraction");
        assert_eq!(verified.artifact_sha256, hex_digest(&bytes));
        assert_eq!(verified.artifact_size_bytes, bytes.len() as u64);
        assert_eq!(verified.ffmpeg_sha256, hex_digest(ffmpeg));
        assert_eq!(verified.ffmpeg_size_bytes, ffmpeg.len() as u64);
        assert_eq!(verified.ffprobe_sha256, hex_digest(ffprobe));
        assert_eq!(verified.ffprobe_size_bytes, ffprobe.len() as u64);
        assert_eq!(verified.license_text_sha256, hex_digest(license));
        assert_eq!(verified.license_text_size_bytes, license.len() as u64);
        let temp_path = verified.temp_root().to_path_buf();
        assert!(temp_path.exists());
        let private_archive_path = temp_path.join("authenticated-candidate.zip");
        assert!(
            private_archive_path.is_file(),
            "extraction must retain a private copy of the authenticated archive"
        );
        assert_eq!(
            fs::read(&private_archive_path).expect("read private archive copy"),
            bytes,
            "private archive copy must contain the exact authenticated bytes"
        );

        fs::write(&archive_path, b"replacement at the original pathname")
            .expect("replace original archive path after verification");
        assert_eq!(
            fs::read(&private_archive_path).expect("private archive survives source replacement"),
            bytes,
            "replacing the public path must not change the authenticated extractor input"
        );

        verified.close().expect("explicit temporary cleanup");
        assert!(
            !temp_path.exists(),
            "explicit cleanup removes extracted contents"
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn rejects_symlink_archive_path_instead_of_following_target() {
        let ffmpeg = b"non-executable ffmpeg fixture";
        let ffprobe = b"non-executable ffprobe fixture";
        let license = b"license fixture";
        let bytes = small_candidate_zip(ffmpeg, ffprobe, license);
        let artifact = test_artifact(&bytes, ffmpeg, ffprobe, license);
        let archive_directory = tempfile::tempdir().expect("archive fixture directory");
        let archive_path = archive_directory.path().join("candidate.zip");
        let symlink_path = archive_directory.path().join("candidate-alias.zip");
        fs::write(&archive_path, &bytes).expect("write archive fixture");
        std::os::unix::fs::symlink(&archive_path, &symlink_path).expect("create archive symlink");

        let error = archive::verify_archive_identity(&artifact, &symlink_path)
            .expect_err("archive verification must reject a symlink path");
        assert!(
            error.to_string().contains("regular"),
            "symlink rejection should identify a non-regular archive path: {error}"
        );
    }

    #[cfg(any(windows, target_os = "macos", target_os = "linux"))]
    #[test]
    fn extracted_executable_or_license_mismatch_fails_before_probe_invocation() {
        let ffmpeg = b"non-executable ffmpeg fixture";
        let ffprobe = b"non-executable ffprobe fixture";
        let license = b"license fixture";
        let bytes = small_candidate_zip(ffmpeg, ffprobe, license);
        let archive_directory = tempfile::tempdir().expect("archive fixture directory");
        let archive_path = archive_directory.path().join("candidate.zip");
        fs::write(&archive_path, &bytes).expect("write archive fixture");

        let mut wrong_ffmpeg = test_artifact(&bytes, ffmpeg, ffprobe, license);
        wrong_ffmpeg.ffmpeg_sha256 = hex_digest(b"substituted ffmpeg");
        let error = archive::extract_and_verify(&wrong_ffmpeg, &archive_path)
            .err()
            .expect("unverified executable must not be returned for probing");
        let executable_name = if cfg!(windows) {
            "ffmpeg.exe"
        } else {
            "ffmpeg"
        };
        assert!(
            error
                .to_string()
                .contains(&format!("{executable_name} identity mismatch"))
        );

        let mut wrong_license = test_artifact(&bytes, ffmpeg, ffprobe, license);
        wrong_license.license_text_sha256 = hex_digest(b"substituted license");
        let error = archive::extract_and_verify(&wrong_license, &archive_path)
            .err()
            .expect("unverified license must fail before any probe");
        assert!(error.to_string().contains("license text identity mismatch"));
    }

    #[test]
    fn rejects_absolute_traversal_and_ambiguous_entry_paths() {
        for name in [
            "../escape.txt",
            "bundle/../../escape.txt",
            "/rooted.txt",
            "C:/drive.txt",
            "bundle\\backslash.txt",
            "bundle//empty.txt",
            "bundle/./dot.txt",
            "bundle/name.",
            "bundle/name ",
            "bundle/CON.txt",
        ] {
            let bytes = test_zip(&[TestEntry::regular(name)], 0);
            assert!(inspect(&bytes).is_err(), "unsafe path {name:?} must fail");
        }
    }

    #[test]
    fn rejects_symlink_reparse_and_unknown_unix_entry_types() {
        let mut symlink = TestEntry::regular("bundle/link");
        symlink.external_attributes = 0xa1ff_0000;
        let mut reparse = TestEntry::regular("bundle/reparse");
        reparse.external_attributes |= 0x0000_0400;
        let mut fifo = TestEntry::regular("bundle/fifo");
        fifo.external_attributes = 0x11a4_0000;
        for entry in [symlink, reparse, fifo] {
            assert!(inspect(&test_zip(&[entry], 0)).is_err());
        }
    }

    #[test]
    fn rejects_device_entries() {
        let mut device = TestEntry::regular("bundle/device");
        device.external_attributes |= 0x0040;
        assert!(inspect(&test_zip(&[device], 0)).is_err());
    }

    #[test]
    fn rejects_stored_entries_with_inconsistent_sizes() {
        let mut inconsistent = TestEntry::with_payload("bundle/data.bin", b"four");
        inconsistent.uncompressed_size_override = Some(5);
        assert!(inspect(&test_zip(&[inconsistent], 0)).is_err());
    }

    #[test]
    fn rejects_case_collisions_and_file_directory_prefix_conflicts() {
        let duplicate = [
            TestEntry::regular("bundle/ffmpeg.exe"),
            TestEntry::regular("BUNDLE/FFMPEG.EXE"),
        ];
        assert!(inspect(&test_zip(&duplicate, 0)).is_err());
        let prefix = [
            TestEntry::regular("bundle"),
            TestEntry::regular("bundle/file.txt"),
        ];
        assert!(inspect(&test_zip(&prefix, 0)).is_err());
    }

    #[test]
    fn rejects_encryption_unsupported_compression_and_multidisk_archives() {
        let mut encrypted = TestEntry::regular("bundle/file");
        encrypted.flags = 1;
        assert!(inspect(&test_zip(&[encrypted], 0)).is_err());
        let mut unsupported = TestEntry::regular("bundle/file");
        unsupported.method = 12;
        assert!(inspect(&test_zip(&[unsupported], 0)).is_err());
        let mut multidisk = TestEntry::regular("bundle/file");
        multidisk.disk_start = 1;
        assert!(inspect(&test_zip(&[multidisk], 0)).is_err());
        assert!(inspect(&test_zip(&[TestEntry::regular("bundle/file")], 1)).is_err());
    }

    #[test]
    fn rejects_zip64_and_local_header_central_directory_mismatch() {
        let mut zip64 = TestEntry::regular("bundle/file");
        zip64.central_extra.extend_from_slice(&1_u16.to_le_bytes());
        zip64.central_extra.extend_from_slice(&0_u16.to_le_bytes());
        assert!(inspect(&test_zip(&[zip64], 0)).is_err());

        let mut mismatched = TestEntry::regular("bundle/safe.txt");
        mismatched.local_name = b"bundle/evil.txt".to_vec();
        assert!(inspect(&test_zip(&[mismatched], 0)).is_err());
    }

    #[test]
    fn rejects_zip_bomb_sized_entries_before_extraction() {
        let mut oversized = TestEntry::regular("bundle/large.bin");
        oversized.uncompressed_size_override =
            Some(crate::archive::MAX_ENTRY_UNCOMPRESSED_BYTES as u32 + 1);
        let bytes = test_zip(&[oversized], 0);
        assert!(inspect(&bytes).is_err());
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fingerprint(path: &Path) -> Result<(String, u64), ProfileError> {
    let mut file = File::open(path).map_err(|source| ProfileError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let size = file
        .metadata()
        .map_err(|source| ProfileError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .len();
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|source| ProfileError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    let hash = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok((hash, size))
}

fn run_probe(program: &Path, arguments: &[&'static str]) -> Result<String, ProfileError> {
    let mut child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| ProfileError::Io {
            path: program.to_path_buf(),
            source,
        })?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let stdout_reader = thread::spawn(move || read_bounded(stdout));
    let stderr_reader = thread::spawn(move || read_bounded(stderr));
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let status = loop {
        match child.try_wait().map_err(|source| ProfileError::Io {
            path: program.to_path_buf(),
            source,
        })? {
            Some(status) => break Some(status),
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| ProfileError::InvalidOutput("stdout reader panicked".to_owned()))?
        .map_err(|source| ProfileError::Io {
            path: program.to_path_buf(),
            source,
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ProfileError::InvalidOutput("stderr reader panicked".to_owned()))?
        .map_err(|source| ProfileError::Io {
            path: program.to_path_buf(),
            source,
        })?;
    if status.is_none() {
        return Err(ProfileError::Timeout(program.to_path_buf()));
    }
    let status = status.expect("status checked above");
    if !status.success() {
        return Err(ProfileError::ProcessFailed {
            program: program.to_path_buf(),
            arguments: arguments.to_vec(),
            status: status.to_string(),
        });
    }
    if stdout.truncated || stderr.truncated {
        return Err(ProfileError::OutputLimit);
    }

    let mut output = String::from_utf8_lossy(&stdout.bytes).into_owned();
    if !stderr.bytes.is_empty() {
        output.push('\n');
        output.push_str(&String::from_utf8_lossy(&stderr.bytes));
    }
    Ok(output)
}

struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn read_bounded(mut reader: impl Read) -> io::Result<BoundedOutput> {
    let mut bytes = Vec::with_capacity(MAX_CAPTURE_BYTES);
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        let remaining = MAX_CAPTURE_BYTES.saturating_sub(bytes.len());
        let captured = read.min(remaining);
        bytes.extend_from_slice(&buffer[..captured]);
        truncated |= captured < read;
    }
    Ok(BoundedOutput { bytes, truncated })
}

fn current_target_triple() -> String {
    let arch = std::env::consts::ARCH;
    match (std::env::consts::OS, arch, cfg!(target_env = "msvc")) {
        ("windows", "x86_64", true) => "x86_64-pc-windows-msvc".to_owned(),
        ("windows", "aarch64", true) => "aarch64-pc-windows-msvc".to_owned(),
        ("windows", "x86_64", false) => "x86_64-pc-windows-gnu".to_owned(),
        ("windows", "aarch64", false) => "aarch64-pc-windows-gnullvm".to_owned(),
        ("macos", "x86_64", _) => "x86_64-apple-darwin".to_owned(),
        ("macos", "aarch64", _) => "aarch64-apple-darwin".to_owned(),
        ("linux", "x86_64", _) => "x86_64-unknown-linux-gnu".to_owned(),
        ("linux", "aarch64", _) => "aarch64-unknown-linux-gnu".to_owned(),
        (os, arch, _) => format!("{arch}-unknown-{os}"),
    }
}

#[derive(Clone)]
enum PathPart {
    Key(String),
    Index(usize),
}

// The controlled profile format uses TOML basic strings, single-line arrays,
// regular tables, and array-of-tables. Unsupported TOML syntax fails closed.
fn parse_toml_subset(input: &str) -> Result<Value, ProfileError> {
    let mut root = Value::Object(Map::new());
    let mut context: Vec<PathPart> = Vec::new();
    for (line_number, original) in input.lines().enumerate() {
        let line = strip_toml_comment(original).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[[") && line.ends_with("]]") {
            let path = parse_header(&line[2..line.len() - 2], line_number)?;
            if path.is_empty() {
                return Err(line_error(line_number, "empty array table"));
            }
            let last = path.last().expect("non-empty path").clone();
            ensure_object_path(&mut root, &path[..path.len() - 1], line_number)?;
            let parent_path = path[..path.len() - 1]
                .iter()
                .cloned()
                .map(PathPart::Key)
                .collect::<Vec<_>>();
            let parent = value_at_path_mut(&mut root, &parent_path)
                .ok_or_else(|| line_error(line_number, "invalid array table parent"))?;
            let object = parent
                .as_object_mut()
                .ok_or_else(|| line_error(line_number, "array table parent is not a table"))?;
            let values = object
                .entry(last.clone())
                .or_insert_with(|| Value::Array(Vec::new()));
            let values = values
                .as_array_mut()
                .ok_or_else(|| line_error(line_number, "array table conflicts with a value"))?;
            let index = values.len();
            values.push(Value::Object(Map::new()));
            context = path.into_iter().map(PathPart::Key).collect::<Vec<_>>();
            context.pop();
            context.push(PathPart::Key(last));
            context.push(PathPart::Index(index));
        } else if line.starts_with('[') && line.ends_with(']') {
            let path = parse_header(&line[1..line.len() - 1], line_number)?;
            ensure_object_path(&mut root, &path, line_number)?;
            context = path.into_iter().map(PathPart::Key).collect();
        } else {
            let (key, raw_value) = line
                .split_once('=')
                .ok_or_else(|| line_error(line_number, "expected key = value"))?;
            let key = key.trim();
            if !valid_key(key) {
                return Err(line_error(line_number, "unsupported key syntax"));
            }
            let value = parse_toml_value(raw_value.trim())
                .map_err(|message| line_error(line_number, &message))?;
            let table = value_at_path_mut(&mut root, &context)
                .ok_or_else(|| line_error(line_number, "key is outside a valid table"))?;
            let object = table
                .as_object_mut()
                .ok_or_else(|| line_error(line_number, "key target is not a table"))?;
            if object.insert(key.to_owned(), value).is_some() {
                return Err(line_error(line_number, "duplicate key"));
            }
        }
    }
    Ok(root)
}

fn parse_header(value: &str, line_number: usize) -> Result<Vec<String>, ProfileError> {
    let path = value.split('.').map(str::trim).collect::<Vec<_>>();
    if path.is_empty() || path.iter().any(|part| !valid_key(part)) {
        return Err(line_error(line_number, "unsupported table name"));
    }
    Ok(path.into_iter().map(str::to_owned).collect())
}

fn ensure_object_path(
    root: &mut Value,
    path: &[String],
    line_number: usize,
) -> Result<(), ProfileError> {
    let mut current = root;
    for part in path {
        let object = current
            .as_object_mut()
            .ok_or_else(|| line_error(line_number, "table path conflicts with a value"))?;
        let entry = object
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            return Err(line_error(line_number, "table path conflicts with a value"));
        }
        current = entry;
    }
    Ok(())
}

fn value_at_path_mut<'a>(root: &'a mut Value, path: &[PathPart]) -> Option<&'a mut Value> {
    let Some((part, remaining)) = path.split_first() else {
        return Some(root);
    };
    let next = match part {
        PathPart::Key(key) => root.as_object_mut()?.get_mut(key)?,
        PathPart::Index(index) => root.as_array_mut()?.get_mut(*index)?,
    };
    value_at_path_mut(next, remaining)
}

fn parse_toml_value(value: &str) -> Result<Value, String> {
    if value.starts_with('[') && value.ends_with(']') {
        let inner = &value[1..value.len() - 1];
        let mut values = Vec::new();
        for item in split_array(inner)? {
            if item.trim().is_empty() {
                continue;
            }
            values.push(parse_scalar(item.trim())?);
        }
        return Ok(Value::Array(values));
    }
    parse_scalar(value)
}

fn parse_scalar(value: &str) -> Result<Value, String> {
    serde_json::from_str(value)
        .map_err(|_| "only JSON-compatible TOML scalar values are supported".to_owned())
}

fn split_array(value: &str) -> Result<Vec<&str>, String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut in_string = false;
    let mut escaped = false;
    for (index, character) in value.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
        } else if character == ',' {
            parts.push(&value[start..index]);
            start = index + character.len_utf8();
        }
    }
    if in_string || escaped {
        return Err("unterminated string in array".to_owned());
    }
    parts.push(&value[start..]);
    Ok(parts)
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_string = false;
    let mut escaped = false;
    for (index, character) in line.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
        } else if character == '"' {
            in_string = true;
        } else if character == '#' {
            return &line[..index];
        }
    }
    line
}

fn valid_key(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "_-".contains(character))
}

fn line_error(line_number: usize, message: &str) -> ProfileError {
    ProfileError::InvalidProfile(format!("line {}: {message}", line_number + 1))
}
