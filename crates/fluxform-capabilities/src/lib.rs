use serde::Deserialize;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

use fluxform_ffmpeg_profile::{BuildProfile, ProbeReport, ProfileError};

pub type TargetTriple = String;

const PROFILE_TARGETS: &[(&str, &str)] = &[
    ("windows-x86_64", "x86_64-pc-windows-msvc"),
    ("macos-aarch64", "aarch64-apple-darwin"),
    ("macos-x86_64", "x86_64-apple-darwin"),
    ("linux-x86_64", "x86_64-unknown-linux-gnu"),
];

#[derive(Debug, Error)]
pub enum ManifestError {
    #[error("could not read {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not load FFmpeg profile {path}: {source}")]
    ProfileLoad {
        path: PathBuf,
        #[source]
        source: ProfileError,
    },
    #[error("invalid capability manifest: {0}")]
    Invalid(String),
    #[error("invalid capability manifest TOML at line {line}: {message}")]
    InvalidToml { line: usize, message: String },
    #[error("the FFmpeg distribution gate is blocked")]
    DistributionGateBlocked,
    #[error("probe report target {report_target} is stored under target key {map_target}")]
    ReportTargetMismatch {
        map_target: String,
        report_target: String,
    },
    #[error("probe report for {target} does not match an approved artifact identity: {source}")]
    ReportIdentity {
        target: String,
        #[source]
        source: ProfileError,
    },
    #[error("required platform profile is missing: {0}")]
    MissingProfile(String),
    #[error("required {kind} is missing from profile {profile_id}: {capability}")]
    MissingCapability {
        kind: &'static str,
        profile_id: String,
        capability: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConversionCategory {
    Image,
    Audio,
    Video,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputTopology {
    SingleVideoFrame,
    SingleVideoStream,
    SingleAudioStream,
    SingleVideoAndAudio,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlphaPolicy {
    PreserveIfPresent,
    Composite,
    Discard,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrientationPolicy {
    ApplyToPixels,
    PreserveTag,
    Ignore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataPolicy {
    SafeImageMetadata,
    Preserve,
    Strip,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDocument {
    manifest_version: String,
    edges: Vec<ConversionEdgeV1>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConversionEdgeV1 {
    pub id: String,
    pub category: ConversionCategory,
    pub input_extensions: Vec<String>,
    pub input_demuxers: Vec<String>,
    pub input_codecs: Vec<String>,
    pub input_topology: InputTopology,
    pub output_format: String,
    pub output_muxer: String,
    #[serde(default)]
    pub video_codec: Option<String>,
    #[serde(default)]
    pub audio_codec: Option<String>,
    pub stream_map: Vec<String>,
    pub alpha_policy: AlphaPolicy,
    pub orientation_policy: OrientationPolicy,
    pub metadata_policy: MetadataPolicy,
    pub profile_ids: Vec<String>,
    pub valid_samples: Vec<String>,
    pub invalid_samples: Vec<String>,
    pub options: BTreeMap<String, ParameterBounds>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterBounds {
    pub minimum: i64,
    pub maximum: i64,
    pub default: i64,
}

#[derive(Debug, Clone)]
pub struct InputProbeV1 {
    pub extension: String,
    pub demuxer: String,
    pub codec: String,
    pub topology: String,
}

#[derive(Debug, Clone)]
pub struct CapabilityManifestV1 {
    edges: Vec<ConversionEdgeV1>,
    profile_path: PathBuf,
}

impl CapabilityManifestV1 {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ManifestError> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|source| ManifestError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let value = parse_toml_subset(&contents)?;
        let mut document: ManifestDocument = serde_json::from_value(value)
            .map_err(|error| ManifestError::Invalid(error.to_string()))?;
        validate_document(&mut document)?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        Ok(Self {
            edges: document.edges,
            profile_path: parent.join("ffmpeg-profile.toml"),
        })
    }

    pub fn validate_profiles(
        &self,
        reports: &BTreeMap<TargetTriple, ProbeReport>,
    ) -> Result<(), ManifestError> {
        let profile = BuildProfile::load(&self.profile_path).map_err(|source| {
            ManifestError::ProfileLoad {
                path: self.profile_path.clone(),
                source,
            }
        })?;
        if !profile.gate_is_approved() {
            return Err(ManifestError::DistributionGateBlocked);
        }

        for (map_target, report) in reports {
            if report.target_triple != *map_target {
                return Err(ManifestError::ReportTargetMismatch {
                    map_target: map_target.clone(),
                    report_target: report.target_triple.clone(),
                });
            }
            let approved = profile
                .approved_artifact(&report.artifact_id)
                .map_err(|source| ManifestError::ReportIdentity {
                    target: map_target.clone(),
                    source,
                })?;
            report
                .verify_identity(&approved)
                .map_err(|source| ManifestError::ReportIdentity {
                    target: map_target.clone(),
                    source,
                })?;
        }

        for edge in &self.edges {
            for profile_id in &edge.profile_ids {
                let target = target_for_profile_id(profile_id)
                    .ok_or_else(|| ManifestError::MissingProfile(profile_id.clone()))?;
                let report = reports
                    .get(target)
                    .ok_or_else(|| ManifestError::MissingProfile(profile_id.clone()))?;
                validate_edge_against_report(edge, profile_id, report)?;
            }
        }
        Ok(())
    }

    pub fn find_edge(
        &self,
        category: ConversionCategory,
        input_probe: &InputProbeV1,
        output_format: &str,
    ) -> Option<&ConversionEdgeV1> {
        let extension = normalize_extension(&input_probe.extension);
        self.edges.iter().find(|edge| {
            edge.category == category
                && edge
                    .input_extensions
                    .iter()
                    .any(|candidate| candidate == &extension)
                && edge
                    .input_demuxers
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&input_probe.demuxer))
                && edge
                    .input_codecs
                    .iter()
                    .any(|candidate| candidate.eq_ignore_ascii_case(&input_probe.codec))
                && edge.input_topology.as_str() == input_probe.topology
                && edge.output_format.eq_ignore_ascii_case(output_format)
        })
    }

    pub fn edges(&self) -> &[ConversionEdgeV1] {
        &self.edges
    }
}

impl InputTopology {
    fn as_str(self) -> &'static str {
        match self {
            Self::SingleVideoFrame => "single_video_frame",
            Self::SingleVideoStream => "single_video_stream",
            Self::SingleAudioStream => "single_audio_stream",
            Self::SingleVideoAndAudio => "single_video_and_audio",
        }
    }
}

fn validate_document(document: &mut ManifestDocument) -> Result<(), ManifestError> {
    if document.manifest_version != "v1" {
        return Err(ManifestError::Invalid(format!(
            "unsupported manifest_version {:?}",
            document.manifest_version
        )));
    }
    if document.edges.is_empty() {
        return Err(ManifestError::Invalid("edges must not be empty".to_owned()));
    }

    let mut edge_ids = BTreeSet::new();
    for edge in &mut document.edges {
        require_nonempty("edge id", &edge.id)?;
        if !edge_ids.insert(edge.id.as_str()) {
            return Err(ManifestError::Invalid(format!(
                "duplicate edge id {}",
                edge.id
            )));
        }

        for extension in &mut edge.input_extensions {
            *extension = normalize_extension(extension);
            if extension.is_empty()
                || extension.contains('.')
                || extension
                    .chars()
                    .any(|character| character.is_whitespace() || matches!(character, '/' | '\\'))
            {
                return Err(ManifestError::Invalid(format!(
                    "edge {} has invalid input extension {:?}",
                    edge.id, extension
                )));
            }
        }
        validate_names("input_extensions", &edge.input_extensions, true)?;
        validate_names("input_demuxers", &edge.input_demuxers, true)?;
        if edge.input_demuxers.len() != 1 {
            return Err(ManifestError::Invalid(format!(
                "edge {} must declare exactly one input demuxer; use another edge for a different demuxer",
                edge.id
            )));
        }
        validate_names("input_codecs", &edge.input_codecs, true)?;
        if edge.input_codecs.len() != 1 {
            return Err(ManifestError::Invalid(format!(
                "edge {} must declare exactly one input codec; use another edge for a different codec",
                edge.id
            )));
        }
        validate_name("output_format", &edge.output_format, true)?;
        validate_name("output_muxer", &edge.output_muxer, true)?;
        if let Some(codec) = &edge.video_codec {
            validate_name("video_codec", codec, true)?;
        }
        if let Some(codec) = &edge.audio_codec {
            validate_name("audio_codec", codec, true)?;
        }
        if edge.video_codec.is_none() && edge.audio_codec.is_none() {
            return Err(ManifestError::Invalid(format!(
                "edge {} must declare an output video_codec or audio_codec",
                edge.id
            )));
        }
        validate_names("stream_map", &edge.stream_map, true)?;
        validate_names("profile_ids", &edge.profile_ids, true)?;
        for profile_id in &edge.profile_ids {
            if target_for_profile_id(profile_id).is_none() {
                return Err(ManifestError::Invalid(format!(
                    "edge {} references unknown profile_id {profile_id}",
                    edge.id
                )));
            }
        }
        validate_names("valid_samples", &edge.valid_samples, false)?;
        validate_names("invalid_samples", &edge.invalid_samples, false)?;
        let valid = edge.valid_samples.iter().collect::<BTreeSet<_>>();
        if edge
            .invalid_samples
            .iter()
            .any(|sample| valid.contains(sample))
        {
            return Err(ManifestError::Invalid(format!(
                "edge {} uses a sample as both valid and invalid",
                edge.id
            )));
        }
        for (name, bounds) in &edge.options {
            require_nonempty("option name", name)?;
            if bounds.minimum > bounds.default || bounds.default > bounds.maximum {
                return Err(ManifestError::Invalid(format!(
                    "edge {} option {name} must satisfy minimum <= default <= maximum",
                    edge.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_edge_against_report(
    edge: &ConversionEdgeV1,
    profile_id: &str,
    report: &ProbeReport,
) -> Result<(), ManifestError> {
    for demuxer in &edge.input_demuxers {
        require_capability("demuxer", profile_id, demuxer, &report.demuxers)?;
    }
    for decoder in &edge.input_codecs {
        require_capability("decoder", profile_id, decoder, &report.decoders)?;
    }
    require_capability("muxer", profile_id, &edge.output_muxer, &report.muxers)?;
    if let Some(encoder) = &edge.video_codec {
        require_capability("encoder", profile_id, encoder, &report.encoders)?;
    }
    if let Some(encoder) = &edge.audio_codec {
        require_capability("encoder", profile_id, encoder, &report.encoders)?;
    }
    Ok(())
}

fn require_capability(
    kind: &'static str,
    profile_id: &str,
    capability: &str,
    available: &[String],
) -> Result<(), ManifestError> {
    if available
        .iter()
        .any(|item| item.eq_ignore_ascii_case(capability))
    {
        Ok(())
    } else {
        Err(ManifestError::MissingCapability {
            kind,
            profile_id: profile_id.to_owned(),
            capability: capability.to_owned(),
        })
    }
}

fn target_for_profile_id(profile_id: &str) -> Option<&'static str> {
    PROFILE_TARGETS
        .iter()
        .find_map(|(candidate, target)| (*candidate == profile_id).then_some(*target))
}

fn validate_names(
    field: &str,
    values: &[String],
    reject_wildcards: bool,
) -> Result<(), ManifestError> {
    if values.is_empty() {
        return Err(ManifestError::Invalid(format!("{field} must not be empty")));
    }
    validate_unique(field, values)?;
    for value in values {
        validate_name(field, value, reject_wildcards)?;
    }
    Ok(())
}

fn validate_unique(field: &str, values: &[String]) -> Result<(), ManifestError> {
    let unique = values.iter().collect::<BTreeSet<_>>();
    if unique.len() != values.len() {
        return Err(ManifestError::Invalid(format!(
            "{field} contains duplicate values"
        )));
    }
    for value in values {
        require_nonempty(field, value)?;
    }
    Ok(())
}

fn validate_name(field: &str, value: &str, reject_wildcards: bool) -> Result<(), ManifestError> {
    require_nonempty(field, value)?;
    if reject_wildcards
        && (value.contains('*') || value.contains('?') || value.eq_ignore_ascii_case("all"))
    {
        return Err(ManifestError::Invalid(format!(
            "{field} must name a concrete capability, got {value:?}"
        )));
    }
    Ok(())
}

fn require_nonempty(field: &str, value: &str) -> Result<(), ManifestError> {
    if value.trim().is_empty() {
        return Err(ManifestError::Invalid(format!("{field} must not be empty")));
    }
    Ok(())
}

fn normalize_extension(extension: &str) -> String {
    extension
        .strip_prefix('.')
        .unwrap_or(extension)
        .to_ascii_lowercase()
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PathPart {
    Key(String),
    Index(usize),
}

/// Parses the deliberately narrow capability-manifest TOML subset.
///
/// Supported syntax is UTF-8 text with simple bare keys, `[[edges]]`,
/// `[edges.options.<name>]`, double-quoted single-line basic strings using
/// `\"`, `\\`, `\b`, `\t`, `\n`, `\f`, `\r`, or `\uXXXX` escapes,
/// lowercase booleans, signed base-10 64-bit integers without separators or
/// leading zeroes, and single-line scalar arrays with an optional trailing
/// comma. Comments start with `#` outside strings. Other TOML forms (including
/// JSON `null`, floats, dates, literal or multiline strings, nested arrays,
/// quoted or dotted keys, and other table headers) are rejected.
fn parse_toml_subset(input: &str) -> Result<Value, ManifestError> {
    let mut root = Value::Object(Map::new());
    let mut context = Vec::new();
    let mut declared_tables = BTreeSet::new();

    for (line_index, original) in input.lines().enumerate() {
        let line_number = line_index + 1;
        let line = strip_comment(original).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[[") && line.ends_with("]]") {
            let path = parse_header(&line[2..line.len() - 2], line_number)?;
            if path.as_slice() != ["edges"] {
                return Err(toml_error(
                    line_number,
                    "only the [[edges]] array table is supported",
                ));
            }
            let object = root
                .as_object_mut()
                .ok_or_else(|| toml_error(line_number, "root is not a table"))?;
            let array = object
                .entry("edges".to_owned())
                .or_insert_with(|| Value::Array(Vec::new()));
            let array = array
                .as_array_mut()
                .ok_or_else(|| toml_error(line_number, "array table conflicts with a value"))?;
            let index = array.len();
            array.push(Value::Object(Map::new()));
            context = vec![PathPart::Key("edges".to_owned()), PathPart::Index(index)];
        } else if line.starts_with('[') && line.ends_with(']') {
            let path = parse_header(&line[1..line.len() - 1], line_number)?;
            if path.len() != 3 || path[0] != "edges" || path[1] != "options" {
                return Err(toml_error(
                    line_number,
                    "only [edges.options.<name>] tables are supported",
                ));
            }
            context = ensure_table_path(&mut root, &path, line_number)?;
            if !declared_tables.insert(context.clone()) {
                return Err(toml_error(line_number, "duplicate table header"));
            }
        } else {
            let (key, raw_value) = line
                .split_once('=')
                .ok_or_else(|| toml_error(line_number, "expected key = value"))?;
            let key = key.trim();
            if !valid_key(key) {
                return Err(toml_error(line_number, "unsupported key syntax"));
            }
            let value = parse_value(raw_value.trim())
                .map_err(|message| toml_error(line_number, &message))?;
            let table = value_at_path_mut(&mut root, &context)
                .ok_or_else(|| toml_error(line_number, "key is outside a valid table"))?;
            let object = table
                .as_object_mut()
                .ok_or_else(|| toml_error(line_number, "key target is not a table"))?;
            if object.insert(key.to_owned(), value).is_some() {
                return Err(toml_error(line_number, "duplicate key"));
            }
        }
    }
    Ok(root)
}

fn ensure_table_path(
    root: &mut Value,
    keys: &[String],
    line_number: usize,
) -> Result<Vec<PathPart>, ManifestError> {
    let mut context = Vec::new();
    for key in keys {
        let table = value_at_path_mut(root, &context)
            .ok_or_else(|| toml_error(line_number, "invalid table parent"))?;
        let object = table
            .as_object_mut()
            .ok_or_else(|| toml_error(line_number, "table parent is not a table"))?;
        let entry = object
            .entry(key.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        context.push(PathPart::Key(key.clone()));
        if let Some(array) = entry.as_array() {
            let index = array
                .len()
                .checked_sub(1)
                .ok_or_else(|| toml_error(line_number, "table array has no elements"))?;
            if !array[index].is_object() {
                return Err(toml_error(
                    line_number,
                    "table array element is not a table",
                ));
            }
            context.push(PathPart::Index(index));
        } else if !entry.is_object() {
            return Err(toml_error(line_number, "table path conflicts with a value"));
        }
    }
    Ok(context)
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

fn parse_header(value: &str, line_number: usize) -> Result<Vec<String>, ManifestError> {
    let path = value.split('.').map(str::trim).collect::<Vec<_>>();
    if path.is_empty() || path.iter().any(|part| !valid_key(part)) {
        return Err(toml_error(line_number, "unsupported table name"));
    }
    Ok(path.into_iter().map(str::to_owned).collect())
}

fn parse_value(value: &str) -> Result<Value, String> {
    if value.starts_with('[') || value.ends_with(']') {
        if !value.starts_with('[') || !value.ends_with(']') {
            return Err("malformed single-line array".to_owned());
        }
        let inner = &value[1..value.len() - 1];
        if inner.trim().is_empty() {
            return Ok(Value::Array(Vec::new()));
        }
        let items = split_array(inner)?;
        let last_index = items.len() - 1;
        let has_trailing_comma = inner.trim_end().ends_with(',');
        let mut values = Vec::new();
        for (index, item) in items.into_iter().enumerate() {
            if item.trim().is_empty() {
                if has_trailing_comma && index == last_index {
                    continue;
                }
                return Err("empty array element".to_owned());
            }
            values.push(parse_scalar(item.trim())?);
        }
        return Ok(Value::Array(values));
    }
    parse_scalar(value)
}

fn parse_scalar(value: &str) -> Result<Value, String> {
    if value.starts_with('"') {
        validate_basic_string(value)?;
        return serde_json::from_str(value)
            .map_err(|_| "invalid double-quoted TOML basic string".to_owned());
    }
    match value {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if is_decimal_integer(value) {
        let integer_text = value.strip_prefix('+').unwrap_or(value);
        let integer = integer_text
            .parse::<i64>()
            .map_err(|_| "TOML integer is outside the supported 64-bit range".to_owned())?;
        return Ok(Value::Number(integer.into()));
    }
    Err("expected a quoted string, lowercase boolean, or decimal integer".to_owned())
}

fn validate_basic_string(value: &str) -> Result<(), String> {
    if value.len() < 2 || !value.starts_with('"') || !value.ends_with('"') {
        return Err("malformed double-quoted TOML basic string".to_owned());
    }
    let inner = &value[1..value.len() - 1];
    let mut characters = inner.chars();
    while let Some(character) = characters.next() {
        match character {
            '"' => return Err("unescaped quote in TOML basic string".to_owned()),
            '\\' => match characters.next() {
                Some('b' | 't' | 'n' | 'f' | 'r' | '"' | '\\') => {}
                Some('u') => {
                    for _ in 0..4 {
                        if !characters
                            .next()
                            .is_some_and(|value| value.is_ascii_hexdigit())
                        {
                            return Err("invalid TOML unicode escape".to_owned());
                        }
                    }
                }
                _ => return Err("unsupported TOML basic string escape".to_owned()),
            },
            _ => {}
        }
    }
    Ok(())
}

fn is_decimal_integer(value: &str) -> bool {
    let digits = value
        .strip_prefix('-')
        .or_else(|| value.strip_prefix('+'))
        .unwrap_or(value);
    !digits.is_empty()
        && digits.bytes().all(|byte| byte.is_ascii_digit())
        && (digits == "0" || !digits.starts_with('0'))
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

fn strip_comment(line: &str) -> &str {
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

fn toml_error(line: usize, message: &str) -> ManifestError {
    ManifestError::InvalidToml {
        line,
        message: message.to_owned(),
    }
}
