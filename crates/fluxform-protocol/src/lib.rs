use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum ProtocolVersionV1 {
    #[serde(rename = "v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CategoryV1 {
    Video,
    Audio,
    Image,
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputTargetV1 {
    ManagedArtifact,
    LocalDirectory { directory_token: String },
    LocalPath { path_token: String },
    ManagedJobDirectory,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OutputTargetWireV1 {
    ManagedArtifact {},
    LocalDirectory { directory_token: String },
    LocalPath { path_token: String },
    ManagedJobDirectory {},
}

impl<'de> Deserialize<'de> for OutputTargetV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match OutputTargetWireV1::deserialize(deserializer)? {
            OutputTargetWireV1::ManagedArtifact {} => Self::ManagedArtifact,
            OutputTargetWireV1::LocalDirectory { directory_token } => {
                Self::LocalDirectory { directory_token }
            }
            OutputTargetWireV1::LocalPath { path_token } => Self::LocalPath { path_token },
            OutputTargetWireV1::ManagedJobDirectory {} => Self::ManagedJobDirectory,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverwritePolicyV1 {
    Reject,
    Rename,
    Replace,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum ResizeModeV1 {
    #[default]
    Contain,
    Cover,
    Stretch,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AudioRetentionV1 {
    #[default]
    Preserve,
    Remove,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlphaHandlingV1 {
    #[default]
    Preserve,
    CompositeWhite,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RationalV1 {
    pub numerator: u32,
    pub denominator: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct VideoOptionsV1 {
    pub encoder: Option<String>,
    pub preset: Option<String>,
    pub quality: Option<u8>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub resize_mode: ResizeModeV1,
    pub frame_rate: Option<RationalV1>,
    pub aspect_ratio: Option<RationalV1>,
    pub audio: AudioRetentionV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct AudioOptionsV1 {
    pub encoder: Option<String>,
    pub bitrate_kbps: Option<u32>,
    pub sample_rate_hz: Option<u32>,
    pub channels: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ImageOptionsV1 {
    pub quality: Option<u8>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub resize_mode: ResizeModeV1,
    pub alpha_handling: AlphaHandlingV1,
    pub apply_orientation: bool,
}

impl Default for ImageOptionsV1 {
    fn default() -> Self {
        Self {
            quality: None,
            width: None,
            height: None,
            resize_mode: ResizeModeV1::Contain,
            alpha_handling: AlphaHandlingV1::Preserve,
            apply_orientation: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ConversionOptionsV1 {
    pub video: Option<VideoOptionsV1>,
    pub audio: Option<AudioOptionsV1>,
    pub image: Option<ImageOptionsV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(default, deny_unknown_fields)]
pub struct ClientContextV1 {
    pub request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConversionRequestV1 {
    pub protocol_version: ProtocolVersionV1,
    pub input_ids: Vec<String>,
    pub category: CategoryV1,
    pub output_format: String,
    pub output_target: OutputTargetV1,
    pub overwrite_policy: OverwritePolicyV1,
    pub options: ConversionOptionsV1,
    pub client_context: ClientContextV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum JobStateV1 {
    Created,
    Validating,
    Queued,
    Probing,
    Converting,
    Finalizing,
    Completed,
    Failed,
    Cancelling,
    Cancelled,
    Interrupted,
}

mod positive_revision {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if *value == 0 {
            return Err(serde::ser::Error::custom("revision must be positive"));
        }
        serializer.serialize_u64(*value)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = u64::deserialize(deserializer)?;
        if value == 0 {
            return Err(serde::de::Error::custom("revision must be positive"));
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum JobEventV1 {
    #[serde(rename = "job.state_changed")]
    StateChanged {
        job_id: String,
        #[serde(with = "positive_revision")]
        #[schemars(with = "u64", range(min = 1))]
        revision: u64,
        state: JobStateV1,
    },
    #[serde(rename = "job.progress")]
    Progress {
        job_id: String,
        #[serde(with = "positive_revision")]
        #[schemars(with = "u64", range(min = 1))]
        revision: u64,
        progress_percent: u8,
    },
    #[serde(rename = "job.warning")]
    Warning {
        job_id: String,
        #[serde(with = "positive_revision")]
        #[schemars(with = "u64", range(min = 1))]
        revision: u64,
        message: String,
    },
    #[serde(rename = "job.completed")]
    Completed {
        job_id: String,
        #[serde(with = "positive_revision")]
        #[schemars(with = "u64", range(min = 1))]
        revision: u64,
        artifact_id: String,
    },
    #[serde(rename = "job.failed")]
    Failed {
        job_id: String,
        #[serde(with = "positive_revision")]
        #[schemars(with = "u64", range(min = 1))]
        revision: u64,
        error: ApiErrorV1,
    },
    #[serde(rename = "queue.position_changed")]
    QueuePositionChanged {
        job_id: String,
        #[serde(with = "positive_revision")]
        #[schemars(with = "u64", range(min = 1))]
        revision: u64,
        position: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct JobSnapshotV1 {
    pub job_id: String,
    pub revision: u64,
    pub state: JobStateV1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCodeV1 {
    UnsupportedInput,
    UnsupportedConversion,
    MixedCategory,
    InvalidOption,
    FileTooLarge,
    QuotaExceeded,
    QueueFull,
    FfprobeFailed,
    ConversionFailed,
    OutputTooLarge,
    Timeout,
    Cancelled,
    Interrupted,
    StorageUnavailable,
}

impl ErrorCodeV1 {
    #[must_use]
    pub const fn public_message(self) -> &'static str {
        match self {
            Self::UnsupportedInput => "input format is not supported",
            Self::UnsupportedConversion => "requested conversion is not supported",
            Self::MixedCategory => "inputs must use one conversion category",
            Self::InvalidOption => "one or more conversion options are invalid",
            Self::FileTooLarge => "input exceeds the allowed size",
            Self::QuotaExceeded => "conversion quota has been exceeded",
            Self::QueueFull => "conversion queue is full",
            Self::FfprobeFailed => "media inspection failed",
            Self::ConversionFailed => "conversion failed",
            Self::OutputTooLarge => "output exceeds the allowed size",
            Self::Timeout => "conversion timed out",
            Self::Cancelled => "conversion was cancelled",
            Self::Interrupted => "conversion was interrupted",
            Self::StorageUnavailable => "artifact storage is unavailable",
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("diagnostic ID must start with 'diag_' and contain only ASCII letters, digits, '_' or '-'")]
pub struct InvalidDiagnosticIdV1;

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct DiagnosticIdV1(
    #[schemars(regex(pattern = r"^diag_[A-Za-z0-9_-]+$"), length(max = 128))] String,
);

impl DiagnosticIdV1 {
    pub fn new(value: impl Into<String>) -> Result<Self, InvalidDiagnosticIdV1> {
        let value = value.into();
        let suffix = value.strip_prefix("diag_").unwrap_or_default();
        if suffix.is_empty()
            || value.len() > 128
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(InvalidDiagnosticIdV1);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DiagnosticIdV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApiErrorV1 {
    code: ErrorCodeV1,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    diagnostic_id: Option<DiagnosticIdV1>,
}

impl ApiErrorV1 {
    #[must_use]
    pub fn new(code: ErrorCodeV1) -> Self {
        Self {
            code,
            message: code.public_message().to_owned(),
            diagnostic_id: None,
        }
    }

    #[must_use]
    pub fn with_diagnostic_id(code: ErrorCodeV1, diagnostic_id: DiagnosticIdV1) -> Self {
        Self {
            code,
            message: code.public_message().to_owned(),
            diagnostic_id: Some(diagnostic_id),
        }
    }

    #[must_use]
    pub const fn code(&self) -> ErrorCodeV1 {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    #[must_use]
    pub fn diagnostic_id(&self) -> Option<&str> {
        self.diagnostic_id.as_ref().map(DiagnosticIdV1::as_str)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApiErrorWireV1 {
    code: ErrorCodeV1,
    message: String,
    diagnostic_id: Option<DiagnosticIdV1>,
}

impl<'de> Deserialize<'de> for ApiErrorV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ApiErrorWireV1::deserialize(deserializer)?;
        if wire.message != wire.code.public_message() {
            return Err(serde::de::Error::custom(
                "message must match the stable public message for the error code",
            ));
        }
        Ok(Self {
            code: wire.code,
            message: wire.message,
            diagnostic_id: wire.diagnostic_id,
        })
    }
}

#[must_use]
pub fn canonical_fixtures() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "contracts/v1/fixtures/completed-image-job.json",
            serde_json::to_value(JobEventV1::Completed {
                job_id: "job_image_01".to_owned(),
                revision: 4,
                artifact_id: "artifact_image_01".to_owned(),
            })
            .expect("canonical completed event must serialize"),
        ),
        (
            "contracts/v1/fixtures/create-image-job.json",
            serde_json::to_value(ConversionRequestV1 {
                protocol_version: ProtocolVersionV1::V1,
                input_ids: vec!["input_image_01".to_owned(), "input_image_02".to_owned()],
                category: CategoryV1::Image,
                output_format: "png".to_owned(),
                output_target: OutputTargetV1::ManagedArtifact,
                overwrite_policy: OverwritePolicyV1::Reject,
                options: ConversionOptionsV1 {
                    image: Some(ImageOptionsV1 {
                        quality: Some(90),
                        width: Some(1920),
                        height: Some(1080),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                client_context: ClientContextV1 {
                    request_id: Some("request_image_01".to_owned()),
                },
            })
            .expect("canonical conversion request must serialize"),
        ),
        (
            "contracts/v1/fixtures/unsupported-conversion.json",
            serde_json::to_value(ApiErrorV1::new(ErrorCodeV1::UnsupportedConversion))
                .expect("canonical API error must serialize"),
        ),
    ])
}

#[must_use]
pub fn exported_contracts() -> BTreeMap<&'static str, Value> {
    let mut job_event_schema = serde_json::to_value(schemars::schema_for!(JobEventV1))
        .expect("job event schema must serialize");
    job_event_schema
        .pointer_mut("/$defs/ApiErrorV1")
        .and_then(Value::as_object_mut)
        .expect("job event schema must define ApiErrorV1")
        .insert("allOf".to_owned(), Value::Array(error_conditions()));

    let mut contracts = BTreeMap::from([
        (
            "contracts/v1/conversion-request.schema.json",
            serde_json::to_value(schemars::schema_for!(ConversionRequestV1))
                .expect("conversion request schema must serialize"),
        ),
        ("contracts/v1/error.schema.json", error_schema()),
        ("contracts/v1/job-event.schema.json", job_event_schema),
    ]);
    contracts.extend(canonical_fixtures());
    contracts
}

fn error_schema() -> Value {
    let mut schema = serde_json::to_value(schemars::schema_for!(ApiErrorV1))
        .expect("API error schema must serialize");
    schema
        .as_object_mut()
        .expect("root schema must be an object")
        .insert("allOf".to_owned(), Value::Array(error_conditions()));
    schema
}

fn error_conditions() -> Vec<Value> {
    [
        ErrorCodeV1::UnsupportedInput,
        ErrorCodeV1::UnsupportedConversion,
        ErrorCodeV1::MixedCategory,
        ErrorCodeV1::InvalidOption,
        ErrorCodeV1::FileTooLarge,
        ErrorCodeV1::QuotaExceeded,
        ErrorCodeV1::QueueFull,
        ErrorCodeV1::FfprobeFailed,
        ErrorCodeV1::ConversionFailed,
        ErrorCodeV1::OutputTooLarge,
        ErrorCodeV1::Timeout,
        ErrorCodeV1::Cancelled,
        ErrorCodeV1::Interrupted,
        ErrorCodeV1::StorageUnavailable,
    ]
    .into_iter()
    .map(|code| {
        json!({
            "if": {
                "properties": { "code": { "const": code } },
                "required": ["code"]
            },
            "then": {
                "properties": { "message": { "const": code.public_message() } }
            }
        })
    })
    .collect()
}

#[must_use]
pub fn contract_digest() -> String {
    let normalized =
        serde_json::to_vec(&exported_contracts()).expect("normalized contracts must serialize");
    format!("{:x}", Sha256::digest(normalized))
}
