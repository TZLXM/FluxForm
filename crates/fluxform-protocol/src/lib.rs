use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

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
pub struct DiagnosticIdV1(String);

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
