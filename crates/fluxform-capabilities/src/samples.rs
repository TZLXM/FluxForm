use serde::Deserialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

use crate::{CapabilityManifestV1, ConversionCategory};

const MAX_SAMPLE_BYTES: u64 = 512 * 1024;
const MAX_CORPUS_BYTES: u64 = 10 * 1024 * 1024;
const ANIMATED_INVALID_IDS: &[&str] = &[
    "image-gif-animated-v1",
    "image-webp-animated-v1",
    "image-tiff-multipage-v1",
];

#[derive(Debug, Error)]
pub enum SampleCatalogError {
    #[error("could not read sample catalog or corpus file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("invalid sample catalog {path}: {message}")]
    Invalid { path: PathBuf, message: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SampleDocument {
    catalog_version: String,
    samples: Vec<SampleRecordV1>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleRecordV1 {
    pub id: String,
    pub path: String,
    pub sha256: String,
    pub provenance: String,
    pub license: String,
    pub category: String,
    pub container: String,
    pub codecs: Vec<String>,
    pub stream_topology: String,
    pub width: u32,
    pub height: u32,
    pub duration_ms: u64,
    pub alpha: String,
    pub orientation: String,
    pub metadata: String,
    pub expected_outcome: String,
    pub expected_error_code: String,
    #[serde(skip)]
    pub size_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct SampleCatalogV1 {
    catalog_path: PathBuf,
    samples: Vec<SampleRecordV1>,
}

impl SampleCatalogV1 {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, SampleCatalogError> {
        let catalog_path = path.as_ref();
        let text = fs::read_to_string(catalog_path).map_err(|source| SampleCatalogError::Io {
            path: catalog_path.to_path_buf(),
            source,
        })?;
        let value = parse_catalog_subset(&text).map_err(|message| SampleCatalogError::Invalid {
            path: catalog_path.to_path_buf(),
            message,
        })?;
        let mut document: SampleDocument =
            serde_json::from_value(value).map_err(|error| SampleCatalogError::Invalid {
                path: catalog_path.to_path_buf(),
                message: error.to_string(),
            })?;
        if document.catalog_version != "v1" || document.samples.is_empty() {
            return Err(invalid(
                catalog_path,
                "catalog_version must be v1 and samples must not be empty",
            ));
        }

        let corpus_root = catalog_path.parent().unwrap_or_else(|| Path::new("."));
        let files_root = corpus_root.join("files");
        let files_metadata =
            fs::symlink_metadata(&files_root).map_err(|source| SampleCatalogError::Io {
                path: files_root.clone(),
                source,
            })?;
        if files_metadata.file_type().is_symlink() || !files_metadata.is_dir() {
            return Err(invalid(
                catalog_path,
                "files/ must be a real directory, not a symlink",
            ));
        }

        let mut inventory = BTreeMap::new();
        let mut total_size = 0u64;
        let entries = fs::read_dir(&files_root).map_err(|source| SampleCatalogError::Io {
            path: files_root.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| SampleCatalogError::Io {
                path: files_root.clone(),
                source,
            })?;
            let entry_path = entry.path();
            let file_type = entry.file_type().map_err(|source| SampleCatalogError::Io {
                path: entry_path.clone(),
                source,
            })?;
            if file_type.is_symlink() || !file_type.is_file() {
                return Err(invalid(
                    catalog_path,
                    &format!(
                        "corpus entry {} is not a regular file",
                        entry_path.display()
                    ),
                ));
            }
            let metadata = entry.metadata().map_err(|source| SampleCatalogError::Io {
                path: entry_path.clone(),
                source,
            })?;
            let size = metadata.len();
            if size == 0 || size > MAX_SAMPLE_BYTES {
                return Err(invalid(
                    catalog_path,
                    &format!(
                        "corpus file {} is empty or exceeds 512 KiB",
                        entry_path.display()
                    ),
                ));
            }
            total_size = total_size.saturating_add(size);
            if total_size > MAX_CORPUS_BYTES {
                return Err(invalid(
                    catalog_path,
                    "complete sample corpus exceeds 10 MiB",
                ));
            }
            let name = entry.file_name();
            let name = name.to_string_lossy().into_owned();
            if inventory.insert(name, size).is_some() {
                return Err(invalid(catalog_path, "duplicate file in corpus directory"));
            }
        }

        let mut ids = BTreeSet::new();
        let mut referenced_files = BTreeSet::new();
        for sample in &mut document.samples {
            if sample.id.trim().is_empty()
                || sample.provenance.trim().is_empty()
                || sample.license.trim().is_empty()
                || sample.container.trim().is_empty()
                || sample.codecs.is_empty()
                || sample.alpha.trim().is_empty()
                || sample.orientation.trim().is_empty()
                || sample.metadata.trim().is_empty()
            {
                return Err(invalid(
                    catalog_path,
                    &format!("sample {} has an empty required field", sample.id),
                ));
            }
            if !matches!(
                sample.alpha.as_str(),
                "present" | "absent" | "not_applicable"
            ) || !matches!(
                sample.orientation.as_str(),
                "present" | "none" | "not_applicable"
            ) || !matches!(sample.metadata.as_str(), "present" | "none")
            {
                return Err(invalid(
                    catalog_path,
                    &format!(
                        "sample {} has noncanonical alpha, orientation, or metadata state",
                        sample.id
                    ),
                ));
            }
            if !ids.insert(sample.id.clone()) {
                return Err(invalid(
                    catalog_path,
                    &format!("duplicate sample ID {}", sample.id),
                ));
            }
            let category_ok = matches!(sample.category.as_str(), "video" | "audio" | "image");
            let topology_ok = matches!(
                sample.stream_topology.as_str(),
                "single_video_stream"
                    | "single_audio_stream"
                    | "single_video_frame"
                    | "multiple_video_frames"
            );
            if !category_ok || !topology_ok {
                return Err(invalid(
                    catalog_path,
                    &format!(
                        "sample {} has invalid category or stream topology",
                        sample.id
                    ),
                ));
            }
            match sample.expected_outcome.as_str() {
                "success" if sample.expected_error_code.is_empty() => {}
                "error" if !sample.expected_error_code.trim().is_empty() => {}
                _ => {
                    return Err(invalid(
                        catalog_path,
                        &format!("sample {} has inconsistent outcome/error code", sample.id),
                    ));
                }
            }
            let relative = Path::new(&sample.path);
            let mut components = relative.components();
            let safe = matches!(components.next(), Some(Component::Normal(part)) if part == "files")
                && matches!(components.next(), Some(Component::Normal(_)))
                && components.next().is_none();
            if !safe || relative.is_absolute() {
                return Err(invalid(
                    catalog_path,
                    &format!("sample {} path must be a direct child of files/", sample.id),
                ));
            }
            let file_name = relative
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| invalid(catalog_path, "sample filename must be valid UTF-8"))?;
            if !referenced_files.insert(file_name.to_owned()) {
                return Err(invalid(
                    catalog_path,
                    &format!("corpus file {file_name} is referenced more than once"),
                ));
            }
            let sample_path = corpus_root.join(relative);
            let bytes = fs::read(&sample_path).map_err(|source| SampleCatalogError::Io {
                path: sample_path.clone(),
                source,
            })?;
            sample.size_bytes = bytes.len() as u64;
            if inventory.get(file_name) != Some(&sample.size_bytes) {
                return Err(invalid(
                    catalog_path,
                    &format!(
                        "sample {} corpus inventory changed while loading",
                        sample.id
                    ),
                ));
            }
            let actual_hash = sha256(&bytes);
            if !is_lower_sha256(&sample.sha256) || sample.sha256 != actual_hash {
                return Err(invalid(
                    catalog_path,
                    &format!("sample {} SHA-256 mismatch", sample.id),
                ));
            }
        }
        if inventory.keys().cloned().collect::<BTreeSet<_>>() != referenced_files {
            return Err(invalid(
                catalog_path,
                "files/ must contain exactly the catalog's referenced sample bytes",
            ));
        }

        Ok(Self {
            catalog_path: catalog_path.to_path_buf(),
            samples: document.samples,
        })
    }

    pub fn samples(&self) -> &[SampleRecordV1] {
        &self.samples
    }

    pub fn find(&self, id: &str) -> Option<&SampleRecordV1> {
        self.samples.iter().find(|sample| sample.id == id)
    }

    pub fn sample_path(&self, id: &str) -> Option<PathBuf> {
        self.find(id).map(|sample| {
            self.catalog_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(&sample.path)
        })
    }

    pub fn validate_manifest_samples(
        &self,
        manifest: &CapabilityManifestV1,
    ) -> Result<(), SampleCatalogError> {
        let mut expected: BTreeMap<&str, (&str, bool)> = BTreeMap::new();
        for edge in manifest.edges() {
            for id in &edge.valid_samples {
                if expected
                    .insert(id, (category_name(edge.category), true))
                    .is_some()
                {
                    return Err(invalid(
                        &self.catalog_path,
                        &format!("sample {id} is referenced more than once"),
                    ));
                }
            }
            for id in &edge.invalid_samples {
                if expected
                    .insert(id, (category_name(edge.category), false))
                    .is_some()
                {
                    return Err(invalid(
                        &self.catalog_path,
                        &format!("sample {id} is referenced more than once"),
                    ));
                }
            }
        }
        let actual = self
            .samples
            .iter()
            .map(|sample| sample.id.as_str())
            .collect::<BTreeSet<_>>();
        let referenced = expected.keys().copied().collect::<BTreeSet<_>>();
        if actual != referenced {
            return Err(invalid(
                &self.catalog_path,
                "catalog samples must equal the manifest's exact valid/invalid sample references",
            ));
        }
        for sample in &self.samples {
            let (expected_category, should_succeed) = expected[sample.id.as_str()];
            if sample.category != expected_category
                || (sample.expected_outcome == "success") != should_succeed
            {
                return Err(invalid(
                    &self.catalog_path,
                    &format!(
                        "sample {} category/outcome disagrees with its manifest reference",
                        sample.id
                    ),
                ));
            }
        }
        for id in ANIMATED_INVALID_IDS {
            let sample = self.find(id).ok_or_else(|| {
                invalid(
                    &self.catalog_path,
                    &format!("required invalid sample {id} is missing"),
                )
            })?;
            if sample.expected_outcome != "error"
                || sample.expected_error_code != "unsupported_conversion"
            {
                return Err(invalid(
                    &self.catalog_path,
                    &format!("{id} must be an unsupported_conversion invalid case"),
                ));
            }
        }
        if self.samples.iter().any(|sample| {
            sample.expected_error_code == "unsupported_conversion"
                && !ANIMATED_INVALID_IDS.contains(&sample.id.as_str())
        }) {
            return Err(invalid(
                &self.catalog_path,
                "only animated GIF, animated WebP, and multipage TIFF may use unsupported_conversion in v1",
            ));
        }
        Ok(())
    }
}

fn parse_catalog_subset(input: &str) -> Result<Value, String> {
    let mut root = Map::new();
    let mut samples = Vec::<Value>::new();
    let mut current: Option<Map<String, Value>> = None;
    for (index, raw) in input.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line == "[[samples]]" {
            if let Some(sample) = current.take() {
                samples.push(Value::Object(sample));
            }
            current = Some(Map::new());
            continue;
        }
        let (key, raw_value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {line_number}: expected key = value"))?;
        let key = key.trim();
        if key.is_empty()
            || !key.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            })
        {
            return Err(format!("line {line_number}: unsupported key syntax"));
        }
        let value: Value = serde_json::from_str(raw_value.trim())
            .map_err(|error| format!("line {line_number}: expected a basic string, string array, integer, or boolean: {error}"))?;
        let table = current.as_mut().unwrap_or(&mut root);
        if table.insert(key.to_owned(), value).is_some() {
            return Err(format!("line {line_number}: duplicate key {key}"));
        }
    }
    if let Some(sample) = current {
        samples.push(Value::Object(sample));
    }
    if root.len() != 1 || !root.contains_key("catalog_version") {
        return Err("root must contain only catalog_version".to_owned());
    }
    root.insert("samples".to_owned(), Value::Array(samples));
    Ok(Value::Object(root))
}

fn category_name(category: ConversionCategory) -> &'static str {
    match category {
        ConversionCategory::Image => "image",
        ConversionCategory::Audio => "audio",
        ConversionCategory::Video => "video",
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn is_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn invalid(path: &Path, message: &str) -> SampleCatalogError {
    SampleCatalogError::Invalid {
        path: path.to_path_buf(),
        message: message.to_owned(),
    }
}
