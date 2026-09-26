use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvidenceError {
    #[error("evidence input closure error: {0}")]
    Invalid(String),
    #[error("could not read evidence input {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("cargo metadata could not run: {0}")]
    MetadataSpawn(#[source] io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceInputDigestV1 {
    pub digest: String,
    pub files: Vec<String>,
    pub local_packages: BTreeSet<String>,
}

#[derive(Debug, Deserialize)]
struct MetadataDocument {
    packages: Vec<MetadataPackage>,
}

#[derive(Debug, Deserialize)]
struct MetadataPackage {
    name: String,
    manifest_path: PathBuf,
    dependencies: Vec<MetadataDependency>,
}

#[derive(Debug, Deserialize)]
struct MetadataDependency {
    name: String,
    path: Option<PathBuf>,
}

pub fn compute_evidence_input_digest(
    repository_root: impl AsRef<Path>,
) -> Result<EvidenceInputDigestV1, EvidenceError> {
    let root = repository_root
        .as_ref()
        .canonicalize()
        .map_err(|source| EvidenceError::Io {
            path: repository_root.as_ref().to_path_buf(),
            source,
        })?;
    let local_packages = local_dependency_closure(&root)?;
    let mut inputs = BTreeMap::<String, Vec<u8>>::new();
    for relative in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
        "config/ffmpeg-profile.toml",
        "config/capabilities-v1.toml",
    ] {
        add_file(&root, &root.join(relative), &mut inputs)?;
    }
    add_tree(&root, &root.join("testdata/media/v1"), &mut inputs)?;
    for package in &local_packages {
        add_tree(&root, &root.join(package), &mut inputs)?;
    }

    let mut hasher = Sha256::new();
    for (relative, bytes) in &inputs {
        let name = relative.as_bytes();
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name);
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    let digest = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Ok(EvidenceInputDigestV1 {
        digest,
        files: inputs.into_keys().collect(),
        local_packages,
    })
}

pub fn local_dependency_closure(
    repository_root: impl AsRef<Path>,
) -> Result<BTreeSet<String>, EvidenceError> {
    let root = repository_root
        .as_ref()
        .canonicalize()
        .map_err(|source| EvidenceError::Io {
            path: repository_root.as_ref().to_path_buf(),
            source,
        })?;
    let output = Command::new("cargo")
        .current_dir(&root)
        .args([
            "metadata",
            "--manifest-path",
            "Cargo.toml",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--no-deps",
        ])
        .output()
        .map_err(EvidenceError::MetadataSpawn)?;
    if !output.status.success() {
        return Err(EvidenceError::Invalid(format!(
            "cargo metadata exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let metadata: MetadataDocument = serde_json::from_slice(&output.stdout).map_err(|error| {
        EvidenceError::Invalid(format!("cargo metadata JSON is invalid: {error}"))
    })?;
    let root_package_path = root.join("crates/fluxform-capabilities");
    let packages = metadata
        .packages
        .iter()
        .map(|package| {
            let parent = package.manifest_path.parent().ok_or_else(|| {
                EvidenceError::Invalid(format!("package {} has no manifest parent", package.name))
            })?;
            let parent = parent.canonicalize().map_err(|source| EvidenceError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
            Ok((parent, package))
        })
        .collect::<Result<Vec<_>, EvidenceError>>()?;
    let start = packages
        .iter()
        .find_map(|(path, package)| {
            (package.name == "fluxform-capabilities" && *path == root_package_path)
                .then_some(path.clone())
        })
        .ok_or_else(|| {
            EvidenceError::Invalid(
                "cargo metadata did not return the capabilities package".to_owned(),
            )
        })?;

    let mut paths = BTreeSet::new();
    let mut queue = VecDeque::from([start]);
    while let Some(path) = queue.pop_front() {
        if !paths.insert(path.clone()) {
            continue;
        }
        let package = packages
            .iter()
            .find_map(|(candidate, package)| (candidate == &path).then_some(*package))
            .ok_or_else(|| {
                EvidenceError::Invalid(format!(
                    "local dependency {path:?} is missing from cargo metadata"
                ))
            })?;
        for dependency in &package.dependencies {
            let Some(dependency_path) = &dependency.path else {
                continue;
            };
            let canonical = dependency_path
                .canonicalize()
                .map_err(|source| EvidenceError::Io {
                    path: dependency_path.clone(),
                    source,
                })?;
            let exists = packages.iter().any(|(candidate, package)| {
                *candidate == canonical && package.name == dependency.name
            });
            if !exists {
                return Err(EvidenceError::Invalid(format!(
                    "local dependency {} at {} is absent from cargo metadata",
                    dependency.name,
                    dependency_path.display()
                )));
            }
            queue.push_back(canonical);
        }
    }

    paths
        .into_iter()
        .map(|path| {
            path.strip_prefix(&root)
                .map_err(|_| {
                    EvidenceError::Invalid(format!(
                        "local dependency escapes repository root: {}",
                        path.display()
                    ))
                })
                .map(|relative| relative.to_string_lossy().replace('\\', "/"))
        })
        .collect()
}

fn add_tree(
    root: &Path,
    directory: &Path,
    inputs: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), EvidenceError> {
    if !directory.is_dir() {
        return Err(EvidenceError::Invalid(format!(
            "required evidence directory is missing: {}",
            directory.display()
        )));
    }
    let mut entries = fs::read_dir(directory)
        .map_err(|source| EvidenceError::Io {
            path: directory.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| EvidenceError::Io {
            path: directory.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type().map_err(|source| EvidenceError::Io {
            path: path.clone(),
            source,
        })?;
        if file_type.is_symlink() {
            return Err(EvidenceError::Invalid(format!(
                "symlink is not allowed in evidence closure: {}",
                path.display()
            )));
        }
        if file_type.is_dir() {
            if matches!(
                entry.file_name().to_str(),
                Some("target" | ".git" | "node_modules")
            ) {
                continue;
            }
            add_tree(root, &path, inputs)?;
        } else if file_type.is_file() {
            add_file(root, &path, inputs)?;
        }
    }
    Ok(())
}

fn add_file(
    root: &Path,
    path: &Path,
    inputs: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), EvidenceError> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| {
            EvidenceError::Invalid(format!(
                "evidence path escapes repository root: {}",
                path.display()
            ))
        })?
        .to_string_lossy()
        .replace('\\', "/");
    if inputs.contains_key(&relative) {
        return Ok(());
    }
    let bytes = fs::read(path).map_err(|source| EvidenceError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    inputs.insert(relative, bytes);
    Ok(())
}
