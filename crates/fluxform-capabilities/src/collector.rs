use crate::evidence::compute_evidence_input_digest;
use crate::runner::{SampleRunReportV1, validate_run_report_inputs};
use crate::{CapabilityManifestV1, samples::SampleCatalogV1};
use fluxform_ffmpeg_profile::{BuildProfile, ProbeReport};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const TARGETS: &[(&str, &str, &str, &str)] = &[
    (
        "windows-x86_64",
        "x86_64-pc-windows-msvc",
        "windows",
        "x86_64",
    ),
    ("macos-aarch64", "aarch64-apple-darwin", "macos", "aarch64"),
    ("macos-x86_64", "x86_64-apple-darwin", "macos", "x86_64"),
    (
        "linux-x86_64",
        "x86_64-unknown-linux-gnu",
        "linux",
        "x86_64",
    ),
];
const EXPECTED_FILES: &[&str] = &[
    "ffmpeg-profile-report.json",
    "provenance.json",
    "sample-report.json",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CollectionMode {
    Workflow,
    Manual,
}

struct ExpectedArtifactIdentity<'a> {
    target_id: &'a str,
    target_triple: &'a str,
    runner_os: &'a str,
    runner_arch: &'a str,
    artifact_name: &'a str,
    evidence_input_digest: &'a str,
    profile_hash: &'a str,
    sample_hash: &'a str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeArtifactProvenanceV1 {
    pub schema: String,
    pub artifact_name: String,
    pub target_profile_id: String,
    pub target_triple: String,
    pub runner_os: String,
    pub runner_arch: String,
    pub git_commit: String,
    pub evidence_input_digest: String,
    pub workflow_run_id: String,
    pub workflow_job_id: String,
    pub ffmpeg_profile_report_sha256: String,
    pub sample_report_sha256: String,
    #[serde(default)]
    pub manual_reviewer: Option<String>,
    #[serde(default)]
    pub transfer_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateSampleReportV1 {
    pub schema: String,
    pub status: String,
    pub evidence_input_digest: String,
    pub targets: Vec<NativeTargetSummaryV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeTargetSummaryV1 {
    pub target_profile_id: String,
    pub target_triple: String,
    pub artifact_id: String,
    pub git_commit: String,
    pub profile_report_sha256: String,
    pub sample_report_sha256: String,
    pub sample_result_count: usize,
    pub native_runner_os: String,
    pub native_runner_arch: String,
}

pub fn collect_sample_reports(
    repository_root: impl AsRef<Path>,
    input_dir: impl AsRef<Path>,
    manifest_path: impl AsRef<Path>,
    samples_path: impl AsRef<Path>,
    expected_input_digest: &str,
) -> Result<AggregateSampleReportV1, String> {
    let root = repository_root
        .as_ref()
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let input = resolve(&root, input_dir.as_ref());
    let manifest_file = resolve(&root, manifest_path.as_ref());
    let samples_file = resolve(&root, samples_path.as_ref());
    if !is_sha256(expected_input_digest) {
        return Err("BLOCKED: expected evidence-input digest is not canonical SHA-256".to_owned());
    }
    let current_digest = compute_evidence_input_digest(&root).map_err(|error| error.to_string())?;
    if current_digest.digest != expected_input_digest {
        return Err(format!(
            "BLOCKED: expected evidence-input digest {expected_input_digest} does not match current {}",
            current_digest.digest
        ));
    }
    let manifest = CapabilityManifestV1::load(&manifest_file).map_err(|error| error.to_string())?;
    let catalog = SampleCatalogV1::load(&samples_file).map_err(|error| error.to_string())?;
    catalog
        .validate_manifest_samples(&manifest)
        .map_err(|error| error.to_string())?;
    let manifest_digest = sha256(&fs::read(&manifest_file).map_err(|error| error.to_string())?);
    let samples_digest = sha256(&fs::read(&samples_file).map_err(|error| error.to_string())?);
    let profile_path = root.join("config/ffmpeg-profile.toml");
    let profile = BuildProfile::load(&profile_path).map_err(|error| error.to_string())?;

    let entries = fs::read_dir(&input)
        .map_err(|error| {
            format!("BLOCKED: collected artifact root is missing or unreadable: {error}")
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("BLOCKED: could not enumerate collected artifacts: {error}"))?;
    let mut target_dirs = BTreeMap::new();
    for entry in entries {
        let path = entry.path();
        if !entry
            .file_type()
            .map_err(|error| error.to_string())?
            .is_dir()
        {
            return Err(format!(
                "BLOCKED: unexpected file in collected root: {}",
                path.display()
            ));
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if !TARGETS.iter().any(|target| target.0 == name) {
            return Err(format!("BLOCKED: unexpected target directory {name}"));
        }
        if target_dirs.insert(name.clone(), path).is_some() {
            return Err(format!("BLOCKED: duplicate target directory {name}"));
        }
    }
    let missing = TARGETS
        .iter()
        .map(|target| target.0)
        .filter(|target| !target_dirs.contains_key(*target))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "BLOCKED: missing native target artifacts: {}",
            missing.join(", ")
        ));
    }

    let mut provenance_records = BTreeMap::new();
    for (target_id, _, _, _) in TARGETS {
        let directory = target_dirs
            .get(*target_id)
            .ok_or_else(|| format!("missing {target_id}"))?;
        validate_exact_files(directory)?;
        let provenance_path = directory.join("provenance.json");
        let bytes = fs::read(&provenance_path).map_err(|error| {
            format!(
                "BLOCKED: cannot read {}: {error}",
                provenance_path.display()
            )
        })?;
        let provenance: NativeArtifactProvenanceV1 = serde_json::from_slice(&bytes)
            .map_err(|error| format!("BLOCKED: invalid provenance for {target_id}: {error}"))?;
        provenance_records.insert((*target_id).to_owned(), provenance);
    }
    let collection_mode = determine_collection_mode(&provenance_records)?;

    let mut targets = Vec::new();
    for (target_id, expected_triple, expected_os, expected_arch) in TARGETS {
        let directory = target_dirs
            .get(*target_id)
            .ok_or_else(|| format!("missing {target_id}"))?;
        let profile_report_path = directory.join("ffmpeg-profile-report.json");
        let sample_report_path = directory.join("sample-report.json");
        let profile_bytes = fs::read(&profile_report_path).map_err(|error| {
            format!(
                "BLOCKED: cannot read {}: {error}",
                profile_report_path.display()
            )
        })?;
        let sample_bytes = fs::read(&sample_report_path).map_err(|error| {
            format!(
                "BLOCKED: cannot read {}: {error}",
                sample_report_path.display()
            )
        })?;
        let profile_report: ProbeReport = serde_json::from_slice(&profile_bytes)
            .map_err(|error| format!("BLOCKED: invalid profile report for {target_id}: {error}"))?;
        let sample_report: SampleRunReportV1 = serde_json::from_slice(&sample_bytes)
            .map_err(|error| format!("BLOCKED: invalid sample report for {target_id}: {error}"))?;
        let provenance = provenance_records
            .get(*target_id)
            .ok_or_else(|| format!("missing {target_id} provenance"))?;

        let profile_hash = sha256(&profile_bytes);
        let sample_hash = sha256(&sample_bytes);
        let expected_artifact_name = format!("stage0-samples-{target_id}-{expected_input_digest}");
        validate_provenance_identity(
            provenance,
            &ExpectedArtifactIdentity {
                target_id,
                target_triple: expected_triple,
                runner_os: expected_os,
                runner_arch: expected_arch,
                artifact_name: &expected_artifact_name,
                evidence_input_digest: expected_input_digest,
                profile_hash: &profile_hash,
                sample_hash: &sample_hash,
            },
        )?;
        if collection_mode == CollectionMode::Manual {
            let expected_transfer_hash =
                compute_manual_transfer_sha256(&profile_bytes, &sample_bytes, provenance)?;
            if provenance.transfer_sha256.as_deref() != Some(expected_transfer_hash.as_str()) {
                return Err(format!(
                    "BLOCKED: manual transfer hash mismatch for {target_id}"
                ));
            }
        }
        if profile_report.target_triple != *expected_triple
            || sample_report.target_triple != *expected_triple
            || sample_report.target_profile_id != *target_id
            || sample_report.runner_os != *expected_os
            || sample_report.runner_arch != *expected_arch
            || sample_report.evidence_input_digest != expected_input_digest
            || sample_report.profile_id != profile_report.profile_id
            || sample_report.artifact_id != profile_report.artifact_id
            || sample_report.profile_digest != profile_report.profile_digest
            || sample_report.ffmpeg_sha256 != profile_report.ffmpeg_sha256
            || sample_report.ffprobe_sha256 != profile_report.ffprobe_sha256
            || sample_report.git_commit != provenance.git_commit
            || sample_report.manifest_digest != manifest_digest
            || sample_report.sample_catalog_digest != samples_digest
        {
            return Err(format!(
                "BLOCKED: native target report identity mismatch for {target_id}"
            ));
        }
        validate_run_report_inputs(&sample_report, &manifest, &catalog, &root)
            .map_err(|error| format!("BLOCKED: {target_id}: {error}"))?;
        if !profile.gate_is_approved() {
            return Err(
                "BLOCKED: checked-in FFmpeg profile distribution gate remains unapproved"
                    .to_owned(),
            );
        }
        let approved = profile
            .approved_artifact(&profile_report.artifact_id)
            .map_err(|error| format!("BLOCKED: {target_id} artifact is not approved: {error}"))?;
        profile_report.verify_identity(&approved).map_err(|error| {
            format!("BLOCKED: {target_id} report identity is not approved: {error}")
        })?;
        targets.push(NativeTargetSummaryV1 {
            target_profile_id: (*target_id).to_owned(),
            target_triple: (*expected_triple).to_owned(),
            artifact_id: profile_report.artifact_id,
            git_commit: provenance.git_commit.clone(),
            profile_report_sha256: profile_hash,
            sample_report_sha256: sample_hash,
            sample_result_count: sample_report.results.len(),
            native_runner_os: (*expected_os).to_owned(),
            native_runner_arch: (*expected_arch).to_owned(),
        });
    }
    targets.sort_by(|left, right| left.target_profile_id.cmp(&right.target_profile_id));
    Ok(AggregateSampleReportV1 {
        schema: "fluxform.sample-aggregate.v1".to_owned(),
        status: "passed".to_owned(),
        evidence_input_digest: current_digest.digest,
        targets,
    })
}

fn determine_collection_mode(
    provenance_records: &BTreeMap<String, NativeArtifactProvenanceV1>,
) -> Result<CollectionMode, String> {
    if provenance_records.len() != TARGETS.len()
        || TARGETS
            .iter()
            .any(|(target_id, _, _, _)| !provenance_records.contains_key(*target_id))
    {
        return Err(
            "BLOCKED: provenance is required for exactly the four native targets".to_owned(),
        );
    }

    let mut collection_mode = None;
    let mut workflow_run_id = None::<&str>;
    for (target_id, _, _, _) in TARGETS {
        let provenance = provenance_records
            .get(*target_id)
            .ok_or_else(|| format!("BLOCKED: missing {target_id} provenance"))?;
        let has_workflow_run = !provenance.workflow_run_id.trim().is_empty();
        let has_workflow_job = !provenance.workflow_job_id.trim().is_empty();
        if has_workflow_run != has_workflow_job {
            return Err(format!(
                "BLOCKED: {target_id} has incomplete workflow run/job provenance"
            ));
        }

        let has_manual_reviewer = match provenance.manual_reviewer.as_deref() {
            Some(reviewer) if reviewer.trim().is_empty() => {
                return Err(format!("BLOCKED: {target_id} has an empty manual reviewer"));
            }
            Some(_) => true,
            None => false,
        };
        let has_transfer_hash = match provenance.transfer_sha256.as_deref() {
            Some(hash) if !is_sha256(hash) => {
                return Err(format!("BLOCKED: {target_id} has an invalid transfer hash"));
            }
            Some(_) => true,
            None => false,
        };
        if has_manual_reviewer != has_transfer_hash {
            return Err(format!(
                "BLOCKED: {target_id} has incomplete manual reviewer/transfer provenance"
            ));
        }

        let workflow_mode = has_workflow_run && has_workflow_job;
        let manual_mode = has_manual_reviewer && has_transfer_hash;
        if workflow_mode && manual_mode {
            return Err(format!(
                "BLOCKED: {target_id} has dual workflow and manual provenance"
            ));
        }
        let mode = if workflow_mode {
            if workflow_run_id.is_some_and(|run_id| run_id != provenance.workflow_run_id) {
                return Err(
                    "BLOCKED: native artifacts do not come from the same workflow run".to_owned(),
                );
            }
            workflow_run_id.get_or_insert(&provenance.workflow_run_id);
            CollectionMode::Workflow
        } else if manual_mode {
            CollectionMode::Manual
        } else {
            return Err(format!(
                "BLOCKED: {target_id} requires workflow run/job IDs or reviewer plus transfer hash"
            ));
        };

        if collection_mode.is_some_and(|existing| existing != mode) {
            return Err("BLOCKED: native artifacts mix workflow and manual provenance".to_owned());
        }
        collection_mode = Some(mode);
    }
    collection_mode.ok_or_else(|| "BLOCKED: no collection provenance was supplied".to_owned())
}

fn validate_provenance_identity(
    provenance: &NativeArtifactProvenanceV1,
    expected: &ExpectedArtifactIdentity<'_>,
) -> Result<(), String> {
    if provenance.schema != "fluxform.native-sample-artifact.v1"
        || provenance.artifact_name != expected.artifact_name
        || provenance.target_profile_id != expected.target_id
        || provenance.target_triple != expected.target_triple
        || provenance.runner_os != expected.runner_os
        || provenance.runner_arch != expected.runner_arch
        || provenance.evidence_input_digest != expected.evidence_input_digest
        || provenance.ffmpeg_profile_report_sha256 != expected.profile_hash
        || provenance.sample_report_sha256 != expected.sample_hash
        || provenance.git_commit.trim().is_empty()
    {
        return Err(format!(
            "BLOCKED: provenance identity or report hash mismatch for {}",
            expected.target_id
        ));
    }
    Ok(())
}

fn validate_exact_files(directory: &Path) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("BLOCKED: could not read {}: {error}", directory.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| {
            format!(
                "BLOCKED: could not enumerate {}: {error}",
                directory.display()
            )
        })?;
    let actual = entries
        .iter()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect::<BTreeSet<_>>();
    let expected = EXPECTED_FILES
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<BTreeSet<_>>();
    if actual != expected
        || entries.iter().any(|entry| {
            entry
                .file_type()
                .map(|file_type| !file_type.is_file() || file_type.is_symlink())
                .unwrap_or(true)
        })
    {
        return Err(format!(
            "BLOCKED: {} must contain exactly the three named regular files",
            directory.display()
        ));
    }
    Ok(())
}

fn resolve(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Computes the manual transfer digest over both reports and a canonicalized
/// provenance document with its own transfer hash cleared, avoiding a
/// self-referential digest while still binding the reviewer and source data.
pub fn compute_manual_transfer_sha256(
    profile_report: &[u8],
    sample_report: &[u8],
    provenance: &NativeArtifactProvenanceV1,
) -> Result<String, String> {
    let mut provenance_without_digest = provenance.clone();
    provenance_without_digest.transfer_sha256 = None;
    let provenance_bytes = serde_json::to_vec(&provenance_without_digest)
        .map_err(|error| format!("could not normalize transfer provenance: {error}"))?;
    let files = [
        ("ffmpeg-profile-report.json", profile_report),
        ("provenance.json", provenance_bytes.as_slice()),
        ("sample-report.json", sample_report),
    ];
    let mut hasher = Sha256::new();
    for (name, bytes) in files {
        hasher.update((name.len() as u64).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((bytes.len() as u64).to_be_bytes());
        hasher.update(bytes);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::{
        ExpectedArtifactIdentity, NativeArtifactProvenanceV1, TARGETS,
        compute_manual_transfer_sha256, determine_collection_mode, validate_provenance_identity,
    };
    use std::collections::BTreeMap;

    fn test_provenance(target_id: &str, workflow: bool) -> NativeArtifactProvenanceV1 {
        let (target_id, target_triple, runner_os, runner_arch) = TARGETS
            .iter()
            .find(|target| target.0 == target_id)
            .expect("known test target");
        NativeArtifactProvenanceV1 {
            schema: "fluxform.native-sample-artifact.v1".to_owned(),
            artifact_name: format!("TEST-ONLY-stage0-samples-{target_id}"),
            target_profile_id: (*target_id).to_owned(),
            target_triple: (*target_triple).to_owned(),
            runner_os: (*runner_os).to_owned(),
            runner_arch: (*runner_arch).to_owned(),
            git_commit: "TEST-ONLY".to_owned(),
            evidence_input_digest: "a".repeat(64),
            workflow_run_id: if workflow {
                "TEST-ONLY-run".to_owned()
            } else {
                String::new()
            },
            workflow_job_id: if workflow {
                format!("TEST-ONLY-job-{target_id}")
            } else {
                String::new()
            },
            ffmpeg_profile_report_sha256: "b".repeat(64),
            sample_report_sha256: "c".repeat(64),
            manual_reviewer: None,
            transfer_sha256: None,
        }
    }

    fn four_test_provenances(workflow: bool) -> BTreeMap<String, NativeArtifactProvenanceV1> {
        TARGETS
            .iter()
            .map(|(target_id, _, _, _)| {
                (
                    (*target_id).to_owned(),
                    test_provenance(target_id, workflow),
                )
            })
            .collect()
    }

    #[test]
    fn test_only_manual_transfer_hash_binds_reports_and_non_circular_provenance() {
        // These TEST-ONLY values test canonical hash mechanics; they are not
        // native artifact reports or product approval evidence.
        let mut provenance = NativeArtifactProvenanceV1 {
            schema: "fluxform.native-sample-artifact.v1".to_owned(),
            artifact_name: "TEST-ONLY-stage0-samples-windows-x86_64".to_owned(),
            target_profile_id: "windows-x86_64".to_owned(),
            target_triple: "x86_64-pc-windows-msvc".to_owned(),
            runner_os: "windows".to_owned(),
            runner_arch: "x86_64".to_owned(),
            git_commit: "TEST-ONLY".to_owned(),
            evidence_input_digest: "a".repeat(64),
            workflow_run_id: String::new(),
            workflow_job_id: String::new(),
            ffmpeg_profile_report_sha256: "b".repeat(64),
            sample_report_sha256: "c".repeat(64),
            manual_reviewer: Some("TEST-ONLY reviewer".to_owned()),
            transfer_sha256: None,
        };
        let profile = b"TEST-ONLY profile report";
        let sample = b"TEST-ONLY sample report";
        let digest = compute_manual_transfer_sha256(profile, sample, &provenance).unwrap();
        provenance.transfer_sha256 = Some(digest.clone());
        assert_eq!(
            compute_manual_transfer_sha256(profile, sample, &provenance).unwrap(),
            digest
        );
        assert_ne!(
            compute_manual_transfer_sha256(profile, b"changed", &provenance).unwrap(),
            digest
        );
    }

    #[test]
    fn test_only_collector_rejects_mixed_dual_and_different_run_provenance() {
        let mut mixed = four_test_provenances(true);
        let manual = mixed.get_mut("macos-aarch64").expect("TEST-ONLY target");
        manual.workflow_run_id.clear();
        manual.workflow_job_id.clear();
        manual.manual_reviewer = Some("TEST-ONLY reviewer".to_owned());
        manual.transfer_sha256 = Some("d".repeat(64));
        assert!(
            determine_collection_mode(&mixed)
                .expect_err("mixed sources must fail closed")
                .contains("mix workflow and manual")
        );

        let mut dual = four_test_provenances(true);
        let dual_record = dual.get_mut("macos-aarch64").expect("TEST-ONLY target");
        dual_record.manual_reviewer = Some("TEST-ONLY reviewer".to_owned());
        dual_record.transfer_sha256 = Some("d".repeat(64));
        assert!(
            determine_collection_mode(&dual)
                .expect_err("dual provenance must fail closed")
                .contains("dual workflow and manual")
        );

        let mut different_runs = four_test_provenances(true);
        different_runs
            .get_mut("linux-x86_64")
            .expect("TEST-ONLY target")
            .workflow_run_id = "TEST-ONLY-other-run".to_owned();
        assert!(
            determine_collection_mode(&different_runs)
                .expect_err("workflow artifacts must share one run")
                .contains("same workflow run")
        );
    }

    #[test]
    fn test_only_collector_rejects_stale_tampered_and_duplicate_target_identity() {
        let provenance = test_provenance("windows-x86_64", true);
        let expected_artifact = "TEST-ONLY-stage0-samples-windows-x86_64";
        let validate = |provenance: &NativeArtifactProvenanceV1, target: &str| {
            validate_provenance_identity(
                provenance,
                &ExpectedArtifactIdentity {
                    target_id: target,
                    target_triple: "x86_64-pc-windows-msvc",
                    runner_os: "windows",
                    runner_arch: "x86_64",
                    artifact_name: expected_artifact,
                    evidence_input_digest: &"a".repeat(64),
                    profile_hash: &"b".repeat(64),
                    sample_hash: &"c".repeat(64),
                },
            )
        };
        assert!(validate(&provenance, "windows-x86_64").is_ok());

        let mut stale = provenance.clone();
        stale.evidence_input_digest = "e".repeat(64);
        assert!(validate(&stale, "windows-x86_64").is_err());

        let mut tampered_profile = provenance.clone();
        tampered_profile.ffmpeg_profile_report_sha256 = "f".repeat(64);
        assert!(validate(&tampered_profile, "windows-x86_64").is_err());

        let mut tampered_sample = provenance.clone();
        tampered_sample.sample_report_sha256 = "0".repeat(64);
        assert!(validate(&tampered_sample, "windows-x86_64").is_err());

        assert!(validate(&provenance, "macos-x86_64").is_err());
    }
}
