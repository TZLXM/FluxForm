use fluxform_atomic_output::{
    AbortError, CommitError, FfmpegOutputSpec, OutputExpectation, OutputReservation,
    OutputValidator, OverwritePolicyV1, RelativeOutputName, TaskOutputDir, ValidationError,
    open_trusted_root,
};
use fluxform_capabilities::{CapabilityManifestV1, samples::SampleCatalogV1};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::thread::{self, JoinHandle};
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

const OLD_BYTES: &[u8] = b"complete-old-output";
const NEW_BYTES: &[u8] = b"complete-validated-output";

struct TestValidator;

impl OutputValidator for TestValidator {
    fn validate(
        &self,
        _partial_path: &Path,
        _expectation: &OutputExpectation,
    ) -> Result<(), ValidationError> {
        Ok(())
    }
}

struct RejectingValidator;

impl OutputValidator for RejectingValidator {
    fn validate(
        &self,
        _partial_path: &Path,
        _expectation: &OutputExpectation,
    ) -> Result<(), ValidationError> {
        Err(ValidationError::Rejected("test rejection".to_owned()))
    }
}

fn fixture() -> (TempDir, TaskOutputDir) {
    let temporary = tempfile::tempdir().expect("temporary root");
    let root = temporary.path().join("root");
    fs::create_dir_all(root.join("task")).expect("task directory");
    let root_handle = open_trusted_root(&root).expect("open trusted root handle");
    let task_dir = TaskOutputDir::open(&root_handle, "task").expect("open task directory");
    (temporary, task_dir)
}

fn expected_image_output() -> OutputExpectation {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("repository root")
        .to_path_buf();
    let manifest = CapabilityManifestV1::load(repository.join("config/capabilities-v1.toml"))
        .expect("checked-in capability manifest");
    let catalog = SampleCatalogV1::load(repository.join("testdata/media/v1/samples.toml"))
        .expect("checked-in sample catalog");
    let edge = manifest
        .edges()
        .iter()
        .find(|edge| edge.id == "image.jpeg-to-png")
        .expect("approved image edge");
    let sample = catalog
        .find("image-jpeg-baseline-rgb-v1")
        .expect("valid image sample");
    OutputExpectation::from_manifest(edge, sample).expect("manifest-derived expectation")
}

fn reservation(task_dir: &TaskOutputDir, name: &str) -> OutputReservation {
    let output_name = RelativeOutputName::parse(name).expect("valid relative output name");
    OutputReservation::create(task_dir, &output_name, Uuid::new_v4(), "png")
        .expect("exclusive sibling reservation")
}

fn validated(
    reservation: &OutputReservation,
    bytes: &[u8],
) -> fluxform_atomic_output::ValidatedOutput {
    fs::write(reservation.partial_path().expect("partial path"), bytes).expect("write output");
    reservation
        .validate(&TestValidator, &expected_image_output())
        .expect("test validator accepts output")
}

fn observe_final(
    final_path: PathBuf,
    stop: std::sync::Arc<AtomicBool>,
    allowed: Vec<Vec<u8>>,
) -> (JoinHandle<Result<(), String>>, mpsc::Receiver<()>) {
    let (armed_tx, armed_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        let mut armed = false;
        while !stop.load(Ordering::Acquire) {
            match fs::File::open(&final_path) {
                Ok(mut file) => {
                    let mut observed = Vec::new();
                    file.read_to_end(&mut observed)
                        .map_err(|error| error.to_string())?;
                    if !allowed.contains(&observed) {
                        return Err(format!(
                            "observer saw incomplete or unvalidated output: {} bytes",
                            observed.len()
                        ));
                    }
                    if !armed {
                        armed = true;
                        let _ = armed_tx.send(());
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !armed => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err("observer saw final path disappear".to_owned());
                }
                Err(error) => return Err(error.to_string()),
            }
            thread::yield_now();
        }
        Ok(())
    });
    (worker, armed_rx)
}

fn stop_observer(stop: &AtomicBool, worker: JoinHandle<Result<(), String>>) -> Result<(), String> {
    stop.store(true, Ordering::Release);
    worker.join().expect("observer thread").map(|_| ())
}

#[test]
fn partial_file_is_created_beside_the_final_file() {
    let (_temporary, task_dir) = fixture();
    let output = reservation(&task_dir, "result.png");
    let partial = output.partial_path().expect("partial path");
    let final_path = output.final_path();
    assert_eq!(partial.parent(), final_path.parent());
    assert!(partial.exists());
    assert!(!final_path.exists());
}

#[test]
fn absolute_parent_traversal_symlink_and_reparse_names_are_rejected() {
    for value in [
        "..",
        ".",
        "../escape.png",
        "nested\\escape.png",
        "nested/escape.png",
        "C:\\escape.png",
        "\\\\server\\share\\escape.png",
        "\\\\?\\C:\\escape.png",
        "result.png:stream",
        "CON.png",
        "NUL",
        "name.",
        "name ",
    ] {
        assert!(
            RelativeOutputName::parse(value).is_err(),
            "unsafe output name was accepted: {value:?}"
        );
    }

    let (_temporary, task_dir) = fixture();
    assert!(TaskOutputDir::open(task_dir.trusted_root_handle(), "..\\outside").is_err());
}

#[test]
fn directory_swap_cannot_redirect_creation_outside_task_handle() {
    let (temporary, task_dir) = fixture();
    let root = temporary.path().join("root");
    let original_task = root.join("task");
    let moved_task = root.join("task-original");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");

    let output = reservation(&task_dir, "result.png");
    fs::write(output.partial_path().expect("partial path"), NEW_BYTES).expect("write output");
    let expectation = expected_image_output();
    let validated = output
        .validate(&TestValidator, &expectation)
        .expect("test validation");

    match fs::rename(&original_task, &moved_task) {
        Ok(()) => {
            #[cfg(unix)]
            std::os::unix::fs::symlink(&outside, &original_task).expect("task swap symlink");
            #[cfg(windows)]
            fs::create_dir(&original_task).expect("replacement directory");
            let commit = validated.commit(OverwritePolicyV1::Reject);
            match commit {
                Ok(_) => assert!(moved_task.join("result.png").exists()),
                Err(CommitError::AtomicCommitUnsupported) => {
                    assert!(!moved_task.join("result.png").exists());
                    assert!(
                        fs::read_dir(&moved_task)
                            .expect("retained task directory")
                            .filter_map(Result::ok)
                            .any(|entry| entry
                                .path()
                                .extension()
                                .is_some_and(|ext| ext == "partial")),
                        "failed native rename must leave the owned partial inside the retained directory"
                    );
                }
                Err(error) => panic!("unexpected handle-relative commit error: {error}"),
            }
            assert!(!outside.join("result.png").exists());
            assert!(!outside.join("result.png.partial").exists());
        }
        Err(error) => {
            println!(
                "directory swap attempt was denied while the task handle remained open: {error}"
            );
            assert!(
                original_task.exists(),
                "failed directory swap moved the original: {error}"
            );
            let final_path = output.final_path().to_path_buf();
            match validated.commit(OverwritePolicyV1::Reject) {
                Ok(_) => assert_eq!(fs::read(final_path).expect("committed output"), NEW_BYTES),
                Err(CommitError::AtomicCommitUnsupported) => assert!(!final_path.exists()),
                Err(error) => panic!("unexpected handle-relative commit error: {error}"),
            }
            assert!(!outside.join("result.png").exists());
        }
    }
}

#[test]
fn reject_never_replaces_an_existing_destination() {
    let (_temporary, task_dir) = fixture();
    let final_path = task_dir.path().join("result.png");
    fs::write(&final_path, OLD_BYTES).expect("existing destination");
    let output = reservation(&task_dir, "result.png");
    let validated = validated(&output, NEW_BYTES);
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let (observer, armed) = observe_final(
        final_path.clone(),
        stop.clone(),
        vec![OLD_BYTES.to_vec(), NEW_BYTES.to_vec()],
    );
    armed
        .recv_timeout(Duration::from_secs(2))
        .expect("observer armed");

    let result = validated.commit(OverwritePolicyV1::Reject);
    assert!(
        matches!(
            &result,
            Err(CommitError::DestinationExists | CommitError::AtomicCommitUnsupported)
        ),
        "reject policy returned an unexpected error: {result:?}"
    );
    assert_eq!(fs::read(&final_path).expect("old final bytes"), OLD_BYTES);
    stop_observer(&stop, observer).expect("observer saw no gap or partial bytes");
    assert!(output.abort().is_err());
}

#[test]
fn rename_commits_to_a_unique_sibling_without_race_prone_precheck() {
    let (_temporary, task_dir) = fixture();
    let output = reservation(&task_dir, "unique.png");
    let validated = validated(&output, NEW_BYTES);
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let (observer, _armed) = observe_final(
        output.final_path().to_path_buf(),
        stop.clone(),
        vec![NEW_BYTES.to_vec()],
    );

    match validated.commit(OverwritePolicyV1::Reject) {
        Ok(_) => assert_eq!(
            fs::read(output.final_path()).expect("final output"),
            NEW_BYTES
        ),
        Err(CommitError::AtomicCommitUnsupported) => {
            assert!(!output.final_path().exists());
            assert!(output.partial_path().expect("partial path").exists());
        }
        Err(error) => panic!("unexpected no-replace commit error: {error}"),
    }
    stop_observer(&stop, observer).expect("observer saw complete output");
}

#[test]
fn two_validated_writers_race_for_one_destination_without_clobbering() {
    let (_temporary, task_dir) = fixture();
    let first = reservation(&task_dir, "contended.png");
    let second = reservation(&task_dir, "contended.png");
    let first_validated = validated(&first, b"writer-one-complete");
    let second_validated = validated(&second, b"writer-two-complete");
    let final_path = task_dir.path().join("contended.png");
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let observer_stop = stop.clone();
    let observer_path = final_path.clone();
    let (observer_started_tx, observer_started_rx) = mpsc::channel();
    let observer = thread::spawn(move || {
        let allowed = [
            b"writer-one-complete".as_slice(),
            b"writer-two-complete".as_slice(),
        ];
        let mut first_open = true;
        let mut saw_final = false;
        while !observer_stop.load(Ordering::Acquire) {
            match fs::read(&observer_path) {
                Ok(bytes) if allowed.contains(&bytes.as_slice()) => {
                    saw_final = true;
                }
                Ok(_) => return Err("observer saw partial bytes".to_owned()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && !saw_final => {}
                Err(error) => return Err(format!("observer saw missing final: {error}")),
            }
            if first_open {
                first_open = false;
                let _ = observer_started_tx.send(());
            }
            thread::yield_now();
        }
        Ok(())
    });
    observer_started_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("observer attempted an open before commit");
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
    let first_barrier = barrier.clone();
    let first_commit = thread::spawn(move || {
        first_barrier.wait();
        first_validated.commit(OverwritePolicyV1::Reject)
    });
    let second_barrier = barrier.clone();
    let second_commit = thread::spawn(move || {
        second_barrier.wait();
        second_validated.commit(OverwritePolicyV1::Reject)
    });
    barrier.wait();

    let first_result = first_commit.join().expect("first writer");
    let second_result = second_commit.join().expect("second writer");
    let successes = usize::from(first_result.is_ok()) + usize::from(second_result.is_ok());
    let unsupported = usize::from(matches!(
        first_result,
        Err(CommitError::AtomicCommitUnsupported)
    )) + usize::from(matches!(
        second_result,
        Err(CommitError::AtomicCommitUnsupported)
    ));
    if unsupported == 2 {
        assert_eq!(successes, 0);
        assert!(!final_path.exists());
        assert!(first.partial_path().expect("first partial").exists());
        assert!(second.partial_path().expect("second partial").exists());
    } else {
        assert_eq!(successes, 1, "exactly one no-replace writer must win");
        let rejected = if matches!(first_result, Err(CommitError::DestinationExists)) {
            second_result
        } else {
            first_result
        };
        assert!(matches!(rejected, Err(CommitError::DestinationExists)));
    }
    stop_observer(&stop, observer).expect("observer saw one complete winner");
    if successes == 1 {
        let final_bytes = fs::read(&final_path).expect("winning output");
        assert!(final_bytes == b"writer-one-complete" || final_bytes == b"writer-two-complete");
    }
}

#[test]
fn replace_atomically_supersedes_an_existing_destination() {
    let (_temporary, task_dir) = fixture();
    let output = reservation(&task_dir, "replace.png");
    let final_path = output.final_path().to_path_buf();
    fs::write(&final_path, OLD_BYTES).expect("existing destination");
    let validated = validated(&output, NEW_BYTES);
    let stop = std::sync::Arc::new(AtomicBool::new(false));
    let (observer, armed) = observe_final(
        final_path.clone(),
        stop.clone(),
        vec![OLD_BYTES.to_vec(), NEW_BYTES.to_vec()],
    );
    armed
        .recv_timeout(Duration::from_secs(2))
        .expect("observer armed");

    let result = validated.commit(OverwritePolicyV1::Replace);
    match result {
        Ok(_) => assert_eq!(fs::read(&final_path).expect("final output"), NEW_BYTES),
        Err(CommitError::AtomicCommitUnsupported) => {
            assert_eq!(fs::read(&final_path).expect("old final remains"), OLD_BYTES);
            assert!(output.partial_path().expect("partial path").exists());
        }
        Err(error) => panic!("unexpected atomic replace error: {error}"),
    }
    stop_observer(&stop, observer).expect("observer saw old or new complete output");
}

#[test]
fn abort_removes_only_the_owned_partial_file() {
    let (_temporary, task_dir) = fixture();
    let final_path = task_dir.path().join("preserved.png");
    fs::write(&final_path, OLD_BYTES).expect("final destination");
    let unrelated_partial = task_dir.path().join("somebody-elses.partial");
    fs::write(&unrelated_partial, b"unowned").expect("unowned partial");
    let output = reservation(&task_dir, "preserved.png");
    let partial = output
        .partial_path()
        .expect("owned partial path")
        .to_path_buf();
    fs::write(&partial, NEW_BYTES).expect("partial bytes");

    output.abort().expect("abort writing reservation");
    assert!(!partial.exists());
    assert_eq!(fs::read(final_path).expect("final destination"), OLD_BYTES);
    assert_eq!(
        fs::read(unrelated_partial).expect("unowned partial"),
        b"unowned"
    );
}

#[test]
fn image_args_name_map_muxer_and_video_codec_only() {
    let spec = FfmpegOutputSpec {
        muxer: "image2".to_owned(),
        video_codec: Some("png".to_owned()),
        audio_codec: None,
    };
    assert_eq!(
        spec.arguments("input.jpg", "output.png").expect("argv"),
        [
            "-y",
            "-i",
            "input.jpg",
            "-map",
            "0:v:0",
            "-f",
            "image2",
            "-c:v",
            "png",
            "output.png"
        ]
    );
}

#[test]
fn audio_args_name_map_muxer_and_audio_codec_only() {
    let spec = FfmpegOutputSpec {
        muxer: "mp4".to_owned(),
        video_codec: None,
        audio_codec: Some("aac".to_owned()),
    };
    assert_eq!(
        spec.arguments("input.m4a", "output.m4a").expect("argv"),
        [
            "-y",
            "-i",
            "input.m4a",
            "-map",
            "0:a:0",
            "-f",
            "mp4",
            "-c:a",
            "aac",
            "output.m4a"
        ]
    );
}

#[test]
fn mixed_av_args_name_both_maps_muxer_and_codecs() {
    let spec = FfmpegOutputSpec {
        muxer: "mp4".to_owned(),
        video_codec: Some("libx264".to_owned()),
        audio_codec: Some("aac".to_owned()),
    };
    assert_eq!(
        spec.arguments("input.mov", "output.mp4").expect("argv"),
        [
            "-y",
            "-i",
            "input.mov",
            "-map",
            "0:v:0",
            "-map",
            "0:a:0",
            "-f",
            "mp4",
            "-c:v",
            "libx264",
            "-c:a",
            "aac",
            "output.mp4"
        ]
    );
}

#[test]
fn unvalidated_output_cannot_be_committed() {
    let (_temporary, task_dir) = fixture();
    let final_path = task_dir.path().join("rejected.png");
    fs::write(&final_path, OLD_BYTES).expect("existing destination");
    let output = reservation(&task_dir, "rejected.png");
    fs::write(output.partial_path().expect("partial path"), NEW_BYTES).expect("partial bytes");
    assert!(matches!(
        output.validate(&RejectingValidator, &expected_image_output()),
        Err(ValidationError::Rejected(_))
    ));
    assert_eq!(fs::read(final_path).expect("unchanged final"), OLD_BYTES);
    output.abort().expect("abort rejected output");
}

#[test]
#[ignore = "BLOCKED until an approved ffprobe artifact and approved native samples are available"]
fn approved_ffprobe_accepts_valid_and_rejects_truncated_or_property_mismatched_sample_before_commit()
 {
    // This test is deliberately ignored unless a later gate supplies a genuinely approved
    // artifact identity. The current Windows candidate is not approved and must not be used.
    panic!("approved FFprobe integration gate is blocked in the current repository state");
}

#[test]
fn concurrent_abort_and_commit_have_only_aborted_or_committed_terminal_states() {
    let expectation = expected_image_output();
    let mut committed_count = 0;
    let mut aborted_count = 0;
    let mut blocked_native_count = 0;
    for _ in 0..1_000 {
        let (_temporary, task_dir) = fixture();
        let output = reservation(&task_dir, "race.png");
        fs::write(output.partial_path().expect("partial path"), NEW_BYTES).expect("partial bytes");
        let expectation = expectation.clone();
        let output = std::sync::Arc::new(output);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let commit_output = output.clone();
        let commit_barrier = barrier.clone();
        let commit = thread::spawn(move || {
            commit_barrier.wait();
            match commit_output.validate(&TestValidator, &expectation) {
                Ok(validated) => validated
                    .commit(OverwritePolicyV1::Reject)
                    .map(|_| "committed")
                    .map_err(|error| error.to_string()),
                Err(error) => Err(error.to_string()),
            }
        });
        let abort_output = output.clone();
        let abort_barrier = barrier.clone();
        let abort = thread::spawn(move || {
            abort_barrier.wait();
            abort_output.abort()
        });
        barrier.wait();

        let committed = commit.join().expect("commit thread");
        let aborted = abort.join().expect("abort thread");
        let final_path = output.final_path().to_path_buf();
        if final_path.exists() {
            assert_eq!(fs::read(&final_path).expect("committed bytes"), NEW_BYTES);
            assert!(
                committed.is_ok(),
                "final exists but commit failed: {committed:?}"
            );
            assert!(matches!(aborted, Err(AbortError::CommitInProgress)));
            committed_count += 1;
        } else {
            match (&committed, &aborted) {
                (Err(commit_error), Ok(())) => {
                    assert!(commit_error.contains("reservation is no longer writable"));
                    aborted_count += 1;
                }
                (Err(commit_error), Err(AbortError::CommitInProgress))
                    if commit_error.contains("atomic output commit is unsupported") =>
                {
                    blocked_native_count += 1;
                }
                other => panic!("invalid abort/commit race outcome: {other:?}"),
            }
        }
    }
    assert_eq!(
        committed_count + aborted_count + blocked_native_count,
        1_000
    );
    eprintln!(
        "1,000 abort/commit races: committed={committed_count}, aborted={aborted_count}, blocked_by_native_rename={blocked_native_count}"
    );
}
