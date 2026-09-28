#![cfg(unix)]

use fluxform_atomic_output::{
    OutputReservation, PathError, ReconcileError, RelativeOutputName, TaskOutputDir,
    open_trusted_root,
};
use std::fs;
use tempfile::TempDir;
use uuid::Uuid;

fn fixture() -> (TempDir, TaskOutputDir) {
    let temporary = tempfile::tempdir().expect("temporary root");
    fs::create_dir(temporary.path().join("task")).expect("task directory");
    let root = open_trusted_root(temporary.path()).expect("trusted root");
    let task = TaskOutputDir::open(&root, "task").expect("task directory handle");
    (temporary, task)
}

#[test]
fn unix_output_lifecycle_is_blocked_before_creating_child_files() {
    let (_temporary, task) = fixture();
    let name = RelativeOutputName::parse("result.png").expect("relative name");
    let result = OutputReservation::create(&task, &name, Uuid::new_v4(), "png");

    assert!(matches!(result, Err(PathError::PlatformBlocked)));
    assert_eq!(
        fs::read_dir(task.path()).expect("task listing").count(),
        0,
        "a blocked create must not leave a partial or journal"
    );
}

#[test]
fn unix_reconciliation_is_blocked_without_touching_journal_names() {
    let (_temporary, task) = fixture();
    let journal = task.path().join(".fluxform-unowned.journal");
    fs::write(&journal, b"not an owned record").expect("unowned journal");

    assert!(matches!(
        task.reconcile(),
        Err(ReconcileError::PlatformBlocked)
    ));
    assert_eq!(
        fs::read(journal).expect("journal remains"),
        b"not an owned record"
    );
}

#[test]
fn unix_directory_swap_cannot_redirect_blocked_creation_outside_retained_handle() {
    use std::os::unix::fs::symlink;

    let (temporary, task) = fixture();
    let root = task.trusted_root_handle();
    let task_path = task.path().to_path_buf();
    let moved_task = temporary.path().join("task-original");
    let outside = temporary.path().join("outside");
    fs::create_dir(&outside).expect("outside directory");

    fs::rename(&task_path, &moved_task).expect("move opened task directory");
    symlink(&outside, &task_path).expect("install task-name symlink");

    let name = RelativeOutputName::parse("result.png").expect("relative name");
    assert!(matches!(
        OutputReservation::create(&task, &name, Uuid::new_v4(), "png"),
        Err(PathError::PlatformBlocked)
    ));
    assert!(
        TaskOutputDir::open(root, "task").is_err(),
        "a fresh task open must reject the swapped symlink"
    );
    assert_eq!(fs::read_dir(&outside).expect("outside listing").count(), 0);
    assert_eq!(
        fs::read_dir(&moved_task)
            .expect("moved task listing")
            .count(),
        0
    );
}
