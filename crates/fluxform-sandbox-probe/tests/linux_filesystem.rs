use fluxform_sandbox_probe::{FilesystemEvidence, ProbeEvidence, ProbeStatus};

#[cfg(not(target_os = "linux"))]
#[test]
fn native_linux_filesystem_gate_is_blocked_off_linux() {
    use fluxform_sandbox_probe::{
        FilesystemPrerequisites, Sandbox, SandboxError, SandboxLimits, SandboxPolicy,
        SpawnPlacement,
    };

    assert!(matches!(
        FilesystemPrerequisites::inspect(),
        Err(SandboxError::UnsupportedPlatform)
    ));

    let ready = std::fs::File::open("Cargo.toml").expect("open portable ready endpoint");
    let release = std::fs::File::open("Cargo.toml").expect("open portable release endpoint");
    let policy = SandboxPolicy {
        input: "uninspected-input".into(),
        job_dir: "uninspected-job".into(),
        tool_dir: "uninspected-tools".into(),
        limits: SandboxLimits::default(),
    };
    assert!(matches!(
        Sandbox::spawn_blocked(
            std::path::Path::new("uninspected-tool"),
            &[],
            &policy,
            SpawnPlacement::ParentAttachBarrier { ready, release },
        ),
        Err(SandboxError::UnsupportedPlatform)
    ));
}

#[test]
fn filesystem_evidence_serializes_each_fail_closed_primitive() {
    let failed = ProbeEvidence {
        status: ProbeStatus::Failed,
        detail: "probe unavailable".into(),
    };
    let evidence = FilesystemEvidence {
        user_namespace: failed.clone(),
        pid_namespace: failed.clone(),
        mount_isolation: failed.clone(),
        pivot_root: failed.clone(),
        capability_drop: failed.clone(),
        descriptor_closure: failed.clone(),
        temporary_root: failed,
    };
    assert!(!evidence.all_passed());

    assert_eq!(
        serde_json::to_value(evidence).expect("serialize structured prerequisites"),
        serde_json::json!({
            "user_namespace": { "status": "failed", "detail": "probe unavailable" },
            "pid_namespace": { "status": "failed", "detail": "probe unavailable" },
            "mount_isolation": { "status": "failed", "detail": "probe unavailable" },
            "pivot_root": { "status": "failed", "detail": "probe unavailable" },
            "capability_drop": { "status": "failed", "detail": "probe unavailable" },
            "descriptor_closure": { "status": "failed", "detail": "probe unavailable" },
            "temporary_root": { "status": "failed", "detail": "probe unavailable" }
        })
    );
}

#[cfg(target_os = "linux")]
mod linux {
    use fluxform_sandbox_probe::{Sandbox, SandboxLimits, SandboxPolicy, SpawnPlacement};
    use std::fs::{self, File, OpenOptions};
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        input: PathBuf,
        job_dir: PathBuf,
        tool_dir: PathBuf,
        child: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = tempfile::tempdir().expect("fixture root");
            let input = root.path().join("assigned-input.bin");
            fs::write(&input, b"assigned-input").expect("write input");

            let job_dir = root.path().join("job");
            fs::create_dir(&job_dir).expect("create job directory");
            fs::set_permissions(&job_dir, fs::Permissions::from_mode(0o700))
                .expect("restrict job directory");

            let tool_dir = root.path().join("tool");
            fs::create_dir(&tool_dir).expect("create tool directory");
            let child = tool_dir.join("sandbox-child");
            let child_source = PathBuf::from(env!("CARGO_BIN_EXE_sandbox-child"));
            fs::copy(&child_source, &child).expect("copy test action binary");
            copy_runtime_dependencies(&child_source, &tool_dir);

            Self {
                _root: root,
                input,
                job_dir,
                tool_dir,
                child,
            }
        }

        fn policy(&self) -> SandboxPolicy {
            SandboxPolicy {
                input: self.input.clone(),
                job_dir: self.job_dir.clone(),
                tool_dir: self.tool_dir.clone(),
                limits: SandboxLimits::default(),
            }
        }
    }

    fn copy_runtime_dependencies(binary: &Path, tool_dir: &Path) {
        let output = Command::new("ldd")
            .arg(binary)
            .output()
            .expect("run ldd for the test action binary");
        assert!(output.status.success(), "ldd failed: {output:?}");
        let stdout = String::from_utf8(output.stdout).expect("ldd output is UTF-8");
        for path in stdout
            .lines()
            .flat_map(str::split_whitespace)
            .filter(|item| item.starts_with('/'))
        {
            let source = Path::new(path);
            let relative = source.strip_prefix("/").expect("absolute ldd path");
            let destination = tool_dir.join(relative);
            if destination.exists() {
                continue;
            }
            fs::create_dir_all(destination.parent().expect("dependency parent"))
                .expect("create dependency directory");
            fs::copy(source, &destination).expect("copy runtime dependency into tool fixture");
        }
    }

    fn barrier() -> (SpawnPlacement, File, File) {
        let mut ready_pipe = [0; 2];
        let mut release_pipe = [0; 2];
        assert_eq!(
            unsafe { libc::pipe2(ready_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "create ready pipe"
        );
        assert_eq!(
            unsafe { libc::pipe2(release_pipe.as_mut_ptr(), libc::O_CLOEXEC) },
            0,
            "create release pipe"
        );

        let child_ready = unsafe { File::from_raw_fd(ready_pipe[1]) };
        let child_release = unsafe { File::from_raw_fd(release_pipe[0]) };
        let parent_ready = unsafe { File::from_raw_fd(ready_pipe[0]) };
        let parent_release = unsafe { File::from_raw_fd(release_pipe[1]) };
        (
            SpawnPlacement::ParentAttachBarrier {
                ready: child_ready,
                release: child_release,
            },
            parent_ready,
            parent_release,
        )
    }

    fn run(action: &str, extra: &[String]) -> (i32, Fixture) {
        let fixture = Fixture::new();
        let (placement, mut ready, mut release) = barrier();
        let mut arguments = vec![action.to_owned()];
        arguments.extend_from_slice(extra);
        let arguments = arguments.into_iter().map(Into::into).collect::<Vec<_>>();
        let mut child =
            Sandbox::spawn_blocked(&fixture.child, &arguments, &fixture.policy(), placement)
                .expect("spawn in the blocked sandbox");

        let mut pid_bytes = [0; std::mem::size_of::<libc::pid_t>()];
        ready.read_exact(&mut pid_bytes).expect("receive ready pid");
        let ready_pid = libc::pid_t::from_ne_bytes(pid_bytes);
        assert_eq!(
            ready_pid as u32,
            child.id(),
            "ready signal is the blocked child"
        );
        release.write_all(&[1]).expect("confirm test placement");
        drop(release);

        let status = child.wait().expect("wait for sandbox child");
        (status.code().unwrap_or(128), fixture)
    }

    #[test]
    fn assigned_input_remains_readable() {
        let (status, _) = run("read-input", &[]);
        assert_eq!(status, 0);
    }

    #[test]
    fn task_directory_remains_writable() {
        let (status, fixture) = run("write-task", &[]);
        assert_eq!(status, 0);
        assert_eq!(
            fs::read(fixture.job_dir.join("result.bin")).expect("task result"),
            b"task-output"
        );
    }

    #[test]
    fn tool_code_stays_blocked_until_placement_is_confirmed() {
        let fixture = Fixture::new();
        let (placement, mut ready, mut release) = barrier();
        let mut child = Sandbox::spawn_blocked(
            &fixture.child,
            &["write-task".into()],
            &fixture.policy(),
            placement,
        )
        .expect("spawn blocked supervisor");

        let mut pid_bytes = [0; std::mem::size_of::<libc::pid_t>()];
        ready.read_exact(&mut pid_bytes).expect("receive ready pid");
        assert_eq!(
            libc::pid_t::from_ne_bytes(pid_bytes) as u32,
            child.id(),
            "ready signal is the process that must be placed"
        );
        assert!(!fixture.job_dir.join("result.bin").exists());
        assert!(
            child
                .try_wait()
                .expect("check blocked supervisor")
                .is_none()
        );

        release.write_all(&[1]).expect("confirm resource placement");
        assert_eq!(child.wait().expect("wait for tool").code(), Some(0));
        assert_eq!(
            fs::read(fixture.job_dir.join("result.bin")).expect("task result"),
            b"task-output"
        );
    }

    #[test]
    fn assigned_input_is_read_only() {
        let (status, fixture) = run("overwrite-path", &["/input".into()]);
        assert_eq!(status, 43, "the input bind allowed a write");
        assert_eq!(
            fs::read(&fixture.input).expect("read original input"),
            b"assigned-input"
        );
    }

    #[test]
    fn tool_directory_is_read_only() {
        let (status, fixture) = run("overwrite-path", &["/tool/sandbox-child".into()]);
        assert_eq!(status, 43, "the tool bind allowed a write");
        assert!(fixture.child.is_file());
    }

    #[test]
    fn host_etc_passwd_is_not_visible() {
        let (status, _) = run("read-path", &["/etc/passwd".into()]);
        assert_eq!(status, 31, "host /etc/passwd unexpectedly readable");
    }

    #[test]
    fn writes_through_parent_directory_are_denied() {
        let (status, fixture) = run("write-path", &["/task/../escape.bin".into()]);
        assert_eq!(status, 41, "write escaped the task-directory bind");
        assert!(
            !fixture
                .job_dir
                .parent()
                .unwrap()
                .join("escape.bin")
                .exists()
        );
    }

    #[test]
    fn symlinks_cannot_reach_files_outside_the_minimal_root() {
        let fixture = Fixture::new();
        let escape = fixture.job_dir.join("outside-link");
        std::os::unix::fs::symlink("/etc/passwd", &escape).expect("create escape symlink");
        let (placement, mut ready, mut release) = barrier();
        let mut child = Sandbox::spawn_blocked(
            &fixture.child,
            &["read-path".into(), "/task/outside-link".into()],
            &fixture.policy(),
            placement,
        )
        .expect("spawn in the blocked sandbox");
        let mut pid_bytes = [0; std::mem::size_of::<libc::pid_t>()];
        ready.read_exact(&mut pid_bytes).expect("receive ready pid");
        assert_eq!(libc::pid_t::from_ne_bytes(pid_bytes) as u32, child.id());
        release.write_all(&[1]).expect("confirm test placement");
        let status = child.wait().expect("wait for sandbox child");
        assert_eq!(status.code(), Some(31));
    }

    #[test]
    fn host_tmp_directory_fd_cannot_be_used_to_write() {
        let fixture = Fixture::new();
        let host_tmp = tempfile::tempdir().expect("host tmp");
        let directory = File::open(host_tmp.path()).expect("open host tmp directory");
        let fd = directory.as_raw_fd();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, 0) },
            0,
            "make undeclared host tmp fd inheritable"
        );

        let (placement, mut ready, mut release) = barrier();
        let mut child = Sandbox::spawn_blocked(
            &fixture.child,
            &[
                "write-at-fd".into(),
                fd.to_string().into(),
                "host-tmp-write.bin".into(),
            ],
            &fixture.policy(),
            placement,
        )
        .expect("spawn in the blocked sandbox");
        let mut pid_bytes = [0; std::mem::size_of::<libc::pid_t>()];
        ready.read_exact(&mut pid_bytes).expect("receive ready pid");
        assert_eq!(libc::pid_t::from_ne_bytes(pid_bytes) as u32, child.id());
        release.write_all(&[1]).expect("confirm test placement");
        let status = child.wait().expect("wait for sandbox child");
        assert_eq!(status.code(), Some(61), "host tmp fd remained usable");
        assert!(!host_tmp.path().join("host-tmp-write.bin").exists());
    }

    #[test]
    fn undeclared_file_descriptor_cannot_read_its_host_file() {
        let fixture = Fixture::new();
        let secret = fixture._root.path().join("outside-secret.bin");
        fs::write(&secret, b"must not be inherited").expect("write fd secret");
        let file = OpenOptions::new()
            .read(true)
            .open(&secret)
            .expect("open fd secret");
        let fd = file.as_raw_fd();
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, 0) },
            0,
            "make undeclared fd inheritable"
        );

        let (placement, mut ready, mut release) = barrier();
        let mut child = Sandbox::spawn_blocked(
            &fixture.child,
            &["read-fd".into(), fd.to_string().into()],
            &fixture.policy(),
            placement,
        )
        .expect("spawn in the blocked sandbox");
        let mut pid_bytes = [0; std::mem::size_of::<libc::pid_t>()];
        ready.read_exact(&mut pid_bytes).expect("receive ready pid");
        assert_eq!(libc::pid_t::from_ne_bytes(pid_bytes) as u32, child.id());
        release.write_all(&[1]).expect("confirm test placement");
        let status = child.wait().expect("wait for sandbox child");
        assert_eq!(status.code(), Some(51), "undeclared fd remained usable");
    }
}
