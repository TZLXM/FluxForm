//! Linux filesystem isolation proof for untrusted media tools.
//!
//! The public API is deliberately fail-closed. On non-Linux targets the probe
//! remains buildable but cannot create a sandbox. On Linux, `spawn_blocked`
//! creates the user/mount/PID namespaces and a minimal root before signaling
//! the parent-side placement barrier. The tool is forked only after placement
//! is confirmed and is executed directly, without a shell.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Result of actively checking one required Linux primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeStatus {
    Passed,
    Failed,
}

/// Structured status and diagnostic for one filesystem prerequisite.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProbeEvidence {
    pub status: ProbeStatus,
    pub detail: String,
}

impl ProbeEvidence {
    #[cfg(target_os = "linux")]
    fn passed(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Passed,
            detail: detail.into(),
        }
    }

    #[cfg(target_os = "linux")]
    fn failed(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Failed,
            detail: detail.into(),
        }
    }
}

/// Evidence for every primitive required by the Linux filesystem boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilesystemEvidence {
    pub user_namespace: ProbeEvidence,
    pub pid_namespace: ProbeEvidence,
    pub mount_isolation: ProbeEvidence,
    pub pivot_root: ProbeEvidence,
    pub capability_drop: ProbeEvidence,
    pub descriptor_closure: ProbeEvidence,
    pub temporary_root: ProbeEvidence,
}

impl FilesystemEvidence {
    pub fn all_passed(&self) -> bool {
        [
            &self.user_namespace,
            &self.pid_namespace,
            &self.mount_isolation,
            &self.pivot_root,
            &self.capability_drop,
            &self.descriptor_closure,
            &self.temporary_root,
        ]
        .into_iter()
        .all(|item| item.status == ProbeStatus::Passed)
    }
}

/// Resource values shared with the cgroup boundary implemented by Task 9.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SandboxLimits {
    pub pids_max: u64,
    pub memory_max_bytes: u64,
    pub memory_swap_max_bytes: u64,
    pub cpu_quota_micros: u64,
    pub cpu_period_micros: u64,
    pub file_size_max_bytes: u64,
    pub open_files_max: u64,
    pub tmpfs_max_bytes: u64,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            pids_max: 16,
            memory_max_bytes: 512 * 1024 * 1024,
            memory_swap_max_bytes: 0,
            cpu_quota_micros: 100_000,
            cpu_period_micros: 100_000,
            file_size_max_bytes: 1024 * 1024 * 1024,
            open_files_max: 64,
            tmpfs_max_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Paths and resource limits declared by the trusted server for one job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxPolicy {
    pub input: PathBuf,
    pub job_dir: PathBuf,
    pub tool_dir: PathBuf,
    pub limits: SandboxLimits,
}

/// Parent-side resource control established before an untrusted tool runs.
///
/// Implementations must prepare their limits before returning a spawn
/// placement. `prepare_spawn` intentionally has no `attach(pid)` operation:
/// the placement is either atomic (`CloneIntoCgroup`) or a child-side barrier
/// whose ready/release pipe ends already belong to the resource controller.
pub trait ResourceBoundary: Send + Sync {
    fn prepare_spawn(&self) -> Result<SpawnPlacement, SandboxError>;
    fn kill_all(&self) -> Result<(), SandboxError>;
    fn is_empty(&self) -> Result<bool, SandboxError>;
}

/// Placement signal handed to a sandbox child before it can fork or exec a
/// tool. `ready` is the child-to-controller pipe; `release` is the controller-
/// to-child pipe. Their ownership transfers to `spawn_blocked`.
#[derive(Debug)]
pub enum SpawnPlacement {
    /// Linux `clone3(CLONE_INTO_CGROUP)` descriptor. The caller retains the
    /// descriptor; it must remain open until `spawn_blocked` returns.
    CloneIntoCgroup(i32),
    /// Child endpoints of a parent-attach barrier prepared by the controller.
    ParentAttachBarrier {
        ready: std::fs::File,
        release: std::fs::File,
    },
}

/// Fail-closed errors returned by the platform and namespace probes.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Linux filesystem isolation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("required Linux filesystem prerequisites failed: {0:?}")]
    Prerequisites(Box<FilesystemEvidence>),
    #[error("invalid sandbox policy: {0}")]
    InvalidPolicy(String),
    #[error("sandbox operation {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("sandbox child setup failed at {operation}: errno {errno}")]
    ChildSetup { operation: &'static str, errno: i32 },
}

/// Performs active checks for the Linux namespace and filesystem primitives.
pub struct FilesystemPrerequisites;

impl FilesystemPrerequisites {
    pub fn inspect() -> Result<FilesystemEvidence, SandboxError> {
        #[cfg(target_os = "linux")]
        {
            linux::inspect_prerequisites()
        }

        #[cfg(not(target_os = "linux"))]
        {
            Err(SandboxError::UnsupportedPlatform)
        }
    }
}

/// The sandbox launcher. `spawn_blocked` returns only after setup is complete;
/// a parent-attach child remains blocked until its controller releases it.
pub struct Sandbox;

impl Sandbox {
    pub fn spawn_blocked(
        program: &Path,
        args: &[OsString],
        policy: &SandboxPolicy,
        placement: SpawnPlacement,
    ) -> Result<SandboxChild, SandboxError> {
        #[cfg(target_os = "linux")]
        {
            linux::spawn_blocked(program, args, policy, placement)
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = (program, args, policy, placement);
            Err(SandboxError::UnsupportedPlatform)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct SandboxChild;

#[cfg(target_os = "linux")]
pub struct SandboxChild {
    pid: libc::pid_t,
    root: Option<linux::TempRoot>,
    status: Option<std::process::ExitStatus>,
}

#[cfg(target_os = "linux")]
impl SandboxChild {
    /// Host PID of the trusted supervisor, which is the barrier PID in
    /// `ParentAttachBarrier` mode.
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        if let Some(status) = self.status {
            return Ok(status);
        }
        let status = linux::wait_for_child(self.pid)?;
        self.status = Some(status);
        self.root.take();
        Ok(status)
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if let Some(status) = self.status {
            return Ok(Some(status));
        }
        let Some(status) = linux::try_wait_for_child(self.pid)? else {
            return Ok(None);
        };
        self.status = Some(status);
        self.root.take();
        Ok(Some(status))
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.status.is_some() {
            return Ok(());
        }
        linux::kill_process_group(self.pid)?;
        let _ = self.wait()?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for SandboxChild {
    fn drop(&mut self) {
        if self.status.is_none() {
            let _ = linux::kill_process_group(self.pid);
            if let Ok(status) = linux::wait_for_child(self.pid) {
                self.status = Some(status);
            }
        }
        self.root.take();
    }
}

#[cfg(target_os = "linux")]
// Each unsafe function is a narrow syscall/FFI sequence; callers only enter
// these helpers through the explicitly unsafe setup boundary.
#[allow(unsafe_op_in_unsafe_fn)]
mod linux {
    use super::{
        FilesystemEvidence, FilesystemPrerequisites, ProbeEvidence, SandboxChild, SandboxError,
        SandboxLimits, SandboxPolicy, SpawnPlacement,
    };
    use std::ffi::CString;
    use std::fs;
    use std::io;
    use std::mem::{size_of, zeroed};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    const MSG_READY: u32 = 1;
    const MSG_ERROR: u32 = 2;
    const PROBE_OK: i32 = 0;
    const STAGE_FORK: i32 = 1;
    const STAGE_USERNS: i32 = 2;
    const STAGE_UID_MAP: i32 = 3;
    const STAGE_GID_MAP: i32 = 4;
    const STAGE_SETIDS: i32 = 5;
    const STAGE_MOUNTNS: i32 = 6;
    const STAGE_PRIVATE_MOUNTS: i32 = 7;
    const STAGE_TMPFS: i32 = 8;
    const STAGE_MKDIR: i32 = 9;
    const STAGE_BIND_INPUT: i32 = 10;
    const STAGE_BIND_TOOL: i32 = 11;
    const STAGE_BIND_TASK: i32 = 12;
    const STAGE_BIND_RO: i32 = 13;
    const STAGE_PIVOT_ROOT: i32 = 14;
    const STAGE_OLD_ROOT: i32 = 15;
    const STAGE_NO_NEW_PRIVS: i32 = 16;
    const STAGE_CAP_DROP: i32 = 17;
    const STAGE_RLIMIT: i32 = 18;
    const STAGE_FD_CLOSE: i32 = 19;
    const STAGE_READY_WRITE: i32 = 20;
    const STAGE_RELEASE_READ: i32 = 21;
    const STAGE_FORK_TOOL: i32 = 22;
    const STAGE_EXEC_TOOL: i32 = 23;
    const STAGE_CLONE3: i32 = 24;
    const STAGE_REPORT_WRITE: i32 = 25;
    const STAGE_TOOL_WAIT: i32 = 26;
    const STAGE_SECCOMP: i32 = 27;
    const STAGE_TASK_CWD: i32 = 28;
    const STAGE_PID_NAMESPACE: i32 = 29;
    const CLONE_INTO_CGROUP: u64 = 1 << 33;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
    const CAP_VERSION_3: u32 = 0x2008_0522;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Message {
        kind: u32,
        operation: i32,
        errno: i32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProbeResult {
        operation: i32,
        errno: i32,
    }

    #[repr(C)]
    struct CapabilityHeader {
        version: u32,
        pid: i32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapabilityData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }

    #[repr(C)]
    struct CloneArgs {
        flags: u64,
        pidfd: u64,
        child_tid: u64,
        parent_tid: u64,
        exit_signal: u64,
        stack: u64,
        stack_size: u64,
        tls: u64,
        set_tid: u64,
        set_tid_size: u64,
        cgroup: u64,
    }

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn create() -> io::Result<Self> {
            let parent = std::env::temp_dir();
            for _ in 0..32 {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let sequence = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let path = parent.join(format!(
                    "fluxform-sandbox-{}-{now:x}-{sequence:x}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(error) =
                            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                        {
                            let _ = fs::remove_dir(&path);
                            return Err(error);
                        }
                        return Ok(Self(path));
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error),
                }
            }
            Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "could not allocate a unique sandbox temporary root",
            ))
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct RootPaths {
        base: CString,
        input: CString,
        task: CString,
        tool: CString,
        tmp: CString,
        oldroot: CString,
        lib: CString,
        lib64: CString,
        usr: CString,
    }

    impl RootPaths {
        fn new(root: &Path) -> Result<Self, SandboxError> {
            let path = |name: &str| -> Result<CString, SandboxError> {
                CString::new(root.join(name).as_os_str().as_bytes())
                    .map_err(|_| SandboxError::InvalidPolicy("temporary root contains NUL".into()))
            };
            Ok(Self {
                base: c_path(root)?,
                input: path("input")?,
                task: path("task")?,
                tool: path("tool")?,
                tmp: path("tmp")?,
                oldroot: path(".oldroot")?,
                lib: path("lib")?,
                lib64: path("lib64")?,
                usr: path("usr")?,
            })
        }
    }

    struct PlacementFds {
        cgroup: Option<RawFd>,
        ready: Option<RawFd>,
        release: Option<RawFd>,
    }

    struct PreparedSpawn {
        root: RootPaths,
        input_source: CString,
        task_source: CString,
        tool_source: CString,
        uid_map: CString,
        gid_map: CString,
        tmpfs_data: CString,
        limits: SandboxLimits,
        placement: PlacementFds,
        _placement_owners: Vec<OwnedFd>,
        report_fd: RawFd,
        null_fd: RawFd,
        program: CString,
        _exec_strings: Vec<CString>,
        argv: Vec<usize>,
        envp: [usize; 1],
        seccomp: Vec<libc::sock_filter>,
    }

    pub(super) fn inspect_prerequisites() -> Result<FilesystemEvidence, SandboxError> {
        let temporary_root = match TempRoot::create() {
            Ok(root) => ProbeEvidence::passed(format!(
                "created private temporary root {} with mode 0700",
                root.path().display()
            )),
            Err(error) => ProbeEvidence::failed(format!("temporary root creation failed: {error}")),
        };
        let probe_root = TempRoot::create().ok();
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };

        let user_namespace = probe_result(
            run_probe(ProbeKind::UserNamespace, None, host_uid, host_gid),
            "created and mapped a rootless user namespace",
        );
        let pid_namespace = probe_result(
            run_probe(ProbeKind::PidNamespace, None, host_uid, host_gid),
            "created a PID namespace and verified its init process has PID 1",
        );
        let mount_isolation = match probe_root.as_ref() {
            Some(root) => {
                let result = run_probe(
                    ProbeKind::MountIsolation,
                    Some(root.path()),
                    host_uid,
                    host_gid,
                );
                match result {
                    Ok(result) if result.operation == PROBE_OK => {
                        if matches!(
                            fs::read_dir(root.path()).map(|mut entries| entries.next().is_none()),
                            Ok(true)
                        ) {
                            ProbeEvidence::passed(
                                "private mount namespace hid the tmpfs marker from the host view",
                            )
                        } else {
                            ProbeEvidence::failed("mount marker escaped the child mount namespace")
                        }
                    }
                    other => probe_result(other, "private mount namespace and tmpfs mount"),
                }
            }
            None => {
                ProbeEvidence::failed("mount isolation could not run: temporary root unavailable")
            }
        };
        let pivot_root = match probe_root.as_ref() {
            Some(root) => probe_result(
                run_probe(ProbeKind::PivotRoot, Some(root.path()), host_uid, host_gid),
                "pivot_root detached the host root and hid /etc/passwd",
            ),
            None => ProbeEvidence::failed("pivot_root could not run: temporary root unavailable"),
        };
        let capability_drop = probe_result(
            run_probe(ProbeKind::CapabilityDrop, None, host_uid, host_gid),
            "no_new_privs was set and capability sets were emptied",
        );
        let descriptor_closure = probe_descriptor_closure();

        let evidence = FilesystemEvidence {
            user_namespace,
            pid_namespace,
            mount_isolation,
            pivot_root,
            capability_drop,
            descriptor_closure,
            temporary_root,
        };
        if evidence.all_passed() {
            Ok(evidence)
        } else {
            Err(SandboxError::Prerequisites(Box::new(evidence)))
        }
    }

    fn probe_result(result: io::Result<ProbeResult>, success: &str) -> ProbeEvidence {
        match result {
            Ok(ProbeResult {
                operation: PROBE_OK,
                ..
            }) => ProbeEvidence::passed(success),
            Ok(result) => ProbeEvidence::failed(format!(
                "operation {} failed with errno {}",
                result.operation, result.errno
            )),
            Err(error) => ProbeEvidence::failed(format!("probe process failed: {error}")),
        }
    }

    #[derive(Clone, Copy)]
    enum ProbeKind {
        UserNamespace,
        PidNamespace,
        MountIsolation,
        PivotRoot,
        CapabilityDrop,
    }

    fn run_probe(
        kind: ProbeKind,
        scratch: Option<&Path>,
        host_uid: libc::uid_t,
        host_gid: libc::gid_t,
    ) -> io::Result<ProbeResult> {
        let scratch = scratch.map(path_to_cstring).transpose()?;
        let uid_map = CString::new(map_line(host_uid)).expect("generated uid map contains no NUL");
        let gid_map = CString::new(map_line(host_gid)).expect("generated gid map contains no NUL");
        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            return Err(io::Error::last_os_error());
        }
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
                let result = run_probe_child(kind, scratch.as_ref(), &uid_map, &gid_map);
                write_struct(pipe[1], &result);
                libc::_exit(if result.operation == PROBE_OK { 0 } else { 1 });
            }
        }

        unsafe { libc::close(pipe[1]) };
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let mut result = ProbeResult {
            operation: STAGE_FORK,
            errno: libc::ECHILD,
        };
        if let Err(error) = read_struct(&mut reader, &mut result) {
            abort_probe(pid);
            return Err(error);
        }
        let status = reap_probe(pid)?;
        if !libc::WIFEXITED(status)
            || (result.operation == PROBE_OK && libc::WEXITSTATUS(status) != 0)
        {
            return Ok(ProbeResult {
                operation: STAGE_FORK,
                errno: libc::ECHILD,
            });
        }
        Ok(result)
    }

    fn probe_descriptor_closure() -> ProbeEvidence {
        let sentinel = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) };
        if sentinel < 0 {
            return ProbeEvidence::failed(format!(
                "could not open descriptor-closure sentinel: {}",
                io::Error::last_os_error()
            ));
        }
        let flags = unsafe { libc::fcntl(sentinel, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(sentinel, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0
        {
            unsafe { libc::close(sentinel) };
            return ProbeEvidence::failed(format!(
                "could not make descriptor-closure sentinel inheritable: {}",
                io::Error::last_os_error()
            ));
        }

        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            unsafe { libc::close(sentinel) };
            return ProbeEvidence::failed(format!(
                "could not create descriptor-closure report pipe: {}",
                io::Error::last_os_error()
            ));
        }
        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
                libc::close(sentinel);
            }
            return ProbeEvidence::failed(format!(
                "could not fork descriptor-closure probe: {}",
                io::Error::last_os_error()
            ));
        }
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
                let result = if close_range_except(&[pipe[1]]) == 0
                    && libc::fcntl(sentinel, libc::F_GETFD) < 0
                    && errno() == libc::EBADF
                {
                    ProbeResult {
                        operation: PROBE_OK,
                        errno: 0,
                    }
                } else {
                    ProbeResult {
                        operation: STAGE_FD_CLOSE,
                        errno: errno(),
                    }
                };
                write_struct(pipe[1], &result);
                libc::_exit(if result.operation == PROBE_OK { 0 } else { 1 });
            }
        }

        unsafe {
            libc::close(pipe[1]);
            libc::close(sentinel);
        }
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let mut result = ProbeResult {
            operation: STAGE_FD_CLOSE,
            errno: libc::ECHILD,
        };
        if let Err(error) = read_struct(&mut reader, &mut result) {
            abort_probe(pid);
            return ProbeEvidence::failed(format!("descriptor-closure probe failed: {error}"));
        }
        if let Err(error) = reap_probe(pid) {
            return ProbeEvidence::failed(format!(
                "could not reap descriptor-closure probe: {error}"
            ));
        }
        match result.operation {
            PROBE_OK => ProbeEvidence::passed(
                "close_range removed an inheritable undeclared descriptor before exec",
            ),
            operation => ProbeEvidence::failed(format!(
                "descriptor closure operation {operation} failed with errno {}",
                result.errno
            )),
        }
    }

    fn reap_probe(pid: libc::pid_t) -> io::Result<i32> {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, 0) };
            if result == pid {
                return Ok(status);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    fn abort_probe(pid: libc::pid_t) {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let _ = reap_probe(pid);
    }

    unsafe fn run_probe_child(
        kind: ProbeKind,
        scratch: Option<&CString>,
        uid_map: &CString,
        gid_map: &CString,
    ) -> ProbeResult {
        match kind {
            ProbeKind::UserNamespace => match enter_user_namespace_from_maps(uid_map, gid_map) {
                Ok(()) => success(),
                Err(result) => result,
            },
            ProbeKind::PidNamespace => {
                if let Err(result) = enter_user_namespace_from_maps(uid_map, gid_map) {
                    return result;
                }
                if libc::unshare(libc::CLONE_NEWPID) != 0 {
                    return failed(STAGE_PID_NAMESPACE);
                }
                let child = libc::fork();
                if child < 0 {
                    return failed(STAGE_PID_NAMESPACE);
                }
                if child == 0 {
                    libc::_exit(if libc::getpid() == 1 { 0 } else { 1 });
                }
                let mut status = 0;
                loop {
                    let waited = libc::waitpid(child, &mut status, 0);
                    if waited == child {
                        break;
                    }
                    if waited < 0 && errno() == libc::EINTR {
                        continue;
                    }
                    return failed(STAGE_PID_NAMESPACE);
                }
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
                    success()
                } else {
                    failed_with_errno(STAGE_PID_NAMESPACE, libc::EPROTO)
                }
            }
            ProbeKind::MountIsolation => {
                if let Err(result) = enter_user_namespace_from_maps(uid_map, gid_map) {
                    return result;
                }
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return failed(STAGE_MOUNTNS);
                }
                if libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                {
                    return failed(STAGE_PRIVATE_MOUNTS);
                }
                let Some(scratch) = scratch else {
                    return failed_with_errno(STAGE_TMPFS, libc::EINVAL);
                };
                if mount_tmpfs(scratch, b"mode=700,size=4m\0") != 0 {
                    return failed(STAGE_TMPFS);
                }
                if libc::chdir(scratch.as_ptr()) != 0
                    || libc::mkdir(c"mount-probe-marker".as_ptr(), 0o700) != 0
                {
                    return failed(STAGE_MKDIR);
                }
                success()
            }
            ProbeKind::PivotRoot => {
                if let Err(result) = enter_user_namespace_from_maps(uid_map, gid_map) {
                    return result;
                }
                if libc::unshare(libc::CLONE_NEWNS) != 0 {
                    return failed(STAGE_MOUNTNS);
                }
                if libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
                {
                    return failed(STAGE_PRIVATE_MOUNTS);
                }
                let Some(scratch) = scratch else {
                    return failed_with_errno(STAGE_TMPFS, libc::EINVAL);
                };
                if mount_tmpfs(scratch, b"mode=755,size=4m\0") != 0 {
                    return failed(STAGE_TMPFS);
                }
                if libc::chdir(scratch.as_ptr()) != 0
                    || libc::mkdir(c".oldroot".as_ptr(), 0o700) != 0
                {
                    return failed(STAGE_MKDIR);
                }
                if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".oldroot".as_ptr()) < 0 {
                    return failed(STAGE_PIVOT_ROOT);
                }
                if libc::chdir(c"/".as_ptr()) != 0 {
                    return failed(STAGE_PIVOT_ROOT);
                }
                let outside = libc::open(c"/etc/passwd".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                if outside >= 0 {
                    libc::close(outside);
                    return failed_with_errno(STAGE_OLD_ROOT, libc::EACCES);
                }
                if libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH) != 0
                    || libc::rmdir(c"/.oldroot".as_ptr()) != 0
                {
                    return failed(STAGE_OLD_ROOT);
                }
                success()
            }
            ProbeKind::CapabilityDrop => match enter_user_namespace_from_maps(uid_map, gid_map) {
                Ok(()) => drop_capabilities_and_set_no_new_privs(),
                Err(result) => result,
            },
        }
    }

    fn map_line(id: u32) -> Vec<u8> {
        format!("0 {id} 1\n").into_bytes()
    }

    unsafe fn write_proc(path: &std::ffi::CStr, bytes: &[u8]) -> i32 {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return -errno();
        }
        let mut written = 0;
        while written < bytes.len() {
            let count = libc::write(fd, bytes[written..].as_ptr().cast(), bytes.len() - written);
            if count < 0 {
                let error = errno();
                libc::close(fd);
                return -error;
            }
            if count == 0 {
                libc::close(fd);
                return -libc::EIO;
            }
            written += count as usize;
        }
        if libc::close(fd) != 0 {
            return -errno();
        }
        0
    }

    unsafe fn enter_user_namespace_from_maps(
        uid_map: &CString,
        gid_map: &CString,
    ) -> Result<(), ProbeResult> {
        if libc::unshare(libc::CLONE_NEWUSER) != 0 {
            return Err(failed(STAGE_USERNS));
        }
        let setgroups = write_proc(c"/proc/self/setgroups", b"deny\n");
        if setgroups != 0 && setgroups != -libc::ENOENT {
            return Err(failed_with_errno(STAGE_GID_MAP, -setgroups));
        }
        let uid_result = write_proc(c"/proc/self/uid_map", uid_map.as_bytes());
        if uid_result != 0 {
            return Err(failed_with_errno(STAGE_UID_MAP, -uid_result));
        }
        let gid_result = write_proc(c"/proc/self/gid_map", gid_map.as_bytes());
        if gid_result != 0 {
            return Err(failed_with_errno(STAGE_GID_MAP, -gid_result));
        }
        if libc::setresgid(0, 0, 0) != 0 || libc::setresuid(0, 0, 0) != 0 {
            return Err(failed(STAGE_SETIDS));
        }
        Ok(())
    }

    unsafe fn drop_capabilities_and_set_no_new_privs() -> ProbeResult {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return failed(STAGE_NO_NEW_PRIVS);
        }
        if drop_capabilities() != 0 || libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 {
            return failed_with_errno(STAGE_CAP_DROP, libc::EPERM);
        }
        success()
    }

    pub(super) fn spawn_blocked(
        program: &Path,
        args: &[std::ffi::OsString],
        policy: &SandboxPolicy,
        placement: SpawnPlacement,
    ) -> Result<SandboxChild, SandboxError> {
        FilesystemPrerequisites::inspect()?;
        validate_limits(policy.limits)?;
        let input = open_pinned_path(&policy.input, false, "input")?;
        let task = open_pinned_path(&policy.job_dir, true, "task directory")?;
        let tool = open_pinned_path(&policy.tool_dir, true, "tool directory")?;
        let tool_dir = fs::canonicalize(&policy.tool_dir).map_err(|source| SandboxError::Io {
            operation: "canonicalize tool directory",
            source,
        })?;
        let program = fs::canonicalize(program).map_err(|source| SandboxError::Io {
            operation: "canonicalize tool executable",
            source,
        })?;
        if !program.starts_with(&tool_dir) {
            return Err(SandboxError::InvalidPolicy(
                "tool executable must be inside the declared tool directory".into(),
            ));
        }
        let metadata = fs::metadata(&program).map_err(|source| SandboxError::Io {
            operation: "inspect tool executable",
            source,
        })?;
        if !metadata.is_file() {
            return Err(SandboxError::InvalidPolicy(
                "tool executable is not a regular file".into(),
            ));
        }
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(SandboxError::InvalidPolicy(
                "tool executable has no execute permission".into(),
            ));
        }
        let relative_program = program.strip_prefix(&tool_dir).map_err(|_| {
            SandboxError::InvalidPolicy(
                "tool executable escaped the declared tool directory".into(),
            )
        })?;
        let virtual_program = Path::new("/tool").join(relative_program);
        let program_c = c_path(&virtual_program)?;
        let exec_strings = prepare_exec_strings(&program_c, args)?;
        let argv = exec_strings
            .iter()
            .map(|item| item.as_ptr() as usize)
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let temp_root = TempRoot::create().map_err(|source| SandboxError::Io {
            operation: "create private temporary root",
            source,
        })?;
        let root = RootPaths::new(temp_root.path())?;
        let input_source = proc_fd_path(input.as_raw_fd())?;
        let task_source = proc_fd_path(task.as_raw_fd())?;
        let tool_source = proc_fd_path(tool.as_raw_fd())?;
        let host_uid = unsafe { libc::getuid() };
        let host_gid = unsafe { libc::getgid() };
        let uid_map = map_line(host_uid);
        let gid_map = map_line(host_gid);
        let uid_map = CString::new(uid_map).expect("generated uid map contains no NUL");
        let gid_map = CString::new(gid_map).expect("generated gid map contains no NUL");
        let tmpfs_data = CString::new(format!("mode=1777,size={}", policy.limits.tmpfs_max_bytes))
            .expect("generated tmpfs options contain no NUL");
        let raw_null_fd =
            unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw_null_fd < 0 {
            return Err(SandboxError::Io {
                operation: "open null standard streams",
                source: io::Error::last_os_error(),
            });
        }
        let null_fd = if raw_null_fd < 3 {
            let duplicate = unsafe { libc::fcntl(raw_null_fd, libc::F_DUPFD_CLOEXEC, 3) };
            unsafe { libc::close(raw_null_fd) };
            if duplicate < 0 {
                return Err(SandboxError::Io {
                    operation: "reserve null standard-stream descriptor",
                    source: io::Error::last_os_error(),
                });
            }
            duplicate
        } else {
            raw_null_fd
        };
        let (placement_fds, placement_owners) = placement_fds(&placement)?;
        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            unsafe { libc::close(null_fd) };
            return Err(SandboxError::Io {
                operation: "create child setup report pipe",
                source: io::Error::last_os_error(),
            });
        }
        let seccomp = build_filesystem_filter();
        let spec = PreparedSpawn {
            root,
            input_source,
            task_source,
            tool_source,
            uid_map,
            gid_map,
            tmpfs_data,
            limits: policy.limits,
            placement: placement_fds,
            _placement_owners: placement_owners,
            report_fd: pipe[1],
            null_fd,
            program: program_c,
            _exec_strings: exec_strings,
            argv,
            envp: [0],
            seccomp,
        };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
                libc::close(null_fd);
            }
            return Err(SandboxError::Io {
                operation: "fork sandbox setup process",
                source: io::Error::last_os_error(),
            });
        }
        if pid == 0 {
            unsafe {
                libc::close(pipe[0]);
                sandbox_supervisor(&spec);
            }
        }

        unsafe {
            libc::close(pipe[1]);
            libc::close(null_fd);
        }
        drop(placement);
        drop(input);
        drop(task);
        drop(tool);
        let mut report = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let mut message = Message {
            kind: MSG_ERROR,
            operation: STAGE_FORK,
            errno: libc::ECHILD,
            pid,
        };
        if let Err(source) = read_struct(&mut report, &mut message) {
            let _ = kill_process_group(pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "read sandbox setup report",
                source,
            });
        }
        if message.kind == MSG_ERROR {
            let _ = wait_for_child(pid);
            return Err(SandboxError::ChildSetup {
                operation: operation_name(message.operation),
                errno: message.errno,
            });
        }
        if message.kind != MSG_READY || message.pid != pid {
            let _ = kill_process_group(pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "validate sandbox setup report",
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid child readiness message",
                ),
            });
        }
        Ok(SandboxChild {
            pid,
            root: Some(temp_root),
            status: None,
        })
    }

    fn placement_fds(
        placement: &SpawnPlacement,
    ) -> Result<(PlacementFds, Vec<OwnedFd>), SandboxError> {
        match placement {
            SpawnPlacement::CloneIntoCgroup(fd) => {
                let owner = duplicate_fd(*fd)?;
                let raw = owner.as_raw_fd();
                Ok((
                    PlacementFds {
                        cgroup: Some(raw),
                        ready: None,
                        release: None,
                    },
                    vec![owner],
                ))
            }
            SpawnPlacement::ParentAttachBarrier { ready, release } => {
                let ready = duplicate_fd(ready.as_raw_fd())?;
                let release = duplicate_fd(release.as_raw_fd())?;
                let ready_fd = ready.as_raw_fd();
                let release_fd = release.as_raw_fd();
                Ok((
                    PlacementFds {
                        cgroup: None,
                        ready: Some(ready_fd),
                        release: Some(release_fd),
                    },
                    vec![ready, release],
                ))
            }
        }
    }

    fn duplicate_fd(fd: RawFd) -> Result<OwnedFd, SandboxError> {
        let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
        if duplicate < 0 {
            return Err(SandboxError::Io {
                operation: "duplicate sandbox placement descriptor",
                source: io::Error::last_os_error(),
            });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }

    fn validate_limits(limits: SandboxLimits) -> Result<(), SandboxError> {
        if limits.pids_max == 0
            || limits.memory_max_bytes == 0
            || limits.cpu_quota_micros == 0
            || limits.cpu_period_micros == 0
            || limits.file_size_max_bytes == 0
            || limits.open_files_max < 4
            || limits.tmpfs_max_bytes == 0
        {
            return Err(SandboxError::InvalidPolicy(
                "all resource limits must be positive and open_files_max must be at least four"
                    .into(),
            ));
        }
        Ok(())
    }

    fn open_pinned_path(
        path: &Path,
        directory: bool,
        label: &'static str,
    ) -> Result<OwnedFd, SandboxError> {
        let path = fs::canonicalize(path).map_err(|source| SandboxError::Io {
            operation: "canonicalize declared sandbox path",
            source,
        })?;
        let c_path = c_path(&path)?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(SandboxError::Io {
                operation: "open declared sandbox path",
                source: io::Error::last_os_error(),
            });
        }
        let mut metadata: libc::stat = unsafe { zeroed() };
        if unsafe { libc::fstat(fd, &mut metadata) } != 0 {
            let source = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(SandboxError::Io {
                operation: "inspect declared sandbox path",
                source,
            });
        }
        let file_type = metadata.st_mode & libc::S_IFMT;
        let expected = if directory {
            libc::S_IFDIR
        } else {
            libc::S_IFREG
        };
        if file_type != expected {
            unsafe { libc::close(fd) };
            return Err(SandboxError::InvalidPolicy(format!(
                "declared {label} is not a {}",
                if directory {
                    "directory"
                } else {
                    "regular file"
                }
            )));
        }
        if fd < 3 {
            let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                let source = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(SandboxError::Io {
                    operation: "reserve declared sandbox path descriptor",
                    source,
                });
            }
            unsafe { libc::close(fd) };
            return Ok(unsafe { OwnedFd::from_raw_fd(duplicate) });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn prepare_exec_strings(
        program: &CString,
        args: &[std::ffi::OsString],
    ) -> Result<Vec<CString>, SandboxError> {
        let mut result = Vec::with_capacity(args.len() + 1);
        result.push(program.clone());
        for arg in args {
            result.push(CString::new(arg.as_os_str().as_bytes()).map_err(|_| {
                SandboxError::InvalidPolicy("tool argument contains an interior NUL byte".into())
            })?);
        }
        Ok(result)
    }

    fn c_path(path: &Path) -> Result<CString, SandboxError> {
        CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            SandboxError::InvalidPolicy("sandbox path contains an interior NUL".into())
        })
    }

    fn path_to_cstring(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
    }

    fn proc_fd_path(fd: RawFd) -> Result<CString, SandboxError> {
        CString::new(format!("/proc/self/fd/{fd}"))
            .map_err(|_| SandboxError::InvalidPolicy("invalid pinned file descriptor".into()))
    }

    unsafe fn sandbox_supervisor(spec: &PreparedSpawn) -> ! {
        if libc::setpgid(0, 0) != 0 {
            fail_and_exit(spec.report_fd, STAGE_FORK, errno());
        }
        if libc::dup2(spec.null_fd, 0) < 0
            || libc::dup2(spec.null_fd, 1) < 0
            || libc::dup2(spec.null_fd, 2) < 0
        {
            fail_and_exit(spec.report_fd, STAGE_FORK, errno());
        }
        libc::close(spec.null_fd);

        if let Err(result) = enter_user_namespace_from_maps(&spec.uid_map, &spec.gid_map) {
            fail_and_exit(spec.report_fd, result.operation, result.errno);
        }
        if libc::unshare(libc::CLONE_NEWNS) != 0 {
            fail_and_exit(spec.report_fd, STAGE_MOUNTNS, errno());
        }
        if libc::unshare(libc::CLONE_NEWPID) != 0 {
            fail_and_exit(spec.report_fd, STAGE_MOUNTNS, errno());
        }
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REC | libc::MS_PRIVATE,
            std::ptr::null(),
        ) != 0
        {
            fail_and_exit(spec.report_fd, STAGE_PRIVATE_MOUNTS, errno());
        }
        if mount_tmpfs(&spec.root.base, b"mode=755,size=16m\0") != 0 {
            fail_and_exit(spec.report_fd, STAGE_TMPFS, errno());
        }
        if make_root_layout(&spec.root) != 0 {
            fail_and_exit(spec.report_fd, STAGE_MKDIR, errno());
        }
        if mount_bind(&spec.input_source, &spec.root.input) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_INPUT, errno());
        }
        if remount_read_only(&spec.root.input, true) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_RO, errno());
        }
        if mount_bind(&spec.tool_source, &spec.root.tool) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_TOOL, errno());
        }
        if remount_read_only(&spec.root.tool, false) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_RO, errno());
        }
        if mount_bind(&spec.task_source, &spec.root.task) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_TASK, errno());
        }
        if remount_task_restricted(&spec.root.task) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_TASK, errno());
        }
        if mount_tmpfs(&spec.root.tmp, spec.tmpfs_data.as_bytes_with_nul()) != 0 {
            fail_and_exit(spec.report_fd, STAGE_TMPFS, errno());
        }
        if pivot_to_root(&spec.root.base) != 0 {
            fail_and_exit(spec.report_fd, STAGE_PIVOT_ROOT, errno());
        }
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        ) != 0
        {
            fail_and_exit(spec.report_fd, STAGE_BIND_RO, errno());
        }
        if libc::chdir(c"/task".as_ptr()) != 0 {
            fail_and_exit(spec.report_fd, STAGE_TASK_CWD, errno());
        }
        libc::umask(0o077);
        if apply_rlimits(spec.limits) != 0 {
            fail_and_exit(spec.report_fd, STAGE_RLIMIT, errno());
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            fail_and_exit(spec.report_fd, STAGE_NO_NEW_PRIVS, errno());
        }
        if drop_capabilities() != 0 {
            fail_and_exit(spec.report_fd, STAGE_CAP_DROP, errno());
        }

        match (spec.placement.ready, spec.placement.release) {
            (Some(ready), Some(release)) => {
                let keep = [spec.report_fd, ready, release];
                if close_range_except(&keep) != 0 {
                    fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, errno());
                }
                let pid = libc::getpid();
                if write_all(
                    ready,
                    (&pid as *const libc::pid_t).cast(),
                    size_of::<libc::pid_t>(),
                ) != 0
                {
                    fail_and_exit(spec.report_fd, STAGE_READY_WRITE, errno());
                }
                send_message(
                    spec.report_fd,
                    Message {
                        kind: MSG_READY,
                        operation: PROBE_OK,
                        errno: 0,
                        pid,
                    },
                );
                let mut release_byte = 0_u8;
                if read_one(release, &mut release_byte) != 1 || release_byte != 1 {
                    fail_and_exit(spec.report_fd, STAGE_RELEASE_READ, errno());
                }
                libc::close(ready);
                libc::close(release);
                libc::close(spec.report_fd);
                let child = libc::fork();
                if child < 0 {
                    libc::_exit(127);
                }
                if child == 0 {
                    if install_seccomp(&spec.seccomp) != 0 {
                        libc::_exit(127);
                    }
                    libc::execve(
                        spec.program.as_ptr(),
                        spec.argv.as_ptr().cast(),
                        spec.envp.as_ptr().cast(),
                    );
                    libc::_exit(127);
                }
                wait_target_or_exit(child);
            }
            (None, None) => {
                let Some(cgroup_fd) = spec.placement.cgroup else {
                    fail_and_exit(spec.report_fd, STAGE_CLONE3, libc::EINVAL);
                };
                let keep = [spec.report_fd, cgroup_fd];
                if close_range_except(&keep) != 0 {
                    fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, errno());
                }
                let flags = libc::fcntl(cgroup_fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(cgroup_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
                {
                    fail_and_exit(spec.report_fd, STAGE_CLONE3, errno());
                }
                let args = CloneArgs {
                    flags: CLONE_INTO_CGROUP,
                    pidfd: 0,
                    child_tid: 0,
                    parent_tid: 0,
                    exit_signal: libc::SIGCHLD as u64,
                    stack: 0,
                    stack_size: 0,
                    tls: 0,
                    set_tid: 0,
                    set_tid_size: 0,
                    cgroup: cgroup_fd as u64,
                };
                let child =
                    libc::syscall(libc::SYS_clone3, &args, size_of::<CloneArgs>()) as libc::pid_t;
                if child < 0 {
                    fail_and_exit(spec.report_fd, STAGE_CLONE3, errno());
                }
                if child == 0 {
                    if install_seccomp(&spec.seccomp) != 0 {
                        libc::_exit(127);
                    }
                    libc::execve(
                        spec.program.as_ptr(),
                        spec.argv.as_ptr().cast(),
                        spec.envp.as_ptr().cast(),
                    );
                    libc::_exit(127);
                }
                send_message(
                    spec.report_fd,
                    Message {
                        kind: MSG_READY,
                        operation: PROBE_OK,
                        errno: 0,
                        pid: libc::getpid(),
                    },
                );
                libc::close(cgroup_fd);
                libc::close(spec.report_fd);
                wait_target_or_exit(child);
            }
            _ => fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, libc::EINVAL),
        }
    }

    unsafe fn make_root_layout(root: &RootPaths) -> i32 {
        let input_fd = libc::open(
            root.input.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o444,
        );
        if input_fd < 0 {
            return -1;
        }
        libc::close(input_fd);
        if libc::mkdir(root.oldroot.as_ptr(), 0o700) != 0
            || libc::mkdir(root.task.as_ptr(), 0o755) != 0
            || libc::mkdir(root.tool.as_ptr(), 0o755) != 0
            || libc::mkdir(root.tmp.as_ptr(), 0o1777) != 0
        {
            return -1;
        }
        if libc::symlink(c"/tool/lib".as_ptr(), root.lib.as_ptr()) != 0
            || libc::symlink(c"/tool/lib64".as_ptr(), root.lib64.as_ptr()) != 0
            || libc::symlink(c"/tool/usr".as_ptr(), root.usr.as_ptr()) != 0
        {
            return -1;
        }
        0
    }

    unsafe fn mount_tmpfs(target: &CString, data: &[u8]) -> i32 {
        libc::mount(
            c"tmpfs".as_ptr(),
            target.as_ptr(),
            c"tmpfs".as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            data.as_ptr().cast(),
        )
    }

    unsafe fn mount_bind(source: &CString, target: &CString) -> i32 {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    }

    unsafe fn remount_read_only(target: &CString, noexec: bool) -> i32 {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND
                | libc::MS_REMOUNT
                | libc::MS_RDONLY
                | libc::MS_NOSUID
                | libc::MS_NODEV
                | if noexec { libc::MS_NOEXEC } else { 0 },
            std::ptr::null(),
        )
    }

    unsafe fn remount_task_restricted(target: &CString) -> i32 {
        libc::mount(
            std::ptr::null(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND | libc::MS_REMOUNT | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    }

    unsafe fn pivot_to_root(root: &CString) -> i32 {
        if libc::chdir(root.as_ptr()) != 0 {
            return -1;
        }
        if libc::syscall(libc::SYS_pivot_root, c".".as_ptr(), c".oldroot".as_ptr()) < 0 {
            return -1;
        }
        if libc::chdir(c"/".as_ptr()) != 0 {
            return -1;
        }
        if libc::umount2(c"/.oldroot".as_ptr(), libc::MNT_DETACH) != 0 {
            return -1;
        }
        libc::rmdir(c"/.oldroot".as_ptr())
    }

    unsafe fn apply_rlimits(limits: SandboxLimits) -> i32 {
        let file_size = libc::rlimit {
            rlim_cur: limits.file_size_max_bytes as libc::rlim_t,
            rlim_max: limits.file_size_max_bytes as libc::rlim_t,
        };
        if libc::setrlimit(libc::RLIMIT_FSIZE, &file_size) != 0 {
            return -1;
        }
        let open_files = libc::rlimit {
            rlim_cur: limits.open_files_max as libc::rlim_t,
            rlim_max: limits.open_files_max as libc::rlim_t,
        };
        libc::setrlimit(libc::RLIMIT_NOFILE, &open_files)
    }

    unsafe fn drop_capabilities() -> i32 {
        for capability in 0..64 {
            if libc::prctl(libc::PR_CAPBSET_DROP, capability, 0, 0, 0) != 0
                && errno() != libc::EINVAL
            {
                return -1;
            }
        }
        let header = CapabilityHeader {
            version: CAP_VERSION_3,
            pid: 0,
        };
        let empty = [
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
            CapabilityData {
                effective: 0,
                permitted: 0,
                inheritable: 0,
            },
        ];
        if libc::syscall(libc::SYS_capset, &header, empty.as_ptr()) < 0 {
            return -1;
        }
        let mut actual = [zeroed::<CapabilityData>(); 2];
        if libc::syscall(libc::SYS_capget, &header, actual.as_mut_ptr()) < 0 {
            return -1;
        }
        let empty_sets = actual
            .iter()
            .all(|word| word.effective == 0 && word.permitted == 0 && word.inheritable == 0);
        if !empty_sets {
            *libc::__errno_location() = libc::EPERM;
            return -1;
        }
        0
    }

    fn build_filesystem_filter() -> Vec<libc::sock_filter> {
        let denied = [
            libc::SYS_mount as u32,
            libc::SYS_umount2 as u32,
            libc::SYS_pivot_root as u32,
            libc::SYS_unshare as u32,
            libc::SYS_setns as u32,
            libc::SYS_clone3 as u32,
            libc::SYS_open_tree as u32,
            libc::SYS_move_mount as u32,
            libc::SYS_fsopen as u32,
            libc::SYS_fsmount as u32,
            libc::SYS_fspick as u32,
            libc::SYS_mount_setattr as u32,
            libc::SYS_chroot as u32,
            libc::SYS_setpgid as u32,
            libc::SYS_setsid as u32,
        ];
        let mut filter = Vec::with_capacity(3 + denied.len() * 2 + 5);
        filter.push(bpf_stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_ARCH_OFFSET,
        ));
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            audit_arch(),
            1,
            0,
        ));
        filter.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_KILL_PROCESS,
        ));
        filter.push(bpf_stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_NR_OFFSET,
        ));
        #[cfg(target_arch = "x86_64")]
        {
            filter.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
                0x4000_0000,
                0,
                1,
            ));
            filter.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_KILL_PROCESS,
            ));
        }
        for syscall_number in denied {
            filter.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                syscall_number,
                0,
                1,
            ));
            filter.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            ));
        }
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_clone as u32,
            0,
            3,
        ));
        filter.push(bpf_stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_ARGS_OFFSET,
        ));
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K,
            namespace_clone_mask(),
            0,
            1,
        ));
        filter.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
        ));
        filter.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ALLOW,
        ));
        filter
    }

    fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }

    fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    fn audit_arch() -> u32 {
        #[cfg(target_arch = "x86_64")]
        {
            0xc000_003e
        }
        #[cfg(target_arch = "aarch64")]
        {
            0xc000_00b7
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            0
        }
    }

    fn namespace_clone_mask() -> u32 {
        (libc::CLONE_NEWNS
            | libc::CLONE_NEWCGROUP
            | libc::CLONE_NEWUTS
            | libc::CLONE_NEWIPC
            | libc::CLONE_NEWUSER
            | libc::CLONE_NEWPID
            | libc::CLONE_NEWNET
            | libc::CLONE_NEWTIME) as u32
    }

    unsafe fn install_seccomp(filter: &[libc::sock_filter]) -> i32 {
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program,
            0,
            0,
        ) as i32
    }

    unsafe fn close_range_except(keep: &[RawFd]) -> i32 {
        let mut kept = [0_i32; 8];
        let mut count = 0;
        for fd in keep.iter().copied().filter(|fd| *fd >= 3) {
            if count == kept.len() {
                *libc::__errno_location() = libc::EINVAL;
                return -1;
            }
            kept[count] = fd;
            count += 1;
        }
        for index in 1..count {
            let value = kept[index];
            let mut cursor = index;
            while cursor > 0 && kept[cursor - 1] > value {
                kept[cursor] = kept[cursor - 1];
                cursor -= 1;
            }
            kept[cursor] = value;
        }
        let mut next = 3_u32;
        for fd in kept[..count].iter().copied() {
            let fd = fd as u32;
            if fd < next {
                continue;
            }
            if fd > next && libc::syscall(libc::SYS_close_range, next, fd - 1, 0_u32) < 0 {
                return -1;
            }
            next = fd.saturating_add(1);
        }
        if libc::syscall(libc::SYS_close_range, next, u32::MAX, 0_u32) < 0 {
            return -1;
        }
        0
    }

    unsafe fn write_struct<T>(fd: RawFd, value: &T) {
        let _ = write_all(fd, (value as *const T).cast(), size_of::<T>());
    }

    fn read_struct<T: Copy>(reader: &mut std::fs::File, value: &mut T) -> io::Result<()> {
        let mut bytes = unsafe {
            std::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>())
        };
        while !bytes.is_empty() {
            let count = std::io::Read::read(reader, bytes)?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "report pipe closed",
                ));
            }
            bytes = &mut bytes[count..];
        }
        Ok(())
    }

    unsafe fn send_message(fd: RawFd, message: Message) {
        write_struct(fd, &message);
    }

    unsafe fn write_all(fd: RawFd, mut pointer: *const libc::c_void, mut len: usize) -> i32 {
        while len > 0 {
            let count = libc::write(fd, pointer, len);
            if count < 0 {
                return -1;
            }
            if count == 0 {
                return -1;
            }
            pointer = pointer.cast::<u8>().add(count as usize).cast();
            len -= count as usize;
        }
        0
    }

    unsafe fn read_one(fd: RawFd, value: &mut u8) -> isize {
        loop {
            let count = libc::read(fd, value as *mut u8 as *mut libc::c_void, 1);
            if count < 0 && errno() == libc::EINTR {
                continue;
            }
            return count;
        }
    }

    unsafe fn wait_target_or_exit(pid: libc::pid_t) -> ! {
        let mut status = 0;
        loop {
            if libc::waitpid(pid, &mut status, 0) >= 0 {
                break;
            }
            if errno() != libc::EINTR {
                libc::_exit(127);
            }
        }
        let code = if libc::WIFEXITED(status) {
            libc::WEXITSTATUS(status)
        } else if libc::WIFSIGNALED(status) {
            128 + libc::WTERMSIG(status)
        } else {
            127
        };
        libc::_exit(code);
    }

    unsafe fn fail_and_exit(report_fd: RawFd, operation: i32, error: i32) -> ! {
        send_message(
            report_fd,
            Message {
                kind: MSG_ERROR,
                operation,
                errno: error,
                pid: libc::getpid(),
            },
        );
        libc::_exit(125)
    }

    fn operation_name(operation: i32) -> &'static str {
        match operation {
            STAGE_FORK => "fork",
            STAGE_USERNS => "user namespace creation",
            STAGE_UID_MAP => "uid mapping",
            STAGE_GID_MAP => "gid mapping",
            STAGE_SETIDS => "namespace identity setup",
            STAGE_MOUNTNS => "mount or pid namespace creation",
            STAGE_PRIVATE_MOUNTS => "mount propagation isolation",
            STAGE_TMPFS => "private tmpfs creation",
            STAGE_MKDIR => "minimal root construction",
            STAGE_BIND_INPUT => "read-only input bind",
            STAGE_BIND_TOOL => "read-only tool bind",
            STAGE_BIND_TASK => "writable task-directory bind",
            STAGE_BIND_RO => "read-only bind remount",
            STAGE_PIVOT_ROOT => "pivot_root",
            STAGE_OLD_ROOT => "old-root detachment",
            STAGE_NO_NEW_PRIVS => "no_new_privs",
            STAGE_CAP_DROP => "capability drop",
            STAGE_RLIMIT => "per-process limits",
            STAGE_FD_CLOSE => "descriptor closure",
            STAGE_READY_WRITE => "placement-ready notification",
            STAGE_RELEASE_READ => "placement-release barrier",
            STAGE_FORK_TOOL => "tool process creation",
            STAGE_EXEC_TOOL => "tool exec",
            STAGE_CLONE3 => "clone3 cgroup placement",
            STAGE_REPORT_WRITE => "child status report",
            STAGE_TOOL_WAIT => "tool wait",
            STAGE_SECCOMP => "filesystem seccomp policy",
            STAGE_TASK_CWD => "task-directory working directory",
            STAGE_PID_NAMESPACE => "PID namespace creation",
            _ => "unknown operation",
        }
    }

    pub(super) fn wait_for_child(pid: libc::pid_t) -> io::Result<ExitStatus> {
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
            if waited == pid {
                return Ok(ExitStatus::from_raw(status));
            }
            if waited < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
    }

    pub(super) fn try_wait_for_child(pid: libc::pid_t) -> io::Result<Option<ExitStatus>> {
        let mut status = 0;
        loop {
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                return Ok(Some(ExitStatus::from_raw(status)));
            }
            if waited == 0 {
                return Ok(None);
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(io::Error::last_os_error());
        }
    }

    pub(super) fn kill_process_group(pid: libc::pid_t) -> io::Result<()> {
        let result = unsafe { libc::kill(-pid, libc::SIGKILL) };
        if result == 0 {
            return Ok(());
        }
        let group_error = io::Error::last_os_error();
        let direct = unsafe { libc::kill(pid, libc::SIGKILL) };
        if direct == 0 {
            return Ok(());
        }
        let direct_error = io::Error::last_os_error();
        if direct_error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else if group_error.raw_os_error() == Some(libc::ESRCH) {
            Err(direct_error)
        } else {
            Err(group_error)
        }
    }

    fn success() -> ProbeResult {
        ProbeResult {
            operation: PROBE_OK,
            errno: 0,
        }
    }

    fn failed(operation: i32) -> ProbeResult {
        ProbeResult {
            operation,
            errno: unsafe { errno() },
        }
    }

    fn failed_with_errno(operation: i32, errno: i32) -> ProbeResult {
        ProbeResult { operation, errno }
    }

    fn errno() -> i32 {
        unsafe { *libc::__errno_location() }
    }
}
