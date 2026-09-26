//! Linux filesystem isolation proof for untrusted media tools.
//!
//! The public API is deliberately fail-closed. On non-Linux targets the probe
//! remains buildable but cannot create a sandbox. On Linux, `spawn_blocked`
//! creates the user/mount/PID/network namespaces and a minimal root before
//! signaling the parent-side placement barrier. The tool is forked only after
//! placement is confirmed and is executed directly, without a shell.

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::collections::BTreeMap;
#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::collections::HashSet;
#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
use std::io;

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
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn passed(detail: impl Into<String>) -> Self {
        Self {
            status: ProbeStatus::Passed,
            detail: detail.into(),
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
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

/// A socket domain listed by the sandbox network policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSocketDomain {
    Unix,
    Ipv4,
    Ipv6,
    Packet,
}

/// A syscall denied after sandbox setup by the Linux seccomp filter.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkSyscall {
    Connect,
    SocketPair,
    Bpf,
    Userfaultfd,
}

/// Declarative socket and syscall policy consumed by the Linux seccomp filter.
///
/// AF_UNIX socket creation is retained for local-only consumers, but `connect`
/// is denied for every address family after setup. Task 8 has no network
/// exception for media tools.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkPolicy {
    pub allowed_socket_domains: [NetworkSocketDomain; 1],
    pub denied_socket_domains: [NetworkSocketDomain; 3],
    pub denied_syscalls: [NetworkSyscall; 4],
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            allowed_socket_domains: [NetworkSocketDomain::Unix],
            denied_socket_domains: [
                NetworkSocketDomain::Ipv4,
                NetworkSocketDomain::Ipv6,
                NetworkSocketDomain::Packet,
            ],
            denied_syscalls: [
                NetworkSyscall::Connect,
                NetworkSyscall::SocketPair,
                NetworkSyscall::Bpf,
                NetworkSyscall::Userfaultfd,
            ],
        }
    }
}

/// Fixed protocol policy used by FFprobe invocations.
///
/// This policy is intentionally separate from `NetworkEvidence`: protocol
/// filtering does not prove operating-system network isolation.
pub const FFPROBE_PROTOCOL_WHITELIST: &str = "file,pipe";

/// Active evidence for the Linux network isolation boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkEvidence {
    pub private_namespace_created: ProbeEvidence,
    pub ipv4_socket_denial: ProbeEvidence,
    pub ipv6_socket_denial: ProbeEvidence,
    pub packet_socket_denial: ProbeEvidence,
    pub ipv4_listener_isolated: ProbeEvidence,
    pub ipv6_listener_isolated: ProbeEvidence,
    /// Pre-seccomp Unix path-visibility probe; success requires connect(2) to
    /// fail with ENOENT after pivot_root, so it is not confused with seccomp.
    pub unix_socket_escape: ProbeEvidence,
    /// Post-seccomp connect(2) probe; success requires EACCES from the filter.
    pub connect_denial: ProbeEvidence,
    pub socketpair_denial: ProbeEvidence,
    pub bpf_denial: ProbeEvidence,
    pub userfaultfd_denial: ProbeEvidence,
    pub namespace_creation_denied: ProbeEvidence,
}

impl NetworkEvidence {
    pub fn all_passed(&self) -> bool {
        [
            &self.private_namespace_created,
            &self.ipv4_socket_denial,
            &self.ipv6_socket_denial,
            &self.packet_socket_denial,
            &self.ipv4_listener_isolated,
            &self.ipv6_listener_isolated,
            &self.unix_socket_escape,
            &self.connect_denial,
            &self.socketpair_denial,
            &self.bpf_denial,
            &self.userfaultfd_denial,
            &self.namespace_creation_denied,
        ]
        .into_iter()
        .all(|item| item.status == ProbeStatus::Passed)
    }
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

/// Result state for the cgroup v2 setup evidence. A ready record proves that
/// the delegated job cgroup and its controls were installed; aggregate
/// behavior still requires the native adversarial tests on a delegated Linux
/// runner.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupEvidenceStatus {
    Ready,
    Blocked,
}

/// Setup facts for one per-job cgroup. This is configuration evidence, not a
/// substitute for aggregate-limit stress evidence from the Linux tests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CgroupEvidence {
    pub status: CgroupEvidenceStatus,
    pub detail: String,
    pub job_id: Option<String>,
    pub pids_max: Option<u64>,
    pub memory_max_bytes: Option<u64>,
    pub memory_swap_max_bytes: Option<u64>,
    pub cpu_quota_micros: Option<u64>,
    pub cpu_period_micros: Option<u64>,
}

impl CgroupEvidence {
    fn blocked(detail: impl Into<String>) -> Self {
        Self {
            status: CgroupEvidenceStatus::Blocked,
            detail: detail.into(),
            job_id: None,
            pids_max: None,
            memory_max_bytes: None,
            memory_swap_max_bytes: None,
            cpu_quota_micros: None,
            cpu_period_micros: None,
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn ready(job_id: &str, limits: SandboxLimits) -> Self {
        Self {
            status: CgroupEvidenceStatus::Ready,
            detail: "delegated cgroup v2 job and aggregate resource limits are configured; native stress evidence is recorded separately".into(),
            job_id: Some(job_id.to_owned()),
            pids_max: Some(limits.pids_max),
            memory_max_bytes: Some(limits.memory_max_bytes),
            memory_swap_max_bytes: Some(0),
            cpu_quota_micros: Some(limits.cpu_quota_micros),
            cpu_period_micros: Some(limits.cpu_period_micros),
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn with_detail(mut self, detail: String) -> Self {
        self.detail = detail;
        self
    }

    pub fn all_passed(&self) -> bool {
        self.status == CgroupEvidenceStatus::Ready
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CgroupLimitControls {
    pids_max: String,
    memory_max: String,
    memory_swap_max: String,
    cpu_max: String,
}

fn validate_cgroup_job_id(job_id: &str) -> Result<(), &'static str> {
    let bytes = job_id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return Err("job id must contain 1 to 64 ASCII characters");
    }
    if !bytes[0].is_ascii_alphanumeric()
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_alphanumeric() && !matches!(*byte, b'.' | b'_' | b'-'))
        || job_id == "."
        || job_id == ".."
    {
        return Err("job id must be one safe ASCII path component");
    }
    Ok(())
}

fn cgroup_limit_controls(limits: SandboxLimits) -> Result<CgroupLimitControls, &'static str> {
    if limits.pids_max == 0
        || limits.memory_max_bytes == 0
        || limits.cpu_quota_micros == 0
        || !(1_000..=1_000_000).contains(&limits.cpu_period_micros)
    {
        return Err("pids, memory, and CPU limits must be valid positive cgroup v2 values");
    }
    if limits.memory_swap_max_bytes != 0 {
        return Err("cgroup v2 swap must be disabled with memory.swap.max = 0");
    }

    Ok(CgroupLimitControls {
        pids_max: format!("{}\n", limits.pids_max),
        memory_max: format!("{}\n", limits.memory_max_bytes),
        memory_swap_max: "0\n".into(),
        cpu_max: format!("{} {}\n", limits.cpu_quota_micros, limits.cpu_period_micros),
    })
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn parse_cgroup_populated(events: &str) -> Result<bool, &'static str> {
    let mut populated = None;
    for line in events.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(value) = fields.next() else {
            if name == "populated" {
                return Err("cgroup.events populated value is missing");
            }
            continue;
        };
        if fields.next().is_some() {
            if name == "populated" {
                return Err("cgroup.events populated record is malformed");
            }
            continue;
        }
        if name == "populated" {
            if populated.is_some() || !matches!(value, "0" | "1") {
                return Err("cgroup.events populated record is duplicated or invalid");
            }
            populated = Some(value == "1");
        }
    }
    populated.ok_or("cgroup.events has no populated record")
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn proc_cgroup_matches(contents: &str, expected_path: &str) -> bool {
    if !expected_path.starts_with('/') || expected_path.ends_with('/') {
        return false;
    }
    let mut unified = None;
    for line in contents.lines() {
        if let Some(path) = line.strip_prefix("0::")
            && unified.replace(path).is_some()
        {
            return false;
        }
    }
    unified == Some(expected_path)
}

/// Paths and resource limits declared by the trusted server for one job.
///
/// On Linux, `job_dir` must be a private empty directory owned by the
/// effective UID/GID, with mode exactly `0700`, link count `2`, and no nested
/// mount. The probe pins and revalidates those properties, but the current
/// interface cannot attest who created the directory or prove its provenance.
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

/// Per-job Linux cgroup v2 resource boundary.
///
/// The delegated root must be the current service process's cgroup and must
/// already expose the `cpu`, `memory`, and `pids` controllers to children.
/// `create` installs every aggregate limit before `prepare_spawn` can return a
/// placement. A ready configuration record is not native stress evidence.
#[derive(Debug)]
pub struct CgroupV2Job {
    evidence: CgroupEvidence,
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    inner: linux::CgroupV2JobInner,
}

impl CgroupV2Job {
    pub fn create(
        delegated_root: impl AsRef<Path>,
        job_id: &str,
        limits: SandboxLimits,
    ) -> Result<Self, SandboxError> {
        validate_cgroup_job_id(job_id)
            .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;
        let controls = cgroup_limit_controls(limits)
            .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;

        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            let (inner, detail) =
                linux::create_cgroup_job(delegated_root.as_ref(), job_id, limits, controls)?;
            Ok(Self {
                evidence: CgroupEvidence::ready(job_id, limits).with_detail(detail),
                inner,
            })
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = (delegated_root, controls);
            Err(SandboxError::CgroupPrerequisitesFailed(Box::new(
                CgroupEvidence::blocked(
                    "BLOCKED: native cgroup v2 delegation can only be inspected on supported Linux targets",
                ),
            )))
        }
    }

    /// Returns the setup evidence for this job. Aggregate enforcement remains
    /// unproven until the native Linux resource tests pass.
    pub fn evidence(&self) -> CgroupEvidence {
        self.evidence.clone()
    }

    /// Absolute path to the job cgroup, useful for diagnostics and native
    /// integration assertions.
    pub fn path(&self) -> &Path {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            &self.inner.path
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Path::new("")
        }
    }
}

impl ResourceBoundary for CgroupV2Job {
    fn prepare_spawn(&self) -> Result<SpawnPlacement, SandboxError> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            Ok(SpawnPlacement::CgroupV2(CgroupPlacement {
                inner: self.inner.prepare_spawn()?,
            }))
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Err(SandboxError::CgroupPrerequisitesFailed(Box::new(
                CgroupEvidence::blocked("BLOCKED: cgroup v2 is unavailable on this platform"),
            )))
        }
    }

    fn kill_all(&self) -> Result<(), SandboxError> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.inner.kill_all()
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Err(SandboxError::CgroupPrerequisitesFailed(Box::new(
                CgroupEvidence::blocked("BLOCKED: cgroup v2 is unavailable on this platform"),
            )))
        }
    }

    fn is_empty(&self) -> Result<bool, SandboxError> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            self.inner.is_empty()
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Err(SandboxError::CgroupPrerequisitesFailed(Box::new(
                CgroupEvidence::blocked("BLOCKED: cgroup v2 is unavailable on this platform"),
            )))
        }
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl Drop for CgroupV2Job {
    fn drop(&mut self) {
        let _ = self.inner.kill_all();
    }
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
    /// Managed cgroup placement. The sandbox completes either atomic clone3
    /// placement or the blocked parent-attach handshake before returning.
    CgroupV2(CgroupPlacement),
}

/// Opaque placement created by `CgroupV2Job`; callers cannot forge cgroup
/// descriptors or bypass the parent-side membership check.
#[derive(Debug)]
pub struct CgroupPlacement {
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    inner: linux::CgroupPlacement,
}

/// Fail-closed errors returned by the platform and namespace probes.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("Linux filesystem isolation is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("required Linux filesystem prerequisites failed: {0:?}")]
    Prerequisites(Box<FilesystemEvidence>),
    #[error("required Linux network prerequisites failed: {0:?}")]
    NetworkPrerequisitesFailed(Box<NetworkEvidence>),
    #[error("required cgroup v2 prerequisites failed: {0:?}")]
    CgroupPrerequisitesFailed(Box<CgroupEvidence>),
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

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn network_namespace_is_private(host: FileIdentity, reported: Option<FileIdentity>) -> bool {
    host.device != 0
        && host.inode != 0
        && reported.is_some_and(|candidate| {
            candidate.device != 0 && candidate.inode != 0 && candidate != host
        })
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn after_parent_ack(
    read_ack: impl FnOnce() -> io::Result<Option<u8>>,
    after_ack: impl FnOnce(),
) -> io::Result<()> {
    match read_ack()? {
        Some(1) => {
            after_ack();
            Ok(())
        }
        Some(_) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "parent readiness acknowledgment was invalid",
        )),
        None => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "parent readiness acknowledgment was missing",
        )),
    }
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TaskDirectorySnapshot {
    identity: FileIdentity,
    owner_uid: u32,
    owner_gid: u32,
    mode: u32,
    link_count: u64,
    mount_id: u64,
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
struct PolicyPathIdentityGraph {
    input: FileIdentity,
    input_parent_chain: Vec<FileIdentity>,
    task: FileIdentity,
    task_ancestors: Vec<FileIdentity>,
    tool: FileIdentity,
    tool_ancestors: Vec<FileIdentity>,
    task_files: HashSet<FileIdentity>,
    tool_files: HashSet<FileIdentity>,
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ToolEntryEvidence {
    identity: FileIdentity,
    link_count: u64,
    mount_id: u64,
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[derive(Clone, Debug, Eq, PartialEq)]
struct ToolInventory {
    entries: BTreeMap<PathBuf, ToolEntryEvidence>,
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const MAX_TOOL_INVENTORY_DIRECTORIES: usize = 32;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
// 32 inventory directory FDs + 8 fixed policy/control FDs + one transient
// entry FD must fit above stdio, whose descriptors occupy 0..=2.
const MINIMUM_OPEN_FILES_FOR_SANDBOX: u64 = MAX_TOOL_INVENTORY_DIRECTORIES as u64 + 12;

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn validate_open_files_limit(open_files_max: u64) -> Result<(), &'static str> {
    if open_files_max < MINIMUM_OPEN_FILES_FOR_SANDBOX {
        return Err("open-file limit is too small for the pinned sandbox policy descriptors");
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn validate_empty_task_snapshot(
    expected_identity: FileIdentity,
    actual_identity: FileIdentity,
    entry_count: usize,
) -> Result<(), &'static str> {
    if expected_identity != actual_identity || entry_count != 0 {
        return Err("task directory changed or was not empty");
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn validate_private_task_snapshot(
    snapshot: &TaskDirectorySnapshot,
    expected_identity: FileIdentity,
    expected_mount_id: u64,
    expected_owner_uid: u32,
    expected_owner_gid: u32,
    entry_count: usize,
) -> Result<(), &'static str> {
    if snapshot.identity != expected_identity
        || snapshot.mount_id != expected_mount_id
        || snapshot.owner_uid != expected_owner_uid
        || snapshot.owner_gid != expected_owner_gid
        || snapshot.mode & 0o170000 != 0o040000
        || snapshot.mode & 0o7777 != 0o700
        || snapshot.link_count != 2
        || entry_count != 0
    {
        return Err("task directory must remain private, owned, empty, and on its pinned mount");
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn validate_tool_inventory(
    input: FileIdentity,
    prepared: &ToolInventory,
    current: &ToolInventory,
) -> Result<(), &'static str> {
    if prepared != current {
        return Err("trusted tool inventory changed after preparation");
    }
    if prepared
        .entries
        .values()
        .any(|entry| entry.identity == input)
    {
        return Err("input aliases an entry in the trusted tool inventory");
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn validate_policy_path_identities(graph: &PolicyPathIdentityGraph) -> Result<(), &'static str> {
    if graph.input == graph.task || graph.input == graph.tool || graph.task == graph.tool {
        return Err("policy roots must not identify the same filesystem object");
    }
    if graph.task_ancestors.contains(&graph.tool) || graph.tool_ancestors.contains(&graph.task) {
        return Err("task and tool directories must not overlap");
    }
    if graph.input_parent_chain.contains(&graph.task) {
        return Err("input must not be contained by the writable task directory");
    }
    if graph.task_files.contains(&graph.input)
        || graph.tool_files.contains(&graph.input)
        || graph
            .task_files
            .iter()
            .any(|identity| graph.tool_files.contains(identity))
    {
        return Err("input, task, and tool files must not alias by filesystem identity");
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
fn write_all_with<F>(mut remaining: &[u8], mut write: F) -> io::Result<()>
where
    F: FnMut(&[u8]) -> io::Result<usize>,
{
    while !remaining.is_empty() {
        match write(remaining) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "pipe write returned zero bytes",
                ));
            }
            Ok(written) if written <= remaining.len() => remaining = &remaining[written..],
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pipe writer reported more bytes than requested",
                ));
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SeccompArchitecture {
    X86_64,
    Aarch64,
    Unsupported,
}

#[cfg(any(
    test,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
))]
const fn seccomp_audit_arch(architecture: SeccompArchitecture) -> Option<u32> {
    match architecture {
        SeccompArchitecture::X86_64 => Some(0xc000_003e),
        SeccompArchitecture::Aarch64 => Some(0xc000_00b7),
        SeccompArchitecture::Unsupported => None,
    }
}

/// Performs active checks for the Linux namespace and filesystem primitives.
pub struct FilesystemPrerequisites;

impl FilesystemPrerequisites {
    pub fn inspect() -> Result<FilesystemEvidence, SandboxError> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            linux::inspect_prerequisites()
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            Err(SandboxError::UnsupportedPlatform)
        }
    }
}

/// Performs active controlled-listener and namespace checks for Linux
/// networking isolation.
pub struct NetworkPrerequisites;

impl NetworkPrerequisites {
    pub fn inspect() -> Result<NetworkEvidence, SandboxError> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            linux::inspect_network_prerequisites()
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
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
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        {
            linux::spawn_blocked(program, args, policy, placement)
        }

        #[cfg(not(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )))]
        {
            let _ = (program, args, policy, placement);
            Err(SandboxError::UnsupportedPlatform)
        }
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
pub struct SandboxChild;

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
pub struct SandboxChild {
    pid: libc::pid_t,
    root: Option<linux::TempRoot>,
    reaper: std::sync::Arc<linux::ChildReaper>,
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl SandboxChild {
    /// Host PID of the trusted supervisor, which is the barrier PID in
    /// `ParentAttachBarrier` mode.
    pub fn id(&self) -> u32 {
        self.pid as u32
    }

    pub fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        let status = self.reaper.wait()?;
        self.root.take();
        Ok(status)
    }

    pub fn try_wait(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let Some(status) = self.reaper.try_wait()? else {
            return Ok(None);
        };
        self.root.take();
        Ok(Some(status))
    }

    pub fn kill(&mut self) -> std::io::Result<()> {
        if self.reaper.try_wait()?.is_some() {
            return Ok(());
        }
        linux::kill_process_group(self.pid)?;
        let _ = self.wait()?;
        Ok(())
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl Drop for SandboxChild {
    fn drop(&mut self) {
        if self.reaper.try_wait().ok().flatten().is_none() {
            let _ = linux::kill_process_group(self.pid);
            let _ = self.reaper.wait();
        }
        self.root.take();
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
// Each unsafe function is a narrow syscall/FFI sequence; callers only enter
// these helpers through the explicitly unsafe setup boundary.
#[allow(unsafe_op_in_unsafe_fn)]
mod linux {
    use super::{
        CgroupEvidence, CgroupLimitControls, FileIdentity, FilesystemEvidence,
        FilesystemPrerequisites, MAX_TOOL_INVENTORY_DIRECTORIES, NetworkEvidence, NetworkPolicy,
        NetworkPrerequisites, NetworkSocketDomain, NetworkSyscall, PolicyPathIdentityGraph,
        ProbeEvidence, SandboxChild, SandboxError, SandboxLimits, SandboxPolicy, SpawnPlacement,
        ToolEntryEvidence, ToolInventory, network_namespace_is_private, validate_open_files_limit,
        validate_policy_path_identities, validate_tool_inventory,
    };
    use std::collections::{BTreeMap, HashSet};
    use std::ffi::CString;
    use std::fs::{self, File};
    use std::io::{self, Read, Write};
    use std::mem::{size_of, zeroed};
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;
    use std::os::unix::process::ExitStatusExt;
    use std::path::{Path, PathBuf};
    use std::process::ExitStatus;
    use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const MSG_READY: u32 = 1;
    const MSG_ERROR: u32 = 2;
    const MSG_NAMESPACE_ATTESTATION: u32 = 3;
    const PROBE_OK: i32 = 0;
    const MAX_TOOL_INVENTORY_ENTRIES: usize = 256;
    const MAX_TOOL_INVENTORY_DEPTH: usize = 8;
    const STATX_MNT_ID: u32 = 0x1000;
    const STATX_BASIC_STATS: u32 = 0x07ff;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const AT_SYMLINK_NOFOLLOW: i32 = 0x0100;
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
    const STAGE_NETWORK_NAMESPACE: i32 = 30;
    const STAGE_NETWORK_SOCKET: i32 = 31;
    const STAGE_NETWORK_UNIX_SOCKET: i32 = 32;
    const STAGE_NETWORK_ESCAPE: i32 = 33;
    const STAGE_NETWORK_SYSCALL: i32 = 34;
    const STAGE_PARENT_ACK: i32 = 35;
    const CLONE_INTO_CGROUP: u64 = 1 << 33;
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;
    const SECCOMP_DATA_ARCH_OFFSET: u32 = 4;
    const SECCOMP_DATA_ARGS_OFFSET: u32 = 16;
    const CAP_VERSION_3: u32 = 0x2008_0522;
    const ACTIVE_PROBE_TIMEOUT: Duration = Duration::from_secs(10);
    const ACTIVE_PROBE_REAP_POLL_INTERVAL: Duration = Duration::from_millis(10);

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Message {
        kind: u32,
        operation: i32,
        errno: i32,
        pid: i32,
        network_namespace_device: u64,
        network_namespace_inode: u64,
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

    extern "C" fn namespace_probe_child(_argument: *mut libc::c_void) -> libc::c_int {
        0
    }

    pub(super) struct TempRoot(PathBuf);

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

    #[derive(Debug)]
    pub(super) struct CgroupV2JobInner {
        root_fd: OwnedFd,
        job_fd: OwnedFd,
        job_name: CString,
        pub(super) path: PathBuf,
        expected_cgroup_path: String,
        placement: CgroupPlacementKind,
        state: Arc<CgroupJobStateShared>,
        cleanup: Mutex<()>,
    }

    #[derive(Debug)]
    pub(super) struct CgroupPlacement {
        kind: CgroupPlacementMode,
        reaper: Arc<ChildReaper>,
        _lease: CgroupLease,
    }

    #[derive(Clone, Copy, Debug)]
    enum CgroupPlacementKind {
        CloneIntoCgroup,
        ParentAttachBarrier,
    }

    #[derive(Debug)]
    enum CgroupPlacementMode {
        CloneIntoCgroup(OwnedFd),
        ParentAttachBarrier {
            child_ready: File,
            child_release: File,
            parent_ready: File,
            parent_release: File,
            cgroup_procs: File,
            cgroup_kill: File,
            expected_cgroup_path: String,
        },
    }

    #[derive(Debug)]
    struct CgroupJobState {
        closing: bool,
        removed: bool,
        active_spawns: usize,
        reapers: Vec<Arc<ChildReaper>>,
    }

    #[derive(Debug)]
    struct CgroupJobStateShared {
        state: Mutex<CgroupJobState>,
        changed: std::sync::Condvar,
    }

    #[derive(Debug)]
    struct CgroupLease {
        state: Arc<CgroupJobStateShared>,
    }

    impl Drop for CgroupLease {
        fn drop(&mut self) {
            if let Ok(mut state) = self.state.state.lock() {
                state.active_spawns = state.active_spawns.saturating_sub(1);
                self.state.changed.notify_all();
            }
        }
    }

    #[derive(Debug)]
    pub(super) struct ChildReaper {
        pid: AtomicI32,
        status: Mutex<Option<ExitStatus>>,
    }

    impl ChildReaper {
        pub(super) fn new() -> Arc<Self> {
            Arc::new(Self {
                pid: AtomicI32::new(0),
                status: Mutex::new(None),
            })
        }

        pub(super) fn register(&self, pid: libc::pid_t) -> io::Result<()> {
            self.pid
                .compare_exchange(0, pid, Ordering::Release, Ordering::Relaxed)
                .map(|_| ())
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::AlreadyExists, "reaper already owns a child")
                })
        }

        pub(super) fn try_wait(&self) -> io::Result<Option<ExitStatus>> {
            let mut cached = self
                .status
                .lock()
                .map_err(|_| io::Error::other("sandbox child reaper lock was poisoned"))?;
            if cached.is_some() {
                return Ok(cached.clone());
            }
            let pid = self.pid.load(Ordering::Acquire);
            if pid <= 0 {
                return Ok(None);
            }
            let Some(status) = try_wait_for_child(pid)? else {
                return Ok(None);
            };
            *cached = Some(status);
            Ok(Some(status))
        }

        pub(super) fn wait(&self) -> io::Result<ExitStatus> {
            let mut cached = self
                .status
                .lock()
                .map_err(|_| io::Error::other("sandbox child reaper lock was poisoned"))?;
            if let Some(status) = *cached {
                return Ok(status);
            }
            let pid = self.pid.load(Ordering::Acquire);
            if pid <= 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "sandbox child has not been registered with its reaper",
                ));
            }
            let status = wait_for_child(pid)?;
            *cached = Some(status);
            Ok(status)
        }

        fn wait_bounded(&self, deadline: Instant) -> io::Result<Option<ExitStatus>> {
            loop {
                if let Some(status) = self.try_wait()? {
                    return Ok(Some(status));
                }
                if self.pid.load(Ordering::Acquire) <= 0 {
                    return Ok(None);
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out reaping cgroup sandbox supervisor",
                    ));
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }

    impl CgroupV2JobInner {
        pub(super) fn prepare_spawn(&self) -> Result<CgroupPlacement, SandboxError> {
            let mut state = self.state.state.lock().map_err(|_| SandboxError::Io {
                operation: "lock job cgroup lifecycle",
                source: io::Error::other("job cgroup lifecycle lock was poisoned"),
            })?;
            if state.closing || state.removed {
                return Err(SandboxError::InvalidPolicy(
                    "cannot spawn into a closing or removed job cgroup".into(),
                ));
            }
            let reaper = ChildReaper::new();
            state.active_spawns += 1;
            state.reapers.push(Arc::clone(&reaper));
            drop(state);
            let lease = CgroupLease {
                state: Arc::clone(&self.state),
            };
            let kind = match self.placement {
                CgroupPlacementKind::CloneIntoCgroup => {
                    CgroupPlacementMode::CloneIntoCgroup(duplicate_fd(self.job_fd.as_raw_fd())?)
                }
                CgroupPlacementKind::ParentAttachBarrier => create_parent_attach_placement(
                    open_cgroup_control(self.job_fd.as_raw_fd(), "cgroup.procs", true).map_err(
                        |source| SandboxError::Io {
                            operation: "open cgroup.procs controller",
                            source,
                        },
                    )?,
                    open_cgroup_control(self.job_fd.as_raw_fd(), "cgroup.kill", true).map_err(
                        |source| SandboxError::Io {
                            operation: "open cgroup.kill controller",
                            source,
                        },
                    )?,
                    self.expected_cgroup_path.clone(),
                )?,
            };
            Ok(CgroupPlacement {
                kind,
                reaper,
                _lease: lease,
            })
        }

        pub(super) fn is_empty(&self) -> Result<bool, SandboxError> {
            let state = self.state.state.lock().map_err(|_| SandboxError::Io {
                operation: "lock job cgroup lifecycle",
                source: io::Error::other("job cgroup lifecycle lock was poisoned"),
            })?;
            if state.removed {
                return Ok(true);
            }
            drop(state);
            let events =
                read_cgroup_file(self.job_fd.as_raw_fd(), "cgroup.events").map_err(|source| {
                    SandboxError::Io {
                        operation: "read job cgroup.events",
                        source,
                    }
                })?;
            parse_cgroup_populated(&events)
                .map(|populated| !populated)
                .map_err(|reason| SandboxError::Io {
                    operation: "parse job cgroup.events",
                    source: io::Error::new(io::ErrorKind::InvalidData, reason),
                })
        }

        pub(super) fn kill_all(&self) -> Result<(), SandboxError> {
            let _cleanup = self.cleanup.lock().map_err(|_| SandboxError::Io {
                operation: "serialize job cgroup cleanup",
                source: io::Error::other("job cgroup cleanup lock was poisoned"),
            })?;
            let mut state = self.state.state.lock().map_err(|_| SandboxError::Io {
                operation: "lock job cgroup lifecycle",
                source: io::Error::other("job cgroup lifecycle lock was poisoned"),
            })?;
            if state.removed {
                return Ok(());
            }
            state.closing = true;
            let lease_deadline = Instant::now() + Duration::from_secs(5);
            while state.active_spawns != 0 {
                let now = Instant::now();
                if now >= lease_deadline {
                    return Err(SandboxError::Io {
                        operation: "wait for active cgroup placements",
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "an in-flight spawn still owns a cgroup placement",
                        ),
                    });
                }
                let (next, timeout) = self
                    .state
                    .changed
                    .wait_timeout(state, lease_deadline.saturating_duration_since(now))
                    .map_err(|_| SandboxError::Io {
                        operation: "wait for active cgroup placements",
                        source: io::Error::other("job cgroup lifecycle lock was poisoned"),
                    })?;
                state = next;
                if timeout.timed_out() && state.active_spawns != 0 {
                    return Err(SandboxError::Io {
                        operation: "wait for active cgroup placements",
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "an in-flight spawn still owns a cgroup placement",
                        ),
                    });
                }
            }
            let reapers = state.reapers.clone();
            drop(state);
            write_cgroup_file(self.job_fd.as_raw_fd(), "cgroup.kill", b"1\n").map_err(
                |source| SandboxError::Io {
                    operation: "write job cgroup.kill",
                    source,
                },
            )?;

            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if self.is_empty()? {
                    break;
                }
                if Instant::now() >= deadline {
                    return Err(SandboxError::Io {
                        operation: "wait for empty job cgroup",
                        source: io::Error::new(
                            io::ErrorKind::TimedOut,
                            "cgroup.events did not report populated 0 within five seconds",
                        ),
                    });
                }
                std::thread::sleep(Duration::from_millis(10));
            }

            let reap_deadline = Instant::now() + Duration::from_secs(5);
            for reaper in reapers {
                reaper
                    .wait_bounded(reap_deadline)
                    .map_err(|source| SandboxError::Io {
                        operation: "reap cgroup sandbox supervisor",
                        source,
                    })?;
            }

            let result = unsafe {
                libc::unlinkat(
                    self.root_fd.as_raw_fd(),
                    self.job_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
            if result != 0 {
                return Err(SandboxError::Io {
                    operation: "remove empty job cgroup",
                    source: io::Error::last_os_error(),
                });
            }
            let mut state = self.state.state.lock().map_err(|_| SandboxError::Io {
                operation: "lock job cgroup lifecycle",
                source: io::Error::other("job cgroup lifecycle lock was poisoned"),
            })?;
            state.removed = true;
            Ok(())
        }
    }

    impl CgroupPlacement {
        fn ensure_open(&self) -> Result<(), SandboxError> {
            ensure_cgroup_job_open(&self._lease.state)
        }

        fn kill_members(&mut self, supervisor_pid: libc::pid_t) -> io::Result<()> {
            let cgroup_result = match &mut self.kind {
                CgroupPlacementMode::CloneIntoCgroup(cgroup) => {
                    write_cgroup_file(cgroup.as_raw_fd(), "cgroup.kill", b"1\n")
                }
                CgroupPlacementMode::ParentAttachBarrier { cgroup_kill, .. } => {
                    cgroup_kill.write_all(b"1\n")
                }
            };
            let supervisor_result = kill_process_group(supervisor_pid);
            cgroup_result.and(supervisor_result)
        }

        fn attach_and_release(&mut self, supervisor_pid: libc::pid_t) -> Result<(), SandboxError> {
            let state = Arc::clone(&self._lease.state);
            let CgroupPlacementMode::ParentAttachBarrier {
                parent_ready,
                parent_release,
                cgroup_procs,
                cgroup_kill,
                expected_cgroup_path,
                ..
            } = &mut self.kind
            else {
                return Ok(());
            };

            let attach = (|| -> io::Result<()> {
                ensure_cgroup_job_open(&state).map_err(|error| {
                    io::Error::new(io::ErrorKind::Interrupted, error.to_string())
                })?;
                let mut reported_pid = [0_u8; size_of::<libc::pid_t>()];
                parent_ready.read_exact(&mut reported_pid)?;
                let reported_pid = libc::pid_t::from_ne_bytes(reported_pid);
                if reported_pid != supervisor_pid {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "blocked supervisor reported a different host PID",
                    ));
                }

                writeln!(cgroup_procs, "{supervisor_pid}")?;
                let membership = fs::read_to_string(format!("/proc/{supervisor_pid}/cgroup"))?;
                if !super::proc_cgroup_matches(&membership, expected_cgroup_path) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "blocked supervisor did not enter exact cgroup {expected_cgroup_path}"
                        ),
                    ));
                }
                ensure_cgroup_job_open(&state).map_err(|error| {
                    io::Error::new(io::ErrorKind::Interrupted, error.to_string())
                })?;
                parent_release.write_all(&[1])?;
                Ok(())
            })();

            if let Err(source) = attach {
                let _ = cgroup_kill.write_all(b"1\n");
                let _ = kill_process_group(supervisor_pid);
                return Err(SandboxError::Io {
                    operation: "attach blocked supervisor to job cgroup",
                    source,
                });
            }
            Ok(())
        }
    }

    fn ensure_cgroup_job_open(shared: &Arc<CgroupJobStateShared>) -> Result<(), SandboxError> {
        let state = shared.state.lock().map_err(|_| SandboxError::Io {
            operation: "lock job cgroup lifecycle",
            source: io::Error::other("job cgroup lifecycle lock was poisoned"),
        })?;
        if state.closing || state.removed {
            return Err(SandboxError::InvalidPolicy(
                "job cgroup was cancelled before tool release".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn create_cgroup_job(
        delegated_root: &Path,
        job_id: &str,
        _limits: SandboxLimits,
        controls: CgroupLimitControls,
    ) -> Result<(CgroupV2JobInner, String), SandboxError> {
        let blocked = |reason: String| {
            SandboxError::CgroupPrerequisitesFailed(Box::new(CgroupEvidence::blocked(format!(
                "BLOCKED: {reason}"
            ))))
        };
        let root_fd = open_cgroup_directory(delegated_root)
            .map_err(|error| blocked(format!("cannot open delegated cgroup v2 root: {error}")))?;
        verify_cgroup2_fs(root_fd.as_raw_fd())
            .map_err(|error| blocked(format!("delegated root is not cgroup v2: {error}")))?;

        let current_path = process_cgroup_path()
            .map_err(|error| blocked(format!("cannot read current process cgroup: {error}")))?;
        verify_delegated_root_is_current_cgroup(root_fd.as_raw_fd(), delegated_root, &current_path)
            .map_err(|error| {
                blocked(format!("delegated root is not the service cgroup: {error}"))
            })?;

        let available = read_cgroup_file(root_fd.as_raw_fd(), "cgroup.controllers")
            .map_err(|error| blocked(format!("cannot read cgroup.controllers: {error}")))?;
        let enabled = read_cgroup_file(root_fd.as_raw_fd(), "cgroup.subtree_control")
            .map_err(|error| blocked(format!("cannot read cgroup.subtree_control: {error}")))?;
        for controller in ["cpu", "memory", "pids"] {
            if !available
                .split_ascii_whitespace()
                .any(|item| item == controller)
                || !enabled
                    .split_ascii_whitespace()
                    .any(|item| item == controller)
            {
                return Err(blocked(format!(
                    "delegated cgroup root must expose and enable the {controller} controller"
                )));
            }
        }

        let job_name = CString::new(job_id)
            .map_err(|_| SandboxError::InvalidPolicy("job id contains NUL".into()))?;
        if unsafe { libc::mkdirat(root_fd.as_raw_fd(), job_name.as_ptr(), 0o755) } != 0 {
            return Err(blocked(format!(
                "cannot create exclusive per-job cgroup {job_id}: {}",
                io::Error::last_os_error()
            )));
        }
        let job_raw = unsafe {
            libc::openat(
                root_fd.as_raw_fd(),
                job_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if job_raw < 0 {
            let source = io::Error::last_os_error();
            remove_empty_cgroup(root_fd.as_raw_fd(), &job_name);
            return Err(blocked(format!(
                "cannot pin per-job cgroup {job_id}: {source}"
            )));
        }
        let job_fd = unsafe { OwnedFd::from_raw_fd(job_raw) };

        let configured = (|| -> Result<(CgroupPlacementKind, String), String> {
            verify_cgroup2_fs(job_fd.as_raw_fd()).map_err(|error| error.to_string())?;
            write_cgroup_file(job_fd.as_raw_fd(), "pids.max", controls.pids_max.as_bytes())
                .map_err(|error| format!("cannot set pids.max: {error}"))?;
            write_cgroup_file(
                job_fd.as_raw_fd(),
                "memory.max",
                controls.memory_max.as_bytes(),
            )
            .map_err(|error| format!("cannot set memory.max: {error}"))?;
            write_cgroup_file(
                job_fd.as_raw_fd(),
                "memory.swap.max",
                controls.memory_swap_max.as_bytes(),
            )
            .map_err(|error| format!("cannot set memory.swap.max: {error}"))?;
            write_cgroup_file(job_fd.as_raw_fd(), "cpu.max", controls.cpu_max.as_bytes())
                .map_err(|error| format!("cannot set cpu.max: {error}"))?;
            verify_cgroup_control(job_fd.as_raw_fd(), "pids.max", controls.pids_max.trim())?;
            verify_cgroup_control(job_fd.as_raw_fd(), "memory.max", controls.memory_max.trim())?;
            verify_cgroup_control(job_fd.as_raw_fd(), "memory.swap.max", "0")?;
            verify_cgroup_control(job_fd.as_raw_fd(), "cpu.max", controls.cpu_max.trim())?;

            drop(
                open_cgroup_control(job_fd.as_raw_fd(), "cgroup.kill", true)
                    .map_err(|error| format!("cgroup.kill is unavailable: {error}"))?,
            );
            let events = read_cgroup_file(job_fd.as_raw_fd(), "cgroup.events")
                .map_err(|error| format!("cgroup.events is unavailable: {error}"))?;
            parse_cgroup_populated(&events).map_err(str::to_owned)?;
            drop(
                open_cgroup_control(job_fd.as_raw_fd(), "cgroup.procs", true)
                    .map_err(|error| format!("cgroup.procs is not writable: {error}"))?,
            );
            let expected_cgroup_path = format!("{}/{}", current_path.trim_end_matches('/'), job_id);
            if expected_cgroup_path.starts_with("//") {
                return Err("current cgroup path is malformed".into());
            }
            let clone3_supported =
                probe_clone3_into_cgroup(job_fd.as_raw_fd(), &expected_cgroup_path)
                    .map_err(|error| format!("CLONE_INTO_CGROUP probe failed: {error}"))?;
            let placement = if clone3_supported {
                CgroupPlacementKind::CloneIntoCgroup
            } else {
                CgroupPlacementKind::ParentAttachBarrier
            };
            Ok((placement, expected_cgroup_path))
        })();

        let (placement, expected_cgroup_path) = match configured {
            Ok(configured) => configured,
            Err(reason) => {
                let _ = write_cgroup_file(job_fd.as_raw_fd(), "cgroup.kill", b"1\n");
                remove_empty_cgroup(root_fd.as_raw_fd(), &job_name);
                return Err(blocked(reason));
            }
        };
        let path = delegated_root.join(job_id);
        let detail = match placement {
            CgroupPlacementKind::CloneIntoCgroup => format!(
                "delegated cgroup {job_id} is configured with pids.max, memory.max, memory.swap.max=0, cpu.max, cgroup.kill, and atomic clone3 placement"
            ),
            CgroupPlacementKind::ParentAttachBarrier => format!(
                "delegated cgroup {job_id} is configured with pids.max, memory.max, memory.swap.max=0, cpu.max, and cgroup.kill; blocked parent-attach placement will verify exact membership"
            ),
        };
        Ok((
            CgroupV2JobInner {
                root_fd,
                job_fd,
                job_name,
                path,
                expected_cgroup_path,
                placement,
                state: Arc::new(CgroupJobStateShared {
                    state: Mutex::new(CgroupJobState {
                        closing: false,
                        removed: false,
                        active_spawns: 0,
                        reapers: Vec::new(),
                    }),
                    changed: std::sync::Condvar::new(),
                }),
                cleanup: Mutex::new(()),
            },
            detail,
        ))
    }

    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;

    fn open_cgroup_directory(path: &Path) -> io::Result<OwnedFd> {
        if !path.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "delegated cgroup root must be absolute",
            ));
        }
        let root = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut current = unsafe { OwnedFd::from_raw_fd(root) };
        for component in path.components() {
            let std::path::Component::Normal(name) = component else {
                if matches!(component, std::path::Component::RootDir) {
                    continue;
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "delegated cgroup root contains a dot or prefix component",
                ));
            };
            let name = CString::new(name.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "cgroup path contains NUL")
            })?;
            let next = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next < 0 {
                return Err(io::Error::last_os_error());
            }
            current = unsafe { OwnedFd::from_raw_fd(next) };
        }
        Ok(current)
    }

    fn verify_cgroup2_fs(fd: RawFd) -> io::Result<()> {
        let mut stat: libc::statfs = unsafe { zeroed() };
        if unsafe { libc::fstatfs(fd, &mut stat) } != 0 {
            return Err(io::Error::last_os_error());
        }
        if stat.f_type as libc::c_long != CGROUP2_SUPER_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "directory is not on a cgroup2 filesystem",
            ));
        }
        Ok(())
    }

    fn open_cgroup_control(dir_fd: RawFd, name: &str, write: bool) -> io::Result<File> {
        let name = CString::new(name).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid cgroup control name")
        })?;
        let flags = if write {
            libc::O_WRONLY
        } else {
            libc::O_RDONLY
        };
        let raw = unsafe {
            libc::openat(
                dir_fd,
                name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn read_cgroup_file(dir_fd: RawFd, name: &str) -> io::Result<String> {
        let mut file = open_cgroup_control(dir_fd, name, false)?;
        let mut content = String::new();
        file.read_to_string(&mut content)?;
        Ok(content)
    }

    fn write_cgroup_file(dir_fd: RawFd, name: &str, value: &[u8]) -> io::Result<()> {
        let mut file = open_cgroup_control(dir_fd, name, true)?;
        file.write_all(value)
    }

    fn verify_cgroup_control(dir_fd: RawFd, name: &str, expected: &str) -> Result<(), String> {
        let actual = read_cgroup_file(dir_fd, name)
            .map_err(|error| format!("cannot read back {name}: {error}"))?;
        if actual.trim() != expected {
            return Err(format!(
                "{name} read back {:?}, expected {:?}",
                actual.trim(),
                expected
            ));
        }
        Ok(())
    }

    fn remove_empty_cgroup(root_fd: RawFd, name: &CString) {
        unsafe {
            libc::unlinkat(root_fd, name.as_ptr(), libc::AT_REMOVEDIR);
        }
    }

    fn process_cgroup_path() -> io::Result<String> {
        let contents = fs::read_to_string("/proc/self/cgroup")?;
        let mut unified = None;
        for line in contents.lines() {
            if let Some(path) = line.strip_prefix("0::") {
                if unified.replace(path.to_owned()).is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "/proc/self/cgroup contains duplicate unified records",
                    ));
                }
            }
        }
        unified.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "/proc/self/cgroup has no unified cgroup v2 record",
            )
        })
    }

    fn decode_mountinfo_path(value: &str) -> String {
        value
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
    }

    fn cgroup2_mountpoint() -> io::Result<PathBuf> {
        let mountinfo = fs::read_to_string("/proc/self/mountinfo")?;
        for line in mountinfo.lines() {
            let Some((before, after)) = line.split_once(" - ") else {
                continue;
            };
            let left = before.split_ascii_whitespace().collect::<Vec<_>>();
            let right = after.split_ascii_whitespace().collect::<Vec<_>>();
            if right.first() == Some(&"cgroup2") && left.len() >= 5 {
                return Ok(PathBuf::from(decode_mountinfo_path(left[4])));
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no cgroup2 mount is visible",
        ))
    }

    fn verify_delegated_root_is_current_cgroup(
        root_fd: RawFd,
        _delegated_root: &Path,
        current_path: &str,
    ) -> io::Result<()> {
        if !current_path.starts_with('/') || current_path.ends_with('/') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "current cgroup path is malformed",
            ));
        }
        let mountpoint = cgroup2_mountpoint()?;
        let current_dir = mountpoint.join(current_path.trim_start_matches('/'));
        let expected = fs::canonicalize(current_dir)?;
        let actual = fs::canonicalize(format!("/proc/self/fd/{root_fd}"))?;
        if actual != expected {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "only the caller's own delegated cgroup can be used as the root",
            ));
        }
        Ok(())
    }

    fn probe_clone3_into_cgroup(fd: RawFd, expected_path: &str) -> io::Result<bool> {
        let pipe = create_pipe_above_stdio()?;
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
            cgroup: fd as u64,
        };
        let child = unsafe { libc::syscall(libc::SYS_clone3, &args, size_of::<CloneArgs>()) }
            as libc::pid_t;
        if child < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
            }
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOSYS)
                    | Some(libc::EINVAL)
                    | Some(libc::EPERM)
                    | Some(libc::EACCES)
                    | Some(libc::EOPNOTSUPP)
            ) {
                return Ok(false);
            }
            return Err(error);
        }
        if child == 0 {
            unsafe {
                libc::close(pipe[1]);
                let mut release = 0_u8;
                let read = read_one(pipe[0], &mut release);
                libc::close(pipe[0]);
                libc::_exit(if read == 1 && release == 1 { 0 } else { 125 });
            }
        }
        unsafe { libc::close(pipe[0]) };
        let membership = fs::read_to_string(format!("/proc/{child}/cgroup"));
        if !membership
            .as_deref()
            .is_ok_and(|contents| super::proc_cgroup_matches(contents, expected_path))
        {
            unsafe {
                libc::kill(child, libc::SIGKILL);
                libc::close(pipe[1]);
            }
            let _ = wait_for_child(child);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("CLONE_INTO_CGROUP child did not enter exact cgroup {expected_path}"),
            ));
        }
        let mut release = unsafe { File::from_raw_fd(pipe[1]) };
        if let Err(error) = release.write_all(&[1]) {
            unsafe { libc::kill(child, libc::SIGKILL) };
            let _ = wait_for_child(child);
            return Err(error);
        }
        let status = wait_for_child(child)?;
        if !status.success() {
            return Err(io::Error::other("CLONE_INTO_CGROUP probe child failed"));
        }
        Ok(true)
    }

    fn create_parent_attach_placement(
        cgroup_procs: File,
        cgroup_kill: File,
        expected_cgroup_path: String,
    ) -> Result<CgroupPlacementMode, SandboxError> {
        let ready_pipe = create_pipe_above_stdio().map_err(|source| SandboxError::Io {
            operation: "create cgroup parent-attach ready pipe",
            source,
        })?;
        let release_pipe = match create_pipe_above_stdio() {
            Ok(pipe) => pipe,
            Err(source) => {
                unsafe {
                    libc::close(ready_pipe[0]);
                    libc::close(ready_pipe[1]);
                }
                return Err(SandboxError::Io {
                    operation: "create cgroup parent-attach release pipe",
                    source,
                });
            }
        };
        Ok(CgroupPlacementMode::ParentAttachBarrier {
            parent_ready: unsafe { File::from_raw_fd(ready_pipe[0]) },
            child_ready: unsafe { File::from_raw_fd(ready_pipe[1]) },
            child_release: unsafe { File::from_raw_fd(release_pipe[0]) },
            parent_release: unsafe { File::from_raw_fd(release_pipe[1]) },
            cgroup_procs,
            cgroup_kill,
            expected_cgroup_path,
        })
    }

    struct PreparedSpawn<'a> {
        root: RootPaths,
        input_source: CString,
        task_source: CString,
        tool_source: CString,
        input: &'a PinnedPath,
        task: &'a PinnedPath,
        task_read_fd: RawFd,
        tool: &'a PinnedPath,
        tool_inventory: &'a PinnedToolInventory,
        program_fd: RawFd,
        policy_fds: Vec<RawFd>,
        uid_map: CString,
        gid_map: CString,
        tmpfs_data: CString,
        limits: SandboxLimits,
        placement: PlacementFds,
        _placement_owners: Vec<OwnedFd>,
        report_fd: RawFd,
        parent_ack_fd: RawFd,
        null_fd: RawFd,
        _exec_strings: Vec<CString>,
        argv: Vec<usize>,
        envp: [usize; 1],
        seccomp: Vec<libc::sock_filter>,
        host_network_namespace: FileIdentity,
    }

    struct PinnedPath {
        fd: OwnedFd,
        identity: FileIdentity,
        directory_chain: Vec<FileIdentity>,
        link_count: u64,
        mode: libc::mode_t,
        owner_uid: u32,
        owner_gid: u32,
        mount_id: u64,
        signature: LinuxFileSignature,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct LinuxFileSignature {
        identity: FileIdentity,
        link_count: u64,
        mode: libc::mode_t,
        size: i64,
        mtime_sec: i64,
        mtime_nsec: i64,
        ctime_sec: i64,
        ctime_nsec: i64,
    }

    struct PinnedToolDirectory {
        fd: OwnedFd,
        relative_path: PathBuf,
        evidence: ToolEntryEvidence,
        signature: LinuxFileSignature,
    }

    struct PinnedToolEntry {
        parent: usize,
        name: CString,
        evidence: ToolEntryEvidence,
        signature: LinuxFileSignature,
    }

    struct PinnedToolInventory {
        snapshot: ToolInventory,
        directories: Vec<PinnedToolDirectory>,
        entries: Vec<PinnedToolEntry>,
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
        let host_uid = unsafe { libc::geteuid() };
        let host_gid = unsafe { libc::getegid() };

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

    pub(super) fn inspect_network_prerequisites() -> Result<NetworkEvidence, SandboxError> {
        let probe_root = TempRoot::create().ok();
        let ipv4_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).and_then(|listener| {
            listener.set_nonblocking(true)?;
            Ok(listener)
        });
        let ipv6_listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).and_then(|listener| {
            listener.set_nonblocking(true)?;
            Ok(listener)
        });
        let unix_listener = probe_root.as_ref().and_then(|root| {
            let path = root.path().join("outside.sock");
            UnixListener::bind(path)
                .and_then(|listener| {
                    listener.set_nonblocking(true)?;
                    Ok(listener)
                })
                .ok()
        });
        let host_uid = unsafe { libc::geteuid() };
        let host_gid = unsafe { libc::getegid() };
        let private_namespace_created = probe_root.as_ref().map_or_else(
            || ProbeEvidence::failed("private network namespace probe root unavailable"),
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkNamespaceCreated,
                    host_uid,
                    host_gid,
                    "created a distinct network namespace (nsfs identity changed)",
                )
            },
        );

        let ipv4_socket_denial = match (&probe_root, &ipv4_listener) {
            (Some(root), Ok(listener)) => {
                let port = listener.local_addr().map(|address| address.port());
                match port {
                    Ok(port) => network_probe(
                        root,
                        ProbeKind::NetworkIpv4(port),
                        host_uid,
                        host_gid,
                        "AF_INET socket creation returned the network seccomp denial",
                    ),
                    Err(error) => ProbeEvidence::failed(format!(
                        "could not inspect controlled IPv4 listener: {error}"
                    )),
                }
            }
            (None, _) => ProbeEvidence::failed(
                "IPv4 socket probe could not run: private probe root unavailable",
            ),
            (_, Err(error)) => {
                ProbeEvidence::failed(format!("could not bind controlled IPv4 listener: {error}"))
            }
        };
        let ipv6_socket_denial = match (&probe_root, &ipv6_listener) {
            (Some(root), Ok(listener)) => {
                let port = listener.local_addr().map(|address| address.port());
                match port {
                    Ok(port) => network_probe(
                        root,
                        ProbeKind::NetworkIpv6(port),
                        host_uid,
                        host_gid,
                        "AF_INET6 socket creation returned the network seccomp denial",
                    ),
                    Err(error) => ProbeEvidence::failed(format!(
                        "could not inspect controlled IPv6 listener: {error}"
                    )),
                }
            }
            (None, _) => ProbeEvidence::failed(
                "IPv6 socket probe could not run: private probe root unavailable",
            ),
            (_, Err(error)) => {
                ProbeEvidence::failed(format!("could not bind controlled IPv6 listener: {error}"))
            }
        };
        let packet_socket_denial = probe_root.as_ref().map_or_else(
            || {
                ProbeEvidence::failed(
                    "packet socket probe could not run: private probe root unavailable",
                )
            },
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkPacket,
                    host_uid,
                    host_gid,
                    "AF_PACKET socket creation returned the network seccomp denial",
                )
            },
        );
        let ipv4_listener_isolated = match &ipv4_listener {
            Ok(listener) => controlled_listener_isolated(listener, "IPv4"),
            Err(error) => {
                ProbeEvidence::failed(format!("IPv4 controlled listener was unavailable: {error}"))
            }
        };
        let ipv6_listener_isolated = match &ipv6_listener {
            Ok(listener) => controlled_listener_isolated(listener, "IPv6"),
            Err(error) => {
                ProbeEvidence::failed(format!("IPv6 controlled listener was unavailable: {error}"))
            }
        };
        let unix_socket_escape = match (&probe_root, &unix_listener) {
            (Some(root), Some(listener)) => {
                let result = network_probe(
                    root,
                    ProbeKind::NetworkUnixEscape,
                    host_uid,
                    host_gid,
                    "pre-seccomp path-visibility probe reached ENOENT outside the sandbox root",
                );
                match listener.accept() {
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => result,
                    Ok((stream, address)) => {
                        drop(stream);
                        ProbeEvidence::failed(format!(
                            "sandbox reached host Unix socket from {address:?}"
                        ))
                    }
                    Err(error) => ProbeEvidence::failed(format!(
                        "could not inspect controlled Unix listener: {error}"
                    )),
                }
            }
            (None, _) => ProbeEvidence::failed(
                "Unix socket escape probe could not run: private probe root unavailable",
            ),
            (_, None) => ProbeEvidence::failed("could not bind controlled host Unix socket"),
        };
        let connect_denial = probe_root.as_ref().map_or_else(
            || ProbeEvidence::failed("connect probe could not run: private probe root unavailable"),
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkConnect,
                    host_uid,
                    host_gid,
                    "post-seccomp AF_UNIX socket creation remained allowed while connect returned EACCES",
                )
            },
        );
        let socketpair_denial = probe_root.as_ref().map_or_else(
            || {
                ProbeEvidence::failed(
                    "socketpair probe could not run: private probe root unavailable",
                )
            },
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkSocketPair,
                    host_uid,
                    host_gid,
                    "socketpair returned the network seccomp denial",
                )
            },
        );
        let bpf_denial = probe_root.as_ref().map_or_else(
            || ProbeEvidence::failed("bpf probe could not run: private probe root unavailable"),
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkBpf,
                    host_uid,
                    host_gid,
                    "bpf returned the network seccomp denial",
                )
            },
        );
        let userfaultfd_denial = probe_root.as_ref().map_or_else(
            || {
                ProbeEvidence::failed(
                    "userfaultfd probe could not run: private probe root unavailable",
                )
            },
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkUserfaultfd,
                    host_uid,
                    host_gid,
                    "userfaultfd returned the network seccomp denial",
                )
            },
        );
        let namespace_creation_denied = probe_root.as_ref().map_or_else(
            || {
                ProbeEvidence::failed(
                    "namespace creation probe could not run: private probe root unavailable",
                )
            },
            |root| {
                network_probe(
                    root,
                    ProbeKind::NetworkNamespaceEscape,
                    host_uid,
                    host_gid,
                    "network namespace creation and entry syscalls were denied after setup",
                )
            },
        );

        let evidence = NetworkEvidence {
            private_namespace_created,
            ipv4_socket_denial,
            ipv6_socket_denial,
            packet_socket_denial,
            ipv4_listener_isolated,
            ipv6_listener_isolated,
            unix_socket_escape,
            connect_denial,
            socketpair_denial,
            bpf_denial,
            userfaultfd_denial,
            namespace_creation_denied,
        };
        if evidence.all_passed() {
            Ok(evidence)
        } else {
            Err(SandboxError::NetworkPrerequisitesFailed(Box::new(evidence)))
        }
    }

    fn network_probe(
        root: &TempRoot,
        kind: ProbeKind,
        host_uid: libc::uid_t,
        host_gid: libc::gid_t,
        success: &str,
    ) -> ProbeEvidence {
        probe_result(
            run_probe(kind, Some(root.path()), host_uid, host_gid),
            success,
        )
    }

    fn controlled_listener_isolated(listener: &TcpListener, family: &str) -> ProbeEvidence {
        match listener.accept() {
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => ProbeEvidence::passed(
                format!("controlled {family} listener accepted zero connections"),
            ),
            Ok((stream, address)) => {
                drop(stream);
                ProbeEvidence::failed(format!(
                    "controlled {family} listener accepted a sandbox connection from {address}"
                ))
            }
            Err(error) => ProbeEvidence::failed(format!(
                "could not inspect controlled {family} listener: {error}"
            )),
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
        NetworkIpv4(u16),
        NetworkIpv6(u16),
        NetworkNamespaceCreated,
        NetworkPacket,
        NetworkUnixEscape,
        NetworkConnect,
        NetworkSocketPair,
        NetworkBpf,
        NetworkUserfaultfd,
        NetworkNamespaceEscape,
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
                let result = run_probe_child(kind, scratch.as_ref(), &uid_map, &gid_map, pipe[1]);
                if write_struct(pipe[1], &result).is_err() {
                    libc::_exit(125);
                }
                libc::_exit(if result.operation == PROBE_OK { 0 } else { 1 });
            }
        }

        unsafe { libc::close(pipe[1]) };
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let deadline = Instant::now() + ACTIVE_PROBE_TIMEOUT;
        let mut result = ProbeResult {
            operation: STAGE_FORK,
            errno: libc::ECHILD,
        };
        if let Err(error) =
            read_struct_until(reader.as_raw_fd(), &mut reader, &mut result, deadline)
        {
            abort_probe(pid);
            return Err(error);
        }
        let status = match reap_probe_until(pid, deadline) {
            Ok(status) => status,
            Err(error) => {
                abort_probe(pid);
                return Err(error);
            }
        };
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
                if write_struct(pipe[1], &result).is_err() {
                    libc::_exit(125);
                }
                libc::_exit(if result.operation == PROBE_OK { 0 } else { 1 });
            }
        }

        unsafe {
            libc::close(pipe[1]);
            libc::close(sentinel);
        }
        let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let deadline = Instant::now() + ACTIVE_PROBE_TIMEOUT;
        let mut result = ProbeResult {
            operation: STAGE_FD_CLOSE,
            errno: libc::ECHILD,
        };
        if let Err(error) =
            read_struct_until(reader.as_raw_fd(), &mut reader, &mut result, deadline)
        {
            abort_probe(pid);
            return ProbeEvidence::failed(format!("descriptor-closure probe failed: {error}"));
        }
        if let Err(error) = reap_probe_until(pid, deadline) {
            abort_probe(pid);
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

    fn reap_probe_until(pid: libc::pid_t, deadline: Instant) -> io::Result<i32> {
        let mut status = 0;
        loop {
            let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if result == pid {
                return Ok(status);
            }
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "active probe exit deadline expired",
                ));
            }
            let timeout_ms = remaining
                .min(ACTIVE_PROBE_REAP_POLL_INTERVAL)
                .as_millis()
                .clamp(1, i32::MAX as u128) as i32;
            let waited = unsafe { libc::poll(std::ptr::null_mut(), 0, timeout_ms) };
            if waited < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
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
        report_fd: RawFd,
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
            ProbeKind::NetworkIpv4(_)
            | ProbeKind::NetworkIpv6(_)
            | ProbeKind::NetworkNamespaceCreated
            | ProbeKind::NetworkPacket
            | ProbeKind::NetworkUnixEscape
            | ProbeKind::NetworkConnect
            | ProbeKind::NetworkSocketPair
            | ProbeKind::NetworkBpf
            | ProbeKind::NetworkUserfaultfd
            | ProbeKind::NetworkNamespaceEscape => {
                run_network_probe_child(kind, scratch, uid_map, gid_map, report_fd)
            }
        }
    }

    unsafe fn run_network_probe_child(
        kind: ProbeKind,
        scratch: Option<&CString>,
        uid_map: &CString,
        gid_map: &CString,
        report_fd: RawFd,
    ) -> ProbeResult {
        if close_range_except(&[report_fd]) != 0 {
            return failed(STAGE_FD_CLOSE);
        }
        if let Err(result) = enter_user_namespace_from_maps(uid_map, gid_map) {
            return result;
        }
        let original_network_namespace = match network_namespace_identity() {
            Ok(identity) => identity,
            Err(_) => return failed(STAGE_NETWORK_NAMESPACE),
        };
        if libc::unshare(libc::CLONE_NEWNET) != 0 {
            return failed(STAGE_NETWORK_NAMESPACE);
        }
        let isolated_network_namespace = match network_namespace_identity() {
            Ok(identity) => identity,
            Err(_) => return failed(STAGE_NETWORK_NAMESPACE),
        };
        if isolated_network_namespace == original_network_namespace {
            return failed_with_errno(STAGE_NETWORK_NAMESPACE, libc::ESTALE);
        }
        if matches!(kind, ProbeKind::NetworkNamespaceCreated) {
            return success();
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
        let scratch_path = Path::new(std::ffi::OsStr::from_bytes(scratch.to_bytes()));
        let root = match RootPaths::new(scratch_path) {
            Ok(root) => root,
            Err(_) => return failed_with_errno(STAGE_TMPFS, libc::EINVAL),
        };
        if mount_tmpfs(&root.base, b"mode=755,size=4m\0") != 0
            || make_root_layout(&root) != 0
            || mount_tmpfs(&root.tmp, b"mode=1777,size=4m\0") != 0
        {
            return failed(STAGE_TMPFS);
        }
        if pivot_to_root(&root.base) != 0 {
            return failed(STAGE_PIVOT_ROOT);
        }
        if libc::mount(
            std::ptr::null(),
            c"/".as_ptr(),
            std::ptr::null(),
            libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        ) != 0
        {
            return failed(STAGE_BIND_RO);
        }
        if libc::chdir(c"/task".as_ptr()) != 0 {
            return failed(STAGE_TASK_CWD);
        }
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return failed(STAGE_NO_NEW_PRIVS);
        }
        if drop_capabilities() != 0 {
            return failed(STAGE_CAP_DROP);
        }
        if matches!(kind, ProbeKind::NetworkUnixEscape) {
            let mut path = scratch.to_bytes().to_vec();
            path.extend_from_slice(b"/outside.sock");
            return match CString::new(path) {
                Ok(path) => probe_unix_socket_is_outside_root(&path),
                Err(_) => failed_with_errno(STAGE_NETWORK_UNIX_SOCKET, libc::EINVAL),
            };
        }
        if install_seccomp(&build_sandbox_filter(false)) != 0 {
            return failed(STAGE_SECCOMP);
        }

        match kind {
            ProbeKind::NetworkIpv4(port) => probe_ipv4_socket_denial(port),
            ProbeKind::NetworkIpv6(port) => probe_ipv6_socket_denial(port),
            ProbeKind::NetworkNamespaceCreated => success(),
            ProbeKind::NetworkPacket => probe_packet_socket_denial(),
            ProbeKind::NetworkUnixEscape => unreachable!(),
            ProbeKind::NetworkConnect => probe_connect_denial(),
            ProbeKind::NetworkSocketPair => probe_socketpair_denial(),
            ProbeKind::NetworkBpf => probe_bpf_denial(),
            ProbeKind::NetworkUserfaultfd => probe_userfaultfd_denial(),
            ProbeKind::NetworkNamespaceEscape => probe_namespace_creation_denial(),
            _ => failed_with_errno(STAGE_NETWORK_ESCAPE, libc::EINVAL),
        }
    }

    fn network_namespace_identity() -> io::Result<FileIdentity> {
        let fd = unsafe {
            libc::open(
                c"/proc/self/ns/net".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut metadata: libc::stat = unsafe { zeroed() };
        let result = unsafe { libc::fstat(fd, &mut metadata) };
        let error = (result != 0).then(io::Error::last_os_error);
        unsafe { libc::close(fd) };
        if let Some(error) = error {
            Err(error)
        } else {
            Ok(identity_from_stat(&metadata))
        }
    }

    unsafe fn probe_ipv4_socket_denial(port: u16) -> ProbeResult {
        let socket = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return if errno() == libc::EACCES {
                success()
            } else {
                failed(STAGE_NETWORK_SOCKET)
            };
        }
        let address = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(Ipv4Addr::LOCALHOST.octets()),
            },
            sin_zero: [0; 8],
        };
        let connected = libc::connect(
            socket,
            (&address as *const libc::sockaddr_in).cast(),
            size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        let connect_errno = errno();
        libc::close(socket);
        failed_with_errno(
            STAGE_NETWORK_SOCKET,
            if connected == 0 { 0 } else { connect_errno },
        )
    }

    unsafe fn probe_ipv6_socket_denial(port: u16) -> ProbeResult {
        let socket = libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return if errno() == libc::EACCES {
                success()
            } else {
                failed(STAGE_NETWORK_SOCKET)
            };
        }
        let address = libc::sockaddr_in6 {
            sin6_family: libc::AF_INET6 as libc::sa_family_t,
            sin6_port: port.to_be(),
            sin6_flowinfo: 0,
            sin6_addr: libc::in6_addr {
                s6_addr: Ipv6Addr::LOCALHOST.octets(),
            },
            sin6_scope_id: 0,
        };
        let connected = libc::connect(
            socket,
            (&address as *const libc::sockaddr_in6).cast(),
            size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        );
        let connect_errno = errno();
        libc::close(socket);
        failed_with_errno(
            STAGE_NETWORK_SOCKET,
            if connected == 0 { 0 } else { connect_errno },
        )
    }

    unsafe fn probe_packet_socket_denial() -> ProbeResult {
        let socket = libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 && errno() == libc::EACCES {
            return success();
        }
        if socket >= 0 {
            libc::close(socket);
        }
        failed(STAGE_NETWORK_SOCKET)
    }

    unsafe fn probe_connect_denial() -> ProbeResult {
        let socket = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return failed(STAGE_NETWORK_SYSCALL);
        }
        let mut address: libc::sockaddr_un = zeroed();
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let abstract_name = b"fluxform-connect-denial";
        for (target, source) in address.sun_path[1..1 + abstract_name.len()]
            .iter_mut()
            .zip(abstract_name)
        {
            *target = *source as libc::c_char;
        }
        let address_len =
            (size_of::<libc::sa_family_t>() + 1 + abstract_name.len()) as libc::socklen_t;
        let connected = libc::connect(
            socket,
            (&address as *const libc::sockaddr_un).cast(),
            address_len,
        );
        let connect_errno = errno();
        libc::close(socket);
        if connected < 0 && connect_errno == libc::EACCES {
            success()
        } else {
            failed_with_errno(
                STAGE_NETWORK_SYSCALL,
                if connected == 0 { 0 } else { connect_errno },
            )
        }
    }

    unsafe fn probe_socketpair_denial() -> ProbeResult {
        let mut pair = [-1; 2];
        let result = libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        );
        if result < 0 && errno() == libc::EACCES {
            return success();
        }
        if result == 0 {
            libc::close(pair[0]);
            libc::close(pair[1]);
        }
        failed(STAGE_NETWORK_SYSCALL)
    }

    unsafe fn probe_bpf_denial() -> ProbeResult {
        let result = libc::syscall(
            libc::SYS_bpf,
            0_u32,
            std::ptr::null_mut::<libc::c_void>(),
            0_u32,
        );
        if result < 0 && errno() == libc::EACCES {
            success()
        } else {
            failed(STAGE_NETWORK_SYSCALL)
        }
    }

    unsafe fn probe_userfaultfd_denial() -> ProbeResult {
        let result = libc::syscall(libc::SYS_userfaultfd, libc::O_CLOEXEC | libc::O_NONBLOCK);
        if result < 0 && errno() == libc::EACCES {
            success()
        } else {
            if result >= 0 {
                libc::close(result as RawFd);
            }
            failed(STAGE_NETWORK_SYSCALL)
        }
    }

    unsafe fn probe_unix_socket_is_outside_root(path: &CString) -> ProbeResult {
        let socket = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
        if socket < 0 {
            return failed(STAGE_NETWORK_UNIX_SOCKET);
        }
        let mut address: libc::sockaddr_un = zeroed();
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        let path_bytes = path.as_bytes_with_nul();
        if path_bytes.len() > address.sun_path.len() {
            libc::close(socket);
            return failed_with_errno(STAGE_NETWORK_UNIX_SOCKET, libc::ENAMETOOLONG);
        }
        std::ptr::copy_nonoverlapping(
            path_bytes.as_ptr(),
            address.sun_path.as_mut_ptr().cast(),
            path_bytes.len(),
        );
        let address_len = (size_of::<libc::sa_family_t>() + path_bytes.len()) as libc::socklen_t;
        let connected = libc::connect(
            socket,
            (&address as *const libc::sockaddr_un).cast(),
            address_len,
        );
        let connect_errno = errno();
        libc::close(socket);
        if connected < 0 && connect_errno == libc::ENOENT {
            success()
        } else {
            failed_with_errno(
                STAGE_NETWORK_UNIX_SOCKET,
                if connected == 0 { 0 } else { connect_errno },
            )
        }
    }

    unsafe fn probe_namespace_creation_denial() -> ProbeResult {
        if libc::unshare(libc::CLONE_NEWNET) == 0 || errno() != libc::EPERM {
            return failed(STAGE_NETWORK_ESCAPE);
        }
        if libc::setns(-1, libc::CLONE_NEWNET) == 0 || errno() != libc::EPERM {
            return failed(STAGE_NETWORK_ESCAPE);
        }
        let clone_args = CloneArgs {
            flags: libc::CLONE_NEWNET as u64,
            pidfd: 0,
            child_tid: 0,
            parent_tid: 0,
            exit_signal: libc::SIGCHLD as u64,
            stack: 0,
            stack_size: 0,
            tls: 0,
            set_tid: 0,
            set_tid_size: 0,
            cgroup: 0,
        };
        if libc::syscall(libc::SYS_clone3, &clone_args, size_of::<CloneArgs>()) >= 0
            || errno() != libc::EPERM
        {
            return failed(STAGE_NETWORK_ESCAPE);
        }

        let mut stack = vec![0_u8; 64 * 1024];
        let stack_top = stack.as_mut_ptr().add(stack.len());
        let stack_top = ((stack_top as usize) & !0xf) as *mut libc::c_void;
        let clone_result = libc::clone(
            namespace_probe_child,
            stack_top,
            libc::CLONE_NEWNET | libc::SIGCHLD,
            std::ptr::null_mut(),
        );
        if clone_result < 0 {
            if errno() != libc::EPERM {
                return failed(STAGE_NETWORK_ESCAPE);
            }
        } else if clone_result == 0 {
            libc::_exit(126);
        } else {
            let mut status = 0;
            loop {
                let waited = libc::waitpid(clone_result, &mut status, 0);
                if waited == clone_result {
                    break;
                }
                if waited < 0 && errno() == libc::EINTR {
                    continue;
                }
                return failed(STAGE_NETWORK_ESCAPE);
            }
            return failed(STAGE_NETWORK_ESCAPE);
        }
        success()
    }

    fn map_line(id: u32) -> Vec<u8> {
        format!("0 {id} 1\n").into_bytes()
    }

    unsafe fn write_proc(path: &std::ffi::CStr, bytes: &[u8]) -> i32 {
        let fd = libc::open(path.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
        if fd < 0 {
            return -errno();
        }
        if let Err(error) = super::write_all_with(bytes, |remaining| {
            let count = libc::write(fd, remaining.as_ptr().cast(), remaining.len());
            if count < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(count as usize)
            }
        }) {
            libc::close(fd);
            return -error.raw_os_error().unwrap_or(libc::EIO);
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
        mut placement: SpawnPlacement,
    ) -> Result<SandboxChild, SandboxError> {
        ensure_spawn_allowed(&placement)?;
        let reaper = match &placement {
            SpawnPlacement::CgroupV2(managed) => Arc::clone(&managed.inner.reaper),
            SpawnPlacement::CloneIntoCgroup(_) | SpawnPlacement::ParentAttachBarrier { .. } => {
                ChildReaper::new()
            }
        };
        validate_limits(policy.limits)?;
        let input = open_pinned_path(&policy.input, false, "input")?;
        let task = open_pinned_path(&policy.job_dir, true, "task directory")?;
        let tool = open_pinned_path(&policy.tool_dir, true, "tool directory")?;

        let root_graph = PolicyPathIdentityGraph {
            input: input.identity,
            input_parent_chain: input.directory_chain.clone(),
            task: task.identity,
            task_ancestors: task.directory_chain.clone(),
            tool: tool.identity,
            tool_ancestors: tool.directory_chain.clone(),
            task_files: HashSet::new(),
            tool_files: HashSet::new(),
        };
        validate_policy_path_identities(&root_graph)
            .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;

        let task_read_fd = open_task_reader(&task)?;
        if !task_directory_is_empty(
            task_read_fd.as_raw_fd(),
            &task,
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
        )? {
            return Err(SandboxError::InvalidPolicy(
                "task directory must be empty, mode 0700, and owned by the current effective user and group when a sandbox is prepared".into(),
            ));
        }
        let tool_inventory = collect_tool_inventory(&tool, input.identity)?;
        let tool_files = tool_inventory
            .snapshot
            .entries
            .values()
            .map(|entry| entry.identity)
            .collect::<HashSet<_>>();
        let policy_graph = PolicyPathIdentityGraph {
            tool_files,
            ..root_graph
        };
        validate_policy_path_identities(&policy_graph)
            .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;

        let program_pin = open_pinned_path(program, false, "tool executable")?;
        if !program_pin.directory_chain.contains(&tool.identity) {
            return Err(SandboxError::InvalidPolicy(
                "tool executable must be inside the declared tool directory".into(),
            ));
        }
        if program_pin.mode & 0o111 == 0 {
            return Err(SandboxError::InvalidPolicy(
                "tool executable has no execute permission".into(),
            ));
        }
        let relative_program = program.strip_prefix(&policy.tool_dir).map_err(|_| {
            SandboxError::InvalidPolicy(
                "tool executable escaped the declared tool directory".into(),
            )
        })?;
        let program_evidence = tool_inventory
            .snapshot
            .entries
            .get(relative_program)
            .ok_or_else(|| {
                SandboxError::InvalidPolicy(
                    "tool executable is not present in the pinned tool inventory".into(),
                )
            })?;
        if program_evidence.identity != program_pin.identity {
            return Err(SandboxError::InvalidPolicy(
                "tool executable changed while its inventory was prepared".into(),
            ));
        }
        validate_tool_inventory(
            input.identity,
            &tool_inventory.snapshot,
            &tool_inventory.snapshot,
        )
        .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;
        FilesystemPrerequisites::inspect()?;
        NetworkPrerequisites::inspect()?;
        let host_network_namespace =
            network_namespace_identity().map_err(|source| SandboxError::Io {
                operation: "capture host network namespace identity",
                source,
            })?;
        if host_network_namespace.device == 0 || host_network_namespace.inode == 0 {
            return Err(SandboxError::Io {
                operation: "validate host network namespace identity",
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "host network namespace identity was incomplete",
                ),
            });
        }
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
        let input_source = proc_fd_path(input.fd.as_raw_fd())?;
        let task_source = proc_fd_path(task.fd.as_raw_fd())?;
        let tool_source = proc_fd_path(tool.fd.as_raw_fd())?;
        let host_uid = unsafe { libc::geteuid() };
        let host_gid = unsafe { libc::getegid() };
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
        let pipe = match create_pipe_above_stdio() {
            Ok(pipe) => pipe,
            Err(source) => {
                unsafe { libc::close(null_fd) };
                return Err(SandboxError::Io {
                    operation: "create child setup report pipe",
                    source,
                });
            }
        };
        let ack_pipe = match create_pipe_above_stdio() {
            Ok(pipe) => pipe,
            Err(source) => {
                unsafe {
                    libc::close(pipe[0]);
                    libc::close(pipe[1]);
                    libc::close(null_fd);
                }
                return Err(SandboxError::Io {
                    operation: "create parent-acknowledgment pipe",
                    source,
                });
            }
        };
        let allow_session_escape = matches!(&placement, SpawnPlacement::CgroupV2(_));
        let seccomp = build_sandbox_filter(allow_session_escape);
        let policy_fds = build_policy_fd_list(
            input.fd.as_raw_fd(),
            task.fd.as_raw_fd(),
            task_read_fd.as_raw_fd(),
            tool.fd.as_raw_fd(),
            program_pin.fd.as_raw_fd(),
            &tool_inventory,
            &placement_fds,
            pipe[1],
            ack_pipe[0],
        );
        let spec = PreparedSpawn {
            root,
            input_source,
            task_source,
            tool_source,
            input: &input,
            task: &task,
            task_read_fd: task_read_fd.as_raw_fd(),
            tool: &tool,
            tool_inventory: &tool_inventory,
            program_fd: program_pin.fd.as_raw_fd(),
            policy_fds,
            uid_map,
            gid_map,
            tmpfs_data,
            limits: policy.limits,
            placement: placement_fds,
            _placement_owners: placement_owners,
            report_fd: pipe[1],
            parent_ack_fd: ack_pipe[0],
            null_fd,
            _exec_strings: exec_strings,
            argv,
            envp: [0],
            seccomp,
            host_network_namespace,
        };

        let pid = unsafe { libc::fork() };
        if pid < 0 {
            unsafe {
                libc::close(pipe[0]);
                libc::close(pipe[1]);
                libc::close(ack_pipe[0]);
                libc::close(ack_pipe[1]);
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
                libc::close(ack_pipe[1]);
                sandbox_supervisor(&spec);
            }
        }

        unsafe {
            libc::close(pipe[1]);
            libc::close(ack_pipe[0]);
            libc::close(null_fd);
        }
        let mut report = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
        let parent_ack = unsafe { std::fs::File::from_raw_fd(ack_pipe[1]) };
        let mut message = Message {
            kind: MSG_ERROR,
            operation: STAGE_FORK,
            errno: libc::ECHILD,
            pid,
            network_namespace_device: 0,
            network_namespace_inode: 0,
        };
        if let Err(source) = read_struct(&mut report, &mut message) {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "read sandbox setup report",
                source,
            });
        }
        if message.kind == MSG_ERROR {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::ChildSetup {
                operation: operation_name(message.operation),
                errno: message.errno,
            });
        }
        if message.kind != MSG_NAMESPACE_ATTESTATION || message.pid != pid {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "validate network namespace attestation",
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid child namespace-attestation message",
                ),
            });
        }
        let reported_network_namespace = (message.network_namespace_device != 0
            && message.network_namespace_inode != 0)
            .then_some(FileIdentity {
                device: message.network_namespace_device,
                inode: message.network_namespace_inode,
            });
        if !network_namespace_is_private(host_network_namespace, reported_network_namespace) {
            let error = if reported_network_namespace.is_some() {
                libc::ESTALE
            } else {
                libc::EPROTO
            };
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::ChildSetup {
                operation: "network namespace identity attestation",
                errno: error,
            });
        }

        if let Err(error) = ensure_spawn_allowed(&placement) {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(error);
        }

        if let Err(source) = write_parent_ack(parent_ack.as_raw_fd()) {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "acknowledge network namespace attestation",
                source,
            });
        }
        drop(parent_ack);

        let mut readiness = Message {
            kind: MSG_ERROR,
            operation: STAGE_FORK,
            errno: libc::ECHILD,
            pid,
            network_namespace_device: 0,
            network_namespace_inode: 0,
        };
        if let Err(source) = read_struct(&mut report, &mut readiness) {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "read post-attestation sandbox readiness",
                source,
            });
        }
        if readiness.kind == MSG_ERROR {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::ChildSetup {
                operation: operation_name(readiness.operation),
                errno: readiness.errno,
            });
        }
        let ready_network_namespace = (readiness.network_namespace_device != 0
            && readiness.network_namespace_inode != 0)
            .then_some(FileIdentity {
                device: readiness.network_namespace_device,
                inode: readiness.network_namespace_inode,
            });
        if readiness.kind != MSG_READY
            || readiness.pid != pid
            || ready_network_namespace != reported_network_namespace
        {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "validate post-attestation sandbox readiness",
                source: io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid readiness message or namespace identity changed after acknowledgment",
                ),
            });
        }
        if let Err(error) = ensure_spawn_allowed(&placement) {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(error);
        }
        if let SpawnPlacement::CgroupV2(managed) = &mut placement {
            if let Err(error) = managed.inner.attach_and_release(pid) {
                let _ = kill_process_group(pid);
                let _ = wait_for_child(pid);
                return Err(error);
            }
        }
        if let Err(source) = reaper.register(pid) {
            let _ = kill_spawn_members(&mut placement, pid);
            let _ = wait_for_child(pid);
            return Err(SandboxError::Io {
                operation: "register sandbox supervisor with reaper",
                source,
            });
        }
        Ok(SandboxChild {
            pid,
            root: Some(temp_root),
            reaper,
        })
    }

    fn ensure_spawn_allowed(placement: &SpawnPlacement) -> Result<(), SandboxError> {
        match placement {
            SpawnPlacement::CgroupV2(managed) => managed.inner.ensure_open(),
            SpawnPlacement::CloneIntoCgroup(_) | SpawnPlacement::ParentAttachBarrier { .. } => {
                Ok(())
            }
        }
    }

    fn kill_spawn_members(
        placement: &mut SpawnPlacement,
        supervisor_pid: libc::pid_t,
    ) -> io::Result<()> {
        match placement {
            SpawnPlacement::CgroupV2(managed) => managed.inner.kill_members(supervisor_pid),
            SpawnPlacement::CloneIntoCgroup(_) | SpawnPlacement::ParentAttachBarrier { .. } => {
                kill_process_group(supervisor_pid)
            }
        }
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
            SpawnPlacement::CgroupV2(managed) => match &managed.inner.kind {
                CgroupPlacementMode::CloneIntoCgroup(cgroup) => {
                    let owner = duplicate_fd(cgroup.as_raw_fd())?;
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
                CgroupPlacementMode::ParentAttachBarrier {
                    child_ready,
                    child_release,
                    ..
                } => {
                    let ready = duplicate_fd(child_ready.as_raw_fd())?;
                    let release = duplicate_fd(child_release.as_raw_fd())?;
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
            },
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
            || limits.tmpfs_max_bytes == 0
        {
            return Err(SandboxError::InvalidPolicy(
                "all resource limits must be positive".into(),
            ));
        }
        validate_open_files_limit(limits.open_files_max)
            .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;
        Ok(())
    }

    fn open_pinned_path(
        path: &Path,
        directory: bool,
        label: &'static str,
    ) -> Result<PinnedPath, SandboxError> {
        if !path.is_absolute() {
            return Err(SandboxError::InvalidPolicy(format!(
                "declared {label} must be an absolute path"
            )));
        }
        let mut components = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::RootDir => {}
                std::path::Component::Normal(name) => components.push(name.to_os_string()),
                std::path::Component::CurDir | std::path::Component::ParentDir => {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "declared {label} must not contain dot components"
                    )));
                }
                std::path::Component::Prefix(_) => {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "declared {label} has an unsupported path prefix"
                    )));
                }
            }
        }

        let root_fd = unsafe {
            libc::open(
                c"/".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if root_fd < 0 {
            return Err(SandboxError::Io {
                operation: "open filesystem root for declared sandbox path",
                source: io::Error::last_os_error(),
            });
        }
        let mut current = unsafe { OwnedFd::from_raw_fd(root_fd) };
        let mut directory_chain = vec![identity_from_fd(current.as_raw_fd())?];
        let mut final_stat = stat_fd(current.as_raw_fd())?;

        for (index, component) in components.iter().enumerate() {
            let name = CString::new(component.as_bytes()).map_err(|_| {
                SandboxError::InvalidPolicy(format!("declared {label} contains a NUL byte"))
            })?;
            let fd = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(SandboxError::Io {
                    operation: "open declared sandbox path component",
                    source: io::Error::last_os_error(),
                });
            }
            let next = unsafe { OwnedFd::from_raw_fd(fd) };
            let metadata = stat_fd(next.as_raw_fd())?;
            let final_component = index + 1 == components.len();
            let expected = if !final_component || directory {
                libc::S_IFDIR
            } else {
                libc::S_IFREG
            };
            if metadata.st_mode & libc::S_IFMT == libc::S_IFLNK {
                return Err(SandboxError::InvalidPolicy(format!(
                    "declared {label} must not traverse a symlink"
                )));
            }
            if metadata.st_mode & libc::S_IFMT != expected {
                return Err(SandboxError::InvalidPolicy(format!(
                    "declared {label} is not a {}",
                    if directory {
                        "directory"
                    } else {
                        "regular file"
                    }
                )));
            }
            if expected == libc::S_IFDIR {
                directory_chain.push(identity_from_stat(&metadata));
            }
            final_stat = metadata;
            current = next;
        }

        if components.is_empty() && !directory {
            return Err(SandboxError::InvalidPolicy(format!(
                "declared {label} is not a regular file"
            )));
        }
        let identity = identity_from_stat(&final_stat);
        let link_count = final_stat.st_nlink as u64;
        let mount_id = mount_id_for_fd(current.as_raw_fd())?;
        if current.as_raw_fd() < 3 {
            let duplicate = unsafe { libc::fcntl(current.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if duplicate < 0 {
                return Err(SandboxError::Io {
                    operation: "reserve declared sandbox path descriptor",
                    source: io::Error::last_os_error(),
                });
            }
            current = unsafe { OwnedFd::from_raw_fd(duplicate) };
        }
        Ok(PinnedPath {
            fd: current,
            identity,
            directory_chain,
            link_count,
            mode: final_stat.st_mode,
            owner_uid: final_stat.st_uid,
            owner_gid: final_stat.st_gid,
            mount_id,
            signature: signature_from_stat(&final_stat),
        })
    }

    fn signature_from_stat(metadata: &libc::stat) -> LinuxFileSignature {
        LinuxFileSignature {
            identity: identity_from_stat(metadata),
            link_count: metadata.st_nlink as u64,
            mode: metadata.st_mode,
            size: metadata.st_size,
            mtime_sec: metadata.st_mtime,
            mtime_nsec: metadata.st_mtime_nsec,
            ctime_sec: metadata.st_ctime,
            ctime_nsec: metadata.st_ctime_nsec,
        }
    }

    fn mount_id_for_fd(fd: RawFd) -> Result<u64, SandboxError> {
        let mut buffer = [0_u64; 32];
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd,
                c"".as_ptr(),
                AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
                STATX_BASIC_STATS | STATX_MNT_ID,
                buffer.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(SandboxError::Io {
                operation: "inspect pinned sandbox mount identity",
                source: io::Error::last_os_error(),
            });
        }
        let bytes = buffer.as_ptr().cast::<u8>();
        let mask = unsafe { std::ptr::read_unaligned(bytes.cast::<u32>()) };
        if mask & STATX_MNT_ID == 0 {
            return Err(SandboxError::InvalidPolicy(
                "kernel does not report mount identities for sandbox paths".into(),
            ));
        }
        Ok(unsafe { std::ptr::read_unaligned(bytes.add(144).cast::<u64>()) })
    }

    fn stat_fd(fd: RawFd) -> Result<libc::stat, SandboxError> {
        let mut metadata: libc::stat = unsafe { zeroed() };
        if unsafe { libc::fstat(fd, &mut metadata) } == 0 {
            Ok(metadata)
        } else {
            Err(SandboxError::Io {
                operation: "inspect pinned sandbox path",
                source: io::Error::last_os_error(),
            })
        }
    }

    fn identity_from_stat(metadata: &libc::stat) -> FileIdentity {
        FileIdentity {
            device: metadata.st_dev as u64,
            inode: metadata.st_ino as u64,
        }
    }

    fn identity_from_fd(fd: RawFd) -> Result<FileIdentity, SandboxError> {
        Ok(identity_from_stat(&stat_fd(fd)?))
    }

    fn collect_tool_inventory(
        root: &PinnedPath,
        input: FileIdentity,
    ) -> Result<PinnedToolInventory, SandboxError> {
        let mut directories = vec![PinnedToolDirectory {
            fd: duplicate_fd(root.fd.as_raw_fd())?,
            relative_path: PathBuf::new(),
            evidence: ToolEntryEvidence {
                identity: root.identity,
                link_count: root.link_count,
                mount_id: root.mount_id,
            },
            signature: root.signature,
        }];
        let mut entries = Vec::new();
        let mut snapshot = BTreeMap::new();
        let mut visited_directories = HashSet::from([root.identity]);
        let mut entry_count = 0_usize;
        let mut cursor = 0_usize;

        while cursor < directories.len() {
            let directory_fd = directories[cursor].fd.as_raw_fd();
            let relative_directory = directories[cursor].relative_path.clone();
            let depth = relative_directory.components().count();
            let directory_path = format!("/proc/self/fd/{directory_fd}");
            let listed = fs::read_dir(directory_path).map_err(|source| SandboxError::Io {
                operation: "inspect pinned trusted tool directory",
                source,
            })?;
            for item in listed {
                let item = item.map_err(|source| SandboxError::Io {
                    operation: "read trusted tool inventory entry",
                    source,
                })?;
                entry_count += 1;
                if entry_count > MAX_TOOL_INVENTORY_ENTRIES {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "trusted tool inventory exceeds {MAX_TOOL_INVENTORY_ENTRIES} entries"
                    )));
                }
                let entry_name = item.file_name();
                let name = CString::new(entry_name.as_bytes()).map_err(|_| {
                    SandboxError::InvalidPolicy(
                        "trusted tool inventory contains an invalid name".into(),
                    )
                })?;
                let raw = unsafe {
                    libc::openat(
                        directory_fd,
                        name.as_ptr(),
                        libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    )
                };
                if raw < 0 {
                    return Err(SandboxError::Io {
                        operation: "pin trusted tool inventory entry",
                        source: io::Error::last_os_error(),
                    });
                }
                let pinned = unsafe { OwnedFd::from_raw_fd(raw) };
                let metadata = stat_fd(pinned.as_raw_fd())?;
                let signature = signature_from_stat(&metadata);
                let identity = signature.identity;
                let mode = metadata.st_mode & libc::S_IFMT;
                let mount_id = mount_id_for_fd(pinned.as_raw_fd())?;
                if mount_id != root.mount_id {
                    return Err(SandboxError::InvalidPolicy(
                        "trusted tool inventory must not cross nested mounts".into(),
                    ));
                }
                let evidence = ToolEntryEvidence {
                    identity,
                    link_count: signature.link_count,
                    mount_id,
                };
                let relative_path = relative_directory.join(&entry_name);
                if snapshot
                    .insert(relative_path.clone(), evidence.clone())
                    .is_some()
                {
                    return Err(SandboxError::InvalidPolicy(
                        "trusted tool inventory contains a duplicate path".into(),
                    ));
                }
                entries.push(PinnedToolEntry {
                    parent: cursor,
                    name,
                    evidence: evidence.clone(),
                    signature,
                });
                match mode {
                    libc::S_IFREG | libc::S_IFLNK => {
                        if mode == libc::S_IFREG && identity == input {
                            return Err(SandboxError::InvalidPolicy(
                                "input aliases a file in the trusted tool inventory".into(),
                            ));
                        }
                    }
                    libc::S_IFDIR => {
                        if depth + 1 > MAX_TOOL_INVENTORY_DEPTH {
                            return Err(SandboxError::InvalidPolicy(format!(
                                "trusted tool inventory exceeds depth {MAX_TOOL_INVENTORY_DEPTH}"
                            )));
                        }
                        if directories.len() >= MAX_TOOL_INVENTORY_DIRECTORIES {
                            return Err(SandboxError::InvalidPolicy(format!(
                                "trusted tool inventory exceeds {MAX_TOOL_INVENTORY_DIRECTORIES} directories"
                            )));
                        }
                        if !visited_directories.insert(identity) {
                            return Err(SandboxError::InvalidPolicy(
                                "trusted tool inventory contains an aliased directory".into(),
                            ));
                        }
                        directories.push(PinnedToolDirectory {
                            fd: pinned,
                            relative_path,
                            evidence,
                            signature,
                        });
                    }
                    _ => {
                        return Err(SandboxError::InvalidPolicy(
                            "trusted tool inventory contains a special file".into(),
                        ));
                    }
                }
            }
            cursor += 1;
        }
        let snapshot = ToolInventory { entries: snapshot };
        validate_tool_inventory(input, &snapshot, &snapshot)
            .map_err(|reason| SandboxError::InvalidPolicy(reason.into()))?;
        Ok(PinnedToolInventory {
            snapshot,
            directories,
            entries,
        })
    }

    fn open_task_reader(task: &PinnedPath) -> Result<OwnedFd, SandboxError> {
        let fd = unsafe {
            libc::openat(
                task.fd.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(SandboxError::Io {
                operation: "open task directory for bounded empty check",
                source: io::Error::last_os_error(),
            });
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        if owned.as_raw_fd() < 3 {
            duplicate_fd(owned.as_raw_fd())
        } else {
            Ok(owned)
        }
    }

    fn task_directory_is_empty(
        fd: RawFd,
        task: &PinnedPath,
        expected_owner_uid: u32,
        expected_owner_gid: u32,
    ) -> Result<bool, SandboxError> {
        let result = unsafe {
            task_directory_is_empty_raw(fd, task, expected_owner_uid, expected_owner_gid)
        };
        match result {
            1 => Ok(true),
            0 => Ok(false),
            _ if io::Error::last_os_error().raw_os_error() == Some(libc::ESTALE) => Ok(false),
            _ => Err(SandboxError::Io {
                operation: "verify task directory is empty",
                source: io::Error::last_os_error(),
            }),
        }
    }

    unsafe fn task_directory_is_empty_raw(
        fd: RawFd,
        task: &PinnedPath,
        expected_owner_uid: u32,
        expected_owner_gid: u32,
    ) -> i32 {
        let mut metadata: libc::stat = zeroed();
        if libc::fstat(fd, &mut metadata) != 0 {
            return -1;
        }
        let actual = signature_from_stat(&metadata);
        let actual_snapshot = TaskDirectorySnapshot {
            identity: actual.identity,
            owner_uid: metadata.st_uid,
            owner_gid: metadata.st_gid,
            mode: metadata.st_mode,
            link_count: metadata.st_nlink as u64,
            mount_id: task.mount_id,
        };
        if actual.identity != task.signature.identity
            || actual.link_count != task.signature.link_count
            || actual.mode != task.signature.mode
            || actual.size != task.signature.size
            || actual.mtime_sec != task.signature.mtime_sec
            || actual.mtime_nsec != task.signature.mtime_nsec
            || actual.ctime_sec != task.signature.ctime_sec
            || actual.ctime_nsec != task.signature.ctime_nsec
            || (expected_owner_uid != task.owner_uid && expected_owner_uid != 0)
            || (expected_owner_gid != task.owner_gid && expected_owner_gid != 0)
            || validate_private_task_snapshot(
                &actual_snapshot,
                task.identity,
                task.mount_id,
                expected_owner_uid,
                expected_owner_gid,
                0,
            )
            .is_err()
            || mount_id_matches(fd, task.mount_id) != 0
        {
            *libc::__errno_location() = libc::ESTALE;
            return -1;
        }
        if libc::lseek(fd, 0, libc::SEEK_SET) < 0 {
            return -1;
        }
        let mut buffer = [0_u8; 4096];
        loop {
            let count = libc::syscall(libc::SYS_getdents64, fd, buffer.as_mut_ptr(), buffer.len());
            if count < 0 {
                if errno() == libc::EINTR {
                    continue;
                }
                return -1;
            }
            if count == 0 {
                return 1;
            }
            let count = count as usize;
            let mut offset = 0_usize;
            while offset < count {
                if count - offset < 19 {
                    *libc::__errno_location() = libc::EIO;
                    return -1;
                }
                let record_size =
                    std::ptr::read_unaligned(buffer.as_ptr().add(offset + 16).cast::<u16>())
                        as usize;
                if record_size < 19 || record_size > count - offset {
                    *libc::__errno_location() = libc::EIO;
                    return -1;
                }
                let name = std::ffi::CStr::from_ptr(
                    buffer.as_ptr().add(offset + 19).cast::<libc::c_char>(),
                )
                .to_bytes();
                if name != b"." && name != b".." {
                    return 0;
                }
                offset += record_size;
            }
        }
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

    fn build_policy_fd_list(
        input_fd: RawFd,
        task_fd: RawFd,
        task_read_fd: RawFd,
        tool_fd: RawFd,
        program_fd: RawFd,
        inventory: &PinnedToolInventory,
        placement: &PlacementFds,
        report_fd: RawFd,
        parent_ack_fd: RawFd,
    ) -> Vec<RawFd> {
        let mut fds = Vec::with_capacity(inventory.directories.len() + 11);
        fds.extend([
            input_fd,
            task_fd,
            task_read_fd,
            tool_fd,
            program_fd,
            report_fd,
            parent_ack_fd,
        ]);
        fds.extend(
            inventory
                .directories
                .iter()
                .map(|directory| directory.fd.as_raw_fd()),
        );
        fds.extend(
            [placement.cgroup, placement.ready, placement.release]
                .into_iter()
                .flatten(),
        );
        fds
    }

    unsafe fn mount_id_matches(fd: RawFd, expected: u64) -> i32 {
        let mut buffer = [0_u64; 32];
        if libc::syscall(
            libc::SYS_statx,
            fd,
            c"".as_ptr(),
            AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW,
            STATX_BASIC_STATS | STATX_MNT_ID,
            buffer.as_mut_ptr(),
        ) != 0
        {
            return -1;
        }
        let bytes = buffer.as_ptr().cast::<u8>();
        let mask = std::ptr::read_unaligned(bytes.cast::<u32>());
        if mask & STATX_MNT_ID == 0 {
            *libc::__errno_location() = libc::EOPNOTSUPP;
            return -1;
        }
        let actual = std::ptr::read_unaligned(bytes.add(144).cast::<u64>());
        if actual != expected {
            *libc::__errno_location() = libc::ESTALE;
            return -1;
        }
        0
    }

    unsafe fn revalidate_pinned_path(path: &PinnedPath, expected_type: libc::mode_t) -> i32 {
        let mut metadata: libc::stat = zeroed();
        if libc::fstat(path.fd.as_raw_fd(), &mut metadata) != 0 {
            return -1;
        }
        if signature_from_stat(&metadata) != path.signature
            || metadata.st_mode & libc::S_IFMT != expected_type
            || mount_id_matches(path.fd.as_raw_fd(), path.mount_id) != 0
        {
            *libc::__errno_location() = libc::ESTALE;
            return -1;
        }
        0
    }

    unsafe fn mounted_object_matches(
        path: &std::ffi::CStr,
        expected: FileIdentity,
        expected_type: libc::mode_t,
    ) -> i32 {
        let mut metadata: libc::stat = zeroed();
        if libc::stat(path.as_ptr(), &mut metadata) != 0 {
            return -1;
        }
        if identity_from_stat(&metadata) != expected
            || metadata.st_mode & libc::S_IFMT != expected_type
        {
            *libc::__errno_location() = libc::ESTALE;
            return -1;
        }
        0
    }

    unsafe fn revalidate_tool_inventory(
        inventory: &PinnedToolInventory,
        input: FileIdentity,
    ) -> i32 {
        for directory in &inventory.directories {
            if revalidate_tool_directory(directory) != 0 {
                return -1;
            }
        }
        for entry in &inventory.entries {
            let parent = inventory.directories[entry.parent].fd.as_raw_fd();
            let fd = libc::openat(
                parent,
                entry.name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            );
            if fd < 0 {
                return -1;
            }
            let mut metadata: libc::stat = zeroed();
            if libc::fstat(fd, &mut metadata) != 0 {
                let saved_errno = errno();
                libc::close(fd);
                *libc::__errno_location() = saved_errno;
                return -1;
            }
            if signature_from_stat(&metadata) != entry.signature
                || identity_from_stat(&metadata) != entry.evidence.identity
                || metadata.st_nlink as u64 != entry.evidence.link_count
                || (metadata.st_mode & libc::S_IFMT == libc::S_IFREG
                    && identity_from_stat(&metadata) == input)
            {
                libc::close(fd);
                *libc::__errno_location() = libc::ESTALE;
                return -1;
            }
            if mount_id_matches(fd, entry.evidence.mount_id) != 0 {
                let saved_errno = errno();
                libc::close(fd);
                *libc::__errno_location() = saved_errno;
                return -1;
            }
            libc::close(fd);
        }
        for directory in &inventory.directories {
            if revalidate_tool_directory(directory) != 0 {
                return -1;
            }
        }
        0
    }

    unsafe fn revalidate_tool_directory(directory: &PinnedToolDirectory) -> i32 {
        let mut metadata: libc::stat = zeroed();
        if libc::fstat(directory.fd.as_raw_fd(), &mut metadata) != 0 {
            return -1;
        }
        if signature_from_stat(&metadata) != directory.signature
            || identity_from_stat(&metadata) != directory.evidence.identity
            || metadata.st_nlink as u64 != directory.evidence.link_count
            || mount_id_matches(directory.fd.as_raw_fd(), directory.evidence.mount_id) != 0
        {
            *libc::__errno_location() = libc::ESTALE;
            return -1;
        }
        0
    }

    unsafe fn revalidate_policy_before_release(spec: &PreparedSpawn<'_>) -> i32 {
        if revalidate_pinned_path(spec.input, libc::S_IFREG) != 0 {
            return -1;
        }
        if revalidate_pinned_path(spec.task, libc::S_IFDIR) != 0 {
            return -1;
        }
        match task_directory_is_empty_raw(spec.task_read_fd, spec.task, 0, 0) {
            1 => {}
            0 => {
                *libc::__errno_location() = libc::ESTALE;
                return -1;
            }
            _ => return -1,
        }
        if revalidate_pinned_path(spec.tool, libc::S_IFDIR) != 0 {
            return -1;
        }
        if revalidate_tool_inventory(spec.tool_inventory, spec.input.identity) != 0 {
            return -1;
        }
        if mounted_object_matches(c"/input", spec.input.identity, libc::S_IFREG) != 0
            || mounted_object_matches(c"/task", spec.task.identity, libc::S_IFDIR) != 0
            || mounted_object_matches(c"/tool", spec.tool.identity, libc::S_IFDIR) != 0
        {
            return -1;
        }
        0
    }

    unsafe fn sandbox_supervisor(spec: &PreparedSpawn<'_>) -> ! {
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

        if close_range_except(&spec.policy_fds) != 0 {
            fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, errno());
        }

        if let Err(result) = enter_user_namespace_from_maps(&spec.uid_map, &spec.gid_map) {
            fail_and_exit(spec.report_fd, result.operation, result.errno);
        }
        if libc::unshare(libc::CLONE_NEWNS) != 0 {
            fail_and_exit(spec.report_fd, STAGE_MOUNTNS, errno());
        }
        if libc::unshare(libc::CLONE_NEWPID) != 0 {
            fail_and_exit(spec.report_fd, STAGE_MOUNTNS, errno());
        }
        if libc::unshare(libc::CLONE_NEWNET) != 0 {
            fail_and_exit(spec.report_fd, STAGE_NETWORK_NAMESPACE, errno());
        }
        let network_namespace = match network_namespace_identity() {
            Ok(identity) => identity,
            Err(error) => fail_and_exit(
                spec.report_fd,
                STAGE_NETWORK_NAMESPACE,
                error.raw_os_error().unwrap_or(libc::EIO),
            ),
        };
        if !network_namespace_is_private(spec.host_network_namespace, Some(network_namespace)) {
            fail_and_exit(spec.report_fd, STAGE_NETWORK_NAMESPACE, libc::ESTALE);
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
        if revalidate_pinned_path(spec.input, libc::S_IFREG) != 0
            || mount_bind(&spec.input_source, &spec.root.input) != 0
        {
            fail_and_exit(spec.report_fd, STAGE_BIND_INPUT, errno());
        }
        if remount_read_only(&spec.root.input, true) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_RO, errno());
        }
        if revalidate_pinned_path(spec.tool, libc::S_IFDIR) != 0
            || revalidate_tool_inventory(spec.tool_inventory, spec.input.identity) != 0
            || mount_bind(&spec.tool_source, &spec.root.tool) != 0
        {
            fail_and_exit(spec.report_fd, STAGE_BIND_TOOL, errno());
        }
        if remount_read_only(&spec.root.tool, false) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_RO, errno());
        }
        if revalidate_pinned_path(spec.task, libc::S_IFDIR) != 0
            || task_directory_is_empty_raw(spec.task_read_fd, spec.task, 0, 0) != 1
            || mount_bind(&spec.task_source, &spec.root.task) != 0
        {
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

        if revalidate_policy_before_release(spec) != 0 {
            fail_and_exit(spec.report_fd, STAGE_BIND_TASK, errno());
        }

        if send_message(
            spec.report_fd,
            Message {
                kind: MSG_NAMESPACE_ATTESTATION,
                operation: PROBE_OK,
                errno: 0,
                pid: libc::getpid(),
                network_namespace_device: network_namespace.device,
                network_namespace_inode: network_namespace.inode,
            },
        )
        .is_err()
        {
            libc::close(spec.parent_ack_fd);
            libc::close(spec.report_fd);
            libc::_exit(125);
        }

        let acknowledgment = super::after_parent_ack(
            || read_parent_ack(spec.parent_ack_fd),
            || {
                libc::close(spec.parent_ack_fd);
                match (spec.placement.ready, spec.placement.release) {
                    (Some(ready), Some(release)) => {
                        if close_range_except(&spec.policy_fds) != 0 {
                            fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, errno());
                        }
                        let pid = libc::getpid();
                        if let Err(error) = write_all(ready, &pid.to_ne_bytes()) {
                            fail_and_exit(
                                spec.report_fd,
                                STAGE_READY_WRITE,
                                error.raw_os_error().unwrap_or(libc::EIO),
                            );
                        }
                        if send_message(
                            spec.report_fd,
                            Message {
                                kind: MSG_READY,
                                operation: PROBE_OK,
                                errno: 0,
                                pid,
                                network_namespace_device: network_namespace.device,
                                network_namespace_inode: network_namespace.inode,
                            },
                        )
                        .is_err()
                        {
                            libc::close(ready);
                            libc::close(release);
                            libc::close(spec.report_fd);
                            libc::_exit(125);
                        }
                        let mut release_byte = 0_u8;
                        if read_one(release, &mut release_byte) != 1 || release_byte != 1 {
                            fail_and_exit(spec.report_fd, STAGE_RELEASE_READ, errno());
                        }
                        libc::close(ready);
                        libc::close(release);
                        libc::close(spec.report_fd);
                        if revalidate_policy_before_release(spec) != 0 {
                            libc::_exit(125);
                        }
                        if close_range_except(&[spec.program_fd]) != 0 {
                            libc::_exit(125);
                        }
                        let child = libc::fork();
                        if child < 0 {
                            libc::_exit(127);
                        }
                        if child == 0 {
                            if install_seccomp(&spec.seccomp) != 0 {
                                libc::_exit(127);
                            }
                            exec_pinned(
                                spec.program_fd,
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
                        if close_range_except(&spec.policy_fds) != 0 {
                            fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, errno());
                        }
                        let flags = libc::fcntl(cgroup_fd, libc::F_GETFD);
                        if flags < 0
                            || libc::fcntl(cgroup_fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0
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
                        let child = libc::syscall(libc::SYS_clone3, &args, size_of::<CloneArgs>())
                            as libc::pid_t;
                        if child < 0 {
                            fail_and_exit(spec.report_fd, STAGE_CLONE3, errno());
                        }
                        if child == 0 {
                            if revalidate_policy_before_release(spec) != 0
                                || close_range_except(&[spec.program_fd]) != 0
                            {
                                libc::_exit(125);
                            }
                            if install_seccomp(&spec.seccomp) != 0 {
                                libc::_exit(127);
                            }
                            exec_pinned(
                                spec.program_fd,
                                spec.argv.as_ptr().cast(),
                                spec.envp.as_ptr().cast(),
                            );
                            libc::_exit(127);
                        }
                        if send_message(
                            spec.report_fd,
                            Message {
                                kind: MSG_READY,
                                operation: PROBE_OK,
                                errno: 0,
                                pid: libc::getpid(),
                                network_namespace_device: network_namespace.device,
                                network_namespace_inode: network_namespace.inode,
                            },
                        )
                        .is_err()
                        {
                            libc::close(cgroup_fd);
                            libc::close(spec.report_fd);
                            libc::_exit(125);
                        }
                        libc::close(cgroup_fd);
                        libc::close(spec.report_fd);
                        wait_target_or_exit(child);
                    }
                    _ => fail_and_exit(spec.report_fd, STAGE_FD_CLOSE, libc::EINVAL),
                }
            },
        );
        if let Err(error) = acknowledgment {
            fail_and_exit(
                spec.report_fd,
                STAGE_PARENT_ACK,
                error.raw_os_error().unwrap_or(libc::EPROTO),
            );
        }
        libc::_exit(125)
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

    fn build_sandbox_filter(allow_session_escape: bool) -> Vec<libc::sock_filter> {
        let mut setup_denied = vec![
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
            libc::SYS_io_uring_setup as u32,
        ];
        if !allow_session_escape {
            setup_denied.push(libc::SYS_setsid as u32);
        }
        let network_policy = NetworkPolicy::default();
        let socket_filter_len = 1
            + 2 * network_policy.denied_socket_domains.len()
            + 2 * network_policy.allowed_socket_domains.len()
            + 1;
        let mut filter = Vec::with_capacity(
            3 + (setup_denied.len() + network_policy.denied_syscalls.len()) * 2
                + socket_filter_len
                + 5,
        );
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
        for syscall_number in setup_denied {
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
        for syscall in network_policy.denied_syscalls {
            filter.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                network_syscall_number(syscall),
                0,
                1,
            ));
            filter.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            ));
        }
        filter.push(bpf_jump(
            libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
            libc::SYS_socket as u32,
            0,
            socket_filter_len as u8,
        ));
        filter.push(bpf_stmt(
            libc::BPF_LD | libc::BPF_W | libc::BPF_ABS,
            SECCOMP_DATA_ARGS_OFFSET,
        ));
        for domain in network_policy.denied_socket_domains {
            filter.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                socket_domain_number(domain),
                0,
                1,
            ));
            filter.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
            ));
        }
        for domain in network_policy.allowed_socket_domains {
            filter.push(bpf_jump(
                libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K,
                socket_domain_number(domain),
                0,
                1,
            ));
            filter.push(bpf_stmt(
                libc::BPF_RET | libc::BPF_K,
                libc::SECCOMP_RET_ALLOW,
            ));
        }
        filter.push(bpf_stmt(
            libc::BPF_RET | libc::BPF_K,
            libc::SECCOMP_RET_ERRNO | libc::EACCES as u32,
        ));
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

    fn socket_domain_number(domain: NetworkSocketDomain) -> u32 {
        match domain {
            NetworkSocketDomain::Unix => libc::AF_UNIX as u32,
            NetworkSocketDomain::Ipv4 => libc::AF_INET as u32,
            NetworkSocketDomain::Ipv6 => libc::AF_INET6 as u32,
            NetworkSocketDomain::Packet => libc::AF_PACKET as u32,
        }
    }

    fn network_syscall_number(syscall: NetworkSyscall) -> u32 {
        match syscall {
            NetworkSyscall::Connect => libc::SYS_connect as u32,
            NetworkSyscall::SocketPair => libc::SYS_socketpair as u32,
            NetworkSyscall::Bpf => libc::SYS_bpf as u32,
            NetworkSyscall::Userfaultfd => libc::SYS_userfaultfd as u32,
        }
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
            super::seccomp_audit_arch(super::SeccompArchitecture::X86_64)
                .expect("x86_64 seccomp architecture is supported")
        }
        #[cfg(target_arch = "aarch64")]
        {
            super::seccomp_audit_arch(super::SeccompArchitecture::Aarch64)
                .expect("aarch64 seccomp architecture is supported")
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

    unsafe fn exec_pinned(
        fd: RawFd,
        argv: *const *const libc::c_char,
        envp: *const *const libc::c_char,
    ) -> i64 {
        libc::syscall(
            libc::SYS_execveat,
            fd,
            c"".as_ptr(),
            argv,
            envp,
            AT_EMPTY_PATH,
        ) as i64
    }

    unsafe fn close_range_except(keep: &[RawFd]) -> i32 {
        let mut kept = [0_i32; MAX_TOOL_INVENTORY_DIRECTORIES + 16];
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

    unsafe fn write_struct<T>(fd: RawFd, value: &T) -> io::Result<()> {
        let bytes = std::slice::from_raw_parts((value as *const T).cast::<u8>(), size_of::<T>());
        write_all(fd, bytes)
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

    fn read_struct_until<T: Copy>(
        fd: RawFd,
        reader: &mut std::fs::File,
        value: &mut T,
        deadline: Instant,
    ) -> io::Result<()> {
        let mut bytes = unsafe {
            std::slice::from_raw_parts_mut((value as *mut T).cast::<u8>(), size_of::<T>())
        };
        while !bytes.is_empty() {
            poll_readable_until(fd, deadline)?;
            match std::io::Read::read(reader, bytes) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "report pipe closed",
                    ));
                }
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn poll_readable_until(fd: RawFd, deadline: Instant) -> io::Result<()> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "active probe report deadline expired",
                ));
            }
            let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let ready = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
            if ready > 0
                && descriptor.revents
                    & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)
                    != 0
            {
                return Ok(());
            }
            if ready < 0 {
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
        }
    }

    fn create_pipe_above_stdio() -> io::Result<[RawFd; 2]> {
        let mut pipe = [0; 2];
        if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
        for index in 0..pipe.len() {
            if pipe[index] < 3 {
                let duplicate = unsafe { libc::fcntl(pipe[index], libc::F_DUPFD_CLOEXEC, 3) };
                if duplicate < 0 {
                    let error = io::Error::last_os_error();
                    unsafe {
                        libc::close(pipe[0]);
                        libc::close(pipe[1]);
                    }
                    return Err(error);
                }
                unsafe { libc::close(pipe[index]) };
                pipe[index] = duplicate;
            }
        }
        Ok(pipe)
    }

    unsafe fn send_message(fd: RawFd, message: Message) -> io::Result<()> {
        write_struct(fd, &message)
    }

    unsafe fn write_all(fd: RawFd, bytes: &[u8]) -> io::Result<()> {
        super::write_all_with(bytes, |remaining| {
            let count = libc::write(fd, remaining.as_ptr().cast(), remaining.len());
            if count < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(count as usize)
            }
        })
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

    fn read_parent_ack(fd: RawFd) -> io::Result<Option<u8>> {
        let mut value = 0_u8;
        match unsafe { read_one(fd, &mut value) } {
            0 => Ok(None),
            1 => Ok(Some(value)),
            _ => Err(io::Error::last_os_error()),
        }
    }

    fn write_parent_ack(fd: RawFd) -> io::Result<()> {
        unsafe { write_all(fd, &[1]) }
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
        if send_message(
            report_fd,
            Message {
                kind: MSG_ERROR,
                operation,
                errno: error,
                pid: libc::getpid(),
                network_namespace_device: 0,
                network_namespace_inode: 0,
            },
        )
        .is_err()
        {
            libc::close(report_fd);
        }
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
            STAGE_SECCOMP => "filesystem and network seccomp policy",
            STAGE_NETWORK_NAMESPACE => "private network namespace creation",
            STAGE_NETWORK_SOCKET => "network socket seccomp policy",
            STAGE_NETWORK_SYSCALL => "network escape syscall policy",
            STAGE_PARENT_ACK => "parent network namespace acknowledgment",
            STAGE_NETWORK_UNIX_SOCKET => "Unix socket host-path isolation",
            STAGE_NETWORK_ESCAPE => "network namespace escape denial",
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

    #[cfg(test)]
    mod race_tests {
        use super::*;
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{Duration, Instant};

        #[test]
        fn stalled_active_probe_report_read_is_bounded_and_child_is_reaped() {
            let mut pipe = [0; 2];
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork stalled probe child");
            if pid == 0 {
                unsafe {
                    libc::close(pipe[0]);
                    loop {
                        libc::pause();
                    }
                }
            }

            unsafe { libc::close(pipe[1]) };
            let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
            let mut result = ProbeResult {
                operation: STAGE_FORK,
                errno: libc::ECHILD,
            };
            let fd = reader.as_raw_fd();
            let (sender, receiver) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let outcome = read_struct_until(
                    fd,
                    &mut reader,
                    &mut result,
                    Instant::now() + Duration::from_millis(100),
                )
                .map(|()| result);
                let _ = sender.send(outcome);
            });
            let timed_out = match receiver.recv_timeout(Duration::from_secs(5)) {
                Ok(Err(error)) => error.kind() == io::ErrorKind::TimedOut,
                Ok(Ok(_)) => false,
                Err(_) => {
                    abort_probe(pid);
                    let _ = receiver.recv_timeout(Duration::from_secs(5));
                    let _ = worker.join();
                    assert_probe_child_reaped(pid);
                    panic!("report read exceeded the parent-side watchdog");
                }
            };
            worker.join().expect("join bounded report reader");

            abort_probe(pid);
            assert_probe_child_reaped(pid);
            assert!(timed_out, "a probe child which never reports must time out");
        }

        #[test]
        fn stalled_active_probe_exit_wait_is_bounded_and_child_is_reaped() {
            let mut pipe = [0; 2];
            assert_eq!(
                unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork stalled probe child");
            if pid == 0 {
                unsafe {
                    libc::close(pipe[0]);
                    let result = ProbeResult {
                        operation: PROBE_OK,
                        errno: 0,
                    };
                    let bytes = std::slice::from_raw_parts(
                        (&result as *const ProbeResult).cast::<u8>(),
                        size_of::<ProbeResult>(),
                    );
                    libc::write(pipe[1], bytes.as_ptr().cast(), bytes.len());
                    loop {
                        libc::pause();
                    }
                }
            }

            unsafe { libc::close(pipe[1]) };
            let mut reader = unsafe { std::fs::File::from_raw_fd(pipe[0]) };
            let mut result = ProbeResult {
                operation: STAGE_FORK,
                errno: libc::ECHILD,
            };
            let deadline = Instant::now() + Duration::from_millis(100);
            read_struct_until(reader.as_raw_fd(), &mut reader, &mut result, deadline)
                .expect("read the completed probe report");
            assert_eq!(result.operation, PROBE_OK);
            let (sender, receiver) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                let _ = sender.send(reap_probe_until(pid, deadline));
            });
            let timed_out = match receiver.recv_timeout(Duration::from_secs(5)) {
                Ok(Err(error)) => error.kind() == io::ErrorKind::TimedOut,
                Ok(Ok(_)) => false,
                Err(_) => {
                    abort_probe(pid);
                    let _ = receiver.recv_timeout(Duration::from_secs(5));
                    let _ = worker.join();
                    assert_probe_child_reaped(pid);
                    panic!("probe exit wait exceeded the parent-side watchdog");
                }
            };
            worker.join().expect("join bounded probe waiter");

            abort_probe(pid);
            assert_probe_child_reaped(pid);
            assert!(timed_out, "a probe child which does not exit must time out");
        }

        #[test]
        fn quick_active_probe_exit_is_reaped_without_waiting_for_full_deadline() {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork quick-exit probe child");
            if pid == 0 {
                unsafe { libc::_exit(0) };
            }

            let started = Instant::now();
            let status = reap_probe_until(pid, started + Duration::from_secs(2))
                .expect("reap quick-exit probe");

            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0);
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "quick child reap consumed the remaining probe deadline: {:?}",
                started.elapsed()
            );
        }

        fn assert_probe_child_reaped(pid: libc::pid_t) {
            let mut status = 0;
            assert_eq!(
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
                -1
            );
            assert_eq!(errno(), libc::ECHILD);
        }

        #[test]
        fn tool_entry_replacement_between_prepare_and_bind_fails_closed() {
            let root = tempfile::tempdir().expect("fixture root");
            let tool_path = root.path().join("tool");
            fs::create_dir(&tool_path).expect("tool directory");
            let executable_path = tool_path.join("tool-bin");
            fs::write(&executable_path, b"approved executable bytes").expect("tool file");
            let input_path = root.path().join("input");
            fs::write(&input_path, b"input").expect("input file");

            let input = open_pinned_path(&input_path, false, "input").expect("pin input");
            let tool = open_pinned_path(&tool_path, true, "tool directory").expect("pin tool");
            let inventory = collect_tool_inventory(&tool, input.identity).expect("inventory");
            assert_eq!(
                unsafe { revalidate_tool_inventory(&inventory, input.identity) },
                0
            );

            fs::rename(&executable_path, tool_path.join("approved-old"))
                .expect("rename approved executable");
            fs::write(&executable_path, b"replacement executable bytes")
                .expect("install replacement executable");

            assert_ne!(
                unsafe { revalidate_tool_inventory(&inventory, input.identity) },
                0,
                "replacement must not pass the pre-bind revalidation"
            );
        }

        #[test]
        fn input_hard_link_insertion_between_prepare_and_bind_fails_closed() {
            let root = tempfile::tempdir().expect("fixture root");
            let tool_path = root.path().join("tool");
            fs::create_dir(&tool_path).expect("tool directory");
            fs::write(tool_path.join("trusted-tool"), b"tool").expect("tool file");
            let input_path = root.path().join("input");
            fs::write(&input_path, b"input").expect("input file");

            let input = open_pinned_path(&input_path, false, "input").expect("pin input");
            let tool = open_pinned_path(&tool_path, true, "tool directory").expect("pin tool");
            let inventory = collect_tool_inventory(&tool, input.identity).expect("inventory");
            fs::hard_link(&input_path, tool_path.join("input-alias")).expect("insert hard link");

            assert_ne!(
                unsafe { revalidate_pinned_path(&input, libc::S_IFREG) },
                0,
                "changed input link count must be noticed"
            );
            assert_ne!(
                unsafe { revalidate_tool_inventory(&inventory, input.identity) },
                0,
                "tool inventory mutation must be noticed"
            );
        }

        #[test]
        fn task_directory_must_stay_empty_until_release() {
            let root = tempfile::tempdir().expect("fixture root");
            let task_path = root.path().join("task");
            fs::create_dir(&task_path).expect("task directory");
            fs::set_permissions(&task_path, fs::Permissions::from_mode(0o700))
                .expect("make task directory private");
            let task = open_pinned_path(&task_path, true, "task directory").expect("pin task");
            let reader = open_task_reader(&task).expect("open task reader");
            assert!(
                task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("empty check")
            );

            fs::write(task_path.join("raced-file"), b"untrusted").expect("mutate task directory");
            assert!(
                !task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("recheck")
            );
        }

        #[test]
        fn task_directory_rejects_group_or_world_access_modes() {
            for mode in [0o777, 0o770] {
                let root = tempfile::tempdir().expect("fixture root");
                let task_path = root.path().join("task");
                fs::create_dir(&task_path).expect("task directory");
                fs::set_permissions(&task_path, fs::Permissions::from_mode(mode))
                    .expect("set insecure task mode");
                let task = open_pinned_path(&task_path, true, "task directory").expect("pin task");
                let reader = open_task_reader(&task).expect("open task reader");

                assert!(
                    !task_directory_is_empty(
                        reader.as_raw_fd(),
                        &task,
                        unsafe { libc::geteuid() },
                        unsafe { libc::getegid() },
                    )
                    .expect("inspect insecure directory"),
                    "mode {mode:o} must fail the private task-directory precondition"
                );
            }
        }

        #[test]
        fn task_directory_mode_change_after_readiness_fails_revalidation() {
            let root = tempfile::tempdir().expect("fixture root");
            let task_path = root.path().join("task");
            fs::create_dir(&task_path).expect("task directory");
            fs::set_permissions(&task_path, fs::Permissions::from_mode(0o700))
                .expect("make task directory private");
            let task = open_pinned_path(&task_path, true, "task directory").expect("pin task");
            let reader = open_task_reader(&task).expect("open task reader");
            assert!(
                task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("initial check")
            );

            fs::set_permissions(&task_path, fs::Permissions::from_mode(0o770))
                .expect("loosen task mode after readiness");
            assert!(
                !task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("revalidate changed task directory"),
                "chmod after readiness must fail closed"
            );
        }

        #[test]
        fn task_directory_subdirectory_insertion_changes_link_count_and_fails_revalidation() {
            let root = tempfile::tempdir().expect("fixture root");
            let task_path = root.path().join("task");
            fs::create_dir(&task_path).expect("task directory");
            fs::set_permissions(&task_path, fs::Permissions::from_mode(0o700))
                .expect("make task directory private");
            let task = open_pinned_path(&task_path, true, "task directory").expect("pin task");
            let reader = open_task_reader(&task).expect("open task reader");
            assert!(
                task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("initial check")
            );

            fs::create_dir(task_path.join("nested")).expect("insert task subdirectory");
            assert!(
                !task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("revalidate task directory"),
                "a nested directory must fail the nlink=2 private snapshot"
            );
        }

        #[test]
        fn task_directory_rejects_foreign_owner_when_chown_is_permitted() {
            let root = tempfile::tempdir().expect("fixture root");
            let task_path = root.path().join("task");
            fs::create_dir(&task_path).expect("task directory");
            fs::set_permissions(&task_path, fs::Permissions::from_mode(0o700))
                .expect("make task directory private");
            let foreign_uid = unsafe { libc::geteuid() }.wrapping_add(1);
            if unsafe { libc::chown(c_path(&task_path).unwrap().as_ptr(), foreign_uid, u32::MAX) }
                != 0
            {
                return;
            }
            let task = open_pinned_path(&task_path, true, "task directory").expect("pin task");
            let reader = open_task_reader(&task).expect("open task reader");

            assert!(
                !task_directory_is_empty(
                    reader.as_raw_fd(),
                    &task,
                    unsafe { libc::geteuid() },
                    unsafe { libc::getegid() },
                )
                .expect("inspect foreign-owned directory"),
                "a directory not owned by the current effective UID must fail closed"
            );
        }

        #[test]
        fn trusted_tool_inventory_has_a_small_fixed_limit() {
            let root = tempfile::tempdir().expect("fixture root");
            let tool_path = root.path().join("tool");
            fs::create_dir(&tool_path).expect("tool directory");
            let input_path = root.path().join("input");
            fs::write(&input_path, b"input").expect("input file");
            for index in 0..=MAX_TOOL_INVENTORY_ENTRIES {
                fs::write(tool_path.join(format!("entry-{index}")), b"tool").expect("tool entry");
            }
            let input = open_pinned_path(&input_path, false, "input").expect("pin input");
            let tool = open_pinned_path(&tool_path, true, "tool directory").expect("pin tool");
            assert!(matches!(
                collect_tool_inventory(&tool, input.identity),
                Err(SandboxError::InvalidPolicy(_))
            ));
        }

        #[test]
        fn execveat_uses_pinned_executable_after_policy_name_is_replaced() {
            let root = tempfile::tempdir().expect("fixture root");
            let tool_path = root.path().join("tool");
            fs::create_dir(&tool_path).expect("tool directory");
            let executable_path = tool_path.join("pinned-test");
            fs::copy(
                std::env::current_exe().expect("current test executable"),
                &executable_path,
            )
            .expect("copy test executable");
            fs::set_permissions(&executable_path, fs::Permissions::from_mode(0o700))
                .expect("make test executable runnable");
            let input_path = root.path().join("input");
            fs::write(&input_path, b"input").expect("input file");

            let input = open_pinned_path(&input_path, false, "input").expect("pin input");
            let tool = open_pinned_path(&tool_path, true, "tool directory").expect("pin tool");
            let inventory = collect_tool_inventory(&tool, input.identity).expect("inventory");
            let executable = open_pinned_path(&executable_path, false, "tool executable")
                .expect("pin executable");

            fs::rename(&executable_path, tool_path.join("approved-original"))
                .expect("rename approved executable");
            fs::write(&executable_path, b"not an executable").expect("replace policy name");
            assert_ne!(
                unsafe { revalidate_tool_inventory(&inventory, input.identity) },
                0,
                "the path inventory must fail after the name is replaced"
            );

            let argv = [
                CString::new("pinned-test").expect("argv zero"),
                CString::new("--list").expect("list argument"),
                CString::new("--format=terse").expect("format argument"),
            ];
            let argv_pointers = argv
                .iter()
                .map(|argument| argument.as_ptr())
                .chain(std::iter::once(std::ptr::null()))
                .collect::<Vec<_>>();
            let envp = [std::ptr::null::<libc::c_char>()];
            let child = unsafe { libc::fork() };
            assert!(child >= 0, "fork test process");
            if child == 0 {
                unsafe {
                    exec_pinned(
                        executable.fd.as_raw_fd(),
                        argv_pointers.as_ptr(),
                        envp.as_ptr(),
                    );
                    libc::_exit(127);
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
            assert!(
                libc::WIFEXITED(status),
                "pinned executable did not exit normally"
            );
            assert_eq!(
                libc::WEXITSTATUS(status),
                0,
                "pinned executable was not run"
            );
        }
    }
}

#[cfg(test)]
mod review_regression_tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::collections::HashSet;
    use std::io;

    fn identity(inode: u64) -> FileIdentity {
        FileIdentity { device: 7, inode }
    }

    fn disjoint_policy_graph() -> PolicyPathIdentityGraph {
        PolicyPathIdentityGraph {
            input: identity(10),
            input_parent_chain: vec![identity(11), identity(1)],
            task: identity(20),
            task_ancestors: vec![identity(20), identity(2), identity(1)],
            tool: identity(30),
            tool_ancestors: vec![identity(30), identity(3), identity(1)],
            task_files: HashSet::from([identity(21)]),
            tool_files: HashSet::from([identity(31)]),
        }
    }

    #[test]
    fn policy_identity_validation_rejects_directory_and_file_aliases() {
        let graph = disjoint_policy_graph();
        assert!(validate_policy_path_identities(&graph).is_ok());

        let mut graph = disjoint_policy_graph();
        graph.tool = graph.task;
        assert!(validate_policy_path_identities(&graph).is_err());

        let mut graph = disjoint_policy_graph();
        graph.input_parent_chain.push(graph.task);
        assert!(validate_policy_path_identities(&graph).is_err());

        let mut graph = disjoint_policy_graph();
        graph.task_ancestors.push(graph.tool);
        assert!(validate_policy_path_identities(&graph).is_err());

        let mut graph = disjoint_policy_graph();
        graph.tool_ancestors.push(graph.task);
        assert!(validate_policy_path_identities(&graph).is_err());

        let mut graph = disjoint_policy_graph();
        graph.task_files.insert(graph.input);
        assert!(validate_policy_path_identities(&graph).is_err());

        let mut graph = disjoint_policy_graph();
        graph.tool_files = graph.task_files.clone();
        assert!(validate_policy_path_identities(&graph).is_err());

        let graph = disjoint_policy_graph();
        assert!(validate_policy_path_identities(&graph).is_ok());
    }

    #[test]
    fn parent_ack_orders_release_before_each_placement_action() {
        let parent_attach_events = std::cell::RefCell::new(Vec::new());
        after_parent_ack(
            || {
                parent_attach_events.borrow_mut().push("read-parent-ack");
                Ok(Some(1))
            },
            || {
                parent_attach_events
                    .borrow_mut()
                    .push("expose-parent-attach-ready")
            },
        )
        .expect("positive parent ack allows parent-attach readiness");
        assert_eq!(
            *parent_attach_events.borrow(),
            ["read-parent-ack", "expose-parent-attach-ready"]
        );

        let cgroup_events = std::cell::RefCell::new(Vec::new());
        after_parent_ack(
            || {
                cgroup_events.borrow_mut().push("read-parent-ack");
                Ok(Some(1))
            },
            || cgroup_events.borrow_mut().push("clone-into-cgroup-target"),
        )
        .expect("positive parent ack allows cgroup target creation");
        assert_eq!(
            *cgroup_events.borrow(),
            ["read-parent-ack", "clone-into-cgroup-target"]
        );
    }

    #[test]
    fn missing_or_invalid_parent_ack_never_runs_placement_action() {
        for ack in [Ok(None), Ok(Some(0))] {
            let mut action_ran = false;
            assert!(after_parent_ack(|| ack, || action_ran = true).is_err());
            assert!(!action_ran, "placement action ran without a positive ack");
        }

        let mut action_ran = false;
        assert!(
            after_parent_ack(
                || Err(io::Error::from(io::ErrorKind::BrokenPipe)),
                || action_ran = true
            )
            .is_err()
        );
        assert!(
            !action_ran,
            "placement action ran after an ack read failure"
        );
    }

    fn inventory(entries: &[(&str, u64, u64)]) -> ToolInventory {
        ToolInventory {
            entries: entries
                .iter()
                .map(|(path, inode, link_count)| {
                    (
                        PathBuf::from(path),
                        ToolEntryEvidence {
                            identity: identity(*inode),
                            link_count: *link_count,
                            mount_id: 55,
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
        }
    }

    #[test]
    fn task_directory_mutation_invalidates_its_empty_preparation_snapshot() {
        assert!(validate_empty_task_snapshot(identity(20), identity(20), 0).is_ok());
        assert!(validate_empty_task_snapshot(identity(20), identity(20), 1).is_err());
        assert!(validate_empty_task_snapshot(identity(20), identity(21), 0).is_err());
    }

    #[test]
    fn private_task_snapshot_requires_current_owner_private_mode_two_links_and_same_mount() {
        let valid = TaskDirectorySnapshot {
            identity: identity(20),
            owner_uid: 1000,
            owner_gid: 1000,
            mode: 0o40700,
            link_count: 2,
            mount_id: 55,
        };
        assert!(validate_private_task_snapshot(&valid, identity(20), 55, 1000, 1000, 0).is_ok());

        for mode in [0o40777, 0o40770] {
            let mut changed = valid;
            changed.mode = mode;
            assert!(
                validate_private_task_snapshot(&changed, identity(20), 55, 1000, 1000, 0).is_err(),
                "mode {mode:o} must not satisfy the private-directory contract"
            );
        }

        for link_count in [1, 3] {
            let mut changed = valid;
            changed.link_count = link_count;
            assert!(
                validate_private_task_snapshot(&changed, identity(20), 55, 1000, 1000, 0).is_err(),
                "link count {link_count} must not satisfy the empty-directory contract"
            );
        }

        for (uid, gid, mount, entries) in [
            (1001, 1000, 55, 0),
            (1000, 1001, 55, 0),
            (1000, 1000, 56, 0),
            (1000, 1000, 55, 1),
        ] {
            assert!(
                validate_private_task_snapshot(&valid, identity(20), mount, uid, gid, entries,)
                    .is_err()
            );
        }
    }

    #[test]
    fn tool_inventory_revalidation_detects_replacement_and_link_mutation() {
        let prepared = inventory(&[("ffmpeg", 30, 2)]);
        assert!(validate_tool_inventory(identity(10), &prepared, &prepared).is_ok());
        assert!(
            validate_tool_inventory(identity(10), &prepared, &inventory(&[("ffmpeg", 31, 2)]))
                .is_err()
        );
        assert!(
            validate_tool_inventory(identity(10), &prepared, &inventory(&[("ffmpeg", 30, 3)]))
                .is_err()
        );
    }

    #[test]
    fn tool_inventory_rejects_input_alias_but_allows_stable_unrelated_hard_links() {
        let prepared = inventory(&[("ffmpeg", 30, 2)]);
        assert!(validate_tool_inventory(identity(10), &prepared, &prepared).is_ok());

        let input_alias = inventory(&[("input-copy", 10, 2)]);
        assert!(validate_tool_inventory(identity(10), &input_alias, &input_alias).is_err());
    }

    #[test]
    fn open_file_limit_reserves_capacity_for_pinned_policy_and_revalidation() {
        assert!(validate_open_files_limit(44).is_ok());
        assert!(validate_open_files_limit(43).is_err());
    }

    #[test]
    fn write_all_retries_interruption_and_partial_writes() {
        let mut interrupted = false;
        let mut output = Vec::new();
        write_all_with(b"ready", |remaining| {
            if !interrupted {
                interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let count = remaining.len().min(2);
            output.extend_from_slice(&remaining[..count]);
            Ok(count)
        })
        .expect("retry EINTR and complete partial writes");

        assert_eq!(output, b"ready");
    }

    #[test]
    fn write_all_propagates_closed_pipe_without_retrying_forever() {
        let mut attempts = 0;
        let error = write_all_with(b"ready", |_| {
            attempts += 1;
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        })
        .expect_err("closed pipe must be surfaced");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(attempts, 1);
    }

    #[test]
    fn unsupported_seccomp_architectures_have_no_audit_arch_fallback() {
        assert_eq!(seccomp_audit_arch(SeccompArchitecture::Unsupported), None);
        assert_eq!(
            seccomp_audit_arch(SeccompArchitecture::X86_64),
            Some(0xc000_003e)
        );
        assert_eq!(
            seccomp_audit_arch(SeccompArchitecture::Aarch64),
            Some(0xc000_00b7)
        );
    }

    #[test]
    fn network_evidence_portable_serialization_uses_synthetic_records_only() {
        let fixture = |status| {
            let item = ProbeEvidence {
                status,
                detail: "synthetic serialization fixture; no OS probe executed".into(),
            };
            NetworkEvidence {
                private_namespace_created: item.clone(),
                ipv4_socket_denial: item.clone(),
                ipv6_socket_denial: item.clone(),
                packet_socket_denial: item.clone(),
                ipv4_listener_isolated: item.clone(),
                ipv6_listener_isolated: item.clone(),
                unix_socket_escape: item.clone(),
                connect_denial: item.clone(),
                socketpair_denial: item.clone(),
                bpf_denial: item.clone(),
                userfaultfd_denial: item.clone(),
                namespace_creation_denied: item,
            }
        };
        let evidence = fixture(ProbeStatus::Failed);

        assert!(!evidence.all_passed());
        assert!(fixture(ProbeStatus::Passed).all_passed());
        assert_eq!(
            serde_json::to_value(evidence).expect("serialize network evidence"),
            serde_json::json!({
                "private_namespace_created": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "ipv4_socket_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "ipv6_socket_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "packet_socket_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "ipv4_listener_isolated": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "ipv6_listener_isolated": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "unix_socket_escape": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "connect_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "socketpair_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "bpf_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "userfaultfd_denial": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" },
                "namespace_creation_denied": { "status": "failed", "detail": "synthetic serialization fixture; no OS probe executed" }
            })
        );
    }

    #[test]
    fn network_evidence_serializes_unix_visibility_and_connect_denial_separately() {
        let item = ProbeEvidence {
            status: ProbeStatus::Passed,
            detail: "synthetic record; no OS probe executed".into(),
        };
        let mut evidence = NetworkEvidence {
            private_namespace_created: item.clone(),
            ipv4_socket_denial: item.clone(),
            ipv6_socket_denial: item.clone(),
            packet_socket_denial: item.clone(),
            ipv4_listener_isolated: item.clone(),
            ipv6_listener_isolated: item.clone(),
            unix_socket_escape: item.clone(),
            connect_denial: item.clone(),
            socketpair_denial: item.clone(),
            bpf_denial: item.clone(),
            userfaultfd_denial: item.clone(),
            namespace_creation_denied: item,
        };
        evidence.unix_socket_escape.detail =
            "synthetic pre-seccomp path probe observed ENOENT".into();
        evidence.connect_denial.detail =
            "synthetic post-seccomp connect probe observed EACCES".into();

        let serialized = serde_json::to_value(evidence).expect("serialize network evidence");
        assert_eq!(
            serialized["unix_socket_escape"]["detail"],
            "synthetic pre-seccomp path probe observed ENOENT"
        );
        assert_eq!(
            serialized["connect_denial"]["detail"],
            "synthetic post-seccomp connect probe observed EACCES"
        );
    }

    #[test]
    fn network_policy_allows_unix_socket_creation_but_denies_escape_syscalls() {
        let policy = NetworkPolicy::default();
        assert_eq!(policy.allowed_socket_domains, [NetworkSocketDomain::Unix]);
        assert_eq!(
            policy.denied_socket_domains,
            [
                NetworkSocketDomain::Ipv4,
                NetworkSocketDomain::Ipv6,
                NetworkSocketDomain::Packet,
            ]
        );
        assert_eq!(
            policy.denied_syscalls,
            [
                NetworkSyscall::Connect,
                NetworkSyscall::SocketPair,
                NetworkSyscall::Bpf,
                NetworkSyscall::Userfaultfd,
            ]
        );
        assert_eq!(FFPROBE_PROTOCOL_WHITELIST, "file,pipe");
    }

    #[test]
    fn production_network_namespace_attestation_rejects_missing_or_host_identity() {
        let host = FileIdentity {
            device: 7,
            inode: 11,
        };
        assert!(!network_namespace_is_private(host, None));
        assert!(!network_namespace_is_private(host, Some(host)));
        assert!(network_namespace_is_private(
            host,
            Some(FileIdentity {
                device: 7,
                inode: 12,
            })
        ));
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    #[test]
    fn network_inspection_reports_unsupported_platform_without_fabricating_evidence() {
        assert!(matches!(
            NetworkPrerequisites::inspect(),
            Err(SandboxError::UnsupportedPlatform)
        ));
    }

    #[test]
    fn cgroup_job_id_is_exactly_one_safe_ascii_component() {
        assert!(validate_cgroup_job_id("job-42").is_ok());
        assert!(validate_cgroup_job_id("job_42.x").is_ok());

        for invalid in [
            "",
            ".",
            "..",
            "../job",
            "job/child",
            "job\\child",
            "/job",
            "job name",
            "é",
        ] {
            assert!(
                validate_cgroup_job_id(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn cgroup_limit_controls_encode_pids_memory_swap_and_cpu() {
        let limits = SandboxLimits {
            pids_max: 7,
            memory_max_bytes: 12_345,
            memory_swap_max_bytes: 0,
            cpu_quota_micros: 25_000,
            cpu_period_micros: 100_000,
            file_size_max_bytes: 1024,
            open_files_max: 16,
            tmpfs_max_bytes: 1024,
        };

        assert_eq!(
            cgroup_limit_controls(limits).expect("valid aggregate limits"),
            CgroupLimitControls {
                pids_max: "7\n".into(),
                memory_max: "12345\n".into(),
                memory_swap_max: "0\n".into(),
                cpu_max: "25000 100000\n".into(),
            }
        );

        assert!(
            cgroup_limit_controls(SandboxLimits {
                memory_swap_max_bytes: 1,
                ..limits
            })
            .is_err()
        );
    }

    #[test]
    fn cgroup_population_and_proc_membership_require_exact_records() {
        assert_eq!(parse_cgroup_populated("populated 0\nfrozen 0\n"), Ok(false));
        assert_eq!(parse_cgroup_populated("populated 1\nfrozen 0\n"), Ok(true));
        assert!(parse_cgroup_populated("frozen 0\n").is_err());

        assert!(proc_cgroup_matches(
            "12:cpu:/user.slice\n0::/delegated/job-42\n",
            "/delegated/job-42"
        ));
        assert!(!proc_cgroup_matches(
            "0::/delegated/job-42-extra\n",
            "/delegated/job-42"
        ));
        assert!(!proc_cgroup_matches(
            "0::/delegated/job-42\n0::/other\n",
            "/delegated/job-42"
        ));
    }

    #[test]
    fn blocked_cgroup_evidence_is_not_reported_as_ready() {
        let evidence = CgroupEvidence::blocked("BLOCKED: no native Linux cgroup v2 delegation");
        assert_eq!(evidence.status, CgroupEvidenceStatus::Blocked);
        assert!(!evidence.all_passed());
        assert!(evidence.detail.contains("BLOCKED"));
    }
}
