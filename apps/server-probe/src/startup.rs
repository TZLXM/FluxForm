//! Fail-closed server startup. Public listeners can only be bound after the
//! live Task 7/8/9 checks have completed successfully.

use crate::auth::CapabilityStore;
use crate::routes::{self, RouteConfigurationError, ServerState};
use crate::{LedgerLimits, UploadLedger};
use fluxform_sandbox_probe::{
    CgroupEvidenceStatus, CgroupV2Job, FilesystemPrerequisites, NetworkPrerequisites, ProbeStatus,
    ResourceBoundary, SandboxLimits,
};
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use fluxform_sandbox_probe::{Sandbox, SandboxPolicy};
use sha2::{Digest, Sha256};
use std::env;
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
use std::ffi::OsString;
use std::fs;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;
use tokio::net::TcpListener;
use uuid::Uuid;

const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const DAILY_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ACTIVE_SESSIONS_PER_IP: u32 = 4;
const MAX_GLOBAL_RESERVED_BYTES: u64 = 1024 * 1024 * 1024;
const DISK_SAFETY_MARGIN_BYTES: u64 = 1024 * 1024 * 1024;
const CAPABILITY_TTL: Duration = Duration::from_secs(60 * 60);
#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
const PROBE_TIMEOUT: Duration = Duration::from_secs(10);

/// The two supported service modes. Mode selection is explicit; there is no
/// implicit fallback from a failed public check to LocalDevelopment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServerMode {
    Public,
    LocalDevelopment,
}

impl ServerMode {
    pub fn parse(value: &str) -> Result<Self, StartupError> {
        match value {
            "public" => Ok(Self::Public),
            "local-development" => Ok(Self::LocalDevelopment),
            _ => Err(StartupError::InvalidConfiguration(
                "FLUXFORM_SERVER_MODE must be explicitly set to public or local-development",
            )),
        }
    }
}

/// The exact checks whose failures deny Public startup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SandboxCheck {
    Filesystem,
    Network,
    CgroupControllers,
    CgroupKill,
    ServiceIdentity,
    PrivateNamespace,
    PlacementBarrier,
}

/// Configuration for the Task 7 fixed-action sandbox-child executable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SandboxProbeConfig {
    pub executable: PathBuf,
    pub tool_directory: PathBuf,
    /// SHA-256 of the exact packaged Task 7 sandbox-child artifact.
    pub sha256: String,
}

/// Validated startup inputs. Values are supplied explicitly by the operator;
/// secrets are never loaded from a report or a test evidence file.
#[derive(Clone)]
pub struct ServerConfig {
    pub mode: ServerMode,
    pub listen_address: SocketAddr,
    pub data_dir: PathBuf,
    pub public_origin: String,
    pub server_secret: [u8; 32],
    pub trusted_proxy_cidrs: Vec<String>,
    pub delegated_cgroup_root: Option<PathBuf>,
    pub sandbox_probe: Option<SandboxProbeConfig>,
}

/// The checker seam supports deterministic unit tests. The executable's
/// production startup path always supplies [`RealSandboxChecker`]; a test
/// double is not persisted, serialized, or accepted as native evidence.
pub trait SandboxChecker {
    fn check(&self, config: &ServerConfig) -> Result<(), StartupError>;
}

/// Active runtime verification of Task 7 filesystem, Task 8 network/seccomp,
/// and Task 9 delegated cgroup/resource boundaries.
pub struct RealSandboxChecker;

impl SandboxChecker for RealSandboxChecker {
    fn check(&self, config: &ServerConfig) -> Result<(), StartupError> {
        let filesystem = FilesystemPrerequisites::inspect()
            .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
        if !filesystem.all_passed() {
            return Err(StartupError::sandbox_check_failed(
                SandboxCheck::Filesystem,
                "one or more Task 7 filesystem prerequisites failed",
            ));
        }

        let network = NetworkPrerequisites::inspect()
            .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Network, error))?;
        if network.private_namespace_created.status != ProbeStatus::Passed {
            return Err(StartupError::sandbox_check_failed(
                SandboxCheck::PrivateNamespace,
                &network.private_namespace_created.detail,
            ));
        }
        if !network.all_passed() {
            return Err(StartupError::sandbox_check_failed(
                SandboxCheck::Network,
                "one or more Task 8 network/seccomp prerequisites failed",
            ));
        }

        let delegated_root =
            config
                .delegated_cgroup_root
                .as_deref()
                .ok_or(StartupError::InvalidConfiguration(
                    "Public mode requires FLUXFORM_SERVER_DELEGATED_CGROUP_ROOT",
                ))?;
        let sandbox_probe = config
            .sandbox_probe
            .as_ref()
            .ok_or(StartupError::InvalidConfiguration(
                "Public mode requires the packaged Task 7 sandbox-child executable and tool directory",
            ))?;
        validate_probe_binary(sandbox_probe)?;

        let job_id = format!("startup-{}", Uuid::new_v4().simple());
        let job = CgroupV2Job::create(delegated_root, &job_id, SandboxLimits::default())
            .map_err(classify_cgroup_error)?;
        if job.evidence().status != CgroupEvidenceStatus::Ready {
            return Err(StartupError::sandbox_check_failed(
                SandboxCheck::CgroupControllers,
                job.evidence().detail,
            ));
        }

        // Exercise the real child-side namespace/seccomp setup and Task 9
        // placement barrier before the HTTP server can obtain a listener.
        run_placement_probe(&job, sandbox_probe)?;

        job.kill_all()
            .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::CgroupKill, error))?;
        if !job
            .is_empty()
            .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::CgroupKill, error))?
        {
            return Err(StartupError::sandbox_check_failed(
                SandboxCheck::CgroupKill,
                "startup probe cgroup remained populated after cgroup.kill",
            ));
        }
        Ok(())
    }
}

/// An error is always surfaced before a [`PreparedServer`] is returned.
#[derive(Debug, Error)]
pub enum StartupError {
    #[error("invalid server startup configuration: {0}")]
    InvalidConfiguration(&'static str),
    #[error("server startup sandbox check {check:?} failed: {detail}")]
    SandboxCheckFailed { check: SandboxCheck, detail: String },
    #[error("server state initialization failed: {0}")]
    StateInitialization(String),
    #[error("server listener bind failed: {0}")]
    Bind(#[source] io::Error),
}

impl StartupError {
    pub fn sandbox_check_failed(check: SandboxCheck, detail: impl std::fmt::Display) -> Self {
        Self::SandboxCheckFailed {
            check,
            detail: detail.to_string(),
        }
    }
}

/// A server whose configuration and security gates have completed, but which
/// does not yet own a network socket.
pub struct PreparedServer {
    mode: ServerMode,
    listen_address: SocketAddr,
    data_dir: PathBuf,
    state: ServerState,
    public_authorization: Option<PublicListenerAuthorization>,
}

impl PreparedServer {
    pub fn mode(&self) -> ServerMode {
        self.mode
    }

    pub fn warning(&self) -> Option<&'static str> {
        (self.mode == ServerMode::LocalDevelopment).then_some(
            "WARNING: LocalDevelopment is not a production service; it is loopback-only and does not run the Linux sandbox gate.",
        )
    }

    pub fn database_path(&self) -> PathBuf {
        self.data_dir.join("server.sqlite3")
    }

    pub fn state(&self) -> &ServerState {
        &self.state
    }

    /// This is the only operation that binds. It is available only after all
    /// config validation and, in Public mode, the live sandbox checker pass.
    pub async fn bind(self) -> Result<BoundServer, StartupError> {
        let listener = TcpListener::bind(self.listen_address)
            .await
            .map_err(StartupError::Bind)?;
        Ok(BoundServer {
            listener,
            mode: self.mode,
            state: self.state,
            public_authorization: self.public_authorization,
        })
    }
}

/// Bound listener wrapper that retains the authorization produced only by
/// successful Public startup.
pub struct BoundServer {
    listener: TcpListener,
    mode: ServerMode,
    state: ServerState,
    public_authorization: Option<PublicListenerAuthorization>,
}

impl BoundServer {
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    pub async fn serve_with_shutdown<F>(self, shutdown: F) -> io::Result<()>
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        match (self.mode, self.public_authorization.as_ref()) {
            (ServerMode::Public, Some(authorization)) => {
                routes::serve_prepared_with_shutdown(
                    self.listener,
                    self.state,
                    authorization,
                    shutdown,
                )
                .await
            }
            (ServerMode::LocalDevelopment, None) => {
                routes::serve_with_shutdown(self.listener, self.state, shutdown).await
            }
            _ => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "prepared listener authorization does not match server mode",
            )),
        }
    }
}

/// Opaque proof that the Public-mode startup gate completed. Its only
/// constructor lives in this module; route adapters cannot synthesize it.
pub(crate) struct PublicListenerAuthorization {
    _private: (),
}

/// Validates every config value and all required security checks before
/// returning a bind-capable server object.
pub fn prepare_server(
    config: ServerConfig,
    sandbox_checker: &dyn SandboxChecker,
) -> Result<PreparedServer, StartupError> {
    validate_config(&config)?;

    if config.mode == ServerMode::Public {
        sandbox_checker.check(&config)?;
    }

    let state = build_server_state(&config)?;
    let public_authorization =
        (config.mode == ServerMode::Public).then_some(PublicListenerAuthorization { _private: () });
    Ok(PreparedServer {
        mode: config.mode,
        listen_address: config.listen_address,
        data_dir: config.data_dir,
        state,
        public_authorization,
    })
}

fn validate_config(config: &ServerConfig) -> Result<(), StartupError> {
    if !config.listen_address.ip().is_loopback() && config.mode != ServerMode::Public {
        return Err(StartupError::InvalidConfiguration(
            "LocalDevelopment listeners must bind to a loopback address",
        ));
    }
    if !is_clean_absolute_path(&config.data_dir) || config.data_dir.file_name().is_none() {
        return Err(StartupError::InvalidConfiguration(
            "server data directory must be an absolute non-root path",
        ));
    }
    if config.server_secret.iter().all(|byte| *byte == 0) {
        return Err(StartupError::InvalidConfiguration(
            "server secret must not be all zeroes",
        ));
    }
    routes::validate_public_origin_for_startup(&config.public_origin)
        .map_err(|_| StartupError::InvalidConfiguration("public origin is invalid"))?;
    if config.trusted_proxy_cidrs.len() > 64 {
        return Err(StartupError::InvalidConfiguration(
            "trusted proxy CIDR list exceeds its bounded configuration limit",
        ));
    }
    for cidr in &config.trusted_proxy_cidrs {
        validate_cidr(cidr)
            .map_err(|_| StartupError::InvalidConfiguration("trusted proxy CIDR is invalid"))?;
    }

    if config.mode == ServerMode::Public {
        let delegated_root =
            config
                .delegated_cgroup_root
                .as_deref()
                .ok_or(StartupError::InvalidConfiguration(
                    "Public mode requires FLUXFORM_SERVER_DELEGATED_CGROUP_ROOT",
                ))?;
        let probe = config.sandbox_probe.as_ref().ok_or(
            StartupError::InvalidConfiguration(
                "Public mode requires the packaged Task 7 sandbox-child executable and tool directory",
            ),
        )?;
        if !is_clean_absolute_path(delegated_root)
            || !is_clean_absolute_path(&probe.executable)
            || !is_clean_absolute_path(&probe.tool_directory)
        {
            return Err(StartupError::InvalidConfiguration(
                "Public sandbox paths must be absolute",
            ));
        }
        if !is_sha256(&probe.sha256) {
            return Err(StartupError::InvalidConfiguration(
                "Public sandbox probe SHA-256 must be 64 lowercase hexadecimal characters",
            ));
        }
        if probe.executable.file_name() != Some(std::ffi::OsStr::new("sandbox-child"))
            || probe.executable.parent() != Some(probe.tool_directory.as_path())
        {
            return Err(StartupError::InvalidConfiguration(
                "Public sandbox probe must be sandbox-child directly inside its declared tool directory",
            ));
        }
    }
    Ok(())
}

fn is_clean_absolute_path(path: &Path) -> bool {
    path.is_absolute()
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_cidr(value: &str) -> Result<(), ()> {
    let (address, prefix) = value.split_once('/').ok_or(())?;
    let prefix = prefix.parse::<u8>().map_err(|_| ())?;
    match address.parse::<IpAddr>().map_err(|_| ())? {
        IpAddr::V4(_) if prefix <= 32 => Ok(()),
        IpAddr::V6(_) if prefix <= 128 => Ok(()),
        _ => Err(()),
    }
}

fn build_server_state(config: &ServerConfig) -> Result<ServerState, StartupError> {
    create_private_directory(&config.data_dir)?;
    let upload_root = config.data_dir.join("uploads");
    create_private_directory(&upload_root)?;

    let database_path = config.data_dir.join("server.sqlite3");
    let ledger = UploadLedger::open(
        &database_path,
        &upload_root,
        LedgerLimits {
            max_file_bytes: MAX_FILE_BYTES,
            daily_quota_bytes: DAILY_QUOTA_BYTES,
            max_active_sessions_per_ip: MAX_ACTIVE_SESSIONS_PER_IP,
            max_global_reserved_bytes: MAX_GLOBAL_RESERVED_BYTES,
            disk_safety_margin_bytes: DISK_SAFETY_MARGIN_BYTES,
        },
        vec![config.server_secret],
    )
    .map_err(|error| StartupError::StateInitialization(error.to_string()))?;
    let capabilities = CapabilityStore::open(&database_path)
        .map_err(|error| StartupError::StateInitialization(error.to_string()))?;
    ServerState::new(
        ledger,
        capabilities,
        config.public_origin.clone(),
        config.trusted_proxy_cidrs.clone(),
        CAPABILITY_TTL,
    )
    .map_err(map_route_configuration_error)
}

fn map_route_configuration_error(error: RouteConfigurationError) -> StartupError {
    StartupError::StateInitialization(error.to_string())
}

fn create_private_directory(path: &Path) -> Result<(), StartupError> {
    let created = match fs::symlink_metadata(path) {
        Ok(_) => false,
        Err(error) if error.kind() == io::ErrorKind::NotFound => true,
        Err(error) => return Err(StartupError::StateInitialization(error.to_string())),
    };
    if created {
        fs::create_dir_all(path)
            .map_err(|error| StartupError::StateInitialization(error.to_string()))?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| StartupError::StateInitialization(error.to_string()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(StartupError::StateInitialization(
            "server data paths must be real directories, not symlinks".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|error| StartupError::StateInitialization(error.to_string()))?;
        }
        let metadata = fs::symlink_metadata(path)
            .map_err(|error| StartupError::StateInitialization(error.to_string()))?;
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid || metadata.permissions().mode() & 0o777 != 0o700 {
            return Err(StartupError::StateInitialization(
                "Public and LocalDevelopment data directories must be owned by the service UID with mode 0700".into(),
            ));
        }
    }
    Ok(())
}

fn validate_probe_binary(probe: &SandboxProbeConfig) -> Result<(), StartupError> {
    if probe.executable.file_name() != Some(std::ffi::OsStr::new("sandbox-child"))
        || probe.executable.parent() != Some(probe.tool_directory.as_path())
    {
        return Err(StartupError::InvalidConfiguration(
            "sandbox probe must be sandbox-child directly inside its declared tool directory",
        ));
    }
    let metadata = fs::symlink_metadata(&probe.executable).map_err(|error| {
        StartupError::sandbox_check_failed(SandboxCheck::PlacementBarrier, error)
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(StartupError::sandbox_check_failed(
            SandboxCheck::PlacementBarrier,
            "sandbox-child must be a regular non-symlink executable",
        ));
    }
    let tool_metadata = fs::symlink_metadata(&probe.tool_directory).map_err(|error| {
        StartupError::sandbox_check_failed(SandboxCheck::PlacementBarrier, error)
    })?;
    if !tool_metadata.is_dir() || tool_metadata.file_type().is_symlink() {
        return Err(StartupError::sandbox_check_failed(
            SandboxCheck::PlacementBarrier,
            "sandbox tool directory must be a real directory, not a symlink",
        ));
    }
    let binary = fs::read(&probe.executable).map_err(|error| {
        StartupError::sandbox_check_failed(SandboxCheck::PlacementBarrier, error)
    })?;
    let actual_sha256 = Sha256::digest(binary)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual_sha256 != probe.sha256 {
        return Err(StartupError::sandbox_check_failed(
            SandboxCheck::PlacementBarrier,
            "sandbox-child SHA-256 does not match the declared packaged binary identity",
        ));
    }
    Ok(())
}

fn classify_cgroup_error(error: impl std::fmt::Display) -> StartupError {
    let detail = error.to_string();
    let lower = detail.to_ascii_lowercase();
    let check = if lower.contains("cgroup.kill") {
        SandboxCheck::CgroupKill
    } else if lower.contains("service management")
        || lower.contains("service cgroup")
        || lower.contains("service uid")
        || lower.contains("effective uid")
        || lower.contains("exclusive per-job")
    {
        SandboxCheck::ServiceIdentity
    } else {
        SandboxCheck::CgroupControllers
    };
    StartupError::sandbox_check_failed(check, detail)
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
#[allow(clippy::too_many_lines)]
fn run_placement_probe(job: &CgroupV2Job, probe: &SandboxProbeConfig) -> Result<(), StartupError> {
    let placement = job.prepare_spawn().map_err(|error| {
        StartupError::sandbox_check_failed(SandboxCheck::PlacementBarrier, error)
    })?;
    let root = StartupProbeDirectory(create_probe_root()?);
    let input = root.0.join("input.bin");
    let job_dir = root.0.join("task");
    fs::write(&input, b"assigned-input")
        .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
    fs::create_dir(&job_dir)
        .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&job_dir, fs::Permissions::from_mode(0o700))
            .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
    }

    let policy = SandboxPolicy {
        input,
        job_dir: job_dir.clone(),
        tool_dir: probe.tool_directory.clone(),
        limits: SandboxLimits::default(),
    };
    let arguments = [OsString::from("write-task")];
    let mut child = Sandbox::spawn_blocked(&probe.executable, &arguments, &policy, placement)
        .map_err(|error| {
            StartupError::sandbox_check_failed(SandboxCheck::PlacementBarrier, error)
        })?;
    let status = child
        .wait_timeout(PROBE_TIMEOUT)
        .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::PlacementBarrier, error))?
        .ok_or_else(|| {
            StartupError::sandbox_check_failed(
                SandboxCheck::PlacementBarrier,
                "sandbox-child did not finish its startup placement probe",
            )
        })?;
    if !status.success() {
        return Err(StartupError::sandbox_check_failed(
            SandboxCheck::PlacementBarrier,
            format!("sandbox-child write-task exited with {status}"),
        ));
    }
    let output = fs::read(job_dir.join("result.bin"))
        .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
    if output != b"task-output" {
        return Err(StartupError::sandbox_check_failed(
            SandboxCheck::Filesystem,
            "sandbox-child did not produce the expected confined task output",
        ));
    }
    drop(child);
    Ok(())
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
struct StartupProbeDirectory(PathBuf);

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
impl Drop for StartupProbeDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
fn run_placement_probe(
    _job: &CgroupV2Job,
    _probe: &SandboxProbeConfig,
) -> Result<(), StartupError> {
    Err(StartupError::sandbox_check_failed(
        SandboxCheck::PlacementBarrier,
        "BLOCKED: the native Task 7 placement probe requires Linux x86_64 or aarch64",
    ))
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
fn create_probe_root() -> Result<PathBuf, StartupError> {
    let root = env::temp_dir().join(format!("fluxform-startup-{}", Uuid::new_v4().simple()));
    fs::create_dir(&root)
        .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|error| StartupError::sandbox_check_failed(SandboxCheck::Filesystem, error))?;
    }
    Ok(root)
}

/// Configuration builder for the executable. It deliberately requires an
/// explicit mode and does not reinterpret failed Public startup as local.
pub fn config_from_environment() -> Result<ServerConfig, StartupError> {
    let mode = ServerMode::parse(&required_environment("FLUXFORM_SERVER_MODE")?)?;
    let default_address = match mode {
        ServerMode::Public => "0.0.0.0:43123",
        ServerMode::LocalDevelopment => "127.0.0.1:43123",
    };
    let listen_address = env::var("FLUXFORM_SERVER_LISTEN")
        .unwrap_or_else(|_| default_address.to_owned())
        .parse::<SocketAddr>()
        .map_err(|_| StartupError::InvalidConfiguration("listen address is invalid"))?;
    let data_dir = PathBuf::from(required_environment("FLUXFORM_SERVER_DATA_DIR")?);
    let server_secret = parse_secret(&required_environment("FLUXFORM_SERVER_SECRET")?)?;
    let public_origin =
        env::var("FLUXFORM_PUBLIC_ORIGIN").unwrap_or_else(|_| format!("http://{listen_address}"));
    let delegated_cgroup_root =
        env::var_os("FLUXFORM_SERVER_DELEGATED_CGROUP_ROOT").map(PathBuf::from);
    let sandbox_probe = match (
        env::var_os("FLUXFORM_SERVER_SANDBOX_PROBE"),
        env::var_os("FLUXFORM_SERVER_SANDBOX_TOOL_DIR"),
        env::var_os("FLUXFORM_SERVER_SANDBOX_PROBE_SHA256"),
    ) {
        (Some(executable), Some(tool_directory), Some(sha256)) => Some(SandboxProbeConfig {
            executable: PathBuf::from(executable),
            tool_directory: PathBuf::from(tool_directory),
            sha256: sha256.to_string_lossy().into_owned(),
        }),
        (None, None, None) => None,
        _ => {
            return Err(StartupError::InvalidConfiguration(
                "FLUXFORM_SERVER_SANDBOX_PROBE, FLUXFORM_SERVER_SANDBOX_TOOL_DIR, and FLUXFORM_SERVER_SANDBOX_PROBE_SHA256 must be set together",
            ));
        }
    };
    let trusted_proxy_cidrs = env::var("FLUXFORM_SERVER_TRUSTED_PROXY_CIDRS")
        .unwrap_or_default()
        .split(',')
        .filter(|entry| !entry.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(ServerConfig {
        mode,
        listen_address,
        data_dir,
        public_origin,
        server_secret,
        trusted_proxy_cidrs,
        delegated_cgroup_root,
        sandbox_probe,
    })
}

fn required_environment(name: &'static str) -> Result<String, StartupError> {
    env::var(name).map_err(|_| {
        StartupError::InvalidConfiguration(match name {
            "FLUXFORM_SERVER_MODE" => "FLUXFORM_SERVER_MODE must be explicit",
            "FLUXFORM_SERVER_DATA_DIR" => "FLUXFORM_SERVER_DATA_DIR must be set",
            "FLUXFORM_SERVER_SECRET" => "FLUXFORM_SERVER_SECRET must be set",
            _ => "required server environment variable is missing",
        })
    })
}

fn parse_secret(value: &str) -> Result<[u8; 32], StartupError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(StartupError::InvalidConfiguration(
            "FLUXFORM_SERVER_SECRET must contain exactly 64 hexadecimal characters",
        ));
    }
    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            StartupError::InvalidConfiguration("FLUXFORM_SERVER_SECRET is invalid hexadecimal")
        })?;
    }
    if secret.iter().all(|byte| *byte == 0) {
        return Err(StartupError::InvalidConfiguration(
            "server secret must not be all zeroes",
        ));
    }
    Ok(secret)
}
