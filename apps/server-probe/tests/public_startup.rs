use fluxform_server_probe::startup::{
    SandboxCheck, SandboxChecker, SandboxProbeConfig, ServerConfig, ServerMode, StartupError,
    prepare_server,
};
use std::fs;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

struct InjectedChecker {
    failed_check: Option<SandboxCheck>,
    calls: Arc<Mutex<usize>>,
}

impl InjectedChecker {
    fn passing() -> Self {
        Self {
            failed_check: None,
            calls: Arc::new(Mutex::new(0)),
        }
    }

    fn failing(check: SandboxCheck) -> Self {
        Self {
            failed_check: Some(check),
            calls: Arc::new(Mutex::new(0)),
        }
    }
}

impl SandboxChecker for InjectedChecker {
    fn check(&self, _config: &ServerConfig) -> Result<(), StartupError> {
        *self.calls.lock().unwrap() += 1;
        match self.failed_check {
            Some(check) => Err(StartupError::sandbox_check_failed(
                check,
                "injected failure",
            )),
            None => Ok(()),
        }
    }
}

struct MustNotRunChecker;

impl SandboxChecker for MustNotRunChecker {
    fn check(&self, _config: &ServerConfig) -> Result<(), StartupError> {
        panic!("LocalDevelopment must not invoke the Linux sandbox checker")
    }
}

fn config(root: &TempDir, mode: ServerMode, address: SocketAddr) -> ServerConfig {
    ServerConfig {
        mode,
        listen_address: address,
        data_dir: root.path().join("server-data"),
        public_origin: format!("http://{address}"),
        server_secret: [0x6d; 32],
        trusted_proxy_cidrs: Vec::new(),
        delegated_cgroup_root: Some(root.path().join("delegated-cgroup")),
        sandbox_probe: Some(SandboxProbeConfig {
            executable: root.path().join("tools").join("sandbox-child"),
            tool_directory: root.path().join("tools"),
            sha256: "0".repeat(64),
        }),
    }
}

fn unused_loopback_address() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap()
}

#[test]
fn every_failed_public_sandbox_gate_returns_before_the_address_can_be_bound() {
    let checks = [
        SandboxCheck::Filesystem,
        SandboxCheck::Network,
        SandboxCheck::CgroupControllers,
        SandboxCheck::CgroupKill,
        SandboxCheck::ServiceIdentity,
        SandboxCheck::PrivateNamespace,
        SandboxCheck::PlacementBarrier,
    ];

    for check in checks {
        let root = tempfile::tempdir().unwrap();
        let address = unused_loopback_address();
        let checker = InjectedChecker::failing(check);
        let error = match prepare_server(config(&root, ServerMode::Public, address), &checker) {
            Err(error) => error,
            Ok(_) => panic!("failed sandbox check {check:?} must reject public startup"),
        };

        assert!(error.to_string().contains(&format!("{check:?}")));
        assert_eq!(*checker.calls.lock().unwrap(), 1);
        assert!(
            TcpListener::bind(address).is_ok(),
            "{check:?} claimed {address}"
        );
    }
}

#[test]
fn invalid_public_configuration_is_rejected_before_sandbox_checker_runs() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let mut invalid = config(&root, ServerMode::Public, address);
    invalid.public_origin = "not-an-origin".to_owned();
    let checker = InjectedChecker::passing();

    let error = match prepare_server(invalid, &checker) {
        Err(error) => error,
        Ok(_) => panic!("invalid Public configuration must be rejected"),
    };

    assert!(error.to_string().contains("configuration"));
    assert_eq!(*checker.calls.lock().unwrap(), 0);
    assert!(TcpListener::bind(address).is_ok());
}

#[test]
fn malformed_public_probe_identity_is_rejected_before_sandbox_checker_runs() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let mut invalid = config(&root, ServerMode::Public, address);
    invalid.sandbox_probe.as_mut().unwrap().sha256 = "test-only".to_owned();
    let checker = InjectedChecker::passing();

    let error = match prepare_server(invalid, &checker) {
        Err(error) => error,
        Ok(_) => panic!("malformed probe identity must be rejected"),
    };

    assert!(error.to_string().contains("SHA-256"));
    assert_eq!(*checker.calls.lock().unwrap(), 0);
    assert!(TcpListener::bind(address).is_ok());
}

#[tokio::test]
async fn passing_injected_checker_can_prepare_and_bind_public_mode() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let checker = InjectedChecker::passing();

    let prepared = prepare_server(config(&root, ServerMode::Public, address), &checker).unwrap();
    assert_eq!(prepared.mode(), ServerMode::Public);
    assert_eq!(*checker.calls.lock().unwrap(), 1);

    let bound = prepared.bind().await.unwrap();
    assert_eq!(bound.local_addr().unwrap(), address);
}

#[tokio::test]
async fn explicit_local_development_binds_loopback_with_a_nonproduction_warning() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let prepared = prepare_server(
        config(&root, ServerMode::LocalDevelopment, address),
        &MustNotRunChecker,
    )
    .unwrap();

    assert!(
        prepared
            .warning()
            .unwrap()
            .to_ascii_lowercase()
            .contains("not a production")
    );
    let bound = prepared.bind().await.unwrap();
    assert!(bound.local_addr().unwrap().ip().is_loopback());
}

#[test]
fn local_development_rejects_non_loopback_addresses_instead_of_upgrading_to_public() {
    let root = tempfile::tempdir().unwrap();
    let address = SocketAddr::from(([0, 0, 0, 0], 43123));
    let error = match prepare_server(
        config(&root, ServerMode::LocalDevelopment, address),
        &MustNotRunChecker,
    ) {
        Err(error) => error,
        Ok(_) => panic!("non-loopback LocalDevelopment must be rejected"),
    };

    assert!(error.to_string().contains("loopback"));
}

#[cfg(target_os = "linux")]
#[ignore = "requires delegated cgroup v2 and supported Linux namespace/seccomp prerequisites"]
#[tokio::test]
async fn delegated_linux_process_binds_public_mode_and_serves_protected_status() {
    use fluxform_server_probe::auth::{Capability, CapabilityStore, Scope};
    use fluxform_server_probe::routes::ServerState;
    use fluxform_server_probe::{LedgerLimits, UploadLedger};
    use std::os::unix::fs::PermissionsExt;
    use std::time::SystemTime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as TokioTcpStream;

    let cgroup_root = native_env_path("FLUXFORM_TEST_CGROUP_ROOT");
    let (probe, tool_directory) = native_sandbox_probe();
    let root = tempfile::tempdir().unwrap();
    let address = unused_public_address();
    let data_dir = root.path().join("server-data");
    fs::create_dir(&data_dir).unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
    let upload_root = data_dir.join("uploads");
    fs::create_dir(&upload_root).unwrap();
    fs::set_permissions(&upload_root, fs::Permissions::from_mode(0o700)).unwrap();
    let database_path = data_dir.join("server.sqlite3");
    let ledger = UploadLedger::open(
        &database_path,
        &upload_root,
        LedgerLimits {
            max_file_bytes: 256 * 1024 * 1024,
            daily_quota_bytes: 512 * 1024 * 1024,
            max_active_sessions_per_ip: 4,
            max_global_reserved_bytes: 1024 * 1024 * 1024,
            disk_safety_margin_bytes: 1024 * 1024 * 1024,
        },
        vec![[0x6d; 32]],
    )
    .unwrap();
    let capabilities = CapabilityStore::open(&database_path).unwrap();
    let state = ServerState::new(
        ledger,
        capabilities,
        "https://fluxform.test",
        Vec::new(),
        Duration::from_secs(60 * 60),
    )
    .unwrap();
    state.register_job("startup-proof", "queued").unwrap();
    let capabilities = CapabilityStore::open(&database_path).unwrap();
    let capability = Capability::issue(
        &capabilities,
        "startup-proof",
        [Scope::Status],
        SystemTime::now() + Duration::from_secs(60),
    )
    .unwrap();

    let mut child = ChildGuard(launch_native_server(
        &data_dir,
        address,
        &cgroup_root,
        &cgroup_root,
        &probe,
        &tool_directory,
        Stdio::null(),
    ));
    let connect_address = loopback_for(address);
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut connected = false;
    while Instant::now() < deadline {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "BLOCKED: real Public startup exited before its listener accepted connections: {status}"
            );
        }
        if TokioTcpStream::connect(connect_address).await.is_ok() {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        connected,
        "BLOCKED: real Public startup did not bind within 45 seconds"
    );

    let mut stream = TokioTcpStream::connect(connect_address).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /v1/jobs/startup-proof HTTP/1.1\r\nHost: {connect_address}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
                capability.token()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
}

#[cfg(target_os = "linux")]
#[ignore = "requires supported Linux filesystem/network checks and a valid cgroup parent to prove cgroup rejection"]
#[test]
fn real_process_rejects_an_unavailable_delegated_cgroup_before_public_bind() {
    let (probe, tool_directory) = native_sandbox_probe();
    let cgroup_parent = native_env_path("FLUXFORM_TEST_CGROUP_ROOT");
    let missing_cgroup =
        cgroup_parent.join(format!("missing-task14-{}", uuid::Uuid::new_v4().simple()));
    assert!(!missing_cgroup.exists());
    let root = tempfile::tempdir().unwrap();
    let address = unused_public_address();
    let stderr_path = root.path().join("server-stderr.log");
    let stderr = fs::File::create(&stderr_path).unwrap();
    let mut child = ChildGuard(launch_native_server(
        root.path().join("server-data").as_path(),
        address,
        &missing_cgroup,
        &cgroup_parent,
        &probe,
        &tool_directory,
        Stdio::from(stderr),
    ));
    let status = wait_for_process_exit(&mut child, Duration::from_secs(45));
    assert!(
        !status.success(),
        "missing delegated cgroup must reject Public startup"
    );
    let diagnostic = fs::read_to_string(stderr_path).unwrap();
    assert!(
        diagnostic.contains("Cgroup") || diagnostic.contains("cgroup"),
        "expected cgroup-specific diagnostic, got: {diagnostic}"
    );
    assert_port_available(address);
}

#[cfg(target_os = "linux")]
#[ignore = "requires a Linux runner where filesystem checks pass but Task 8 network/seccomp prerequisites fail"]
#[test]
fn real_process_rejects_unavailable_network_seccomp_before_public_bind() {
    assert_eq!(
        std::env::var("FLUXFORM_TEST_EXPECT_NETWORK_FAILURE").as_deref(),
        Ok("1"),
        "BLOCKED: opt in only on a runner prepared to fail the Task 8 check"
    );
    let (probe, tool_directory) = native_sandbox_probe();
    let cgroup_root = native_env_path("FLUXFORM_TEST_CGROUP_ROOT");
    let root = tempfile::tempdir().unwrap();
    let address = unused_public_address();
    let stderr_path = root.path().join("server-stderr.log");
    let stderr = fs::File::create(&stderr_path).unwrap();
    let mut child = ChildGuard(launch_native_server(
        root.path().join("server-data").as_path(),
        address,
        &cgroup_root,
        &cgroup_root,
        &probe,
        &tool_directory,
        Stdio::from(stderr),
    ));
    let status = wait_for_process_exit(&mut child, Duration::from_secs(45));
    assert!(
        !status.success(),
        "unavailable network/seccomp must reject Public startup"
    );
    let diagnostic = fs::read_to_string(stderr_path).unwrap();
    assert!(
        diagnostic.contains("Network") || diagnostic.contains("PrivateNamespace"),
        "expected Task 8-specific diagnostic, got: {diagnostic}"
    );
    assert_port_available(address);
}

#[cfg(target_os = "linux")]
fn native_env_path(name: &str) -> std::path::PathBuf {
    std::env::var_os(name)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| panic!("BLOCKED: set {name} to the delegated Linux test input"))
}

#[cfg(target_os = "linux")]
fn native_sandbox_probe() -> (std::path::PathBuf, std::path::PathBuf) {
    use sha2::{Digest, Sha256};

    let probe = native_env_path("FLUXFORM_SERVER_SANDBOX_PROBE");
    let tool_directory = native_env_path("FLUXFORM_SERVER_SANDBOX_TOOL_DIR");
    let expected_sha256 = native_env_string("FLUXFORM_TEST_SANDBOX_PROBE_SHA256");
    assert!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "BLOCKED: Task 7 probe SHA-256 must be 64 lowercase hexadecimal characters"
    );
    let actual_sha256 = Sha256::digest(fs::read(&probe).unwrap_or_else(|error| {
        panic!("BLOCKED: cannot read packaged Task 7 probe binary: {error}")
    }))
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect::<String>();
    assert_eq!(
        actual_sha256, expected_sha256,
        "BLOCKED: packaged Task 7 probe identity is stale or wrong"
    );
    (probe, tool_directory)
}

#[cfg(target_os = "linux")]
fn launch_native_server(
    data_dir: &std::path::Path,
    address: SocketAddr,
    delegated_cgroup_root: &std::path::Path,
    service_cgroup_root: &std::path::Path,
    probe: &std::path::Path,
    tool_directory: &std::path::Path,
    stderr: Stdio,
) -> Child {
    use std::fs::OpenOptions;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let service_procs_path = service_cgroup_root.join("service/cgroup.procs");
    let service_processes = fs::read_to_string(&service_procs_path).unwrap_or_else(|error| {
        panic!("BLOCKED: cannot inspect the exclusive service cgroup leaf: {error}")
    });
    assert!(
        service_processes.trim().is_empty(),
        "BLOCKED: native harness must run outside the dedicated service cgroup leaf"
    );
    let service_procs = OpenOptions::new()
        .write(true)
        .open(&service_procs_path)
        .unwrap_or_else(|error| {
            panic!("BLOCKED: cannot open service cgroup.procs for process placement: {error}")
        });
    let mut command = native_server_command(
        data_dir,
        address,
        delegated_cgroup_root,
        probe,
        tool_directory,
        stderr,
    );
    // `pre_exec` runs after fork but before the server code. Only async-signal-
    // safe getpid/write operations are used so the management leaf contains
    // exactly the service process before Task 9 inspects it.
    unsafe {
        command.pre_exec(move || {
            let mut digits = [0_u8; 16];
            let mut position = digits.len();
            let mut pid = unsafe { libc::getpid() as u32 };
            loop {
                position -= 1;
                digits[position] = b'0' + (pid % 10) as u8;
                pid /= 10;
                if pid == 0 {
                    break;
                }
            }
            position -= 1;
            digits[position] = b'\n';
            let bytes = &digits[position..];
            let written = unsafe {
                libc::write(
                    service_procs.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                )
            };
            if written != bytes.len() as isize {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().unwrap()
}

#[cfg(target_os = "linux")]
fn native_server_command(
    data_dir: &std::path::Path,
    address: SocketAddr,
    cgroup_root: &std::path::Path,
    probe: &std::path::Path,
    tool_directory: &std::path::Path,
    stderr: Stdio,
) -> Command {
    Command::new(native_server_binary())
        .env("FLUXFORM_SERVER_MODE", "public")
        .env("FLUXFORM_SERVER_LISTEN", address.to_string())
        .env("FLUXFORM_SERVER_DATA_DIR", data_dir)
        .env("FLUXFORM_SERVER_SECRET", "6d".repeat(32))
        .env("FLUXFORM_PUBLIC_ORIGIN", "https://fluxform.test")
        .env("FLUXFORM_SERVER_DELEGATED_CGROUP_ROOT", cgroup_root)
        .env("FLUXFORM_SERVER_SANDBOX_PROBE", probe)
        .env("FLUXFORM_SERVER_SANDBOX_TOOL_DIR", tool_directory)
        .env(
            "FLUXFORM_SERVER_SANDBOX_PROBE_SHA256",
            native_env_string("FLUXFORM_TEST_SANDBOX_PROBE_SHA256"),
        )
        // Debug builds reject this native-evidence launch; release builds
        // compile the test-only rejection hook out.
        .env("FLUXFORM_TEST_REQUIRE_RELEASE", "1")
        .env_remove("FLUXFORM_TEST_FORCE_SANDBOX_FAILURE")
        .env_remove("FLUXFORM_TEST_SANDBOX_READY_FILE")
        .env_remove("FLUXFORM_TEST_SANDBOX_RELEASE_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr)
}

#[cfg(target_os = "linux")]
fn native_server_binary() -> std::path::PathBuf {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command as GitCommand;

    let binary = native_env_path("FLUXFORM_TEST_SERVER_BINARY");
    assert_eq!(
        binary.file_name(),
        Some(std::ffi::OsStr::new("fluxform-server-probe")),
        "native process proof requires the packaged fluxform-server-probe binary"
    );
    let binary_metadata = fs::symlink_metadata(&binary)
        .unwrap_or_else(|error| panic!("BLOCKED: cannot inspect packaged server binary: {error}"));
    assert!(
        binary_metadata.is_file() && !binary_metadata.file_type().is_symlink(),
        "BLOCKED: packaged server binary must be a regular non-symlink file"
    );
    assert_ne!(
        binary_metadata.permissions().mode() & 0o111,
        0,
        "BLOCKED: packaged server binary is not executable"
    );
    let expected_sha256 = native_env_string("FLUXFORM_TEST_SERVER_SHA256");
    assert!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "BLOCKED: server SHA-256 identity must be 64 lowercase hexadecimal characters"
    );
    let actual_sha256 = Sha256::digest(fs::read(&binary).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    assert_eq!(
        actual_sha256, expected_sha256,
        "BLOCKED: packaged server binary identity is stale or wrong"
    );

    let runner_os = native_env_string("FLUXFORM_TEST_RUNNER_OS");
    let runner_arch = native_env_string("FLUXFORM_TEST_RUNNER_ARCH");
    let target_triple = native_env_string("FLUXFORM_TEST_TARGET_TRIPLE");
    assert_eq!(runner_os, std::env::consts::OS);
    assert_eq!(runner_arch, std::env::consts::ARCH);
    assert_eq!(runner_os, "linux");
    let expected_triple = match runner_arch.as_str() {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        _ => panic!("BLOCKED: unsupported Task 7/8/9 native runner architecture"),
    };
    assert_eq!(target_triple, expected_triple, "wrong-host target identity");

    let repository_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap();
    let commit = GitCommand::new("git")
        .current_dir(repository_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap_or_else(|error| panic!("BLOCKED: git identity check could not run: {error}"));
    assert!(
        commit.status.success(),
        "BLOCKED: git identity check failed"
    );
    let commit = String::from_utf8(commit.stdout).unwrap().trim().to_owned();
    assert_eq!(
        native_env_string("FLUXFORM_TEST_GIT_COMMIT"),
        commit,
        "BLOCKED: native process evidence is stale for this checkout"
    );
    binary
}

#[cfg(target_os = "linux")]
fn native_env_string(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("BLOCKED: set {name} for native evidence identity"))
}

#[cfg(target_os = "linux")]
fn unused_public_address() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], unused_loopback_address().port()))
}

#[cfg(target_os = "linux")]
fn loopback_for(address: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], address.port()))
}

#[cfg(target_os = "linux")]
fn assert_port_available(address: SocketAddr) {
    let listener =
        TcpListener::bind(address).expect("failed startup must leave the port unclaimed");
    listener.set_nonblocking(true).unwrap();
    let client = TcpStream::connect(loopback_for(address))
        .expect("test harness must connect to the still-available port");
    let _accepted = listener.accept().unwrap().0;
    drop(client);
}

#[cfg(target_os = "linux")]
fn wait_for_process_exit(child: &mut ChildGuard, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.0.kill();
            let _ = child.0.wait();
            panic!(
                "server process did not fail within {timeout:?}; it may have bound the Public listener"
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(debug_assertions)]
#[test]
fn forced_public_checker_failure_leaves_the_reserved_port_available_while_process_runs() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let ready = root.path().join("checker-ready");
    let release = root.path().join("checker-release");
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_fluxform-server-probe"))
            .env("FLUXFORM_SERVER_MODE", "public")
            .env("FLUXFORM_SERVER_LISTEN", address.to_string())
            .env("FLUXFORM_SERVER_DATA_DIR", root.path().join("server-data"))
            .env("FLUXFORM_SERVER_SECRET", "6d".repeat(32))
            .env(
                "FLUXFORM_SERVER_DELEGATED_CGROUP_ROOT",
                root.path().join("cgroup"),
            )
            .env(
                "FLUXFORM_SERVER_SANDBOX_PROBE",
                root.path().join("tools").join("sandbox-child"),
            )
            .env(
                "FLUXFORM_SERVER_SANDBOX_TOOL_DIR",
                root.path().join("tools"),
            )
            .env("FLUXFORM_SERVER_SANDBOX_PROBE_SHA256", "0".repeat(64))
            .env("FLUXFORM_TEST_FORCE_SANDBOX_FAILURE", "filesystem")
            .env("FLUXFORM_TEST_SANDBOX_READY_FILE", &ready)
            .env("FLUXFORM_TEST_SANDBOX_RELEASE_FILE", &release)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(ready.exists(), "forced checker did not reach its barrier");

    let listener =
        TcpListener::bind(address).expect("server must not have bound before checks pass");
    listener.set_nonblocking(true).unwrap();
    let client = TcpStream::connect(address).expect("reserved port must accept the harness");
    let _accepted = listener.accept().unwrap().0;
    drop(client);

    fs::write(&release, b"release failure").unwrap();
    let status = child.0.wait().unwrap();
    assert!(
        !status.success(),
        "forced sandbox failure must stop startup"
    );
}

#[cfg(debug_assertions)]
#[test]
fn debug_server_binary_is_rejected_for_native_public_startup_evidence() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let output = Command::new(env!("CARGO_BIN_EXE_fluxform-server-probe"))
        .env("FLUXFORM_SERVER_MODE", "public")
        .env("FLUXFORM_SERVER_LISTEN", address.to_string())
        .env("FLUXFORM_SERVER_DATA_DIR", root.path().join("server-data"))
        .env("FLUXFORM_SERVER_SECRET", "6d".repeat(32))
        .env(
            "FLUXFORM_SERVER_DELEGATED_CGROUP_ROOT",
            root.path().join("delegated-cgroup"),
        )
        .env(
            "FLUXFORM_SERVER_SANDBOX_PROBE",
            root.path().join("tools").join("sandbox-child"),
        )
        .env(
            "FLUXFORM_SERVER_SANDBOX_TOOL_DIR",
            root.path().join("tools"),
        )
        .env("FLUXFORM_SERVER_SANDBOX_PROBE_SHA256", "0".repeat(64))
        .env("FLUXFORM_TEST_REQUIRE_RELEASE", "1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("release-built server executable"));
    assert!(TcpListener::bind(address).is_ok());
}
