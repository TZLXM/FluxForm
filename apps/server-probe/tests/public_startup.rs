use fluxform_server_probe::startup::{
    SandboxProbeConfig, ServerConfig, ServerMode, prepare_server,
};
#[cfg(any(target_os = "linux", debug_assertions))]
use std::fs;
#[cfg(any(target_os = "linux", debug_assertions))]
use std::net::TcpStream;
use std::net::{SocketAddr, TcpListener};
#[cfg(any(target_os = "linux", debug_assertions))]
use std::process::{Child, Command, Stdio};
#[cfg(any(target_os = "linux", debug_assertions))]
use std::thread;
#[cfg(any(target_os = "linux", debug_assertions))]
use std::time::{Duration, Instant};
use tempfile::TempDir;

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

#[tokio::test]
async fn explicit_local_development_binds_loopback_with_a_nonproduction_warning() {
    let root = tempfile::tempdir().unwrap();
    let address = unused_loopback_address();
    let prepared = prepare_server(config(&root, ServerMode::LocalDevelopment, address)).unwrap();

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
    let error = match prepare_server(config(&root, ServerMode::LocalDevelopment, address)) {
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
    use fluxform_server_probe::events::EventStore;
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
    let artifact_root = upload_root.join(".fluxform-artifacts");
    fs::create_dir(&artifact_root).unwrap();
    fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700)).unwrap();
    let database_path = data_dir.join("server.sqlite3");
    let events = EventStore::open(&database_path, &artifact_root).unwrap();
    let retain_until = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
        + 3600;
    events
        .register_state("startup-proof", "queued", retain_until)
        .unwrap();
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
    let (mut command, _verified_server) = native_server_command(
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
) -> (Command, std::fs::File) {
    use std::os::fd::AsRawFd;

    let verified_server = native_server_binary();
    let executable = format!("/proc/self/fd/{}", verified_server.as_raw_fd());
    let mut command = Command::new(executable);
    command
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
        .stderr(stderr);
    (command, verified_server)
}

#[cfg(target_os = "linux")]
fn native_server_binary() -> std::fs::File {
    use std::process::Command as GitCommand;

    let binary = native_env_path("FLUXFORM_TEST_SERVER_BINARY");
    assert_eq!(
        binary.file_name(),
        Some(std::ffi::OsStr::new("fluxform-server-probe")),
        "native process proof requires the packaged fluxform-server-probe binary"
    );
    let expected_sha256 = native_env_string("FLUXFORM_TEST_SERVER_SHA256");
    assert!(
        expected_sha256.len() == 64
            && expected_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "BLOCKED: server SHA-256 identity must be 64 lowercase hexadecimal characters"
    );
    let verified_binary =
        open_verified_executable(&binary, &expected_sha256).unwrap_or_else(|error| {
            panic!("BLOCKED: packaged server binary failed identity check: {error}")
        });

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
    verified_binary
}

#[cfg(target_os = "linux")]
fn open_verified_executable(
    path: &std::path::Path,
    expected_sha256: &str,
) -> std::io::Result<std::fs::File> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.mode() & 0o111 == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "verified executable must be a regular executable file",
        ));
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual_sha256 = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let after = file.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.ctime(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.ctime(),
    ) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "verified executable changed while its digest was checked",
        ));
    }
    if actual_sha256 != expected_sha256 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "verified executable digest is stale or wrong",
        ));
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
#[test]
fn verified_native_artifact_is_executed_from_its_retained_descriptor_after_name_replacement() {
    use sha2::{Digest, Sha256};
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let root = tempfile::tempdir().expect("temporary artifact root");
    let artifact_path = root.path().join("fluxform-server-probe");
    let source = std::env::current_exe().expect("current integration-test artifact");
    fs::copy(&source, &artifact_path).expect("copy artifact fixture");
    let expected_sha256 = Sha256::digest(fs::read(&artifact_path).expect("read fixture digest"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let verified = open_verified_executable(&artifact_path, &expected_sha256)
        .expect("open and verify exact artifact object");
    let original = verified.metadata().expect("verified descriptor metadata");

    fs::rename(&artifact_path, root.path().join("verified-original"))
        .expect("retain original under a different name");
    fs::write(
        &artifact_path,
        b"replacement is deliberately not executable",
    )
    .expect("replace the launch pathname");
    let replacement = fs::metadata(&artifact_path).expect("replacement metadata");
    assert_ne!(
        (original.dev(), original.ino()),
        (replacement.dev(), replacement.ino())
    );

    let executable = format!("/proc/self/fd/{}", verified.as_raw_fd());
    let output = Command::new(executable)
        .args(["--exact", "native_verified_exec_marker", "--nocapture"])
        .env("FLUXFORM_TEST_EXEC_MARKER", "1")
        .output()
        .expect("execute retained verified object");
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("retained-verified-object"));
}

#[cfg(target_os = "linux")]
#[test]
fn native_verified_exec_marker() {
    if std::env::var_os("FLUXFORM_TEST_EXEC_MARKER").is_some() {
        println!("retained-verified-object");
    }
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

#[cfg(any(target_os = "linux", debug_assertions))]
struct ChildGuard(Child);

#[cfg(any(target_os = "linux", debug_assertions))]
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
