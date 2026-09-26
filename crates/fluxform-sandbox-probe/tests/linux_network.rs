#![cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]

use fluxform_ffmpeg_profile::BuildProfile;
use fluxform_sandbox_probe::{
    FFPROBE_PROTOCOL_WHITELIST, NetworkPrerequisites, Sandbox, SandboxError, SandboxLimits,
    SandboxPolicy, SpawnPlacement,
};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct Fixture {
    _root: tempfile::TempDir,
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

fn run_network_probe(
    fixture: &Fixture,
    ipv4_port: u16,
    ipv6_port: u16,
    unix_socket_path: &Path,
) -> i32 {
    let (placement, mut ready, mut release) = barrier();
    let arguments = [
        OsString::from("probe-network"),
        OsString::from(ipv4_port.to_string()),
        OsString::from(ipv6_port.to_string()),
        unix_socket_path.as_os_str().to_owned(),
    ];
    let mut child =
        Sandbox::spawn_blocked(&fixture.child, &arguments, &fixture.policy(), placement)
            .expect("spawn under the network-isolated sandbox");

    let mut pid_bytes = [0; std::mem::size_of::<libc::pid_t>()];
    ready
        .read_exact(&mut pid_bytes)
        .expect("receive placement-ready pid");
    assert_eq!(
        libc::pid_t::from_ne_bytes(pid_bytes) as u32,
        child.id(),
        "ready signal is the blocked sandbox process"
    );
    release
        .write_all(&[1])
        .expect("release after placement confirmation");
    child
        .wait()
        .expect("wait for network probe")
        .code()
        .unwrap_or(128)
}

fn assert_no_connection(listener: &TcpListener) {
    match listener.accept() {
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok((stream, peer)) => panic!("sandbox connected to host listener from {peer}: {stream:?}"),
        Err(error) => panic!("could not inspect controlled listener: {error}"),
    }
}

#[test]
fn network_prerequisites_collect_active_controlled_probe_evidence() {
    let evidence = NetworkPrerequisites::inspect()
        .unwrap_or_else(|error| panic!("active Linux network probes failed: {error:?}"));

    assert!(evidence.all_passed(), "network evidence: {evidence:#?}");
    assert!(
        evidence
            .private_namespace_created
            .detail
            .contains("distinct network namespace")
    );
    assert!(
        evidence
            .ipv4_listener_isolated
            .detail
            .contains("zero connections")
    );
    assert!(
        evidence
            .ipv6_listener_isolated
            .detail
            .contains("zero connections")
    );
}

#[test]
fn sandbox_denies_inet_packet_and_namespace_escape_and_hides_host_unix_socket() {
    let ipv4_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind IPv4 listener");
    let ipv6_listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind IPv6 listener");
    ipv4_listener
        .set_nonblocking(true)
        .expect("make IPv4 listener nonblocking");
    ipv6_listener
        .set_nonblocking(true)
        .expect("make IPv6 listener nonblocking");

    let fixture = Fixture::new();
    let host_socket_path = fixture._root.path().join("host-control.sock");
    let _unix_listener = UnixListener::bind(&host_socket_path).expect("bind host Unix listener");

    assert_eq!(
        run_network_probe(
            &fixture,
            ipv4_listener.local_addr().expect("IPv4 address").port(),
            ipv6_listener.local_addr().expect("IPv6 address").port(),
            &host_socket_path,
        ),
        0,
        "probe child must observe configured seccomp denials and no Unix escape"
    );

    assert_no_connection(&ipv4_listener);
    assert_no_connection(&ipv6_listener);
}

#[test]
#[ignore = "BLOCKED: no approved Linux FFprobe artifact or native Linux runner is available"]
fn ffprobe_protocol_policy_rejects_urls() {
    let candidate =
        approved_linux_ffprobe_candidate().unwrap_or_else(|reason| panic!("BLOCKED: {reason}"));
    let sample = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/media/v1/files/audio-m4a-aac-lc-mono-v1.m4a");

    let local = Command::new(&candidate)
        .args([
            "-v",
            "error",
            "-protocol_whitelist",
            FFPROBE_PROTOCOL_WHITELIST,
            "-show_format",
            "-show_streams",
            "-of",
            "json",
        ])
        .arg(&sample)
        .stdin(Stdio::null())
        .output()
        .expect("run approved FFprobe against local sample");
    assert!(
        local.status.success(),
        "approved FFprobe rejected local sample: {}",
        String::from_utf8_lossy(&local.stderr)
    );

    let remote = Command::new(&candidate)
        .args([
            "-v",
            "error",
            "-protocol_whitelist",
            FFPROBE_PROTOCOL_WHITELIST,
            "-show_format",
            "-show_streams",
            "-of",
            "json",
            "http://127.0.0.1:9/blocked-input.m4a",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run approved FFprobe against blocked URL");
    let diagnostic = String::from_utf8_lossy(&remote.stderr).to_ascii_lowercase();
    assert!(!remote.status.success(), "HTTP URL unexpectedly accepted");
    assert!(
        diagnostic.contains("http") && diagnostic.contains("whitelist"),
        "HTTP denial did not come from the protocol whitelist: {diagnostic}"
    );
}

fn approved_linux_ffprobe_candidate() -> Result<PathBuf, String> {
    let profile_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/ffmpeg-profile.toml");
    let profile = fs::read_to_string(&profile_path)
        .map_err(|error| format!("could not read approved artifact profile: {error}"))?;
    let validated_profile = BuildProfile::load(&profile_path)
        .map_err(|error| format!("FFmpeg artifact profile failed validation: {error}"))?;
    if !validated_profile.gate_is_approved() {
        return Err("FFmpeg distribution gate is not approved".to_owned());
    }

    let target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-gnu",
        "aarch64" => "aarch64-unknown-linux-gnu",
        other => return Err(format!("unsupported Linux architecture {other}")),
    };
    let artifact = profile
        .split("[[artifacts]]")
        .skip(1)
        .find(|row| {
            toml_value(row, "status") == Some("approved")
                && toml_value(row, "target_triple") == Some(target)
        })
        .ok_or_else(|| format!("profile has no approved artifact for {target}"))?;
    let expected_hash = toml_value(artifact, "ffprobe_sha256")
        .ok_or_else(|| "approved artifact has no FFprobe hash".to_owned())?;
    let artifact_id = toml_value(artifact, "artifact_id")
        .ok_or_else(|| "approved artifact has no identity".to_owned())?;
    validated_profile
        .approved_artifact(artifact_id)
        .map_err(|error| format!("Linux FFprobe artifact is not approved: {error}"))?;
    let expected_size = toml_value(artifact, "ffprobe_size_bytes")
        .and_then(|size| size.parse::<u64>().ok())
        .ok_or_else(|| "approved artifact has no valid FFprobe size".to_owned())?;
    let candidate = std::env::var_os("FLUXFORM_APPROVED_LINUX_FFPROBE")
        .map(PathBuf::from)
        .ok_or_else(|| "FLUXFORM_APPROVED_LINUX_FFPROBE is not configured".to_owned())?;
    let mut file = File::open(&candidate)
        .map_err(|error| format!("could not open profile-matched FFprobe: {error}"))?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not fingerprint profile-matched FFprobe: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes += read as u64;
    }
    let actual_hash = digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if bytes != expected_size || actual_hash != expected_hash {
        return Err(
            "candidate FFprobe does not match the approved profile hash and size".to_owned(),
        );
    }
    Ok(candidate)
}

fn toml_value<'a>(table: &'a str, key: &str) -> Option<&'a str> {
    table.lines().find_map(|line| {
        let (candidate_key, value) = line.split_once('=')?;
        (candidate_key.trim() == key).then(|| value.trim().trim_matches('"'))
    })
}
