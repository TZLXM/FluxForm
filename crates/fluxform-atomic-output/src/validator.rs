use crate::{FileIdentity, OutputExpectation, ValidationError, file_identity};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
#[cfg(test)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Child;
#[cfg(windows)]
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const MAX_STDOUT_BYTES: usize = 1024 * 1024;
const MAX_STDERR_BYTES: usize = 128 * 1024;
const FFPROBE_TIMEOUT: Duration = Duration::from_secs(20);

#[cfg(test)]
type BeforeFfprobeSpawnHook = Box<dyn FnOnce(&Path)>;

#[cfg(test)]
thread_local! {
    static BEFORE_FFPROBE_SPAWN: std::cell::RefCell<Option<BeforeFfprobeSpawnHook>> =
        const { std::cell::RefCell::new(None) };
}

/// Validates a partial output against the media contract derived from the
/// approved manifest edge and sample catalog.
pub trait OutputValidator: Send + Sync {
    fn validate(
        &self,
        partial_path: &Path,
        expectation: &OutputExpectation,
    ) -> Result<(), ValidationError>;
}

/// A no-shell FFprobe runner with fixed argv, bounded capture, and timeout.
pub struct FfprobeOutputValidator {
    ffprobe_path: PathBuf,
    protocol_whitelist: &'static str,
    fingerprint: ExecutableFingerprint,
    approved_file: std::sync::Mutex<File>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExecutableFingerprint {
    identity: FileIdentity,
    sha256: [u8; 32],
}

impl FfprobeOutputValidator {
    pub fn new(
        ffprobe_path: impl AsRef<Path>,
        protocol_whitelist: &str,
    ) -> Result<Self, ValidationError> {
        let requested = protocol_whitelist
            .split(',')
            .map(str::trim)
            .collect::<BTreeSet<_>>();
        let permitted = BTreeSet::from(["file", "pipe"]);
        if requested != permitted {
            return Err(ValidationError::Rejected(
                "FFprobe protocol whitelist must be exactly file,pipe".to_owned(),
            ));
        }
        let ffprobe_path = ffprobe_path.as_ref();
        let approved_file = open_executable_candidate(ffprobe_path).map_err(|error| {
            ValidationError::Rejected(format!("cannot approve FFprobe candidate: {error}"))
        })?;
        let fingerprint = executable_fingerprint(&approved_file).map_err(|error| {
            ValidationError::Rejected(format!("cannot fingerprint FFprobe candidate: {error}"))
        })?;
        Ok(Self {
            ffprobe_path: ffprobe_path.to_path_buf(),
            protocol_whitelist: "file,pipe",
            fingerprint,
            approved_file: std::sync::Mutex::new(approved_file),
        })
    }

    fn verify_candidate(&self, approved_file: &File) -> Result<(), ValidationError> {
        match executable_fingerprint(approved_file) {
            Ok(current) if current == self.fingerprint => Ok(()),
            _ => Err(ValidationError::ExecutableChanged),
        }
    }

    fn spawn_candidate(&self, arguments: Vec<String>) -> Result<Child, ValidationError> {
        let approved_file = self
            .approved_file
            .lock()
            .expect("approved FFprobe file mutex poisoned");
        self.verify_candidate(&approved_file)?;
        #[cfg(test)]
        BEFORE_FFPROBE_SPAWN.with(|hook| {
            if let Some(hook) = hook.borrow_mut().take() {
                hook(&self.ffprobe_path);
            }
        });

        #[cfg(windows)]
        {
            Command::new(&self.ffprobe_path)
                .args(arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|error| ValidationError::Ffprobe(error.to_string()))
        }
        #[cfg(not(windows))]
        {
            let _ = (approved_file, arguments);
            Err(ValidationError::PlatformBlocked)
        }
    }

    fn arguments(&self, partial_path: &Path) -> Vec<String> {
        vec![
            "-v".to_owned(),
            "error".to_owned(),
            "-protocol_whitelist".to_owned(),
            self.protocol_whitelist.to_owned(),
            "-count_frames".to_owned(),
            "-show_format".to_owned(),
            "-show_streams".to_owned(),
            "-of".to_owned(),
            "json".to_owned(),
            "-i".to_owned(),
            partial_path.as_os_str().to_string_lossy().into_owned(),
        ]
    }

    fn probe(&self, partial_path: &Path) -> Result<Value, ValidationError> {
        let mut child = self.spawn_candidate(self.arguments(partial_path))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| ValidationError::Ffprobe("FFprobe stdout was unavailable".to_owned()))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| ValidationError::Ffprobe("FFprobe stderr was unavailable".to_owned()))?;
        let output_limited = Arc::new(AtomicBool::new(false));
        let stdout_limited = output_limited.clone();
        let stdout_reader =
            thread::spawn(move || read_bounded(stdout, MAX_STDOUT_BYTES, stdout_limited));
        let stderr_limited = output_limited.clone();
        let stderr_reader =
            thread::spawn(move || read_bounded(stderr, MAX_STDERR_BYTES, stderr_limited));

        let started = Instant::now();
        let status = loop {
            if output_limited.load(Ordering::Acquire) {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if started.elapsed() < FFPROBE_TIMEOUT => {
                    thread::sleep(Duration::from_millis(10));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(ValidationError::Timeout);
                }
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stdout_reader.join();
                    let _ = stderr_reader.join();
                    return Err(ValidationError::Ffprobe(error.to_string()));
                }
            }
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| ValidationError::Ffprobe("FFprobe stdout reader panicked".to_owned()))?
            .map_err(|error| {
                if error.kind() == io::ErrorKind::FileTooLarge {
                    ValidationError::OutputLimit
                } else {
                    ValidationError::Ffprobe(error.to_string())
                }
            })?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| ValidationError::Ffprobe("FFprobe stderr reader panicked".to_owned()))?
            .map_err(|error| {
                if error.kind() == io::ErrorKind::FileTooLarge {
                    ValidationError::OutputLimit
                } else {
                    ValidationError::Ffprobe(error.to_string())
                }
            })?;
        let status = status.ok_or(ValidationError::OutputLimit)?;
        if !status.success() {
            return Err(ValidationError::Ffprobe(format!(
                "exit status {status}: {}",
                String::from_utf8_lossy(&stderr)
            )));
        }
        serde_json::from_slice(&stdout)
            .map_err(|error| ValidationError::Ffprobe(format!("invalid FFprobe JSON: {error}")))
    }
}

fn open_executable_candidate(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        // Leave read sharing enabled for CreateProcess image loading; denying
        // write/delete sharing pins the approved path through spawn.
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        options.share_mode(FILE_SHARE_READ);
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FFprobe candidate must be a regular non-reparse file",
            ));
        }
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "FFprobe candidate must be a regular file",
            ));
        }
        Ok(file)
    }
}

fn executable_fingerprint(file: &File) -> io::Result<ExecutableFingerprint> {
    let identity = file_identity(file)?;
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let sha256 = hasher.finalize().into();
    Ok(ExecutableFingerprint { identity, sha256 })
}

impl OutputValidator for FfprobeOutputValidator {
    fn validate(
        &self,
        partial_path: &Path,
        expectation: &OutputExpectation,
    ) -> Result<(), ValidationError> {
        let probe = self.probe(partial_path)?;
        validate_probe(&probe, expectation)
    }
}

fn read_bounded(
    mut reader: impl Read,
    limit: usize,
    overflow: Arc<AtomicBool>,
) -> io::Result<Vec<u8>> {
    let mut buffer = Vec::with_capacity(limit.min(16 * 1024));
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        let remaining = limit.saturating_add(1).saturating_sub(buffer.len());
        if remaining == 0 {
            overflow.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "capture limit exceeded",
            ));
        }
        let chunk_len = chunk.len();
        let read = reader.read(&mut chunk[..chunk_len.min(remaining)])?;
        if read == 0 {
            return Ok(buffer);
        }
        buffer.extend_from_slice(&chunk[..read]);
        if buffer.len() > limit {
            overflow.store(true, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "capture limit exceeded",
            ));
        }
    }
}

fn validate_probe(probe: &Value, expected: &OutputExpectation) -> Result<(), ValidationError> {
    let format = probe
        .get("format")
        .and_then(Value::as_object)
        .ok_or_else(|| ValidationError::Rejected("FFprobe omitted format metadata".to_owned()))?;
    let streams = probe
        .get("streams")
        .and_then(Value::as_array)
        .ok_or_else(|| ValidationError::Rejected("FFprobe omitted stream metadata".to_owned()))?;
    let format_name = format
        .get("format_name")
        .and_then(Value::as_str)
        .ok_or_else(|| ValidationError::Rejected("FFprobe omitted format_name".to_owned()))?;
    if !container_matches(&expected.container, format_name) {
        return reject(format!(
            "container mismatch: expected {}, observed {format_name}",
            expected.container
        ));
    }

    let mut codecs = Vec::with_capacity(streams.len());
    let mut stream_types = Vec::with_capacity(streams.len());
    let mut video_dimensions = Vec::new();
    let mut alpha_present = false;
    let mut orientation_present = false;
    let mut metadata_keys = BTreeSet::new();
    collect_user_metadata(format.get("tags"), &mut metadata_keys);
    for stream in streams {
        let stream = stream.as_object().ok_or_else(|| {
            ValidationError::Rejected("FFprobe stream entry is not an object".to_owned())
        })?;
        let codec_type = required_string(stream.get("codec_type"), "codec_type")?;
        let codec_name = required_string(stream.get("codec_name"), "codec_name")?;
        stream_types.push(codec_type.to_ascii_lowercase());
        codecs.push(normalize_output_codec(&codec_name));
        collect_user_metadata(stream.get("tags"), &mut metadata_keys);
        if codec_type.eq_ignore_ascii_case("video") {
            let width = required_u32(stream.get("width"), "width")?;
            let height = required_u32(stream.get("height"), "height")?;
            video_dimensions.push((width, height));
            alpha_present |= pixel_format_has_alpha(
                stream
                    .get("pix_fmt")
                    .and_then(Value::as_str)
                    .unwrap_or_default(),
            );
            orientation_present |= stream_has_orientation(stream);
        }
    }

    let expected_types = expected
        .stream_map
        .iter()
        .map(|mapping| match mapping.as_str() {
            "0:v:0" => "video".to_owned(),
            "0:a:0" => "audio".to_owned(),
            _ => String::new(),
        })
        .collect::<Vec<_>>();
    if expected_types.iter().any(String::is_empty) || stream_types != expected_types {
        return reject(format!(
            "stream map mismatch: expected {expected_types:?}, observed {stream_types:?}"
        ));
    }
    let topology = topology_for_streams(&stream_types, streams, &expected.stream_topology)?;
    if topology != expected.stream_topology {
        return reject(format!(
            "stream topology mismatch: expected {}, observed {topology}",
            expected.stream_topology
        ));
    }
    codecs.sort_unstable();
    let mut expected_codecs = expected
        .codecs
        .iter()
        .map(|codec| normalize_output_codec(codec))
        .collect::<Vec<_>>();
    expected_codecs.sort_unstable();
    if codecs != expected_codecs {
        return reject(format!(
            "codec mismatch: expected {expected_codecs:?}, observed {codecs:?}"
        ));
    }

    let (width, height) = video_dimensions.first().copied().unwrap_or((0, 0));
    if width != expected.width || height != expected.height {
        return reject(format!(
            "dimensions mismatch: expected {}x{}, observed {width}x{height}",
            expected.width, expected.height
        ));
    }
    if width > expected.max_width || height > expected.max_height {
        return reject(format!(
            "dimensions exceed {}x{} bound",
            expected.max_width, expected.max_height
        ));
    }
    let duration_ms = format
        .get("duration")
        .and_then(value_duration_ms)
        .unwrap_or(0);
    if expected.expected_duration_ms > 0
        && duration_ms.abs_diff(expected.expected_duration_ms) > expected.duration_tolerance_ms
    {
        return reject(format!(
            "duration {duration_ms} ms differs from expected {} ms by more than {} ms",
            expected.expected_duration_ms, expected.duration_tolerance_ms
        ));
    }
    if duration_ms > expected.max_duration_ms {
        return reject(format!(
            "duration {duration_ms} ms exceeds {} ms bound",
            expected.max_duration_ms
        ));
    }
    if let Some(expected_alpha) = expected.expected_alpha
        && alpha_present != expected_alpha
    {
        return reject(format!(
            "alpha mismatch: expected {expected_alpha}, observed {alpha_present}"
        ));
    }
    if let Some(expected_orientation) = expected.expected_orientation
        && orientation_present != expected_orientation
    {
        return reject(format!(
            "orientation mismatch: expected {expected_orientation}, observed {orientation_present}"
        ));
    }
    match expected.metadata_policy.as_str() {
        "strip" => {
            if !metadata_keys.is_empty() {
                return reject(format!("stripped metadata remains: {metadata_keys:?}"));
            }
        }
        "safe_image_metadata" => {
            if metadata_keys
                .iter()
                .any(|key| !matches!(key.as_str(), "orientation" | "icc_profile"))
            {
                return reject(format!("unsafe image metadata remains: {metadata_keys:?}"));
            }
        }
        "preserve" => {
            if expected
                .expected_metadata_present
                .is_some_and(|present| present == metadata_keys.is_empty())
            {
                return reject("preserved metadata presence does not match the sample".to_owned());
            }
        }
        _ => return reject("unknown metadata policy".to_owned()),
    }
    Ok(())
}

fn collect_user_metadata(tags: Option<&Value>, target: &mut BTreeSet<String>) {
    let Some(tags) = tags.and_then(Value::as_object) else {
        return;
    };
    for (key, value) in tags {
        if is_non_user_metadata_tag(key, value.as_str().unwrap_or_default()) {
            continue;
        }
        target.insert(key.to_ascii_lowercase());
    }
}

fn is_non_user_metadata_tag(key: &str, value: &str) -> bool {
    match key.to_ascii_lowercase().as_str() {
        "encoder" | "major_brand" | "minor_version" | "compatible_brands" | "handler_name"
        | "vendor_id" => true,
        "language" => value.eq_ignore_ascii_case("und"),
        _ => false,
    }
}

fn container_matches(expected: &str, actual: &str) -> bool {
    let names = actual
        .split(',')
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    match expected.to_ascii_lowercase().as_str() {
        "m4a" => names
            .iter()
            .any(|name| ["m4a", "mp4", "mov"].contains(&name.as_str())),
        "mp4" => names
            .iter()
            .any(|name| ["mp4", "mov"].contains(&name.as_str())),
        "jpeg" | "jpg" => names
            .iter()
            .any(|name| ["jpeg_pipe", "image2", "jpeg"].contains(&name.as_str())),
        "png" => names
            .iter()
            .any(|name| ["png_pipe", "image2", "png"].contains(&name.as_str())),
        "webp" => names
            .iter()
            .any(|name| ["webp_pipe", "webp"].contains(&name.as_str())),
        "tiff" | "tif" => names
            .iter()
            .any(|name| ["tiff_pipe", "tiff"].contains(&name.as_str())),
        "gif" => names.contains("gif"),
        _ => names.contains(&expected.to_ascii_lowercase()),
    }
}

fn normalize_output_codec(codec: &str) -> String {
    match codec.to_ascii_lowercase().as_str() {
        "libx264" | "h264" => "h264".to_owned(),
        "libx265" | "hevc" => "hevc".to_owned(),
        "libmp3lame" => "mp3".to_owned(),
        "libwebp" | "libwebp_anim" => "webp".to_owned(),
        other => other.to_owned(),
    }
}

fn topology_for_streams(
    stream_types: &[String],
    streams: &[Value],
    expected: &str,
) -> Result<String, ValidationError> {
    match stream_types {
        [video] if video == "video" && expected == "single_video_frame" => {
            let frames = streams[0]
                .get("nb_read_frames")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u64>().ok())
                .unwrap_or(0);
            if frames != 1 {
                return reject(format!(
                    "single-frame output must contain exactly one decoded frame, observed {frames}"
                ));
            }
            Ok("single_video_frame".to_owned())
        }
        [video] if video == "video" => Ok("single_video_stream".to_owned()),
        [audio] if audio == "audio" => Ok("single_audio_stream".to_owned()),
        [video, audio] if video == "video" && audio == "audio" => {
            Ok("single_video_and_audio".to_owned())
        }
        _ => Ok("unsupported".to_owned()),
    }
}

fn value_duration_ms(value: &Value) -> Option<u64> {
    let seconds = value
        .as_str()
        .and_then(|value| value.parse::<f64>().ok())
        .or_else(|| value.as_f64())?;
    if !seconds.is_finite() || seconds < 0.0 {
        return None;
    }
    Some((seconds * 1000.0).round().min(u64::MAX as f64) as u64)
}

fn required_string(value: Option<&Value>, name: &str) -> Result<String, ValidationError> {
    value
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| ValidationError::Rejected(format!("FFprobe omitted {name}")))
}

fn required_u32(value: Option<&Value>, name: &str) -> Result<u32, ValidationError> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| ValidationError::Rejected(format!("FFprobe omitted or invalid {name}")))
}

fn pixel_format_has_alpha(pixel_format: &str) -> bool {
    let pixel_format = pixel_format.to_ascii_lowercase();
    [
        "rgba", "bgra", "argb", "abgr", "yuva", "gbrap", "ya8", "ya16",
    ]
    .iter()
    .any(|marker| pixel_format.contains(marker))
}

fn stream_has_orientation(stream: &serde_json::Map<String, Value>) -> bool {
    if stream
        .get("tags")
        .and_then(Value::as_object)
        .is_some_and(|tags| tags.keys().any(|key| key.eq_ignore_ascii_case("rotate")))
    {
        return true;
    }
    stream
        .get("side_data_list")
        .and_then(Value::as_array)
        .is_some_and(|items| {
            items.iter().any(|item| {
                item.get("rotation")
                    .and_then(Value::as_f64)
                    .is_some_and(|rotation| rotation != 0.0)
            })
        })
}

fn reject<T>(message: String) -> Result<T, ValidationError> {
    Err(ValidationError::Rejected(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn expectation() -> OutputExpectation {
        OutputExpectation {
            edge_id: "test.image".to_owned(),
            container: "png".to_owned(),
            codecs: vec!["png".to_owned()],
            stream_topology: "single_video_frame".to_owned(),
            stream_map: vec!["0:v:0".to_owned()],
            width: 1,
            height: 1,
            max_width: 1,
            max_height: 1,
            expected_duration_ms: 0,
            duration_tolerance_ms: 0,
            max_duration_ms: 0,
            alpha_policy: "preserve_if_present".to_owned(),
            orientation_policy: "apply_to_pixels".to_owned(),
            metadata_policy: "strip".to_owned(),
            expected_alpha: None,
            expected_orientation: None,
            expected_metadata_present: Some(false),
        }
    }

    fn valid_png_probe() -> Value {
        serde_json::json!({
            "format": { "format_name": "png_pipe" },
            "streams": [{
                "codec_type": "video",
                "codec_name": "png",
                "width": 1,
                "height": 1,
                "pix_fmt": "rgba",
                "nb_read_frames": "1"
            }]
        })
    }

    #[test]
    fn bounded_capture_accepts_exact_limit_and_rejects_one_byte_over() {
        let flag = Arc::new(AtomicBool::new(false));
        assert_eq!(
            read_bounded(Cursor::new(b"1234"), 4, flag.clone()).expect("exact limit"),
            b"1234"
        );
        assert!(!flag.load(Ordering::Acquire));

        let error =
            read_bounded(Cursor::new(b"12345"), 4, flag.clone()).expect_err("capture over limit");
        assert_eq!(error.kind(), io::ErrorKind::FileTooLarge);
        assert!(flag.load(Ordering::Acquire));
    }

    #[test]
    fn ffprobe_whitelist_must_be_exactly_file_and_pipe_and_argv_is_fixed() {
        let executable = std::env::current_exe().expect("test executable");
        let validator =
            FfprobeOutputValidator::new(&executable, "pipe,file").expect("permitted whitelist set");
        assert!(FfprobeOutputValidator::new(&executable, "file").is_err());
        assert!(FfprobeOutputValidator::new(&executable, "file,pipe,tcp").is_err());
        assert_eq!(
            validator.arguments(Path::new("partial output.png")),
            [
                "-v",
                "error",
                "-protocol_whitelist",
                "file,pipe",
                "-count_frames",
                "-show_format",
                "-show_streams",
                "-of",
                "json",
                "-i",
                "partial output.png"
            ]
        );
    }

    #[cfg(windows)]
    #[test]
    fn replacing_ffprobe_candidate_before_validation_is_denied_by_retained_handle() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let candidate = temporary.path().join("ffprobe-candidate.exe");
        let original = temporary.path().join("approved-original.exe");
        fs::copy(
            std::env::current_exe().expect("test executable"),
            &candidate,
        )
        .expect("create candidate executable");
        let validator =
            FfprobeOutputValidator::new(&candidate, "file,pipe").expect("approved candidate");

        let replacement = fs::rename(&candidate, &original);
        assert!(
            replacement.is_err(),
            "the retained FFprobe handle must deny replacement"
        );
        assert!(candidate.exists(), "approved executable path must remain");
        assert_eq!(validator.ffprobe_path, candidate);
    }

    #[cfg(unix)]
    #[test]
    fn ffprobe_execution_is_blocked_without_handle_bound_process_creation() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let executable = std::env::current_exe().expect("test executable");
        let validator =
            FfprobeOutputValidator::new(&executable, "file,pipe").expect("candidate handle");
        let partial = temporary.path().join("input.png");
        fs::write(&partial, b"input bytes").expect("input file");

        assert!(matches!(
            validator.validate(&partial, &expectation()),
            Err(ValidationError::PlatformBlocked)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn replacement_after_fingerprint_before_spawn_is_denied_and_approved_image_runs() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let candidate = temporary.path().join("ffprobe-candidate.exe");
        let moved = temporary.path().join("attacker-moved-approved.exe");
        let partial = temporary.path().join("input.png");
        fs::copy(
            std::env::current_exe().expect("test executable"),
            &candidate,
        )
        .expect("create candidate executable");
        fs::write(&partial, b"input bytes").expect("input file");
        let validator =
            FfprobeOutputValidator::new(&candidate, "file,pipe").expect("approved candidate");
        let hook_entered = Arc::new(AtomicBool::new(false));
        let replacement_succeeded = Arc::new(AtomicBool::new(false));
        let hook_entered_from_hook = hook_entered.clone();
        let replacement_succeeded_from_hook = replacement_succeeded.clone();
        let moved_from_hook = moved.clone();
        BEFORE_FFPROBE_SPAWN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |verified_path| {
                hook_entered_from_hook.store(true, Ordering::Release);
                replacement_succeeded_from_hook.store(
                    fs::rename(verified_path, &moved_from_hook).is_ok(),
                    Ordering::Release,
                );
            }));
        });

        let result = validator.validate(&partial, &expectation());
        assert!(hook_entered.load(Ordering::Acquire));
        assert!(
            !replacement_succeeded.load(Ordering::Acquire),
            "replacement in the verify-to-spawn window must be denied by the retained handle"
        );
        assert!(
            !moved.exists(),
            "the attacker must not acquire the approved name"
        );
        assert!(candidate.exists(), "approved image must retain its path");
        let approved_file = validator
            .approved_file
            .lock()
            .expect("approved FFprobe file mutex");
        assert_eq!(
            executable_fingerprint(&approved_file).expect("retained image fingerprint"),
            validator.fingerprint
        );
        assert!(
            matches!(&result, Err(ValidationError::Ffprobe(message)) if message.starts_with("exit status")),
            "the approved test executable should be the image that was spawned: {result:?}"
        );
    }

    #[test]
    fn generated_probe_json_enforces_stream_topology_and_critical_properties() {
        let expected = expectation();
        let valid = valid_png_probe();
        validate_probe(&valid, &expected).expect("valid single frame PNG");

        let mut truncated = valid.clone();
        truncated["streams"][0]["nb_read_frames"] = Value::String("0".to_owned());
        assert!(validate_probe(&truncated, &expected).is_err());

        let mut mismatched = valid;
        mismatched["streams"][0]["width"] = Value::from(2);
        assert!(validate_probe(&mismatched, &expected).is_err());
    }
}
