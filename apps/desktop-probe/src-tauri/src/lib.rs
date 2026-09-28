use hit_region::{HitRegionController, HitRegionStatus, WindowGeometryEvent};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use tauri::{
    AppHandle, DragDropEvent, Emitter, Manager, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
    WindowEvent,
};

mod hit_region;

const PROBE_MODES: [&str; 3] = [
    "transparent-orb",
    "transparent-window-with-rectangular-hit-region",
    "opaque-frameless-fallback",
];

const DISPLAY_SERVERS: [&str; 4] = ["windows", "macos", "x11", "wayland"];
const BACKGROUND_TARGET_LABEL: &str = "background-target";
const INSTALLED_PROVENANCE_FILE: &str = "installed-provenance.json";

static BACKGROUND_CLICK_COUNT: AtomicU64 = AtomicU64::new(0);
static BACKGROUND_DROP_COUNT: AtomicU64 = AtomicU64::new(0);

#[cfg(not(any(
    feature = "probe-transparent-orb",
    feature = "probe-transparent-window-with-rectangular-hit-region",
    feature = "probe-opaque-frameless-fallback"
)))]
compile_error!("exactly one desktop probe mode feature must be enabled");

#[cfg(any(
    all(
        feature = "probe-transparent-orb",
        feature = "probe-transparent-window-with-rectangular-hit-region"
    ),
    all(
        feature = "probe-transparent-orb",
        feature = "probe-opaque-frameless-fallback"
    ),
    all(
        feature = "probe-transparent-window-with-rectangular-hit-region",
        feature = "probe-opaque-frameless-fallback"
    )
))]
compile_error!("desktop probe mode features are mutually exclusive");

#[cfg(feature = "probe-transparent-orb")]
pub const PROBE_MODE: &str = "transparent-orb";
#[cfg(feature = "probe-transparent-window-with-rectangular-hit-region")]
pub const PROBE_MODE: &str = "transparent-window-with-rectangular-hit-region";
#[cfg(feature = "probe-opaque-frameless-fallback")]
pub const PROBE_MODE: &str = "opaque-frameless-fallback";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowProbeResult {
    pub probe_mode: String,
    pub os: String,
    pub os_version: String,
    pub display_server: String,
    pub installed_artifact_sha256: String,
    pub installed_executable_sha256: String,
    pub install_identity: String,
    pub provenance_verified: bool,
    pub provenance_error: String,
    pub installed_launch_path: String,
    pub native_hit_region_supported: bool,
    pub input_hit_region_status: String,
    pub network_disconnected: bool,
    pub first_launch_succeeded: bool,
    pub transparent_pixels_visible: bool,
    pub transparent_pixels_click_through: bool,
    pub frameless_drag_works: bool,
    pub file_drop_works: bool,
    pub outside_orb_drop_reached_background_target: bool,
    pub outside_orb_drop_reached_fluxform: bool,
    pub focus_recovery_works: bool,
    pub keyboard_input_works: bool,
    pub repeated_launch_created_second_window: bool,
    pub repeated_launch_backend_process_count: u32,
    pub single_window_close_works: bool,
    pub last_window_close_works: bool,
    pub dpi_change_works: bool,
    pub multi_monitor_move_works: bool,
    pub idle_cpu_percent: f32,
    pub idle_gpu_percent: f32,
    pub notes: String,
    pub passed: bool,
    pub webview_helper_process_count: u32,
}

impl WindowProbeResult {
    pub fn validate(&self) -> Result<(), &'static str> {
        if !PROBE_MODES.contains(&self.probe_mode.as_str()) {
            return Err("unknown probe mode");
        }
        if !DISPLAY_SERVERS.contains(&self.display_server.as_str()) {
            return Err("unknown display server");
        }
        if self.os.trim().is_empty() || self.os_version.trim().is_empty() {
            return Err("OS and OS version are required");
        }
        if self.installed_launch_path.trim().is_empty() {
            return Err("installed launch path is required");
        }
        if !is_sha256_hex(&self.installed_executable_sha256) {
            return Err("installed executable identity must be a SHA-256 hex digest");
        }
        if !self.installed_artifact_sha256.is_empty()
            && !is_sha256_hex(&self.installed_artifact_sha256)
        {
            return Err("installer package identity must be empty or a SHA-256 hex digest");
        }
        if self.provenance_verified
            && (!is_sha256_hex(&self.installed_artifact_sha256)
                || !is_install_identity(&self.install_identity))
        {
            return Err("verified provenance requires a package hash and install identity");
        }
        let valid_hit_region_status = [
            "pending",
            "circular-applied",
            "rectangular-fallback-unsupported",
            "rectangular-fallback-apply-failed",
            "failed-closed",
            "rectangular",
            "opaque",
            "unknown",
        ]
        .contains(&self.input_hit_region_status.as_str());
        if !valid_hit_region_status {
            return Err("unknown native input hit-region status");
        }
        if !self.idle_cpu_percent.is_finite()
            || self.idle_cpu_percent < 0.0
            || !self.idle_gpu_percent.is_finite()
            || self.idle_gpu_percent < 0.0
        {
            return Err("idle CPU and GPU percentages must be finite and non-negative");
        }
        if !self.passed {
            return Ok(());
        }
        if !self.provenance_verified {
            return Err("passing evidence requires a verified installed-package manifest");
        }

        let expected_hit_region_status = match self.probe_mode.as_str() {
            "transparent-orb" => "circular-applied",
            "transparent-window-with-rectangular-hit-region" => "rectangular",
            "opaque-frameless-fallback" => "opaque",
            _ => return Err("unknown probe mode"),
        };
        if !self.native_hit_region_supported
            || self.input_hit_region_status != expected_hit_region_status
        {
            return Err("passing result requires the selected native input hit region");
        }

        if self.repeated_launch_backend_process_count != 1 {
            return Err("repeated launch must use exactly one FluxForm backend process");
        }

        let common_behavior_passes = self.network_disconnected
            && self.first_launch_succeeded
            && self.frameless_drag_works
            && self.file_drop_works
            && self.focus_recovery_works
            && self.keyboard_input_works
            && self.repeated_launch_created_second_window
            && self.single_window_close_works
            && self.last_window_close_works
            && self.dpi_change_works
            && self.multi_monitor_move_works;
        if !common_behavior_passes {
            return Err("passing result is missing a required manual behavior");
        }

        let mode_behavior_passes = match self.probe_mode.as_str() {
            "transparent-orb" => {
                self.transparent_pixels_visible
                    && self.transparent_pixels_click_through
                    && self.outside_orb_drop_reached_background_target
                    && !self.outside_orb_drop_reached_fluxform
            }
            "transparent-window-with-rectangular-hit-region" => {
                self.transparent_pixels_visible
                    && !self.transparent_pixels_click_through
                    && !self.outside_orb_drop_reached_background_target
                    && self.outside_orb_drop_reached_fluxform
            }
            "opaque-frameless-fallback" => {
                !self.transparent_pixels_visible
                    && !self.transparent_pixels_click_through
                    && !self.outside_orb_drop_reached_background_target
                    && self.outside_orb_drop_reached_fluxform
            }
            _ => false,
        };
        if !mode_behavior_passes {
            return Err("passing result does not satisfy the selected mode's behavior");
        }

        Ok(())
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_install_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstalledProvenance {
    schema_version: u32,
    installer_package_sha256: String,
    installed_executable_path: String,
    installed_executable_sha256: String,
    probe_mode: String,
    install_identity: String,
}

#[cfg(test)]
fn write_installed_provenance_to(
    directory: &Path,
    manifest: &InstalledProvenance,
) -> io::Result<PathBuf> {
    fs::create_dir_all(directory)?;
    let path = directory.join(INSTALLED_PROVENANCE_FILE);
    let json = serde_json::to_vec_pretty(manifest)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let write_result = file
        .write_all(&json)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());
    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }
    Ok(path)
}

fn load_installed_provenance_from(
    directory: &Path,
    current_executable: &Path,
    current_executable_sha256: &str,
    current_mode: &str,
) -> Result<InstalledProvenance, String> {
    let manifest_path = directory.join(INSTALLED_PROVENANCE_FILE);
    let manifest_bytes = fs::read(&manifest_path)
        .map_err(|error| format!("installed provenance manifest is unavailable: {error}"))?;
    let manifest: InstalledProvenance = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("installed provenance manifest is invalid: {error}"))?;
    if manifest.schema_version != 1 {
        return Err("unsupported installed provenance manifest schema".to_owned());
    }
    if !is_sha256_hex(&manifest.installer_package_sha256) {
        return Err("installer package SHA-256 is missing or invalid".to_owned());
    }
    if !is_sha256_hex(&manifest.installed_executable_sha256)
        || !manifest
            .installed_executable_sha256
            .eq_ignore_ascii_case(current_executable_sha256)
    {
        return Err(
            "installed executable SHA-256 does not match the running executable".to_owned(),
        );
    }
    if !is_install_identity(&manifest.install_identity) {
        return Err("installed provenance identity is missing or invalid".to_owned());
    }
    if manifest.probe_mode != current_mode {
        return Err("installed provenance mode does not match this build".to_owned());
    }
    let current_path = fs::canonicalize(current_executable)
        .map_err(|error| format!("could not resolve running executable path: {error}"))?;
    let recorded_path = PathBuf::from(&manifest.installed_executable_path);
    if !recorded_path.is_absolute() {
        return Err("installed provenance executable path must be absolute".to_owned());
    }
    let recorded_path = fs::canonicalize(&recorded_path)
        .map_err(|error| format!("could not resolve recorded executable path: {error}"))?;
    let paths_match = if cfg!(target_os = "windows") {
        current_path
            .to_string_lossy()
            .eq_ignore_ascii_case(&recorded_path.to_string_lossy())
    } else {
        current_path == recorded_path
    };
    if !paths_match {
        return Err("installed provenance path does not match the running executable".to_owned());
    }
    Ok(manifest)
}

fn write_probe_result_to(directory: &Path, result: &WindowProbeResult) -> io::Result<PathBuf> {
    result
        .validate()
        .map_err(|message| io::Error::new(io::ErrorKind::InvalidInput, message))?;
    fs::create_dir_all(directory)?;

    let filename = format!(
        "{}-{}-{}.json",
        result.probe_mode,
        result.display_server,
        result.installed_artifact_sha256.to_ascii_lowercase()
    );
    let path = directory.join(filename);
    let json = serde_json::to_vec_pretty(result)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    let write_result = file
        .write_all(&json)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all());

    if let Err(error) = write_result {
        drop(file);
        let _ = fs::remove_file(&path);
        return Err(error);
    }

    Ok(path)
}

fn point_is_inside_orb(x: f64, y: f64, width: f64, height: f64) -> bool {
    if !x.is_finite() || !y.is_finite() || !width.is_finite() || !height.is_finite() {
        return false;
    }
    let radius = (width.min(height) / 2.0) - 8.0;
    if radius <= 0.0 {
        return false;
    }
    let dx = x - width / 2.0;
    let dy = y - height / 2.0;
    dx.mul_add(dx, dy * dy) <= radius * radius
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProbeSnapshot {
    probe_mode: &'static str,
    os: String,
    os_version: String,
    display_server: String,
    installed_artifact_sha256: String,
    installed_executable_sha256: String,
    install_identity: String,
    provenance_verified: bool,
    provenance_error: String,
    installed_launch_path: String,
    native_hit_region_supported: bool,
    input_hit_region_status: HitRegionStatus,
    backend_process_count: u32,
    webview_helper_process_count: u32,
    probe_window_count: usize,
    background_target_available: bool,
    background_click_count: u64,
    background_drop_count: u64,
    available_monitor_count: usize,
    current_monitor_name: Option<String>,
    current_monitor_identity: Option<String>,
    window_position_x: i32,
    window_position_y: i32,
    scale_factor: f64,
    window_label: String,
    development_build: bool,
}

#[derive(Debug, Clone)]
struct ProbeIdentity {
    os: String,
    os_version: String,
    display_server: String,
    executable_sha256: String,
    executable: PathBuf,
}

static PROBE_IDENTITY: OnceLock<Result<ProbeIdentity, String>> = OnceLock::new();
static HIT_REGION_CONTROLLERS: OnceLock<Mutex<HashMap<String, HitRegionController>>> =
    OnceLock::new();

fn hit_region_controllers() -> &'static Mutex<HashMap<String, HitRegionController>> {
    HIT_REGION_CONTROLLERS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn update_hit_region_for_window(
    window: &WebviewWindow,
    event: WindowGeometryEvent,
    width: u32,
    height: u32,
    scale_factor: f64,
) -> HitRegionStatus {
    let mut controllers = hit_region_controllers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let controller = controllers
        .entry(window.label().to_owned())
        .or_insert_with(|| HitRegionController::new(PROBE_MODE, std::env::consts::OS));
    controller.on_window_geometry(
        event,
        width,
        height,
        scale_factor,
        |bounds| apply_platform_circle_region(window, bounds),
        || clear_platform_window_region(window),
    );
    controller.status()
}

fn hit_region_controller_for(window_label: &str) -> HitRegionController {
    hit_region_controllers()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(window_label)
        .copied()
        .unwrap_or_else(|| HitRegionController::new(PROBE_MODE, std::env::consts::OS))
}

fn should_exit_after_probe_destroyed<'a>(
    window_labels: impl IntoIterator<Item = &'a str>,
    destroyed_label: &str,
) -> bool {
    !window_labels
        .into_iter()
        .any(|label| label.starts_with("probe-") && label != destroyed_label)
}

fn next_probe_window_label<'a>(
    window_labels: impl IntoIterator<Item = &'a str>,
) -> Option<&'static str> {
    let labels = window_labels.into_iter().collect::<Vec<_>>();
    if !labels.contains(&"probe-primary") {
        Some("probe-primary")
    } else if !labels.contains(&"probe-secondary") {
        Some("probe-secondary")
    } else {
        None
    }
}

fn is_background_target_window(window_label: &str) -> bool {
    window_label == BACKGROUND_TARGET_LABEL
}

#[cfg(target_os = "windows")]
#[link(name = "gdi32")]
unsafe extern "system" {
    fn CreateEllipticRgn(left: i32, top: i32, right: i32, bottom: i32) -> *mut std::ffi::c_void;
    fn DeleteObject(object: *mut std::ffi::c_void) -> i32;
}

#[cfg(target_os = "windows")]
#[link(name = "user32")]
unsafe extern "system" {
    fn SetWindowRgn(
        window: *mut std::ffi::c_void,
        region: *mut std::ffi::c_void,
        redraw: i32,
    ) -> i32;
}

#[cfg(target_os = "windows")]
fn apply_platform_circle_region(
    window: &WebviewWindow,
    (left, top, right, bottom): (i32, i32, i32, i32),
) -> bool {
    let Ok(hwnd) = window.hwnd() else {
        return false;
    };
    let region = unsafe { CreateEllipticRgn(left, top, right, bottom) };
    if region.is_null() {
        return false;
    }
    if unsafe { SetWindowRgn(hwnd.0, region, 1) } == 0 {
        let _ = unsafe { DeleteObject(region) };
        false
    } else {
        true
    }
}

#[cfg(not(target_os = "windows"))]
fn apply_platform_circle_region(_window: &WebviewWindow, _bounds: (i32, i32, i32, i32)) -> bool {
    false
}

#[cfg(target_os = "windows")]
fn clear_platform_window_region(window: &WebviewWindow) -> bool {
    let Ok(hwnd) = window.hwnd() else {
        return false;
    };
    unsafe { SetWindowRgn(hwnd.0, std::ptr::null_mut(), 1) != 0 }
}

#[cfg(not(target_os = "windows"))]
fn clear_platform_window_region(_window: &WebviewWindow) -> bool {
    false
}

fn command_stdout(program: &str, arguments: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(arguments)
        .output()
        .map_err(|error| format!("could not read platform information with {program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program} exited with {}", output.status));
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if stdout.is_empty() {
        return Err(format!("{program} returned no platform information"));
    }
    Ok(stdout)
}

#[cfg(target_os = "windows")]
fn current_os_version() -> Result<String, String> {
    command_stdout("cmd.exe", &["/C", "ver"])
}

#[cfg(target_os = "macos")]
fn current_os_version() -> Result<String, String> {
    command_stdout("sw_vers", &["-productVersion"])
}

#[cfg(target_os = "linux")]
fn current_os_version() -> Result<String, String> {
    command_stdout("uname", &["-sr"])
}

#[cfg(target_os = "windows")]
fn current_display_server() -> Result<String, String> {
    Ok("windows".to_owned())
}

fn probe_identity() -> Result<ProbeIdentity, String> {
    PROBE_IDENTITY
        .get_or_init(|| {
            let executable = fs::canonicalize(
                std::env::current_exe()
                    .map_err(|error| format!("could not resolve running executable: {error}"))?,
            )
            .map_err(|error| format!("could not canonicalize running executable: {error}"))?;
            let executable_sha256 = sha256_file(&executable)
                .map_err(|error| format!("could not hash running executable: {error}"))?;
            Ok(ProbeIdentity {
                os: std::env::consts::OS.to_owned(),
                os_version: current_os_version()?,
                display_server: current_display_server()?,
                executable_sha256,
                executable,
            })
        })
        .clone()
}

fn sha256_file(path: &Path) -> io::Result<String> {
    use std::io::Read;

    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(target_os = "macos")]
fn current_display_server() -> Result<String, String> {
    Ok("macos".to_owned())
}

#[cfg(target_os = "linux")]
fn current_display_server() -> Result<String, String> {
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        Ok("wayland".to_owned())
    } else if std::env::var_os("DISPLAY").is_some() {
        Ok("x11".to_owned())
    } else {
        Err("Linux display server is not identified by WAYLAND_DISPLAY or DISPLAY".to_owned())
    }
}

fn process_counts(executable: &Path) -> Result<(u32, u32), String> {
    #[cfg(target_os = "windows")]
    {
        fn image_count(image_name: &str) -> Result<u32, String> {
            let filter = format!("IMAGENAME eq {image_name}");
            let output = Command::new("tasklist.exe")
                .args(["/FO", "CSV", "/NH", "/FI", filter.as_str()])
                .output()
                .map_err(|error| format!("could not count {image_name} processes: {error}"))?;
            if !output.status.success() {
                return Err(format!("tasklist.exe exited with {}", output.status));
            }
            let expected = image_name.to_ascii_lowercase();
            Ok(String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| {
                    line.split(',')
                        .next()
                        .unwrap_or_default()
                        .trim_matches('"')
                        .eq_ignore_ascii_case(&expected)
                })
                .count()
                .min(u32::MAX as usize) as u32)
        }

        let image_name = executable
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "running executable has no UTF-8 image name".to_owned())?;
        Ok((image_count(image_name)?, image_count("msedgewebview2.exe")?))
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let output = Command::new("ps")
            .args(["-A", "-o", "command="])
            .output()
            .map_err(|error| format!("could not enumerate running processes: {error}"))?;
        if !output.status.success() {
            return Err(format!("ps exited with {}", output.status));
        }
        let listing = String::from_utf8_lossy(&output.stdout);
        let executable_path = executable.to_string_lossy();
        let executable_name = executable
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let mut backend_count = 0_u32;
        let mut webview_count = 0_u32;
        for command_line in listing.lines().map(str::trim_start) {
            let command_lowercase = command_line.to_ascii_lowercase();
            if command_lowercase.contains("webkit") || command_lowercase.contains("msedgewebview2")
            {
                webview_count = webview_count.saturating_add(1);
            }
            if command_line.starts_with(executable_path.as_ref())
                || command_line
                    .split_whitespace()
                    .next()
                    .and_then(|argument| Path::new(argument).file_name())
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.eq_ignore_ascii_case(executable_name))
            {
                backend_count = backend_count.saturating_add(1);
            }
        }
        Ok((backend_count, webview_count))
    }
}

fn probe_snapshot(app: &AppHandle, window: &WebviewWindow) -> Result<ProbeSnapshot, String> {
    let identity = probe_identity()?;
    let (backend_process_count, webview_helper_process_count) =
        process_counts(&identity.executable)?;
    let current_monitor = window
        .current_monitor()
        .map_err(|error| format!("could not read current monitor: {error}"))?;
    let current_monitor_name = current_monitor
        .as_ref()
        .and_then(|monitor| monitor.name().cloned());
    let current_monitor_identity = current_monitor.as_ref().map(|monitor| {
        let position = monitor.position();
        format!(
            "{}|{}|{}",
            monitor.name().map(String::as_str).unwrap_or("unnamed"),
            position.x,
            position.y
        )
    });
    let window_position = window
        .outer_position()
        .map_err(|error| format!("could not read window position: {error}"))?;
    let available_monitor_count = window
        .available_monitors()
        .map_err(|error| format!("could not enumerate monitors: {error}"))?
        .len();
    let scale_factor = window
        .scale_factor()
        .map_err(|error| format!("could not read window scale factor: {error}"))?;
    let provenance = match app.path().app_local_data_dir() {
        Ok(directory) => load_installed_provenance_from(
            &directory,
            &identity.executable,
            &identity.executable_sha256,
            PROBE_MODE,
        ),
        Err(error) => Err(format!(
            "could not resolve app-local data directory: {error}"
        )),
    };
    let (installed_artifact_sha256, install_identity, provenance_verified, provenance_error) =
        match provenance {
            Ok(manifest) => (
                manifest.installer_package_sha256.to_ascii_lowercase(),
                manifest.install_identity,
                true,
                String::new(),
            ),
            Err(error) => (String::new(), String::new(), false, error),
        };
    let webview_windows = app.webview_windows();
    let probe_window_count = webview_windows
        .keys()
        .filter(|label| label.starts_with("probe-"))
        .count();
    let hit_region_controller = hit_region_controller_for(window.label());

    Ok(ProbeSnapshot {
        probe_mode: PROBE_MODE,
        os: identity.os,
        os_version: identity.os_version,
        display_server: identity.display_server,
        installed_artifact_sha256,
        installed_executable_sha256: identity.executable_sha256,
        install_identity,
        provenance_verified,
        provenance_error,
        installed_launch_path: identity.executable.to_string_lossy().into_owned(),
        native_hit_region_supported: hit_region_controller.can_pass(),
        input_hit_region_status: hit_region_controller.status(),
        backend_process_count,
        webview_helper_process_count,
        probe_window_count,
        background_target_available: app.get_webview_window(BACKGROUND_TARGET_LABEL).is_some(),
        background_click_count: BACKGROUND_CLICK_COUNT.load(Ordering::Relaxed),
        background_drop_count: BACKGROUND_DROP_COUNT.load(Ordering::Relaxed),
        available_monitor_count,
        current_monitor_name,
        current_monitor_identity,
        window_position_x: window_position.x,
        window_position_y: window_position.y,
        scale_factor,
        window_label: window.label().to_owned(),
        development_build: cfg!(debug_assertions),
    })
}

fn track_window_events(window: &WebviewWindow, app: &AppHandle) {
    let event_window = window.clone();
    let app_handle = app.clone();
    let event_label = window.label().to_owned();
    window.on_window_event(move |event| {
        if event_label.starts_with("probe-") {
            match event {
                WindowEvent::Resized(size) => {
                    let scale_factor = event_window.scale_factor().unwrap_or(1.0);
                    let status = update_hit_region_for_window(
                        &event_window,
                        WindowGeometryEvent::Resized,
                        size.width,
                        size.height,
                        scale_factor,
                    );
                    if status == HitRegionStatus::FailedClosed {
                        let _ = event_window.hide();
                        let _ = app_handle.emit(
                            "probe://hit-region-unsupported",
                            "Could not apply or clear the native input region; probe window hidden.",
                        );
                    }
                }
                WindowEvent::ScaleFactorChanged {
                    scale_factor,
                    new_inner_size,
                    ..
                } => {
                    let status = update_hit_region_for_window(
                        &event_window,
                        WindowGeometryEvent::ScaleFactorChanged,
                        new_inner_size.width,
                        new_inner_size.height,
                        *scale_factor,
                    );
                    if status == HitRegionStatus::FailedClosed {
                        let _ = event_window.hide();
                        let _ = app_handle.emit(
                            "probe://hit-region-unsupported",
                            "Could not apply or clear the native input region; probe window hidden.",
                        );
                    }
                }
                WindowEvent::Moved(_) => {
                    if let (Ok(size), Ok(scale_factor)) =
                        (event_window.inner_size(), event_window.scale_factor())
                    {
                        let _ = update_hit_region_for_window(
                            &event_window,
                            WindowGeometryEvent::Moved,
                            size.width,
                            size.height,
                            scale_factor,
                        );
                    }
                }
                _ => {}
            }
        }
        let event_payload = match event {
            WindowEvent::Focused(focused) => Some(json!({"kind": "focused", "focused": focused})),
            WindowEvent::Resized(size) => Some(json!({"kind": "resized", "width": size.width, "height": size.height})),
            WindowEvent::Moved(position) => Some(json!({"kind": "moved", "x": position.x, "y": position.y})),
            WindowEvent::ScaleFactorChanged { scale_factor, new_inner_size, .. } => Some(json!({
                "kind": "scale-factor-changed",
                "scaleFactor": scale_factor,
                "width": new_inner_size.width,
                "height": new_inner_size.height
            })),
            WindowEvent::DragDrop(DragDropEvent::Drop { paths, position }) => {
                if event_label == BACKGROUND_TARGET_LABEL {
                    let drop_count = BACKGROUND_DROP_COUNT.fetch_add(1, Ordering::Relaxed) + 1;
                    let payload = json!({
                        "count": drop_count,
                        "paths": paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                        "physicalX": position.x,
                        "physicalY": position.y
                    });
                    let _ = app_handle.emit("probe://background-drop", payload);
                } else {
                    let scale_factor = event_window.scale_factor().unwrap_or(1.0);
                    let physical_size = event_window.inner_size().ok();
                    let inside_orb = physical_size.map(|size| {
                        let logical_size = size.to_logical::<f64>(scale_factor);
                        let logical_position = position.to_logical::<f64>(scale_factor);
                        point_is_inside_orb(
                            logical_position.x,
                            logical_position.y,
                            logical_size.width,
                            logical_size.height,
                        )
                    }).unwrap_or(false);
                    let payload = json!({
                        "paths": paths.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
                        "physicalX": position.x,
                        "physicalY": position.y,
                        "insideOrb": inside_orb
                    });
                    let _ = event_window.emit("probe://file-drop", payload);
                }
                None
            }
            _ => None,
        };
        if let Some(payload) = event_payload {
            let _ = event_window.emit("probe://window-event", payload);
        }

        if event_label.starts_with("probe-") && matches!(event, WindowEvent::Destroyed) {
            hit_region_controllers()
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .remove(&event_label);
            let windows = app_handle.webview_windows();
            if should_exit_after_probe_destroyed(
                windows.keys().map(String::as_str),
                &event_label,
            ) {
                if let Some(background_target) = app_handle.get_webview_window(BACKGROUND_TARGET_LABEL) {
                    let _ = background_target.close();
                }
                app_handle.exit(0);
            }
        }
    });
}

fn create_background_target(app: &AppHandle) -> tauri::Result<()> {
    if app.get_webview_window(BACKGROUND_TARGET_LABEL).is_some() {
        return Ok(());
    }

    let target = WebviewWindowBuilder::new(
        app,
        BACKGROUND_TARGET_LABEL,
        WebviewUrl::App("target.html".into()),
    )
    .title("FluxForm Probe Background Target")
    .inner_size(460.0, 460.0)
    .resizable(false)
    .decorations(false)
    .transparent(false)
    .center()
    .visible(true)
    .build()?;
    track_window_events(&target, app);
    Ok(())
}

/// Create another 360×360 probe window in the existing backend runtime.
pub fn create_probe_window(app: &AppHandle, launch_id: &str) -> tauri::Result<WebviewWindow> {
    create_background_target(app)?;

    let windows = app.webview_windows();
    let existing_labels = windows.keys().map(String::as_str).collect::<Vec<_>>();
    let Some(label) = next_probe_window_label(existing_labels) else {
        let window = app
            .get_webview_window("probe-secondary")
            .or_else(|| app.get_webview_window("probe-primary"))
            .expect("one of the two fixed probe windows exists");
        let _ = window.set_focus();
        return Ok(window);
    };
    let is_secondary = label == "probe-secondary";
    let launch_id_script = format!(
        "window.__PROBE_LAUNCH_ID__ = {};",
        serde_json::to_string(launch_id).expect("string serialization is infallible")
    );
    let transparent = PROBE_MODE != "opaque-frameless-fallback";
    let window = WebviewWindowBuilder::new(app, label, WebviewUrl::App("index.html".into()))
        .title(if is_secondary {
            "FluxForm Probe 2"
        } else {
            "FluxForm Probe 1"
        })
        .inner_size(360.0, 360.0)
        .min_inner_size(360.0, 360.0)
        .max_inner_size(360.0, 360.0)
        .resizable(false)
        .decorations(false)
        .transparent(transparent)
        .always_on_top(true)
        .center()
        .visible(false)
        .focused(true)
        .initialization_script(launch_id_script)
        .build()?;
    if is_secondary && let Ok(position) = window.outer_position() {
        let offset = 28;
        let _ = window.set_position(tauri::PhysicalPosition::new(
            position.x.saturating_add(offset),
            position.y.saturating_add(offset),
        ));
    }
    track_window_events(&window, app);
    let inner_size = window.inner_size()?;
    let scale_factor = window.scale_factor()?;
    let status = update_hit_region_for_window(
        &window,
        WindowGeometryEvent::Created,
        inner_size.width,
        inner_size.height,
        scale_factor,
    );
    if status == HitRegionStatus::FailedClosed {
        let _ = window.close();
        return Ok(window);
    }
    window.show()?;
    Ok(window)
}

#[tauri::command]
fn get_probe_snapshot(app: AppHandle, window: WebviewWindow) -> Result<ProbeSnapshot, String> {
    probe_snapshot(&app, &window)
}

#[tauri::command]
fn record_probe_result(
    app: AppHandle,
    window: WebviewWindow,
    mut result: WindowProbeResult,
) -> Result<String, String> {
    let snapshot = probe_snapshot(&app, &window)?;
    if snapshot.development_build && result.passed {
        return Err("passing evidence cannot be recorded from a development build".to_owned());
    }
    result.probe_mode = PROBE_MODE.to_owned();
    result.os = snapshot.os;
    result.os_version = snapshot.os_version;
    result.display_server = snapshot.display_server;
    result.installed_artifact_sha256 = snapshot.installed_artifact_sha256;
    result.installed_executable_sha256 = snapshot.installed_executable_sha256;
    result.install_identity = snapshot.install_identity;
    result.provenance_verified = snapshot.provenance_verified;
    result.provenance_error = snapshot.provenance_error.clone();
    result.installed_launch_path = snapshot.installed_launch_path;
    result.native_hit_region_supported = snapshot.native_hit_region_supported;
    result.input_hit_region_status = snapshot.input_hit_region_status.as_str().to_owned();
    if snapshot.development_build {
        result.passed = false;
        append_note(
            &mut result.notes,
            "development build cannot produce PASS evidence",
        );
    }
    if !snapshot.provenance_verified {
        result.passed = false;
        append_note(
            &mut result.notes,
            &format!(
                "installed provenance unverified ({}); PASS disabled",
                snapshot.provenance_error
            ),
        );
    }
    if !snapshot.native_hit_region_supported {
        result.passed = false;
        append_note(
            &mut result.notes,
            &format!(
                "native input hit region unsupported ({}); PASS disabled",
                snapshot.input_hit_region_status.as_str()
            ),
        );
    }
    result.repeated_launch_backend_process_count = snapshot.backend_process_count;
    result.webview_helper_process_count = snapshot.webview_helper_process_count;

    let evidence_directory = app
        .path()
        .app_local_data_dir()
        .map_err(|error| format!("could not resolve app-local data directory: {error}"))?
        .join("probe-results");
    let path = write_probe_result_to(&evidence_directory, &result)
        .map_err(|error| format!("could not safely write probe evidence: {error}"))?;
    Ok(path.to_string_lossy().into_owned())
}

fn append_note(notes: &mut String, note: &str) {
    if !notes.trim().is_empty() {
        notes.push_str(" | ");
    }
    notes.push_str(note);
}

#[tauri::command]
fn record_background_interaction(window: WebviewWindow, corner: String) -> Result<u64, String> {
    if !is_background_target_window(window.label()) {
        return Err("background clicks may only be counted by the background target".to_owned());
    }
    match corner.as_str() {
        "top-left" | "top-right" | "bottom-left" | "bottom-right" => {
            Ok(BACKGROUND_CLICK_COUNT.fetch_add(1, Ordering::Relaxed) + 1)
        }
        _ => Err("unknown background target control".to_owned()),
    }
}

#[tauri::command]
fn close_probe_window(window: WebviewWindow) -> Result<(), String> {
    window
        .close()
        .map_err(|error| format!("could not close probe window: {error}"))
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(
            |app, args, _working_directory| {
                let launch_id = args
                    .get(1)
                    .cloned()
                    .unwrap_or_else(|| "secondary-launch".to_owned());
                if let Err(error) = create_probe_window(app, &launch_id) {
                    eprintln!("could not create second probe window: {error}");
                }
            },
        ))
        .invoke_handler(tauri::generate_handler![
            get_probe_snapshot,
            record_probe_result,
            record_background_interaction,
            close_probe_window
        ])
        .setup(|app| {
            create_background_target(app.handle())?;
            create_probe_window(app.handle(), "initial-launch")?;
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("failed to run FluxForm desktop window probe");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_TEMP_DIR: AtomicUsize = AtomicUsize::new(0);

    fn fresh_temp_dir() -> PathBuf {
        loop {
            let id = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "fluxform-desktop-probe-{}-{id}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("could not create test directory: {error}"),
            }
        }
    }

    fn remove_temp_dir(path: PathBuf) {
        fs::remove_dir_all(path).unwrap();
    }

    fn passing_result(mode: &str) -> WindowProbeResult {
        let transparent = mode != "opaque-frameless-fallback";
        let orb_hit_testing = mode == "transparent-orb";
        let hit_region_status = match mode {
            "transparent-orb" => "circular-applied",
            "transparent-window-with-rectangular-hit-region" => "rectangular",
            "opaque-frameless-fallback" => "opaque",
            _ => "unknown",
        };

        WindowProbeResult {
            probe_mode: mode.to_owned(),
            os: "windows".to_owned(),
            os_version: "Windows 11".to_owned(),
            display_server: "windows".to_owned(),
            installed_artifact_sha256: "0".repeat(64),
            installed_executable_sha256: "1".repeat(64),
            install_identity: "task16-test-install".to_owned(),
            provenance_verified: true,
            provenance_error: String::new(),
            installed_launch_path: r"C:\Program Files\FluxFormProbe\FluxFormDesktopProbe.exe"
                .to_owned(),
            native_hit_region_supported: true,
            input_hit_region_status: hit_region_status.to_owned(),
            network_disconnected: true,
            first_launch_succeeded: true,
            transparent_pixels_visible: transparent,
            transparent_pixels_click_through: orb_hit_testing,
            frameless_drag_works: true,
            file_drop_works: true,
            outside_orb_drop_reached_background_target: orb_hit_testing,
            outside_orb_drop_reached_fluxform: !orb_hit_testing,
            focus_recovery_works: true,
            keyboard_input_works: true,
            repeated_launch_created_second_window: true,
            repeated_launch_backend_process_count: 1,
            single_window_close_works: true,
            last_window_close_works: true,
            dpi_change_works: true,
            multi_monitor_move_works: true,
            idle_cpu_percent: 0.1,
            idle_gpu_percent: 0.2,
            notes: String::new(),
            passed: true,
            webview_helper_process_count: 3,
        }
    }

    #[test]
    fn closing_one_of_two_probe_windows_does_not_exit_before_or_after_registry_removal() {
        assert!(!should_exit_after_probe_destroyed(
            ["probe-primary", "probe-secondary"],
            "probe-primary"
        ));
        assert!(!should_exit_after_probe_destroyed(
            ["probe-secondary"],
            "probe-primary"
        ));
    }

    #[test]
    fn closing_last_probe_window_exits_before_or_after_registry_removal() {
        assert!(should_exit_after_probe_destroyed(
            ["probe-primary"],
            "probe-primary"
        ));
        assert!(should_exit_after_probe_destroyed([], "probe-primary"));
    }

    #[test]
    fn fixed_probe_window_labels_are_only_primary_secondary_and_background() {
        assert_eq!(
            next_probe_window_label([BACKGROUND_TARGET_LABEL]),
            Some("probe-primary")
        );
        assert_eq!(
            next_probe_window_label(["probe-primary", BACKGROUND_TARGET_LABEL]),
            Some("probe-secondary")
        );
        assert_eq!(
            next_probe_window_label(["probe-primary", "probe-secondary", BACKGROUND_TARGET_LABEL]),
            None
        );
    }

    #[test]
    fn background_click_command_is_restricted_to_the_background_target_window() {
        assert!(is_background_target_window(BACKGROUND_TARGET_LABEL));
        assert!(!is_background_target_window("probe-primary"));
        assert!(!is_background_target_window("probe-secondary"));
    }

    #[test]
    fn renderer_capability_is_limited_to_exact_windows_and_never_allows_event_emission() {
        let probe_capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/default.json")).unwrap();
        let target_capability: serde_json::Value =
            serde_json::from_str(include_str!("../capabilities/background-target.json")).unwrap();
        let windows = probe_capability["windows"].as_array().unwrap();
        assert_eq!(
            windows
                .iter()
                .map(serde_json::Value::as_str)
                .collect::<Vec<_>>(),
            [Some("probe-primary"), Some("probe-secondary")]
        );
        assert_eq!(
            target_capability["windows"]
                .as_array()
                .unwrap()
                .iter()
                .map(serde_json::Value::as_str)
                .collect::<Vec<_>>(),
            [Some(BACKGROUND_TARGET_LABEL)]
        );

        let probe_permissions = probe_capability["permissions"].as_array().unwrap();
        let probe_permission_names = probe_permissions
            .iter()
            .map(|permission| permission.as_str().unwrap())
            .collect::<Vec<_>>();
        let target_permissions = target_capability["permissions"].as_array().unwrap();
        let target_permission_names = target_permissions
            .iter()
            .map(|permission| permission.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            probe_permission_names,
            [
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "core:window:allow-start-dragging",
                "allow-get-probe-snapshot",
                "allow-record-probe-result",
                "allow-close-probe-window",
            ]
        );
        assert_eq!(
            target_permission_names,
            [
                "core:event:allow-listen",
                "core:event:allow-unlisten",
                "allow-record-background-interaction"
            ]
        );
        for permission_names in [&probe_permission_names, &target_permission_names] {
            assert!(permission_names.iter().all(|permission| {
                !permission.ends_with(":default")
                    && !permission.contains("allow-emit")
                    && *permission != "core:default"
            }));
        }
        assert!(!probe_permission_names.contains(&"allow-record-background-interaction"));
        assert!(!target_permission_names.contains(&"allow-record-probe-result"));
    }

    #[test]
    fn build_script_autogenerates_acl_for_only_the_registered_probe_commands() {
        let build_script = include_str!("../build.rs");
        let commands_section = build_script
            .split(".commands(&[")
            .nth(1)
            .expect("build script must use an explicit app-command manifest")
            .split("]));")
            .next()
            .expect("build script command manifest must close");
        let commands = commands_section
            .lines()
            .filter_map(|line| {
                line.trim()
                    .strip_prefix('"')
                    .and_then(|command| command.strip_suffix("\","))
            })
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            [
                "get_probe_snapshot",
                "record_probe_result",
                "record_background_interaction",
                "close_probe_window"
            ]
        );
    }

    fn test_provenance(
        directory: &Path,
        executable_path: &Path,
        executable_hash: &str,
    ) -> InstalledProvenance {
        InstalledProvenance {
            schema_version: 1,
            installer_package_sha256: "a".repeat(64),
            installed_executable_path: executable_path.to_string_lossy().into_owned(),
            installed_executable_sha256: executable_hash.to_owned(),
            probe_mode: "transparent-orb".to_owned(),
            install_identity: format!(
                "task16-{}",
                directory.file_name().unwrap().to_string_lossy()
            ),
        }
    }

    #[test]
    fn installed_provenance_matches_package_executable_mode_and_install_identity() {
        let directory = fresh_temp_dir();
        let executable = directory.join("installed-probe.exe");
        fs::write(&executable, b"the exact installed test executable").unwrap();
        let executable = fs::canonicalize(executable).unwrap();
        let executable_hash = format!(
            "{:x}",
            Sha256::digest(b"the exact installed test executable")
        );
        let manifest = test_provenance(&directory, &executable, &executable_hash);
        write_installed_provenance_to(&directory, &manifest).unwrap();

        let verified = load_installed_provenance_from(
            &directory,
            &executable,
            &executable_hash,
            "transparent-orb",
        )
        .unwrap();

        assert_eq!(verified.installer_package_sha256, "a".repeat(64));
        assert_eq!(verified.install_identity, manifest.install_identity);
        remove_temp_dir(directory);
    }

    #[test]
    fn missing_external_manifest_keeps_direct_build_tree_execution_unverified() {
        let directory = fresh_temp_dir();
        let executable = directory.join("release-build-tree.exe");
        fs::write(&executable, b"release build tree").unwrap();
        let executable = fs::canonicalize(executable).unwrap();
        let executable_hash = format!("{:x}", Sha256::digest(b"release build tree"));

        assert!(
            load_installed_provenance_from(
                &directory,
                &executable,
                &executable_hash,
                "transparent-orb",
            )
            .is_err()
        );
        remove_temp_dir(directory);
    }

    #[test]
    fn provenance_tampering_of_package_executable_path_mode_or_install_identity_is_rejected() {
        let directory = fresh_temp_dir();
        let executable = directory.join("installed-probe.exe");
        fs::write(&executable, b"the exact installed test executable").unwrap();
        let executable = fs::canonicalize(executable).unwrap();
        let executable_hash = format!(
            "{:x}",
            Sha256::digest(b"the exact installed test executable")
        );
        let original = test_provenance(&directory, &executable, &executable_hash);

        for tamper in ["package", "executable", "path", "mode", "install"] {
            let mut manifest = original.clone();
            match tamper {
                "package" => manifest.installer_package_sha256 = "not-a-hash".to_owned(),
                "executable" => manifest.installed_executable_sha256 = "b".repeat(64),
                "path" => {
                    manifest.installed_executable_path =
                        directory.join("other.exe").to_string_lossy().into_owned()
                }
                "mode" => manifest.probe_mode = "opaque-frameless-fallback".to_owned(),
                "install" => manifest.install_identity = "../different-install".to_owned(),
                _ => unreachable!(),
            }
            write_installed_provenance_to(&directory, &manifest).unwrap();
            assert!(
                load_installed_provenance_from(
                    &directory,
                    &executable,
                    &executable_hash,
                    "transparent-orb"
                )
                .is_err(),
                "tampered {tamper} provenance was accepted"
            );
            fs::remove_file(directory.join(INSTALLED_PROVENANCE_FILE)).unwrap();
        }

        remove_temp_dir(directory);
    }

    #[test]
    fn external_provenance_manifest_uses_create_new_and_never_overwrites() {
        let directory = fresh_temp_dir();
        let executable = directory.join("installed-probe.exe");
        fs::write(&executable, b"the exact installed test executable").unwrap();
        let executable = fs::canonicalize(executable).unwrap();
        let executable_hash = format!(
            "{:x}",
            Sha256::digest(b"the exact installed test executable")
        );
        let manifest = test_provenance(&directory, &executable, &executable_hash);
        let path = write_installed_provenance_to(&directory, &manifest).unwrap();
        let original = fs::read(&path).unwrap();

        let error = write_installed_provenance_to(&directory, &manifest).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(path).unwrap(), original);
        remove_temp_dir(directory);
    }

    #[test]
    fn rejects_unknown_probe_mode() {
        let mut result = passing_result("transparent-orb");
        result.probe_mode = "mostly-transparent".to_owned();

        assert!(result.validate().is_err());
    }

    #[test]
    fn rejects_unknown_display_server() {
        let mut result = passing_result("transparent-orb");
        result.display_server = "mirrors".to_owned();

        assert!(result.validate().is_err());
    }

    #[test]
    fn rejects_negative_cpu_or_gpu_percentages() {
        for field in ["cpu", "gpu"] {
            let mut result = passing_result("transparent-orb");
            if field == "cpu" {
                result.idle_cpu_percent = -0.01;
            } else {
                result.idle_gpu_percent = -0.01;
            }

            assert!(result.validate().is_err(), "negative {field} was accepted");
        }
    }

    #[test]
    fn rejects_non_finite_cpu_or_gpu_percentages() {
        for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let mut cpu = passing_result("transparent-orb");
            cpu.idle_cpu_percent = invalid;
            assert!(cpu.validate().is_err(), "non-finite CPU value was accepted");

            let mut gpu = passing_result("transparent-orb");
            gpu.idle_gpu_percent = invalid;
            assert!(gpu.validate().is_err(), "non-finite GPU value was accepted");
        }
    }

    #[test]
    fn rejects_repeated_launch_backend_process_counts_other_than_one() {
        for process_count in [0, 2] {
            let mut result = passing_result("transparent-orb");
            result.repeated_launch_backend_process_count = process_count;

            assert!(
                result.validate().is_err(),
                "backend process count {process_count} was accepted"
            );
        }
    }

    #[test]
    fn failed_observation_can_record_a_repeated_launch_backend_process_mismatch() {
        let mut result = passing_result("transparent-orb");
        result.passed = false;
        result.repeated_launch_backend_process_count = 2;

        assert!(result.validate().is_ok());
    }

    #[test]
    fn build_selects_exactly_one_declared_probe_mode() {
        assert!(PROBE_MODES.contains(&PROBE_MODE));
        #[cfg(feature = "probe-transparent-orb")]
        assert_eq!(PROBE_MODE, "transparent-orb");
        #[cfg(feature = "probe-transparent-window-with-rectangular-hit-region")]
        assert_eq!(PROBE_MODE, "transparent-window-with-rectangular-hit-region");
        #[cfg(feature = "probe-opaque-frameless-fallback")]
        assert_eq!(PROBE_MODE, "opaque-frameless-fallback");
    }

    #[test]
    fn hit_test_geometry_distinguishes_the_orb_from_its_rectangular_window() {
        assert!(point_is_inside_orb(180.0, 180.0, 360.0, 360.0));
        assert!(point_is_inside_orb(180.0, 30.0, 360.0, 360.0));
        assert!(point_is_inside_orb(349.0, 180.0, 360.0, 360.0));
        assert!(!point_is_inside_orb(12.0, 12.0, 360.0, 360.0));
        assert!(!point_is_inside_orb(355.0, 180.0, 360.0, 360.0));
        assert!(!point_is_inside_orb(f64::NAN, 180.0, 360.0, 360.0));
    }

    #[test]
    fn records_webview_helpers_separately_from_the_backend_runtime() {
        let mut result = passing_result("transparent-orb");
        result.webview_helper_process_count = 17;

        assert!(result.validate().is_ok());
        assert_eq!(result.repeated_launch_backend_process_count, 1);
        assert_eq!(result.webview_helper_process_count, 17);
    }

    #[test]
    fn passing_records_require_each_shared_manual_behavior() {
        type BehaviorMutation = (&'static str, fn(&mut WindowProbeResult));
        let required_behaviors: [BehaviorMutation; 11] = [
            ("network disconnection", |r| r.network_disconnected = false),
            ("first launch", |r| r.first_launch_succeeded = false),
            ("frameless drag", |r| r.frameless_drag_works = false),
            ("file drop", |r| r.file_drop_works = false),
            ("focus recovery", |r| r.focus_recovery_works = false),
            ("keyboard input", |r| r.keyboard_input_works = false),
            ("second window", |r| {
                r.repeated_launch_created_second_window = false
            }),
            ("single-window close", |r| {
                r.single_window_close_works = false
            }),
            ("last-window close", |r| r.last_window_close_works = false),
            ("DPI change", |r| r.dpi_change_works = false),
            ("multi-monitor move", |r| r.multi_monitor_move_works = false),
        ];

        for (behavior, remove_behavior) in required_behaviors {
            let mut result = passing_result("transparent-orb");
            remove_behavior(&mut result);

            assert!(
                result.validate().is_err(),
                "missing {behavior} was accepted as a pass"
            );
        }
    }

    #[test]
    fn passing_records_enforce_hit_testing_for_the_selected_mode() {
        for (mode, break_contract) in [
            ("transparent-orb", 0),
            ("transparent-orb", 1),
            ("transparent-orb", 2),
            ("transparent-orb", 3),
            ("transparent-window-with-rectangular-hit-region", 4),
            ("transparent-window-with-rectangular-hit-region", 5),
            ("transparent-window-with-rectangular-hit-region", 6),
            ("transparent-window-with-rectangular-hit-region", 7),
            ("opaque-frameless-fallback", 8),
            ("opaque-frameless-fallback", 9),
            ("opaque-frameless-fallback", 10),
            ("opaque-frameless-fallback", 11),
        ] {
            let mut result = passing_result(mode);
            match break_contract {
                0 => result.transparent_pixels_visible = false,
                1 => result.transparent_pixels_click_through = false,
                2 => result.outside_orb_drop_reached_background_target = false,
                3 => result.outside_orb_drop_reached_fluxform = true,
                4 => result.transparent_pixels_visible = false,
                5 => result.transparent_pixels_click_through = true,
                6 => result.outside_orb_drop_reached_background_target = true,
                7 => result.outside_orb_drop_reached_fluxform = false,
                8 => result.transparent_pixels_visible = true,
                9 => result.transparent_pixels_click_through = true,
                10 => result.outside_orb_drop_reached_background_target = true,
                11 => result.outside_orb_drop_reached_fluxform = false,
                _ => unreachable!(),
            }

            assert!(
                result.validate().is_err(),
                "incorrect hit-test result passed for {mode}"
            );
        }
    }

    #[test]
    fn unsupported_native_hit_region_cannot_pass_but_failed_observation_is_recordable() {
        let mut result = passing_result("transparent-orb");
        result.native_hit_region_supported = false;
        result.input_hit_region_status = "rectangular-fallback-unsupported".to_owned();

        assert!(result.validate().is_err());

        result.passed = false;
        assert!(result.validate().is_ok());
    }

    #[test]
    fn failed_observations_remain_recordable_for_fallback_decisions() {
        let mut result = passing_result("transparent-orb");
        result.passed = false;
        result.transparent_pixels_click_through = false;
        result.outside_orb_drop_reached_background_target = false;

        assert!(result.validate().is_ok());
    }

    #[test]
    fn deserialization_requires_every_evidence_field() {
        let mut json = serde_json::to_value(passing_result("transparent-orb")).unwrap();
        json.as_object_mut().unwrap().remove("idle_gpu_percent");

        assert!(serde_json::from_value::<WindowProbeResult>(json).is_err());
    }

    #[test]
    fn rejects_a_non_sha256_artifact_identity() {
        let mut result = passing_result("transparent-orb");
        result.installed_artifact_sha256 = "../outside.json".to_owned();

        assert!(result.validate().is_err());
    }

    #[test]
    fn unverified_package_provenance_cannot_pass_but_failed_observations_remain_recordable() {
        let mut result = passing_result("transparent-orb");
        result.provenance_verified = false;
        result.provenance_error = "manifest missing".to_owned();

        assert!(result.validate().is_err());

        result.passed = false;
        result.installed_artifact_sha256.clear();
        result.install_identity.clear();
        assert!(result.validate().is_ok());
    }

    #[test]
    fn writes_deterministic_json_under_the_requested_evidence_directory() {
        let first_dir = fresh_temp_dir();
        let second_dir = fresh_temp_dir();
        let result = passing_result("transparent-orb");

        let first_path = write_probe_result_to(&first_dir, &result).unwrap();
        let second_path = write_probe_result_to(&second_dir, &result).unwrap();

        let expected_name = format!("transparent-orb-windows-{}.json", "0".repeat(64));
        assert_eq!(
            first_path.file_name().unwrap().to_str().unwrap(),
            expected_name
        );
        assert_eq!(first_path.parent().unwrap(), first_dir);
        assert_eq!(
            fs::read(first_path).unwrap(),
            fs::read(second_path).unwrap(),
            "the same evidence must produce byte-identical JSON"
        );

        remove_temp_dir(first_dir);
        remove_temp_dir(second_dir);
    }

    #[test]
    fn refuses_to_overwrite_existing_evidence() {
        let directory = fresh_temp_dir();
        let result = passing_result("transparent-orb");
        let path = write_probe_result_to(&directory, &result).unwrap();
        let original = fs::read(&path).unwrap();

        let error = write_probe_result_to(&directory, &result).unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(path).unwrap(), original);
        remove_temp_dir(directory);
    }

    #[test]
    fn record_fields_cannot_redirect_the_evidence_output_path() {
        let directory = fresh_temp_dir();
        let mut result = passing_result("transparent-orb");
        result.installed_launch_path = r"..\outside.json".to_owned();
        result.notes = r"../../overwrite.json".to_owned();

        let path = write_probe_result_to(&directory, &result).unwrap();

        assert_eq!(path.parent().unwrap(), directory);
        assert!(!directory.parent().unwrap().join("outside.json").exists());
        remove_temp_dir(directory);
    }
}
