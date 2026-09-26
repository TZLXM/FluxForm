use fluxform_capabilities::{
    CapabilityManifestV1, OrientationPolicy, runner::build_ffmpeg_arguments,
};
use std::path::Path;
use std::process::{Command, Output};

#[test]
fn ffmpeg_arguments_are_deterministic_and_bound_to_each_manifest_edge() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let manifest = CapabilityManifestV1::load(root.join("config/capabilities-v1.toml"))
        .expect("frozen manifest");
    let video = manifest
        .edges()
        .iter()
        .find(|edge| edge.id == "video.mov-to-mp4")
        .unwrap();
    assert_eq!(
        build_ffmpeg_arguments(video, "input.mov", "out.mp4"),
        [
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-y",
            "-autorotate",
            "-i",
            "input.mov",
            "-map",
            "0:v:0",
            "-map_metadata",
            "-1",
            "-c:v",
            "libx264",
            "-crf",
            "23",
            "-an",
            "-f",
            "mp4",
            "out.mp4",
        ]
    );
    let audio = manifest
        .edges()
        .iter()
        .find(|edge| edge.id == "audio.m4a-to-m4a")
        .unwrap();
    assert_eq!(
        build_ffmpeg_arguments(audio, "input.m4a", "out.m4a"),
        [
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-y",
            "-i",
            "input.m4a",
            "-map",
            "0:a:0",
            "-map_metadata",
            "-1",
            "-c:a",
            "aac",
            "-b:a",
            "64k",
            "-vn",
            "-f",
            "mp4",
            "out.m4a",
        ]
    );
    let image = manifest
        .edges()
        .iter()
        .find(|edge| edge.id == "image.jpeg-to-png")
        .unwrap();
    assert_eq!(
        build_ffmpeg_arguments(image, "input.jpg", "out.png"),
        [
            "-hide_banner",
            "-nostdin",
            "-v",
            "error",
            "-y",
            "-autorotate",
            "-i",
            "input.jpg",
            "-map",
            "0:v:0",
            "-frames:v",
            "1",
            "-map_metadata",
            "-1",
            "-c:v",
            "png",
            "-compression_level",
            "6",
            "-an",
            "-f",
            "image2",
            "out.png",
        ]
    );
}

#[test]
fn real_ffmpeg_executes_autorotate_switches_and_rejects_value_form() {
    let ffmpeg = ffmpeg_for_regression();
    let Some(ffmpeg) = ffmpeg else {
        assert_ne!(
            std::env::var_os("FLUXFORM_REQUIRE_FFMPEG_REGRESSION").as_deref(),
            Some(std::ffi::OsStr::new("1")),
            "FLUXFORM_REQUIRE_FFMPEG_REGRESSION=1 requires FLUXFORM_TEST_FFMPEG or ffmpeg on PATH"
        );
        eprintln!(
            "skipping real FFmpeg parser regression: set FLUXFORM_TEST_FFMPEG or add ffmpeg to PATH"
        );
        return;
    };

    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let input = root.join("testdata/media/v1/files/video-mov-h264-silent-240p-v1.mov");
    let input = input.to_string_lossy().into_owned();
    let manifest = CapabilityManifestV1::load(root.join("config/capabilities-v1.toml"))
        .expect("frozen manifest");
    let video = manifest
        .edges()
        .iter()
        .find(|edge| edge.id == "video.mov-to-mp4")
        .expect("enabled video edge");
    let temporary = tempfile::tempdir().expect("temporary FFmpeg regression output directory");
    let positive_output = temporary.path().join("bare-autorotate.mp4");
    let positive_output = positive_output.to_string_lossy().into_owned();
    let mut positive_arguments = build_ffmpeg_arguments(video, &input, &positive_output);
    set_info_loglevel(&mut positive_arguments);
    let positive = run_ffmpeg(&ffmpeg, &positive_arguments);
    let positive_log = process_log(&positive);
    assert!(
        positive.status.success(),
        "bare -autorotate must execute: {positive_log}"
    );
    assert_option_immediately_before_input(&positive_arguments, "-autorotate");
    assert!(
        positive_log.contains("Input #0, mov,"),
        "bare -autorotate must reach real input processing: {positive_log}"
    );
    assert!(Path::new(&positive_output).is_file());

    let mut preserve_tag_edge = video.clone();
    preserve_tag_edge.orientation_policy = OrientationPolicy::PreserveTag;
    let negative_output = temporary.path().join("noautorotate.mp4");
    let negative_output = negative_output.to_string_lossy().into_owned();
    let mut negative_arguments =
        build_ffmpeg_arguments(&preserve_tag_edge, &input, &negative_output);
    set_info_loglevel(&mut negative_arguments);
    let negative = run_ffmpeg(&ffmpeg, &negative_arguments);
    let negative_log = process_log(&negative);
    assert!(
        negative.status.success(),
        "-noautorotate must execute: {negative_log}"
    );
    assert_option_immediately_before_input(&negative_arguments, "-noautorotate");
    assert!(
        negative_log.contains("Input #0, mov,"),
        "-noautorotate must reach real input processing: {negative_log}"
    );
    assert!(Path::new(&negative_output).is_file());

    let legacy_output = temporary.path().join("legacy-autorotate-value.mp4");
    let legacy_output = legacy_output.to_string_lossy().into_owned();
    let mut legacy_arguments = build_ffmpeg_arguments(video, &input, &legacy_output);
    let autorotate_index = legacy_arguments
        .iter()
        .position(|argument| argument == "-autorotate")
        .expect("switch in production argument vector");
    legacy_arguments.insert(autorotate_index + 1, "1".to_owned());
    set_info_loglevel(&mut legacy_arguments);
    let legacy = run_ffmpeg(&ffmpeg, &legacy_arguments);
    let legacy_log = process_log(&legacy);
    assert!(
        !legacy.status.success(),
        "the old `-autorotate 1` form must be rejected: {legacy_log}"
    );
    assert!(
        legacy_log.contains("Error parsing options for output file 1"),
        "FFmpeg must identify `1` as an invalid output URL: {legacy_log}"
    );
    assert!(!Path::new(&legacy_output).exists());
}

fn ffmpeg_for_regression() -> Option<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("FLUXFORM_TEST_FFMPEG") {
        return Some(path.into());
    }
    let executable = if cfg!(windows) {
        "ffmpeg.exe"
    } else {
        "ffmpeg"
    };
    Command::new(executable)
        .arg("-version")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|_| executable.into())
}

fn set_info_loglevel(arguments: &mut [String]) {
    let verbosity_index = arguments
        .iter()
        .position(|argument| argument == "-v")
        .expect("runner verbosity option");
    arguments[verbosity_index + 1] = "info".to_owned();
}

fn assert_option_immediately_before_input(arguments: &[String], option: &str) {
    let option_index = arguments
        .iter()
        .position(|argument| argument == option)
        .expect("orientation switch");
    assert_eq!(arguments[option_index + 1], "-i");
}

fn run_ffmpeg(ffmpeg: &Path, arguments: &[String]) -> Output {
    Command::new(ffmpeg)
        .args(arguments)
        .output()
        .unwrap_or_else(|error| panic!("start FFmpeg {}: {error}", ffmpeg.display()))
}

fn process_log(output: &Output) -> String {
    format!(
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}
