use fluxform_capabilities::{CapabilityManifestV1, runner::build_ffmpeg_arguments};
use std::path::Path;

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
