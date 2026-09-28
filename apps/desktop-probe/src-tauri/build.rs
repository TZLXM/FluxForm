fn main() {
    let attributes =
        tauri_build::Attributes::new().app_manifest(tauri_build::AppManifest::new().commands(&[
            "get_probe_snapshot",
            "record_probe_result",
            "record_background_interaction",
            "close_probe_window",
        ]));
    tauri_build::try_build(attributes).expect("failed to generate the probe command ACL");
}
