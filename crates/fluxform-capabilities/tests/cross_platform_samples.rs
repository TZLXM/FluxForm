use fluxform_capabilities::collector::collect_sample_reports;
use fluxform_capabilities::evidence::compute_evidence_input_digest;
use std::path::Path;

#[test]
fn every_approved_native_profile_has_a_current_sample_report() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let digest = compute_evidence_input_digest(&root)
        .expect("current evidence input digest")
        .digest;
    let aggregate = collect_sample_reports(
        &root,
        root.join("target/stage0/collected"),
        root.join("config/capabilities-v1.toml"),
        root.join("testdata/media/v1/samples.toml"),
        &digest,
    )
    .expect("BLOCKED: all four exact native profile/sample artifacts are required");
    assert_eq!(aggregate.status, "passed");
    assert_eq!(aggregate.targets.len(), 4);
    assert!(
        aggregate
            .targets
            .iter()
            .all(|target| target.sample_result_count == 9)
    );
}
