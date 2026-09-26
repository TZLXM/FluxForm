use fluxform_capabilities::CapabilityManifestV1;
use fluxform_ffmpeg_profile::ProbeReport;
use std::collections::BTreeMap;
use std::env;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("verify-manifest: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = env::args().skip(1);
    if arguments.next().as_deref() != Some("verify-manifest") {
        return Err(
            "usage: fluxform-capabilities verify-manifest --manifest PATH --reports DIR".into(),
        );
    }

    let mut manifest_path = None;
    let mut reports_path = None;
    let remaining = arguments.collect::<Vec<_>>();
    let mut index = 0;
    while index < remaining.len() {
        let flag = remaining[index].as_str();
        let value = remaining
            .get(index + 1)
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag {
            "--manifest" if manifest_path.is_none() => {
                manifest_path = Some(PathBuf::from(value));
            }
            "--reports" if reports_path.is_none() => {
                reports_path = Some(PathBuf::from(value));
            }
            "--manifest" | "--reports" => return Err(format!("duplicate flag {flag}").into()),
            _ => return Err(format!("unknown argument {flag}").into()),
        }
        index += 2;
    }

    let manifest_path = manifest_path.ok_or("--manifest is required")?;
    let reports_path = reports_path.ok_or("--reports is required")?;
    let manifest = CapabilityManifestV1::load(manifest_path)?;
    let mut reports = BTreeMap::new();
    for entry in fs::read_dir(&reports_path)? {
        let path = entry?.path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
            continue;
        }
        let bytes = fs::read(&path)?;
        let report: ProbeReport = serde_json::from_slice(&bytes)?;
        let target = report.target_triple.clone();
        if reports.insert(target.clone(), report).is_some() {
            return Err(format!("duplicate probe report for target {target}").into());
        }
    }

    manifest.validate_profiles(&reports)?;
    println!(
        "Manifest identity and capability checks passed for {} report(s).",
        reports.len()
    );
    Ok(())
}
