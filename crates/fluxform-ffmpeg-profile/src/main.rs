use fluxform_ffmpeg_profile::{ArtifactStatus, BuildProfile, ProbeReport};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

fn main() {
    if let Err(error) = run() {
        eprintln!("FFmpeg profile verification failed: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("verify") {
        return Err("usage: fluxform-ffmpeg-profile verify --profile PROFILE_PATH --ffmpeg FFMPEG_PATH --ffprobe FFPROBE_PATH --out REPORT_PATH".into());
    }

    let mut options = BTreeMap::new();
    while let Some(option) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {option}"))?;
        if !matches!(
            option.as_str(),
            "--profile" | "--ffmpeg" | "--ffprobe" | "--out"
        ) {
            return Err(format!("unknown option {option}").into());
        }
        if options.insert(option.clone(), value).is_some() {
            return Err(format!("duplicate option {option}").into());
        }
    }
    let required = |name: &str| {
        options
            .get(name)
            .map(PathBuf::from)
            .ok_or_else(|| format!("missing required option {name}"))
    };
    let profile_path = required("--profile")?;
    let ffmpeg_path = required("--ffmpeg")?;
    let ffprobe_path = required("--ffprobe")?;
    let output_path = required("--out")?;

    let profile = BuildProfile::load(profile_path)?;
    let mut report = ProbeReport::collect(ffmpeg_path, ffprobe_path)?;
    report.validate(&profile)?;
    if report.artifact_status == ArtifactStatus::Approved {
        let approval = profile.approved_artifact(&report.artifact_id)?;
        report.verify_identity(&approval)?;
    }

    if let Some(parent) = output_path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut json = serde_json::to_string_pretty(&report)?;
    json.push('\n');
    fs::write(&output_path, json)?;
    println!(
        "verified {} ({:?}) for target {} with distribution gate {}",
        report.artifact_id,
        report.artifact_status,
        report.target_triple,
        report.distribution_gate_status
    );
    Ok(())
}
