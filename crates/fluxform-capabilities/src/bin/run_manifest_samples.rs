use fluxform_capabilities::runner::{RUN_REPORT_SCHEMA_V1, RunSampleOptions, run_manifest_samples};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = parse_args(std::env::args().skip(1))?;
    let root = std::env::current_dir().map_err(|error| error.to_string())?;
    let required = |name: &str| -> Result<&Path, String> {
        arguments
            .get(name)
            .map(PathBuf::as_path)
            .ok_or_else(|| format!("missing required argument --{name}"))
    };
    let options = RunSampleOptions {
        repository_root: &root,
        manifest_path: required("manifest")?,
        samples_path: required("samples")?,
        profile_report_path: required("profile-report")?,
        ffmpeg_path: required("ffmpeg")?,
        ffprobe_path: required("ffprobe")?,
    };
    let report = run_manifest_samples(options)?;
    let report_path = required("out")?;
    if let Some(parent) = report_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create report directory: {error}"))?;
    }
    let mut bytes = serde_json::to_vec_pretty(&report).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(report_path, bytes).map_err(|error| format!("could not write report: {error}"))?;
    match report.status.as_str() {
        "passed" => {
            println!(
                "{}: passed ({} sample results)",
                RUN_REPORT_SCHEMA_V1,
                report.results.len()
            );
            Ok(())
        }
        "blocked" => Err(format!(
            "BLOCKED: {}; report written to {}",
            report.blockers.join("; "),
            report_path.display()
        )),
        _ => Err(format!(
            "FAILED: sample validation did not pass; report written to {}",
            report_path.display()
        )),
    }
}

fn parse_args(
    arguments: impl Iterator<Item = String>,
) -> Result<BTreeMap<String, PathBuf>, String> {
    let mut parsed = BTreeMap::new();
    let mut args = arguments;
    while let Some(flag) = args.next() {
        let name = flag
            .strip_prefix("--")
            .ok_or_else(|| format!("unexpected argument {flag}"))?;
        if !matches!(
            name,
            "manifest" | "samples" | "profile-report" | "ffmpeg" | "ffprobe" | "out"
        ) {
            return Err(format!("unknown argument --{name}"));
        }
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for --{name}"))?;
        if value.starts_with("--") {
            return Err(format!("missing value for --{name}"));
        }
        if parsed
            .insert(name.to_owned(), PathBuf::from(value))
            .is_some()
        {
            return Err(format!("duplicate argument --{name}"));
        }
    }
    for required in [
        "manifest",
        "samples",
        "profile-report",
        "ffmpeg",
        "ffprobe",
        "out",
    ] {
        if !parsed.contains_key(required) {
            return Err(format!("missing required argument --{required}"));
        }
    }
    Ok(parsed)
}
