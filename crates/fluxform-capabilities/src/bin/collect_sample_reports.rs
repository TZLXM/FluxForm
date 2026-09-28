use fluxform_capabilities::collector::collect_sample_reports;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
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
    let required = |name: &str| -> Result<&PathBuf, String> {
        arguments
            .get(name)
            .ok_or_else(|| format!("missing required argument --{name}"))
    };
    let expected_digest = arguments
        .get("expected-input-digest")
        .ok_or_else(|| "missing required argument --expected-input-digest".to_owned())?
        .to_string_lossy();
    let aggregate = collect_sample_reports(
        &root,
        required("input")?.clone(),
        required("manifest")?.clone(),
        required("samples")?.clone(),
        &expected_digest,
    )?;
    let output = required("out")?.clone();
    if let Some(parent) = output
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .map_err(|error| format!("could not create aggregate directory: {error}"))?;
    }
    let mut bytes = serde_json::to_vec_pretty(&aggregate).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    fs::write(&output, bytes)
        .map_err(|error| format!("could not write aggregate report: {error}"))?;
    println!(
        "{}: passed ({} native targets)",
        aggregate.schema,
        aggregate.targets.len()
    );
    Ok(())
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
            "input" | "manifest" | "samples" | "expected-input-digest" | "out"
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
        "input",
        "manifest",
        "samples",
        "expected-input-digest",
        "out",
    ] {
        if !parsed.contains_key(required) {
            return Err(format!("missing required argument --{required}"));
        }
    }
    Ok(parsed)
}
