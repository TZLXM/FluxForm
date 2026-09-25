use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

const CONTRACT_PREFIX: &str = "contracts/v1/";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let freeze_v1 = match std::env::args().skip(1).collect::<Vec<_>>().as_slice() {
        [] => false,
        [flag] if flag == "--freeze-v1" => true,
        _ => return Err("usage: export_contracts [--freeze-v1]".into()),
    };

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()?;
    let contract_root = workspace.join("contracts/v1");
    fs::create_dir_all(&contract_root)?;
    let contract_root = contract_root.canonicalize()?;

    for (relative_path, value) in fluxform_protocol::exported_contracts() {
        let output = safe_output_path(&contract_root, relative_path)?;
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut rendered = serde_json::to_string_pretty(&value)?;
        rendered.push('\n');
        fs::write(output, rendered)?;
    }

    if freeze_v1 {
        let digest_path = contract_root.join("compatibility.sha256");
        let mut digest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(digest_path)?;
        writeln!(digest_file, "{}", fluxform_protocol::contract_digest())?;
    }

    Ok(())
}

fn safe_output_path(
    contract_root: &Path,
    relative_path: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let relative = relative_path
        .strip_prefix(CONTRACT_PREFIX)
        .ok_or("contract path is outside contracts/v1")?;
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err("contract path is outside contracts/v1".into());
    }
    Ok(contract_root.join(relative))
}
