use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
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
    ensure_directory_tree(&workspace, &contract_root)?;

    for (relative_path, value) in fluxform_protocol::exported_contracts() {
        let mut rendered = serde_json::to_string_pretty(&value)?;
        rendered.push('\n');
        write_contract(&contract_root, relative_path, rendered.as_bytes())?;
    }

    if freeze_v1 {
        freeze_digest(&contract_root)?;
    }

    Ok(())
}

fn freeze_digest(contract_root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    ensure_directory_tree(contract_root, contract_root)?;
    let digest_path = safe_output_path(contract_root, "contracts/v1/compatibility.sha256")?;
    let mut digest_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(digest_path)?;
    writeln!(digest_file, "{}", fluxform_protocol::contract_digest())?;
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

fn write_contract(
    contract_root: &Path,
    relative_path: &str,
    contents: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let output = safe_output_path(contract_root, relative_path)?;
    let parent = output.parent().ok_or("contract has no parent directory")?;
    ensure_directory_tree(contract_root, parent)?;

    if let Ok(metadata) = fs::symlink_metadata(&output)
        && is_link_or_reparse_point(&metadata)
    {
        return Err("contract destination is a link or reparse point".into());
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(contents)?;
    temporary.as_file().sync_all()?;

    ensure_directory_tree(contract_root, parent)?;
    match fs::symlink_metadata(&output) {
        Ok(metadata) => {
            if is_link_or_reparse_point(&metadata) {
                return Err("contract destination is a link or reparse point".into());
            }
            if !metadata.is_file() {
                return Err("contract destination is not a regular file".into());
            }
            fs::remove_file(&output)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    temporary.persist(&output)?;
    Ok(())
}

fn ensure_directory_tree(root: &Path, directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let relative = directory
        .strip_prefix(root)
        .map_err(|_| "contract directory is outside contracts/v1")?;
    let mut current = root.to_owned();
    reject_directory_link(&current)?;
    for component in relative.components() {
        if !matches!(component, Component::Normal(_)) {
            return Err("contract directory is outside contracts/v1".into());
        }
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(_) => reject_directory_link(&current)?,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                fs::create_dir(&current)?;
                reject_directory_link(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn reject_directory_link(directory: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(directory)?;
    if !metadata.is_dir() || is_link_or_reparse_point(&metadata) {
        return Err("contract directory is a link, reparse point, or non-directory".into());
    }
    Ok(())
}

fn is_link_or_reparse_point(metadata: &fs::Metadata) -> bool {
    if metadata.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_directory_link_escape() {
        let temp = tempfile::tempdir().unwrap();
        let contract_root = temp.path().join("contracts/v1");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&contract_root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        create_directory_link(&outside, &contract_root.join("fixtures"));

        let result = write_contract(
            &contract_root,
            "contracts/v1/fixtures/escape.json",
            b"escaped\n",
        );

        assert!(result.is_err());
        assert!(!outside.join("escape.json").exists());
    }

    #[test]
    fn replaces_destination_hard_link_without_writing_its_external_target() {
        let temp = tempfile::tempdir().unwrap();
        let contract_root = temp.path().join("contracts/v1");
        let outside = temp.path().join("outside.json");
        let destination = contract_root.join("error.schema.json");
        fs::create_dir_all(&contract_root).unwrap();
        fs::write(&outside, "outside\n").unwrap();
        fs::hard_link(&outside, &destination).unwrap();

        write_contract(
            &contract_root,
            "contracts/v1/error.schema.json",
            b"contract\n",
        )
        .unwrap();

        assert_eq!(fs::read_to_string(outside).unwrap(), "outside\n");
        assert_eq!(fs::read_to_string(destination).unwrap(), "contract\n");
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) {
        junction::create(target, link).unwrap();
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }
}
