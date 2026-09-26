use super::{ArchiveFormat, ArtifactRecord, ProfileError};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::OsString;
#[cfg(windows)]
use std::fs::OpenOptions;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const EOCD_SIGNATURE: u32 = 0x0605_4b50;
const ZIP64_LOCATOR_SIGNATURE: u32 = 0x0706_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const DATA_DESCRIPTOR_SIGNATURE: u32 = 0x0807_4b50;
const MAX_ZIP_ENTRIES: usize = 4096;
const MAX_CENTRAL_DIRECTORY_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_ENTRY_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(120);
const SYSTEM_UNZIP: &str = "/usr/bin/unzip";

#[derive(Debug, Clone)]
pub(super) struct ZipEntry {
    pub(super) name: String,
    pub(super) is_directory: bool,
    compressed_size: u64,
    uncompressed_size: u64,
    local_offset: u64,
    flags: u16,
    method: u16,
    crc32: u32,
}

#[derive(Debug)]
struct LocalRange {
    start: u64,
    end: u64,
}

pub(crate) struct VerifiedArchive {
    _temp_dir: TempDir,
    pub(crate) ffmpeg_path: PathBuf,
    pub(crate) ffprobe_path: PathBuf,
    pub(crate) artifact_sha256: String,
    pub(crate) artifact_size_bytes: u64,
    pub(crate) ffmpeg_sha256: String,
    pub(crate) ffmpeg_size_bytes: u64,
    pub(crate) ffprobe_sha256: String,
    pub(crate) ffprobe_size_bytes: u64,
    pub(crate) license_text_sha256: String,
    pub(crate) license_text_size_bytes: u64,
}

impl VerifiedArchive {
    pub(crate) fn close(self) -> Result<(), ProfileError> {
        let temp_path = self._temp_dir.path().to_path_buf();
        self._temp_dir
            .close()
            .map_err(|source| io_error(&temp_path, source))
    }
}

#[cfg(test)]
impl VerifiedArchive {
    pub(super) fn temp_root(&self) -> &Path {
        self._temp_dir.path()
    }
}

pub(super) fn verify_archive_identity(
    artifact: &ArtifactRecord,
    archive_path: &Path,
) -> Result<(), ProfileError> {
    let mut archive = open_regular_file_without_reparse(archive_path)?;
    let metadata = archive
        .metadata()
        .map_err(|source| io_error(archive_path, source))?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(unsafe_archive("archive path is not a regular file"));
    }
    let (observed_sha256, observed_size_bytes) = fingerprint_handle(&mut archive)?;
    if observed_size_bytes != artifact.artifact_size_bytes
        || !observed_sha256.eq_ignore_ascii_case(&artifact.artifact_sha256)
    {
        return Err(ProfileError::ArchiveIdentityMismatch);
    }
    Ok(())
}

pub(crate) fn extract_and_verify(
    artifact: &ArtifactRecord,
    archive_path: &Path,
) -> Result<VerifiedArchive, ProfileError> {
    verify_archive_identity(artifact, archive_path)?;
    extract_and_verify_native(artifact, archive_path)
}

fn extract_and_verify_native(
    artifact: &ArtifactRecord,
    archive_path: &Path,
) -> Result<VerifiedArchive, ProfileError> {
    let original_archive = open_regular_file_without_reparse(archive_path)?;
    let metadata = original_archive
        .metadata()
        .map_err(|source| io_error(archive_path, source))?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(unsafe_archive("archive path is not a regular file"));
    }

    let resolved_path = archive_path
        .canonicalize()
        .map_err(|source| io_error(archive_path, source))?;
    let mut archive_file = open_regular_file_without_reparse(&resolved_path)?;
    let (artifact_sha256, artifact_size_bytes) = fingerprint_handle(&mut archive_file)?;
    if artifact_size_bytes != artifact.artifact_size_bytes
        || !artifact_sha256.eq_ignore_ascii_case(&artifact.artifact_sha256)
    {
        return Err(ProfileError::ArchiveIdentityMismatch);
    }

    let entries = inspect_zip_archive(&mut archive_file, artifact_size_bytes)?;
    let (ffmpeg_name, ffprobe_name) = executable_names(&artifact.target_triple)?;
    let ffmpeg_entry = unique_executable_entry(&entries, ffmpeg_name)?;
    let ffprobe_entry = unique_executable_entry(&entries, ffprobe_name)?;
    if parent_entry(&ffmpeg_entry.name) != parent_entry(&ffprobe_entry.name) {
        return Err(unsafe_archive("ffmpeg and ffprobe must be sibling entries"));
    }
    let license_entry = entries
        .iter()
        .find(|entry| entry.name == artifact.license_text_path && !entry.is_directory)
        .ok_or_else(|| unsafe_archive("declared license text is missing from the archive"))?;
    validate_entry_name(&artifact.license_text_path, false)?;

    let temp_dir = TempDir::new().map_err(|source| io_error(Path::new("system temp"), source))?;
    let extracted = (|| {
        let extractor = extractor_spec(
            std::env::consts::OS,
            artifact.archive_format,
            &resolved_path,
            temp_dir.path(),
        )?;
        extract_with_trusted_program(&extractor)?;

        let ffmpeg_path = verified_extracted_file(temp_dir.path(), &ffmpeg_entry.name)?;
        let ffprobe_path = verified_extracted_file(temp_dir.path(), &ffprobe_entry.name)?;
        let license_path = verified_extracted_file(temp_dir.path(), &license_entry.name)?;
        let (ffmpeg_sha256, ffmpeg_size_bytes) = fingerprint_verified_file(&ffmpeg_path)?;
        let (ffprobe_sha256, ffprobe_size_bytes) = fingerprint_verified_file(&ffprobe_path)?;
        let (license_text_sha256, license_text_size_bytes) =
            fingerprint_verified_file(&license_path)?;

        verify_expected_file(
            ffmpeg_name,
            &ffmpeg_sha256,
            ffmpeg_size_bytes,
            &artifact.ffmpeg_sha256,
            artifact.ffmpeg_size_bytes,
        )?;
        verify_expected_file(
            ffprobe_name,
            &ffprobe_sha256,
            ffprobe_size_bytes,
            &artifact.ffprobe_sha256,
            artifact.ffprobe_size_bytes,
        )?;
        verify_expected_file(
            "license text",
            &license_text_sha256,
            license_text_size_bytes,
            &artifact.license_text_sha256,
            artifact.license_text_size_bytes,
        )?;

        Ok::<_, ProfileError>((
            ffmpeg_path,
            ffprobe_path,
            ffmpeg_sha256,
            ffmpeg_size_bytes,
            ffprobe_sha256,
            ffprobe_size_bytes,
            license_text_sha256,
            license_text_size_bytes,
        ))
    })();

    drop(archive_file);
    drop(original_archive);
    let (
        ffmpeg_path,
        ffprobe_path,
        ffmpeg_sha256,
        ffmpeg_size_bytes,
        ffprobe_sha256,
        ffprobe_size_bytes,
        license_text_sha256,
        license_text_size_bytes,
    ) = match extracted {
        Ok(measurements) => measurements,
        Err(error) => {
            let temp_path = temp_dir.path().to_path_buf();
            return match temp_dir.close() {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(unsafe_archive(format!(
                    "{error}; temporary archive cleanup also failed: {}",
                    io_error(&temp_path, cleanup_error)
                ))),
            };
        }
    };
    Ok(VerifiedArchive {
        _temp_dir: temp_dir,
        ffmpeg_path,
        ffprobe_path,
        artifact_sha256,
        artifact_size_bytes,
        ffmpeg_sha256,
        ffmpeg_size_bytes,
        ffprobe_sha256,
        ffprobe_size_bytes,
        license_text_sha256,
        license_text_size_bytes,
    })
}

fn unique_executable_entry<'a>(
    entries: &'a [ZipEntry],
    executable_name: &str,
) -> Result<&'a ZipEntry, ProfileError> {
    let mut matches = entries.iter().filter(|entry| {
        !entry.is_directory
            && entry
                .name
                .rsplit('/')
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case(executable_name))
    });
    let entry = matches
        .next()
        .ok_or_else(|| unsafe_archive(format!("{executable_name} is missing from the archive")))?;
    if matches.next().is_some() {
        return Err(unsafe_archive(format!(
            "archive contains more than one {executable_name}"
        )));
    }
    Ok(entry)
}

fn parent_entry(name: &str) -> &str {
    name.rsplit_once('/').map_or("", |(parent, _)| parent)
}

fn extractor_spec(
    os: &str,
    archive_format: ArchiveFormat,
    archive_path: &Path,
    destination: &Path,
) -> Result<ExtractorSpec, ProfileError> {
    let (program, fixed_arguments, destination_flag) = match (os, archive_format) {
        ("windows", ArchiveFormat::Zip32) => (
            r"C:\Windows\System32\tar.exe",
            vec!["-x", "-k", "-m", "-f"],
            "-C",
        ),
        ("macos" | "linux", ArchiveFormat::Zip32) => (SYSTEM_UNZIP, vec!["-qq", "-o"], "-d"),
        _ => {
            return Err(unsafe_archive(format!(
                "no trusted extractor is configured for {archive_format:?} on {os}"
            )));
        }
    };
    let mut arguments = fixed_arguments
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    arguments.push(archive_path.as_os_str().to_owned());
    arguments.push(OsString::from(destination_flag));
    arguments.push(destination.as_os_str().to_owned());
    Ok(ExtractorSpec {
        program: PathBuf::from(program),
        arguments,
    })
}

#[derive(Debug)]
struct ExtractorSpec {
    program: PathBuf,
    arguments: Vec<OsString>,
}

fn executable_names(target_triple: &str) -> Result<(&'static str, &'static str), ProfileError> {
    if target_triple.contains("-windows-") {
        Ok(("ffmpeg.exe", "ffprobe.exe"))
    } else if target_triple.contains("-apple-darwin") || target_triple.contains("-linux-") {
        Ok(("ffmpeg", "ffprobe"))
    } else {
        Err(unsafe_archive(format!(
            "native archive executable names are unsupported for target {target_triple}"
        )))
    }
}

fn extract_with_trusted_program(spec: &ExtractorSpec) -> Result<(), ProfileError> {
    let extractor = &spec.program;
    let metadata = fs::symlink_metadata(extractor).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            unsafe_archive(format!(
                "trusted extractor is unavailable at {}",
                extractor.display()
            ))
        } else {
            io_error(extractor, source)
        }
    })?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(unsafe_archive(
            "trusted archive extractor is not a regular file",
        ));
    }

    let mut child = Command::new(extractor)
        .args(&spec.arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|source| io_error(extractor, source))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|source| io_error(extractor, source))?
        {
            if !status.success() {
                return Err(unsafe_archive(format!(
                    "trusted archive extractor exited with {status}"
                )));
            }
            return Ok(());
        }
        if started.elapsed() >= EXTRACT_TIMEOUT {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ProfileError::Timeout(extractor.to_path_buf()));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn verified_extracted_file(root: &Path, relative_name: &str) -> Result<PathBuf, ProfileError> {
    validate_entry_name(relative_name, false)?;
    let mut candidate = root.to_path_buf();
    for component in relative_name.split('/') {
        candidate.push(component);
        let metadata =
            fs::symlink_metadata(&candidate).map_err(|source| io_error(&candidate, source))?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(unsafe_archive(
                "extracted entry contains a link or reparse point",
            ));
        }
    }
    let metadata =
        fs::symlink_metadata(&candidate).map_err(|source| io_error(&candidate, source))?;
    if !metadata.is_file() {
        return Err(unsafe_archive(
            "expected extracted entry is not a regular file",
        ));
    }
    let canonical_root = root
        .canonicalize()
        .map_err(|source| io_error(root, source))?;
    let canonical_candidate = candidate
        .canonicalize()
        .map_err(|source| io_error(&candidate, source))?;
    if !canonical_candidate.starts_with(&canonical_root) {
        return Err(unsafe_archive("extracted entry escaped its temporary root"));
    }
    Ok(candidate)
}

fn fingerprint_verified_file(path: &Path) -> Result<(String, u64), ProfileError> {
    let mut file = open_regular_file_without_reparse(path)?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(unsafe_archive(
            "expected extracted entry is not a regular file",
        ));
    }
    fingerprint_handle(&mut file)
}

fn open_regular_file_without_reparse(path: &Path) -> Result<File, ProfileError> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|source| io_error(path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(path, source))?;
        if !metadata.is_file() || is_reparse_point(&metadata) {
            return Err(unsafe_archive("path is not a regular non-reparse file"));
        }
        Ok(file)
    }
    #[cfg(not(windows))]
    {
        let file = File::open(path).map_err(|source| io_error(path, source))?;
        let metadata = file.metadata().map_err(|source| io_error(path, source))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(unsafe_archive("path is not a regular file"));
        }
        Ok(file)
    }
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_symlink()
}

fn fingerprint_handle(file: &mut File) -> Result<(String, u64), ProfileError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| unsafe_archive(format!("could not rewind archive/file: {error}")))?;
    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| unsafe_archive(format!("could not read archive/file: {error}")))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes_read = bytes_read
            .checked_add(count as u64)
            .ok_or_else(|| unsafe_archive("archive/file size overflow"))?;
    }
    Ok((format!("{:x}", hasher.finalize()), bytes_read))
}

fn verify_expected_file(
    name: &str,
    observed_sha256: &str,
    observed_size_bytes: u64,
    expected_sha256: &str,
    expected_size_bytes: u64,
) -> Result<(), ProfileError> {
    if observed_size_bytes != expected_size_bytes
        || !observed_sha256.eq_ignore_ascii_case(expected_sha256)
    {
        return Err(unsafe_archive(format!(
            "{name} identity mismatch: measured size or SHA-256 differs from the immutable profile row"
        )));
    }
    Ok(())
}

#[cfg(any(unix, windows, test))]
pub(super) fn inspect_zip_archive<R: Read + Seek>(
    archive: &mut R,
    archive_size: u64,
) -> Result<Vec<ZipEntry>, ProfileError> {
    if archive_size < 22 || archive_size > u32::MAX as u64 {
        return Err(unsafe_archive(
            "archive size is outside supported ZIP32 limits",
        ));
    }
    let tail_size = archive_size.min(22 + u16::MAX as u64) as usize;
    let tail_offset = archive_size - tail_size as u64;
    let tail = read_region(archive, tail_offset, tail_size as u64)?;
    let eocd = (0..=tail.len() - 22)
        .rev()
        .find(|offset| {
            read_u32(&tail, *offset) == Some(EOCD_SIGNATURE)
                && read_u16(&tail, *offset + 20)
                    .is_some_and(|comment| *offset + 22 + comment as usize == tail.len())
        })
        .ok_or_else(|| unsafe_archive("ZIP end-of-central-directory record is missing"))?;
    let eocd_offset = tail_offset + eocd as u64;
    if eocd_offset >= 20 {
        let locator = read_region(archive, eocd_offset - 20, 4)?;
        if read_u32(&locator, 0) == Some(ZIP64_LOCATOR_SIGNATURE) {
            return Err(unsafe_archive("ZIP64 archives are not supported"));
        }
    }
    let disk = required_u16(&tail, eocd + 4, "EOCD disk number")?;
    let central_disk = required_u16(&tail, eocd + 6, "central directory disk number")?;
    let entries_on_disk = required_u16(&tail, eocd + 8, "entries on disk")?;
    let entry_count = required_u16(&tail, eocd + 10, "entry count")?;
    let central_size = required_u32(&tail, eocd + 12, "central directory size")? as u64;
    let central_offset = required_u32(&tail, eocd + 16, "central directory offset")? as u64;
    if disk != 0 || central_disk != 0 || entries_on_disk != entry_count {
        return Err(unsafe_archive("multi-disk ZIP archives are not supported"));
    }
    if entry_count == u16::MAX || entry_count as usize > MAX_ZIP_ENTRIES {
        return Err(unsafe_archive(
            "ZIP entry count is unsupported or exceeds its limit",
        ));
    }
    if central_size > MAX_CENTRAL_DIRECTORY_BYTES
        || central_offset.checked_add(central_size) != Some(eocd_offset)
    {
        return Err(unsafe_archive(
            "central directory bounds are invalid or include unsupported records",
        ));
    }
    let central = read_region(archive, central_offset, central_size)?;
    let mut cursor = 0_usize;
    let mut entries = Vec::with_capacity(entry_count as usize);
    let mut names = BTreeSet::new();
    let mut local_ranges = Vec::with_capacity(entry_count as usize);
    let mut expanded_size = 0_u64;
    for _ in 0..entry_count {
        if read_u32(&central, cursor) != Some(CENTRAL_SIGNATURE) {
            return Err(unsafe_archive(
                "central directory entry signature is invalid",
            ));
        }
        let version_made_by = required_u16(&central, cursor + 4, "version made by")?;
        let version_needed = required_u16(&central, cursor + 6, "version needed")?;
        let flags = required_u16(&central, cursor + 8, "entry flags")?;
        let method = required_u16(&central, cursor + 10, "compression method")?;
        let crc32 = required_u32(&central, cursor + 16, "entry CRC-32")?;
        let compressed_size = required_u32(&central, cursor + 20, "compressed size")? as u64;
        let uncompressed_size = required_u32(&central, cursor + 24, "uncompressed size")? as u64;
        let name_len = required_u16(&central, cursor + 28, "entry name length")? as usize;
        let extra_len = required_u16(&central, cursor + 30, "entry extra length")? as usize;
        let comment_len = required_u16(&central, cursor + 32, "entry comment length")? as usize;
        let disk_start = required_u16(&central, cursor + 34, "entry disk number")?;
        let external_attributes = required_u32(&central, cursor + 38, "external attributes")?;
        let local_offset = required_u32(&central, cursor + 42, "local header offset")? as u64;
        if version_needed >= 45
            || compressed_size == u32::MAX as u64
            || uncompressed_size == u32::MAX as u64
            || local_offset == u32::MAX as u64
        {
            return Err(unsafe_archive("ZIP64 entries are not supported"));
        }
        if disk_start != 0 {
            return Err(unsafe_archive("multi-disk ZIP entries are not supported"));
        }
        if flags & !0x0808 != 0 {
            return Err(unsafe_archive(
                "encrypted or reserved ZIP entry flags are not supported",
            ));
        }
        if !matches!(method, 0 | 8) {
            return Err(unsafe_archive(
                "only stored and deflate ZIP entries are supported",
            ));
        }
        if method == 0 && compressed_size != uncompressed_size {
            return Err(unsafe_archive(
                "stored ZIP entries must have equal compressed and uncompressed sizes",
            ));
        }
        let variable_start = cursor
            .checked_add(46)
            .ok_or_else(|| unsafe_archive("central directory offset overflow"))?;
        let name_end = variable_start
            .checked_add(name_len)
            .ok_or_else(|| unsafe_archive("entry name length overflow"))?;
        let extra_end = name_end
            .checked_add(extra_len)
            .ok_or_else(|| unsafe_archive("entry extra length overflow"))?;
        let comment_end = extra_end
            .checked_add(comment_len)
            .ok_or_else(|| unsafe_archive("entry comment length overflow"))?;
        if comment_end > central.len() {
            return Err(unsafe_archive("central directory entry is truncated"));
        }
        let raw_name = &central[variable_start..name_end];
        let extra = &central[name_end..extra_end];
        inspect_extra_fields(extra)?;
        let name = std::str::from_utf8(raw_name)
            .map_err(|_| unsafe_archive("non-UTF-8 ZIP entry names are not supported"))?;
        let mode = (external_attributes >> 16) as u16;
        let dos_attributes = external_attributes as u16;
        let unix_type = if version_made_by >> 8 == 3 {
            mode & 0xf000
        } else {
            0
        };
        const FILE_ATTRIBUTE_DIRECTORY: u16 = 0x0010;
        const FILE_ATTRIBUTE_VOLUME_LABEL: u16 = 0x0008;
        const FILE_ATTRIBUTE_DEVICE: u16 = 0x0040;
        const FILE_ATTRIBUTE_REPARSE_POINT: u16 = 0x0400;
        if dos_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(unsafe_archive(
                "ZIP reparse-point entries are not supported",
            ));
        }
        if dos_attributes & (FILE_ATTRIBUTE_VOLUME_LABEL | FILE_ATTRIBUTE_DEVICE) != 0 {
            return Err(unsafe_archive(
                "ZIP volume-label and device entries are not supported",
            ));
        }
        if unix_type != 0 && !matches!(unix_type, 0x4000 | 0x8000) {
            return Err(unsafe_archive(
                "ZIP symlinks and special Unix files are not supported",
            ));
        }
        let trailing_slash = name.ends_with('/');
        let unix_directory = unix_type == 0x4000;
        let dos_directory = dos_attributes & FILE_ATTRIBUTE_DIRECTORY != 0;
        let is_directory = trailing_slash || unix_directory || dos_directory;
        if trailing_slash != is_directory
            || (unix_type == 0x8000 && is_directory)
            || (is_directory && (compressed_size != 0 || uncompressed_size != 0 || method != 0))
        {
            return Err(unsafe_archive("ZIP directory metadata is inconsistent"));
        }
        let safe_name = validate_entry_name(name, is_directory)?;
        let normalized_name = safe_name.to_ascii_lowercase();
        if !names.insert(normalized_name) {
            return Err(unsafe_archive(
                "ZIP contains duplicate or case-colliding paths",
            ));
        }
        if uncompressed_size > MAX_ENTRY_UNCOMPRESSED_BYTES {
            return Err(unsafe_archive(
                "ZIP entry exceeds the uncompressed size limit",
            ));
        }
        expanded_size = expanded_size
            .checked_add(uncompressed_size)
            .ok_or_else(|| unsafe_archive("ZIP expanded size overflow"))?;
        if expanded_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            return Err(unsafe_archive(
                "ZIP exceeds the total uncompressed size limit",
            ));
        }
        let entry = ZipEntry {
            name: safe_name,
            is_directory,
            compressed_size,
            uncompressed_size,
            local_offset,
            flags,
            method,
            crc32,
        };
        let local_end = inspect_local_header(archive, &entry, central_offset)?;
        local_ranges.push(LocalRange {
            start: local_offset,
            end: local_end,
        });
        entries.push(entry);
        cursor = comment_end;
    }
    if cursor != central.len() {
        return Err(unsafe_archive(
            "central directory has unindexed trailing data",
        ));
    }
    validate_path_prefixes(&entries)?;
    local_ranges.sort_by_key(|range| range.start);
    let mut next_local_offset = 0_u64;
    for range in local_ranges {
        if range.start != next_local_offset || range.end < range.start {
            return Err(unsafe_archive(
                "local ZIP entries overlap, contain gaps, or have an unsafe prefix",
            ));
        }
        next_local_offset = range.end;
    }
    if next_local_offset != central_offset {
        return Err(unsafe_archive(
            "ZIP local entries do not cover the data region",
        ));
    }
    Ok(entries)
}

#[cfg(any(unix, windows, test))]
fn inspect_local_header<R: Read + Seek>(
    archive: &mut R,
    entry: &ZipEntry,
    central_offset: u64,
) -> Result<u64, ProfileError> {
    let fixed = read_region(archive, entry.local_offset, 30)?;
    if read_u32(&fixed, 0) != Some(LOCAL_SIGNATURE) {
        return Err(unsafe_archive("local ZIP header signature is invalid"));
    }
    let flags = required_u16(&fixed, 6, "local entry flags")?;
    let method = required_u16(&fixed, 8, "local compression method")?;
    let crc32 = required_u32(&fixed, 14, "local entry CRC-32")?;
    let compressed_size = required_u32(&fixed, 18, "local compressed size")? as u64;
    let uncompressed_size = required_u32(&fixed, 22, "local uncompressed size")? as u64;
    let name_len = required_u16(&fixed, 26, "local entry name length")? as usize;
    let extra_len = required_u16(&fixed, 28, "local entry extra length")? as usize;
    let local_name_offset = entry.local_offset + 30;
    let local_name = read_region(archive, local_name_offset, name_len as u64)?;
    if local_name != entry.name.as_bytes() || flags != entry.flags || method != entry.method {
        return Err(unsafe_archive(
            "local ZIP header disagrees with its central-directory entry",
        ));
    }
    let local_extra_offset = local_name_offset + name_len as u64;
    let local_extra = read_region(archive, local_extra_offset, extra_len as u64)?;
    inspect_extra_fields(&local_extra)?;
    let has_data_descriptor = entry.flags & 0x0008 != 0;
    if has_data_descriptor {
        if !matches!(crc32, 0 | u32::MAX) && crc32 != entry.crc32
            || !(compressed_size == 0 || compressed_size == u32::MAX as u64)
                && compressed_size != entry.compressed_size
            || !(uncompressed_size == 0 || uncompressed_size == u32::MAX as u64)
                && uncompressed_size != entry.uncompressed_size
        {
            return Err(unsafe_archive(
                "local ZIP placeholder sizes are inconsistent",
            ));
        }
    } else if crc32 != entry.crc32
        || compressed_size != entry.compressed_size
        || uncompressed_size != entry.uncompressed_size
    {
        return Err(unsafe_archive(
            "local ZIP sizes or CRC disagree with the central directory",
        ));
    }
    let data_start = local_extra_offset + extra_len as u64;
    let data_end = data_start
        .checked_add(entry.compressed_size)
        .ok_or_else(|| unsafe_archive("compressed data offset overflow"))?;
    if data_end > central_offset {
        return Err(unsafe_archive(
            "ZIP entry data overlaps the central directory",
        ));
    }
    let end = if has_data_descriptor {
        inspect_data_descriptor(archive, data_end, entry, central_offset)?
    } else {
        data_end
    };
    if end > central_offset {
        return Err(unsafe_archive(
            "ZIP data descriptor overlaps the central directory",
        ));
    }
    Ok(end)
}

#[cfg(any(unix, windows, test))]
fn inspect_data_descriptor<R: Read + Seek>(
    archive: &mut R,
    offset: u64,
    entry: &ZipEntry,
    central_offset: u64,
) -> Result<u64, ProfileError> {
    let first = read_region(archive, offset, 4)?;
    let first_value = required_u32(&first, 0, "data descriptor")?;
    let (crc_offset, descriptor_end) = if first_value == DATA_DESCRIPTOR_SIGNATURE {
        (offset + 4, offset + 16)
    } else {
        (offset, offset + 12)
    };
    if descriptor_end > central_offset {
        return Err(unsafe_archive("ZIP data descriptor is truncated"));
    }
    let descriptor = read_region(archive, crc_offset, 12)?;
    if required_u32(&descriptor, 0, "data descriptor CRC")? != entry.crc32
        || required_u32(&descriptor, 4, "data descriptor compressed size")? as u64
            != entry.compressed_size
        || required_u32(&descriptor, 8, "data descriptor uncompressed size")? as u64
            != entry.uncompressed_size
    {
        return Err(unsafe_archive(
            "ZIP data descriptor disagrees with the central directory",
        ));
    }
    Ok(descriptor_end)
}

#[cfg(any(unix, windows, test))]
fn inspect_extra_fields(extra: &[u8]) -> Result<(), ProfileError> {
    let mut cursor = 0_usize;
    while cursor < extra.len() {
        if cursor + 4 > extra.len() {
            return Err(unsafe_archive("ZIP extra field is truncated"));
        }
        let field_id = required_u16(extra, cursor, "extra field ID")?;
        let field_len = required_u16(extra, cursor + 2, "extra field length")? as usize;
        cursor += 4;
        let end = cursor
            .checked_add(field_len)
            .ok_or_else(|| unsafe_archive("ZIP extra field length overflow"))?;
        if end > extra.len() {
            return Err(unsafe_archive("ZIP extra field value is truncated"));
        }
        if matches!(field_id, 0x0001 | 0x7075 | 0x9901) {
            return Err(unsafe_archive(
                "ZIP64, Unicode path override, or AES extra fields are not supported",
            ));
        }
        cursor = end;
    }
    Ok(())
}

#[cfg(any(unix, windows, test))]
fn validate_entry_name(name: &str, is_directory: bool) -> Result<String, ProfileError> {
    if name.is_empty() || name.len() > 180 || !name.is_ascii() {
        return Err(unsafe_archive(
            "ZIP entry path is empty, too long, or non-ASCII",
        ));
    }
    if name.starts_with('/') || name.contains('\\') || name.contains(':') {
        return Err(unsafe_archive(
            "ZIP entry path is absolute or platform-ambiguous",
        ));
    }
    if name.ends_with('/') != is_directory {
        return Err(unsafe_archive("ZIP directory path marker is inconsistent"));
    }
    let relative = if is_directory {
        name.strip_suffix('/').unwrap_or_default()
    } else {
        name
    };
    if relative.is_empty() {
        return Err(unsafe_archive(
            "ZIP entry path resolves to its extraction root",
        ));
    }
    for component in relative.split('/') {
        if component.is_empty()
            || matches!(component, "." | "..")
            || component.ends_with('.')
            || component.ends_with(' ')
            || component.chars().any(|character| {
                character.is_ascii_control()
                    || matches!(character, '<' | '>' | '"' | '|' | '?' | '*')
            })
        {
            return Err(unsafe_archive(
                "ZIP entry path contains an unsafe component",
            ));
        }
        let basename = component.split('.').next().unwrap_or_default();
        let uppercase = basename.to_ascii_uppercase();
        if matches!(uppercase.as_str(), "CON" | "PRN" | "AUX" | "NUL")
            || ["COM", "LPT"].iter().any(|prefix| {
                uppercase.strip_prefix(prefix).is_some_and(|suffix| {
                    suffix.len() == 1 && matches!(suffix.as_bytes()[0], b'1'..=b'9')
                })
            })
        {
            return Err(unsafe_archive(
                "ZIP entry path uses a reserved Windows name",
            ));
        }
    }
    Ok(name.to_owned())
}

#[cfg(any(unix, windows, test))]
fn validate_path_prefixes(entries: &[ZipEntry]) -> Result<(), ProfileError> {
    let mut files = BTreeSet::new();
    for entry in entries {
        let normalized = entry.name.trim_end_matches('/').to_ascii_lowercase();
        if !entry.is_directory {
            files.insert(normalized);
        }
    }
    for entry in entries {
        let normalized = entry.name.trim_end_matches('/').to_ascii_lowercase();
        let components = normalized.split('/').collect::<Vec<_>>();
        for index in 1..components.len() {
            let parent = components[..index].join("/");
            if files.contains(&parent) {
                return Err(unsafe_archive(
                    "a regular file is used as an entry directory",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(any(unix, windows, test))]
fn read_region<R: Read + Seek>(
    reader: &mut R,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, ProfileError> {
    let size =
        usize::try_from(length).map_err(|_| unsafe_archive("archive region is too large"))?;
    let end = offset
        .checked_add(length)
        .ok_or_else(|| unsafe_archive("archive region offset overflow"))?;
    reader
        .seek(SeekFrom::Start(offset))
        .map_err(|error| unsafe_archive(format!("could not seek in ZIP archive: {error}")))?;
    let mut bytes = vec![0_u8; size];
    reader.read_exact(&mut bytes).map_err(|error| {
        unsafe_archive(format!(
            "truncated ZIP archive region ending at {end}: {error}"
        ))
    })?;
    Ok(bytes)
}

#[cfg(any(unix, windows, test))]
fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let value = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes([value[0], value[1]]))
}

#[cfg(any(unix, windows, test))]
fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let value = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

#[cfg(any(unix, windows, test))]
fn required_u16(bytes: &[u8], offset: usize, label: &str) -> Result<u16, ProfileError> {
    read_u16(bytes, offset).ok_or_else(|| unsafe_archive(format!("truncated {label}")))
}

#[cfg(any(unix, windows, test))]
fn required_u32(bytes: &[u8], offset: usize, label: &str) -> Result<u32, ProfileError> {
    read_u32(bytes, offset).ok_or_else(|| unsafe_archive(format!("truncated {label}")))
}

fn unsafe_archive(message: impl Into<String>) -> ProfileError {
    ProfileError::UnsafeArchive(message.into())
}

fn io_error(path: &Path, source: io::Error) -> ProfileError {
    ProfileError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod extractor_spec_tests {
    use super::{ArchiveFormat, extractor_spec};
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    #[test]
    fn declared_zip32_format_has_fixed_native_extractors_and_argument_vectors() {
        let cases = [
            (
                "windows",
                r"C:\Windows\System32\tar.exe",
                vec![
                    "-x",
                    "-k",
                    "-m",
                    "-f",
                    r"C:\stage\candidate archive.zip",
                    "-C",
                    r"C:\stage\extracted",
                ],
            ),
            (
                "macos",
                "/usr/bin/unzip",
                vec![
                    "-qq",
                    "-o",
                    "/stage/candidate archive.zip",
                    "-d",
                    "/stage/extracted",
                ],
            ),
            (
                "linux",
                "/usr/bin/unzip",
                vec![
                    "-qq",
                    "-o",
                    "/stage/candidate archive.zip",
                    "-d",
                    "/stage/extracted",
                ],
            ),
        ];

        for (os, expected_program, expected_arguments) in cases {
            let (archive, destination) = if os == "windows" {
                (
                    PathBuf::from(r"C:\stage\candidate archive.zip"),
                    PathBuf::from(r"C:\stage\extracted"),
                )
            } else {
                (
                    PathBuf::from("/stage/candidate archive.zip"),
                    PathBuf::from("/stage/extracted"),
                )
            };
            let spec = extractor_spec(os, ArchiveFormat::Zip32, &archive, &destination)
                .expect("required native extractor");

            assert_eq!(spec.program, PathBuf::from(expected_program));
            let program_text = spec.program.to_string_lossy();
            assert!(program_text.starts_with('/') || program_text.as_bytes().get(1) == Some(&b':'));
            assert_eq!(
                spec.arguments,
                expected_arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn unsupported_extractor_platform_fails_closed() {
        assert!(
            extractor_spec(
                "freebsd",
                ArchiveFormat::Zip32,
                Path::new("a.zip"),
                Path::new("out")
            )
            .is_err()
        );
    }
}
