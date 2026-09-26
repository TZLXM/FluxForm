//! Validated, handle-relative output reservations and atomic commits.
//!
//! A reservation is not committable until validation succeeds. Callers write
//! only to `partial_path()`, validate that file, and then consume the returned
//! `ValidatedOutput` to commit it.

use fluxform_capabilities::runner::{OutputExpectationsV1, expected_output};
use fluxform_capabilities::{ConversionEdgeV1, samples::SampleRecordV1};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;
use uuid::Uuid;

mod validator;
pub use validator::{FfprobeOutputValidator, OutputValidator};

#[cfg(windows)]
mod native {
    use super::{FileIdentity, OverwritePolicyV1, PathError, TrustedRootHandle};
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::path::Path;
    use std::ptr;

    type Handle = *mut c_void;
    type NtStatus = i32;

    const INVALID_HANDLE_VALUE: Handle = -1_isize as Handle;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;
    const FILE_ADD_FILE: u32 = 0x0000_0002;
    const FILE_DELETE_CHILD: u32 = 0x0000_0040;
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    const DELETE: u32 = 0x0001_0000;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
    const OBJ_CASE_INSENSITIVE: u32 = 0x0000_0040;
    const FILE_OPEN: u32 = 1;
    const FILE_CREATE: u32 = 2;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_INFO_BY_HANDLE_CLASS_FILE_RENAME_INFO: i32 = 3;
    const FILE_INFO_BY_HANDLE_CLASS_FILE_DISPOSITION_INFO: i32 = 4;
    const FILE_INFO_BY_HANDLE_CLASS_FILE_ATTRIBUTE_TAG_INFO: i32 = 9;
    const FILE_INFO_BY_HANDLE_CLASS_FILE_ID_INFO: i32 = 18;
    const ERROR_FILE_NOT_FOUND: i32 = 2;
    const ERROR_PATH_NOT_FOUND: i32 = 3;
    const ERROR_FILE_EXISTS: i32 = 80;
    const ERROR_ALREADY_EXISTS: i32 = 183;
    const ERROR_NOT_SUPPORTED: i32 = 50;
    const ERROR_INVALID_FUNCTION: i32 = 1;
    const ERROR_INVALID_PARAMETER: i32 = 87;
    const ERROR_FILENAME_EXCED_RANGE: i32 = 206;

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: Handle,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut c_void,
        security_quality_of_service: *mut c_void,
    }

    #[repr(C)]
    union IoStatusValue {
        status: NtStatus,
        pointer: *mut c_void,
    }

    #[repr(C)]
    struct IoStatusBlock {
        status: IoStatusValue,
        information: usize,
    }

    #[repr(C)]
    struct FileAttributeTagInfo {
        file_attributes: u32,
        reparse_tag: u32,
    }

    #[repr(C)]
    struct FileIdInfo {
        volume_serial_number: u64,
        file_id: [u8; 16],
    }

    #[repr(C)]
    union FileRenameFlags {
        replace_if_exists: u8,
        flags: u32,
    }

    #[repr(C)]
    struct FileRenameInfo {
        flags: FileRenameFlags,
        root_directory: Handle,
        file_name_length: u32,
        file_name: [u16; 1],
    }

    #[repr(C)]
    struct FileDispositionInfo {
        delete_file: i32,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            file_name: *const u16,
            desired_access: u32,
            share_mode: u32,
            security_attributes: *mut c_void,
            creation_disposition: u32,
            flags_and_attributes: u32,
            template_file: Handle,
        ) -> Handle;
        fn GetFileInformationByHandleEx(
            file: Handle,
            information_class: i32,
            information: *mut c_void,
            buffer_size: u32,
        ) -> i32;
        fn SetFileInformationByHandle(
            file: Handle,
            information_class: i32,
            information: *const c_void,
            buffer_size: u32,
        ) -> i32;
        fn FlushFileBuffers(file: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut Handle,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut c_void,
            ea_length: u32,
        ) -> NtStatus;
        fn RtlNtStatusToDosError(status: NtStatus) -> u32;
    }

    pub(super) fn open_trusted_root(path: &Path) -> io::Result<TrustedRootHandle> {
        let wide = wide_path(path);
        let raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(last_error());
        }
        let file = unsafe { File::from_raw_handle(raw) };
        ensure_directory(&file)?;
        let path = path.to_path_buf();
        TrustedRootHandle::new(file, path).map_err(path_error_to_io)
    }

    fn path_error_to_io(error: PathError) -> io::Error {
        match error {
            PathError::Native(error) => error,
            other => io::Error::new(io::ErrorKind::InvalidInput, other.to_string()),
        }
    }

    pub(super) fn open_relative_directory(root: &File, name: &str) -> io::Result<File> {
        let file = nt_open_relative(
            root,
            name,
            FILE_LIST_DIRECTORY
                | FILE_ADD_FILE
                | FILE_DELETE_CHILD
                | FILE_READ_ATTRIBUTES
                | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_DIRECTORY,
        )?;
        ensure_directory(&file)?;
        Ok(file)
    }

    pub(super) fn create_relative_file(directory: &File, name: &str) -> io::Result<File> {
        nt_open_relative(
            directory,
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
        )
    }

    pub(super) fn create_relative_partial(directory: &File, name: &str) -> io::Result<File> {
        nt_open_relative(
            directory,
            name,
            GENERIC_READ | GENERIC_WRITE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
        )
    }

    pub(super) fn open_relative_partial(directory: &File, name: &str) -> io::Result<File> {
        let file = nt_open_relative(
            directory,
            name,
            GENERIC_READ | GENERIC_WRITE | DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
        )?;
        ensure_regular_file(&file)?;
        Ok(file)
    }

    pub(super) fn open_relative_file(
        directory: &File,
        name: &str,
        delete_access: bool,
    ) -> io::Result<File> {
        let access = GENERIC_READ
            | FILE_READ_ATTRIBUTES
            | SYNCHRONIZE
            | if delete_access { DELETE } else { 0 };
        let share = if delete_access {
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
        } else {
            FILE_SHARE_READ | FILE_SHARE_DELETE
        };
        let file = nt_open_relative(
            directory,
            name,
            access,
            share,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_ATTRIBUTE_NORMAL,
        )?;
        ensure_regular_file(&file)?;
        Ok(file)
    }

    fn nt_open_relative(
        directory: &File,
        name: &str,
        desired_access: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
        attributes: u32,
    ) -> io::Result<File> {
        let mut name: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = u16::try_from(name.len())
            .ok()
            .and_then(|length| length.checked_mul(2))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let mut unicode = UnicodeString {
            length: name_bytes,
            maximum_length: name_bytes,
            buffer: name.as_mut_ptr(),
        };
        let mut object_attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: directory.as_raw_handle().cast(),
            object_name: &mut unicode,
            attributes: OBJ_CASE_INSENSITIVE,
            security_descriptor: ptr::null_mut(),
            security_quality_of_service: ptr::null_mut(),
        };
        let mut io_status = IoStatusBlock {
            status: IoStatusValue { status: 0 },
            information: 0,
        };
        let mut handle = ptr::null_mut();
        let status = unsafe {
            NtCreateFile(
                &mut handle,
                desired_access,
                &mut object_attributes,
                &mut io_status,
                ptr::null_mut(),
                attributes,
                share_access,
                disposition,
                options,
                ptr::null_mut(),
                0,
            )
        };
        if status < 0 {
            let code = unsafe { RtlNtStatusToDosError(status) } as i32;
            return Err(io::Error::from_raw_os_error(code));
        }
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other("NtCreateFile returned an invalid handle"));
        }
        Ok(unsafe { File::from_raw_handle(handle) })
    }

    pub(super) fn rename_relative(
        directory: &File,
        source: &File,
        _source_name: &str,
        destination_name: &str,
        policy: OverwritePolicyV1,
    ) -> io::Result<()> {
        let file_name: Vec<u16> = destination_name.encode_utf16().collect();
        set_file_rename_info(directory, source, &file_name, policy)
    }

    fn set_file_rename_info(
        directory: &File,
        source: &File,
        file_name: &[u16],
        policy: OverwritePolicyV1,
    ) -> io::Result<()> {
        let offset = offset_of!(FileRenameInfo, file_name);
        let byte_len = file_name
            .len()
            .checked_mul(size_of::<u16>())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let buffer_len = offset
            .checked_add(byte_len)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?;
        let words = buffer_len.div_ceil(size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        let info = buffer.as_mut_ptr().cast::<FileRenameInfo>();
        unsafe {
            ptr::write(
                info,
                FileRenameInfo {
                    flags: FileRenameFlags {
                        replace_if_exists: u8::from(policy == OverwritePolicyV1::Replace),
                    },
                    root_directory: directory.as_raw_handle().cast(),
                    file_name_length: u32::try_from(byte_len).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "name too long")
                    })?,
                    file_name: [0],
                },
            );
            ptr::copy_nonoverlapping(
                file_name.as_ptr(),
                buffer.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                file_name.len(),
            );
        }
        let result = unsafe {
            SetFileInformationByHandle(
                source.as_raw_handle().cast(),
                FILE_INFO_BY_HANDLE_CLASS_FILE_RENAME_INFO,
                buffer.as_ptr().cast(),
                u32::try_from(buffer_len)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name too long"))?,
            )
        };
        if result == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn delete_open_file(file: &File) -> io::Result<()> {
        let disposition = FileDispositionInfo { delete_file: 1 };
        let result = unsafe {
            SetFileInformationByHandle(
                file.as_raw_handle().cast(),
                FILE_INFO_BY_HANDLE_CLASS_FILE_DISPOSITION_INFO,
                (&disposition as *const FileDispositionInfo).cast(),
                size_of::<FileDispositionInfo>() as u32,
            )
        };
        if result == 0 {
            return Err(last_error());
        }
        Ok(())
    }

    pub(super) fn delete_owned_file(
        directory: &File,
        name: &str,
        expected_file: &File,
    ) -> io::Result<()> {
        let expected_identity = file_identity(expected_file)?;
        let owned = open_relative_file(directory, name, true)?;
        if file_identity(&owned)? != expected_identity {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "relative name no longer identifies the owned file",
            ));
        }
        delete_open_file(&owned)
    }

    pub(super) fn cleanup_replaced_source(
        _directory: &File,
        _source_name: &str,
        _source: &File,
        _source_identity: FileIdentity,
        _policy: OverwritePolicyV1,
    ) -> io::Result<()> {
        Ok(())
    }

    pub(super) fn sync_directory(_directory: &File) -> io::Result<()> {
        // Windows does not provide a documented, general directory-handle
        // FlushFileBuffers contract. File contents and journal records are
        // flushed; process-crash atomicity is the tested durability boundary.
        Ok(())
    }

    pub(super) fn file_identity(file: &File) -> io::Result<FileIdentity> {
        let mut info = FileIdInfo {
            volume_serial_number: 0,
            file_id: [0; 16],
        };
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FILE_INFO_BY_HANDLE_CLASS_FILE_ID_INFO,
                (&mut info as *mut FileIdInfo).cast(),
                size_of::<FileIdInfo>() as u32,
            )
        };
        if result == 0 {
            return Err(last_error());
        }
        Ok(FileIdentity {
            volume: info.volume_serial_number,
            high: u64::from_le_bytes(info.file_id[..8].try_into().expect("8 bytes")),
            low: u64::from_le_bytes(info.file_id[8..].try_into().expect("8 bytes")),
        })
    }

    fn attributes(file: &File) -> io::Result<u32> {
        let mut info = FileAttributeTagInfo {
            file_attributes: 0,
            reparse_tag: 0,
        };
        let result = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle().cast(),
                FILE_INFO_BY_HANDLE_CLASS_FILE_ATTRIBUTE_TAG_INFO,
                (&mut info as *mut FileAttributeTagInfo).cast(),
                size_of::<FileAttributeTagInfo>() as u32,
            )
        };
        if result == 0 {
            return Err(last_error());
        }
        if info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "reparse points are not permitted",
            ));
        }
        Ok(info.file_attributes)
    }

    pub(super) fn ensure_directory(file: &File) -> io::Result<()> {
        if attributes(file)? & FILE_ATTRIBUTE_DIRECTORY == 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "handle is not a directory",
            ));
        }
        Ok(())
    }

    pub(super) fn ensure_regular_file(file: &File) -> io::Result<()> {
        if attributes(file)? & FILE_ATTRIBUTE_DIRECTORY != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "handle is a directory",
            ));
        }
        Ok(())
    }

    pub(super) fn identity_at(directory: &File, name: &str) -> io::Result<FileIdentity> {
        let file = open_relative_directory(directory, name)?;
        file_identity(&file)
    }

    pub(super) fn is_not_found(error: &io::Error) -> bool {
        error
            .raw_os_error()
            .is_some_and(|code| [ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND].contains(&code))
    }

    pub(super) fn is_exists(error: &io::Error) -> bool {
        error
            .raw_os_error()
            .is_some_and(|code| [ERROR_FILE_EXISTS, ERROR_ALREADY_EXISTS].contains(&code))
    }

    pub(super) fn is_unsupported(error: &io::Error) -> bool {
        error.raw_os_error().is_some_and(|code| {
            [
                ERROR_NOT_SUPPORTED,
                ERROR_INVALID_FUNCTION,
                ERROR_INVALID_PARAMETER,
                ERROR_FILENAME_EXCED_RANGE,
            ]
            .contains(&code)
        })
    }

    fn last_error() -> io::Error {
        io::Error::from_raw_os_error(unsafe { GetLastError() } as i32)
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    #[allow(dead_code)]
    fn _flush_file_for_native_evidence(file: &File) -> io::Result<()> {
        let result = unsafe { FlushFileBuffers(file.as_raw_handle().cast()) };
        if result == 0 {
            Err(last_error())
        } else {
            Ok(())
        }
    }
}

#[cfg(unix)]
mod native {
    use super::{FileIdentity, OverwritePolicyV1, TrustedRootHandle};
    use std::ffi::CString;
    use std::fs::File;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::path::Path;
    use std::sync::Arc;

    #[cfg(target_os = "linux")]
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    #[cfg(target_os = "linux")]
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    #[cfg(target_os = "linux")]
    const RESOLVE_BENEATH: u64 = 0x08;
    #[cfg(target_os = "linux")]
    const RENAME_NOREPLACE: u32 = 1;
    #[cfg(target_os = "linux")]
    const SYS_OPENAT2: libc::c_long = 437;

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[cfg(target_os = "macos")]
    const RENAME_SWAP: u32 = 0x0000_0002;
    #[cfg(target_os = "macos")]
    const RENAME_EXCL: u32 = 0x0000_0004;

    pub(super) fn open_trusted_root(path: &Path) -> io::Result<TrustedRootHandle> {
        let path_c = c_path(path)?;
        let fd = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let file = unsafe { File::from_raw_fd(fd) };
        ensure_directory(&file)?;
        let identity = file_identity(&file)?;
        Ok(TrustedRootHandle {
            file: Arc::new(file),
            path: path.to_path_buf(),
            identity,
        })
    }

    pub(super) fn open_relative_directory(root: &File, name: &str) -> io::Result<File> {
        let file = open_relative(root, name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        ensure_directory(&file)?;
        Ok(file)
    }

    pub(super) fn create_relative_file(directory: &File, name: &str) -> io::Result<File> {
        open_relative(
            directory,
            name,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW,
        )
    }

    pub(super) fn create_relative_partial(directory: &File, name: &str) -> io::Result<File> {
        open_relative(
            directory,
            name,
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_NOFOLLOW,
        )
    }

    pub(super) fn open_relative_partial(directory: &File, name: &str) -> io::Result<File> {
        let file = open_relative(directory, name, libc::O_RDWR | libc::O_NOFOLLOW)?;
        ensure_regular_file(&file)?;
        Ok(file)
    }

    pub(super) fn open_relative_file(
        directory: &File,
        name: &str,
        _delete_access: bool,
    ) -> io::Result<File> {
        let file = open_relative(directory, name, libc::O_RDONLY | libc::O_NOFOLLOW)?;
        ensure_regular_file(&file)?;
        Ok(file)
    }

    fn open_relative(directory: &File, name: &str, flags: i32) -> io::Result<File> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))?;
        #[cfg(target_os = "linux")]
        {
            let how = OpenHow {
                flags: (flags | libc::O_CLOEXEC) as u64,
                mode: if flags & libc::O_CREAT != 0 { 0o600 } else { 0 },
                resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
            };
            let fd = unsafe {
                libc::syscall(
                    SYS_OPENAT2,
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    &how as *const OpenHow,
                    std::mem::size_of::<OpenHow>(),
                ) as i32
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }
        #[cfg(target_os = "macos")]
        {
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                    0o600,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(unsafe { File::from_raw_fd(fd) })
        }
    }

    pub(super) fn rename_relative(
        directory: &File,
        _source: &File,
        source_name: &str,
        destination_name: &str,
        policy: OverwritePolicyV1,
    ) -> io::Result<()> {
        let source = CString::new(source_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in source name"))?;
        let destination = CString::new(destination_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in destination name"))?;
        #[cfg(target_os = "linux")]
        {
            let flags = if policy == OverwritePolicyV1::Reject {
                RENAME_NOREPLACE
            } else {
                0
            };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    directory.as_raw_fd(),
                    source.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                    flags,
                ) as i32
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        #[cfg(target_os = "macos")]
        {
            let source_id = identity_at(directory, source_name)?;
            let flags = if policy == OverwritePolicyV1::Reject {
                RENAME_EXCL
            } else {
                RENAME_SWAP
            };
            let result = unsafe {
                libc::renameatx_np(
                    directory.as_raw_fd(),
                    source.as_ptr(),
                    directory.as_raw_fd(),
                    destination.as_ptr(),
                    flags,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if policy == OverwritePolicyV1::Replace
                    && error.raw_os_error() == Some(libc::ENOENT)
                {
                    let exclusive = unsafe {
                        libc::renameatx_np(
                            directory.as_raw_fd(),
                            source.as_ptr(),
                            directory.as_raw_fd(),
                            destination.as_ptr(),
                            RENAME_EXCL,
                        )
                    };
                    if exclusive == 0 {
                        return Ok(());
                    }
                }
                return Err(error);
            }
            if identity_at(directory, source_name).is_ok()
                && identity_at(directory, source_name)? == source_id
            {
                return Err(io::Error::other(
                    "rename swap did not move the owned source",
                ));
            }
            Ok(())
        }
    }

    pub(super) fn delete_name(directory: &File, name: &str) -> io::Result<()> {
        let name = CString::new(name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in name"))?;
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn delete_owned_file(
        directory: &File,
        name: &str,
        expected_file: &File,
    ) -> io::Result<()> {
        if file_identity(expected_file)? != identity_at(directory, name)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "relative name no longer identifies the owned file",
            ));
        }
        delete_name(directory, name)
    }

    pub(super) fn cleanup_replaced_source(
        directory: &File,
        source_name: &str,
        source: &File,
        source_identity: FileIdentity,
        policy: OverwritePolicyV1,
    ) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        if policy == OverwritePolicyV1::Replace {
            match open_relative_file(directory, source_name, true) {
                Ok(backup) if file_identity(&backup)? != source_identity => {
                    delete_owned_file(directory, source_name, &backup)?;
                }
                Ok(_) => {
                    return Err(io::Error::other(
                        "atomic swap left the owned source under its partial name",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        #[cfg(not(target_os = "macos"))]
        let _ = (directory, source_name, source, source_identity, policy);
        #[cfg(target_os = "macos")]
        let _ = source;
        Ok(())
    }

    pub(super) fn sync_directory(directory: &File) -> io::Result<()> {
        let result = unsafe { libc::fsync(directory.as_raw_fd()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn file_identity(file: &File) -> io::Result<FileIdentity> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        let result = unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };
        Ok(FileIdentity {
            volume: stat.st_dev as u64,
            high: 0,
            low: stat.st_ino as u64,
        })
    }

    pub(super) fn identity_at(directory: &File, name: &str) -> io::Result<FileIdentity> {
        let file = open_relative(directory, name, libc::O_RDONLY | libc::O_NOFOLLOW)?;
        file_identity(&file)
    }

    pub(super) fn ensure_directory(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_dir() {
            Err(io::Error::new(
                io::ErrorKind::NotADirectory,
                "not a directory",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn ensure_regular_file(file: &File) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ))
        } else {
            Ok(())
        }
    }

    pub(super) fn is_not_found(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::NotFound
    }

    pub(super) fn is_exists(error: &io::Error) -> bool {
        error.kind() == io::ErrorKind::AlreadyExists
    }

    pub(super) fn is_unsupported(error: &io::Error) -> bool {
        error
            .raw_os_error()
            .is_some_and(|code| [libc::ENOSYS, libc::EINVAL, libc::EOPNOTSUPP].contains(&code))
            || error.kind() == io::ErrorKind::Unsupported
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))
    }
}

const JOURNAL_SCHEMA: &str = "fluxform.atomic-output.journal.v1";
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;

/// Opens a trusted directory without following a final symlink/reparse point.
/// The returned handle is the authority used by all child operations.
pub fn open_trusted_root(path: impl AsRef<Path>) -> Result<TrustedRootHandle, PathError> {
    native::open_trusted_root(path.as_ref()).map_err(PathError::Native)
}

/// A retained handle to the trusted server-owned root directory.
#[derive(Clone)]
pub struct TrustedRootHandle {
    pub(crate) file: Arc<File>,
    pub(crate) path: PathBuf,
    pub(crate) identity: FileIdentity,
}

impl TrustedRootHandle {
    fn new(file: File, path: PathBuf) -> Result<Self, PathError> {
        let identity = native::file_identity(&file).map_err(PathError::Native)?;
        Ok(Self {
            file: Arc::new(file),
            path,
            identity,
        })
    }

    /// Returns the path used to launch sibling tools. Filesystem mutations do
    /// not use this path; they remain relative to the retained directory handle.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// A task directory opened relative to a trusted root handle and retained for
/// the lifetime of its reservations.
#[derive(Clone)]
pub struct TaskOutputDir {
    inner: Arc<TaskOutputDirInner>,
}

struct TaskOutputDirInner {
    root: TrustedRootHandle,
    directory: Arc<File>,
    root_identity: FileIdentity,
    identity: FileIdentity,
    task_id: String,
    path: PathBuf,
}

impl TaskOutputDir {
    /// Opens one simple task-id component relative to `trusted_root_handle`.
    pub fn open(trusted_root_handle: &TrustedRootHandle, task_id: &str) -> Result<Self, PathError> {
        validate_component(task_id)?;
        let root_identity =
            native::file_identity(&trusted_root_handle.file).map_err(PathError::Native)?;
        if root_identity != trusted_root_handle.identity {
            return Err(PathError::TrustedRootChanged);
        }
        let directory = native::open_relative_directory(&trusted_root_handle.file, task_id)
            .map_err(PathError::Native)?;
        let identity = native::file_identity(&directory).map_err(PathError::Native)?;
        native::ensure_directory(&directory).map_err(PathError::Native)?;
        let path = trusted_root_handle.path.join(task_id);
        let inner = TaskOutputDirInner {
            root: trusted_root_handle.clone(),
            directory: Arc::new(directory),
            root_identity,
            identity,
            task_id: task_id.to_owned(),
            path,
        };
        inner.ensure_still_attached()?;
        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    /// The retained task directory's current path, used only for launching
    /// FFprobe or FFmpeg. Mutations always use the open directory handle.
    pub fn path(&self) -> &Path {
        &self.inner.path
    }

    /// The root handle from which this task directory was opened.
    pub fn trusted_root_handle(&self) -> &TrustedRootHandle {
        &self.inner.root
    }

    /// Reconciles journals in this task directory. Only strict, identity-bound
    /// records created by this crate authorize deleting their own partials.
    pub fn reconcile(&self) -> Result<ReconciliationReport, ReconcileError> {
        self.inner
            .ensure_still_attached()
            .map_err(ReconcileError::Path)?;
        let mut report = ReconciliationReport::default();
        let entries = fs::read_dir(&self.inner.path).map_err(ReconcileError::Io)?;
        for entry in entries {
            let entry = entry.map_err(ReconcileError::Io)?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                report.ignored_entries += 1;
                continue;
            };
            if !name.starts_with(".fluxform-") || !name.ends_with(".journal") {
                continue;
            }
            match self.inner.reconcile_journal(name) {
                Ok(ReconcileAction::RemovedPartial) => report.removed_partials += 1,
                Ok(ReconcileAction::CleanedCommitted) => report.cleaned_committed += 1,
                Ok(ReconcileAction::NoChange) => report.ignored_entries += 1,
                Err(_) => report.ignored_entries += 1,
            }
        }
        Ok(report)
    }
}

impl TaskOutputDirInner {
    fn ensure_still_attached(&self) -> Result<(), PathError> {
        let root_identity = native::file_identity(&self.root.file).map_err(PathError::Native)?;
        if root_identity != self.root_identity || root_identity != self.root.identity {
            return Err(PathError::TrustedRootChanged);
        }
        let task_identity =
            native::identity_at(&self.root.file, &self.task_id).map_err(PathError::Native)?;
        if task_identity != self.identity {
            return Err(PathError::TaskDirectoryChanged);
        }
        let opened_identity = native::file_identity(&self.directory).map_err(PathError::Native)?;
        if opened_identity != self.identity {
            return Err(PathError::TaskDirectoryChanged);
        }
        Ok(())
    }

    fn partial_path(&self, partial_name: &str) -> Result<PathBuf, PathError> {
        self.ensure_still_attached()?;
        Ok(self.path.join(partial_name))
    }

    fn reconcile_journal(&self, journal_name: &str) -> Result<ReconcileAction, ReconcileError> {
        validate_component(journal_name).map_err(ReconcileError::Path)?;
        let mut journal_file = match native::open_relative_file(&self.directory, journal_name, true)
        {
            Ok(file) => file,
            Err(error) if native::is_not_found(&error) => return Ok(ReconcileAction::NoChange),
            Err(error) => return Err(ReconcileError::Native(error)),
        };
        let size = journal_file.metadata().map_err(ReconcileError::Io)?.len();
        if size == 0 || size > MAX_JOURNAL_BYTES {
            return Ok(ReconcileAction::NoChange);
        }
        let mut bytes = Vec::with_capacity(size as usize);
        journal_file
            .read_to_end(&mut bytes)
            .map_err(ReconcileError::Io)?;
        let record: JournalRecord = match serde_json::from_slice(&bytes) {
            Ok(record) => record,
            Err(_) => return Ok(ReconcileAction::NoChange),
        };
        if !record.is_valid_for(self, journal_name) {
            return Ok(ReconcileAction::NoChange);
        }

        let partial = match native::open_relative_file(&self.directory, &record.partial_name, true)
        {
            Ok(file) => Some(file),
            Err(error) if native::is_not_found(&error) => None,
            Err(_) => return Ok(ReconcileAction::NoChange),
        };
        let final_file =
            match native::open_relative_file(&self.directory, &record.final_name, false) {
                Ok(file) => Some(file),
                Err(error) if native::is_not_found(&error) => None,
                Err(_) => return Ok(ReconcileAction::NoChange),
            };

        if let Some(expected_hash) = &record.content_sha256
            && let Some(final_file) = final_file.as_ref()
            && native::file_identity(final_file).ok() == Some(record.partial_identity)
            && hash_file(final_file).ok().as_deref() == Some(expected_hash)
        {
            if let Some(partial_file) = partial.as_ref() {
                let partial_id = native::file_identity(partial_file).ok();
                if partial_id != Some(record.partial_identity) {
                    native::delete_owned_file(&self.directory, &record.partial_name, partial_file)
                        .map_err(ReconcileError::Native)?;
                }
            }
            native::delete_owned_file(&self.directory, journal_name, &journal_file)
                .map_err(ReconcileError::Native)?;
            return Ok(ReconcileAction::CleanedCommitted);
        }

        if let Some(partial_file) = partial.as_ref()
            && native::file_identity(partial_file).ok() == Some(record.partial_identity)
        {
            native::delete_owned_file(&self.directory, &record.partial_name, partial_file)
                .map_err(ReconcileError::Native)?;
            native::delete_owned_file(&self.directory, journal_name, &journal_file)
                .map_err(ReconcileError::Native)?;
            return Ok(ReconcileAction::RemovedPartial);
        }
        Ok(ReconcileAction::NoChange)
    }
}

/// A filename restricted to one safe component.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelativeOutputName(String);

impl RelativeOutputName {
    pub fn parse(file_name: &str) -> Result<Self, PathError> {
        validate_component(file_name)?;
        if file_name.starts_with('.') && file_name.starts_with(".fluxform-") {
            return Err(PathError::ReservedName);
        }
        Ok(Self(file_name.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn validate_component(value: &str) -> Result<(), PathError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.len() > 240
        || value.ends_with('.')
        || value.ends_with(' ')
        || value.chars().any(|character| {
            character.is_control()
                || matches!(
                    character,
                    '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*'
                )
        })
    {
        return Err(PathError::InvalidName(value.to_owned()));
    }
    let base = value
        .split('.')
        .next()
        .unwrap_or(value)
        .to_ascii_uppercase();
    let device_name = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4
            && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'));
    if device_name {
        return Err(PathError::ReservedName);
    }
    Ok(())
}

/// An immutable manifest-derived media contract.
#[derive(Debug, Clone)]
pub struct OutputExpectation {
    pub edge_id: String,
    pub container: String,
    pub codecs: Vec<String>,
    pub stream_topology: String,
    pub stream_map: Vec<String>,
    pub width: u32,
    pub height: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub expected_duration_ms: u64,
    pub duration_tolerance_ms: u64,
    pub max_duration_ms: u64,
    pub alpha_policy: String,
    pub orientation_policy: String,
    pub metadata_policy: String,
    pub expected_alpha: Option<bool>,
    pub expected_orientation: Option<bool>,
    pub expected_metadata_present: Option<bool>,
}

impl OutputExpectation {
    pub fn from_manifest(
        edge: &ConversionEdgeV1,
        sample: &SampleRecordV1,
    ) -> Result<Self, ValidationError> {
        if !edge.valid_samples.iter().any(|id| id == &sample.id) {
            return Err(ValidationError::Rejected(format!(
                "sample {} is not a valid sample for manifest edge {}",
                sample.id, edge.id
            )));
        }
        let expected: OutputExpectationsV1 = expected_output(edge, sample);
        let expected_alpha = (sample.alpha != "not_applicable")
            .then(|| expected.alpha_policy == "preserve_if_present" && sample.alpha == "present");
        let expected_orientation = (sample.orientation != "not_applicable").then(|| {
            expected.orientation_policy == "preserve_tag" && sample.orientation == "present"
        });
        let expected_metadata_present = match expected.metadata_policy.as_str() {
            "strip" => Some(false),
            "preserve" => Some(sample.metadata == "present"),
            "safe_image_metadata" => None,
            _ => {
                return Err(ValidationError::Rejected(
                    "unknown metadata policy".to_owned(),
                ));
            }
        };
        if edge.stream_map.is_empty()
            || edge
                .stream_map
                .iter()
                .any(|mapping| !matches!(mapping.as_str(), "0:v:0" | "0:a:0"))
        {
            return Err(ValidationError::Rejected(format!(
                "edge {} has an unsupported stream map",
                edge.id
            )));
        }
        Ok(Self {
            edge_id: edge.id.clone(),
            container: expected.container,
            codecs: expected.codecs,
            stream_topology: expected.stream_topology,
            stream_map: edge.stream_map.clone(),
            width: expected.width,
            height: expected.height,
            max_width: expected.max_width,
            max_height: expected.max_height,
            expected_duration_ms: expected.expected_duration_ms,
            duration_tolerance_ms: expected.duration_tolerance_ms,
            max_duration_ms: expected.max_duration_ms,
            alpha_policy: expected.alpha_policy,
            orientation_policy: expected.orientation_policy,
            metadata_policy: expected.metadata_policy,
            expected_alpha,
            expected_orientation,
            expected_metadata_present,
        })
    }
}

/// FFmpeg's output-selection options derived from a manifest edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FfmpegOutputSpec {
    pub muxer: String,
    pub video_codec: Option<String>,
    pub audio_codec: Option<String>,
}

impl FfmpegOutputSpec {
    pub fn from_manifest(edge: &ConversionEdgeV1) -> Result<Self, OutputSpecError> {
        if edge.stream_map.is_empty()
            || edge
                .stream_map
                .iter()
                .any(|mapping| !matches!(mapping.as_str(), "0:v:0" | "0:a:0"))
        {
            return Err(OutputSpecError::InvalidStreamMap);
        }
        if edge.video_codec.is_none() && edge.audio_codec.is_none() {
            return Err(OutputSpecError::MissingCodec);
        }
        let mut expected_stream_map = Vec::new();
        if edge.video_codec.is_some() {
            expected_stream_map.push("0:v:0");
        }
        if edge.audio_codec.is_some() {
            expected_stream_map.push("0:a:0");
        }
        if edge
            .stream_map
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_stream_map
        {
            return Err(OutputSpecError::StreamMapCodecMismatch);
        }
        Ok(Self {
            muxer: edge.output_muxer.clone(),
            video_codec: edge.video_codec.clone(),
            audio_codec: edge.audio_codec.clone(),
        })
    }

    /// Builds only fixed FFmpeg argv entries; no shell is involved. `-y`
    /// allows FFmpeg to write the exclusively reserved partial created earlier.
    pub fn arguments(
        &self,
        input: impl AsRef<Path>,
        output: impl AsRef<Path>,
    ) -> Result<Vec<String>, OutputSpecError> {
        validate_ffmpeg_token(&self.muxer)?;
        if self.video_codec.is_none() && self.audio_codec.is_none() {
            return Err(OutputSpecError::MissingCodec);
        }
        if let Some(codec) = &self.video_codec {
            validate_ffmpeg_token(codec)?;
        }
        if let Some(codec) = &self.audio_codec {
            validate_ffmpeg_token(codec)?;
        }
        let mut arguments = vec![
            "-y".to_owned(),
            "-i".to_owned(),
            input.as_ref().to_string_lossy().into_owned(),
        ];
        if self.video_codec.is_some() {
            arguments.extend(["-map".to_owned(), "0:v:0".to_owned()]);
        }
        if self.audio_codec.is_some() {
            arguments.extend(["-map".to_owned(), "0:a:0".to_owned()]);
        }
        arguments.extend(["-f".to_owned(), self.muxer.clone()]);
        if let Some(codec) = &self.video_codec {
            arguments.extend(["-c:v".to_owned(), codec.clone()]);
        }
        if let Some(codec) = &self.audio_codec {
            arguments.extend(["-c:a".to_owned(), codec.clone()]);
        }
        arguments.push(output.as_ref().to_string_lossy().into_owned());
        Ok(arguments)
    }
}

fn validate_ffmpeg_token(value: &str) -> Result<(), OutputSpecError> {
    if value.is_empty()
        || value.starts_with('-')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        return Err(OutputSpecError::InvalidToken(value.to_owned()));
    }
    Ok(())
}

/// The no-clobber or atomic-replace behavior to use at finalization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverwritePolicyV1 {
    Reject,
    Replace,
}

#[derive(Debug, Error)]
pub enum PathError {
    #[error("invalid relative name: {0}")]
    InvalidName(String),
    #[error("name is reserved by the output service or operating system")]
    ReservedName,
    #[error("trusted root directory identity changed")]
    TrustedRootChanged,
    #[error("task directory was moved, swapped, or replaced")]
    TaskDirectoryChanged,
    #[error("native directory operation failed: {0}")]
    Native(#[source] io::Error),
}

#[derive(Debug, Error)]
pub enum OutputSpecError {
    #[error("the manifest edge does not contain a supported stream map")]
    InvalidStreamMap,
    #[error("the manifest edge has no output codec")]
    MissingCodec,
    #[error("the manifest edge stream map and codec set disagree")]
    StreamMapCodecMismatch,
    #[error("invalid FFmpeg option token: {0}")]
    InvalidToken(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("output validation rejected the partial file: {0}")]
    Rejected(String),
    #[error("output changed while it was being validated")]
    ChangedDuringValidation,
    #[error("the partial file is missing or is not a regular file")]
    InvalidPartial,
    #[error("native file operation failed: {0}")]
    Native(#[source] io::Error),
    #[error("FFprobe failed: {0}")]
    Ffprobe(String),
    #[error("FFprobe timed out")]
    Timeout,
    #[error("FFprobe output exceeded the configured capture limit")]
    OutputLimit,
}

#[derive(Debug, Error)]
pub enum AbortError {
    #[error("commit or validation has begun and cannot be aborted")]
    CommitInProgress,
    #[error("reservation is no longer writable")]
    NotWritable,
    #[error("native abort operation failed: {0}")]
    Native(#[source] io::Error),
}

#[derive(Debug, Error)]
pub enum CommitError {
    #[error("destination already exists")]
    DestinationExists,
    #[error("atomic output commit is unsupported by this filesystem or policy")]
    AtomicCommitUnsupported,
    #[error("commit is already in progress or reservation was consumed")]
    CommitInProgress,
    #[error("the validated output is no longer owned by this reservation")]
    OwnershipChanged,
    #[error("commit requires reconciliation: {0}")]
    ReconciliationRequired(String),
    #[error("native commit operation failed: {0}")]
    Native(#[source] io::Error),
}

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error("task directory is not the originally opened directory: {0}")]
    Path(#[source] PathError),
    #[error("directory enumeration failed: {0}")]
    Io(#[source] io::Error),
    #[error("native reconciliation operation failed: {0}")]
    Native(#[source] io::Error),
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconciliationReport {
    pub removed_partials: usize,
    pub cleaned_committed: usize,
    pub ignored_entries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct FileIdentity {
    volume: u64,
    high: u64,
    low: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JournalPhase {
    Writing,
    Validated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    schema: String,
    task_directory_identity: FileIdentity,
    job_id: Uuid,
    partial_name: String,
    final_name: String,
    partial_identity: FileIdentity,
    phase: JournalPhase,
    content_sha256: Option<String>,
}

impl JournalRecord {
    fn is_valid_for(&self, task_dir: &TaskOutputDirInner, journal_name: &str) -> bool {
        self.schema == JOURNAL_SCHEMA
            && self.task_directory_identity == task_dir.identity
            && journal_name == journal_name_for(self.job_id)
            && self
                .partial_name
                .starts_with(&format!(".fluxform-{}-", self.job_id))
            && self.partial_name.ends_with(".partial")
            && validate_component(&self.partial_name).is_ok()
            && RelativeOutputName::parse(&self.final_name).is_ok()
            && match self.phase {
                JournalPhase::Writing => self.content_sha256.is_none(),
                JournalPhase::Validated => {
                    self.content_sha256.as_deref().is_some_and(is_sha256_hex)
                }
            }
    }
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn journal_name_for(job_id: Uuid) -> String {
    format!(".fluxform-{job_id}.journal")
}

#[derive(Default)]
struct ReservationState {
    phase: Phase,
    validated_hash: Option<String>,
}

#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    #[default]
    Writing,
    Validated,
    Committing,
    Committed,
    Aborted,
}

/// An exclusively created output partial and its owned journal record.
#[derive(Clone)]
pub struct OutputReservation {
    inner: Arc<ReservationInner>,
}

impl OutputReservation {
    pub fn create(
        task_dir: &TaskOutputDir,
        name: &RelativeOutputName,
        job_id: Uuid,
        extension: &str,
    ) -> Result<Self, PathError> {
        validate_extension(extension, name.as_str())?;
        task_dir.inner.ensure_still_attached()?;
        let nonce = Uuid::new_v4();
        let partial_name = format!(".fluxform-{job_id}-{nonce}.{extension}.partial");
        let journal_name = journal_name_for(job_id);
        let partial = native::create_relative_partial(&task_dir.inner.directory, &partial_name)
            .map_err(PathError::Native)?;
        let partial_identity = native::file_identity(&partial).map_err(PathError::Native)?;
        let journal = match native::create_relative_file(&task_dir.inner.directory, &journal_name) {
            Ok(file) => file,
            Err(error) => {
                let _ =
                    native::delete_owned_file(&task_dir.inner.directory, &partial_name, &partial);
                return Err(PathError::Native(error));
            }
        };
        let record = JournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            task_directory_identity: task_dir.inner.identity,
            job_id,
            partial_name: partial_name.clone(),
            final_name: name.as_str().to_owned(),
            partial_identity,
            phase: JournalPhase::Writing,
            content_sha256: None,
        };
        if let Err(error) = write_journal(&journal, &record) {
            let _ = native::delete_owned_file(&task_dir.inner.directory, &partial_name, &partial);
            let _ = native::delete_owned_file(&task_dir.inner.directory, &journal_name, &journal);
            return Err(PathError::Native(error));
        }
        if let Err(error) = native::sync_directory(&task_dir.inner.directory) {
            let _ = native::delete_owned_file(&task_dir.inner.directory, &partial_name, &partial);
            let _ = native::delete_owned_file(&task_dir.inner.directory, &journal_name, &journal);
            return Err(PathError::Native(error));
        }
        Ok(Self {
            inner: Arc::new(ReservationInner {
                task_dir: task_dir.clone(),
                final_name: name.as_str().to_owned(),
                partial_name,
                journal_name,
                partial: Mutex::new(Some(partial)),
                journal: Mutex::new(Some(journal)),
                state: Mutex::new(ReservationState::default()),
            }),
        })
    }

    /// Returns the sibling path supplied to the output process. All filesystem
    /// mutation and finalization continues to use retained handles.
    pub fn partial_path(&self) -> Result<PathBuf, PathError> {
        self.inner
            .task_dir
            .inner
            .partial_path(&self.inner.partial_name)
    }

    pub fn final_path(&self) -> PathBuf {
        self.inner.task_dir.inner.path.join(&self.inner.final_name)
    }

    pub fn abort(&self) -> Result<(), AbortError> {
        let mut state = self.inner.lock_state();
        match state.phase {
            Phase::Writing => {
                let mut partial_slot = self.inner.partial.lock().expect("partial mutex poisoned");
                if let Some(partial) = partial_slot.as_ref() {
                    native::delete_owned_file(
                        &self.inner.task_dir.inner.directory,
                        &self.inner.partial_name,
                        partial,
                    )
                    .map_err(AbortError::Native)?;
                    drop(partial_slot.take());
                } else {
                    let partial = native::open_relative_file(
                        &self.inner.task_dir.inner.directory,
                        &self.inner.partial_name,
                        true,
                    )
                    .map_err(AbortError::Native)?;
                    native::delete_owned_file(
                        &self.inner.task_dir.inner.directory,
                        &self.inner.partial_name,
                        &partial,
                    )
                    .map_err(AbortError::Native)?;
                }
                let mut journal_slot = self.inner.journal.lock().expect("journal mutex poisoned");
                let journal = journal_slot.as_ref().ok_or(AbortError::NotWritable)?;
                native::delete_owned_file(
                    &self.inner.task_dir.inner.directory,
                    &self.inner.journal_name,
                    journal,
                )
                .map_err(AbortError::Native)?;
                drop(journal_slot.take());
                native::sync_directory(&self.inner.task_dir.inner.directory)
                    .map_err(AbortError::Native)?;
                state.phase = Phase::Aborted;
                Ok(())
            }
            Phase::Committing | Phase::Committed | Phase::Validated => {
                Err(AbortError::CommitInProgress)
            }
            Phase::Aborted => Err(AbortError::NotWritable),
        }
    }

    pub fn validate(
        &self,
        validator: &dyn OutputValidator,
        expectation: &OutputExpectation,
    ) -> Result<ValidatedOutput, ValidationError> {
        let mut state = self.inner.lock_state();
        if state.phase != Phase::Writing {
            return Err(ValidationError::Rejected(
                "reservation is no longer writable".to_owned(),
            ));
        }
        self.inner
            .task_dir
            .inner
            .ensure_still_attached()
            .map_err(|error| ValidationError::Rejected(error.to_string()))?;
        let mut partial_slot = self.inner.partial.lock().expect("partial mutex poisoned");
        let partial = partial_slot
            .as_ref()
            .ok_or(ValidationError::InvalidPartial)?;
        native::ensure_regular_file(partial).map_err(ValidationError::Native)?;
        partial.sync_all().map_err(ValidationError::Native)?;
        let partial_identity = native::file_identity(partial).map_err(ValidationError::Native)?;
        let before_hash = hash_file(partial).map_err(ValidationError::Native)?;
        partial_slot.take();
        let partial = native::open_relative_partial(
            &self.inner.task_dir.inner.directory,
            &self.inner.partial_name,
        )
        .map_err(ValidationError::Native)?;
        if native::file_identity(&partial).map_err(ValidationError::Native)? != partial_identity
            || hash_file(&partial).map_err(ValidationError::Native)? != before_hash
        {
            *partial_slot = Some(partial);
            return Err(ValidationError::ChangedDuringValidation);
        }
        *partial_slot = Some(partial);
        let partial = partial_slot.as_ref().expect("partial restored");
        let partial_path = self
            .partial_path()
            .map_err(|error| ValidationError::Rejected(error.to_string()))?;
        validator.validate(&partial_path, expectation)?;
        self.inner
            .task_dir
            .inner
            .ensure_still_attached()
            .map_err(|error| ValidationError::Rejected(error.to_string()))?;
        let after_hash = hash_file(partial).map_err(ValidationError::Native)?;
        let after_identity = native::file_identity(partial).map_err(ValidationError::Native)?;
        if before_hash != after_hash || partial_identity != after_identity {
            return Err(ValidationError::ChangedDuringValidation);
        }
        let journal_slot = self.inner.journal.lock().expect("journal mutex poisoned");
        let journal = journal_slot
            .as_ref()
            .ok_or_else(|| ValidationError::Rejected("reservation journal is closed".to_owned()))?;
        let record = JournalRecord {
            schema: JOURNAL_SCHEMA.to_owned(),
            task_directory_identity: self.inner.task_dir.inner.identity,
            job_id: parse_job_id(&self.inner.journal_name).ok_or_else(|| {
                ValidationError::Rejected("invalid owned journal name".to_owned())
            })?,
            partial_name: self.inner.partial_name.clone(),
            final_name: self.inner.final_name.clone(),
            partial_identity,
            phase: JournalPhase::Validated,
            content_sha256: Some(after_hash.clone()),
        };
        write_journal(journal, &record).map_err(ValidationError::Native)?;
        native::sync_directory(&self.inner.task_dir.inner.directory)
            .map_err(ValidationError::Native)?;
        state.phase = Phase::Validated;
        state.validated_hash = Some(after_hash.clone());
        Ok(ValidatedOutput {
            inner: self.inner.clone(),
            content_sha256: after_hash,
        })
    }
}

fn parse_job_id(journal_name: &str) -> Option<Uuid> {
    journal_name
        .strip_prefix(".fluxform-")?
        .strip_suffix(".journal")?
        .parse()
        .ok()
}

fn validate_extension(extension: &str, final_name: &str) -> Result<(), PathError> {
    let extension = extension.strip_prefix('.').unwrap_or(extension);
    if extension.is_empty() || !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return Err(PathError::InvalidName(extension.to_owned()));
    }
    let actual = Path::new(final_name)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    if !actual.eq_ignore_ascii_case(extension) {
        return Err(PathError::InvalidName(final_name.to_owned()));
    }
    Ok(())
}

fn write_journal(file: &File, record: &JournalRecord) -> io::Result<()> {
    let bytes = serde_json::to_vec(record).map_err(io::Error::other)?;
    if bytes.len() > MAX_JOURNAL_BYTES as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "journal too large",
        ));
    }
    let mut file = file;
    file.set_len(0)?;
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&bytes)?;
    file.sync_all()
}

fn hash_file(file: &File) -> io::Result<String> {
    let mut file = file;
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hasher.finalize();
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

struct ReservationInner {
    task_dir: TaskOutputDir,
    final_name: String,
    partial_name: String,
    journal_name: String,
    partial: Mutex<Option<File>>,
    journal: Mutex<Option<File>>,
    state: Mutex<ReservationState>,
}

impl ReservationInner {
    fn lock_state(&self) -> MutexGuard<'_, ReservationState> {
        self.state.lock().expect("reservation state mutex poisoned")
    }
}

/// Proof-carrying output value. Its constructor is private; only successful
/// validation can produce one.
pub struct ValidatedOutput {
    inner: Arc<ReservationInner>,
    content_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitBoundary {
    BeforeSourceFlush,
    AfterSourceFlush,
    BeforeNativeRename,
    AfterNativeRename,
    BeforeFinalReopen,
    AfterFinalReopen,
    BeforeIdentityHashCheck,
    AfterIdentityHashCheck,
    BeforeDirectorySync,
    AfterDirectorySync,
    BeforeReplacementCleanup,
    AfterReplacementCleanup,
    BeforeJournalCleanup,
    AfterJournalCleanup,
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitTestAction {
    Fail,
    Crash,
}

#[cfg(test)]
std::thread_local! {
    static COMMIT_TEST_ACTION: std::cell::Cell<Option<(CommitBoundary, CommitTestAction)>> = const { std::cell::Cell::new(None) };
}

fn commit_boundary(boundary: CommitBoundary) -> io::Result<()> {
    #[cfg(test)]
    if let Some((selected, action)) = COMMIT_TEST_ACTION.with(std::cell::Cell::get)
        && selected == boundary
    {
        match action {
            CommitTestAction::Fail => {
                return Err(io::Error::other(format!(
                    "injected failure at {boundary:?}"
                )));
            }
            CommitTestAction::Crash => std::process::abort(),
        }
    }
    let _ = boundary;
    Ok(())
}

impl ValidatedOutput {
    /// Atomically publishes the validated sibling under the selected policy.
    pub fn commit(self, policy: OverwritePolicyV1) -> Result<CommitReceipt, CommitError> {
        let mut state = self.inner.lock_state();
        if state.phase != Phase::Validated
            || state.validated_hash.as_deref() != Some(&self.content_sha256)
        {
            return Err(CommitError::CommitInProgress);
        }
        state.phase = Phase::Committing;
        let partial_slot = self.inner.partial.lock().expect("partial mutex poisoned");
        let partial = partial_slot.as_ref().ok_or(CommitError::OwnershipChanged)?;
        let mut journal_slot = self.inner.journal.lock().expect("journal mutex poisoned");
        let journal = journal_slot.as_ref().ok_or(CommitError::OwnershipChanged)?;
        commit_boundary(CommitBoundary::BeforeSourceFlush).map_err(CommitError::Native)?;
        if let Err(error) = partial.sync_all() {
            return Err(if native::is_unsupported(&error) {
                CommitError::AtomicCommitUnsupported
            } else {
                CommitError::Native(error)
            });
        }
        commit_boundary(CommitBoundary::AfterSourceFlush).map_err(CommitError::Native)?;
        let source_identity = native::file_identity(partial).map_err(CommitError::Native)?;
        commit_boundary(CommitBoundary::BeforeNativeRename).map_err(CommitError::Native)?;
        let rename_result = native::rename_relative(
            &self.inner.task_dir.inner.directory,
            partial,
            &self.inner.partial_name,
            &self.inner.final_name,
            policy,
        );
        if let Err(error) = rename_result {
            if native::is_exists(&error) && policy == OverwritePolicyV1::Reject {
                return Err(CommitError::DestinationExists);
            }
            return Err(if native::is_unsupported(&error) {
                CommitError::AtomicCommitUnsupported
            } else {
                CommitError::Native(error)
            });
        }
        commit_boundary(CommitBoundary::AfterNativeRename)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::BeforeFinalReopen)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        let final_file = native::open_relative_file(
            &self.inner.task_dir.inner.directory,
            &self.inner.final_name,
            true,
        )
        .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::AfterFinalReopen)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        native::ensure_regular_file(&final_file)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::BeforeIdentityHashCheck)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        if native::file_identity(&final_file).map_err(CommitError::Native)? != source_identity
            || hash_file(&final_file).map_err(CommitError::Native)? != self.content_sha256
        {
            return Err(CommitError::OwnershipChanged);
        }
        commit_boundary(CommitBoundary::AfterIdentityHashCheck)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::BeforeDirectorySync)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        native::sync_directory(&self.inner.task_dir.inner.directory)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::AfterDirectorySync)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::BeforeReplacementCleanup)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        native::cleanup_replaced_source(
            &self.inner.task_dir.inner.directory,
            &self.inner.partial_name,
            partial,
            source_identity,
            policy,
        )
        .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::AfterReplacementCleanup)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::BeforeJournalCleanup)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        native::delete_owned_file(
            &self.inner.task_dir.inner.directory,
            &self.inner.journal_name,
            journal,
        )
        .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        commit_boundary(CommitBoundary::AfterJournalCleanup)
            .map_err(|error| CommitError::ReconciliationRequired(error.to_string()))?;
        drop(journal_slot.take());
        state.phase = Phase::Committed;
        Ok(CommitReceipt {
            final_path: self.inner.task_dir.inner.path.join(&self.inner.final_name),
            size_bytes: final_file.metadata().map_err(CommitError::Native)?.len(),
            sha256: self.content_sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitReceipt {
    pub final_path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Debug)]
enum ReconcileAction {
    RemovedPartial,
    CleanedCommitted,
    NoChange,
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;
    use tempfile::TempDir;

    const OLD: &[u8] = b"complete-old-output";
    const NEW: &[u8] = b"complete-validated-output";

    struct Accept;

    impl OutputValidator for Accept {
        fn validate(
            &self,
            _partial_path: &Path,
            _expectation: &OutputExpectation,
        ) -> Result<(), ValidationError> {
            Ok(())
        }
    }

    fn expectation() -> OutputExpectation {
        OutputExpectation {
            edge_id: "test.image".to_owned(),
            container: "png".to_owned(),
            codecs: vec!["png".to_owned()],
            stream_topology: "single_video_frame".to_owned(),
            stream_map: vec!["0:v:0".to_owned()],
            width: 1,
            height: 1,
            max_width: 1,
            max_height: 1,
            expected_duration_ms: 0,
            duration_tolerance_ms: 0,
            max_duration_ms: 0,
            alpha_policy: "preserve_if_present".to_owned(),
            orientation_policy: "apply_to_pixels".to_owned(),
            metadata_policy: "strip".to_owned(),
            expected_alpha: None,
            expected_orientation: None,
            expected_metadata_present: Some(false),
        }
    }

    fn fixture() -> (TempDir, PathBuf) {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("root");
        std::fs::create_dir_all(root.join("task")).expect("task directory");
        (temporary, root)
    }

    fn task_dir(root: &Path) -> TaskOutputDir {
        let trusted_root = open_trusted_root(root).expect("trusted root handle");
        TaskOutputDir::open(&trusted_root, "task").expect("task output directory")
    }

    fn validated(task: &TaskOutputDir) -> ValidatedOutput {
        let name = RelativeOutputName::parse("result.png").expect("safe name");
        let reservation =
            OutputReservation::create(task, &name, Uuid::new_v4(), "png").expect("reservation");
        std::fs::write(reservation.partial_path().expect("partial path"), NEW)
            .expect("partial bytes");
        reservation
            .validate(&Accept, &expectation())
            .expect("validated output")
    }

    fn observe_complete_final(
        path: PathBuf,
        stop: Arc<AtomicBool>,
    ) -> (thread::JoinHandle<Result<(), String>>, mpsc::Receiver<()>) {
        let (armed_tx, armed_rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut armed = false;
            while !stop.load(Ordering::Acquire) {
                match std::fs::read(&path) {
                    Ok(bytes) if bytes == OLD || bytes == NEW => {
                        if !armed {
                            armed = true;
                            let _ = armed_tx.send(());
                        }
                    }
                    Ok(_) => return Err("observer saw partial final bytes".to_owned()),
                    Err(error) if error.kind() == io::ErrorKind::NotFound && !armed => {}
                    Err(error) => return Err(format!("observer could not read final: {error}")),
                }
                thread::yield_now();
            }
            Ok(())
        });
        (worker, armed_rx)
    }

    #[test]
    fn injected_failures_cover_every_replacement_boundary_when_native_rename_is_available() {
        let boundaries = [
            CommitBoundary::BeforeSourceFlush,
            CommitBoundary::AfterSourceFlush,
            CommitBoundary::BeforeNativeRename,
            CommitBoundary::AfterNativeRename,
            CommitBoundary::BeforeFinalReopen,
            CommitBoundary::AfterFinalReopen,
            CommitBoundary::BeforeIdentityHashCheck,
            CommitBoundary::AfterIdentityHashCheck,
            CommitBoundary::BeforeDirectorySync,
            CommitBoundary::AfterDirectorySync,
            CommitBoundary::BeforeReplacementCleanup,
            CommitBoundary::AfterReplacementCleanup,
            CommitBoundary::BeforeJournalCleanup,
            CommitBoundary::AfterJournalCleanup,
        ];
        let mut injected = 0;
        let mut blocked_after_rename = 0;
        for boundary in boundaries {
            let (_temporary, root) = fixture();
            let task = task_dir(&root);
            let final_path = task.path().join("result.png");
            std::fs::write(&final_path, OLD).expect("old final");
            let unowned_journal = task.path().join(".fluxform-unowned.journal");
            std::fs::write(&unowned_journal, b"not an owned record").expect("unowned journal");
            let validated = validated(&task);
            let partial_path = validated
                .inner
                .task_dir
                .inner
                .partial_path(&validated.inner.partial_name)
                .expect("owned partial path");

            let stop = Arc::new(AtomicBool::new(false));
            let (observer, armed) = observe_complete_final(final_path.clone(), stop.clone());
            armed
                .recv_timeout(Duration::from_secs(2))
                .expect("observer armed");

            COMMIT_TEST_ACTION.with(|action| action.set(Some((boundary, CommitTestAction::Fail))));
            let result = validated.commit(OverwritePolicyV1::Replace);
            COMMIT_TEST_ACTION.with(|action| action.set(None));

            let final_expected = match (&boundary, result) {
                (
                    CommitBoundary::BeforeSourceFlush
                    | CommitBoundary::AfterSourceFlush
                    | CommitBoundary::BeforeNativeRename,
                    Err(CommitError::Native(error)),
                ) if error.to_string().contains("injected failure") => {
                    injected += 1;
                    OLD
                }
                (
                    CommitBoundary::AfterNativeRename
                    | CommitBoundary::BeforeFinalReopen
                    | CommitBoundary::AfterFinalReopen
                    | CommitBoundary::BeforeIdentityHashCheck
                    | CommitBoundary::AfterIdentityHashCheck
                    | CommitBoundary::BeforeDirectorySync
                    | CommitBoundary::AfterDirectorySync
                    | CommitBoundary::BeforeReplacementCleanup
                    | CommitBoundary::AfterReplacementCleanup
                    | CommitBoundary::BeforeJournalCleanup
                    | CommitBoundary::AfterJournalCleanup,
                    Err(CommitError::AtomicCommitUnsupported),
                ) => {
                    blocked_after_rename += 1;
                    OLD
                }
                (
                    CommitBoundary::AfterNativeRename
                    | CommitBoundary::BeforeFinalReopen
                    | CommitBoundary::AfterFinalReopen
                    | CommitBoundary::BeforeIdentityHashCheck
                    | CommitBoundary::AfterIdentityHashCheck
                    | CommitBoundary::BeforeDirectorySync
                    | CommitBoundary::AfterDirectorySync
                    | CommitBoundary::BeforeReplacementCleanup
                    | CommitBoundary::AfterReplacementCleanup
                    | CommitBoundary::BeforeJournalCleanup
                    | CommitBoundary::AfterJournalCleanup,
                    Err(CommitError::ReconciliationRequired(_)),
                ) => NEW,
                (boundary, result) => {
                    panic!("failure injection did not reach {boundary:?}: {result:?}")
                }
            };

            stop.store(true, Ordering::Release);
            observer
                .join()
                .expect("observer thread")
                .unwrap_or_else(|error| panic!("{boundary:?}: {error}"));
            let bytes = std::fs::read(&final_path).expect("final remains present");
            assert_eq!(bytes, final_expected, "{boundary:?}: wrong complete final");
            let _ = task.reconcile().expect("crash recovery reconciliation");
            assert_eq!(
                std::fs::read(&final_path).expect("final after reconcile"),
                bytes
            );
            assert!(
                !partial_path.exists(),
                "reconciliation left the owned partial for {boundary:?}"
            );
            assert!(
                unowned_journal.exists(),
                "reconciliation removed invalid/unowned journal for {boundary:?}"
            );
        }
        eprintln!(
            "replacement failure injection: exercised={injected}/14 boundaries; blocked_after_native_rename={blocked_after_rename}/11"
        );
    }

    #[test]
    fn crash_child_process() {
        let Ok(mode) = std::env::var("FLUXFORM_ATOMIC_CRASH_MODE") else {
            return;
        };
        let root = PathBuf::from(std::env::var_os("FLUXFORM_ATOMIC_CRASH_ROOT").expect("root"));
        let task = task_dir(&root);
        let output = validated(&task);
        let boundary = match mode.as_str() {
            "before" => CommitBoundary::BeforeNativeRename,
            "after" => CommitBoundary::AfterNativeRename,
            _ => panic!("unknown crash helper mode"),
        };
        COMMIT_TEST_ACTION.with(|action| action.set(Some((boundary, CommitTestAction::Crash))));
        let result = output.commit(OverwritePolicyV1::Replace);
        panic!("crash boundary was not reached; commit result: {result:?}");
    }

    #[test]
    fn process_crashes_before_rename_and_after_rename_are_distinguished_safely() {
        for (mode, expected_final) in [("before", OLD), ("after", NEW)] {
            let (_temporary, root) = fixture();
            let task_path = root.join("task");
            std::fs::write(task_path.join("result.png"), OLD).expect("old final");
            std::fs::write(
                task_path.join(".fluxform-unowned.journal"),
                b"not a valid journal",
            )
            .expect("unowned invalid journal");
            let stop_observer = Arc::new(AtomicBool::new(false));
            let (observer, armed) =
                observe_complete_final(task_path.join("result.png"), stop_observer.clone());
            armed
                .recv_timeout(Duration::from_secs(2))
                .expect("crash observer armed");
            let executable = std::env::current_exe().expect("current test executable");
            let output = Command::new(executable)
                .args([
                    "--exact",
                    "native_tests::crash_child_process",
                    "--nocapture",
                ])
                .env("FLUXFORM_ATOMIC_CRASH_MODE", mode)
                .env("FLUXFORM_ATOMIC_CRASH_ROOT", &root)
                .output()
                .expect("launch crash helper");
            assert!(
                !output.status.success(),
                "helper did not terminate at {mode} boundary"
            );
            stop_observer.store(true, Ordering::Release);
            observer
                .join()
                .expect("crash observer thread")
                .unwrap_or_else(|error| panic!("crash mode {mode}: {error}"));

            let task = task_dir(&root);
            let final_path = task.path().join("result.png");
            let bytes = std::fs::read(&final_path).expect("old or new complete final");
            if mode == "after" && bytes == OLD {
                let child_output = String::from_utf8_lossy(&output.stderr);
                assert!(
                    child_output.contains("AtomicCommitUnsupported"),
                    "old final after the-rename child exit was not explained by the unsupported gate: {child_output}"
                );
                eprintln!(
                    "BLOCKED: crash-after-rename evidence unavailable; handle-relative native rename returned AtomicCommitUnsupported before the injected crash"
                );
            } else {
                assert_eq!(bytes, expected_final, "crash mode {mode}");
            }
            task.reconcile().expect("reconcile after child termination");
            assert_eq!(
                std::fs::read(&final_path).expect("final after reconcile"),
                bytes
            );
            assert!(
                task_path.join(".fluxform-unowned.journal").exists(),
                "invalid/unowned journal was removed"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_handle_relative_rename_gate_records_raw_error_without_fallback() {
        let (_temporary, root) = fixture();
        let task = task_dir(&root);
        let output = validated(&task);
        let partial_name = output.inner.partial_name.clone();
        let final_name = output.inner.final_name.clone();
        let partial_slot = output.inner.partial.lock().expect("partial lock");
        let source = partial_slot.as_ref().expect("partial handle");
        let result = native::rename_relative(
            &task.inner.directory,
            source,
            &partial_name,
            &final_name,
            OverwritePolicyV1::Reject,
        );

        match result {
            Ok(()) => {
                assert_eq!(
                    std::fs::read(task.path().join(&final_name)).expect("renamed final"),
                    NEW
                );
                println!("Windows handle-relative FileRenameInfo gate: native rename succeeded");
            }
            Err(error) => {
                let code = error.raw_os_error();
                assert!(
                    native::is_unsupported(&error),
                    "unexpected native error from handle-relative FileRenameInfo: {error:?}"
                );
                assert!(
                    !task.path().join(&final_name).exists(),
                    "failed native rename mutated the final name"
                );
                assert!(
                    task.path().join(&partial_name).exists(),
                    "failed native rename removed the owned partial"
                );
                println!(
                    "BLOCKED Windows handle-relative FileRenameInfo gate: raw_os_error={code:?}; no pathname fallback attempted"
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_commit_maps_error_87_to_atomic_unsupported_without_mutation() {
        let (_temporary, root) = fixture();
        let task = task_dir(&root);
        let validated = validated(&task);
        let final_path = task.path().join("result.png");
        let partial_path = validated
            .inner
            .task_dir
            .inner
            .partial_path(&validated.inner.partial_name)
            .expect("owned partial path");

        match validated.commit(OverwritePolicyV1::Reject) {
            Err(CommitError::AtomicCommitUnsupported) => {
                assert!(
                    !final_path.exists(),
                    "unsupported commit created a final name"
                );
                assert!(partial_path.exists(), "unsupported commit lost its partial");
                println!(
                    "BLOCKED Windows commit result: ERROR_INVALID_PARAMETER (87) mapped to AtomicCommitUnsupported"
                );
            }
            Ok(_) => assert_eq!(std::fs::read(final_path).expect("final output"), NEW),
            Err(error) => panic!("unexpected Windows commit error: {error}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_relative_rename_name_range_error_is_classified_as_unsupported() {
        let error = io::Error::from_raw_os_error(206);
        assert!(native::is_unsupported(&error));
    }
}
