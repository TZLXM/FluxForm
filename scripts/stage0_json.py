"""Strict JSON parsing and single-handle, identity-pinned file reads."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any


class DuplicateJsonKey(ValueError):
    pass


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def loads_unique_json(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8", errors="strict")
        return json.loads(text, object_pairs_hook=_unique_object)
    except (UnicodeError, json.JSONDecodeError, DuplicateJsonKey) as error:
        raise ValueError(f"{label} is invalid UTF-8 JSON: {error}") from error


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _contained_real_path(path: Path, root: Path) -> Path:
    root_real = root.resolve(strict=True)
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(root_real)
    except ValueError as error:
        raise ValueError("evidence file is outside the repository root") from error

    current = root_real
    for part in relative.parts:
        current = current / part
        metadata = current.lstat()
        attributes = getattr(metadata, "st_file_attributes", 0)
        if stat.S_ISLNK(metadata.st_mode) or attributes & 0x400:
            raise ValueError("evidence path contains a symlink or reparse point")
    resolved = absolute.resolve(strict=True)
    try:
        resolved.relative_to(root_real)
    except ValueError as error:
        raise ValueError("evidence file resolves outside the repository root") from error
    if resolved != absolute:
        raise ValueError("evidence path is not its canonical repository path")
    return absolute


def _read_windows(path: Path, root: Path) -> tuple[bytes, tuple[int, ...], str]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time_low", wintypes.DWORD),
            ("creation_time_high", wintypes.DWORD),
            ("last_access_time_low", wintypes.DWORD),
            ("last_access_time_high", wintypes.DWORD),
            ("last_write_time_low", wintypes.DWORD),
            ("last_write_time_high", wintypes.DWORD),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final_path.restype = wintypes.DWORD

    generic_read = 0x80000000
    share_read_only = 0x00000001
    open_existing = 3
    open_reparse_point = 0x00200000
    handle = create_file(str(path), generic_read, share_read_only, None, open_existing, open_reparse_point, None)
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        raise OSError(ctypes.get_last_error(), "CreateFileW failed for pinned evidence", str(path))

    def details() -> tuple[int, ...]:
        information = ByHandleFileInformation()
        if not get_information(handle, ctypes.byref(information)):
            raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed", str(path))
        size = (information.size_high << 32) | information.size_low
        file_index = (information.file_index_high << 32) | information.file_index_low
        write_time = (information.last_write_time_high << 32) | information.last_write_time_low
        if information.attributes & 0x400:
            raise ValueError("evidence file is a reparse point")
        if information.attributes & 0x10:
            raise ValueError("evidence path is a directory")
        return (information.volume_serial, file_index, size, write_time, information.attributes)

    try:
        before = details()
        path_buffer = ctypes.create_unicode_buffer(32768)
        length = get_final_path(handle, path_buffer, len(path_buffer), 0)
        if not length or length >= len(path_buffer):
            raise OSError(ctypes.get_last_error(), "GetFinalPathNameByHandleW failed", str(path))
        final_path = path_buffer.value
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        root_real = os.path.normcase(os.path.abspath(root))
        final_normalized = os.path.normcase(os.path.abspath(final_path))
        if os.path.commonpath([root_real, final_normalized]) != root_real or final_normalized == root_real:
            raise ValueError("evidence handle resolves outside the repository root")

        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = None
        with os.fdopen(fd, "rb") as source:
            chunks = []
            while chunk := source.read(1024 * 1024):
                chunks.append(chunk)
            data = b"".join(chunks)
            after_fd = os.fstat(source.fileno())
            after = details_from_fd(source.fileno(), after_fd)
        if before != after or len(data) != before[2]:
            raise ValueError("evidence file identity or size changed while reading")
        return data, before, final_path
    finally:
        if handle is not None:
            kernel32.CloseHandle(handle)


def details_from_fd(fd: int, metadata: os.stat_result) -> tuple[int, ...]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_time_low", wintypes.DWORD),
            ("creation_time_high", wintypes.DWORD),
            ("last_access_time_low", wintypes.DWORD),
            ("last_access_time_high", wintypes.DWORD),
            ("last_write_time_low", wintypes.DWORD),
            ("last_write_time_high", wintypes.DWORD),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD),
            ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD),
            ("file_index_low", wintypes.DWORD),
        ]

    information = ByHandleFileInformation()
    handle = msvcrt.get_osfhandle(fd)
    get_information = ctypes.WinDLL("kernel32", use_last_error=True).GetFileInformationByHandle
    get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
    get_information.restype = wintypes.BOOL
    if not get_information(wintypes.HANDLE(handle), ctypes.byref(information)):
        raise OSError(ctypes.get_last_error(), "GetFileInformationByHandle failed")
    size = (information.size_high << 32) | information.size_low
    file_index = (information.file_index_high << 32) | information.file_index_low
    write_time = (information.last_write_time_high << 32) | information.last_write_time_low
    return (information.volume_serial, file_index, size, write_time, information.attributes)


def read_pinned_bytes(path: Path, label: str, repository_root: Path) -> tuple[bytes, str, tuple[int, ...]]:
    if os.name == "nt":
        absolute = _contained_real_path(path, repository_root)
        data, identity, _final_path = _read_windows(absolute, repository_root)
        return data, hashlib.sha256(data).hexdigest(), identity
    if os.name not in ("posix",):
        raise ValueError("this platform has no supported pinned evidence reader")
    required_dirfd = os.open in os.supports_dir_fd and os.stat in os.supports_dir_fd
    required_follow_symlinks = os.stat in os.supports_follow_symlinks
    if not required_dirfd or not required_follow_symlinks or not all(hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_DIRECTORY")):
        raise ValueError("this Unix platform cannot safely pin evidence with dirfd and O_NOFOLLOW")

    root = repository_root.resolve(strict=True)
    absolute = Path(os.path.abspath(path))
    try:
        relative = absolute.relative_to(root)
    except ValueError as error:
        raise ValueError("evidence file is outside the repository root") from error
    components = relative.parts
    if not components or any(part in ("", ".", "..") for part in components):
        raise ValueError("evidence path is not a regular file beneath the repository root")

    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    parent_fds: list[int] = []
    parent_names: list[str] = []
    try:
        root_fd = os.open(root, directory_flags)
        parent_fds.append(root_fd)
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            raise ValueError("repository root is not a directory")

        for component in components[:-1]:
            parent_fd = parent_fds[-1]
            entry_before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(entry_before.st_mode) or not stat.S_ISDIR(entry_before.st_mode):
                raise ValueError("evidence path contains a symlink or non-directory parent")
            child_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            child_metadata = os.fstat(child_fd)
            if not stat.S_ISDIR(child_metadata.st_mode) or (entry_before.st_dev, entry_before.st_ino) != (child_metadata.st_dev, child_metadata.st_ino):
                os.close(child_fd)
                raise ValueError("evidence parent directory changed while opening")
            parent_fds.append(child_fd)
            parent_names.append(component)

        parent_fd = parent_fds[-1]
        leaf = components[-1]
        leaf_before = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if stat.S_ISLNK(leaf_before.st_mode) or not stat.S_ISREG(leaf_before.st_mode):
            raise ValueError(f"{label} is not a regular non-symlink file")
        fd = os.open(leaf, file_flags, dir_fd=parent_fd)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or (leaf_before.st_dev, leaf_before.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError(f"{label} identity changed while opening")
            chunks = []
            while chunk := os.read(fd, 1024 * 1024):
                chunks.append(chunk)
            data = b"".join(chunks)
            after = os.fstat(fd)
            leaf_after = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
            if _identity(before) != _identity(after) or _identity(before) != _identity(leaf_after):
                raise ValueError(f"{label} identity or size changed while reading")
            if len(data) != before.st_size:
                raise ValueError(f"{label} size changed while reading")
        finally:
            os.close(fd)

        for index, component in enumerate(parent_names):
            containing_fd = parent_fds[index]
            opened_fd = parent_fds[index + 1]
            named = os.stat(component, dir_fd=containing_fd, follow_symlinks=False)
            opened = os.fstat(opened_fd)
            if stat.S_ISLNK(named.st_mode) or not stat.S_ISDIR(named.st_mode) or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                raise ValueError("evidence parent directory changed while reading")

        return data, hashlib.sha256(data).hexdigest(), _identity(before)
    finally:
        for descriptor in reversed(parent_fds):
            os.close(descriptor)


def read_pinned_json_bytes(path: Path, label: str, repository_root: Path) -> tuple[Any, bytes, str, tuple[int, ...]]:
    data, digest, identity = read_pinned_bytes(path, label, repository_root)
    try:
        document = loads_unique_json(data, label)
    except ValueError as error:
        raise ValueError(str(error)) from error
    return document, data, digest, identity


def read_pinned_json(path: Path, label: str, repository_root: Path) -> tuple[Any, str, tuple[int, ...]]:
    document, _data, digest, identity = read_pinned_json_bytes(path, label, repository_root)
    return document, digest, identity
