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
    absolute = _contained_real_path(path, repository_root)
    if os.name == "nt":
        data, identity, _final_path = _read_windows(absolute, repository_root)
        return data, hashlib.sha256(data).hexdigest(), identity
    if os.name not in ("posix",):
        raise ValueError("this platform has no supported pinned evidence reader")
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("this Unix platform does not provide O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(absolute, flags)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError(f"{label} is not a regular file")
        chunks = []
        while chunk := os.read(fd, 1024 * 1024):
            chunks.append(chunk)
        data = b"".join(chunks)
        after = os.fstat(fd)
        path_after = absolute.lstat()
        if _identity(before) != _identity(after) or _identity(before) != _identity(path_after):
            raise ValueError(f"{label} identity or size changed while reading")
        if len(data) != before.st_size:
            raise ValueError(f"{label} size changed while reading")
        return data, hashlib.sha256(data).hexdigest(), _identity(before)
    finally:
        os.close(fd)


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
