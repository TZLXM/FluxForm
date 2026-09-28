#!/usr/bin/env python3
"""Copy Git-tracked desktop probe source to an invocation-owned snapshot."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

RESERVED_ROOT_NAMES = {".git", "target"}
OWNERSHIP_MARKER = ".stage0-owned-desktop-snapshot"
WINDOWS_RESERVED_NAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


class SnapshotError(RuntimeError):
    """A source or destination cannot be snapshotted safely."""


@dataclass(frozen=True)
class TrackedFile:
    path: str
    parts: tuple[str, ...]
    mode: int


def reparse_or_symlink(path: Path) -> bool:
    return _metadata_is_reparse(path.lstat())


def _metadata_is_reparse(metadata: os.stat_result) -> bool:
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(getattr(metadata, "st_file_attributes", 0) & reparse_flag)


def _parse_git_path(raw_path: bytes) -> tuple[str, tuple[str, ...]]:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SnapshotError("Git tracked a path that is not valid UTF-8.") from error

    parts = path.split("/")
    if (
        not path
        or "\\" in path
        or any(part in ("", ".", "..") for part in parts)
        or any(
            ":" in part
            or part.endswith((".", " "))
            or any(ord(character) < 32 or character in '<>"|?*' for character in part)
            for part in parts
        )
    ):
        raise SnapshotError(f"Git tracked an unsafe or non-portable path: {path!r}")

    for part in parts:
        device_basename = part.split(".", 1)[0].rstrip(" .").casefold()
        if device_basename in WINDOWS_RESERVED_NAMES:
            raise SnapshotError(f"Git tracked a reserved Windows path: {path!r}")

    return path, tuple(parts)


def _normalized_parts(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


def _validate_tracked_paths(entries: list[TrackedFile]) -> None:
    marker_key = _normalized_parts((OWNERSHIP_MARKER,))
    file_paths = {marker_key}
    directory_paths: set[tuple[str, ...]] = set()
    spellings: dict[tuple[str, ...], tuple[str, ...]] = {}

    for entry in entries:
        normalized = _normalized_parts(entry.parts)
        for length in range(1, len(entry.parts) + 1):
            key = normalized[:length]
            spelling = entry.parts[:length]
            previous_spelling = spellings.get(key)
            if previous_spelling is not None and previous_spelling != spelling:
                raise SnapshotError(f"Tracked paths collide by case or Unicode normalization: {entry.path!r}")
            spellings[key] = spelling

            if length < len(entry.parts):
                if key in file_paths:
                    raise SnapshotError(f"A tracked file is also a parent directory: {entry.path!r}")
                directory_paths.add(key)
            else:
                if key in file_paths:
                    raise SnapshotError(f"Duplicate or reserved tracked path: {entry.path!r}")
                if key in directory_paths:
                    raise SnapshotError(f"A tracked file collides with a tracked directory: {entry.path!r}")
                file_paths.add(key)


def parse_git_index(output: bytes) -> list[TrackedFile]:
    """Parse `git ls-files --stage -z` output and reject unsafe entries."""
    if output and not output.endswith(b"\0"):
        raise SnapshotError("Git returned an incomplete tracked-file manifest.")

    entries: list[TrackedFile] = []
    for record in output[:-1].split(b"\0") if output else []:
        header, separator, raw_path = record.partition(b"\t")
        fields = header.split()
        if not separator or len(fields) != 3:
            raise SnapshotError("Git returned a malformed tracked-file manifest.")
        try:
            mode = int(fields[0], 8)
            stage = int(fields[2], 10)
        except ValueError as error:
            raise SnapshotError("Git returned an invalid mode or stage in the tracked-file manifest.") from error

        path, parts = _parse_git_path(raw_path)
        if stage != 0:
            raise SnapshotError(f"Tracked path has an unresolved Git index stage: {path!r}")
        if mode not in (0o100644, 0o100755):
            raise SnapshotError(f"Tracked path is not a regular file in the Git index: {path!r}")
        entries.append(TrackedFile(path=path, parts=parts, mode=mode))

    _validate_tracked_paths(entries)
    return entries


def read_tracked_files(repo_root: Path) -> list[TrackedFile]:
    try:
        root_result = subprocess.run(
            ["git", "-C", str(repo_root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=False,
        )
        if root_result.returncode != 0:
            detail = root_result.stderr.decode("utf-8", errors="replace").strip()
            raise SnapshotError(f"Cannot identify the Git repository root: {detail}")
        git_root = Path(root_result.stdout.decode("utf-8").strip()).resolve(strict=True)
        if os.path.normcase(str(git_root)) != os.path.normcase(str(repo_root)):
            raise SnapshotError("The requested source root is not the Git repository root.")

        index_result = subprocess.run(
            ["git", "-C", str(repo_root), "ls-files", "--stage", "--full-name", "-z"],
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise SnapshotError(f"Cannot read the Git tracked-file manifest: {error}") from error

    if index_result.returncode != 0:
        detail = index_result.stderr.decode("utf-8", errors="replace").strip()
        raise SnapshotError(f"Cannot read the Git tracked-file manifest: {detail}")
    return parse_git_index(index_result.stdout)


def inspect_source_path(repo_root: Path, entry: TrackedFile) -> tuple[Path, os.stat_result]:
    current = repo_root
    metadata: os.stat_result | None = None
    for index, part in enumerate(entry.parts):
        current = current / part
        metadata = current.lstat()
        if _metadata_is_reparse(metadata):
            raise SnapshotError(f"Tracked source contains a symlink or reparse point: {entry.path!r}")
        is_file = index == len(entry.parts) - 1
        if is_file and not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError(f"Tracked source is missing or not a regular file: {entry.path!r}")
        if not is_file and not stat.S_ISDIR(metadata.st_mode):
            raise SnapshotError(f"Tracked source parent is not a directory: {entry.path!r}")

    assert metadata is not None
    return current, metadata


def _open_posix_source(repo_root: Path, entry: TrackedFile) -> tuple[BinaryIO, os.stat_result]:
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    open_directory_fds: list[int] = []
    file_fd: int | None = None
    try:
        current_fd = os.open(repo_root, directory_flags)
        open_directory_fds.append(current_fd)
        for part in entry.parts[:-1]:
            next_fd = os.open(part, directory_flags, dir_fd=current_fd)
            if not stat.S_ISDIR(os.fstat(next_fd).st_mode):
                os.close(next_fd)
                raise SnapshotError(f"Tracked source parent is not a directory: {entry.path!r}")
            open_directory_fds.append(next_fd)
            current_fd = next_fd

        file_fd = os.open(entry.parts[-1], file_flags, dir_fd=current_fd)
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError(f"Tracked source is not a regular file: {entry.path!r}")
        stream = os.fdopen(file_fd, "rb")
        file_fd = None
        return stream, metadata
    except OSError as error:
        raise SnapshotError(f"Cannot safely open tracked source {entry.path!r}: {error}") from error
    finally:
        if file_fd is not None:
            os.close(file_fd)
        for descriptor in reversed(open_directory_fds):
            os.close(descriptor)


def _open_windows_source(source: Path, entry: TrackedFile) -> tuple[BinaryIO, os.stat_result]:
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [("file_attributes", wintypes.DWORD), ("reparse_tag", wintypes.DWORD)]

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
    get_info = kernel32.GetFileInformationByHandleEx
    get_info.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD]
    get_info.restype = wintypes.BOOL
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
    get_final_path.restype = wintypes.DWORD

    generic_read = 0x80000000
    share_all = 0x00000001 | 0x00000002 | 0x00000004
    open_existing = 3
    open_reparse_point = 0x00200000
    sequential_scan = 0x08000000
    invalid_handle = ctypes.c_void_p(-1).value
    handle = create_file(
        str(source),
        generic_read,
        share_all,
        None,
        open_existing,
        open_reparse_point | sequential_scan,
        None,
    )
    if handle == invalid_handle:
        raise SnapshotError(f"Cannot safely open tracked source {entry.path!r}: {ctypes.WinError(ctypes.get_last_error())}")

    file_descriptor: int | None = None
    try:
        attributes = FileAttributeTagInfo()
        if not get_info(handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)):
            raise SnapshotError(f"Cannot inspect tracked source handle: {ctypes.WinError(ctypes.get_last_error())}")
        if attributes.file_attributes & 0x400:
            raise SnapshotError(f"Tracked source contains a reparse point: {entry.path!r}")

        final_path_buffer = ctypes.create_unicode_buffer(32768)
        final_path_length = get_final_path(handle, final_path_buffer, len(final_path_buffer), 0)
        if final_path_length == 0 or final_path_length >= len(final_path_buffer):
            raise SnapshotError(f"Cannot resolve opened tracked source handle: {ctypes.WinError(ctypes.get_last_error())}")
        final_path = final_path_buffer.value
        if final_path.startswith("\\\\?\\UNC\\"):
            final_path = "\\\\" + final_path[8:]
        elif final_path.startswith("\\\\?\\"):
            final_path = final_path[4:]
        if os.path.normcase(os.path.normpath(final_path)) != os.path.normcase(os.path.normpath(os.path.abspath(source))):
            raise SnapshotError(f"Tracked source resolved outside its expected path: {entry.path!r}")

        file_descriptor = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
        handle = invalid_handle
        metadata = os.fstat(file_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SnapshotError(f"Tracked source is not a regular file: {entry.path!r}")
        stream = os.fdopen(file_descriptor, "rb")
        file_descriptor = None
        return stream, metadata
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if handle != invalid_handle:
            kernel32.CloseHandle(handle)


def open_tracked_source(repo_root: Path, entry: TrackedFile) -> tuple[BinaryIO, os.stat_result]:
    source, _ = inspect_source_path(repo_root, entry)
    if os.name == "nt":
        return _open_windows_source(source, entry)
    if (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in getattr(os, "supports_dir_fd", set())
    ):
        return _open_posix_source(repo_root, entry)

    raise SnapshotError("This platform does not provide safe no-follow traversal for tracked source files.")


def _copy_tracked_file(repo_root: Path, destination: Path, entry: TrackedFile) -> None:
    target_directory = destination
    for part in entry.parts[:-1]:
        target_directory = target_directory / part
        try:
            target_directory.mkdir()
        except FileExistsError:
            metadata = target_directory.lstat()
            if reparse_or_symlink(target_directory) or not stat.S_ISDIR(metadata.st_mode):
                raise SnapshotError(f"Unsafe snapshot directory: {target_directory}")

    target = target_directory / entry.parts[-1]
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    source_stream, source_metadata = open_tracked_source(repo_root, entry)
    with source_stream:
        try:
            descriptor = os.open(target, flags, 0o600)
        except OSError as error:
            raise SnapshotError(f"Cannot create snapshot file {entry.path!r}: {error}") from error
        with os.fdopen(descriptor, "wb") as target_stream:
            shutil.copyfileobj(source_stream, target_stream, length=1024 * 1024)
            mode = stat.S_IMODE(source_metadata.st_mode)
            if hasattr(os, "fchmod"):
                os.fchmod(target_stream.fileno(), mode)
            else:
                os.chmod(target, mode)
            timestamps = (source_metadata.st_atime_ns, source_metadata.st_mtime_ns)
            if os.utime in getattr(os, "supports_fd", set()):
                os.utime(target_stream.fileno(), ns=timestamps)
            else:
                os.utime(target, ns=timestamps)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()

    try:
        repo_root = args.repo_root.resolve(strict=True)
    except OSError as error:
        print(f"FAIL: source repository does not exist: {error}", file=sys.stderr)
        return 2

    target_stage0 = repo_root / "target" / "stage0"
    destination = args.destination.absolute()
    try:
        destination.relative_to(target_stage0.absolute())
    except ValueError:
        print("FAIL: desktop build snapshot destination must stay under target/stage0", file=sys.stderr)
        return 2

    current = repo_root
    try:
        for component in destination.relative_to(repo_root).parts[:-1]:
            current = current / component
            if not current.exists() or reparse_or_symlink(current):
                print(f"FAIL: unsafe or missing snapshot parent: {current}", file=sys.stderr)
                return 2
        resolved_parent = destination.parent.resolve(strict=True)
        resolved_parent.relative_to(target_stage0.resolve(strict=True))
    except (OSError, ValueError) as error:
        print(f"FAIL: unsafe desktop snapshot path: {error}", file=sys.stderr)
        return 2

    if destination.exists() or destination.is_symlink():
        if args.cleanup:
            relative = destination.relative_to(repo_root)
            if len(relative.parts) != 5 or relative.parts[:3] != ("target", "stage0", "runs") or relative.parts[-1] != "desktop-source":
                print("FAIL: cleanup target is not this invocation's target/stage0 desktop snapshot", file=sys.stderr)
                return 2
            run_id = relative.parts[3]
            marker = destination / OWNERSHIP_MARKER
            try:
                if reparse_or_symlink(destination) or reparse_or_symlink(marker):
                    print("FAIL: refusing to clean a linked desktop snapshot or ownership marker", file=sys.stderr)
                    return 2
                if marker.read_text(encoding="utf-8") != run_id:
                    print("FAIL: refusing to clean a desktop snapshot without this run's ownership marker", file=sys.stderr)
                    return 2
                shutil.rmtree(destination)
            except OSError as error:
                print(f"FAIL: cannot clean this invocation's isolated desktop snapshot: {error}", file=sys.stderr)
                return 2
            print(f"removed invocation-owned desktop source snapshot={destination}")
            return 0
        print(f"FAIL: refusing to overwrite an existing desktop snapshot: {destination}", file=sys.stderr)
        return 2
    if args.cleanup:
        print(f"FAIL: refusing to clean a missing desktop snapshot: {destination}", file=sys.stderr)
        return 2

    try:
        entries = read_tracked_files(repo_root)
        for entry in entries:
            root_name = entry.parts[0].casefold() if os.name == "nt" else entry.parts[0]
            if root_name in RESERVED_ROOT_NAMES:
                raise SnapshotError(f"Refusing tracked reserved repository-root path: {entry.path!r}")
            inspect_source_path(repo_root, entry)

        destination.mkdir()
        marker = destination / OWNERSHIP_MARKER
        with marker.open("x", encoding="utf-8", newline="") as marker_file:
            marker_file.write(destination.parent.name)
        for entry in entries:
            _copy_tracked_file(repo_root, destination, entry)
    except (OSError, SnapshotError) as error:
        print(f"FAIL: cannot create isolated desktop source snapshot: {error}", file=sys.stderr)
        return 2

    if (destination / ".git").exists() or (destination / "target").exists():
        print("FAIL: isolated desktop snapshot unexpectedly contains .git or target", file=sys.stderr)
        return 2
    print(f"desktop source snapshot={destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
