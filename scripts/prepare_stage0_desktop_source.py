#!/usr/bin/env python3
"""Copy the desktop probe source to an invocation-owned target/stage0 workspace."""

from __future__ import annotations

import argparse
import os
import shutil
import stat
import sys
from pathlib import Path

IGNORED_NAMES = {".git", "target", "node_modules", "bin", "obj", "publish", "tools-cache"}


def reparse_or_symlink(path: Path) -> bool:
    metadata = path.lstat()
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    parser.add_argument("--cleanup", action="store_true")
    args = parser.parse_args()

    repo_root = args.repo_root.resolve(strict=True)
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
            marker = destination / ".stage0-owned-desktop-snapshot"
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

    # Reject links instead of following user-controlled links into or out of the source tree.
    for root, directories, files in os.walk(repo_root, topdown=True, followlinks=False):
        root_path = Path(root)
        directories[:] = [name for name in directories if name not in IGNORED_NAMES]
        if root_path == repo_root:
            directories[:] = [name for name in directories if name not in IGNORED_NAMES]
        for name in directories + files:
            candidate = root_path / name
            try:
                if reparse_or_symlink(candidate):
                    print(f"FAIL: source snapshot contains a symlink or reparse point: {candidate}", file=sys.stderr)
                    return 2
            except OSError as error:
                print(f"FAIL: cannot inspect source path {candidate}: {error}", file=sys.stderr)
                return 2

    def ignore(directory: str, names: list[str]) -> set[str]:
        return set(names).intersection(IGNORED_NAMES)

    try:
        shutil.copytree(repo_root, destination, ignore=ignore, symlinks=False)
        run_id = destination.parent.name
        (destination / ".stage0-owned-desktop-snapshot").write_text(run_id, encoding="utf-8")
    except OSError as error:
        print(f"FAIL: cannot create isolated desktop source snapshot: {error}", file=sys.stderr)
        return 2

    if (destination / ".git").exists() or (destination / "target").exists():
        print("FAIL: isolated desktop snapshot unexpectedly contains .git or target", file=sys.stderr)
        return 2
    print(f"desktop source snapshot={destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
