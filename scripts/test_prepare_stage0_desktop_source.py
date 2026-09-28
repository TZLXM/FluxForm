#!/usr/bin/env python3
"""Behavior tests for tracked-only Stage 0 desktop source snapshots."""

from __future__ import annotations

import os
import runpy
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("prepare_stage0_desktop_source.py")


class DesktopSourceSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.repo = Path(self.temporary_directory.name)
        self.git("init", "--quiet")
        self.git("config", "user.email", "snapshot-test@example.invalid")
        self.git("config", "user.name", "Snapshot Test")
        (self.repo / "tracked.txt").write_text("indexed version\n", encoding="utf-8")
        self.git("add", "tracked.txt")
        self.destination = self.repo / "target" / "stage0" / "runs" / "run-test" / "desktop-source"
        self.destination.parent.mkdir(parents=True)

    def git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.repo), *arguments],
            check=True,
            capture_output=True,
            text=True,
        )

    def run_snapshot(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--repo-root",
                str(self.repo),
                "--destination",
                str(self.destination),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_untracked_large_directory_is_not_copied(self) -> None:
        untracked = self.repo / "target-task-untracked-sentinel"
        untracked.mkdir()
        for index in range(1024):
            (untracked / f"sentinel-{index:04}.txt").write_text("untracked\n", encoding="utf-8")

        result = self.run_snapshot()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.destination / untracked.name).exists())
        self.assertEqual((self.destination / "tracked.txt").read_text(encoding="utf-8"), "indexed version\n")

    def test_untracked_directory_symlink_or_junction_is_not_scanned(self) -> None:
        outside_temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(outside_temporary_directory.cleanup)
        outside = Path(outside_temporary_directory.name)
        (outside / "outside-sentinel.txt").write_text("outside\n", encoding="utf-8")
        link = self.repo / "target-task-untracked-link"
        if os.name == "nt":
            result = subprocess.run(
                ["cmd.exe", "/c", "mklink", "/J", str(link), str(outside)],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest(f"directory junctions are unavailable on this host: {result.stderr}")
        else:
            try:
                link.symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"directory symlinks are unavailable on this host: {error}")
        self.assertTrue(link.is_dir())
        self.assertTrue(
            getattr(link.lstat(), "st_file_attributes", 0)
            & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
            or link.is_symlink()
        )

        snapshot_result = self.run_snapshot()

        self.assertEqual(snapshot_result.returncode, 0, snapshot_result.stdout + snapshot_result.stderr)
        self.assertFalse((self.destination / link.name).exists())

    def test_unstaged_changes_to_tracked_files_are_copied(self) -> None:
        (self.repo / "tracked.txt").write_text("working tree version\n", encoding="utf-8")

        result = self.run_snapshot()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.destination / "tracked.txt").read_text(encoding="utf-8"), "working tree version\n")

    @unittest.skipIf(os.name == "nt", "POSIX executable mode bits are unavailable on this host")
    def test_tracked_executable_mode_is_preserved(self) -> None:
        executable = self.repo / "run-tool.sh"
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o751)
        self.git("add", "run-tool.sh")

        result = self.run_snapshot()

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(stat.S_IMODE((self.destination / executable.name).stat().st_mode), 0o751)

    def test_tracked_symlink_is_rejected(self) -> None:
        link = self.repo / "tracked-link"
        try:
            link.symlink_to(self.repo / "tracked.txt")
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"file symlinks are unavailable on this host: {error}")
        self.git("add", "tracked-link")

        result = self.run_snapshot()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())

    def test_missing_tracked_file_is_rejected(self) -> None:
        (self.repo / "tracked.txt").unlink()

        result = self.run_snapshot()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "named pipes are unavailable on this host")
    def test_tracked_path_replaced_with_fifo_is_rejected(self) -> None:
        (self.repo / "tracked.txt").unlink()
        os.mkfifo(self.repo / "tracked.txt")

        result = self.run_snapshot()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())

    @unittest.skipIf(os.name == "nt", "case-colliding names cannot be represented on this filesystem")
    def test_case_colliding_tracked_paths_are_rejected(self) -> None:
        (self.repo / "Case.txt").write_text("upper\n", encoding="utf-8")
        (self.repo / "case.txt").write_text("lower\n", encoding="utf-8")
        self.git("add", "Case.txt", "case.txt")

        result = self.run_snapshot()

        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(self.destination.exists())

    def test_git_manifest_parent_traversal_is_rejected(self) -> None:
        parse_git_index = runpy.run_path(str(SCRIPT))["parse_git_index"]
        for bad_path in (b"../outside.txt", b"folder/../outside.txt", b"/outside.txt", b"folder\\outside.txt"):
            with self.subTest(path=bad_path):
                malformed_record = b"100644 " + (b"0" * 40) + b" 0\t" + bad_path + b"\0"
                with self.assertRaises(RuntimeError):
                    parse_git_index(malformed_record)


if __name__ == "__main__":
    unittest.main()
