"""Regression for Bash desktop snapshot errors followed by cleanup errors."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_STAGE0 = REPO_ROOT / "scripts" / "check-stage0.sh"
PRIMARY_DIAGNOSTIC = "PRIMARY_SNAPSHOT_FAILURE_DIAGNOSTIC"
CLEANUP_DIAGNOSTIC = "CLEANUP_FAILURE_DIAGNOSTIC"


def bash_executable() -> Path:
    if os.name == "nt":
        candidates = [Path(r"C:\Program Files\Git\bin\bash.exe")]
        located = shutil.which("bash")
        if located:
            candidates.append(Path(located))
        for candidate in candidates:
            if candidate.is_file():
                return candidate
        raise unittest.SkipTest("Git Bash is unavailable on this Windows host")

    located = shutil.which("bash")
    if not located:
        raise unittest.SkipTest("Bash is unavailable on this host")
    return Path(located)


def to_bash_path(bash: Path, path: Path) -> str:
    if os.name != "nt":
        return str(path)

    result = subprocess.run(
        [
            str(bash),
            "-c",
            'export PATH="/usr/bin:/mingw64/bin:/cmd"; cygpath -u "$1"',
            "stage0-test",
            str(path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        raise RuntimeError(f"cygpath failed for {path}: {result.stderr}")
    return result.stdout.strip()


def write_executable(path: Path, contents: str) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        stream.write(contents)
    if os.name != "nt":
        path.chmod(0o755)


class BashSnapshotFailureTests(unittest.TestCase):
    def test_snapshot_failure_remains_primary_when_cleanup_also_fails(self) -> None:
        bash = bash_executable()
        real_git = shutil.which("git")
        self.assertIsNotNone(real_git, "git is required for the source-status guard")

        with tempfile.TemporaryDirectory(prefix="stage0-bash-failure-") as temporary:
            tools = Path(temporary)
            python_shim = tools / "python3"
            pnpm_shim = tools / "pnpm"
            git_shim = tools / "git"
            status_log = tools / "git-status.log"
            pnpm_log = tools / "pnpm.log"
            write_executable(
                python_shim,
                """#!/bin/sh
if [ "$1" = '-c' ]; then exit 0; fi
destination=''
cleanup=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --destination) destination="$2"; shift 2 ;;
    --cleanup) cleanup=1; shift ;;
    *) shift ;;
  esac
done
if [ "$cleanup" -eq 1 ]; then
  printf '%s\\n' 'CLEANUP_FAILURE_DIAGNOSTIC' >&2
  exit 29
fi
mkdir -- "$destination"
run_dir="$(dirname -- "$destination")"
run_id="$(basename -- "$run_dir")"
printf '%s' "$run_id" > "$destination/.stage0-owned-desktop-snapshot"
printf '%s\\n' 'PRIMARY_SNAPSHOT_FAILURE_DIAGNOSTIC' >&2
exit 23
""",
            )
            write_executable(
                pnpm_shim,
                """#!/bin/sh
if [ "$1" = '--version' ]; then printf '%s\\n' '11.19.0'; exit 0; fi
printf '%s\\n' "$*" >> "$FLUXFORM_STAGE0_TEST_PNPM_LOG"
exit 0
""",
            )
            write_executable(
                git_shim,
                """#!/bin/sh
case " $* " in
  *' status --porcelain --untracked-files=all '*) printf '%s\\n' status >> "$FLUXFORM_STAGE0_TEST_GIT_STATUS_LOG" ;;
esac
exec "$FLUXFORM_STAGE0_TEST_REAL_GIT" "$@"
""",
            )

            bin_path = to_bash_path(bash, tools)
            script_path = to_bash_path(bash, CHECK_STAGE0)
            git_path = to_bash_path(bash, Path(real_git))
            if os.name == "nt":
                chmod = subprocess.run(
                    [
                        str(bash),
                        "-c",
                        'export PATH="/usr/bin:/mingw64/bin:/cmd"; chmod +x "$1" "$2" "$3"',
                        "stage0-test",
                        to_bash_path(bash, python_shim),
                        to_bash_path(bash, pnpm_shim),
                        to_bash_path(bash, git_shim),
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self.assertEqual(chmod.returncode, 0, chmod.stdout + chmod.stderr)

            status_before = subprocess.run(
                [real_git, "status", "--porcelain", "--untracked-files=all"],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            status_log_bash = to_bash_path(bash, status_log)
            pnpm_log_bash = to_bash_path(bash, pnpm_log)
            env = os.environ.copy()
            env.update(
                {
                    "FLUXFORM_STAGE0_TEST_GIT_STATUS_LOG": status_log_bash,
                    "FLUXFORM_STAGE0_TEST_PNPM_LOG": pnpm_log_bash,
                    "FLUXFORM_STAGE0_TEST_REAL_GIT": git_path,
                }
            )
            if os.name == "nt":
                path_setup = 'export PATH="$1:/usr/bin:/mingw64/bin:/cmd"'
            else:
                path_setup = 'export PATH="$1:$PATH"'
            command = (
                f"{path_setup}; "
                'exec bash "$2" --mode automated --gate desktop-build'
            )
            result = subprocess.run(
                [str(bash), "-c", command, "stage0-test", bin_path, script_path],
                cwd=REPO_ROOT,
                env=env,
                check=False,
                capture_output=True,
                text=True,
                timeout=90,
            )
            output = result.stdout + result.stderr
            match = re.search(
                r"runs[\\/]+([^\\/]+)[\\/]+desktop-build-snapshot\.log",
                output,
            )
            self.assertIsNotNone(match, output)
            run_id = match.group(1)
            snapshot = REPO_ROOT / "target" / "stage0" / "runs" / run_id / "desktop-source"
            marker = snapshot / ".stage0-owned-desktop-snapshot"
            try:
                marker_was_valid = marker.is_file() and marker.read_text(encoding="utf-8") == run_id
                status_after = subprocess.run(
                    [real_git, "status", "--porcelain", "--untracked-files=all"],
                    cwd=REPO_ROOT,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
                self.assertNotEqual(result.returncode, 0, output)
                self.assertTrue(marker_was_valid, "snapshot shim did not create a valid run-owned marker")
                self.assertEqual(status_before, status_after, "source Git status changed")
                self.assertEqual(status_log.read_text(encoding="utf-8").splitlines(), ["status", "status"])
                self.assertFalse(pnpm_log.exists(), "pnpm must not run after snapshot creation fails")
                gate_line = next(
                    (line for line in output.splitlines() if line.startswith("gate desktop-build=FAIL")),
                    "",
                )
                self.assertIn(PRIMARY_DIAGNOSTIC, gate_line, output)
                self.assertIn(CLEANUP_DIAGNOSTIC, gate_line, output)
                self.assertLess(gate_line.index(PRIMARY_DIAGNOSTIC), gate_line.index(CLEANUP_DIAGNOSTIC), gate_line)
                self.assertIn("command exited 23", gate_line, output)
                self.assertIn("command exited 29", gate_line, output)
                self.assertIn("desktop-build=FAIL", output.split("Stage 0 gate summary:")[-1])
            finally:
                if marker.is_file() and marker.read_text(encoding="utf-8") == run_id:
                    shutil.rmtree(snapshot)


if __name__ == "__main__":
    unittest.main()
