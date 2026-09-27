#!/usr/bin/env python3
"""Bind native sample reports to the current GitHub workflow run."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
from pathlib import Path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    target = os.environ.get("TARGET", "")
    allowed_targets = {"windows-x86_64", "macos-x86_64", "macos-aarch64", "linux-x86_64"}
    if target not in allowed_targets:
        print(f"FAIL: unexpected native target {target!r}", file=sys.stderr)
        return 2
    required_env = ("RUNNER_OS_NAME", "RUNNER_ARCH_NAME", "WORKFLOW_RUN_ID", "WORKFLOW_JOB_ID", "COMMIT_SHA", "GITHUB_OUTPUT")
    missing = [name for name in required_env if not os.environ.get(name)]
    if missing:
        print(f"FAIL: missing provenance environment values: {', '.join(missing)}", file=sys.stderr)
        return 2

    profile = Path(f"target/stage0/ffmpeg-{target}.json")
    sample = Path(f"target/stage0/samples-{target}.json")
    try:
        report = json.loads(sample.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"FAIL: native sample report is unavailable or invalid: {error}", file=sys.stderr)
        return 2
    digest = report.get("evidence_input_digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        print("FAIL: native sample report has no valid evidence-input digest", file=sys.stderr)
        return 2
    if not profile.is_file():
        print("FAIL: native FFmpeg profile report is missing", file=sys.stderr)
        return 2

    arch_value = os.environ["RUNNER_ARCH_NAME"].lower()
    arch = {"x64": "x86_64", "arm64": "aarch64"}.get(arch_value, arch_value)
    provenance = {
        "schema": "fluxform.native-sample-artifact.v1",
        "artifact_name": f"stage0-samples-{target}-{digest}",
        "target_profile_id": report.get("target_profile_id"),
        "target_triple": report.get("target_triple"),
        "runner_os": os.environ["RUNNER_OS_NAME"].lower(),
        "runner_arch": arch,
        "git_commit": os.environ["COMMIT_SHA"],
        "evidence_input_digest": digest,
        "workflow_run_id": os.environ["WORKFLOW_RUN_ID"],
        "workflow_job_id": os.environ["WORKFLOW_JOB_ID"],
        "ffmpeg_profile_report_sha256": sha256(profile),
        "sample_report_sha256": sha256(sample),
    }
    output_directory = Path(f"target/stage0/native-artifact-{target}")
    try:
        output_directory.mkdir(parents=True, exist_ok=False)
        shutil.copyfile(profile, output_directory / "ffmpeg-profile-report.json")
        shutil.copyfile(sample, output_directory / "sample-report.json")
        (output_directory / "provenance.json").write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="") as output:
            output.write(f"digest={digest}\n")
    except OSError as error:
        print(f"FAIL: cannot write native provenance artifacts: {error}", file=sys.stderr)
        return 2
    print(f"native provenance bound for {target}: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
