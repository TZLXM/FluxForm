#!/usr/bin/env python3
"""Record the current Stage 0 sample collector and verification closure."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tomllib
from pathlib import Path, PurePosixPath

from stage0_json import read_pinned_bytes, read_pinned_json

TARGET_IDS = ("windows-x86_64", "macos-x86_64", "macos-aarch64", "linux-x86_64")
COMMANDS = {
    "collector": (
        "aggregate-samples.log",
        "collect_sample_reports",
        "cargo --locked --offline run -p fluxform-capabilities --bin collect_sample_reports",
        ("--input target/stage0/collected", "--manifest config/capabilities-v1.toml", "--samples testdata/media/v1/samples.toml", "--expected-input-digest", "--out"),
    ),
    "verify_manifest": (
        "aggregate-samples-manifest.log",
        "verify_manifest verify-manifest",
        "cargo --locked --offline run -p fluxform-capabilities --bin verify_manifest",
        ("verify-manifest --manifest config/capabilities-v1.toml", "--reports", "collected-profiles"),
    ),
    "cross_platform_samples": (
        "aggregate-samples-cross-platform.log",
        "cross_platform_samples",
        "cargo --locked --offline test -p fluxform-capabilities --test cross_platform_samples",
        ("--test cross_platform_samples",),
    ),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _safe_relative(raw: str) -> PurePosixPath:
    path = PurePosixPath(raw)
    if not raw or "\\" in raw or "\x00" in raw or path.is_absolute() or str(path) != raw or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError("receipt input path is not a normalized repository-relative path")
    if re.match(r"^[A-Za-z]:", raw):
        raise ValueError("receipt input path must not be drive-qualified")
    return path


def _read_file(repo_root: Path, relative: PurePosixPath, label: str) -> tuple[bytes, str]:
    path = repo_root.joinpath(*relative.parts)
    data, digest, _identity = read_pinned_bytes(path, label, repo_root)
    return data, digest


def _is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def _ensure_output_parent(repo_root: Path, relative: PurePosixPath) -> Path:
    current = repo_root
    for component in relative.parts[:-1]:
        current = current / component
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or _is_reparse_point(metadata):
            raise ValueError("aggregate receipt output contains a symlink or non-directory parent")
    return repo_root.joinpath(*relative.parts)


def _write_atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def write_receipt(repo_root: Path, aggregate_report_path: Path, commit_sha: str) -> Path:
    root = repo_root.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{40}", commit_sha):
        raise ValueError("GITHUB_SHA must be a lowercase 40-character commit SHA")

    aggregate_path = Path(os.path.abspath(aggregate_report_path))
    try:
        aggregate_relative = aggregate_path.relative_to(root).as_posix()
    except ValueError as error:
        raise ValueError("collector aggregate output is outside the repository root") from error
    run_relative = _safe_relative(aggregate_relative)
    if len(run_relative.parts) != 5 or run_relative.parts[:3] != ("target", "stage0", "runs") or run_relative.name != "aggregate-sample-report.json":
        raise ValueError("collector aggregate output is not inside one target/stage0/runs invocation")
    run_id = run_relative.parts[3]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        raise ValueError("collector aggregate output has a malformed invocation identity")

    aggregate, aggregate_digest, _aggregate_identity = read_pinned_json(aggregate_path, "current collector aggregate output", root)
    if not isinstance(aggregate, dict) or set(aggregate) != {"schema", "status", "evidence_input_digest", "targets"}:
        raise ValueError("collector aggregate output does not match its exact schema")
    evidence_input_digest = aggregate["evidence_input_digest"]
    if aggregate["schema"] != "fluxform.sample-aggregate.v1" or aggregate["status"] != "passed" or not isinstance(evidence_input_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", evidence_input_digest):
        raise ValueError("collector aggregate output is not a successful current v1 report")

    expected_files: dict[str, str] = {}

    def record(relative_text: str, label: str) -> str:
        relative = _safe_relative(relative_text)
        data, digest = _read_file(root, relative, label)
        expected_files[relative.as_posix()] = digest
        return digest

    record("config/capabilities-v1.toml", "tracked capability manifest")
    catalog_relative = "testdata/media/v1/samples.toml"
    catalog_bytes, catalog_digest = _read_file(root, _safe_relative(catalog_relative), "tracked sample catalog")
    expected_files[catalog_relative] = catalog_digest
    catalog = tomllib.loads(catalog_bytes.decode("utf-8", errors="strict"))
    sample_records = catalog.get("samples")
    if not isinstance(sample_records, list) or not sample_records:
        raise ValueError("tracked sample catalog has no samples")
    for sample in sample_records:
        if not isinstance(sample, dict) or not isinstance(sample.get("path"), str):
            raise ValueError("tracked sample catalog contains a malformed sample path")
        record(f"testdata/media/v1/{sample['path']}", "tracked sample corpus file")

    record(aggregate_relative, "current collector aggregate output")
    run_prefix = run_relative.parent.as_posix()
    for target_id in TARGET_IDS:
        for filename in ("ffmpeg-profile-report.json", "sample-report.json", "provenance.json"):
            record(f"target/stage0/collected/{target_id}/{filename}", "same-run collected native artifact")
        collected_profile_path = f"target/stage0/collected/{target_id}/ffmpeg-profile-report.json"
        collected_profile_digest = expected_files[collected_profile_path]
        copied_profile_digest = record(f"{run_prefix}/collected-profiles/{target_id}.json", "same-run collected profile copy")
        if copied_profile_digest != collected_profile_digest:
            raise ValueError(f"{target_id} verify_manifest profile copy differs from the collector input")

    commands: dict[str, dict[str, object]] = {}
    for command_id, (filename, command_name, prefix, required_fragments) in COMMANDS.items():
        log_relative = f"{run_prefix}/{filename}"
        log_bytes, log_digest = _read_file(root, _safe_relative(log_relative), f"same-run {command_id} log")
        expected_files[log_relative] = log_digest
        lines = log_bytes.decode("utf-8", errors="strict").splitlines()
        invocation = lines[0].removeprefix("+ ") if lines else ""
        if not lines or not invocation.startswith(prefix) or lines[-1] != "exit_code=0" or any(fragment not in invocation for fragment in required_fragments):
            raise ValueError(f"same-run {command_id} log does not prove its required successful invocation")
        if command_id == "collector" and (evidence_input_digest not in invocation or "aggregate-sample-report.json" not in invocation or run_id not in invocation):
            raise ValueError("same-run collector log targets a different input digest or output invocation")
        if command_id == "verify_manifest" and run_id not in invocation:
            raise ValueError("same-run verify_manifest log targets a different invocation")
        commands[command_id] = {
            "command": command_name,
            "path": log_relative,
            "sha256": log_digest,
            "exit_code": 0,
        }

    files = [{"path": path, "sha256": digest} for path, digest in sorted(expected_files.items())]
    receipt = {
        "schema": "fluxform.stage0.aggregate-execution-receipt.v1",
        "status": "PASS",
        "commit_sha": commit_sha,
        "evidence_input_digest": evidence_input_digest,
        "aggregate_report": {"path": aggregate_relative, "sha256": aggregate_digest},
        "commands": commands,
        "files": files,
        "closure_digest": _sha256(_canonical_json(files)),
    }
    receipt_relative = run_relative.parent / "aggregate-validation.json"
    receipt_path = _ensure_output_parent(root, receipt_relative)
    _write_atomic(receipt_path, _canonical_json(receipt))
    return receipt_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--aggregate-report", required=True, type=Path)
    parser.add_argument("--commit-sha", required=True)
    args = parser.parse_args()
    try:
        path = write_receipt(args.repo_root, args.aggregate_report, args.commit_sha)
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        print(f"BLOCKED: aggregate execution receipt could not be recorded: {error}", file=sys.stderr)
        return 10
    print(f"PASS: recorded same-run aggregate execution receipt at {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
