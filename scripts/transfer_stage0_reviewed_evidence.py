#!/usr/bin/env python3
"""Stage a pre-provisioned read-only review bundle and bind it to this CI run."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from stage0_json import loads_unique_json, read_pinned_bytes


class TransferBlocked(Exception):
    pass


def validate_json_bytes(data: bytes, label: str):
    try:
        return loads_unique_json(data, label)
    except ValueError as error:
        raise TransferBlocked(str(error)) from error


def closure_digest(files: list[dict[str, str]]) -> str:
    normalized = sorted(({"path": item["path"], "sha256": item["sha256"]} for item in files), key=lambda item: item["path"])
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _readonly(path: Path) -> bool:
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
        return False
    if os.name == "nt":
        return not os.access(path, os.W_OK)
    return not (metadata.st_mode & 0o222) and not os.access(path, os.W_OK)


def _walk_json_inputs(root: Path) -> list[tuple[Path, str, bytes, str]]:
    if not root.is_dir() or not _readonly(root):
        raise TransferBlocked("review input directory must exist and be read-only for this runner account")
    files: list[tuple[Path, str, bytes, str]] = []
    total = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            directory = current_path / name
            if not _readonly(directory):
                raise TransferBlocked(f"review input directory is writable or a reparse point: {directory}")
        for name in filenames:
            path = current_path / name
            if path.suffix.lower() != ".json" or not _readonly(path):
                raise TransferBlocked("review bundle may contain only read-only JSON result/manifest files")
            relative = path.relative_to(root).as_posix()
            if len(Path(relative).parts) != 1:
                raise TransferBlocked("review bundle inputs must be a flat set of row manifests and raw JSON results")
            if relative.startswith("/") or ".." in Path(relative).parts:
                raise TransferBlocked("review input contains a non-normalized path")
            try:
                data, digest, _identity = read_pinned_bytes(path, "pre-provisioned review input", root)
            except (OSError, ValueError) as error:
                raise TransferBlocked(f"review input cannot be pinned safely: {error}") from error
            document = validate_json_bytes(data, relative)
            if not isinstance(document, dict):
                raise TransferBlocked(f"review input {relative} must be a JSON object")
            _reject_sensitive_content(document, relative)
            total += len(data)
            if len(data) > 32 * 1024 * 1024 or total > 512 * 1024 * 1024:
                raise TransferBlocked("review bundle exceeds its bounded JSON evidence size")
            files.append((path, relative, data, digest))
    if not files:
        raise TransferBlocked("pre-provisioned review input bundle is empty")
    manifests = [relative for _path, relative, _data, _digest in files if re.fullmatch(r"row-(?:0[1-9]|1[0-9]|2[0-3])\.manifest\.json", Path(relative).name)]
    if len(manifests) != 23:
        raise TransferBlocked(f"pre-provisioned review bundle must contain exactly 23 row manifests; found {len(manifests)}")
    return sorted(files, key=lambda item: item[1])


def _reject_sensitive_content(value, label: str) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if re.search(r"(?i)(?:token|secret|credential|authorization|sample[_-]?(?:bytes|content|data)|media[_-]?data)", str(key)):
                raise TransferBlocked(f"review input {label} contains a forbidden secret or sample-content field")
            _reject_sensitive_content(child, label)
    elif isinstance(value, list):
        for child in value:
            _reject_sensitive_content(child, label)
    elif isinstance(value, str):
        if len(value) > 65536 or re.search(r"(?i)\bBearer\s+|\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b", value):
            raise TransferBlocked(f"review input {label} contains a possible token or oversized sample-content value")
        if re.search(r"[A-Za-z0-9+/]{1024,}={0,2}", value):
            raise TransferBlocked(f"review input {label} contains a base64-like sample payload")


def prepare_bundle(
    *,
    input_directory: Path,
    repository_root: Path,
    bundle_id: str,
    workflow_run_id: str,
    commit_sha: str,
    actor: str,
    environment: str,
) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", bundle_id):
        raise TransferBlocked("review bundle id is missing or malformed")
    if not workflow_run_id.isdigit():
        raise TransferBlocked("workflow run id is missing or malformed")
    if not re.fullmatch(r"[0-9a-fA-F]{40,64}", commit_sha):
        raise TransferBlocked("workflow commit SHA is missing or malformed")
    if not actor.strip():
        raise TransferBlocked("workflow actor identity is missing")
    if environment != "stage0-manual-review":
        raise TransferBlocked("review evidence must run inside the protected stage0-manual-review environment")

    root = repository_root.resolve(strict=True)
    try:
        input_metadata = input_directory.lstat()
    except OSError as error:
        raise TransferBlocked(f"pre-provisioned review input directory is unavailable: {error}") from error
    if stat.S_ISLNK(input_metadata.st_mode) or getattr(input_metadata, "st_file_attributes", 0) & 0x400:
        raise TransferBlocked("pre-provisioned review input directory cannot be a symlink or reparse point")
    source = input_directory.resolve(strict=True)
    files = _walk_json_inputs(source)
    stage0 = root / "target" / "stage0"
    for directory in (root / "target", stage0):
        if directory.exists():
            metadata = directory.lstat()
            if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
                raise TransferBlocked("target/stage0 output path cannot contain a symlink or reparse point")
            if directory.resolve(strict=True) != directory:
                raise TransferBlocked("target/stage0 output path is not canonical")
        else:
            directory.mkdir()
    evidence_destination = stage0 / "reviewed-evidence"
    if evidence_destination.exists():
        metadata = evidence_destination.lstat()
        if stat.S_ISLNK(metadata.st_mode) or getattr(metadata, "st_file_attributes", 0) & 0x400:
            raise TransferBlocked("target/stage0/reviewed-evidence cannot be a symlink or reparse point")
        if evidence_destination.resolve(strict=True) != evidence_destination:
            raise TransferBlocked("target/stage0/reviewed-evidence is not a canonical output directory")
    else:
        evidence_destination.mkdir()
    bundle_destination = evidence_destination / bundle_id
    attestation_path = stage0 / "reviewed-evidence-attestation.json"
    if bundle_destination.exists() or attestation_path.exists():
        raise TransferBlocked("reviewed evidence output already exists; refusing to overwrite same-run state")
    bundle_destination.mkdir(parents=True, exist_ok=False)

    attested_files = []
    try:
        for _source_path, relative, data, digest in files:
            destination = bundle_destination / relative
            with destination.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            target_relative = destination.relative_to(root).as_posix()
            attested_files.append({"path": target_relative, "sha256": digest})
        attestation = {
            "schema": "fluxform.stage0.reviewed-evidence-ci-attestation.v1",
            "bundle_id": bundle_id,
            "workflow_run_id": workflow_run_id,
            "commit_sha": commit_sha.lower(),
            "actor": actor,
            "environment": environment,
            "closure_digest": closure_digest(attested_files),
            "files": sorted(attested_files, key=lambda item: item["path"]),
        }
        with attestation_path.open("xb") as output:
            output.write((json.dumps(attestation, indent=2, sort_keys=True) + "\n").encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
    except OSError as error:
        raise TransferBlocked(f"could not stage the reviewed bundle under target/stage0: {error}") from error
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with Path(output_path).open("a", encoding="utf-8", newline="\n") as output:
            output.write(f"bundle_id={bundle_id}\n")
    print(f"reviewed evidence staged for run {workflow_run_id}/{commit_sha}; {len(attested_files)} JSON files; no media or tokens")
    return attestation_path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--commit-sha", required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--environment", required=True)
    args = parser.parse_args()
    try:
        prepare_bundle(
            input_directory=args.input,
            repository_root=args.repo_root,
            bundle_id=args.bundle_id,
            workflow_run_id=args.run_id,
            commit_sha=args.commit_sha,
            actor=args.actor,
            environment=args.environment,
        )
    except (OSError, TransferBlocked) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 10
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
