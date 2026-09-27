#!/usr/bin/env python3
"""Fail-closed validation for the reviewed, per-row Stage 0 evidence bundle."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path, PurePosixPath

LABELS = [
    "Protocol/schema determinism",
    "Windows FFmpeg profile and license record",
    "macOS x86_64 FFmpeg profile and license record",
    "macOS aarch64 FFmpeg profile and license record",
    "Linux x86_64 FFmpeg profile and license record",
    "Exact approved/deferred capability matrix and product-owner approval",
    "Every enabled edge and rejection sample executed against all four approved native profiles",
    "Atomic reject/rename/replace, injected replacement failures, and crash recovery on each supported local filesystem",
    "Linux filesystem sandbox denial",
    "Linux OS network denial, distinct from FFmpeg protocol-policy denial",
    "Linux cgroup v2 birth placement, aggregate process/memory/CPU containment, and kill",
    "Streaming upload, reservation expansion, and early body termination",
    "Capability authorization on every concrete endpoint, Origin enforcement, and trusted-proxy IP provenance",
    "SSE reconnect, replay, resync snapshot, and expiry",
    "Real positive and negative fail-closed public-server startup",
    "Windows installed-app window, repeated-launch, close, DPI, and multi-monitor behavior",
    "Native Intel and Apple Silicon installed-app macOS window behavior",
    "Linux X11 installed-AppImage window behavior",
    "Linux Wayland installed-AppImage behavior and explicit degraded capability",
    "Windows offline WebView2 installation and first launch",
    "Signed/notarized disconnected macOS installation and first launch on both architectures",
    "Linux disconnected AppImage first launch",
    "Approved FFmpeg/FFprobe sidecar hashes and offline fixed `-version` execution per platform",
]

KINDS = [
    "protocol-contract",
    "windows-ffmpeg-profile",
    "macos-x86_64-ffmpeg-profile",
    "macos-aarch64-ffmpeg-profile",
    "linux-x86_64-ffmpeg-profile",
    "approved-capability-matrix",
    "native-sample-aggregate",
    "native-atomic-output",
    "linux-filesystem-sandbox",
    "linux-network-sandbox",
    "linux-cgroup-containment",
    "streaming-upload-reservation",
    "capability-auth-origin-proxy",
    "sse-reconnect-replay",
    "linux-public-server-startup",
    "windows-installed-window",
    "macos-installed-window",
    "linux-x11-installed-window",
    "linux-wayland-installed-window",
    "windows-offline-webview2-install",
    "macos-offline-install",
    "linux-offline-appimage-install",
    "approved-ffmpeg-sidecars",
]

PLATFORMS = [
    "windows-x86_64",
    "windows-x86_64",
    "macos-x86_64",
    "macos-aarch64",
    "linux-x86_64",
    "product-scope",
    "native-cross-platform",
    "native-filesystem-matrix",
    "linux-native",
    "linux-native",
    "linux-cgroupv2-delegated",
    "server-integration",
    "server-integration",
    "server-integration",
    "linux-cgroupv2-delegated",
    "windows-x86_64",
    "macos-native",
    "linux-x11",
    "linux-wayland",
    "windows-offline-vm",
    "macos-offline-native",
    "linux-offline-appimage",
    "four-native-platforms",
]

REQUIRED_FIELDS = [
    ["command", "passed_tests", "failed_tests", "contract_sha256"],
    *[["target_triple", "profile_id", "archive_sha256", "ffmpeg_sha256", "ffprobe_sha256", "license_sha256", "distribution_approval"] for _ in range(4)],
    ["approval_text", "enabled_edge_count", "deferred_edge_count", "matrix_sha256"],
    ["target_profiles", "enabled_edge_results", "rejection_results", "aggregate_sha256"],
    ["filesystem_set", "replace_rejection", "injected_failures", "crash_recovery"],
    ["native_platform", "filesystem_denials", "result_sha256"],
    ["native_platform", "connect_denials", "ffmpeg_policy_distinctness"],
    ["native_platform", "controllers", "birth_placement", "cpu_limits", "memory_limits", "pids_limits", "kill_result"],
    ["stream_sha256", "reservation_expansion", "early_body_termination"],
    ["endpoint_matrix_sha256", "origin_results", "trusted_proxy_results"],
    ["reconnect", "replay", "resync_snapshot", "expiry"],
    ["native_runner", "positive_startup", "negative_startup", "listener_state"],
    ["installed_app_sha256", "repeated_launch", "close_behavior", "transparency", "click_through", "drag_drop", "dpi", "multi_monitor", "idle_cpu_gpu"],
    ["installed_app_sha256", "architectures", "visual_behavior", "input_behavior", "focus_behavior", "close_behavior", "dpi", "multi_monitor", "idle_cpu_gpu"],
    ["appimage_sha256", "display_server", "window_behavior", "input_behavior", "degraded_capability"],
    ["appimage_sha256", "display_server", "window_behavior", "degraded_capability"],
    ["installer_sha256", "network_state", "webview_runtime_precondition", "first_launch"],
    ["installer_sha256_intel", "installer_sha256_arm64", "network_state", "signature", "notarization", "first_launch"],
    ["appimage_sha256", "network_state", "first_launch"],
    ["windows_x86_64_sha256", "macos_x86_64_sha256", "macos_aarch64_sha256", "linux_x86_64_sha256", "version_execution"],
]

ROW_PATTERN = re.compile(
    r"^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*\*\*(PASS|FAIL|BLOCKED)\*\*\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|$"
)
MANIFEST_REFERENCE = re.compile(
    r"^Reviewed evidence manifest: `([^`]+)` SHA-256 `([0-9a-fA-F]{64})`$"
)


class EvidenceBlocked(Exception):
    pass


class ReportInvalid(Exception):
    pass


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_relative_path(raw: object) -> PurePosixPath:
    if not isinstance(raw, str) or not raw or "\\" in raw or "\x00" in raw:
        raise EvidenceBlocked("evidence path is not a normalized repository-relative POSIX path")
    path = PurePosixPath(raw)
    if path.is_absolute() or str(path) != raw or any(part in ("", ".", "..") for part in path.parts):
        raise EvidenceBlocked("evidence path is not a normalized repository-relative POSIX path")
    if re.match(r"^[A-Za-z]:", raw):
        raise EvidenceBlocked("absolute or drive-qualified evidence paths are forbidden")
    return path


def is_reparse_point(metadata: os.stat_result) -> bool:
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(attributes & reparse)


def safe_file(repo_root: Path, relative: PurePosixPath, label: str) -> Path:
    current = repo_root
    for component in relative.parts:
        current = current / component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise EvidenceBlocked(f"{label} is missing or unreadable: {relative}: {error}") from error
        if stat.S_ISLNK(metadata.st_mode) or is_reparse_point(metadata):
            raise EvidenceBlocked(f"{label} contains a symlink or reparse point: {relative}")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(repo_root)
    except (OSError, ValueError) as error:
        raise EvidenceBlocked(f"{label} escapes the repository root: {relative}") from error
    if not resolved.is_file():
        raise EvidenceBlocked(f"{label} is not a regular file: {relative}")
    return resolved


def parse_date(value: object, field: str) -> dt.date:
    if not isinstance(value, str):
        raise EvidenceBlocked(f"{field} is missing or malformed")
    try:
        return dt.date.fromisoformat(value)
    except ValueError as error:
        raise EvidenceBlocked(f"{field} is missing or malformed") from error


def reviewer_cell(value: str, row_id: int) -> tuple[str, str, str]:
    parts = [part.strip() for part in value.split(";", 2)]
    if len(parts) != 3 or not all(parts):
        raise EvidenceBlocked(f"evidence row {row_id} must identify platform, date, and reviewer")
    platform, report_date, identity = parts
    parse_date(report_date, f"evidence row {row_id} report date")
    if re.search(r"pending|unreviewed|placeholder|fixture|codex.*recorder", identity, re.I):
        raise EvidenceBlocked(f"evidence row {row_id} has no independent human review")
    return platform, report_date, identity


def parse_json(path: Path, label: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceBlocked(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceBlocked(f"{label} must be a JSON object")
    return value


def load_report(path: Path) -> tuple[str, list[tuple[int, str, str, str, str]], tuple[int, int, int]]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise ReportInvalid(f"cannot read gate report: {error}") from error
    rows = []
    for line in text.splitlines():
        match = ROW_PATTERN.match(line)
        if match:
            rows.append((int(match.group(1)), match.group(2).strip(), match.group(3), match.group(4).strip(), match.group(5).strip()))
    if len(rows) != 23:
        raise ReportInvalid(f"expected 23 uniquely numbered evidence rows, found {len(rows)}")
    if sorted(row[0] for row in rows) != list(range(1, 24)):
        raise ReportInvalid("report evidence rows must cover every number from 1 through 23 exactly once")
    for number, label, status, reviewer, details in rows:
        if label != LABELS[number - 1]:
            raise ReportInvalid(f"evidence row {number} label does not match the required Stage 0 evidence item")
        if not reviewer or not details:
            raise ReportInvalid(f"evidence row {number} has a blank reviewer or details cell")
        if status == "BLOCKED" and not re.search(r"blocked|not run|no .* exists|no .* available|not available|missing", details, re.I):
            raise ReportInvalid(f"blocked evidence row {number} does not explain its prerequisite")
    summary = re.search(r"\*\*Overall status: (PASS|FAIL|BLOCKED)\.\*\*\s*Current matrix:\s*\*\*(\d+) PASS,\s*(\d+) FAIL,\s*(\d+) BLOCKED\*\*", text)
    if not summary:
        raise ReportInvalid("gate report does not contain a canonical status summary")
    counts = tuple(sum(row[2] == status for row in rows) for status in ("PASS", "FAIL", "BLOCKED"))
    expected_overall = "FAIL" if counts[1] else "BLOCKED" if counts[2] else "PASS"
    if summary.group(1) != expected_overall or tuple(map(int, summary.groups()[1:])) != counts:
        raise ReportInvalid("gate report summary does not match its evidence rows")
    return expected_overall, rows, counts


def validate_manifest_references(rows: list[tuple[int, str, str, str, str]]) -> list[tuple[int, str, str, str, str, str, PurePosixPath]]:
    references = []
    manifest_keys: set[str] = set()
    for number, label, status, reviewer, details in rows:
        if status != "PASS":
            continue
        match = MANIFEST_REFERENCE.fullmatch(details)
        if not match:
            raise EvidenceBlocked(f"evidence row {number} requires a reviewed evidence manifest")
        relative = safe_relative_path(match.group(1))
        if len(relative.parts) != 5 or relative.parts[:3] != ("target", "stage0", "reviewed-evidence"):
            raise EvidenceBlocked(f"evidence row {number} manifest is outside target/stage0/reviewed-evidence")
        bundle_id = relative.parts[3]
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", bundle_id):
            raise EvidenceBlocked(f"evidence row {number} has an invalid reviewed bundle id")
        key = os.path.normcase(relative.as_posix())
        if key in manifest_keys:
            raise EvidenceBlocked("a manifest is reused across report rows")
        if relative.parts[4] != f"row-{number:02}.manifest.json":
            raise EvidenceBlocked(f"evidence row {number} manifest filename is not bound to its row id")
        manifest_keys.add(key)
        references.append((number, label, reviewer, match.group(2).lower(), bundle_id, key, relative))
    return references


def validate_bundle(repo_root: Path, references: list[tuple[int, str, str, str, str, str, PurePosixPath]]) -> None:
    loaded = []
    payload_keys: set[str] = set()
    payload_digests: set[str] = set()
    manifests_by_reference: set[str] = set()

    # Read all distinct manifests first so reuse is rejected before row-specific checks.
    for number, label, reviewer, expected_manifest_sha, bundle_id, key, manifest_relative in references:
        manifest_path = safe_file(repo_root, manifest_relative, f"evidence row {number} manifest")
        actual_manifest_sha = sha256(manifest_path)
        if actual_manifest_sha != expected_manifest_sha:
            raise EvidenceBlocked(f"evidence row {number} manifest SHA-256 does not match the report")
        manifest = parse_json(manifest_path, f"evidence row {number} manifest")
        payload = manifest.get("payload")
        if not isinstance(payload, dict):
            raise EvidenceBlocked(f"evidence row {number} manifest has no payload object")
        raw_payload_path = payload.get("path")
        if not isinstance(raw_payload_path, str) or not raw_payload_path.startswith("target/stage0/reviewed-evidence/"):
            raise EvidenceBlocked(f"evidence row {number} evidence payload escaped its reviewed bundle")
        try:
            payload_relative = safe_relative_path(raw_payload_path)
        except EvidenceBlocked as error:
            raise EvidenceBlocked(f"evidence row {number} evidence payload escaped its reviewed bundle: {error}") from error
        payload_key = os.path.normcase(payload_relative.as_posix())
        payload_sha = payload.get("sha256")
        if not isinstance(payload_sha, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", payload_sha):
            raise EvidenceBlocked(f"evidence row {number} payload SHA-256 is missing or malformed")
        if payload_key in payload_keys or payload_sha.lower() in payload_digests:
            raise EvidenceBlocked("a payload is reused across report rows")
        payload_keys.add(payload_key)
        payload_digests.add(payload_sha.lower())
        manifests_by_reference.add(key)
        loaded.append((number, label, reviewer, bundle_id, manifest_relative, manifest, payload_relative, payload_sha.lower()))

    for number, label, report_reviewer, bundle_id, manifest_relative, manifest, payload_relative, payload_sha in loaded:
        kind = KINDS[number - 1]
        schema = f"fluxform.stage0.{kind}.v1"
        expected_manifest = {
            "schema": "fluxform.stage0.reviewed-row-manifest.v1",
            "bundle_id": bundle_id,
            "row_id": number,
            "label": label,
            "status": "PASS",
            "evidence_kind": kind,
            "platform": PLATFORMS[number - 1],
            "review_state": "reviewed",
        }
        if manifest.get("evidence_kind") != kind:
            raise EvidenceBlocked(f"evidence row {number} evidence kind does not match required row")
        for key, expected in expected_manifest.items():
            if manifest.get(key) != expected:
                raise EvidenceBlocked(f"evidence row {number} manifest {key} does not bind the exact required row")
        report_platform, report_date, report_identity = reviewer_cell(report_reviewer, number)
        if manifest.get("platform") != report_platform:
            raise EvidenceBlocked(f"evidence row {number} manifest platform does not match the report")
        if report_platform != PLATFORMS[number - 1]:
            raise EvidenceBlocked(f"evidence row {number} platform does not match the required evidence kind")
        if manifest.get("date") != report_date:
            raise EvidenceBlocked(f"evidence row {number} manifest date does not match the report")
        reviewer = manifest.get("reviewer")
        if not isinstance(reviewer, dict) or reviewer.get("identity") != report_identity:
            raise EvidenceBlocked(f"evidence row {number} reviewer identity does not match the report")
        reviewed_at = reviewer.get("reviewed_at")
        if not isinstance(reviewed_at, str):
            raise EvidenceBlocked(f"evidence row {number} has no reviewed timestamp")
        try:
            parsed_reviewed_at = dt.datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise EvidenceBlocked(f"evidence row {number} reviewed timestamp is malformed") from error
        if parsed_reviewed_at.tzinfo is None or parsed_reviewed_at.date().isoformat() != report_date:
            raise EvidenceBlocked(f"evidence row {number} reviewed timestamp is not on the reported review date")

        expected_parent = PurePosixPath("target/stage0/reviewed-evidence", bundle_id)
        if payload_relative.parent != expected_parent:
            raise EvidenceBlocked(f"evidence row {number} evidence payload escaped its reviewed bundle")
        if payload_relative.name != f"row-{number:02}.payload.json":
            raise EvidenceBlocked(f"evidence row {number} payload filename is not bound to its row id")
        manifest_parent = PurePosixPath(*manifest_relative.parts[:-1])
        if manifest_parent != expected_parent:
            raise EvidenceBlocked(f"evidence row {number} manifest is outside its reviewed bundle")

        payload_metadata = manifest.get("payload")
        if payload_metadata.get("type") != "application/json" or payload_metadata.get("schema") != schema:
            raise EvidenceBlocked(f"evidence row {number} payload type or schema does not match its evidence kind")
        payload_path = safe_file(repo_root, payload_relative, f"evidence row {number} payload")
        if sha256(payload_path) != payload_sha:
            raise EvidenceBlocked(f"evidence row {number} payload SHA-256 does not match its manifest")
        payload_document = parse_json(payload_path, f"evidence row {number} payload")
        required_payload = {
            "schema": schema,
            "row_id": number,
            "label": label,
            "evidence_kind": kind,
            "result": "PASS",
        }
        for key, expected in required_payload.items():
            if payload_document.get(key) != expected:
                raise EvidenceBlocked(f"evidence row {number} payload {key} does not match its manifest")
        for field in REQUIRED_FIELDS[number - 1]:
            value = payload_document.get(field)
            if not isinstance(value, (str, int, bool, list, dict)) or value == "" or value is None or value == [] or value == {}:
                raise EvidenceBlocked(f"evidence row {number} payload is missing required field {field}")
            if field.endswith("_sha256") and (not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value)):
                raise EvidenceBlocked(f"evidence row {number} payload field {field} is not a SHA-256")

        # Offline installation and human-observed desktop behavior need actual manual evidence,
        # not a generic build/lock artifact with a plausible hash.
        if number in (20, 21, 22):
            if payload_document.get("network_state") != "disconnected" or payload_document.get("first_launch") != "PASS":
                raise EvidenceBlocked(f"evidence row {number} requires a disconnected first-launch observation")
        if number == 20 and "runtime" not in str(payload_document.get("webview_runtime_precondition", "")).lower():
            raise EvidenceBlocked("evidence row 20 must record the offline WebView2 runtime precondition")
        if number == 21 and (payload_document.get("signature") != "valid" or payload_document.get("notarization") != "accepted"):
            raise EvidenceBlocked("evidence row 21 must record valid signature and accepted notarization")
        if number == 16 and payload_document.get("click_through") in ("", "not observed", "unknown"):
            raise EvidenceBlocked("evidence row 16 requires a human-observed click-through result")


def validate(repo_root: Path, report_path: Path) -> None:
    overall, rows, counts = load_report(report_path)
    references = validate_manifest_references(rows)
    validate_bundle(repo_root, references)
    if counts[1]:
        raise ReportInvalid(f"{counts[1]} gate report row(s) are FAIL")
    if counts[2]:
        raise EvidenceBlocked(f"{counts[2]} gate report row(s) are BLOCKED")
    if counts[0] != 23 or overall != "PASS":
        raise ReportInvalid("every one of the 23 gate report rows must be PASS")
    print("PASS: all 23 report rows have unique, reviewed, row-bound evidence manifests and payloads")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    try:
        repo_root = args.repo_root.resolve(strict=True)
        report_path = args.report.resolve(strict=True)
        validate(repo_root, report_path)
    except EvidenceBlocked as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 10
    except ReportInvalid as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    except (OSError, ValueError) as error:
        print(f"BLOCKED: report path or repository root is unavailable: {error}", file=sys.stderr)
        return 10
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
