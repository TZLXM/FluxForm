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
import subprocess
import sys
import tomllib
from pathlib import Path, PurePosixPath

from stage0_json import loads_unique_json as _loads_unique_json
from stage0_json import read_pinned_bytes as _read_pinned_bytes
from stage0_json import read_pinned_json as _read_pinned_json

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

PROFILE_TARGETS = {
    2: ("windows-x86_64", "x86_64-pc-windows-msvc", "windows", "x86_64"),
    3: ("macos-x86_64", "x86_64-apple-darwin", "macos", "x86_64"),
    4: ("macos-aarch64", "aarch64-apple-darwin", "macos", "aarch64"),
    5: ("linux-x86_64", "x86_64-unknown-linux-gnu", "linux", "x86_64"),
}
SAMPLE_TARGETS = {
    "windows-x86_64": ("x86_64-pc-windows-msvc", "windows", "x86_64"),
    "macos-x86_64": ("x86_64-apple-darwin", "macos", "x86_64"),
    "macos-aarch64": ("aarch64-apple-darwin", "macos", "aarch64"),
    "linux-x86_64": ("x86_64-unknown-linux-gnu", "linux", "x86_64"),
}
ROW_RESULT_SCHEMAS = {
    1: {"primary": "fluxform.stage0.protocol-contract-run.v1"},
    2: {"probe-report": "rust.fluxform_ffmpeg_profile.ProbeReport.v1"},
    3: {"probe-report": "rust.fluxform_ffmpeg_profile.ProbeReport.v1"},
    4: {"probe-report": "rust.fluxform_ffmpeg_profile.ProbeReport.v1"},
    5: {"probe-report": "rust.fluxform_ffmpeg_profile.ProbeReport.v1"},
    6: {"approval-record": "fluxform.stage0.product-approval.v1"},
    7: {
        "aggregate-report": "fluxform.sample-aggregate.v1",
        **{f"profile-report-{target}": "rust.fluxform_ffmpeg_profile.ProbeReport.v1" for target in SAMPLE_TARGETS},
        **{f"sample-report-{target}": "fluxform.sample-run.v1" for target in SAMPLE_TARGETS},
        **{f"provenance-{target}": "fluxform.native-sample-artifact.v1" for target in SAMPLE_TARGETS},
    },
    16: {"window-result": "rust.fluxform_desktop_probe.WindowProbeResult.v1"},
}

PROBE_REPORT_FIELDS = {
    "profile_id", "profile_digest", "distribution_gate_status", "artifact_id", "artifact_status",
    "archive_format", "artifact_uri", "artifact_sha256", "artifact_size_bytes", "target_triple",
    "ffmpeg_sha256", "ffmpeg_size_bytes", "ffprobe_sha256", "ffprobe_size_bytes", "version",
    "ffprobe_version", "source_revision", "source_offer_url", "source_revision_reported_by_binary",
    "build_configuration", "license_declaration", "license_text_path", "license_text_sha256",
    "license_text_size_bytes", "approval_record_id", "approval_date", "protocols", "demuxers",
    "muxers", "decoders", "encoders",
}
SAMPLE_REPORT_FIELDS = {
    "schema", "status", "evidence_input_digest", "manifest_digest", "sample_catalog_digest", "git_commit",
    "runner_os", "runner_arch", "profile_id", "target_profile_id", "target_triple", "artifact_id",
    "profile_digest", "ffmpeg_sha256", "ffprobe_sha256", "blockers", "results",
}
SAMPLE_RESULT_FIELDS = {
    "edge_id", "edge_spec_digest", "sample_id", "sample_sha256", "expected_outcome", "expected_error_code",
    "status", "actual_error_code", "diagnostic", "ffprobe_arguments", "ffmpeg_arguments", "ffmpeg_invoked",
    "output_expectations", "output_expectations_digest", "observed_input", "observed_output",
}
OUTPUT_EXPECTATION_FIELDS = {
    "container", "codecs", "stream_topology", "width", "height", "max_width", "max_height",
    "expected_duration_ms", "duration_tolerance_ms", "max_duration_ms", "alpha_policy", "orientation_policy",
    "metadata_policy",
}
OBSERVED_MEDIA_FIELDS = {
    "format_name", "codecs", "stream_topology", "width", "height", "duration_ms", "alpha_present",
    "orientation_present", "metadata_keys", "frame_count",
}
PROVENANCE_FIELDS = {
    "schema", "artifact_name", "target_profile_id", "target_triple", "runner_os", "runner_arch",
    "git_commit", "evidence_input_digest", "workflow_run_id", "workflow_job_id",
    "ffmpeg_profile_report_sha256", "sample_report_sha256", "manual_reviewer", "transfer_sha256",
}
WINDOW_RESULT_FIELDS = {
    "probe_mode", "os", "os_version", "display_server", "installed_artifact_sha256",
    "installed_executable_sha256", "install_identity", "provenance_verified", "provenance_error",
    "installed_launch_path", "native_hit_region_supported", "input_hit_region_status", "network_disconnected",
    "first_launch_succeeded", "transparent_pixels_visible", "transparent_pixels_click_through",
    "frameless_drag_works", "file_drop_works", "outside_orb_drop_reached_background_target",
    "outside_orb_drop_reached_fluxform", "focus_recovery_works", "keyboard_input_works",
    "repeated_launch_created_second_window", "repeated_launch_backend_process_count", "single_window_close_works",
    "last_window_close_works", "dpi_change_works", "multi_monitor_move_works", "idle_cpu_percent",
    "idle_gpu_percent", "notes", "passed", "webview_helper_process_count",
}

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


def loads_unique_json(data: bytes, label: str):
    try:
        return _loads_unique_json(data, label)
    except ValueError as error:
        raise EvidenceBlocked(str(error)) from error


def read_pinned_json(path: Path, label: str, repository_root: Path | None = None):
    root = repository_root or path.parent
    try:
        return _read_pinned_json(path, label, root)
    except (OSError, ValueError) as error:
        raise EvidenceBlocked(f"{label} could not be read safely: {error}") from error


def parse_json(path: Path, label: str) -> dict:
    value, _digest, _identity = read_pinned_json(path, label, path.parent)
    if not isinstance(value, dict):
        raise EvidenceBlocked(f"{label} must be a JSON object")
    return value


def load_report(path: Path, repo_root: Path) -> tuple[str, list[tuple[int, str, str, str, str]], tuple[int, int, int]]:
    try:
        data, _digest, _identity = _read_pinned_bytes(path, "gate report", repo_root)
        text = data.decode("utf-8", errors="strict")
    except (OSError, UnicodeError, ValueError) as error:
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
        if status == "BLOCKED" and not re.search(r"blocked|not run|not .* (?:verified|performed|measured|available)|no .* exists|no .* available|no .* (?:collected|recorded|observed|claim|evidence|result)|not available|missing|unknown|false", details, re.I):
            raise ReportInvalid(f"blocked evidence row {number} does not explain its prerequisite")
    summary = re.search(r"\*\*Overall status: (PASS|FAIL|BLOCKED)\.\*\*\s*Current matrix:\s*\*\*(\d+) PASS,\s*(\d+) FAIL,\s*(\d+) BLOCKED\*\*", text)
    if not summary:
        raise ReportInvalid("gate report does not contain a canonical status summary")
    counts = tuple(sum(row[2] == status for row in rows) for status in ("PASS", "FAIL", "BLOCKED"))
    expected_overall = "FAIL" if counts[1] else "BLOCKED" if counts[2] else "PASS"
    if summary.group(1) != expected_overall or tuple(map(int, summary.groups()[1:])) != counts:
        raise ReportInvalid("gate report summary does not match its evidence rows")
    return expected_overall, rows, counts


def exact_keys(value: object, keys: set[str], label: str) -> dict:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceBlocked(f"{label} does not match its exact documented schema")
    return value


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _tracked_identity(repo_root: Path, path_text: str) -> dict[str, str]:
    relative = safe_relative_path(path_text)
    path = safe_file(repo_root, relative, "tracked approval artifact")
    try:
        _data, digest, _identity = _read_pinned_bytes(path, "tracked approval artifact", repo_root)
    except (OSError, ValueError) as error:
        raise EvidenceBlocked(f"tracked approval artifact could not be read safely: {error}") from error
    return {"path": path_text, "sha256": digest}


def _profile_config(repo_root: Path) -> dict:
    path = repo_root / "config/ffmpeg-profile.toml"
    try:
        data, _digest, _identity = _read_pinned_bytes(path, "FFmpeg profile configuration", repo_root)
        return tomllib.loads(data.decode("utf-8"))
    except (OSError, UnicodeError, ValueError, tomllib.TOMLDecodeError) as error:
        raise EvidenceBlocked(f"FFmpeg profile configuration is unavailable or invalid: {error}") from error


def _validate_probe_report(repo_root: Path, row: int, report: object) -> None:
    report = exact_keys(report, PROBE_REPORT_FIELDS, f"evidence row {row} ProbeReport")
    target_id, triple, _os_name, _arch = PROFILE_TARGETS[row]
    config = _profile_config(repo_root)
    if report["target_triple"] != triple or report["profile_id"] != config.get("profile_id"):
        raise EvidenceBlocked(f"evidence row {row} ProbeReport target/profile identity does not match configuration")
    artifacts = config.get("artifacts")
    if not isinstance(artifacts, list):
        raise EvidenceBlocked("FFmpeg profile has no immutable artifact table")
    expected = next((item for item in artifacts if item.get("target_triple") == triple), None)
    if expected is None:
        raise EvidenceBlocked(f"evidence row {row} has no immutable configured target artifact")
    mapping = {
        "artifact_id": "artifact_id",
        "artifact_status": "status",
        "archive_format": "archive_format",
        "artifact_uri": "artifact_uri",
        "artifact_sha256": "artifact_sha256",
        "artifact_size_bytes": "artifact_size_bytes",
        "ffmpeg_sha256": "ffmpeg_sha256",
        "ffmpeg_size_bytes": "ffmpeg_size_bytes",
        "ffprobe_sha256": "ffprobe_sha256",
        "ffprobe_size_bytes": "ffprobe_size_bytes",
        "license_text_path": "license_text_path",
        "license_text_sha256": "license_text_sha256",
        "license_text_size_bytes": "license_text_size_bytes",
        "source_revision": "source_revision",
        "source_offer_url": "source_offer_url",
        "approval_record_id": "approval_record_id",
        "approval_date": "approval_date",
    }
    for report_field, config_field in mapping.items():
        if report[report_field] != expected.get(config_field):
            raise EvidenceBlocked(f"evidence row {row} ProbeReport {report_field} differs from immutable profile identity")
    if report["artifact_status"] != "approved" or report["distribution_gate_status"] != "approved":
        raise EvidenceBlocked(f"evidence row {row} FFmpeg profile is candidate-only or distribution approval is not approved")
    gate = config.get("distribution_gate", {})
    if gate.get("status") != "approved" or not gate.get("owner_approval_record_id") or not gate.get("legal_approval_record_id"):
        raise EvidenceBlocked(f"evidence row {row} checked-in profile lacks owner/legal distribution approval")
    if not report["approval_record_id"] or not report["approval_date"]:
        raise EvidenceBlocked(f"evidence row {row} ProbeReport has no immutable approval record/date")


def validate_semantics(repo_root: Path, row: int, result: object, artifact_identities: object, role_documents: dict[str, dict] | None = None, attestation: dict | None = None) -> None:
    kind = KINDS[row - 1]
    if row not in ROW_RESULT_SCHEMAS:
        raise EvidenceBlocked(f"evidence row {row} ({kind}) has no authoritative machine-readable source schema; it remains BLOCKED")

    if row == 1:
        keys = {"schema", "row_id", "label", "evidence_kind", "status", "command", "exit_code", "passed_tests", "failed_tests", "stdout_summary", "compatibility_digest", "compatibility_file_sha256", "artifact_identities"}
        value = exact_keys(result, keys, "protocol contract command result")
        if value["schema"] != ROW_RESULT_SCHEMAS[1]["primary"] or value["row_id"] != 1 or value["label"] != LABELS[0] or value["evidence_kind"] != kind or value["status"] != "PASS":
            raise EvidenceBlocked("protocol contract raw result does not bind row 1")
        if value["command"] != "cargo test --locked --offline -p fluxform-protocol --test contracts":
            raise EvidenceBlocked("protocol raw result command does not match the required contract suite")
        if type(value["exit_code"]) is not int or value["exit_code"] != 0:
            raise EvidenceBlocked("protocol raw result exit_code is not zero")
        if type(value["passed_tests"]) is not int or value["passed_tests"] <= 0:
            raise EvidenceBlocked("protocol raw result passed_tests must be positive")
        if type(value["failed_tests"]) is not int or value["failed_tests"] != 0:
            raise EvidenceBlocked("protocol raw result failed_tests must be zero")
        match = re.fullmatch(r"test result: ok\. (\d+) passed; (\d+) failed", value["stdout_summary"] if isinstance(value["stdout_summary"], str) else "")
        if not match or (int(match.group(1)), int(match.group(2))) != (value["passed_tests"], value["failed_tests"]):
            raise EvidenceBlocked("protocol command output summary contradicts its test counts")
        compatibility_path = "contracts/v1/compatibility.sha256"
        relative = safe_relative_path(compatibility_path)
        path = safe_file(repo_root, relative, "protocol compatibility digest")
        data, digest, _identity = _read_pinned_bytes(path, "protocol compatibility digest", repo_root)
        expected_digest = data.decode("ascii").strip().lower()
        expected_artifacts = {"compatibility-file": {"path": compatibility_path, "sha256": digest}}
        if artifact_identities != expected_artifacts or value["artifact_identities"] != expected_artifacts:
            raise EvidenceBlocked("protocol raw result does not bind the tracked compatibility digest file")
        if value["compatibility_digest"] != expected_digest or value["compatibility_file_sha256"] != digest:
            raise EvidenceBlocked("protocol compatibility digest differs from the tracked contract file")
        return

    if row in PROFILE_TARGETS:
        _validate_probe_report(repo_root, row, result)
        return

    if row == 6:
        keys = {"schema", "row_id", "label", "evidence_kind", "status", "approval_text", "enabled_edge_count", "deferred_edge_count", "matrix_sha256", "approval_record_sha256", "artifact_identities"}
        value = exact_keys(result, keys, "product approval result")
        if value["schema"] != ROW_RESULT_SCHEMAS[6]["approval-record"] or value["row_id"] != 6 or value["label"] != LABELS[5] or value["evidence_kind"] != KINDS[5] or value["status"] != "PASS":
            raise EvidenceBlocked("product approval raw result does not bind row 6")
        adr = "docs/architecture/adr/0002-v1-capability-matrix.md"
        approval = ".superpowers/sdd/2026-09-25-fluxform-stage-0-feasibility/task-5-product-approval.md"
        adr_identity = _tracked_identity(repo_root, adr)
        approval_identity = _tracked_identity(repo_root, approval)
        expected_artifacts = {"capability-matrix-adr": adr_identity, "product-approval-record": approval_identity}
        if artifact_identities != expected_artifacts or value["artifact_identities"] != expected_artifacts:
            raise EvidenceBlocked("product approval does not bind the exact tracked ADR and approval record")
        adr_data, _adr_sha, _ = _read_pinned_bytes(repo_root / adr, "capability matrix ADR", repo_root)
        approval_data, _approval_sha, _ = _read_pinned_bytes(repo_root / approval, "product approval record", repo_root)
        adr_text = adr_data.decode("utf-8")
        approval_text = approval_data.decode("utf-8")
        matrix = re.search(r"<!-- matrix-json-v1:begin -->\s*```json\s*(.*?)\s*```", adr_text, re.S)
        if not matrix:
            raise EvidenceBlocked("tracked product ADR has no canonical matrix JSON block")
        matrix_bytes = matrix.group(1).encode("utf-8")
        matrix_value = loads_unique_json(matrix_bytes, "tracked capability matrix")
        if not isinstance(matrix_value, list) or len(matrix_value) != 129:
            raise EvidenceBlocked("tracked product matrix is not the exact 129-row record")
        enabled = sum(isinstance(item, dict) and item.get("status") == "enabled" for item in matrix_value)
        deferred = sum(isinstance(item, dict) and item.get("status") == "deferred" for item in matrix_value)
        if (enabled, deferred) != (3, 126):
            raise EvidenceBlocked("tracked product matrix does not contain exactly 3 enabled and 126 deferred edges")
        if "批准" not in adr_text or "批准" not in approval_text or value["approval_text"] != "批准":
            raise EvidenceBlocked("tracked approval decision is absent or does not match the exact response")
        if type(value["enabled_edge_count"]) is not int or value["enabled_edge_count"] != enabled or type(value["deferred_edge_count"]) is not int or value["deferred_edge_count"] != deferred:
            raise EvidenceBlocked("product approval counts do not match the tracked matrix")
        if value["matrix_sha256"] != sha256_bytes(matrix_bytes) or value["approval_record_sha256"] != approval_identity["sha256"]:
            raise EvidenceBlocked("product approval hashes do not match tracked matrix and approval record")
        return

    if row == 7:
        if role_documents is None or attestation is None:
            raise EvidenceBlocked("native sample aggregate requires its complete raw result closure and same-run attestation")
        aggregate = exact_keys(role_documents.get("aggregate-report"), {"schema", "status", "evidence_input_digest", "targets"}, "native sample aggregate")
        if aggregate["schema"] != "fluxform.sample-aggregate.v1" or aggregate["status"] != "passed" or not re.fullmatch(r"[0-9a-f]{64}", str(aggregate["evidence_input_digest"])):
            raise EvidenceBlocked("native collector aggregate is blocked, stale, or has an unknown schema")
        targets = aggregate["targets"]
        if not isinstance(targets, list) or {item.get("target_profile_id") for item in targets if isinstance(item, dict)} != set(SAMPLE_TARGETS) or len(targets) != 4:
            raise EvidenceBlocked("native collector aggregate does not contain exactly the four native targets")
        if attestation.get("commit_sha") != os.environ.get("GITHUB_SHA"):
            raise EvidenceBlocked("native aggregate provenance does not match the reviewed workflow commit")
        for target_id, (triple, runner_os, runner_arch) in SAMPLE_TARGETS.items():
            profile = exact_keys(role_documents.get(f"profile-report-{target_id}"), PROBE_REPORT_FIELDS, f"{target_id} ProbeReport")
            sample = exact_keys(role_documents.get(f"sample-report-{target_id}"), SAMPLE_REPORT_FIELDS, f"{target_id} sample report")
            provenance = exact_keys(role_documents.get(f"provenance-{target_id}"), PROVENANCE_FIELDS, f"{target_id} native provenance")
            _validate_probe_report(repo_root, {"windows-x86_64": 2, "macos-x86_64": 3, "macos-aarch64": 4, "linux-x86_64": 5}[target_id], profile)
            if sample["schema"] != "fluxform.sample-run.v1" or sample["status"] != "passed" or sample["blockers"] != [] or not sample["results"]:
                raise EvidenceBlocked(f"{target_id} sample result has no passing current result set")
            if len(sample["results"]) != 9:
                raise EvidenceBlocked(f"{target_id} sample result does not contain the complete nine-case matrix")
            case_ids = set()
            for sample_result in sample["results"]:
                sample_result = exact_keys(sample_result, SAMPLE_RESULT_FIELDS, f"{target_id} sample case")
                if sample_result["status"] != "passed" or type(sample_result["ffmpeg_invoked"]) is not bool:
                    raise EvidenceBlocked(f"{target_id} sample result contains a non-passing edge/rejection result")
                case_id = (sample_result["edge_id"], sample_result["sample_id"], sample_result["expected_outcome"])
                if case_id in case_ids:
                    raise EvidenceBlocked(f"{target_id} sample result repeats an edge/sample case")
                case_ids.add(case_id)
                exact_keys(sample_result["output_expectations"], OUTPUT_EXPECTATION_FIELDS, f"{target_id} output expectations")
                for observed_name in ("observed_input", "observed_output"):
                    observed = sample_result[observed_name]
                    if observed is not None:
                        observed = exact_keys(observed, OBSERVED_MEDIA_FIELDS, f"{target_id} {observed_name}")
                        if type(observed["alpha_present"]) is not bool or type(observed["orientation_present"]) is not bool:
                            raise EvidenceBlocked(f"{target_id} observed media has malformed boolean facts")
            if provenance["schema"] != "fluxform.native-sample-artifact.v1" or provenance["workflow_run_id"] != attestation["workflow_run_id"] or provenance["git_commit"] != attestation["commit_sha"]:
                raise EvidenceBlocked(f"{target_id} native provenance is not bound to this workflow run and commit")
            if not provenance["workflow_job_id"] or not all(re.fullmatch(r"[0-9a-f]{64}", str(provenance[field])) for field in ("ffmpeg_profile_report_sha256", "sample_report_sha256")):
                raise EvidenceBlocked(f"{target_id} native provenance has a missing job identity or report hash")
            if (sample["target_triple"], sample["target_profile_id"], sample["runner_os"], sample["runner_arch"]) != (triple, target_id, runner_os, runner_arch):
                raise EvidenceBlocked(f"{target_id} sample result target identity does not match its native platform")
            if sample["evidence_input_digest"] != aggregate["evidence_input_digest"] or provenance["evidence_input_digest"] != aggregate["evidence_input_digest"]:
                raise EvidenceBlocked(f"{target_id} result is stale relative to the collector evidence-input closure")
            if sample["profile_digest"] != profile["profile_digest"] or sample["artifact_id"] != profile["artifact_id"] or sample["ffmpeg_sha256"] != profile["ffmpeg_sha256"] or sample["ffprobe_sha256"] != profile["ffprobe_sha256"]:
                raise EvidenceBlocked(f"{target_id} sample/profile artifact identity mismatch")
            target_summary = next(item for item in targets if item["target_profile_id"] == target_id)
            target_summary = exact_keys(target_summary, {"target_profile_id", "target_triple", "artifact_id", "git_commit", "profile_report_sha256", "sample_report_sha256", "sample_result_count", "native_runner_os", "native_runner_arch"}, f"{target_id} collector target summary")
            if target_summary != {
                "target_profile_id": target_id,
                "target_triple": triple,
                "artifact_id": profile["artifact_id"],
                "git_commit": provenance["git_commit"],
                "profile_report_sha256": provenance["ffmpeg_profile_report_sha256"],
                "sample_report_sha256": provenance["sample_report_sha256"],
                "sample_result_count": len(sample["results"]),
                "native_runner_os": runner_os,
                "native_runner_arch": runner_arch,
            }:
                raise EvidenceBlocked(f"{target_id} aggregate summary does not bind the exact raw profile/sample reports")
        return

    if row == 16:
        result = exact_keys(result, WINDOW_RESULT_FIELDS, "Windows WindowProbeResult")
        boolean_fields = {
            "provenance_verified", "network_disconnected", "first_launch_succeeded", "transparent_pixels_visible",
            "transparent_pixels_click_through", "frameless_drag_works", "file_drop_works",
            "outside_orb_drop_reached_background_target", "outside_orb_drop_reached_fluxform", "focus_recovery_works",
            "keyboard_input_works", "repeated_launch_created_second_window", "single_window_close_works",
            "last_window_close_works", "dpi_change_works", "multi_monitor_move_works", "passed",
        }
        if any(type(result[field]) is not bool for field in boolean_fields):
            raise EvidenceBlocked("Windows WindowProbeResult contains non-boolean behavioral facts")
        if type(result["repeated_launch_backend_process_count"]) is not int or type(result["webview_helper_process_count"]) is not int:
            raise EvidenceBlocked("Windows WindowProbeResult process counts are not integers")
        if not isinstance(result["os"], str) or not isinstance(result["probe_mode"], str):
            raise EvidenceBlocked("Windows WindowProbeResult OS or probe mode is malformed")
        if result["os"].lower() != "windows" or result["passed"] is not True or result["provenance_verified"] is not True:
            raise EvidenceBlocked("Windows WindowProbeResult is not a passing verified installed-app result")
        if result["network_disconnected"] is not True or result["first_launch_succeeded"] is not True:
            raise EvidenceBlocked("Windows WindowProbeResult lacks disconnected install/first-launch evidence")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", result["installed_artifact_sha256"]):
            raise EvidenceBlocked("Windows WindowProbeResult has no installer package identity")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", result["installed_executable_sha256"]):
            raise EvidenceBlocked("Windows WindowProbeResult has no installed executable identity")
        if result["repeated_launch_backend_process_count"] != 1 or result["repeated_launch_created_second_window"] is not True or result["single_window_close_works"] is not True or result["last_window_close_works"] is not True or result["dpi_change_works"] is not True or result["multi_monitor_move_works"] is not True:
            raise EvidenceBlocked("Windows WindowProbeResult lacks required launch/close/DPI/monitor behavior")
        if result["probe_mode"] == "transparent-orb":
            mode_passed = result["transparent_pixels_visible"] and result["transparent_pixels_click_through"] and result["outside_orb_drop_reached_background_target"] and not result["outside_orb_drop_reached_fluxform"]
        elif result["probe_mode"] == "transparent-window-with-rectangular-hit-region":
            mode_passed = result["transparent_pixels_visible"] and not result["transparent_pixels_click_through"] and not result["outside_orb_drop_reached_background_target"] and result["outside_orb_drop_reached_fluxform"]
        elif result["probe_mode"] == "opaque-frameless-fallback":
            mode_passed = not result["transparent_pixels_visible"] and not result["transparent_pixels_click_through"] and not result["outside_orb_drop_reached_background_target"] and result["outside_orb_drop_reached_fluxform"]
        else:
            mode_passed = False
        if not mode_passed:
            raise EvidenceBlocked("Windows WindowProbeResult does not satisfy its declared input/display mode")
        expected = {"installer-package": result["installed_artifact_sha256"], "installed-executable": result["installed_executable_sha256"]}
        if not isinstance(artifact_identities, dict) or {key: value.get("sha256") for key, value in artifact_identities.items() if isinstance(value, dict)} != expected:
            raise EvidenceBlocked("Windows WindowProbeResult package/executable identities do not match its manifest")
        return


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


def validate_attestation(repo_root: Path, path: Path | None, expected_bundle: str) -> dict:
    if path is None or not path.exists():
        raise EvidenceBlocked("same-run reviewed-evidence attestation is missing")
    attestation, _digest, _identity = read_pinned_json(path, "reviewed evidence CI attestation", repo_root)
    keys = {"schema", "bundle_id", "workflow_run_id", "commit_sha", "actor", "environment", "closure_digest", "files"}
    attestation = exact_keys(attestation, keys, "reviewed evidence CI attestation")
    if attestation["schema"] != "fluxform.stage0.reviewed-evidence-ci-attestation.v1" or attestation["bundle_id"] != expected_bundle:
        raise EvidenceBlocked("reviewed evidence attestation has an unknown schema or bundle identity")
    expected = {
        "workflow_run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "commit_sha": os.environ.get("GITHUB_SHA", ""),
        "actor": os.environ.get("GITHUB_ACTOR", ""),
        "environment": os.environ.get("STAGE0_REVIEWED_EVIDENCE_ENV", ""),
    }
    if not all(expected.values()) or any(attestation[key] != value for key, value in expected.items()):
        raise EvidenceBlocked("reviewed evidence attestation does not match this workflow run, commit, actor, and protected environment")
    if expected["environment"] != "stage0-manual-review":
        raise EvidenceBlocked("reviewed evidence requires the protected stage0-manual-review environment")
    files = attestation["files"]
    if not isinstance(files, list) or not files:
        raise EvidenceBlocked("reviewed evidence attestation has no file closure")
    normalized = []
    for item in files:
        item = exact_keys(item, {"path", "sha256"}, "attested reviewed file")
        relative = safe_relative_path(item["path"])
        if relative.parts[:4] != ("target", "stage0", "reviewed-evidence", expected_bundle) or not re.fullmatch(r"[0-9a-f]{64}", str(item["sha256"])):
            raise EvidenceBlocked("reviewed evidence attestation contains an invalid file identity")
        file_path = safe_file(repo_root, relative, "attested reviewed evidence file")
        _data, digest, _file_identity = _read_pinned_bytes(file_path, "attested reviewed evidence file", repo_root)
        if digest != item["sha256"]:
            raise EvidenceBlocked("reviewed evidence file changed after the CI attestation was created")
        normalized.append({"path": relative.as_posix(), "sha256": digest})
    if len({item["path"] for item in normalized}) != len(normalized):
        raise EvidenceBlocked("reviewed evidence attestation repeats a file path")
    normalized.sort(key=lambda item: item["path"])
    closure = hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    if attestation["closure_digest"] != closure:
        raise EvidenceBlocked("reviewed evidence attestation closure digest is stale")
    return attestation


def validate_bundle(repo_root: Path, references: list[tuple[int, str, str, str, str, str, PurePosixPath]], attestation: dict, aggregate_report_path: Path | None) -> None:
    loaded = []
    result_paths: set[str] = set()
    result_digests: set[str] = set()
    manifest_paths: set[str] = set()
    all_bundles = {reference[4] for reference in references}
    if len(all_bundles) != 1:
        raise EvidenceBlocked("all PASS rows must use one same-run reviewed evidence bundle")
    bundle_id = next(iter(all_bundles))
    if bundle_id != attestation["bundle_id"]:
        raise EvidenceBlocked("row manifests do not match the attested reviewed bundle")

    for number, label, reviewer_text, expected_sha, row_bundle, key, relative in references:
        path = safe_file(repo_root, relative, f"evidence row {number} manifest")
        manifest, actual_sha, _identity = read_pinned_json(path, f"evidence row {number} manifest", repo_root)
        if actual_sha != expected_sha:
            raise EvidenceBlocked(f"evidence row {number} manifest SHA-256 does not match the report")
        manifest_paths.add(relative.as_posix())
        exact_keys(manifest, {"schema", "bundle_id", "row_id", "label", "status", "evidence_kind", "platform", "date", "reviewer", "review_state", "artifact_identities", "raw_results"}, f"evidence row {number} manifest")
        kind = KINDS[number - 1]
        if manifest["schema"] != "fluxform.stage0.reviewed-row-manifest.v2" or manifest["bundle_id"] != row_bundle or manifest["row_id"] != number or manifest["label"] != label or manifest["status"] != "PASS" or manifest["evidence_kind"] != kind or manifest["platform"] != PLATFORMS[number - 1] or manifest["review_state"] != "reviewed":
            raise EvidenceBlocked(f"evidence row {number} manifest does not bind its exact row identity")
        report_platform, report_date, report_reviewer = reviewer_cell(reviewer_text, number)
        if report_platform != manifest["platform"] or report_platform != PLATFORMS[number - 1] or report_date != manifest["date"]:
            raise EvidenceBlocked(f"evidence row {number} platform/date does not match the reviewed manifest")
        reviewer = exact_keys(manifest["reviewer"], {"identity", "reviewed_at"}, f"evidence row {number} reviewer")
        if reviewer["identity"] != report_reviewer or not isinstance(reviewer["reviewed_at"], str):
            raise EvidenceBlocked(f"evidence row {number} reviewer identity does not match the report")
        try:
            reviewed_at = dt.datetime.fromisoformat(reviewer["reviewed_at"].replace("Z", "+00:00"))
        except ValueError as error:
            raise EvidenceBlocked(f"evidence row {number} reviewed timestamp is malformed") from error
        if reviewed_at.tzinfo is None or reviewed_at.date().isoformat() != report_date:
            raise EvidenceBlocked(f"evidence row {number} reviewed timestamp is not on its reported date")
        if number not in ROW_RESULT_SCHEMAS:
            raise EvidenceBlocked(f"evidence row {number} ({kind}) has no authoritative machine-readable source schema; it remains BLOCKED")
        descriptors = manifest["raw_results"]
        expected_roles = ROW_RESULT_SCHEMAS[number]
        if not isinstance(descriptors, list) or len(descriptors) != len(expected_roles):
            raise EvidenceBlocked(f"evidence row {number} raw-result file set is incomplete")
        role_documents = {}
        for descriptor in descriptors:
            descriptor = exact_keys(descriptor, {"role", "path", "sha256", "type", "schema", "row_id"}, f"evidence row {number} raw-result descriptor")
            role = descriptor["role"]
            schema = expected_roles.get(role)
            if schema is None or descriptor["schema"] != schema or descriptor["type"] != "application/json" or descriptor["row_id"] != number:
                raise EvidenceBlocked(f"evidence row {number} raw-result role/schema/row identity is invalid")
            if role in role_documents:
                raise EvidenceBlocked(f"evidence row {number} repeats a raw-result role")
            raw_relative = safe_relative_path(descriptor["path"])
            expected_parent = PurePosixPath("target", "stage0", "reviewed-evidence", bundle_id)
            expected_name = f"row-{number:02}-{role}.json"
            if raw_relative.parent != expected_parent or raw_relative.name != expected_name:
                raise EvidenceBlocked(f"evidence row {number} raw result is outside its row-bound bundle path")
            key_path = os.path.normcase(raw_relative.as_posix())
            digest = descriptor["sha256"]
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise EvidenceBlocked(f"evidence row {number} raw result has a malformed SHA-256")
            if key_path in result_paths or digest in result_digests:
                raise EvidenceBlocked("a raw result file is reused across report rows")
            result_paths.add(key_path)
            result_digests.add(digest)
            raw_path = safe_file(repo_root, raw_relative, f"evidence row {number} raw result")
            document, actual_digest, _file_identity = read_pinned_json(raw_path, f"evidence row {number} raw result", repo_root)
            if actual_digest != digest:
                raise EvidenceBlocked(f"evidence row {number} raw-result SHA-256 does not match its manifest")
            if descriptor["schema"] == "fluxform.stage0.protocol-contract-run.v1":
                if not isinstance(document, dict) or document.get("schema") != descriptor["schema"]:
                    raise EvidenceBlocked(f"evidence row {number} raw result does not match its declared schema")
            elif descriptor["schema"] == "fluxform.stage0.product-approval.v1":
                if not isinstance(document, dict) or document.get("schema") != descriptor["schema"]:
                    raise EvidenceBlocked(f"evidence row {number} raw result does not match its declared schema")
            elif descriptor["schema"] == "fluxform.sample-aggregate.v1":
                if not isinstance(document, dict) or document.get("schema") != descriptor["schema"]:
                    raise EvidenceBlocked(f"evidence row {number} raw result does not match its declared schema")
            role_documents[role] = document
        if set(role_documents) != set(expected_roles):
            raise EvidenceBlocked(f"evidence row {number} does not contain every required raw-result role")
        artifacts = manifest["artifact_identities"]
        if not isinstance(artifacts, dict):
            raise EvidenceBlocked(f"evidence row {number} artifact identities must be a typed object")
        primary_role = "primary" if number == 1 else "probe-report" if number in PROFILE_TARGETS else "approval-record" if number == 6 else "aggregate-report" if number == 7 else "window-result"
        primary = role_documents[primary_role]
        validate_semantics(repo_root, number, primary, artifacts, role_documents, attestation)
        loaded.append(number)

    attested_paths = {item["path"] for item in attestation["files"]}
    if manifest_paths | result_paths != attested_paths:
        raise EvidenceBlocked("same-run attestation file closure does not exactly match all row manifests and raw result files")
    if 7 in loaded:
        if aggregate_report_path is None:
            raise EvidenceBlocked("current collector output is required to prove the sample evidence-input closure")
        current_path = aggregate_report_path.resolve(strict=True)
        current, _digest, _identity = read_pinned_json(current_path, "current collector aggregate output", repo_root)
        aggregate_descriptor = next(reference for reference in references if reference[0] == 7)
        manifest_path = safe_file(repo_root, aggregate_descriptor[6], "row 7 manifest")
        manifest, _manifest_sha, _ = read_pinned_json(manifest_path, "row 7 manifest", repo_root)
        report_info = next(item for item in manifest["raw_results"] if item["role"] == "aggregate-report")
        raw_path = safe_file(repo_root, safe_relative_path(report_info["path"]), "row 7 aggregate raw result")
        recorded, _recorded_sha, _ = read_pinned_json(raw_path, "row 7 aggregate raw result", repo_root)
        if current != recorded:
            raise EvidenceBlocked("row 7 aggregate raw result is stale relative to the collector run in this Complete invocation")


def validate(repo_root: Path, report_path: Path, attestation_path: Path | None = None, aggregate_report_path: Path | None = None) -> None:
    overall, rows, counts = load_report(report_path, repo_root)
    if counts[1]:
        raise ReportInvalid(f"{counts[1]} gate report row(s) are FAIL")
    if counts[2]:
        raise EvidenceBlocked(f"{counts[2]} gate report row(s) remain BLOCKED")
    if counts[0] != 23 or overall != "PASS":
        raise ReportInvalid("every one of the 23 gate report rows must be PASS")
    references = validate_manifest_references(rows)
    bundle_ids = {reference[4] for reference in references}
    if len(bundle_ids) != 1:
        raise EvidenceBlocked("all PASS rows must use one reviewed evidence bundle")
    attestation = validate_attestation(repo_root, attestation_path, next(iter(bundle_ids)))
    validate_bundle(repo_root, references, attestation, aggregate_report_path)
    print("PASS: all 23 report rows have per-kind raw-result semantics and same-run reviewed attestation")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--attestation", type=Path)
    parser.add_argument("--aggregate-report", type=Path)
    args = parser.parse_args()
    try:
        repo_root = args.repo_root.resolve(strict=True)
        report_path = args.report.resolve(strict=True)
        aggregate_path = args.aggregate_report
        validate(repo_root, report_path, args.attestation, aggregate_path)
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
