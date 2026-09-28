#!/usr/bin/env python3
"""Fail-closed validation for the reviewed, per-row Stage 0 evidence bundle."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
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
WINDOW_PROBE_MODES = {
    "transparent-orb",
    "transparent-window-with-rectangular-hit-region",
    "opaque-frameless-fallback",
}
WINDOW_DISPLAY_SERVERS = {"windows", "macos", "x11", "wayland"}
WINDOW_HIT_REGION_STATUSES = {
    "pending", "circular-applied", "rectangular-fallback-unsupported",
    "rectangular-fallback-apply-failed", "failed-closed", "rectangular", "opaque", "unknown",
}
WINDOW_BOOLEAN_FIELDS = {
    "provenance_verified", "native_hit_region_supported", "network_disconnected",
    "first_launch_succeeded", "transparent_pixels_visible", "transparent_pixels_click_through",
    "frameless_drag_works", "file_drop_works", "outside_orb_drop_reached_background_target",
    "outside_orb_drop_reached_fluxform", "focus_recovery_works", "keyboard_input_works",
    "repeated_launch_created_second_window", "single_window_close_works", "last_window_close_works",
    "dpi_change_works", "multi_monitor_move_works", "passed",
}
WINDOW_STRING_FIELDS = {
    "probe_mode", "os", "os_version", "display_server", "installed_artifact_sha256",
    "installed_executable_sha256", "install_identity", "provenance_error",
    "installed_launch_path", "input_hit_region_status", "notes",
}
WINDOW_U32_FIELDS = {"repeated_launch_backend_process_count", "webview_helper_process_count"}
WINDOW_F32_FIELDS = {"idle_cpu_percent", "idle_gpu_percent"}
WINDOW_F32_MAX = 3.4028234663852886e38

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


def _validate_window_probe_result(result: object) -> dict:
    value = exact_keys(result, WINDOW_RESULT_FIELDS, "Windows WindowProbeResult")
    if any(type(value[field]) is not str for field in WINDOW_STRING_FIELDS):
        raise EvidenceBlocked("Windows WindowProbeResult contains a non-string field")
    if any(type(value[field]) is not bool for field in WINDOW_BOOLEAN_FIELDS):
        raise EvidenceBlocked("Windows WindowProbeResult contains a non-boolean field")
    if any(type(value[field]) is not int or not 0 <= value[field] <= 0xFFFFFFFF for field in WINDOW_U32_FIELDS):
        raise EvidenceBlocked("Windows WindowProbeResult contains a value outside its u32 process-count fields")
    for field in WINDOW_F32_FIELDS:
        metric = value[field]
        if isinstance(metric, bool) or not isinstance(metric, (int, float)):
            raise EvidenceBlocked(f"Windows WindowProbeResult {field} is not an f32-compatible number")
        try:
            metric_value = float(metric)
        except (OverflowError, ValueError) as error:
            raise EvidenceBlocked(f"Windows WindowProbeResult {field} is outside the f32 range") from error
        if not math.isfinite(metric_value) or metric_value < 0 or metric_value > WINDOW_F32_MAX:
            raise EvidenceBlocked("Windows WindowProbeResult idle metrics must be finite, non-negative f32 values")

    if value["probe_mode"] not in WINDOW_PROBE_MODES:
        raise EvidenceBlocked("Windows WindowProbeResult has an unknown probe mode")
    if value["display_server"] not in WINDOW_DISPLAY_SERVERS:
        raise EvidenceBlocked("Windows WindowProbeResult has an unknown display server")
    if not value["os"].strip() or not value["os_version"].strip():
        raise EvidenceBlocked("Windows WindowProbeResult OS and OS version are required")
    if not value["installed_launch_path"].strip():
        raise EvidenceBlocked("Windows WindowProbeResult installed launch path is required")
    is_sha256 = lambda item: re.fullmatch(r"[0-9a-fA-F]{64}", item, flags=re.ASCII) is not None
    if not is_sha256(value["installed_executable_sha256"]):
        raise EvidenceBlocked("Windows WindowProbeResult installed executable identity must be a SHA-256 hex digest")
    if value["installed_artifact_sha256"] and not is_sha256(value["installed_artifact_sha256"]):
        raise EvidenceBlocked("Windows WindowProbeResult installer package identity must be empty or a SHA-256 hex digest")
    if value["provenance_verified"] and (
        not is_sha256(value["installed_artifact_sha256"])
        or not re.fullmatch(r"[A-Za-z0-9._-]{1,128}", value["install_identity"], flags=re.ASCII)
    ):
        raise EvidenceBlocked("Windows WindowProbeResult verified provenance requires a package hash and valid install identity")
    if value["input_hit_region_status"] not in WINDOW_HIT_REGION_STATUSES:
        raise EvidenceBlocked("Windows WindowProbeResult has an unknown native input hit-region status")

    if not value["passed"]:
        return value
    if not value["provenance_verified"]:
        raise EvidenceBlocked("Windows WindowProbeResult passing evidence requires verified installed-package provenance")
    expected_status = {
        "transparent-orb": "circular-applied",
        "transparent-window-with-rectangular-hit-region": "rectangular",
        "opaque-frameless-fallback": "opaque",
    }[value["probe_mode"]]
    if not value["native_hit_region_supported"] or value["input_hit_region_status"] != expected_status:
        raise EvidenceBlocked("Windows WindowProbeResult passing evidence requires the selected native input hit region")
    if value["repeated_launch_backend_process_count"] != 1:
        raise EvidenceBlocked("Windows WindowProbeResult repeated launch must use exactly one backend process")
    common_behavior_fields = {
        "network_disconnected", "first_launch_succeeded", "frameless_drag_works", "file_drop_works",
        "focus_recovery_works", "keyboard_input_works", "repeated_launch_created_second_window",
        "single_window_close_works", "last_window_close_works", "dpi_change_works", "multi_monitor_move_works",
    }
    if any(value[field] is not True for field in common_behavior_fields):
        raise EvidenceBlocked("Windows WindowProbeResult passing evidence is missing a required manual behavior")
    mode_behavior_passes = {
        "transparent-orb": (
            value["transparent_pixels_visible"]
            and value["transparent_pixels_click_through"]
            and value["outside_orb_drop_reached_background_target"]
            and not value["outside_orb_drop_reached_fluxform"]
        ),
        "transparent-window-with-rectangular-hit-region": (
            value["transparent_pixels_visible"]
            and not value["transparent_pixels_click_through"]
            and not value["outside_orb_drop_reached_background_target"]
            and value["outside_orb_drop_reached_fluxform"]
        ),
        "opaque-frameless-fallback": (
            not value["transparent_pixels_visible"]
            and not value["transparent_pixels_click_through"]
            and not value["outside_orb_drop_reached_background_target"]
            and value["outside_orb_drop_reached_fluxform"]
        ),
    }[value["probe_mode"]]
    if not mode_behavior_passes:
        raise EvidenceBlocked("Windows WindowProbeResult passing evidence does not satisfy its selected mode")
    return value


def _serialized_sha256(value: object) -> str:
    encoded = json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return sha256_bytes(encoded)


def _row7_sources(repo_root: Path) -> tuple[dict, dict, dict[str, dict], dict[str, dict], dict[str, str]]:
    manifest_relative = safe_relative_path("config/capabilities-v1.toml")
    catalog_relative = safe_relative_path("testdata/media/v1/samples.toml")
    manifest_path = safe_file(repo_root, manifest_relative, "tracked capability manifest")
    catalog_path = safe_file(repo_root, catalog_relative, "tracked sample catalog")
    manifest_bytes, manifest_digest, _ = _read_pinned_bytes(manifest_path, "tracked capability manifest", repo_root)
    catalog_bytes, catalog_digest, _ = _read_pinned_bytes(catalog_path, "tracked sample catalog", repo_root)
    try:
        manifest = tomllib.loads(manifest_bytes.decode("utf-8", errors="strict"))
        catalog = tomllib.loads(catalog_bytes.decode("utf-8", errors="strict"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise EvidenceBlocked(f"tracked row 7 manifest or sample catalog is invalid: {error}") from error
    if set(manifest) != {"manifest_version", "edges"} or manifest["manifest_version"] != "v1" or not isinstance(manifest["edges"], list):
        raise EvidenceBlocked("tracked row 7 capability manifest has an unknown v1 shape")
    if set(catalog) != {"catalog_version", "samples"} or catalog["catalog_version"] != "v1" or not isinstance(catalog["samples"], list):
        raise EvidenceBlocked("tracked row 7 sample catalog has an unknown v1 shape")

    edge_fields = {
        "id", "category", "input_extensions", "input_demuxers", "input_codecs", "input_topology",
        "output_format", "output_muxer", "video_codec", "audio_codec", "stream_map", "alpha_policy",
        "orientation_policy", "metadata_policy", "profile_ids", "valid_samples", "invalid_samples", "options",
    }
    required_edge_fields = edge_fields - {"video_codec", "audio_codec"}
    edge_values: dict[str, dict] = {}
    matrix: dict[tuple[str, str], tuple[dict, dict]] = {}
    for edge in manifest["edges"]:
        if not isinstance(edge, dict) or set(edge) - edge_fields or required_edge_fields - set(edge):
            raise EvidenceBlocked("tracked row 7 edge does not match the Rust ConversionEdgeV1 schema")
        normalized = {field: edge.get(field) for field in (
            "id", "category", "input_extensions", "input_demuxers", "input_codecs", "input_topology",
            "output_format", "output_muxer", "video_codec", "audio_codec", "stream_map", "alpha_policy",
            "orientation_policy", "metadata_policy", "profile_ids", "valid_samples", "invalid_samples",
        )}
        options = edge["options"]
        if not isinstance(options, dict):
            raise EvidenceBlocked("tracked row 7 edge options must be a typed object")
        normalized["options"] = {}
        for name in sorted(options):
            bounds = options[name]
            if not isinstance(bounds, dict) or set(bounds) != {"minimum", "maximum", "default"} or any(type(bounds[field]) is not int for field in ("minimum", "maximum", "default")):
                raise EvidenceBlocked("tracked row 7 edge parameter bounds do not match Rust ParameterBounds")
            normalized["options"][name] = {field: bounds[field] for field in ("minimum", "maximum", "default")}
        if not isinstance(edge["id"], str) or not edge["id"] or edge["id"] in edge_values:
            raise EvidenceBlocked("tracked row 7 manifest repeats or omits an edge identity")
        edge_values[edge["id"]] = {**edge, "_rust_value": normalized, "_digest": _serialized_sha256(normalized)}

    sample_fields = {
        "id", "path", "sha256", "provenance", "license", "category", "container", "codecs",
        "stream_topology", "width", "height", "duration_ms", "alpha", "orientation", "metadata",
        "expected_outcome", "expected_error_code",
    }
    samples: dict[str, dict] = {}
    for sample in catalog["samples"]:
        if not isinstance(sample, dict) or set(sample) != sample_fields:
            raise EvidenceBlocked("tracked row 7 sample does not match the Rust SampleRecordV1 schema")
        if not isinstance(sample["id"], str) or not sample["id"] or sample["id"] in samples:
            raise EvidenceBlocked("tracked row 7 sample catalog repeats or omits a sample identity")
        if type(sample["width"]) is not int or not 0 <= sample["width"] <= 0xFFFFFFFF or type(sample["height"]) is not int or not 0 <= sample["height"] <= 0xFFFFFFFF or type(sample["duration_ms"]) is not int or not 0 <= sample["duration_ms"] <= 0xFFFFFFFFFFFFFFFF:
            raise EvidenceBlocked("tracked row 7 sample dimensions or duration are outside Rust integer bounds")
        if not isinstance(sample["codecs"], list) or not all(type(item) is str for item in sample["codecs"]):
            raise EvidenceBlocked("tracked row 7 sample codecs are malformed")
        if not isinstance(sample["path"], str) or not re.fullmatch(r"files/[^/\\]+", sample["path"]):
            raise EvidenceBlocked("tracked row 7 sample path is not a direct files/ child")
        if not isinstance(sample["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", sample["sha256"]):
            raise EvidenceBlocked("tracked row 7 sample SHA-256 is malformed")
        sample_path = safe_file(repo_root, safe_relative_path(f"testdata/media/v1/{sample['path']}"), "tracked media sample")
        sample_bytes, sample_digest, _ = _read_pinned_bytes(sample_path, "tracked media sample", repo_root)
        if sample_digest != sample["sha256"]:
            raise EvidenceBlocked(f"tracked row 7 sample bytes do not match catalog identity: {sample['id']}")
        samples[sample["id"]] = sample

    expected_references: set[tuple[str, str]] = set()
    sample_references: set[str] = set()
    for edge_id, edge in edge_values.items():
        for sample_id in edge["valid_samples"]:
            sample = samples.get(sample_id)
            if sample is None or sample["expected_outcome"] != "success" or sample["category"] != edge["category"]:
                raise EvidenceBlocked("tracked row 7 valid sample does not match its manifest edge")
            expected_references.add((edge_id, sample_id))
            sample_references.add(sample_id)
        for sample_id in edge["invalid_samples"]:
            sample = samples.get(sample_id)
            if sample is None or sample["expected_outcome"] != "error" or sample["category"] != edge["category"]:
                raise EvidenceBlocked("tracked row 7 invalid sample does not match its manifest edge")
            expected_references.add((edge_id, sample_id))
            sample_references.add(sample_id)
    if sample_references != set(samples):
        raise EvidenceBlocked("tracked row 7 sample catalog is not the exact manifest sample closure")

    corpus_directory = safe_file(repo_root, safe_relative_path("testdata/media/v1/samples.toml"), "tracked sample catalog").parent / "files"
    try:
        corpus_names = {entry.name for entry in corpus_directory.iterdir()}
    except OSError as error:
        raise EvidenceBlocked(f"tracked row 7 media corpus cannot be enumerated: {error}") from error
    expected_corpus_names = {Path(sample["path"]).name for sample in samples.values()}
    if corpus_names != expected_corpus_names:
        raise EvidenceBlocked("tracked row 7 media corpus is not the exact catalog file set")
    return manifest, catalog, edge_values, samples, {
        "manifest_digest": manifest_digest,
        "catalog_digest": catalog_digest,
        "expected_cases": _serialized_sha256(sorted(expected_references)),
    }


def _row7_expected_output(edge: dict, sample: dict) -> dict:
    options = edge["options"]
    option = lambda name, fallback: options.get(name, {}).get("default", fallback)
    edge_duration = min(0xFFFFFFFFFFFFFFFF, option("max_duration_seconds", 3600) * 1000)
    sample_duration = edge_duration if sample["duration_ms"] == 0 else min(0xFFFFFFFFFFFFFFFF, sample["duration_ms"] + 100)
    codec_names = {
        "libx264": "h264", "h264": "h264", "libx265": "hevc", "hevc": "hevc",
        "libmp3lame": "mp3", "libwebp": "webp", "libwebp_anim": "webp",
    }
    codecs = [codec_names.get(edge[field].lower(), edge[field]) for field in ("video_codec", "audio_codec") if edge.get(field) is not None]
    return {
        "container": edge["output_format"],
        "codecs": codecs,
        "stream_topology": {"audio": "single_audio_stream", "image": "single_video_frame", "video": "single_video_stream"}[edge["category"]],
        "width": sample["width"],
        "height": sample["height"],
        "max_width": option("max_width", 4096) & 0xFFFFFFFF,
        "max_height": option("max_height", 4096) & 0xFFFFFFFF,
        "expected_duration_ms": sample["duration_ms"],
        "duration_tolerance_ms": 100,
        "max_duration_ms": min(edge_duration, sample_duration),
        "alpha_policy": edge["alpha_policy"],
        "orientation_policy": edge["orientation_policy"],
        "metadata_policy": edge["metadata_policy"],
    }


def _validate_observed_media(value: object, label: str) -> dict:
    observed = exact_keys(value, OBSERVED_MEDIA_FIELDS, label)
    if any(type(observed[field]) is not str for field in ("format_name", "stream_topology")):
        raise EvidenceBlocked(f"{label} has a malformed text field")
    if not isinstance(observed["codecs"], list) or not all(type(item) is str for item in observed["codecs"]):
        raise EvidenceBlocked(f"{label} codecs are malformed")
    if not isinstance(observed["metadata_keys"], list) or not all(type(item) is str for item in observed["metadata_keys"]):
        raise EvidenceBlocked(f"{label} metadata keys are malformed")
    for field in ("width", "height"):
        if type(observed[field]) is not int or not 0 <= observed[field] <= 0xFFFFFFFF:
            raise EvidenceBlocked(f"{label} {field} is outside its Rust u32 range")
    for field in ("duration_ms", "frame_count"):
        if type(observed[field]) is not int or not 0 <= observed[field] <= 0xFFFFFFFFFFFFFFFF:
            raise EvidenceBlocked(f"{label} {field} is outside its Rust u64 range")
    if type(observed["alpha_present"]) is not bool or type(observed["orientation_present"]) is not bool:
        raise EvidenceBlocked(f"{label} has a malformed boolean fact")
    return observed


def _validate_row7_result_matrix(repo_root: Path, sample: dict, edge_values: dict[str, dict], samples: dict[str, dict]) -> None:
    if not isinstance(sample["results"], list):
        raise EvidenceBlocked("row 7 sample report results must be a list")
    expected_cases = {
        (edge_id, sample_id)
        for edge_id, edge in edge_values.items()
        for sample_id in edge["valid_samples"] + edge["invalid_samples"]
    }
    actual_cases: set[tuple[str, str]] = set()
    for raw_result in sample["results"]:
        result = exact_keys(raw_result, SAMPLE_RESULT_FIELDS, "row 7 sample result")
        case = (result["edge_id"], result["sample_id"])
        if case in actual_cases or case not in expected_cases:
            raise EvidenceBlocked("row 7 sample report has a repeated or unknown manifest/sample case")
        actual_cases.add(case)
        edge = edge_values[case[0]]
        source_sample = samples[case[1]]
        expected_outcome = source_sample["expected_outcome"]
        if (
            result["edge_spec_digest"] != edge["_digest"]
            or result["sample_sha256"] != source_sample["sha256"]
            or result["expected_outcome"] != expected_outcome
            or result["expected_error_code"] != source_sample["expected_error_code"]
        ):
            raise EvidenceBlocked("row 7 sample result identity differs from the tracked manifest/catalog")
        expectations = _row7_expected_output(edge, source_sample)
        if result["output_expectations"] != expectations or result["output_expectations_digest"] != _serialized_sha256(expectations):
            raise EvidenceBlocked("row 7 output expectations do not match the tracked edge and sample")
        if result["status"] != "passed" or type(result["ffmpeg_invoked"]) is not bool:
            raise EvidenceBlocked("row 7 collector result did not pass its native execution")
        if not isinstance(result["actual_error_code"], str) or not isinstance(result["diagnostic"], str):
            raise EvidenceBlocked("row 7 collector result has malformed diagnostic fields")
        if not isinstance(result["ffprobe_arguments"], list) or not all(type(item) is str for item in result["ffprobe_arguments"]) or not isinstance(result["ffmpeg_arguments"], list) or not all(type(item) is str for item in result["ffmpeg_arguments"]):
            raise EvidenceBlocked("row 7 collector result has malformed command arguments")
        observed_input = _validate_observed_media(result["observed_input"], "row 7 observed input")
        if (
            observed_input["width"] != source_sample["width"]
            or observed_input["height"] != source_sample["height"]
            or observed_input["stream_topology"] != source_sample["stream_topology"]
            or {item.lower() for item in observed_input["codecs"]} != {item.lower() for item in source_sample["codecs"]}
            or abs(observed_input["duration_ms"] - source_sample["duration_ms"]) > 20
            or (source_sample["alpha"] != "not_applicable" and observed_input["alpha_present"] != (source_sample["alpha"] == "present"))
            or (source_sample["orientation"] != "not_applicable" and observed_input["orientation_present"] != (source_sample["orientation"] == "present"))
            or (bool(observed_input["metadata_keys"]) != (source_sample["metadata"] == "present"))
        ):
            raise EvidenceBlocked("row 7 observed input does not match the tracked sample identity")
        if expected_outcome == "success":
            if result["actual_error_code"] != "" or result["ffmpeg_invoked"] is not True:
                raise EvidenceBlocked("row 7 successful sample did not invoke FFmpeg cleanly")
            _validate_observed_media(result["observed_output"], "row 7 observed output")
        elif result["actual_error_code"] != source_sample["expected_error_code"] or result["ffmpeg_invoked"] is not False or result["observed_output"] is not None:
            raise EvidenceBlocked("row 7 rejected sample does not match its stable expected error")
    if actual_cases != expected_cases:
        raise EvidenceBlocked("row 7 sample result set is not the exact tracked manifest/catalog cross-product")


def validate_semantics(repo_root: Path, row: int, result: object, artifact_identities: object, role_documents: dict[str, dict] | None = None, attestation: dict | None = None, role_digests: dict[str, str] | None = None, aggregate_report_path: Path | None = None) -> None:
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
        if role_documents is None or attestation is None or role_digests is None:
            raise EvidenceBlocked("native sample aggregate requires its actual raw-byte digests and same-run attestation")
        _manifest, _catalog, edge_values, samples, source_digests = _row7_sources(repo_root)
        aggregate = exact_keys(role_documents.get("aggregate-report"), {"schema", "status", "evidence_input_digest", "targets"}, "native sample aggregate")
        if aggregate["schema"] != "fluxform.sample-aggregate.v1" or aggregate["status"] != "passed" or not re.fullmatch(r"[0-9a-f]{64}", str(aggregate["evidence_input_digest"])):
            raise EvidenceBlocked("native collector aggregate is blocked, stale, or has an unknown schema")
        targets = aggregate["targets"]
        if not isinstance(targets, list) or {item.get("target_profile_id") for item in targets if isinstance(item, dict)} != set(SAMPLE_TARGETS) or len(targets) != 4:
            raise EvidenceBlocked("native collector aggregate does not contain exactly the four native targets")
        if attestation.get("commit_sha") != os.environ.get("GITHUB_SHA"):
            raise EvidenceBlocked("native aggregate provenance does not match the reviewed workflow commit")
        aggregate_raw_digest = role_digests.get("aggregate-report")
        if not isinstance(aggregate_raw_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", aggregate_raw_digest):
            raise EvidenceBlocked("native aggregate actual raw-byte SHA-256 is missing")
        if aggregate_report_path is None:
            raise EvidenceBlocked("current collector output is required to prove the reviewed aggregate raw-byte identity")
        _validate_aggregate_execution_receipt(repo_root, aggregate_report_path, attestation, aggregate, aggregate_raw_digest)
        for target_id, (triple, runner_os, runner_arch) in SAMPLE_TARGETS.items():
            profile = exact_keys(role_documents.get(f"profile-report-{target_id}"), PROBE_REPORT_FIELDS, f"{target_id} ProbeReport")
            sample = exact_keys(role_documents.get(f"sample-report-{target_id}"), SAMPLE_REPORT_FIELDS, f"{target_id} sample report")
            provenance = exact_keys(role_documents.get(f"provenance-{target_id}"), PROVENANCE_FIELDS, f"{target_id} native provenance")
            _validate_probe_report(repo_root, {"windows-x86_64": 2, "macos-x86_64": 3, "macos-aarch64": 4, "linux-x86_64": 5}[target_id], profile)
            if sample["schema"] != "fluxform.sample-run.v1" or sample["status"] != "passed" or sample["blockers"] != [] or not sample["results"]:
                raise EvidenceBlocked(f"{target_id} sample result has no passing current result set")
            if len(sample["results"]) != 9:
                raise EvidenceBlocked(f"{target_id} sample result does not contain the complete nine-case matrix")
            _validate_row7_result_matrix(repo_root, sample, edge_values, samples)
            if provenance["schema"] != "fluxform.native-sample-artifact.v1" or provenance["workflow_run_id"] != attestation["workflow_run_id"] or provenance["git_commit"] != attestation["commit_sha"] or sample["git_commit"] != attestation["commit_sha"]:
                raise EvidenceBlocked(f"{target_id} native provenance is not bound to this workflow run and commit")
            if not provenance["workflow_job_id"] or not all(re.fullmatch(r"[0-9a-f]{64}", str(provenance[field])) for field in ("ffmpeg_profile_report_sha256", "sample_report_sha256")):
                raise EvidenceBlocked(f"{target_id} native provenance has a missing job identity or report hash")
            if role_digests.get(f"profile-report-{target_id}") != provenance["ffmpeg_profile_report_sha256"] or role_digests.get(f"sample-report-{target_id}") != provenance["sample_report_sha256"]:
                raise EvidenceBlocked(f"{target_id} provenance hashes do not match the actual reviewed raw bytes")
            if (sample["target_triple"], sample["target_profile_id"], sample["runner_os"], sample["runner_arch"]) != (triple, target_id, runner_os, runner_arch):
                raise EvidenceBlocked(f"{target_id} sample result target identity does not match its native platform")
            if sample["evidence_input_digest"] != aggregate["evidence_input_digest"] or provenance["evidence_input_digest"] != aggregate["evidence_input_digest"]:
                raise EvidenceBlocked(f"{target_id} result is stale relative to the collector evidence-input closure")
            if sample["manifest_digest"] != source_digests["manifest_digest"] or sample["sample_catalog_digest"] != source_digests["catalog_digest"]:
                raise EvidenceBlocked(f"{target_id} sample report does not bind the current tracked manifest and catalog bytes")
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
        target_by_id = {item["target_profile_id"]: item for item in targets}
        if len(target_by_id) != len(SAMPLE_TARGETS) or any(type(target_by_id[target]["sample_result_count"]) is not int or target_by_id[target]["sample_result_count"] != 9 for target in SAMPLE_TARGETS):
            raise EvidenceBlocked("native collector aggregate has duplicate or incomplete target result identities")
        return

    if row == 16:
        result = _validate_window_probe_result(result)
        if result["os"].lower() != "windows" or result["display_server"] != "windows" or result["passed"] is not True:
            raise EvidenceBlocked("Windows WindowProbeResult is not a passing verified installed-app result")
        expected = {
            "installer-package": {"sha256": result["installed_artifact_sha256"]},
            "installed-executable": {"sha256": result["installed_executable_sha256"]},
        }
        if artifact_identities != expected:
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


def _pinned_repository_digest(repo_root: Path, relative_text: str, label: str) -> str:
    relative = safe_relative_path(relative_text)
    path = safe_file(repo_root, relative, label)
    _data, digest, _identity = _read_pinned_bytes(path, label, repo_root)
    return digest


def _validate_aggregate_execution_receipt(
    repo_root: Path,
    aggregate_report_path: Path,
    attestation: dict,
    aggregate: dict,
    aggregate_digest: str,
) -> None:
    root = repo_root.resolve(strict=True)
    aggregate_path = Path(os.path.abspath(aggregate_report_path))
    try:
        aggregate_relative = aggregate_path.relative_to(root).as_posix()
    except ValueError as error:
        raise EvidenceBlocked("current collector aggregate is outside the repository root") from error
    run_relative = safe_relative_path(aggregate_relative)
    if len(run_relative.parts) != 5 or run_relative.parts[:3] != ("target", "stage0", "runs") or run_relative.name != "aggregate-sample-report.json":
        raise EvidenceBlocked("current collector aggregate is not inside one target/stage0/runs invocation")
    run_id = run_relative.parts[3]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", run_id):
        raise EvidenceBlocked("current collector aggregate run identity is malformed")

    _manifest, _catalog, _edges, samples, source_digests = _row7_sources(repo_root)
    current, current_digest, _current_identity = read_pinned_json(aggregate_path, "current collector aggregate output", repo_root)
    if current != aggregate:
        raise EvidenceBlocked("current collector aggregate document differs from the reviewed row 7 report")
    if current_digest != aggregate_digest:
        raise EvidenceBlocked("reviewed aggregate raw bytes do not match the same-run collector output")

    receipt_relative = f"target/stage0/runs/{run_id}/aggregate-validation.json"
    receipt_path = safe_file(repo_root, safe_relative_path(receipt_relative), "same-run aggregate execution receipt")
    receipt, _receipt_digest, _receipt_identity = read_pinned_json(receipt_path, "same-run aggregate execution receipt", repo_root)
    receipt = exact_keys(receipt, {
        "schema", "status", "commit_sha", "evidence_input_digest", "aggregate_report", "commands", "files", "closure_digest",
    }, "same-run aggregate execution receipt")
    if receipt["schema"] != "fluxform.stage0.aggregate-execution-receipt.v1" or receipt["status"] != "PASS":
        raise EvidenceBlocked("same-run aggregate execution receipt is not a successful v1 receipt")
    expected_commit = os.environ.get("GITHUB_SHA", "")
    if not expected_commit or receipt["commit_sha"] != expected_commit or receipt["commit_sha"] != attestation["commit_sha"]:
        raise EvidenceBlocked("same-run aggregate receipt, attestation, and current workflow commit differ")
    if receipt["evidence_input_digest"] != aggregate["evidence_input_digest"]:
        raise EvidenceBlocked("same-run aggregate receipt is stale relative to the collector evidence-input digest")
    aggregate_identity = exact_keys(receipt["aggregate_report"], {"path", "sha256"}, "same-run aggregate output identity")
    if aggregate_identity != {"path": aggregate_relative, "sha256": current_digest}:
        raise EvidenceBlocked("same-run aggregate receipt does not bind the current collector output bytes")

    command_specs = {
        "collector": (
            "aggregate-samples.log",
            "cargo --locked --offline run -p fluxform-capabilities --bin collect_sample_reports",
        ),
        "verify_manifest": (
            "aggregate-samples-manifest.log",
            "cargo --locked --offline run -p fluxform-capabilities --bin verify_manifest",
        ),
        "cross_platform_samples": (
            "aggregate-samples-cross-platform.log",
            "cargo --locked --offline test -p fluxform-capabilities --test cross_platform_samples",
        ),
    }
    commands = exact_keys(receipt["commands"], set(command_specs), "same-run aggregate command receipts")
    required_log_fragments = {
        "collector": ("--input target/stage0/collected", "--manifest config/capabilities-v1.toml", "--samples testdata/media/v1/samples.toml", "--expected-input-digest", "--out"),
        "verify_manifest": ("verify-manifest --manifest config/capabilities-v1.toml", "--reports", "collected-profiles"),
        "cross_platform_samples": ("--test cross_platform_samples",),
    }
    expected_command_values = {
        "collector": "collect_sample_reports",
        "verify_manifest": "verify_manifest verify-manifest",
        "cross_platform_samples": "cross_platform_samples",
    }
    expected_files: dict[str, str] = {
        "config/capabilities-v1.toml": source_digests["manifest_digest"],
        "testdata/media/v1/samples.toml": source_digests["catalog_digest"],
        aggregate_relative: current_digest,
    }
    for sample in samples.values():
        sample_relative = f"testdata/media/v1/{sample['path']}"
        expected_files[sample_relative] = _pinned_repository_digest(repo_root, sample_relative, "tracked sample corpus file")
    for target_id in SAMPLE_TARGETS:
        for filename in ("ffmpeg-profile-report.json", "sample-report.json", "provenance.json"):
            relative = f"target/stage0/collected/{target_id}/{filename}"
            expected_files[relative] = _pinned_repository_digest(repo_root, relative, "same-run collected native artifact")
        collected_profile_relative = f"target/stage0/collected/{target_id}/ffmpeg-profile-report.json"
        copied_profile_relative = f"target/stage0/runs/{run_id}/collected-profiles/{target_id}.json"
        collected_profile_digest = expected_files[collected_profile_relative]
        copied_profile_digest = _pinned_repository_digest(repo_root, copied_profile_relative, "same-run collected profile copy")
        if copied_profile_digest != collected_profile_digest:
            raise EvidenceBlocked(f"{target_id} verify_manifest profile copy differs from the collector input")
        expected_files[copied_profile_relative] = copied_profile_digest
    for command_id, (filename, prefix) in command_specs.items():
        log_relative = f"target/stage0/runs/{run_id}/{filename}"
        log_digest = _pinned_repository_digest(repo_root, log_relative, f"same-run {command_id} log")
        expected_files[log_relative] = log_digest
        command = exact_keys(commands[command_id], {"command", "path", "sha256", "exit_code"}, f"same-run {command_id} command receipt")
        if type(command["exit_code"]) is not int or command["exit_code"] != 0:
            raise EvidenceBlocked(f"same-run {command_id} exit code is not an integer zero")
        if command != {
            "command": expected_command_values[command_id],
            "path": log_relative,
            "sha256": log_digest,
            "exit_code": 0,
        }:
            raise EvidenceBlocked(f"same-run {command_id} command receipt is stale or did not exit successfully")
        log_path = safe_file(repo_root, safe_relative_path(log_relative), f"same-run {command_id} log")
        log_bytes, _digest, _identity = _read_pinned_bytes(log_path, f"same-run {command_id} log", repo_root)
        try:
            lines = log_bytes.decode("utf-8", errors="strict").splitlines()
        except UnicodeError as error:
            raise EvidenceBlocked(f"same-run {command_id} log is not UTF-8") from error
        invocation = lines[0].removeprefix("+ ") if lines else ""
        if not invocation.startswith(prefix) or not lines or lines[-1] != "exit_code=0":
            raise EvidenceBlocked(f"same-run {command_id} log does not prove its exact successful tool invocation")
        if any(fragment not in invocation for fragment in required_log_fragments[command_id]):
            raise EvidenceBlocked(f"same-run {command_id} log omits required collector/verification arguments")
        if command_id == "collector" and (aggregate["evidence_input_digest"] not in invocation or "aggregate-sample-report.json" not in invocation or run_id not in invocation):
            raise EvidenceBlocked("same-run collector log targets another input digest or run output")
        if command_id == "verify_manifest" and run_id not in invocation:
            raise EvidenceBlocked("same-run verify_manifest log targets another invocation")

    file_records = receipt["files"]
    if not isinstance(file_records, list):
        raise EvidenceBlocked("same-run aggregate receipt file closure is malformed")
    normalized_files = []
    for item in file_records:
        item = exact_keys(item, {"path", "sha256"}, "same-run aggregate receipt file")
        relative = safe_relative_path(item["path"])
        normalized_files.append({"path": relative.as_posix(), "sha256": item["sha256"]})
    normalized_files.sort(key=lambda item: item["path"])
    expected_records = [{"path": path, "sha256": digest} for path, digest in sorted(expected_files.items())]
    if normalized_files != expected_records:
        raise EvidenceBlocked("same-run aggregate receipt does not bind the exact current collector/manifest/catalog/profile/log file closure")
    if receipt["closure_digest"] != _serialized_sha256(expected_records):
        raise EvidenceBlocked("same-run aggregate receipt closure digest is stale")


def validate_bundle(repo_root: Path, references: list[tuple[int, str, str, str, str, str, PurePosixPath]], attestation: dict, aggregate_report_path: Path | None) -> None:
    loaded = []
    result_paths: set[str] = set()
    result_path_keys: set[str] = set()
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
        role_digests = {}
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
            if key_path in result_path_keys or digest in result_digests:
                raise EvidenceBlocked("a raw result file is reused across report rows")
            result_path_keys.add(key_path)
            result_paths.add(raw_relative.as_posix())
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
            role_digests[role] = actual_digest
        if set(role_documents) != set(expected_roles):
            raise EvidenceBlocked(f"evidence row {number} does not contain every required raw-result role")
        artifacts = manifest["artifact_identities"]
        if not isinstance(artifacts, dict):
            raise EvidenceBlocked(f"evidence row {number} artifact identities must be a typed object")
        primary_role = "primary" if number == 1 else "probe-report" if number in PROFILE_TARGETS else "approval-record" if number == 6 else "aggregate-report" if number == 7 else "window-result"
        primary = role_documents[primary_role]
        validate_semantics(repo_root, number, primary, artifacts, role_documents, attestation, role_digests, aggregate_report_path)
        loaded.append(number)

    attested_paths = {item["path"] for item in attestation["files"]}
    if manifest_paths | result_paths != attested_paths:
        raise EvidenceBlocked("same-run attestation file closure does not exactly match all row manifests and raw result files")
    if 7 in loaded:
        if aggregate_report_path is None:
            raise EvidenceBlocked("current collector output is required to prove the sample evidence-input closure")
        current_path = Path(os.path.abspath(aggregate_report_path))
        current, current_digest, _identity = read_pinned_json(current_path, "current collector aggregate output", repo_root)
        aggregate_descriptor = next(reference for reference in references if reference[0] == 7)
        manifest_path = safe_file(repo_root, aggregate_descriptor[6], "row 7 manifest")
        manifest, _manifest_sha, _ = read_pinned_json(manifest_path, "row 7 manifest", repo_root)
        report_info = next(item for item in manifest["raw_results"] if item["role"] == "aggregate-report")
        raw_path = safe_file(repo_root, safe_relative_path(report_info["path"]), "row 7 aggregate raw result")
        recorded, recorded_digest, _ = read_pinned_json(raw_path, "row 7 aggregate raw result", repo_root)
        if current != recorded or current_digest != recorded_digest:
            raise EvidenceBlocked("row 7 reviewed aggregate raw bytes are stale relative to the collector run in this Complete invocation")


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
