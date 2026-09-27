"""Focused regression tests for Stage 0 evidence parsing and semantics."""

from __future__ import annotations

import hashlib
import tomllib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_stage0_report as validator


class Stage0EvidenceParserTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaises(validator.EvidenceBlocked):
            validator.loads_unique_json(b'{"schema":"good","schema":"evil"}', "fixture")

    def test_row_one_fails_when_failed_count_is_nonzero(self) -> None:
        result = {
            "schema": "fluxform.stage0.protocol-contract-run.v1",
            "row_id": 1,
            "label": validator.LABELS[0],
            "evidence_kind": validator.KINDS[0],
            "status": "PASS",
            "command": "cargo test --locked --offline -p fluxform-protocol --test contracts",
            "exit_code": 0,
            "passed_tests": 19,
            "failed_tests": 1,
            "compatibility_digest": "0" * 64,
            "compatibility_file_sha256": "0" * 64,
            "stdout_summary": "test result: ok. 19 passed; 0 failed",
            "artifact_identities": {},
        }
        with self.assertRaisesRegex(validator.EvidenceBlocked, "failed_tests"):
            validator.validate_semantics(Path.cwd(), 1, result, [])

    def test_pinned_json_digest_and_document_come_from_the_same_bytes(self) -> None:
        original = b'{"schema":"pinned","row_id":1}'
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "result.json"
            path.write_bytes(original)
            document, digest, _identity = validator.read_pinned_json(path, "fixture", Path(directory))
            path.write_bytes(b'{"schema":"replacement","row_id":1}')

        self.assertEqual(document["schema"], "pinned")
        self.assertEqual(digest, hashlib.sha256(original).hexdigest())

    def test_unique_json_load_rejects_duplicate_nested_keys(self) -> None:
        with self.assertRaises(validator.EvidenceBlocked):
            validator.loads_unique_json(b'{"outer":{"status":"PASS","status":"FAIL"}}', "fixture")

    def test_valid_protocol_result_binds_the_tracked_compatibility_file(self) -> None:
        root = Path.cwd()
        path = root / "contracts/v1/compatibility.sha256"
        content = path.read_bytes()
        file_sha = hashlib.sha256(content).hexdigest()
        expected_digest = content.decode("ascii").strip()
        artifacts = {"compatibility-file": {"path": "contracts/v1/compatibility.sha256", "sha256": file_sha}}
        result = {
            "schema": validator.ROW_RESULT_SCHEMAS[1]["primary"],
            "row_id": 1,
            "label": validator.LABELS[0],
            "evidence_kind": validator.KINDS[0],
            "status": "PASS",
            "command": "cargo test --locked --offline -p fluxform-protocol --test contracts",
            "exit_code": 0,
            "passed_tests": 19,
            "failed_tests": 0,
            "stdout_summary": "test result: ok. 19 passed; 0 failed",
            "compatibility_digest": expected_digest,
            "compatibility_file_sha256": file_sha,
            "artifact_identities": artifacts,
        }
        validator.validate_semantics(root, 1, result, artifacts)

    def test_profile_row_requires_approved_immutable_profile_and_license(self) -> None:
        root = Path.cwd()
        profile = tomllib.loads((root / "config/ffmpeg-profile.toml").read_text(encoding="utf-8"))
        artifact = next(item for item in profile["artifacts"] if item["target_triple"] == "x86_64-pc-windows-msvc")
        report = {
            "profile_id": profile["profile_id"],
            "profile_digest": "a" * 64,
            "distribution_gate_status": "approved",
            "artifact_id": artifact["artifact_id"],
            "artifact_status": "approved",
            "archive_format": artifact["archive_format"],
            "artifact_uri": artifact["artifact_uri"],
            "artifact_sha256": artifact["artifact_sha256"],
            "artifact_size_bytes": artifact["artifact_size_bytes"],
            "target_triple": artifact["target_triple"],
            "ffmpeg_sha256": artifact["ffmpeg_sha256"],
            "ffmpeg_size_bytes": artifact["ffmpeg_size_bytes"],
            "ffprobe_sha256": artifact["ffprobe_sha256"],
            "ffprobe_size_bytes": artifact["ffprobe_size_bytes"],
            "version": "ffmpeg version fixture",
            "ffprobe_version": "ffprobe version fixture",
            "source_revision": artifact["source_revision"],
            "source_offer_url": artifact["source_offer_url"],
            "source_revision_reported_by_binary": None,
            "build_configuration": "fixture",
            "license_declaration": profile["license_declaration"],
            "license_text_path": artifact["license_text_path"],
            "license_text_sha256": artifact["license_text_sha256"],
            "license_text_size_bytes": artifact["license_text_size_bytes"],
            "approval_record_id": "fixture-approved-record",
            "approval_date": "2026-09-28",
            "protocols": ["file", "pipe"],
            "demuxers": ["mov"],
            "muxers": ["mp4"],
            "decoders": ["aac", "h264"],
            "encoders": ["aac", "libx264"],
        }
        with self.assertRaisesRegex(validator.EvidenceBlocked, "immutable profile identity"):
            validator.validate_semantics(root, 2, report, {})

    def test_product_approval_result_matches_both_tracked_records(self) -> None:
        root = Path.cwd()
        adr = "docs/architecture/adr/0002-v1-capability-matrix.md"
        approval = ".superpowers/sdd/2026-09-25-fluxform-stage-0-feasibility/task-5-product-approval.md"
        adr_identity = validator._tracked_identity(root, adr)
        approval_identity = validator._tracked_identity(root, approval)
        artifacts = {"capability-matrix-adr": adr_identity, "product-approval-record": approval_identity}
        text = (root / adr).read_text(encoding="utf-8")
        matrix = __import__("re").search(r"<!-- matrix-json-v1:begin -->\s*```json\s*(.*?)\s*```", text, __import__("re").S).group(1).encode("utf-8")
        result = {
            "schema": validator.ROW_RESULT_SCHEMAS[6]["approval-record"],
            "row_id": 6,
            "label": validator.LABELS[5],
            "evidence_kind": validator.KINDS[5],
            "status": "PASS",
            "approval_text": "批准",
            "enabled_edge_count": 3,
            "deferred_edge_count": 126,
            "matrix_sha256": hashlib.sha256(matrix).hexdigest(),
            "approval_record_sha256": approval_identity["sha256"],
            "artifact_identities": artifacts,
        }
        validator.validate_semantics(root, 6, result, artifacts)

    def test_valid_windows_window_probe_result_binds_both_package_identities(self) -> None:
        artifacts = {
            "installer-package": {"sha256": "a" * 64},
            "installed-executable": {"sha256": "b" * 64},
        }
        result = {field: False for field in validator.WINDOW_RESULT_FIELDS}
        result.update({
            "probe_mode": "transparent-orb",
            "os": "windows",
            "os_version": "Windows 11 fixture",
            "display_server": "DWM",
            "installed_artifact_sha256": "a" * 64,
            "installed_executable_sha256": "b" * 64,
            "install_identity": "fixture-user-install",
            "provenance_verified": True,
            "provenance_error": None,
            "installed_launch_path": "C:/Program Files/FluxForm/FluxForm.exe",
            "native_hit_region_supported": True,
            "input_hit_region_status": "supported",
            "network_disconnected": True,
            "first_launch_succeeded": True,
            "transparent_pixels_visible": True,
            "transparent_pixels_click_through": True,
            "frameless_drag_works": True,
            "file_drop_works": True,
            "outside_orb_drop_reached_background_target": True,
            "outside_orb_drop_reached_fluxform": False,
            "focus_recovery_works": True,
            "keyboard_input_works": True,
            "repeated_launch_created_second_window": True,
            "repeated_launch_backend_process_count": 1,
            "single_window_close_works": True,
            "last_window_close_works": True,
            "dpi_change_works": True,
            "multi_monitor_move_works": True,
            "idle_cpu_percent": 0.0,
            "idle_gpu_percent": 0.0,
            "notes": "reviewed fixture",
            "passed": True,
            "webview_helper_process_count": 1,
        })
        validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_windows_window_probe_rejects_string_boolean_claim(self) -> None:
        result = {field: False for field in validator.WINDOW_RESULT_FIELDS}
        result.update({
            "probe_mode": "transparent-orb",
            "os": "windows",
            "installed_artifact_sha256": "a" * 64,
            "installed_executable_sha256": "b" * 64,
            "repeated_launch_backend_process_count": 1,
            "webview_helper_process_count": 1,
            "provenance_verified": True,
            "passed": True,
            "network_disconnected": "true",
            "first_launch_succeeded": True,
        })
        with self.assertRaisesRegex(validator.EvidenceBlocked, "non-boolean"):
            validator.validate_semantics(Path.cwd(), 16, result, {
                "installer-package": {"sha256": "a" * 64},
                "installed-executable": {"sha256": "b" * 64},
            })

    def test_kind_without_authoritative_result_schema_is_blocked(self) -> None:
        with self.assertRaisesRegex(validator.EvidenceBlocked, "no authoritative machine-readable source schema"):
            validator.validate_semantics(Path.cwd(), 8, {"result": "PASS"}, {})


if __name__ == "__main__":
    unittest.main()
