"""Focused regression tests for Stage 0 evidence parsing and semantics."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import validate_stage0_report as validator
import stage0_json
import write_stage0_aggregate_receipt as aggregate_receipts


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rust_edge_sha256(edge: dict) -> str:
    fields = (
        "id", "category", "input_extensions", "input_demuxers", "input_codecs", "input_topology",
        "output_format", "output_muxer", "video_codec", "audio_codec", "stream_map", "alpha_policy",
        "orientation_policy", "metadata_policy", "profile_ids", "valid_samples", "invalid_samples", "options",
    )
    normalized = {}
    for field in fields:
        if field == "options":
            normalized[field] = {
                name: {key: edge["options"][name][key] for key in ("minimum", "maximum", "default")}
                for name in sorted(edge.get("options", {}))
            }
        else:
            normalized[field] = edge.get(field)
    data = json.dumps(normalized, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return _sha256(data)


def _expected_output(edge: dict, sample: dict) -> dict:
    codecs = []
    for field in ("video_codec", "audio_codec"):
        codec = edge.get(field)
        if codec is not None:
            codecs.append({"libx264": "h264", "libx265": "hevc", "libmp3lame": "mp3"}.get(codec.lower(), codec))
    options = edge.get("options", {})
    edge_duration = options.get("max_duration_seconds", {}).get("default", 3600) * 1000
    sample_duration = sample["duration_ms"] + 100 if sample["duration_ms"] else edge_duration
    return {
        "container": edge["output_format"],
        "codecs": codecs,
        "stream_topology": {"audio": "single_audio_stream", "image": "single_video_frame", "video": "single_video_stream"}[edge["category"]],
        "width": sample["width"],
        "height": sample["height"],
        "max_width": options.get("max_width", {}).get("default", 4096),
        "max_height": options.get("max_height", {}).get("default", 4096),
        "expected_duration_ms": sample["duration_ms"],
        "duration_tolerance_ms": 100,
        "max_duration_ms": min(edge_duration, sample_duration),
        "alpha_policy": edge["alpha_policy"],
        "orientation_policy": edge["orientation_policy"],
        "metadata_policy": edge["metadata_policy"],
    }


def _sample_result_fixture(edge: dict, sample: dict) -> dict:
    expectations = _expected_output(edge, sample)
    expectation_sha = _sha256(json.dumps(expectations, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    animated = sample["id"] in {"image-gif-animated-v1", "image-webp-animated-v1", "image-tiff-multipage-v1"}
    observed_input = {
        "format_name": sample["container"],
        "codecs": sample["codecs"],
        "stream_topology": sample["stream_topology"],
        "width": sample["width"],
        "height": sample["height"],
        "duration_ms": sample["duration_ms"],
        "alpha_present": sample["alpha"] == "present",
        "orientation_present": sample["orientation"] == "present",
        "metadata_keys": [],
        "frame_count": 2 if animated else 1,
    }
    successful = sample["expected_outcome"] == "success"
    observed_output = None
    if successful:
        observed_output = {
            **observed_input,
            "format_name": expectations["container"],
            "codecs": expectations["codecs"],
            "stream_topology": expectations["stream_topology"],
            "alpha_present": sample["alpha"] == "present" and edge["alpha_policy"] == "preserve_if_present",
            "orientation_present": False,
            "frame_count": 1,
        }
    return {
        "edge_id": edge["id"],
        "edge_spec_digest": _rust_edge_sha256(edge),
        "sample_id": sample["id"],
        "sample_sha256": sample["sha256"],
        "expected_outcome": sample["expected_outcome"],
        "expected_error_code": sample["expected_error_code"],
        "status": "passed",
        "actual_error_code": "" if successful else sample["expected_error_code"],
        "diagnostic": "fixture observation",
        "ffprobe_arguments": ["-v", "error", "-show_streams"],
        "ffmpeg_arguments": ["-hide_banner", "-nostdin", "-v", "error"],
        "ffmpeg_invoked": successful,
        "output_expectations": expectations,
        "output_expectations_digest": expectation_sha,
        "observed_input": observed_input,
        "observed_output": observed_output,
    }


def _refresh_attestation(root: Path, attestation: dict, bundle_path: Path) -> None:
    paths = [bundle_path, *(root / item["path"] for item in attestation["files"] if item["path"] != bundle_path.relative_to(root).as_posix())]
    unique = {path.relative_to(root).as_posix(): path for path in paths}
    files = [{"path": name, "sha256": _sha256(path.read_bytes())} for name, path in sorted(unique.items())]
    attestation["files"] = files
    attestation["closure_digest"] = _sha256(_canonical_json(files))


def _row7_fixture(root: Path) -> dict:
    bundle_id = "review-bundle"
    bundle = root / "target/stage0/reviewed-evidence" / bundle_id
    run_root = root / "target/stage0/runs/aggregate-fixture"
    collected = root / "target/stage0/collected"
    manifest_file = root / "config/capabilities-v1.toml"
    catalog_file = root / "testdata/media/v1/samples.toml"
    corpus_dir = root / "testdata/media/v1/files"
    bundle.mkdir(parents=True)
    run_root.mkdir(parents=True)
    collected.mkdir(parents=True)
    manifest_file.parent.mkdir(parents=True)
    catalog_file.parent.mkdir(parents=True)
    corpus_dir.mkdir(parents=True)
    source_root = Path(__file__).resolve().parent.parent
    manifest_file.write_bytes((source_root / "config/capabilities-v1.toml").read_bytes())
    catalog_file.write_bytes((source_root / "testdata/media/v1/samples.toml").read_bytes())
    for source in (source_root / "testdata/media/v1/files").iterdir():
        (corpus_dir / source.name).write_bytes(source.read_bytes())

    commit = "c" * 40
    run_id = "workflow-run-123"
    input_digest = "d" * 64
    manifest_digest = _sha256(manifest_file.read_bytes())
    catalog_digest = _sha256(catalog_file.read_bytes())
    targets = {
        "windows-x86_64": ("x86_64-pc-windows-msvc", "windows", "x86_64"),
        "macos-x86_64": ("x86_64-apple-darwin", "macos", "x86_64"),
        "macos-aarch64": ("aarch64-apple-darwin", "macos", "aarch64"),
        "linux-x86_64": ("x86_64-unknown-linux-gnu", "linux", "x86_64"),
    }
    documents: dict[str, dict] = {}
    raw_entries: list[dict] = []
    collected_summaries = []
    for target_id, (triple, runner_os, runner_arch) in targets.items():
        artifact_id = f"fixture-{target_id}"
        profile = {field: None for field in validator.PROBE_REPORT_FIELDS}
        profile.update({
            "profile_id": "fluxform-ffmpeg-v1",
            "profile_digest": "e" * 64,
            "distribution_gate_status": "approved",
            "artifact_id": artifact_id,
            "artifact_status": "approved",
            "archive_format": "zip32",
            "artifact_uri": f"https://artifacts.invalid/{target_id}.zip",
            "artifact_sha256": "1" * 64,
            "artifact_size_bytes": 100,
            "target_triple": triple,
            "ffmpeg_sha256": "2" * 64,
            "ffmpeg_size_bytes": 200,
            "ffprobe_sha256": "3" * 64,
            "ffprobe_size_bytes": 300,
            "version": "ffmpeg fixture",
            "ffprobe_version": "ffprobe fixture",
            "source_revision": "fixture-revision",
            "source_offer_url": "https://artifacts.invalid/source",
            "source_revision_reported_by_binary": None,
            "build_configuration": "fixture",
            "license_declaration": "GPL v3",
            "license_text_path": "LICENSE",
            "license_text_sha256": "4" * 64,
            "license_text_size_bytes": 10,
            "approval_record_id": "fixture-approval",
            "approval_date": "2026-09-28",
            "protocols": ["file", "pipe"],
            "demuxers": ["mov"],
            "muxers": ["mp4"],
            "decoders": ["aac", "h264"],
            "encoders": ["aac", "libx264"],
        })
        sample = {
            "schema": "fluxform.sample-run.v1",
            "status": "passed",
            "evidence_input_digest": input_digest,
            "manifest_digest": manifest_digest,
            "sample_catalog_digest": catalog_digest,
            "git_commit": commit,
            "runner_os": runner_os,
            "runner_arch": runner_arch,
            "profile_id": profile["profile_id"],
            "target_profile_id": target_id,
            "target_triple": triple,
            "artifact_id": artifact_id,
            "profile_digest": profile["profile_digest"],
            "ffmpeg_sha256": profile["ffmpeg_sha256"],
            "ffprobe_sha256": profile["ffprobe_sha256"],
            "blockers": [],
            "results": [],
        }
        sample["manifest_digest"] = manifest_digest
        sample["sample_catalog_digest"] = catalog_digest
        manifest_document = tomllib.loads(manifest_file.read_text(encoding="utf-8"))
        catalog_document = tomllib.loads(catalog_file.read_text(encoding="utf-8"))
        catalog_samples = {item["id"]: item for item in catalog_document["samples"]}
        sample["results"] = [
            _sample_result_fixture(edge, catalog_samples[sample_id])
            for edge in manifest_document["edges"]
            for sample_id in edge["valid_samples"] + edge["invalid_samples"]
        ]
        sample["results"].sort(key=lambda item: (item["edge_id"], item["sample_id"]))
        profile_bytes = _canonical_json(profile)
        sample_bytes = _canonical_json(sample)
        profile_sha = _sha256(profile_bytes)
        sample_sha = _sha256(sample_bytes)
        provenance = {
            "schema": "fluxform.native-sample-artifact.v1",
            "artifact_name": f"stage0-samples-{target_id}-{input_digest}",
            "target_profile_id": target_id,
            "target_triple": triple,
            "runner_os": runner_os,
            "runner_arch": runner_arch,
            "git_commit": commit,
            "evidence_input_digest": input_digest,
            "workflow_run_id": run_id,
            "workflow_job_id": f"job-{target_id}",
            "ffmpeg_profile_report_sha256": profile_sha,
            "sample_report_sha256": sample_sha,
            "manual_reviewer": None,
            "transfer_sha256": None,
        }
        provenance_bytes = _canonical_json(provenance)
        documents[f"profile-report-{target_id}"] = profile
        documents[f"sample-report-{target_id}"] = sample
        documents[f"provenance-{target_id}"] = provenance
        for role, data, document in (
            (f"profile-report-{target_id}", profile_bytes, profile),
            (f"sample-report-{target_id}", sample_bytes, sample),
            (f"provenance-{target_id}", provenance_bytes, provenance),
        ):
            path = f"target/stage0/reviewed-evidence/{bundle_id}/row-07-{role}.json"
            (root / path).write_bytes(data)
            raw_entries.append({
                "role": role, "path": path, "sha256": _sha256(data), "type": "application/json",
                "schema": validator.ROW_RESULT_SCHEMAS[7][role], "row_id": 7,
            })
        target_collected = collected / target_id
        target_collected.mkdir()
        (target_collected / "ffmpeg-profile-report.json").write_bytes(profile_bytes)
        (target_collected / "sample-report.json").write_bytes(sample_bytes)
        (target_collected / "provenance.json").write_bytes(provenance_bytes)
        collected_summaries.append({
            "target_profile_id": target_id,
            "target_triple": triple,
            "artifact_id": artifact_id,
            "git_commit": commit,
            "profile_report_sha256": profile_sha,
            "sample_report_sha256": sample_sha,
            "sample_result_count": 9,
            "native_runner_os": runner_os,
            "native_runner_arch": runner_arch,
        })

    aggregate = {
        "schema": "fluxform.sample-aggregate.v1", "status": "passed",
        "evidence_input_digest": input_digest, "targets": collected_summaries,
    }
    aggregate_bytes = _canonical_json(aggregate)
    documents["aggregate-report"] = aggregate
    aggregate_relative = "target/stage0/reviewed-evidence/review-bundle/row-07-aggregate-report.json"
    (root / aggregate_relative).write_bytes(aggregate_bytes)
    raw_entries.append({
        "role": "aggregate-report", "path": aggregate_relative, "sha256": _sha256(aggregate_bytes),
        "type": "application/json", "schema": validator.ROW_RESULT_SCHEMAS[7]["aggregate-report"], "row_id": 7,
    })
    raw_entries.sort(key=lambda item: item["role"])
    manifest = {
        "schema": "fluxform.stage0.reviewed-row-manifest.v2", "bundle_id": bundle_id,
        "row_id": 7, "label": validator.LABELS[6], "status": "PASS", "evidence_kind": validator.KINDS[6],
        "platform": validator.PLATFORMS[6], "date": "2026-09-28",
        "reviewer": {"identity": "Reviewer One", "reviewed_at": "2026-09-28T00:00:00Z"},
        "review_state": "reviewed", "artifact_identities": {}, "raw_results": raw_entries,
    }
    manifest_rel = "target/stage0/reviewed-evidence/review-bundle/row-07.manifest.json"
    manifest_path = root / manifest_rel
    manifest_path.write_bytes(_canonical_json(manifest))
    manifest_sha = _sha256(manifest_path.read_bytes())
    reference = (7, validator.LABELS[6], f"{validator.PLATFORMS[6]}; 2026-09-28; Reviewer One", manifest_sha, bundle_id, "row-7-key", Path(manifest_rel))

    aggregate_path = run_root / "aggregate-sample-report.json"
    aggregate_path.write_bytes(aggregate_bytes)
    command_logs = {
        "collector": "aggregate-samples.log",
        "verify_manifest": "aggregate-samples-manifest.log",
        "cross_platform_samples": "aggregate-samples-cross-platform.log",
    }
    log_contents = {
        "collector": f"cargo --locked --offline run -p fluxform-capabilities --bin collect_sample_reports -- --input target/stage0/collected --manifest config/capabilities-v1.toml --samples testdata/media/v1/samples.toml --expected-input-digest {input_digest} --out target/stage0/runs/aggregate-fixture/aggregate-sample-report.json\nfluxform.sample-aggregate.v1: passed (4 native targets)\nexit_code=0\n",
        "verify_manifest": "cargo --locked --offline run -p fluxform-capabilities --bin verify_manifest -- verify-manifest --manifest config/capabilities-v1.toml --reports target/stage0/runs/aggregate-fixture/collected-profiles\nManifest identity and capability checks passed for 4 report(s).\nexit_code=0\n",
        "cross_platform_samples": "cargo --locked --offline test -p fluxform-capabilities --test cross_platform_samples\nrunning 1 test\ntest every_approved_native_profile_has_a_current_sample_report ... ok\ntest result: ok. 1 passed; 0 failed\nexit_code=0\n",
    }
    for kind, filename in command_logs.items():
        (run_root / filename).write_text(log_contents[kind], encoding="utf-8")
    for target_id in targets:
        profile_copy = run_root / "collected-profiles" / f"{target_id}.json"
        profile_copy.parent.mkdir(parents=True, exist_ok=True)
        profile_copy.write_bytes((collected / target_id / "ffmpeg-profile-report.json").read_bytes())
    receipt_path = aggregate_receipts.write_receipt(root, aggregate_path, commit)
    attestation_files = [{"path": manifest_rel, "sha256": manifest_sha}]
    attestation_files.extend({"path": item["path"], "sha256": item["sha256"]} for item in raw_entries)
    attestation_files.sort(key=lambda item: item["path"])
    attestation = {
        "schema": "fluxform.stage0.reviewed-evidence-ci-attestation.v1", "bundle_id": bundle_id,
        "workflow_run_id": run_id, "commit_sha": commit, "actor": "reviewer",
        "environment": "stage0-manual-review", "files": attestation_files,
        "closure_digest": _sha256(_canonical_json(attestation_files)),
    }
    return {
        "root": root, "aggregate_path": aggregate_path, "receipt_path": receipt_path,
        "manifest": manifest, "manifest_path": manifest_path, "manifest_relative": manifest_rel,
        "manifest_sha": manifest_sha, "raw_entries": raw_entries, "attestation": attestation,
        "reference": reference, "documents": documents, "commit": commit, "input_digest": input_digest,
        "run_id": run_id,
    }


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
        result, artifacts = self._passing_window_result()
        validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_result_contract_has_all_33_rust_fields(self) -> None:
        result, _artifacts = self._passing_window_result()
        rust_source = (Path(__file__).resolve().parent.parent / "apps/desktop-probe/src-tauri/src/lib.rs").read_text(encoding="utf-8")
        declaration = re.search(r"pub struct WindowProbeResult\s*\{([^}]*)\}", rust_source, re.S)
        self.assertIsNotNone(declaration)
        rust_fields = dict(re.findall(r"^\s*pub (\w+): (\w+),\s*$", declaration.group(1), re.M))
        self.assertEqual(len(rust_fields), 33)
        self.assertEqual(set(rust_fields), validator.WINDOW_RESULT_FIELDS)
        python_fields_by_type = {
            "String": validator.WINDOW_STRING_FIELDS,
            "bool": validator.WINDOW_BOOLEAN_FIELDS,
            "u32": validator.WINDOW_U32_FIELDS,
            "f32": validator.WINDOW_F32_FIELDS,
        }
        for rust_type, python_fields in python_fields_by_type.items():
            self.assertEqual({name for name, field_type in rust_fields.items() if field_type == rust_type}, python_fields)
        self.assertEqual(set(result), validator.WINDOW_RESULT_FIELDS)
        validator.validate_semantics(Path.cwd(), 16, result, {
            "installer-package": {"sha256": result["installed_artifact_sha256"]},
            "installed-executable": {"sha256": result["installed_executable_sha256"]},
        })

    def _passing_window_result(self, mode: str = "transparent-orb") -> tuple[dict, dict]:
        transparent = mode != "opaque-frameless-fallback"
        orb = mode == "transparent-orb"
        status = {
            "transparent-orb": "circular-applied",
            "transparent-window-with-rectangular-hit-region": "rectangular",
            "opaque-frameless-fallback": "opaque",
        }[mode]
        package_sha = "a" * 64
        executable_sha = "b" * 64
        result = {
            "probe_mode": mode, "os": "windows", "os_version": "Windows 11 fixture",
            "display_server": "windows", "installed_artifact_sha256": package_sha,
            "installed_executable_sha256": executable_sha, "install_identity": "fixture-user-install",
            "provenance_verified": True, "provenance_error": "",
            "installed_launch_path": "C:/Program Files/FluxForm/FluxForm.exe",
            "native_hit_region_supported": True, "input_hit_region_status": status,
            "network_disconnected": True, "first_launch_succeeded": True,
            "transparent_pixels_visible": transparent, "transparent_pixels_click_through": orb,
            "frameless_drag_works": True, "file_drop_works": True,
            "outside_orb_drop_reached_background_target": orb,
            "outside_orb_drop_reached_fluxform": not orb, "focus_recovery_works": True,
            "keyboard_input_works": True, "repeated_launch_created_second_window": True,
            "repeated_launch_backend_process_count": 1, "single_window_close_works": True,
            "last_window_close_works": True, "dpi_change_works": True,
            "multi_monitor_move_works": True, "idle_cpu_percent": 0.1, "idle_gpu_percent": 0.2,
            "notes": "reviewed fixture", "passed": True, "webview_helper_process_count": 3,
        }
        artifacts = {
            "installer-package": {"sha256": package_sha},
            "installed-executable": {"sha256": executable_sha},
        }
        return result, artifacts

    def test_window_pass_requires_each_rust_common_behavior_and_native_hit_region(self) -> None:
        required = (
            "frameless_drag_works", "file_drop_works", "focus_recovery_works", "keyboard_input_works",
            "native_hit_region_supported",
        )
        for field in required:
            with self.subTest(field=field):
                result, artifacts = self._passing_window_result()
                result[field] = False
                with self.assertRaises(validator.EvidenceBlocked, msg=f"false {field} was accepted"):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_pass_requires_mode_exact_hit_region_and_drop_behavior(self) -> None:
        for mode, field in (
            ("transparent-orb", "input_hit_region_status"),
            ("transparent-window-with-rectangular-hit-region", "outside_orb_drop_reached_fluxform"),
            ("opaque-frameless-fallback", "transparent_pixels_click_through"),
        ):
            with self.subTest(mode=mode, field=field):
                result, artifacts = self._passing_window_result(mode)
                if field == "input_hit_region_status":
                    result[field] = "rectangular"
                else:
                    result[field] = not result[field]
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_pass_rejects_bad_provenance_display_and_install_identity(self) -> None:
        for field, value in (
            ("os", "  "),
            ("os_version", "\t"),
            ("install_identity", "../outside"),
            ("display_server", "DWM"),
            ("installed_executable_sha256", "g" * 64),
            ("installed_artifact_sha256", "a" * 63),
            ("installed_launch_path", " "),
            ("input_hit_region_status", "supported"),
        ):
            with self.subTest(field=field):
                result, artifacts = self._passing_window_result()
                result[field] = value
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_pass_rejects_nonfinite_negative_and_non_numeric_idle_metrics(self) -> None:
        for field, value in (
            ("idle_cpu_percent", float("nan")),
            ("idle_cpu_percent", float("inf")),
            ("idle_gpu_percent", -0.01),
            ("idle_gpu_percent", "0.1"),
        ):
            with self.subTest(field=field, value=value):
                result, artifacts = self._passing_window_result()
                result[field] = value
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_pass_rejects_invalid_helper_process_counts(self) -> None:
        for value in (-1, "3", 2**32, True):
            with self.subTest(value=value):
                result, artifacts = self._passing_window_result()
                result["webview_helper_process_count"] = value
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)

        result, artifacts = self._passing_window_result()
        result["webview_helper_process_count"] = 257
        validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_pass_rejects_rust_field_type_and_f32_range_mismatches(self) -> None:
        boolean_fields = (
            "provenance_verified", "native_hit_region_supported", "network_disconnected",
            "first_launch_succeeded", "transparent_pixels_visible", "transparent_pixels_click_through",
            "frameless_drag_works", "file_drop_works", "outside_orb_drop_reached_background_target",
            "outside_orb_drop_reached_fluxform", "focus_recovery_works", "keyboard_input_works",
            "repeated_launch_created_second_window", "single_window_close_works", "last_window_close_works",
            "dpi_change_works", "multi_monitor_move_works", "passed",
        )
        string_fields = (
            "probe_mode", "os", "os_version", "display_server", "installed_artifact_sha256",
            "installed_executable_sha256", "install_identity", "provenance_error",
            "installed_launch_path", "input_hit_region_status", "notes",
        )
        for field in boolean_fields:
            with self.subTest(field=field):
                result, artifacts = self._passing_window_result()
                result[field] = "true"
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)
        for field in string_fields:
            with self.subTest(field=field):
                result, artifacts = self._passing_window_result()
                result[field] = None
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)
        for field in ("repeated_launch_backend_process_count", "webview_helper_process_count"):
            for value in (False, -1, 2**32, "1"):
                with self.subTest(field=field, value=value):
                    result, artifacts = self._passing_window_result()
                    result[field] = value
                    with self.assertRaises(validator.EvidenceBlocked):
                        validator.validate_semantics(Path.cwd(), 16, result, artifacts)
        for field, value in (
            ("idle_cpu_percent", True),
            ("idle_gpu_percent", "0.1"),
            ("idle_cpu_percent", -0.01),
            ("idle_gpu_percent", float("nan")),
            ("idle_cpu_percent", float("inf")),
            ("idle_gpu_percent", 3.5e38),
        ):
            with self.subTest(field=field, value=value):
                result, artifacts = self._passing_window_result()
                result[field] = value
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_window_pass_uses_rust_provenance_error_field_as_text_only(self) -> None:
        result, artifacts = self._passing_window_result()
        result["provenance_error"] = "historical diagnostic retained by the probe"
        validator.validate_semantics(Path.cwd(), 16, result, artifacts)

    def test_row7_complete_raw_bundle_accepts_current_same_run_tool_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _row7_fixture(Path(directory))
            with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
            }):
                validator.validate_bundle(fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"])

    def test_row7_rejects_replaced_provenance_after_descriptor_updates(self) -> None:
        target_id = "windows-x86_64"
        replacements = {
            "artifact_name": "stage0-samples-linux-x86_64-" + "d" * 64,
            "target_profile_id": "macos-x86_64",
            "target_triple": "x86_64-unknown-linux-gnu",
            "runner_os": "linux",
            "runner_arch": "aarch64",
            # This otherwise-valid job ID mutation specifically exercises receipt-byte binding.
            "workflow_job_id": "another-nonempty-job",
        }
        for field, value in replacements.items():
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                fixture = _row7_fixture(Path(directory))
                provenance = dict(fixture["documents"][f"provenance-{target_id}"])
                provenance[field] = value
                raw_entry = next(
                    item for item in fixture["raw_entries"]
                    if item["role"] == f"provenance-{target_id}"
                )
                raw_path = fixture["root"] / raw_entry["path"]
                raw_bytes = _canonical_json(provenance)
                raw_path.write_bytes(raw_bytes)
                raw_entry["sha256"] = _sha256(raw_bytes)
                fixture["manifest_path"].write_bytes(_canonical_json(fixture["manifest"]))
                manifest_sha = _sha256(fixture["manifest_path"].read_bytes())
                fixture["reference"] = (*fixture["reference"][:3], manifest_sha, *fixture["reference"][4:])
                _refresh_attestation(fixture["root"], fixture["attestation"], fixture["manifest_path"])
                with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                    "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                    "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
                }):
                    with self.assertRaises(validator.EvidenceBlocked):
                        validator.validate_bundle(
                            fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"]
                        )

    def test_row7_rejects_replaced_raw_bytes_even_when_descriptor_hash_is_updated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _row7_fixture(Path(directory))
            sample_entry = next(item for item in fixture["raw_entries"] if item["role"] == "sample-report-windows-x86_64")
            sample_path = fixture["root"] / sample_entry["path"]
            sample_path.write_bytes(sample_path.read_bytes() + b" ")
            sample_entry["sha256"] = _sha256(sample_path.read_bytes())
            fixture["manifest_path"].write_bytes(_canonical_json(fixture["manifest"]))
            new_manifest_sha = _sha256(fixture["manifest_path"].read_bytes())
            fixture["reference"] = (*fixture["reference"][:3], new_manifest_sha, *fixture["reference"][4:])
            _refresh_attestation(fixture["root"], fixture["attestation"], fixture["manifest_path"])
            with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
            }):
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_bundle(fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"])

    def test_row7_requires_reviewed_aggregate_raw_sha_to_match_current_collector_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _row7_fixture(Path(directory))
            aggregate_entry = next(item for item in fixture["raw_entries"] if item["role"] == "aggregate-report")
            aggregate_raw_path = fixture["root"] / aggregate_entry["path"]
            aggregate_raw_path.write_bytes(aggregate_raw_path.read_bytes() + b" ")
            aggregate_entry["sha256"] = _sha256(aggregate_raw_path.read_bytes())
            fixture["manifest_path"].write_bytes(_canonical_json(fixture["manifest"]))
            new_manifest_sha = _sha256(fixture["manifest_path"].read_bytes())
            fixture["reference"] = (*fixture["reference"][:3], new_manifest_sha, *fixture["reference"][4:])
            _refresh_attestation(fixture["root"], fixture["attestation"], fixture["manifest_path"])
            with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
            }):
                with self.assertRaisesRegex(validator.EvidenceBlocked, "reviewed aggregate raw bytes"):
                    validator.validate_bundle(fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"])

    def test_row7_requires_successful_same_run_cross_platform_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _row7_fixture(Path(directory))
            receipt = json.loads(fixture["receipt_path"].read_bytes())
            receipt["commands"]["cross_platform_samples"]["exit_code"] = 1
            fixture["receipt_path"].write_bytes(_canonical_json(receipt))
            with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
            }):
                with self.assertRaises(validator.EvidenceBlocked):
                    validator.validate_bundle(fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"])

    def test_row7_rejects_boolean_command_exit_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _row7_fixture(Path(directory))
            receipt = json.loads(fixture["receipt_path"].read_bytes())
            receipt["commands"]["cross_platform_samples"]["exit_code"] = False
            fixture["receipt_path"].write_bytes(_canonical_json(receipt))
            with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
            }):
                with self.assertRaisesRegex(validator.EvidenceBlocked, "exit code is not an integer zero"):
                    validator.validate_bundle(fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"])

    def test_row7_rejects_profile_copy_that_differs_from_collector_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture = _row7_fixture(Path(directory))
            relative = f"target/stage0/runs/{fixture['aggregate_path'].parent.name}/collected-profiles/linux-x86_64.json"
            copied_profile = fixture["root"] / relative
            copied_profile.write_bytes(copied_profile.read_bytes() + b" ")
            receipt = json.loads(fixture["receipt_path"].read_bytes())
            for item in receipt["files"]:
                if item["path"] == relative:
                    item["sha256"] = _sha256(copied_profile.read_bytes())
            receipt["files"].sort(key=lambda item: item["path"])
            receipt["closure_digest"] = _sha256(_canonical_json(receipt["files"]))
            fixture["receipt_path"].write_bytes(_canonical_json(receipt))
            with mock.patch.object(validator, "_validate_probe_report"), mock.patch.dict(os.environ, {
                "GITHUB_SHA": fixture["commit"], "GITHUB_RUN_ID": fixture["run_id"],
                "GITHUB_ACTOR": "reviewer", "STAGE0_REVIEWED_EVIDENCE_ENV": "stage0-manual-review",
            }):
                with self.assertRaisesRegex(validator.EvidenceBlocked, "profile copy differs from the collector input"):
                    validator.validate_bundle(fixture["root"], [fixture["reference"]], fixture["attestation"], fixture["aggregate_path"])

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
        with self.assertRaises(validator.EvidenceBlocked):
            validator.validate_semantics(Path.cwd(), 16, result, {
                "installer-package": {"sha256": "a" * 64},
                "installed-executable": {"sha256": "b" * 64},
            })

    def test_kind_without_authoritative_result_schema_is_blocked(self) -> None:
        with self.assertRaisesRegex(validator.EvidenceBlocked, "no authoritative machine-readable source schema"):
            validator.validate_semantics(Path.cwd(), 8, {"result": "PASS"}, {})


@unittest.skipUnless(os.name == "posix" and hasattr(os, "O_NOFOLLOW"), "Unix dirfd/O_NOFOLLOW behavior")
class UnixPinnedReaderRaceTests(unittest.TestCase):
    def test_parent_directory_swap_to_symlink_cannot_redirect_pinned_read(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "reviewed"
            parent.mkdir()
            (parent / "result.json").write_bytes(b'{"value":"inside"}')
            outside = root / "outside"
            outside.mkdir()
            (outside / "result.json").write_bytes(b'{"value":"outside-secret"}')
            target = parent / "result.json"
            original_open = stage0_json.os.open
            swapped = False

            def swap_parent() -> None:
                nonlocal swapped
                parent.rename(root / "reviewed-original")
                parent.symlink_to(outside, target_is_directory=True)
                swapped = True

            def racing_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal swapped
                descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
                if not swapped and path == "reviewed" and dir_fd is not None:
                    swap_parent()
                elif not swapped and Path(os.fsdecode(path)) == target:
                    descriptor and os.close(descriptor)
                    swap_parent()
                    descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
                return descriptor

            with mock.patch.object(stage0_json.os, "open", side_effect=racing_open):
                with self.assertRaises(ValueError):
                    stage0_json.read_pinned_bytes(target, "fixture", root)
            self.assertTrue(swapped, "test did not interleave the parent-directory swap")


if __name__ == "__main__":
    unittest.main()
