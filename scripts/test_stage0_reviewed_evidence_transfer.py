"""Tests for same-run reviewed evidence staging and attestation."""

from __future__ import annotations

import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import transfer_stage0_reviewed_evidence as transfer


class ReviewedEvidenceTransferTests(unittest.TestCase):
    def test_duplicate_json_keys_in_input_are_rejected(self) -> None:
        with self.assertRaisesRegex(transfer.TransferBlocked, "duplicate JSON object key"):
            transfer.validate_json_bytes(b'{"status":"PASS","status":"FAIL"}', "raw result")

    def test_attestation_closure_changes_when_any_attested_result_changes(self) -> None:
        files = [
            {"path": "target/stage0/reviewed-evidence/run-a/row-01.manifest.json", "sha256": "a" * 64},
            {"path": "target/stage0/reviewed-evidence/run-a/row-01-primary.json", "sha256": "b" * 64},
        ]
        original = transfer.closure_digest(files)
        mutated = [dict(item) for item in files]
        mutated[1]["sha256"] = hashlib.sha256(b"changed").hexdigest()
        self.assertNotEqual(original, transfer.closure_digest(mutated))

    def test_transfer_requires_explicit_bundle_and_workflow_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "input"
            source.mkdir()
            with self.assertRaisesRegex(transfer.TransferBlocked, "workflow run id"):
                transfer.prepare_bundle(
                    input_directory=source,
                    repository_root=root,
                    bundle_id="review-bundle",
                    workflow_run_id="",
                    commit_sha="1" * 40,
                    actor="reviewer",
                    environment="stage0-manual-review",
                )


if __name__ == "__main__":
    unittest.main()
