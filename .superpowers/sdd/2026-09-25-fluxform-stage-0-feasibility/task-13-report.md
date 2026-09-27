## Task 13 — durable SSE event recovery

**Status: DONE**

### RED / GREEN

- RED was observed against the authorized router before implementation: 0/3 passed. An empty `Last-Event-ID` incorrectly returned 200, replay emitted only revision 1 instead of `[1, 2, 3]`, and a stale cursor emitted no resynchronization event.
- GREEN: the four authorized router tests pass. They cover strict malformed/duplicate/future cursor rejection, monotonic replay without duplicates, a bounded-retention stale cursor producing exactly one `resync_required` frame with the current revision and `Connection: close`, and a protected snapshot at the same revision. The expiry case verifies completed event/snapshot data, capabilities, artifact metadata, and the artifact are retired together, with durable cleanup completing.

### Changes

- Added SQLite-backed per-job event state and snapshots. Revisions are persisted as fixed-width big-endian 64-bit unsigned values and advance atomically with each event. Replay is ordered and accepted only when the entire requested suffix is retained; otherwise it returns a single authoritative resynchronization snapshot.
- Retention is bounded to 64 ordinary events plus a pinned `job.completed` event, with limits on active records, event/snapshot payloads, identifiers, artifacts, replay output, and cleanup batches. Last-Event-ID accepts only a single canonical decimal u64 and rejects malformed, duplicate, and future cursors with stable redacted errors.
- Replaced process-local job/artifact state with the persistent store. Protected status, events, cancellation, and download routes continue through Task 11 capability scope/subject checks. SSE responses carry exact revision `id:` fields and secure common no-store headers.
- Expiry reconciliation atomically revokes job/artifact capabilities and removes snapshots, events, and artifact metadata while recording a bounded durable file-cleanup outbox. Startup and periodic reconciliation retry idempotent file cleanup. Linked artifact registration aligns the snapshot/capability lifetime with artifact expiry.
- No dependency or lockfile changes. Task 12 listener, connection admission, bounded storage worker, and delivery-settlement gates remain in place.

### Verification

- `cargo test --offline --target-dir E:\aicode\FluxForm\target\task13-final -p fluxform-server-probe`: passed; includes the new SSE tests (4/4), capability/auth, upload HTTP, upload ledger, and unit tests.
- `cargo test --offline --target-dir E:\aicode\FluxForm\target\task13-final --workspace -- --skip every_approved_native_profile_has_a_current_sample_report`: exit 0. The separately gated native-profile sentinel was explicitly skipped; one approved-ffprobe artifact test remains ignored. No native artifact evidence is claimed.
- `cargo fmt --all -- --check`, `cargo clippy --offline --target-dir E:\aicode\FluxForm\target\task13-final --workspace --all-targets -- -D warnings`, and `git diff --check`: passed.
- Tests were run on Windows using the native filesystem. No network access was used.

### Commit

- `43e3fcae34fd2da909b212197215fb5b3f4c715` — `feat(server): add durable SSE event recovery`.
- This report is ignored by `.gitignore`, consistent with prior task reports.

## Task 13 review fix 1 — 2026-09-27

### Changes and recovery guarantees

- Capability-to-artifact linking now selects exact-subject, currently-live `status`, `events`, and `download` rows inside the same `IMMEDIATE` transaction as artifact registration. The common expiry can only shorten live rows and job retention. Missing, expired, revoked (`expires_at = 0`), and wrong-subject capabilities do not get recreated or extended; a competing expiry transaction wins without partial linking.
- Artifacts are constrained to a single normalized leaf under the configured private `.fluxform-artifacts` root. The event store opens through Task 12's pinned directory handle, persists platform file identity, and verifies identity and link count on read/removal. Reopen tests prove a replacement is neither served nor removed. Legacy records without identity are preserved during migration but are never served or followed for cleanup.
- Jobs persist a bounded worker lease. A valid lease protects queued/running jobs from cleanup; an elapsed lease performs one explicit `job.failed` transition. Completion and cancellation atomically begin terminal retention and clear the lease. Cancellation is idempotent; terminal states cannot regress. Completion is unique and pinned separately from the 64-event ordinary suffix.
- An elapsed active lease now blocks event append, state re-registration, and lease renewal even while the older catalog retention deadline is in the future. A migration gives pre-lease active rows an immediately stale lease; reconciliation converts them to a terminal stale-worker failure.
- Cleanup retries persist attempts and next-due time, use capped exponential backoff and a fixed 32-item work pass, and survive store reopen. Retryable outbox rows are excluded from active-job admission accounting; a separate finite cleanup-storage quota bounds durable backlog rows. If that quota is full, expiry defers before changing capabilities or metadata, preserving atomic linked-artifact state until a cleanup intent can be recorded.
- Revisions remain fixed-width persisted u64 values: concurrent appends serialize to exact revisions, reopen replay is contiguous, `u64::MAX` is accepted once, and the next append fails closed.

### RED / GREEN evidence

- Added an authorized router regression for cancellation. With the required Origin header present, RED was a 503 from the old route attempting to append a terminal snapshot through the ordinary event path. GREEN verifies one terminal revision, retention starting at cancellation, cleared worker lease, and repeat-cancel idempotency.
- Added regressions for legacy null-identity and active-job migration, traversal/nested paths, active-job admission with pending cleanup failures, and full-outbox expiry deferral without partial capability revocation. Existing expiry-vs-link, revoked/expired/missing capability, replacement/reopen, stale-lease non-resurrection, cleanup fairness/recovery, completion uniqueness, concurrent revision/replay, and overflow regressions remain green.

### Verification

- `cargo test --offline --target-dir E:\aicode\FluxForm\target\task13-final -p fluxform-server-probe`: passed (27 unit, 22 capability/auth, 21 SSE recovery, 24 upload HTTP, 32 upload-ledger tests; 126 total, no failures).
- `cargo test --offline --target-dir E:\aicode\FluxForm\target\task13-final --workspace -- --skip every_approved_native_profile_has_a_current_sample_report`: exited 0. The separate native-profile evidence sentinel was explicitly skipped; the approved-ffprobe integration test remains ignored pending approved artifact/sample evidence.
- `cargo fmt --all -- --check`, workspace Clippy with `--all-targets -- -D warnings`, and `git diff --check`: passed.
- Tests ran on the Windows native filesystem. No network or new dependencies were used. No native deployment/artifact evidence is claimed.
