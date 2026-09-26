# Task 12 Fix Round 1 Implementation Plan

**Design:** [Task 12 streaming lifecycle hardening](../specs/2026-09-27-task-12-fix-1-streaming-lifecycle-design.md) (parent-approved).
**Execution:** strict RED → GREEN → REFACTOR for each concern; no network Cargo operations.

## 1. Pin staging identity and prove write ordering

- Add a production writer seam used only at the final chunk write; inject a test writer that queries committed ledger state at the exact call and records the file bytes/identity it was asked to write. Assert the second (first excess) chunk is invoked only after reservation expansion commits.
- Add race tests that rename/replace the reservation directory entry after opening the receiving handle. Assert `settle` rejects and never accounts the divergent file as uploaded. Cover cleanup without deleting an unrelated replacement.
- Change allocation expansion and rollback to use the already-open `File`; capture/compare platform identity from the open handle and no-follow directory-relative entry immediately before settlement. Preserve safe handle semantics on Unix and Windows.
- Run the focused ordering/replacement tests RED before changing ledger or route code, then GREEN.

## 2. Durable expiration, active lease, and reconciliation

- Add tests for four active sessions on one peer, expiry of their stored capability/session timestamp, periodic cleanup releasing all four slots and reservations, and startup cleanup of a simulated expired Receiving row with a crash-partial allocation.
- Persist capability/session expiry with each upload and a `lease_expires_at` for Receiving. Atomically claim the Reserved row before opening the file; renew the lease during both stream waits and storage waits. Cleanup uses one immediate transaction to claim only expired Reserved rows or Receiving rows with expired leases, release global/IP accounting, and enqueue file deletion. Reconcile outbox and orphan files before listener startup and in a bounded periodic task.
- Add concurrency test: cleanup while a lease is valid leaves file/quota untouched; renewal racing cleanup has one transactionally ordered winner.
- Run each new lifecycle test RED, implement the schema migration and ledger reconciliation, then verify GREEN.

## 3. Bound blocking storage work and deadlines

- Add a blocking-disk fault injector that pauses an expansion/write/flush operation. Tests assert a Tokio heartbeat and unrelated route continue, the upload returns at the configured storage/overall deadline, and storage ownership/lease remains until the syscall is released; only after release may settlement or cleanup be asserted.
- Add a semaphore-bounded blocking executor and explicit task tracking for SQLite/filesystem calls. Move upload open, expansion, disk checks, chunk writes, truncate/flush, settlement, expiration, and reconciliation off async workers. Use absolute total and per-operation deadlines. A started syscall remains non-cancellable; retain its permit, lease, handle and supervisor record until return, then fail/clean idempotently if the request deadline elapsed.
- Add a shutdown path that stops accepting, waits the bounded grace period, and keeps explicitly tracked blocking owners alive. If an OS call outlives grace, remain pending or report a distinct shutdown failure; never silently detach it or claim immediate deletion/clean shutdown.
- Run focused slow-storage tests RED first, then GREEN and re-run upload/auth tests.

## 4. Bound listener admission and header time

- Add real-socket tests with an intentionally partial request header. Verify the configured Hyper header timeout closes it, and with connection limit one, a second accepted socket is closed without spawning a handler while the first retains its slot. Verify an accepted socket still determines `TransportPeer`.
- Add a finite listener semaphore acquired with `try_acquire_owned` before spawning connection service. Give Hyper HTTP/1 a Tokio timer and finite `header_read_timeout`. Ensure the permit follows the entire connection lifetime and is released on every exit path.
- Add graceful listener shutdown coverage alongside active connection/worker draining.

## 5. Verification and handoff

- Run `cargo test --offline -p fluxform-server-probe --test upload_http`, `capability_auth`, and `upload_ledger`, then `cargo test --offline -p fluxform-server-probe`.
- Run `cargo test --offline --workspace -- --skip every_approved_native_profile_has_a_current_sample_report`; run the exact native artifact gate only if the controller provides its artifact root, and report `BLOCKED` otherwise.
- Run `cargo fmt --all -- --check`, `cargo clippy --offline --workspace --all-targets -- -D warnings`, and `git diff --check`.
- Update the ignored Task 12 report with actual commands/results, make a Conventional Commit for implementation, and return commit SHA plus evidence/blockers.

## Self-check against the five review items

1. Pinned identity + directory replacement: section 1.
2. Startup/periodic lifecycle + four-session release + crash partial + race-free leases: section 2.
3. Blocking isolation, bounds/deadlines, injected slow storage, truthful cleanup and explicit shutdown tracking: section 3.
4. Exact excess-chunk writer observation after committed expansion: section 1.
5. Connection cap + Hyper header timeout + socket tests: section 4.

The listener uses the already-cached, locked `hyper-util 0.1.21` Tokio timer integration, and Tokio's existing locked dependency graph with the `signal`/`sync` features. No network resolution or version upgrade was used. Any further missing crate must be reported by exact name/version before fetching.
