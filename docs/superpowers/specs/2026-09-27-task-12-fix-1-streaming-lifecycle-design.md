# Task 12 Fix Round 1: Streaming Upload Lifecycle and Resource Bounds

**Date:** 2026-09-27
**Status:** Approved.

## Scope

Close the five Task 12 review findings without weakening existing authorization, origin, streaming, quota, peer identity, or error-close behavior. This remains a loopback server probe, not a production deployment claim. On Unix, loopback operation assumes an exclusive trusted service UID and a private storage namespace; it does not resist an untrusted same-UID process. A non-loopback listener is rejected before reconciliation/accept until Task 7/14 prerequisite evidence is integrated. No production attestation path currently exists. The listener uses the parent-approved cached/locked `hyper-util 0.1.21` timer integration; all dependency resolution remains offline.

## Invariants

1. The staging file is one pinned file identity from reservation through expansion, write, settlement, and cleanup. Expansion mutates the opened file handle; settle verifies the recorded directory entry still names that same object. A replaced or renamed entry cannot be reported as a successful upload. On Unix, same-UID namespace mutation remains outside the supported threat model; public binding stays fail-closed without Task 7/14 exclusive-identity and private-storage evidence. Windows deletion remains bound to the verified handle.
2. A persisted upload lease protects an active receiver from cleanup. Lease acquisition/renewal and expiry are transactional. Reserved-session expiry follows the durable capability expiry timestamp; Receiving expiry additionally requires an elapsed renewable lease. Startup reconciliation and bounded periodic cleanup release quota and enqueue/delete stale partial files idempotently.
3. Upload request storage work runs on bounded blocking workers rather than Tokio executor threads. Per-operation and overall upload deadlines bound the handler's wait. A timed-out non-cancellable OS operation remains owned by its worker and persisted lease; the response closes promptly, while later worker completion performs truthful settlement or cleanup. No response claims deletion until deletion is confirmed.
4. Reservation expansion commits before the writer is invoked for the excess chunk; tests observe state at that exact writer call.
5. The listener limits accepted live connections and uses Hyper's HTTP/1 header-read timeout before a request reaches route/body enforcement. Over-cap connections are closed without spawning work; timed-out partial headers are closed.
6. The accepted socket supplies `TransportPeer`. Exact `Origin`, upload capability scope, checked streamed totals, hard byte limit, quota and disk watermark behavior, redacted errors, and `Connection: close` on rejected PUT responses remain unchanged.
7. Upload settlement writes a durable pending-ack/remediation row in the same SQLite transaction that publishes `Uploaded` and charges actual-byte usage. A successful PUT forces `Connection: close`; only successful Hyper connection completion removes the pending intent. On startup, every remaining intent is transactionally expired, refunded once, capability-revoked, and queued for exact-identity cleanup. During service, intents older than the acknowledgment grace are handled by the same bounded reconciler. A transport error or process crash before Hyper reports success is fail-closed; the service cannot prove remote application receipt, so the acknowledgment boundary is explicitly transport completion, not client confirmation.
8. Identity scans are limited to 64 directory entries and a shared 100 ms scan deadline per cleanup attempt. Startup orphan enumeration is bounded separately and fails closed on overflow/deadline. Cleanup passes process at most 64 due jobs, retain per-session outbox results, and use persisted bounded backoff; a sticky unrelated identity cannot poison another session's compensation or hold an actor/worker permit forever.

## Design

### File identity

Pass the pinned staging `File` into ledger expansion and perform `set_len`/allocation on that handle under the existing immediate transaction. The rollback guard retains that same handle and prior length. Record a platform file identity when the receiving handle is opened; before settlement compare both the pinned-handle identity and secure directory-entry identity using the already-open reservation directory. Use handle metadata plus no-follow relative-open metadata (Unix device/inode; Windows volume/file index) and fail closed when identity cannot be established. Settlement may account usage only after identity validation. Cleanup jobs remain directory-relative and idempotent.

### Durable session expiry and leases

Use the capability row's durable `expires_at` as the authoritative expiry for `Reserved` rows; persist a renewable lease deadline on each `Receiving` upload. Starting and renewing a receiver lease require the expected session state/capability; an independent tracked heartbeat renews the persisted lease while the actor owns the pinned file, including when a synchronous write is blocked. Expansion renews the lease in the same transaction that commits its reservation, after file allocation returns, so a held SQLite write lock cannot be followed by an expired lease becoming visible. Cleanup takes an immediate transaction and expires only `Reserved` rows after their capability expiry or `Receiving` rows whose lease expired. Startup performs reconciliation before serving, and the runnable process runs a bounded periodic maintenance loop. Stale crash allocations release IP/global reservation and enqueue path cleanup atomically.

The server shutdown path stops accepting first, then waits a bounded grace period for connection/worker owners. Blocking workers are explicitly tracked. On deadline, it aborts request tasks but does not pretend to cancel blocking syscalls; supervised workers retain their persisted lease until they return and settle or clean up. If a non-cancellable syscall outlives the grace period, shutdown remains pending or reports a distinct shutdown failure; it never silently orphans the worker or claims clean shutdown.

### Blocking storage and deadlines

Use a semaphore-bounded `spawn_blocking` executor for route storage operations and a separately bounded per-upload blocking actor that owns its pinned handle and lease. Handler waits use `timeout_at` with the absolute upload deadline and the per-operation bound. Queued storage and actor commands carry deadlines and recheck them before mutation; a running OS syscall is explicitly non-cancellable. A slow-storage test hook blocks a write to prove the Tokio runtime remains responsive, the request returns at deadline, the lease is independently renewed while the actor is blocked, and cleanup occurs only after release. Error text reflects whether cleanup is confirmed or pending.

### Listener admission

Configure finite maximum live connections. `serve` uses a semaphore and `try_acquire_owned` immediately after accept, dropping over-cap sockets. Hyper HTTP/1 gets a Tokio-backed `Timer` and finite `header_read_timeout`; test slow/incomplete headers through real sockets, including saturation proving no more than the cap of connections enter service. The same real listener keeps inserting peer identity from `accept()`. Both the executable and library adapter reject non-loopback binds. The test-only synthetic evidence marker only exercises the policy helper and cannot be passed to the production listener. On Unix, loopback probe operation requires the documented trusted single-service-UID model, not resistance to another untrusted process running under that UID.

### Settlement acknowledgment and recovery

The `settlement_outbox` row is inserted in the same transaction as `Uploaded`, actual-byte quota charge, and reservation release. The route returns an internal acknowledgment candidate with its successful 204 response and closes that connection. The socket adapter deletes the intent only after Hyper returns success for that connection; any connection error leaves the intent durable. If the process restarts before acknowledgment, startup compensation expires the session, refunds the actual-byte charge exactly once, revokes the capability, and enqueues identity-bound cleanup. A periodic TTL pass handles old pending intents. The response contract is fail-closed at the observable transport boundary: uncertain connection completion is treated as unacknowledged. Hyper success is not represented as proof that the remote application processed the response; end-to-end client receipt is not available in this probe protocol.

### Bounded cleanup

Each exact-identity scan stops on its entry or deadline bound and fails closed without unlinking if it cannot establish one unique identity. The cleanup outbox is processed in capped batches. Failures update that row's persisted attempt count and capped exponential `next_attempt_at`; immediate late-compensation retries target only their own session and are finite. Durable pending work is resumed by later passes/restart without keeping a streaming actor or semaphore permit alive. Startup rejects a pending settlement backlog larger than its explicit recovery cap before serving.

## Validation evidence

Add regression tests before implementation for (a) same-handle expansion and exact excess-write ordering, (b) directory-entry replacement/rename, (c) startup/periodic expiry and four-session quota release, (d) crash-partial cleanup, (e) slow storage deadlines and truthful delayed cleanup, (f) listener connection cap and slow-header timeout. Existing upload/auth/socket suites remain regression gates. All Cargo resolution and verification stays offline against the existing lockfile.
