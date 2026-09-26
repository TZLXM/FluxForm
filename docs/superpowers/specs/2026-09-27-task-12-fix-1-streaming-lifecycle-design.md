# Task 12 Fix Round 1: Streaming Upload Lifecycle and Resource Bounds

**Date:** 2026-09-27  
**Status:** Parent-approved architecture; detailed implementation plan pending review.

## Scope

Close the five Task 12 review findings without weakening existing authorization, origin, streaming, quota, peer identity, or error-close behavior. This remains a loopback server probe, not a production deployment claim. No new dependency is planned; use the already locked Hyper/Tokio stack.

## Invariants

1. The staging file is one pinned file identity from reservation through expansion, write, settlement, and cleanup. Expansion mutates the opened file handle; settle verifies the recorded directory entry still names that same object. A replaced or renamed entry cannot be reported as a successful upload.
2. A persisted upload lease protects an active receiver from cleanup. Lease acquisition/renewal and expiry are transactional. Reserved-session expiry follows the durable capability expiry timestamp; Receiving expiry additionally requires an elapsed renewable lease. Startup reconciliation and bounded periodic cleanup release quota and enqueue/delete stale partial files idempotently.
3. HTTP/Tokio tasks perform no synchronous SQLite or filesystem calls. A bounded blocking-operation pool owns each storage action. Per-operation and overall upload deadlines bound the handler's wait. A timed-out non-cancellable OS operation remains owned by its worker and lease; the response closes promptly, while later worker completion performs truthful settlement or cleanup. No response claims deletion until deletion is confirmed.
4. Reservation expansion commits before the writer is invoked for the excess chunk; tests observe state at that exact writer call.
5. The listener limits accepted live connections and uses Hyper's HTTP/1 header-read timeout before a request reaches route/body enforcement. Over-cap connections are closed without spawning work; timed-out partial headers are closed.
6. The accepted socket supplies `TransportPeer`. Exact `Origin`, upload capability scope, checked streamed totals, hard byte limit, quota and disk watermark behavior, redacted errors, and `Connection: close` on rejected PUT responses remain unchanged.

## Design

### File identity

Pass the pinned staging `File` into ledger expansion and perform `set_len`/allocation on that handle under the existing immediate transaction. The rollback guard retains that same handle and prior length. Record a platform file identity when the receiving handle is opened; before settlement compare both the pinned-handle identity and secure directory-entry identity using the already-open reservation directory. Use handle metadata plus no-follow relative-open metadata (Unix device/inode; Windows volume/file index) and fail closed when identity cannot be established. Settlement may account usage only after identity validation. Cleanup jobs remain directory-relative and idempotent.

### Durable session expiry and leases

Persist `expires_at` with each upload row at the same ledger transaction that reserves bytes; derive it from the capability's authenticated durable expiry, not a separately guessed TTL. Persist a lease deadline for `Receiving`. Starting and renewing a receiver lease require the expected session state/capability; renewal is conditional and occurs at a bounded interval during body and storage work. Cleanup takes an immediate transaction and expires only `Reserved` rows after their persisted expiry or `Receiving` rows whose lease expired. Startup performs reconciliation before serving, and the runnable process runs a bounded periodic maintenance loop. Active lease ownership prevents cleanup; stale crash allocations release IP/global reservation and enqueue path cleanup atomically.

The server shutdown path stops accepting first, then waits a bounded grace period for connection/worker owners. On deadline, it aborts request tasks but does not pretend to cancel blocking syscalls; supervised workers retain their persisted lease until they return and settle or clean up. The process does not exit while untracked blocking workers remain.

### Blocking storage and deadlines

Use a shared semaphore-bounded `spawn_blocking` executor for ledger/filesystem operations, acquired asynchronously before spawning. Handler waits use `timeout_at` with the absolute upload deadline and the per-operation bound. Each queued operation receives a deadline/lease context and rechecks it before mutation; a running OS syscall is explicitly non-cancellable. A slow-storage test hook blocks a storage operation to prove the Tokio runtime remains responsive, the request returns at deadline, the lease is retained until worker completion, and eventual cleanup occurs after release. Error text reflects whether cleanup is confirmed or pending.

### Listener admission

Configure finite maximum live connections. `serve` uses a semaphore and `try_acquire_owned` immediately after accept, dropping over-cap sockets. Hyper HTTP/1 gets a Tokio-backed `Timer` and finite `header_read_timeout`; test slow/incomplete headers through real sockets, including saturation proving no more than the cap of connections enter service. The same real listener keeps inserting peer identity from `accept()`.

## Validation evidence

Add regression tests before implementation for (a) same-handle expansion and exact excess-write ordering, (b) directory-entry replacement/rename, (c) startup/periodic expiry and four-session quota release, (d) crash-partial cleanup, (e) slow storage deadlines and truthful delayed cleanup, (f) listener connection cap and slow-header timeout. Existing upload/auth/socket suites remain regression gates. All Cargo resolution and verification stays offline against the existing lockfile.
