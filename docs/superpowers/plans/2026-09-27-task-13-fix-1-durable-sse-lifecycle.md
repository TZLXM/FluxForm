# Task 13 Fix Round 1: Durable SSE Lifecycle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make Task 13 event, worker, capability, artifact, and cleanup lifecycles durable, bounded, identity-safe, and replay-correct.

**Architecture:** Persist explicit job state, worker leases, terminal retention, u64 revisions, artifacts, identities, and cleanup retries in the existing SQLite database. Reuse Task 12's pinned private-directory identity operations for files under the configured ledger root, and serialize capability linking, event changes, and expiry in immediate transactions.

**Tech Stack:** Rust, rusqlite/SQLite, Hyper/Tower tests, Tokio, Windows and Unix filesystem APIs already present in the repository.

**Spec:** `docs/superpowers/specs/2026-09-27-task-13-fix-1-durable-sse-lifecycle-design.md`

## Global Constraints

- Keep Task 11 exact scope/subject authorization and strict SSE cursor/resync behavior.
- Keep Task 12 bounded storage, connection admission, and delivery-settlement gates unchanged.
- Use only existing locked dependencies and offline Cargo resolution.
- Reject unsafe artifact paths and fail closed on missing/ambiguous file identity; never fall back to absolute path access.
- Persist no bearer tokens or sensitive absolute-path diagnostics; keep error responses stable and redacted.
- Keep all catalog, event, file-read, and cleanup work bounded, with explicit storage limits and per-pass caps.

## Review Focus

1. Expired, revoked, or missing capability rows never become live during linking; exercise the real immediate transaction and a competing expiry operation.
2. Absolute, parent, symlink/reparse, replaced, or renamed artifact paths never expose or delete a replacement; exercise registration, download, cleanup, and reopen using native filesystem handles.
3. A still-leased queued/running job cannot be expired; an elapsed worker lease becomes a terminal stale-worker event and only then starts terminal retention.
4. A permanently failing first cleanup batch backs off without starving later rows; retries survive reopen and do not consume active admission capacity.
5. Completion is a single legal terminal event; concurrent appenders serialize exact revisions, replay after reopen is contiguous, and u64 overflow fails closed.

---

### Task 1: Persist job leases, legal transitions, and revision boundaries

**Files:**
- Modify: `apps/server-probe/src/events.rs`
- Modify: `apps/server-probe/src/routes.rs`
- Test: `apps/server-probe/tests/sse_recovery.rs`

**Interfaces:**
- Produces: `EventStore::renew_job_lease(job_id, lease_for)`, transactional `register_state`, legal `append`, and terminal retention derived inside the transaction.
- Consumes: existing `ServerState::register_job`, cancellation, status, and SSE routes.

- [x] **Step 1: Write failing real-store/router tests** for active lease renewal across the old creation TTL, stale lease transition after restart, legal single completion and terminal-state rejection, concurrent append revisions plus replay after reopen, and `u64::MAX` success followed by overflow rejection.
- [x] **Step 2: Run RED** with `cargo test --offline -p fluxform-server-probe --test sse_recovery`; each assertion must fail on the current implementation for the reported behavior, not setup errors.
- [x] **Step 3: Implement the minimal schema/API changes** in `events.rs` and wire lease policy/terminal transition into `routes.rs`. State transitions and revision increments remain one immediate transaction; keep 64 ordinary events and one pinned completion.
- [x] **Step 4: Run GREEN** with the same focused test command, then rerun all server-probe tests.

### Task 2: Pin managed artifact paths and link capabilities atomically

**Files:**
- Modify: `apps/server-probe/src/ledger.rs`
- Modify: `apps/server-probe/src/events.rs`
- Modify: `apps/server-probe/src/auth.rs`
- Modify: `apps/server-probe/src/routes.rs`
- Modify: `apps/server-probe/tests/capability_auth.rs`
- Modify: `apps/server-probe/tests/sse_recovery.rs`

**Interfaces:**
- Consumes: Task 12 `SecureReservationDirectory` and platform `file_identity`/identity-checked cleanup semantics.
- Produces: a dedicated private artifact-directory handle derived from the configured ledger root; registration, verified read, and identity-checked cleanup by canonical relative path.

- [x] **Step 1: Write failing tests** for exact live status/events/download scope requirements, expired and revoked capability non-revival, link-vs-expiry serialization, rejection of absolute/traversal paths, and replacement/rename verification after EventStore and ledger reopen.
- [x] **Step 2: Run RED** with the focused capability and SSE integration tests; confirm unsafe paths are currently trusted and expired capability registration currently succeeds or lacks the expected atomic rejection.
- [x] **Step 3: Implement root-relative identity persistence** and the single immediate transaction for required-scope selection, artifact insertion, common-minimum expiry, terminal retention update, and linked capability shortening. Downloads and cleanup must use the persisted identity via pinned no-follow handles.
- [x] **Step 4: Run GREEN** with the focused tests, then rerun all server-probe tests.

### Task 3: Make cleanup retry fair, bounded, and restart-recoverable

**Files:**
- Modify: `apps/server-probe/src/events.rs`
- Test: `apps/server-probe/tests/sse_recovery.rs`

**Interfaces:**
- Consumes: Task 2 root-relative artifact identity and Task 1 terminal/lease lifecycle.
- Produces: persisted `attempt_count`/`next_attempt_at`, a capped fair due-work pass, and admission accounting independent of retryable outbox rows.

- [x] **Step 1: Write failing tests** for a full 32-row failing batch not starving later due cleanup, capped retry metadata surviving reopen and succeeding when repaired, and new active records remaining admissible while retryable cleanup rows exist.
- [x] **Step 2: Run RED** with the focused SSE integration tests and capture starvation/capacity assertions.
- [x] **Step 3: Implement bounded fair retry** with stable backoff and a separate finite cleanup-backlog budget; do not remove metadata or files when durable identity cleanup intent cannot be established.
- [x] **Step 4: Run GREEN** with the focused tests and all server-probe tests.

### Task 4: Full verification, review record, and commit

**Files:**
- Modify: `.superpowers/sdd/2026-09-25-fluxform-stage-0-feasibility/task-13-report.md`

- [x] **Step 1: Run verification**: `cargo fmt --all -- --check`, focused SSE/capability suites, full server-probe suite, feasible offline workspace suite excluding the native-profile sentinel, workspace Clippy with `-D warnings`, and `git diff --check`.
- [x] **Step 2: Review the spec against all six coordinator findings** and record the observed RED/GREEN evidence, migration/path safety decisions, skipped native gate, and any remaining constraints in the Task 13 report.
- [x] **Step 3: Commit** implementation, regression tests, spec, plan, and report using a Conventional Commit message; confirm the requested base is the commit parent and the worktree is clean.
