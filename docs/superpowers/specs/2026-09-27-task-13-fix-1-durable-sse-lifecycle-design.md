# Task 13 Fix Round 1: Durable SSE and Artifact Lifecycle

**Date:** 2026-09-27
**Status:** Approved for implementation by the task coordinator.

## Scope

Harden the Task 13 SQLite event store and its protected routes without weakening Task 11 capability gates or Task 12's listener, storage-worker, and filesystem protections. This remains the loopback server probe; no production deployment claim, dependency change, or native artifact evidence is in scope.

## Invariants

1. Event revisions are persistent u64 values. Immediate transactions serialize appenders; the maximum value may be committed once and overflow fails closed. A replay is returned only for a complete contiguous suffix. Existing strict cursor, authorization, no-store, and resync-close behavior remains unchanged.
2. A job has an explicit persisted state and renewable worker lease. Queued/running jobs have no creation-based expiry; a valid lease prevents cleanup. An elapsed lease causes one explicit stale-worker terminal transition. Terminal retention starts in the same transaction as the terminal state/event transition and lasts through the linked artifact's effective download lifetime.
3. State transitions reject invalid changes after terminal state. There is at most one pinned `job.completed` event; identical completion through the state API is idempotent and direct duplicate completion append is rejected. Retention remains at most 64 ordinary events plus one pinned completion.
4. Artifact paths are normalized relative paths beneath a private artifact directory derived from the configured upload root. Registration captures the exact platform identity through a no-follow root-relative handle. Download reads from a verified identity; cleanup removes only that identity. No absolute/lossy/arbitrary-path fallback is allowed. Identity/path intent survives reopen.
5. Artifact linking and capability selection happen under one immediate SQLite transaction. Linking requires currently-live status and events capabilities for exactly `job:<id>` and download capability for exactly `artifact:<id>`. It shortens only live rows to their common minimum expiry and never resurrects missing, expired, or revoked rows. Expiry and linking serialize.
6. Cleanup is persistent, bounded, fair, and recoverable: due-time selection uses attempt count and capped backoff; every pass has a fixed work limit; retryable rows do not count against active-job/artifact admission capacity. Both the active catalog and cleanup backlog have explicit finite storage bounds.

## Design

Extend the existing private `UploadLedger` directory-handle machinery with a dedicated `.fluxform-artifacts` root. The ledger supplies the pinned root-relative file operations and platform identity to `EventStore`; event metadata stores only a canonical relative path and the identity bytes. Artifact reads use a verified open handle, and the cleanup outbox persists the same relative path/identity so startup recovery can safely reopen and verify it.

Migrate the event schema transactionally. Keep job state, lease deadline, terminal deadline, event revision, artifact identity, and cleanup retry state together in SQLite. A completion/cancellation/failure transition sets terminal expiry atomically; a linked artifact may shorten the effective lifetime to the minimum current capability expiry. Expired running jobs become an explicit failed/interrupted snapshot/event before later terminal cleanup. Event appends validate state and completion uniqueness inside the same immediate transaction.

Artifact link code reads the exact required live capability scopes and computes one common expiry within that same transaction. It rejects absent or expired rows before modifying any data, then updates only rows whose expiry is still live and later than the chosen bound. Capability authorization continues through existing route middleware.

Cleanup selects a bounded set of due rows ordered by `next_attempt_at` and stable identity. Failure increments persisted attempts and schedules capped exponential retry; a failed early row therefore yields to later due rows. Admission counts live jobs and standalone artifacts independently from durable cleanup retry records, with a separate hard cleanup backlog cap that preserves recoverable identity data.

## Validation

Add real-store/router RED tests before implementation for capability non-revival and serialized link/expiry; root-relative path validation, replacement/rename and restart identity checks; active lease and stale-worker recovery; bounded fair cleanup with reopen/retry; legal single completion; concurrent exact revisions, reopen replay, and u64 maximum/overflow. Then run focused server tests, offline feasible workspace tests, format, Clippy, diff checks, and final review. Do not weaken existing auth, Task 12 delivery, or listener gates to make a test pass.
