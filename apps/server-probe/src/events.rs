use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use thiserror::Error;

use crate::ledger::{IdentityCleanupPage, SecureReservationDirectory, file_identity};

// SQLite serializes writers. The bounded listener storage deadline is five
// seconds; allow short bursts of independent event workers to queue without
// turning a transient lock collision into a lost revision.
const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ACTIVE_JOBS_AND_CLEANUPS: i64 = 128;
const MAX_RETAINED_SUFFIX: i64 = 64;
const DEFAULT_JOB_LEASE_SECONDS: i64 = 60;
const MAX_JOB_LEASE_SECONDS: i64 = 24 * 60 * 60;
const MAX_EVENT_BYTES: usize = 2 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024;
const MAX_RESOURCE_ID_BYTES: usize = 128;
const MAX_EVENT_TYPE_BYTES: usize = 64;
const MAX_FILENAME_BYTES: usize = 255;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_ARTIFACT_PATH_BYTES: usize = 4096;
const MAX_IDENTITY_SCAN_CURSOR_BYTES: usize = 1024;
const MAX_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PENDING_CLEANUPS: i64 = 4096;
const MAX_EXPIRY_BATCH: usize = 32;
const MAX_LINK_CAPABILITY_ROWS: i64 = 256;
const IDENTITY_REVIEW_BACKOFF_SECONDS: i64 = 24 * 60 * 60;

const EVENT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS event_jobs (
    job_id TEXT PRIMARY KEY NOT NULL CHECK (length(job_id) BETWEEN 1 AND 128),
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    snapshot_json TEXT NOT NULL CHECK (length(CAST(snapshot_json AS BLOB)) <= 4096),
    retain_until INTEGER NOT NULL CHECK (retain_until >= 0),
    worker_lease_until INTEGER NOT NULL DEFAULT 0 CHECK (worker_lease_until >= 0),
    retention_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (retention_seconds > 0)
);
CREATE TABLE IF NOT EXISTS job_events (
    job_id TEXT NOT NULL REFERENCES event_jobs(job_id) ON DELETE CASCADE,
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    event_type TEXT NOT NULL CHECK (length(event_type) BETWEEN 1 AND 64),
    payload_json TEXT NOT NULL CHECK (length(CAST(payload_json AS BLOB)) <= 2048),
    is_completion INTEGER NOT NULL DEFAULT 0 CHECK (is_completion IN (0, 1)),
    PRIMARY KEY (job_id, revision)
);
CREATE INDEX IF NOT EXISTS job_events_ordered ON job_events(job_id, revision);
CREATE TABLE IF NOT EXISTS event_artifacts (
    artifact_id TEXT PRIMARY KEY NOT NULL CHECK (length(artifact_id) BETWEEN 1 AND 128),
    job_id TEXT UNIQUE REFERENCES event_jobs(job_id) ON DELETE CASCADE,
    path TEXT NOT NULL CHECK (length(CAST(path AS BLOB)) BETWEEN 1 AND 4096),
    filename TEXT NOT NULL CHECK (length(CAST(filename AS BLOB)) BETWEEN 1 AND 255),
    content_type TEXT NOT NULL CHECK (length(CAST(content_type AS BLOB)) BETWEEN 1 AND 256),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0),
    file_identity BLOB NOT NULL CHECK (length(file_identity) BETWEEN 1 AND 64)
);
CREATE INDEX IF NOT EXISTS event_artifacts_expiry ON event_artifacts(expires_at);
CREATE TABLE IF NOT EXISTS event_expiry_outbox (
    job_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    path TEXT NOT NULL CHECK (length(CAST(path AS BLOB)) BETWEEN 1 AND 4096),
    file_identity BLOB NOT NULL CHECK (length(file_identity) BETWEEN 1 AND 64),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at INTEGER NOT NULL DEFAULT 0 CHECK (next_attempt_at >= 0),
    scan_cursor TEXT CHECK (scan_cursor IS NULL OR length(CAST(scan_cursor AS BLOB)) <= 1024),
    scan_pass INTEGER NOT NULL DEFAULT 0 CHECK (scan_pass IN (0, 1)),
    PRIMARY KEY (job_id, artifact_id)
);
"#;

#[derive(Clone)]
pub struct EventStore {
    database_path: PathBuf,
    artifact_root: PathBuf,
    artifact_directory: Arc<SecureReservationDirectory>,
}

#[derive(Debug, Error)]
pub enum EventStoreError {
    #[error("event store database is unavailable")]
    Storage(#[from] rusqlite::Error),
    #[error("job is not available")]
    JobNotFound,
    #[error("event revision is greater than the current revision")]
    FutureRevision,
    #[error("job is expired")]
    Expired,
    #[error("event store capacity is exhausted")]
    Capacity,
    #[error("job revision is exhausted")]
    RevisionExhausted,
    #[error("event or snapshot is invalid or too large")]
    InvalidRecord,
    #[error("job state transition is not legal")]
    InvalidTransition,
    #[error("event store data is corrupt")]
    Corrupt,
    #[error("managed artifact filesystem operation failed")]
    Filesystem(#[from] io::Error),
    #[error("required live capabilities are missing")]
    CapabilityMissing,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JobSnapshot {
    pub revision: u64,
    pub data: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub struct JobEvent {
    pub revision: u64,
    pub event_type: String,
    pub data: Value,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ReplayResult {
    Events {
        snapshot: JobSnapshot,
        events: Vec<JobEvent>,
    },
    ResyncRequired(JobSnapshot),
}

#[derive(Clone, Debug)]
pub struct ArtifactMetadata {
    /// Normalized path relative to the pinned private artifact root.
    pub path: PathBuf,
    pub filename: String,
    pub content_type: String,
    pub file_identity: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExpiryReport {
    pub records_expired: usize,
    pub artifacts_deleted: usize,
    pub cleanup_pending: usize,
}

#[derive(Clone, Copy)]
struct AppendPolicy {
    is_completion: bool,
    allow_terminal_event: bool,
    allow_stale_worker: bool,
}

type CapabilityShortening = (Vec<u8>, String);
type LiveLinkCapabilitySelection = (i64, Vec<CapabilityShortening>);

impl EventStore {
    pub fn open(
        database_path: impl AsRef<Path>,
        artifact_root: impl AsRef<Path>,
    ) -> Result<Self, EventStoreError> {
        let artifact_root = artifact_root.as_ref().to_path_buf();
        let artifact_directory = Arc::new(
            SecureReservationDirectory::open(&artifact_root)
                .map_err(EventStoreError::Filesystem)?,
        );
        let store = Self {
            database_path: database_path.as_ref().to_path_buf(),
            artifact_root,
            artifact_directory,
        };
        let mut connection = store.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let has_jobs = table_exists(&transaction, "event_jobs")?;
        let has_worker_lease =
            has_jobs && table_has_column(&transaction, "event_jobs", "worker_lease_until")?;
        let has_retention =
            has_jobs && table_has_column(&transaction, "event_jobs", "retention_seconds")?;
        let has_artifacts = table_exists(&transaction, "event_artifacts")?;
        let has_artifact_identity =
            has_artifacts && table_has_column(&transaction, "event_artifacts", "file_identity")?;
        let has_expiry_outbox = table_exists(&transaction, "event_expiry_outbox")?;
        let has_outbox_identity = has_expiry_outbox
            && table_has_column(&transaction, "event_expiry_outbox", "file_identity")?;
        let has_outbox_attempts = has_expiry_outbox
            && table_has_column(&transaction, "event_expiry_outbox", "attempt_count")?;
        let has_outbox_next_attempt = has_expiry_outbox
            && table_has_column(&transaction, "event_expiry_outbox", "next_attempt_at")?;
        let has_outbox_scan_cursor = has_expiry_outbox
            && table_has_column(&transaction, "event_expiry_outbox", "scan_cursor")?;
        let has_outbox_scan_pass = has_expiry_outbox
            && table_has_column(&transaction, "event_expiry_outbox", "scan_pass")?;
        transaction.execute_batch(EVENT_SCHEMA)?;
        if has_jobs && !has_worker_lease {
            transaction.execute(
                "ALTER TABLE event_jobs ADD COLUMN worker_lease_until INTEGER NOT NULL DEFAULT 0 CHECK (worker_lease_until >= 0)",
                [],
            )?;
            let legacy_jobs = {
                let mut statement =
                    transaction.prepare("SELECT job_id, snapshot_json FROM event_jobs")?;
                statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?
            };
            let now = current_unix_seconds();
            for (job_id, snapshot_json) in legacy_jobs {
                let snapshot: Value =
                    serde_json::from_str(&snapshot_json).map_err(|_| EventStoreError::Corrupt)?;
                if !is_terminal_state(snapshot.get("state").and_then(Value::as_str).unwrap_or("")) {
                    // Legacy active jobs have no surviving worker lease after
                    // process restart. Expire the lease now so reconciliation
                    // records a stale-worker terminal event instead of
                    // silently reviving them through a status update.
                    transaction.execute(
                        "UPDATE event_jobs SET worker_lease_until = ?1 WHERE job_id = ?2",
                        params![now, job_id],
                    )?;
                }
            }
        }
        if has_jobs && !has_retention {
            transaction.execute(
                "ALTER TABLE event_jobs ADD COLUMN retention_seconds INTEGER NOT NULL DEFAULT 3600 CHECK (retention_seconds > 0)",
                [],
            )?;
        }
        if has_artifacts && !has_artifact_identity {
            transaction.execute(
                "ALTER TABLE event_artifacts ADD COLUMN file_identity BLOB",
                [],
            )?;
        }
        if has_expiry_outbox && !has_outbox_identity {
            transaction.execute(
                "ALTER TABLE event_expiry_outbox ADD COLUMN file_identity BLOB",
                [],
            )?;
        }
        if has_expiry_outbox && !has_outbox_attempts {
            transaction.execute(
                "ALTER TABLE event_expiry_outbox ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if has_expiry_outbox && !has_outbox_next_attempt {
            transaction.execute(
                "ALTER TABLE event_expiry_outbox ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if has_expiry_outbox && !has_outbox_scan_cursor {
            transaction.execute(
                "ALTER TABLE event_expiry_outbox ADD COLUMN scan_cursor TEXT",
                [],
            )?;
        }
        if has_expiry_outbox && !has_outbox_scan_pass {
            transaction.execute(
                "ALTER TABLE event_expiry_outbox ADD COLUMN scan_pass INTEGER NOT NULL DEFAULT 0 CHECK (scan_pass IN (0, 1))",
                [],
            )?;
        }
        // Preserve legacy rows, but they have no pinned file identity and
        // must never be served or deleted by pathname. Runtime reads and
        // cleanup select only identity-bearing records.
        let duplicate_completions: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM (SELECT job_id FROM job_events WHERE is_completion = 1 GROUP BY job_id HAVING COUNT(*) > 1)",
            [],
            |row| row.get(0),
        )?;
        if duplicate_completions != 0 {
            return Err(EventStoreError::Corrupt);
        }
        transaction.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS job_events_single_completion \
             ON job_events(job_id) WHERE is_completion = 1;\
             CREATE INDEX IF NOT EXISTS event_expiry_due \
             ON event_expiry_outbox(next_attempt_at, job_id, artifact_id);",
        )?;
        transaction.commit()?;
        Ok(store)
    }

    pub(crate) fn shares_database_with(&self, path: &Path) -> bool {
        match (
            fs::canonicalize(&self.database_path),
            fs::canonicalize(path),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }

    fn connect(&self) -> Result<Connection, EventStoreError> {
        let connection = Connection::open(&self.database_path)?;
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(connection)
    }

    /// Creates a job or records a state transition, advancing its durable revision once.
    pub fn register_state(
        &self,
        job_id: &str,
        state: &str,
        retain_until: i64,
    ) -> Result<u64, EventStoreError> {
        if !valid_resource_id(job_id)
            || state.is_empty()
            || state.len() > MAX_EVENT_BYTES
            || retain_until < 0
        {
            return Err(EventStoreError::InvalidRecord);
        }
        let snapshot = json!({"job_id": job_id, "state": state});
        let snapshot_json = encode_bounded_json(&snapshot, MAX_SNAPSHOT_BYTES)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = transaction
            .query_row(
                "SELECT revision, snapshot_json, retention_seconds, retain_until, worker_lease_until \
                 FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                )),
            )
            .optional()?;

        let now = current_unix_seconds();
        let retention_seconds = retain_until.saturating_sub(now).max(1);
        let revision = if let Some((
            revision_blob,
            previous_json,
            _previous_retention_seconds,
            previous_retain_until,
            previous_worker_lease_until,
        )) = existing
        {
            let previous_revision = decode_revision(&revision_blob)?;
            let previous: Value =
                serde_json::from_str(&previous_json).map_err(|_| EventStoreError::Corrupt)?;
            let previous_state = previous.get("state").and_then(Value::as_str).unwrap_or("");
            if job_is_expired(
                &previous,
                previous_retain_until,
                previous_worker_lease_until,
                now,
            ) {
                return Err(EventStoreError::Expired);
            }
            if previous_state == state {
                if !is_terminal_state(state) {
                    let lease_until = now.saturating_add(DEFAULT_JOB_LEASE_SECONDS);
                    transaction.execute(
                        "UPDATE event_jobs SET worker_lease_until = ?1, retention_seconds = ?2 WHERE job_id = ?3",
                        params![lease_until, retention_seconds, job_id],
                    )?;
                }
                transaction.commit()?;
                return Ok(previous_revision);
            }

            if is_terminal_state(previous_state) {
                return Err(EventStoreError::InvalidTransition);
            }

            let event_type = match state {
                "completed" => "job.completed",
                "failed" => "job.failed",
                _ => "job.state_changed",
            };
            let terminal = matches!(state, "completed" | "failed" | "cancelled");
            let revision = append_in_transaction(
                &transaction,
                job_id,
                event_type,
                &snapshot,
                &snapshot_json,
                AppendPolicy {
                    is_completion: terminal && state == "completed",
                    allow_terminal_event: terminal,
                    allow_stale_worker: false,
                },
            )?;
            if terminal {
                transaction.execute(
                    "UPDATE event_jobs SET retain_until = ?1, worker_lease_until = 0, retention_seconds = ?2 WHERE job_id = ?3",
                    params![retain_until, retention_seconds, job_id],
                )?;
            } else {
                transaction.execute(
                    "UPDATE event_jobs SET worker_lease_until = ?1, retention_seconds = ?2 WHERE job_id = ?3",
                    params![now.saturating_add(DEFAULT_JOB_LEASE_SECONDS), retention_seconds, job_id],
                )?;
            }
            revision
        } else {
            let active_records: i64 = transaction.query_row(
                "SELECT (SELECT COUNT(*) FROM event_jobs WHERE \
                            worker_lease_until > ?1 OR retain_until > ?1) + \
                 (SELECT COUNT(*) FROM event_artifacts WHERE job_id IS NULL AND expires_at > ?1)",
                [now],
                |row| row.get(0),
            )?;
            if active_records >= MAX_ACTIVE_JOBS_AND_CLEANUPS {
                return Err(EventStoreError::Capacity);
            }
            transaction.execute(
                "INSERT INTO event_jobs(job_id, revision, snapshot_json, retain_until, worker_lease_until, retention_seconds) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    job_id,
                    encode_revision(0).as_slice(),
                    snapshot_json,
                    retain_until,
                    if is_terminal_state(state) { 0 } else { now.saturating_add(DEFAULT_JOB_LEASE_SECONDS) },
                    retention_seconds
                ],
            )?;
            let event_type = if state == "completed" {
                "job.completed"
            } else if state == "failed" {
                "job.failed"
            } else {
                "job.state_changed"
            };
            append_in_transaction(
                &transaction,
                job_id,
                event_type,
                &snapshot,
                &snapshot_json,
                AppendPolicy {
                    is_completion: state == "completed",
                    allow_terminal_event: is_terminal_state(state),
                    allow_stale_worker: false,
                },
            )?
        };
        transaction.commit()?;
        Ok(revision)
    }

    /// Appends an event and advances the job's persisted 64-bit unsigned revision atomically.
    pub fn append(
        &self,
        job_id: &str,
        event_type: &str,
        payload: &Value,
        snapshot: &Value,
    ) -> Result<u64, EventStoreError> {
        if !valid_resource_id(job_id) || !valid_event_type(event_type) {
            return Err(EventStoreError::InvalidRecord);
        }
        if is_terminal_event(event_type) {
            return Err(EventStoreError::InvalidTransition);
        }
        let snapshot_json = encode_bounded_json(snapshot, MAX_SNAPSHOT_BYTES)?;
        if snapshot
            .get("state")
            .and_then(Value::as_str)
            .is_some_and(is_terminal_state)
        {
            return Err(EventStoreError::InvalidTransition);
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = append_in_transaction(
            &transaction,
            job_id,
            event_type,
            payload,
            &snapshot_json,
            AppendPolicy {
                is_completion: false,
                allow_terminal_event: false,
                allow_stale_worker: false,
            },
        )?;
        transaction.commit()?;
        Ok(revision)
    }

    /// Cancels an active job with one durable terminal transition. Repeating
    /// cancellation is idempotent; a different terminal state cannot regress.
    pub fn cancel(&self, job_id: &str) -> Result<u64, EventStoreError> {
        if !valid_resource_id(job_id) {
            return Err(EventStoreError::InvalidRecord);
        }
        let now = current_unix_seconds();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (revision_blob, snapshot_json, retain_until, worker_lease_until, retention_seconds): (
            Vec<u8>,
            String,
            i64,
            i64,
            i64,
        ) = transaction
            .query_row(
                "SELECT revision, snapshot_json, retain_until, worker_lease_until, retention_seconds \
                 FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(EventStoreError::JobNotFound)?;
        let snapshot: Value =
            serde_json::from_str(&snapshot_json).map_err(|_| EventStoreError::Corrupt)?;
        let current_state = snapshot.get("state").and_then(Value::as_str).unwrap_or("");
        if job_is_expired(&snapshot, retain_until, worker_lease_until, now) {
            return Err(EventStoreError::Expired);
        }
        if current_state == "cancelled" {
            let revision = decode_revision(&revision_blob)?;
            transaction.commit()?;
            return Ok(revision);
        }
        if is_terminal_state(current_state) {
            return Err(EventStoreError::InvalidTransition);
        }

        let cancelled_snapshot = json!({"job_id": job_id, "state": "cancelled"});
        let cancelled_json = encode_bounded_json(&cancelled_snapshot, MAX_SNAPSHOT_BYTES)?;
        let retain_until = now.saturating_add(retention_seconds.max(1));
        let revision = append_in_transaction(
            &transaction,
            job_id,
            "job.state_changed",
            &cancelled_snapshot,
            &cancelled_json,
            AppendPolicy {
                is_completion: false,
                allow_terminal_event: true,
                allow_stale_worker: false,
            },
        )?;
        transaction.execute(
            "UPDATE event_jobs SET retain_until = ?1, worker_lease_until = 0 WHERE job_id = ?2",
            params![retain_until, job_id],
        )?;
        transaction.commit()?;
        Ok(revision)
    }

    /// Extends a live worker lease without allowing an expired worker to
    /// resurrect its claim. Leases are deliberately capped to one day.
    pub fn renew_worker_lease(
        &self,
        job_id: &str,
        lease_seconds: i64,
    ) -> Result<i64, EventStoreError> {
        if !valid_resource_id(job_id) || lease_seconds <= 0 || lease_seconds > MAX_JOB_LEASE_SECONDS
        {
            return Err(EventStoreError::InvalidRecord);
        }
        let now = current_unix_seconds();
        let lease_until = now.saturating_add(lease_seconds);
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (snapshot_json, current_lease): (String, i64) = transaction
            .query_row(
                "SELECT snapshot_json, worker_lease_until FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(EventStoreError::JobNotFound)?;
        let snapshot: Value =
            serde_json::from_str(&snapshot_json).map_err(|_| EventStoreError::Corrupt)?;
        if is_terminal_state(snapshot.get("state").and_then(Value::as_str).unwrap_or(""))
            || current_lease <= now
        {
            return Err(EventStoreError::InvalidTransition);
        }
        transaction.execute(
            "UPDATE event_jobs SET worker_lease_until = ?1 WHERE job_id = ?2",
            params![lease_until, job_id],
        )?;
        transaction.commit()?;
        Ok(lease_until)
    }

    pub fn snapshot(&self, job_id: &str) -> Result<JobSnapshot, EventStoreError> {
        if !valid_resource_id(job_id) {
            return Err(EventStoreError::JobNotFound);
        }
        let connection = self.connect()?;
        let row = connection
            .query_row(
                "SELECT revision, snapshot_json, retain_until, worker_lease_until FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(EventStoreError::JobNotFound)?;
        let data: Value = serde_json::from_str(&row.1).map_err(|_| EventStoreError::Corrupt)?;
        if job_is_expired(&data, row.2, row.3, current_unix_seconds()) {
            return Err(EventStoreError::Expired);
        }
        Ok(JobSnapshot {
            revision: decode_revision(&row.0)?,
            data,
        })
    }

    /// Returns the complete suffix or a snapshot revision the caller can use to resynchronize.
    pub fn replay_after(
        &self,
        job_id: &str,
        last_event_id: u64,
    ) -> Result<ReplayResult, EventStoreError> {
        if !valid_resource_id(job_id) {
            return Err(EventStoreError::JobNotFound);
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Deferred)?;
        let row = transaction
            .query_row(
                "SELECT revision, snapshot_json, retain_until, worker_lease_until FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .ok_or(EventStoreError::JobNotFound)?;
        let data: Value = serde_json::from_str(&row.1).map_err(|_| EventStoreError::Corrupt)?;
        if job_is_expired(&data, row.2, row.3, current_unix_seconds()) {
            return Err(EventStoreError::Expired);
        }
        let snapshot = JobSnapshot {
            revision: decode_revision(&row.0)?,
            data,
        };
        if last_event_id > snapshot.revision {
            return Err(EventStoreError::FutureRevision);
        }
        let missing_count = snapshot.revision - last_event_id;
        if missing_count > u64::try_from(MAX_RETAINED_SUFFIX + 1).unwrap_or(u64::MAX) {
            transaction.commit()?;
            return Ok(ReplayResult::ResyncRequired(snapshot));
        }

        let after_blob = encode_revision(last_event_id);
        let mut statement = transaction.prepare(
            "SELECT revision, event_type, payload_json FROM job_events \
             WHERE job_id = ?1 AND revision > ?2 ORDER BY revision ASC LIMIT ?3",
        )?;
        let rows = statement.query_map(
            params![job_id, after_blob.as_slice(), MAX_RETAINED_SUFFIX + 2],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            },
        )?;
        let mut events = Vec::new();
        for row in rows {
            let (revision, event_type, payload) = row?;
            events.push(JobEvent {
                revision: decode_revision(&revision)?,
                event_type,
                data: serde_json::from_str(&payload).map_err(|_| EventStoreError::Corrupt)?,
            });
        }
        drop(statement);
        transaction.commit()?;

        let complete = events.len() == usize::try_from(missing_count).unwrap_or(usize::MAX)
            && events.iter().enumerate().all(|(index, event)| {
                u64::try_from(index)
                    .ok()
                    .and_then(|index| last_event_id.checked_add(index + 1))
                    == Some(event.revision)
            })
            && events
                .last()
                .map(|event| event.revision)
                .unwrap_or(last_event_id)
                == snapshot.revision;
        if complete {
            Ok(ReplayResult::Events { snapshot, events })
        } else {
            Ok(ReplayResult::ResyncRequired(snapshot))
        }
    }

    pub fn register_artifact(
        &self,
        artifact_id: &str,
        path: &Path,
        filename: &str,
        content_type: &str,
        expires_at: i64,
    ) -> Result<(), EventStoreError> {
        self.store_artifact(None, artifact_id, path, filename, content_type, expires_at)
    }

    pub fn register_job_artifact(
        &self,
        job_id: &str,
        artifact_id: &str,
        path: &Path,
        filename: &str,
        content_type: &str,
        expires_at: i64,
    ) -> Result<(), EventStoreError> {
        self.store_artifact(
            Some(job_id),
            artifact_id,
            path,
            filename,
            content_type,
            expires_at,
        )
    }

    fn store_artifact(
        &self,
        job_id: Option<&str>,
        artifact_id: &str,
        path: &Path,
        filename: &str,
        content_type: &str,
        expires_at: i64,
    ) -> Result<(), EventStoreError> {
        if !valid_resource_id(artifact_id)
            || job_id.is_some_and(|job_id| !valid_resource_id(job_id))
            || path.as_os_str().is_empty()
            || filename.is_empty()
            || filename.len() > MAX_FILENAME_BYTES
            || content_type.is_empty()
            || content_type.len() > MAX_CONTENT_TYPE_BYTES
            || content_type.chars().any(char::is_control)
            || expires_at < 0
        {
            return Err(EventStoreError::InvalidRecord);
        }
        let path = self.normalize_artifact_path(path)?;
        let leaf = path
            .to_str()
            .ok_or(EventStoreError::InvalidRecord)?
            .to_owned();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let now = current_unix_seconds();
        let file = self.artifact_directory.open_readonly_file(&leaf)?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.len() > MAX_ARTIFACT_BYTES
            || crate::ledger::file_link_count(&file)? != 1
        {
            return Err(EventStoreError::InvalidRecord);
        }
        let identity = file_identity(&file)?;
        if identity.is_empty() || identity.len() > 64 {
            return Err(EventStoreError::InvalidRecord);
        }
        let expires_at = if let Some(job_id) = job_id {
            if pending_cleanup_count(&transaction)? >= MAX_PENDING_CLEANUPS {
                return Err(EventStoreError::Capacity);
            }
            let (snapshot_json, retain_until): (String, i64) = transaction
                .query_row(
                    "SELECT snapshot_json, retain_until FROM event_jobs WHERE job_id = ?1",
                    [job_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?
                .ok_or(EventStoreError::JobNotFound)?;
            let snapshot: Value =
                serde_json::from_str(&snapshot_json).map_err(|_| EventStoreError::Corrupt)?;
            if snapshot.get("state").and_then(Value::as_str) != Some("completed") {
                return Err(EventStoreError::InvalidTransition);
            }
            if retain_until <= now || expires_at <= now {
                return Err(EventStoreError::Expired);
            }
            let (common_expiry, capabilities) = live_link_capabilities(
                &transaction,
                job_id,
                artifact_id,
                now,
                expires_at.min(retain_until),
            )?;
            if common_expiry <= current_unix_seconds() {
                return Err(EventStoreError::Expired);
            }
            for (token_hash, subject) in capabilities {
                transaction.execute(
                    "UPDATE capabilities SET expires_at = ?1 \
                     WHERE token_hash = ?2 AND subject = ?3 AND expires_at > ?4 AND expires_at > ?1",
                    params![common_expiry, token_hash, subject, now],
                )?;
            }
            transaction.execute(
                "UPDATE event_jobs SET retain_until = MIN(retain_until, ?1) WHERE job_id = ?2",
                params![common_expiry, job_id],
            )?;
            common_expiry
        } else {
            let active_records: i64 = transaction.query_row(
                "SELECT (SELECT COUNT(*) FROM event_jobs WHERE \
                            worker_lease_until > ?1 OR retain_until > ?1) + \
                 (SELECT COUNT(*) FROM event_artifacts WHERE job_id IS NULL AND expires_at > ?1)",
                [now],
                |row| row.get(0),
            )?;
            if active_records >= MAX_ACTIVE_JOBS_AND_CLEANUPS {
                return Err(EventStoreError::Capacity);
            }
            if pending_cleanup_count(&transaction)? >= MAX_PENDING_CLEANUPS {
                return Err(EventStoreError::Capacity);
            }
            expires_at
        };
        transaction.execute(
            "INSERT INTO event_artifacts(artifact_id, job_id, path, filename, content_type, expires_at, file_identity) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![artifact_id, job_id, leaf, filename, content_type, expires_at, identity],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn normalize_artifact_path(&self, path: &Path) -> Result<PathBuf, EventStoreError> {
        let relative = if path.is_absolute() {
            path.strip_prefix(&self.artifact_root)
                .map_err(|_| EventStoreError::InvalidRecord)?
        } else {
            path
        };
        let mut components = relative.components();
        let Some(Component::Normal(leaf)) = components.next() else {
            return Err(EventStoreError::InvalidRecord);
        };
        if components.next().is_some() {
            return Err(EventStoreError::InvalidRecord);
        }
        let leaf = leaf.to_str().ok_or(EventStoreError::InvalidRecord)?;
        if leaf.is_empty()
            || leaf.len() > 255
            || leaf.starts_with('.')
            || leaf.contains(['/', '\\', ':', '\0'])
            || leaf.chars().any(char::is_control)
            || leaf.len() > MAX_ARTIFACT_PATH_BYTES
        {
            return Err(EventStoreError::InvalidRecord);
        }
        Ok(PathBuf::from(leaf))
    }

    pub fn artifact(&self, artifact_id: &str) -> Result<ArtifactMetadata, EventStoreError> {
        if !valid_resource_id(artifact_id) {
            return Err(EventStoreError::JobNotFound);
        }
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT path, filename, content_type, expires_at, file_identity FROM event_artifacts \
                 WHERE artifact_id = ?1 AND file_identity IS NOT NULL",
                [artifact_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Option<Vec<u8>>>(4)?,
                    ))
                },
            )
            .optional()?
            .filter(|(_, _, _, expires_at, identity)| {
                *expires_at > current_unix_seconds() && identity.is_some()
            })
            .map(|(path, filename, content_type, _, identity)| ArtifactMetadata {
                path: PathBuf::from(path),
                filename,
                content_type,
                file_identity: identity.unwrap_or_default(),
            })
            .ok_or(EventStoreError::JobNotFound)
    }

    /// Opens and reads only the exact pinned regular file, with a hard byte cap.
    pub fn read_artifact(
        &self,
        artifact_id: &str,
    ) -> Result<(ArtifactMetadata, Vec<u8>), EventStoreError> {
        let artifact = self.artifact(artifact_id)?;
        let leaf = artifact.path.to_str().ok_or(EventStoreError::Corrupt)?;
        let file = self.artifact_directory.open_readonly_file(leaf)?;
        if file_identity(&file)? != artifact.file_identity
            || crate::ledger::file_link_count(&file)? != 1
        {
            return Err(EventStoreError::Filesystem(io::Error::new(
                io::ErrorKind::InvalidData,
                "managed artifact identity mismatch",
            )));
        }
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(EventStoreError::InvalidRecord);
        }
        let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
        file.take(MAX_ARTIFACT_BYTES + 1).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_ARTIFACT_BYTES {
            return Err(EventStoreError::InvalidRecord);
        }
        Ok((artifact, bytes))
    }

    /// Atomically retires expired capabilities, snapshots, and event metadata,
    /// then completes artifact deletion from a durable outbox.
    pub fn reconcile_expired(&self) -> Result<ExpiryReport, EventStoreError> {
        let now = current_unix_seconds();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut report = ExpiryReport::default();
        let cleanup_capacity_available =
            i64::from(pending_cleanup_count(&transaction)? < MAX_PENDING_CLEANUPS);

        let expired_jobs = {
            let mut statement = transaction.prepare(
                "SELECT event_jobs.job_id, event_jobs.snapshot_json, event_jobs.worker_lease_until, \
                        event_jobs.retain_until, event_jobs.retention_seconds, \
                        event_artifacts.artifact_id, event_artifacts.path, event_artifacts.file_identity \
                 FROM event_jobs LEFT JOIN event_artifacts ON event_artifacts.job_id = event_jobs.job_id \
                 WHERE ((event_jobs.worker_lease_until > 0 AND event_jobs.worker_lease_until <= ?1) \
                    OR (event_jobs.worker_lease_until = 0 AND event_jobs.retain_until <= ?1)) \
                 AND (?2 = 1 OR event_artifacts.file_identity IS NULL \
                      OR (event_jobs.worker_lease_until > 0 AND event_jobs.worker_lease_until <= ?1)) \
                 ORDER BY CASE WHEN event_jobs.worker_lease_until > 0 \
                               THEN event_jobs.worker_lease_until ELSE event_jobs.retain_until END, \
                          event_jobs.job_id LIMIT ?3",
            )?;
            statement
                .query_map(
                    params![
                        now,
                        cleanup_capacity_available,
                        i64::try_from(MAX_EXPIRY_BATCH).unwrap_or(i64::MAX)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, Option<String>>(6)?,
                            row.get::<_, Option<Vec<u8>>>(7)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (
            job_id,
            snapshot_json,
            worker_lease_until,
            retain_until,
            retention_seconds,
            artifact_id,
            path,
            file_identity,
        ) in expired_jobs
        {
            let snapshot: Value =
                serde_json::from_str(&snapshot_json).map_err(|_| EventStoreError::Corrupt)?;
            let state = snapshot.get("state").and_then(Value::as_str).unwrap_or("");
            if !is_terminal_state(state) {
                if worker_lease_until > now {
                    continue;
                }
                let failed = json!({
                    "job_id": job_id,
                    "state": "failed",
                    "failure": "worker_lease_expired"
                });
                let failed_json = encode_bounded_json(&failed, MAX_SNAPSHOT_BYTES)?;
                let next_retain_until = now.saturating_add(retention_seconds.max(1));
                append_in_transaction(
                    &transaction,
                    &job_id,
                    "job.failed",
                    &failed,
                    &failed_json,
                    AppendPolicy {
                        is_completion: false,
                        allow_terminal_event: true,
                        allow_stale_worker: true,
                    },
                )?;
                transaction.execute(
                    "UPDATE event_jobs SET retain_until = ?1, worker_lease_until = 0 WHERE job_id = ?2",
                    params![next_retain_until, job_id],
                )?;
                continue;
            }
            if retain_until > now {
                continue;
            }
            if file_identity.is_some()
                && pending_cleanup_count(&transaction)? >= MAX_PENDING_CLEANUPS
            {
                // Keep capability and metadata state together until there is
                // room to persist the exact identity-bound cleanup intent.
                continue;
            }
            expire_capability_subject(&transaction, &format!("job:{job_id}"))?;
            if let (Some(artifact_id), Some(path), Some(file_identity)) =
                (&artifact_id, &path, &file_identity)
            {
                expire_capability_subject(&transaction, &format!("artifact:{artifact_id}"))?;
                transaction.execute(
                    "INSERT OR IGNORE INTO event_expiry_outbox(\
                         job_id, artifact_id, path, file_identity, attempt_count, next_attempt_at\
                     ) VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                    params![job_id, artifact_id, path, file_identity, now],
                )?;
            } else if let Some(artifact_id) = &artifact_id {
                // Legacy metadata without identity can be retired but its
                // pathname is never followed or placed into cleanup work.
                expire_capability_subject(&transaction, &format!("artifact:{artifact_id}"))?;
            }
            transaction.execute("DELETE FROM event_jobs WHERE job_id = ?1", [&job_id])?;
            report.records_expired = report.records_expired.saturating_add(1);
        }

        let standalone_artifacts = {
            let mut statement = transaction.prepare(
                "SELECT artifact_id, path, file_identity FROM event_artifacts \
                 WHERE job_id IS NULL AND expires_at <= ?1 \
                   AND (?2 = 1 OR file_identity IS NULL) \
                 ORDER BY expires_at, artifact_id LIMIT ?3",
            )?;
            statement
                .query_map(
                    params![
                        now,
                        cleanup_capacity_available,
                        i64::try_from(MAX_EXPIRY_BATCH).unwrap_or(i64::MAX)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<Vec<u8>>>(2)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (artifact_id, path, file_identity) in standalone_artifacts {
            if file_identity.is_some()
                && pending_cleanup_count(&transaction)? >= MAX_PENDING_CLEANUPS
            {
                continue;
            }
            expire_capability_subject(&transaction, &format!("artifact:{artifact_id}"))?;
            if let Some(file_identity) = file_identity {
                transaction.execute(
                    "INSERT OR IGNORE INTO event_expiry_outbox(\
                         job_id, artifact_id, path, file_identity, attempt_count, next_attempt_at\
                     ) VALUES ('', ?1, ?2, ?3, 0, ?4)",
                    params![artifact_id, path, file_identity, now],
                )?;
            }
            transaction.execute(
                "DELETE FROM event_artifacts WHERE artifact_id = ?1 AND job_id IS NULL",
                [&artifact_id],
            )?;
            report.records_expired = report.records_expired.saturating_add(1);
        }
        transaction.commit()?;

        let (deleted, _) = self.process_cleanup_outbox(MAX_EXPIRY_BATCH)?;
        let connection = self.connect()?;
        let remaining: i64 = connection.query_row(
            "SELECT COUNT(*) FROM event_expiry_outbox WHERE file_identity IS NOT NULL",
            [],
            |row| row.get(0),
        )?;
        report.artifacts_deleted = deleted;
        report.cleanup_pending = usize::try_from(remaining).unwrap_or(usize::MAX);
        Ok(report)
    }

    fn process_cleanup_outbox(&self, limit: usize) -> Result<(usize, usize), EventStoreError> {
        let now = current_unix_seconds();
        let pending = {
            let connection = self.connect()?;
            let mut statement = connection.prepare(
                "SELECT job_id, artifact_id, path, file_identity, attempt_count, scan_cursor, scan_pass \
                 FROM event_expiry_outbox WHERE file_identity IS NOT NULL AND next_attempt_at <= ?1 \
                 ORDER BY next_attempt_at, job_id, artifact_id LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![now, i64::try_from(limit).unwrap_or(i64::MAX)],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, i64>(4)?,
                            row.get::<_, Option<String>>(5)?,
                            row.get::<_, i64>(6)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut deleted = 0usize;
        let mut retryable = 0usize;
        for (job_id, artifact_id, path, identity, attempt_count, scan_cursor, scan_pass) in pending
        {
            if !(0..=1).contains(&scan_pass)
                || scan_cursor
                    .as_ref()
                    .is_some_and(|cursor| cursor.len() > MAX_IDENTITY_SCAN_CURSOR_BYTES)
            {
                return Err(EventStoreError::Corrupt);
            }
            let leaf = Path::new(&path)
                .file_name()
                .and_then(|leaf| leaf.to_str())
                .ok_or(EventStoreError::Corrupt)?;
            let cleanup = self.artifact_directory.remove_named_file_if_identity_page(
                leaf,
                &identity,
                scan_cursor.as_deref(),
            );
            match cleanup {
                Ok(IdentityCleanupPage::Removed) => {}
                Ok(IdentityCleanupPage::Continue(next_cursor)) => {
                    retryable = retryable.saturating_add(1);
                    if next_cursor.is_some() {
                        let connection = self.connect()?;
                        connection.execute(
                            "UPDATE event_expiry_outbox SET scan_cursor = ?1, next_attempt_at = ?2 \
                             WHERE job_id = ?3 AND artifact_id = ?4",
                            params![next_cursor, now, job_id, artifact_id],
                        )?;
                    } else if scan_cursor.is_some() && scan_pass == 0 {
                        // The sorted scan reached its end; make one bounded
                        // wraparound pass before classifying the identity as
                        // absent, so directory changes cannot hide earlier names.
                        let connection = self.connect()?;
                        connection.execute(
                            "UPDATE event_expiry_outbox SET scan_cursor = NULL, scan_pass = 1, next_attempt_at = ?1 \
                             WHERE job_id = ?2 AND artifact_id = ?3",
                            params![now, job_id, artifact_id],
                        )?;
                    } else {
                        let next_attempt = attempt_count.saturating_add(1);
                        let next_at = now.saturating_add(IDENTITY_REVIEW_BACKOFF_SECONDS);
                        let connection = self.connect()?;
                        connection.execute(
                            "UPDATE event_expiry_outbox SET attempt_count = ?1, next_attempt_at = ?2, \
                                 scan_cursor = NULL, scan_pass = 0 \
                             WHERE job_id = ?3 AND artifact_id = ?4",
                            params![next_attempt, next_at, job_id, artifact_id],
                        )?;
                    }
                    continue;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    // NotFound means the bounded scan completed and did not
                    // find the pinned identity. Keep the durable intent for
                    // manual recovery; absence is never proof of deletion.
                    retryable = retryable.saturating_add(1);
                    let next_attempt = attempt_count.saturating_add(1);
                    let next_at = now.saturating_add(IDENTITY_REVIEW_BACKOFF_SECONDS);
                    let connection = self.connect()?;
                    connection.execute(
                        "UPDATE event_expiry_outbox SET attempt_count = ?1, next_attempt_at = ?2, \
                             scan_cursor = NULL, scan_pass = 0 \
                         WHERE job_id = ?3 AND artifact_id = ?4",
                        params![next_attempt, next_at, job_id, artifact_id],
                    )?;
                    continue;
                }
                Err(_) => {
                    retryable = retryable.saturating_add(1);
                    let next_attempt = attempt_count.saturating_add(1);
                    let delay = cleanup_retry_delay(next_attempt);
                    let connection = self.connect()?;
                    connection.execute(
                        "UPDATE event_expiry_outbox SET attempt_count = ?1, next_attempt_at = ?2 \
                         WHERE job_id = ?3 AND artifact_id = ?4",
                        params![next_attempt, now.saturating_add(delay), job_id, artifact_id],
                    )?;
                    continue;
                }
            }
            let connection = self.connect()?;
            connection.execute(
                "DELETE FROM event_expiry_outbox WHERE job_id = ?1 AND artifact_id = ?2",
                params![job_id, artifact_id],
            )?;
            deleted = deleted.saturating_add(1);
        }
        Ok((deleted, retryable))
    }
}

fn append_in_transaction(
    transaction: &Transaction<'_>,
    job_id: &str,
    event_type: &str,
    payload: &Value,
    snapshot_json: &str,
    policy: AppendPolicy,
) -> Result<u64, EventStoreError> {
    if !valid_resource_id(job_id) || !valid_event_type(event_type) {
        return Err(EventStoreError::InvalidRecord);
    }
    let payload_json = encode_bounded_json(payload, MAX_EVENT_BYTES)?;
    let (current_blob, current_snapshot_json, retain_until, worker_lease_until):
        (Vec<u8>, String, i64, i64) = transaction
        .query_row(
            "SELECT revision, snapshot_json, retain_until, worker_lease_until FROM event_jobs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or(EventStoreError::JobNotFound)?;
    let now = current_unix_seconds();
    let current_snapshot: Value =
        serde_json::from_str(&current_snapshot_json).map_err(|_| EventStoreError::Corrupt)?;
    let current_state = current_snapshot
        .get("state")
        .and_then(Value::as_str)
        .unwrap_or("");
    if is_terminal_state(current_state) && !policy.allow_terminal_event {
        return Err(EventStoreError::InvalidTransition);
    }
    if !policy.allow_stale_worker
        && job_is_expired(&current_snapshot, retain_until, worker_lease_until, now)
    {
        return Err(EventStoreError::Expired);
    }
    let current = decode_revision(&current_blob)?;
    let next = current
        .checked_add(1)
        .ok_or(EventStoreError::RevisionExhausted)?;
    let revision = encode_revision(next);
    transaction.execute(
        "INSERT INTO job_events(job_id, revision, event_type, payload_json, is_completion) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            job_id,
            revision.as_slice(),
            event_type,
            payload_json,
            policy.is_completion
        ],
    )?;
    transaction.execute(
        "UPDATE event_jobs SET revision = ?1, snapshot_json = ?2 WHERE job_id = ?3",
        params![revision.as_slice(), snapshot_json, job_id],
    )?;
    transaction.execute(
        "DELETE FROM job_events WHERE job_id = ?1 AND is_completion = 0 AND revision NOT IN (\
             SELECT revision FROM job_events WHERE job_id = ?1 AND is_completion = 0 \
             ORDER BY revision DESC LIMIT ?2)",
        params![job_id, MAX_RETAINED_SUFFIX],
    )?;
    Ok(next)
}

fn expire_capability_subject(
    transaction: &Transaction<'_>,
    subject: &str,
) -> Result<(), EventStoreError> {
    if table_exists(transaction, "capabilities")? {
        transaction.execute(
            "UPDATE capabilities SET expires_at = 0 WHERE subject = ?1",
            [subject],
        )?;
    }
    Ok(())
}

fn table_exists(transaction: &Transaction<'_>, table: &str) -> Result<bool, rusqlite::Error> {
    transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [table],
        |row| row.get(0),
    )
}

fn table_has_column(
    transaction: &Transaction<'_>,
    table: &str,
    column: &str,
) -> Result<bool, rusqlite::Error> {
    // Both identifiers are internal schema constants, never request values.
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|name| name == column))
}

fn pending_cleanup_count(transaction: &Transaction<'_>) -> Result<i64, EventStoreError> {
    Ok(transaction.query_row(
        "SELECT COUNT(*) FROM event_expiry_outbox WHERE file_identity IS NOT NULL",
        [],
        |row| row.get(0),
    )?)
}

fn cleanup_retry_delay(attempt_count: i64) -> i64 {
    let exponent = u32::try_from(attempt_count.clamp(1, 12)).unwrap_or(12);
    1i64.checked_shl(exponent).unwrap_or(3600).min(3600)
}

fn live_link_capabilities(
    transaction: &Transaction<'_>,
    job_id: &str,
    artifact_id: &str,
    now: i64,
    proposed_expiry: i64,
) -> Result<LiveLinkCapabilitySelection, EventStoreError> {
    if !table_exists(transaction, "capabilities")? {
        return Err(EventStoreError::CapabilityMissing);
    }
    let job_subject = format!("job:{job_id}");
    let artifact_subject = format!("artifact:{artifact_id}");
    let mut statement = transaction.prepare(
        "SELECT token_hash, subject, scopes, expires_at FROM capabilities \
         WHERE subject = ?1 OR subject = ?2 ORDER BY subject, expires_at DESC LIMIT ?3",
    )?;
    let rows = statement
        .query_map(
            params![job_subject, artifact_subject, MAX_LINK_CAPABILITY_ROWS + 1],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )?
        .collect::<Result<Vec<_>, _>>()?;
    drop(statement);
    if i64::try_from(rows.len()).unwrap_or(i64::MAX) > MAX_LINK_CAPABILITY_ROWS {
        return Err(EventStoreError::Capacity);
    }

    let mut has_status = false;
    let mut has_events = false;
    let mut has_download = false;
    let mut minimum = proposed_expiry;
    let mut shorten = Vec::new();
    for (token_hash, subject, scopes, expires_at) in rows {
        if expires_at <= now {
            continue;
        }
        if token_hash.len() != 32 {
            return Err(EventStoreError::Corrupt);
        }
        let has_scope = |required: &str| scopes.split(',').any(|scope| scope == required);
        let relevant = if subject == job_subject {
            let status = has_scope("status");
            let events = has_scope("events");
            has_status |= status;
            has_events |= events;
            status || events
        } else if subject == artifact_subject {
            let download = has_scope("download");
            has_download |= download;
            download
        } else {
            false
        };
        if relevant {
            minimum = minimum.min(expires_at);
            shorten.push((token_hash, subject));
        }
    }
    if !has_status || !has_events || !has_download {
        return Err(EventStoreError::CapabilityMissing);
    }
    Ok((minimum, shorten))
}

fn encode_bounded_json(value: &Value, maximum: usize) -> Result<String, EventStoreError> {
    let bytes = serde_json::to_vec(value).map_err(|_| EventStoreError::InvalidRecord)?;
    if bytes.len() > maximum {
        return Err(EventStoreError::InvalidRecord);
    }
    String::from_utf8(bytes).map_err(|_| EventStoreError::InvalidRecord)
}

fn encode_revision(revision: u64) -> [u8; 8] {
    revision.to_be_bytes()
}

fn decode_revision(revision: &[u8]) -> Result<u64, EventStoreError> {
    let bytes: [u8; 8] = revision.try_into().map_err(|_| EventStoreError::Corrupt)?;
    Ok(u64::from_be_bytes(bytes))
}

fn valid_resource_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_RESOURCE_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_event_type(value: &str) -> bool {
    value.len() <= MAX_EVENT_TYPE_BYTES
        && matches!(
            value,
            "job.state_changed"
                | "job.progress"
                | "job.warning"
                | "job.completed"
                | "job.failed"
                | "queue.position_changed"
        )
}

fn is_terminal_state(state: &str) -> bool {
    matches!(state, "completed" | "failed" | "cancelled")
}

fn is_terminal_event(event_type: &str) -> bool {
    matches!(event_type, "job.completed" | "job.failed")
}

fn job_is_expired(snapshot: &Value, retain_until: i64, worker_lease_until: i64, now: i64) -> bool {
    let state = snapshot.get("state").and_then(Value::as_str).unwrap_or("");
    if is_terminal_state(state) {
        retain_until <= now
    } else {
        worker_lease_until <= now
    }
}

fn current_unix_seconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}
