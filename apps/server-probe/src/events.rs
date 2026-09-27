use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use serde_json::{Value, json};
use thiserror::Error;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_ACTIVE_JOBS_AND_CLEANUPS: i64 = 128;
const MAX_RETAINED_SUFFIX: i64 = 64;
const MAX_EVENT_BYTES: usize = 2 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 4 * 1024;
const MAX_RESOURCE_ID_BYTES: usize = 128;
const MAX_EVENT_TYPE_BYTES: usize = 64;
const MAX_FILENAME_BYTES: usize = 255;
const MAX_CONTENT_TYPE_BYTES: usize = 256;
const MAX_ARTIFACT_PATH_BYTES: usize = 4096;
const MAX_EXPIRY_BATCH: usize = 32;

const EVENT_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS event_jobs (
    job_id TEXT PRIMARY KEY NOT NULL CHECK (length(job_id) BETWEEN 1 AND 128),
    revision BLOB NOT NULL CHECK (length(revision) = 8),
    snapshot_json TEXT NOT NULL CHECK (length(CAST(snapshot_json AS BLOB)) <= 4096),
    retain_until INTEGER NOT NULL CHECK (retain_until >= 0)
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
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0)
);
CREATE INDEX IF NOT EXISTS event_artifacts_expiry ON event_artifacts(expires_at);
CREATE TABLE IF NOT EXISTS event_expiry_outbox (
    job_id TEXT NOT NULL,
    artifact_id TEXT NOT NULL,
    path TEXT NOT NULL CHECK (length(CAST(path AS BLOB)) BETWEEN 1 AND 4096),
    PRIMARY KEY (job_id, artifact_id)
);
"#;

#[derive(Clone)]
pub struct EventStore {
    database_path: PathBuf,
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
    #[error("event store data is corrupt")]
    Corrupt,
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
    pub path: PathBuf,
    pub filename: String,
    pub content_type: String,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExpiryReport {
    pub records_expired: usize,
    pub artifacts_deleted: usize,
    pub cleanup_pending: usize,
}

impl EventStore {
    pub fn open(database_path: impl AsRef<Path>) -> Result<Self, EventStoreError> {
        let store = Self {
            database_path: database_path.as_ref().to_path_buf(),
        };
        let mut connection = store.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(EVENT_SCHEMA)?;
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
                "SELECT revision, snapshot_json FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;

        let revision = if let Some((revision_blob, previous_json)) = existing {
            let previous_revision = decode_revision(&revision_blob)?;
            let previous: Value =
                serde_json::from_str(&previous_json).map_err(|_| EventStoreError::Corrupt)?;
            if previous.get("state").and_then(Value::as_str) == Some(state) {
                transaction.commit()?;
                return Ok(previous_revision);
            }

            let event_type = match state {
                "completed" => "job.completed",
                "failed" => "job.failed",
                _ => "job.state_changed",
            };
            let terminal = matches!(state, "completed" | "failed" | "cancelled");
            if terminal {
                transaction.execute(
                    "UPDATE event_jobs SET retain_until = ?1 WHERE job_id = ?2",
                    params![retain_until, job_id],
                )?;
            }
            append_in_transaction(
                &transaction,
                job_id,
                event_type,
                &snapshot,
                &snapshot_json,
                terminal && state == "completed",
            )?
        } else {
            let active_records: i64 = transaction.query_row(
                "SELECT (SELECT COUNT(*) FROM event_jobs) + \
                 (SELECT COUNT(*) FROM event_artifacts WHERE job_id IS NULL) + \
                 (SELECT COUNT(*) FROM event_expiry_outbox)",
                [],
                |row| row.get(0),
            )?;
            if active_records >= MAX_ACTIVE_JOBS_AND_CLEANUPS {
                return Err(EventStoreError::Capacity);
            }
            transaction.execute(
                "INSERT INTO event_jobs(job_id, revision, snapshot_json, retain_until) \
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    job_id,
                    encode_revision(0).as_slice(),
                    snapshot_json,
                    retain_until
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
                state == "completed",
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
        let snapshot_json = encode_bounded_json(snapshot, MAX_SNAPSHOT_BYTES)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let revision = append_in_transaction(
            &transaction,
            job_id,
            event_type,
            payload,
            &snapshot_json,
            event_type == "job.completed",
        )?;
        transaction.commit()?;
        Ok(revision)
    }

    pub fn snapshot(&self, job_id: &str) -> Result<JobSnapshot, EventStoreError> {
        if !valid_resource_id(job_id) {
            return Err(EventStoreError::JobNotFound);
        }
        let connection = self.connect()?;
        let row = connection
            .query_row(
                "SELECT revision, snapshot_json, retain_until FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(EventStoreError::JobNotFound)?;
        if row.2 <= current_unix_seconds() {
            return Err(EventStoreError::Expired);
        }
        Ok(JobSnapshot {
            revision: decode_revision(&row.0)?,
            data: serde_json::from_str(&row.1).map_err(|_| EventStoreError::Corrupt)?,
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
                "SELECT revision, snapshot_json, retain_until FROM event_jobs WHERE job_id = ?1",
                [job_id],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(EventStoreError::JobNotFound)?;
        if row.2 <= current_unix_seconds() {
            return Err(EventStoreError::Expired);
        }
        let snapshot = JobSnapshot {
            revision: decode_revision(&row.0)?,
            data: serde_json::from_str(&row.1).map_err(|_| EventStoreError::Corrupt)?,
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
        let path = path.to_string_lossy().into_owned();
        if path.len() > MAX_ARTIFACT_PATH_BYTES {
            return Err(EventStoreError::InvalidRecord);
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(job_id) = job_id {
            let exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM event_jobs WHERE job_id = ?1)",
                [job_id],
                |row| row.get(0),
            )?;
            if !exists {
                return Err(EventStoreError::JobNotFound);
            }
        } else {
            let active_records: i64 = transaction.query_row(
                "SELECT (SELECT COUNT(*) FROM event_jobs) + \
                 (SELECT COUNT(*) FROM event_artifacts WHERE job_id IS NULL) + \
                 (SELECT COUNT(*) FROM event_expiry_outbox)",
                [],
                |row| row.get(0),
            )?;
            if active_records >= MAX_ACTIVE_JOBS_AND_CLEANUPS {
                return Err(EventStoreError::Capacity);
            }
        }
        transaction.execute(
            "INSERT INTO event_artifacts(artifact_id, job_id, path, filename, content_type, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![artifact_id, job_id, path, filename, content_type, expires_at],
        )?;
        if let Some(job_id) = job_id {
            transaction.execute(
                "UPDATE event_jobs SET retain_until = ?1 WHERE job_id = ?2",
                params![expires_at, job_id],
            )?;
            if table_exists(&transaction, "capabilities")? {
                transaction.execute(
                    "UPDATE capabilities SET expires_at = ?1 \
                     WHERE subject = ?2 OR subject = ?3",
                    params![
                        expires_at,
                        format!("job:{job_id}"),
                        format!("artifact:{artifact_id}")
                    ],
                )?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn artifact(&self, artifact_id: &str) -> Result<ArtifactMetadata, EventStoreError> {
        if !valid_resource_id(artifact_id) {
            return Err(EventStoreError::JobNotFound);
        }
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT path, filename, content_type, expires_at FROM event_artifacts WHERE artifact_id = ?1",
                [artifact_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                    ))
                },
            )
            .optional()?
            .filter(|(_, _, _, expires_at)| *expires_at > current_unix_seconds())
            .map(|(path, filename, content_type, _)| ArtifactMetadata {
                path: PathBuf::from(path),
                filename,
                content_type,
            })
            .ok_or(EventStoreError::JobNotFound)
    }

    /// Atomically retires expired capabilities, snapshots, and event metadata,
    /// then completes artifact deletion from a durable outbox.
    pub fn reconcile_expired(&self) -> Result<ExpiryReport, EventStoreError> {
        let now = current_unix_seconds();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut report = ExpiryReport::default();

        let expired_jobs = {
            let mut statement = transaction.prepare(
                "SELECT event_jobs.job_id, event_artifacts.artifact_id, event_artifacts.path \
                 FROM event_jobs LEFT JOIN event_artifacts ON event_artifacts.job_id = event_jobs.job_id \
                 WHERE event_jobs.retain_until <= ?1 ORDER BY event_jobs.retain_until, event_jobs.job_id LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![now, i64::try_from(MAX_EXPIRY_BATCH).unwrap_or(i64::MAX)],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, Option<String>>(1)?,
                            row.get::<_, Option<String>>(2)?,
                        ))
                    },
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (job_id, artifact_id, path) in expired_jobs {
            expire_capability_subject(&transaction, &format!("job:{job_id}"))?;
            if let (Some(artifact_id), Some(path)) = (&artifact_id, &path) {
                expire_capability_subject(&transaction, &format!("artifact:{artifact_id}"))?;
                transaction.execute(
                    "INSERT OR IGNORE INTO event_expiry_outbox(job_id, artifact_id, path) VALUES (?1, ?2, ?3)",
                    params![job_id, artifact_id, path],
                )?;
            }
            transaction.execute("DELETE FROM event_jobs WHERE job_id = ?1", [&job_id])?;
            report.records_expired = report.records_expired.saturating_add(1);
        }

        let standalone_artifacts = {
            let mut statement = transaction.prepare(
                "SELECT artifact_id, path FROM event_artifacts \
                 WHERE job_id IS NULL AND expires_at <= ?1 ORDER BY expires_at, artifact_id LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![now, i64::try_from(MAX_EXPIRY_BATCH).unwrap_or(i64::MAX)],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (artifact_id, path) in standalone_artifacts {
            expire_capability_subject(&transaction, &format!("artifact:{artifact_id}"))?;
            transaction.execute(
                "INSERT OR IGNORE INTO event_expiry_outbox(job_id, artifact_id, path) VALUES ('', ?1, ?2)",
                params![artifact_id, path],
            )?;
            transaction.execute(
                "DELETE FROM event_artifacts WHERE artifact_id = ?1 AND job_id IS NULL",
                [&artifact_id],
            )?;
            report.records_expired = report.records_expired.saturating_add(1);
        }
        transaction.commit()?;

        let (deleted, _) = self.process_cleanup_outbox(MAX_EXPIRY_BATCH)?;
        let connection = self.connect()?;
        let remaining: i64 =
            connection.query_row("SELECT COUNT(*) FROM event_expiry_outbox", [], |row| {
                row.get(0)
            })?;
        report.artifacts_deleted = deleted;
        report.cleanup_pending = usize::try_from(remaining).unwrap_or(usize::MAX);
        Ok(report)
    }

    fn process_cleanup_outbox(&self, limit: usize) -> Result<(usize, usize), EventStoreError> {
        let pending = {
            let connection = self.connect()?;
            let mut statement = connection.prepare(
                "SELECT job_id, artifact_id, path FROM event_expiry_outbox ORDER BY job_id, artifact_id LIMIT ?1",
            )?;
            statement
                .query_map([i64::try_from(limit).unwrap_or(i64::MAX)], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        let mut deleted = 0usize;
        let mut retryable = 0usize;
        for (job_id, artifact_id, path) in pending {
            match fs::remove_file(Path::new(&path)) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => {
                    retryable = retryable.saturating_add(1);
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
    is_completion: bool,
) -> Result<u64, EventStoreError> {
    if !valid_resource_id(job_id) || !valid_event_type(event_type) {
        return Err(EventStoreError::InvalidRecord);
    }
    let payload_json = encode_bounded_json(payload, MAX_EVENT_BYTES)?;
    let (current_blob, retain_until): (Vec<u8>, i64) = transaction
        .query_row(
            "SELECT revision, retain_until FROM event_jobs WHERE job_id = ?1",
            [job_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(EventStoreError::JobNotFound)?;
    if retain_until <= current_unix_seconds() {
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
            is_completion
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

fn current_unix_seconds() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    )
    .unwrap_or(i64::MAX)
}
