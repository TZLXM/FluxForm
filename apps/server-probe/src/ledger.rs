use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_IP_TEXT_BYTES: usize = 45;
const MAX_SECRET_ROTATION_KEYS: usize = 4;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS global_budget (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0)
);
CREATE TABLE IF NOT EXISTS ip_identities (
    id INTEGER PRIMARY KEY AUTOINCREMENT
);
CREATE TABLE IF NOT EXISTS ip_hashes (
    identity_id INTEGER NOT NULL REFERENCES ip_identities(id),
    ip_hash TEXT NOT NULL UNIQUE CHECK (length(ip_hash) = 64),
    PRIMARY KEY (identity_id, ip_hash)
);
CREATE TABLE IF NOT EXISTS daily_usage (
    identity_id INTEGER NOT NULL REFERENCES ip_identities(id),
    day INTEGER NOT NULL CHECK (day >= 0),
    used_bytes INTEGER NOT NULL CHECK (used_bytes >= 0),
    PRIMARY KEY (identity_id, day)
);
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id INTEGER NOT NULL REFERENCES ip_identities(id),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'receiving', 'uploaded', 'probing', 'queued', 'expired', 'rejected')),
    reserved_bytes INTEGER NOT NULL CHECK (reserved_bytes >= 0),
    actual_bytes INTEGER CHECK (actual_bytes IS NULL OR actual_bytes >= 0),
    created_day INTEGER NOT NULL CHECK (created_day >= 0),
    upload_path TEXT
);
CREATE INDEX IF NOT EXISTS uploads_identity_state ON uploads(identity_id, state);
CREATE TABLE IF NOT EXISTS cleanup_outbox (
    session_id INTEGER PRIMARY KEY REFERENCES uploads(id),
    relative_path TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0)
);
"#;

#[derive(Debug, Error)]
pub enum LimitError {
    #[error("invalid upload ledger configuration")]
    InvalidConfiguration,
    #[error("invalid client IP address")]
    InvalidIp,
    #[error("invalid upload size")]
    InvalidSize,
    #[error("upload exceeds the per-file limit")]
    FileTooLarge,
    #[error("daily upload quota exceeded")]
    DailyQuotaExceeded,
    #[error("simultaneous session limit exceeded")]
    SessionLimitExceeded,
    #[error("global reservation capacity exceeded")]
    GlobalCapacityExceeded,
    #[error("disk safety margin would be consumed")]
    DiskSafetyMargin,
    #[error("actual upload size exceeds its reservation")]
    SettlementExceedsReservation,
    #[error("illegal upload state transition")]
    InvalidTransition,
    #[error("upload session does not exist")]
    UnknownSession,
    #[error("invalid upload path")]
    InvalidUploadPath,
    #[error("upload accounting invariant failed")]
    AccountingInvariant,
    #[error("database is busy")]
    DatabaseBusy,
    #[error("database operation failed")]
    Database(#[source] rusqlite::Error),
    #[error("filesystem operation failed")]
    Filesystem(#[source] io::Error),
}

impl From<rusqlite::Error> for LimitError {
    fn from(error: rusqlite::Error) -> Self {
        match &error {
            rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
                rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked => {
                    Self::DatabaseBusy
                }
                _ => Self::Database(error),
            },
            _ => Self::Database(error),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UploadState {
    Reserved,
    Receiving,
    Uploaded,
    Probing,
    Queued,
    Expired,
    Rejected,
}

impl UploadState {
    pub const ALL: [Self; 7] = [
        Self::Reserved,
        Self::Receiving,
        Self::Uploaded,
        Self::Probing,
        Self::Queued,
        Self::Expired,
        Self::Rejected,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reserved => "reserved",
            Self::Receiving => "receiving",
            Self::Uploaded => "uploaded",
            Self::Probing => "probing",
            Self::Queued => "queued",
            Self::Expired => "expired",
            Self::Rejected => "rejected",
        }
    }

    fn from_str(value: &str) -> Result<Self, LimitError> {
        match value {
            "reserved" => Ok(Self::Reserved),
            "receiving" => Ok(Self::Receiving),
            "uploaded" => Ok(Self::Uploaded),
            "probing" => Ok(Self::Probing),
            "queued" => Ok(Self::Queued),
            "expired" => Ok(Self::Expired),
            "rejected" => Ok(Self::Rejected),
            _ => Err(LimitError::AccountingInvariant),
        }
    }

    fn is_reserved(self) -> bool {
        matches!(self, Self::Reserved | Self::Receiving)
    }

    fn is_terminal(self) -> bool {
        matches!(self, Self::Expired | Self::Rejected)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UploadReservation {
    pub session_id: i64,
    pub reserved_bytes: u64,
    pub state: UploadState,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupReport {
    pub completed: usize,
    pub retryable: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LedgerLimits {
    pub max_file_bytes: u64,
    pub daily_quota_bytes: u64,
    pub max_active_sessions_per_ip: u32,
    pub max_global_reserved_bytes: u64,
    pub disk_available_bytes: u64,
    pub disk_safety_margin_bytes: u64,
}

#[derive(Clone)]
pub struct UploadLedger {
    database_path: PathBuf,
    upload_root: PathBuf,
    limits: LedgerLimits,
    // Secrets stay process-local. Only domain-separated HMAC values enter SQLite.
    secrets: Vec<[u8; 32]>,
}

impl UploadLedger {
    pub fn open(
        database_path: impl AsRef<Path>,
        upload_root: impl AsRef<Path>,
        limits: LedgerLimits,
        secrets: Vec<[u8; 32]>,
    ) -> Result<Self, LimitError> {
        validate_limits(limits)?;
        if secrets.is_empty() || secrets.len() > MAX_SECRET_ROTATION_KEYS {
            return Err(LimitError::InvalidConfiguration);
        }
        let upload_root =
            fs::canonicalize(upload_root).map_err(|_| LimitError::InvalidConfiguration)?;
        if !upload_root.is_dir() {
            return Err(LimitError::InvalidConfiguration);
        }

        let ledger = Self {
            database_path: database_path.as_ref().to_path_buf(),
            upload_root,
            limits,
            secrets,
        };
        let mut connection = ledger.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute_batch(SCHEMA)?;
        transaction.execute(
            "INSERT OR IGNORE INTO global_budget(singleton, reserved_bytes) VALUES (1, 0)",
            [],
        )?;
        transaction.commit()?;
        Ok(ledger)
    }

    pub fn reserve(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
    ) -> Result<UploadReservation, LimitError> {
        let requested = declared_bytes.unwrap_or(self.limits.max_file_bytes);
        if requested == 0 {
            return Err(LimitError::InvalidSize);
        }
        if requested > self.limits.max_file_bytes {
            return Err(LimitError::FileTooLarge);
        }
        let canonical_ip = normalize_ip(ip_key)?;
        let day = current_day_bucket();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let identity_id = self.resolve_identity(&transaction, &canonical_ip)?;
        let (used, active_reserved, active_sessions) =
            identity_usage(&transaction, identity_id, day)?;
        if active_sessions >= u64::from(self.limits.max_active_sessions_per_ip) {
            return Err(LimitError::SessionLimitExceeded);
        }
        let daily_commitment = checked_add(checked_add(used, active_reserved)?, requested)?;
        if daily_commitment > self.limits.daily_quota_bytes {
            return Err(LimitError::DailyQuotaExceeded);
        }

        let current_reserved = read_global_reserved(&transaction)?;
        let next_reserved = checked_add(current_reserved, requested)?;
        if next_reserved > self.limits.max_global_reserved_bytes {
            return Err(LimitError::GlobalCapacityExceeded);
        }
        if next_reserved > disk_reservation_limit(self.limits) {
            return Err(LimitError::DiskSafetyMargin);
        }

        transaction.execute(
            "INSERT INTO uploads(identity_id, state, reserved_bytes, actual_bytes, created_day) \
             VALUES (?1, 'reserved', ?2, NULL, ?3)",
            params![identity_id, to_sql_integer(requested)?, day],
        )?;
        let session_id = transaction.last_insert_rowid();
        write_global_reserved(&transaction, next_reserved)?;
        transaction.commit()?;
        Ok(UploadReservation {
            session_id,
            reserved_bytes: requested,
            state: UploadState::Reserved,
        })
    }

    pub fn expand(
        &self,
        session_id: i64,
        required_total: u64,
    ) -> Result<UploadReservation, LimitError> {
        if required_total == 0 {
            return Err(LimitError::InvalidSize);
        }
        if required_total > self.limits.max_file_bytes {
            return Err(LimitError::FileTooLarge);
        }
        let day = current_day_bucket();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, identity_id) = load_session(&transaction, session_id)?;
        if !state.is_reserved() {
            return Err(LimitError::InvalidTransition);
        }
        if required_total <= reserved {
            transaction.commit()?;
            return Ok(UploadReservation {
                session_id,
                reserved_bytes: reserved,
                state,
            });
        }

        let delta = required_total - reserved;
        let (used, active_reserved, _) = identity_usage(&transaction, identity_id, day)?;
        if checked_add(checked_add(used, active_reserved)?, delta)? > self.limits.daily_quota_bytes
        {
            return Err(LimitError::DailyQuotaExceeded);
        }
        let next_reserved = checked_add(read_global_reserved(&transaction)?, delta)?;
        if next_reserved > self.limits.max_global_reserved_bytes {
            return Err(LimitError::GlobalCapacityExceeded);
        }
        if next_reserved > disk_reservation_limit(self.limits) {
            return Err(LimitError::DiskSafetyMargin);
        }

        let changed = transaction.execute(
            "UPDATE uploads SET reserved_bytes = ?1 WHERE id = ?2 AND state IN ('reserved', 'receiving')",
            params![to_sql_integer(required_total)?, session_id],
        )?;
        if changed != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        write_global_reserved(&transaction, next_reserved)?;
        transaction.commit()?;
        Ok(UploadReservation {
            session_id,
            reserved_bytes: required_total,
            state,
        })
    }

    pub fn transition(&self, session_id: i64, target: UploadState) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, _) = load_session(&transaction, session_id)?;
        if !transition_is_legal(state, target) {
            return Err(LimitError::InvalidTransition);
        }
        let releases = target == UploadState::Rejected && reserved > 0;
        if releases {
            release_global_reserved(&transaction, reserved)?;
        }
        let changed = transaction.execute(
            "UPDATE uploads SET state = ?1, reserved_bytes = CASE WHEN ?2 THEN 0 ELSE reserved_bytes END \
             WHERE id = ?3 AND state = ?4",
            params![target.as_str(), releases, session_id, state.as_str()],
        )?;
        if changed != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        if target == UploadState::Rejected {
            enqueue_cleanup(&transaction, session_id)?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn settle(&self, session_id: i64, actual_bytes: u64) -> Result<(), LimitError> {
        if actual_bytes > self.limits.max_file_bytes {
            return Err(LimitError::FileTooLarge);
        }
        let day = current_day_bucket();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, identity_id) = load_session(&transaction, session_id)?;
        if state != UploadState::Receiving {
            return Err(LimitError::InvalidTransition);
        }
        if actual_bytes > reserved {
            return Err(LimitError::SettlementExceedsReservation);
        }

        let (used, active_reserved, _) = identity_usage(&transaction, identity_id, day)?;
        let other_reserved = active_reserved
            .checked_sub(reserved)
            .ok_or(LimitError::AccountingInvariant)?;
        let next_daily_usage = checked_add(used, actual_bytes)?;
        if checked_add(next_daily_usage, other_reserved)? > self.limits.daily_quota_bytes {
            return Err(LimitError::DailyQuotaExceeded);
        }
        let next_global_reserved = read_global_reserved(&transaction)?
            .checked_sub(reserved)
            .ok_or(LimitError::AccountingInvariant)?;

        transaction.execute(
            "INSERT INTO daily_usage(identity_id, day, used_bytes) VALUES (?1, ?2, ?3) \
             ON CONFLICT(identity_id, day) DO UPDATE SET used_bytes = used_bytes + excluded.used_bytes",
            params![identity_id, day, to_sql_integer(actual_bytes)?],
        )?;
        let changed = transaction.execute(
            "UPDATE uploads SET state = 'uploaded', reserved_bytes = 0, actual_bytes = ?1 \
             WHERE id = ?2 AND state = 'receiving' AND reserved_bytes = ?3",
            params![
                to_sql_integer(actual_bytes)?,
                session_id,
                to_sql_integer(reserved)?
            ],
        )?;
        if changed != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        write_global_reserved(&transaction, next_global_reserved)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn expire(&self, session_id: i64) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, _) = load_session(&transaction, session_id)?;
        if state == UploadState::Expired {
            transaction.commit()?;
            return Ok(());
        }
        if state == UploadState::Rejected {
            return Err(LimitError::InvalidTransition);
        }
        if reserved > 0 {
            release_global_reserved(&transaction, reserved)?;
        }
        let changed = transaction.execute(
            "UPDATE uploads SET state = 'expired', reserved_bytes = 0 WHERE id = ?1 AND state = ?2",
            params![session_id, state.as_str()],
        )?;
        if changed != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        enqueue_cleanup(&transaction, session_id)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn set_upload_path(&self, session_id: i64, relative_path: &Path) -> Result<(), LimitError> {
        let relative_path = normalize_relative_path(relative_path)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, _, _) = load_session(&transaction, session_id)?;
        if state.is_terminal() || state == UploadState::Queued {
            return Err(LimitError::InvalidTransition);
        }
        let changed = transaction.execute(
            "UPDATE uploads SET upload_path = ?1 WHERE id = ?2 AND upload_path IS NULL",
            params![relative_path, session_id],
        )?;
        if changed != 1 {
            return Err(LimitError::InvalidTransition);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn reconcile_cleanup_jobs(&self) -> Result<CleanupReport, LimitError> {
        let connection = self.connect()?;
        let jobs = {
            let mut statement = connection.prepare(
                "SELECT session_id, relative_path FROM cleanup_outbox ORDER BY session_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        drop(connection);

        let mut report = CleanupReport::default();
        for (session_id, relative_path) in jobs {
            let relative = normalize_relative_path(Path::new(&relative_path));
            let deletion = match relative {
                Ok(relative) => self.remove_upload_file(Path::new(&relative)),
                Err(_) => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid path")),
            };
            let mut connection = self.connect()?;
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            match deletion {
                Ok(()) => {
                    let changed = transaction.execute(
                        "DELETE FROM cleanup_outbox WHERE session_id = ?1",
                        [session_id],
                    )?;
                    if changed == 1 {
                        report.completed += 1;
                    }
                }
                Err(_) => {
                    transaction.execute(
                        "UPDATE cleanup_outbox SET attempts = attempts + 1 WHERE session_id = ?1",
                        [session_id],
                    )?;
                    report.retryable += 1;
                }
            }
            transaction.commit()?;
        }
        Ok(report)
    }

    pub fn reserved_bytes(&self) -> Result<u64, LimitError> {
        read_global_reserved(&self.connect()?)
    }

    pub fn state(&self, session_id: i64) -> Result<UploadState, LimitError> {
        let connection = self.connect()?;
        let state = connection
            .query_row(
                "SELECT state FROM uploads WHERE id = ?1",
                [session_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or(LimitError::UnknownSession)?;
        UploadState::from_str(&state)
    }

    fn connect(&self) -> Result<Connection, LimitError> {
        let connection = Connection::open(&self.database_path)?;
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        connection.execute_batch("PRAGMA foreign_keys = ON;")?;
        Ok(connection)
    }

    fn resolve_identity(
        &self,
        transaction: &Transaction<'_>,
        canonical_ip: &str,
    ) -> Result<i64, LimitError> {
        let mut identities = Vec::new();
        for secret in &self.secrets {
            let hash = hmac_ip(secret, canonical_ip);
            if let Some(identity_id) = transaction
                .query_row(
                    "SELECT identity_id FROM ip_hashes WHERE ip_hash = ?1",
                    [&hash],
                    |row| row.get(0),
                )
                .optional()?
                && !identities.contains(&identity_id)
            {
                identities.push(identity_id);
            }
        }

        let identity_id = if identities.is_empty() {
            transaction.execute("INSERT INTO ip_identities DEFAULT VALUES", [])?;
            transaction.last_insert_rowid()
        } else {
            identities.sort_unstable();
            let primary = identities[0];
            for other in identities.into_iter().skip(1) {
                merge_identity(transaction, primary, other)?;
            }
            primary
        };

        for secret in &self.secrets {
            let hash = hmac_ip(secret, canonical_ip);
            transaction.execute(
                "INSERT OR IGNORE INTO ip_hashes(identity_id, ip_hash) VALUES (?1, ?2)",
                params![identity_id, hash],
            )?;
        }
        Ok(identity_id)
    }

    fn remove_upload_file(&self, relative: &Path) -> io::Result<()> {
        let target = self.upload_root.join(relative);
        let parent = target.parent().unwrap_or(&self.upload_root);
        let canonical_parent = match fs::canonicalize(parent) {
            Ok(path) => path,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if !canonical_parent.starts_with(&self.upload_root) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path escaped root",
            ));
        }
        match fs::remove_file(target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

fn validate_limits(limits: LedgerLimits) -> Result<(), LimitError> {
    if limits.max_file_bytes == 0 || limits.max_active_sessions_per_ip == 0 {
        return Err(LimitError::InvalidConfiguration);
    }
    for value in [
        limits.max_file_bytes,
        limits.daily_quota_bytes,
        limits.max_global_reserved_bytes,
        limits.disk_available_bytes,
        limits.disk_safety_margin_bytes,
    ] {
        to_sql_integer(value).map_err(|_| LimitError::InvalidConfiguration)?;
    }
    Ok(())
}

fn normalize_ip(ip_key: &str) -> Result<String, LimitError> {
    if ip_key.is_empty() || ip_key.len() > MAX_IP_TEXT_BYTES {
        return Err(LimitError::InvalidIp);
    }
    let ip = ip_key
        .parse::<IpAddr>()
        .map_err(|_| LimitError::InvalidIp)?;
    Ok(ip.to_string())
}

fn normalize_relative_path(path: &Path) -> Result<String, LimitError> {
    let text = path.to_str().ok_or(LimitError::InvalidUploadPath)?;
    if text.is_empty() || text.len() > 4096 || text.contains('\0') || path.is_absolute() {
        return Err(LimitError::InvalidUploadPath);
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(LimitError::InvalidUploadPath);
    }
    Ok(text.to_owned())
}

fn transition_is_legal(from: UploadState, to: UploadState) -> bool {
    matches!(
        (from, to),
        (UploadState::Reserved, UploadState::Receiving)
            | (UploadState::Uploaded, UploadState::Probing)
            | (UploadState::Probing, UploadState::Queued)
    ) || (to == UploadState::Rejected && !from.is_terminal())
}

fn load_session(
    transaction: &Transaction<'_>,
    session_id: i64,
) -> Result<(UploadState, u64, i64), LimitError> {
    let row = transaction
        .query_row(
            "SELECT state, reserved_bytes, identity_id FROM uploads WHERE id = ?1",
            [session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?
        .ok_or(LimitError::UnknownSession)?;
    Ok((
        UploadState::from_str(&row.0)?,
        from_sql_integer(row.1)?,
        row.2,
    ))
}

fn identity_usage(
    connection: &Connection,
    identity_id: i64,
    day: i64,
) -> Result<(u64, u64, u64), LimitError> {
    let used = connection
        .query_row(
            "SELECT COALESCE(used_bytes, 0) FROM daily_usage WHERE identity_id = ?1 AND day = ?2",
            params![identity_id, day],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .unwrap_or(0);
    let used = from_sql_integer(used)?;
    let (reserved, sessions): (i64, i64) = connection.query_row(
        "SELECT COALESCE(SUM(reserved_bytes), 0), COUNT(*) FROM uploads \
         WHERE identity_id = ?1 AND state IN ('reserved', 'receiving')",
        [identity_id],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    Ok((
        used,
        from_sql_integer(reserved)?,
        from_sql_integer(sessions)?,
    ))
}

fn read_global_reserved(connection: &Connection) -> Result<u64, LimitError> {
    let reserved = connection.query_row(
        "SELECT reserved_bytes FROM global_budget WHERE singleton = 1",
        [],
        |row| row.get::<_, i64>(0),
    )?;
    from_sql_integer(reserved)
}

fn write_global_reserved(transaction: &Transaction<'_>, reserved: u64) -> Result<(), LimitError> {
    let changed = transaction.execute(
        "UPDATE global_budget SET reserved_bytes = ?1 WHERE singleton = 1",
        [to_sql_integer(reserved)?],
    )?;
    if changed != 1 {
        return Err(LimitError::AccountingInvariant);
    }
    Ok(())
}

fn release_global_reserved(transaction: &Transaction<'_>, bytes: u64) -> Result<(), LimitError> {
    let current = read_global_reserved(transaction)?;
    let remaining = current
        .checked_sub(bytes)
        .ok_or(LimitError::AccountingInvariant)?;
    write_global_reserved(transaction, remaining)
}

fn enqueue_cleanup(transaction: &Transaction<'_>, session_id: i64) -> Result<(), LimitError> {
    transaction.execute(
        "INSERT OR IGNORE INTO cleanup_outbox(session_id, relative_path, attempts) \
         SELECT id, upload_path, 0 FROM uploads WHERE id = ?1 AND upload_path IS NOT NULL",
        [session_id],
    )?;
    Ok(())
}

fn merge_identity(
    transaction: &Transaction<'_>,
    primary: i64,
    other: i64,
) -> Result<(), LimitError> {
    transaction.execute(
        "UPDATE uploads SET identity_id = ?1 WHERE identity_id = ?2",
        params![primary, other],
    )?;
    let other_usage = {
        let mut statement = transaction
            .prepare("SELECT day, used_bytes FROM daily_usage WHERE identity_id = ?1")?;
        statement
            .query_map([other], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    for (day, used) in other_usage {
        let existing = transaction
            .query_row(
                "SELECT used_bytes FROM daily_usage WHERE identity_id = ?1 AND day = ?2",
                params![primary, day],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        let combined = checked_add(from_sql_integer(existing)?, from_sql_integer(used)?)?;
        transaction.execute(
            "INSERT INTO daily_usage(identity_id, day, used_bytes) VALUES (?1, ?2, ?3) \
             ON CONFLICT(identity_id, day) DO UPDATE SET used_bytes = excluded.used_bytes",
            params![primary, day, to_sql_integer(combined)?],
        )?;
    }
    transaction.execute("DELETE FROM daily_usage WHERE identity_id = ?1", [other])?;
    transaction.execute(
        "UPDATE ip_hashes SET identity_id = ?1 WHERE identity_id = ?2",
        params![primary, other],
    )?;
    transaction.execute("DELETE FROM ip_identities WHERE id = ?1", [other])?;
    Ok(())
}

fn current_day_bucket() -> i64 {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    i64::try_from(seconds / 86_400).unwrap_or(i64::MAX)
}

fn disk_reservation_limit(limits: LedgerLimits) -> u64 {
    limits
        .disk_available_bytes
        .saturating_sub(limits.disk_safety_margin_bytes)
}

fn checked_add(left: u64, right: u64) -> Result<u64, LimitError> {
    left.checked_add(right)
        .ok_or(LimitError::AccountingInvariant)
}

fn to_sql_integer(value: u64) -> Result<i64, LimitError> {
    i64::try_from(value).map_err(|_| LimitError::InvalidSize)
}

fn from_sql_integer(value: i64) -> Result<u64, LimitError> {
    u64::try_from(value).map_err(|_| LimitError::AccountingInvariant)
}

fn hmac_ip(secret: &[u8; 32], canonical_ip: &str) -> String {
    let mut inner_pad = [0x36; 64];
    let mut outer_pad = [0x5c; 64];
    for (index, key_byte) in secret.iter().enumerate() {
        inner_pad[index] ^= key_byte;
        outer_pad[index] ^= key_byte;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(b"fluxform-upload-ip-v1\0");
    inner.update(canonical_ip.as_bytes());
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    let digest = outer.finalize();
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}
