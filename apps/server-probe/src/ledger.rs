use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::Capability;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_IP_TEXT_BYTES: usize = 45;
const MAX_SECRET_ROTATION_KEYS: usize = 4;
const CURRENT_SCHEMA_VERSION: i64 = 3;

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
    key_id BLOB NOT NULL CHECK (length(key_id) = 32),
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
    capability_hash BLOB NOT NULL CHECK (length(capability_hash) = 32),
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
    #[error("upload session capability is invalid")]
    Unauthorized,
    #[error("operating system random source failed")]
    RandomUnavailable,
    #[error("capability could not be created")]
    CapabilityIssueFailed,
    #[error("invalid upload path")]
    InvalidUploadPath,
    #[error("upload accounting invariant failed")]
    AccountingInvariant,
    #[error("database is busy")]
    DatabaseBusy,
    #[error("database operation failed")]
    Database(#[source] rusqlite::Error),
    #[error("database schema version is newer than this server supports")]
    UnsupportedSchemaVersion,
    #[error("existing upload commitments exceed current limits")]
    ExistingCommitmentsExceedLimits,
    #[error("server secret rotation would lose an active or current-day quota identity")]
    SecretRetentionRequired,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UploadReservation {
    pub session_id: i64,
    pub reserved_bytes: u64,
    pub state: UploadState,
    /// Keep secret and send only to the client that created this reservation.
    pub session_token: SessionToken,
    /// Existing physically preallocated file; writers must not replace or truncate it.
    pub upload_path: PathBuf,
}

/// An opaque bearer credential. Debug output is intentionally redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionToken(String);

impl SessionToken {
    /// Returns the canonical bearer token returned with an upload reservation.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Parses a canonical bearer token received from a client.
    pub fn parse(value: &str) -> Result<Self, LimitError> {
        if let Ok(uuid) = Uuid::parse_str(value) {
            return Ok(Self(uuid.to_string()));
        }
        if crate::auth::is_canonical_capability_token(value) {
            return Ok(Self(value.to_owned()));
        }
        Err(LimitError::Unauthorized)
    }

    fn generate() -> Result<Self, LimitError> {
        crate::auth::generate_random_token()
            .map(Self)
            .map_err(|_| LimitError::RandomUnavailable)
    }

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0.as_bytes()).into()
    }
}

impl std::fmt::Debug for SessionToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SessionToken([REDACTED])")
    }
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
    pub disk_safety_margin_bytes: u64,
}

struct SecureReservationDirectory {
    handle: fs::File,
}

/// Reports currently available bytes on the filesystem containing `path`.
pub trait DiskSpaceProvider: Send + Sync {
    fn available_bytes(&self, path: &Path) -> io::Result<u64>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDiskSpace;

impl DiskSpaceProvider for SystemDiskSpace {
    fn available_bytes(&self, path: &Path) -> io::Result<u64> {
        system_available_bytes(path)
    }
}

#[derive(Clone)]
pub struct UploadLedger {
    database_path: PathBuf,
    upload_root: PathBuf,
    upload_root_directory: Arc<SecureReservationDirectory>,
    reservation_directory: Arc<SecureReservationDirectory>,
    limits: LedgerLimits,
    disk_space: Arc<dyn DiskSpaceProvider>,
    // Secrets stay process-local. Only domain-separated HMAC values enter SQLite.
    secrets: Vec<[u8; 32]>,
}

impl UploadLedger {
    /// Opens or migrates the ledger using the platform's live disk-space provider.
    ///
    /// Keep every secret needed by an active upload or by a current UTC-day
    /// quota identity in `secrets`. Startup rejects a rotation that would lose
    /// the identity alias until those sessions and quota windows have ended.
    pub fn open(
        database_path: impl AsRef<Path>,
        upload_root: impl AsRef<Path>,
        limits: LedgerLimits,
        secrets: Vec<[u8; 32]>,
    ) -> Result<Self, LimitError> {
        Self::open_internal(
            database_path,
            upload_root,
            limits,
            secrets,
            Arc::new(SystemDiskSpace),
            None,
        )
    }

    /// Opens a legacy database while retaining the explicitly declared key
    /// whose HMACs were used for its key-ID-less quota rows.
    ///
    /// The ID is SHA-256 of the 32-byte secret material.
    /// The operator must declare the key that generated every legacy IP hash;
    /// the key must also be present in `secrets` so quota lookup and future
    /// rotation checks continue to work. Legacy sessions without capabilities
    /// are expired and their files are queued for secure cleanup.
    pub fn open_with_legacy_key_id(
        database_path: impl AsRef<Path>,
        upload_root: impl AsRef<Path>,
        limits: LedgerLimits,
        secrets: Vec<[u8; 32]>,
        retained_key_id: [u8; 32],
    ) -> Result<Self, LimitError> {
        Self::open_internal(
            database_path,
            upload_root,
            limits,
            secrets,
            Arc::new(SystemDiskSpace),
            Some(retained_key_id),
        )
    }

    pub fn open_with_disk_space(
        database_path: impl AsRef<Path>,
        upload_root: impl AsRef<Path>,
        limits: LedgerLimits,
        secrets: Vec<[u8; 32]>,
        disk_space: Arc<dyn DiskSpaceProvider>,
    ) -> Result<Self, LimitError> {
        Self::open_internal(
            database_path,
            upload_root,
            limits,
            secrets,
            disk_space,
            None,
        )
    }

    fn open_internal(
        database_path: impl AsRef<Path>,
        upload_root: impl AsRef<Path>,
        limits: LedgerLimits,
        secrets: Vec<[u8; 32]>,
        disk_space: Arc<dyn DiskSpaceProvider>,
        retained_legacy_key_id: Option<[u8; 32]>,
    ) -> Result<Self, LimitError> {
        validate_limits(limits)?;
        if secrets.is_empty() || secrets.len() > MAX_SECRET_ROTATION_KEYS {
            return Err(LimitError::InvalidConfiguration);
        }
        if retained_legacy_key_id.is_some_and(|retained| {
            !secrets
                .iter()
                .any(|secret| secret_key_id(secret) == retained)
        }) {
            return Err(LimitError::InvalidConfiguration);
        }
        let upload_root =
            fs::canonicalize(upload_root).map_err(|_| LimitError::InvalidConfiguration)?;
        if !upload_root.is_dir() {
            return Err(LimitError::InvalidConfiguration);
        }
        let upload_root_directory = Arc::new(
            SecureReservationDirectory::open(&upload_root).map_err(LimitError::Filesystem)?,
        );
        let reservations_dir = upload_root.join(".fluxform-reservations");
        match fs::create_dir(&reservations_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(LimitError::Filesystem(error)),
        }
        let reservation_directory = Arc::new(
            SecureReservationDirectory::open(&reservations_dir).map_err(LimitError::Filesystem)?,
        );

        let ledger = Self {
            database_path: database_path.as_ref().to_path_buf(),
            upload_root,
            upload_root_directory,
            reservation_directory,
            limits,
            disk_space,
            secrets,
        };
        let mut connection = ledger.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let schema_version: i64 =
            transaction.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if !(0..=CURRENT_SCHEMA_VERSION).contains(&schema_version) {
            return Err(LimitError::UnsupportedSchemaVersion);
        }
        let had_uploads = table_exists(&transaction, "uploads")?;
        let had_capability_hash =
            had_uploads && table_has_column(&transaction, "uploads", "capability_hash")?;
        let had_ip_hashes = table_exists(&transaction, "ip_hashes")?;
        let had_key_id = had_ip_hashes && table_has_column(&transaction, "ip_hashes", "key_id")?;
        transaction.execute_batch(SCHEMA)?;
        if had_uploads && !had_capability_hash {
            transaction.execute(
                "ALTER TABLE uploads ADD COLUMN capability_hash BLOB CHECK (capability_hash IS NULL OR length(capability_hash) = 32)",
                [],
            )?;
        }
        if had_ip_hashes && !had_key_id {
            transaction.execute(
                "ALTER TABLE ip_hashes ADD COLUMN key_id BLOB CHECK (key_id IS NULL OR length(key_id) = 32)",
                [],
            )?;
        }
        transaction.execute(
            "INSERT OR IGNORE INTO global_budget(singleton, reserved_bytes) VALUES (1, 0)",
            [],
        )?;
        if schema_version < CURRENT_SCHEMA_VERSION {
            // Retire every legacy session without a capability, regardless of
            // its former state, and preserve deletion work before committing.
            transaction.execute(
                "INSERT OR IGNORE INTO cleanup_outbox(session_id, relative_path, attempts) \
                 SELECT id, upload_path, 0 FROM uploads \
                 WHERE capability_hash IS NULL AND upload_path IS NOT NULL",
                [],
            )?;
            transaction.execute(
                "UPDATE uploads SET state = 'expired', reserved_bytes = 0, capability_hash = NULL \
                 WHERE capability_hash IS NULL",
                [],
            )?;
        }
        if let Some(retained_key_id) = retained_legacy_key_id {
            transaction.execute(
                "UPDATE ip_hashes SET key_id = ?1 WHERE key_id IS NULL",
                [retained_key_id.as_slice()],
            )?;
        }
        transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
        ledger.validate_startup_invariants(&transaction)?;
        transaction.commit()?;
        ledger.reconcile_unreferenced_files()?;
        Ok(ledger)
    }

    pub fn reserve(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
    ) -> Result<UploadReservation, LimitError> {
        self.reserve_internal(ip_key, declared_bytes, SessionToken::generate()?, None)
            .map(|(reservation, _)| reservation)
    }

    pub(crate) fn reserve_with_upload_capability(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
        expires_at: SystemTime,
    ) -> Result<(UploadReservation, Capability), LimitError> {
        let (reservation, capability) = self.reserve_internal(
            ip_key,
            declared_bytes,
            SessionToken::generate()?,
            Some(expires_at),
        )?;
        capability
            .map(|capability| (reservation, capability))
            .ok_or(LimitError::AccountingInvariant)
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
    }

    fn reserve_internal(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
        session_token: SessionToken,
        capability_expiry: Option<SystemTime>,
    ) -> Result<(UploadReservation, Option<Capability>), LimitError> {
        let requested = declared_bytes.unwrap_or(self.limits.max_file_bytes);
        if requested == 0 {
            return Err(LimitError::InvalidSize);
        }
        if requested > self.limits.max_file_bytes {
            return Err(LimitError::FileTooLarge);
        }
        let canonical_ip = normalize_ip(ip_key)?;
        let day = current_day_bucket();
        let capability_hash = session_token.hash();
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
        self.check_disk_capacity(requested)?;

        let relative_path = format!(".fluxform-reservations/{}.upload", Uuid::new_v4());
        let file_name = Path::new(&relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(LimitError::InvalidUploadPath)?
            .to_owned();
        let upload_path = self.upload_root.join(&relative_path);
        let mut file_reservation = create_reserved_file(
            Arc::clone(&self.reservation_directory),
            &file_name,
            requested,
        )?;
        self.check_disk_safety_margin()?;

        transaction.execute(
            "INSERT INTO uploads(identity_id, capability_hash, state, reserved_bytes, actual_bytes, created_day, upload_path) \
             VALUES (?1, ?2, 'reserved', ?3, NULL, ?4, ?5)",
            params![identity_id, capability_hash.as_slice(), to_sql_integer(requested)?, day, relative_path],
        )?;
        let session_id = transaction.last_insert_rowid();

        let capability = if let Some(expires_at) = capability_expiry {
            let capability = Capability::prepare(
                format!("upload-session:{session_id}"),
                [crate::auth::Scope::Upload],
                expires_at,
            )
            .map_err(|_| LimitError::CapabilityIssueFailed)?;
            capability.insert_in_transaction(&transaction)?;

            let replacement = SessionToken::parse(capability.token())?;
            let changed = transaction.execute(
                "UPDATE uploads SET capability_hash = ?1 WHERE id = ?2 AND capability_hash = ?3",
                params![
                    replacement.hash().as_slice(),
                    session_id,
                    session_token.hash().as_slice(),
                ],
            )?;
            if changed != 1 {
                return Err(LimitError::AccountingInvariant);
            }
            Some((capability, replacement))
        } else {
            None
        };

        write_global_reserved(&transaction, next_reserved)?;
        transaction.commit()?;
        file_reservation.commit();
        let (capability, session_token) = match capability {
            Some((capability, session_token)) => (Some(capability), session_token),
            None => (None, session_token),
        };
        Ok((
            UploadReservation {
                session_id,
                reserved_bytes: requested,
                state: UploadState::Reserved,
                session_token,
                upload_path,
            },
            capability,
        ))
    }

    pub fn expand(
        &self,
        session_id: i64,
        capability: &SessionToken,
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
        let (state, reserved, identity_id, relative_path) =
            load_session(&transaction, session_id, capability)?;
        let upload_path = self.reservation_path(relative_path.as_deref())?;
        if !state.is_reserved() {
            return Err(LimitError::InvalidTransition);
        }
        if required_total <= reserved {
            transaction.commit()?;
            return Ok(UploadReservation {
                session_id,
                reserved_bytes: reserved,
                state,
                session_token: capability.clone(),
                upload_path,
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
        self.check_disk_capacity(delta)?;
        let file_name = reservation_leaf(Path::new(
            relative_path
                .as_deref()
                .ok_or(LimitError::AccountingInvariant)?,
        ))
        .map_err(|_| LimitError::InvalidUploadPath)?;
        let mut file_reservation = resize_reserved_file(
            Arc::clone(&self.reservation_directory),
            &file_name,
            required_total,
        )?;
        self.check_disk_safety_margin()?;

        let changed = transaction.execute(
            "UPDATE uploads SET reserved_bytes = ?1 WHERE id = ?2 AND state IN ('reserved', 'receiving')",
            params![to_sql_integer(required_total)?, session_id],
        )?;
        if changed != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        write_global_reserved(&transaction, next_reserved)?;
        transaction.commit()?;
        file_reservation.commit();
        Ok(UploadReservation {
            session_id,
            reserved_bytes: required_total,
            state,
            session_token: capability.clone(),
            upload_path,
        })
    }

    pub fn transition(
        &self,
        session_id: i64,
        capability: &SessionToken,
        target: UploadState,
    ) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, _, _) = load_session(&transaction, session_id, capability)?;
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

    pub fn settle(
        &self,
        session_id: i64,
        capability: &SessionToken,
        actual_bytes: u64,
    ) -> Result<(), LimitError> {
        if actual_bytes > self.limits.max_file_bytes {
            return Err(LimitError::FileTooLarge);
        }
        let day = current_day_bucket();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, identity_id, _) = load_session(&transaction, session_id, capability)?;
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

    pub fn expire(&self, session_id: i64, capability: &SessionToken) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, _, _) = load_session(&transaction, session_id, capability)?;
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

    pub fn state(
        &self,
        session_id: i64,
        capability: &SessionToken,
    ) -> Result<UploadState, LimitError> {
        let connection = self.connect()?;
        let row = connection
            .query_row(
                "SELECT state, capability_hash FROM uploads WHERE id = ?1",
                [session_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()?
            .ok_or(LimitError::UnknownSession)?;
        if !row
            .1
            .as_ref()
            .is_some_and(|stored| constant_time_equal(stored, &capability.hash()))
        {
            return Err(LimitError::Unauthorized);
        }
        UploadState::from_str(&row.0)
    }

    fn reservation_path(&self, relative: Option<&str>) -> Result<PathBuf, LimitError> {
        let relative = relative.ok_or(LimitError::AccountingInvariant)?;
        let normalized = normalize_relative_path(Path::new(relative))?;
        if !normalized.starts_with(".fluxform-reservations/") {
            return Err(LimitError::InvalidUploadPath);
        }
        Ok(self.upload_root.join(normalized))
    }

    fn check_disk_capacity(&self, additional: u64) -> Result<(), LimitError> {
        let required = checked_add(additional, self.limits.disk_safety_margin_bytes)?;
        let available = self
            .disk_space
            .available_bytes(&self.upload_root)
            .map_err(LimitError::Filesystem)?;
        if available < required {
            return Err(LimitError::DiskSafetyMargin);
        }
        Ok(())
    }

    fn check_disk_safety_margin(&self) -> Result<(), LimitError> {
        let available = self
            .disk_space
            .available_bytes(&self.upload_root)
            .map_err(LimitError::Filesystem)?;
        if available < self.limits.disk_safety_margin_bytes {
            return Err(LimitError::DiskSafetyMargin);
        }
        Ok(())
    }

    fn validate_startup_invariants(&self, transaction: &Transaction<'_>) -> Result<(), LimitError> {
        let active_reserved_sql: i64 = transaction.query_row(
            "SELECT COALESCE(SUM(reserved_bytes), 0) FROM uploads \
             WHERE state IN ('reserved', 'receiving')",
            [],
            |row| row.get(0),
        )?;
        let active_reserved = from_sql_integer(active_reserved_sql)?;
        if active_reserved > self.limits.max_global_reserved_bytes {
            return Err(LimitError::ExistingCommitmentsExceedLimits);
        }

        let active_files = {
            let mut statement = transaction.prepare(
                "SELECT reserved_bytes, upload_path FROM uploads \
                 WHERE state IN ('reserved', 'receiving') ORDER BY id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (reserved_sql, relative) in active_files {
            let reserved = from_sql_integer(reserved_sql)?;
            if reserved > self.limits.max_file_bytes {
                return Err(LimitError::ExistingCommitmentsExceedLimits);
            }
            let relative = relative.ok_or(LimitError::AccountingInvariant)?;
            let file_name = reservation_leaf(Path::new(&relative))
                .map_err(|_| LimitError::InvalidUploadPath)?;
            let file = self
                .reservation_directory
                .open_file(&file_name, false)
                .map_err(LimitError::Filesystem)?;
            let allocated = allocated_file_bytes(&file)?;
            if allocated < reserved {
                self.check_disk_capacity(reserved - allocated)?;
            }
            // Always reassert the committed size: a crash can leave excess
            // physical allocation even when the logical length looks correct.
            set_file_allocation(&file, reserved).map_err(LimitError::Filesystem)?;
            if allocated < reserved {
                self.check_disk_safety_margin()?;
            }
            if file.metadata().map_err(LimitError::Filesystem)?.len() != reserved
                || allocated_file_bytes(&file)? < reserved
            {
                return Err(LimitError::AccountingInvariant);
            }
        }

        let day = current_day_bucket();
        let identity_commitments = {
            let mut statement = transaction.prepare(
                "SELECT identity_id, COALESCE(SUM(reserved_bytes), 0), COUNT(*) \
                 FROM uploads WHERE state IN ('reserved', 'receiving') \
                 GROUP BY identity_id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (identity_id, reserved_sql, sessions_sql) in identity_commitments {
            let reserved = from_sql_integer(reserved_sql)?;
            let sessions = from_sql_integer(sessions_sql)?;
            let used_sql = transaction
                .query_row(
                    "SELECT used_bytes FROM daily_usage WHERE identity_id = ?1 AND day = ?2",
                    params![identity_id, day],
                    |row| row.get::<_, i64>(0),
                )
                .optional()?
                .unwrap_or(0);
            let used = from_sql_integer(used_sql)?;
            if sessions > u64::from(self.limits.max_active_sessions_per_ip)
                || checked_add(used, reserved)? > self.limits.daily_quota_bytes
            {
                return Err(LimitError::ExistingCommitmentsExceedLimits);
            }
        }

        let over_quota_identities = {
            let mut statement = transaction.prepare(
                "SELECT identity_id, used_bytes FROM daily_usage WHERE day = ?1 AND used_bytes > ?2",
            )?;
            statement
                .query_map(
                    params![day, to_sql_integer(self.limits.daily_quota_bytes)?],
                    |row| row.get::<_, i64>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        if !over_quota_identities.is_empty() {
            return Err(LimitError::ExistingCommitmentsExceedLimits);
        }

        validate_secret_retention(transaction, &self.secrets, day)?;

        let current_reserved = read_global_reserved(transaction)?;
        if current_reserved != active_reserved {
            write_global_reserved(transaction, active_reserved)?;
        }
        if active_reserved > 0 {
            self.check_disk_safety_margin()?;
        }
        Ok(())
    }

    fn reconcile_unreferenced_files(&self) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let committed_paths = {
            let mut statement = transaction.prepare(
                "SELECT upload_path FROM uploads \
                 WHERE upload_path IS NOT NULL \
                   AND state IN ('reserved', 'receiving', 'uploaded', 'probing', 'queued') \
                 UNION SELECT relative_path FROM cleanup_outbox",
            )?;
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let referenced_leaves: std::collections::HashSet<String> = committed_paths
            .iter()
            .filter_map(|relative| reservation_leaf(Path::new(relative)).ok())
            .collect();

        let orphans = self
            .reservation_directory
            .enumerate_files()
            .map_err(LimitError::Filesystem)?
            .into_iter()
            .filter(|leaf| !referenced_leaves.contains(leaf))
            .collect::<Vec<_>>();
        transaction.commit()?;

        for leaf in orphans {
            self.reservation_directory
                .remove_file(&leaf)
                .map_err(LimitError::Filesystem)?;
        }
        Ok(())
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
                "INSERT OR IGNORE INTO ip_hashes(identity_id, ip_hash, key_id) VALUES (?1, ?2, ?3)",
                params![identity_id, hash, secret_key_id(secret).as_slice()],
            )?;
        }
        Ok(identity_id)
    }

    fn remove_upload_file(&self, relative: &Path) -> io::Result<()> {
        self.remove_upload_file_with_hook(relative, || {})
    }

    fn remove_upload_file_with_hook<F>(&self, relative: &Path, before_remove: F) -> io::Result<()>
    where
        F: FnOnce(),
    {
        let normalized = normalize_relative_path(relative).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid upload cleanup path")
        })?;
        let relative = Path::new(&normalized);
        let mut components = Vec::new();
        for component in relative.components() {
            let Component::Normal(component) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid upload cleanup component",
                ));
            };
            let component = component.to_str().ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "upload cleanup component is not UTF-8",
                )
            })?;
            if component.is_empty()
                || component.contains(['/', '\\', '\0'])
                || cfg!(windows) && component.contains(':')
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid upload cleanup component",
                ));
            }
            components.push(component.to_owned());
        }
        if components.len() == 2 && components[0] == ".fluxform-reservations" {
            before_remove();
            return self.reservation_directory.remove_file(&components[1]);
        }
        let leaf = components.pop().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "empty upload cleanup path")
        })?;
        let mut parent = self.upload_root_directory.try_clone()?;
        for component in components {
            parent = parent.open_directory_child(&component)?;
        }
        before_remove();
        parent.remove_file(&leaf)
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
    capability: &SessionToken,
) -> Result<(UploadState, u64, i64, Option<String>), LimitError> {
    let row = transaction
        .query_row(
            "SELECT state, reserved_bytes, identity_id, capability_hash, upload_path FROM uploads WHERE id = ?1",
            [session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            },
        )
        .optional()?
        .ok_or(LimitError::UnknownSession)?;
    if !row
        .3
        .as_ref()
        .is_some_and(|stored| constant_time_equal(stored, &capability.hash()))
    {
        return Err(LimitError::Unauthorized);
    }
    Ok((
        UploadState::from_str(&row.0)?,
        from_sql_integer(row.1)?,
        row.2,
        row.4,
    ))
}

fn reservation_leaf(relative: &Path) -> io::Result<String> {
    let mut components = relative.components();
    let Some(Component::Normal(directory)) = components.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid reservation path",
        ));
    };
    if directory != ".fluxform-reservations" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid reservation directory",
        ));
    }
    let Some(Component::Normal(leaf)) = components.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid reservation filename",
        ));
    };
    if components.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "nested reservation path",
        ));
    }
    let leaf = leaf
        .to_str()
        .filter(|leaf| !leaf.is_empty() && !leaf.contains('\0'))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid reservation filename")
        })?;
    Ok(leaf.to_owned())
}

impl SecureReservationDirectory {
    #[cfg(unix)]
    fn open(path: &Path) -> io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;

        let handle = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        Ok(Self { handle })
    }

    #[cfg(unix)]
    fn open_directory_child(&self, leaf: &str) -> io::Result<Self> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};

        let leaf = CString::new(leaf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid directory name"))?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(self.handle.as_raw_fd(), leaf.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            handle: unsafe { fs::File::from_raw_fd(fd) },
        })
    }

    #[cfg(unix)]
    fn open_file(&self, leaf: &str, create_new: bool) -> io::Result<fs::File> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};

        let leaf = CString::new(leaf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?;
        let mut flags = libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        if create_new {
            flags |= libc::O_CREAT | libc::O_EXCL;
        }
        let fd = unsafe { libc::openat(self.handle.as_raw_fd(), leaf.as_ptr(), flags, 0o600) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    #[cfg(windows)]
    fn open(path: &Path) -> io::Result<Self> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::FromRawHandle;

        #[repr(C)]
        struct FileAttributeTagInfo {
            attributes: u32,
            reparse_tag: u32,
        }

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateFileW(
                filename: *const u16,
                desired_access: u32,
                share_mode: u32,
                security_attributes: *mut std::ffi::c_void,
                creation_disposition: u32,
                flags_and_attributes: u32,
                template_file: *mut std::ffi::c_void,
            ) -> *mut std::ffi::c_void;
            fn GetFileInformationByHandleEx(
                file: *mut std::ffi::c_void,
                info_class: i32,
                info: *mut std::ffi::c_void,
                size: u32,
            ) -> i32;
            fn CloseHandle(handle: *mut std::ffi::c_void) -> i32;
        }

        let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
        wide.push(0);
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                0x0001 | 0x0002 | 0x0020 | 0x0040 | 0x0080 | 0x0010_0000,
                0x0001 | 0x0002 | 0x0004,
                std::ptr::null_mut(),
                3,
                0x0200_0000 | 0x0020_0000,
                std::ptr::null_mut(),
            )
        };
        if handle as isize == -1 {
            return Err(io::Error::last_os_error());
        }
        let mut tag_info = FileAttributeTagInfo {
            attributes: 0,
            reparse_tag: 0,
        };
        let valid = unsafe {
            GetFileInformationByHandleEx(
                handle,
                9,
                (&mut tag_info as *mut FileAttributeTagInfo).cast(),
                std::mem::size_of::<FileAttributeTagInfo>() as u32,
            )
        } != 0;
        if !valid {
            let error = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(error);
        }
        if tag_info.attributes & 0x10 == 0 || tag_info.attributes & 0x400 != 0 {
            unsafe { CloseHandle(handle) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reservation path is not a non-reparse directory",
            ));
        }
        let handle = unsafe { fs::File::from_raw_handle(handle) };
        Ok(Self { handle })
    }

    #[cfg(windows)]
    fn open_file(&self, leaf: &str, create_new: bool) -> io::Result<fs::File> {
        windows_open_relative_file(&self.handle, leaf, create_new, false)
    }

    #[cfg(windows)]
    fn open_directory_child(&self, leaf: &str) -> io::Result<Self> {
        windows_open_relative_directory(&self.handle, leaf).map(|handle| Self { handle })
    }

    #[cfg(not(any(unix, windows)))]
    fn open(_path: &Path) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure reservation directory handles are unsupported",
        ))
    }

    #[cfg(not(any(unix, windows)))]
    fn open_file(&self, _leaf: &str, _create_new: bool) -> io::Result<fs::File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative file access is unsupported",
        ))
    }

    #[cfg(not(any(unix, windows)))]
    fn open_directory_child(&self, _leaf: &str) -> io::Result<Self> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative directory access is unsupported",
        ))
    }

    fn try_clone(&self) -> io::Result<Self> {
        Ok(Self {
            handle: self.handle.try_clone()?,
        })
    }

    fn remove_file(&self, leaf: &str) -> io::Result<()> {
        secure_unlink(&self.handle, leaf)
    }

    #[cfg(unix)]
    fn enumerate_files(&self) -> io::Result<Vec<String>> {
        use std::os::fd::AsRawFd;

        let descriptor_path = if cfg!(target_os = "linux") {
            PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()))
        } else {
            PathBuf::from(format!("/dev/fd/{}", self.handle.as_raw_fd()))
        };
        let mut names = Vec::new();
        for entry in fs::read_dir(descriptor_path)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let name = entry.file_name().into_string().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reservation filename is not UTF-8",
                )
            })?;
            names.push(name);
        }
        Ok(names)
    }

    #[cfg(windows)]
    fn enumerate_files(&self) -> io::Result<Vec<String>> {
        windows_enumerate_files(&self.handle)
    }
}

#[cfg(windows)]
fn windows_enumerate_files(directory: &fs::File) -> io::Result<Vec<String>> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileIdBothDirectoryInfo {
        next_entry_offset: u32,
        file_index: u32,
        creation_time: i64,
        last_access_time: i64,
        last_write_time: i64,
        change_time: i64,
        end_of_file: i64,
        allocation_size: i64,
        file_attributes: u32,
        file_name_length: u32,
        ea_size: u32,
        short_name_length: u8,
        short_name: [u16; 12],
        file_id: i64,
        file_name: [u16; 1],
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut std::ffi::c_void,
            info_class: i32,
            info: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    const BUFFER_BYTES: usize = 64 * 1024;
    const FILE_ID_BOTH_DIRECTORY_INFO: i32 = 10;
    const FILE_ID_BOTH_DIRECTORY_RESTART_INFO: i32 = 11;
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
    const ERROR_NO_MORE_FILES: i32 = 18;

    let mut names = Vec::new();
    let mut restart = true;
    loop {
        let mut buffer = vec![0_u64; BUFFER_BYTES / std::mem::size_of::<u64>()];
        let info_class = if restart {
            FILE_ID_BOTH_DIRECTORY_RESTART_INFO
        } else {
            FILE_ID_BOTH_DIRECTORY_INFO
        };
        let success = unsafe {
            GetFileInformationByHandleEx(
                directory.as_raw_handle().cast(),
                info_class,
                buffer.as_mut_ptr().cast(),
                BUFFER_BYTES as u32,
            )
        };
        if success == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES) {
                break;
            }
            return Err(error);
        }
        restart = false;

        let mut offset = 0_usize;
        loop {
            if offset + std::mem::size_of::<FileIdBothDirectoryInfo>() > BUFFER_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid directory enumeration entry",
                ));
            }
            let info = unsafe {
                &*(buffer
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .cast::<FileIdBothDirectoryInfo>())
            };
            let name_length = usize::try_from(info.file_name_length).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid filename length")
            })?;
            let file_name_offset = std::mem::offset_of!(FileIdBothDirectoryInfo, file_name);
            if name_length % 2 != 0
                || offset
                    .checked_add(file_name_offset)
                    .and_then(|start| start.checked_add(name_length))
                    .is_none_or(|end| end > BUFFER_BYTES)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid directory enumeration filename",
                ));
            }
            let name_units = unsafe {
                std::slice::from_raw_parts(
                    info.file_name.as_ptr(),
                    name_length / std::mem::size_of::<u16>(),
                )
            };
            let name = String::from_utf16(name_units).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "reservation filename is not UTF-16",
                )
            })?;
            if name != "."
                && name != ".."
                && info.file_attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)
                    == 0
            {
                names.push(name);
            }

            if info.next_entry_offset == 0 {
                break;
            }
            offset = offset
                .checked_add(info.next_entry_offset as usize)
                .filter(|next| *next < BUFFER_BYTES)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid directory entry offset")
                })?;
        }
    }
    Ok(names)
}

#[cfg(unix)]
fn secure_unlink(directory: &fs::File, leaf: &str) -> io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::AsRawFd;

    let leaf = CString::new(leaf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?;
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), leaf.as_ptr(), 0) };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::NotFound {
        Ok(())
    } else {
        Err(error)
    }
}

#[cfg(windows)]
fn windows_open_relative_file(
    directory: &fs::File,
    leaf: &str,
    create_new: bool,
    delete_access: bool,
) -> io::Result<fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut std::ffi::c_void,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut std::ffi::c_void,
        security_quality_of_service: *mut std::ffi::c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: *mut std::ffi::c_void,
        information: usize,
    }
    #[repr(C)]
    struct FileAttributeTagInfo {
        attributes: u32,
        reparse_tag: u32,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut *mut std::ffi::c_void,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut std::ffi::c_void,
            ea_length: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut std::ffi::c_void,
            info_class: i32,
            info: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    if leaf.is_empty() || leaf.contains(['\\', '/']) || leaf.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid filename",
        ));
    }
    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let byte_len = u16::try_from(name.len().saturating_mul(2))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename too long"))?;
    let mut unicode_name = UnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: directory.as_raw_handle().cast(),
        object_name: &mut unicode_name,
        attributes: 0x40 | 0x1000,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = IoStatusBlock {
        status: std::ptr::null_mut(),
        information: 0,
    };
    let mut raw_file = std::ptr::null_mut();
    let desired_access = if delete_access {
        0x0001_0000 | 0x0080 | 0x0010_0000
    } else {
        0x0002 | 0x0080 | 0x0100 | 0x0010_0000
    };
    let status = unsafe {
        NtCreateFile(
            &mut raw_file,
            desired_access,
            &mut attributes,
            &mut status_block,
            std::ptr::null_mut(),
            0x80,
            0x0001 | 0x0002 | 0x0004,
            if create_new { 2 } else { 1 },
            0x40 | 0x20 | 0x0020_0000,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let file = unsafe { fs::File::from_raw_handle(raw_file) };
    let mut tag_info = FileAttributeTagInfo {
        attributes: 0,
        reparse_tag: 0,
    };
    let valid = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            9,
            (&mut tag_info as *mut FileAttributeTagInfo).cast(),
            std::mem::size_of::<FileAttributeTagInfo>() as u32,
        )
    } != 0;
    if !valid {
        return Err(io::Error::last_os_error());
    }
    if tag_info.attributes & (0x10 | 0x400) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to open a directory or reparse point as a reservation file",
        ));
    }
    Ok(file)
}

#[cfg(windows)]
fn windows_open_relative_directory(directory: &fs::File, leaf: &str) -> io::Result<fs::File> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut std::ffi::c_void,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut std::ffi::c_void,
        security_quality_of_service: *mut std::ffi::c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: *mut std::ffi::c_void,
        information: usize,
    }
    #[repr(C)]
    struct FileAttributeTagInfo {
        attributes: u32,
        reparse_tag: u32,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut *mut std::ffi::c_void,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut std::ffi::c_void,
            ea_length: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut std::ffi::c_void,
            info_class: i32,
            info: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    if leaf.is_empty() || leaf.contains(['\\', '/', ':', '\0']) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid directory name",
        ));
    }
    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let byte_len = u16::try_from(name.len().saturating_mul(2))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "directory name too long"))?;
    let mut unicode_name = UnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: directory.as_raw_handle().cast(),
        object_name: &mut unicode_name,
        attributes: 0x40 | 0x1000,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = IoStatusBlock {
        status: std::ptr::null_mut(),
        information: 0,
    };
    let mut raw_directory = std::ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut raw_directory,
            0x0001 | 0x0020 | 0x0080 | 0x0010_0000,
            &mut attributes,
            &mut status_block,
            std::ptr::null_mut(),
            0x80,
            0x0001 | 0x0002 | 0x0004,
            1,
            0x0001 | 0x0020 | 0x0020_0000,
            std::ptr::null_mut(),
            0,
        )
    };
    if status < 0 {
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let handle = unsafe { fs::File::from_raw_handle(raw_directory) };
    let mut tag_info = FileAttributeTagInfo {
        attributes: 0,
        reparse_tag: 0,
    };
    let valid = unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle().cast(),
            9,
            (&mut tag_info as *mut FileAttributeTagInfo).cast(),
            std::mem::size_of::<FileAttributeTagInfo>() as u32,
        )
    } != 0;
    if !valid {
        return Err(io::Error::last_os_error());
    }
    if tag_info.attributes & 0x10 == 0 || tag_info.attributes & 0x400 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "upload cleanup parent is not a non-reparse directory",
        ));
    }
    Ok(handle)
}

#[cfg(windows)]
fn secure_unlink(directory: &fs::File, leaf: &str) -> io::Result<()> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root_directory: *mut std::ffi::c_void,
        object_name: *mut UnicodeString,
        attributes: u32,
        security_descriptor: *mut std::ffi::c_void,
        security_quality_of_service: *mut std::ffi::c_void,
    }
    #[repr(C)]
    struct IoStatusBlock {
        status: *mut std::ffi::c_void,
        information: usize,
    }
    #[repr(C)]
    struct FileAttributeTagInfo {
        attributes: u32,
        reparse_tag: u32,
    }

    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            file_handle: *mut *mut std::ffi::c_void,
            desired_access: u32,
            object_attributes: *mut ObjectAttributes,
            io_status_block: *mut IoStatusBlock,
            allocation_size: *mut i64,
            file_attributes: u32,
            share_access: u32,
            create_disposition: u32,
            create_options: u32,
            ea_buffer: *mut std::ffi::c_void,
            ea_length: u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut std::ffi::c_void,
            info_class: i32,
            info: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
        fn SetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            class: i32,
            info: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    let mut name: Vec<u16> = leaf.encode_utf16().collect();
    let byte_len = u16::try_from(name.len().saturating_mul(2))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "filename too long"))?;
    if name.is_empty() || name.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid filename",
        ));
    }
    let mut unicode_name = UnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        buffer: name.as_mut_ptr(),
    };
    let mut attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: directory.as_raw_handle().cast(),
        object_name: &mut unicode_name,
        attributes: 0x40 | 0x1000,
        security_descriptor: std::ptr::null_mut(),
        security_quality_of_service: std::ptr::null_mut(),
    };
    let mut status_block = IoStatusBlock {
        status: std::ptr::null_mut(),
        information: 0,
    };
    let mut raw_file = std::ptr::null_mut();
    let status = unsafe {
        NtCreateFile(
            &mut raw_file,
            0x0001_0000 | 0x0080 | 0x0010_0000,
            &mut attributes,
            &mut status_block,
            std::ptr::null_mut(),
            0x80,
            0x0001 | 0x0002 | 0x0004,
            1,
            0x40 | 0x20 | 0x0020_0000,
            std::ptr::null_mut(),
            0,
        )
    };
    if status == 0xC000_0034u32 as i32 || status == 0xC000_003Au32 as i32 {
        return Ok(());
    }
    if status < 0 {
        let code = unsafe { RtlNtStatusToDosError(status) };
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let file = unsafe { fs::File::from_raw_handle(raw_file) };
    let mut tag_info = FileAttributeTagInfo {
        attributes: 0,
        reparse_tag: 0,
    };
    let valid = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            9,
            (&mut tag_info as *mut FileAttributeTagInfo).cast(),
            std::mem::size_of::<FileAttributeTagInfo>() as u32,
        )
    } != 0;
    if !valid {
        return Err(io::Error::last_os_error());
    }
    if tag_info.attributes & (0x10 | 0x400) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to remove a directory or reparse point",
        ));
    }
    let delete_file = 1u8;
    let deleted = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            4,
            (&delete_file as *const u8).cast(),
            std::mem::size_of::<u8>() as u32,
        )
    } != 0;
    if deleted {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(unix, windows)))]
fn secure_unlink(_directory: &fs::File, _leaf: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "secure relative deletion is unsupported on this platform",
    ))
}

fn table_exists(transaction: &Transaction<'_>, name: &str) -> Result<bool, LimitError> {
    let exists: i64 = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn table_has_column(
    transaction: &Transaction<'_>,
    table: &str,
    column: &str,
) -> Result<bool, LimitError> {
    if !matches!(table, "uploads" | "ip_hashes") {
        return Err(LimitError::AccountingInvariant);
    }
    let mut statement = transaction.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(columns.iter().any(|name| name == column))
}

fn validate_secret_retention(
    transaction: &Transaction<'_>,
    secrets: &[[u8; 32]],
    day: i64,
) -> Result<(), LimitError> {
    let active_key_ids: std::collections::HashSet<[u8; 32]> =
        secrets.iter().map(secret_key_id).collect();
    let required_identities = {
        let mut statement = transaction.prepare(
            "SELECT identity_id FROM uploads WHERE state IN ('reserved', 'receiving') \
             UNION SELECT identity_id FROM daily_usage WHERE day = ?1 AND used_bytes > 0",
        )?;
        statement
            .query_map([day], |row| row.get::<_, i64>(0))?
            .collect::<Result<Vec<_>, _>>()?
    };
    for identity_id in required_identities {
        let stored_key_ids = {
            let mut statement =
                transaction.prepare("SELECT key_id FROM ip_hashes WHERE identity_id = ?1")?;
            statement
                .query_map([identity_id], |row| row.get::<_, Option<Vec<u8>>>(0))?
                .collect::<Result<Vec<_>, _>>()?
        };
        let has_active_key = stored_key_ids.iter().flatten().any(|key_id| {
            <[u8; 32]>::try_from(key_id.as_slice())
                .map(|key_id| active_key_ids.contains(&key_id))
                .unwrap_or(false)
        });
        if !has_active_key {
            return Err(LimitError::SecretRetentionRequired);
        }
    }
    Ok(())
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

struct ReservationFileGuard {
    directory: Arc<SecureReservationDirectory>,
    file_name: String,
    previous_size: Option<u64>,
    committed: bool,
}

impl ReservationFileGuard {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for ReservationFileGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(previous_size) = self.previous_size {
            if let Ok(file) = self.directory.open_file(&self.file_name, false) {
                let _ = set_file_allocation(&file, previous_size);
            }
        } else {
            let _ = self.directory.remove_file(&self.file_name);
        }
    }
}

fn create_reserved_file(
    directory: Arc<SecureReservationDirectory>,
    file_name: &str,
    size: u64,
) -> Result<ReservationFileGuard, LimitError> {
    let file = directory
        .open_file(file_name, true)
        .map_err(LimitError::Filesystem)?;
    let guard = ReservationFileGuard {
        directory,
        file_name: file_name.to_owned(),
        previous_size: None,
        committed: false,
    };
    set_file_allocation(&file, size).map_err(LimitError::Filesystem)?;
    Ok(guard)
}

fn resize_reserved_file(
    directory: Arc<SecureReservationDirectory>,
    file_name: &str,
    size: u64,
) -> Result<ReservationFileGuard, LimitError> {
    let file = directory
        .open_file(file_name, false)
        .map_err(LimitError::Filesystem)?;
    let previous_size = file.metadata().map_err(LimitError::Filesystem)?.len();
    let guard = ReservationFileGuard {
        directory,
        file_name: file_name.to_owned(),
        previous_size: Some(previous_size),
        committed: false,
    };
    set_file_allocation(&file, size).map_err(LimitError::Filesystem)?;
    Ok(guard)
}

#[cfg(unix)]
fn allocated_file_bytes(file: &fs::File) -> Result<u64, LimitError> {
    use std::os::unix::fs::MetadataExt;

    let blocks = file.metadata().map_err(LimitError::Filesystem)?.blocks();
    Ok(blocks.saturating_mul(512))
}

#[cfg(windows)]
fn allocated_file_bytes(file: &fs::File) -> Result<u64, LimitError> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileStandardInfo {
        allocation_size: i64,
        end_of_file: i64,
        number_of_links: u32,
        delete_pending: u8,
        directory: u8,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            file: *mut std::ffi::c_void,
            info_class: i32,
            info: *mut std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    let mut info = FileStandardInfo {
        allocation_size: 0,
        end_of_file: 0,
        number_of_links: 0,
        delete_pending: 0,
        directory: 0,
    };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle().cast(),
            1,
            (&mut info as *mut FileStandardInfo).cast(),
            std::mem::size_of::<FileStandardInfo>() as u32,
        )
    };
    if ok == 0 || info.allocation_size < 0 {
        return Err(LimitError::Filesystem(io::Error::last_os_error()));
    }
    Ok(info.allocation_size as u64)
}

#[cfg(not(any(unix, windows)))]
fn allocated_file_bytes(file: &fs::File) -> Result<u64, LimitError> {
    Ok(file.metadata().map_err(LimitError::Filesystem)?.len())
}

#[cfg(windows)]
fn set_file_allocation(file: &fs::File, size: u64) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileAllocationInfo {
        allocation_size: i64,
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            class: i32,
            info: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
    }

    let allocation_size = i64::try_from(size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "allocation too large"))?;
    file.set_len(size)?;
    let info = FileAllocationInfo { allocation_size };
    let ok = unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            5,
            (&info as *const FileAllocationInfo).cast(),
            std::mem::size_of::<FileAllocationInfo>() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn set_file_allocation(file: &fs::File, size: u64) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let length = i64::try_from(size)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "allocation too large"))?;
    file.set_len(size)?;
    let result = unsafe { libc::posix_fallocate(file.as_raw_fd(), 0, length) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result))
    }
}

#[cfg(not(any(unix, windows)))]
fn set_file_allocation(_file: &fs::File, _size: u64) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "physical file allocation is unsupported on this platform",
    ))
}

#[cfg(windows)]
fn system_available_bytes(path: &Path) -> io::Result<u64> {
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetDiskFreeSpaceExW(
            directory: *const u16,
            available_to_caller: *mut u64,
            total_bytes: *mut u64,
            free_bytes: *mut u64,
        ) -> i32;
    }

    let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
    path.push(0);
    let mut available = 0u64;
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(available)
    }
}

#[cfg(unix)]
fn system_available_bytes(path: &Path) -> io::Result<u64> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))?;
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    let stats = unsafe { stats.assume_init() };
    let bytes = u128::from(stats.f_bavail) * u128::from(stats.f_frsize);
    Ok(u64::try_from(bytes).unwrap_or(u64::MAX))
}

#[cfg(not(any(unix, windows)))]
fn system_available_bytes(_path: &Path) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "free-space queries are unsupported on this platform",
    ))
}

fn secret_key_id(secret: &[u8; 32]) -> [u8; 32] {
    Sha256::digest(secret).into()
}

fn constant_time_equal(left: &[u8], right: &[u8; 32]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(test)]
mod cleanup_security_tests {
    use super::*;

    fn test_limits() -> LedgerLimits {
        LedgerLimits {
            max_file_bytes: 4,
            daily_quota_bytes: 20,
            max_active_sessions_per_ip: 2,
            max_global_reserved_bytes: 20,
            disk_safety_margin_bytes: 0,
        }
    }

    #[test]
    fn cleanup_does_not_follow_a_directory_link_swapped_after_validation() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let attacker_dir = temp.path().join("attacker");
        fs::create_dir(&upload_root).unwrap();
        fs::create_dir(&attacker_dir).unwrap();
        let ledger = UploadLedger::open(
            temp.path().join("ledger.sqlite3"),
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let reservation = ledger.reserve("192.0.2.10", Some(1)).unwrap();
        let leaf = reservation.upload_path.file_name().unwrap();
        let relative = Path::new(".fluxform-reservations").join(leaf);
        let attacker_file = attacker_dir.join(leaf);
        fs::write(&attacker_file, b"must survive").unwrap();
        let reservations_dir = upload_root.join(".fluxform-reservations");
        let moved_dir = upload_root.join(".fluxform-reservations-pinned");

        ledger
            .remove_upload_file_with_hook(&relative, || {
                fs::rename(&reservations_dir, &moved_dir).unwrap();
                create_directory_link(&attacker_dir, &reservations_dir);
            })
            .unwrap();

        assert_eq!(fs::read(attacker_file).unwrap(), b"must survive");
    }

    #[test]
    fn cleanup_does_not_follow_a_legacy_parent_link_swapped_after_validation() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads-root");
        let legacy_dir = upload_root.join("uploads");
        let moved_dir = upload_root.join("uploads-pinned");
        let attacker_dir = temp.path().join("attacker");
        fs::create_dir(&upload_root).unwrap();
        fs::create_dir(&legacy_dir).unwrap();
        fs::create_dir(&attacker_dir).unwrap();
        let in_root_file = legacy_dir.join("payload.bin");
        let attacker_file = attacker_dir.join("payload.bin");
        fs::write(&in_root_file, b"in-root payload").unwrap();
        fs::write(&attacker_file, b"must survive").unwrap();
        let ledger = UploadLedger::open(
            temp.path().join("ledger.sqlite3"),
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();

        ledger
            .remove_upload_file_with_hook(Path::new("uploads/payload.bin"), || {
                fs::rename(&legacy_dir, &moved_dir).unwrap();
                create_directory_link(&attacker_dir, &legacy_dir);
            })
            .unwrap();

        assert!(!moved_dir.join("payload.bin").exists());
        assert_eq!(fs::read(attacker_file).unwrap(), b"must survive");
    }

    #[cfg(unix)]
    fn create_directory_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    #[cfg(windows)]
    fn create_directory_link(target: &Path, link: &Path) {
        let output = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "junction creation failed: {output:?}"
        );
    }
}
