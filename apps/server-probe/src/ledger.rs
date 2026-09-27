use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use crate::auth::Capability;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_IP_TEXT_BYTES: usize = 45;
const MAX_SECRET_ROTATION_KEYS: usize = 4;
const CURRENT_SCHEMA_VERSION: i64 = 9;
const MAX_CLEANUP_JOBS_PER_PASS: usize = 64;
const MAX_IDENTITY_SCAN_ENTRIES: usize = 64;
const MAX_RESERVATION_DIRECTORY_ENTRIES: usize = 4096;
const MAX_IDENTITY_SCAN_DIRECTORY_ENTRIES: usize = MAX_RESERVATION_DIRECTORY_ENTRIES;
const IDENTITY_SCAN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_STARTUP_ORPHAN_SCAN_ENTRIES: usize = MAX_RESERVATION_DIRECTORY_ENTRIES;
const STARTUP_ORPHAN_SCAN_TIMEOUT: Duration = Duration::from_secs(2);
const SETTLEMENT_ACK_GRACE_SECONDS: i64 = 30;
const MAX_STARTUP_SETTLEMENT_RECOVERIES: usize = 128;

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
    upload_path TEXT,
    file_identity BLOB,
    lease_expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS uploads_identity_state ON uploads(identity_id, state);
CREATE TABLE IF NOT EXISTS cleanup_outbox (
    session_id INTEGER PRIMARY KEY REFERENCES uploads(id),
    relative_path TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    scan_cursor TEXT
);
CREATE TABLE IF NOT EXISTS settlement_outbox (
    session_id INTEGER PRIMARY KEY REFERENCES uploads(id),
    day INTEGER NOT NULL CHECK (day >= 0),
    actual_bytes INTEGER NOT NULL CHECK (actual_bytes >= 0),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    delivery_possible INTEGER NOT NULL DEFAULT 0 CHECK (delivery_possible IN (0, 1)),
    delivery_attempt_id TEXT
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
    #[error("upload staging file identity changed")]
    FileIdentityMismatch,
    #[error("unacknowledged settlements exceed the bounded startup recovery limit")]
    PendingSettlementRecoveryLimit,
    #[error("upload capability has expired")]
    CapabilityExpired,
    #[error("database is busy")]
    DatabaseBusy,
    #[error("storage operation deadline elapsed")]
    OperationTimedOut,
    #[error("late upload reservation compensation remains pending")]
    LateReservationCompensationRequired {
        session_id: i64,
        capability: SessionToken,
    },
    #[error("late upload settlement compensation remains pending")]
    LateSettlementCompensationRequired(SettlementReceipt),
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

#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct SettlementReceipt {
    session_id: i64,
    identity_id: i64,
    day: i64,
    actual_bytes: u64,
}

struct SettlementHooks<B, A> {
    before_commit: B,
    after_commit: A,
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
    pub deferred: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct LedgerLimits {
    pub max_file_bytes: u64,
    pub daily_quota_bytes: u64,
    pub max_active_sessions_per_ip: u32,
    pub max_global_reserved_bytes: u64,
    pub disk_safety_margin_bytes: u64,
}

pub(crate) struct SecureReservationDirectory {
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
    artifact_root: PathBuf,
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
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&reservations_dir, fs::Permissions::from_mode(0o700))
                .map_err(LimitError::Filesystem)?;
        }
        let reservation_directory = Arc::new(
            SecureReservationDirectory::open(&reservations_dir).map_err(LimitError::Filesystem)?,
        );
        let artifact_root = upload_root.join(".fluxform-artifacts");
        match fs::create_dir(&artifact_root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(LimitError::Filesystem(error)),
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&artifact_root, fs::Permissions::from_mode(0o700))
                .map_err(LimitError::Filesystem)?;
        }
        // Verify and pin a non-reparse managed root before the service starts.
        let _ = SecureReservationDirectory::open(&artifact_root).map_err(LimitError::Filesystem)?;

        let ledger = Self {
            database_path: database_path.as_ref().to_path_buf(),
            upload_root,
            artifact_root,
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
        let had_file_identity =
            had_uploads && table_has_column(&transaction, "uploads", "file_identity")?;
        let had_lease_expiry =
            had_uploads && table_has_column(&transaction, "uploads", "lease_expires_at")?;
        let had_cleanup_outbox = table_exists(&transaction, "cleanup_outbox")?;
        let had_cleanup_next_attempt = had_cleanup_outbox
            && table_has_column(&transaction, "cleanup_outbox", "next_attempt_at")?;
        let had_cleanup_scan_cursor =
            had_cleanup_outbox && table_has_column(&transaction, "cleanup_outbox", "scan_cursor")?;
        let had_settlement_outbox = table_exists(&transaction, "settlement_outbox")?;
        let had_delivery_possible = had_settlement_outbox
            && table_has_column(&transaction, "settlement_outbox", "delivery_possible")?;
        let had_delivery_attempt_id = had_settlement_outbox
            && table_has_column(&transaction, "settlement_outbox", "delivery_attempt_id")?;
        let had_ip_hashes = table_exists(&transaction, "ip_hashes")?;
        let had_key_id = had_ip_hashes && table_has_column(&transaction, "ip_hashes", "key_id")?;
        transaction.execute_batch(SCHEMA)?;
        if had_uploads && !had_capability_hash {
            transaction.execute(
                "ALTER TABLE uploads ADD COLUMN capability_hash BLOB CHECK (capability_hash IS NULL OR length(capability_hash) = 32)",
                [],
            )?;
        }
        if had_uploads && !had_file_identity {
            transaction.execute("ALTER TABLE uploads ADD COLUMN file_identity BLOB", [])?;
        }
        if had_uploads && !had_lease_expiry {
            transaction.execute(
                "ALTER TABLE uploads ADD COLUMN lease_expires_at INTEGER",
                [],
            )?;
        }
        if had_cleanup_outbox && !had_cleanup_next_attempt {
            transaction.execute(
                "ALTER TABLE cleanup_outbox ADD COLUMN next_attempt_at INTEGER NOT NULL DEFAULT 0",
                [],
            )?;
        }
        if had_cleanup_outbox && !had_cleanup_scan_cursor {
            transaction.execute("ALTER TABLE cleanup_outbox ADD COLUMN scan_cursor TEXT", [])?;
        }
        if had_settlement_outbox && !had_delivery_possible {
            transaction.execute(
                "ALTER TABLE settlement_outbox ADD COLUMN delivery_possible INTEGER NOT NULL DEFAULT 0 CHECK (delivery_possible IN (0, 1))",
                [],
            )?;
            // Older rows may already have produced a 204 before their ACK
            // write failed. Their transport outcome is unknowable, so favor
            // identity-verified ACK recovery over destructive compensation.
            transaction.execute(
                "UPDATE settlement_outbox SET delivery_possible = 1 \
                 WHERE session_id IN (SELECT id FROM uploads WHERE state = 'uploaded')",
                [],
            )?;
        }
        if had_settlement_outbox && !had_delivery_attempt_id {
            transaction.execute(
                "ALTER TABLE settlement_outbox ADD COLUMN delivery_attempt_id TEXT",
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
            // Rows predating persisted file identities cannot safely unlink a
            // reservation filename after restart because it may now name a
            // different file. Release quota and preserve a retryable cleanup
            // record instead of guessing which object the old row referred to.
            transaction.execute(
                "INSERT OR IGNORE INTO cleanup_outbox(session_id, relative_path, attempts) \
                 SELECT id, upload_path, 0 FROM uploads \
                 WHERE file_identity IS NULL AND upload_path IS NOT NULL \
                   AND state IN ('reserved', 'receiving')",
                [],
            )?;
            transaction.execute(
                "UPDATE uploads SET state = 'expired', reserved_bytes = 0 \
                 WHERE file_identity IS NULL AND state IN ('reserved', 'receiving')",
                [],
            )?;
        }
        if let Some(retained_key_id) = retained_legacy_key_id {
            transaction.execute(
                "UPDATE ip_hashes SET key_id = ?1 WHERE key_id IS NULL",
                [retained_key_id.as_slice()],
            )?;
        }
        recover_unacknowledged_settlements_in_transaction(
            &transaction,
            None,
            MAX_STARTUP_SETTLEMENT_RECOVERIES,
            true,
            None,
        )?;
        expire_abandoned_sessions_in_transaction(&transaction, current_unix_seconds())?;
        transaction.pragma_update(None, "user_version", CURRENT_SCHEMA_VERSION)?;
        ledger.validate_startup_invariants(&transaction)?;
        transaction.commit()?;
        ledger
            .acknowledge_delivery_possible_settlements(MAX_STARTUP_SETTLEMENT_RECOVERIES, true)?;
        ledger.reconcile_cleanup_jobs()?;
        ledger.reconcile_unreferenced_files()?;
        Ok(ledger)
    }

    pub fn reserve(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
    ) -> Result<UploadReservation, LimitError> {
        self.reserve_internal_until(
            ip_key,
            declared_bytes,
            SessionToken::generate()?,
            None,
            None,
        )
        .map(|(reservation, _)| reservation)
    }

    #[cfg(test)]
    pub(crate) fn reserve_with_upload_capability(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
        expires_at: SystemTime,
    ) -> Result<(UploadReservation, Capability), LimitError> {
        let (reservation, capability) = self.reserve_internal_until(
            ip_key,
            declared_bytes,
            SessionToken::generate()?,
            Some(expires_at),
            None,
        )?;
        capability
            .map(|capability| (reservation, capability))
            .ok_or(LimitError::AccountingInvariant)
    }

    pub(crate) fn reserve_with_upload_capability_until(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
        expires_at: SystemTime,
        deadline: Instant,
    ) -> Result<(UploadReservation, Capability), LimitError> {
        let (reservation, capability) = self.reserve_internal_until(
            ip_key,
            declared_bytes,
            SessionToken::generate()?,
            Some(expires_at),
            Some(deadline),
        )?;
        capability
            .map(|capability| (reservation, capability))
            .ok_or(LimitError::AccountingInvariant)
    }

    pub(crate) fn compensate_late_reservation(
        &self,
        session_id: i64,
        capability: &SessionToken,
    ) -> Result<(), LimitError> {
        let mut last_error = LimitError::DatabaseBusy;
        for _ in 0..4 {
            match self
                .expire(session_id, capability)
                .and_then(|()| self.reconcile_cleanup_job(session_id))
            {
                Ok(report) if report.retryable == 0 => return Ok(()),
                Ok(_) => {
                    last_error = LimitError::Filesystem(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "late reservation cleanup remains pending",
                    ));
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(LimitError::DatabaseBusy) => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error)
    }

    pub(crate) fn database_path(&self) -> &Path {
        &self.database_path
    }

    pub(crate) fn artifact_root(&self) -> &Path {
        &self.artifact_root
    }

    fn reserve_internal_until(
        &self,
        ip_key: &str,
        declared_bytes: Option<u64>,
        session_token: SessionToken,
        capability_expiry: Option<SystemTime>,
        deadline: Option<Instant>,
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
        // Serialize the namespace admission check with all reservation writes
        // so concurrent callers cannot exceed the directory-entry policy.
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(LimitError::OperationTimedOut);
        }
        let scan_deadline =
            deadline.unwrap_or_else(|| Instant::now() + STARTUP_ORPHAN_SCAN_TIMEOUT);
        let existing_entries = match self
            .reservation_directory
            .enumerate_files_bounded(MAX_RESERVATION_DIRECTORY_ENTRIES, scan_deadline)
        {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(LimitError::GlobalCapacityExceeded);
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut && deadline.is_some() => {
                return Err(LimitError::OperationTimedOut);
            }
            Err(error) => return Err(LimitError::Filesystem(error)),
        };
        if existing_entries.len() >= MAX_RESERVATION_DIRECTORY_ENTRIES {
            return Err(LimitError::GlobalCapacityExceeded);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(LimitError::OperationTimedOut);
        }
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
        let file_identity = file_reservation.file_identity.clone();
        self.check_disk_safety_margin()?;

        transaction.execute(
            "INSERT INTO uploads(identity_id, capability_hash, state, reserved_bytes, actual_bytes, created_day, upload_path, file_identity) \
             VALUES (?1, ?2, 'reserved', ?3, NULL, ?4, ?5, ?6)",
            params![identity_id, capability_hash.as_slice(), to_sql_integer(requested)?, day, relative_path, file_identity],
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
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(LimitError::OperationTimedOut);
        }
        transaction.commit()?;
        file_reservation.commit();
        let (capability, session_token) = match capability {
            Some((capability, session_token)) => (Some(capability), session_token),
            None => (None, session_token),
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            if self
                .compensate_late_reservation(session_id, &session_token)
                .is_err()
            {
                return Err(LimitError::LateReservationCompensationRequired {
                    session_id,
                    capability: session_token,
                });
            }
            return Err(LimitError::OperationTimedOut);
        }
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
        file: &mut fs::File,
        required_total: u64,
    ) -> Result<UploadReservation, LimitError> {
        self.expand_internal(session_id, capability, file, required_total, None)
    }

    pub(crate) fn expand_receiving(
        &self,
        session_id: i64,
        capability: &SessionToken,
        file: &mut fs::File,
        required_total: u64,
        lease_duration: Duration,
    ) -> Result<UploadReservation, LimitError> {
        self.expand_internal(
            session_id,
            capability,
            file,
            required_total,
            Some(lease_duration),
        )
    }

    fn expand_internal(
        &self,
        session_id: i64,
        capability: &SessionToken,
        file: &mut fs::File,
        required_total: u64,
        lease_duration: Option<Duration>,
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
        let expected_file_identity = load_file_identity(&transaction, session_id)?;
        let upload_path = self.reservation_path(relative_path.as_deref())?;
        if !state.is_reserved() {
            return Err(LimitError::InvalidTransition);
        }
        if let Some(lease_duration) = lease_duration {
            if state != UploadState::Receiving || lease_duration.is_zero() {
                return Err(LimitError::InvalidTransition);
            }
            let current_lease = transaction.query_row(
                "SELECT lease_expires_at FROM uploads WHERE id = ?1",
                [session_id],
                |row| row.get::<_, Option<i64>>(0),
            )?;
            if current_lease.is_none_or(|expires_at| expires_at <= current_unix_seconds()) {
                return Err(LimitError::InvalidTransition);
            }
        }
        self.verify_file_identity(relative_path.as_deref(), file, &expected_file_identity)?;
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
        let mut file_reservation = resize_reserved_file(file, required_total)?;
        self.check_disk_safety_margin()?;

        // Expansion performs synchronous allocation while holding this
        // immediate transaction, preventing another reconciler from expiring
        // the row mid-operation. Renew again after allocation and commit the
        // new lease with the reservation so no observer can see an expired
        // lease in the gap after the transaction releases its write lock.
        let renewed_lease = lease_duration
            .map(|duration| {
                capability_expiry(&transaction, session_id, capability)?;
                new_lease_expiry(current_unix_seconds(), duration, i64::MAX)
            })
            .transpose()?;

        let changed = transaction.execute(
            "UPDATE uploads SET reserved_bytes = ?1, lease_expires_at = COALESCE(?2, lease_expires_at) \
             WHERE id = ?3 AND state IN ('reserved', 'receiving')",
            params![to_sql_integer(required_total)?, renewed_lease, session_id],
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
        let (state, reserved, _, relative_path) =
            load_session(&transaction, session_id, capability)?;
        if !transition_is_legal(state, target) {
            return Err(LimitError::InvalidTransition);
        }
        let pinned_uploaded_file = if state == UploadState::Uploaded {
            let pending_settlement: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM settlement_outbox WHERE session_id = ?1)",
                [session_id],
                |row| row.get(0),
            )?;
            if pending_settlement {
                return Err(LimitError::InvalidTransition);
            }
            let expected_file_identity = load_file_identity(&transaction, session_id)?;
            Some(self.open_verified_reservation_file(
                relative_path.as_deref(),
                &expected_file_identity,
            )?)
        } else {
            None
        };
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
        drop(pinned_uploaded_file);
        Ok(())
    }

    pub fn settle(
        &self,
        session_id: i64,
        capability: &SessionToken,
        actual_bytes: u64,
    ) -> Result<(), LimitError> {
        self.settle_internal(session_id, capability, None, actual_bytes)?;
        self.acknowledge_settlement(session_id)
    }

    pub(crate) fn settle_pinned_until(
        &self,
        session_id: i64,
        capability: &SessionToken,
        file: &fs::File,
        actual_bytes: u64,
        deadline: Instant,
    ) -> Result<SettlementReceipt, LimitError> {
        self.settle_internal_with_hook_until(
            session_id,
            capability,
            Some(file),
            actual_bytes,
            Some(deadline),
            SettlementHooks {
                before_commit: || {},
                after_commit: || {},
            },
        )
    }

    fn settle_internal(
        &self,
        session_id: i64,
        capability: &SessionToken,
        pinned_file: Option<&fs::File>,
        actual_bytes: u64,
    ) -> Result<(), LimitError> {
        self.settle_internal_with_hook_until(
            session_id,
            capability,
            pinned_file,
            actual_bytes,
            None,
            SettlementHooks {
                before_commit: || {},
                after_commit: || {},
            },
        )
        .map(|_| ())
    }

    #[cfg(test)]
    fn settle_internal_with_hook<F>(
        &self,
        session_id: i64,
        capability: &SessionToken,
        pinned_file: Option<&fs::File>,
        actual_bytes: u64,
        before_commit: F,
    ) -> Result<(), LimitError>
    where
        F: FnOnce(),
    {
        self.settle_internal_with_hook_until(
            session_id,
            capability,
            pinned_file,
            actual_bytes,
            None,
            SettlementHooks {
                before_commit,
                after_commit: || {},
            },
        )
        .map(|_| ())
    }

    #[cfg(test)]
    fn settle_internal_with_commit_hooks<B, A>(
        &self,
        session_id: i64,
        capability: &SessionToken,
        pinned_file: Option<&fs::File>,
        actual_bytes: u64,
        deadline: Instant,
        hooks: SettlementHooks<B, A>,
    ) -> Result<SettlementReceipt, LimitError>
    where
        B: FnOnce(),
        A: FnOnce(),
    {
        self.settle_internal_with_hook_until(
            session_id,
            capability,
            pinned_file,
            actual_bytes,
            Some(deadline),
            hooks,
        )
    }

    fn settle_internal_with_hook_until<B, A>(
        &self,
        session_id: i64,
        capability: &SessionToken,
        pinned_file: Option<&fs::File>,
        actual_bytes: u64,
        deadline: Option<Instant>,
        hooks: SettlementHooks<B, A>,
    ) -> Result<SettlementReceipt, LimitError>
    where
        B: FnOnce(),
        A: FnOnce(),
    {
        if actual_bytes > self.limits.max_file_bytes {
            return Err(LimitError::FileTooLarge);
        }
        let day = current_day_bucket();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, identity_id, relative_path) =
            load_session(&transaction, session_id, capability)?;
        if state != UploadState::Receiving {
            return Err(LimitError::InvalidTransition);
        }
        let expected_file_identity = load_file_identity(&transaction, session_id)?;
        // The writer handle may permit Windows delete sharing. A separate
        // identity pin denies delete sharing through final verification and
        // the SQLite commit.
        let identity_pin =
            self.open_verified_reservation_file(relative_path.as_deref(), &expected_file_identity)?;
        if let Some(file) = pinned_file {
            self.verify_file_identity(relative_path.as_deref(), file, &expected_file_identity)?;
        } else {
            self.verify_file_identity(
                relative_path.as_deref(),
                &identity_pin,
                &expected_file_identity,
            )?;
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
            "UPDATE uploads SET state = 'uploaded', reserved_bytes = 0, actual_bytes = ?1, lease_expires_at = NULL \
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
        transaction.execute(
            "INSERT INTO settlement_outbox(session_id, day, actual_bytes, created_at) \
             VALUES (?1, ?2, ?3, ?4)",
            params![
                session_id,
                day,
                to_sql_integer(actual_bytes)?,
                current_unix_seconds()
            ],
        )?;
        write_global_reserved(&transaction, next_global_reserved)?;
        if let Some(file) = pinned_file {
            self.verify_file_identity(relative_path.as_deref(), file, &expected_file_identity)?;
        } else {
            self.verify_file_identity(
                relative_path.as_deref(),
                &identity_pin,
                &expected_file_identity,
            )?;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(LimitError::OperationTimedOut);
        }
        (hooks.before_commit)();
        transaction.commit()?;
        drop(identity_pin);
        (hooks.after_commit)();
        let receipt = SettlementReceipt {
            session_id,
            identity_id,
            day,
            actual_bytes,
        };
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            if self
                .compensate_late_settlement(session_id, capability, receipt)
                .is_err()
            {
                return Err(LimitError::LateSettlementCompensationRequired(receipt));
            }
            return Err(LimitError::OperationTimedOut);
        }
        Ok(receipt)
    }

    /// Reserves this Uploaded settlement for one HTTP delivery attempt.
    ///
    /// Persisting the attempt before the delivery marker lets timeout handling
    /// choose a durable abort outcome. A competing request cannot claim the
    /// same settlement while that outcome is being classified.
    pub(crate) fn begin_settlement_delivery_attempt(
        &self,
        session_id: i64,
        attempt_id: &str,
    ) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state: String = transaction.query_row(
            "SELECT state FROM uploads WHERE id = ?1",
            [session_id],
            |row| row.get(0),
        )?;
        if UploadState::from_str(&state)? != UploadState::Uploaded {
            return Err(LimitError::InvalidTransition);
        }
        let changed = transaction.execute(
            "UPDATE settlement_outbox SET delivery_attempt_id = ?1 \
             WHERE session_id = ?2 AND delivery_attempt_id IS NULL AND delivery_possible = 0",
            params![attempt_id, session_id],
        )?;
        if changed != 1 {
            return Err(LimitError::InvalidTransition);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Records that Hyper may now deliver a 204 response. Once this conditional
    /// marker commits, recovery preserves the Uploaded row and retries only
    /// the identity-verified acknowledgment. `attempt_id` makes the marker
    /// mutually exclusive with a timeout abort for the same delivery.
    pub(crate) fn mark_settlement_delivery_possible(
        &self,
        session_id: i64,
        attempt_id: &str,
    ) -> Result<(), LimitError> {
        self.mark_settlement_delivery_possible_inner(session_id, attempt_id, || {})
    }

    #[cfg(test)]
    pub(crate) fn mark_settlement_delivery_possible_with_hook<F>(
        &self,
        session_id: i64,
        attempt_id: &str,
        before_commit: F,
    ) -> Result<(), LimitError>
    where
        F: FnOnce(),
    {
        self.mark_settlement_delivery_possible_inner(session_id, attempt_id, before_commit)
    }

    fn mark_settlement_delivery_possible_inner<F>(
        &self,
        session_id: i64,
        attempt_id: &str,
        before_commit: F,
    ) -> Result<(), LimitError>
    where
        F: FnOnce(),
    {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, relative_path): (String, Option<String>) = transaction.query_row(
            "SELECT state, upload_path FROM uploads WHERE id = ?1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if UploadState::from_str(&state)? != UploadState::Uploaded {
            return Err(LimitError::InvalidTransition);
        }
        let expected_file_identity = load_file_identity(&transaction, session_id)?;
        let file =
            self.open_verified_reservation_file(relative_path.as_deref(), &expected_file_identity)?;
        let changed = transaction.execute(
            "UPDATE settlement_outbox SET delivery_possible = 1 \
             WHERE session_id = ?1 AND delivery_attempt_id = ?2 AND delivery_possible = 0",
            params![session_id, attempt_id],
        )?;
        if changed != 1 {
            return Err(LimitError::InvalidTransition);
        }
        before_commit();
        transaction.commit()?;
        drop(file);
        Ok(())
    }

    /// Durably classifies an unsuccessful delivery attempt and refunds its
    /// settlement. The marker and this abort serialize in SQLite's immediate
    /// transaction: either abort removes the pending row before a marker can
    /// commit, or it observes and compensates a late marker. A caller may send
    /// a definitive 503 only after this transaction commits.
    pub(crate) fn abort_settlement_delivery_attempt(
        &self,
        session_id: i64,
        attempt_id: &str,
        deadline: Instant,
    ) -> Result<(), LimitError> {
        if Instant::now() >= deadline {
            return Err(LimitError::OperationTimedOut);
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        // BEGIN IMMEDIATE can itself wait behind a non-cancellable marker
        // transaction. Never let that late waiter turn an already-ambiguous
        // transport outcome into a durable abort after its response deadline.
        if Instant::now() >= deadline {
            return Err(LimitError::OperationTimedOut);
        }
        let changed = transaction.execute(
            "UPDATE settlement_outbox SET delivery_possible = 0 \
             WHERE session_id = ?1 AND delivery_attempt_id = ?2",
            params![session_id, attempt_id],
        )?;
        if changed == 0 {
            let already_compensated: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM uploads \
                 WHERE id = ?1 AND state = 'expired' AND actual_bytes IS NULL AND reserved_bytes = 0) \
                 AND NOT EXISTS(SELECT 1 FROM settlement_outbox WHERE session_id = ?1)",
                [session_id],
                |row| row.get(0),
            )?;
            if already_compensated {
                transaction.commit()?;
                return Ok(());
            }
            return Err(LimitError::InvalidTransition);
        }
        let compensated = recover_unacknowledged_settlements_in_transaction(
            &transaction,
            None,
            1,
            true,
            Some(session_id),
        )?;
        if compensated != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        if Instant::now() >= deadline {
            return Err(LimitError::OperationTimedOut);
        }
        transaction.commit()?;
        Ok(())
    }

    /// Acknowledges a settlement after Hyper completes its connection. Both
    /// the persisted identity and the directory entry are pinned through the
    /// acknowledgment commit; a mismatched replacement is never accepted.
    pub(crate) fn acknowledge_settlement(&self, session_id: i64) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, relative_path): (String, Option<String>) = transaction.query_row(
            "SELECT state, upload_path FROM uploads WHERE id = ?1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        if UploadState::from_str(&state)? != UploadState::Uploaded {
            return Err(LimitError::InvalidTransition);
        }
        let pending: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM settlement_outbox WHERE session_id = ?1)",
            [session_id],
            |row| row.get(0),
        )?;
        if !pending {
            transaction.commit()?;
            return Ok(());
        }
        let expected_file_identity = load_file_identity(&transaction, session_id)?;
        let file =
            self.open_verified_reservation_file(relative_path.as_deref(), &expected_file_identity)?;
        transaction.execute(
            "DELETE FROM settlement_outbox WHERE session_id = ?1",
            [session_id],
        )?;
        transaction.commit()?;
        drop(file);
        Ok(())
    }

    fn acknowledge_delivery_possible_settlements(
        &self,
        maximum: usize,
        include_crash_ambiguous_attempts: bool,
    ) -> Result<usize, LimitError> {
        let limit = i64::try_from(maximum.saturating_add(1)).unwrap_or(i64::MAX);
        let session_ids = {
            let connection = self.connect()?;
            let mut statement = connection.prepare(
                "SELECT session_id FROM settlement_outbox \
                 WHERE delivery_possible = 1 AND (?1 = 1 OR delivery_attempt_id IS NULL) \
                 ORDER BY created_at, session_id LIMIT ?2",
            )?;
            statement
                .query_map(params![include_crash_ambiguous_attempts, limit], |row| {
                    row.get::<_, i64>(0)
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        if session_ids.len() > maximum {
            return Err(LimitError::PendingSettlementRecoveryLimit);
        }
        for session_id in &session_ids {
            self.acknowledge_settlement(*session_id)?;
        }
        Ok(session_ids.len())
    }

    pub(crate) fn compensate_late_settlement(
        &self,
        session_id: i64,
        capability: &SessionToken,
        receipt: SettlementReceipt,
    ) -> Result<(), LimitError> {
        let mut last_error = LimitError::DatabaseBusy;
        for _ in 0..4 {
            match self.compensate_late_settlement_once(session_id, capability, receipt) {
                Ok(report) if report.retryable == 0 => return Ok(()),
                Ok(_) => {
                    last_error = LimitError::Filesystem(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "late settlement cleanup remains pending",
                    ));
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(LimitError::DatabaseBusy) => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error)
    }

    fn compensate_late_settlement_once(
        &self,
        session_id: i64,
        capability: &SessionToken,
        receipt: SettlementReceipt,
    ) -> Result<CleanupReport, LimitError> {
        if receipt.session_id != session_id {
            return Err(LimitError::AccountingInvariant);
        }
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved, identity_id, _) = load_session(&transaction, session_id, capability)?;
        let delivery_possible: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM settlement_outbox \
             WHERE session_id = ?1 AND delivery_possible = 1)",
            [session_id],
            |row| row.get(0),
        )?;
        if delivery_possible {
            return Err(LimitError::InvalidTransition);
        }
        if identity_id != receipt.identity_id {
            return Err(LimitError::AccountingInvariant);
        }
        match state {
            UploadState::Uploaded => {
                let actual: Option<i64> = transaction.query_row(
                    "SELECT actual_bytes FROM uploads WHERE id = ?1",
                    [session_id],
                    |row| row.get(0),
                )?;
                if actual != Some(to_sql_integer(receipt.actual_bytes)?) {
                    return Err(LimitError::AccountingInvariant);
                }
                let changed = transaction.execute(
                    "UPDATE daily_usage SET used_bytes = used_bytes - ?1 \
                     WHERE identity_id = ?2 AND day = ?3 AND used_bytes >= ?1",
                    params![
                        to_sql_integer(receipt.actual_bytes)?,
                        receipt.identity_id,
                        receipt.day
                    ],
                )?;
                if changed != 1 {
                    return Err(LimitError::AccountingInvariant);
                }
                transaction.execute(
                    "DELETE FROM daily_usage WHERE identity_id = ?1 AND day = ?2 AND used_bytes = 0",
                    params![receipt.identity_id, receipt.day],
                )?;
                let changed = transaction.execute(
                    "UPDATE uploads SET state = 'expired', actual_bytes = NULL, \
                     reserved_bytes = 0, lease_expires_at = NULL \
                     WHERE id = ?1 AND state = 'uploaded' AND actual_bytes = ?2",
                    params![session_id, to_sql_integer(receipt.actual_bytes)?],
                )?;
                if changed != 1 {
                    return Err(LimitError::AccountingInvariant);
                }
                revoke_session_capability(&transaction, session_id)?;
                enqueue_cleanup(&transaction, session_id)?;
            }
            UploadState::Reserved | UploadState::Receiving => {
                if reserved > 0 {
                    release_global_reserved(&transaction, reserved)?;
                }
                let changed = transaction.execute(
                    "UPDATE uploads SET state = 'expired', actual_bytes = NULL, \
                     reserved_bytes = 0, lease_expires_at = NULL \
                     WHERE id = ?1 AND state IN ('reserved', 'receiving')",
                    [session_id],
                )?;
                if changed != 1 {
                    return Err(LimitError::AccountingInvariant);
                }
                revoke_session_capability(&transaction, session_id)?;
                enqueue_cleanup(&transaction, session_id)?;
            }
            UploadState::Expired => {
                let actual: Option<i64> = transaction.query_row(
                    "SELECT actual_bytes FROM uploads WHERE id = ?1",
                    [session_id],
                    |row| row.get(0),
                )?;
                if actual == Some(to_sql_integer(receipt.actual_bytes)?) {
                    let changed = transaction.execute(
                        "UPDATE daily_usage SET used_bytes = used_bytes - ?1 \
                         WHERE identity_id = ?2 AND day = ?3 AND used_bytes >= ?1",
                        params![
                            to_sql_integer(receipt.actual_bytes)?,
                            receipt.identity_id,
                            receipt.day
                        ],
                    )?;
                    if changed != 1 {
                        return Err(LimitError::AccountingInvariant);
                    }
                    transaction.execute(
                        "DELETE FROM daily_usage WHERE identity_id = ?1 AND day = ?2 AND used_bytes = 0",
                        params![receipt.identity_id, receipt.day],
                    )?;
                    transaction.execute(
                        "UPDATE uploads SET actual_bytes = NULL WHERE id = ?1 AND state = 'expired'",
                        [session_id],
                    )?;
                } else if actual.is_some() {
                    return Err(LimitError::AccountingInvariant);
                }
                revoke_session_capability(&transaction, session_id)?;
            }
            UploadState::Rejected | UploadState::Probing | UploadState::Queued => {
                return Err(LimitError::InvalidTransition);
            }
        }
        transaction.execute(
            "DELETE FROM settlement_outbox WHERE session_id = ?1",
            [session_id],
        )?;
        transaction.commit()?;
        self.reconcile_cleanup_job(session_id)
            .map(|report| CleanupReport {
                completed: report.completed,
                retryable: report.retryable,
                deferred: report.deferred,
            })
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
        let delivery_possible: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM settlement_outbox \
             WHERE session_id = ?1 AND delivery_possible = 1)",
            [session_id],
            |row| row.get(0),
        )?;
        if delivery_possible {
            return Err(LimitError::InvalidTransition);
        }
        if reserved > 0 {
            release_global_reserved(&transaction, reserved)?;
        }
        let changed = transaction.execute(
            "UPDATE uploads SET state = 'expired', reserved_bytes = 0, lease_expires_at = NULL WHERE id = ?1 AND state = ?2",
            params![session_id, state.as_str()],
        )?;
        if changed != 1 {
            return Err(LimitError::AccountingInvariant);
        }
        revoke_session_capability(&transaction, session_id)?;
        enqueue_cleanup(&transaction, session_id)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn reconcile_cleanup_jobs(&self) -> Result<CleanupReport, LimitError> {
        let connection = self.connect()?;
        let jobs = {
            let mut statement = connection.prepare(
                "SELECT cleanup_outbox.session_id FROM cleanup_outbox \
                 WHERE cleanup_outbox.next_attempt_at <= ?1 \
                 ORDER BY cleanup_outbox.next_attempt_at, cleanup_outbox.session_id LIMIT ?2",
            )?;
            statement
                .query_map(
                    params![
                        current_unix_seconds(),
                        i64::try_from(MAX_CLEANUP_JOBS_PER_PASS + 1).unwrap_or(i64::MAX)
                    ],
                    |row| row.get::<_, i64>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?
        };
        drop(connection);

        let mut report = CleanupReport::default();
        let has_more_due = jobs.len() > MAX_CLEANUP_JOBS_PER_PASS;
        let mut retryable_this_pass = 0usize;
        for session_id in jobs.into_iter().take(MAX_CLEANUP_JOBS_PER_PASS) {
            let result = self.reconcile_cleanup_job_once(session_id)?;
            report.completed += result.completed;
            retryable_this_pass += result.retryable;
        }
        let connection = self.connect()?;
        report.retryable = usize::try_from(connection.query_row(
            "SELECT COUNT(*) FROM cleanup_outbox",
            [],
            |row| row.get::<_, i64>(0),
        )?)
        .unwrap_or(usize::MAX);
        if has_more_due {
            report.deferred = report.deferred.saturating_add(1);
        }
        report.deferred = report
            .deferred
            .max(report.retryable.saturating_sub(retryable_this_pass));
        Ok(report)
    }

    pub(crate) fn reconcile_cleanup_job(
        &self,
        session_id: i64,
    ) -> Result<CleanupReport, LimitError> {
        self.reconcile_cleanup_job_once(session_id)
    }

    fn reconcile_cleanup_job_once(&self, session_id: i64) -> Result<CleanupReport, LimitError> {
        let connection = self.connect()?;
        let job = connection
            .query_row(
                "SELECT cleanup_outbox.relative_path, uploads.file_identity, cleanup_outbox.scan_cursor \
                 FROM cleanup_outbox JOIN uploads ON uploads.id = cleanup_outbox.session_id \
                 WHERE cleanup_outbox.session_id = ?1",
                [session_id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<Vec<u8>>>(1)?,
                        row.get::<_, Option<String>>(2)?,
                    ))
                },
            )
            .optional()?;
        drop(connection);
        let Some((relative_path, expected_identity, scan_cursor)) = job else {
            return Ok(CleanupReport::default());
        };
        let relative = normalize_relative_path(Path::new(&relative_path));
        let deletion = match (relative, expected_identity) {
            (Ok(relative), Some(expected_identity)) => self.remove_upload_file_if_identity_page(
                Path::new(&relative),
                &expected_identity,
                scan_cursor.as_deref(),
            ),
            (Ok(relative), None) if reservation_leaf(Path::new(&relative)).is_err() => self
                .remove_upload_file(Path::new(&relative))
                .map(|()| IdentityCleanupPage::Removed),
            (Ok(_), None) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "upload cleanup has no pinned file identity",
            )),
            (Err(_), _) => Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid path")),
        };
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut report = CleanupReport::default();
        match deletion {
            Ok(IdentityCleanupPage::Removed) => {
                let changed = transaction.execute(
                    "DELETE FROM cleanup_outbox WHERE session_id = ?1",
                    [session_id],
                )?;
                report.completed = usize::from(changed == 1);
            }
            Ok(IdentityCleanupPage::Continue(next_cursor)) => {
                let attempts: i64 = transaction.query_row(
                    "SELECT attempts FROM cleanup_outbox WHERE session_id = ?1",
                    [session_id],
                    |row| row.get(0),
                )?;
                let next_attempts = attempts.saturating_add(1);
                // A page miss is forward progress, not a failed delete. Keep
                // pagination moving without applying the error backoff.
                transaction.execute(
                    "UPDATE cleanup_outbox SET attempts = ?1, next_attempt_at = ?2, scan_cursor = ?3 \
                     WHERE session_id = ?4",
                    params![
                        next_attempts,
                        current_unix_seconds().saturating_add(1),
                        next_cursor,
                        session_id
                    ],
                )?;
                report.retryable = 1;
            }
            Err(_) => {
                let attempts: i64 = transaction.query_row(
                    "SELECT attempts FROM cleanup_outbox WHERE session_id = ?1",
                    [session_id],
                    |row| row.get(0),
                )?;
                let next_attempts = attempts.saturating_add(1);
                let backoff = 1_i64
                    .checked_shl(u32::try_from(next_attempts.min(8)).unwrap_or(8))
                    .unwrap_or(256)
                    .min(300);
                transaction.execute(
                    "UPDATE cleanup_outbox SET attempts = ?1, next_attempt_at = ?2 \
                     WHERE session_id = ?3",
                    params![
                        next_attempts,
                        current_unix_seconds().saturating_add(backoff),
                        session_id
                    ],
                )?;
                report.retryable = 1;
            }
        }
        transaction.commit()?;
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

    pub(crate) fn max_file_bytes(&self) -> u64 {
        self.limits.max_file_bytes
    }

    pub(crate) fn ensure_disk_safety_margin(&self) -> Result<(), LimitError> {
        self.check_disk_safety_margin()
    }

    pub(crate) fn open_receiving_upload_file(
        &self,
        session_id: i64,
        capability: &SessionToken,
    ) -> Result<(fs::File, u64), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, reserved_bytes, _, relative_path) =
            load_session(&transaction, session_id, capability)?;
        if state != UploadState::Receiving {
            return Err(LimitError::InvalidTransition);
        }
        let relative_path = relative_path.ok_or(LimitError::AccountingInvariant)?;
        let file_name = reservation_leaf(Path::new(&relative_path))
            .map_err(|_| LimitError::InvalidUploadPath)?;
        let file = self
            .reservation_directory
            .open_file(&file_name, false)
            .map_err(LimitError::Filesystem)?;
        let expected_file_identity = load_file_identity(&transaction, session_id)?;
        if file_identity(&file).map_err(LimitError::Filesystem)? != expected_file_identity {
            return Err(LimitError::FileIdentityMismatch);
        }
        if file.metadata().map_err(LimitError::Filesystem)?.len() != reserved_bytes {
            return Err(LimitError::AccountingInvariant);
        }
        transaction.commit()?;
        Ok((file, reserved_bytes))
    }

    pub(crate) fn verify_upload_file_identity(
        &self,
        session_id: i64,
        capability: &SessionToken,
        file: &fs::File,
    ) -> Result<(), LimitError> {
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (_, _, _, relative_path) = load_session(&transaction, session_id, capability)?;
        let expected_file_identity = load_file_identity(&transaction, session_id)?;
        self.verify_file_identity(relative_path.as_deref(), file, &expected_file_identity)?;
        transaction.commit()?;
        Ok(())
    }

    pub fn claim_receiving_lease(
        &self,
        session_id: i64,
        capability: &SessionToken,
        lease_duration: Duration,
    ) -> Result<i64, LimitError> {
        let now = current_unix_seconds();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, _, _, _) = load_session(&transaction, session_id, capability)?;
        if state != UploadState::Reserved {
            return Err(LimitError::InvalidTransition);
        }
        let capability_expiry = capability_expiry(&transaction, session_id, capability)?;
        let lease_expiry = new_lease_expiry(now, lease_duration, capability_expiry)?;
        let changed = transaction.execute(
            "UPDATE uploads SET state = 'receiving', lease_expires_at = ?1 \
             WHERE id = ?2 AND state = 'reserved'",
            params![lease_expiry, session_id],
        )?;
        if changed != 1 {
            return Err(LimitError::InvalidTransition);
        }
        transaction.commit()?;
        Ok(lease_expiry)
    }

    pub fn renew_receiving_lease(
        &self,
        session_id: i64,
        capability: &SessionToken,
        lease_duration: Duration,
    ) -> Result<i64, LimitError> {
        let now = current_unix_seconds();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (state, _, _, _) = load_session(&transaction, session_id, capability)?;
        if state != UploadState::Receiving {
            return Err(LimitError::InvalidTransition);
        }
        let current_lease = transaction.query_row(
            "SELECT lease_expires_at FROM uploads WHERE id = ?1",
            [session_id],
            |row| row.get::<_, Option<i64>>(0),
        )?;
        if current_lease.is_none_or(|expires_at| expires_at <= now) {
            return Err(LimitError::InvalidTransition);
        }
        let capability_expiry = capability_expiry(&transaction, session_id, capability)?;
        let lease_expiry = new_lease_expiry(now, lease_duration, capability_expiry)?;
        let changed = transaction.execute(
            "UPDATE uploads SET lease_expires_at = ?1 \
             WHERE id = ?2 AND state = 'receiving' AND lease_expires_at > ?3",
            params![lease_expiry, session_id, now],
        )?;
        if changed != 1 {
            return Err(LimitError::InvalidTransition);
        }
        transaction.commit()?;
        Ok(lease_expiry)
    }

    /// Expires durable sessions whose capability or renewable receiver lease
    /// has elapsed, then runs the idempotent cleanup outbox.
    pub fn reconcile_expired_sessions(&self) -> Result<CleanupReport, LimitError> {
        self.reconcile_expired_sessions_excluding(&[])
    }

    /// Expires abandoned sessions except for upload owners held by this live
    /// process. The durable lease is still checked transactionally; the owner
    /// set only protects a non-cancellable syscall that has outlived its lease.
    pub fn reconcile_expired_sessions_excluding(
        &self,
        active_uploads: &[i64],
    ) -> Result<CleanupReport, LimitError> {
        let now = current_unix_seconds();
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        recover_unacknowledged_settlements_in_transaction(
            &transaction,
            Some(now.saturating_sub(SETTLEMENT_ACK_GRACE_SECONDS)),
            MAX_CLEANUP_JOBS_PER_PASS,
            false,
            None,
        )?;
        expire_abandoned_sessions_excluding_in_transaction(&transaction, now, active_uploads)?;
        transaction.commit()?;
        self.acknowledge_delivery_possible_settlements(MAX_CLEANUP_JOBS_PER_PASS, false)?;
        self.reconcile_cleanup_jobs()
    }

    fn open_verified_reservation_file(
        &self,
        relative_path: Option<&str>,
        expected_file_identity: &[u8],
    ) -> Result<fs::File, LimitError> {
        let relative_path = relative_path.ok_or(LimitError::AccountingInvariant)?;
        let file_name = reservation_leaf(Path::new(relative_path))
            .map_err(|_| LimitError::InvalidUploadPath)?;
        let file = self
            .reservation_directory
            .open_identity_file(&file_name)
            .map_err(LimitError::Filesystem)?;
        if file_identity(&file).map_err(LimitError::Filesystem)? != expected_file_identity {
            return Err(LimitError::FileIdentityMismatch);
        }
        Ok(file)
    }

    fn verify_file_identity(
        &self,
        relative_path: Option<&str>,
        file: &fs::File,
        expected_file_identity: &[u8],
    ) -> Result<(), LimitError> {
        let relative_path = relative_path.ok_or(LimitError::AccountingInvariant)?;
        if file_identity(file).map_err(LimitError::Filesystem)? != expected_file_identity {
            return Err(LimitError::FileIdentityMismatch);
        }
        self.verify_file_entry_identity(Some(relative_path), expected_file_identity)
    }

    fn verify_file_entry_identity(
        &self,
        relative_path: Option<&str>,
        expected_file_identity: &[u8],
    ) -> Result<(), LimitError> {
        let relative_path = relative_path.ok_or(LimitError::AccountingInvariant)?;
        let file_name = reservation_leaf(Path::new(relative_path))
            .map_err(|_| LimitError::InvalidUploadPath)?;
        let directory_entry = self
            .reservation_directory
            .open_file(&file_name, false)
            .map_err(LimitError::Filesystem)?;
        if file_identity(&directory_entry).map_err(LimitError::Filesystem)?
            != expected_file_identity
        {
            return Err(LimitError::FileIdentityMismatch);
        }
        Ok(())
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
                "SELECT reserved_bytes, upload_path, file_identity FROM uploads \
                 WHERE state IN ('reserved', 'receiving') ORDER BY id",
            )?;
            statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, Option<Vec<u8>>>(2)?,
                    ))
                })?
                .collect::<Result<Vec<_>, _>>()?
        };
        for (reserved_sql, relative, expected_identity) in active_files {
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
            let expected_identity = expected_identity.ok_or(LimitError::AccountingInvariant)?;
            if file_identity(&file).map_err(LimitError::Filesystem)? != expected_identity {
                return Err(LimitError::FileIdentityMismatch);
            }
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
            .enumerate_files_bounded(
                MAX_STARTUP_ORPHAN_SCAN_ENTRIES,
                Instant::now() + STARTUP_ORPHAN_SCAN_TIMEOUT,
            )
            .map_err(LimitError::Filesystem)?
            .into_iter()
            .filter(|leaf| is_managed_reservation_leaf(leaf) && !referenced_leaves.contains(leaf))
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

    #[cfg(test)]
    fn remove_upload_file_if_identity(
        &self,
        relative: &Path,
        expected_identity: &[u8],
    ) -> io::Result<()> {
        self.remove_upload_file_with_identity_and_hook(relative, Some(expected_identity), || {})
    }

    fn remove_upload_file_if_identity_page(
        &self,
        relative: &Path,
        expected_identity: &[u8],
        scan_cursor: Option<&str>,
    ) -> io::Result<IdentityCleanupPage> {
        let normalized = normalize_relative_path(relative).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid upload cleanup path")
        })?;
        let leaf = reservation_leaf(Path::new(&normalized))?;
        remove_file_if_identity_page(
            &self.reservation_directory,
            &leaf,
            expected_identity,
            scan_cursor,
            || {},
        )
    }

    fn remove_upload_file_with_hook<F>(&self, relative: &Path, before_remove: F) -> io::Result<()>
    where
        F: FnOnce(),
    {
        self.remove_upload_file_with_identity_and_hook(relative, None, before_remove)
    }

    fn remove_upload_file_with_identity_and_hook<F>(
        &self,
        relative: &Path,
        expected_identity: Option<&[u8]>,
        before_remove: F,
    ) -> io::Result<()>
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
            if let Some(expected_identity) = expected_identity {
                return remove_file_if_identity(
                    &self.reservation_directory,
                    &components[1],
                    expected_identity,
                    before_remove,
                );
            }
            before_remove();
            return self.reservation_directory.remove_file(&components[1]);
        }
        if expected_identity.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "identity cleanup is restricted to the pinned reservation directory",
            ));
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

fn remove_file_if_identity<F>(
    directory: &SecureReservationDirectory,
    preferred_leaf: &str,
    expected_identity: &[u8],
    before_unlink: F,
) -> io::Result<()>
where
    F: FnOnce(),
{
    match remove_file_if_identity_page(
        directory,
        preferred_leaf,
        expected_identity,
        None,
        before_unlink,
    )? {
        IdentityCleanupPage::Removed => Ok(()),
        IdentityCleanupPage::Continue(_) => Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "pinned upload identity was not present on this bounded scan page",
        )),
    }
}

pub(crate) enum IdentityCleanupPage {
    Removed,
    Continue(Option<String>),
}

fn remove_file_if_identity_page<F>(
    directory: &SecureReservationDirectory,
    preferred_leaf: &str,
    expected_identity: &[u8],
    scan_cursor: Option<&str>,
    before_unlink: F,
) -> io::Result<IdentityCleanupPage>
where
    F: FnOnce(),
{
    if expected_identity.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "upload cleanup has no file identity",
        ));
    }
    let mut before_unlink = Some(before_unlink);
    let scan_deadline = Instant::now() + IDENTITY_SCAN_TIMEOUT;

    match directory.open_readonly_file(preferred_leaf) {
        Ok(file) if file_identity(&file)? == expected_identity => {
            if file_link_count(&file)? > 1 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "pinned upload identity is ambiguous in its reservation directory",
                ));
            }
            drop(file);
            if remove_identity_entry(
                directory,
                preferred_leaf,
                expected_identity,
                &mut before_unlink,
            )? {
                return Ok(IdentityCleanupPage::Removed);
            }
        }
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let (candidates, next_cursor) =
        enumerate_identity_scan_page(directory, scan_cursor, scan_deadline)?;
    let mut matches = Vec::new();
    for candidate in &candidates {
        if Instant::now() >= scan_deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "pinned upload identity scan exceeded its time bound",
            ));
        }
        match directory.open_readonly_file(candidate) {
            Ok(file) if file_identity(&file)? == expected_identity => {
                matches.push(candidate.clone())
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    if matches.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "pinned upload identity is ambiguous in its reservation directory",
        ));
    }
    if let Some(candidate) = matches.first()
        && remove_identity_entry(directory, candidate, expected_identity, &mut before_unlink)?
    {
        return Ok(IdentityCleanupPage::Removed);
    }
    if next_cursor.is_none() && scan_cursor.is_none() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "pinned upload identity is absent from its complete reservation-directory scan",
        ));
    }
    Ok(IdentityCleanupPage::Continue(next_cursor))
}

fn enumerate_identity_scan_page(
    directory: &SecureReservationDirectory,
    scan_cursor: Option<&str>,
    deadline: Instant,
) -> io::Result<(Vec<String>, Option<String>)> {
    let mut entries =
        directory.enumerate_files_bounded(MAX_IDENTITY_SCAN_DIRECTORY_ENTRIES, deadline)?;
    entries.sort_unstable();
    let mut start = scan_cursor.map_or(0, |cursor| {
        entries
            .iter()
            .position(|entry| entry.as_str() > cursor)
            .unwrap_or(entries.len())
    });
    if start == entries.len() && scan_cursor.is_some() {
        start = 0;
    }
    let end = start
        .saturating_add(MAX_IDENTITY_SCAN_ENTRIES)
        .min(entries.len());
    let page = entries[start..end].to_vec();
    let next_cursor = (end < entries.len()).then(|| entries[end - 1].clone());
    Ok((page, next_cursor))
}

fn remove_identity_entry<F>(
    directory: &SecureReservationDirectory,
    candidate: &str,
    expected_identity: &[u8],
    before_unlink: &mut Option<F>,
) -> io::Result<bool>
where
    F: FnOnce(),
{
    #[cfg(windows)]
    {
        let file = match directory.open_file_for_delete(candidate) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if file_identity(&file)? != expected_identity {
            return Ok(false);
        }
        if file_link_count(&file)? > 1 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "pinned upload identity is ambiguous in its reservation directory",
            ));
        }
        if let Some(before_unlink) = before_unlink.take() {
            before_unlink();
        }
        delete_open_file(&file)?;
        Ok(true)
    }
    #[cfg(unix)]
    {
        let quarantine = format!(".cleanup-{}.tmp", Uuid::new_v4());
        match directory.rename_file(candidate, &quarantine) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        }
        let moved = match directory.open_readonly_file(&quarantine) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if file_identity(&moved)? != expected_identity {
            drop(moved);
            if directory.open_file(candidate, false).is_err() {
                let _ = directory.rename_file(&quarantine, candidate);
            }
            return Ok(false);
        }
        if file_link_count(&moved)? > 1 {
            drop(moved);
            if directory.open_file(candidate, false).is_err() {
                let _ = directory.rename_file(&quarantine, candidate);
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "pinned upload identity is ambiguous in its reservation directory",
            ));
        }
        drop(moved);
        if let Some(before_unlink) = before_unlink.take() {
            before_unlink();
        }
        let verified = match directory.open_readonly_file(&quarantine) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        if file_identity(&verified)? != expected_identity {
            drop(verified);
            if directory.open_file(candidate, false).is_err() {
                let _ = directory.rename_file(&quarantine, candidate);
            }
            return Ok(false);
        }
        if file_link_count(&verified)? > 1 {
            drop(verified);
            if directory.open_file(candidate, false).is_err() {
                let _ = directory.rename_file(&quarantine, candidate);
            }
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "pinned upload identity is ambiguous in its reservation directory",
            ));
        }
        drop(verified);
        directory.remove_file(&quarantine)?;
        return Ok(true);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (directory, candidate, expected_identity, before_unlink);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "identity-safe upload cleanup is unsupported on this platform",
        ))
    }
}

fn load_file_identity(
    transaction: &Transaction<'_>,
    session_id: i64,
) -> Result<Vec<u8>, LimitError> {
    transaction
        .query_row(
            "SELECT file_identity FROM uploads WHERE id = ?1",
            [session_id],
            |row| row.get::<_, Option<Vec<u8>>>(0),
        )
        .optional()?
        .flatten()
        .ok_or(LimitError::AccountingInvariant)
}

fn capability_expiry(
    transaction: &Transaction<'_>,
    session_id: i64,
    capability: &SessionToken,
) -> Result<i64, LimitError> {
    transaction
        .query_row(
            "SELECT expires_at FROM capabilities \
             WHERE token_hash = ?1 AND subject = ?2",
            params![
                capability.hash().as_slice(),
                format!("upload-session:{session_id}")
            ],
            |row| row.get(0),
        )
        .optional()?
        .ok_or(LimitError::CapabilityExpired)
}

fn new_lease_expiry(
    now: i64,
    lease_duration: Duration,
    capability_expiry: i64,
) -> Result<i64, LimitError> {
    if capability_expiry <= now || lease_duration.is_zero() {
        return Err(LimitError::CapabilityExpired);
    }
    let whole_seconds = lease_duration
        .as_secs()
        .checked_add(u64::from(lease_duration.subsec_nanos() > 0))
        .ok_or(LimitError::InvalidConfiguration)?;
    let seconds =
        i64::try_from(whole_seconds.max(1)).map_err(|_| LimitError::InvalidConfiguration)?;
    let lease_expiry = now
        .checked_add(seconds)
        .ok_or(LimitError::InvalidConfiguration)?;
    Ok(lease_expiry.min(capability_expiry))
}

fn expire_abandoned_sessions_in_transaction(
    transaction: &Transaction<'_>,
    now: i64,
) -> Result<(), LimitError> {
    expire_abandoned_sessions_excluding_in_transaction(transaction, now, &[])
}

fn recover_unacknowledged_settlements_in_transaction(
    transaction: &Transaction<'_>,
    created_at_before: Option<i64>,
    maximum: usize,
    fail_closed_on_overflow: bool,
    only_session_id: Option<i64>,
) -> Result<usize, LimitError> {
    let limit = i64::try_from(maximum.saturating_add(1)).unwrap_or(i64::MAX);
    let rows = {
        let mut statement = transaction.prepare(
            "SELECT session_id, day, actual_bytes, delivery_possible FROM settlement_outbox \
             WHERE (?1 IS NULL OR created_at <= ?1) \
               AND (?2 IS NULL OR session_id = ?2) \
             ORDER BY created_at, session_id LIMIT ?3",
        )?;
        statement
            .query_map(params![created_at_before, only_session_id, limit], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };
    if rows.len() > maximum && fail_closed_on_overflow {
        return Err(LimitError::PendingSettlementRecoveryLimit);
    }
    let mut count = 0;
    for (session_id, day, actual_sql, delivery_possible) in rows.into_iter().take(maximum) {
        let _actual_bytes = from_sql_integer(actual_sql)?;
        let (state, identity_id, stored_actual) = transaction.query_row(
            "SELECT state, identity_id, actual_bytes FROM uploads WHERE id = ?1",
            [session_id],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                ))
            },
        )?;
        let state = UploadState::from_str(&state)?;
        if delivery_possible {
            if state != UploadState::Uploaded || stored_actual != Some(actual_sql) {
                return Err(LimitError::AccountingInvariant);
            }
            // A 204 might have reached the peer. Preserve both its charge and
            // file until an identity-verified ACK retry clears this intent.
            continue;
        }
        count += 1;
        match state {
            UploadState::Uploaded => {
                if stored_actual != Some(actual_sql) {
                    return Err(LimitError::AccountingInvariant);
                }
                let changed = transaction.execute(
                    "UPDATE daily_usage SET used_bytes = used_bytes - ?1 \
                     WHERE identity_id = ?2 AND day = ?3 AND used_bytes >= ?1",
                    params![actual_sql, identity_id, day],
                )?;
                if changed != 1 {
                    return Err(LimitError::AccountingInvariant);
                }
                transaction.execute(
                    "DELETE FROM daily_usage WHERE identity_id = ?1 AND day = ?2 AND used_bytes = 0",
                    params![identity_id, day],
                )?;
                let changed = transaction.execute(
                    "UPDATE uploads SET state = 'expired', actual_bytes = NULL, reserved_bytes = 0, \
                     lease_expires_at = NULL WHERE id = ?1 AND state = 'uploaded' AND actual_bytes = ?2",
                    params![session_id, actual_sql],
                )?;
                if changed != 1 {
                    return Err(LimitError::AccountingInvariant);
                }
                revoke_session_capability(transaction, session_id)?;
                enqueue_cleanup(transaction, session_id)?;
            }
            UploadState::Expired => {
                // A manual expiry can win after settlement committed but
                // before transport acknowledgment. The durable intent still
                // proves the byte charge has not been acknowledged, so refund
                // it exactly once before clearing the intent.
                if let Some(stored_actual) = stored_actual {
                    if stored_actual != actual_sql {
                        return Err(LimitError::AccountingInvariant);
                    }
                    let changed = transaction.execute(
                        "UPDATE daily_usage SET used_bytes = used_bytes - ?1 \
                         WHERE identity_id = ?2 AND day = ?3 AND used_bytes >= ?1",
                        params![actual_sql, identity_id, day],
                    )?;
                    if changed != 1 {
                        return Err(LimitError::AccountingInvariant);
                    }
                    transaction.execute(
                        "DELETE FROM daily_usage WHERE identity_id = ?1 AND day = ?2 AND used_bytes = 0",
                        params![identity_id, day],
                    )?;
                    transaction.execute(
                        "UPDATE uploads SET actual_bytes = NULL WHERE id = ?1 AND state = 'expired'",
                        [session_id],
                    )?;
                }
                enqueue_cleanup(transaction, session_id)?;
            }
            _ => return Err(LimitError::AccountingInvariant),
        }
        transaction.execute(
            "DELETE FROM settlement_outbox WHERE session_id = ?1",
            [session_id],
        )?;
    }
    Ok(count)
}

fn expire_abandoned_sessions_excluding_in_transaction(
    transaction: &Transaction<'_>,
    now: i64,
    active_uploads: &[i64],
) -> Result<(), LimitError> {
    let active_uploads = active_uploads.iter().copied().collect::<HashSet<_>>();
    let sessions = if table_exists(transaction, "capabilities")? {
        let mut statement = transaction.prepare(
            "SELECT uploads.id, uploads.reserved_bytes FROM uploads \
             LEFT JOIN capabilities ON capabilities.token_hash = uploads.capability_hash \
               AND capabilities.subject = 'upload-session:' || uploads.id \
             WHERE (uploads.state = 'reserved' AND \
                    (capabilities.expires_at IS NULL OR capabilities.expires_at <= ?1)) \
                OR (uploads.state = 'receiving' AND \
                    (uploads.lease_expires_at IS NULL OR uploads.lease_expires_at <= ?1)) \
             ORDER BY uploads.id",
        )?;
        statement
            .query_map([now], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    } else {
        let mut statement = transaction.prepare(
            "SELECT id, reserved_bytes FROM uploads WHERE state = 'receiving' \
             AND (lease_expires_at IS NULL OR lease_expires_at <= ?1) ORDER BY id",
        )?;
        statement
            .query_map([now], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
            })?
            .collect::<Result<Vec<_>, _>>()?
    };

    for (session_id, reserved_sql) in sessions {
        if active_uploads.contains(&session_id) {
            continue;
        }
        let reserved = from_sql_integer(reserved_sql)?;
        enqueue_cleanup(transaction, session_id)?;
        let changed = transaction.execute(
            "UPDATE uploads SET state = 'expired', reserved_bytes = 0, lease_expires_at = NULL \
             WHERE id = ?1 AND state IN ('reserved', 'receiving')",
            [session_id],
        )?;
        if changed == 1 {
            if reserved > 0 {
                release_global_reserved(transaction, reserved)?;
            }
            revoke_session_capability(transaction, session_id)?;
        }
    }
    Ok(())
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

fn is_managed_reservation_leaf(leaf: &str) -> bool {
    leaf.strip_suffix(".upload")
        .or_else(|| {
            leaf.strip_prefix(".cleanup-")
                .and_then(|name| name.strip_suffix(".tmp"))
        })
        .is_some_and(|name| Uuid::parse_str(name).is_ok())
}

impl SecureReservationDirectory {
    #[cfg(unix)]
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
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

    #[cfg(unix)]
    fn open_identity_file(&self, leaf: &str) -> io::Result<fs::File> {
        self.open_file(leaf, false)
    }

    #[cfg(unix)]
    pub(crate) fn open_readonly_file(&self, leaf: &str) -> io::Result<fs::File> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};

        let leaf = CString::new(leaf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        let fd = unsafe { libc::openat(self.handle.as_raw_fd(), leaf.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { fs::File::from_raw_fd(fd) })
    }

    #[cfg(unix)]
    fn rename_file(&self, from: &str, to: &str) -> io::Result<()> {
        use std::ffi::CString;
        use std::os::fd::AsRawFd;

        let from = CString::new(from)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?;
        let to = CString::new(to)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid filename"))?;
        let result = unsafe {
            libc::renameat(
                self.handle.as_raw_fd(),
                from.as_ptr(),
                self.handle.as_raw_fd(),
                to.as_ptr(),
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    #[cfg(windows)]
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
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
        windows_open_relative_file(&self.handle, leaf, create_new, false, false)
    }

    #[cfg(windows)]
    fn open_identity_file(&self, leaf: &str) -> io::Result<fs::File> {
        windows_open_relative_file(&self.handle, leaf, false, false, true)
    }

    #[cfg(windows)]
    pub(crate) fn open_readonly_file(&self, leaf: &str) -> io::Result<fs::File> {
        windows_open_relative_file(&self.handle, leaf, false, false, true)
    }

    #[cfg(windows)]
    fn open_file_for_delete(&self, leaf: &str) -> io::Result<fs::File> {
        windows_open_relative_file(&self.handle, leaf, false, true, false)
    }

    #[cfg(windows)]
    fn open_directory_child(&self, leaf: &str) -> io::Result<Self> {
        windows_open_relative_directory(&self.handle, leaf).map(|handle| Self { handle })
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn open(_path: &Path) -> io::Result<Self> {
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
    fn open_identity_file(&self, _leaf: &str) -> io::Result<fs::File> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "secure relative file access is unsupported",
        ))
    }

    #[cfg(not(any(unix, windows)))]
    pub(crate) fn open_readonly_file(&self, _leaf: &str) -> io::Result<fs::File> {
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

    pub(crate) fn remove_named_file_if_identity_page(
        &self,
        leaf: &str,
        expected_identity: &[u8],
        scan_cursor: Option<&str>,
    ) -> io::Result<IdentityCleanupPage> {
        remove_file_if_identity_page(self, leaf, expected_identity, scan_cursor, || {})
    }

    #[cfg(unix)]
    #[cfg(test)]
    fn enumerate_files(&self) -> io::Result<Vec<String>> {
        self.enumerate_files_bounded(usize::MAX, Instant::now() + Duration::from_secs(30))
    }

    #[cfg(unix)]
    fn enumerate_files_bounded(
        &self,
        maximum_entries: usize,
        deadline: Instant,
    ) -> io::Result<Vec<String>> {
        use std::os::fd::AsRawFd;

        let descriptor_path = if cfg!(target_os = "linux") {
            PathBuf::from(format!("/proc/self/fd/{}", self.handle.as_raw_fd()))
        } else {
            PathBuf::from(format!("/dev/fd/{}", self.handle.as_raw_fd()))
        };
        let mut names = Vec::new();
        let mut entries_seen = 0usize;
        for entry in fs::read_dir(descriptor_path)? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "reservation directory scan exceeded its time bound",
                ));
            }
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > maximum_entries {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "reservation directory scan exceeded its entry bound",
                ));
            }
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
    fn enumerate_files_bounded(
        &self,
        maximum_entries: usize,
        deadline: Instant,
    ) -> io::Result<Vec<String>> {
        windows_enumerate_files_bounded(&self.handle, maximum_entries, deadline)
    }
}

#[cfg(windows)]
fn windows_enumerate_files_bounded(
    directory: &fs::File,
    maximum_entries: usize,
    deadline: Instant,
) -> io::Result<Vec<String>> {
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
    let mut entries_seen = 0usize;
    let mut restart = true;
    loop {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "reservation directory scan exceeded its time bound",
            ));
        }
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
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "reservation directory scan exceeded its time bound",
                ));
            }
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > maximum_entries {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "reservation directory scan exceeded its entry bound",
                ));
            }
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
    deny_delete_sharing: bool,
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
        0x0001 | 0x0002 | 0x0080 | 0x0100 | 0x0010_0000
    };
    let status = unsafe {
        NtCreateFile(
            &mut raw_file,
            desired_access,
            &mut attributes,
            &mut status_block,
            std::ptr::null_mut(),
            0x80,
            if deny_delete_sharing {
                0x0001 | 0x0002
            } else {
                0x0001 | 0x0002 | 0x0004
            },
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

#[cfg(windows)]
fn delete_open_file(file: &fs::File) -> io::Result<()> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            class: i32,
            info: *const std::ffi::c_void,
            size: u32,
        ) -> i32;
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
    if !matches!(
        table,
        "uploads" | "ip_hashes" | "cleanup_outbox" | "settlement_outbox"
    ) {
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

fn revoke_session_capability(
    transaction: &Transaction<'_>,
    session_id: i64,
) -> Result<(), LimitError> {
    if table_exists(transaction, "capabilities")? {
        transaction.execute(
            "UPDATE capabilities SET expires_at = 0 \
             WHERE token_hash = (SELECT capability_hash FROM uploads WHERE id = ?1)",
            [session_id],
        )?;
    }
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
    current_unix_seconds() / 86_400
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

#[cfg(unix)]
pub(crate) fn file_identity(file: &fs::File) -> io::Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata()?;
    let mut identity = Vec::with_capacity(17);
    identity.push(b'u');
    identity.extend_from_slice(&metadata.dev().to_be_bytes());
    identity.extend_from_slice(&metadata.ino().to_be_bytes());
    Ok(identity)
}

#[cfg(windows)]
pub(crate) fn file_identity(file: &fs::File) -> io::Result<Vec<u8>> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time_low: u32,
        creation_time_high: u32,
        last_access_time_low: u32,
        last_access_time_high: u32,
        last_write_time_low: u32,
        last_write_time_high: u32,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = ByHandleFileInformation {
        file_attributes: 0,
        creation_time_low: 0,
        creation_time_high: 0,
        last_access_time_low: 0,
        last_access_time_high: 0,
        last_write_time_low: 0,
        last_write_time_high: 0,
        volume_serial_number: 0,
        file_size_high: 0,
        file_size_low: 0,
        number_of_links: 0,
        file_index_high: 0,
        file_index_low: 0,
    };
    let valid =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } != 0;
    if !valid {
        return Err(io::Error::last_os_error());
    }
    let mut identity = Vec::with_capacity(13);
    identity.push(b'w');
    identity.extend_from_slice(&information.volume_serial_number.to_be_bytes());
    identity.extend_from_slice(&information.file_index_high.to_be_bytes());
    identity.extend_from_slice(&information.file_index_low.to_be_bytes());
    Ok(identity)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn file_identity(_file: &fs::File) -> io::Result<Vec<u8>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable file identities are unsupported on this platform",
    ))
}

#[cfg(unix)]
pub(crate) fn file_link_count(file: &fs::File) -> io::Result<u64> {
    use std::os::unix::fs::MetadataExt;

    Ok(file.metadata()?.nlink())
}

#[cfg(windows)]
pub(crate) fn file_link_count(file: &fs::File) -> io::Result<u64> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time_low: u32,
        creation_time_high: u32,
        last_access_time_low: u32,
        last_access_time_high: u32,
        last_write_time_low: u32,
        last_write_time_high: u32,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            file: *mut std::ffi::c_void,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = ByHandleFileInformation {
        file_attributes: 0,
        creation_time_low: 0,
        creation_time_high: 0,
        last_access_time_low: 0,
        last_access_time_high: 0,
        last_write_time_low: 0,
        last_write_time_high: 0,
        volume_serial_number: 0,
        file_size_high: 0,
        file_size_low: 0,
        number_of_links: 0,
        file_index_high: 0,
        file_index_low: 0,
    };
    let valid =
        unsafe { GetFileInformationByHandle(file.as_raw_handle().cast(), &mut information) } != 0;
    if !valid {
        return Err(io::Error::last_os_error());
    }
    Ok(u64::from(information.number_of_links))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn file_link_count(_file: &fs::File) -> io::Result<u64> {
    Ok(1)
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
    file_identity: Vec<u8>,
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
            if let Ok(file) = self.directory.open_file(&self.file_name, false)
                && file_identity(&file).ok().as_deref() == Some(self.file_identity.as_slice())
            {
                let _ = set_file_allocation(&file, previous_size);
            }
        } else {
            let _ = remove_file_if_identity(
                &self.directory,
                &self.file_name,
                &self.file_identity,
                || {},
            );
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
    let file_identity = file_identity(&file).map_err(LimitError::Filesystem)?;
    let guard = ReservationFileGuard {
        directory,
        file_name: file_name.to_owned(),
        file_identity,
        previous_size: None,
        committed: false,
    };
    set_file_allocation(&file, size).map_err(LimitError::Filesystem)?;
    Ok(guard)
}

struct PinnedFileResizeGuard<'a> {
    file: &'a fs::File,
    previous_size: u64,
    committed: bool,
}

impl PinnedFileResizeGuard<'_> {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PinnedFileResizeGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            let _ = set_file_allocation(self.file, self.previous_size);
        }
    }
}

fn resize_reserved_file(
    file: &fs::File,
    size: u64,
) -> Result<PinnedFileResizeGuard<'_>, LimitError> {
    let previous_size = file.metadata().map_err(LimitError::Filesystem)?.len();
    let guard = PinnedFileResizeGuard {
        file,
        previous_size,
        committed: false,
    };
    set_file_allocation(file, size).map_err(LimitError::Filesystem)?;
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
    use std::io::Write;

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

    #[test]
    fn identity_cleanup_preserves_replacement_and_removes_displaced_original() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        fs::create_dir(&upload_root).unwrap();
        let ledger = UploadLedger::open(
            temp.path().join("ledger.sqlite3"),
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let reservation = ledger.reserve("192.0.2.10", Some(1)).unwrap();
        let path = reservation.upload_path.clone();
        let displaced = path.with_extension("displaced");
        let relative = path.strip_prefix(&ledger.upload_root).unwrap().to_owned();
        let original = ledger
            .reservation_directory
            .open_file(path.file_name().unwrap().to_str().unwrap(), false)
            .unwrap();
        let identity = file_identity(&original).unwrap();
        drop(original);
        let hook_called = std::sync::atomic::AtomicBool::new(false);

        ledger
            .remove_upload_file_with_identity_and_hook(&relative, Some(&identity), || {
                hook_called.store(true, std::sync::atomic::Ordering::SeqCst);
                #[cfg(unix)]
                {
                    let quarantine = ledger
                        .reservation_directory
                        .enumerate_files()
                        .unwrap()
                        .into_iter()
                        .find(|name| name.starts_with(".cleanup-"))
                        .expect("the pinned identity must already be quarantined");
                    let quarantine_path = path.parent().unwrap().join(quarantine);
                    fs::rename(&quarantine_path, &displaced).unwrap();
                    fs::write(&quarantine_path, b"unrelated replacement").unwrap();
                }
                #[cfg(windows)]
                {
                    fs::rename(&path, &displaced).unwrap();
                    fs::write(&path, b"unrelated replacement").unwrap();
                }
            })
            .unwrap();

        assert!(hook_called.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(fs::read(&path).unwrap(), b"unrelated replacement");
        assert!(
            !displaced.exists(),
            "identity cleanup must remove the pinned original after a rename"
        );
    }

    #[test]
    fn identity_cleanup_fails_closed_when_identity_is_absent_or_ambiguous() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        fs::create_dir(&upload_root).unwrap();
        let ledger = UploadLedger::open(
            temp.path().join("ledger.sqlite3"),
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();

        let missing = ledger.reserve("192.0.2.10", Some(1)).unwrap();
        let missing_path = missing.upload_path;
        let missing_identity = {
            let file = ledger
                .reservation_directory
                .open_file(missing_path.file_name().unwrap().to_str().unwrap(), false)
                .unwrap();
            file_identity(&file).unwrap()
        };
        let displaced = temp.path().join("displaced-upload");
        fs::rename(&missing_path, &displaced).unwrap();
        fs::write(&missing_path, b"unrelated replacement").unwrap();
        let relative = missing_path
            .strip_prefix(&ledger.upload_root)
            .unwrap()
            .to_owned();
        let absent = ledger.remove_upload_file_with_identity_and_hook(
            &relative,
            Some(&missing_identity),
            || {},
        );
        assert_eq!(absent.unwrap_err().kind(), io::ErrorKind::NotFound);
        assert_eq!(fs::read(&missing_path).unwrap(), b"unrelated replacement");
        assert!(displaced.exists());

        let ambiguous = ledger.reserve("192.0.2.10", Some(1)).unwrap();
        let alias = ambiguous.upload_path.with_extension("alias");
        fs::hard_link(&ambiguous.upload_path, &alias).unwrap();
        let identity = {
            let file = ledger
                .reservation_directory
                .open_file(
                    ambiguous.upload_path.file_name().unwrap().to_str().unwrap(),
                    false,
                )
                .unwrap();
            file_identity(&file).unwrap()
        };
        let relative = ambiguous
            .upload_path
            .strip_prefix(&ledger.upload_root)
            .unwrap()
            .to_owned();
        let duplicate =
            ledger.remove_upload_file_with_identity_and_hook(&relative, Some(&identity), || {});
        assert_eq!(duplicate.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert!(ambiguous.upload_path.exists());
        assert!(alias.exists());
    }

    #[test]
    fn identity_cleanup_uses_the_known_name_before_bounded_fallback_scan() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        fs::create_dir(&upload_root).unwrap();
        let ledger = UploadLedger::open(
            temp.path().join("ledger.sqlite3"),
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let timed_out = ledger
            .reservation_directory
            .enumerate_files_bounded(MAX_IDENTITY_SCAN_ENTRIES, Instant::now())
            .unwrap_err();
        assert_eq!(timed_out.kind(), io::ErrorKind::TimedOut);
        let reservation = ledger.reserve("192.0.2.10", Some(1)).unwrap();
        let reservation_directory = upload_root.join(".fluxform-reservations");
        for index in 0..65 {
            fs::write(
                reservation_directory.join(format!("unrelated-{index:03}")),
                b"not a reservation",
            )
            .unwrap();
        }
        let pinned = ledger
            .reservation_directory
            .open_file(
                reservation
                    .upload_path
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap(),
                false,
            )
            .unwrap();
        let identity = file_identity(&pinned).unwrap();
        drop(pinned);

        let result = ledger.remove_upload_file_if_identity(
            reservation
                .upload_path
                .strip_prefix(&ledger.upload_root)
                .unwrap(),
            &identity,
        );

        result.unwrap();
        assert!(!reservation.upload_path.exists());
        for index in 0..65 {
            assert_eq!(
                fs::read(reservation_directory.join(format!("unrelated-{index:03}"))).unwrap(),
                b"not a reservation"
            );
        }
    }

    #[test]
    fn reservation_namespace_admission_is_bounded_by_directory_policy() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        fs::create_dir(&upload_root).unwrap();
        let ledger = UploadLedger::open(
            temp.path().join("ledger.sqlite3"),
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        for index in 0..MAX_RESERVATION_DIRECTORY_ENTRIES {
            fs::write(
                upload_root
                    .join(".fluxform-reservations")
                    .join(format!("untrusted-{index:04}")),
                b"unrelated",
            )
            .unwrap();
        }

        assert!(matches!(
            ledger.reserve("192.0.2.10", Some(1)),
            Err(LimitError::GlobalCapacityExceeded)
        ));
        let rows: i64 = Connection::open(&ledger.database_path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM uploads", [], |row| row.get(0))
            .unwrap();
        assert_eq!(rows, 0, "directory policy must reject before reservation");
        assert_eq!(
            ledger
                .reservation_directory
                .enumerate_files_bounded(
                    MAX_RESERVATION_DIRECTORY_ENTRIES + 2,
                    Instant::now() + Duration::from_secs(2)
                )
                .unwrap()
                .len(),
            MAX_RESERVATION_DIRECTORY_ENTRIES
        );
    }

    #[test]
    fn identity_cleanup_fallback_paginates_persists_cursor_and_preserves_other_files() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let limits = LedgerLimits {
            max_file_bytes: 1,
            daily_quota_bytes: 200,
            max_active_sessions_per_ip: 2,
            max_global_reserved_bytes: 200,
            disk_safety_margin_bytes: 0,
        };
        let ledger =
            UploadLedger::open(&database_path, &upload_root, limits, vec![[0xA1; 32]]).unwrap();
        let expires_at = SystemTime::now() + Duration::from_secs(600);
        let (target, _) = ledger
            .reserve_with_upload_capability("198.51.100.250", Some(1), expires_at)
            .unwrap();
        let target_original = target.upload_path.clone();
        let displaced = upload_root
            .join(".fluxform-reservations")
            .join("zzzz-displaced-original.upload");
        let mut unrelated_paths = Vec::new();
        for index in 1..=70 {
            let reservation = ledger
                .reserve_with_upload_capability(&format!("198.51.100.{index}"), Some(1), expires_at)
                .unwrap()
                .0;
            unrelated_paths.push(reservation.upload_path);
        }
        fs::rename(&target_original, &displaced).unwrap();
        fs::write(&target_original, b"unrelated replacement").unwrap();
        ledger
            .expire(target.session_id, &target.session_token)
            .unwrap();

        let first_page = ledger.reconcile_cleanup_job(target.session_id).unwrap();
        assert_eq!(first_page.retryable, 1);
        let (cursor, attempts): (Option<String>, i64) = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT scan_cursor, attempts FROM cleanup_outbox WHERE session_id = ?1",
                [target.session_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(
            cursor.is_some(),
            "page one must persist a stable resume cursor"
        );
        assert_eq!(attempts, 1);
        Connection::open(&database_path)
            .unwrap()
            .execute(
                "UPDATE cleanup_outbox SET next_attempt_at = 0 WHERE session_id = ?1",
                [target.session_id],
            )
            .unwrap();
        drop(ledger);

        let reopened =
            UploadLedger::open(&database_path, &upload_root, limits, vec![[0xA1; 32]]).unwrap();

        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM cleanup_outbox WHERE session_id = ?1",
                [target.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "the next bounded page must resume after reopen");
        assert!(
            !displaced.exists(),
            "only the persisted target identity is removed"
        );
        assert_eq!(
            fs::read(&target_original).unwrap(),
            b"unrelated replacement"
        );
        for path in unrelated_paths {
            assert!(
                path.exists(),
                "normal retained upload was removed: {path:?}"
            );
        }
        assert_eq!(
            reopened
                .state(target.session_id, &target.session_token)
                .unwrap(),
            UploadState::Expired
        );
    }

    #[test]
    fn unrelated_sticky_cleanup_does_not_fail_target_settlement_compensation() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();

        let sticky = ledger.reserve("192.0.2.11", Some(1)).unwrap();
        let sticky_path = sticky.upload_path.clone();
        let sticky_identity = {
            let file = ledger
                .reservation_directory
                .open_file(sticky_path.file_name().unwrap().to_str().unwrap(), false)
                .unwrap();
            file_identity(&file).unwrap()
        };
        let displaced = temp.path().join("displaced-sticky-upload");
        fs::rename(&sticky_path, &displaced).unwrap();
        fs::write(&sticky_path, b"replacement").unwrap();
        Connection::open(&database_path)
            .unwrap()
            .execute(
                "UPDATE uploads SET file_identity = ?1 WHERE id = ?2",
                params![sticky_identity, sticky.session_id],
            )
            .unwrap();
        ledger
            .expire(sticky.session_id, &sticky.session_token)
            .unwrap();
        assert_eq!(ledger.reconcile_cleanup_jobs().unwrap().retryable, 1);

        let target = ledger
            .reserve_with_upload_capability(
                "192.0.2.12",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap()
            .0;
        ledger
            .claim_receiving_lease(
                target.session_id,
                &target.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(target.session_id, &target.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        let receipt = ledger
            .settle_pinned_until(
                target.session_id,
                &target.session_token,
                &file,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        drop(file);

        let result =
            ledger.compensate_late_settlement(target.session_id, &target.session_token, receipt);

        assert!(
            result.is_ok(),
            "unrelated sticky work must not poison target cleanup"
        );
        assert_eq!(
            ledger
                .state(target.session_id, &target.session_token)
                .unwrap(),
            UploadState::Expired
        );
        assert!(!target.upload_path.exists());
        assert_eq!(fs::read(sticky_path).unwrap(), b"replacement");
        assert!(
            displaced.exists(),
            "the unidentifiable pinned object remains pending"
        );
        assert_eq!(ledger.reconcile_cleanup_jobs().unwrap().retryable, 1);
    }

    #[test]
    fn settlement_acknowledgement_rejects_a_replacement_at_the_persisted_path() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        ledger
            .settle_pinned_until(
                reservation.session_id,
                &reservation.session_token,
                &file,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        drop(file);

        let displaced = reservation.upload_path.with_extension("displaced");
        fs::rename(&reservation.upload_path, &displaced).unwrap();
        fs::write(&reservation.upload_path, b"unrelated replacement").unwrap();

        assert!(matches!(
            ledger.acknowledge_settlement(reservation.session_id),
            Err(LimitError::FileIdentityMismatch)
        ));
        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM settlement_outbox WHERE session_id = ?1",
                [reservation.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1, "identity failure must leave the durable intent");
        assert_eq!(
            fs::read(&reservation.upload_path).unwrap(),
            b"unrelated replacement"
        );
        assert_eq!(fs::read(displaced).unwrap(), b"x");
    }

    #[test]
    fn uploaded_consumer_transition_rejects_a_replacement_file_identity() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        ledger
            .settle(reservation.session_id, &reservation.session_token, 1)
            .unwrap();
        drop(file);

        let displaced = reservation.upload_path.with_extension("displaced");
        fs::rename(&reservation.upload_path, &displaced).unwrap();
        fs::write(&reservation.upload_path, b"unrelated replacement").unwrap();

        assert!(matches!(
            ledger.transition(
                reservation.session_id,
                &reservation.session_token,
                UploadState::Probing
            ),
            Err(LimitError::FileIdentityMismatch)
        ));
        assert_eq!(
            ledger
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Uploaded
        );
        assert_eq!(
            fs::read(&reservation.upload_path).unwrap(),
            b"unrelated replacement"
        );
        assert_eq!(fs::read(displaced).unwrap(), b"x");
    }

    #[test]
    fn delivery_possible_ack_failure_survives_reopen_and_is_eventually_acknowledged() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        ledger
            .settle_pinned_until(
                reservation.session_id,
                &reservation.session_token,
                &file,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        drop(file);

        Connection::open(&database_path)
            .unwrap()
            .execute(
                "UPDATE settlement_outbox SET delivery_possible = 1 WHERE session_id = ?1",
                [reservation.session_id],
            )
            .unwrap();
        let lock = Connection::open(&database_path).unwrap();
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        assert!(
            ledger
                .acknowledge_settlement(reservation.session_id)
                .is_err()
        );
        lock.execute_batch("ROLLBACK").unwrap();
        drop(lock);
        drop(ledger);

        let reopened = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        assert_eq!(
            reopened
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Uploaded,
            "a response marked delivery-possible must not be rolled back on startup"
        );
        assert_eq!(fs::read(&reservation.upload_path).unwrap(), b"x");
        reopened
            .acknowledge_settlement(reservation.session_id)
            .unwrap();
        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM settlement_outbox WHERE session_id = ?1",
                [reservation.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0);
        assert_eq!(
            reopened
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Uploaded
        );
    }

    #[test]
    fn migration_treats_legacy_pending_settlements_as_delivery_ambiguous() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        ledger
            .settle_internal(
                reservation.session_id,
                &reservation.session_token,
                Some(&file),
                1,
            )
            .unwrap();
        drop(file);
        drop(ledger);

        Connection::open(&database_path)
            .unwrap()
            .execute_batch(
                "ALTER TABLE cleanup_outbox DROP COLUMN scan_cursor;
                 ALTER TABLE settlement_outbox DROP COLUMN delivery_possible;
                 PRAGMA user_version = 6;",
            )
            .unwrap();

        let reopened = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        assert_eq!(
            reopened
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Uploaded,
            "legacy pending settlement delivery is unknowable and must not be rolled back"
        );
        assert_eq!(fs::read(&reservation.upload_path).unwrap(), b"x");
        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM settlement_outbox WHERE session_id = ?1",
                [reservation.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "startup should finish the conservative ACK");
    }

    #[test]
    fn unacknowledged_settlement_is_compensated_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let reservation = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap()
            .0;
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        ledger
            .settle_pinned_until(
                reservation.session_id,
                &reservation.session_token,
                &file,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM settlement_outbox WHERE session_id = ?1",
                [reservation.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            pending, 1,
            "settlement and remediation intent commit atomically"
        );
        drop(file);
        drop(ledger);

        let reopened = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();

        assert_eq!(
            reopened
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Expired
        );
        assert_eq!(reopened.reserved_bytes().unwrap(), 0);
        assert!(!reservation.upload_path.exists());
        let usage: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(used_bytes), 0) FROM daily_usage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(usage, 0);
        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM settlement_outbox WHERE session_id = ?1",
                [reservation.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 0, "startup compensation is durable and idempotent");
        drop(reopened);

        let reopened_again = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        assert_eq!(
            reopened_again
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Expired,
            "a crash after compensation commit is idempotently recovered"
        );
    }

    #[test]
    fn acknowledged_settlement_survives_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let reservation = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap()
            .0;
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        ledger
            .settle_pinned_until(
                reservation.session_id,
                &reservation.session_token,
                &file,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        ledger
            .acknowledge_settlement(reservation.session_id)
            .unwrap();
        let pending: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM settlement_outbox WHERE session_id = ?1",
                [reservation.session_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            pending, 0,
            "successful transport completion acknowledges intent"
        );
        drop(file);
        drop(ledger);

        let reopened = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        assert_eq!(
            reopened
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Uploaded
        );
        assert!(reservation.upload_path.exists());
        let usage: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(used_bytes), 0) FROM daily_usage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(usage, 1);
    }

    #[test]
    fn stale_unacknowledged_settlement_is_compensated_by_periodic_reconciliation() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let reservation = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap()
            .0;
        ledger
            .claim_receiving_lease(
                reservation.session_id,
                &reservation.session_token,
                Duration::from_secs(30),
            )
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(reservation.session_id, &reservation.session_token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        ledger
            .settle_pinned_until(
                reservation.session_id,
                &reservation.session_token,
                &file,
                1,
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
        drop(file);
        Connection::open(&database_path)
            .unwrap()
            .execute(
                "UPDATE settlement_outbox SET created_at = 0 WHERE session_id = ?1",
                [reservation.session_id],
            )
            .unwrap();

        ledger.reconcile_expired_sessions().unwrap();

        assert_eq!(
            ledger
                .state(reservation.session_id, &reservation.session_token)
                .unwrap(),
            UploadState::Expired
        );
        assert_eq!(ledger.reserved_bytes().unwrap(), 0);
        assert!(!reservation.upload_path.exists());
        let usage: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(used_bytes), 0) FROM daily_usage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(usage, 0);
    }

    #[test]
    #[cfg(unix)]
    fn same_uid_unix_swap_is_not_claimed_but_ack_refuses_the_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        let session_id = reservation.session_id;
        let token = reservation.session_token;
        let path = reservation.upload_path;
        let displaced = path.with_extension("displaced");
        ledger
            .claim_receiving_lease(session_id, &token, Duration::from_secs(30))
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(session_id, &token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();

        let result = ledger.settle_internal_with_hook(session_id, &token, Some(&file), 1, || {
            fs::rename(&path, &displaced).unwrap();
            fs::write(&path, b"unrelated replacement").unwrap();
        });

        assert!(result.is_ok());
        assert_eq!(
            ledger.state(session_id, &token).unwrap(),
            UploadState::Uploaded
        );
        assert!(matches!(
            ledger.acknowledge_settlement(session_id),
            Err(LimitError::FileIdentityMismatch)
        ));
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), b"unrelated replacement");
        assert_eq!(fs::read(displaced).unwrap(), b"x");
    }

    #[cfg(windows)]
    #[test]
    fn settlement_pins_the_namespace_through_final_verification_and_commit() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        let session_id = reservation.session_id;
        let token = reservation.session_token;
        let path = reservation.upload_path;
        let displaced = path.with_extension("displaced");
        ledger
            .claim_receiving_lease(session_id, &token, Duration::from_secs(30))
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(session_id, &token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();

        let mut namespace_swap_succeeded = false;
        let result = ledger.settle_internal_with_hook(session_id, &token, Some(&file), 1, || {
            namespace_swap_succeeded = fs::rename(&path, &displaced).is_ok();
            if namespace_swap_succeeded {
                fs::write(&path, b"unrelated replacement").unwrap();
            }
        });

        assert!(
            result.is_ok(),
            "an open no-delete-sharing handle must pin the verified directory entry until commit"
        );
        assert!(
            !namespace_swap_succeeded,
            "the entry must not be replaceable in the final verification-to-commit interval"
        );
        assert_eq!(
            ledger.state(session_id, &token).unwrap(),
            UploadState::Uploaded
        );
        assert_eq!(fs::read(&path).unwrap(), b"x");
        assert!(!displaced.exists());
    }

    #[test]
    fn late_committed_settlement_is_idempotently_reverted() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        let session_id = reservation.session_id;
        let token = reservation.session_token;
        let path = reservation.upload_path;
        ledger
            .claim_receiving_lease(session_id, &token, Duration::from_secs(30))
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(session_id, &token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        let committed_after_deadline = std::sync::atomic::AtomicBool::new(false);
        let hook_called = &committed_after_deadline;

        let result = ledger.settle_internal_with_commit_hooks(
            session_id,
            &token,
            Some(&file),
            1,
            Instant::now() + Duration::from_millis(500),
            SettlementHooks {
                before_commit: || {},
                after_commit: || {
                    hook_called.store(true, std::sync::atomic::Ordering::SeqCst);
                    std::thread::sleep(Duration::from_millis(600));
                },
            },
        );

        assert!(committed_after_deadline.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(result, Err(LimitError::OperationTimedOut)));
        ledger
            .compensate_late_settlement(
                session_id,
                &token,
                SettlementReceipt {
                    session_id,
                    identity_id: Connection::open(&database_path)
                        .unwrap()
                        .query_row(
                            "SELECT identity_id FROM uploads WHERE id = ?1",
                            [session_id],
                            |row| row.get(0),
                        )
                        .unwrap(),
                    day: current_day_bucket(),
                    actual_bytes: 1,
                },
            )
            .unwrap();
        drop(file);

        assert_eq!(
            ledger.state(session_id, &token).unwrap(),
            UploadState::Expired
        );
        assert_eq!(ledger.reserved_bytes().unwrap(), 0);
        assert!(
            !path.exists(),
            "late settlement cleanup must remove the file"
        );
        let used: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(used_bytes), 0) FROM daily_usage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            used, 0,
            "timed-out settlement must refund actual-byte usage"
        );
    }

    #[test]
    fn late_settlement_preserves_receipt_when_first_compensation_fails() {
        let temp = tempfile::tempdir().unwrap();
        let upload_root = temp.path().join("uploads");
        let database_path = temp.path().join("ledger.sqlite3");
        fs::create_dir(&upload_root).unwrap();
        crate::auth::CapabilityStore::open(&database_path).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            test_limits(),
            vec![[0xA1; 32]],
        )
        .unwrap();
        let (reservation, _) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        let session_id = reservation.session_id;
        let token = reservation.session_token;
        let path = reservation.upload_path;
        ledger
            .claim_receiving_lease(session_id, &token, Duration::from_secs(30))
            .unwrap();
        let (mut file, _) = ledger
            .open_receiving_upload_file(session_id, &token)
            .unwrap();
        file.write_all(b"x").unwrap();
        file.flush().unwrap();
        let db = database_path.clone();
        let result = ledger.settle_internal_with_commit_hooks(
            session_id,
            &token,
            Some(&file),
            1,
            Instant::now() + Duration::from_millis(500),
            SettlementHooks {
                before_commit: || {},
                after_commit: move || {
                    Connection::open(&db)
                        .unwrap()
                        .execute(
                            "UPDATE uploads SET actual_bytes = 2 WHERE id = ?1",
                            [session_id],
                        )
                        .unwrap();
                    std::thread::sleep(Duration::from_millis(600));
                },
            },
        );

        let receipt = match result {
            Err(LimitError::LateSettlementCompensationRequired(receipt)) => receipt,
            other => panic!("expected a retained late-settlement receipt, got {other:?}"),
        };
        Connection::open(&database_path)
            .unwrap()
            .execute(
                "UPDATE uploads SET actual_bytes = 1 WHERE id = ?1",
                [session_id],
            )
            .unwrap();
        ledger
            .compensate_late_settlement(session_id, &token, receipt)
            .unwrap();
        ledger
            .compensate_late_settlement(session_id, &token, receipt)
            .unwrap();
        drop(file);

        assert_eq!(
            ledger.state(session_id, &token).unwrap(),
            UploadState::Expired
        );
        assert_eq!(ledger.reserved_bytes().unwrap(), 0);
        assert!(!path.exists());
        let used: i64 = Connection::open(&database_path)
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(used_bytes), 0) FROM daily_usage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(used, 0, "retriable compensation refunds usage exactly once");
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
