use std::collections::BTreeSet;
#[cfg(unix)]
use std::fs::File;
use std::io;
#[cfg(unix)]
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use thiserror::Error;

const TOKEN_BYTES: usize = 32;
const TOKEN_ENCODED_LEN: usize = 43;
const MAX_SUBJECT_BYTES: usize = 256;
const SQLITE_BUSY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);
const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

const CAPABILITY_SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS capabilities (
    token_hash BLOB PRIMARY KEY NOT NULL CHECK (length(token_hash) = 32),
    subject TEXT NOT NULL CHECK (length(subject) BETWEEN 1 AND 256),
    scopes TEXT NOT NULL CHECK (length(scopes) > 0),
    expires_at INTEGER NOT NULL CHECK (expires_at >= 0)
);
"#;

#[derive(Clone)]
pub struct CapabilityStore {
    database_path: PathBuf,
}

impl CapabilityStore {
    pub fn open(database_path: impl AsRef<Path>) -> Result<Self, CapabilityError> {
        let store = Self {
            database_path: database_path.as_ref().to_path_buf(),
        };
        let connection = store.connect()?;
        connection.execute_batch(CAPABILITY_SCHEMA)?;
        Ok(store)
    }

    fn connect(&self) -> Result<Connection, CapabilityError> {
        let connection = Connection::open(&self.database_path)?;
        connection.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        Ok(connection)
    }

    pub(crate) fn shares_database_with(&self, path: &Path) -> bool {
        match (
            std::fs::canonicalize(&self.database_path),
            std::fs::canonicalize(path),
        ) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        }
    }

    fn store(
        &self,
        token_hash: &[u8; TOKEN_BYTES],
        subject: &str,
        scopes: &BTreeSet<Scope>,
        expires_at: i64,
    ) -> Result<(), CapabilityError> {
        let scope_set = scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(",");
        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        transaction.execute(
            "INSERT INTO capabilities(token_hash, subject, scopes, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token_hash.as_slice(), subject, scope_set, expires_at],
        )?;
        transaction.commit()?;
        Ok(())
    }

    fn find(
        &self,
        token_hash: &[u8; TOKEN_BYTES],
    ) -> Result<Option<StoredCapability>, CapabilityError> {
        // Scan rows and compare fixed-size hashes in constant time in Rust.
        // Tokens are short lived and this probe deliberately favors a simple,
        // auditable comparison over a timing-sensitive hash lookup.
        let connection = self.connect()?;
        let mut statement = connection
            .prepare("SELECT token_hash, subject, scopes, expires_at FROM capabilities")?;
        let rows = statement.query_map([], |row| {
            Ok(StoredCapability {
                token_hash: row.get(0)?,
                subject: row.get(1)?,
                scopes: row.get(2)?,
                expires_at: row.get(3)?,
            })
        })?;

        let mut found = None;
        for row in rows {
            let stored = row?;
            let mut fixed_hash = [0u8; TOKEN_BYTES];
            if stored.token_hash.len() == TOKEN_BYTES {
                fixed_hash.copy_from_slice(&stored.token_hash);
            }
            let equal = constant_time_equal(&fixed_hash, token_hash)
                && stored.token_hash.len() == TOKEN_BYTES;
            if equal {
                found = Some(stored);
            }
        }
        Ok(found)
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum Scope {
    Upload,
    Status,
    Events,
    Cancel,
    Download,
}

impl Scope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Status => "status",
            Self::Events => "events",
            Self::Cancel => "cancel",
            Self::Download => "download",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "upload" => Some(Self::Upload),
            "status" => Some(Self::Status),
            "events" => Some(Self::Events),
            "cancel" => Some(Self::Cancel),
            "download" => Some(Self::Download),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct Capability {
    token: String,
    subject: String,
    scopes: BTreeSet<Scope>,
    expires_at: i64,
}

impl Capability {
    pub fn issue(
        store: &CapabilityStore,
        subject: impl Into<String>,
        scopes: impl IntoIterator<Item = Scope>,
        expires_at: SystemTime,
    ) -> Result<Self, CapabilityError> {
        let capability = Self::prepare(subject, scopes, expires_at)?;
        let token_hash = hash_presented_token(&capability.token)?;
        store.store(
            &token_hash,
            &capability.subject,
            &capability.scopes,
            capability.expires_at,
        )?;
        Ok(capability)
    }

    pub(crate) fn prepare(
        subject: impl Into<String>,
        scopes: impl IntoIterator<Item = Scope>,
        expires_at: SystemTime,
    ) -> Result<Self, CapabilityError> {
        let subject = subject.into();
        if subject.is_empty()
            || subject.len() > MAX_SUBJECT_BYTES
            || subject.chars().any(char::is_control)
        {
            return Err(CapabilityError::InvalidConfiguration);
        }
        let scopes = scopes.into_iter().collect::<BTreeSet<_>>();
        if scopes.is_empty() {
            return Err(CapabilityError::InvalidConfiguration);
        }
        let expires_at = expires_at
            .duration_since(UNIX_EPOCH)
            .map_err(|_| CapabilityError::InvalidConfiguration)?
            .as_secs();
        let expires_at =
            i64::try_from(expires_at).map_err(|_| CapabilityError::InvalidConfiguration)?;
        if expires_at <= current_unix_seconds() {
            return Err(CapabilityError::InvalidConfiguration);
        }

        let token = generate_random_token()?;
        Ok(Self {
            token,
            subject,
            scopes,
            expires_at,
        })
    }

    pub(crate) fn insert_in_transaction(
        &self,
        transaction: &Transaction<'_>,
    ) -> rusqlite::Result<()> {
        let token_hash: [u8; TOKEN_BYTES] = Sha256::digest(self.token.as_bytes()).into();
        let scope_set = self
            .scopes
            .iter()
            .map(|scope| scope.as_str())
            .collect::<Vec<_>>()
            .join(",");
        transaction.execute(
            "INSERT INTO capabilities(token_hash, subject, scopes, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token_hash.as_slice(), self.subject, scope_set, self.expires_at],
        )?;
        Ok(())
    }

    pub fn verify(
        store: &CapabilityStore,
        token: &str,
        subject: &str,
        required_scope: Scope,
    ) -> Result<(), CapabilityError> {
        decode_canonical_token(token)?;
        let token_hash = hash_presented_token(token)?;
        let stored = store
            .find(&token_hash)?
            .ok_or(CapabilityError::Unauthorized)?;
        if stored.subject != subject {
            return Err(CapabilityError::SubjectMismatch);
        }
        let scopes = parse_scope_set(&stored.scopes)?;
        if stored.expires_at <= current_unix_seconds() {
            return Err(CapabilityError::Expired);
        }
        if !scopes.contains(&required_scope) {
            return Err(CapabilityError::InsufficientScope);
        }
        Ok(())
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn subject(&self) -> &str {
        &self.subject
    }

    pub fn scopes(&self) -> &BTreeSet<Scope> {
        &self.scopes
    }

    pub fn expires_at_unix_seconds(&self) -> i64 {
        self.expires_at
    }
}

impl std::fmt::Debug for Capability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Capability")
            .field("token", &"[REDACTED]")
            .field("subject", &self.subject)
            .field("scopes", &self.scopes)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum CapabilityError {
    #[error("capability is not authorized")]
    Unauthorized,
    #[error("capability has expired")]
    Expired,
    #[error("capability does not grant the requested scope")]
    InsufficientScope,
    #[error("capability belongs to another subject")]
    SubjectMismatch,
    #[error("invalid capability configuration")]
    InvalidConfiguration,
    #[error("operating system random source failed")]
    RandomUnavailable,
    #[error("capability store is unavailable")]
    Storage(#[from] rusqlite::Error),
}

struct StoredCapability {
    token_hash: Vec<u8>,
    subject: String,
    scopes: String,
    expires_at: i64,
}

fn parse_scope_set(value: &str) -> Result<BTreeSet<Scope>, CapabilityError> {
    let scopes = value
        .split(',')
        .map(Scope::parse)
        .collect::<Option<BTreeSet<_>>>()
        .ok_or(CapabilityError::Unauthorized)?;
    if scopes.is_empty() {
        return Err(CapabilityError::Unauthorized);
    }
    Ok(scopes)
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .try_into()
        .unwrap_or(i64::MAX)
}

fn hash_presented_token(token: &str) -> Result<[u8; TOKEN_BYTES], CapabilityError> {
    decode_canonical_token(token)?;
    Ok(Sha256::digest(token.as_bytes()).into())
}

fn base64url_encode(bytes: &[u8; TOKEN_BYTES]) -> String {
    let mut encoded = String::with_capacity(TOKEN_ENCODED_LEN);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied();
        let third = chunk.get(2).copied();
        encoded.push(char::from(BASE64URL[usize::from(first >> 2)]));
        encoded.push(char::from(
            BASE64URL[usize::from((first & 0b0000_0011) << 4 | second.unwrap_or(0) >> 4)],
        ));
        if let Some(second) = second {
            encoded.push(char::from(
                BASE64URL[usize::from((second & 0b0000_1111) << 2 | third.unwrap_or(0) >> 6)],
            ));
        }
        if let Some(third) = third {
            encoded.push(char::from(BASE64URL[usize::from(third & 0b0011_1111)]));
        }
    }
    encoded
}

fn decode_canonical_token(token: &str) -> Result<[u8; TOKEN_BYTES], CapabilityError> {
    if token.len() != TOKEN_ENCODED_LEN || !token.is_ascii() {
        return Err(CapabilityError::Unauthorized);
    }
    let mut decoded = Vec::with_capacity(TOKEN_BYTES);
    let mut accumulator = 0u32;
    let mut buffered_bits = 0u32;
    for byte in token.bytes() {
        let value = BASE64URL
            .iter()
            .position(|candidate| *candidate == byte)
            .ok_or(CapabilityError::Unauthorized)?;
        accumulator = (accumulator << 6) | u32::try_from(value).unwrap_or_default();
        buffered_bits += 6;
        if buffered_bits >= 8 {
            buffered_bits -= 8;
            decoded.push((accumulator >> buffered_bits) as u8);
            accumulator &= (1 << buffered_bits) - 1;
        }
    }
    if decoded.len() != TOKEN_BYTES || buffered_bits != 2 || accumulator != 0 {
        return Err(CapabilityError::Unauthorized);
    }
    let decoded: [u8; TOKEN_BYTES] = decoded
        .try_into()
        .map_err(|_| CapabilityError::Unauthorized)?;
    if base64url_encode(&decoded) != token {
        return Err(CapabilityError::Unauthorized);
    }
    Ok(decoded)
}

pub(crate) fn is_canonical_capability_token(token: &str) -> bool {
    decode_canonical_token(token).is_ok()
}

pub(crate) fn generate_random_token() -> Result<String, CapabilityError> {
    let mut random = [0u8; TOKEN_BYTES];
    fill_os_random(&mut random).map_err(|_| CapabilityError::RandomUnavailable)?;
    Ok(base64url_encode(&random))
}

fn constant_time_equal(left: &[u8; TOKEN_BYTES], right: &[u8; TOKEN_BYTES]) -> bool {
    left.iter()
        .zip(right.iter())
        .fold(0u8, |difference, (left, right)| difference | (left ^ right))
        == 0
}

#[cfg(unix)]
fn fill_os_random(buffer: &mut [u8; TOKEN_BYTES]) -> io::Result<()> {
    File::open("/dev/urandom")?.read_exact(buffer)
}

#[cfg(windows)]
fn fill_os_random(buffer: &mut [u8; TOKEN_BYTES]) -> io::Result<()> {
    use std::ffi::c_void;

    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptGenRandom(
            algorithm_provider: *mut c_void,
            buffer: *mut u8,
            buffer_length: u32,
            flags: u32,
        ) -> i32;
    }

    const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
    // SAFETY: `buffer` is a valid writable 32-byte slice for the duration of
    // the call, and the null provider selects Windows' system RNG provider.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buffer.as_mut_ptr(),
            u32::try_from(buffer.len()).expect("32 fits in u32"),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status >= 0 {
        Ok(())
    } else {
        Err(io::Error::other("Windows system random source failed"))
    }
}

#[cfg(not(any(unix, windows)))]
fn fill_os_random(_buffer: &mut [u8; TOKEN_BYTES]) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "operating system random source is unsupported on this platform",
    ))
}
