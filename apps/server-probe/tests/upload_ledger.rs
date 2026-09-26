use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use fluxform_server_probe::{
    DiskSpaceProvider, LedgerLimits, LimitError, UploadLedger, UploadState,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const SECRET_A: [u8; 32] = [0xA1; 32];
const SECRET_B: [u8; 32] = [0xB2; 32];

struct SequencedDiskSpace(Mutex<Vec<u64>>);

impl DiskSpaceProvider for SequencedDiskSpace {
    fn available_bytes(&self, _path: &Path) -> io::Result<u64> {
        let mut values = self.0.lock().unwrap();
        let value = if values.len() > 1 {
            values.remove(0)
        } else {
            *values.first().unwrap_or(&0)
        };
        Ok(value)
    }
}

fn limits() -> LedgerLimits {
    LedgerLimits {
        max_file_bytes: 10,
        daily_quota_bytes: 100,
        max_active_sessions_per_ip: 3,
        max_global_reserved_bytes: 100,
        disk_safety_margin_bytes: 100,
    }
}

fn open(temp_dir: &TempDir, limits: LedgerLimits, secrets: Vec<[u8; 32]>) -> UploadLedger {
    UploadLedger::open(
        temp_dir.path().join("ledger.sqlite3"),
        temp_dir.path(),
        limits,
        secrets,
    )
    .expect("ledger should initialize")
}

fn raw_connection(temp_dir: &TempDir) -> Connection {
    Connection::open(temp_dir.path().join("ledger.sqlite3")).expect("database should open")
}

#[test]
fn declared_sizes_reserve_the_declaration_and_missing_length_reserves_the_file_maximum() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);

    let declared = ledger.reserve("192.0.2.10", Some(4)).unwrap();
    let missing = ledger.reserve("192.0.2.11", None).unwrap();

    assert_eq!(declared.reserved_bytes, 4);
    assert_eq!(missing.reserved_bytes, 10);
    assert_eq!(ledger.reserved_bytes().unwrap(), 14);
}

#[test]
fn declared_sizes_cannot_exceed_the_per_file_maximum() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);

    assert!(matches!(
        ledger.reserve("192.0.2.10", Some(11)),
        Err(LimitError::FileTooLarge)
    ));
    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
}

#[test]
fn normalizes_ip_addresses_before_enforcing_simultaneous_sessions() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.max_active_sessions_per_ip = 1;
    let ledger = open(&temp_dir, configured, vec![SECRET_A]);

    ledger.reserve("2001:0db8:0:0:0:0:0:1", Some(1)).unwrap();
    assert!(matches!(
        ledger.reserve("2001:db8::1", Some(1)),
        Err(LimitError::SessionLimitExceeded)
    ));
    assert!(ledger.reserve("2001:db8::2", Some(1)).is_ok());
}

#[test]
fn rejects_non_ip_and_unbounded_ip_inputs() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);

    assert!(matches!(
        ledger.reserve("not-an-ip", Some(1)),
        Err(LimitError::InvalidIp)
    ));
    assert!(matches!(
        ledger.reserve(&"1".repeat(100), Some(1)),
        Err(LimitError::InvalidIp)
    ));
}

#[test]
fn daily_quota_matches_hashed_ip_across_secret_rotation() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.daily_quota_bytes = 8;
    let old_ledger = open(&temp_dir, configured, vec![SECRET_A]);

    let first = old_ledger.reserve("2001:0db8::1", Some(4)).unwrap();
    old_ledger
        .transition(
            first.session_id,
            &first.session_token,
            UploadState::Receiving,
        )
        .unwrap();
    old_ledger
        .settle(first.session_id, &first.session_token, 4)
        .unwrap();

    let rotated_ledger = open(&temp_dir, configured, vec![SECRET_B, SECRET_A]);
    rotated_ledger.reserve("2001:db8::1", Some(4)).unwrap();
    assert!(matches!(
        rotated_ledger.reserve("2001:db8::1", Some(1)),
        Err(LimitError::DailyQuotaExceeded)
    ));
}

#[test]
fn daily_quota_counts_reserved_and_settled_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.daily_quota_bytes = 7;
    let ledger = open(&temp_dir, configured, vec![SECRET_A]);

    let session = ledger.reserve("192.0.2.10", Some(5)).unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving,
        )
        .unwrap();
    ledger
        .settle(session.session_id, &session.session_token, 3)
        .unwrap();
    ledger.reserve("192.0.2.10", Some(4)).unwrap();
    assert!(matches!(
        ledger.reserve("192.0.2.10", Some(1)),
        Err(LimitError::DailyQuotaExceeded)
    ));
}

#[test]
fn enforces_the_global_reservation_limit() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.max_global_reserved_bytes = 8;
    let ledger = open(&temp_dir, configured, vec![SECRET_A]);

    ledger.reserve("192.0.2.10", Some(5)).unwrap();
    assert!(matches!(
        ledger.reserve("192.0.2.11", Some(4)),
        Err(LimitError::GlobalCapacityExceeded)
    ));
}

#[test]
fn preserves_the_configured_disk_safety_margin() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.disk_safety_margin_bytes = 5;
    let disk = Arc::new(SequencedDiskSpace(Mutex::new(vec![12, 12, 7])));
    let ledger = UploadLedger::open_with_disk_space(
        temp_dir.path().join("ledger.sqlite3"),
        temp_dir.path(),
        configured,
        vec![SECRET_A],
        disk,
    )
    .unwrap();

    ledger.reserve("192.0.2.10", Some(5)).unwrap();
    assert!(matches!(
        ledger.reserve("192.0.2.11", Some(3)),
        Err(LimitError::DiskSafetyMargin)
    ));
}

#[test]
fn settle_releases_the_reservation_and_records_only_actual_bytes() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(8)).unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving,
        )
        .unwrap();

    ledger
        .settle(session.session_id, &session.session_token, 5)
        .unwrap();

    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(
        ledger
            .state(session.session_id, &session.session_token)
            .unwrap(),
        UploadState::Uploaded
    );
    let day = current_day_bucket();
    let used: i64 = raw_connection(&temp_dir)
        .query_row(
            "SELECT used_bytes FROM daily_usage WHERE day = ?1",
            [day],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(used, 5);
}

#[test]
fn rejects_settlement_larger_than_the_current_reservation() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(4)).unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving,
        )
        .unwrap();

    assert!(matches!(
        ledger.settle(session.session_id, &session.session_token, 5),
        Err(LimitError::SettlementExceedsReservation)
    ));
    assert_eq!(ledger.reserved_bytes().unwrap(), 4);
}

#[test]
fn expands_are_serialized_so_only_one_over_capacity_race_commits() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.max_file_bytes = 10;
    configured.max_global_reserved_bytes = 10;
    let ledger = open(&temp_dir, configured, vec![SECRET_A]);
    let first = ledger.reserve("192.0.2.10", Some(2)).unwrap();
    let second = ledger.reserve("192.0.2.11", Some(2)).unwrap();

    let barrier = Arc::new(Barrier::new(3));
    let handles = [
        (first.session_id, first.session_token),
        (second.session_id, second.session_token),
    ]
    .map(|(session_id, token)| {
        let ledger = ledger.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            ledger.expand(session_id, &token, 8)
        })
    });
    barrier.wait();

    let outcomes: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(ledger.reserved_bytes().unwrap(), 10);
    let active_bytes: i64 = raw_connection(&temp_dir)
        .query_row(
            "SELECT SUM(reserved_bytes) FROM uploads WHERE state IN ('reserved', 'receiving')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(active_bytes, 10);
    assert!(active_bytes >= 0);
}

#[test]
fn rejects_illegal_transitions_and_keeps_terminal_states_terminal() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(2)).unwrap();

    assert!(matches!(
        ledger.transition(
            session.session_id,
            &session.session_token,
            UploadState::Queued
        ),
        Err(LimitError::InvalidTransition)
    ));
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving,
        )
        .unwrap();
    ledger
        .settle(session.session_id, &session.session_token, 2)
        .unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Probing,
        )
        .unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Queued,
        )
        .unwrap();
    assert!(matches!(
        ledger.transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving
        ),
        Err(LimitError::InvalidTransition)
    ));
    assert_eq!(
        UploadState::ALL.map(UploadState::as_str),
        [
            "reserved",
            "receiving",
            "uploaded",
            "probing",
            "queued",
            "expired",
            "rejected"
        ]
    );
}

#[test]
fn expiration_releases_once_and_deletion_runs_only_through_the_reconciler() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(4)).unwrap();
    let file_path = session.upload_path.clone();

    ledger
        .expire(session.session_id, &session.session_token)
        .unwrap();
    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(
        ledger
            .state(session.session_id, &session.session_token)
            .unwrap(),
        UploadState::Expired
    );
    assert!(file_path.exists(), "expiry must enqueue, not delete inline");
    ledger
        .expire(session.session_id, &session.session_token)
        .unwrap();
    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(cleanup_job_count(&temp_dir), 1);

    let report = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(report.completed, 1);
    assert_eq!(report.retryable, 0);
    assert!(!file_path.exists());
    assert_eq!(cleanup_job_count(&temp_dir), 0);
}

#[test]
fn failed_cleanup_remains_pending_and_succeeds_on_a_later_retry() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(1)).unwrap();
    let blocked_path = session.upload_path.clone();
    fs::remove_file(&blocked_path).unwrap();
    fs::create_dir_all(blocked_path.join("child")).unwrap();
    fs::write(blocked_path.join("child/file"), b"x").unwrap();
    ledger
        .expire(session.session_id, &session.session_token)
        .unwrap();

    let first = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(first.completed, 0);
    assert_eq!(first.retryable, 1);
    assert_eq!(cleanup_job_attempts(&temp_dir), 1);

    fs::remove_file(blocked_path.join("child/file")).unwrap();
    fs::remove_dir(blocked_path.join("child")).unwrap();
    fs::remove_dir(&blocked_path).unwrap();
    let second = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(second.completed, 1);
    assert_eq!(second.retryable, 0);
    assert!(!blocked_path.exists());
}

#[test]
fn rejects_cleanup_paths_that_escape_the_upload_root() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(1)).unwrap();

    let outside = temp_dir.path().join("outside");
    fs::write(&outside, b"keep").unwrap();
    ledger
        .expire(session.session_id, &session.session_token)
        .unwrap();
    raw_connection(&temp_dir)
        .execute(
            "UPDATE cleanup_outbox SET relative_path = '../outside' WHERE session_id = ?1",
            [session.session_id],
        )
        .unwrap();

    let report = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(report.retryable, 1);
    assert_eq!(fs::read(outside).unwrap(), b"keep");
}

#[test]
fn database_contains_only_ip_hashes_and_never_persists_server_secrets() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    ledger.reserve("2001:db8::abcd", Some(1)).unwrap();
    drop(ledger);

    let ip_hash: String = raw_connection(&temp_dir)
        .query_row("SELECT ip_hash FROM ip_hashes", [], |row| row.get(0))
        .unwrap();
    assert_ne!(ip_hash, "2001:db8::abcd");
    assert_eq!(ip_hash.len(), 64);

    let bytes = fs::read(temp_dir.path().join("ledger.sqlite3")).unwrap();
    assert!(!contains_bytes(&bytes, b"2001:db8::abcd"));
    assert!(!contains_bytes(&bytes, &SECRET_A));
}

#[test]
fn bounded_busy_timeout_returns_a_stable_database_busy_error() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let lock = raw_connection(&temp_dir);
    lock.execute_batch("BEGIN IMMEDIATE;").unwrap();

    let started = Instant::now();
    let result = ledger.reserve("192.0.2.10", Some(1));
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(LimitError::DatabaseBusy)));
    assert!(
        elapsed < Duration::from_secs(3),
        "lock wait must be bounded"
    );
    lock.execute_batch("ROLLBACK;").unwrap();
}

#[test]
fn rejects_values_that_cannot_be_represented_safely_by_sqlite_integers() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.max_file_bytes = u64::MAX;

    assert!(matches!(
        UploadLedger::open(
            temp_dir.path().join("ledger.sqlite3"),
            temp_dir.path(),
            configured,
            vec![SECRET_A]
        ),
        Err(LimitError::InvalidConfiguration)
    ));

    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(1)).unwrap();
    assert!(matches!(
        ledger.expand(session.session_id, &session.session_token, u64::MAX),
        Err(LimitError::FileTooLarge)
    ));
}

#[test]
fn reserve_rechecks_live_free_space_after_physical_preallocation_before_commit() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.disk_safety_margin_bytes = 100;
    let disk = Arc::new(SequencedDiskSpace(Mutex::new(vec![1_000, 99])));
    let ledger = UploadLedger::open_with_disk_space(
        temp_dir.path().join("ledger.sqlite3"),
        temp_dir.path(),
        configured,
        vec![SECRET_A],
        disk,
    )
    .unwrap();

    assert!(matches!(
        ledger.reserve("192.0.2.10", Some(4)),
        Err(LimitError::DiskSafetyMargin)
    ));
    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
    let rows: i64 = raw_connection(&temp_dir)
        .query_row("SELECT COUNT(*) FROM uploads", [], |row| row.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn reserve_observes_external_disk_consumption_since_startup() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.disk_safety_margin_bytes = 100;
    let disk = Arc::new(SequencedDiskSpace(Mutex::new(vec![1_000, 1_000, 99])));
    let ledger = UploadLedger::open_with_disk_space(
        temp_dir.path().join("ledger.sqlite3"),
        temp_dir.path(),
        configured,
        vec![SECRET_A],
        disk,
    )
    .unwrap();

    ledger.reserve("192.0.2.10", Some(4)).unwrap();
    assert!(matches!(
        ledger.reserve("192.0.2.11", Some(4)),
        Err(LimitError::DiskSafetyMargin)
    ));
    assert_eq!(ledger.reserved_bytes().unwrap(), 4);
}

#[test]
fn expand_rolls_back_when_post_allocation_space_would_violate_the_margin() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.disk_safety_margin_bytes = 5;
    let disk = Arc::new(SequencedDiskSpace(Mutex::new(vec![1_000, 1_000, 10, 4])));
    let ledger = UploadLedger::open_with_disk_space(
        temp_dir.path().join("ledger.sqlite3"),
        temp_dir.path(),
        configured,
        vec![SECRET_A],
        disk,
    )
    .unwrap();
    let session = ledger.reserve("192.0.2.10", Some(1)).unwrap();

    assert!(matches!(
        ledger.expand(session.session_id, &session.session_token, 4),
        Err(LimitError::DiskSafetyMargin)
    ));
    assert_eq!(ledger.reserved_bytes().unwrap(), 1);
    assert_eq!(fs::metadata(session.upload_path).unwrap().len(), 1);
}

#[test]
fn guessed_session_ids_cannot_mutate_another_clients_session() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let victim = ledger.reserve("192.0.2.10", Some(4)).unwrap();
    let attacker = ledger.reserve("192.0.2.11", Some(2)).unwrap();

    assert_ne!(
        victim.session_token.as_str(),
        attacker.session_token.as_str()
    );
    assert!(matches!(
        ledger.expand(victim.session_id, &attacker.session_token, 8),
        Err(LimitError::Unauthorized)
    ));
    assert!(matches!(
        ledger.transition(
            victim.session_id,
            &attacker.session_token,
            UploadState::Receiving
        ),
        Err(LimitError::Unauthorized)
    ));
    assert!(matches!(
        ledger.settle(victim.session_id, &attacker.session_token, 1),
        Err(LimitError::Unauthorized)
    ));
    assert!(matches!(
        ledger.expire(victim.session_id, &attacker.session_token),
        Err(LimitError::Unauthorized)
    ));
    assert_eq!(
        ledger
            .state(victim.session_id, &victim.session_token)
            .unwrap(),
        UploadState::Reserved
    );
    assert_eq!(ledger.reserved_bytes().unwrap(), 6);
}

#[test]
fn session_capability_is_hashed_before_it_is_persisted() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(1)).unwrap();
    let capability = session.session_token.as_str().as_bytes().to_vec();
    drop(ledger);

    let stored_hash: Vec<u8> = raw_connection(&temp_dir)
        .query_row(
            "SELECT capability_hash FROM uploads WHERE id = ?1",
            [session.session_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(stored_hash.len(), 32);
    assert_ne!(stored_hash, capability);
    let database = fs::read(temp_dir.path().join("ledger.sqlite3")).unwrap();
    assert!(!contains_bytes(&database, &capability));
}

#[test]
fn opening_a_legacy_database_applies_a_schema_versioned_migration() {
    let temp_dir = TempDir::new().unwrap();
    let db_path = temp_dir.path().join("ledger.sqlite3");
    let legacy = Connection::open(&db_path).unwrap();
    legacy
        .execute_batch(
            "CREATE TABLE global_budget(singleton INTEGER PRIMARY KEY, reserved_bytes INTEGER NOT NULL);
             CREATE TABLE ip_identities(id INTEGER PRIMARY KEY AUTOINCREMENT);
             CREATE TABLE ip_hashes(identity_id INTEGER NOT NULL, ip_hash TEXT NOT NULL UNIQUE,
                 PRIMARY KEY(identity_id, ip_hash));
             CREATE TABLE daily_usage(identity_id INTEGER NOT NULL, day INTEGER NOT NULL,
                 used_bytes INTEGER NOT NULL, PRIMARY KEY(identity_id, day));
             CREATE TABLE uploads(id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id INTEGER NOT NULL,
                 state TEXT NOT NULL, reserved_bytes INTEGER NOT NULL, actual_bytes INTEGER,
                 created_day INTEGER NOT NULL, upload_path TEXT);
             CREATE TABLE cleanup_outbox(session_id INTEGER PRIMARY KEY, relative_path TEXT NOT NULL,
                 attempts INTEGER NOT NULL DEFAULT 0);
             PRAGMA user_version = 0;",
        )
        .unwrap();
    drop(legacy);

    open(&temp_dir, limits(), vec![SECRET_A]);

    let version: i64 = raw_connection(&temp_dir)
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(
        version, 3,
        "the database needs the current committed schema version"
    );
}

#[test]
fn startup_recovers_orphaned_and_oversized_files_after_an_allocation_crash() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(4)).unwrap();
    let reservations = temp_dir.path().join(".fluxform-reservations");
    let orphan = reservations.join("crashed-before-commit.upload");
    fs::write(&orphan, [0_u8; 8]).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&session.upload_path)
        .unwrap()
        .set_len(8)
        .unwrap();
    drop(ledger);

    let reopened = open(&temp_dir, limits(), vec![SECRET_A]);

    assert_eq!(reopened.reserved_bytes().unwrap(), 4);
    assert_eq!(fs::metadata(&session.upload_path).unwrap().len(), 4);
    assert!(
        !orphan.exists(),
        "uncommitted reservation files must be reclaimed on startup"
    );
}

#[test]
fn populated_legacy_sessions_in_every_state_are_retired_and_their_files_enqueued() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let mut sessions = Vec::new();
    for index in 10..17 {
        sessions.push(
            ledger
                .reserve(&format!("192.0.2.{index}"), Some(2))
                .unwrap(),
        );
    }
    ledger
        .transition(
            sessions[1].session_id,
            &sessions[1].session_token,
            UploadState::Receiving,
        )
        .unwrap();
    for index in [2, 3, 4] {
        ledger
            .transition(
                sessions[index].session_id,
                &sessions[index].session_token,
                UploadState::Receiving,
            )
            .unwrap();
        ledger
            .settle(
                sessions[index].session_id,
                &sessions[index].session_token,
                0,
            )
            .unwrap();
    }
    ledger
        .transition(
            sessions[3].session_id,
            &sessions[3].session_token,
            UploadState::Probing,
        )
        .unwrap();
    ledger
        .transition(
            sessions[4].session_id,
            &sessions[4].session_token,
            UploadState::Probing,
        )
        .unwrap();
    ledger
        .transition(
            sessions[4].session_id,
            &sessions[4].session_token,
            UploadState::Queued,
        )
        .unwrap();
    ledger
        .expire(sessions[5].session_id, &sessions[5].session_token)
        .unwrap();
    ledger
        .transition(
            sessions[6].session_id,
            &sessions[6].session_token,
            UploadState::Rejected,
        )
        .unwrap();
    drop(ledger);

    raw_connection(&temp_dir)
        .execute_batch(
            "ALTER TABLE uploads DROP COLUMN capability_hash;
             ALTER TABLE ip_hashes DROP COLUMN key_id;
             PRAGMA user_version = 0;",
        )
        .unwrap();

    let migrated = open(&temp_dir, limits(), vec![SECRET_A]);

    for session in &sessions {
        assert_eq!(
            migrated
                .state(session.session_id, &session.session_token)
                .unwrap_err()
                .to_string(),
            "upload session capability is invalid"
        );
    }
    let states: Vec<String> = {
        let connection = raw_connection(&temp_dir);
        let mut statement = connection
            .prepare("SELECT state FROM uploads ORDER BY id")
            .unwrap();
        statement
            .query_map([], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    };
    assert_eq!(states, vec!["expired"; sessions.len()]);
    assert_eq!(cleanup_job_count(&temp_dir), sessions.len() as i64);

    let cleanup = migrated.reconcile_cleanup_jobs().unwrap();
    assert_eq!(cleanup.completed, sessions.len());
    assert!(sessions.iter().all(|session| !session.upload_path.exists()));
}

#[test]
fn populated_v0_nested_cleanup_retries_a_link_and_deletes_after_safe_restore() {
    let temp_dir = TempDir::new().unwrap();
    let upload_root = temp_dir.path().join("upload-root");
    let attacker_dir = temp_dir.path().join("attacker-target");
    fs::create_dir(&upload_root).unwrap();
    fs::create_dir(&attacker_dir).unwrap();
    let outside_payload = attacker_dir.join("payload.bin");
    fs::write(&outside_payload, b"must survive").unwrap();
    let legacy_directory = upload_root.join("uploads");
    create_directory_link(&attacker_dir, &legacy_directory);

    let db_path = temp_dir.path().join("ledger.sqlite3");
    let legacy = Connection::open(&db_path).unwrap();
    legacy
        .execute_batch(
            "CREATE TABLE global_budget(singleton INTEGER PRIMARY KEY, reserved_bytes INTEGER NOT NULL);
             INSERT INTO global_budget(singleton, reserved_bytes) VALUES (1, 0);
             CREATE TABLE ip_identities(id INTEGER PRIMARY KEY AUTOINCREMENT);
             INSERT INTO ip_identities(id) VALUES (1);
             CREATE TABLE ip_hashes(identity_id INTEGER NOT NULL, ip_hash TEXT NOT NULL UNIQUE,
                 PRIMARY KEY(identity_id, ip_hash));
             CREATE TABLE daily_usage(identity_id INTEGER NOT NULL, day INTEGER NOT NULL,
                 used_bytes INTEGER NOT NULL, PRIMARY KEY(identity_id, day));
             CREATE TABLE uploads(id INTEGER PRIMARY KEY AUTOINCREMENT, identity_id INTEGER NOT NULL,
                 state TEXT NOT NULL, reserved_bytes INTEGER NOT NULL, actual_bytes INTEGER,
                 created_day INTEGER NOT NULL, upload_path TEXT);
             CREATE TABLE cleanup_outbox(session_id INTEGER PRIMARY KEY, relative_path TEXT NOT NULL,
                 attempts INTEGER NOT NULL DEFAULT 0);
             INSERT INTO uploads(identity_id, state, reserved_bytes, actual_bytes, created_day, upload_path)
                 VALUES (1, 'uploaded', 0, 1, 0, 'uploads/payload.bin');
             PRAGMA user_version = 0;",
        )
        .unwrap();
    drop(legacy);

    let ledger = UploadLedger::open(&db_path, &upload_root, limits(), vec![SECRET_A])
        .expect("a populated authentic v0 ledger should migrate");

    let first = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(first.completed, 0);
    assert_eq!(
        first.retryable, 1,
        "a linked legacy parent must be rejected"
    );
    assert_eq!(cleanup_job_attempts_at(&db_path), 1);
    assert_eq!(fs::read(&outside_payload).unwrap(), b"must survive");

    remove_directory_link(&legacy_directory);
    fs::create_dir(&legacy_directory).unwrap();
    let in_root_payload = legacy_directory.join("payload.bin");
    fs::write(&in_root_payload, b"legacy payload").unwrap();

    let second = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(second.completed, 1);
    assert_eq!(second.retryable, 0);
    assert!(!in_root_payload.exists());
    assert_eq!(cleanup_job_count_at(&db_path), 0);
    assert_eq!(fs::read(outside_payload).unwrap(), b"must survive");
}

#[test]
fn populated_legacy_quota_is_preserved_with_an_operator_retained_key_id() {
    let temp_dir = TempDir::new().unwrap();
    let mut configured = limits();
    configured.daily_quota_bytes = 1;
    let ledger = open(&temp_dir, configured, vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(1)).unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving,
        )
        .unwrap();
    ledger
        .settle(session.session_id, &session.session_token, 1)
        .unwrap();
    drop(ledger);

    raw_connection(&temp_dir)
        .execute_batch(
            "ALTER TABLE uploads DROP COLUMN capability_hash;
             ALTER TABLE ip_hashes DROP COLUMN key_id;
             PRAGMA user_version = 0;",
        )
        .unwrap();
    let retained_key_id: [u8; 32] = Sha256::digest(SECRET_A).into();

    let migrated = UploadLedger::open_with_legacy_key_id(
        temp_dir.path().join("ledger.sqlite3"),
        temp_dir.path(),
        configured,
        vec![SECRET_B, SECRET_A],
        retained_key_id,
    )
    .expect("operator-declared retained key should preserve the v0 quota identity");

    let stored_key_id: Vec<u8> = raw_connection(&temp_dir)
        .query_row("SELECT key_id FROM ip_hashes LIMIT 1", [], |row| row.get(0))
        .unwrap();
    assert_eq!(stored_key_id, retained_key_id);
    assert!(matches!(
        migrated.reserve("192.0.2.10", Some(1)),
        Err(LimitError::DailyQuotaExceeded)
    ));
    let migrated_state: String = raw_connection(&temp_dir)
        .query_row(
            "SELECT state FROM uploads WHERE id = ?1",
            [session.session_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(migrated_state, "expired");
    assert_eq!(cleanup_job_count(&temp_dir), 1);
}

#[test]
fn previously_migrated_v2_rows_without_capabilities_are_retired() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(2)).unwrap();
    ledger
        .transition(
            session.session_id,
            &session.session_token,
            UploadState::Receiving,
        )
        .unwrap();
    ledger
        .settle(session.session_id, &session.session_token, 0)
        .unwrap();
    drop(ledger);

    raw_connection(&temp_dir)
        .execute_batch(
            "ALTER TABLE uploads DROP COLUMN capability_hash;
             ALTER TABLE uploads ADD COLUMN capability_hash BLOB
                 CHECK (capability_hash IS NULL OR length(capability_hash) = 32);
             ALTER TABLE ip_hashes DROP COLUMN key_id;
             ALTER TABLE ip_hashes ADD COLUMN key_id BLOB
                 CHECK (key_id IS NULL OR length(key_id) = 32);
             UPDATE uploads SET state = 'queued', capability_hash = NULL;
             PRAGMA user_version = 2;",
        )
        .unwrap();

    let migrated = open(&temp_dir, limits(), vec![SECRET_A]);

    let state: String = raw_connection(&temp_dir)
        .query_row(
            "SELECT state FROM uploads WHERE id = ?1",
            [session.session_id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(state, "expired");
    assert_eq!(cleanup_job_count(&temp_dir), 1);
    assert_eq!(migrated.reconcile_cleanup_jobs().unwrap().completed, 1);
    assert!(!session.upload_path.exists());
}

#[test]
fn startup_rejects_existing_reservations_above_reduced_global_limit() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    let session = ledger.reserve("192.0.2.10", Some(8)).unwrap();
    drop(ledger);

    let mut reduced = limits();
    reduced.max_global_reserved_bytes = 7;
    assert!(
        UploadLedger::open(
            temp_dir.path().join("ledger.sqlite3"),
            temp_dir.path(),
            reduced,
            vec![SECRET_A]
        )
        .is_err()
    );
    assert_eq!(
        raw_connection(&temp_dir)
            .query_row(
                "SELECT reserved_bytes FROM global_budget WHERE singleton = 1",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        8
    );
    assert_eq!(
        raw_connection(&temp_dir)
            .query_row(
                "SELECT reserved_bytes FROM uploads WHERE id = ?1",
                [session.session_id],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        8
    );
}

#[test]
fn startup_reconciles_the_global_counter_from_active_upload_rows() {
    let temp_dir = TempDir::new().unwrap();
    let ledger = open(&temp_dir, limits(), vec![SECRET_A]);
    ledger.reserve("192.0.2.10", Some(8)).unwrap();
    drop(ledger);
    raw_connection(&temp_dir)
        .execute(
            "UPDATE global_budget SET reserved_bytes = 3 WHERE singleton = 1",
            [],
        )
        .unwrap();

    let reopened = open(&temp_dir, limits(), vec![SECRET_A]);

    assert_eq!(reopened.reserved_bytes().unwrap(), 8);
}

#[test]
fn secret_rotation_refuses_to_drop_keys_needed_by_active_or_daily_identities() {
    let temp_dir = TempDir::new().unwrap();
    let old = open(&temp_dir, limits(), vec![SECRET_A]);
    let active = old.reserve("192.0.2.10", Some(2)).unwrap();

    assert!(
        UploadLedger::open(
            temp_dir.path().join("ledger.sqlite3"),
            temp_dir.path(),
            limits(),
            vec![SECRET_B]
        )
        .is_err()
    );

    old.transition(
        active.session_id,
        &active.session_token,
        UploadState::Receiving,
    )
    .unwrap();
    old.settle(active.session_id, &active.session_token, 1)
        .unwrap();
    drop(old);
    assert!(
        UploadLedger::open(
            temp_dir.path().join("ledger.sqlite3"),
            temp_dir.path(),
            limits(),
            vec![SECRET_B]
        )
        .is_err()
    );

    let overlapping = open(&temp_dir, limits(), vec![SECRET_B, SECRET_A]);
    overlapping.reserve("192.0.2.10", Some(1)).unwrap();
    drop(overlapping);
    assert!(
        UploadLedger::open(
            temp_dir.path().join("ledger.sqlite3"),
            temp_dir.path(),
            limits(),
            vec![SECRET_B]
        )
        .is_ok()
    );
}

fn current_day_bucket() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    (SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        / 86_400) as i64
}

fn cleanup_job_count(temp_dir: &TempDir) -> i64 {
    raw_connection(temp_dir)
        .query_row("SELECT COUNT(*) FROM cleanup_outbox", [], |row| row.get(0))
        .unwrap()
}

fn cleanup_job_count_at(db_path: &Path) -> i64 {
    Connection::open(db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM cleanup_outbox", [], |row| row.get(0))
        .unwrap()
}

fn cleanup_job_attempts_at(db_path: &Path) -> i64 {
    Connection::open(db_path)
        .unwrap()
        .query_row("SELECT attempts FROM cleanup_outbox", [], |row| row.get(0))
        .unwrap()
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

#[cfg(unix)]
fn remove_directory_link(link: &Path) {
    fs::remove_file(link).unwrap();
}

#[cfg(windows)]
fn remove_directory_link(link: &Path) {
    fs::remove_dir(link).unwrap();
}

fn cleanup_job_attempts(temp_dir: &TempDir) -> i64 {
    raw_connection(temp_dir)
        .query_row("SELECT attempts FROM cleanup_outbox", [], |row| row.get(0))
        .unwrap()
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
