use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

use fluxform_server_probe::{LedgerLimits, LimitError, UploadLedger, UploadState};
use rusqlite::Connection;
use tempfile::TempDir;

const SECRET_A: [u8; 32] = [0xA1; 32];
const SECRET_B: [u8; 32] = [0xB2; 32];

fn limits() -> LedgerLimits {
    LedgerLimits {
        max_file_bytes: 10,
        daily_quota_bytes: 100,
        max_active_sessions_per_ip: 3,
        max_global_reserved_bytes: 100,
        disk_available_bytes: 1_000,
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
        .transition(first.session_id, UploadState::Receiving)
        .unwrap();
    old_ledger.settle(first.session_id, 4).unwrap();

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
        .transition(session.session_id, UploadState::Receiving)
        .unwrap();
    ledger.settle(session.session_id, 3).unwrap();
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
    configured.disk_available_bytes = 12;
    configured.disk_safety_margin_bytes = 5;
    let ledger = open(&temp_dir, configured, vec![SECRET_A]);

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
        .transition(session.session_id, UploadState::Receiving)
        .unwrap();

    ledger.settle(session.session_id, 5).unwrap();

    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(
        ledger.state(session.session_id).unwrap(),
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
        .transition(session.session_id, UploadState::Receiving)
        .unwrap();

    assert!(matches!(
        ledger.settle(session.session_id, 5),
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
    let handles = [first.session_id, second.session_id].map(|session_id| {
        let ledger = ledger.clone();
        let barrier = Arc::clone(&barrier);
        thread::spawn(move || {
            barrier.wait();
            ledger.expand(session_id, 8)
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
        ledger.transition(session.session_id, UploadState::Queued),
        Err(LimitError::InvalidTransition)
    ));
    ledger
        .transition(session.session_id, UploadState::Receiving)
        .unwrap();
    ledger.settle(session.session_id, 2).unwrap();
    ledger
        .transition(session.session_id, UploadState::Probing)
        .unwrap();
    ledger
        .transition(session.session_id, UploadState::Queued)
        .unwrap();
    assert!(matches!(
        ledger.transition(session.session_id, UploadState::Receiving),
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
    fs::create_dir(temp_dir.path().join("uploads")).unwrap();
    let relative = Path::new("uploads/payload.bin");
    let file_path = temp_dir.path().join(relative);
    fs::write(&file_path, b"body").unwrap();
    ledger
        .set_upload_path(session.session_id, relative)
        .unwrap();

    ledger.expire(session.session_id).unwrap();
    assert_eq!(ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(
        ledger.state(session.session_id).unwrap(),
        UploadState::Expired
    );
    assert!(file_path.exists(), "expiry must enqueue, not delete inline");
    ledger.expire(session.session_id).unwrap();
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
    let relative = Path::new("uploads/blocked");
    let blocked_path = temp_dir.path().join(relative);
    fs::create_dir_all(blocked_path.join("child")).unwrap();
    fs::write(blocked_path.join("child/file"), b"x").unwrap();
    ledger
        .set_upload_path(session.session_id, relative)
        .unwrap();
    ledger.expire(session.session_id).unwrap();

    let first = ledger.reconcile_cleanup_jobs().unwrap();
    assert_eq!(first.completed, 0);
    assert_eq!(first.retryable, 1);
    assert_eq!(cleanup_job_attempts(&temp_dir), 1);

    fs::remove_file(blocked_path.join("child/file")).unwrap();
    fs::remove_dir(blocked_path.join("child")).unwrap();
    fs::remove_dir(&blocked_path).unwrap();
    fs::write(&blocked_path, b"now removable").unwrap();
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

    assert!(matches!(
        ledger.set_upload_path(session.session_id, Path::new("../outside")),
        Err(LimitError::InvalidUploadPath)
    ));
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
        ledger.expand(session.session_id, u64::MAX),
        Err(LimitError::FileTooLarge)
    ));
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
