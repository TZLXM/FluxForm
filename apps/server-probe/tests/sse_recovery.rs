use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fluxform_server_probe::auth::{Capability, CapabilityStore, Scope};
use fluxform_server_probe::events::{EventStore, EventStoreError, ReplayResult};
use fluxform_server_probe::routes::{HttpBody, ServerState, TransportPeer, router};
use fluxform_server_probe::{LedgerLimits, UploadLedger};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use rusqlite::Connection;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;

const PUBLIC_ORIGIN: &str = "https://flux.test";
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

struct Harness {
    _temp: TempDir,
    database_path: PathBuf,
    artifact_root: PathBuf,
    capabilities: CapabilityStore,
    state: ServerState,
}

impl Harness {
    fn new(capability_ttl: Duration) -> Self {
        let temp = match std::env::var_os("FLUXFORM_TEST_TEMP") {
            Some(path) => tempfile::tempdir_in(path).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let database_path = temp.path().join("server.sqlite3");
        let upload_root = temp.path().join("uploads");
        std::fs::create_dir(&upload_root).unwrap();
        let artifact_root = upload_root.join(".fluxform-artifacts");
        std::fs::create_dir(&artifact_root).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            LedgerLimits {
                max_file_bytes: 64,
                daily_quota_bytes: 256,
                max_active_sessions_per_ip: 4,
                max_global_reserved_bytes: 1024,
                disk_safety_margin_bytes: 0,
            },
            vec![[0x41; 32]],
        )
        .unwrap();
        let artifact_root = std::fs::canonicalize(artifact_root).unwrap();
        let capabilities = CapabilityStore::open(&database_path).unwrap();
        let state = ServerState::new(
            ledger,
            capabilities.clone(),
            PUBLIC_ORIGIN,
            vec![],
            capability_ttl,
        )
        .unwrap();

        Self {
            _temp: temp,
            database_path,
            artifact_root,
            capabilities,
            state,
        }
    }

    fn issue(&self, subject: &str, scope: Scope) -> String {
        Capability::issue(
            &self.capabilities,
            subject,
            [scope],
            SystemTime::now() + Duration::from_secs(1800),
        )
        .unwrap()
        .token()
        .to_owned()
    }

    fn issue_until(&self, subject: &str, scope: Scope, expires_at: SystemTime) -> String {
        Capability::issue(&self.capabilities, subject, [scope], expires_at)
            .unwrap()
            .token()
            .to_owned()
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: &str,
        headers: &[(&str, &str)],
    ) -> Response<HttpBody> {
        let request_body = Full::new(Bytes::new())
            .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
            .boxed_unsync();
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(request_body)
            .unwrap();
        request
            .extensions_mut()
            .insert(TransportPeer(SocketAddr::new(PEER, 43123)));
        request
            .headers_mut()
            .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        for (name, value) in headers {
            request.headers_mut().append(
                (*name).parse::<hyper::header::HeaderName>().unwrap(),
                (*value).parse::<hyper::header::HeaderValue>().unwrap(),
            );
        }

        router(self.state.clone()).oneshot(request).await.unwrap()
    }
}

async fn response_parts(response: Response<HttpBody>) -> (StatusCode, hyper::HeaderMap, Vec<u8>) {
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.unwrap().to_bytes().to_vec();
    (parts.status, parts.headers, bytes)
}

fn sse_event_ids(body: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|line| line.strip_prefix("id: ").map(str::to_owned))
        .collect()
}

fn error_code(body: &[u8]) -> String {
    serde_json::from_slice::<Value>(body).unwrap()["error"]["code"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn event_job_columns(connection: &Connection) -> Vec<String> {
    let mut statement = connection.prepare("PRAGMA table_info(event_jobs)").unwrap();
    statement
        .query_map([], |row| row.get::<_, String>(1))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap()
}

fn event_store(harness: &Harness) -> EventStore {
    EventStore::open(&harness.database_path, &harness.artifact_root).unwrap()
}

#[tokio::test]
async fn authorized_sse_replays_the_monotonic_suffix_and_snapshot_revision() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "queued").unwrap();
    harness.state.register_job("job-a", "running").unwrap();
    harness.state.register_job("job-a", "completed").unwrap();
    let events_token = harness.issue("job:job-a", Scope::Events);
    let status_token = harness.issue("job:job-a", Scope::Status);

    let (status, headers, body) = response_parts(
        harness
            .call(Method::GET, "/v1/jobs/job-a/events", &events_token, &[])
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers.get(CONTENT_TYPE).unwrap(),
        "text/event-stream; charset=utf-8"
    );
    assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(sse_event_ids(&body), ["1", "2", "3"]);
    assert!(String::from_utf8_lossy(&body).contains("event: job.completed"));

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/jobs/job-a/events",
                &events_token,
                &[("last-event-id", "1")],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(sse_event_ids(&body), ["2", "3"]);

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/jobs/job-a/events",
                &events_token,
                &[("last-event-id", "3")],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.is_empty());

    let (status, _, body) = response_parts(
        harness
            .call(Method::GET, "/v1/jobs/job-a", &status_token, &[])
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let snapshot: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(snapshot["revision"], 3);
    assert_eq!(snapshot["state"], "completed");
}

#[tokio::test]
async fn malformed_duplicate_and_future_event_ids_are_rejected() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "queued").unwrap();
    let events_token = harness.issue("job:job-a", Scope::Events);

    for value in ["", "+1", " 1", "01", "18446744073709551616"] {
        let (status, _, body) = response_parts(
            harness
                .call(
                    Method::GET,
                    "/v1/jobs/job-a/events",
                    &events_token,
                    &[("last-event-id", value)],
                )
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "cursor {value:?}");
        assert_eq!(
            error_code(&body),
            "invalid_last_event_id",
            "cursor {value:?}"
        );
    }

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/jobs/job-a/events",
                &events_token,
                &[("last-event-id", "1"), ("last-event-id", "1")],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&body), "invalid_last_event_id");

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/jobs/job-a/events",
                &events_token,
                &[("last-event-id", "2")],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(error_code(&body), "last_event_id_in_future");
}

#[tokio::test]
async fn stale_cursor_emits_one_resync_event_then_snapshot_matches_revision() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "queued").unwrap();
    for index in 0..130 {
        harness
            .state
            .register_job("job-a", &format!("phase-{index:03}"))
            .unwrap();
    }
    let events_token = harness.issue("job:job-a", Scope::Events);
    let status_token = harness.issue("job:job-a", Scope::Status);

    let (status, headers, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/jobs/job-a/events",
                &events_token,
                &[("last-event-id", "1")],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get("connection").unwrap(), "close");
    let event_text = String::from_utf8_lossy(&body);
    assert_eq!(event_text.matches("event:").count(), 1);
    assert!(event_text.contains("event: resync_required"));
    assert_eq!(sse_event_ids(&body), ["131"]);
    assert!(event_text.contains(r#""revision":131"#));

    let (status, _, body) = response_parts(
        harness
            .call(Method::GET, "/v1/jobs/job-a", &status_token, &[])
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let snapshot: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(snapshot["revision"], 131);
    assert_eq!(snapshot["state"], "phase-129");
}

#[tokio::test]
async fn authorized_cancellation_is_one_terminal_transition_and_starts_retention() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let connection = Connection::open(&harness.database_path).unwrap();
    let lease_until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    connection
        .execute(
            "UPDATE event_jobs SET retain_until = 0, worker_lease_until = ?1 WHERE job_id = 'job-a'",
            [i64::try_from(lease_until).unwrap()],
        )
        .unwrap();
    let cancel_token = harness.issue("job:job-a", Scope::Cancel);

    let (status, _, _) = response_parts(
        harness
            .call(
                Method::DELETE,
                "/v1/jobs/job-a",
                &cancel_token,
                &[("origin", PUBLIC_ORIGIN)],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    let cancelled = event_store(&harness).snapshot("job-a").unwrap();
    assert_eq!(cancelled.data["state"], "cancelled");

    let (status, _, _) = response_parts(
        harness
            .call(
                Method::DELETE,
                "/v1/jobs/job-a",
                &cancel_token,
                &[("origin", PUBLIC_ORIGIN)],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(
        event_store(&harness).snapshot("job-a").unwrap().revision,
        cancelled.revision
    );

    let (retain_until, worker_lease_until): (i64, i64) = connection
        .query_row(
            "SELECT retain_until, worker_lease_until FROM event_jobs WHERE job_id = 'job-a'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert!(
        retain_until > now,
        "terminal retention starts at cancellation"
    );
    assert_eq!(worker_lease_until, 0);
}

#[test]
fn legacy_artifact_rows_without_identity_are_preserved_but_never_served_or_deleted() {
    let temp = tempfile::tempdir().unwrap();
    let database_path = temp.path().join("legacy.sqlite3");
    let artifact_root = temp.path().join("artifacts");
    std::fs::create_dir(&artifact_root).unwrap();
    let legacy_path = artifact_root.join("legacy.bin");
    std::fs::write(&legacy_path, b"legacy artifact").unwrap();
    let connection = Connection::open(&database_path).unwrap();
    connection
        .execute_batch(
            "CREATE TABLE event_jobs (
                 job_id TEXT PRIMARY KEY NOT NULL,
                 revision BLOB NOT NULL,
                 snapshot_json TEXT NOT NULL,
                 retain_until INTEGER NOT NULL
             );
             CREATE TABLE job_events (
                 job_id TEXT NOT NULL,
                 revision BLOB NOT NULL,
                 event_type TEXT NOT NULL,
                 payload_json TEXT NOT NULL,
                 is_completion INTEGER NOT NULL DEFAULT 0,
                 PRIMARY KEY (job_id, revision)
             );
             CREATE TABLE event_artifacts (
                 artifact_id TEXT PRIMARY KEY NOT NULL,
                 job_id TEXT,
                 path TEXT NOT NULL,
                 filename TEXT NOT NULL,
                 content_type TEXT NOT NULL,
                 expires_at INTEGER NOT NULL
             );
             CREATE TABLE event_expiry_outbox (
                 job_id TEXT NOT NULL,
                 artifact_id TEXT NOT NULL,
                 path TEXT NOT NULL,
                 PRIMARY KEY (job_id, artifact_id)
             );
             INSERT INTO event_jobs(job_id, revision, snapshot_json, retain_until)
                 VALUES ('legacy-job', X'0000000000000001', '{\"job_id\":\"legacy-job\",\"state\":\"running\"}', unixepoch('now') + 3600);
             INSERT INTO event_artifacts(artifact_id, job_id, path, filename, content_type, expires_at)
                 VALUES ('legacy-artifact', NULL, 'legacy.bin', 'legacy.bin', 'application/octet-stream', 0);
             INSERT INTO event_expiry_outbox(job_id, artifact_id, path)
                 VALUES ('', 'legacy-artifact', 'legacy.bin');",
        )
        .unwrap();
    drop(connection);

    let store = EventStore::open(&database_path, &artifact_root).unwrap();
    assert!(matches!(
        store.snapshot("legacy-job"),
        Err(EventStoreError::Expired)
    ));
    assert!(matches!(
        store.artifact("legacy-artifact"),
        Err(EventStoreError::JobNotFound)
    ));
    assert!(matches!(
        store.read_artifact("legacy-artifact"),
        Err(EventStoreError::JobNotFound)
    ));
    store.reconcile_expired().unwrap();
    assert_eq!(
        store.snapshot("legacy-job").unwrap().data["state"],
        "failed"
    );

    assert!(
        legacy_path.exists(),
        "migration and cleanup never follow legacy paths"
    );
    let connection = Connection::open(&database_path).unwrap();
    let legacy_outbox: (i64, i64) = connection
        .query_row(
            "SELECT COUNT(*), COUNT(file_identity) FROM event_expiry_outbox \
             WHERE artifact_id = 'legacy-artifact'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(legacy_outbox, (1, 0));
    let legacy_metadata: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_artifacts WHERE artifact_id = 'legacy-artifact'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(legacy_metadata, 0, "expired metadata is retired safely");
}

#[tokio::test]
async fn completion_snapshot_capabilities_and_artifact_expire_together() {
    let lifetime = Duration::from_secs(3);
    let harness = Harness::new(lifetime);
    let expires_at = SystemTime::now() + lifetime;
    let events_token = harness.issue_until("job:job-a", Scope::Events, expires_at);
    let status_token = harness.issue_until("job:job-a", Scope::Status, expires_at);
    let download_token = harness.issue_until("artifact:artifact-a", Scope::Download, expires_at);
    harness.state.register_job("job-a", "completed").unwrap();
    let artifact_path = harness.artifact_root.join("result.bin");
    std::fs::write(&artifact_path, b"result bytes").unwrap();
    harness
        .state
        .register_job_artifact(
            "job-a",
            "artifact-a",
            PathBuf::from("result.bin"),
            "result.bin",
            "application/octet-stream",
        )
        .unwrap();

    let (status, _, event_body) = response_parts(
        harness
            .call(Method::GET, "/v1/jobs/job-a/events", &events_token, &[])
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&event_body).contains("event: job.completed"));

    let (status, _, snapshot_body) = response_parts(
        harness
            .call(Method::GET, "/v1/jobs/job-a", &status_token, &[])
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_slice::<Value>(&snapshot_body).unwrap()["state"],
        "completed"
    );

    let (status, _, artifact_body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/artifacts/artifact-a/download",
                &download_token,
                &[],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(artifact_body, b"result bytes");

    let expiry_unix = expires_at.duration_since(UNIX_EPOCH).unwrap().as_secs();
    while SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        <= expiry_unix
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    for (uri, token) in [
        ("/v1/jobs/job-a/events", &events_token),
        ("/v1/jobs/job-a", &status_token),
        ("/v1/artifacts/artifact-a/download", &download_token),
    ] {
        let (status, _, body) =
            response_parts(harness.call(Method::GET, uri, token, &[]).await).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{uri}");
        assert_eq!(error_code(&body), "capability_expired", "{uri}");
    }
    assert!(!artifact_path.exists());

    let connection = Connection::open(&harness.database_path).unwrap();
    let jobs: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_jobs WHERE job_id = 'job-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM job_events WHERE job_id = 'job-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let artifacts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_artifacts WHERE artifact_id = 'artifact-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let live_capabilities: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM capabilities WHERE subject IN ('job:job-a', 'artifact:artifact-a') \
             AND expires_at > unixepoch('now')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let pending_cleanup: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_expiry_outbox WHERE job_id = 'job-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 0);
    assert_eq!(events, 0);
    assert_eq!(artifacts, 0);
    assert_eq!(live_capabilities, 0);
    assert_eq!(pending_cleanup, 0);
}

#[test]
fn artifact_linking_requires_live_exact_scope_rows_and_never_revives_them() {
    for scenario in [
        "missing_events",
        "missing_status",
        "missing_download",
        "revoked_download",
        "expired_status",
        "wrong_subject_status",
    ] {
        let harness = Harness::new(Duration::from_secs(3600));
        harness.state.register_job("job-a", "completed").unwrap();
        if scenario == "wrong_subject_status" {
            harness.issue("job:job-b", Scope::Status);
        } else if scenario != "missing_status" {
            harness.issue("job:job-a", Scope::Status);
        }
        if scenario != "missing_events" {
            harness.issue("job:job-a", Scope::Events);
        }
        if scenario != "missing_download" {
            harness.issue("artifact:artifact-a", Scope::Download);
        }
        let connection = Connection::open(&harness.database_path).unwrap();
        if scenario == "revoked_download" {
            connection
                .execute(
                    "UPDATE capabilities SET expires_at = 0 WHERE subject = 'artifact:artifact-a'",
                    [],
                )
                .unwrap();
        }
        if scenario == "expired_status" {
            connection
                .execute(
                    "UPDATE capabilities SET expires_at = unixepoch('now') - 1 WHERE subject = 'job:job-a' AND scopes = 'status'",
                    [],
                )
                .unwrap();
        }
        let file = harness.artifact_root.join("result.bin");
        std::fs::write(&file, b"result").unwrap();

        assert!(
            harness
                .state
                .register_job_artifact(
                    "job-a",
                    "artifact-a",
                    PathBuf::from("result.bin"),
                    "result.bin",
                    "application/octet-stream",
                )
                .is_err(),
            "link must reject missing/revoked/expired scope: {scenario}"
        );
        let metadata: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM event_artifacts WHERE artifact_id = 'artifact-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(metadata, 0, "failed links are atomic");
        let revoked_expiry: Option<i64> = connection
            .query_row(
                "SELECT MAX(expires_at) FROM capabilities WHERE subject = 'artifact:artifact-a'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        if scenario == "revoked_download" {
            assert_eq!(revoked_expiry, Some(0), "revocation remains permanent");
        }
    }
}

#[test]
fn artifact_link_shortens_live_scopes_and_job_retention_to_the_common_minimum() {
    let harness = Harness::new(Duration::from_secs(3600));
    let now = SystemTime::now();
    let status_expiry = now + Duration::from_secs(300);
    let events_expiry = now + Duration::from_secs(600);
    let download_expiry = now + Duration::from_secs(900);
    harness.issue_until("job:job-a", Scope::Status, status_expiry);
    harness.issue_until("job:job-a", Scope::Events, events_expiry);
    harness.issue_until("artifact:artifact-a", Scope::Download, download_expiry);
    harness.state.register_job("job-a", "completed").unwrap();
    let file = harness.artifact_root.join("result.bin");
    std::fs::write(&file, b"result").unwrap();

    harness
        .state
        .register_job_artifact(
            "job-a",
            "artifact-a",
            PathBuf::from("result.bin"),
            "result.bin",
            "application/octet-stream",
        )
        .unwrap();

    let connection = Connection::open(&harness.database_path).unwrap();
    let expiries = [
        connection
            .query_row(
                "SELECT expires_at FROM capabilities WHERE subject = 'job:job-a' AND scopes = 'status'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        connection
            .query_row(
                "SELECT expires_at FROM capabilities WHERE subject = 'job:job-a' AND scopes = 'events'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        connection
            .query_row(
                "SELECT expires_at FROM capabilities WHERE subject = 'artifact:artifact-a' AND scopes = 'download'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        connection
            .query_row(
                "SELECT retain_until FROM event_jobs WHERE job_id = 'job-a'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        connection
            .query_row(
                "SELECT expires_at FROM event_artifacts WHERE artifact_id = 'artifact-a'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
    ];
    assert!(expiries.iter().all(|expiry| *expiry == expiries[0]));
    assert!(
        expiries[0]
            <= i64::try_from(status_expiry.duration_since(UNIX_EPOCH).unwrap().as_secs()).unwrap()
    );
}

#[test]
fn concurrent_capability_expiry_wins_over_a_waiting_artifact_link() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "completed").unwrap();
    harness.issue("job:job-a", Scope::Status);
    harness.issue("job:job-a", Scope::Events);
    harness.issue("artifact:artifact-a", Scope::Download);
    let file = harness.artifact_root.join("result.bin");
    std::fs::write(&file, b"result").unwrap();

    let mut connection = Connection::open(&harness.database_path).unwrap();
    let transaction = connection.transaction().unwrap();
    transaction
        .execute(
            "UPDATE capabilities SET expires_at = 0 WHERE subject = 'artifact:artifact-a'",
            [],
        )
        .unwrap();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let state = harness.state.clone();
    let handle = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        state.register_job_artifact(
            "job-a",
            "artifact-a",
            PathBuf::from("result.bin"),
            "result.bin",
            "application/octet-stream",
        )
    });
    started_rx.recv().unwrap();
    std::thread::sleep(Duration::from_millis(100));
    transaction.commit().unwrap();
    assert!(handle.join().unwrap().is_err());

    let expires_at: i64 = connection
        .query_row(
            "SELECT expires_at FROM capabilities WHERE subject = 'artifact:artifact-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(expires_at, 0);
}

#[tokio::test]
async fn artifact_download_refuses_a_replacement_file_after_store_reopen() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "completed").unwrap();
    harness.issue("job:job-a", Scope::Status);
    harness.issue("job:job-a", Scope::Events);
    let token = harness.issue("artifact:artifact-a", Scope::Download);
    let outside_path = harness._temp.path().join("outside-result.bin");
    std::fs::write(&outside_path, b"original bytes").unwrap();
    assert!(
        harness
            .state
            .register_job_artifact(
                "job-a",
                "artifact-a",
                &outside_path,
                "result.bin",
                "application/octet-stream",
            )
            .is_err(),
        "artifact registration must reject paths outside the pinned managed root"
    );

    let artifact_path = harness.artifact_root.join("result.bin");
    std::fs::write(&artifact_path, b"original bytes").unwrap();
    harness
        .state
        .register_job_artifact(
            "job-a",
            "artifact-a",
            &artifact_path,
            "result.bin",
            "application/octet-stream",
        )
        .unwrap();
    let moved_original = harness.artifact_root.join("moved-original.bin");
    std::fs::rename(&artifact_path, &moved_original).unwrap();
    std::fs::write(&artifact_path, b"replacement bytes").unwrap();
    assert!(event_store(&harness).read_artifact("artifact-a").is_err());

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/artifacts/artifact-a/download",
                &token,
                &[],
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        !body
            .windows(b"replacement bytes".len())
            .any(|chunk| chunk == b"replacement bytes")
    );
    Connection::open(&harness.database_path)
        .unwrap()
        .execute_batch(
            "UPDATE event_jobs SET retain_until = 0 WHERE job_id = 'job-a'; \
             UPDATE event_artifacts SET expires_at = 0 WHERE artifact_id = 'artifact-a';",
        )
        .unwrap();
    event_store(&harness).reconcile_expired().unwrap();
    assert!(
        artifact_path.exists(),
        "cleanup must not delete a replacement"
    );
    assert!(
        moved_original.exists(),
        "cleanup does not guess a renamed pathname"
    );
}

#[test]
fn full_cleanup_backlog_defers_expiry_without_partially_revoking_a_linked_artifact() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "completed").unwrap();
    harness.issue("job:job-a", Scope::Status);
    harness.issue("job:job-a", Scope::Events);
    harness.issue("artifact:artifact-a", Scope::Download);
    let artifact_path = harness.artifact_root.join("result.bin");
    std::fs::write(&artifact_path, b"still retained until cleanup intent fits").unwrap();
    harness
        .state
        .register_job_artifact(
            "job-a",
            "artifact-a",
            &artifact_path,
            "result.bin",
            "application/octet-stream",
        )
        .unwrap();

    let mut connection = Connection::open(&harness.database_path).unwrap();
    connection
        .execute_batch(
            "UPDATE event_jobs SET retain_until = 0 WHERE job_id = 'job-a'; \
             UPDATE event_artifacts SET expires_at = 0 WHERE artifact_id = 'artifact-a';",
        )
        .unwrap();
    let transaction = connection.transaction().unwrap();
    for index in 0..4096 {
        transaction
            .execute(
                "INSERT INTO event_expiry_outbox(job_id, artifact_id, path, file_identity, attempt_count, next_attempt_at) \
                 VALUES (?1, ?2, 'blocked.bin', X'01', 0, unixepoch('now') + 3600)",
                rusqlite::params![format!("block-{index}"), format!("block-{index}")],
            )
            .unwrap();
    }
    transaction.commit().unwrap();

    event_store(&harness).reconcile_expired().unwrap();

    assert!(artifact_path.exists());
    let jobs: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_jobs WHERE job_id = 'job-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let artifacts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM event_artifacts WHERE artifact_id = 'artifact-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let linked_capabilities: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM capabilities WHERE subject IN ('job:job-a', 'artifact:artifact-a') \
             AND expires_at > unixepoch('now')",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(jobs, 1);
    assert_eq!(artifacts, 1);
    assert_eq!(linked_capabilities, 3);
}

#[test]
fn artifact_registration_rejects_traversal_and_nested_paths() {
    let harness = Harness::new(Duration::from_secs(3600));
    let outside = harness._temp.path().join("secret.bin");
    std::fs::write(&outside, b"must not be linked").unwrap();
    let store = event_store(&harness);
    let expires_at = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600,
    )
    .unwrap();

    for (artifact_id, path) in [
        ("traversal", PathBuf::from("..").join("secret.bin")),
        ("nested", PathBuf::from("nested").join("result.bin")),
    ] {
        assert!(matches!(
            store.register_artifact(
                artifact_id,
                &path,
                "result.bin",
                "application/octet-stream",
                expires_at,
            ),
            Err(EventStoreError::InvalidRecord)
        ));
    }
    assert!(outside.exists());
    assert!(matches!(
        store.artifact("traversal"),
        Err(EventStoreError::JobNotFound)
    ));
}

#[test]
fn cleanup_outbox_has_bounded_retry_state_and_does_not_starve_later_artifacts() {
    let harness = Harness::new(Duration::from_secs(3600));
    let connection = Connection::open(&harness.database_path).unwrap();
    let columns = {
        let mut statement = connection
            .prepare("PRAGMA table_info(event_expiry_outbox)")
            .unwrap();
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    };
    assert!(columns.contains(&"attempt_count".to_owned()));
    assert!(columns.contains(&"next_attempt_at".to_owned()));
    assert!(columns.contains(&"file_identity".to_owned()));

    let store = event_store(&harness);
    for index in 0..40 {
        let blocker = harness
            .artifact_root
            .join(format!("blocker-{index:02}.bin"));
        let original = harness
            .artifact_root
            .join(format!("blocker-{index:02}-moved.bin"));
        std::fs::write(&blocker, b"pinned original").unwrap();
        store
            .register_artifact(
                &format!("artifact-{index:02}"),
                PathBuf::from(format!("blocker-{index:02}.bin")).as_path(),
                "blocker.bin",
                "application/octet-stream",
                0,
            )
            .unwrap();
        std::fs::rename(&blocker, &original).unwrap();
        std::fs::create_dir(&blocker).unwrap();
    }
    let later = harness.artifact_root.join("later.bin");
    std::fs::write(&later, b"delete me").unwrap();
    store
        .register_artifact(
            "artifact-later",
            PathBuf::from("later.bin").as_path(),
            "later.bin",
            "application/octet-stream",
            0,
        )
        .unwrap();

    store.reconcile_expired().unwrap();
    assert!(
        later.exists(),
        "the first bounded pass should stop at 32 rows"
    );
    connection
        .execute(
            "UPDATE event_expiry_outbox SET next_attempt_at = unixepoch('now') + 3600 \
             WHERE artifact_id != 'artifact-later'",
            [],
        )
        .unwrap();
    store.reconcile_expired().unwrap();
    assert!(
        !later.exists(),
        "the 33rd row must not be starved by 32 failures"
    );
    let attempts: i64 = connection
        .query_row(
            "SELECT MIN(attempt_count) FROM event_expiry_outbox WHERE artifact_id LIKE 'artifact-%'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(attempts >= 1);

    let recoverable = harness.artifact_root.join("blocker-00.bin");
    let original = harness.artifact_root.join("blocker-00-moved.bin");
    std::fs::remove_dir(&recoverable).unwrap();
    std::fs::rename(&original, &recoverable).unwrap();
    connection
        .execute(
            "UPDATE event_expiry_outbox SET next_attempt_at = 0 WHERE artifact_id = 'artifact-00'",
            [],
        )
        .unwrap();
    event_store(&harness).reconcile_expired().unwrap();
    assert!(
        !recoverable.exists(),
        "cleanup retry recovers after store reopen"
    );

    for index in 0..128 {
        harness
            .state
            .register_job(&format!("job-capacity-{index:03}"), "queued")
            .unwrap();
    }
    assert!(
        harness
            .state
            .register_job("job-capacity-overflow", "queued")
            .is_err(),
        "retryable outbox records do not count toward active job capacity"
    );
}

#[tokio::test]
async fn active_job_with_a_valid_worker_lease_survives_catalog_ttl() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let store = event_store(&harness);
    let connection = Connection::open(&harness.database_path).unwrap();
    assert!(
        event_job_columns(&connection).contains(&"worker_lease_until".to_owned()),
        "event_jobs must persist the worker lease"
    );
    let lease_until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    connection
        .execute(
            "UPDATE event_jobs SET retain_until = 0, worker_lease_until = ?1 WHERE job_id = 'job-a'",
            [i64::try_from(lease_until).unwrap()],
        )
        .unwrap();

    store.reconcile_expired().unwrap();

    assert_eq!(store.snapshot("job-a").unwrap().data["state"], "running");
}

#[test]
fn expired_worker_lease_cannot_append_or_be_renewed_by_state_registration() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let store = event_store(&harness);
    let connection = Connection::open(&harness.database_path).unwrap();
    let expired_lease = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
        - 1;
    connection
        .execute(
            "UPDATE event_jobs SET worker_lease_until = ?1 WHERE job_id = 'job-a'",
            [expired_lease],
        )
        .unwrap();
    let progress = json!({"job_id": "job-a", "state": "running", "progress": 1});

    assert!(matches!(
        store.append("job-a", "job.progress", &progress, &progress),
        Err(EventStoreError::Expired)
    ));
    assert!(harness.state.register_job("job-a", "running").is_err());

    store.reconcile_expired().unwrap();
    assert_eq!(store.snapshot("job-a").unwrap().data["state"], "failed");
}

#[test]
fn elapsed_worker_lease_transitions_to_failed_and_starts_terminal_retention() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let store = event_store(&harness);
    let connection = Connection::open(&harness.database_path).unwrap();
    assert!(
        event_job_columns(&connection).contains(&"worker_lease_until".to_owned()),
        "event_jobs must persist the worker lease"
    );
    connection
        .execute(
            "UPDATE event_jobs SET retain_until = 0, worker_lease_until = 0 WHERE job_id = 'job-a'",
            [],
        )
        .unwrap();

    store.reconcile_expired().unwrap();

    let snapshot = store.snapshot("job-a").unwrap();
    assert_eq!(snapshot.revision, 2);
    assert_eq!(snapshot.data["state"], "failed");
    let failure_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM job_events WHERE job_id = 'job-a' AND event_type = 'job.failed'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(failure_events, 1);
}

#[test]
fn terminal_retention_begins_when_the_job_completes_not_when_it_was_created() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let connection = Connection::open(&harness.database_path).unwrap();
    assert!(
        event_job_columns(&connection).contains(&"worker_lease_until".to_owned()),
        "event_jobs must persist the worker lease"
    );
    let lease_until = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    connection
        .execute(
            "UPDATE event_jobs SET retain_until = 0, worker_lease_until = ?1 WHERE job_id = 'job-a'",
            [i64::try_from(lease_until).unwrap()],
        )
        .unwrap();

    assert!(harness.state.register_job("job-a", "completed").is_ok());

    let terminal_until: i64 = connection
        .query_row(
            "SELECT retain_until FROM event_jobs WHERE job_id = 'job-a'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let now = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap();
    assert!(terminal_until > now);
}

#[test]
fn terminal_state_cannot_transition_back_to_running() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    harness.state.register_job("job-a", "completed").unwrap();

    assert!(harness.state.register_job("job-a", "running").is_err());
    assert_eq!(
        harness.state.job_status("job-a").as_deref(),
        Some("completed")
    );
}

#[test]
fn completion_is_pinned_once_after_the_bounded_ordinary_suffix() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let store = event_store(&harness);
    for index in 0..70 {
        let data = json!({"job_id": "job-a", "state": "running", "progress": index});
        store.append("job-a", "job.progress", &data, &data).unwrap();
    }
    harness.state.register_job("job-a", "completed").unwrap();
    let completed = json!({"job_id": "job-a", "state": "completed"});

    assert!(
        store
            .append("job-a", "job.completed", &completed, &completed)
            .is_err()
    );

    let connection = Connection::open(&harness.database_path).unwrap();
    let ordinary_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM job_events WHERE job_id = 'job-a' AND is_completion = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let completion_events: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM job_events WHERE job_id = 'job-a' AND is_completion = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ordinary_events, 64);
    assert_eq!(completion_events, 1);
}

#[test]
fn concurrent_event_appends_have_exact_revisions_and_replay_after_reopen() {
    const WRITERS: u64 = 24;
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let store = event_store(&harness);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WRITERS as usize));
    let handles = (0..WRITERS)
        .map(|index| {
            let store = store.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            std::thread::spawn(move || {
                let data = json!({"job_id": "job-a", "state": "running", "writer": index});
                barrier.wait();
                store.append("job-a", "job.progress", &data, &data).unwrap()
            })
        })
        .collect::<Vec<_>>();
    let mut revisions = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect::<Vec<_>>();
    revisions.sort_unstable();
    assert_eq!(revisions, (2..=WRITERS + 1).collect::<Vec<_>>());

    let reopened = event_store(&harness);
    let ReplayResult::Events { events, snapshot } = reopened.replay_after("job-a", 1).unwrap()
    else {
        panic!("a fresh store must replay the complete retained suffix");
    };
    assert_eq!(snapshot.revision, WRITERS + 1);
    assert_eq!(
        events
            .iter()
            .map(|event| event.revision)
            .collect::<Vec<_>>(),
        (2..=WRITERS + 1).collect::<Vec<_>>()
    );
}

#[test]
fn revision_maximum_is_appendable_once_then_overflow_fails_closed() {
    let harness = Harness::new(Duration::from_secs(3600));
    harness.state.register_job("job-a", "running").unwrap();
    let store = event_store(&harness);
    let connection = Connection::open(&harness.database_path).unwrap();
    connection
        .execute(
            "UPDATE event_jobs SET revision = ?1 WHERE job_id = 'job-a'",
            [(u64::MAX - 1).to_be_bytes().as_slice()],
        )
        .unwrap();
    let progress = json!({"job_id": "job-a", "state": "running"});

    assert_eq!(
        store
            .append("job-a", "job.progress", &progress, &progress)
            .unwrap(),
        u64::MAX
    );
    assert!(matches!(
        store.append("job-a", "job.progress", &progress, &progress),
        Err(EventStoreError::RevisionExhausted)
    ));
    assert_eq!(store.snapshot("job-a").unwrap().revision, u64::MAX);
}
