use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fluxform_server_probe::auth::{Capability, CapabilityStore, Scope};
use fluxform_server_probe::routes::{HttpBody, ServerState, TransportPeer, router};
use fluxform_server_probe::{LedgerLimits, UploadLedger};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use hyper::{Method, Request, Response, StatusCode};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;
use tower::ServiceExt;

const PUBLIC_ORIGIN: &str = "https://flux.test";
const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

struct Harness {
    _temp: TempDir,
    database_path: PathBuf,
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
async fn completion_snapshot_capabilities_and_artifact_expire_together() {
    let lifetime = Duration::from_secs(3);
    let harness = Harness::new(lifetime);
    let expires_at = SystemTime::now() + lifetime;
    let events_token = harness.issue_until("job:job-a", Scope::Events, expires_at);
    let status_token = harness.issue_until("job:job-a", Scope::Status, expires_at);
    let download_token = harness.issue_until("artifact:artifact-a", Scope::Download, expires_at);
    harness.state.register_job("job-a", "completed").unwrap();
    let artifact_path = harness._temp.path().join("result.bin");
    std::fs::write(&artifact_path, b"result bytes").unwrap();
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
