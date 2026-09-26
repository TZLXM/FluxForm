use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fluxform_server_probe::auth::{Capability, CapabilityStore, Scope};
use fluxform_server_probe::routes::{HttpBody, ServerState, TransportPeer, router};
use fluxform_server_probe::{LedgerLimits, SessionToken, UploadLedger, UploadState};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, ORIGIN};
use hyper::{Method, Request, Response, StatusCode};
use rusqlite::{Connection, params};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;

const PUBLIC_ORIGIN: &str = "https://flux.test";
const DEFAULT_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

struct Harness {
    _temp: TempDir,
    database_path: PathBuf,
    ledger: UploadLedger,
    capabilities: CapabilityStore,
    state: ServerState,
}

impl Harness {
    fn new(max_sessions_per_ip: u32, trusted_proxies: Vec<String>) -> Self {
        Self::new_with_ttl(
            max_sessions_per_ip,
            trusted_proxies,
            Duration::from_secs(3600),
        )
    }

    fn new_with_ttl(
        max_sessions_per_ip: u32,
        trusted_proxies: Vec<String>,
        capability_ttl: Duration,
    ) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let database_path = temp.path().join("server.sqlite3");
        let upload_root = temp.path().join("uploads");
        std::fs::create_dir(&upload_root).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            LedgerLimits {
                max_file_bytes: 64,
                daily_quota_bytes: 256,
                max_active_sessions_per_ip: max_sessions_per_ip,
                max_global_reserved_bytes: 1024,
                disk_safety_margin_bytes: 0,
            },
            vec![[0x41; 32]],
        )
        .unwrap();
        let capabilities = CapabilityStore::open(&database_path).unwrap();
        let state = ServerState::new(
            ledger.clone(),
            capabilities.clone(),
            PUBLIC_ORIGIN,
            trusted_proxies,
            capability_ttl,
        )
        .unwrap();

        Self {
            _temp: temp,
            database_path,
            ledger,
            capabilities,
            state,
        }
    }

    fn issue(&self, subject: &str, scope: Scope) -> Capability {
        Capability::issue(
            &self.capabilities,
            subject,
            [scope],
            SystemTime::now() + Duration::from_secs(1800),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)] // Keeps each in-process request fully explicit.
    async fn call(
        &self,
        method: Method,
        uri: &str,
        token: Option<&str>,
        origin: Option<&str>,
        peer: IpAddr,
        extra_headers: &[(&str, &str)],
        body: &str,
    ) -> Response<HttpBody> {
        let request_body = Full::new(Bytes::copy_from_slice(body.as_bytes()))
            .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} })
            .boxed_unsync();
        let mut request = Request::builder()
            .method(method)
            .uri(uri)
            .body(request_body)
            .unwrap();
        request
            .extensions_mut()
            .insert(TransportPeer(SocketAddr::new(peer, 43123)));
        if let Some(token) = token {
            request
                .headers_mut()
                .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
        }
        if let Some(origin) = origin {
            request
                .headers_mut()
                .insert(ORIGIN, origin.parse().unwrap());
        }
        for (name, value) in extra_headers {
            request.headers_mut().append(
                (*name).parse::<hyper::header::HeaderName>().unwrap(),
                (*value).parse::<hyper::header::HeaderValue>().unwrap(),
            );
        }

        router(self.state.clone()).oneshot(request).await.unwrap()
    }

    async fn create_upload(&self, peer: IpAddr) -> (i64, String) {
        let (status, _, body) = response_parts(
            self.call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                peer,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "{}",
            String::from_utf8_lossy(&body)
        );
        let response: Value = serde_json::from_slice(&body).unwrap();
        (
            response["session_id"].as_i64().unwrap(),
            response["capability"].as_str().unwrap().to_owned(),
        )
    }

    fn force_expired(&self, token: &str) {
        let connection = Connection::open(&self.database_path).unwrap();
        let token_hash = Sha256::digest(token.as_bytes());
        let changed = connection
            .execute(
                "UPDATE capabilities SET expires_at = 0 WHERE token_hash = ?1",
                params![token_hash.as_slice()],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }

    fn upload_count(&self) -> i64 {
        Connection::open(&self.database_path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM uploads", [], |row| row.get(0))
            .unwrap()
    }

    fn active_upload_count(&self) -> i64 {
        Connection::open(&self.database_path)
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM uploads WHERE state IN ('reserved', 'receiving', 'uploaded', 'probing', 'queued')",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn capability_count(&self) -> i64 {
        Connection::open(&self.database_path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM capabilities", [], |row| row.get(0))
            .unwrap()
    }

    fn reservation_file_count(&self) -> usize {
        std::fs::read_dir(self._temp.path().join("uploads/.fluxform-reservations"))
            .unwrap()
            .count()
    }

    fn inject_sql(&self, sql: &str) {
        Connection::open(&self.database_path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
    }
}

struct PollCountingBody {
    polls: Arc<AtomicUsize>,
    yielded: bool,
}

impl Body for PollCountingBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        if this.yielded {
            Poll::Ready(None)
        } else {
            this.yielded = true;
            Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"data")))))
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Endpoint {
    Upload,
    Status,
    Events,
    Cancel,
    Download,
}

#[derive(Clone, Copy, Debug)]
enum CredentialCase {
    Valid,
    Absent,
    Expired,
    WrongScope,
    CrossSubject,
}

impl Endpoint {
    const ALL: [Self; 5] = [
        Self::Upload,
        Self::Status,
        Self::Events,
        Self::Cancel,
        Self::Download,
    ];

    const CASES: [CredentialCase; 5] = [
        CredentialCase::Valid,
        CredentialCase::Absent,
        CredentialCase::Expired,
        CredentialCase::WrongScope,
        CredentialCase::CrossSubject,
    ];

    fn scope(self) -> Scope {
        match self {
            Self::Upload => Scope::Upload,
            Self::Status => Scope::Status,
            Self::Events => Scope::Events,
            Self::Cancel => Scope::Cancel,
            Self::Download => Scope::Download,
        }
    }

    fn subject(self, id: &str) -> String {
        match self {
            Self::Upload => format!("upload-session:{id}"),
            Self::Status | Self::Events | Self::Cancel => format!("job:{id}"),
            Self::Download => format!("artifact:{id}"),
        }
    }

    fn method(self) -> Method {
        match self {
            Self::Upload => Method::PUT,
            Self::Status | Self::Events | Self::Download => Method::GET,
            Self::Cancel => Method::DELETE,
        }
    }

    fn path(self, id: &str) -> String {
        match self {
            Self::Upload => format!("/v1/upload-sessions/{id}/content"),
            Self::Status => format!("/v1/jobs/{id}"),
            Self::Events => format!("/v1/jobs/{id}/events"),
            Self::Cancel => format!("/v1/jobs/{id}"),
            Self::Download => format!("/v1/artifacts/{id}/download"),
        }
    }

    fn allowed_status(self) -> StatusCode {
        match self {
            Self::Upload => StatusCode::NO_CONTENT,
            Self::Status | Self::Events | Self::Download => StatusCode::OK,
            Self::Cancel => StatusCode::ACCEPTED,
        }
    }
}

#[tokio::test]
async fn every_protected_route_enforces_scope_subject_and_expiration() {
    for endpoint in Endpoint::ALL {
        for case in Endpoint::CASES {
            let harness = Harness::new(8, vec!["192.0.2.0/24".to_owned()]);
            let (id, upload_capability) = match endpoint {
                Endpoint::Upload => {
                    let (session_id, token) = harness.create_upload(DEFAULT_PEER).await;
                    (session_id.to_string(), Some(token))
                }
                Endpoint::Status | Endpoint::Events | Endpoint::Cancel => {
                    harness.state.register_job("job-a", "queued").unwrap();
                    harness.state.register_job("job-b", "queued").unwrap();
                    ("job-a".to_owned(), None)
                }
                Endpoint::Download => {
                    let first = harness._temp.path().join("first.bin");
                    let second = harness._temp.path().join("second.bin");
                    std::fs::write(&first, b"first artifact").unwrap();
                    std::fs::write(&second, b"second artifact").unwrap();
                    harness
                        .state
                        .register_artifact(
                            "artifact-a",
                            &first,
                            "first.bin",
                            "application/octet-stream",
                        )
                        .unwrap();
                    harness
                        .state
                        .register_artifact(
                            "artifact-b",
                            &second,
                            "second.bin",
                            "application/octet-stream",
                        )
                        .unwrap();
                    ("artifact-a".to_owned(), None)
                }
            };
            let subject = endpoint.subject(&id);
            let valid = upload_capability
                .unwrap_or_else(|| harness.issue(&subject, endpoint.scope()).token().to_owned());

            let presented = match case {
                CredentialCase::Valid => Some(valid.clone()),
                CredentialCase::Absent => None,
                CredentialCase::Expired => {
                    harness.force_expired(&valid);
                    Some(valid.clone())
                }
                CredentialCase::WrongScope => {
                    let other_scope = match endpoint.scope() {
                        Scope::Upload => Scope::Status,
                        _ => Scope::Upload,
                    };
                    Some(harness.issue(&subject, other_scope).token().to_owned())
                }
                CredentialCase::CrossSubject => {
                    let other_id = match endpoint {
                        Endpoint::Upload => harness.create_upload(DEFAULT_PEER).await.0.to_string(),
                        Endpoint::Status | Endpoint::Events | Endpoint::Cancel => {
                            "job-b".to_owned()
                        }
                        Endpoint::Download => "artifact-b".to_owned(),
                    };
                    let other_subject = endpoint.subject(&other_id);
                    Some(
                        harness
                            .issue(&other_subject, endpoint.scope())
                            .token()
                            .to_owned(),
                    )
                }
            };

            let (status, headers, body) = response_parts(
                harness
                    .call(
                        endpoint.method(),
                        &endpoint.path(&id),
                        presented.as_deref(),
                        matches!(endpoint.method(), Method::PUT | Method::DELETE)
                            .then_some(PUBLIC_ORIGIN),
                        DEFAULT_PEER,
                        &[],
                        "payload",
                    )
                    .await,
            )
            .await;

            match case {
                CredentialCase::Valid => {
                    assert_eq!(status, endpoint.allowed_status(), "{endpoint:?}");
                    assert!(headers.get("referrer-policy").is_some(), "{endpoint:?}");
                    if matches!(endpoint, Endpoint::Events) {
                        assert!(String::from_utf8_lossy(&body).contains("event:"));
                    }
                }
                CredentialCase::Absent => {
                    assert_eq!(status, StatusCode::UNAUTHORIZED, "{endpoint:?}");
                    assert_error_code(&body, "unauthorized");
                }
                CredentialCase::Expired => {
                    assert_eq!(status, StatusCode::UNAUTHORIZED, "{endpoint:?}");
                    assert_error_code(&body, "capability_expired");
                }
                CredentialCase::WrongScope => {
                    assert_eq!(status, StatusCode::FORBIDDEN, "{endpoint:?}");
                    assert_error_code(&body, "insufficient_scope");
                }
                CredentialCase::CrossSubject => {
                    assert_eq!(status, StatusCode::FORBIDDEN, "{endpoint:?}");
                    assert_error_code(&body, "capability_subject_mismatch");
                }
            }
        }
    }
}

#[tokio::test]
async fn bootstrap_returns_one_hashed_capability_and_upload_content_uses_it() {
    let harness = Harness::new(8, vec![]);
    let response = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            DEFAULT_PEER,
            &[],
            r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    let (status, _, body) = response_parts(response).await;
    assert_eq!(status, StatusCode::CREATED);
    let body_text = String::from_utf8(body).unwrap();
    let response: Value = serde_json::from_str(&body_text).unwrap();
    let session_id = response["session_id"].as_i64().unwrap();
    let token = response["capability"].as_str().unwrap();
    assert_eq!(
        token.len(),
        43,
        "32 bytes encode to 43 unpadded base64url chars"
    );
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    );
    assert_eq!(body_text.matches(token).count(), 1);

    let db = Connection::open(&harness.database_path).unwrap();
    let (stored_hash, subject, scopes, expires_at): (Vec<u8>, String, String, i64) = db
        .query_row(
            "SELECT token_hash, subject, scopes, expires_at FROM capabilities",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .unwrap();
    assert_eq!(stored_hash, Sha256::digest(token.as_bytes()).as_slice());
    assert_eq!(subject, format!("upload-session:{session_id}"));
    assert_eq!(scopes, "upload");
    assert!(expires_at > i64::try_from(now_unix_seconds()).unwrap());
    assert!(
        !std::fs::read(&harness.database_path)
            .unwrap()
            .windows(token.len())
            .any(|window| window == token.as_bytes())
    );

    let body_polls = Arc::new(AtomicUsize::new(0));
    let request_body = PollCountingBody {
        polls: Arc::clone(&body_polls),
        yielded: false,
    }
    .map_err(|error| -> Box<dyn Error + Send + Sync> { Box::new(error) })
    .boxed_unsync();
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/v1/upload-sessions/{session_id}/content"))
        .body(request_body)
        .unwrap();
    request
        .extensions_mut()
        .insert(TransportPeer(SocketAddr::new(DEFAULT_PEER, 43123)));
    request
        .headers_mut()
        .insert(AUTHORIZATION, format!("Bearer {token}").parse().unwrap());
    request
        .headers_mut()
        .insert(ORIGIN, PUBLIC_ORIGIN.parse().unwrap());
    let upload = router(harness.state.clone())
        .oneshot(request)
        .await
        .unwrap();
    let (status, _, response_body) = response_parts(upload).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(response_body.is_empty());
    assert_eq!(body_polls.load(Ordering::SeqCst), 2);
    let token = SessionToken::parse(token).unwrap();
    assert_eq!(
        harness.ledger.state(session_id, &token).unwrap(),
        UploadState::Uploaded
    );
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
}

#[tokio::test]
async fn capability_insert_failure_rolls_back_even_if_legacy_cleanup_would_fail() {
    let harness = Harness::new(8, vec![]);
    harness.inject_sql(
        "CREATE TRIGGER task11_fail_capability_insert BEFORE INSERT ON capabilities \
         BEGIN SELECT RAISE(ABORT, 'injected capability insert failure'); END; \
         CREATE TRIGGER task11_fail_expiration BEFORE UPDATE ON uploads \
         WHEN NEW.state = 'expired' \
         BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;",
    );

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_code(&body, "storage_unavailable");
    assert_eq!(harness.active_upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(harness.capability_count(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[tokio::test]
async fn capability_hash_rebind_failure_rolls_back_without_compensation() {
    let harness = Harness::new(8, vec![]);
    harness.inject_sql(
        "CREATE TRIGGER task11_fail_capability_hash_rebind \
         BEFORE UPDATE OF capability_hash ON uploads \
         WHEN NEW.capability_hash != OLD.capability_hash \
         BEGIN SELECT RAISE(ABORT, 'injected capability hash rebind failure'); END; \
         CREATE TRIGGER task11_fail_capability_delete BEFORE DELETE ON capabilities \
         BEGIN SELECT RAISE(ABORT, 'injected capability revoke failure'); END; \
         CREATE TRIGGER task11_fail_expiration BEFORE UPDATE ON uploads \
         WHEN NEW.state = 'expired' \
         BEGIN SELECT RAISE(ABORT, 'injected cleanup failure'); END;",
    );

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_code(&body, "storage_unavailable");
    assert_eq!(harness.active_upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(harness.capability_count(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[tokio::test]
async fn upload_insert_failure_rolls_back_file_and_accounting_state() {
    let harness = Harness::new(8, vec![]);
    harness.inject_sql(
        "CREATE TRIGGER task11_fail_upload_insert BEFORE INSERT ON uploads \
         BEGIN SELECT RAISE(ABORT, 'injected upload insert failure'); END;",
    );

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_code(&body, "storage_unavailable");
    assert_eq!(harness.active_upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(harness.capability_count(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[tokio::test]
async fn global_quota_write_failure_rolls_back_upload_and_capability_together() {
    let harness = Harness::new(8, vec![]);
    harness.inject_sql(
        "CREATE TRIGGER task11_fail_global_budget BEFORE UPDATE ON global_budget \
         BEGIN SELECT RAISE(ABORT, 'injected global budget write failure'); END;",
    );

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_code(&body, "storage_unavailable");
    assert_eq!(harness.active_upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(harness.capability_count(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[tokio::test]
async fn deferred_commit_failure_rolls_back_upload_and_capability_together() {
    let harness = Harness::new(8, vec![]);
    harness.inject_sql(
        "CREATE TABLE task11_commit_parent (id INTEGER PRIMARY KEY); \
         CREATE TABLE task11_commit_child (parent_id INTEGER NOT NULL \
         REFERENCES task11_commit_parent(id) DEFERRABLE INITIALLY DEFERRED); \
         CREATE TRIGGER task11_fail_deferred_commit AFTER UPDATE ON global_budget \
         BEGIN INSERT INTO task11_commit_child(parent_id) VALUES (-1); END;",
    );

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_code(&body, "storage_unavailable");
    assert_eq!(harness.active_upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(harness.capability_count(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[tokio::test]
async fn capability_expiry_overflow_is_rejected_before_reservation() {
    let harness = Harness::new_with_ttl(8, vec![], Duration::MAX);

    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_code(&body, "storage_unavailable");
    assert_eq!(harness.active_upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
    assert_eq!(harness.capability_count(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[test]
fn server_state_rejects_ledger_and_capability_stores_with_different_databases() {
    let harness = Harness::new(8, vec![]);
    let other_store = CapabilityStore::open(harness._temp.path().join("other.sqlite3")).unwrap();

    let result = ServerState::new(
        harness.ledger.clone(),
        other_store,
        PUBLIC_ORIGIN,
        vec![],
        Duration::from_secs(3600),
    );

    assert!(
        result.is_err(),
        "atomic bootstrap requires one canonical database"
    );
}

#[tokio::test]
async fn state_changing_routes_require_an_exact_origin() {
    let origins = [
        ("allowed", Some(PUBLIC_ORIGIN), true),
        ("absent", None, false),
        ("null", Some("null"), false),
        ("malformed", Some("https://flux.test/"), false),
        ("cross-origin", Some("https://other.test"), false),
    ];

    for method in [Method::POST, Method::PUT, Method::DELETE] {
        for (label, origin, allowed) in origins {
            let harness = Harness::new(8, vec![]);
            let (path, token, before_state) = match method {
                Method::POST => ("/v1/upload-sessions".to_owned(), None, None),
                Method::PUT => {
                    let (session_id, token) = harness.create_upload(DEFAULT_PEER).await;
                    let old_state = harness
                        .ledger
                        .state(session_id, &SessionToken::parse(&token).unwrap())
                        .unwrap();
                    (
                        format!("/v1/upload-sessions/{session_id}/content"),
                        Some(token),
                        Some((session_id, old_state)),
                    )
                }
                Method::DELETE => {
                    harness.state.register_job("job-a", "queued").unwrap();
                    let token = harness.issue("job:job-a", Scope::Cancel).token().to_owned();
                    ("/v1/jobs/job-a".to_owned(), Some(token), None)
                }
                _ => unreachable!(),
            };
            let body = if matches!(method, Method::POST) {
                r#"{"declared_bytes":4,"output_target":{"type":"managed_artifact"}}"#
            } else {
                "payload"
            };
            let (status, _, response_body) = response_parts(
                harness
                    .call(
                        method.clone(),
                        &path,
                        token.as_deref(),
                        origin,
                        DEFAULT_PEER,
                        &[],
                        body,
                    )
                    .await,
            )
            .await;

            if allowed {
                assert_ne!(status, StatusCode::FORBIDDEN, "{method} {label}");
                if method == Method::PUT {
                    assert_eq!(status, StatusCode::NO_CONTENT, "{label}");
                }
            } else {
                assert_eq!(status, StatusCode::FORBIDDEN, "{method} {label}");
                assert_error_code(&response_body, "origin_denied");
            }

            match method {
                Method::POST => assert_eq!(harness.upload_count(), i64::from(allowed), "{label}"),
                Method::PUT => {
                    let (session_id, initial_state) = before_state.unwrap();
                    let current = harness
                        .ledger
                        .state(
                            session_id,
                            &SessionToken::parse(token.as_deref().unwrap()).unwrap(),
                        )
                        .unwrap();
                    assert_eq!(
                        current,
                        if allowed {
                            UploadState::Uploaded
                        } else {
                            initial_state
                        },
                        "{label}"
                    );
                }
                Method::DELETE => {
                    assert_eq!(
                        harness.state.job_status("job-a").unwrap(),
                        if allowed { "cancelled" } else { "queued" },
                        "{label}"
                    );
                }
                _ => unreachable!(),
            }
        }
    }
}

#[tokio::test]
async fn local_output_targets_are_rejected_before_upload_creation() {
    let harness = Harness::new(8, vec![]);
    let (status, _, body) = response_parts(
        harness
            .call(
                Method::POST,
                "/v1/upload-sessions",
                None,
                Some(PUBLIC_ORIGIN),
                DEFAULT_PEER,
                &[],
                r#"{"declared_bytes":4,"output_target":{"type":"local_path","path":"C:\\private\\result.mp4"}}"#,
            )
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_code(&body, "managed_artifact_only");
    assert_eq!(harness.upload_count(), 0);
    assert_eq!(harness.ledger.reserved_bytes().unwrap(), 0);
}

#[tokio::test]
async fn bearer_tokens_are_rejected_in_paths_and_queries() {
    let harness = Harness::new(8, vec![]);
    harness.state.register_job("job-a", "queued").unwrap();
    let token = harness.issue("job:job-a", Scope::Status).token().to_owned();

    for uri in [
        format!("/v1/jobs/{token}"),
        format!("/v1/jobs/job-a?token={token}"),
        format!("/v1/jobs/job-a?x={token}"),
    ] {
        let (status, _, body) = response_parts(
            harness
                .call(Method::GET, &uri, Some(&token), None, DEFAULT_PEER, &[], "")
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{uri}");
        assert_error_code(&body, "credential_in_url");
    }
}

#[tokio::test]
async fn artifact_download_returns_the_registered_file_with_secure_headers() {
    let harness = Harness::new(8, vec![]);
    let artifact_path = harness._temp.path().join("result.bin");
    std::fs::write(&artifact_path, b"download bytes").unwrap();
    harness
        .state
        .register_artifact(
            "artifact-one",
            &artifact_path,
            "result.bin",
            "application/octet-stream",
        )
        .unwrap();
    let token = harness
        .issue("artifact:artifact-one", Scope::Download)
        .token()
        .to_owned();

    let (status, headers, body) = response_parts(
        harness
            .call(
                Method::GET,
                "/v1/artifacts/artifact-one/download",
                Some(&token),
                None,
                DEFAULT_PEER,
                &[],
                "",
            )
            .await,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"download bytes");
    assert_eq!(
        headers.get(CONTENT_DISPOSITION).unwrap(),
        "attachment; filename=\"result.bin\""
    );
    assert_eq!(headers.get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
    assert_eq!(
        headers.get(CONTENT_TYPE).unwrap(),
        "application/octet-stream"
    );
}

#[tokio::test]
async fn quota_identity_ignores_forwarding_from_an_untrusted_peer() {
    let harness = Harness::new(1, vec!["192.0.2.0/24".to_owned()]);
    let forwarded = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            DEFAULT_PEER,
            &[("x-forwarded-for", "198.51.100.50")],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(forwarded.status(), StatusCode::CREATED);

    let same_peer = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            DEFAULT_PEER,
            &[],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(same_peer.status(), StatusCode::TOO_MANY_REQUESTS);

    let claimed_client = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            "198.51.100.50".parse().unwrap(),
            &[],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(claimed_client.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn trusted_proxy_uses_the_nearest_untrusted_address_in_a_bounded_chain() {
    let harness = Harness::new(
        1,
        vec!["192.0.2.0/24".to_owned(), "203.0.113.0/24".to_owned()],
    );
    let through_proxy = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            "192.0.2.8".parse().unwrap(),
            &[("forwarded", "for=198.51.100.7, for=203.0.113.9")],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(through_proxy.status(), StatusCode::CREATED);

    let direct_client = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            "198.51.100.7".parse().unwrap(),
            &[],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(direct_client.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[test]
fn trusted_proxy_cidr_configuration_is_bounded() {
    let harness = Harness::new(8, vec![]);
    let too_many_cidrs = vec!["192.0.2.0/24".to_owned(); 65];

    let result = ServerState::new(
        harness.ledger.clone(),
        harness.capabilities.clone(),
        PUBLIC_ORIGIN,
        too_many_cidrs,
        Duration::from_secs(3600),
    );

    assert!(result.is_err(), "trusted proxy CIDR count must be bounded");
}

#[tokio::test]
async fn trusted_ipv6_proxy_cidr_applies_the_same_quota_identity_policy() {
    let harness = Harness::new(1, vec!["2001:db8::/32".to_owned()]);
    let client = "2001:db9::7".parse().unwrap();
    let through_proxy = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            "2001:db8::a".parse().unwrap(),
            &[("x-forwarded-for", "2001:db9::7")],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(through_proxy.status(), StatusCode::CREATED);

    let direct_client = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            client,
            &[],
            r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
        )
        .await;
    assert_eq!(direct_client.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn trusted_forwarding_rejects_ambiguous_malformed_and_oversized_chains_before_quota() {
    for (headers, expected_code) in [
        (
            vec![
                ("forwarded", "for=198.51.100.7"),
                ("x-forwarded-for", "198.51.100.7"),
            ],
            "invalid_forwarded_chain",
        ),
        (
            vec![("x-forwarded-for", "198.51.100.7,,203.0.113.9")],
            "invalid_forwarded_chain",
        ),
        (
            vec![("forwarded", "for=_hidden")],
            "invalid_forwarded_chain",
        ),
        (
            vec![(
                "x-forwarded-for",
                "198.51.100.1,198.51.100.2,198.51.100.3,198.51.100.4,198.51.100.5,198.51.100.6,198.51.100.7,198.51.100.8,198.51.100.9",
            )],
            "forwarded_chain_too_long",
        ),
    ] {
        let harness = Harness::new(8, vec!["192.0.2.0/24".to_owned()]);
        let (status, _, body) = response_parts(
            harness
                .call(
                    Method::POST,
                    "/v1/upload-sessions",
                    None,
                    Some(PUBLIC_ORIGIN),
                    "192.0.2.10".parse().unwrap(),
                    &headers,
                    r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
                )
                .await,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_error_code(&body, expected_code);
        assert_eq!(harness.upload_count(), 0);
    }
}

#[tokio::test]
async fn trusted_forwarding_rejects_oversized_headers_and_excess_hops_before_parsing_fully() {
    let valid_xff = "198.51.100.7,".repeat(600);
    let valid_forwarded = "for=198.51.100.7,".repeat(400);
    let too_many_xff = format!("{}not-an-ip", ["198.51.100.1"; 8].join(",") + ",");
    let too_many_forwarded = format!("{}for=_hidden", ["for=198.51.100.1"; 8].join(",") + ",");
    let cases = [
        (
            "x-forwarded-for",
            valid_xff.as_str(),
            "forwarded_headers_too_large",
        ),
        (
            "forwarded",
            valid_forwarded.as_str(),
            "forwarded_headers_too_large",
        ),
        (
            "x-forwarded-for",
            too_many_xff.as_str(),
            "forwarded_chain_too_long",
        ),
        (
            "forwarded",
            too_many_forwarded.as_str(),
            "forwarded_chain_too_long",
        ),
    ];

    for (header, value, expected_code) in cases {
        let harness = Harness::new(8, vec!["192.0.2.0/24".to_owned()]);
        let (status, _, body) = response_parts(
            harness
                .call(
                    Method::POST,
                    "/v1/upload-sessions",
                    None,
                    Some(PUBLIC_ORIGIN),
                    "192.0.2.10".parse().unwrap(),
                    &[(header, value)],
                    r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#,
                )
                .await,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_REQUEST, "{header}");
        assert_error_code(&body, expected_code);
        assert_eq!(harness.upload_count(), 0);
    }
}

#[tokio::test]
async fn forwarded_headers_must_be_unambiguous_and_unique() {
    let harness = Harness::new(8, vec!["192.0.2.0/24".to_owned()]);
    let request_body = r#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#;
    let duplicate = harness
        .call(
            Method::POST,
            "/v1/upload-sessions",
            None,
            Some(PUBLIC_ORIGIN),
            "192.0.2.10".parse().unwrap(),
            &[
                ("x-forwarded-for", "198.51.100.7"),
                ("x-forwarded-for", "198.51.100.8"),
            ],
            request_body,
        )
        .await;
    assert_eq!(duplicate.status(), StatusCode::BAD_REQUEST);
    assert_eq!(harness.upload_count(), 0);
}

#[tokio::test]
async fn capability_tokens_are_distinct_unpadded_and_redacted_from_debug() {
    let harness = Harness::new(8, vec![]);
    let first = harness.issue("job:one", Scope::Status);
    let second = harness.issue("job:one", Scope::Status);
    assert_eq!(first.token().len(), 43);
    assert_ne!(first.token(), second.token());
    assert!(!format!("{first:?}").contains(first.token()));
    assert!(!format!("{first:?}").contains("[0x"));
}

#[test]
fn ledger_reservation_tokens_use_full_256_bit_base64url_entropy() {
    let harness = Harness::new(8, vec![]);
    let reservation = harness.ledger.reserve("203.0.113.50", Some(1)).unwrap();
    let token = reservation.session_token.as_str();

    assert_eq!(token.len(), 43);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    );
}

async fn response_parts(response: Response<HttpBody>) -> (StatusCode, hyper::HeaderMap, Vec<u8>) {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, headers, body)
}

fn assert_error_code(body: &[u8], expected: &str) {
    let value: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(value["error"]["code"], expected);
    assert!(value["error"]["diagnostic_id"].as_str().is_some());
    let response = String::from_utf8_lossy(body);
    assert!(!response.contains("C:\\"), "server path leaked: {response}");
    assert!(
        !response.contains("/tmp/"),
        "server path leaked: {response}"
    );
    assert!(!response.to_ascii_lowercase().contains("ffmpeg"));
}

fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
