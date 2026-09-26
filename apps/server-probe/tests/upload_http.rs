use std::collections::VecDeque;
use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use fluxform_server_probe::auth::CapabilityStore;
use fluxform_server_probe::routes::{HttpBody, ServerState, TransportPeer, router, serve};
use fluxform_server_probe::{
    DiskSpaceProvider, LedgerLimits, SessionToken, UploadLedger, UploadState,
};
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Bytes, Frame};
use hyper::header::{AUTHORIZATION, CONTENT_LENGTH, ORIGIN};
use hyper::{Method, Request, Response, StatusCode};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tower::ServiceExt;

const PUBLIC_ORIGIN: &str = "https://flux.test";
const DEFAULT_PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
const MAX_FILE_BYTES: u64 = 8;
type BoxError = Box<dyn Error + Send + Sync + 'static>;

#[derive(Clone)]
struct TestDiskSpace(Arc<AtomicU64>);

impl TestDiskSpace {
    fn new(available: u64) -> Self {
        Self(Arc::new(AtomicU64::new(available)))
    }

    fn set_available(&self, available: u64) {
        self.0.store(available, Ordering::SeqCst);
    }
}

impl DiskSpaceProvider for TestDiskSpace {
    fn available_bytes(&self, _path: &std::path::Path) -> io::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

struct Harness {
    _temp: TempDir,
    database_path: PathBuf,
    upload_root: PathBuf,
    ledger: UploadLedger,
    state: ServerState,
    disk_space: TestDiskSpace,
}

impl Harness {
    fn new(max_global_reserved_bytes: u64, disk_safety_margin_bytes: u64) -> Self {
        Self::with_active_session_limit(max_global_reserved_bytes, disk_safety_margin_bytes, 8)
    }

    fn with_active_session_limit(
        max_global_reserved_bytes: u64,
        disk_safety_margin_bytes: u64,
        max_active_sessions_per_ip: u32,
    ) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let database_path = temp.path().join("server.sqlite3");
        let upload_root = temp.path().join("uploads");
        std::fs::create_dir(&upload_root).unwrap();
        let disk_space = TestDiskSpace::new(1024 * 1024);
        let ledger = UploadLedger::open_with_disk_space(
            &database_path,
            &upload_root,
            LedgerLimits {
                max_file_bytes: MAX_FILE_BYTES,
                daily_quota_bytes: 256,
                max_active_sessions_per_ip,
                max_global_reserved_bytes,
                disk_safety_margin_bytes,
            },
            vec![[0x41; 32]],
            Arc::new(disk_space.clone()),
        )
        .unwrap();
        let capabilities = CapabilityStore::open(&database_path).unwrap();
        let state = ServerState::new(
            ledger.clone(),
            capabilities,
            PUBLIC_ORIGIN,
            vec![],
            Duration::from_secs(3600),
        )
        .unwrap();

        Self {
            _temp: temp,
            database_path,
            upload_root,
            ledger,
            state,
            disk_space,
        }
    }

    async fn create_upload(&self, declared_bytes: u64) -> (i64, String) {
        let body = format!(
            r#"{{"declared_bytes":{declared_bytes},"output_target":{{"type":"managed_artifact"}}}}"#
        );
        let request_body = Full::new(Bytes::from(body))
            .map_err(|never| -> BoxError { match never {} })
            .boxed_unsync();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/v1/upload-sessions")
            .header(ORIGIN, PUBLIC_ORIGIN)
            .body(request_body)
            .unwrap();
        request
            .extensions_mut()
            .insert(TransportPeer(SocketAddr::new(DEFAULT_PEER, 43123)));

        let (status, body) =
            response_parts(router(self.state.clone()).oneshot(request).await.unwrap()).await;
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

    async fn put_body<B>(
        &self,
        session_id: i64,
        token: &str,
        body: B,
        content_length: Option<&str>,
    ) -> Response<HttpBody>
    where
        B: Body<Data = Bytes, Error = io::Error> + Send + 'static,
    {
        let request_body = body
            .map_err(|error| -> BoxError { Box::new(error) })
            .boxed_unsync();
        let mut builder = Request::builder()
            .method(Method::PUT)
            .uri(format!("/v1/upload-sessions/{session_id}/content"))
            .header(ORIGIN, PUBLIC_ORIGIN)
            .header(AUTHORIZATION, format!("Bearer {token}"));
        if let Some(content_length) = content_length {
            builder = builder.header(CONTENT_LENGTH, content_length);
        }
        let mut request = builder.body(request_body).unwrap();
        request
            .extensions_mut()
            .insert(TransportPeer(SocketAddr::new(DEFAULT_PEER, 43123)));
        router(self.state.clone()).oneshot(request).await.unwrap()
    }

    fn upload_path(&self, session_id: i64) -> PathBuf {
        let relative: String = Connection::open(&self.database_path)
            .unwrap()
            .query_row(
                "SELECT upload_path FROM uploads WHERE id = ?1",
                [session_id],
                |row| row.get(0),
            )
            .unwrap();
        self.upload_root.join(relative)
    }

    fn state(&self, session_id: i64, token: &str) -> UploadState {
        self.ledger
            .state(session_id, &SessionToken::parse(token).unwrap())
            .unwrap()
    }

    fn reserved_bytes(&self) -> u64 {
        self.ledger.reserved_bytes().unwrap()
    }

    fn with_upload_timeouts(mut self, idle: Duration, total: Duration) -> Self {
        self.state = self.state.with_upload_timeouts(idle, total).unwrap();
        self
    }

    fn reservation_file_count(&self) -> usize {
        std::fs::read_dir(self.upload_root.join(".fluxform-reservations"))
            .unwrap()
            .count()
    }
}

async fn start_server(state: ServerState) -> (SocketAddr, JoinHandle<io::Result<()>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (address, tokio::spawn(serve(listener, state)))
}

async fn connect(address: SocketAddr) -> BufReader<TcpStream> {
    BufReader::new(TcpStream::connect(address).await.unwrap())
}

async fn send_request(
    stream: &mut BufReader<TcpStream>,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) {
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n");
    for (name, value) in headers {
        request.push_str(name);
        request.push_str(": ");
        request.push_str(value);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .unwrap();
    stream.get_mut().write_all(body).await.unwrap();
    stream.get_mut().flush().await.unwrap();
}

async fn read_response(
    stream: &mut BufReader<TcpStream>,
) -> io::Result<(u16, Vec<(String, String)>, Vec<u8>)> {
    let mut line = Vec::new();
    stream.read_until(b'\n', &mut line).await?;
    let status = std::str::from_utf8(&line)
        .ok()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP status"))?;
    let mut headers = Vec::new();
    loop {
        line.clear();
        stream.read_until(b'\n', &mut line).await?;
        if line == b"\r\n" || line.is_empty() {
            break;
        }
        let text = std::str::from_utf8(&line)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP header"))?;
        let (name, value) = text
            .trim_end_matches("\r\n")
            .split_once(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP header"))?;
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let content_length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map(|(_, value)| value.parse::<usize>())
        .transpose()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid content length"))?
        .unwrap_or(0);
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body).await?;
    Ok((status, headers, body))
}

struct InstrumentedBody {
    chunks: VecDeque<Result<Bytes, io::Error>>,
    polls: Arc<AtomicUsize>,
    before_chunk: Option<Arc<dyn Fn(usize) + Send + Sync>>,
    yielded: usize,
}

impl InstrumentedBody {
    fn chunks(chunks: impl IntoIterator<Item = impl Into<Bytes>>) -> (Self, Arc<AtomicUsize>) {
        Self::items(chunks.into_iter().map(|chunk| Ok(chunk.into())))
    }

    fn items(
        chunks: impl IntoIterator<Item = Result<Bytes, io::Error>>,
    ) -> (Self, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        (
            Self {
                chunks: chunks.into_iter().collect(),
                polls: Arc::clone(&polls),
                before_chunk: None,
                yielded: 0,
            },
            polls,
        )
    }

    fn with_before_chunk(mut self, check: Arc<dyn Fn(usize) + Send + Sync>) -> Self {
        self.before_chunk = Some(check);
        self
    }
}

struct StallingBody {
    polls: Arc<AtomicUsize>,
    emitted_frames: Arc<AtomicUsize>,
    emitted_first: bool,
    wake_sent: bool,
    wake_after: Duration,
    tail: Option<Bytes>,
}

impl StallingBody {
    fn after_first_chunk(wake_after: Duration) -> (Self, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let emitted_frames = Arc::new(AtomicUsize::new(0));
        (
            Self {
                polls: Arc::clone(&polls),
                emitted_frames: Arc::clone(&emitted_frames),
                emitted_first: false,
                wake_sent: false,
                wake_after,
                tail: Some(Bytes::from_static(b"not-consumed")),
            },
            polls,
            emitted_frames,
        )
    }
}

impl Body for StallingBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        if !this.emitted_first {
            this.emitted_first = true;
            this.emitted_frames.fetch_add(1, Ordering::SeqCst);
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"first")))));
        }
        if this.wake_sent
            && let Some(tail) = this.tail.take()
        {
            this.emitted_frames.fetch_add(1, Ordering::SeqCst);
            return Poll::Ready(Some(Ok(Frame::data(tail))));
        }
        if !this.wake_sent {
            this.wake_sent = true;
            let wake = context.waker().clone();
            let delay = this.wake_after;
            std::thread::spawn(move || {
                std::thread::sleep(delay);
                wake.wake();
            });
        }
        Poll::Pending
    }
}

impl Body for InstrumentedBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        this.polls.fetch_add(1, Ordering::SeqCst);
        let Some(chunk) = this.chunks.pop_front() else {
            return Poll::Ready(None);
        };
        if let Some(check) = &this.before_chunk {
            check(this.yielded);
        }
        this.yielded += 1;
        Poll::Ready(Some(chunk.map(Frame::data)))
    }
}

async fn response_parts(response: Response<HttpBody>) -> (StatusCode, Vec<u8>) {
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

fn assert_error_code(body: &[u8], expected: &str) {
    let value: Value = serde_json::from_slice(body).unwrap();
    assert_eq!(value["error"]["code"], expected);
    assert!(value["error"]["diagnostic_id"].as_str().is_some());
    let response = String::from_utf8_lossy(body);
    assert!(!response.contains(".fluxform-reservations"));
    assert!(!response.contains("Bearer "));
}

#[tokio::test]
async fn underdeclared_upload_expands_before_polling_and_writing_the_excess_chunk() {
    let harness = Harness::new(64, 0);
    let (session_id, token) = harness.create_upload(4).await;
    let path = harness.upload_path(session_id);
    let ledger = harness.ledger.clone();
    let path_at_poll = path.clone();
    let body = InstrumentedBody::chunks([
        Bytes::from_static(b"abc"),
        Bytes::from_static(b"de"),
        Bytes::from_static(b"f"),
    ])
    .0
    .with_before_chunk(Arc::new(move |index| {
        if index == 2 {
            assert_eq!(ledger.reserved_bytes().unwrap(), 5);
            assert_eq!(&std::fs::read(&path_at_poll).unwrap()[..5], b"abcde");
        }
    }));
    let polls = Arc::clone(&body.polls);

    let (status, response_body) =
        response_parts(harness.put_body(session_id, &token, body, Some("1")).await).await;

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&response_body)
    );
    assert_eq!(polls.load(Ordering::SeqCst), 4, "three chunks and EOF");
    assert_eq!(std::fs::read(&path).unwrap(), b"abcdef");
    assert_eq!(harness.state(session_id, &token), UploadState::Uploaded);
    assert_eq!(harness.reserved_bytes(), 0);
}

#[tokio::test]
async fn declared_size_and_hard_limit_boundaries_are_counted_across_chunks() {
    for (declared, actual, expected_status) in [
        (4, 3, StatusCode::NO_CONTENT),
        (4, 4, StatusCode::NO_CONTENT),
        (4, 5, StatusCode::NO_CONTENT),
        (8, 7, StatusCode::NO_CONTENT),
        (8, 8, StatusCode::NO_CONTENT),
        (8, 9, StatusCode::PAYLOAD_TOO_LARGE),
    ] {
        let harness = Harness::new(64, 0);
        let (session_id, token) = harness.create_upload(declared).await;
        let mut chunks = (0..actual)
            .map(|_| Bytes::from_static(b"x"))
            .collect::<Vec<_>>();
        if actual == 9 {
            chunks.push(Bytes::from_static(b"not-consumed"));
        }
        let (body, polls) = InstrumentedBody::chunks(chunks);
        let path = harness.upload_path(session_id);
        let (status, response_body) =
            response_parts(harness.put_body(session_id, &token, body, None).await).await;

        assert_eq!(
            status,
            expected_status,
            "declared={declared}, actual={actual}: {}",
            String::from_utf8_lossy(&response_body)
        );
        if actual == 9 {
            assert_error_code(&response_body, "file_too_large");
            assert_eq!(
                polls.load(Ordering::SeqCst),
                9,
                "must stop at the violating chunk"
            );
            assert!(!path.exists());
            assert_eq!(harness.state(session_id, &token), UploadState::Expired);
            assert_eq!(harness.reserved_bytes(), 0);
        } else {
            assert_eq!(polls.load(Ordering::SeqCst), actual as usize + 1);
            assert_eq!(std::fs::read(path).unwrap(), vec![b'x'; actual as usize]);
            assert_eq!(harness.state(session_id, &token), UploadState::Uploaded);
        }
    }
}

#[tokio::test]
async fn content_length_does_not_override_the_streamed_byte_total() {
    let harness = Harness::new(64, 0);
    let (session_id, token) = harness.create_upload(3).await;
    let path = harness.upload_path(session_id);
    let body = InstrumentedBody::chunks([Bytes::from_static(b"abc")]).0;

    let (status, response_body) = response_parts(
        harness
            .put_body(session_id, &token, body, Some("999"))
            .await,
    )
    .await;

    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "{}",
        String::from_utf8_lossy(&response_body)
    );
    assert_eq!(std::fs::read(path).unwrap(), b"abc");
    assert_eq!(harness.state(session_id, &token), UploadState::Uploaded);
    assert_eq!(harness.reserved_bytes(), 0);
}

#[tokio::test]
async fn expansion_failure_cleans_staging_and_does_not_poll_remaining_chunks() {
    let harness = Harness::new(4, 0);
    let (session_id, token) = harness.create_upload(4).await;
    let path = harness.upload_path(session_id);
    let (body, polls) = InstrumentedBody::chunks([
        Bytes::from_static(b"abcd"),
        Bytes::from_static(b"e"),
        Bytes::from_static(b"not-consumed"),
    ]);

    let (status, response_body) =
        response_parts(harness.put_body(session_id, &token, body, None).await).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_error_code(&response_body, "quota_exceeded");
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert!(!path.exists());
    assert_eq!(harness.state(session_id, &token), UploadState::Expired);
    assert_eq!(harness.reserved_bytes(), 0);
    assert_eq!(harness.reservation_file_count(), 0);
}

#[tokio::test]
async fn disk_watermark_failure_cleans_staging_before_any_chunk_is_written() {
    let harness = Harness::new(64, 1);
    let (session_id, token) = harness.create_upload(2).await;
    let path = harness.upload_path(session_id);
    harness.disk_space.set_available(0);
    let (body, polls) =
        InstrumentedBody::chunks([Bytes::from_static(b"a"), Bytes::from_static(b"b")]);

    let (status, response_body) =
        response_parts(harness.put_body(session_id, &token, body, None).await).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_error_code(&response_body, "quota_exceeded");
    assert_eq!(polls.load(Ordering::SeqCst), 1);
    assert!(!path.exists());
    assert_eq!(harness.state(session_id, &token), UploadState::Expired);
    assert_eq!(harness.reserved_bytes(), 0);
}

#[tokio::test]
async fn body_error_rejects_upload_and_stops_polling() {
    let harness = Harness::new(64, 0);
    let (session_id, token) = harness.create_upload(4).await;
    let path = harness.upload_path(session_id);
    let (body, polls) = InstrumentedBody::items([
        Ok(Bytes::from_static(b"ab")),
        Err(io::Error::other("simulated transport failure")),
        Ok(Bytes::from_static(b"not-consumed")),
    ]);

    let (status, response_body) =
        response_parts(harness.put_body(session_id, &token, body, None).await).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_code(&response_body, "upload_interrupted");
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert!(!path.exists());
    assert_eq!(harness.state(session_id, &token), UploadState::Expired);
    assert_eq!(harness.reserved_bytes(), 0);
}

#[tokio::test]
async fn upload_total_timeout_cleans_staging_and_stops_polling() {
    let harness =
        Harness::new(64, 0).with_upload_timeouts(Duration::from_secs(1), Duration::from_millis(10));
    let (session_id, token) = harness.create_upload(8).await;
    let path = harness.upload_path(session_id);
    let (body, polls, emitted_frames) = StallingBody::after_first_chunk(Duration::from_millis(200));

    let (status, response_body) =
        response_parts(harness.put_body(session_id, &token, body, None).await).await;

    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_error_code(&response_body, "upload_timeout");
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert_eq!(emitted_frames.load(Ordering::SeqCst), 1);
    assert!(!path.exists());
    assert_eq!(harness.state(session_id, &token), UploadState::Expired);
    assert_eq!(harness.reserved_bytes(), 0);
}

#[tokio::test]
async fn upload_idle_timeout_cleans_staging_and_stops_polling() {
    let harness =
        Harness::new(64, 0).with_upload_timeouts(Duration::from_millis(10), Duration::from_secs(1));
    let (session_id, token) = harness.create_upload(8).await;
    let path = harness.upload_path(session_id);
    let (body, polls, emitted_frames) = StallingBody::after_first_chunk(Duration::from_millis(200));

    let (status, response_body) =
        response_parts(harness.put_body(session_id, &token, body, None).await).await;

    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_error_code(&response_body, "upload_timeout");
    assert_eq!(polls.load(Ordering::SeqCst), 2);
    assert_eq!(emitted_frames.load(Ordering::SeqCst), 1);
    assert!(!path.exists());
    assert_eq!(harness.state(session_id, &token), UploadState::Expired);
    assert_eq!(harness.reserved_bytes(), 0);
}

#[tokio::test]
async fn origin_and_capability_checks_still_precede_upload_body_polling() {
    let harness = Harness::new(64, 0);
    let (session_id, token) = harness.create_upload(4).await;
    let (body, polls) = InstrumentedBody::chunks([Bytes::from_static(b"payload")]);
    let request_body = body
        .map_err(|error| -> BoxError { Box::new(error) })
        .boxed_unsync();
    let mut request = Request::builder()
        .method(Method::PUT)
        .uri(format!("/v1/upload-sessions/{session_id}/content"))
        .header(ORIGIN, "https://other.test")
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(request_body)
        .unwrap();
    request
        .extensions_mut()
        .insert(TransportPeer(SocketAddr::new(DEFAULT_PEER, 43123)));

    let (status, response_body) = response_parts(
        router(harness.state.clone())
            .oneshot(request)
            .await
            .unwrap(),
    )
    .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_code(&response_body, "origin_denied");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(harness.state(session_id, &token), UploadState::Reserved);
    assert_eq!(harness.reserved_bytes(), 4);
}

#[tokio::test]
async fn invalid_capability_rejects_before_upload_body_polling() {
    let harness = Harness::new(64, 0);
    let (session_id, valid_token) = harness.create_upload(4).await;
    let (body, polls) = InstrumentedBody::chunks([Bytes::from_static(b"payload")]);

    let (status, response_body) = response_parts(
        harness
            .put_body(session_id, "not-a-valid-capability", body, None)
            .await,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_code(&response_body, "unauthorized");
    assert_eq!(polls.load(Ordering::SeqCst), 0);
    assert_eq!(
        harness.state(session_id, &valid_token),
        UploadState::Reserved
    );
    assert_eq!(harness.reserved_bytes(), 4);
}

#[tokio::test]
async fn accepted_socket_peer_overrides_spoofed_forwarding_headers() {
    let harness = Harness::with_active_session_limit(64, 0, 1);
    let (address, server) = start_server(harness.state.clone()).await;
    let mut stream = connect(address).await;
    let body = br#"{"declared_bytes":1,"output_target":{"type":"managed_artifact"}}"#;
    let headers = [
        ("Origin", PUBLIC_ORIGIN),
        ("Content-Type", "application/json"),
        ("Content-Length", &body.len().to_string()),
        ("X-Forwarded-For", "198.51.100.1"),
    ];

    send_request(&mut stream, "POST", "/v1/upload-sessions", &headers, body).await;
    let (status, _, response_body) = read_response(&mut stream).await.unwrap();
    assert_eq!(status, StatusCode::CREATED.as_u16());
    let first: Value = serde_json::from_slice(&response_body).unwrap();
    assert!(first["session_id"].as_i64().is_some());

    let second_headers = [
        ("Origin", PUBLIC_ORIGIN),
        ("Content-Type", "application/json"),
        ("Content-Length", &body.len().to_string()),
        ("X-Forwarded-For", "198.51.100.2"),
    ];
    send_request(
        &mut stream,
        "POST",
        "/v1/upload-sessions",
        &second_headers,
        body,
    )
    .await;
    let (status, _, response_body) = read_response(&mut stream).await.unwrap();
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS.as_u16());
    assert_error_code(&response_body, "quota_exceeded");

    server.abort();
}

#[tokio::test]
async fn timed_out_partial_socket_upload_returns_error_then_closes_without_drain() {
    let harness = Harness::new(64, 0)
        .with_upload_timeouts(Duration::from_millis(50), Duration::from_millis(250));
    let (address, server) = start_server(harness.state.clone()).await;
    let mut bootstrap = connect(address).await;
    let create_body = br#"{"declared_bytes":8,"output_target":{"type":"managed_artifact"}}"#;
    let create_headers = [
        ("Origin", PUBLIC_ORIGIN),
        ("Content-Type", "application/json"),
        ("Content-Length", &create_body.len().to_string()),
    ];
    send_request(
        &mut bootstrap,
        "POST",
        "/v1/upload-sessions",
        &create_headers,
        create_body,
    )
    .await;
    let (status, _, response_body) = read_response(&mut bootstrap).await.unwrap();
    assert_eq!(status, StatusCode::CREATED.as_u16());
    let created: Value = serde_json::from_slice(&response_body).unwrap();
    let session_id = created["session_id"].as_i64().unwrap();
    let capability = created["capability"].as_str().unwrap();
    let path = harness.upload_path(session_id);

    let mut upload = connect(address).await;
    let upload_headers = [
        ("Origin", PUBLIC_ORIGIN),
        ("Authorization", &format!("Bearer {capability}")),
        ("Content-Length", "8"),
    ];
    send_request(
        &mut upload,
        "PUT",
        &format!("/v1/upload-sessions/{session_id}/content"),
        &upload_headers,
        b"a",
    )
    .await;

    let (status, headers, response_body) =
        tokio::time::timeout(Duration::from_secs(2), read_response(&mut upload))
            .await
            .expect("server should respond at the idle deadline")
            .unwrap();
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT.as_u16());
    assert_error_code(&response_body, "upload_timeout");
    assert!(
        headers
            .iter()
            .any(|(name, value)| { name == "connection" && value.eq_ignore_ascii_case("close") })
    );

    let mut byte = [0; 1];
    let closed = tokio::time::timeout(Duration::from_secs(1), upload.read(&mut byte))
        .await
        .expect("server should close the incomplete request connection")
        .unwrap();
    assert_eq!(closed, 0);
    assert!(!path.exists());
    assert_eq!(harness.state(session_id, capability), UploadState::Expired);
    assert_eq!(harness.reserved_bytes(), 0);

    server.abort();
}
