use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{self, Seek, SeekFrom, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::thread;
use std::time::{Duration, SystemTime};

use futures_util::StreamExt;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::header::{
    AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY,
    CONTENT_TYPE, FORWARDED, HeaderMap, HeaderValue, ORIGIN, REFERRER_POLICY,
    X_CONTENT_TYPE_OPTIONS,
};
use hyper::rt::{Read as HyperRead, ReadBufCursor, Write as HyperWrite};
use hyper::server::conn::http1;
use hyper::service::service_fn as hyper_service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioTimer;
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf as TokioReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, mpsc, oneshot};
use tokio::task::JoinSet;
use tower::Service;
use tower::service_fn;
use uuid::Uuid;

use crate::auth::{Capability, CapabilityError, CapabilityStore, Scope};
use crate::ledger::{LimitError, SessionToken, UploadLedger, UploadReservation};

const MAX_BOOTSTRAP_BODY_BYTES: usize = 16 * 1024;
const DEFAULT_UPLOAD_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const DEFAULT_UPLOAD_TOTAL_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const DEFAULT_UPLOAD_LEASE_DURATION: Duration = Duration::from_secs(60);
const SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(1);
const DEFAULT_MAX_CONNECTIONS: usize = 64;
const DEFAULT_MAX_UPLOAD_WORKERS: usize = 4;
const DEFAULT_MAX_STORAGE_WORKERS: usize = 8;
const DEFAULT_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const STORAGE_OPERATION_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);
const MAX_FORWARDED_HOPS: usize = 8;
const MAX_FORWARDED_HEADER_BYTES: usize = 4 * 1024;
const MAX_TRUSTED_PROXY_CIDRS: usize = 64;
const MAX_CIDR_TEXT_BYTES: usize = 64;
const CSP: &str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const PUBLIC_ORIGIN_ERROR: HttpError = HttpError {
    status: StatusCode::FORBIDDEN,
    code: "origin_denied",
    message: "The request origin is not allowed.",
};
const UPLOAD_INTERRUPTED_ERROR: HttpError = HttpError {
    status: StatusCode::BAD_REQUEST,
    code: "upload_interrupted",
    message: "The upload stream ended unexpectedly.",
};
const UPLOAD_TIMEOUT_ERROR: HttpError = HttpError {
    status: StatusCode::REQUEST_TIMEOUT,
    code: "upload_timeout",
    message: "The upload exceeded its time limit.",
};
const INVALID_FORWARDED_ERROR: HttpError = HttpError {
    status: StatusCode::BAD_REQUEST,
    code: "invalid_forwarded_chain",
    message: "The forwarded client address is invalid.",
};
const OVERSIZED_FORWARDING_ERROR: HttpError = HttpError {
    status: StatusCode::BAD_REQUEST,
    code: "forwarded_headers_too_large",
    message: "The forwarded client address headers are too large.",
};
const TOO_MANY_FORWARDING_HOPS_ERROR: HttpError = HttpError {
    status: StatusCode::BAD_REQUEST,
    code: "forwarded_chain_too_long",
    message: "The forwarded client address chain is too long.",
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;
pub type HttpBody = UnsyncBoxBody<Bytes, BoxError>;

/// Performs the final synchronous write of one already-reserved upload chunk.
///
/// The trait is injectable so tests can observe the committed reservation at
/// the exact writer call. Implementations run on the bounded storage worker.
pub trait UploadChunkWriter: Send + Sync + 'static {
    fn write_chunk(&self, file: &mut File, chunk: &[u8]) -> io::Result<()>;
}

struct FileUploadChunkWriter;

impl UploadChunkWriter for FileUploadChunkWriter {
    fn write_chunk(&self, file: &mut File, chunk: &[u8]) -> io::Result<()> {
        file.write_all(chunk)
    }
}

/// Socket peer supplied by the connection adapter, never copied from a header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportPeer(pub SocketAddr);

#[derive(Clone)]
pub struct ServerState {
    ledger: UploadLedger,
    capabilities: CapabilityStore,
    public_origin: String,
    trusted_proxies: Vec<IpCidr>,
    capability_ttl: Duration,
    upload_idle_timeout: Duration,
    upload_total_timeout: Duration,
    upload_lease_duration: Duration,
    upload_lease_renew_interval: Duration,
    storage_operation_timeout: Duration,
    upload_chunk_writer: Arc<dyn UploadChunkWriter>,
    max_connections: usize,
    header_read_timeout: Duration,
    upload_workers: Arc<Semaphore>,
    storage_workers: Arc<Semaphore>,
    active_uploads: Arc<Mutex<HashSet<i64>>>,
    worker_tracker: Arc<WorkerTracker>,
    resources: Arc<Mutex<ResourceCatalog>>,
}

impl ServerState {
    pub fn new(
        ledger: UploadLedger,
        capabilities: CapabilityStore,
        public_origin: impl Into<String>,
        trusted_proxy_cidrs: Vec<String>,
        capability_ttl: Duration,
    ) -> Result<Self, RouteConfigurationError> {
        let public_origin = public_origin.into();
        validate_public_origin(&public_origin)?;
        if capability_ttl.is_zero() {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        if !capabilities.shares_database_with(ledger.database_path()) {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        if trusted_proxy_cidrs.len() > MAX_TRUSTED_PROXY_CIDRS {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        let trusted_proxies = trusted_proxy_cidrs
            .iter()
            .map(|cidr| IpCidr::from_str(cidr))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            ledger,
            capabilities,
            public_origin,
            trusted_proxies,
            capability_ttl,
            upload_idle_timeout: DEFAULT_UPLOAD_IDLE_TIMEOUT,
            upload_total_timeout: DEFAULT_UPLOAD_TOTAL_TIMEOUT,
            upload_lease_duration: DEFAULT_UPLOAD_LEASE_DURATION,
            upload_lease_renew_interval: Duration::from_secs(10),
            storage_operation_timeout: STORAGE_OPERATION_TIMEOUT,
            upload_chunk_writer: Arc::new(FileUploadChunkWriter),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            header_read_timeout: DEFAULT_HEADER_READ_TIMEOUT,
            upload_workers: Arc::new(Semaphore::new(DEFAULT_MAX_UPLOAD_WORKERS)),
            storage_workers: Arc::new(Semaphore::new(DEFAULT_MAX_STORAGE_WORKERS)),
            active_uploads: Arc::new(Mutex::new(HashSet::new())),
            worker_tracker: Arc::new(WorkerTracker::default()),
            resources: Arc::new(Mutex::new(ResourceCatalog::default())),
        })
    }

    pub fn with_upload_timeouts(
        mut self,
        idle_timeout: Duration,
        total_timeout: Duration,
    ) -> Result<Self, RouteConfigurationError> {
        if idle_timeout.is_zero() || total_timeout.is_zero() {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        self.upload_idle_timeout = idle_timeout;
        self.upload_total_timeout = total_timeout;
        Ok(self)
    }

    pub fn with_upload_chunk_writer(mut self, writer: Arc<dyn UploadChunkWriter>) -> Self {
        self.upload_chunk_writer = writer;
        self
    }

    pub fn with_upload_lease_policy(
        mut self,
        lease_duration: Duration,
        renewal_interval: Duration,
    ) -> Result<Self, RouteConfigurationError> {
        if lease_duration.is_zero()
            || renewal_interval.is_zero()
            || renewal_interval >= lease_duration
        {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        self.upload_lease_duration = lease_duration;
        self.upload_lease_renew_interval = renewal_interval;
        Ok(self)
    }

    pub fn with_storage_operation_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<Self, RouteConfigurationError> {
        if timeout.is_zero() {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        self.storage_operation_timeout = timeout;
        Ok(self)
    }

    pub fn with_listener_limits(
        mut self,
        max_connections: usize,
        header_read_timeout: Duration,
    ) -> Result<Self, RouteConfigurationError> {
        if max_connections == 0 || header_read_timeout.is_zero() {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        self.max_connections = max_connections;
        self.header_read_timeout = header_read_timeout;
        Ok(self)
    }

    pub fn register_job(
        &self,
        id: &str,
        initial_state: &str,
    ) -> Result<(), RouteConfigurationError> {
        if !valid_resource_id(id) || initial_state.is_empty() || initial_state.len() > 64 {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        self.resources
            .lock()
            .map_err(|_| RouteConfigurationError::StorageUnavailable)?
            .jobs
            .insert(
                id.to_owned(),
                JobRecord {
                    state: initial_state.to_owned(),
                },
            );
        Ok(())
    }

    pub fn job_status(&self, id: &str) -> Option<String> {
        self.resources
            .lock()
            .ok()?
            .jobs
            .get(id)
            .map(|job| job.state.clone())
    }

    pub fn register_artifact(
        &self,
        id: &str,
        path: impl AsRef<Path>,
        filename: &str,
        content_type: &str,
    ) -> Result<(), RouteConfigurationError> {
        if !valid_resource_id(id) || filename.is_empty() || filename.len() > 255 {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        let content_type = HeaderValue::from_str(content_type)
            .map_err(|_| RouteConfigurationError::InvalidConfiguration)?;
        let filename = safe_download_filename(filename);
        self.resources
            .lock()
            .map_err(|_| RouteConfigurationError::StorageUnavailable)?
            .artifacts
            .insert(
                id.to_owned(),
                ArtifactRecord {
                    path: path.as_ref().to_path_buf(),
                    filename,
                    content_type,
                },
            );
        Ok(())
    }
}

#[derive(Default)]
struct WorkerTracker {
    active: AtomicUsize,
    failed_late_compensations: AtomicUsize,
    finished: Notify,
}

impl WorkerTracker {
    fn begin(self: &Arc<Self>) -> WorkerGuard {
        self.active.fetch_add(1, Ordering::AcqRel);
        WorkerGuard(Arc::clone(self))
    }

    fn has_failed_late_compensations(&self) -> bool {
        self.failed_late_compensations.load(Ordering::Acquire) > 0
    }

    async fn wait_until_idle(&self, deadline: tokio::time::Instant) -> bool {
        loop {
            let notified = self.finished.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.active.load(Ordering::Acquire) == 0;
            }
        }
    }
}

struct WorkerGuard(Arc<WorkerTracker>);

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
        self.0.finished.notify_one();
    }
}

#[derive(Clone, Copy)]
enum StorageTaskError {
    Timeout,
    Failed,
}

async fn run_storage<T, F>(
    state: &ServerState,
    deadline: tokio::time::Instant,
    operation: F,
) -> Result<T, StorageTaskError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    run_storage_with_late_completion(state, deadline, operation, |_| async { true }).await
}

async fn compensate_late_bootstrap_result(
    ledger: UploadLedger,
    result: Result<(UploadReservation, Capability), LimitError>,
) -> bool {
    let pending = match result {
        Ok((reservation, _capability)) => Some((reservation.session_id, reservation.session_token)),
        Err(LimitError::LateReservationCompensationRequired {
            session_id,
            capability,
        }) => Some((session_id, capability)),
        _ => None,
    };
    if let Some((session_id, token)) = pending {
        tokio::task::spawn_blocking(move || ledger.compensate_late_reservation(session_id, &token))
            .await
            .is_ok_and(|result| result.is_ok())
    } else {
        true
    }
}

async fn run_storage_with_late_completion<T, F, L, LFut>(
    state: &ServerState,
    deadline: tokio::time::Instant,
    operation: F,
    late_completion: L,
) -> Result<T, StorageTaskError>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
    L: FnOnce(T) -> LFut + Send + 'static,
    LFut: Future<Output = bool> + Send + 'static,
{
    let permit: OwnedSemaphorePermit =
        tokio::time::timeout_at(deadline, Arc::clone(&state.storage_workers).acquire_owned())
            .await
            .map_err(|_| StorageTaskError::Timeout)?
            .map_err(|_| StorageTaskError::Failed)?;
    let worker_guard = state.worker_tracker.begin();
    let (sender, receiver) = oneshot::channel();
    let worker = tokio::task::spawn_blocking(move || {
        let result = (tokio::time::Instant::now() < deadline).then(operation);
        (worker_guard, permit, result)
    });
    tokio::spawn(async move {
        match worker.await {
            Ok((worker_guard, permit, result)) => {
                if let Err(Ok(Some(value))) = sender.send(Ok(result))
                    && !late_completion(value).await
                {
                    worker_guard
                        .0
                        .failed_late_compensations
                        .fetch_add(1, Ordering::AcqRel);
                }
                drop(permit);
                drop(worker_guard);
            }
            Err(error) => {
                let _ = sender.send(Err(error));
            }
        }
    });
    match tokio::time::timeout_at(deadline, receiver).await {
        Err(_) => Err(StorageTaskError::Timeout),
        Ok(Err(_)) | Ok(Ok(Err(_))) => Err(StorageTaskError::Failed),
        Ok(Ok(Ok(Some(value)))) => Ok(value),
        Ok(Ok(Ok(None))) => Err(StorageTaskError::Timeout),
    }
}

fn active_upload_ids(state: &ServerState) -> Vec<i64> {
    state
        .active_uploads
        .lock()
        .map(|sessions| sessions.iter().copied().collect())
        .unwrap_or_default()
}

enum UploadWorkerCommand {
    Start {
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<u64, UploadWorkerError>>,
    },
    Write {
        required_total: u64,
        chunk: Bytes,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<u64, UploadWorkerError>>,
    },
    Finish {
        actual_bytes: u64,
        deadline: tokio::time::Instant,
        response: oneshot::Sender<Result<(), UploadWorkerError>>,
    },
    Abort(Option<oneshot::Sender<()>>),
}

enum UploadWorkerError {
    Timeout,
    Storage(LimitError),
}

impl From<LimitError> for UploadWorkerError {
    fn from(error: LimitError) -> Self {
        Self::Storage(error)
    }
}

struct UploadWorker {
    sender: mpsc::Sender<UploadWorkerCommand>,
}

impl UploadWorker {
    async fn start(
        state: &ServerState,
        session_id: i64,
        token: SessionToken,
        lease_duration: Duration,
        deadline: tokio::time::Instant,
    ) -> Result<(Self, oneshot::Receiver<Result<u64, UploadWorkerError>>), HttpError> {
        let permit =
            tokio::time::timeout_at(deadline, Arc::clone(&state.upload_workers).acquire_owned())
                .await
                .map_err(|_| UPLOAD_TIMEOUT_ERROR)?
                .map_err(|_| HttpError::storage_unavailable())?;
        let inserted = state
            .active_uploads
            .lock()
            .map_err(|_| HttpError::storage_unavailable())?
            .insert(session_id);
        if !inserted {
            return Err(HttpError {
                status: StatusCode::CONFLICT,
                code: "invalid_state",
                message: "The request cannot be completed in the current state.",
            });
        }

        let ledger = state.ledger.clone();
        let writer = Arc::clone(&state.upload_chunk_writer);
        let active_uploads = Arc::clone(&state.active_uploads);
        let worker_state = state.clone();
        let recovery_token = token.clone();
        let worker_guard = state.worker_tracker.begin();
        let (sender, receiver) = mpsc::channel(1);
        let (reply, reply_receiver) = oneshot::channel();
        let (claimed_sender, claimed_receiver) = oneshot::channel();
        let actor = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let _worker_guard = worker_guard;
            run_upload_worker(
                UploadWorkerContext {
                    ledger,
                    writer,
                    active_uploads,
                    session_id,
                    token,
                    lease_duration,
                    claimed_sender,
                },
                receiver,
            );
        });
        let heartbeat_sender = sender.clone();
        let heartbeat_guard = state.worker_tracker.begin();
        tokio::spawn(async move {
            let mut actor = actor;
            if claimed_receiver.await.is_err() {
                if actor.await.is_err() {
                    recover_upload_worker(&worker_state, session_id, recovery_token).await;
                }
                return;
            }

            let _heartbeat_guard = heartbeat_guard;
            let mut renewal = tokio::time::interval(worker_state.upload_lease_renew_interval);
            renewal.tick().await;
            loop {
                tokio::select! {
                    result = &mut actor => {
                        if result.is_err() {
                            recover_upload_worker(&worker_state, session_id, recovery_token).await;
                        }
                        break;
                    }
                    _ = renewal.tick() => {
                        let ledger = worker_state.ledger.clone();
                        let token = recovery_token.clone();
                        let lease_duration = worker_state.upload_lease_duration;
                        let deadline = tokio::time::Instant::now()
                            + worker_state.storage_operation_timeout;
                        if !matches!(
                            run_storage(&worker_state, deadline, move || {
                                ledger.renew_receiving_lease(session_id, &token, lease_duration)
                            }).await,
                            Ok(Ok(_))
                        ) {
                            let _ = heartbeat_sender.try_send(UploadWorkerCommand::Abort(None));
                        }
                    }
                }
            }
        });

        tokio::time::timeout_at(
            deadline,
            sender.send(UploadWorkerCommand::Start {
                deadline,
                response: reply,
            }),
        )
        .await
        .map_err(|_| UPLOAD_TIMEOUT_ERROR)?
        .map_err(|_| HttpError::storage_unavailable())?;
        Ok((Self { sender }, reply_receiver))
    }

    async fn write(
        &self,
        required_total: u64,
        chunk: Bytes,
        deadline: tokio::time::Instant,
    ) -> Result<oneshot::Receiver<Result<u64, UploadWorkerError>>, HttpError> {
        let (reply, receiver) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.sender.send(UploadWorkerCommand::Write {
                required_total,
                chunk,
                deadline,
                response: reply,
            }),
        )
        .await
        .map_err(|_| UPLOAD_TIMEOUT_ERROR)?
        .map_err(|_| HttpError::storage_unavailable())?;
        Ok(receiver)
    }

    async fn finish(
        &self,
        actual_bytes: u64,
        deadline: tokio::time::Instant,
    ) -> Result<oneshot::Receiver<Result<(), UploadWorkerError>>, HttpError> {
        let (reply, receiver) = oneshot::channel();
        tokio::time::timeout_at(
            deadline,
            self.sender.send(UploadWorkerCommand::Finish {
                actual_bytes,
                deadline,
                response: reply,
            }),
        )
        .await
        .map_err(|_| UPLOAD_TIMEOUT_ERROR)?
        .map_err(|_| HttpError::storage_unavailable())?;
        Ok(receiver)
    }

    async fn abort(&self, deadline: tokio::time::Instant) -> bool {
        let (reply, receiver) = oneshot::channel();
        if tokio::time::timeout_at(
            deadline,
            self.sender.send(UploadWorkerCommand::Abort(Some(reply))),
        )
        .await
        .is_err()
        {
            return false;
        }
        tokio::time::timeout_at(deadline, receiver).await.is_ok()
    }
}

impl Drop for UploadWorker {
    fn drop(&mut self) {
        let _ = self.sender.try_send(UploadWorkerCommand::Abort(None));
    }
}

struct UploadWorkerContext {
    ledger: UploadLedger,
    writer: Arc<dyn UploadChunkWriter>,
    active_uploads: Arc<Mutex<HashSet<i64>>>,
    session_id: i64,
    token: SessionToken,
    lease_duration: Duration,
    claimed_sender: oneshot::Sender<()>,
}

fn run_upload_worker(
    context: UploadWorkerContext,
    mut commands: mpsc::Receiver<UploadWorkerCommand>,
) {
    let UploadWorkerContext {
        ledger,
        writer,
        active_uploads,
        session_id,
        token,
        lease_duration,
        claimed_sender,
    } = context;
    let mut file = None;
    let mut reserved_bytes = 0;
    let mut claimed = false;
    let mut settled = false;
    let mut claimed_sender = Some(claimed_sender);

    while let Some(command) = commands.blocking_recv() {
        match command {
            UploadWorkerCommand::Start { deadline, response } => {
                let result = if tokio::time::Instant::now() >= deadline {
                    Err(UploadWorkerError::Timeout)
                } else {
                    let claimed_result =
                        ledger.claim_receiving_lease(session_id, &token, lease_duration);
                    if claimed_result.is_ok() {
                        claimed = true;
                        if let Some(sender) = claimed_sender.take() {
                            let _ = sender.send(());
                        }
                    }
                    match claimed_result {
                        Err(error) => Err(UploadWorkerError::Storage(error)),
                        Ok(_) if tokio::time::Instant::now() >= deadline => {
                            Err(UploadWorkerError::Timeout)
                        }
                        Ok(_) => match ledger.open_receiving_upload_file(session_id, &token) {
                            Err(error) => Err(UploadWorkerError::Storage(error)),
                            Ok((mut opened, reserved)) => {
                                if tokio::time::Instant::now() >= deadline {
                                    Err(UploadWorkerError::Timeout)
                                } else if let Err(error) = opened.seek(SeekFrom::Start(0)) {
                                    Err(UploadWorkerError::Storage(LimitError::Filesystem(error)))
                                } else if tokio::time::Instant::now() >= deadline {
                                    Err(UploadWorkerError::Timeout)
                                } else {
                                    file = Some(opened);
                                    reserved_bytes = reserved;
                                    Ok(reserved)
                                }
                            }
                        },
                    }
                };
                if result.is_err() && claimed {
                    cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                }
                let success = result.is_ok();
                let delivered = response.send(result).is_ok();
                if !success || !delivered {
                    if claimed && !settled {
                        cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                    }
                    break;
                }
            }
            UploadWorkerCommand::Write {
                required_total,
                chunk,
                deadline,
                response,
            } => {
                if tokio::time::Instant::now() >= deadline {
                    let _ = response.send(Err(UploadWorkerError::Timeout));
                    cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                    break;
                }
                let Some(mut pinned_file) = file.take() else {
                    let _ = response.send(Err(UploadWorkerError::Storage(
                        LimitError::InvalidTransition,
                    )));
                    break;
                };
                let result = (|| {
                    ledger.renew_receiving_lease(session_id, &token, lease_duration)?;
                    if tokio::time::Instant::now() >= deadline {
                        return Err(UploadWorkerError::Timeout);
                    }
                    ledger.ensure_disk_safety_margin()?;
                    if tokio::time::Instant::now() >= deadline {
                        return Err(UploadWorkerError::Timeout);
                    }
                    if required_total > reserved_bytes {
                        reserved_bytes = ledger
                            .expand_receiving(
                                session_id,
                                &token,
                                &mut pinned_file,
                                required_total,
                                lease_duration,
                            )?
                            .reserved_bytes;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(UploadWorkerError::Timeout);
                    }
                    ledger.verify_upload_file_identity(session_id, &token, &pinned_file)?;
                    if tokio::time::Instant::now() >= deadline {
                        return Err(UploadWorkerError::Timeout);
                    }
                    writer
                        .write_chunk(&mut pinned_file, &chunk)
                        .map_err(LimitError::Filesystem)?;
                    if tokio::time::Instant::now() >= deadline {
                        return Err(UploadWorkerError::Timeout);
                    }
                    Ok(reserved_bytes)
                })();
                file = Some(pinned_file);
                if result.is_err() {
                    cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                }
                let success = result.is_ok();
                let delivered = response.send(result).is_ok();
                if !success || !delivered {
                    if claimed && !settled {
                        cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                    }
                    break;
                }
            }
            UploadWorkerCommand::Finish {
                actual_bytes,
                deadline,
                response,
            } => {
                let mut settlement_receipt = None;
                let result = if tokio::time::Instant::now() >= deadline {
                    Err(UploadWorkerError::Timeout)
                } else {
                    match file.as_mut() {
                        Some(pinned_file) => match pinned_file
                            .set_len(actual_bytes)
                            .map_err(LimitError::Filesystem)
                        {
                            Err(error) => Err(UploadWorkerError::Storage(error)),
                            Ok(()) if tokio::time::Instant::now() >= deadline => {
                                Err(UploadWorkerError::Timeout)
                            }
                            Ok(()) => match pinned_file.flush().map_err(LimitError::Filesystem) {
                                Err(error) => Err(UploadWorkerError::Storage(error)),
                                Ok(()) if tokio::time::Instant::now() >= deadline => {
                                    Err(UploadWorkerError::Timeout)
                                }
                                Ok(()) => match ledger.settle_pinned_until(
                                    session_id,
                                    &token,
                                    pinned_file,
                                    actual_bytes,
                                    deadline.into_std(),
                                ) {
                                    Ok(receipt) => {
                                        settlement_receipt = Some(receipt);
                                        Ok(())
                                    }
                                    Err(LimitError::OperationTimedOut) => {
                                        Err(UploadWorkerError::Timeout)
                                    }
                                    Err(LimitError::LateSettlementCompensationRequired(
                                        receipt,
                                    )) => {
                                        settlement_receipt = Some(receipt);
                                        Err(UploadWorkerError::Timeout)
                                    }
                                    Err(error) => Err(UploadWorkerError::Storage(error)),
                                },
                            },
                        },
                        None => Err(UploadWorkerError::Storage(LimitError::InvalidTransition)),
                    }
                };
                if let Some(receipt) = settlement_receipt {
                    let (successful, delivered) = match result {
                        Ok(()) => (true, response.send(Ok(()))),
                        Err(error) => (false, response.send(Err(error))),
                    };
                    if successful && delivered.is_ok() {
                        settled = true;
                        drop(file.take());
                    } else {
                        // A late commit or a completed commit whose HTTP
                        // waiter timed out is revoked before releasing the
                        // pinned handle. The durable compensation is retryable
                        // and remains covered by the tracked actor until complete.
                        while ledger
                            .compensate_late_settlement(session_id, &token, receipt)
                            .is_err()
                        {
                            thread::sleep(Duration::from_millis(25));
                        }
                        drop(file.take());
                    }
                } else {
                    let _ = response.send(result);
                    cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                }
                break;
            }
            UploadWorkerCommand::Abort(reply) => {
                cleanup_upload_worker(&ledger, session_id, &token, &mut file);
                if let Some(reply) = reply {
                    let _ = reply.send(());
                }
                break;
            }
        }
    }

    if !settled && claimed {
        cleanup_upload_worker(&ledger, session_id, &token, &mut file);
    }
    if let Ok(mut active) = active_uploads.lock() {
        active.remove(&session_id);
    }
}

fn cleanup_upload_worker(
    ledger: &UploadLedger,
    session_id: i64,
    token: &SessionToken,
    file: &mut Option<File>,
) {
    let _ = ledger.expire(session_id, token);
    let _ = ledger.reconcile_cleanup_jobs();
    drop(file.take());
}

async fn recover_upload_worker(state: &ServerState, session_id: i64, token: SessionToken) {
    let ledger = state.ledger.clone();
    let deadline = tokio::time::Instant::now() + state.storage_operation_timeout;
    let _ = run_storage(state, deadline, move || {
        match ledger.expire(session_id, &token) {
            Ok(()) => ledger.reconcile_cleanup_jobs(),
            Err(error) => Err(error),
        }
    })
    .await;
    if let Ok(mut active) = state.active_uploads.lock() {
        active.remove(&session_id);
    }
}

#[derive(Debug, Error)]
pub enum RouteConfigurationError {
    #[error("invalid server route configuration")]
    InvalidConfiguration,
    #[error("server route state is unavailable")]
    StorageUnavailable,
}

#[derive(Default)]
struct ResourceCatalog {
    jobs: HashMap<String, JobRecord>,
    artifacts: HashMap<String, ArtifactRecord>,
}

struct JobRecord {
    state: String,
}

#[derive(Clone)]
struct ArtifactRecord {
    path: PathBuf,
    filename: String,
    content_type: HeaderValue,
}

/// Builds the same HTTP handler as [`serve`] for in-process route tests.
pub fn router(
    state: ServerState,
) -> impl Clone
+ Service<Request<HttpBody>, Response = Response<HttpBody>, Error = Infallible>
+ Send
+ 'static {
    service_fn(move |request| {
        let state = state.clone();
        async move { Ok::<_, Infallible>(handle_request(request, state).await) }
    })
}

/// Accepts HTTP/1 connections and attaches each accepted socket's peer address
/// to its requests. Forwarding headers are never used as the transport identity.
pub async fn serve(listener: TcpListener, state: ServerState) -> io::Result<()> {
    serve_with_shutdown(listener, state, std::future::pending()).await
}

/// Serves HTTP/1 connections until `shutdown` resolves, then stops accepting,
/// drains connections and waits for tracked blocking workers within a grace
/// period. A non-cancellable worker past that deadline is reported explicitly.
pub async fn serve_with_shutdown<F>(
    listener: TcpListener,
    state: ServerState,
    shutdown: F,
) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let startup_ledger = state.ledger.clone();
    let startup_deadline = tokio::time::Instant::now() + state.storage_operation_timeout;
    let startup = run_storage(&state, startup_deadline, move || {
        startup_ledger.reconcile_expired_sessions()
    })
    .await;
    match startup {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => {
            return Err(io::Error::other(
                "upload session startup reconciliation failed",
            ));
        }
    }
    let mut maintenance = tokio::time::interval(SESSION_CLEANUP_INTERVAL);
    maintenance.tick().await;
    let connection_slots = Arc::new(Semaphore::new(state.max_connections));
    let mut connections = JoinSet::new();
    let mut shutdown = Box::pin(shutdown);
    let mut serve_error = None;
    'accept: loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                let permit = match Arc::clone(&connection_slots).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        drop(stream);
                        continue;
                    }
                };
                let connection_state = state.clone();
                let header_timeout = connection_state.header_read_timeout;
                connections.spawn(async move {
                    let _permit = permit;
                    let service = hyper_service_fn(move |request: Request<Incoming>| {
                        let state = connection_state.clone();
                        async move {
                            let mut request = request.map(|body| {
                                body.map_err(|error| Box::new(error) as BoxError)
                                    .boxed_unsync()
                            });
                            request.extensions_mut().insert(TransportPeer(peer));
                            Ok::<_, Infallible>(handle_request(request, state).await)
                        }
                    });
                    let mut builder = http1::Builder::new();
                    builder.timer(TokioTimer::new());
                    builder.header_read_timeout(header_timeout);
                    let _ = builder.serve_connection(TokioIo(stream), service).await;
                });
            }
            _ = maintenance.tick() => {
                let ledger = state.ledger.clone();
                let active = active_upload_ids(&state);
                let deadline = tokio::time::Instant::now() + state.storage_operation_timeout;
                match run_storage(&state, deadline, move || {
                    ledger.reconcile_expired_sessions_excluding(&active)
                }).await {
                    Ok(Ok(_)) => {}
                    Ok(Err(_)) | Err(_) => {
                        serve_error = Some(io::Error::other(
                            "upload session periodic reconciliation failed",
                        ));
                        break 'accept;
                    }
                }
            }
            _ = &mut shutdown => break 'accept,
            _ = connections.join_next(), if !connections.is_empty() => {}
        }
    }

    let shutdown_deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
    while !connections.is_empty() {
        match tokio::time::timeout_at(shutdown_deadline, connections.join_next()).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                break;
            }
        }
    }
    if !state
        .worker_tracker
        .wait_until_idle(shutdown_deadline)
        .await
    {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "server shutdown grace elapsed with non-cancellable storage workers still active",
        ));
    }
    if state.worker_tracker.has_failed_late_compensations() {
        return Err(io::Error::other(
            "server shutdown observed incomplete late storage compensation",
        ));
    }
    if let Some(error) = serve_error {
        return Err(error);
    }
    Ok(())
}

struct TokioIo<T>(T);

impl<T> HyperRead for TokioIo<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        mut buffer: ReadBufCursor<'_>,
    ) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        let filled = {
            let mut tokio_buffer = TokioReadBuf::uninit(unsafe { buffer.as_mut() });
            match Pin::new(&mut this.0).poll_read(context, &mut tokio_buffer) {
                Poll::Ready(Ok(())) => tokio_buffer.filled().len(),
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        };
        // SAFETY: Tokio's ReadBuf reports only bytes initialized by `poll_read`.
        unsafe { buffer.advance(filled) };
        Poll::Ready(Ok(()))
    }
}

impl<T> HyperWrite for TokioIo<T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_write(context, buffer)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_flush(context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(context)
    }
}

async fn handle_request(request: Request<HttpBody>, state: ServerState) -> Response<HttpBody> {
    let close_on_error = request.method() == Method::PUT;
    let result = dispatch(request, &state).await;
    let mut response = result.unwrap_or_else(error_response);
    if close_on_error && !response.status().is_success() {
        // A rejected upload body may still have unread frames. Closing the
        // HTTP/1 connection prevents Hyper from draining attacker-controlled
        // bytes before the error response can complete.
        response
            .headers_mut()
            .insert(CONNECTION, HeaderValue::from_static("close"));
    }
    add_common_headers(&mut response);
    response
}

async fn dispatch(
    request: Request<HttpBody>,
    state: &ServerState,
) -> Result<Response<HttpBody>, HttpError> {
    if is_state_changing(request.method())
        && !origin_matches(request.headers(), &state.public_origin)
    {
        return Err(PUBLIC_ORIGIN_ERROR);
    }
    if contains_url_credential(request.uri().path(), request.uri().query()) {
        return Err(HttpError::bad_request(
            "credential_in_url",
            "Credentials are not accepted in URL paths or queries.",
        ));
    }

    let method = request.method().as_str().to_owned();
    let path = request.uri().path().to_owned();
    let segments = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    match (method.as_str(), segments.as_slice()) {
        ("POST", ["v1", "upload-sessions"]) => create_upload_session(request, state).await,
        ("PUT", ["v1", "upload-sessions", session_id, "content"]) => {
            upload_content(request, state, session_id).await
        }
        ("GET", ["v1", "jobs", job_id, "events"]) => job_events(request, state, job_id),
        ("GET", ["v1", "jobs", job_id]) => job_status(request, state, job_id),
        ("DELETE", ["v1", "jobs", job_id]) => cancel_job(request, state, job_id),
        ("GET", ["v1", "artifacts", artifact_id, "download"]) => {
            download_artifact(request, state, artifact_id)
        }
        _ => Err(HttpError::not_found()),
    }
}

async fn create_upload_session(
    request: Request<HttpBody>,
    state: &ServerState,
) -> Result<Response<HttpBody>, HttpError> {
    let (parts, request_body) = request.into_parts();
    let body = collect_limited(request_body, MAX_BOOTSTRAP_BODY_BYTES).await?;
    let request_value: Value = serde_json::from_slice(&body)
        .map_err(|_| HttpError::bad_request("invalid_request", "The upload request is invalid."))?;
    let declared_bytes = parse_upload_request(&request_value)?;
    let peer = parts
        .extensions
        .get::<TransportPeer>()
        .copied()
        .ok_or(HttpError::bad_request(
            "client_ip_unavailable",
            "The client address could not be verified.",
        ))?;
    let client_ip = resolve_client_ip(peer.0.ip(), &parts.headers, &state.trusted_proxies)?;
    let expires_at = SystemTime::now()
        .checked_add(state.capability_ttl)
        .ok_or_else(HttpError::storage_unavailable)?;
    let ledger = state.ledger.clone();
    let late_ledger = state.ledger.clone();
    let client_ip = client_ip.to_string();
    let storage_deadline = tokio::time::Instant::now() + state.storage_operation_timeout;
    let deadline = storage_deadline.into_std();
    let (reservation, capability) = run_storage_with_late_completion(
        state,
        storage_deadline,
        move || {
            ledger.reserve_with_upload_capability_until(
                &client_ip,
                declared_bytes,
                expires_at,
                deadline,
            )
        },
        move |result| compensate_late_bootstrap_result(late_ledger, result),
    )
    .await
    .map_err(|error| match error {
        StorageTaskError::Timeout => UPLOAD_TIMEOUT_ERROR,
        StorageTaskError::Failed => HttpError::storage_unavailable(),
    })?
    .map_err(map_limit_error)?;

    Ok(json_response(
        StatusCode::CREATED,
        json!({
            "session_id": reservation.session_id,
            "capability": capability.token(),
            "expires_at": capability.expires_at_unix_seconds(),
        }),
    ))
}

async fn upload_content(
    request: Request<HttpBody>,
    state: &ServerState,
    session_id: &str,
) -> Result<Response<HttpBody>, HttpError> {
    let session_id = parse_session_id(session_id)?;
    let subject = format!("upload-session:{session_id}");
    let token = authorize_upload(request.headers(), state, &subject, Scope::Upload).await?;
    let session_token = SessionToken::parse(&token).map_err(map_limit_error)?;
    let max_file_bytes = state.ledger.max_file_bytes();
    let body = request.into_body();
    let started = tokio::time::Instant::now();
    let total_deadline = started
        .checked_add(state.upload_total_timeout)
        .ok_or_else(HttpError::storage_unavailable)?;
    let lease_duration = state.upload_lease_duration;
    let start_deadline =
        total_deadline.min(tokio::time::Instant::now() + state.storage_operation_timeout);
    let (worker, start_reply) = UploadWorker::start(
        state,
        session_id,
        session_token.clone(),
        lease_duration,
        start_deadline,
    )
    .await?;
    let received = async {
        await_upload_worker(start_reply, start_deadline).await?;
        let mut stream = body.into_data_stream();
        let mut actual_bytes = 0_u64;
        loop {
            let now = tokio::time::Instant::now();
            if now >= total_deadline {
                return Err(UPLOAD_TIMEOUT_ERROR);
            }
            let idle_deadline = now
                .checked_add(state.upload_idle_timeout)
                .unwrap_or(total_deadline)
                .min(total_deadline);
            let next = tokio::select! {
                biased;
                _ = tokio::time::sleep_until(idle_deadline) => return Err(UPLOAD_TIMEOUT_ERROR),
                next = stream.next() => next,
            };
            let Some(frame) = next else {
                break;
            };
            let chunk = match frame {
                Ok(chunk) => chunk,
                Err(error) => {
                    if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::TimedOut)
                    {
                        return Err(UPLOAD_TIMEOUT_ERROR);
                    }
                    return Err(UPLOAD_INTERRUPTED_ERROR);
                }
            };
            if tokio::time::Instant::now() >= total_deadline {
                return Err(UPLOAD_TIMEOUT_ERROR);
            }

            let chunk_bytes = u64::try_from(chunk.len())
                .map_err(|_| map_limit_error(LimitError::FileTooLarge))?;
            let next_total = actual_bytes
                .checked_add(chunk_bytes)
                .ok_or_else(|| map_limit_error(LimitError::FileTooLarge))?;
            if next_total > max_file_bytes {
                return Err(map_limit_error(LimitError::FileTooLarge));
            }
            let operation_deadline =
                total_deadline.min(tokio::time::Instant::now() + state.storage_operation_timeout);
            let response = worker.write(next_total, chunk, operation_deadline).await?;
            await_upload_worker(response, operation_deadline).await?;
            actual_bytes = next_total;
        }

        let operation_deadline =
            total_deadline.min(tokio::time::Instant::now() + state.storage_operation_timeout);
        let response = worker.finish(actual_bytes, operation_deadline).await?;
        await_upload_worker(response, operation_deadline).await?;
        Ok::<_, HttpError>(())
    }
    .await;

    match received {
        Ok(()) => Ok(empty_response(StatusCode::NO_CONTENT)),
        Err(error) => {
            // The actor still owns its pinned file and lease until any
            // non-cancellable syscall returns. Do not hold the HTTP response
            // open for cleanup once the upload deadline itself has elapsed.
            if error.code != UPLOAD_TIMEOUT_ERROR.code {
                let cleanup_deadline =
                    tokio::time::Instant::now() + state.storage_operation_timeout;
                let _ = worker.abort(cleanup_deadline).await;
            }
            Err(error)
        }
    }
}

async fn await_upload_worker<T>(
    receiver: oneshot::Receiver<Result<T, UploadWorkerError>>,
    deadline: tokio::time::Instant,
) -> Result<T, HttpError>
where
    T: Send + 'static,
{
    match tokio::time::timeout_at(deadline, receiver).await {
        Err(_) => Err(UPLOAD_TIMEOUT_ERROR),
        Ok(Err(_)) => Err(HttpError::storage_unavailable()),
        Ok(Ok(Ok(value))) => Ok(value),
        Ok(Ok(Err(UploadWorkerError::Timeout))) => Err(UPLOAD_TIMEOUT_ERROR),
        Ok(Ok(Err(UploadWorkerError::Storage(error)))) => Err(map_limit_error(error)),
    }
}

fn job_status(
    request: Request<HttpBody>,
    state: &ServerState,
    job_id: &str,
) -> Result<Response<HttpBody>, HttpError> {
    validate_resource_id(job_id)?;
    let subject = format!("job:{job_id}");
    authorize(request.headers(), state, &subject, Scope::Status)?;
    let status = state
        .resources
        .lock()
        .map_err(|_| HttpError::storage_unavailable())?
        .jobs
        .get(job_id)
        .map(|job| job.state.clone())
        .ok_or_else(HttpError::not_found)?;
    Ok(json_response(
        StatusCode::OK,
        json!({"job_id": job_id, "state": status}),
    ))
}

fn job_events(
    request: Request<HttpBody>,
    state: &ServerState,
    job_id: &str,
) -> Result<Response<HttpBody>, HttpError> {
    validate_resource_id(job_id)?;
    let subject = format!("job:{job_id}");
    authorize(request.headers(), state, &subject, Scope::Events)?;
    let status = state
        .resources
        .lock()
        .map_err(|_| HttpError::storage_unavailable())?
        .jobs
        .get(job_id)
        .map(|job| job.state.clone())
        .ok_or_else(HttpError::not_found)?;
    let event = format!(
        "id: 1\nevent: job.state_changed\ndata: {}\n\n",
        json!({"job_id": job_id, "state": status})
    );
    let mut response = Response::new(full_body(Bytes::from(event)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    Ok(response)
}

fn cancel_job(
    request: Request<HttpBody>,
    state: &ServerState,
    job_id: &str,
) -> Result<Response<HttpBody>, HttpError> {
    validate_resource_id(job_id)?;
    let subject = format!("job:{job_id}");
    authorize(request.headers(), state, &subject, Scope::Cancel)?;
    let mut resources = state
        .resources
        .lock()
        .map_err(|_| HttpError::storage_unavailable())?;
    let job = resources
        .jobs
        .get_mut(job_id)
        .ok_or_else(HttpError::not_found)?;
    job.state = "cancelled".to_owned();
    Ok(empty_response(StatusCode::ACCEPTED))
}

fn download_artifact(
    request: Request<HttpBody>,
    state: &ServerState,
    artifact_id: &str,
) -> Result<Response<HttpBody>, HttpError> {
    validate_resource_id(artifact_id)?;
    let subject = format!("artifact:{artifact_id}");
    authorize(request.headers(), state, &subject, Scope::Download)?;
    let artifact = state
        .resources
        .lock()
        .map_err(|_| HttpError::storage_unavailable())?
        .artifacts
        .get(artifact_id)
        .cloned()
        .ok_or_else(HttpError::not_found)?;
    let bytes = std::fs::read(&artifact.path).map_err(|_| HttpError::storage_unavailable())?;
    let mut response = Response::new(full_body(Bytes::from(bytes)));
    *response.status_mut() = StatusCode::OK;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, artifact.content_type);
    response.headers_mut().insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", artifact.filename))
            .map_err(|_| HttpError::storage_unavailable())?,
    );
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    Ok(response)
}

fn authorize(
    headers: &HeaderMap,
    state: &ServerState,
    subject: &str,
    scope: Scope,
) -> Result<String, HttpError> {
    let token = bearer_token(headers)?;
    Capability::verify(&state.capabilities, &token, subject, scope)
        .map_err(map_capability_error)?;
    Ok(token)
}

async fn authorize_upload(
    headers: &HeaderMap,
    state: &ServerState,
    subject: &str,
    scope: Scope,
) -> Result<String, HttpError> {
    let token = bearer_token(headers)?;
    let store = state.capabilities.clone();
    let token_for_verification = token.clone();
    let subject = subject.to_owned();
    let deadline = tokio::time::Instant::now() + state.storage_operation_timeout;
    match run_storage(state, deadline, move || {
        Capability::verify(&store, &token_for_verification, &subject, scope)
    })
    .await
    {
        Ok(Ok(_)) => Ok(token),
        Ok(Err(error)) => Err(map_capability_error(error)),
        Err(StorageTaskError::Timeout) => Err(HttpError::storage_unavailable()),
        Err(StorageTaskError::Failed) => Err(HttpError::storage_unavailable()),
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<String, HttpError> {
    let values = headers.get_all(AUTHORIZATION).iter().collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(HttpError::unauthorized());
    }
    let value = values[0].to_str().map_err(|_| HttpError::unauthorized())?;
    let (scheme, token) = value.split_once(' ').ok_or_else(HttpError::unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.contains(char::is_whitespace)
        || !crate::auth::is_canonical_capability_token(token)
    {
        return Err(HttpError::unauthorized());
    }
    Ok(token.to_owned())
}

fn parse_upload_request(value: &Value) -> Result<Option<u64>, HttpError> {
    let object = value.as_object().ok_or_else(|| {
        HttpError::bad_request("invalid_request", "The upload request is invalid.")
    })?;
    let target = object.get("output_target").ok_or_else(|| {
        HttpError::bad_request(
            "managed_artifact_only",
            "Web uploads can only create managed artifacts.",
        )
    })?;
    let managed = target.as_str() == Some("managed_artifact")
        || target
            .get("type")
            .and_then(Value::as_str)
            .is_some_and(|kind| kind == "managed_artifact");
    if !managed || contains_local_path(value) {
        return Err(HttpError::bad_request(
            "managed_artifact_only",
            "Web uploads can only create managed artifacts.",
        ));
    }
    match object.get("declared_bytes") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_u64().map(Some).ok_or_else(|| {
            HttpError::bad_request("invalid_request", "The upload request is invalid.")
        }),
    }
}

fn contains_local_path(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "path" | "local_path" | "filesystem_path" | "output_path" | "local_directory"
            ) || contains_local_path(value)
        }),
        Value::Array(values) => values.iter().any(contains_local_path),
        _ => false,
    }
}

async fn collect_limited(mut body: HttpBody, limit: usize) -> Result<Vec<u8>, HttpError> {
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            HttpError::bad_request("invalid_request", "The upload request is invalid.")
        })?;
        if let Some(data) = frame.data_ref() {
            if bytes.len().saturating_add(data.len()) > limit {
                return Err(HttpError::bad_request(
                    "invalid_request",
                    "The upload request is too large.",
                ));
            }
            bytes.extend_from_slice(data);
        }
    }
    Ok(bytes)
}

fn origin_matches(headers: &HeaderMap, expected: &str) -> bool {
    let values = headers.get_all(ORIGIN).iter().collect::<Vec<_>>();
    values.len() == 1 && values[0].to_str().is_ok_and(|origin| origin == expected)
}

fn is_state_changing(method: &Method) -> bool {
    method == Method::POST || method == Method::PUT || method == Method::DELETE
}

fn contains_url_credential(path: &str, query: Option<&str>) -> bool {
    if query.is_some() || path.contains('%') {
        return true;
    }
    path.split('/')
        .any(crate::auth::is_canonical_capability_token)
}

fn resolve_client_ip(
    peer: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpCidr],
) -> Result<IpAddr, HttpError> {
    if !trusted_proxies.iter().any(|cidr| cidr.contains(peer)) {
        return Ok(peer);
    }

    let mut forwarded_values = headers.get_all(FORWARDED).iter();
    let forwarded = forwarded_values.next();
    if forwarded_values.next().is_some() {
        return Err(INVALID_FORWARDED_ERROR);
    }
    let mut x_forwarded_for_values = headers.get_all("x-forwarded-for").iter();
    let x_forwarded_for = x_forwarded_for_values.next();
    if x_forwarded_for_values.next().is_some() {
        return Err(INVALID_FORWARDED_ERROR);
    }
    if forwarded.is_none() && x_forwarded_for.is_none() {
        return Ok(peer);
    }
    if forwarded.is_some() && x_forwarded_for.is_some() {
        return Err(INVALID_FORWARDED_ERROR);
    }
    let header_bytes = forwarded
        .map_or(0, |value| value.as_bytes().len())
        .saturating_add(x_forwarded_for.map_or(0, |value| value.as_bytes().len()));
    if header_bytes > MAX_FORWARDED_HEADER_BYTES {
        return Err(OVERSIZED_FORWARDING_ERROR);
    }
    let chain = if let Some(value) = forwarded {
        parse_forwarded(value.to_str().map_err(|_| INVALID_FORWARDED_ERROR)?)?
    } else {
        let value = x_forwarded_for.ok_or(INVALID_FORWARDED_ERROR)?;
        parse_x_forwarded_for(value.to_str().map_err(|_| INVALID_FORWARDED_ERROR)?)?
    };
    if chain.is_empty() {
        return Err(INVALID_FORWARDED_ERROR);
    }

    // Proxy chains are listed client-first. Walk from the socket peer toward
    // the client, skipping trusted proxy hops; the first untrusted address is
    // the quota identity. Any remaining left-side entries are ignored.
    chain
        .into_iter()
        .rev()
        .chain(std::iter::once(peer))
        .find(|address| !trusted_proxies.iter().any(|cidr| cidr.contains(*address)))
        .ok_or(INVALID_FORWARDED_ERROR)
}

fn parse_x_forwarded_for(value: &str) -> Result<Vec<IpAddr>, HttpError> {
    let mut chain = Vec::with_capacity(MAX_FORWARDED_HOPS);
    for (index, address) in value.split(',').enumerate() {
        if index == MAX_FORWARDED_HOPS {
            return Err(TOO_MANY_FORWARDING_HOPS_ERROR);
        }
        let address = address.trim();
        if address.is_empty() {
            return Err(INVALID_FORWARDED_ERROR);
        }
        chain.push(address.parse().map_err(|_| INVALID_FORWARDED_ERROR)?);
    }
    Ok(chain)
}

fn parse_forwarded(value: &str) -> Result<Vec<IpAddr>, HttpError> {
    // Accept only one unquoted `for=IP[:port]` parameter per element; reject
    // proto/by/extensions so each chain has one unambiguous parse.
    let mut chain = Vec::with_capacity(MAX_FORWARDED_HOPS);
    for (index, element) in value.split(',').enumerate() {
        if index == MAX_FORWARDED_HOPS {
            return Err(TOO_MANY_FORWARDING_HOPS_ERROR);
        }
        let mut for_value = None;
        for parameter in element.split(';') {
            let (name, value) = parameter
                .trim()
                .split_once('=')
                .ok_or(INVALID_FORWARDED_ERROR)?;
            if !name.eq_ignore_ascii_case("for") || for_value.is_some() {
                return Err(INVALID_FORWARDED_ERROR);
            }
            let value = value.trim();
            if value.is_empty() || value.starts_with('"') || value.ends_with('"') {
                return Err(INVALID_FORWARDED_ERROR);
            }
            for_value = Some(parse_forwarded_node(value)?);
        }
        chain.push(for_value.ok_or(INVALID_FORWARDED_ERROR)?);
    }
    Ok(chain)
}

fn parse_forwarded_node(value: &str) -> Result<IpAddr, HttpError> {
    if let Ok(address) = value.parse::<IpAddr>() {
        return Ok(address);
    }
    if let Some(after_open) = value.strip_prefix('[') {
        let (address, suffix) = after_open.split_once(']').ok_or(INVALID_FORWARDED_ERROR)?;
        let address = address
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| INVALID_FORWARDED_ERROR)?;
        if !suffix.is_empty() {
            let port = suffix
                .strip_prefix(':')
                .ok_or(INVALID_FORWARDED_ERROR)?
                .parse::<u16>()
                .map_err(|_| INVALID_FORWARDED_ERROR)?;
            if port == 0 {
                return Err(INVALID_FORWARDED_ERROR);
            }
        }
        return Ok(IpAddr::V6(address));
    }
    if let Some((address, port)) = value.rsplit_once(':')
        && let Ok(address) = address.parse::<std::net::Ipv4Addr>()
    {
        let port = port.parse::<u16>().map_err(|_| INVALID_FORWARDED_ERROR)?;
        if port == 0 {
            return Err(INVALID_FORWARDED_ERROR);
        }
        return Ok(IpAddr::V4(address));
    }
    Err(INVALID_FORWARDED_ERROR)
}

#[derive(Clone, Copy)]
struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl FromStr for IpCidr {
    type Err = RouteConfigurationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() > MAX_CIDR_TEXT_BYTES {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        let (address, prefix) = value
            .split_once('/')
            .ok_or(RouteConfigurationError::InvalidConfiguration)?;
        let network = address
            .parse::<IpAddr>()
            .map_err(|_| RouteConfigurationError::InvalidConfiguration)?;
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| RouteConfigurationError::InvalidConfiguration)?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(RouteConfigurationError::InvalidConfiguration);
        }
        Ok(Self { network, prefix })
    }
}

impl IpCidr {
    fn contains(self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let shift = 32 - u32::from(self.prefix);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << shift
                };
                u32::from(network) & mask == u32::from(address) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let shift = 128 - u32::from(self.prefix);
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << shift
                };
                u128::from(network) & mask == u128::from(address) & mask
            }
            _ => false,
        }
    }
}

fn validate_public_origin(value: &str) -> Result<(), RouteConfigurationError> {
    if !(value.starts_with("https://") || value.starts_with("http://"))
        || value.contains('/') && value.matches('/').count() != 2
        || value.contains(['?', '#', '@'])
        || value.len() > 512
    {
        return Err(RouteConfigurationError::InvalidConfiguration);
    }
    let authority = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or(RouteConfigurationError::InvalidConfiguration)?;
    if authority.is_empty()
        || authority.parse::<hyper::http::uri::Authority>().is_err()
        || authority.chars().any(char::is_whitespace)
    {
        return Err(RouteConfigurationError::InvalidConfiguration);
    }
    HeaderValue::from_str(value).map_err(|_| RouteConfigurationError::InvalidConfiguration)?;
    Ok(())
}

fn parse_session_id(value: &str) -> Result<i64, HttpError> {
    let id = value.parse::<i64>().map_err(|_| HttpError::not_found())?;
    if id <= 0 {
        return Err(HttpError::not_found());
    }
    Ok(id)
}

fn validate_resource_id(id: &str) -> Result<(), HttpError> {
    if valid_resource_id(id) {
        Ok(())
    } else {
        Err(HttpError::not_found())
    }
}

fn valid_resource_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn safe_download_filename(filename: &str) -> String {
    let leaf = filename.rsplit(['/', '\\']).next().unwrap_or("download");
    let sanitized = leaf
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | ' ') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim()
        .trim_matches('.')
        .to_owned();
    if sanitized.is_empty() {
        "download".to_owned()
    } else {
        sanitized
    }
}

fn map_capability_error(error: CapabilityError) -> HttpError {
    match error {
        CapabilityError::Unauthorized => HttpError::unauthorized(),
        CapabilityError::Expired => HttpError {
            status: StatusCode::UNAUTHORIZED,
            code: "capability_expired",
            message: "The capability has expired.",
        },
        CapabilityError::InsufficientScope => HttpError {
            status: StatusCode::FORBIDDEN,
            code: "insufficient_scope",
            message: "The capability does not allow this action.",
        },
        CapabilityError::SubjectMismatch => HttpError {
            status: StatusCode::FORBIDDEN,
            code: "capability_subject_mismatch",
            message: "The capability is not valid for this resource.",
        },
        CapabilityError::InvalidConfiguration | CapabilityError::RandomUnavailable => {
            HttpError::storage_unavailable()
        }
        CapabilityError::Storage(_) => HttpError::storage_unavailable(),
    }
}

fn map_limit_error(error: LimitError) -> HttpError {
    match error {
        LimitError::OperationTimedOut => UPLOAD_TIMEOUT_ERROR,
        LimitError::Unauthorized => HttpError::unauthorized(),
        LimitError::UnknownSession => HttpError::not_found(),
        LimitError::InvalidTransition => HttpError {
            status: StatusCode::CONFLICT,
            code: "invalid_state",
            message: "The request cannot be completed in the current state.",
        },
        LimitError::FileTooLarge => HttpError {
            status: StatusCode::PAYLOAD_TOO_LARGE,
            code: "file_too_large",
            message: "The upload exceeds the configured size limit.",
        },
        LimitError::DailyQuotaExceeded
        | LimitError::SessionLimitExceeded
        | LimitError::GlobalCapacityExceeded
        | LimitError::DiskSafetyMargin => HttpError {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "quota_exceeded",
            message: "The upload quota is unavailable.",
        },
        LimitError::InvalidIp => HttpError::bad_request(
            "client_ip_unavailable",
            "The client address could not be verified.",
        ),
        LimitError::InvalidSize => {
            HttpError::bad_request("invalid_request", "The upload request is invalid.")
        }
        _ => HttpError::storage_unavailable(),
    }
}

#[derive(Clone, Copy)]
struct HttpError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl HttpError {
    fn unauthorized() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: "A valid capability is required.",
        }
    }

    fn bad_request(code: &'static str, message: &'static str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code,
            message,
        }
    }

    fn not_found() -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: "The requested resource was not found.",
        }
    }

    fn storage_unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "storage_unavailable",
            message: "The request could not be completed.",
        }
    }
}

fn error_response(error: HttpError) -> Response<HttpBody> {
    json_response(
        error.status,
        json!({
            "error": {
                "code": error.code,
                "message": error.message,
                "diagnostic_id": Uuid::new_v4().to_string(),
            }
        }),
    )
}

fn json_response(status: StatusCode, value: Value) -> Response<HttpBody> {
    let mut response = Response::new(full_body(Bytes::from(
        serde_json::to_vec(&value).unwrap_or_else(|_| b"{}".to_vec()),
    )));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/json; charset=utf-8"),
    );
    response
}

fn empty_response(status: StatusCode) -> Response<HttpBody> {
    let mut response = Response::new(full_body(Bytes::new()));
    *response.status_mut() = status;
    response
}

fn full_body(bytes: Bytes) -> HttpBody {
    Full::new(bytes)
        .map_err(|never| -> BoxError { match never {} })
        .boxed_unsync()
}

fn add_common_headers(response: &mut Response<HttpBody>) {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    response
        .headers_mut()
        .insert(CONTENT_SECURITY_POLICY, HeaderValue::from_static(CSP));
}

#[cfg(test)]
mod late_completion_tests {
    use super::*;
    use crate::ledger::LedgerLimits;
    use rusqlite::Connection;
    use std::sync::Barrier;

    fn test_state() -> (tempfile::TempDir, UploadLedger, ServerState) {
        let temp = tempfile::tempdir().unwrap();
        let database_path = temp.path().join("ledger.sqlite3");
        let upload_root = temp.path().join("uploads");
        std::fs::create_dir(&upload_root).unwrap();
        let ledger = UploadLedger::open(
            &database_path,
            &upload_root,
            LedgerLimits {
                max_file_bytes: 4,
                daily_quota_bytes: 20,
                max_active_sessions_per_ip: 4,
                max_global_reserved_bytes: 20,
                disk_safety_margin_bytes: 0,
            },
            vec![[0xA1; 32]],
        )
        .unwrap();
        let capabilities = CapabilityStore::open(&database_path).unwrap();
        let state = ServerState::new(
            ledger.clone(),
            capabilities,
            "https://flux.test",
            vec![],
            Duration::from_secs(60),
        )
        .unwrap();
        (temp, ledger, state)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn committed_bootstrap_after_timeout_is_compensated_by_late_completion() {
        let (temp, ledger, state) = test_state();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let operation_ledger = ledger.clone();
        let late_ledger = ledger.clone();
        let operation_entered = Arc::clone(&entered);
        let operation_release = Arc::clone(&release);
        let (compensated, compensation_result) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let worker = run_storage_with_late_completion(
            &state,
            deadline,
            move || {
                let result = operation_ledger.reserve_with_upload_capability(
                    "192.0.2.10",
                    Some(1),
                    SystemTime::now() + Duration::from_secs(60),
                );
                operation_entered.wait();
                operation_release.wait();
                result
            },
            move |result| async move {
                let succeeded = match result {
                    Ok((reservation, _)) => {
                        let session_id = reservation.session_id;
                        let token = reservation.session_token;
                        matches!(
                            tokio::task::spawn_blocking(move || {
                                late_ledger.compensate_late_reservation(session_id, &token)
                            })
                            .await,
                            Ok(Ok(()))
                        )
                    }
                    Err(_) => false,
                };
                let _ = compensated.send(succeeded);
                succeeded
            },
        );
        tokio::pin!(worker);
        let entered_wait = tokio::task::spawn_blocking(move || entered.wait());
        tokio::select! {
            _ = &mut worker => panic!("storage timed out before entering gate"),
            _ = entered_wait => {}
        }
        assert!(matches!(worker.await, Err(StorageTaskError::Timeout)));
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), compensation_result)
                .await
                .expect("late successful result must trigger compensation")
                .unwrap()
        );

        assert_eq!(ledger.reserved_bytes().unwrap(), 0);
        let (state_name, relative_path, expires_at): (String, String, i64) =
            Connection::open(ledger.database_path())
                .unwrap()
                .query_row(
                    "SELECT uploads.state, uploads.upload_path, capabilities.expires_at \
                     FROM uploads JOIN capabilities ON capabilities.token_hash = uploads.capability_hash",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
        assert_eq!(state_name, "expired");
        assert_eq!(expires_at, 0);
        assert!(!temp.path().join("uploads").join(relative_path).exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn bootstrap_compensation_required_result_is_retried_after_timeout() {
        let (temp, ledger, state) = test_state();
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let operation_ledger = ledger.clone();
        let late_ledger = ledger.clone();
        let operation_entered = Arc::clone(&entered);
        let operation_release = Arc::clone(&release);
        let (compensated, compensation_result) = oneshot::channel();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(100);
        let worker = run_storage_with_late_completion(
            &state,
            deadline,
            move || -> Result<(UploadReservation, Capability), LimitError> {
                let (reservation, _capability) = operation_ledger
                    .reserve_with_upload_capability(
                        "192.0.2.10",
                        Some(1),
                        SystemTime::now() + Duration::from_secs(60),
                    )
                    .unwrap();
                operation_entered.wait();
                operation_release.wait();
                Err(LimitError::LateReservationCompensationRequired {
                    session_id: reservation.session_id,
                    capability: reservation.session_token,
                })
            },
            move |result| async move {
                let succeeded = compensate_late_bootstrap_result(late_ledger, result).await;
                let _ = compensated.send(succeeded);
                succeeded
            },
        );
        tokio::pin!(worker);
        let entered_wait = tokio::task::spawn_blocking(move || entered.wait());
        tokio::select! {
            _ = &mut worker => panic!("storage timed out before entering gate"),
            _ = entered_wait => {}
        }
        assert!(matches!(worker.await, Err(StorageTaskError::Timeout)));
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(3), compensation_result)
                .await
                .expect("late compensation marker must trigger a retry")
                .unwrap()
        );

        assert_eq!(ledger.reserved_bytes().unwrap(), 0);
        let (state_name, relative_path, expires_at): (String, String, i64) =
            Connection::open(ledger.database_path())
                .unwrap()
                .query_row(
                    "SELECT uploads.state, uploads.upload_path, capabilities.expires_at \
                     FROM uploads JOIN capabilities ON capabilities.token_hash = uploads.capability_hash",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
        assert_eq!(state_name, "expired");
        assert_eq!(expires_at, 0);
        assert!(!temp.path().join("uploads").join(relative_path).exists());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn dropped_finish_receiver_revokes_a_committed_settlement() {
        let (_temp, ledger, state) = test_state();
        let (reservation, _capability) = ledger
            .reserve_with_upload_capability(
                "192.0.2.10",
                Some(1),
                SystemTime::now() + Duration::from_secs(60),
            )
            .unwrap();
        let session_id = reservation.session_id;
        let token = reservation.session_token;
        let upload_path = reservation.upload_path;
        let (claimed_sender, claimed) = oneshot::channel();
        let context = UploadWorkerContext {
            ledger: ledger.clone(),
            writer: Arc::clone(&state.upload_chunk_writer),
            active_uploads: Arc::clone(&state.active_uploads),
            session_id,
            token: token.clone(),
            lease_duration: Duration::from_secs(30),
            claimed_sender,
        };
        let (commands, receiver) = mpsc::channel(4);
        let actor = thread::spawn(move || run_upload_worker(context, receiver));
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        let (start_reply, start_result) = oneshot::channel();
        commands
            .send(UploadWorkerCommand::Start {
                deadline,
                response: start_reply,
            })
            .await
            .unwrap();
        assert!(matches!(start_result.await.unwrap(), Ok(1)));
        claimed.await.unwrap();

        let (write_reply, write_result) = oneshot::channel();
        commands
            .send(UploadWorkerCommand::Write {
                required_total: 1,
                chunk: Bytes::from_static(b"x"),
                deadline,
                response: write_reply,
            })
            .await
            .unwrap();
        assert!(matches!(write_result.await.unwrap(), Ok(1)));

        let (finish_reply, finish_result) = oneshot::channel();
        drop(finish_result);
        commands
            .send(UploadWorkerCommand::Finish {
                actual_bytes: 1,
                deadline,
                response: finish_reply,
            })
            .await
            .unwrap();
        drop(commands);
        tokio::task::spawn_blocking(move || actor.join().unwrap())
            .await
            .unwrap();

        assert_eq!(
            ledger.state(session_id, &token).unwrap(),
            crate::ledger::UploadState::Expired
        );
        assert_eq!(ledger.reserved_bytes().unwrap(), 0);
        assert!(!upload_path.exists());
        let used: i64 = Connection::open(ledger.database_path())
            .unwrap()
            .query_row(
                "SELECT COALESCE(SUM(used_bytes), 0) FROM daily_usage",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(used, 0);
    }
}
