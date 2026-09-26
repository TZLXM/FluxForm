use std::collections::HashMap;
use std::convert::Infallible;
use std::error::Error;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::header::{
    AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_SECURITY_POLICY, CONTENT_TYPE,
    FORWARDED, HeaderMap, HeaderValue, ORIGIN, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Method, Request, Response, StatusCode};
use serde_json::{Value, json};
use thiserror::Error;
use tower::Service;
use tower::service_fn;
use uuid::Uuid;

use crate::auth::{Capability, CapabilityError, CapabilityStore, Scope};
use crate::ledger::{LimitError, SessionToken, UploadLedger};

const MAX_BOOTSTRAP_BODY_BYTES: usize = 16 * 1024;
const MAX_FORWARDED_HOPS: usize = 8;
const MAX_TRUSTED_PROXY_CIDRS: usize = 64;
const MAX_CIDR_TEXT_BYTES: usize = 64;
const CSP: &str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const PUBLIC_ORIGIN_ERROR: HttpError = HttpError {
    status: StatusCode::FORBIDDEN,
    code: "origin_denied",
    message: "The request origin is not allowed.",
};
const INVALID_FORWARDED_ERROR: HttpError = HttpError {
    status: StatusCode::BAD_REQUEST,
    code: "invalid_forwarded_chain",
    message: "The forwarded client address is invalid.",
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;
pub type HttpBody = UnsyncBoxBody<Bytes, BoxError>;

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
            resources: Arc::new(Mutex::new(ResourceCatalog::default())),
        })
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

/// Builds the production HTTP service used by the server and in-process route tests.
/// The network adapter must insert [`TransportPeer`] from the accepted socket.
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

async fn handle_request(request: Request<HttpBody>, state: ServerState) -> Response<HttpBody> {
    let result = dispatch(request, &state).await;
    let mut response = result.unwrap_or_else(error_response);
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
            upload_content(request, state, session_id)
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
    let reservation = state
        .ledger
        .reserve(&client_ip.to_string(), declared_bytes)
        .map_err(map_limit_error)?;
    let subject = format!("upload-session:{}", reservation.session_id);
    let capability = match Capability::issue(
        &state.capabilities,
        subject,
        [Scope::Upload],
        SystemTime::now()
            .checked_add(state.capability_ttl)
            .ok_or_else(HttpError::storage_unavailable)?,
    ) {
        Ok(capability) => capability,
        Err(_) => {
            let _ = state
                .ledger
                .expire(reservation.session_id, &reservation.session_token);
            return Err(HttpError::storage_unavailable());
        }
    };
    let replacement = SessionToken::parse(capability.token()).map_err(map_limit_error)?;
    if state
        .ledger
        .bind_session_token(
            reservation.session_id,
            &reservation.session_token,
            &replacement,
        )
        .is_err()
    {
        let _ = state.capabilities.revoke(capability.token());
        let _ = state
            .ledger
            .expire(reservation.session_id, &reservation.session_token);
        return Err(HttpError::storage_unavailable());
    }

    Ok(json_response(
        StatusCode::CREATED,
        json!({
            "session_id": reservation.session_id,
            "capability": capability.token(),
            "expires_at": capability.expires_at_unix_seconds(),
        }),
    ))
}

fn upload_content(
    request: Request<HttpBody>,
    state: &ServerState,
    session_id: &str,
) -> Result<Response<HttpBody>, HttpError> {
    let session_id = parse_session_id(session_id)?;
    let subject = format!("upload-session:{session_id}");
    let token = authorize(request.headers(), state, &subject, Scope::Upload)?;
    let session_token = SessionToken::parse(&token).map_err(map_limit_error)?;
    state
        .ledger
        .transition(session_id, &session_token, crate::UploadState::Receiving)
        .map_err(map_limit_error)?;
    Ok(empty_response(StatusCode::NO_CONTENT))
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

    let forwarded = headers.get_all(FORWARDED).iter().collect::<Vec<_>>();
    let x_forwarded_for = headers
        .get_all("x-forwarded-for")
        .iter()
        .collect::<Vec<_>>();
    if forwarded.is_empty() && x_forwarded_for.is_empty() {
        return Ok(peer);
    }
    if forwarded.len() > 1
        || x_forwarded_for.len() > 1
        || (!forwarded.is_empty() && !x_forwarded_for.is_empty())
    {
        return Err(INVALID_FORWARDED_ERROR);
    }
    let chain = if let Some(value) = forwarded.first() {
        parse_forwarded(value.to_str().map_err(|_| INVALID_FORWARDED_ERROR)?)?
    } else {
        parse_x_forwarded_for(
            x_forwarded_for[0]
                .to_str()
                .map_err(|_| INVALID_FORWARDED_ERROR)?,
        )?
    };
    if chain.is_empty() || chain.len() > MAX_FORWARDED_HOPS {
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
    value
        .split(',')
        .map(|address| {
            let address = address.trim();
            if address.is_empty() {
                return Err(INVALID_FORWARDED_ERROR);
            }
            address.parse().map_err(|_| INVALID_FORWARDED_ERROR)
        })
        .collect()
}

fn parse_forwarded(value: &str) -> Result<Vec<IpAddr>, HttpError> {
    // Accept only one unquoted `for=IP[:port]` parameter per element; reject
    // proto/by/extensions so each chain has one unambiguous parse.
    value
        .split(',')
        .map(|element| {
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
            for_value.ok_or(INVALID_FORWARDED_ERROR)
        })
        .collect()
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
