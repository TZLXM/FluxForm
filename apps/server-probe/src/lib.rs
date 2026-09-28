//! Release consumers must not construct the server's route state directly.
//!
//! ```compile_fail
//! use fluxform_server_probe::auth::CapabilityStore;
//! use fluxform_server_probe::routes::ServerState;
//! use fluxform_server_probe::UploadLedger;
//! use std::time::Duration;
//! fn construct(ledger: UploadLedger, capabilities: CapabilityStore) {
//!     let _ = ServerState::new(
//!         ledger,
//!         capabilities,
//!         "https://example.test",
//!         Vec::new(),
//!         Duration::from_secs(1),
//!     );
//! }
//! ```
//!
//! Prepared state stays owned by the object that applies the authorization
//! gates and the configured bind address.
//!
//! ```compile_fail
//! use fluxform_server_probe::startup::PreparedServer;
//! fn extract_state(server: &PreparedServer) {
//!     let _ = server.state();
//! }
//! ```
//!
//! Raw routing and listener adapters are not a supported downstream API.
//!
//! ```compile_fail
//! let _raw_router = fluxform_server_probe::routes::router;
//! ```
//!
//! ```compile_fail
//! let _raw_listener_adapter = fluxform_server_probe::routes::serve_with_shutdown;
//! ```
//!
//! Transport peer identity may only be installed by the accepted-socket
//! adapter, never fabricated by a caller.
//!
//! ```compile_fail
//! use fluxform_server_probe::routes::TransportPeer;
//! let _forged = TransportPeer(std::net::SocketAddr::from(([127, 0, 0, 1], 43123)));
//! ```

#[cfg(test)]
extern crate self as fluxform_server_probe;

pub mod auth;
pub mod events;
mod ledger;
pub mod routes;
/// Startup's public surface intentionally does not permit a downstream
/// checker to authorize Public mode.
///
/// ```compile_fail
/// use fluxform_server_probe::startup::{
///     prepare_server, PreparedServer, ServerConfig, StartupError,
/// };
/// struct AlwaysPass;
/// fn bypass(config: ServerConfig) -> Result<PreparedServer, StartupError> {
///     prepare_server(config, &AlwaysPass)
/// }
/// ```
pub mod startup;

pub use ledger::{
    CleanupReport, DiskSpaceProvider, LedgerLimits, LimitError, SessionToken, SystemDiskSpace,
    UploadLedger, UploadReservation, UploadState,
};

#[cfg(test)]
#[path = "../tests/capability_auth.rs"]
mod capability_auth_integration;
#[cfg(test)]
#[path = "../tests/sse_recovery.rs"]
mod sse_recovery_integration;
#[cfg(test)]
#[path = "../tests/upload_http.rs"]
mod upload_http_integration;
