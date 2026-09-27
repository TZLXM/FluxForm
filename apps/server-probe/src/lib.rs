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
