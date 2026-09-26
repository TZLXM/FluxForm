use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use fluxform_server_probe::auth::CapabilityStore;
use fluxform_server_probe::routes::{ServerState, serve};
use fluxform_server_probe::{LedgerLimits, UploadLedger};
use tokio::net::TcpListener;

const DEFAULT_LISTEN_ADDRESS: &str = "127.0.0.1:43123";
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const DAILY_QUOTA_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ACTIVE_SESSIONS_PER_IP: u32 = 4;
const MAX_GLOBAL_RESERVED_BYTES: u64 = 1024 * 1024 * 1024;
const DISK_SAFETY_MARGIN_BYTES: u64 = 1024 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listen_address = env::var("FLUXFORM_SERVER_LISTEN")
        .unwrap_or_else(|_| DEFAULT_LISTEN_ADDRESS.to_owned())
        .parse::<SocketAddr>()?;
    if !listen_address.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the server probe only supports loopback local-development binding",
        )
        .into());
    }

    let data_root = PathBuf::from(required_environment("FLUXFORM_SERVER_DATA_DIR")?);
    fs::create_dir_all(&data_root)?;
    let upload_root = data_root.join("uploads");
    fs::create_dir_all(&upload_root)?;
    let database_path = data_root.join("server.sqlite3");
    let secret = parse_secret(&required_environment("FLUXFORM_SERVER_SECRET")?)?;
    let ledger = UploadLedger::open(
        &database_path,
        &upload_root,
        LedgerLimits {
            max_file_bytes: MAX_FILE_BYTES,
            daily_quota_bytes: DAILY_QUOTA_BYTES,
            max_active_sessions_per_ip: MAX_ACTIVE_SESSIONS_PER_IP,
            max_global_reserved_bytes: MAX_GLOBAL_RESERVED_BYTES,
            disk_safety_margin_bytes: DISK_SAFETY_MARGIN_BYTES,
        },
        vec![secret],
    )?;
    let capabilities = CapabilityStore::open(&database_path)?;
    let public_origin =
        env::var("FLUXFORM_PUBLIC_ORIGIN").unwrap_or_else(|_| format!("http://{listen_address}"));
    let state = ServerState::new(
        ledger,
        capabilities,
        public_origin,
        Vec::new(),
        Duration::from_secs(60 * 60),
    )?;

    let listener = TcpListener::bind(listen_address).await?;
    let bound_address = listener.local_addr()?;
    eprintln!(
        "WARNING: FluxForm server probe is local-development only, is bound to loopback, and is not a production service."
    );
    println!("server probe listening at http://{bound_address}");
    serve(listener, state).await?;
    Ok(())
}

fn required_environment(name: &'static str) -> Result<String, io::Error> {
    env::var(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must be set before starting the server probe"),
        )
    })
}

fn parse_secret(value: &str) -> Result<[u8; 32], io::Error> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "FLUXFORM_SERVER_SECRET must contain exactly 64 hexadecimal characters",
        ));
    }

    let mut secret = [0_u8; 32];
    for (index, byte) in secret.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "FLUXFORM_SERVER_SECRET is not valid hexadecimal",
            )
        })?;
    }
    Ok(secret)
}
