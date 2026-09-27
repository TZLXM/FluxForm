#[cfg(debug_assertions)]
use std::env;
use std::error::Error;
#[cfg(debug_assertions)]
use std::fs;
#[cfg(debug_assertions)]
use std::path::PathBuf;
#[cfg(debug_assertions)]
use std::thread;
#[cfg(debug_assertions)]
use std::time::{Duration, Instant};

#[cfg(debug_assertions)]
use fluxform_server_probe::startup::{SandboxCheck, ServerMode, StartupError};
use fluxform_server_probe::startup::{config_from_environment, prepare_server};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = config_from_environment()?;
    #[cfg(debug_assertions)]
    if config.mode == ServerMode::Public {
        reject_debug_public_startup()?;
    }
    let prepared = prepare_server(config)?;
    if let Some(warning) = prepared.warning() {
        eprintln!("{warning}");
    }
    let bound = prepared.bind().await?;
    let address = bound.local_addr()?;
    println!("server probe listening at http://{address}");
    bound
        .serve_with_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

#[cfg(debug_assertions)]
fn reject_debug_public_startup() -> Result<(), StartupError> {
    if env::var_os("FLUXFORM_TEST_REQUIRE_RELEASE").is_some() {
        return Err(StartupError::InvalidConfiguration(
            "native Public startup evidence requires a release-built server executable",
        ));
    }

    if let Some(value) = env::var_os("FLUXFORM_TEST_FORCE_SANDBOX_FAILURE") {
        let check = parse_forced_check(&value.to_string_lossy())?;
        let ready = env::var_os("FLUXFORM_TEST_SANDBOX_READY_FILE").map(PathBuf::from);
        let release = env::var_os("FLUXFORM_TEST_SANDBOX_RELEASE_FILE").map(PathBuf::from);
        if let (Some(ready), Some(release)) = (ready, release) {
            fs::write(&ready, b"forced startup rejection is holding before bind")
                .map_err(|_| StartupError::InvalidConfiguration("test barrier could not start"))?;
            let deadline = Instant::now() + Duration::from_secs(15);
            while !release.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if !release.exists() {
                return Err(StartupError::sandbox_check_failed(
                    check,
                    "test failure barrier timed out",
                ));
            }
        }
        return Err(StartupError::sandbox_check_failed(
            check,
            "debug-build forced failure; this hook can never produce passing evidence",
        ));
    }

    Ok(())
}

#[cfg(debug_assertions)]
fn parse_forced_check(value: &str) -> Result<SandboxCheck, StartupError> {
    match value {
        "filesystem" => Ok(SandboxCheck::Filesystem),
        "network" => Ok(SandboxCheck::Network),
        "cgroup-controllers" => Ok(SandboxCheck::CgroupControllers),
        "cgroup-kill" => Ok(SandboxCheck::CgroupKill),
        "service-identity" => Ok(SandboxCheck::ServiceIdentity),
        "private-namespace" => Ok(SandboxCheck::PrivateNamespace),
        "placement-barrier" => Ok(SandboxCheck::PlacementBarrier),
        _ => Err(StartupError::InvalidConfiguration(
            "test-only forced sandbox failure name is invalid",
        )),
    }
}
