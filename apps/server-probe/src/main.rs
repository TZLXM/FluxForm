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

use fluxform_server_probe::startup::{
    RealSandboxChecker, SandboxChecker, StartupError, config_from_environment, prepare_server,
};
#[cfg(debug_assertions)]
use fluxform_server_probe::startup::{SandboxCheck, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let config = config_from_environment()?;
    let checker = startup_checker()?;
    let prepared = prepare_server(config, checker.as_ref())?;
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

fn startup_checker() -> Result<Box<dyn SandboxChecker>, StartupError> {
    #[cfg(debug_assertions)]
    if let Some(value) = env::var_os("FLUXFORM_TEST_FORCE_SANDBOX_FAILURE") {
        let check = parse_forced_check(&value.to_string_lossy())?;
        return Ok(Box::new(ForcedFailureChecker { check }));
    }

    Ok(Box::new(RealSandboxChecker))
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

/// Debug-build-only test hook. It can reject Public startup, never pass it.
#[cfg(debug_assertions)]
struct ForcedFailureChecker {
    check: SandboxCheck,
}

#[cfg(debug_assertions)]
impl SandboxChecker for ForcedFailureChecker {
    fn check(&self, _config: &ServerConfig) -> Result<(), StartupError> {
        let ready = env::var_os("FLUXFORM_TEST_SANDBOX_READY_FILE").map(PathBuf::from);
        let release = env::var_os("FLUXFORM_TEST_SANDBOX_RELEASE_FILE").map(PathBuf::from);
        if let (Some(ready), Some(release)) = (ready, release) {
            fs::write(&ready, b"forced checker is holding startup before bind")
                .map_err(|_| StartupError::InvalidConfiguration("test barrier could not start"))?;
            let deadline = Instant::now() + Duration::from_secs(15);
            while !release.exists() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(10));
            }
            if !release.exists() {
                return Err(StartupError::sandbox_check_failed(
                    self.check,
                    "test failure barrier timed out",
                ));
            }
        }
        Err(StartupError::sandbox_check_failed(
            self.check,
            "debug-build forced failure; this hook can never produce passing evidence",
        ))
    }
}
