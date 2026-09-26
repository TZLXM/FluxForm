#[cfg(not(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
)))]
#[test]
fn native_cgroup_evidence_is_explicitly_blocked_without_linux() {
    use fluxform_sandbox_probe::{CgroupV2Job, SandboxError, SandboxLimits};

    let result = CgroupV2Job::create("unavailable-delegation", "job-1", SandboxLimits::default());
    let error = match result {
        Ok(_) => panic!("non-Linux host must not claim native cgroup evidence"),
        Err(error) => error,
    };
    assert!(matches!(error, SandboxError::CgroupPrerequisitesFailed(_)));
    assert!(error.to_string().contains("BLOCKED"));
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod linux {
    use fluxform_sandbox_probe::{
        CgroupV2Job, ResourceBoundary, Sandbox, SandboxLimits, SandboxPolicy,
    };
    use std::fs;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    static NEXT_JOB: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        _root: tempfile::TempDir,
        input: PathBuf,
        job_dir: PathBuf,
        tool_dir: PathBuf,
        child: PathBuf,
        limits: SandboxLimits,
        cgroup: CgroupV2Job,
    }

    impl Fixture {
        fn new(pids: u64, memory: u64, cpu_quota: u64) -> Self {
            let root = tempfile::tempdir().expect("fixture root");
            let input = root.path().join("assigned-input.bin");
            fs::write(&input, b"assigned-input").expect("write input");
            let job_dir = root.path().join("job");
            fs::create_dir(&job_dir).expect("create job directory");
            fs::set_permissions(&job_dir, fs::Permissions::from_mode(0o700))
                .expect("restrict job directory");
            let tool_dir = root.path().join("tool");
            fs::create_dir(&tool_dir).expect("create tool directory");
            let child = tool_dir.join("sandbox-child");
            let child_source = PathBuf::from(env!("CARGO_BIN_EXE_sandbox-child"));
            fs::copy(&child_source, &child).expect("copy test action binary");
            copy_runtime_dependencies(&child_source, &tool_dir);

            let limits = SandboxLimits {
                pids_max: pids,
                memory_max_bytes: memory,
                memory_swap_max_bytes: 0,
                cpu_quota_micros: cpu_quota,
                cpu_period_micros: 100_000,
                ..SandboxLimits::default()
            };
            let delegated_root = std::env::var_os("FLUXFORM_TEST_CGROUP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| {
                    panic!("BLOCKED: set FLUXFORM_TEST_CGROUP_ROOT to an already delegated cgroup v2 subtree")
                });
            let job_id = format!(
                "fluxform-test-{}-{}",
                std::process::id(),
                NEXT_JOB.fetch_add(1, Ordering::Relaxed)
            );
            let cgroup =
                CgroupV2Job::create(&delegated_root, &job_id, limits).unwrap_or_else(|error| {
                    panic!("BLOCKED: delegated cgroup v2 setup unavailable: {error}")
                });
            assert!(
                cgroup.evidence().all_passed(),
                "cgroup setup evidence: {:#?}",
                cgroup.evidence()
            );

            Self {
                _root: root,
                input,
                job_dir,
                tool_dir,
                child,
                limits,
                cgroup,
            }
        }

        fn policy(&self) -> SandboxPolicy {
            SandboxPolicy {
                input: self.input.clone(),
                job_dir: self.job_dir.clone(),
                tool_dir: self.tool_dir.clone(),
                limits: self.limits,
            }
        }

        fn spawn(&self, action: &str, args: &[&str]) -> fluxform_sandbox_probe::SandboxChild {
            let arguments = std::iter::once(action)
                .chain(args.iter().copied())
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>();
            Sandbox::spawn_blocked(
                &self.child,
                &arguments,
                &self.policy(),
                self.cgroup
                    .prepare_spawn()
                    .expect("prepare cgroup placement before spawn"),
            )
            .unwrap_or_else(|error| {
                panic!("BLOCKED: sandbox/resource placement unavailable: {error}")
            })
        }
    }

    fn copy_runtime_dependencies(binary: &Path, tool_dir: &Path) {
        let output = Command::new("ldd")
            .arg(binary)
            .output()
            .expect("run ldd for the test action");
        assert!(output.status.success(), "ldd failed: {output:?}");
        let stdout = String::from_utf8(output.stdout).expect("ldd output is UTF-8");
        for path in stdout
            .lines()
            .flat_map(str::split_ascii_whitespace)
            .filter(|part| part.starts_with('/'))
        {
            let source = Path::new(path);
            let destination = tool_dir.join(source.strip_prefix("/").expect("absolute ldd path"));
            if destination.exists() {
                continue;
            }
            fs::create_dir_all(destination.parent().expect("dependency parent"))
                .expect("create dependency parent");
            fs::copy(source, destination).expect("copy runtime dependency");
        }
    }

    fn read_members(fixture: &Fixture) -> Vec<u32> {
        fs::read_to_string(fixture.cgroup.path().join("cgroup.procs"))
            .expect("read cgroup.procs")
            .lines()
            .map(|line| line.parse().expect("numeric cgroup PID"))
            .collect()
    }

    fn expected_cgroup_path(fixture: &Fixture) -> String {
        fixture.cgroup.membership_path().to_owned()
    }

    fn assert_exact_membership(fixture: &Fixture, host_pids: &[u32]) {
        let expected = expected_cgroup_path(fixture);
        for pid in host_pids {
            let membership =
                fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_else(|error| {
                    panic!("worker PID {pid} disappeared before membership check: {error}")
                });
            let entries = membership
                .lines()
                .filter_map(|line| line.strip_prefix("0::"))
                .collect::<Vec<_>>();
            assert_eq!(
                entries,
                [expected.as_str()],
                "PID {pid} membership: {membership}"
            );
        }
    }

    fn host_tree_pids(fixture: &Fixture) -> Vec<u32> {
        let reported = wait_for_lines(
            &fixture.job_dir.join("tree-pids.txt"),
            3,
            Duration::from_secs(5),
        )
        .lines()
        .map(|line| line.parse::<u32>().expect("namespace PID"))
        .collect::<Vec<_>>();
        assert_eq!(reported.len(), 3, "worker and double-fork tree report PIDs");
        let members = read_members(fixture);
        assert!(
            members.len() >= 2,
            "setsid tree must leave live cgroup members"
        );
        for host_pid in &members {
            let status = fs::read_to_string(format!("/proc/{host_pid}/status"))
                .expect("read cgroup member status");
            let namespace_pid = status
                .lines()
                .find_map(|line| line.strip_prefix("NSpid:"))
                .expect("PID namespace mapping")
                .split_ascii_whitespace()
                .last()
                .and_then(|part| part.parse::<u32>().ok())
                .expect("numeric innermost namespace PID");
            assert!(
                reported.contains(&namespace_pid),
                "cgroup PID {host_pid} ({namespace_pid}) was not reported by tree action"
            );
        }
        members
    }

    fn assert_processes_gone(pids: &[u32]) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let survivors = pids
                .iter()
                .filter(|pid| Path::new("/proc").join(pid.to_string()).exists())
                .copied()
                .collect::<Vec<_>>();
            if survivors.is_empty() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "cgroup cancellation left descendants visible in /proc: {survivors:?}"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_file(path: &Path, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(contents) = fs::read_to_string(path) {
                if !contents.is_empty() {
                    return contents;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_lines(path: &Path, minimum: usize, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            if let Ok(contents) = fs::read_to_string(path) {
                if contents.lines().count() >= minimum {
                    return contents;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {minimum} lines in {}",
                path.display()
            );
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn read_counter(path: &Path, field: &str) -> u64 {
        fs::read_to_string(path)
            .expect("read cgroup statistics")
            .lines()
            .find_map(|line| {
                let mut fields = line.split_ascii_whitespace();
                (fields.next()? == field)
                    .then(|| fields.next()?.parse().ok())
                    .flatten()
            })
            .unwrap_or_else(|| panic!("missing {field} counter in {}", path.display()))
    }

    #[test]
    fn pids_max_limits_the_combined_worker_and_forks() {
        let fixture = Fixture::new(8, 128 * 1024 * 1024, 100_000);
        let mut child = fixture.spawn("resource-pids", &[]);
        let content = wait_for_file(
            &fixture.job_dir.join("pids-count.txt"),
            Duration::from_secs(5),
        );
        let successful_forks: u64 = content.trim().parse().expect("fork count");
        assert!(successful_forks > 0, "worker did not fork before pids.max");
        assert!(successful_forks + 1 <= fixture.limits.pids_max);
        assert!(
            read_counter(&fixture.cgroup.path().join("pids.events"), "max") > 0,
            "the pids controller did not report a rejected fork"
        );
        let members = read_members(&fixture);
        assert!(members.len() <= fixture.limits.pids_max as usize);
        assert_exact_membership(&fixture, &members);

        child.kill().expect("cancel worker through SandboxChild");
        assert!(fixture.cgroup.is_empty().expect("check empty cgroup"));
        assert!(
            child
                .try_wait()
                .expect("cgroup kill reaped supervisor")
                .is_some()
        );
    }

    #[test]
    fn memory_max_is_aggregate_and_swap_stays_disabled() {
        let fixture = Fixture::new(16, 96 * 1024 * 1024, 100_000);
        let memory_events = fixture.cgroup.path().join("memory.events");
        let oom_kills_before = read_counter(&memory_events, "oom_kill");
        let mut child = fixture.spawn("resource-memory", &["64"]);
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if read_counter(&memory_events, "oom_kill") > oom_kills_before {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "aggregate memory limit never produced an OOM kill"
            );
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(
            fs::read_to_string(fixture.cgroup.path().join("memory.swap.max"))
                .expect("read swap limit")
                .trim(),
            "0"
        );
        assert_eq!(
            fs::read_to_string(fixture.cgroup.path().join("memory.swap.current"))
                .expect("read swap usage")
                .trim(),
            "0"
        );
        child
            .kill()
            .expect("cancel aggregate memory workers through SandboxChild");
        assert!(child.try_wait().expect("reap memory supervisor").is_some());
    }

    #[test]
    fn cpu_max_throttles_total_job_bandwidth() {
        let fixture = Fixture::new(16, 128 * 1024 * 1024, 25_000);
        let cpu_stat = fixture.cgroup.path().join("cpu.stat");
        let mut child = fixture.spawn("resource-cpu", &["1500"]);
        let _ = wait_for_file(
            &fixture.job_dir.join("cpu-ready.txt"),
            Duration::from_secs(5),
        );
        let usage_before = read_counter(&cpu_stat, "usage_usec");
        let throttled_before = read_counter(&cpu_stat, "nr_throttled");
        let status = child.wait().expect("wait for CPU stress worker");
        assert!(status.success(), "CPU stress worker failed: {status}");
        let usage = read_counter(&cpu_stat, "usage_usec") - usage_before;
        let throttled = read_counter(&cpu_stat, "nr_throttled") - throttled_before;
        assert!(throttled > 0, "cpu.max did not throttle the job");
        assert!(
            usage <= 800_000,
            "job used {usage} CPU microseconds under a 25% quota"
        );
        child
            .kill()
            .expect("remove CPU job cgroup through SandboxChild");
    }

    #[test]
    fn setsid_double_fork_descendants_are_born_in_job_cgroup() {
        let fixture = Fixture::new(16, 128 * 1024 * 1024, 100_000);
        let mut child = fixture.spawn("resource-tree", &[]);
        let host_pids = host_tree_pids(&fixture);
        let session: i32 = fs::read_to_string(fixture.job_dir.join("tree-session.txt"))
            .expect("setsid result")
            .trim()
            .parse()
            .expect("numeric session id");
        assert!(
            session > 0,
            "managed cgroup worker could not create a session"
        );
        assert_exact_membership(&fixture, &host_pids);

        child
            .kill()
            .expect("SandboxChild::kill stops every cgroup descendant");
        assert!(
            fixture
                .cgroup
                .is_empty()
                .expect("cgroup populated must reach zero")
        );
        assert!(
            child
                .try_wait()
                .expect("kill_all must reap outer supervisor")
                .is_some()
        );
        assert!(
            !fixture.cgroup.path().exists(),
            "empty job cgroup was not removed"
        );
        assert_processes_gone(&host_pids);
    }

    #[test]
    fn dropping_sandbox_child_kills_setsid_double_fork_descendants_and_removes_cgroup() {
        let fixture = Fixture::new(16, 128 * 1024 * 1024, 100_000);
        let child = fixture.spawn("resource-tree", &[]);
        let host_pids = host_tree_pids(&fixture);
        assert_exact_membership(&fixture, &host_pids);

        drop(child);

        assert!(fixture.cgroup.is_empty().expect("drop should empty cgroup"));
        assert!(
            !fixture.cgroup.path().exists(),
            "drop should remove job cgroup"
        );
        assert_processes_gone(&host_pids);
    }

    #[test]
    fn dropping_cgroup_owner_before_child_is_idempotent_and_keeps_child_reapable() {
        let fixture = Fixture::new(16, 128 * 1024 * 1024, 100_000);
        let mut child = fixture.spawn("resource-tree", &[]);
        let host_pids = host_tree_pids(&fixture);
        assert_exact_membership(&fixture, &host_pids);
        let cgroup_path = fixture.cgroup.path().to_path_buf();

        drop(fixture.cgroup);

        assert!(
            !cgroup_path.exists(),
            "job owner drop should empty and remove cgroup"
        );
        assert!(
            child
                .try_wait()
                .expect("cgroup owner drop reaps supervisor")
                .is_some()
        );
        drop(child);
        assert_processes_gone(&host_pids);
    }

    #[test]
    fn sandbox_child_timeout_kills_setsid_double_fork_descendants() {
        let fixture = Fixture::new(16, 128 * 1024 * 1024, 100_000);
        let mut child = fixture.spawn("resource-tree", &[]);
        let host_pids = host_tree_pids(&fixture);
        assert_exact_membership(&fixture, &host_pids);

        let error = child
            .wait_timeout(Duration::from_millis(25))
            .expect_err("long-running tree should time out");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);

        assert!(
            fixture
                .cgroup
                .is_empty()
                .expect("timeout should empty cgroup")
        );
        assert!(
            !fixture.cgroup.path().exists(),
            "timeout should remove job cgroup"
        );
        assert_processes_gone(&host_pids);
    }

    #[test]
    fn cancellation_during_fork_race_leaves_no_process_outside_or_alive() {
        let fixture = Fixture::new(64, 128 * 1024 * 1024, 100_000);
        let mut child = fixture.spawn("resource-fork-race", &[]);
        let _ = wait_for_file(
            &fixture.job_dir.join("race-pids.txt"),
            Duration::from_secs(5),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        let members_before = loop {
            let members = read_members(&fixture);
            if members.len() > 1 {
                break members;
            }
            assert!(
                Instant::now() < deadline,
                "fork race did not create descendants"
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert!(
            members_before.len() > 1,
            "fork race did not create descendants"
        );
        assert_exact_membership(&fixture, &members_before);

        child
            .kill()
            .expect("SandboxChild::kill must stop concurrent forks");
        assert!(
            fixture
                .cgroup
                .is_empty()
                .expect("wait for cgroup populated=0")
        );
        assert!(
            child
                .try_wait()
                .expect("kill_all reaps sandbox supervisor")
                .is_some()
        );
        for pid in members_before {
            assert!(
                !Path::new("/proc").join(pid.to_string()).exists(),
                "process {pid} survived cgroup.kill"
            );
        }
        assert!(
            !fixture.cgroup.path().exists(),
            "job cgroup remained after cleanup"
        );
    }
}
