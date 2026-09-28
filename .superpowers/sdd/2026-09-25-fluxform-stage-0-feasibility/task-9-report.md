# Task 9 Report — Per-Job Aggregate Resource Containment

## Outcome

Implemented `CgroupV2Job` and the Linux-only aggregate resource stress suite.
Portable checks pass on this Windows host. Linux compilation, delegated-cgroup
execution, and native stress evidence remain **BLOCKED**; no aggregate Linux
containment success is claimed.

## TDD record

- Added `tests/linux_resources.rs` with the pids, aggregate memory/swap, CPU,
  setsid/double-fork, exact membership, and cancellation/fork-race cases before
  the boundary implementation. The native behavior RED/GREEN run is blocked on
  this host.
- Portable RED: the focused resource integration test failed to compile as
  expected because `CgroupV2Job` and `SandboxError::CgroupPrerequisitesFailed`
  did not yet exist. The focused `cgroup_` library tests likewise failed on
  missing validation, limit-serialization, event/membership, and evidence
  helpers.
- Portable GREEN: the final package run passed 20 library tests, 2 filesystem
  integration tests, and 1 non-Linux test asserting that cgroup evidence is
  explicitly `BLOCKED`. The Linux resource stress module was not executed by
  this Windows run and is not counted as passing.

## Implementation

- Validates `job_id` as one bounded ASCII component and validates positive
  `pids.max`, `memory.max`, `cpu.max` values plus `memory.swap.max = 0`.
- Opens and pins the delegated cgroup root without following symlinks, requires
  the service's current cgroup with enabled `cpu`, `memory`, and `pids`
  controllers, creates the per-job directory exclusively, and writes/readbacks
  all four aggregate controls before any worker placement is prepared. Missing
  delegation, controllers, or `cgroup.kill` returns structured `BLOCKED`
  evidence.
- Probes `clone3(CLONE_INTO_CGROUP)` using the opened job directory descriptor.
  If unavailable, the managed fallback reuses Task 8's namespace-attestation
  acknowledgment order: the supervisor stays blocked, the parent checks its
  reported PID, writes it to `cgroup.procs`, verifies the exact unified
  `/proc/<pid>/cgroup` path, then releases it. Attach/verification failures
  kill the blocked child; there is no post-tool attachment path.
- Tracks active placements and per-spawn reapers. `kill_all` closes the job to
  new spawns, uses `cgroup.kill`, waits a bounded interval for
  `cgroup.events populated 0`, reaps registered supervisors, then removes the
  cgroup. Dropping the job also attempts cleanup. Managed cgroup workers may
  use `setsid` so the stress test exercises containment beyond process-group
  killing; non-cgroup sandbox placements retain the existing denial. RLIMITs
  remain per-process defense in depth and are not used as aggregate proof.
- Added fixed `sandbox-child` actions for process-count, memory, CPU, session /
  double-fork, and cancellation/fork-race stress. Setup evidence is distinct
  from native stress evidence.
- No dependencies, C# files, publishing, or network changes.

## Verification

Passed on the available Windows target:

```text
cargo test --offline --locked -p fluxform-sandbox-probe --all-targets
cargo clippy --offline --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
cargo test --offline --locked --workspace --exclude fluxform-atomic-output --exclude fluxform-capabilities --all-targets
cargo test --offline --locked -p fluxform-capabilities --lib --bins --test runner --test manifest
```

The full workspace test command was also attempted. Four unrelated
`fluxform-atomic-output` Windows-native tests failed while opening their task
output directories with Windows `PermissionDenied` / OS error 5; its other
seven tests passed. The selected workspace suite and feasible capability
tests above passed.

## Native Linux evidence: BLOCKED

- `rustup target list --installed` reports only `x86_64-pc-windows-msvc`.
- `cargo check --offline --locked --target x86_64-unknown-linux-gnu -p fluxform-sandbox-probe --all-targets`
  stopped before compilation because cached `errno v0.3.14` is unavailable.
  The library-only target check then failed because the Linux `core` / `std`
  target is not installed. No target was downloaded and no network fetch was
  attempted.
- There is no Linux host or delegated cgroup subtree here. The eight native
  resource tests remain **BLOCKED**, not skipped/passed evidence. Their Linux
  fixture requires `FLUXFORM_TEST_CGROUP_ROOT` to name an already delegated
  cgroup v2 subtree. A supported Linux runner must compile with strict Clippy
  and execute `cargo test -p fluxform-sandbox-probe --test linux_resources`
  before Task 9 can be treated as natively verified.

## Commit

Required subject: `feat(server): contain worker resources with cgroup v2`.

## Review fix round 1 — topology and cancellation ownership

- Root cause confirmed: setup equated the delegated root with the process's
  current cgroup, which both blocks the normal no-internal-process delegated
  domain layout and nests each job beneath the service process. Setup now pins
  the root descriptor's mount ID with `statx`, selects exactly one matching
  cgroup2 record from `/proc/self/mountinfo`, maps that pinned filesystem path
  to its unified hierarchy path, and validates `root/service` as the direct,
  single-process management leaf. The delegated root must be owned by the
  effective service UID, have no internal processes, be a domain cgroup, and
  expose and enable `cpu`, `memory`, and `pids`; the management leaf must be
  same-owner, domain-type, contain only the service process, and have no child
  cgroups. Jobs remain exclusive direct children of the delegated root, so
  their exact `/proc/<pid>/cgroup` identity is derived as `root/job`, not from
  the service leaf.
- Added portable topology/mount/delegation fixtures covering valid
  root/service plus root/job placement; root-equals-service, outside/prefix
  escape, nested/noncanonical/ambiguous paths; duplicate or missing pinned
  mount IDs; missing available/enabled controllers; wrong owner; internal root
  processes; and non-leaf or shared-process management cgroups.
- Cancellation root cause confirmed: a returned `SandboxChild` retained only
  the supervisor PID and always signaled a process group, while `setsid`
  descendants could remain outside it. The child now retains a shared Arc
  cleanup handle for the job. Explicit `kill`, timeout, and `Drop` use the
  serialized/idempotent cgroup cleanup path: `cgroup.kill` before waiting for
  active placements, a second `cgroup.kill` after they drain, bounded wait for
  `populated 0`, supervisor reap, and cgroup removal. Explicit kill returns
  cleanup errors; Drop remains best-effort. Managed placement-failure paths
  kill the still-blocked supervisor directly, with no process-group fallback.
  Shared ownership supports either owner-drop order; Task 8 attestation ACK
  and placement/release order is unchanged.
- The Linux aggregate tests now exercise cleanup through
  `SandboxChild::kill`, `wait_timeout`, and `Drop` rather than directly invoking
  `fixture.cgroup.kill_all`; added tests cover both drop orders and verify exact
  membership before cancellation, empty/removal afterward, and no surviving
  reported processes. A final static audit replaced a stale reference to the
  removed per-PID lookup helper with the live-member collector. These Linux
  cases remain BLOCKED on this Windows host and cannot be type-checked here.
- TDD evidence: portable tests first failed to compile on the missing topology,
  delegation, management-leaf, and pinned-path helpers (expected RED); after
  implementation, all 10 cgroup-focused portable unit tests passed. The
  cleanup-order test then failed to compile on the missing sequence helper
  (expected RED), and passed after the production cleanup path was routed
  through the tested kill-before-drain / kill-after-drain sequence. The
  Linux-only kill/timeout/Drop tests cannot be compiled or executed here and
  are not claimed as RED/GREEN evidence.
- Review-fix verification passed: `cargo test --offline --locked
  -p fluxform-sandbox-probe --all-targets` (27 library tests, 2 filesystem
  tests, 1 explicit non-Linux BLOCKED-evidence test), workspace Clippy with
  `-D warnings`, formatting check, diff check, selected workspace tests
  excluding the previously failing Windows-native atomic-output cases, and the
  capability runner/manifest tests.
- Native Linux compilation remains BLOCKED: only
  `x86_64-pc-windows-msvc` is installed; offline all-target Linux check lacks
  cached `errno v0.3.14`, and library-only Linux check lacks Linux `core` and
  `std`. No target download or network fetch was attempted. A delegated Linux
  runner is still required for the eight native cgroup integration tests.
- Review-fix commit subject: `fix(server): correct cgroup delegation and cancellation`.

## Review fix round 3 — live fixed-action process evidence

Task 14's `resource-tree` cgroup-kill proof uses the same strict Task 9
expectation: the supervisor, setsid session child, and grandchild are exactly
three reported PIDs, all remain live/non-zombie in the exact job cgroup until
`cgroup.kill`, and all are then removed by the job-wide cancellation. The
session child now blocks after recording its PID instead of exiting early. A
Linux-only lifecycle regression checks the complete set repeatedly through a
delay and immediately before cancellation. Its native execution remains
**BLOCKED** on this Windows host; the portable fake-proc identity tests do not
substitute for delegated-cgroup evidence.
