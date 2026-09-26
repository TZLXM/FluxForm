# Task 8 report: Linux network isolation

## Result

Implementation is in place, with native Linux and approved-FFprobe verification
blocked on this Windows host. No Linux success is claimed. The Task 7 filesystem
preflight and resource-placement barrier/cgroup sequence remain in their prior
order.

## TDD record

### RED

Added the portable evidence and policy tests first. The focused `network_` test
run failed to compile as expected because `NetworkEvidence`, `NetworkPolicy`,
`NetworkSocketDomain`, and `FFPROBE_PROTOCOL_WHITELIST` did not yet exist. The
Linux-only integration test could not supply the RED run: this host has only the
Windows Rust target installed. A later RED check for the explicit
`private_namespace_created` evidence field also failed at compile time until
that field and its active probe were implemented.

### GREEN

Implemented the public evidence/policy types and active Linux probe paths. The
portable tests now pass and verify the serialized evidence shape, explicit
synthetic fixture labeling, unsupported-platform behavior, and the declarative
Unix-only socket policy. These are not operating-system proof.

## Boundary and ordering

- `Sandbox::spawn_blocked` still validates pinned filesystem policy and runs
  `FilesystemPrerequisites::inspect()` before the added
  `NetworkPrerequisites::inspect()` call.
- The existing supervisor now creates `CLONE_NEWNET` after user, mount, and PID
  namespace setup and before the filesystem mounts and existing placement
  notification/release sequence. Resource placement itself was not reordered.
- The target receives the post-setup seccomp filter before exec. It denies
  AF_INET, AF_INET6, AF_PACKET, and every unrecognized socket domain with
  `EACCES`; AF_UNIX socket creation remains allowed, but every `connect` is
  denied. `socketpair`, `bpf`, and `userfaultfd` are also denied with `EACCES`.
  Existing direct denies for `unshare`, `setns`, and `clone3`, and the existing
  `clone` namespace flag mask were retained. `CLONE_NEWNET` was already present
  in that mask, so it was not added a second time. `io_uring_setup` is also
  denied to close its socket creation path.
- `NetworkPrerequisites::inspect()` binds controlled host IPv4 and IPv6 loopback
  listeners and a host Unix-domain listener, then launches isolated active
  probes. Its private-namespace evidence compares the `/proc/self/ns/net` nsfs
  identity before and after `unshare(CLONE_NEWNET)` and requires it to change.
  IPv4/IPv6 probes call `socket()` and, if not denied, attempt `connect()` to
  their controlled listener. It checks both listeners for zero accepts, probes
  AF_PACKET denial, verifies the outside-root Unix socket path is unreachable
  after pivoting before installing seccomp, and actively asserts post-setup
  `connect`, `socketpair`, `bpf`, and `userfaultfd` denials. It attempts
  `unshare`, `setns`, `clone3`, and `clone` with `CLONE_NEWNET` after installing
  the sandbox filter.
- Production `Sandbox::spawn_blocked` now captures the caller's netns identity;
  its supervisor validates the identity immediately after its own
  `CLONE_NEWNET` and sends an internal namespace-attestation report. The parent
  authenticates the supervisor PID and checks the reported nsfs device/inode
  differs from the captured host identity, then sends a positive ack over a
  separate internal pipe. Only after that ack can the supervisor write the
  external placement-ready signal or create the `CLONE_INTO_CGROUP` target.
  The parent waits for a second READY report with the same namespace identity
  before returning. Missing, zero, equal, malformed, or changed identity is
  fatal. A Linux integration regression exercises the production
  `ParentAttachBarrier` path; portable ordering tests cover both placement
  actions and invalid/missing acknowledgments.
- Unix socket path visibility and seccomp connect denial are separate facts:
  `unix_socket_escape` is measured before seccomp and requires `ENOENT` after
  `pivot_root`; `connect_denial` is measured after seccomp and requires
  `EACCES`. The post-seccomp sandbox-child action no longer treats `EACCES` as
  filesystem-path evidence.
- Active probe report reads and child-exit waits now use a 10-second deadline.
  Child reaping polls in bounded 10 ms slices rather than sleeping for the
  entire remaining deadline. Timeout handling kills and reaps the probe child.
  Linux-only regressions cover an absent report, a child that reports but never
  exits, and a quick exit that must not wait out the deadline; a parent-side
  watchdog bounds the stalled-child tests.
- `NetworkEvidence` contains OS-boundary results only. FFprobe filtering is a
  separate fixed `file,pipe` constant and test; protocol policy is not counted
  as network-isolation evidence.

## Verification

| Check | Result |
| --- | --- |
| `cargo test --offline --locked -p fluxform-sandbox-probe` | PASS: 13 unit tests, 2 filesystem integration tests; `linux_network` is cfg-excluded on Windows and ran 0 tests |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo fmt --all --check` | PASS |
| `git diff --check` | PASS |
| `cargo test --offline --locked --workspace --no-fail-fast` | BLOCKED/FAIL: 3 targets failed for existing host/artifact prerequisites (details below) |
| Linux target check | BLOCKED: installed target list contains only `x86_64-pc-windows-msvc`; offline Linux check also lacks `errno v0.3.14`, and no network fetch was attempted |
| `ffprobe_protocol_policy_rejects_urls` | BLOCKED on this host: review round 1 removed its permanent ignore; it is enabled on Linux and fails with an explicit `BLOCKED:` diagnostic/nonzero result when approved inputs are absent. This Windows run cfg-excludes it; the profile gate is blocked and no approved Linux FFprobe is available |

The workspace test failures are unrelated to Task 8: four unit tests and ten
atomic-output integration tests fail with Windows error 5 (`Access is denied`)
while opening their task output directories; the `cross_platform_samples`
artifact-gate test reports its collected artifact root missing (OS error 3).
The remaining workspace tests completed successfully in that run.

## Required blocked evidence

| Evidence | Status | Reason |
| --- | --- | --- |
| Compile Linux-only implementation | BLOCKED | No Linux target installed; offline target check cannot resolve `errno v0.3.14`; network fetch prohibited |
| Run controlled IPv4/IPv6 listener and Unix/namespace escape probes | BLOCKED | Windows host; Linux integration target is cfg-excluded |
| Run approved FFprobe local-success/HTTP-denial policy test | BLOCKED | No approved Linux artifact/native Linux runner; diagnostic binaries are not approval evidence |
| External artifact gates | BLOCKED | Required approved native profile/sample artifacts are unavailable |

No shell is used to launch the sandboxed action; no network fetch, publishing,
or C# changes were made.

## Review round 2 follow-up (2026-09-26)

This follow-up supersedes the earlier namespace-ready ordering, Unix probe
phase, reaper polling, and latest verification-count wording above.

### RED / GREEN

- RED: the new portable parent-ack tests initially failed to compile because
  the ordering gate did not yet exist. After adding the gate, both placement
  ordering cases and invalid/missing/read-error ack cases passed (2 tests).
- Linux-only RED/GREEN could not be observed on this host. The changed Linux
  integration tests assert separate pre-seccomp `ENOENT` and post-seccomp
  `EACCES` evidence, and a quick-exit reaper regression contrasts with the
  existing stalled-child timeout/kill/reap tests; all remain unexecuted here.
- GREEN by implementation review: production now sends an attestation before
  either placement action, validates the supervisor PID and distinct nsfs
  identity in the parent, acknowledges only after validation, and waits for a
  post-ack READY carrying the same identity. The ack read end is preserved
  through `close_range_except`; the parent closes its writer on all returns,
  kills/reaps on validation/read/write failures, and the supervisor fails
  closed on missing or invalid ack. The cgroup target clone is nested inside
  the positive-ack action.
- GREEN by portable tests: evidence serialization keeps synthetic Unix path
  visibility and connect denial as distinct records. These records are
  explicitly synthetic and are not presented as OS proof.
- GREEN by implementation review: `reap_probe_until` now wakes at most every
  10 ms while respecting the original overall deadline; the existing timeout
  path still kills and reaps stalled children.

### Review round 2 verification

| Check | Result |
| --- | --- |
| `cargo test --offline --locked -p fluxform-sandbox-probe --all-targets` | PASS: 16 unit tests and 2 filesystem tests; Linux network tests cfg-excluded on Windows (0 run) |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS on Windows target; Linux-only supervisor/probe code is cfg-excluded |
| `cargo fmt --all -- --check` | PASS |
| `git diff --check` | PASS |
| `cargo test --offline --locked --workspace --all-targets --no-fail-fast` | 3 unrelated targets fail: atomic-output library (4 tests) and commit integration tests (10 tests) get Windows error 5 (`Access is denied`) opening task output directories; `cross_platform_samples` lacks its collected artifact root (OS error 3). Other targets pass. |
| `cargo check --offline --locked -p fluxform-sandbox-probe --target x86_64-unknown-linux-gnu --all-targets` | BLOCKED before compilation: offline cache lacks `errno v0.3.14`; installed Rust target list contains only `x86_64-pc-windows-msvc`; no network fetch attempted. |
| Production namespace handshake, controlled listeners, Unix/namespace escape probes, and reaper latency/timeout regressions | BLOCKED: no native Linux target/runner; no Linux OS evidence claimed. |
| `ffprobe_protocol_policy_rejects_urls` | BLOCKED: enabled Linux-only gate has no configured approved Linux FFprobe artifact or native Linux runner. It remains non-ignored and reports an explicit `BLOCKED:` failure when inputs are absent. |

No shell-launched action, network fetch, publishing, or C# change was made.

## Review round 1 follow-up (2026-09-26)

This follow-up supersedes earlier status wording above where the review changed
test behavior or evidence counts.

### RED / GREEN

- RED: after adding portable regressions for the four explicit syscall denials,
  evidence serialization, policy construction, and missing/equal namespace
  identities, the focused package test failed to compile with 12 expected
  errors against the previous implementation. Linux-only regressions were
  authored for actual production-supervisor attestation and stalled probe
  children, but cannot be executed on this Windows host.
- GREEN: portable policy/evidence and identity tests pass. The Linux seccomp
  filter consumes the declared syscall-denial policy, while live prerequisite
  and production-sandbox probes assert those denials on Linux. `connect` is
  rejected across all socket domains; AF_UNIX creation remains allowed and its
  post-filter probe confirms `connect` returns `EACCES`. The existing
  namespace-related syscall denies and `CLONE_NEWNET` clone mask remain
  unchanged, with no duplicate flag added.
- GREEN: the approved-FFprobe test is no longer ignored. It invokes only the
  profile-approved Linux candidate configured by
  `FLUXFORM_APPROVED_LINUX_FFPROBE`, fingerprints it against the approved hash
  and size, uses fixed `-protocol_whitelist file,pipe`, and asserts local-file
  success plus HTTP denial. Missing approval is a visible `BLOCKED:` test
  failure rather than a skip or diagnostic-binary fallback.

### Review round 1 verification

| Check | Result |
| --- | --- |
| `cargo test --offline --locked -p fluxform-sandbox-probe` | PASS: 13 unit tests and 2 filesystem tests; Linux network/FFprobe tests cfg-excluded on Windows (0 run) |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo fmt --all --check` | PASS |
| `git diff --check` | PASS |
| `cargo test --offline --locked --workspace --no-fail-fast` | 3 targets remain blocked by host prerequisites: 4 atomic-output unit tests and 10 commit integration tests fail with Windows error 5; `cross_platform_samples` has no collected artifact root (OS error 3). Other targets pass. |
| `cargo check --offline --locked --target x86_64-unknown-linux-gnu -p fluxform-sandbox-probe --all-targets` | BLOCKED before compilation: offline cache lacks `errno v0.3.14`; no network fetch attempted. `rustup target list --installed` shows only `x86_64-pc-windows-msvc`. |
| Active Linux listeners, seccomp probes, production netns regression, timeout regressions | BLOCKED: no native Linux target/runner on this host. No OS proof is claimed. |
| `ffprobe_protocol_policy_rejects_urls` | BLOCKED: Linux-only enabled gate, but no native Linux runner or profile-approved Linux FFprobe artifact is configured. |

Portable serialization and policy-construction tests are not presented as
operating-system evidence. No C# changes, shell-launched sandbox actions,
network fetches, or publishing were performed in this review round.
