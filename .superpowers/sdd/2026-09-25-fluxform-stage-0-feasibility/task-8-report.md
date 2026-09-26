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
  `CLONE_NEWNET`, includes the resulting nsfs device/inode in the READY report,
  and the parent compares that report to the captured host identity before
  returning the blocked child. Missing, zero, or equal identity is fatal before
  the target can launch. A Linux integration regression exercises the real
  production barrier path.
- Active probe report reads and child-exit waits now use a 10-second deadline.
  Timeout handling kills and reaps the probe child. Linux-only stalled-child
  regressions cover both an absent report and a child that reports but never
  exits; a parent-side watchdog ensures a regression cannot hang the test
  process indefinitely.
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
