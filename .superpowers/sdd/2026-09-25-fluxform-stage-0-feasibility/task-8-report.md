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
  `EACCES`; AF_UNIX remains allowed for local sockets. Existing direct denies
  for `unshare`, `setns`, and `clone3`, and the existing `clone` namespace flag
  mask were retained. `CLONE_NEWNET` was already present in that mask, so it was
  not added a second time. `io_uring_setup` is also denied to close its socket
  creation path.
- `NetworkPrerequisites::inspect()` binds controlled host IPv4 and IPv6 loopback
  listeners and a host Unix-domain listener, then launches isolated active
  probes. Its private-namespace evidence compares the `/proc/self/ns/net` nsfs
  identity before and after `unshare(CLONE_NEWNET)` and requires it to change.
  IPv4/IPv6 probes call `socket()` and, if not denied, attempt `connect()` to
  their controlled listener. It checks both listeners for zero accepts, probes
  AF_PACKET denial, verifies the outside-root Unix socket path is unreachable
  after pivoting, and attempts `unshare`, `setns`, `clone3`, and `clone` with
  `CLONE_NEWNET` after installing the sandbox filter.
- `NetworkEvidence` contains OS-boundary results only. FFprobe filtering is a
  separate fixed `file,pipe` constant and test; protocol policy is not counted
  as network-isolation evidence.

## Verification

| Check | Result |
| --- | --- |
| `cargo test --offline --locked -p fluxform-sandbox-probe` | PASS: 12 unit tests, 2 filesystem integration tests; `linux_network` is cfg-excluded on Windows and ran 0 tests |
| `cargo clippy --offline --locked --workspace --all-targets -- -D warnings` | PASS |
| `cargo fmt --all --check` | PASS |
| `git diff --check` | PASS |
| `cargo test --offline --locked --workspace --no-fail-fast` | BLOCKED/FAIL: 3 targets failed for existing host/artifact prerequisites (details below) |
| Linux target check | BLOCKED: installed target list contains only `x86_64-pc-windows-msvc`; offline Linux check also lacks `errno v0.3.14`, and no network fetch was attempted |
| `ffprobe_protocol_policy_rejects_urls` | BLOCKED: explicitly ignored with a BLOCKED reason; profile distribution gate is `blocked`, its only listed artifact is a Windows candidate, and there is no native Linux runner or approved Linux FFprobe |

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
