# Task 7 Report — Linux Filesystem Isolation

## Outcome

Implemented the Linux-only rootless filesystem isolation probe in `fluxform-sandbox-probe`. The public `SandboxPolicy`, `FilesystemPrerequisites`, `ResourceBoundary`, `SpawnPlacement`, `Sandbox::spawn_blocked`, and `SandboxChild` surfaces are present for follow-on Tasks 8/9. Non-Linux builds compile and return `SandboxError::UnsupportedPlatform` from both prerequisite inspection and spawn.

The Linux implementation and its adversarial tests are **not natively verified** on this host. Their evidence state remains **BLOCKED**, not skipped or passed.

## TDD record

The Linux adversarial test file was added before the implementation. The initial RED command was:

```text
cargo test -p fluxform-sandbox-probe --test linux_filesystem --offline
```

It failed during crate compilation because the declared `sandbox-child` binary and library implementation had not yet been created. This was a scaffold RED, not a behavioral failure of the Linux filesystem boundary. Native behavioral RED/GREEN execution could not be observed here because this host is Windows; the Linux tests are `cfg(target_os = "linux")` and were not executed here.

During final static review, a portable evidence-serialization assertion was added for explicit PID-namespace evidence. Its RED command was:

```text
cargo test -p fluxform-sandbox-probe --test linux_filesystem --offline
```

It failed with `E0560` because `FilesystemEvidence` did not yet expose `pid_namespace`; the field and an active PID-namespace probe were then implemented. This is portable shape evidence only, not a native PID-namespace proof.

After implementation, the portable Windows GREEN command was:

```text
cargo test -p fluxform-sandbox-probe --offline
```

Result: **2 passed**. These are only the portable evidence-serialization test and the non-Linux `UnsupportedPlatform` checks. They are not evidence of Linux isolation.

## Implementation

- Uses the cached `libc` crate for a confined set of Linux syscalls; no network dependency or publishing action was used.
- Creates a rootless user namespace, writes one-entry UID/GID maps, then creates private mount and PID namespaces. Mount propagation is recursively private.
- Builds a tmpfs-only root, bind-mounts exactly one input file read-only, the declared tool directory read-only, and the task directory writable with `nosuid`, `nodev`, and `noexec`; mounts a fresh empty size-limited tmpfs at `/tmp`; pivots and detaches the old root. No host root, `/proc`, or `/dev` mount is exposed. The tool directory is the only source for the minimal `/lib`, `/lib64`, and `/usr` loader paths.
- Replaces standard streams with `/dev/null`, reserves internal descriptors above stdio, and uses `close_range` to retain only setup-report and declared placement descriptors. The probe actively checks `close_range` and fails closed if unavailable.
- Applies `RLIMIT_FSIZE` and `RLIMIT_NOFILE`, sets `no_new_privs`, drops/verifies capability sets, uses a restrictive seccomp filter for mount/namespace operations and process-group escape, and executes the selected program directly with `execve` and an empty environment. No shell is invoked.
- `ParentAttachBarrier` notifies the resource controller and waits for release before forking or executing tool code. `CloneIntoCgroup` uses `clone3(CLONE_INTO_CGROUP)` for atomic placement. There is no post-spawn `attach(pid)` API or best-effort placement path.
- `FilesystemPrerequisites::inspect` independently records structured status/detail for user and PID namespaces, mount isolation, `pivot_root`, capability dropping, descriptor closure, and temporary-root creation; the PID probe verifies a child in the new namespace observes PID 1. Any failed primitive prevents public spawn.
- Added a fixed-action test binary and Linux-only tests for allowed input/task access, pre-release blocking, `/etc/passwd`, parent traversal, host `/tmp` descriptor writes, symlink traversal, undeclared file descriptors, and read-only input/tool mounts.

`SandboxLimits` carries the shared resource policy shape. This task applies file-size/open-file rlimits and the `/tmp` size; cgroup resource enforcement and network containment remain for Tasks 8/9. The `ResourceBoundary` trait here is the required integration interface, not a concrete controller.

## Verification

Passed on Windows:

```text
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --offline -- -D warnings
cargo test -p fluxform-sandbox-probe --offline
cargo test --workspace --exclude fluxform-capabilities --offline
cargo test -p fluxform-capabilities --lib --bins --test runner --test manifest --offline
git diff --check
```

The full workspace command was also attempted:

```text
cargo test --workspace --offline
```

All tests reached before the artifact gate passed, but `fluxform-capabilities/tests/cross_platform_samples.rs::every_approved_native_profile_has_a_current_sample_report` failed with `BLOCKED: collected artifact root is missing or unreadable` (Windows OS error 3). Its feasible unit/bin/runner/manifest tests passed when run separately as listed above. This gate is unrelated to Task 7 and requires native approved sample artifacts.

`rustup target list --installed` reported only `x86_64-pc-windows-msvc`. Therefore no Linux cross-compilation was attempted, and no target was downloaded. Windows compilation verifies only the non-Linux branch.

## Linux gate evidence: BLOCKED

- Host OS is Windows; the crate's native Linux adversarial tests are conditionally compiled only for Linux and did not run.
- No Linux Rust target is installed; there is no Linux compile result for the syscall module.
- Consequently there is no native evidence for namespace creation, bind-remount flags, `pivot_root`, seccomp behavior, descriptor closure under Linux, or any adversarial filesystem test. Do not treat the Windows `UnsupportedPlatform` test as Linux proof.
- Required next verification is to run `cargo test -p fluxform-sandbox-probe --test linux_filesystem --offline` and strict Clippy on a supported Linux CI/host, then inspect the actual `FilesystemPrerequisites` evidence there.

## Concerns and limitations

- Linux-specific FFI code has not been type-checked or executed by a Linux target in this environment; a manual cfg-hidden static audit corrected a missing wait-status binding and a non-comparable `Result` check, but native compile/test remains a release gate.
- Kernels or configurations lacking user namespaces, mount namespaces, `pivot_root`, seccomp, `close_range`, or `clone3(CLONE_INTO_CGROUP)` are rejected rather than downgraded. The barrier placement mode is the explicit alternative to atomic cgroup clone, not a post-spawn attach fallback.
- Real cgroup/resource and network containment is not implemented by Task 7; the interfaces and placement barrier only make that safe integration possible.
- The full workspace remains blocked by the missing approved native sample artifact root described above.

## Commit

Commit subject required by the task: `feat(server): prove Linux filesystem isolation`.

Report path: `.superpowers/sdd/2026-09-25-fluxform-stage-0-feasibility/task-7-report.md`.
