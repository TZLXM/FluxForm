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
- Replaces standard streams with `/dev/null`, reserves internal descriptors above stdio, and uses `close_range` to close undeclared inherited descriptors before namespace setup while retaining only pinned policy handles plus setup-report/placement descriptors; after release it retains only the pinned executable for the tool fork/exec. The probe actively checks `close_range` and fails closed if unavailable.
- Applies `RLIMIT_FSIZE` and `RLIMIT_NOFILE`, sets `no_new_privs`, drops/verifies capability sets, uses a restrictive seccomp filter for mount/namespace operations and process-group escape, and executes the selected program directly with `execveat(AT_EMPTY_PATH)` from a pinned executable descriptor and an empty environment. No shell is invoked.
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

## Review round 2 — required fixes

Both Important findings were verified against the previous implementation: it executed the tool by a mutable `/tool/<relative>` name after preparing the policy, and performed unbounded-in-practice task/tool tree walks (up to 200,000 entries) for every spawn. Round 2 supersedes the corresponding round-1 implementation notes above:

1. **Pinned paths, executable, and mutation revalidation:** input, task, and tool mount sources still use retained O_PATH descriptors. The approved executable descriptor is retained through placement and invoked with `execveat(AT_EMPTY_PATH)`, so replacing its directory name cannot redirect execution. The trusted tool inventory snapshots each entry's device/inode identity, link count, mount ID, mode, size, and modification/change timestamps. It pins directory handles and revalidates directory metadata and each named entry immediately before binding, before readiness, and again after placement release (or inside the atomically placed child before exec). Replacements, inserted hard links to the input, content/metadata changes, and nested mounts fail closed. Stable unrelated hard links are allowed; input/tool identity aliasing is not.
2. **Bounded inventory and fresh task directory:** task contents are no longer recursively scanned. Preparation requires an empty task directory and a retained read descriptor performs a bounded `getdents64` empty check before binding, before readiness, and after release just before tool fork/exec. Trusted tools are inventoried under fixed limits of 256 entries, 32 directories, and depth 8; exceeding any limit fails closed. The inventory is revalidated via retained directory handles and one transient pinned entry descriptor at a time. Unrelated inherited descriptors are closed before setup checks, and `open_files_max` must be at least 44 to reserve descriptor numbers for the maximum pinned inventory and transient validation. The small limits avoid request-sized task scans but may require policy adjustment for unusually large packaged tool trees.
3. **Deterministic Linux regression tests:** added Linux-only tests that mutate/replace a tool name between inventory preparation and validation and while the supervisor waits for placement, insert an input hard link after preparation, mutate a task directory after its empty check and while waiting for placement, exceed the fixed inventory bound, and execute the previously pinned ELF after its pathname is replaced. The existing symlink adversarial test now has the sandboxed test tool create the symlink after release, preserving the new empty-task requirement while still testing that `/etc/passwd` stays outside the minimal root. These tests are Linux-only and did not run on this Windows host.

Review-round TDD and verification evidence:

- RED: `cargo test -p fluxform-sandbox-probe --lib --offline` failed to compile because `ToolInventory`, `ToolEntryEvidence`, `validate_empty_task_snapshot`, and `validate_tool_inventory` were missing. Implemented the evidence types/validators and Linux pinned inventory/revalidation after this failure.
- RED: after a static descriptor-budget review, a new portable regression test failed to compile because `validate_open_files_limit` was not implemented. The helper now enforces the minimum descriptor budget used by the Linux setup.
- GREEN on Windows: `cargo test -p fluxform-sandbox-probe --offline` passed **10 tests total** (8 library tests, 2 portable integration tests). The Linux race tests are cfg-excluded here; this result verifies portable behavior only.
- `cargo fmt --all` passed.
- `cargo fmt --all -- --check` passed.
- `cargo clippy --workspace --all-targets --offline -- -D warnings` passed on the Windows target only.
- `cargo test --workspace --exclude fluxform-capabilities --offline` passed. The feasible capabilities tests passed separately with `cargo test -p fluxform-capabilities --lib --bins --test runner --test manifest --offline`.
- `git diff --check` passed.
- `cargo test --workspace --offline` was run. Crates/tests reached before `fluxform-capabilities/tests/cross_platform_samples.rs::every_approved_native_profile_has_a_current_sample_report` passed; that gate failed with `BLOCKED: collected artifact root is missing or unreadable` (Windows OS error 3), matching the existing missing-artifacts gate. The workspace command therefore exited nonzero.
- `rustup target list --installed` reports only `x86_64-pc-windows-msvc`. No Linux target was installed, so cross-compilation was not attempted and no target was downloaded.

## Linux gate evidence: BLOCKED (review round 2)

The new pinned-exec, bounded-inventory, mutation, and task-emptiness tests have **not** been type-checked or run for a Linux target in this environment. Do not interpret the Windows tests as Linux evidence. Required follow-up remains a Linux x86_64/aarch64 run of the crate tests and strict Clippy, including the new Linux-only adversarial tests and actual `FilesystemPrerequisites` evidence.

Static review for this round confirms that child-side revalidation is bounded by the fixed inventory limits and uses retained directory descriptors plus stack buffers/raw syscalls (no recursive task walk or heap-built inventory after fork); the tool is not forked or execed until atomic cgroup placement or the parent release barrier succeeds. Actual Linux compiler/type checking and native behavior remain release gates.

The changes and this appendix are included under the required commit subject: `feat(server): prove Linux filesystem isolation`.

## Review round 1 — required fixes

The three Important findings were checked against the implementation and addressed:

1. **Policy path overlap and aliasing:** policy input/task/tool roots are opened component-by-component from `/` using `openat(O_PATH|O_NOFOLLOW)`; symlink components and non-absolute/dot paths fail closed. Device/inode identities and ancestor chains are taken from those opened handles, not from a canonicalize-then-reopen path. Task/tool trees are walked through pinned directory descriptors, regular-file identities and link counts are compared, and overlapping roots, input-under-task, tool/task nesting in either direction, identical roots, and hard links are rejected. The root descriptors are retained through `fork`, checked with `fstat` against their recorded dev/inode immediately before bind mount, and the input link count is rechecked.
2. **Readiness/report pipe writes:** the shared writer retries injected or actual `EINTR`, completes partial writes, and propagates zero/error results. Readiness and report-message callers check the result; an incomplete ready report exits and closes the relevant descriptors instead of entering the release wait. Failure reporting remains best-effort only when the child is already exiting, and closes the report descriptor if that write fails.
3. **Linux architecture support:** the syscall module, child type, prerequisite inspector, and spawn implementation are compiled only for Linux x86_64/aarch64. All other platforms/architectures return `UnsupportedPlatform`. The seccomp audit-architecture mapping has no zero fallback.

Review-round TDD evidence:

- Added Linux-only regression policies before the path implementation for input nested under task, task/tool nesting both ways, symlinked roots and ancestors, identical roots, input inside tool, and hard-link aliases across input/task/tool. Their Linux-native RED/GREEN behavior is **BLOCKED** on this Windows host; these tests are not counted as passed.
- Added portable identity-graph tests, injected `EINTR`/partial-write tests, `BrokenPipe` propagation tests, and audit-architecture mapping tests before their helpers. The first portable RED command, `cargo test -p fluxform-sandbox-probe --lib --offline`, failed compilation because the new helper/type names were not implemented yet. After implementation, that command passed **4/4**.
- Final portable package GREEN: `cargo test -p fluxform-sandbox-probe --offline --all-targets` passed **6/6** (four helper tests plus evidence serialization and Windows `UnsupportedPlatform`). These results do not establish Linux isolation.

Final review-round checks:

```text
cargo fmt --all -- --check                                      PASS
cargo clippy --workspace --all-targets --offline -- -D warnings PASS
cargo test -p fluxform-sandbox-probe --offline --all-targets    PASS (6 tests)
cargo test --workspace --exclude fluxform-capabilities --offline PASS
cargo test -p fluxform-capabilities --lib --bins --test runner --test manifest --offline PASS
git diff --check                                                PASS
```

`cargo test --workspace --offline` was rerun; all tests before `cross_platform_samples::every_approved_native_profile_has_a_current_sample_report` passed, and that gate remains **BLOCKED** because its approved artifact root is missing/unreadable (Windows OS error 3). Only `x86_64-pc-windows-msvc` is installed (`rustup target list --installed`); no Linux cross-compilation was attempted and no target was downloaded. The Linux native filesystem and adversarial test gate remains **BLOCKED**, not passed or skipped.

Static Linux review confirms that ready-pipe `EINTR` retries, write errors terminate the supervisor before a release wait, report-pipe failure closes/exits, and unsupported architectures cannot reach a seccomp filter with audit arch zero. Native Linux compilation and execution are still required before treating these fixes as verified.
