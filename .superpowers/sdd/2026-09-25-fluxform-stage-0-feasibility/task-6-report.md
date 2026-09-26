# Task 6 Report: Validated Same-Directory Atomic Output

Status: **BLOCKED — implementation is fail-closed, but the required Windows handle-relative rename gate did not pass on the available host.**

## Scope and implementation

Added `fluxform-atomic-output` with retained trusted-root/task-directory handles, validated single-component names, exclusive sibling partial/journal creation, identity-bound recovery records, abort/validate/commit state transitions, FFmpeg argv construction, and an FFprobe validator. The output expectation is derived from the existing Task 4/5 manifest and sample types; those types and gates were not weakened.

Windows uses `NtCreateFile` with `OBJECT_ATTRIBUTES.RootDirectory` for relative create/open operations and only `SetFileInformationByHandle(FileRenameInfo)` with the retained task-directory handle as `RootDirectory` for commit. Linux uses `openat2` confinement and `renameat2`; macOS uses `openat`/`O_NOFOLLOW` and `renameatx_np`. The macOS/Linux adapters are cfg-gated and were not compiled or executed on this host. There is no `MoveFileExW`, `ReplaceFileW`, delete-then-rename, pathname-based commit, destination precheck, or fallback to an absolute rename.

FFprobe is spawned directly without a shell, with fixed argv, exact `file,pipe` whitelist, bounded stdout/stderr capture, and a 20-second timeout. The approved-candidate media integration gate remains blocked and is explicitly ignored; generated JSON validator tests are not represented as approved FFprobe evidence.

## RED / GREEN evidence

- Initial RED, before implementation: `cargo test --offline -p fluxform-atomic-output --test commit` failed because the package/API and `fluxform_atomic_output` module did not exist.
- Additional RED: `cargo test --offline --locked --target-dir "$env:TEMP\fluxform-task6-target" -p fluxform-atomic-output --lib native_tests::windows_relative_rename_name_range_error_is_classified_as_unsupported -- --exact` failed because Win32 error 206 was not yet classified as an unsupported relative-rename result. After adding the fail-closed mapping, the same test passed.
- Additional RED: `cargo test --offline --locked --target-dir "$env:TEMP\fluxform-task6-target" -p fluxform-atomic-output --test commit image_args_name_map_muxer_and_video_codec_only -- --exact` showed argv omitted `-y`, which would make FFmpeg reject the exclusively pre-created partial. After adding fixed `-y` for the owned partial and updating image/audio/mixed argv tests, the same test passed.
- Focused GREEN: `cargo test --offline --locked --target-dir "$env:TEMP\fluxform-task6-target" -p fluxform-atomic-output --all-targets -- --nocapture` — unit tests 9/9 passed; integration tests 13 passed, 1 intentionally ignored. Output explicitly records error 87, crash-after-rename blocked, and `3/14` injected boundaries exercised with the remaining `11/11` post-rename boundaries blocked by the native rename gate.
- 1,000-race test ran in the final package command: `committed=0`, `aborted=952`, `blocked_by_native_rename=48`. The blocked results are recorded as blocked—not successful commits—and final output was never partial or redirected.
- A final focused package run and final full offline workspace run passed. One earlier workspace run exposed error 206 in the directory-swap case; after adding the specific fail-closed classification and regression test, the final suites passed. The isolated crash gate also passed 10/10 repeat runs after the earlier one-off 206 observation.
- Workspace GREEN: `cargo test --offline --locked --target-dir "$env:TEMP\fluxform-task6-target" --workspace --exclude fluxform-capabilities` passed: atomic output 22 tests (1 ignored), FFmpeg profile 33 tests, protocol 21 tests, plus doc tests. `fluxform-capabilities` was excluded because Task 5's documented approved-native-sample gate requires absent external reports; its dependency still compiled.
- Static checks GREEN: `cargo fmt --all -- --check`; `cargo clippy --offline --locked --target-dir "$env:TEMP\fluxform-task6-target" --workspace --all-targets -- -D warnings`; `git diff --check`.
- Commit subject: `feat(runtime): prove atomic output commits`.

## Native Windows gate

Host evidence: Windows `Microsoft Windows NT 10.0.26200.0`; `.NET DriveInfo` reports `C:` as NTFS. The test calls the actual handle-relative `SetFileInformationByHandle(FileRenameInfo)` path with a retained directory handle and a relative single-component name. It consistently returned raw Win32 error 87 (`ERROR_INVALID_PARAMETER`) on this host. The public commit path maps that to `AtomicCommitUnsupported`; tests verify the final path is not created/replaced and no pathname fallback is attempted. A diagnostic absolute-name call was used only to isolate the invocation and was removed; it is not present in production or tests as a fallback.

Error 206 (`ERROR_FILENAME_EXCED_RANGE`) also appeared in a directory-swap/crash-child run and was classified as unsupported for this relative rename path. Microsoft documents `RootDirectory` as a directory handle when `FileName` is relative ([FILE_RENAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)); therefore the evidence is an unresolved invocation/host gate, **not** a claim that Windows or NTFS generally lacks the primitive.

The crash-before-rename process-termination test and concurrent observers ran. Crash-after-rename was not reached: the handle-relative API returned `AtomicCommitUnsupported` before the injected boundary. The failure-injection harness covers every replacement boundary, but only the three pre-rename failures executed; all eleven post-rename injection cases are blocked until the primitive succeeds. The process-crash test covers process termination, not sudden power loss. Windows directory `sync_directory` is intentionally a no-op because this implementation does not claim a documented general directory-handle flush contract.

The Windows directory-swap attempt itself was denied while the task handle remained open (sharing violation, error 32); the directory handle intentionally does not grant share-delete. The test's alternate branch remains for platforms where renaming an open directory is permitted and still verifies handle confinement.

## Blocked evidence and residual concerns

- Windows happy-path no-replace/replace commit and crash-after-rename evidence: **BLOCKED** by the observed error 87 (and error 206 in the directory-swap invocation); the API remains fail-closed.
- ReFS test run/filesystem evidence: **BLOCKED**; no ReFS volume was available. The observed NTFS gate does not stand in for ReFS.
- macOS and Linux native execution, and cross-target compilation: **BLOCKED**; only `x86_64-pc-windows-msvc` was installed. No native evidence is claimed.
- Approved FFprobe artifact/sample acceptance and rejection integration: **BLOCKED**; Task 5 identifies the local artifact as an unapproved candidate, so it was not run or represented as evidence.
- Residual path-use race for later integration: `partial_path()` verifies directory identity before returning a lexical path for FFmpeg/FFprobe. On Unix a directory may be swapped after that check and before a child opens the path. Retained-handle creation/commit stays confined, but child path-based I/O has a TOCTOU window; this was not expanded beyond the Task 6 interfaces and should be resolved before connecting the crate to a hostile multi-user output directory. Windows' task-directory handle omits share-delete, so the tested directory move is denied while it remains open.

No network access, publishing, or C# changes were made.
