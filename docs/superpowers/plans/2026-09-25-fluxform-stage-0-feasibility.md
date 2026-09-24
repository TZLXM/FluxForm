# FluxForm Stage 0 Feasibility Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish executable contracts and pass/fail evidence for the five assumptions that can invalidate the Rust rewrite: protocol stability, FFmpeg distribution capability, atomic output, anonymous-upload security, and cross-platform transparent-window behavior.

**Architecture:** Add an isolated Rust workspace beside the existing .NET solution. Stage 0 contains probes rather than product adapters: a versioned protocol crate, an FFmpeg profile inspector, an atomic-output proof, a minimal Axum upload/security probe, and a minimal Tauri window probe. Every probe emits machine-readable evidence into one gate report. No existing WPF, CLI, Core, installer, or release path is replaced in this plan.

**Tech Stack:** Rust 1.94.1, Cargo, Tokio, Serde, Schemars, Axum, SQLite via rusqlite, Tauri 2, PowerShell/Bash verification scripts, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-25-fluxform-rust-water-platform-design.md`

**Global Constraints:** Preserve the current C# implementation as the runnable baseline. Do not implement Water Lab, production conversion, public deployment, desktop packaging, or MCP in this plan. Do not accept raw FFmpeg arguments, client-supplied server paths, bearer tokens in URLs, or output writes outside a task-owned directory. All generated contracts and evidence must be deterministic after volatile fields are removed.

**Review Focus:** Treat a false-positive gate as the highest-risk defect. In particular, review whether upload bytes are rejected while streaming, whether capability tokens authorize every protected operation, whether the Linux sandbox test proves both filesystem and network denial, whether FFmpeg output format is explicit despite partial filenames, and whether transparent-window results distinguish visual transparency from input hit-testing.

---

## Why this is a separate plan

The approved design contains six later stages with different release surfaces. Their detailed plans depend on Stage 0 results:

- Water rendering depends on the stable protocol fixtures and the desktop transparency fallback.
- The conversion engine depends on the approved FFmpeg build profile and atomic-commit adapter.
- The web application depends on a proven upload, authorization, cleanup, and Linux sandbox model.
- The desktop application depends on platform-specific window and offline WebView findings.
- MCP depends on the final local-runtime contract.

Write one implementation plan per later stage only after this plan records all required decisions. A failed gate changes the architecture; it must not be papered over by continuing implementation.

## Spec Traceability

| Approved design requirement | Stage 0 evidence |
|---|---|
| Versioned request, event, error, revision, replay semantics | Tasks 1, 2, and 6 |
| Fixed capability manifest constrained by an approved FFmpeg build | Task 3 |
| Explicit muxer/codec and same-directory atomic output | Task 4 |
| No-network, resource-limited Linux worker | Task 5 |
| Streaming limits, reservations, IP quota primitives, token authorization | Task 6 |
| Transparent independent windows and platform fallbacks | Task 7 |
| Offline Windows first launch with bundled conversion dependencies | Tasks 3 and 7 |
| Legacy implementation remains available during migration | Tasks 1 and 8 |
| Evidence-backed gate before Water Lab and product code | Task 8 and final verification |

## Target File Structure

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
.cargo/config.toml
config/
  ffmpeg-profile.toml
contracts/v1/
  conversion-request.schema.json
  job-event.schema.json
  error.schema.json
  fixtures/
    create-image-job.json
    completed-image-job.json
    unsupported-conversion.json
crates/
  fluxform-protocol/
    Cargo.toml
    src/lib.rs
    src/bin/export_contracts.rs
    tests/contracts.rs
  fluxform-ffmpeg-profile/
    Cargo.toml
    src/lib.rs
    src/main.rs
    tests/profile.rs
  fluxform-atomic-output/
    Cargo.toml
    src/lib.rs
    tests/commit.rs
  fluxform-sandbox-probe/
    Cargo.toml
    src/lib.rs
    src/bin/sandbox-child.rs
    tests/linux_sandbox.rs
apps/
  server-probe/
    Cargo.toml
    src/lib.rs
    src/main.rs
    tests/upload_security.rs
  desktop-probe/
    package.json
    src-tauri/Cargo.toml
    src-tauri/tauri.conf.json
    src-tauri/capabilities/default.json
    src-tauri/src/main.rs
    ui/index.html
    ui/styles.css
    ui/probe.js
docs/architecture/
  adr/0001-ffmpeg-distribution-profile.md
  stage-0-gate-report.md
scripts/
  check-stage0.ps1
  check-stage0.sh
.github/workflows/stage0-gates.yml
```

Add each new Rust crate to the root workspace in the task that creates it. Keep the desktop probe as a workspace member through its `src-tauri/Cargo.toml`; the static probe UI does not introduce a JavaScript workspace.

## Task 1: Bootstrap the Rust Workspace Through the Protocol Contract

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `.cargo/config.toml`
- Create: `crates/fluxform-protocol/Cargo.toml`
- Create: `crates/fluxform-protocol/src/lib.rs`
- Create: `crates/fluxform-protocol/tests/contracts.rs`

**Interfaces:**
- `ConversionRequestV1`
- `OutputTargetV1`
- `ConversionOptionsV1`
- `JobStateV1`
- `JobEventV1`
- `ErrorCodeV1`
- `ApiErrorV1`

- [ ] **Step 1: Add the workspace and a failing protocol test**

Pin Rust to the locally verified toolchain:

```toml
# rust-toolchain.toml
[toolchain]
channel = "1.94.1"
profile = "minimal"
components = ["clippy", "rustfmt"]
```

Create a Cargo workspace with resolver 3 and only `fluxform-protocol` as the first member. Add `serde`, `serde_json`, `schemars`, `thiserror`, and `uuid` as workspace dependencies. Then add `crates/fluxform-protocol/tests/contracts.rs`:

```rust
use fluxform_protocol::{
    CategoryV1, ConversionRequestV1, ErrorCodeV1, OutputTargetV1, OverwritePolicyV1,
    PROTOCOL_VERSION,
};

#[test]
fn managed_artifact_target_serializes_without_a_filesystem_path() {
    let request = ConversionRequestV1 {
        protocol_version: PROTOCOL_VERSION.to_owned(),
        input_ids: vec!["input_01".to_owned()],
        category: CategoryV1::Image,
        output_format: "png".to_owned(),
        output_target: OutputTargetV1::ManagedArtifact,
        overwrite_policy: OverwritePolicyV1::Reject,
        options: Default::default(),
        client_context: Default::default(),
    };

    let json = serde_json::to_value(request).unwrap();
    assert_eq!(json["output_target"]["kind"], "managed_artifact");
    assert!(json.to_string().find("path").is_none());
}

#[test]
fn error_codes_use_stable_snake_case_values() {
    assert_eq!(
        serde_json::to_string(&ErrorCodeV1::UnsupportedConversion).unwrap(),
        "\"unsupported_conversion\""
    );
}
```

- [ ] **Step 2: Run the test and verify the crate does not compile**

Run:

```powershell
cargo test -p fluxform-protocol --test contracts
```

Expected: FAIL because the protocol types do not exist.

- [ ] **Step 3: Implement the smallest versioned protocol model**

Implement the types in `crates/fluxform-protocol/src/lib.rs`. Use internally tagged enums for targets and events, deny unknown fields on request-bearing structs, and derive both `Serialize`/`Deserialize` and `JsonSchema`:

```rust
pub const PROTOCOL_VERSION: &str = "v1";

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CategoryV1 { Video, Audio, Image }

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OutputTargetV1 {
    ManagedArtifact,
    LocalDirectory { directory_token: String },
    LocalPath { path_token: String },
    ManagedJobDirectory,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OverwritePolicyV1 { Reject, Rename, Replace }
```

The request must use `input_ids`, not raw paths. Adapter-specific tokens are opaque strings whose validation belongs to the adapter. Add every state, event, and error code listed in sections 5.2 and 5.3 of the spec. Model `revision` as `u64` and serialize it on every event and snapshot.

- [ ] **Step 4: Add invariants to the tests**

Extend the tests to prove:

- `protocol_version` is required and equals `v1` in the canonical fixture.
- unknown request fields are rejected;
- every job event contains `job_id` and a positive `revision`;
- terminal states cannot be confused with `cancelling`;
- `ApiErrorV1` serializes `code`, `message`, and optional redacted `diagnostic_id`, never a command line or absolute path.

- [ ] **Step 5: Run formatting, lint, and tests**

Run:

```powershell
cargo fmt --all -- --check
cargo clippy -p fluxform-protocol --all-targets -- -D warnings
cargo test -p fluxform-protocol
```

Expected: all commands PASS.

- [ ] **Step 6: Commit**

```powershell
git add Cargo.toml Cargo.lock rust-toolchain.toml .cargo/config.toml crates/fluxform-protocol
git commit -m "feat(protocol): add versioned conversion contract"
```

## Task 2: Export Deterministic Schemas and Contract Fixtures

**Files:**
- Create: `crates/fluxform-protocol/src/bin/export_contracts.rs`
- Modify: `crates/fluxform-protocol/src/lib.rs`
- Modify: `crates/fluxform-protocol/tests/contracts.rs`
- Create: `contracts/v1/conversion-request.schema.json`
- Create: `contracts/v1/job-event.schema.json`
- Create: `contracts/v1/error.schema.json`
- Create: `contracts/v1/fixtures/create-image-job.json`
- Create: `contracts/v1/fixtures/completed-image-job.json`
- Create: `contracts/v1/fixtures/unsupported-conversion.json`

**Interfaces:**
- `exported_contracts() -> BTreeMap<&'static str, serde_json::Value>`
- `canonical_fixtures() -> BTreeMap<&'static str, serde_json::Value>`

- [ ] **Step 1: Add a failing drift test**

The test must compare normalized JSON values rather than whitespace:

```rust
#[test]
fn committed_contracts_match_the_rust_source() {
    for (relative_path, expected) in fluxform_protocol::exported_contracts() {
        let path = workspace_root().join(relative_path);
        let committed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(committed, expected, "contract drift in {relative_path}");
    }
}
```

- [ ] **Step 2: Run the drift test and verify it fails**

```powershell
cargo test -p fluxform-protocol committed_contracts_match_the_rust_source
```

Expected: FAIL because `contracts/v1` does not exist.

- [ ] **Step 3: Implement deterministic schema and fixture generation**

Use `schemars::schema_for!` for the three public roots. Store outputs in a `BTreeMap`, remove only generator-version metadata, and pretty-print with a final newline. The exporter must refuse to write outside `<workspace>/contracts/v1`.

The create fixture must describe two image inputs sharing one PNG output format and one parameter set. The completed fixture must include a monotonic revision and a managed artifact ID. The error fixture must use `unsupported_conversion` and contain no local path.

- [ ] **Step 4: Generate and inspect the committed artifacts**

```powershell
cargo run -p fluxform-protocol --bin export-contracts
git diff -- contracts/v1
```

Expected: three schemas and three fixtures are created; no timestamps, machine paths, UUIDs, or unordered maps appear.

- [ ] **Step 5: Prove regeneration is clean**

Stage the first generated result, run the exporter a second time, then:

```powershell
git add contracts/v1
cargo run -p fluxform-protocol --bin export-contracts
git diff --exit-code -- contracts/v1
cargo test -p fluxform-protocol
```

Expected: PASS after the generated files are staged once; the second export changes nothing.

- [ ] **Step 6: Commit**

```powershell
git add crates/fluxform-protocol contracts/v1
git commit -m "feat(protocol): publish deterministic v1 fixtures"
```

## Task 3: Fingerprint and Approve the FFmpeg Distribution Profile

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `config/ffmpeg-profile.toml`
- Create: `crates/fluxform-ffmpeg-profile/Cargo.toml`
- Create: `crates/fluxform-ffmpeg-profile/src/lib.rs`
- Create: `crates/fluxform-ffmpeg-profile/src/main.rs`
- Create: `crates/fluxform-ffmpeg-profile/tests/profile.rs`
- Create: `docs/architecture/adr/0001-ffmpeg-distribution-profile.md`

**Interfaces:**
- `BuildProfile::load(path)`
- `ProbeReport::collect(ffmpeg, ffprobe)`
- `ProbeReport::validate(&BuildProfile)`
- CLI: `fluxform-ffmpeg-profile verify --profile <file> --ffmpeg <file> --ffprobe <file> --out <file>`

- [ ] **Step 1: Add failing policy tests**

Tests must reject a profile when:

- `ffmpeg` and `ffprobe` do not share the same version and configuration;
- required muxers, demuxers, encoders, decoders, or protocols are absent;
- a capability references an undeclared codec;
- the distribution record omits license, source revision, source-offer URL, artifact SHA-256, or target triple;
- `protocol_whitelist` contains `http`, `https`, `tcp`, `udp`, `srt`, `ftp`, `ssh`, or `crypto`.

Use captured command outputs under the test module as strings; do not require a real FFmpeg binary for unit tests.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-ffmpeg-profile
```

Expected: FAIL because the profile parser and validator do not exist.

- [ ] **Step 3: Implement the profile parser and process probe**

The process probe must execute only fixed argument vectors:

```rust
const PROBES: &[&[&str]] = &[
    &["-hide_banner", "-version"],
    &["-hide_banner", "-protocols"],
    &["-hide_banner", "-demuxers"],
    &["-hide_banner", "-muxers"],
    &["-hide_banner", "-decoders"],
    &["-hide_banner", "-encoders"],
];
```

Apply a timeout, capture bounded stdout/stderr, and hash both executables. Never invoke a shell. The JSON report must include target triple, file hashes, FFmpeg version, source revision when reported, build configuration, license declaration, and sorted capability lists.

- [ ] **Step 4: Encode the existing Windows build as an explicit candidate, not an implicit dependency**

The cached archive currently identifies itself as `8.1.1-essentials_build-www.gyan.dev`, GPL v3, source commit `239f2c733d`, and includes network support. Record those observed facts in the ADR. The ADR must state:

- FluxForm calls FFmpeg as a separate executable;
- redistribution obligations and patent exposure require owner/legal approval before public release;
- network-enabled FFmpeg builds remain constrained at invocation and by the server OS sandbox;
- Windows, macOS, and Linux artifacts must each have an immutable URL or internal artifact identity, SHA-256, license text, source correspondence, and an equivalent required-capability set;
- the Stage 0 gate is red until all three target rows are approved.

Do not claim that external-process separation settles licensing. Record the product owner's approval as a dated ADR decision before marking this gate green.

- [ ] **Step 5: Verify the cached Windows candidate**

Extract the archive into a temporary directory outside the repository, then run:

```powershell
$stage0Extract = Join-Path ([System.IO.Path]::GetTempPath()) 'FluxFormStage0Ffmpeg'
Expand-Archive -LiteralPath tools-cache/ffmpeg-release-essentials.zip -DestinationPath $stage0Extract -Force
$stage0Ffmpeg = (Get-ChildItem -LiteralPath $stage0Extract -Recurse -Filter ffmpeg.exe | Select-Object -First 1).FullName
$stage0Ffprobe = (Get-ChildItem -LiteralPath $stage0Extract -Recurse -Filter ffprobe.exe | Select-Object -First 1).FullName
cargo run -p fluxform-ffmpeg-profile -- verify `
  --profile config/ffmpeg-profile.toml `
  --ffmpeg $stage0Ffmpeg `
  --ffprobe $stage0Ffprobe `
  --out target/stage0/ffmpeg-windows-x86_64.json
```

Expected: PASS only if the hashes and required features match the profile. Never commit extracted binaries or their temporary path.

- [ ] **Step 6: Repeat the same verifier on macOS and Linux candidates**

Run the identical CLI on each target. The build versions may differ only if the ADR explicitly accepts the difference and all manifest-required codecs/muxers remain equivalent. Attach the three generated JSON reports to the gate evidence; do not commit binaries.

- [ ] **Step 7: Commit**

```powershell
git add Cargo.toml Cargo.lock config/ffmpeg-profile.toml crates/fluxform-ffmpeg-profile docs/architecture/adr/0001-ffmpeg-distribution-profile.md
git commit -m "build(ffmpeg): define verified distribution profile"
```

## Task 4: Prove Same-Directory Atomic Output Semantics

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/fluxform-atomic-output/Cargo.toml`
- Create: `crates/fluxform-atomic-output/src/lib.rs`
- Create: `crates/fluxform-atomic-output/tests/commit.rs`

**Interfaces:**
- `OutputReservation::create(final_path, job_id, extension)`
- `OutputReservation::partial_path()`
- `OutputReservation::commit(OverwritePolicyV1)`
- `OutputReservation::abort()`
- `FfmpegOutputSpec { muxer, video_codec, audio_codec }`

- [ ] **Step 1: Write failing filesystem contract tests**

Cover all of these cases in a temporary directory:

```rust
#[test]
fn partial_file_is_created_beside_the_final_file() { /* same parent */ }

#[test]
fn reject_never_replaces_an_existing_destination() { /* bytes unchanged */ }

#[test]
fn rename_commits_to_a_unique_sibling_without_race_prone_precheck() { /* two writers */ }

#[test]
fn abort_removes_only_the_owned_partial_file() { /* final file preserved */ }

#[test]
fn ffmpeg_output_args_name_muxer_and_codecs_explicitly() { /* includes -f/-c:v/-c:a */ }
```

Also add a process-crash test helper that leaves a `.fluxform-<job-id>.partial.<ext>` file, then prove reconciliation recognizes only files with a valid owned journal record.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-atomic-output
```

Expected: FAIL because the reservation API does not exist.

- [ ] **Step 3: Implement no-clobber and replace as platform adapters**

Create the partial file with `create_new(true)` in the destination directory. Keep the file handle and journal until commit. Implement:

- Windows with the documented Win32 rename/replace primitive and write-through flag;
- macOS with the documented `renameatx_np` no-replace/swap behavior;
- Linux with `renameat2` and `RENAME_NOREPLACE` where supported.

Do not implement `replace` as delete-then-rename. Return `AtomicCommitUnsupported` when the filesystem or platform primitive cannot meet the contract. Flush file contents before commit and sync the parent directory where the platform supports it.

- [ ] **Step 4: Linearize cancellation and finalization**

Add an internal state lock with only these transitions:

```text
Writing -> Aborted
Writing -> Committing -> Committed
```

Once `Committing` begins, `abort()` returns `CommitInProgress`; it must not delete or rename anything. Add a concurrency test that races `abort` and `commit` 1,000 times and accepts only the two valid terminal outcomes.

- [ ] **Step 5: Run on all three target operating systems**

```powershell
cargo test -p fluxform-atomic-output --all-targets
```

Expected: PASS on Windows, macOS, and the supported Linux filesystem. Record filesystem type and kernel/OS version in the gate evidence. Network filesystems are not accepted based on a local-disk pass.

- [ ] **Step 6: Commit**

```powershell
git add Cargo.toml Cargo.lock crates/fluxform-atomic-output
git commit -m "feat(runtime): prove atomic output commits"
```

## Task 5: Prove Linux Worker Sandboxing

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/fluxform-sandbox-probe/Cargo.toml`
- Create: `crates/fluxform-sandbox-probe/src/lib.rs`
- Create: `crates/fluxform-sandbox-probe/src/bin/sandbox-child.rs`
- Create: `crates/fluxform-sandbox-probe/tests/linux_sandbox.rs`

**Interfaces:**
- `SandboxPolicy { input, job_dir, tool_dir, limits }`
- `Sandbox::self_check(policy) -> SandboxEvidence`
- `Sandbox::spawn(program, args, policy)`

- [ ] **Step 1: Add Linux-only failing adversarial tests**

The child binary accepts a fixed test action enum. The integration test launches it through the sandbox and must prove:

- reading the assigned input succeeds;
- reading `/etc/passwd` fails;
- writing inside the assigned job directory succeeds;
- writing to its parent or `/tmp` fails;
- opening an IPv4 or IPv6 TCP socket fails;
- spawning beyond the process limit fails;
- exceeding the output-file limit fails;
- timeout kills the full process group, including a grandchild.

On non-Linux hosts, compile the crate but return `UnsupportedPlatform`; do not report a skipped test as a green public-server gate.

- [ ] **Step 2: Run on Linux and verify failure**

```bash
cargo test -p fluxform-sandbox-probe --all-targets
```

Expected: FAIL because sandbox creation is not implemented.

- [ ] **Step 3: Implement the minimum rootless Linux sandbox**

Use a child-process pre-exec boundary with no shell. The supported public-server path must combine:

- Linux user, mount, PID, and network namespaces;
- a minimal `pivot_root` filesystem assembled from bind mounts;
- read-only tool and input exposure;
- one writable task directory;
- no inherited descriptors except the declared pipes/files;
- seccomp filtering that also denies socket creation;
- `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, and `RLIMIT_NPROC`;
- a new process group that can be terminated as a tree;
- `no_new_privs` and a closed capability set.

If any required primitive is unavailable, `self_check` must return a hard error. Public mode is not allowed to fall back to an unsandboxed worker.

- [ ] **Step 4: Verify FFmpeg cannot escape the same policy**

Run the approved Linux `ffprobe` candidate against one valid local sample and one URL input. The local probe must succeed. The URL attempt must fail before network access; the invocation must also include a fixed `-protocol_whitelist file,pipe`.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/fluxform-sandbox-probe
git commit -m "feat(server): prove fail-closed Linux sandbox"
```

## Task 6: Prove Streaming Upload, Reservation, and Capability Authorization

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `apps/server-probe/Cargo.toml`
- Create: `apps/server-probe/src/lib.rs`
- Create: `apps/server-probe/src/main.rs`
- Create: `apps/server-probe/tests/upload_security.rs`

**Interfaces:**
- `POST /v1/upload-sessions`
- `PUT /v1/upload-sessions/{id}/content`
- `GET /v1/jobs/{id}`
- `GET /v1/jobs/{id}/events`
- `DELETE /v1/jobs/{id}`
- `UploadLedger::reserve(ip_key, declared_bytes)`
- `Capability::issue(scope, expires_at)`
- `Capability::verify(token, required_scope)`

- [ ] **Step 1: Add failing black-box HTTP tests**

Use `tower::ServiceExt` against the router without binding a port. Cover:

- a declared size over the hard limit is rejected before a session is created;
- a web request using `local_directory`, `local_path`, or `managed_job_directory` is rejected before job creation;
- missing `Content-Length` reserves the configured per-file maximum;
- two concurrent reservations cannot exceed the global reserved-byte limit;
- the body is stopped and the partial file removed on the first chunk that crosses the actual byte limit;
- an interrupted upload expires and releases its reservation exactly once;
- a token is at least 32 random bytes before encoding, only its SHA-256 hash is stored, and it is returned once;
- absent, expired, wrong-scope, and cross-job tokens receive `401` or `403` on status, event, cancel, and download-like operations;
- no response body contains a server absolute path;
- SSE accepts `Authorization: Bearer`, emits monotonic `id:` revisions, replays a retained range, and emits `resync_required` after a gap.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-server-probe --test upload_security
```

Expected: FAIL because the router and ledger do not exist.

- [ ] **Step 3: Implement the transactional SQLite ledger**

Use SQLite transactions for reservation, actual-byte settlement, daily-IP counters, expiration, and release. Hash the normalized IP plus a rotating server secret before storage; do not store raw IP addresses. Every release operation must be idempotent and conditioned on the current lifecycle state.

Required upload states:

```text
reserved -> receiving -> uploaded -> probing -> queued
reserved|receiving -> expired|rejected
```

The state transition and reserved-byte delta belong to the same transaction. Filesystem deletion happens after commit and a reconciler retries failed deletions.

- [ ] **Step 4: Implement streaming enforcement**

Consume `Body::into_data_stream()` one chunk at a time. For each chunk:

1. update a checked byte counter;
2. reject before writing if the new total exceeds the hard limit or reservation;
3. enforce idle and total deadlines;
4. check the disk safety watermark;
5. write only to the session-owned file opened with exclusive creation.

Do not call `to_bytes` with an unbounded limit, buffer the whole body, or trust `Content-Length` as the final count.

- [ ] **Step 5: Implement scoped bearer capabilities and fetch-compatible SSE**

Generate 32 bytes from the operating-system CSPRNG. Return the base64url token once, persist only its hash, job/session ID, scope set, and expiry, and compare hashes in constant time. Never accept the token in a path or query string. The SSE endpoint must use the same authorization middleware as other protected endpoints.

- [ ] **Step 6: Run tests under forced small chunks and concurrency**

```powershell
cargo test -p fluxform-server-probe --all-targets
```

Expected: PASS with test bodies split before, exactly at, and one byte beyond each limit; the database invariant `reserved_bytes >= 0` holds after concurrent tests.

- [ ] **Step 7: Commit**

```powershell
git add Cargo.toml Cargo.lock apps/server-probe
git commit -m "feat(server): prove anonymous upload security"
```

## Task 7: Build the Cross-Platform Transparent Window Probe

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `apps/desktop-probe/package.json`
- Create: `apps/desktop-probe/src-tauri/Cargo.toml`
- Create: `apps/desktop-probe/src-tauri/tauri.conf.json`
- Create: `apps/desktop-probe/src-tauri/capabilities/default.json`
- Create: `apps/desktop-probe/src-tauri/src/main.rs`
- Create: `apps/desktop-probe/ui/index.html`
- Create: `apps/desktop-probe/ui/styles.css`
- Create: `apps/desktop-probe/ui/probe.js`

**Interfaces:**
- Tauri command `record_probe_result(result)`
- Tauri event `probe://file-drop`
- JSON evidence for transparency, drag, file drop, hit testing, focus, and close behavior

- [ ] **Step 1: Add failing Rust tests for evidence completeness**

The result model must require all fields:

```rust
pub struct WindowProbeResult {
    pub os: String,
    pub os_version: String,
    pub display_server: String,
    pub transparent_pixels_visible: bool,
    pub transparent_pixels_click_through: bool,
    pub frameless_drag_works: bool,
    pub file_drop_works: bool,
    pub focus_recovery_works: bool,
    pub idle_cpu_percent: f32,
    pub idle_gpu_percent: f32,
    pub notes: String,
}
```

Tests reject an unknown display server, negative percentages, or a supposedly passing record without all five behavioral checks.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test --manifest-path apps/desktop-probe/src-tauri/Cargo.toml
```

Expected: FAIL because the probe model does not exist.

- [ ] **Step 3: Create the smallest visible probe**

Configure one 360×360, transparent, undecorated window. Enable Tauri's required macOS private API setting for transparent windows and configure the Windows bundle probe to use the offline WebView2 installer mode. The UI contains a circular translucent CSS surface, a visible pixel grid behind its transparent corners, a drag handle, a file-drop counter, a focus counter, and a button that saves the result JSON. This is not the final water shader.

The UI must show the exact manual test order:

1. verify the desktop is visible through all four corners;
2. click a control behind each transparent corner;
3. drag the window from the orb surface;
4. drop a file on the surface and outside the circle but inside window bounds;
5. switch away and restore focus ten times;
6. measure 60 seconds of idle CPU/GPU.

- [ ] **Step 4: Run the platform matrix**

Execute and save evidence for:

- Windows 11 with the bundled/offline WebView2 strategy under consideration;
- macOS on both Intel or Rosetta where supported and Apple Silicon, using the intended direct distribution path;
- Linux X11;
- Linux Wayland.

For Wayland, record lack of global positioning or always-on-top support as an explicit degraded capability rather than a generic failure. Visual transparency and transparent-pixel click-through are separate results.

For Windows, build the probe installer with `webviewInstallMode.type = "offlineInstaller"`, disconnect a clean Windows 11 VM before installation, and prove installation plus first launch without a pre-existing evergreen WebView2 runtime or network access. Record installer size and first-launch result. If the offline installer mode cannot satisfy this, Stage 0 remains red until a fixed-runtime design is tested and approved.

- [ ] **Step 5: Make the architecture decision from evidence**

Record exactly one supported behavior per platform in the gate report:

- `transparent-orb` when all required checks pass;
- `transparent-window-with-rectangular-hit-region` only if the product owner accepts the interaction consequence;
- `opaque-frameless-fallback` when transparency or hit testing is unreliable;
- `unsupported` when file drop, focus, or stable rendering fails.

Do not silently map a red result to green. If the accepted fallback changes the spec, amend the spec and obtain user approval before Stage 1.

- [ ] **Step 6: Commit**

```powershell
git add Cargo.toml Cargo.lock apps/desktop-probe
git commit -m "test(desktop): add transparent window feasibility probe"
```

## Task 8: Add Reproducible Gate Commands and CI

**Files:**
- Create: `scripts/check-stage0.ps1`
- Create: `scripts/check-stage0.sh`
- Create: `.github/workflows/stage0-gates.yml`
- Create: `docs/architecture/stage-0-gate-report.md`
- Create: `crates/fluxform-protocol/tests/stage0_scripts.rs`
- Modify: `AGENTS.md`

**Interfaces:**
- PowerShell: `./scripts/check-stage0.ps1 [-Ffmpeg <path>] [-Ffprobe <path>]`
- Bash: `./scripts/check-stage0.sh [--ffmpeg <path>] [--ffprobe <path>]`

- [ ] **Step 1: Add a failing repository-policy test**

Add `crates/fluxform-protocol/tests/stage0_scripts.rs`. Read both scripts from the workspace root and assert they:

- run format, clippy, and all Stage 0 tests;
- regenerate contracts and fail on drift;
- invoke the FFmpeg verifier when paths are supplied;
- require the Linux sandbox suite in public-server mode;
- never download a tool or dependency implicitly;
- write volatile evidence only under `target/stage0`.

- [ ] **Step 2: Implement both scripts with matching semantics**

Scripts must stop at the first failure and print a final summary containing each gate name and status. They may read candidate binaries but must not modify `tools-cache`, `publish`, or the existing .NET projects.

- [ ] **Step 3: Add the CI matrix**

The workflow must use minimum `contents: read`, dependency caching keyed by lockfiles, and concurrency cancellation. Required jobs:

- Windows: protocol, FFmpeg parser fixtures, atomic output, server-probe unit tests, desktop-probe compile;
- macOS: protocol, atomic output, desktop-probe compile;
- Ubuntu: protocol, atomic output, server-probe tests, sandbox adversarial tests, desktop-probe compile under X11-capable dependencies.

Do not mark manual transparent-window checks as automated. Upload non-secret test reports as artifacts; never upload capability tokens or uploaded sample contents.

- [ ] **Step 4: Fill the gate report with actual evidence**

The report must contain one row for each item below, with `PASS`, `FAIL`, or `BLOCKED`, the exact command/manual procedure, artifact hash or result path, date, platform, and reviewer:

1. protocol/schema determinism;
2. Windows FFmpeg profile and license record;
3. macOS FFmpeg profile and license record;
4. Linux FFmpeg profile and license record;
5. atomic reject/rename/replace on each supported local filesystem;
6. Linux filesystem sandbox denial;
7. Linux network sandbox denial;
8. streaming upload and reservation races;
9. capability authorization and SSE recovery;
10. Windows window behavior;
11. macOS window behavior;
12. Linux X11 window behavior;
13. Linux Wayland fallback behavior;
14. Windows offline WebView2 installation strategy.

No blank evidence cells are permitted. A blocked row explains the external prerequisite and keeps Stage 0 incomplete.

- [ ] **Step 5: Update developer guidance**

Add the Rust workspace commands and the rule that later Rust stages may not begin until the Stage 0 report is green or the approved spec has been amended for a documented fallback. Preserve all existing .NET guidance.

- [ ] **Step 6: Run the complete local verification**

```powershell
./scripts/check-stage0.ps1
./scripts/build.ps1
./scripts/test.ps1
```

Expected: Stage 0 automated checks PASS and the legacy .NET build/tests remain PASS. Manual cross-platform rows may remain `BLOCKED`, but then this plan is not complete and Stage 1 must not begin.

- [ ] **Step 7: Request code review against the approved spec**

Use `superpowers:requesting-code-review`. The reviewer must inspect the tests and evidence, not only the report labels. Resolve all critical and important findings before completion.

- [ ] **Step 8: Commit**

```powershell
git add scripts/check-stage0.ps1 scripts/check-stage0.sh .github/workflows/stage0-gates.yml docs/architecture/stage-0-gate-report.md crates/fluxform-protocol/tests/stage0_scripts.rs AGENTS.md
git commit -m "ci: enforce Rust rewrite feasibility gates"
```

## Final Verification Before Declaring Stage 0 Complete

- [ ] Run `cargo fmt --all -- --check`.
- [ ] Run `cargo clippy --workspace --all-targets --all-features -- -D warnings`.
- [ ] Run `cargo test --workspace --all-targets --all-features` on Windows, macOS, and Linux.
- [ ] Regenerate `contracts/v1` twice and confirm the second run produces no diff.
- [ ] Confirm the three FFmpeg reports match approved artifacts and license records.
- [ ] Confirm public-server startup fails when the Linux sandbox self-check is forced to fail.
- [ ] Confirm an over-limit upload stops before the complete body reaches disk.
- [ ] Confirm every protected endpoint rejects a token for another job.
- [ ] Confirm atomic commit tests never expose a partial file at the final path.
- [ ] Confirm transparent-window evidence covers both visuals and hit testing on every target/fallback.
- [ ] Run `./scripts/build.ps1` and `./scripts/test.ps1` for the legacy solution.
- [ ] Scan the new tree for unfinished markers, ignored tests, and unconditional skips; resolve each occurrence.
- [ ] Verify `git status --short` contains only intended Stage 0 changes.

Stage 0 is complete only when every report row is green or the user has approved a spec amendment that removes or changes the failed requirement. After that, write separate implementation plans in this order: Water Lab, Rust conversion core, web single application, Tauri desktop, generic MCP server, legacy retirement.
