# FluxForm Stage 0 Feasibility Gates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish executable contracts and pass/fail evidence for the five assumptions that can invalidate the Rust rewrite: protocol stability, FFmpeg distribution capability, atomic output, anonymous-upload security, and cross-platform transparent-window behavior.

**Architecture:** Add an isolated Rust workspace beside the existing .NET solution. Stage 0 contains probes rather than product adapters: a versioned protocol crate, an FFmpeg profile inspector, an atomic-output proof, a minimal Axum upload/security probe, and a minimal Tauri window probe. Every probe emits machine-readable evidence into one gate report. No existing WPF, CLI, Core, installer, or release path is replaced in this plan.

**Tech Stack:** Rust 1.94.1, Cargo, Tokio, Serde, Schemars, Axum, SQLite via rusqlite, Tauri 2, PowerShell/Bash verification scripts, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-09-25-fluxform-rust-water-platform-design.md`

**Global Constraints:** Preserve the current C# implementation as the runnable baseline. Do not implement Water Lab, production conversion, public deployment, desktop packaging, or MCP in this plan. Do not accept raw FFmpeg arguments, client-supplied server paths, bearer tokens in URLs, or output writes outside a task-owned directory. All generated contracts and evidence must be deterministic after volatile fields are removed.

## Review Focus

- An under-declared or chunked upload must expand its reservation atomically before writing the excess chunk, and must stop polling the body when expansion or a hard limit fails; Tasks 10 and 12 pin this behavior.
- A public worker must remain inside its filesystem, network, process-count, aggregate-memory, and aggregate-CPU boundary even after it forks or changes process groups; Tasks 7, 8, and 9 pin this behavior.
- A conversion edge must never appear in the protocol or UI unless the versioned manifest binds it to codecs, muxers, stream rules, samples, and an approved platform build profile; Tasks 4 and 5 pin this behavior.
- A completed output must become visible only after FFprobe validation and an atomic policy-specific commit; process crashes must expose either the old final file or the validated new file, never a partial result; Task 6 pins this behavior.
- A transparent desktop window must be tested separately for rendering, transparent-pixel hit testing, repeated launch, close, DPI changes, and multiple monitors on every supported display backend; Task 15 pins this behavior.

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
| Versioned request, event, error, revision, replay semantics | Tasks 1, 2, and 13 |
| Fixed capability manifest constrained by an approved FFmpeg build | Tasks 3, 4, and 5 |
| Explicit muxer/codec, FFprobe validation, and same-directory atomic output | Task 6 |
| No-network, aggregate-resource-limited Linux worker | Tasks 7, 8, and 9 |
| Streaming limits, reservations, IP quota primitives, token authorization | Tasks 10, 11, and 12 |
| SSE recovery and fail-closed public startup | Tasks 13 and 14 |
| Transparent independent windows and platform fallbacks | Task 15 |
| Offline Windows WebView2 first launch | Task 15 |
| Verified FFmpeg/FFprobe artifacts for each supported platform/architecture | Task 3 |
| Legacy implementation remains available during migration | Tasks 1 and 16 |
| Evidence-backed gate before Water Lab and product code | Task 16 and final verification |

## Target File Structure

```text
Cargo.toml
Cargo.lock
rust-toolchain.toml
.cargo/config.toml
config/
  ffmpeg-profile.toml
  capabilities-v1.toml
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
  fluxform-capabilities/
    Cargo.toml
    src/lib.rs
    src/bin/verify_manifest.rs
    tests/manifest.rs
  fluxform-atomic-output/
    Cargo.toml
    src/lib.rs
    src/validator.rs
    tests/commit.rs
  fluxform-sandbox-probe/
    Cargo.toml
    src/lib.rs
    src/bin/sandbox-child.rs
    tests/linux_filesystem.rs
    tests/linux_network.rs
    tests/linux_resources.rs
apps/
  server-probe/
    Cargo.toml
    src/auth.rs
    src/events.rs
    src/ledger.rs
    src/lib.rs
    src/main.rs
    src/routes.rs
    src/startup.rs
    tests/capability_auth.rs
    tests/public_startup.rs
    tests/sse_recovery.rs
    tests/upload_http.rs
    tests/upload_ledger.rs
  desktop-probe/
    package.json
    pnpm-lock.yaml
    src-tauri/build.rs
    src-tauri/Cargo.toml
    src-tauri/tauri.conf.json
    src-tauri/capabilities/default.json
    src-tauri/src/lib.rs
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

Add each new Rust crate to the root workspace in the task that creates it. Keep the desktop probe as a workspace member through its `src-tauri/Cargo.toml`; its local `package.json` and `pnpm-lock.yaml` pin the Tauri CLI used by the probe.

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
    ProtocolVersionV1,
};

fn valid_request() -> ConversionRequestV1 {
    ConversionRequestV1 {
        protocol_version: ProtocolVersionV1::V1,
        input_ids: vec!["input_01".to_owned()],
        category: CategoryV1::Image,
        output_format: "png".to_owned(),
        output_target: OutputTargetV1::ManagedArtifact,
        overwrite_policy: OverwritePolicyV1::Reject,
        options: Default::default(),
        client_context: Default::default(),
    }
}

#[test]
fn managed_artifact_target_serializes_without_a_filesystem_path() {
    let json = serde_json::to_value(valid_request()).unwrap();
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

#[test]
fn deserialization_rejects_any_version_other_than_v1() {
    let mut value = serde_json::to_value(valid_request()).unwrap();
    value["protocol_version"] = serde_json::json!("v2");
    assert!(serde_json::from_value::<ConversionRequestV1>(value).is_err());
}
```

- [ ] **Step 2: Run the test and verify the crate does not compile**

Run:

```powershell
cargo test -p fluxform-protocol --test contracts
```

Expected: FAIL because the protocol types do not exist.

- [ ] **Step 3: Implement the smallest versioned protocol model**

Implement the types in `crates/fluxform-protocol/src/lib.rs`. Represent the version as a single-variant enum so Serde and JSON Schema accept exactly the string `v1`; do not store it as an unconstrained `String`. Use internally tagged enums for targets and events, deny unknown fields on request-bearing structs, and derive both `Serialize`/`Deserialize` and `JsonSchema`:

```rust
pub const PROTOCOL_VERSION: &str = "v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq)]
pub enum ProtocolVersionV1 {
    #[serde(rename = "v1")]
    V1,
}

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

- `protocol_version` is required, serializes as `v1`, and rejects `v2`, empty, numeric, and missing values during deserialization;
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
- Create: `contracts/v1/compatibility.sha256`
- Create: `contracts/v1/fixtures/create-image-job.json`
- Create: `contracts/v1/fixtures/completed-image-job.json`
- Create: `contracts/v1/fixtures/unsupported-conversion.json`

**Interfaces:**
- `exported_contracts() -> BTreeMap<&'static str, serde_json::Value>`
- `canonical_fixtures() -> BTreeMap<&'static str, serde_json::Value>`
- `contract_digest() -> String`

- [ ] **Step 1: Add a failing drift test**

The test must compare normalized JSON values rather than whitespace:

```rust
fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

#[test]
fn committed_contracts_match_the_rust_source() {
    for (relative_path, expected) in fluxform_protocol::exported_contracts() {
        let path = workspace_root().join(relative_path);
        let committed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(committed, expected, "contract drift in {relative_path}");
    }
}

#[test]
fn v1_compatibility_digest_cannot_change_with_normal_regeneration() {
    let frozen = std::fs::read_to_string(
        workspace_root().join("contracts/v1/compatibility.sha256")
    ).unwrap();
    assert_eq!(frozen.trim(), fluxform_protocol::contract_digest());
}
```

- [ ] **Step 2: Run the drift test and verify it fails**

```powershell
cargo test -p fluxform-protocol committed_contracts_match_the_rust_source
```

Expected: FAIL because `contracts/v1` does not exist.

- [ ] **Step 3: Implement deterministic schema and fixture generation**

Use `schemars::schema_for!` for the three public roots. Store outputs in a `BTreeMap`, remove only generator-version metadata, and pretty-print with a final newline. The exporter must refuse to write outside the workspace `contracts/v1` directory. Compute `contract_digest()` from the sorted normalized schemas and fixtures. The normal exporter must never rewrite `compatibility.sha256`; a one-time `--freeze-v1` flag creates it with `create_new(true)` and fails if it already exists. After Stage 0 approval, a contract change requires a new protocol directory rather than a new v1 digest.

The create fixture must describe two image inputs sharing one PNG output format and one parameter set. The completed fixture must include a monotonic revision and a managed artifact ID. The error fixture must use `unsupported_conversion` and contain no local path.

- [ ] **Step 4: Generate and inspect the committed artifacts**

```powershell
cargo run -p fluxform-protocol --bin export_contracts
cargo run -p fluxform-protocol --bin export_contracts -- --freeze-v1
git status --short -- contracts/v1
```

Expected: three schemas, three fixtures, and the one-time compatibility digest are created; no timestamps, machine paths, UUIDs, or unordered maps appear. Add a round-trip assertion for each frozen fixture before proceeding.

- [ ] **Step 5: Prove regeneration is clean**

Stage the first generated result, run the exporter a second time, then:

```powershell
git add contracts/v1
cargo run -p fluxform-protocol --bin export_contracts
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
- CLI: `fluxform-ffmpeg-profile verify --profile PROFILE_PATH --ffmpeg FFMPEG_PATH --ffprobe FFPROBE_PATH --out REPORT_PATH`

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
$stage0Extract = Join-Path ([System.IO.Path]::GetTempPath()) ("FluxFormStage0Ffmpeg-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -LiteralPath $stage0Extract | Out-Null
try {
  Expand-Archive -LiteralPath tools-cache/ffmpeg-release-essentials.zip -DestinationPath $stage0Extract
  $ffmpegMatches = @(Get-ChildItem -LiteralPath $stage0Extract -Recurse -Filter ffmpeg.exe)
  $ffprobeMatches = @(Get-ChildItem -LiteralPath $stage0Extract -Recurse -Filter ffprobe.exe)
  if ($ffmpegMatches.Count -ne 1 -or $ffprobeMatches.Count -ne 1) { throw 'Archive must contain exactly one ffmpeg.exe and one ffprobe.exe' }
  if ($ffmpegMatches[0].DirectoryName -ne $ffprobeMatches[0].DirectoryName) { throw 'ffmpeg.exe and ffprobe.exe must be sibling files' }
  cargo run -p fluxform-ffmpeg-profile -- verify `
    --profile config/ffmpeg-profile.toml `
    --ffmpeg $ffmpegMatches[0].FullName `
    --ffprobe $ffprobeMatches[0].FullName `
    --out target/stage0/ffmpeg-windows-x86_64.json
} finally {
  if (Test-Path -LiteralPath $stage0Extract) { Remove-Item -LiteralPath $stage0Extract -Recurse -Force }
}
```

Expected: PASS only if the hashes and required features match the profile. Never commit extracted binaries or their temporary path.

- [ ] **Step 6: Repeat the same verifier for every supported target**

Run the identical CLI for native Windows x86_64, macOS x86_64, macOS aarch64, and Linux x86_64 candidates. The build versions may differ only if the ADR explicitly accepts the difference and all manifest-required codecs/muxers remain equivalent. Attach all four generated JSON reports to the gate evidence; do not commit binaries. Rosetta output does not substitute for the native macOS x86_64 report.

- [ ] **Step 7: Commit**

```powershell
git add Cargo.toml Cargo.lock config/ffmpeg-profile.toml crates/fluxform-ffmpeg-profile docs/architecture/adr/0001-ffmpeg-distribution-profile.md
git commit -m "build(ffmpeg): define verified distribution profile"
```

## Task 4: Define and Validate the Versioned Capability Schema

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/fluxform-capabilities/Cargo.toml`
- Create: `crates/fluxform-capabilities/src/lib.rs`
- Create: `crates/fluxform-capabilities/src/bin/verify_manifest.rs`
- Create: `crates/fluxform-capabilities/tests/manifest.rs`

**Interfaces:**
- Consumes: `fluxform_ffmpeg_profile::ProbeReport`
- Produces: `CapabilityManifestV1::load(path) -> Result<Self, ManifestError>`
- Produces: `CapabilityManifestV1::validate_profiles(&BTreeMap<TargetTriple, ProbeReport>) -> Result<(), ManifestError>`
- Produces: `CapabilityManifestV1::find_edge(category, input_probe, output_format) -> Option<&ConversionEdgeV1>`
- CLI: `fluxform-capabilities verify-manifest --manifest MANIFEST_PATH --reports REPORT_DIRECTORY`

- [ ] **Step 1: Write failing manifest-policy tests**

Add tests proving that the manifest rejects duplicate edge IDs, wildcard codecs, extension-only input matching, an output codec or muxer absent from any bound platform profile, missing parameter bounds/defaults, missing stream mapping, missing Alpha/orientation/metadata policies, and missing valid or invalid sample IDs.

Use one complete edge as the positive fixture:

```toml
manifest_version = "v1"

[[edges]]
id = "image.jpeg-to-png"
category = "image"
input_extensions = ["jpg", "jpeg"]
input_demuxers = ["image2"]
input_codecs = ["mjpeg"]
input_topology = "single_video_frame"
output_format = "png"
output_muxer = "image2"
video_codec = "png"
stream_map = ["0:v:0"]
alpha_policy = "preserve_if_present"
orientation_policy = "apply_to_pixels"
metadata_policy = "safe_image_metadata"
profile_ids = ["windows-x86_64", "macos-aarch64", "macos-x86_64", "linux-x86_64"]
valid_samples = ["jpeg-baseline-rgb"]
invalid_samples = ["jpeg-truncated", "jpeg-multi-stream"]

[edges.options.quality]
minimum = 0
maximum = 100
default = 90
```

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-capabilities --test manifest
```

Expected: FAIL because the crate and validator do not exist.

- [ ] **Step 3: Implement strict loading and profile binding**

Deserialize with `deny_unknown_fields` on every manifest struct. Normalize extensions to lowercase without a leading dot, require exact enum values for policies, and reject implicit input/output cross-products. `validate_profiles` must verify every declared demuxer, decoder, muxer, and encoder against every referenced immutable `ProbeReport`; a missing report keeps the gate blocked.

- [ ] **Step 4: Run and commit the schema validator**

```powershell
cargo test -p fluxform-capabilities --test manifest
git add Cargo.toml Cargo.lock crates/fluxform-capabilities
git commit -m "feat(core): add capability manifest schema"
```

## Task 5: Freeze the Approved v1 Directed-Edge Set

**Files:**
- Create: `config/capabilities-v1.toml`
- Modify: `crates/fluxform-capabilities/tests/manifest.rs`

**Interfaces:**
- Consumes: `CapabilityManifestV1` and `ProbeReport` from Tasks 3 and 4
- Produces: the immutable `config/capabilities-v1.toml` product promise
- Produces: normalized public capability response derived only from the manifest

- [ ] **Step 1: Add a failing completeness test**

Load `config/capabilities-v1.toml` and assert it has at least one approved video, audio, and image edge; every candidate input/output family from spec section 6 is either referenced by an enabled edge or listed in a top-level `deferred_formats` record with a reason; every enabled edge binds all four target profiles and names both valid and invalid samples. The test fails if the manifest file is absent.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-capabilities approved_v1_edges_are_explicit_and_complete
```

Expected: FAIL because `config/capabilities-v1.toml` does not exist.

- [ ] **Step 3: Populate the complete approved v1 edge set**

Encode each approved directed edge from the candidate families in spec section 6. Every edge must contain the fields shown above plus category-appropriate audio/video/image options. Do not add an edge merely because one FFmpeg binary lists a codec: it must have the same required capability on every referenced target and named real samples. Animated GIF, animated WebP, and multi-page TIFF are represented only as invalid sample cases returning `unsupported_conversion`.

- [ ] **Step 4: Prove the manifest is the only capability source**

Add a test that derives the public format response exclusively from `CapabilityManifestV1` and compares it with a committed normalized fixture. Add a negative test showing an FFmpeg-reported encoder that is absent from the manifest never appears in the response.

- [ ] **Step 5: Run the profile-bound gate**

```powershell
cargo test -p fluxform-capabilities --all-targets
cargo run -p fluxform-capabilities --bin verify_manifest -- verify-manifest --manifest config/capabilities-v1.toml --reports target/stage0
```

Expected: PASS only when every manifest edge is supported by all referenced platform reports. A missing macOS or Linux report is `BLOCKED`, never a skipped pass.

- [ ] **Step 6: Commit**

```powershell
git add config/capabilities-v1.toml crates/fluxform-capabilities/tests/manifest.rs
git commit -m "feat(core): freeze v1 capability manifest"
```

## Task 6: Prove Validated Same-Directory Atomic Output Semantics

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/fluxform-atomic-output/Cargo.toml`
- Create: `crates/fluxform-atomic-output/src/lib.rs`
- Create: `crates/fluxform-atomic-output/src/validator.rs`
- Create: `crates/fluxform-atomic-output/tests/commit.rs`

**Interfaces:**
- `OutputReservation::create(final_path, job_id, extension)`
- `OutputReservation::partial_path()`
- `OutputReservation::validate(validator: &dyn OutputValidator, expectation: &OutputExpectation) -> Result<ValidatedOutput, ValidationError>`
- `FfprobeOutputValidator::new(ffprobe_path, protocol_whitelist)`
- `ValidatedOutput::commit(OverwritePolicyV1)`
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
fn replace_atomically_supersedes_an_existing_destination() { /* old or new, never missing */ }

#[test]
fn abort_removes_only_the_owned_partial_file() { /* final file preserved */ }

#[test]
fn ffmpeg_output_args_name_muxer_and_codecs_explicitly() { /* includes -f/-c:v/-c:a */ }

#[test]
fn unvalidated_output_cannot_be_committed() { /* no public commit method on reservation */ }
```

Also add a process-crash helper with two modes: crash before commit and crash immediately after the platform rename returns. On restart, assert that the final path contains either the complete old bytes or the complete validated new bytes, never a missing or partial file, and that reconciliation recognizes only partial files with a valid owned journal record.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-atomic-output
```

Expected: FAIL because the reservation API does not exist.

- [ ] **Step 3: Implement no-clobber and replace as platform adapters**

Create the partial file with `create_new(true)` in the destination directory. Keep the file handle and journal until commit. Keep the `ValidatedOutput` constructor private; only `OutputReservation::validate` may create it after the validator confirms the manifest edge's container, codec, stream map, and critical media properties. `FfprobeOutputValidator` executes the approved sibling binary directly, with fixed arguments, bounded output, timeout, and `-protocol_whitelist file,pipe`. Implement:

- Windows no-replace with `MoveFileExW` without `MOVEFILE_REPLACE_EXISTING` and with `MOVEFILE_WRITE_THROUGH`; replace an existing target with `ReplaceFileW(..., 0, ...)` after `FlushFileBuffers` on the replacement file. Record that `REPLACEFILE_WRITE_THROUGH` is unsupported and do not use it;
- macOS with the documented `renameatx_np` no-replace/swap behavior;
- Linux with `renameat2` and `RENAME_NOREPLACE` where supported.

Do not implement `replace` as delete-then-rename. Return `AtomicCommitUnsupported` when the filesystem or platform primitive cannot meet the contract. Flush file contents before commit and sync the parent directory where the platform supports it. The gate report must state the tested durability boundary: the automated crash test covers process termination, not sudden power loss.

- [ ] **Step 4: Linearize cancellation and finalization**

Add an internal state lock with only these transitions:

```text
Writing -> Aborted
Writing -> Validated -> Committing -> Committed
```

Once `Committing` begins, `abort()` returns `CommitInProgress`; it must not delete or rename anything. Add a concurrency test that races `abort` and `commit` 1,000 times and accepts only the two valid terminal outcomes. Run reject, rename, replace, crash-before-commit, and crash-after-rename cases independently on every supported platform and filesystem.

- [ ] **Step 5: Run on all three target operating systems**

```powershell
cargo test -p fluxform-atomic-output --all-targets
```

Expected: PASS on Windows, macOS, and the supported Linux filesystem. On each target, an integration test uses the approved `ffprobe` candidate to accept a valid generated sample and reject a truncated or property-mismatched sample before commit. Record filesystem type and kernel/OS version in the gate evidence. Network filesystems are not accepted based on a local-disk pass.

- [ ] **Step 6: Commit**

```powershell
git add Cargo.toml Cargo.lock crates/fluxform-atomic-output
git commit -m "feat(runtime): prove atomic output commits"
```

## Task 7: Prove Linux Filesystem Isolation

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `crates/fluxform-sandbox-probe/Cargo.toml`
- Create: `crates/fluxform-sandbox-probe/src/lib.rs`
- Create: `crates/fluxform-sandbox-probe/src/bin/sandbox-child.rs`
- Create: `crates/fluxform-sandbox-probe/tests/linux_filesystem.rs`

**Interfaces:**
- Produces: `SandboxPolicy { input, job_dir, tool_dir, limits }`
- Produces: `FilesystemPrerequisites::inspect() -> Result<FilesystemEvidence, SandboxError>`
- Produces: `ResourceBoundary` trait with `attach(pid)`, `kill_all()`, and `is_empty()`
- Produces: `Sandbox::spawn(program: &Path, args: &[OsString], policy: &SandboxPolicy, boundary: &dyn ResourceBoundary) -> Result<SandboxChild, SandboxError>`

- [ ] **Step 1: Add Linux-only failing filesystem tests**

The child binary accepts fixed test actions. Tests must prove that assigned-input reads and task-directory writes succeed, while `/etc/passwd` reads, parent-directory writes, host `/tmp` writes, symlink traversal, and undeclared file-descriptor access fail.

- [ ] **Step 2: Run on Linux and verify failure**

```bash
cargo test -p fluxform-sandbox-probe --test linux_filesystem
```

Expected: FAIL because namespace and mount setup do not exist. On non-Linux hosts the crate compiles and returns `UnsupportedPlatform`, but the Linux CI gate remains `BLOCKED` rather than skipped.

- [ ] **Step 3: Implement the rootless isolation boundary**

Create user, mount, and PID namespaces before executing untrusted media tooling. Assemble a minimal `pivot_root` tree with the tool directory and one input bind-mounted read-only, one task directory bind-mounted writable, an empty private `/tmp`, no host root mount, and no inherited descriptors other than declared pipes/files. Apply `no_new_privs`, drop all capabilities, and deny namespace-creation and mount syscalls after setup. Never invoke a shell. Task 7 tests may use a probe-only boundary implementation, but it cannot satisfy the public-server prerequisite until Tasks 8 and 9 add network and resource containment.

- [ ] **Step 4: Make prerequisite failure explicit**

`FilesystemPrerequisites::inspect` must test user-namespace availability, mount isolation, `pivot_root`, capability dropping, descriptor closure, and creation of the temporary root. Return structured evidence for each primitive. Public mode treats any missing primitive as fatal; this task does not define a weaker production fallback.

- [ ] **Step 5: Run and commit**

```bash
cargo test -p fluxform-sandbox-probe --test linux_filesystem
git add Cargo.toml Cargo.lock crates/fluxform-sandbox-probe
git commit -m "feat(server): prove Linux filesystem isolation"
```

Expected: all filesystem-boundary tests PASS.

## Task 8: Prove Linux Network Isolation and FFmpeg Protocol Policy

**Files:**
- Modify: `crates/fluxform-sandbox-probe/src/lib.rs`
- Create: `crates/fluxform-sandbox-probe/tests/linux_network.rs`

**Interfaces:**
- Consumes: `Sandbox::spawn` from Task 7
- Produces: `NetworkPrerequisites::inspect() -> Result<NetworkEvidence, SandboxError>`

- [ ] **Step 1: Add a failing OS-network test**

Bind controlled IPv4 and IPv6 listeners in the host namespace. Launch a sandbox child that calls `socket` and `connect`; assert the socket syscall receives the configured seccomp denial and both listeners accept zero connections. Also try Unix-domain sockets outside the task root and namespace-creation syscalls. This test is the OS network evidence.

- [ ] **Step 2: Add a separate failing FFprobe protocol-policy test**

Run the approved Linux FFprobe candidate directly against a valid local sample and an HTTP URL using fixed `-protocol_whitelist file,pipe`. Local probing must succeed and the URL must fail with a protocol-policy diagnostic. Name this test `ffprobe_protocol_policy_rejects_urls`; it must never satisfy or replace the OS-network test.

- [ ] **Step 3: Implement and inspect the network boundary**

Add a private network namespace and a post-setup seccomp allowlist that denies IPv4/IPv6 socket creation, packet sockets, and namespace escape. `NetworkPrerequisites::inspect` must actively execute the controlled-listener probe; checking for kernel flags or crate support alone is insufficient.

- [ ] **Step 4: Run and commit**

```bash
cargo test -p fluxform-sandbox-probe --test linux_network
git add crates/fluxform-sandbox-probe
git commit -m "feat(server): prove Linux network isolation"
```

## Task 9: Prove Per-Job Aggregate Resource Containment

**Files:**
- Modify: `crates/fluxform-sandbox-probe/src/lib.rs`
- Create: `crates/fluxform-sandbox-probe/tests/linux_resources.rs`

**Interfaces:**
- Consumes: `ResourceBoundary` and `Sandbox::spawn` from Task 7
- Produces: `CgroupV2Job::create(delegated_root, job_id, limits) -> Result<Self, SandboxError>`
- Produces: `CgroupV2Job::kill_all()`
- Produces: `CgroupV2Job::evidence() -> CgroupEvidence`

- [ ] **Step 1: Add failing aggregate-limit tests**

Under a delegated test subtree, prove that `pids.max` limits the combined worker and descendants, `memory.max` limits aggregate resident memory across multiple children, `memory.swap.max = 0` prevents swap escape, and `cpu.max` throttles total CPU bandwidth. Create a child that forks, calls `setsid`, and forks again; after timeout, assert `cgroup.events` reports no populated descendants and the escaped process is gone.

- [ ] **Step 2: Run and verify failure**

```bash
cargo test -p fluxform-sandbox-probe --test linux_resources
```

Expected: FAIL because the per-job cgroup does not exist. If the runner lacks a writable delegated cgroup v2 subtree with the `cpu`, `memory`, and `pids` controllers, return `BLOCKED`; never convert that condition into PASS.

- [ ] **Step 3: Implement the cgroup v2 boundary**

Require the production service to run under a systemd unit with `Delegate=yes` or an equivalent container delegation. For every job, create a child cgroup, write `pids.max`, `memory.max`, `memory.swap.max`, and `cpu.max`, then place the worker in it before untrusted parsing begins. Keep `RLIMIT_FSIZE` and `RLIMIT_NOFILE` as per-process defense in depth, but do not use `RLIMIT_NPROC`, `RLIMIT_AS`, or a process group as evidence for aggregate containment.

- [ ] **Step 4: Implement timeout and cancellation with `cgroup.kill`**

On timeout or cancellation, write `1` to `cgroup.kill`, wait for `populated 0`, reap the worker, and remove the cgroup. If `cgroup.kill` or a required controller is unavailable, fail the public sandbox self-check. Add a race test where the worker forks while cancellation begins.

- [ ] **Step 5: Run and commit**

```bash
cargo test -p fluxform-sandbox-probe --test linux_resources
git add crates/fluxform-sandbox-probe
git commit -m "feat(server): contain worker resources with cgroup v2"
```

## Task 10: Prove Transactional Upload Reservations and Daily Quotas

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `apps/server-probe/Cargo.toml`
- Create: `apps/server-probe/src/lib.rs`
- Create: `apps/server-probe/src/ledger.rs`
- Create: `apps/server-probe/tests/upload_ledger.rs`

**Interfaces:**
- Produces: `UploadLedger::reserve(ip_key, declared_bytes) -> UploadReservation`
- Produces: `UploadLedger::expand(session_id, required_total) -> Result<Reservation, LimitError>`
- Produces: `UploadLedger::settle(session_id, actual_bytes)`
- Produces: `UploadLedger::expire(session_id)`

- [ ] **Step 1: Add failing transactional tests**

Use a real temporary SQLite database. Test declared sizes, missing lengths reserving the per-file maximum, daily hashed-IP limits, simultaneous-session limits, global reserved bytes, disk safety margin, idempotent expiration, and actual-byte settlement. Race two `expand` calls whose combined increase exceeds global capacity; exactly one may commit, and `reserved_bytes` must never become negative or exceed the configured maximum.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-server-probe --test upload_ledger
```

Expected: FAIL because the ledger does not exist.

- [ ] **Step 3: Implement the SQLite state machine**

Use one immediate transaction for each reserve, expand, settle, expire, and daily-counter mutation. Hash normalized IP plus a rotating server secret before storage. Store states `reserved`, `receiving`, `uploaded`, `probing`, `queued`, `expired`, and `rejected`; make every release conditional on its current state and therefore idempotent. Filesystem deletion happens after commit and is retried by a reconciler.

- [ ] **Step 4: Run and commit**

```powershell
cargo test -p fluxform-server-probe --test upload_ledger
git add Cargo.toml Cargo.lock apps/server-probe
git commit -m "feat(server): add transactional upload reservations"
```

## Task 11: Prove Capability Authorization on Every Protected Endpoint

**Files:**
- Create: `apps/server-probe/src/auth.rs`
- Create: `apps/server-probe/src/routes.rs`
- Create: `apps/server-probe/tests/capability_auth.rs`

**Interfaces:**
- `POST /v1/upload-sessions`
- `PUT /v1/upload-sessions/{session_id}/content` requires `upload`
- `GET /v1/jobs/{job_id}` requires `status`
- `GET /v1/jobs/{job_id}/events` requires `events`
- `DELETE /v1/jobs/{job_id}` requires `cancel`
- `GET /v1/artifacts/{artifact_id}/download` requires `download`
- Produces: `Capability::issue(subject, scopes, expires_at)`
- Produces: `Capability::verify(token, subject, required_scope)`

- [ ] **Step 1: Add failing authorization tests for every concrete route**

Generate 32 random bytes from the OS CSPRNG, return the base64url token once, and persist only its SHA-256 hash, subject, scope set, and expiry. For each route listed above, test absent, expired, wrong-scope, and cross-job/cross-artifact tokens. Include the upload-content `PUT`, actual artifact-download path, and SSE path explicitly. Reject tokens in paths and query strings. Test that web requests containing local output targets are rejected before job creation.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-server-probe --test capability_auth
```

Expected: FAIL because capability issuance and middleware do not exist.

- [ ] **Step 3: Implement scoped capability middleware**

Use the same middleware for every protected route. Compare stored and presented hashes in constant time, verify subject and required scope on every request, and never log plaintext tokens. The download handler must use `Content-Disposition: attachment`, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`. Error responses contain stable codes and diagnostic IDs but no server paths or command lines.

- [ ] **Step 4: Run and commit**

```powershell
cargo test -p fluxform-server-probe --test capability_auth
git add apps/server-probe/src/auth.rs apps/server-probe/src/routes.rs apps/server-probe/tests/capability_auth.rs
git commit -m "feat(server): enforce capability scopes"
```

## Task 12: Prove Streaming Upload Enforcement

**Files:**
- Create: `apps/server-probe/src/main.rs`
- Modify: `apps/server-probe/src/routes.rs`
- Create: `apps/server-probe/tests/upload_http.rs`

**Interfaces:**
- Consumes: `UploadLedger` from Task 10 and upload-scope middleware from Task 11
- Implements: `POST /v1/upload-sessions`
- Implements: `PUT /v1/upload-sessions/{session_id}/content`

- [ ] **Step 1: Add failing streaming tests with an instrumented body**

Build a custom body stream that counts `poll_next` calls. Test bodies split before, exactly at, and one byte beyond each limit. When actual bytes exceed a smaller declaration but remain below the hard limit, assert `UploadLedger::expand` commits before the excess chunk is written. When expansion, disk watermark, timeout, or hard limit fails, assert the staging file is deleted and the handler stops polling before the remaining chunks are consumed.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-server-probe --test upload_http
```

Expected: FAIL because the streaming handlers do not exist.

- [ ] **Step 3: Implement streaming in write-after-reserve order**

Consume `Body::into_data_stream()` one chunk at a time. For each chunk, calculate the checked new total; reject a hard-limit breach; atomically expand a smaller reservation when needed; check deadlines and disk watermark; only then write to the exclusively created session file. Never collect the whole body or treat `Content-Length` as authoritative.

- [ ] **Step 4: Run and commit**

```powershell
cargo test -p fluxform-server-probe --test upload_http
git add apps/server-probe/src/main.rs apps/server-probe/src/routes.rs apps/server-probe/tests/upload_http.rs
git commit -m "feat(server): enforce streaming upload limits"
```

## Task 13: Prove SSE Revision, Replay, and Resynchronization

**Files:**
- Create: `apps/server-probe/src/events.rs`
- Create: `apps/server-probe/tests/sse_recovery.rs`

**Interfaces:**
- Implements: `GET /v1/jobs/{job_id}/events` with the `events` scope from Task 11
- Consumes: `GET /v1/jobs/{job_id}` snapshot route from Task 11
- Produces: `EventStore::append`, `EventStore::replay_after`, and `EventStore::snapshot`

- [ ] **Step 1: Add failing SSE recovery tests**

Use authorized fetch-style requests with an `Authorization` header. Assert SSE `id:` equals the monotonically increasing job revision; `Last-Event-ID` replays the retained suffix without duplicates; malformed and future IDs are rejected; an older-than-retained revision emits one `resync_required` event containing the current revision; the subsequent snapshot returns that same or a newer revision. Keep `job.completed` and the authoritative snapshot available until artifact download expiry, then expire token, events, metadata, and artifact together.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-server-probe --test sse_recovery
```

Expected: FAIL because replay storage and event streaming do not exist.

- [ ] **Step 3: Implement bounded replay and authoritative resync**

Persist the current snapshot and a bounded ordered event suffix in SQLite. Parse `Last-Event-ID` as `u64`. Replay only when the complete suffix is available; otherwise emit `resync_required` and close so the client fetches the protected snapshot route.

- [ ] **Step 4: Run and commit**

```powershell
cargo test -p fluxform-server-probe --test sse_recovery
git add apps/server-probe/src/events.rs apps/server-probe/tests/sse_recovery.rs
git commit -m "feat(server): prove SSE event recovery"
```

## Task 14: Prove Fail-Closed Public Server Startup

**Files:**
- Create: `apps/server-probe/src/startup.rs`
- Create: `apps/server-probe/tests/public_startup.rs`

**Interfaces:**
- Consumes: filesystem evidence from Task 7, network evidence from Task 8, and cgroup v2 evidence from Task 9
- Produces: `ServerMode::Public | ServerMode::LocalDevelopment`
- Produces: `prepare_server(config, sandbox_checker) -> Result<PreparedServer, StartupError>`

- [ ] **Step 1: Add failing startup-mode tests**

Inject a `SandboxChecker` test double. In `Public` mode, force filesystem, network, cgroup-controller, and `cgroup.kill` checks to fail one at a time and assert `prepare_server` returns an error before any TCP listener is bound or upload route is exposed. `LocalDevelopment` may start without the Linux sandbox only when selected explicitly, binds loopback by default, and prints an unambiguous non-production warning.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test -p fluxform-server-probe --test public_startup
```

Expected: FAIL because startup validation does not exist.

- [ ] **Step 3: Wire sandbox self-check before binding**

Make `prepare_server` complete configuration validation plus filesystem, network, cgroup delegation/controller, and `cgroup.kill` checks before returning any bindable server object. `main` binds only after successful preparation. Add a process-level test that starts the binary with a forced failing checker and proves the chosen port remains connectable by the test harness because the server never claimed it.

- [ ] **Step 4: Run and commit**

```powershell
cargo test -p fluxform-server-probe --test public_startup
git add apps/server-probe/src/startup.rs apps/server-probe/tests/public_startup.rs
git commit -m "feat(server): fail closed before public bind"
```

## Task 15: Build the Cross-Platform Transparent Window Probe

**Files:**
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `apps/desktop-probe/package.json`
- Create: `apps/desktop-probe/pnpm-lock.yaml`
- Create: `apps/desktop-probe/src-tauri/build.rs`
- Create: `apps/desktop-probe/src-tauri/Cargo.toml`
- Create: `apps/desktop-probe/src-tauri/tauri.conf.json`
- Create: `apps/desktop-probe/src-tauri/capabilities/default.json`
- Create: `apps/desktop-probe/src-tauri/src/lib.rs`
- Create: `apps/desktop-probe/src-tauri/src/main.rs`
- Create: `apps/desktop-probe/ui/index.html`
- Create: `apps/desktop-probe/ui/styles.css`
- Create: `apps/desktop-probe/ui/probe.js`

**Interfaces:**
- Tauri command `record_probe_result(result)`
- Tauri event `probe://file-drop`
- Single-instance callback `create_probe_window(app, launch_id)`
- JSON evidence for transparency, drag, file drop, hit testing, focus, repeated launch, close, DPI, and multi-monitor behavior

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
    pub repeated_launch_created_second_window: bool,
    pub repeated_launch_backend_process_count: u32,
    pub single_window_close_works: bool,
    pub last_window_close_works: bool,
    pub dpi_change_works: bool,
    pub multi_monitor_move_works: bool,
    pub idle_cpu_percent: f32,
    pub idle_gpu_percent: f32,
    pub notes: String,
}
```

Tests reject an unknown display server, negative percentages, a repeated-launch FluxForm backend process count other than one, or a supposedly passing record without every behavioral check. WebView helper processes are recorded separately and are not mistaken for extra Rust runtimes.

- [ ] **Step 2: Run and verify failure**

```powershell
cargo test --manifest-path apps/desktop-probe/src-tauri/Cargo.toml
```

Expected: FAIL because the probe model does not exist.

- [ ] **Step 3: Pin the Tauri toolchain and create the smallest visible probe**

Use a local `package.json` with scripts `tauri:dev` and `tauri:build`; install `@tauri-apps/cli@2` with `pnpm add --save-dev --save-exact` and commit `pnpm-lock.yaml`. Add `build.rs` calling `tauri_build::build()`, keep desktop application logic in `src/lib.rs`, and let `src/main.rs` call that library entry point. Add `tauri-plugin-single-instance`; a later process invocation sends its launch ID to the first process, which creates another 360×360 probe window without another Runtime.

Configure transparent, undecorated windows. Enable Tauri's required macOS private API setting and configure `webviewInstallMode.type = "offlineInstaller"` for the Windows bundle. The UI contains a circular translucent CSS surface, visible corner markers, a drag handle, file-drop/focus/DPI/monitor counters, live process/window counts, and a button that saves result JSON. This is not the final water shader.

The UI must show the exact manual test order:

1. verify the desktop is visible through all four corners;
2. click a control behind each transparent corner;
3. drag the window from the orb surface;
4. drop a file on the surface and outside the circle but inside window bounds;
5. switch away and restore focus ten times;
6. start the executable again and verify a second window appears while the OS reports one application process;
7. close a non-last window and verify the remaining window stays alive, then close the last idle window and verify the process exits;
8. move the window between displays with different scale factors and verify size, hit region, and pointer coordinates after each DPI event;
9. visit every monitor edge and reconnect a secondary display while the probe runs;
10. measure 60 seconds of idle CPU/GPU.

- [ ] **Step 4: Run the platform matrix**

Execute and save evidence for:

- Windows 11 x86_64 with the offline WebView2 installer;
- macOS natively on Intel x86_64 hardware and natively on Apple Silicon, using the intended signed/notarized direct distribution path; Rosetta evidence is supplemental and cannot replace native Intel evidence;
- Linux X11;
- Linux Wayland.

For Wayland, record lack of global positioning or always-on-top support as an explicit degraded capability rather than a generic failure. Visual transparency and transparent-pixel click-through are separate results.

For Windows, build the probe installer with `webviewInstallMode.type = "offlineInstaller"`, disconnect a clean Windows 11 VM before installation, and prove installation plus first launch without a pre-existing evergreen WebView2 runtime or network access. Record installer size and first-launch result. If the offline installer mode cannot satisfy this, Stage 0 remains red until a fixed-runtime design is tested and approved.

Document prerequisites and exact commands in the gate report: Microsoft C++ Build Tools on Windows, Xcode Command Line Tools on macOS, and the Tauri-documented WebKitGTK 4.1, GTK/AppIndicator, OpenSSL, librsvg, and build packages on the chosen Linux baseline. Build with `pnpm --dir apps/desktop-probe install --frozen-lockfile` followed by `pnpm --dir apps/desktop-probe run tauri:build`; CI must use the committed lockfiles.

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

## Task 16: Add Reproducible Gate Commands and CI

**Files:**
- Create: `scripts/check-stage0.ps1`
- Create: `scripts/check-stage0.sh`
- Create: `.github/workflows/stage0-gates.yml`
- Create: `docs/architecture/stage-0-gate-report.md`
- Create: `crates/fluxform-protocol/tests/stage0_scripts.rs`
- Modify: `AGENTS.md`

**Interfaces:**
- PowerShell: `./scripts/check-stage0.ps1 [-Ffmpeg FFMPEG_PATH] [-Ffprobe FFPROBE_PATH] [-Gate GATE_NAME]`
- Bash: `./scripts/check-stage0.sh [--ffmpeg FFMPEG_PATH] [--ffprobe FFPROBE_PATH] [--gate GATE_NAME]`

- [ ] **Step 1: Add failing behavioral tests for both gate scripts**

Add `crates/fluxform-protocol/tests/stage0_scripts.rs`. On Windows, create a temporary failing `cargo.cmd`, prepend it to `PATH`, run `check-stage0.ps1 -Gate protocol`, and assert a nonzero exit plus `protocol=FAIL`. On Linux, do the same with an executable `cargo` shim and `check-stage0.sh --gate protocol`. Repeat with a successful shim and assert the scripts continue to contract drift verification. These tests execute the scripts; they do not merely search their source text.

The complete scripts must:

- run format, clippy, and all Stage 0 tests;
- regenerate contracts and fail on drift;
- invoke the FFmpeg verifier when paths are supplied;
- require the Linux sandbox suite in public-server mode;
- never download a tool or dependency implicitly;
- write volatile evidence only under `target/stage0`.

- [ ] **Step 2: Implement both scripts with matching semantics**

Scripts must accept a repeatable gate selector for focused testing, stop at the first failed selected gate, and print a final summary containing every selected gate and status. They may read candidate binaries but must not modify `tools-cache`, `publish`, or the existing .NET projects. `BLOCKED` is a nonzero result for the complete Stage 0 command.

- [ ] **Step 3: Add the CI matrix**

The workflow must use minimum `contents: read`, dependency caching keyed by lockfiles, and concurrency cancellation. Required jobs:

- Windows: protocol, capability-manifest/profile fixtures, atomic output, server-probe unit tests, script behavior, and desktop-probe build with pinned pnpm dependencies;
- macOS: protocol, capability-manifest/profile fixtures, atomic output, script behavior, and desktop-probe build on both supported architectures;
- Ubuntu: protocol, capability-manifest/profile fixtures, atomic output, server-probe tests, script behavior, delegated-cgroup sandbox adversarial tests, and desktop-probe build after installing the documented WebKitGTK/GTK packages.

Do not mark manual transparent-window checks as automated. Upload non-secret test reports as artifacts; never upload capability tokens or uploaded sample contents.

- [ ] **Step 4: Fill the gate report with actual evidence**

The report must contain one row for each item below, with `PASS`, `FAIL`, or `BLOCKED`, the exact command/manual procedure, artifact hash or result path, date, platform, and reviewer:

1. protocol/schema determinism;
2. Windows FFmpeg profile and license record;
3. macOS x86_64 FFmpeg profile and license record;
4. macOS aarch64 FFmpeg profile and license record;
5. Linux x86_64 FFmpeg profile and license record;
6. capability manifest validation against every referenced profile;
7. atomic reject/rename/replace and crash recovery on each supported local filesystem;
8. Linux filesystem sandbox denial;
9. Linux OS network denial, separately from FFmpeg protocol-policy denial;
10. Linux cgroup v2 aggregate process/memory/CPU containment and kill;
11. streaming upload, reservation expansion, and early body termination;
12. capability authorization on every concrete endpoint;
13. SSE reconnect, replay, resync snapshot, and expiry;
14. fail-closed public-server startup;
15. Windows window, repeated-launch, close, DPI, and multi-monitor behavior;
16. native Intel and Apple Silicon macOS window behavior;
17. Linux X11 window behavior;
18. Linux Wayland fallback behavior;
19. Windows offline WebView2 installation strategy.

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
- [ ] Confirm Windows x86_64, macOS x86_64, macOS aarch64, and Linux x86_64 FFmpeg reports match approved artifacts and license records.
- [ ] Confirm every capability-manifest edge validates against every profile it references.
- [ ] Confirm public-server startup fails when the Linux sandbox self-check is forced to fail.
- [ ] Confirm an under-declared upload expands its reservation before writing, while a denied expansion or over-limit upload stops polling the remaining body.
- [ ] Confirm every protected endpoint rejects a token for another job.
- [ ] Confirm atomic commit tests never expose a partial file at the final path.
- [ ] Confirm transparent-window evidence covers visuals, hit testing, repeated launch, close, DPI, and multiple monitors on every target/fallback.
- [ ] Run `./scripts/build.ps1` and `./scripts/test.ps1` for the legacy solution.
- [ ] Scan the new tree for unfinished markers, ignored tests, and unconditional skips; resolve each occurrence.
- [ ] Verify `git status --short` contains only intended Stage 0 changes.

Stage 0 is complete only when every report row is green or the user has approved a spec amendment that removes or changes the failed requirement. After that, write separate implementation plans in this order: Water Lab, Rust conversion core, web single application, Tauri desktop, generic MCP server, legacy retirement.
