# Task 15 Report — Cross-Platform Desktop Window Feasibility Probe

## Outcome

Added a minimal Tauri 2 desktop probe with three build-time modes for
transparent-orb, transparent-window/rectangular-hit-region, and opaque-frameless
fallback behavior. A second launch requests another 360×360 probe window in
the existing backend process. The UI records manual observations and live
instrumentation separately; it is explicitly a window-feasibility probe, not
the final water shader.

Review fix round 1 adds a native Windows circular input region for orb mode,
strictly bounded two-probe-window lifecycle, external installed-package
provenance gating, separate least-privilege renderer capabilities, and monitor
identity-based transition counting. Unsupported platforms remain visibly
rectangular/opaque fallback probes and cannot report a transparent-orb PASS.

The Windows production build and both installable bundle formats succeeded.
No GUI was launched during this task, so this report makes no claim about
native transparency, hit testing, drag/drop, focus, DPI, monitor movement, or
idle CPU/GPU behavior. Those observations, and the Task 16 installed-artifact
offline/manual matrix, remain outstanding.

## TDD record

- Added model/validation tests first. The initial RED run failed to compile
  because `WindowProbeResult`, its validator, and the evidence writer did not
  yet exist.
- GREEN: implemented a strict serde evidence model and validator. Tests reject
  missing/unknown modes and display servers, absent identity fields, invalid
  artifact digests, negative/non-finite CPU or GPU readings, backend-process
  counts other than one for passing results, missing shared manual checks, and
  mode-specific transparency/hit-test/drop contradictions.
- GREEN: failed observations remain recordable. Passing results are gated on
  network disconnection, successful installed first launch, one backend,
  common interaction checks, and the selected mode's required pixel/drop
  behavior. WebView helper count is stored separately from backend count.
- Evidence-writer regressions verify byte-deterministic JSON, fixed
  mode/server/digest-derived filenames, `create_new` no-overwrite behavior,
  and that notes/launch-path data cannot redirect output. The runtime chooses
  the application-local `probe-results` directory; callers cannot supply an
  arbitrary output path.
- Geometry RED/GREEN: a boundary-point test exposed an orb hit radius that
  excluded a point still inside the CSS circle. The radius was corrected to
  match the 8 px CSS inset and the regression now passes.
- Fix-round RED/GREEN: the missing native hit-region controller, lifecycle
  decision, external provenance reader/writer, and monitor identity helper
  each produced their expected missing-symbol/module failures before GREEN.
  The ACL regression was also run RED against the original wildcard/default
  permissions (`*` did not match the exact probe-window expectation), then
  passed after least-privilege codegen was restored.
  The updated suite covers native ellipse bounds plus resize/DPI lifecycle,
  unsupported/failing region fallbacks, 2→1 and 1→0 close ordering, matching
  and tampered/missing provenance, create-new manifest behavior, exact ACL
  labels/permissions, and same/cross-monitor identity changes.

## Implementation

- Added the app under `apps/desktop-probe`, pinned Tauri dependencies to
  `tauri = 2.12.0`, `tauri-build = 2.7.0`, and
  `tauri-plugin-single-instance = 2.5.0`; pinned the frontend CLI to
  `@tauri-apps/cli = 2.12.0`. Root Cargo workspace/lock files include the
  application and fully resolved graph.
- Three mutually exclusive Cargo features select build-time modes. Compilation
  fails if no mode or multiple modes are selected; package scripts expose all
  three explicit build variants.
- Configured a frameless, always-on-top, transparent 360×360 orb (except in the
  opaque fallback mode), Tauri 2 single-instance plugin, macOS private API, and
  Windows `offlineInstaller` WebView2 runtime packaging. A separate visible
  background target exposes controls at all four corners for click-through and
  file-drop observations.
- On Windows, the backend binds a GDI elliptical window region to each probe
  HWND. It applies/reapplies the CSS-aligned 8 px inset on creation, resize, and
  DPI changes; if applying fails it attempts a rectangular region reset, then
  hides the window if even clearing the region fails. On macOS/Linux, circular
  native input regions are not implemented: transparent-orb remains an
  explicitly unsupported rectangular fallback and is blocked from PASS.
- Probe labels are fixed to `probe-primary` and `probe-secondary`; later launch
  requests focus the existing secondary window instead of creating unbounded
  labels. Closing one of two leaves the other alive; only the last probe
  window exits the process.
- Added CSS orb/corner markers, native drag control, ordered ten-step manual
  checklist, OS/network/manual fields, live window/backend/WebView-helper,
  focus/key/drag/drop/DPI/monitor counters, and a 60-second idle measurement
  gate. CPU/GPU values are manually entered from the OS monitor, not inferred
  or synthesized by the app. Linux Wayland positioning/topmost behavior is
  explicitly called out as potentially degraded.
- Native instrumentation reports OS/version, display server, exact running
  executable path and SHA-256, monitor identity/scale/position, process counts,
  window events, and file-drop events. Backend and WebView helper counts
  remain separate. `installed_artifact_sha256` is now the externally supplied
  installer/package digest, not the running EXE digest. Passing evidence also
  includes the separate executable digest, install identity, verified mode,
  and provenance status/error.
- The app reads only
  `<app_local_data_dir>/installed-provenance.json`; it does not expose a
  renderer command to create or alter that manifest. Task 16's installer
  verifier must write it with exclusive create-new semantics after installing
  a package and must populate schema version 1 fields: `installer_package_sha256`,
  canonical `installed_executable_path`, `installed_executable_sha256`,
  `probe_mode`, and a safe unique `install_identity`. At launch, the app checks
  the package-hash format, actual executable hash/path, mode, and identity.
  Missing or mismatched manifests allow only failed/unverified evidence. The
  app does not inspect or self-verify installer bytes and does not authenticate
  the external manifest; its package SHA is a verifier-supplied provenance
  claim, not cryptographic attestation.
- Renderer capabilities are split: probe windows can listen/unlisten, start
  native drag, snapshot/save/close; the background target can only
  listen/unlisten and invoke its click counter. Window labels are exact, app
  commands are generated from an explicit four-command manifest, and no
  renderer has `core:default`, event defaults, `emit`, or `emit_to`. Background
  drop observations originate in the trusted Rust native-window drop callback.
- Monitor move counts increment only when a known monitor identity
  (`name|origin-x|origin-y`) changes; ordinary moves still refresh physical
  coordinates. An initially discovered or unavailable monitor is not counted
  as a transition.
- Direct build-tree execution, including a release EXE without the external
  manifest, cannot produce PASS. Failed/unverified observations remain
  recordable. Evidence digests are backend-overwritten rather than accepted
  from renderer input.
- Evidence filenames are deterministic. The writer validates the model and
  creates a new file only; an existing matching filename is never overwritten.
- The app-scoped `pnpm-workspace.yaml` includes exact-version release-age
  exclusions for the pinned CLI and its platform packages. pnpm 11 generated
  these requirements for offline frozen-lockfile operation; keeping them
  scoped to this new app avoids changing repository-wide package policy.
- No final shader, product integration, fabricated native result, or Task 16
  completion is claimed.

## Verification

- `cargo test --offline --locked --target-dir target-task15 -p
  fluxform-desktop-probe` and the corresponding `--no-default-features
  --features probe-transparent-window-with-rectangular-hit-region` and
  `--features probe-opaque-frameless-fallback` runs — PASS, 17/17 tests for
  each mode (51 executions total). The repository-default `target/debug`
  Cargo lock could not be opened under the ordinary sandbox, so these runs
  used a separate target directory in the approved worktree.
- `cargo fmt --manifest-path apps/desktop-probe/src-tauri/Cargo.toml` — PASS.
- `node --check apps/desktop-probe/ui/probe.js` — PASS.
- `pnpm --dir apps/desktop-probe install --frozen-lockfile --offline` — PASS,
  lockfile already up to date.
- Parsed `tauri.conf.json` successfully.
- `CARGO_NET_OFFLINE=true pnpm --dir apps/desktop-probe run tauri:build` —
  PASS on Windows x64. The release executable and both bundle outputs were
  generated. Tauri's bundle process validated/downloaded its installer and
  WebView2 packaging assets under the controller-authorized bundling step.
- Fix-round mode suites: each exact build mode (`transparent-orb`,
  `transparent-window-with-rectangular-hit-region`, and
  `opaque-frameless-fallback`) — PASS, 36/36 Rust tests per mode (108 total).
- `cargo clippy --offline --locked --manifest-path
  apps/desktop-probe/src-tauri/Cargo.toml --all-targets -- -D warnings` — PASS.
- `cargo fmt --manifest-path apps/desktop-probe/src-tauri/Cargo.toml --check` —
  PASS.
- `node --check` for `probe.js` and `monitor-identity.js`, plus
  `node --test apps/desktop-probe/ui/tests/monitor-identity.test.cjs` — PASS,
  4/4 Node tests.
- `pnpm --dir apps/desktop-probe install --frozen-lockfile --offline` — PASS,
  already up-to-date on pnpm 11.19.0.
- Tauri ACL codegen/build — PASS; two exact capability files generated for
  probe and background-target windows and all custom command permissions
  resolved. Renderer event emission is not permitted.
- Final Windows x64 `tauri:build` after review fixes — PASS; both bundles
  regenerated using the previously approved Tauri installer/WebView2 asset
  setup. This verifies build/package production only, not GUI behavior.
- `git diff --check` — PASS.

### Windows build artifacts

Build outputs are local ignored artifacts and are not committed. Hashes identify
the exact files produced by the successful build; they are not native behavior
evidence.

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `target/release/fluxform-desktop-probe.exe` | 8,962,560 bytes | `D0EF712D4ADC71C3A6A3ECAAB7A0E7821323246CDB1C07CBEF10C032F2F32B19` |
| `target/release/bundle/msi/FluxForm Desktop Probe_0.1.0_x64_en-US.msi` | 215,449,600 bytes | `7F07C64EEB850BD13B4F13EC93C1F39842785F80939C1465646C35CE4A480120` |
| `target/release/bundle/nsis/FluxForm Desktop Probe_0.1.0_x64-setup.exe` | 216,957,048 bytes | `42B5EE0D33CA1B0B3379D916388F083A4844B7DDE303459975E7222531D87491` |

The stale pre-fix EXE row was independently corrected to
`2AF9220F586D9701BE28029703AF1B60A299106AB196AA8EA08D0081CF2C76F4` before
this source rebuild. The hashes in the table are authoritative for the final
post-fix binaries and intentionally supersede that earlier EXE digest.

## Outstanding observations

The GUI was not launched and no native interaction was observed. The updated
EXE and installers have independent build-artifact SHA-256 values above; this
does not constitute an installed provenance manifest or native result.
Before using this probe to decide product feasibility, install each mode,
have the Task 16 verifier exclusively create the manifest for that specific
package/install, then run each installed mode with the
network disconnected and follow its visible manual order on the target OS and
display server. Record actual CPU/GPU values and failures/degradation in the
generated JSON. Task 16's install/offline matrix must also be completed; a
successful Windows bundle build alone does not satisfy it.

## Commit

Pending final commit.
