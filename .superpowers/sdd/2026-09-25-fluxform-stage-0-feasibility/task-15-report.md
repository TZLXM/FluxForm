# Task 15 Report — Cross-Platform Desktop Window Feasibility Probe

## Outcome

Added a minimal Tauri 2 desktop probe with three build-time modes for
transparent-orb, transparent-window/rectangular-hit-region, and opaque-frameless
fallback behavior. A second launch requests another 360×360 probe window in
the existing backend process. The UI records manual observations and live
instrumentation separately; it is explicitly a window-feasibility probe, not
the final water shader.

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
- Added CSS orb/corner markers, native drag control, ordered ten-step manual
  checklist, OS/network/manual fields, live window/backend/WebView-helper,
  focus/key/drag/drop/DPI/monitor counters, and a 60-second idle measurement
  gate. CPU/GPU values are manually entered from the OS monitor, not inferred
  or synthesized by the app. Linux Wayland positioning/topmost behavior is
  explicitly called out as potentially degraded.
- Native instrumentation reports OS/version, display server, executable path
  and SHA-256, monitor/scale information, process counts, window events, and
  file-drop events. Backend and WebView helper counts remain separate. Pass
  evidence from debug builds is blocked; failed debug observations may still
  be saved for diagnosis.
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
- `git diff --check` — PASS.

### Windows build artifacts

Build outputs are local ignored artifacts and are not committed. Hashes identify
the exact files produced by the successful build; they are not native behavior
evidence.

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `target/release/fluxform-desktop-probe.exe` | 9,088,000 bytes | `2AF9220F586D9701BE28029703AF1B60A299106AB196AA8EA08D0081CF2C76F3` |
| `target/release/bundle/msi/FluxForm Desktop Probe_0.1.0_x64_en-US.msi` | 215,445,504 bytes | `6ADC19818591A217B78A8486FD182F3A21EE16409B58232415FB31669CE6D9BB` |
| `target/release/bundle/nsis/FluxForm Desktop Probe_0.1.0_x64-setup.exe` | 216,952,597 bytes | `4B945DBE44D634777AB843E56082B19B7E025187253835FFCC4F57D20CAF9561` |

## Outstanding observations

The GUI was not launched and no native interaction was observed. Before using
this probe to decide product feasibility, run each installed mode with the
network disconnected and follow its visible manual order on the target OS and
display server. Record actual CPU/GPU values and failures/degradation in the
generated JSON. Task 16's install/offline matrix must also be completed; a
successful Windows bundle build alone does not satisfy it.

## Commit

Pending final commit.
