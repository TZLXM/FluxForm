# Task 15 Fix Round 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six Task 15 desktop-probe review findings without claiming unobserved native behavior.

**Architecture:** Keep the existing Tauri/Cargo/pnpm pins and use a tested platform abstraction for the Windows circular input region; unsupported platforms stay on a rectangular input fallback and can never produce a transparent-orb PASS. Bind PASS to a fixed, externally-created install provenance manifest, restrict renderer ACLs to exact windows/commands/events, and count monitor changes from stable monitor identity rather than ordinary move events.

**Tech Stack:** Rust/Tauri 2.12.0, `tauri-build` 2.7.0, `tauri-plugin-single-instance` 2.5.0, Win32 GDI/User32 FFI (no new package), pnpm 11.19.0, Node's built-in test runner.

**Spec:** `docs/superpowers/plans/2026-09-25-fluxform-stage-0-feasibility.md` Task 15 and Task 16; `.superpowers/sdd/2026-09-25-fluxform-stage-0-feasibility/task-15-brief.md`; reviewer instructions from the parent task.

## Global Constraints

- Preserve the exact existing Tauri and CLI pins and Cargo/pnpm lockfiles; do not fetch or add a dependency.
- Apply a real circular native input region on Windows and reapply it after resize and DPI events; elsewhere report unsupported and use the explicit rectangular/opaque fallback behavior without a PASS.
- Exit only when no probe window remains, accounting for Tauri's Destroyed event before or after registry removal.
- Passing evidence must include a valid external installer/package provenance manifest matching the exact running executable, mode, and install identity; the application does not verify installer bytes itself.
- Renderer capabilities must name exact window labels and only needed commands/events; renderer cannot emit trusted probe events.
- Keep Task 16/native GUI interaction evidence outstanding unless actually run.

## Review Focus

- Stale, missing, or failed Windows region updates must never leave a transparent click-through area while evidence claims circular hit-testing.
- A Destroyed event observed against either pre-removal or post-removal Tauri window registries must preserve the remaining window.
- Direct build-tree execution, manifest tampering, wrong install path, wrong executable hash, wrong mode, or invalid package hash must never produce PASS.
- Renderer attempts to invoke unlisted commands or synthesize event observations must be blocked by the compiled ACL.
- Ordinary movement within one monitor must not increment monitor transitions, including when monitor names are absent.

---

### Task 1: Native shaped hit-testing and fail-closed fallback

**Files:** Modify `apps/desktop-probe/src-tauri/src/lib.rs`; add `apps/desktop-probe/src-tauri/src/hit_region.rs`; test in the Rust modules.

**Interfaces:** Keep `PROBE_MODE`; add a pure hit-region capability/state abstraction consumed by window creation, resize/DPI handlers, snapshots, and result validation. Windows implementation uses `WebviewWindow::hwnd()` with direct GDI/User32 FFI; other platforms return unsupported.

- [x] Write tests for Windows ellipse bounds/inset, initial/resize/DPI reapplication, failed native application falling back without PASS, and unsupported non-Windows orb behavior.
- [x] Run the focused tests and observe the expected missing behavior.
- [x] Implement the minimum native-region lifecycle and unsupported rectangular fallback.
- [x] Run focused tests for all build modes.

### Task 2: Probe window exit lifecycle

**Files:** Modify `apps/desktop-probe/src-tauri/src/lib.rs`; test in the same module.

**Interfaces:** Add a pure `should_exit_after_probe_destroyed(labels, destroyed_label)` decision used by the Tauri Destroyed callback.

- [x] Test 2→1 against both a pre-removal registry containing the destroyed label and a post-removal registry; test 1→0 in both orderings.
- [x] Run tests to observe the current premature-exit behavior or missing helper.
- [x] Implement exact-zero remaining-window logic and keep the background target until then.
- [x] Run focused tests.

### Task 3: External install provenance and PASS gate

**Files:** Modify `apps/desktop-probe/src-tauri/src/lib.rs`, `apps/desktop-probe/ui/index.html`, `apps/desktop-probe/ui/probe.js`; test in Rust module.

**Interfaces:** Add strict `InstalledProvenance` schema with installer/package SHA-256, canonical installed executable path and executable SHA-256, compile-time mode, and install identity. Read only from `<app_local_data_dir>/installed-provenance.json`; externally create with exclusive create-new semantics. Replace running-EXE `installed_artifact_sha256` with package hash and add separate executable hash/install identity/provenance status.

- [x] Test matching install metadata, missing manifest/build-tree rejection, tampered package/executable/path/mode/install identity rejection, and external create-new/no-overwrite behavior.
- [x] Run those tests and observe missing provenance enforcement.
- [x] Implement strict manifest reading/validation and overwrite renderer fields from the verified backend snapshot. Failed/unverified records remain saveable but PASS is forcibly false.
- [x] Run focused tests for all modes.

### Task 4: Exact Tauri ACL and trusted background observation

**Files:** Modify `apps/desktop-probe/src-tauri/build.rs`, `apps/desktop-probe/src-tauri/capabilities/default.json`, `apps/desktop-probe/src-tauri/src/lib.rs`; add ACL test.

**Interfaces:** Use the Tauri application manifest to generate permissions for the four custom commands; grant only those, `core:event:allow-listen`, `core:event:allow-unlisten`, and `core:window:allow-start-dragging` to the exact `probe-primary`, `probe-secondary`, and `background-target` labels. Keep background-drop events sourced only from native Rust window events.

- [x] Add a parsed ACL regression that fails for wildcard labels, `core:default`, generic event defaults, emit/emit_to permissions, or unlisted custom commands.
- [x] Run it against the original wildcard/default capability and observe its expected failure.
- [x] Implement the least-privilege per-window capability and bounded exact probe labels.
- [x] Run the ACL test and Tauri build codegen to verify permission identifiers.

### Task 5: Monitor transition counting

**Files:** Modify `apps/desktop-probe/src-tauri/src/lib.rs`, `apps/desktop-probe/ui/probe.js`, and `apps/desktop-probe/ui/index.html`; add `apps/desktop-probe/ui/monitor-identity.js` and `apps/desktop-probe/ui/tests/monitor-identity.test.cjs`.

**Interfaces:** Pure `monitorIdentityChanged(previous, current)` helper returns true only for two known unequal monitor identities; probe JS refreshes coordinates on every move but increments monitorMoves only on actual identity change.

- [x] Add Node tests for same monitor, changed monitor, first identity, absent identity, and repeated move events.
- [x] Run them to observe the current false increments/absent helper.
- [x] Implement monitor-identity comparison and expose stable monitor identity in native snapshots.
- [x] Run Node tests and syntax validation.

### Task 6: Evidence correction, full verification, report, and commit

**Files:** Modify `.superpowers/sdd/2026-09-25-fluxform-stage-0-feasibility/task-15-report.md`; commit prior code/config tests.

- [x] Re-read the plan and Task 16 expectations; rerun all three mode suites, offline frozen pnpm install, Node tests, formatting, Clippy, config/ACL validation, and `git diff --check`.
- [x] Build/bundle Windows with the already authorized Tauri/WebView2/WiX/NSIS setup; do not claim GUI behavior.
- [x] Independently SHA-256 the final executable/MSI/NSIS outputs and report those exact values; explicitly distinguish installer hash from executable hash and external provenance.
- [x] Commit the fix round with a Conventional Commit message.
