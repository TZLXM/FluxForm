(() => {
  "use strict";

  const api = window.__TAURI__;
  const byId = (id) => document.getElementById(id);
  const setText = (id, value) => {
    const node = byId(id);
    if (node) node.textContent = String(value);
  };

  if (!api?.core?.invoke || !api?.event?.listen) {
    setText("runtime-message", "Tauri APIs are unavailable. Open this UI through the desktop probe runtime.");
    return;
  }

  const invoke = api.core.invoke;
  const listen = api.event.listen;

  if (document.body.dataset.surface === "target") {
    let clickCount = 0;
    let dropCount = 0;
    for (const button of document.querySelectorAll(".target-control")) {
      button.addEventListener("click", async () => {
        try {
          clickCount = await invoke("record_background_interaction", { corner: button.dataset.corner });
          setText("target-status", `Background clicks: ${clickCount} · drops: ${dropCount}`);
        } catch (error) {
          setText("target-status", `Target instrumentation error: ${error}`);
        }
      });
    }
    void listen("probe://background-drop", ({ payload }) => {
      dropCount = payload.count ?? dropCount + 1;
      setText("target-status", `Background clicks: ${clickCount} · drops: ${dropCount}`);
    });
    return;
  }

  let snapshot = null;
  let focusEvents = 0;
  let keyEvents = 0;
  let dragAttempts = 0;
  let appDrops = 0;
  let dpiEvents = 0;
  let monitorMoves = 0;
  let lastMonitorIdentity = null;
  let backgroundClicks = 0;
  let backgroundDrops = 0;
  let idleTimer = null;
  let idleMeasurementComplete = false;

  const checks = () => Object.fromEntries(
    Array.from(document.querySelectorAll("input[data-check]"), (input) => [input.dataset.check, input.checked]),
  );

  function updateCounters() {
    setText("focus-key-count", `${focusEvents} / ${keyEvents}`);
    setText("drag-drop-count", `${dragAttempts} / ${appDrops}`);
    setText("background-count", `${backgroundClicks} / ${backgroundDrops}`);
    setText("dpi-monitor-count", `${dpiEvents} / ${monitorMoves}`);
  }

  async function refreshSnapshot() {
    if (idleTimer !== null) return;
    try {
      snapshot = await invoke("get_probe_snapshot");
      document.body.dataset.mode = snapshot.probeMode;
      setText("mode-label", snapshot.probeMode);
      setText("window-label", `${snapshot.windowLabel} · launch ${window.__PROBE_LAUNCH_ID__ || "unknown"}`);
      setText("window-count", snapshot.probeWindowCount);
      setText("backend-count", snapshot.backendProcessCount);
      setText("helper-count", snapshot.webviewHelperProcessCount);
      setText("input-region-status", `Native input region: ${snapshot.inputHitRegionStatus}`);
      setText("provenance-status", snapshot.provenanceVerified
        ? `Installed package SHA-256: ${snapshot.installedArtifactSha256} · ${snapshot.installIdentity}`
        : `Installed package provenance unverified: ${snapshot.provenanceError}`);
      const monitor = snapshot.currentMonitorName || "unnamed";
      setText("display-info", `${Number(snapshot.scaleFactor).toFixed(2)}× / ${snapshot.availableMonitorCount} · ${monitor} · ${snapshot.windowPositionX},${snapshot.windowPositionY}`);
      if (monitorIdentityChanged(lastMonitorIdentity, snapshot.currentMonitorIdentity)) monitorMoves += 1;
      if (snapshot.currentMonitorIdentity !== null) lastMonitorIdentity = snapshot.currentMonitorIdentity;
      backgroundClicks = snapshot.backgroundClickCount;
      backgroundDrops = snapshot.backgroundDropCount;
      updateCounters();
      const warning = byId("build-warning");
      if (!snapshot.nativeHitRegionSupported) {
        warning.hidden = false;
        warning.textContent = `Native circular input region is unsupported (${snapshot.inputHitRegionStatus}); using a rectangular/closed fallback. This mode cannot PASS.`;
      } else if (snapshot.developmentBuild) {
        warning.hidden = false;
        warning.textContent = "Development build — not an installed-artifact result. Failed observations may be saved; PASS is blocked.";
      } else if (!snapshot.provenanceVerified) {
        warning.hidden = false;
        warning.textContent = `Installed-package provenance is unavailable or mismatched (${snapshot.provenanceError}); failed observations may be saved, but PASS is blocked.`;
      } else if (snapshot.displayServer === "wayland") {
        warning.hidden = false;
        warning.textContent = "Wayland may restrict global positioning or always-on-top behavior; document these as degraded capabilities in Notes, not generic failures.";
      } else {
        warning.hidden = true;
      }
    } catch (error) {
      setText("runtime-message", `Native instrumentation unavailable: ${error}`);
    }
  }

  void listen("probe://file-drop", ({ payload }) => {
    appDrops += 1;
    const paths = Array.isArray(payload.paths) ? payload.paths.map((path) => path.split(/[\\/]/).pop()).join(", ") : "file";
    if (payload.insideOrb) {
      const checkbox = document.querySelector('[data-check="file_drop_works"]');
      if (checkbox) checkbox.checked = true;
    } else {
      const checkbox = document.querySelector('[data-check="outside_orb_drop_reached_fluxform"]');
      if (checkbox) checkbox.checked = true;
    }
    setText("drop-status", `FluxForm received ${paths} ${payload.insideOrb ? "inside" : "outside"} the orb.`);
    updateCounters();
  });

  void listen("probe://background-drop", ({ payload }) => {
    backgroundDrops = payload.count ?? backgroundDrops + 1;
    const checkbox = document.querySelector('[data-check="outside_orb_drop_reached_background_target"]');
    if (checkbox) checkbox.checked = true;
    setText("drop-status", "The visible background target received a file drop.");
    updateCounters();
  });

  void listen("probe://window-event", ({ payload }) => {
    if (payload.kind === "focused" && payload.focused) focusEvents += 1;
    if (payload.kind === "scale-factor-changed") {
      dpiEvents += 1;
      setText("drop-status", `DPI event: ${payload.scaleFactor}× · ${payload.width}×${payload.height} physical pixels.`);
      void refreshSnapshot();
    }
    if (payload.kind === "moved") {
      void refreshSnapshot();
    }
    updateCounters();
  });

  void listen("probe://hit-region-unsupported", ({ payload }) => {
    const warning = byId("build-warning");
    warning.hidden = false;
    warning.textContent = `Native input region failed closed: ${payload}`;
  });

  document.addEventListener("keydown", (event) => {
    if (!event.repeat) keyEvents += 1;
    updateCounters();
  });

  byId("drag-handle").addEventListener("click", async () => {
    try {
      await api.window.getCurrentWindow().startDragging();
      dragAttempts += 1;
      setText("drop-status", "Native drag request sent; mark the drag check only after the window actually moves.");
    } catch (error) {
      setText("drop-status", `Native drag request failed: ${error}`);
    }
    updateCounters();
  });

  byId("close-window").addEventListener("click", async () => {
    try {
      await invoke("close_probe_window");
    } catch (error) {
      setText("runtime-message", `Could not close this window: ${error}`);
    }
  });

  byId("idle-timer").addEventListener("click", () => {
    if (idleTimer !== null) return;
    idleMeasurementComplete = false;
    byId("idle-timer").disabled = true;
    setText("idle-status", "Probe polling paused. Leave it idle in the OS monitor; enter CPU/GPU readings after 60 seconds.");
    idleTimer = window.setTimeout(() => {
      idleTimer = null;
      idleMeasurementComplete = true;
      byId("idle-timer").disabled = false;
      setText("idle-status", "60 seconds elapsed. Enter the observed CPU/GPU percentages below.");
      void refreshSnapshot();
    }, 60000);
  });

  byId("save-result").addEventListener("click", async () => {
    if (!snapshot) {
      setText("save-status", "Waiting for native snapshot; try again after the status panel loads.");
      return;
    }
    const cpu = Number(byId("cpu-percent").value);
    const gpu = Number(byId("gpu-percent").value);
    if (!idleMeasurementComplete || !byId("cpu-percent").value.trim() || !byId("gpu-percent").value.trim()) {
      setText("save-status", "Complete the 60-second idle timer and enter both OS-observed CPU/GPU readings before saving.");
      return;
    }
    if (!Number.isFinite(cpu) || cpu < 0 || !Number.isFinite(gpu) || gpu < 0) {
      setText("save-status", "CPU and GPU readings must be finite, non-negative percentages.");
      return;
    }
    const result = {
      probe_mode: snapshot.probeMode,
      os: snapshot.os,
      os_version: snapshot.osVersion,
      display_server: snapshot.displayServer,
      installed_artifact_sha256: snapshot.installedArtifactSha256,
      installed_executable_sha256: snapshot.installedExecutableSha256,
      install_identity: snapshot.installIdentity,
      provenance_verified: snapshot.provenanceVerified,
      provenance_error: snapshot.provenanceError,
      installed_launch_path: snapshot.installedLaunchPath,
      native_hit_region_supported: snapshot.nativeHitRegionSupported,
      input_hit_region_status: snapshot.inputHitRegionStatus,
      network_disconnected: byId("network-disconnected").checked,
      first_launch_succeeded: byId("first-launch-succeeded").checked,
      transparent_pixels_visible: checks().transparent_pixels_visible,
      transparent_pixels_click_through: checks().transparent_pixels_click_through,
      frameless_drag_works: checks().frameless_drag_works,
      file_drop_works: checks().file_drop_works,
      outside_orb_drop_reached_background_target: checks().outside_orb_drop_reached_background_target,
      outside_orb_drop_reached_fluxform: checks().outside_orb_drop_reached_fluxform,
      focus_recovery_works: checks().focus_recovery_works,
      keyboard_input_works: checks().keyboard_input_works,
      repeated_launch_created_second_window: checks().repeated_launch_created_second_window,
      repeated_launch_backend_process_count: snapshot.backendProcessCount,
      single_window_close_works: checks().single_window_close_works,
      last_window_close_works: checks().last_window_close_works,
      dpi_change_works: checks().dpi_change_works,
      multi_monitor_move_works: checks().multi_monitor_move_works,
      idle_cpu_percent: cpu,
      idle_gpu_percent: gpu,
      notes: byId("notes").value,
      passed: byId("passed").checked,
      webview_helper_process_count: snapshot.webviewHelperProcessCount,
    };
    try {
      const path = await invoke("record_probe_result", { result });
      setText("save-status", `JSON saved without overwriting existing evidence: ${path}`);
    } catch (error) {
      setText("save-status", `Evidence was not saved: ${error}`);
    }
  });

  void refreshSnapshot();
  window.setInterval(() => void refreshSnapshot(), 2500);
})();
