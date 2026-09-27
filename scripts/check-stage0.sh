#!/usr/bin/env bash
set -u

usage() {
  cat <<'USAGE'
Usage: scripts/check-stage0.sh --mode automated|complete [options]
  --gate NAME                 Select a gate; repeat to select multiple gates.
  --ffmpeg PATH --ffprobe PATH
                              Legacy direct executable inputs are fail-closed.
  --ffmpeg-archive PATH --artifact-id ID --profile PATH
                              Run the hardened immutable archive verifier.
  --report-path PATH          Override the report path (primarily for fixtures).
USAGE
}

mode=''
report_path=''
ffmpeg_path=''
ffprobe_path=''
ffmpeg_archive=''
artifact_id=''
profile_path=''
declare -a requested_gates=()

while (($#)); do
  case "$1" in
    --mode|--gate|--report-path|--ffmpeg|--ffprobe|--ffmpeg-archive|--artifact-id|--profile)
      if (($# < 2)); then echo "FAIL: missing value for $1" >&2; exit 2; fi
      option="$1"; value="$2"; shift 2
      case "$option" in
        --mode) mode="$value" ;;
        --gate) requested_gates+=("$value") ;;
        --report-path) report_path="$value" ;;
        --ffmpeg) ffmpeg_path="$value" ;;
        --ffprobe) ffprobe_path="$value" ;;
        --ffmpeg-archive) ffmpeg_archive="$value" ;;
        --artifact-id) artifact_id="$value" ;;
        --profile) profile_path="$value" ;;
      esac
      ;;
    --help|-h) usage; exit 0 ;;
    *) echo "FAIL: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$mode" != 'automated' && "$mode" != 'complete' ]]; then
  echo 'FAIL: --mode must be automated or complete.' >&2
  usage >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/.." && pwd)"
evidence_root="$repo_root/target/stage0"
run_id="$(date -u +%Y%m%dT%H%M%S)-$$-$RANDOM"
run_root="$evidence_root/runs/$run_id"
mkdir -p -- "$run_root"
report_path="${report_path:-$repo_root/docs/architecture/stage-0-gate-report.md}"
export CARGO_NET_OFFLINE=true

automated_defaults=(format clippy protocol contract-drift capabilities ffmpeg-profile-tests atomic-output sandbox-unit server-probe desktop-probe-modes desktop-build ffmpeg-profile)
complete_defaults=(report ffmpeg-artifacts aggregate-samples public-server-linux)
complete_required=("${automated_defaults[@]}" "${complete_defaults[@]}")
if ((${#requested_gates[@]})); then
  selected_gates=("${requested_gates[@]}")
elif [[ "$mode" == 'complete' ]]; then
  selected_gates=("${complete_required[@]}")
else
  selected_gates=("${automated_defaults[@]}")
fi

declare -a statuses=()
declare -a reasons=()
gate_status='PASS'
gate_reason=''

log_command() {
  local name="$1"; shift
  local safe_name="${name//[^A-Za-z0-9_.-]/_}"
  local log_path="$run_root/$safe_name.log"
  printf '+ %q' "$1"; shift
  printf ' %q' "$@"; printf '\n'
  "$@" >/dev/null 2>&1 && return 0
}

run_logged() {
  local name="$1"; local executable="$2"; shift 2
  local safe_name="${name//[^A-Za-z0-9_.-]/_}"
  local log_path="$run_root/$safe_name.log"
  printf '+ %s' "$executable"
  printf ' %q' "$@"
  printf '\n'
  "$executable" "$@" >"$log_path" 2>&1
  local exit_code=$?
  cat -- "$log_path"
  printf '\nexit_code=%s\n' "$exit_code" >>"$log_path"
  printf 'log: %s\n' "$log_path"
  if ((exit_code != 0)); then
    gate_status='FAIL'
    gate_reason="command exited $exit_code: $executable $*"
    return 1
  fi
}

run_cargo() {
  local name="$1"; shift
  if ! command -v cargo >/dev/null 2>&1; then
    gate_status='BLOCKED'
    gate_reason='cargo is not installed or is not on PATH.'
    return 1
  fi
  run_logged "$name" cargo --locked --offline "$@"
}

blocked() { gate_status='BLOCKED'; gate_reason="$1"; return 1; }
failed() { gate_status='FAIL'; gate_reason="$1"; return 1; }

find_python3() {
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

validate_report() {
  local path="$1"
  if [[ ! -f "$path" ]]; then blocked "gate report does not exist: $path"; return 1; fi
  local python_command='python3'
  if ! command -v "$python_command" >/dev/null 2>&1 || ! "$python_command" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' >/dev/null 2>&1; then
    python_command='python'
  fi
  if ! command -v "$python_command" >/dev/null 2>&1 || ! "$python_command" -c 'import sys; raise SystemExit(0 if sys.version_info.major == 3 else 1)' >/dev/null 2>&1; then
    blocked 'a runnable Python 3 interpreter is required to validate the complete evidence report.'; return 1
  fi
  "$python_command" - "$path" "$repo_root" <<'PY'
import hashlib
import re
import sys
from pathlib import Path

path = sys.argv[1]
repo_root = Path(sys.argv[2]).resolve()
expected_evidence = [
    "Protocol/schema determinism",
    "Windows FFmpeg profile and license record",
    "macOS x86_64 FFmpeg profile and license record",
    "macOS aarch64 FFmpeg profile and license record",
    "Linux x86_64 FFmpeg profile and license record",
    "Exact approved/deferred capability matrix and product-owner approval",
    "Every enabled edge and rejection sample executed against all four approved native profiles",
    "Atomic reject/rename/replace, injected replacement failures, and crash recovery on each supported local filesystem",
    "Linux filesystem sandbox denial",
    "Linux OS network denial, distinct from FFmpeg protocol-policy denial",
    "Linux cgroup v2 birth placement, aggregate process/memory/CPU containment, and kill",
    "Streaming upload, reservation expansion, and early body termination",
    "Capability authorization on every concrete endpoint, Origin enforcement, and trusted-proxy IP provenance",
    "SSE reconnect, replay, resync snapshot, and expiry",
    "Real positive and negative fail-closed public-server startup",
    "Windows installed-app window, repeated-launch, close, DPI, and multi-monitor behavior",
    "Native Intel and Apple Silicon installed-app macOS window behavior",
    "Linux X11 installed-AppImage window behavior",
    "Linux Wayland installed-AppImage behavior and explicit degraded capability",
    "Windows offline WebView2 installation and first launch",
    "Signed/notarized disconnected macOS installation and first launch on both architectures",
    "Linux disconnected AppImage first launch",
    "Approved FFmpeg/FFprobe sidecar hashes and offline fixed `-version` execution per platform",
]
try:
    text = open(path, encoding="utf-8").read()
except OSError as error:
    print(f"FAIL: cannot read gate report: {error}", file=sys.stderr)
    raise SystemExit(2)

rows = []
pattern = re.compile(r"^\|\s*(\d+)\s*\|\s*([^|]+?)\s*\|\s*\*\*(PASS|FAIL|BLOCKED)\*\*\s*\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|$")
for line in text.splitlines():
    match = pattern.match(line)
    if match:
        rows.append((int(match.group(1)), match.group(2).strip(), match.group(3), match.group(4).strip(), match.group(5).strip()))

def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    raise SystemExit(2)

def blocked(message):
    print(f"BLOCKED: {message}", file=sys.stderr)
    raise SystemExit(10)

if len(rows) != 23:
    fail(f"expected 23 uniquely numbered evidence rows, found {len(rows)}")
if sorted(row[0] for row in rows) != list(range(1, 24)):
    fail("report evidence rows must cover every number from 1 through 23 exactly once")
for number, evidence, status, reviewer, details in rows:
    if not evidence or not reviewer or not details:
        fail(f"evidence row {number} has a blank evidence cell")
    if evidence != expected_evidence[number - 1]:
        fail(f"evidence row {number} label does not match the required Stage 0 evidence item")
    if not re.search(r"\b20\d{2}-\d{2}-\d{2}\b", reviewer):
        fail(f"evidence row {number} has no ISO date")
    if re.search(r"pending|unreviewed|placeholder|fixture|codex.*recorder", reviewer, re.I):
        blocked(f"evidence row {number} has no independent human review")
    if status == "PASS":
        recorded_hashes = {match.group(1).lower() for match in re.finditer(r"sha-?256\s*[:=]?\s*`?([0-9a-f]{64})`?", details, re.I)}
        if not recorded_hashes:
            blocked(f"passing evidence row {number} has no SHA-256 artifact identity")
        verified_identity = False
        for match in re.finditer(r"`([^`]+)`", details):
            token = match.group(1).strip()
            if "/" not in token and "\\" not in token:
                continue
            candidate = Path(token)
            if not candidate.is_absolute():
                candidate = repo_root / candidate
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(repo_root)
                if not resolved.is_file() or candidate.is_symlink():
                    continue
                digest = hashlib.sha256()
                with resolved.open("rb") as artifact:
                    for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() in recorded_hashes:
                    verified_identity = True
                    break
            except (OSError, ValueError):
                continue
        if not verified_identity:
            blocked(f"passing evidence row {number} has no existing in-repository artifact whose SHA-256 matches the recorded identity")
    if status == "BLOCKED" and not re.search(r"blocked|not run|no .* exists|no .* available|not available|missing", details, re.I):
        fail(f"blocked evidence row {number} does not explain its prerequisite")

summary = re.search(r"\*\*Overall status: (PASS|FAIL|BLOCKED)\.\*\*\s*Current matrix:\s*\*\*(\d+) PASS,\s*(\d+) FAIL,\s*(\d+) BLOCKED\*\*", text)
if not summary:
    fail("gate report does not contain a canonical status summary")
counts = {status: sum(row[2] == status for row in rows) for status in ("PASS", "FAIL", "BLOCKED")}
expected_overall = "FAIL" if counts["FAIL"] else "BLOCKED" if counts["BLOCKED"] else "PASS"
if summary.group(1) != expected_overall or tuple(map(int, summary.groups()[1:])) != (counts["PASS"], counts["FAIL"], counts["BLOCKED"]):
    fail("gate report summary does not match its evidence rows")
if counts["FAIL"]:
    print(f"FAIL: {counts['FAIL']} gate report row(s) are FAIL", file=sys.stderr)
    raise SystemExit(2)
if counts["BLOCKED"]:
    print(f"BLOCKED: {counts['BLOCKED']} gate report row(s) are BLOCKED", file=sys.stderr)
    raise SystemExit(10)
if counts["PASS"] != 23:
    fail("every one of the 23 gate report rows must be PASS")
print("PASS: all 23 report rows are PASS, dated, identified, and independently reviewed")
PY
  "$python_command" "$script_dir/validate_stage0_report.py" --repo-root "$repo_root" --report "$path"
  local evidence_exit_code=$?
  if ((evidence_exit_code == 10)); then gate_status='BLOCKED'; gate_reason='reviewed per-row evidence bundle is missing, untrusted, or invalid.'; return 1; fi
  if ((evidence_exit_code != 0)); then gate_status='FAIL'; gate_reason='reviewed per-row evidence bundle or report is malformed.'; return 1; fi
  local exit_code=$?
  if ((exit_code == 0)); then gate_status='PASS'; gate_reason=''; return 0; fi
  if ((exit_code == 10)); then gate_status='BLOCKED'; gate_reason='one or more report rows are BLOCKED or await human review.'; return 1; fi
  gate_status='FAIL'; gate_reason='the gate report is malformed or its evidence summary is inconsistent.'; return 1
}

copy_profile_evidence() {
  local source_root="$1"; local destination_root="$2"
  local names=(windows-x86_64 macos-x86_64 macos-aarch64 linux-x86_64)
  local triples=(x86_64-pc-windows-msvc x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-gnu)
  local files=(ffmpeg-windows-x86_64.json ffmpeg-macos-x86_64.json ffmpeg-macos-aarch64.json ffmpeg-linux-x86_64.json)
  local python_command
  python_command="$(find_python3)" || { blocked 'a runnable Python 3 interpreter is required to validate native profile report artifacts.'; return 1; }
  mkdir -p -- "$destination_root"
  for index in "${!names[@]}"; do
    local source="$source_root/${files[$index]}"
    [[ -f "$source" ]] || { blocked "exact native profile artifact is missing: $source"; return 1; }
    "$python_command" - "$source" "${triples[$index]}" <<'PY'
import json
import sys
try:
    report = json.load(open(sys.argv[1], encoding="utf-8"))
except Exception as error:
    print(f"FAIL: invalid profile JSON: {error}", file=sys.stderr)
    raise SystemExit(2)
if report.get("target_triple") != sys.argv[2]:
    print(f"FAIL: profile target mismatch: {report.get('target_triple')}", file=sys.stderr)
    raise SystemExit(2)
if report.get("artifact_status") != "approved" or report.get("distribution_gate_status") != "approved" or not report.get("approval_record_id") or not report.get("approval_date"):
    print("BLOCKED: profile artifact or distribution gate is not approved", file=sys.stderr)
    raise SystemExit(10)
PY
    local verify_status=$?
    if ((verify_status == 10)); then blocked "profile artifact is not approved: $source"; return 1; fi
    if ((verify_status != 0)); then failed "profile artifact is malformed or mismatched: $source"; return 1; fi
    cp -- "$source" "$destination_root/${names[$index]}.json" || { failed "could not stage profile evidence: $source"; return 1; }
  done
}

run_gate() {
  local name="$1"
  gate_status='PASS'; gate_reason=''
  case "$name" in
    format) run_cargo "$name" fmt --all -- --check || return 1 ;;
    clippy)
      run_cargo "$name" clippy --workspace --exclude fluxform-desktop-probe --all-targets --all-features -- -D warnings || return 1
      run_cargo "$name-desktop-transparent-orb" clippy -p fluxform-desktop-probe --all-targets -- -D warnings || return 1
      run_cargo "$name-desktop-rectangular-hit-region" clippy -p fluxform-desktop-probe --no-default-features --features probe-transparent-window-with-rectangular-hit-region --all-targets -- -D warnings || return 1
      run_cargo "$name-desktop-opaque-fallback" clippy -p fluxform-desktop-probe --no-default-features --features probe-opaque-frameless-fallback --all-targets -- -D warnings || return 1
      ;;
    protocol) run_cargo "$name" test -p fluxform-protocol --all-targets --all-features || return 1 ;;
    contract-drift) run_cargo "$name" test -p fluxform-protocol --test contracts committed_contracts_match_the_rust_source || return 1 ;;
    capabilities)
      run_cargo "$name" test -p fluxform-capabilities --lib || return 1
      run_cargo "$name-manifest" test -p fluxform-capabilities --test manifest || return 1
      run_cargo "$name-runner" test -p fluxform-capabilities --test runner || return 1
      ;;
    ffmpeg-profile-tests) run_cargo "$name" test -p fluxform-ffmpeg-profile --all-targets --all-features || return 1 ;;
    atomic-output) run_cargo "$name" test -p fluxform-atomic-output --all-targets --all-features || return 1 ;;
    sandbox-unit) run_cargo "$name" test -p fluxform-sandbox-probe --lib --all-features || return 1 ;;
    server-probe)
      run_cargo "$name" test -p fluxform-server-probe --all-targets --all-features || return 1
      ;;
    desktop-probe-modes)
      run_cargo "$name-transparent-orb" test -p fluxform-desktop-probe --all-targets || return 1
      run_cargo "$name-rectangular-hit-region" test -p fluxform-desktop-probe --no-default-features --features probe-transparent-window-with-rectangular-hit-region --all-targets || return 1
      run_cargo "$name-opaque-fallback" test -p fluxform-desktop-probe --no-default-features --features probe-opaque-frameless-fallback --all-targets || return 1
      ;;
    desktop-build)
      if ! command -v pnpm >/dev/null 2>&1; then echo 'SKIPPED: pnpm is unavailable; no package was installed.'; gate_status='SKIPPED'; return 0; fi
      local pnpm_version
      pnpm_version="$(pnpm --version 2>/dev/null)" || { gate_status='BLOCKED'; gate_reason='could not read the installed pnpm version.'; return 1; }
      if [[ "$pnpm_version" != '11.19.0' ]]; then echo "SKIPPED: expected pinned pnpm 11.19.0, found $pnpm_version; no package was installed."; gate_status='SKIPPED'; return 0; fi
      local python_command
      python_command="$(find_python3)" || { blocked 'a runnable Python 3 interpreter is required to make an isolated desktop source snapshot.'; return 1; }
      local source_status_before source_status_after snapshot install_failed=0 build_failed=0
      source_status_before="$(git -C "$repo_root" status --porcelain --untracked-files=all)" || { blocked 'git status could not verify source-tree cleanliness around the desktop build.'; return 1; }
      snapshot="$run_root/desktop-source"
      run_logged "$name-snapshot" "$python_command" "$script_dir/prepare_stage0_desktop_source.py" --repo-root "$repo_root" --destination "$snapshot" || return 1
      if ! run_logged "$name-pnpm-install" pnpm --dir "$snapshot/apps/desktop-probe" install --offline --frozen-lockfile; then install_failed=1; fi
      if ((install_failed == 0)); then
        if ! run_logged "$name" pnpm --dir "$snapshot/apps/desktop-probe" run tauri:build --no-bundle; then build_failed=1; fi
      fi
      if ! run_logged "$name-snapshot-cleanup" "$python_command" "$script_dir/prepare_stage0_desktop_source.py" --repo-root "$repo_root" --destination "$snapshot" --cleanup; then failed 'could not safely clean this invocation-owned desktop snapshot.'; return 1; fi
      source_status_after="$(git -C "$repo_root" status --porcelain --untracked-files=all)" || { failed 'git status could not verify source-tree cleanliness after the desktop build.'; return 1; }
      if [[ "$source_status_after" != "$source_status_before" ]]; then failed 'desktop build changed source Git status; build outputs must stay in target/stage0.'; return 1; fi
      if ((install_failed)); then blocked 'offline frozen pnpm install failed; no download was attempted.'; return 1; fi
      if ((build_failed)); then return 1; fi
      ;;
    ffmpeg-profile)
      if [[ -n "$ffmpeg_path" || -n "$ffprobe_path" ]]; then
        blocked 'direct executable path verification was retired by the Task3 hardened archive review; supplied binaries were not executed.'; return 1
      fi
      if [[ -z "$ffmpeg_archive$artifact_id$profile_path" ]]; then echo 'SKIPPED: no explicit immutable archive verifier inputs were supplied.'; gate_status='SKIPPED'; return 0; fi
      if [[ -z "$ffmpeg_archive" || -z "$artifact_id" || -z "$profile_path" ]]; then blocked 'provide --ffmpeg-archive, --artifact-id, and --profile together.'; return 1; fi
      if [[ ! -f "$ffmpeg_archive" || ! -f "$profile_path" ]]; then blocked 'archive/profile input does not exist; no dependency will be downloaded.'; return 1; fi
      local output="$run_root/ffmpeg-profile-verification.json"
      run_cargo "$name" run -p fluxform-ffmpeg-profile -- verify --profile "$profile_path" --artifact-id "$artifact_id" --archive "$ffmpeg_archive" --out "$output" || return 1
      [[ -f "$output" ]] || { blocked 'hardened verifier did not produce a report.'; return 1; }
      local python_command
      python_command="$(find_python3)" || { blocked 'a runnable Python 3 interpreter is required to inspect the verifier report.'; return 1; }
      "$python_command" - "$output" <<'PY'
import json
import sys
report = json.load(open(sys.argv[1], encoding="utf-8"))
if report.get("artifact_status") != "approved" or report.get("distribution_gate_status") != "approved":
    print("BLOCKED: verifier evidence is candidate-only or distribution approval is missing", file=sys.stderr)
    raise SystemExit(10)
PY
      local report_status=$?
      if ((report_status == 10)); then blocked 'verifier evidence is candidate-only or distribution approval is missing.'; return 1; fi
      if ((report_status != 0)); then failed 'hardened verifier report is invalid.'; return 1; fi
      ;;
    public-server-linux)
      if [[ "$(uname -s)" != 'Linux' ]]; then echo 'SKIPPED: native Linux sandbox evidence is not applicable on this host.'; gate_status='SKIPPED'; return 0; fi
      [[ "${FLUXFORM_STAGE0_LINUX_CGROUPV2_DELEGATED:-}" == '1' ]] || { blocked 'public Linux gate requires the registered native linux-cgroupv2-delegated runner.'; return 1; }
      [[ "${GITHUB_ACTIONS:-}" == 'true' && "${RUNNER_ENVIRONMENT:-}" == 'self-hosted' ]] || { blocked 'public Linux gate only accepts the registered self-hosted native runner.'; return 1; }
      [[ "$(uname -m)" == 'x86_64' ]] || { blocked "public Linux gate requires native x86_64, found $(uname -m)."; return 1; }
      local cgroup_root="${FLUXFORM_TEST_CGROUP_ROOT:-}"
      [[ -n "$cgroup_root" ]] || { blocked 'FLUXFORM_TEST_CGROUP_ROOT must name the runner delegated cgroup v2 subtree.'; return 1; }
      [[ -f "$cgroup_root/cgroup.controllers" && -f "$cgroup_root/cgroup.subtree_control" ]] || { blocked 'delegated cgroup v2 controllers are unavailable.'; return 1; }
      local controllers enabled_controllers controller
      controllers="$(<"$cgroup_root/cgroup.controllers")"
      enabled_controllers="$(<"$cgroup_root/cgroup.subtree_control")"
      for controller in cpu memory pids; do
        [[ " $controllers " == *" $controller "* && " $enabled_controllers " == *" $controller "* ]] || { blocked "delegated cgroup v2 controller '$controller' is unavailable or disabled."; return 1; }
      done
      run_cargo "$name" test -p fluxform-sandbox-probe --all-targets --all-features || return 1
      run_cargo "$name-startup-negative" test -p fluxform-server-probe --test public_startup --all-features || return 1
      run_cargo "$name-startup-positive" test -p fluxform-server-probe --test public_startup delegated_linux_process_binds_public_mode_and_serves_protected_status --all-features -- --ignored --exact || return 1
      ;;
    report)
      validate_report "$report_path" || return 1
      ;;
    ffmpeg-artifacts)
      copy_profile_evidence "$evidence_root" "$run_root/profiles" || return 1
      run_cargo "$name" run -p fluxform-capabilities --bin verify_manifest -- verify-manifest --manifest config/capabilities-v1.toml --reports "$run_root/profiles" || return 1
      ;;
    aggregate-samples)
      local collected="$evidence_root/collected"
      [[ -d "$collected" ]] || { blocked 'target/stage0/collected is missing; four native artifacts are required.'; return 1; }
      local python_command
      python_command="$(find_python3)" || { blocked 'a runnable Python 3 interpreter is required to validate native sample evidence.'; return 1; }
      local digest
      digest="$("$python_command" - "$collected" <<'PY'
import json
import os
import re
import sys
root = sys.argv[1]
expected = {"windows-x86_64", "macos-x86_64", "macos-aarch64", "linux-x86_64"}
try:
    names = {name for name in os.listdir(root) if os.path.isdir(os.path.join(root, name))}
except OSError as error:
    print(f"BLOCKED: cannot enumerate native sample evidence: {error}", file=sys.stderr)
    raise SystemExit(10)
if names != expected:
    print(f"BLOCKED: expected exactly four native targets, found {sorted(names)}", file=sys.stderr)
    raise SystemExit(10)
digests = set()
required = {"ffmpeg-profile-report.json", "provenance.json", "sample-report.json"}
for name in expected:
    directory = os.path.join(root, name)
    if set(os.listdir(directory)) != required:
        print(f"BLOCKED: {name} has missing or unexpected artifact files", file=sys.stderr)
        raise SystemExit(10)
    try:
        report = json.load(open(os.path.join(directory, "sample-report.json"), encoding="utf-8"))
    except Exception as error:
        print(f"BLOCKED: invalid sample report for {name}: {error}", file=sys.stderr)
        raise SystemExit(10)
    digest = report.get("evidence_input_digest", "")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        print(f"BLOCKED: invalid evidence-input digest for {name}", file=sys.stderr)
        raise SystemExit(10)
    digests.add(digest)
if len(digests) != 1:
    print("BLOCKED: native sample evidence has mismatched evidence-input digests", file=sys.stderr)
    raise SystemExit(10)
print(next(iter(digests)))
PY
      )"
      local digest_status=$?
      if ((digest_status != 0)); then blocked 'native sample evidence is incomplete, malformed, or stale.'; return 1; fi
      local aggregate="$run_root/aggregate-sample-report.json"
      run_cargo "$name" run -p fluxform-capabilities --bin collect_sample_reports -- --input target/stage0/collected --manifest config/capabilities-v1.toml --samples testdata/media/v1/samples.toml --expected-input-digest "$digest" --out "$aggregate" || return 1
      local profiles="$run_root/collected-profiles"
      mkdir -p -- "$profiles"
      for target in windows-x86_64 macos-x86_64 macos-aarch64 linux-x86_64; do
        cp -- "$collected/$target/ffmpeg-profile-report.json" "$profiles/$target.json" || { failed "could not stage the profile report for $target."; return 1; }
      done
      run_cargo "$name-manifest" run -p fluxform-capabilities --bin verify_manifest -- verify-manifest --manifest config/capabilities-v1.toml --reports "$profiles" || return 1
      run_cargo "$name-cross-platform" test -p fluxform-capabilities --test cross_platform_samples || return 1
      ;;
    *) failed "unknown gate selector: $name"; return 1 ;;
  esac
}

if ((${#selected_gates[@]} != $(printf '%s\n' "${selected_gates[@]}" | sort -u | wc -l))); then
  echo 'FAIL: duplicate --gate selectors are not allowed.' >&2
  exit 2
fi

failed_gate=0
for index in "${!selected_gates[@]}"; do
  name="${selected_gates[$index]}"
  if ((failed_gate)); then statuses+=("NOT_RUN"); reasons+=(""); continue; fi
  known=0
  for candidate in "${automated_defaults[@]}" "${complete_defaults[@]}"; do [[ "$candidate" == "$name" ]] && known=1; done
  if ((known == 0)); then gate_status='FAIL'; gate_reason='unknown selector'; failed_gate=1; statuses+=("FAIL"); reasons+=("$gate_reason"); echo "gate $name=FAIL (unknown selector)"; continue; fi
  echo "gate $name: running"
  if run_gate "$name"; then status="$gate_status"; else status="${gate_status:-FAIL}"; fi
  statuses+=("$status"); reasons+=("$gate_reason")
  if [[ -n "$gate_reason" ]]; then echo "gate $name=$status ($gate_reason)"; else echo "gate $name=$status"; fi
  if [[ "$status" == 'FAIL' || "$status" == 'BLOCKED' ]]; then failed_gate=1; fi
done

echo 'Stage 0 gate summary:'
for index in "${!selected_gates[@]}"; do echo "${selected_gates[$index]}=${statuses[$index]}"; done
complete=false
complete_set=0
if [[ "$mode" == 'complete' && ${#selected_gates[@]} -eq ${#complete_required[@]} ]]; then
  complete_set=1
  for index in "${!complete_required[@]}"; do
    [[ "${selected_gates[$index]}" == "${complete_required[$index]}" ]] || complete_set=0
  done
  if ((complete_set)); then
    complete=true
    for status in "${statuses[@]}"; do [[ "$status" == 'PASS' ]] || complete=false; done
  fi
fi
echo "stage0_complete=$complete"
if ((failed_gate)) || { [[ "$mode" == 'complete' && ${#selected_gates[@]} -eq ${#complete_required[@]} ]] && [[ "$complete" != true ]]; }; then exit 1; fi
exit 0
