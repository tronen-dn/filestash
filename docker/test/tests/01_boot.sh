#!/usr/bin/env bash
# Test 01 — Boot + shared-libs.
#
# Boots the image with a documented-schema config.json mounted in. Asserts:
#   1. an HTTP endpoint on 8334 responds 2xx/3xx within 30s;
#   2. container is still running at the end of the check window;
#   3. no glibc dynamic-linker missing-library lines in the logs.
#
# Cost: image build is amortized; this test itself is sub-30s.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

CFG="$HERE/../config/boot.json"
HOST_PORT="${HOST_PORT:-18334}"

cleanup() {
  if [[ -n "${CID:-}" ]]; then
    log "tearing down $CID"
    docker logs "$CID" >"$LOGFILE" 2>&1 || true
    stop_container "$CID"
  fi
}
LOGFILE=$(mktemp -t filestash-boot.XXXXXX.log)
CID=""
trap cleanup EXIT

CID=$(HOST_PORT="$HOST_PORT" run_with_config "$CFG")
log "container=$CID port=$HOST_PORT"

# Share one 30-second deadline across both probe paths. /about is the
# preferred endpoint (cheap, version-stable); / is the fallback because
# some Filestash builds 302 the root before /about is registered. Either
# response (2xx/3xx) is success — we only care the server is alive on
# the port. Liveness is re-checked at the end of the window so a
# crash-after-bind is still caught.
deadline=$(( $(date +%s) + 30 ))
ready=0
while (( $(date +%s) < deadline )); do
  if ! state=$(docker inspect -f '{{.State.Running}}' "$CID" 2>/dev/null); then
    break
  fi
  [[ "$state" == "true" ]] || break
  for path in /about /; do
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 \
      "http://127.0.0.1:${HOST_PORT}${path}" || echo 000)
    if [[ "$code" =~ ^[23] ]]; then
      log "ready: ${path} -> ${code}"
      ready=1
      break 2
    fi
  done
  sleep 1
done

if (( ready != 1 )); then
  log "container state at failure:"
  docker inspect -f '{{json .State}}' "$CID" >&2 || true
  log "container logs (may be empty if exec failed early):"
  docker logs "$CID" >&2 || true
  die "no 2xx/3xx on :${HOST_PORT} within 30s"
fi

# Re-check liveness *after* the wait — catches a process that 200s once
# then crashes during late init.
state=$(docker inspect -f '{{.State.Running}}' "$CID")
if [[ "$state" != "true" ]]; then
  log "container exited after first 2xx — late-init crash. logs:"
  docker logs "$CID" >&2 || true
  die "container exited (Running=$state)"
fi

# Capture logs *now*, while still running, then run the linker-pattern check.
docker logs "$CID" >"$LOGFILE" 2>&1 || true
if ! assert_no_missing_libs "$(cat "$LOGFILE")"; then
  die "missing-library pattern in container logs"
fi

# Provenance: label is whatever FORK_SHA was passed at build time. Test
# that the label *exists and is non-empty* — the workflow asserts equality
# against $GITHUB_SHA. Locally we just check the label propagated.
label=$(docker inspect --format='{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$IMAGE_TAG")
[[ -n "$label" && "$label" != "unknown" ]] || die "image is missing org.opencontainers.image.revision label (got: '$label')"
log "provenance label: $label"

log "01_boot: OK"
