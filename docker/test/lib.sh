# Shared helpers for docker/test scripts. Source from a test, do not exec.
# All output goes to stderr so test scripts can use stdout for return values.

set -u

: "${IMAGE_TAG:=filestash-test:local}"
: "${FORK_SHA:=$(git rev-parse HEAD 2>/dev/null || echo unknown)}"
: "${CONTAINER_PREFIX:=filestash-test}"

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "FAIL: $*"; exit 1; }

repo_root() { git rev-parse --show-toplevel; }

build_image() {
  local sha="${1:-$FORK_SHA}"
  log "building $IMAGE_TAG (FORK_SHA=$sha)"
  docker build \
    --build-arg "FORK_SHA=${sha}" \
    -t "$IMAGE_TAG" \
    -f "$(repo_root)/docker/Dockerfile" \
    "$(repo_root)" >&2
}

# Start a detached filestash container with the given config file mounted.
# Prints the container name on stdout.
run_with_config() {
  local config_path="$1"
  local name="${CONTAINER_PREFIX}-$$-$RANDOM"
  local host_port="${HOST_PORT:-18334}"
  [[ -r "$config_path" ]] || die "config not readable: $config_path"
  # Intentionally no --rm: if the container crashes during boot we need
  # to read its logs from stop_container's cleanup path to surface the
  # missing-library output that caused the crash.
  docker run -d \
    --name "$name" \
    -p "${host_port}:8334" \
    -v "${config_path}:/app/data/state/config/config.json:ro" \
    "$IMAGE_TAG" >/dev/null \
    || die "docker run failed"
  echo "$name"
}

stop_container() {
  local name="$1"
  [[ -n "$name" ]] || return 0
  docker rm -f "$name" >/dev/null 2>&1 || true
}

# Poll an HTTP endpoint until it returns a 2xx/3xx status, or the deadline expires.
# Usage: wait_for_http <url> <timeout_seconds>
wait_for_http() {
  local url="$1" timeout="${2:-30}"
  local deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    local code
    code=$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$url" || echo 000)
    if [[ "$code" =~ ^[23] ]]; then
      log "wait_for_http: $url -> $code"
      return 0
    fi
    sleep 1
  done
  return 1
}

# Patterns that indicate the runtime is missing a shared library the binary
# needs. Patterns are taken from the exact strings emitted by glibc's
# dynamic linker (ld.so) so they don't false-positive on app-level log lines
# that contain words like "undefined symbol" in unrelated contexts.
MISSING_LIB_REGEX='cannot open shared object file|error while loading shared libraries|symbol lookup error: .*: undefined symbol:'

assert_no_missing_libs() {
  local logs="$1"
  if grep -E -q "$MISSING_LIB_REGEX" <<<"$logs"; then
    log "missing-library lines found in logs:"
    grep -E "$MISSING_LIB_REGEX" <<<"$logs" >&2
    return 1
  fi
}
