#!/usr/bin/env bash
# Test 03 — S3 round-trip against MinIO (plain HTTP and TLS).
#
# Compose-fixture test, per UPGRADE_TEST_PLAN.md §4. Brings up:
#
#   minio + mc-init + filestash               (compose.yml)
#
# then drives Filestash's HTTP API end-to-end:
#
#   (a) list /test-bucket                 — expect hello.txt
#   (b) cat /hello.txt                    — body == "filestash-upgrade-canary"
#   (c) save /roundtrip.bin (64 KiB)      — 2xx, and `mc cat` against MinIO
#                                            confirms identical bytes landed
#   (d) re-list                            — both hello.txt + roundtrip.bin
#   (e) rm /roundtrip.bin                  — 2xx; subsequent list omits it
#
# The whole flow is then repeated with compose.tls.yml layered on, which
# fronts MinIO with an nginx TLS sidecar holding a self-signed cert.
# Filestash's CA store gets the fixture cert installed at boot via
# certs/filestash-tls-entrypoint.sh — that overlay is what catches Go
# stdlib changes to TLS roots / HTTP/2 / cert validation.
#
# Cost: ~60-90s warm cache (compose up dominates). Gated to the extended
# lane in run.sh, not PR-blocking.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"

TEST_DIR="$HERE/.."
HOST_PORT="${HOST_PORT:-18334}"
BASE_URL="http://127.0.0.1:${HOST_PORT}"

# Curl flag bundle: silent, fail-on-error suppressed (we want bodies on
# 4xx/5xx to surface in logs), follow no redirects (Filestash returns
# 302 for the auto-login flow but the API endpoints we drive don't).
# `--max-time 30` is generous enough for the 64 KiB upload but tight
# enough that a stuck listener fails the run rather than hanging CI.
CURL=(curl -sS --max-time 30 -H 'X-Requested-With: XmlHttpRequest')

# Compose project name keeps networks/volumes from this test isolated
# from anything else on the host. PID makes it unique across parallel
# local runs.
PROJECT="filestash-roundtrip-$$"
COMPOSE_FILES=(-f "$TEST_DIR/compose.yml")
COOKIE_JAR=""
CURRENT_VARIANT="plain"

cleanup() {
  log "tearing down compose project $PROJECT"
  # `--volumes` so the next run doesn't pick up a stale MinIO data dir.
  # `--remove-orphans` in case a previous failed run left a sidecar
  # service the current compose file doesn't reference.
  (cd "$TEST_DIR" && docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" \
      down --volumes --remove-orphans --timeout 5) >/dev/null 2>&1 || true
  if [[ -n "$COOKIE_JAR" && -f "$COOKIE_JAR" ]]; then
    rm -f "$COOKIE_JAR"
  fi
  return 0
}
trap cleanup EXIT

# Generate the TLS fixture cert if it isn't already on disk. Idempotent;
# the script no-ops if certs exist and haven't expired. Invoked via
# `bash` so the file doesn't need its exec bit set (some local clones
# can lose +x flags through patches or chmod-stripping fs mounts).
bash "$TEST_DIR/certs/make-certs.sh"

# --- helpers -----------------------------------------------------------------

# Dump diagnostic state for the current compose project. Called from each
# assertion failure so we have logs to triage from CI artifact upload.
dump_state() {
  log "--- compose ps ---"
  (cd "$TEST_DIR" && docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" ps) >&2 || true
  for svc in filestash minio nginx-tls mc-init; do
    log "--- $svc logs (tail) ---"
    (cd "$TEST_DIR" && docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" \
        logs --tail=100 "$svc") >&2 || true
  done
}

compose_up() {
  log "[$CURRENT_VARIANT] compose up"
  (cd "$TEST_DIR" && docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" \
      up -d --wait --wait-timeout 90) >&2 \
    || { dump_state; die "[$CURRENT_VARIANT] compose up failed"; }
}

wait_filestash_ready() {
  if ! wait_for_http "${BASE_URL}/about" 30; then
    dump_state
    die "[$CURRENT_VARIANT] filestash not ready on $BASE_URL within 30s"
  fi
}

# POST /api/session with full S3 credentials. The fork *also* supports a
# `_preconfigured_label` merge that pulls server-side creds out of the
# auto_login connection, but the prod Docker image is built from upstream
# `mickael-kerjean/filestash@master` (the Dockerfile's `git clone` step
# doesn't reference this fork unless GIT_REPO is overridden), so that
# code path isn't guaranteed to be in the binary under test. Sending the
# creds verbatim keeps the test compatible with both fork and upstream.
# Endpoint is templated from $S3_ENDPOINT so the TLS variant can swap in
# https://nginx-tls:9000 without forking the function.
filestash_login() {
  COOKIE_JAR=$(mktemp -t filestash-cookie.XXXXXX)
  local body endpoint="${S3_ENDPOINT:-http://minio:9000}"
  local payload
  payload=$(printf '{"type":"s3","access_key_id":"minioadmin","secret_access_key":"minioadmin","region":"us-east-1","endpoint":"%s","path":"/test-bucket"}' "$endpoint")
  body=$("${CURL[@]}" -o /dev/null -w '%{http_code}' \
    -c "$COOKIE_JAR" \
    -X POST "${BASE_URL}/api/session" \
    -H 'Content-Type: application/json' \
    -d "$payload") || body="000"
  log "[$CURRENT_VARIANT] login: HTTP $body"
  if [[ ! "$body" =~ ^2 ]]; then
    dump_state
    die "[$CURRENT_VARIANT] login failed (HTTP $body)"
  fi
  # Sanity-check the session is actually authenticated; saves a confusing
  # 401 on the first /api/files call.
  local sess
  sess=$("${CURL[@]}" -b "$COOKIE_JAR" "${BASE_URL}/api/session")
  if ! grep -Eq '"is_authenticated"[[:space:]]*:[[:space:]]*true' <<<"$sess"; then
    dump_state
    die "[$CURRENT_VARIANT] /api/session reports not authenticated: $sess"
  fi
}

# Stdout: response body. Stderr: log line. Non-2xx response -> die.
fs_get() {
  local path="$1" out code
  out=$(mktemp)
  code=$("${CURL[@]}" -b "$COOKIE_JAR" -o "$out" \
    -w '%{http_code}' "${BASE_URL}${path}") || code="000"
  if [[ ! "$code" =~ ^2 ]]; then
    log "[$CURRENT_VARIANT] GET $path -> $code"
    cat "$out" >&2 || true
    rm -f "$out"
    dump_state
    die "[$CURRENT_VARIANT] GET $path failed"
  fi
  cat "$out"
  rm -f "$out"
}

# POST raw body bytes. Args: api_path body_file content_type
fs_post_body() {
  local path="$1" body_file="$2" ctype="$3" out code
  out=$(mktemp)
  code=$("${CURL[@]}" -b "$COOKIE_JAR" -o "$out" \
    -w '%{http_code}' \
    -X POST "${BASE_URL}${path}" \
    -H "Content-Type: ${ctype}" \
    --data-binary "@${body_file}") || code="000"
  if [[ ! "$code" =~ ^2 ]]; then
    log "[$CURRENT_VARIANT] POST $path -> $code"
    cat "$out" >&2 || true
    rm -f "$out"
    dump_state
    die "[$CURRENT_VARIANT] POST $path failed"
  fi
  rm -f "$out"
}

# Run `mc` against the live MinIO via a one-shot container on the project
# network. Used for the end-to-end byte-for-byte check on (c).
mc_exec() {
  docker run --rm --network "${PROJECT}_s3net" \
    --entrypoint /bin/sh \
    minio/mc:RELEASE.2024-10-08T09-37-26Z -c \
    "mc alias set local http://minio:9000 minioadmin minioadmin >/dev/null && $*"
}

# --- the actual test --------------------------------------------------------

run_variant() {
  CURRENT_VARIANT="$1"
  shift
  COMPOSE_FILES=("$@")

  compose_up
  wait_filestash_ready
  filestash_login

  # (a) list /test-bucket. Filestash joins session path (/test-bucket/)
  # with the `path` query, so ?path=/ lists the bucket root.
  local ls_json
  ls_json=$(fs_get '/api/files/ls?path=/')
  if ! grep -Eq '"name"[[:space:]]*:[[:space:]]*"hello\.txt"' <<<"$ls_json"; then
    log "[$CURRENT_VARIANT] ls payload: $ls_json"
    dump_state
    die "[$CURRENT_VARIANT] (a) hello.txt missing from initial listing"
  fi
  log "[$CURRENT_VARIANT] (a) ls OK"

  # (b) cat hello.txt. The cat endpoint streams raw object bytes, so a
  # direct equality check is meaningful.
  local cat_body
  cat_body=$(fs_get '/api/files/cat?path=/hello.txt')
  if [[ "$cat_body" != "filestash-upgrade-canary" ]]; then
    log "[$CURRENT_VARIANT] cat got: '$cat_body'"
    dump_state
    die "[$CURRENT_VARIANT] (b) hello.txt body mismatch"
  fi
  log "[$CURRENT_VARIANT] (b) cat OK"

  # (c) Upload a deterministic 64 KiB blob. Deterministic = the same
  # bytes every run; lets us byte-compare via `mc cat` afterwards. We
  # use /dev/zero so the contents have no entropy and any partial-upload
  # bug shows up as a length mismatch rather than a hash mismatch buried
  # in MIME-sniffing noise.
  local blob
  blob=$(mktemp -t roundtrip.XXXXXX.bin)
  dd if=/dev/zero of="$blob" bs=1024 count=64 status=none
  fs_post_body '/api/files/cat?path=/roundtrip.bin' "$blob" 'application/octet-stream'

  # End-to-end verification: pull the object back through MinIO directly
  # (not via Filestash) and compare bytes. This is what makes (c) a real
  # round-trip and not just a "Filestash returned 200" assertion.
  #
  # We use two independent checks so a single missing tool in busybox/mc
  # can't silently let a bad upload through:
  #   1. Byte-identical via `mc cat | cmp` against the original blob.
  #   2. Server-reported size via `mc stat`.
  # md5sum was the previous approach; busybox in some minio/mc tags ships
  # without it, and an empty stdout silently compares equal-to-empty.
  local expected_size mc_size
  expected_size=$(wc -c <"$blob")
  if ! mc_exec "mc cat local/test-bucket/roundtrip.bin" \
      | cmp -s - "$blob"; then
    rm -f "$blob"
    dump_state
    die "[$CURRENT_VARIANT] (c) round-trip bytes differ (cmp failed)"
  fi
  mc_size=$(mc_exec "mc stat --json local/test-bucket/roundtrip.bin" \
    | jq -r '.size // empty')
  rm -f "$blob"
  if [[ "$mc_size" != "$expected_size" ]]; then
    dump_state
    die "[$CURRENT_VARIANT] (c) size mismatch: minio=$mc_size expected=$expected_size"
  fi
  log "[$CURRENT_VARIANT] (c) upload OK (${mc_size} bytes, byte-identical)"

  # (d) Re-list. Both objects must be present.
  ls_json=$(fs_get '/api/files/ls?path=/')
  if ! grep -Eq '"name"[[:space:]]*:[[:space:]]*"roundtrip\.bin"' <<<"$ls_json"; then
    log "[$CURRENT_VARIANT] re-ls: $ls_json"
    dump_state
    die "[$CURRENT_VARIANT] (d) roundtrip.bin missing from listing after upload"
  fi
  if ! grep -Eq '"name"[[:space:]]*:[[:space:]]*"hello\.txt"' <<<"$ls_json"; then
    dump_state
    die "[$CURRENT_VARIANT] (d) hello.txt vanished between listings"
  fi
  log "[$CURRENT_VARIANT] (d) re-ls OK"

  # (e) Delete roundtrip.bin. FileRm takes path via query string and
  # ignores the body, but we send an empty JSON object so any future
  # BodyParser middleware change doesn't break us silently.
  local rm_code
  rm_code=$("${CURL[@]}" -b "$COOKIE_JAR" -o /dev/null -w '%{http_code}' \
    -X POST "${BASE_URL}/api/files/rm?path=/roundtrip.bin" \
    -H 'Content-Type: application/json' -d '{}')
  if [[ ! "$rm_code" =~ ^2 ]]; then
    dump_state
    die "[$CURRENT_VARIANT] (e) rm returned HTTP $rm_code"
  fi
  ls_json=$(fs_get '/api/files/ls?path=/')
  if grep -Eq '"name"[[:space:]]*:[[:space:]]*"roundtrip\.bin"' <<<"$ls_json"; then
    log "[$CURRENT_VARIANT] post-rm ls: $ls_json"
    dump_state
    die "[$CURRENT_VARIANT] (e) roundtrip.bin still listed after rm"
  fi
  # Independent server-side check: confirm the object is *actually gone*
  # from MinIO, not just hidden by a stale Filestash listing cache. `mc
  # stat` exits non-zero on a missing object.
  if mc_exec "mc stat local/test-bucket/roundtrip.bin" >/dev/null 2>&1; then
    dump_state
    die "[$CURRENT_VARIANT] (e) roundtrip.bin still present in MinIO after rm"
  fi
  log "[$CURRENT_VARIANT] (e) rm OK (gone from MinIO too)"

  # Per-variant teardown. The trap cleans up whatever variant was last
  # active, but if we're proceeding to the next variant we want a clean
  # slate now (different config mount, different sidecar set).
  log "[$CURRENT_VARIANT] tearing down between variants"
  (cd "$TEST_DIR" && docker compose -p "$PROJECT" "${COMPOSE_FILES[@]}" \
      down --volumes --remove-orphans --timeout 5) >/dev/null 2>&1 || true
  rm -f "$COOKIE_JAR"
  COOKIE_JAR=""
}

S3_ENDPOINT="http://minio:9000"     run_variant plain -f "$TEST_DIR/compose.yml"
S3_ENDPOINT="https://nginx-tls:9000" run_variant tls   -f "$TEST_DIR/compose.yml" -f "$TEST_DIR/compose.tls.yml"

log "03_s3_roundtrip: OK"
