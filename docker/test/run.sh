#!/usr/bin/env bash
# Orchestrate the Filestash image test suite.
#
# Usage:
#   docker/test/run.sh                # default: fast lane (build + 01 + 02)
#   docker/test/run.sh fast           # same as above
#   docker/test/run.sh extended       # fast + 03 (S3 round-trip)
#   docker/test/run.sh build          # build the image only
#   docker/test/run.sh test 01_boot   # run a single named test
#
# All tests assume a usable local Docker daemon.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"

lane="${1:-fast}"

run_test() {
  local name="$1"
  local script="$HERE/tests/${name}.sh"
  [[ -r "$script" ]] || die "no such test: $name (expected $script)"
  log "=== test: $name ==="
  bash "$script"
  log "=== pass: $name ==="
}

case "$lane" in
  build)
    build_image
    ;;
  fast)
    build_image
    run_test 01_boot
    run_test 02_config_contract
    ;;
  extended)
    build_image
    run_test 01_boot
    run_test 02_config_contract
    run_test 03_s3_roundtrip
    ;;
  test)
    name="${2:-}"
    [[ -n "$name" ]] || die "usage: run.sh test <name>"
    run_test "$name"
    ;;
  *)
    die "unknown lane: $lane (fast|extended|build|test)"
    ;;
esac
