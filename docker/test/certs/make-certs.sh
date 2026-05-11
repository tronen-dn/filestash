#!/usr/bin/env bash
# Generate a self-signed cert + key for the nginx TLS sidecar.
#
# Idempotent: if `nginx-tls.crt` and `nginx-tls.key` already exist *and* the
# cert is still within its validity window, this is a no-op. Otherwise both
# are regenerated.
#
# SANs include `nginx-tls` (the compose service name Filestash dials),
# `minio` (in case anything probes it via that name), and `localhost` /
# `127.0.0.1` for ad-hoc curl from the host.
#
# Requires `openssl`. ubuntu-latest in GHA ships with it; locally any recent
# Debian/macOS has it. Cert is committed under docker/test/certs/ so CI
# doesn't need openssl, but re-running this script lets contributors refresh
# an expired fixture without hand-rolling args.

set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRT="$HERE/nginx-tls.crt"
KEY="$HERE/nginx-tls.key"

if [[ -s "$CRT" && -s "$KEY" ]]; then
  # `openssl x509 -checkend 0` exits 0 if still valid, 1 if expired.
  if openssl x509 -in "$CRT" -checkend 0 -noout >/dev/null 2>&1; then
    exit 0
  fi
fi

openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout "$KEY" -out "$CRT" \
  -subj "/CN=nginx-tls" \
  -addext "subjectAltName=DNS:nginx-tls,DNS:minio,DNS:localhost,IP:127.0.0.1" \
  >/dev/null 2>&1
chmod 644 "$CRT" "$KEY"
