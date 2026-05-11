#!/bin/sh
# Entrypoint shim used only by compose.tls.yml.
#
# Why this exists: in the TLS overlay the upstream MinIO endpoint is
# wrapped by an nginx sidecar presenting a self-signed cert. The Go
# stdlib (and via it, the AWS SDK v1 the Filestash S3 backend uses)
# loads CAs from the system trust store at process start. We therefore
# need our fixture CA in /etc/ssl/certs before the filestash binary
# starts.
#
# Approach: run as root (override `user:` in the overlay), drop the
# cert into the Debian per-machine trust dir, refresh
# /etc/ssl/certs/ca-certificates.crt with `update-ca-certificates`,
# then exec the binary still as root. Running the SUT as root is fine
# for a self-contained test fixture — production deployments inherit
# the image's `USER filestash` default.

set -e

CERT_SRC="/fixture/nginx-tls.crt"
# Fail loudly if the fixture cert isn't mounted or update-ca-certificates
# errors — silently continuing would mean Filestash dials the TLS endpoint
# with no fixture CA in trust, the dial fails for the *wrong* reason, and
# the diagnostic is much harder to read.
[ -r "$CERT_SRC" ] || { echo "fixture cert not readable: $CERT_SRC" >&2; exit 1; }
cp "$CERT_SRC" /usr/local/share/ca-certificates/nginx-tls.crt
update-ca-certificates >/dev/null

exec /app/filestash
