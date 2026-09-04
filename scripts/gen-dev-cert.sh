#!/usr/bin/env bash
# Generate a self-signed certificate for local HTTPS development.
#
#   scripts/gen-dev-cert.sh                     # -> backend/data/tls/dev-{cert,key}.pem
#   scripts/gen-dev-cert.sh myhost.local        # custom CN / SAN
#
# Then:
#   ACT_SSL_ENABLED=true python -m app.main --mode service
# (ACT auto-generates this pair too if ACT_SSL_ENABLED=true and no cert is set.)
set -euo pipefail

CN="${1:-localhost}"
DIR="$(cd "$(dirname "$0")/.." && pwd)/backend/data/tls"
mkdir -p "$DIR"

openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout "$DIR/dev-key.pem" -out "$DIR/dev-cert.pem" \
    -days 825 -subj "/CN=$CN" \
    -addext "subjectAltName=DNS:$CN,DNS:localhost,IP:127.0.0.1"

chmod 600 "$DIR/dev-key.pem"
echo "wrote $DIR/dev-cert.pem and dev-key.pem (self-signed; browsers will warn)"
