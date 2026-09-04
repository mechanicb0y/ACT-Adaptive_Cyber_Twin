#!/usr/bin/env bash
# Obtain / renew a Let's Encrypt certificate for ACT with certbot.
#
#   sudo scripts/letsencrypt.sh act.example.com you@example.com
#
# Uses certbot's standalone HTTP-01 challenge, so port 80 must be free while it
# runs (this script stops `act` if ACT is bound to :80, then restarts it).
# After first issue, add a renewal timer:
#   sudo systemctl enable --now certbot.timer      # Debian/Ubuntu package
# certbot's deploy hook below restarts ACT when the cert is renewed.
set -euo pipefail

DOMAIN="${1:?usage: letsencrypt.sh <domain> <email>}"
EMAIL="${2:?usage: letsencrypt.sh <domain> <email>}"

if ! command -v certbot >/dev/null 2>&1; then
    echo "certbot not found. Install it:  apt install certbot   /   dnf install certbot" >&2
    exit 1
fi

STOPPED=0
if systemctl is-active --quiet act 2>/dev/null; then
    echo "stopping act for the standalone challenge ..."
    systemctl stop act
    STOPPED=1
fi
restart_act() { [ "$STOPPED" = 1 ] && systemctl start act || true; }
trap restart_act EXIT

certbot certonly \
    --standalone \
    --non-interactive --agree-tos \
    --email "$EMAIL" \
    -d "$DOMAIN" \
    --deploy-hook "systemctl try-restart act"

echo
echo "certificate ready:"
echo "  ACT_SSL_CERT=/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
echo "  ACT_SSL_KEY=/etc/letsencrypt/live/$DOMAIN/privkey.pem"
echo "Set ACT_SSL_ENABLED=true and those paths (see systemd/act-https.conf), then restart act."
