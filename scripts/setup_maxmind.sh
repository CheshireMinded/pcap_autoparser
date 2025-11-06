#!/usr/bin/env bash
set -euo pipefail
# You need a MaxMind license key from https://www.maxmind.com/
KEY="${MAXMIND_LICENSE_KEY:?Set MAXMIND_LICENSE_KEY env var}"
DEST="data/mmdb"
mkdir -p "$DEST"
curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$KEY&suffix=tar.gz" | tar -xz --strip-components=1 -C "$DEST"
curl -L "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=$KEY&suffix=tar.gz" | tar -xz --strip-components=1 -C "$DEST"
echo "MMDBs in $DEST"
