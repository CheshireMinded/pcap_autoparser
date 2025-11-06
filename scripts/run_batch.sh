#!/usr/bin/env bash
set -euo pipefail
DIR="${1:?Usage: $0 <dir-with-pcaps>}"
OUTDIR="${OUTDIR:-pcap_out}"
DB="${DB:-pcap_out/pcaps.sqlite}"
python pcap_autoparser_pro.py "$DIR" --profile noc --deep --csv --processes 4 --db "$DB" --outdir "$OUTDIR"
