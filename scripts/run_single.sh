#!/usr/bin/env bash
set -euo pipefail
PCAP="${1:?Usage: $0 <file.pcap|pcapng>}"
OUTDIR="${OUTDIR:-pcap_out}"
REPORTS="${REPORTS:-reports}"
DB="${DB:-pcap_out/pcaps.sqlite}"
PROFILE="${PROFILE:-noc}"
DEEP="${DEEP:-true}"
CSV="${CSV:-true}"
JA4="${JA4:-false}"
CIR="${CIR_MBPS:-}"

python pcap_autoparser_pro.py "$PCAP" \
  --profile "$PROFILE" \
  ${DEEP:+--deep} \
  ${JA4:+--ja4} \
  ${CSV:+--csv} \
  ${CIR:+--cir-mbps "$CIR"} \
  --db "$DB" \
  --outdir "$OUTDIR"

mkdir -p "$REPORTS"
# Move HTML/CSVs to reports for convenience
find "$OUTDIR" -maxdepth 1 -name "$(basename "$PCAP").*.csv" -exec mv {} "$REPORTS" \;
find "$OUTDIR" -maxdepth 1 -name "$(basename "$PCAP").html" -exec mv {} "$REPORTS" \;
echo "Reports in $REPORTS"
