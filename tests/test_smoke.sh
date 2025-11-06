#!/usr/bin/env bash
set -euo pipefail
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python pcap_autoparser_pro.py tests/samples/sample.pcap --profile noc --deep --csv
test -f pcap_out/pcaps.sqlite
echo "Smoke OK"
