# PCAP Triage

Triage → Enrich → Detect → Deep Scan → Store → Report.

## Quickstart
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo apt-get install -y tshark   # optional deep scan
cp config/.env.example .env      # optional
./scripts/run_single.sh tests/samples/sample.pcap
```

## Sample PCAP Files

The `samples/` directory contains sample PCAP files for testing:

- **`samples/investigating.pcap`**: Sample network traffic capture
  - Source: [Pranav-ai-cyber/network-security-basics](https://github.com/Pranav-ai-cyber/network-security-basics/blob/main/network-security-basics/investigating.pcap)
  - Contains mixed IPv4/IPv6 traffic, DNS queries, HTTPS connections, and various protocols
  - Useful for testing detection capabilities including sensitive ports, beaconing, and volume analysis

- **`samples/CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng`**: SMBGhost vulnerability traffic
  - Source: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
  - Contains SMB traffic on port 445 (CVE-2020-0796 exploitation)
  - Useful for testing SMB detection, sensitive port detection, and loopback traffic parsing

- **`samples/rdp_tunneling_meterpreter_portfwd.pcapng`**: RDP tunneling with Meterpreter
  - Source: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
  - Contains Meterpreter C2 traffic on port 4444 (1,221 packets, 4.9 MB)
  - Useful for testing command & control detection and lateral movement traffic

- **`samples/Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng`**: ZeroLogon with Mimikatz
  - Source: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
  - Contains SMB/RPC traffic on port 445 (67 packets, 16.2 KB)
  - Useful for testing ZeroLogon attack detection and credential access patterns

To analyze the samples:
```bash
python3 pcap_autoparser_pro.py samples/investigating.pcap --profile noc --deep --csv
python3 pcap_autoparser_pro.py samples/CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng --profile noc --deep --csv
python3 pcap_autoparser_pro.py samples/rdp_tunneling_meterpreter_portfwd.pcapng --profile noc --deep --csv
python3 pcap_autoparser_pro.py samples/Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng --profile noc --deep --csv
```
