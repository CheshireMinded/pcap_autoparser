# Sample PCAP Files

This directory contains sample PCAP files for testing and demonstration purposes.

## Files

### investigating.pcap
- **Source**: [Pranav-ai-cyber/network-security-basics](https://github.com/Pranav-ai-cyber/network-security-basics/blob/main/network-security-basics/investigating.pcap)
- **Description**: Sample network traffic capture containing mixed IPv4/IPv6 traffic, DNS queries, HTTPS connections, and various protocols
- **Useful for**: Testing detection capabilities including sensitive ports, beaconing, and volume analysis
- **Analysis**: Run with `python3 pcap_autoparser_pro.py samples/investigating.pcap --profile noc --deep --csv`

### CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng
- **Source**: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
- **Description**: SMBGhost (CVE-2020-0796) vulnerability exploitation traffic captured on loopback interface
- **Contains**: SMB traffic on port 445 between 127.0.0.1:49955 and 127.0.0.1:445
- **Useful for**: Testing SMB traffic detection, sensitive port detection, and loopback traffic parsing (Linux cooked capture/SLL)
- **Analysis**: Run with `python3 pcap_autoparser_pro.py samples/CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng --profile noc --deep --csv`

### rdp_tunneling_meterpreter_portfwd.pcapng
- **Source**: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
- **Description**: RDP tunneling with Meterpreter port forwarding - demonstrates lateral movement and command & control traffic
- **Contains**: Meterpreter reverse shell traffic on port 4444 between 10.0.2.15:4444 and 10.0.2.16:49682 (1,221 TCP packets, 4.9 MB)
- **Useful for**: Testing C2 traffic detection, Meterpreter port detection (4444), and large volume traffic analysis
- **Analysis**: Run with `python3 pcap_autoparser_pro.py samples/rdp_tunneling_meterpreter_portfwd.pcapng --profile noc --deep --csv`

### Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng
- **Source**: [sbousseaden/PCAP-ATTACK](https://github.com/sbousseaden/PCAP-ATTACK)
- **Description**: Post-ZeroLogon (CVE-2020-1472) attack with Mimikatz password reset via RPC - demonstrates credential access and privilege escalation
- **Contains**: SMB/RPC traffic on port 445 between 172.16.66.37:50037 and 172.16.66.36:445 (67 TCP packets, 16.2 KB)
- **Useful for**: Testing SMB/RPC detection, ZeroLogon attack patterns, and credential access detection
- **Analysis**: Run with `python3 pcap_autoparser_pro.py samples/Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng --profile noc --deep --csv`

## Adding New Samples

When adding new sample PCAP files:
1. Place the `.pcap` or `.pcapng` file in this directory
2. Add source information to `pcap_autoparser_pro.py` in the `KNOWN_SAMPLE_SOURCES` dictionary
3. Update this README with file description and source
