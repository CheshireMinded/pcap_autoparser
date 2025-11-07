PCAP Analysis Summary
---------------------

This program automatically processes packet capture (PCAP) files to identify network communication patterns, highlight unusual behavior, and flag traffic that may indicate security concerns. It performs both high-level statistical analysis and heuristic-based detections.

1. Protocol Breakdown
   The program begins by classifying all packets by protocol (e.g., TCP, UDP, ICMP). This provides a macro-level view of the capture and helps determine whether the traffic is expected (e.g., normal TCP flows) or potentially suspicious (e.g., excessive UDP or ICMP activity).

2. Flow Analysis
   It then identifies the "Top Talkers" by grouping packets into flows based on:
      - Source IP
      - Destination IP
      - Port
      - Protocol

   This allows quick visibility into which hosts communicated the most and what services/ports were involved. High-volume flows often indicate file transfers, remote sessions, port scanning, tunneling, or beaconing activity.

3. Detection Engine (Heuristics)
   The program applies a series of heuristic rules to flag indicators of potentially risky or abnormal traffic. Examples of detections include:
      - Sensitive or high-risk service ports in use (e.g., SMB/445, RDP/3389)
      - Unusual high-numbered source or destination ports
      - Repeated connection patterns that resemble command-and-control beacons
      - Possible MTU fragmentation or black-hole conditions based on retransmissions
      - Traffic linked to privilege escalation or lateral movement (e.g., SMB admin operations)

   These detections appear under the "Detections" section and include both plain-language descriptions and contextual packet details.

4. Example Findings from the Provided PCAPs
   - **SMB traffic to TCP port 445** was repeatedly detected, which is commonly associated with Windows file sharing, lateral movement, or exploitation activity (e.g., Mimikatz post-exploitation or ZeroLogon-style access).
   - **High-port UDP traffic** and inconsistent service negotiation were observed in another capture, consistent with WAN acceleration issues or malformed session handshakes.
   - **RDP tunneling traffic** showed signs of possible MTU misconfiguration (large packets not being acknowledged and no ICMP Fragmentation Needed response), suggesting an MTU black-hole condition.
   - **Beacon-like TCP patterns** were detected in some flows, indicating possible periodic check-in behavior commonly associated with remote agent tooling or malware command-and-control channels.

5. Use Cases
   This tool is suitable for:
      - Incident Response Triage
      - Malware Traffic Analysis
      - Internal Network Investigations
      - PCAP Review for Security Exercises & Labs
      - Troubleshooting Broken Services (SMB, RDP, HTTPS, etc.)

6. Output Presentation
   Results are cleanly displayed in structured sections (Protocol breakdowns, top flows, and detections). Output may also include color-coding for readability (e.g., ports in blue, alerts in yellow, critical detections in red).

Summary
-------
The program provides an automated and repeatable workflow for analyzing network captures. It reduces the manual effort normally required when inspecting PCAPs in Wireshark by extracting key network behaviors and highlighting suspicious or abnormal activity, allowing faster and more informed investigation decisions.
