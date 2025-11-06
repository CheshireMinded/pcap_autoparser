#!/usr/bin/env python3
# pcap_autoparser_pro.py
# Triage → Enrich → Store → Scale (with NOC-style detectors + HTML report)

import argparse, os, socket, json, subprocess, html, csv
from pathlib import Path
from collections import Counter, defaultdict, deque
from statistics import pstdev
from shutil import which
from math import ceil
import sqlite3
import dpkt
import logging

# -------- Third-party optional enrichers --------
try:
    import geoip2.database
    GEOIP_OK = True
except Exception:
    GEOIP_OK = False

# -------- Console colorizer --------
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
console = Console()

# -------- Logging --------
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ===================== CONFIG =====================
SENSITIVE_PORTS = {22,23,25,53,80,110,111,135,139,143,389,445,465,587,993,995,1433,1521,2049,2375,27017,3306,3389,5432,5900,6379,8080,9200}
RARE_HIGHPORT = 60000
SCAN_PORT_THRESHOLD = 20
SCAN_HOST_THRESHOLD = 20
BEACON_MIN_PKTS = 8
BEACON_JITTER_MAX = 0.15
DNS_LONG_LABEL = 40
DNS_NXDOMAIN_RATE = 0.5
ICMP_FLOOD_PPS = 500
TOP_N_FLOWS = 15
MICROBURST_BUCKET_MS = 10
VOLUME_SPIKE_BYTES = 50_000_000  # 50MB per source per pcap

CAT_COLOR = {
    "PORT": "blue",
    "SCAN": "red",
    "DNS": "yellow",
    "TLS": "magenta",
    "ICMP": "cyan",
    "VOLUME": "bright_green",
    "BEACON": "white",
    "OTHER": "white",
}

# ===================== Service-name map (ALL ports) =====================
_SVC_MAP = {}
def _load_services():
    global _SVC_MAP
    try:
        with open("/etc/services","r",encoding="utf-8",errors="ignore") as f:
            for line in f:
                line=line.strip()
                if not line or line.startswith("#"): continue
                parts=line.split()
                if len(parts)<2: continue
                name=parts[0]
                num_proto=parts[1]
                if "/" in num_proto:
                    num, proto = num_proto.split("/",1)
                    try:
                        p = int(num)
                        _SVC_MAP[(p, proto.lower())] = name
                    except: pass
    except Exception:
        pass
def port_name(port:int, proto:str)->str:
    proto = (proto or "").lower()
    if (port, proto) in _SVC_MAP:
        return _SVC_MAP[(port, proto)]
    try:
        return socket.getservbyport(port, proto)
    except Exception:
        return ""
_load_services()

# ===================== GeoIP / ASN =====================
class Geo:
    def __init__(self, city_db=None, asn_db=None):
        self.city_reader = None
        self.asn_reader = None
        if GEOIP_OK and city_db and Path(city_db).exists():
            self.city_reader = geoip2.database.Reader(city_db)
        if GEOIP_OK and asn_db and Path(asn_db).exists():
            self.asn_reader = geoip2.database.Reader(asn_db)
    def lookup(self, ip):
        res = {"country":"","city":"","asn":"","org":""}
        if self.city_reader:
            try:
                r = self.city_reader.city(ip)
                res["country"] = (r.country.iso_code or "") or ""
                res["city"] = (r.city.name or "") or ""
            except Exception:
                pass
        if self.asn_reader:
            try:
                a = self.asn_reader.asn(ip)
                res["asn"] = f"AS{a.autonomous_system_number}" if a.autonomous_system_number else ""
                res["org"] = a.autonomous_system_organization or ""
            except Exception:
                pass
        return res

# ===================== SQLite =====================
DDL = """
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=30000;
CREATE TABLE IF NOT EXISTS packets(
  id INTEGER PRIMARY KEY,
  pcap TEXT,
  ts REAL,
  src TEXT, sport INTEGER,
  dst TEXT, dport INTEGER,
  proto TEXT,
  len_bytes INTEGER,
  tcp_flags TEXT,
  service TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(src, sport, dst, dport, proto);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);

CREATE TABLE IF NOT EXISTS enrich_ip(
  ip TEXT PRIMARY KEY,
  country TEXT,
  city TEXT,
  asn TEXT,
  org TEXT
);

CREATE TABLE IF NOT EXISTS detections(
  id INTEGER PRIMARY KEY,
  pcap TEXT,
  category TEXT,
  message TEXT,
  context_json TEXT
);

CREATE TABLE IF NOT EXISTS tls_artifacts(
  id INTEGER PRIMARY KEY,
  pcap TEXT,
  filter TEXT,
  json TEXT
);
"""
def db_connect(path):
    """Connect to SQLite database with proper settings for concurrency"""
    try:
        # Ensure parent directory exists
        db_path = Path(path)
        db_path.parent.mkdir(parents=True, exist_ok=True)
        
        conn = sqlite3.connect(str(db_path), timeout=30.0)
        conn.execute("PRAGMA foreign_keys=ON;")
        # Parse DDL more carefully
        statements = [s.strip() for s in DDL.strip().split(";") if s.strip()]
        for stmt in statements:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError as e:
                # Ignore "table already exists" errors
                if "already exists" not in str(e).lower():
                    logger.warning(f"DDL statement failed: {e}")
        conn.commit()
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to database {path}: {e}")
        raise
def db_insert_packets(conn, rows, batch_size=10000):
    """Insert packets in batches to avoid memory issues"""
    if not rows:
        return
    try:
        # Insert in batches
        for i in range(0, len(rows), batch_size):
            batch = rows[i:i+batch_size]
            conn.executemany("""INSERT INTO packets
              (pcap, ts, src, sport, dst, dport, proto, len_bytes, tcp_flags, service)
              VALUES (?,?,?,?,?,?,?,?,?,?)""", batch)
            conn.commit()
        logger.debug(f"Inserted {len(rows)} packets in batches")
    except sqlite3.OperationalError as e:
        logger.error(f"Database error inserting packets: {e}")
        conn.rollback()
        raise
    except Exception as e:
        logger.error(f"Unexpected error inserting packets: {e}")
        conn.rollback()
        raise
def db_upsert_enrich(conn, ip, e):
    conn.execute("""INSERT INTO enrich_ip(ip,country,city,asn,org)
        VALUES(?,?,?,?,?)
        ON CONFLICT(ip) DO UPDATE SET
          country=excluded.country,
          city=excluded.city,
          asn=excluded.asn,
          org=excluded.org
    """, (ip, e["country"], e["city"], e["asn"], e["org"]))
def db_insert_detection(conn, pcap, cat, msg, ctx):
    conn.execute("""INSERT INTO detections(pcap, category, message, context_json)
                    VALUES(?,?,?,?)""", (pcap, cat, msg, json.dumps(ctx)))
def db_insert_tls_artifacts(conn, pcap, filt, js):
    conn.execute("""INSERT INTO tls_artifacts(pcap, filter, json)
                    VALUES(?,?,?)""", (pcap, filt, json.dumps(js)))

# ===================== Helpers =====================
def inet_to_str(addr):
    try:
        if isinstance(addr, (bytes, bytearray)):
            return socket.inet_ntop(socket.AF_INET, addr) if len(addr)==4 else socket.inet_ntop(socket.AF_INET6, addr)
        return ""
    except Exception:
        return ""

# --- TCP option parsing (MSS, WScale, SACK Perm) ---
def parse_tcp_options(optbytes: bytes):
    opts = {"mss": None, "wscale": None, "sack_perm": False}
    i = 0
    while i < len(optbytes):
        kind = optbytes[i]
        if kind == 0:  # EOL
            break
        if kind == 1:  # NOP
            i += 1
            continue
        if i+1 >= len(optbytes):
            break
        length = optbytes[i+1]
        if length < 2 or i+length > len(optbytes):
            break
        data = optbytes[i+2:i+length]
        if kind == 2 and len(data) == 2:
            opts["mss"] = int.from_bytes(data, "big")
        elif kind == 3 and len(data) == 1:
            opts["wscale"] = data[0]
        elif kind == 4:
            opts["sack_perm"] = True
        i += length
    return opts

# ===================== Heuristics & State =====================
# State is now function-local to avoid multiprocessing issues
class AnalysisState:
    """Encapsulates all analysis state to avoid global variable issues in multiprocessing"""
    def __init__(self):
        self.issues = []
        self.flow_times = defaultdict(list)      # (src,dst,dport,proto)->[ts]
        self.src_to_dstports = defaultdict(set)  # src -> {dports}
        self.src_to_dsts = defaultdict(set)      # src -> {dsts}
        self.flow_bytes = Counter()              # (src,dst,dport,proto) -> bytes
        self.src_out_bytes = Counter()           # src -> total outbound bytes
        self.buckets = Counter()                 # microburst bins
        self.ip2macs = defaultdict(set)          # ARP analysis
        self.mac2ips = defaultdict(set)
        self.syn_opts = {}   # (src,dst,sport,dport)->opts
        self.synack_opts = {}# (dst,src,dport,sport)->opts
        self.saw_ptb_v6 = False
        self.saw_fragneeded_v4 = False
        self.retrans_counter = 0
        self._seen_seq = {}  # (src,dst,sp,dp) -> set of seq numbers for better retrans detection
    
    def flag_issue(self, cat, msg, ctx):
        self.issues.append({"cat": cat, "msg": msg, "ctx": ctx})
    
    def reset(self):
        """Reset all state (for reuse if needed)"""
        self.issues.clear()
        self.flow_times.clear()
        self.src_to_dstports.clear()
        self.src_to_dsts.clear()
        self.flow_bytes.clear()
        self.src_out_bytes.clear()
        self.buckets.clear()
        self.ip2macs.clear()
        self.mac2ips.clear()
        self.syn_opts.clear()
        self.synack_opts.clear()
        self.saw_ptb_v6 = False
        self.saw_fragneeded_v4 = False
        self.retrans_counter = 0
        self._seen_seq.clear()

# -------- "War Stories" Rule Pack (enabled by --profile noc) --------
def rule_port_anomaly(src, dst, dport, proto):
    if proto in ("TCP","UDP") and dport is not None:
        if dport in SENSITIVE_PORTS:
            return ("PORT", f"Sensitive service port {dport} to {dst}")
        if dport > RARE_HIGHPORT:
            return ("PORT", f"Very high port {dport} to {dst}")
    return None

def rule_scan_behavior(state, src):
    if len(state.src_to_dstports[src]) >= SCAN_PORT_THRESHOLD:
        return ("SCAN", f"{src} contacted many destination ports ({len(state.src_to_dstports[src])})")
    if len(state.src_to_dsts[src]) >= SCAN_HOST_THRESHOLD:
        return ("SCAN", f"{src} contacted many distinct hosts ({len(state.src_to_dsts[src])})")
    return None

def is_beacon_like(times):
    if len(times) < BEACON_MIN_PKTS: return False
    intervals = [t2-t1 for t1,t2 in zip(times, times[1:])]
    if not intervals: return False
    if len(intervals) < 2: return False  # Need at least 2 intervals for stddev
    mu = sum(intervals)/len(intervals)
    if mu <= 0: return False
    try:
        jitter = pstdev(intervals)/mu
        return jitter < BEACON_JITTER_MAX
    except (ValueError, ZeroDivisionError):
        return False

def rule_beacon(state, src, dst, dport, proto):
    key=(src,dst,dport,proto)
    times=state.flow_times.get(key,[])
    if is_beacon_like(times):
        return ("BEACON", f"Beacon-like timing {src}->{dst}:{dport} {proto} (low jitter)")
    return None

def rule_volume_spike(state, src, threshold=VOLUME_SPIKE_BYTES):
    if state.src_out_bytes[src] >= threshold:
        return ("VOLUME", f"{src} sent {state.src_out_bytes[src]:,} bytes")
    return None

def check_option_stripping(state):
    # SYN had SACK/WScale but SYN/ACK doesn't → middlebox stripping
    for k, c in state.syn_opts.items():
        s = state.synack_opts.get(k)
        if not s: continue
        if c.get("sack_perm") and not s.get("sack_perm"):
            state.flag_issue("PORT", "SACK stripped by middlebox (SYN has it; SYN/ACK lacks)", {"flow": str(k)})
        if c.get("wscale") is not None and s.get("wscale") is None:
            state.flag_issue("PORT", "Window scaling stripped by middlebox", {"flow": str(k)})

def finalize_arp_checks(state):
    for ip, macs in state.ip2macs.items():
        if len(macs) > 1:
            state.flag_issue("OTHER", f"IP {ip} seen with multiple MACs", {"ip": ip, "macs": sorted(list(macs))})
    for mac, ips in state.mac2ips.items():
        if len(ips) > 3:
            state.flag_issue("OTHER", f"MAC {mac} answered for many IPs", {"mac": mac, "ips": sorted(list(ips))})

def finalize_microbursts(state, cir_mbps=None):
    if not state.buckets:
        return
    peak_bps = max((v * 8) / (MICROBURST_BUCKET_MS/1000.0) for v in state.buckets.values())
    # If user provided CIR, compare; else just report large spikes
    if cir_mbps:
        if peak_bps > cir_mbps * 1_000_000 * 1.5:
            state.flag_issue("VOLUME", f"Microburst peak ~{int(peak_bps/1e6)} Mbps (>150% CIR)", {"peak_mbps": round(peak_bps/1e6,2)})
    else:
        if peak_bps > 200e6:  # arbitrary: >200 Mbps momentary burst
            state.flag_issue("VOLUME", f"Microburst peak ~{int(peak_bps/1e6)} Mbps", {"peak_mbps": round(peak_bps/1e6,2)})

def finalize_path_mtu(state):
    if state.retrans_counter >= 50 and not (state.saw_ptb_v6 or state.saw_fragneeded_v4):
        state.flag_issue("ICMP", "Likely MTU black-hole (no ICMP PTB/Frag-Needed observed amid retransmissions)", {})

# ===================== Deep scan helpers =====================
def build_filters_from_issues(issues):
    filters=set()
    for it in issues:
        c=it["ctx"]
        dst=c.get("dst"); dport=c.get("dport"); proto=c.get("proto")
        if not dst or dport is None or not proto: continue
        if proto=="TCP":
            filters.add(f"tcp && ip.dst=={dst} && tcp.dstport=={dport}")
        elif proto=="UDP":
            if dport==53:
                filters.add(f"udp && dns && ip.dst=={dst}")
            else:
                filters.add(f"udp && ip.dst=={dst} && udp.dstport=={dport}")
    return list(filters)

def tshark_deep_scan(pcap_path, filters, want_ja4=False):
    if which("tshark") is None:
        return {"note":"tshark not available"}
    results=[]
    base_fields = [
        "frame.time_epoch","ip.src","ip.dst",
        "tcp.srcport","tcp.dstport","udp.srcport","udp.dstport",
        "dns.qry.name","dns.qry.type","dns.flags.rcode",
        "http.host","http.request.method","http.request.uri","http.user_agent",
        "tls.handshake.version","tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite","ssl.handshake.extensions_server_name",
        "ja3", "ja3s"
    ]
    if want_ja4:
        base_fields += ["tls.ja4","tls.ja4s"]
    for flt in filters:
        cmd = ["tshark","-r",str(pcap_path),"-Y",flt,"-T","json"]
        for f in base_fields:
            cmd += ["-e", f]
        try:
            out = subprocess.check_output(cmd, text=True)
            results.append({"filter":flt,"json":json.loads(out or "[]")})
        except subprocess.CalledProcessError as e:
            results.append({"filter":flt,"error":str(e)})
    return {"tshark":results}

# ===================== Sample PCAP Sources =====================
KNOWN_SAMPLE_SOURCES = {
    "investigating.pcap": "https://github.com/Pranav-ai-cyber/network-security-basics/blob/main/network-security-basics/investigating.pcap",
    "CVE-2020-0796_SMBGhost_PrivEsc_Loopback_traffic.pcapng": "https://github.com/sbousseaden/PCAP-ATTACK",
    "rdp_tunneling_meterpreter_portfwd.pcapng": "https://github.com/sbousseaden/PCAP-ATTACK",
    "Remote_Pwd_Reset_RPC_Admin_Mimikatz_PostZeroLogon.pcapng": "https://github.com/sbousseaden/PCAP-ATTACK",
}

def get_pcap_source(pcap_name: str) -> str:
    """Get the source URL for known sample PCAP files"""
    return KNOWN_SAMPLE_SOURCES.get(pcap_name, None)

# ===================== Presentation =====================
def _print_summary(pcap_path, stats, by_proto, flows):
    console.print(f"\n[bold]Summary for[/bold] {pcap_path.name}")
    console.print("-"*60)
    console.print(f"Packets: {stats['packets']:,}  Bytes: {stats['bytes']:,}  Malformed: {stats['malformed']:,}  Non-IP: {stats['non_ip']:,}")
    if by_proto:
        t=Table(title="By protocol",box=box.SIMPLE)
        t.add_column("Proto"); t.add_column("Packets", justify="right")
        for pr,cnt in by_proto.most_common():
            t.add_row(pr, f"{cnt:,}")
        console.print(t)
    tf=Table(title=f"Top {TOP_N_FLOWS} flows",box=box.SIMPLE)
    tf.add_column("Flow"); tf.add_column("Packets", justify="right")
    for (src,sp,dst,dp,pr), cnt in flows.most_common(TOP_N_FLOWS):
        tf.add_row(f"{src}:{sp} -> {dst}:{dp} {pr}", f"{cnt:,}")
    console.print(tf)

def _print_detections(issues):
    if not issues:
        console.print(Panel(Text("No issues detected by heuristics."), border_style="green"))
        return
    table = Table(title="Detections", box=box.SIMPLE_HEAVY)
    table.add_column("Category"); table.add_column("Message", ratio=60); table.add_column("Context", ratio=40)
    for it in issues:
        color = CAT_COLOR.get(it["cat"], "white")
        ctx = ", ".join(f"{k}={v}" for k,v in it["ctx"].items() if v not in (None, "", []))
        table.add_row(Text(it["cat"], style=color), Text(it["msg"]), Text(ctx))
    console.print(Panel(table, title="Heuristic Findings", border_style="green"))

def write_html_report(outdir: Path, pcap_name: str, stats, by_proto, flows, issues, pcap_source=None):
    """Write HTML report with proper HTML escaping to prevent injection"""
    css = """
    <style>
      body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px;background:#0b0c10;color:#e6f1ff}
      h1{margin:0 0 6px 0} .muted{color:#9fb3c8}
      .card{background:#111319;border:1px solid #1b2030;border-radius:12px;padding:16px;margin:18px 0}
      table{width:100%;border-collapse:collapse}
      th,td{padding:8px;border-bottom:1px solid #1b2030}
      .chip{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.85rem;margin-right:8px}
      .PORT{background:#0d234a;color:#9ec8ff}
      .SCAN{background:#3a0b0b;color:#ff9ea3}
      .DNS{background:#3a2f0b;color:#ffe39e}
      .TLS{background:#2a0b3a;color:#f0a3ff}
      .ICMP{background:#0b2a3a;color:#9ee8ff}
      .VOLUME{background:#0b3a22;color:#9effc2}
      .BEACON{background:#2b2b2b;color:#e6f1ff}
      code{color:#b8d1ff}
      .source-info{background:#1a1f2e;border-left:3px solid #4a9eff;padding:12px;margin:18px 0;border-radius:4px}
      .source-info a{color:#9ec8ff;text-decoration:none}
      .source-info a:hover{text-decoration:underline}
    </style>"""
    safe_name = html.escape(pcap_name)
    html_content = [f"<!doctype html><meta charset='utf-8'><title>PCAP Report - {safe_name}</title>{css}",
            f"<h1>PCAP Report: {safe_name}</h1>",
            f"<div class='muted'>Packets: {stats['packets']:,} &nbsp; Bytes: {stats['bytes']:,} &nbsp; Malformed: {stats['malformed']:,} &nbsp; Non-IP: {stats['non_ip']:,}</div>"]
    
    # Add source information if available
    if pcap_source:
        safe_source = html.escape(pcap_source)
        html_content.append(f"<div class='source-info'><strong>Source:</strong> <a href='{safe_source}' target='_blank'>{safe_source}</a></div>")

    # By protocol
    bp = "<div class='card'><h3>By protocol</h3><table><tr><th>Protocol</th><th>Packets</th></tr>"
    for pr, cnt in by_proto.most_common():
        safe_pr = html.escape(str(pr))
        bp += f"<tr><td>{safe_pr}</td><td style='text-align:right'>{cnt:,}</td></tr>"
    bp += "</table></div>"
    html_content.append(bp)

    # Top flows
    tf = f"<div class='card'><h3>Top {TOP_N_FLOWS} flows</h3><table><tr><th>Flow</th><th>Packets</th></tr>"
    for (src,sp,dst,dp,pr), cnt in flows.most_common(TOP_N_FLOWS):
        safe_src = html.escape(str(src))
        safe_sp = html.escape(str(sp))
        safe_dst = html.escape(str(dst))
        safe_dp = html.escape(str(dp))
        safe_pr = html.escape(str(pr))
        tf += f"<tr><td><code>{safe_src}:{safe_sp}</code> → <code>{safe_dst}:{safe_dp}</code> {safe_pr}</td><td style='text-align:right'>{cnt:,}</td></tr>"
    tf += "</table></div>"
    html_content.append(tf)

    # Detections
    det = "<div class='card'><h3>Detections</h3>"
    if not issues:
        det += "<p class='muted'>No heuristic findings.</p>"
    else:
        det += "<table><tr><th>Category</th><th>Message</th><th>Context</th></tr>"
        for it in issues:
            cat = html.escape(it["cat"])
            msg = html.escape(it["msg"])
            ctx_parts = []
            for k, v in it["ctx"].items():
                if v not in (None, "", []):
                    safe_k = html.escape(str(k))
                    safe_v = html.escape(str(v))
                    ctx_parts.append(f"{safe_k}={safe_v}")
            ctx = ", ".join(ctx_parts)
            det += f"<tr><td><span class='chip {cat}'>{cat}</span></td><td>{msg}</td><td><code>{ctx}</code></td></tr>"
        det += "</table>"
    det += "</div>"
    html_content.append(det)

    report_path = outdir / f"{pcap_name}.html"
    try:
        report_path.write_text("".join(html_content), encoding="utf-8")
        logger.info(f"HTML report written to {report_path}")
    except Exception as e:
        logger.error(f"Failed to write HTML report: {e}")
        raise
    return report_path

def write_csv_report(outdir: Path, pcap_name: str, stats, by_proto, flows, issues):
    """Write CSV reports for detections and flows"""
    base_name = Path(pcap_name).stem
    reports_written = []
    
    # Detections CSV
    detections_path = outdir / f"{base_name}_detections.csv"
    try:
        with open(detections_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Category', 'Message', 'Context'])
            for it in issues:
                ctx_str = ", ".join(f"{k}={v}" for k, v in it["ctx"].items() if v not in (None, "", []))
                writer.writerow([it["cat"], it["msg"], ctx_str])
        reports_written.append(detections_path)
        logger.info(f"Detections CSV written to {detections_path}")
    except Exception as e:
        logger.error(f"Failed to write detections CSV: {e}")
    
    # Top flows CSV
    flows_path = outdir / f"{base_name}_flows.csv"
    try:
        with open(flows_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Source', 'Source Port', 'Destination', 'Dest Port', 'Protocol', 'Packets'])
            for (src, sp, dst, dp, pr), cnt in flows.most_common():
                writer.writerow([src, sp, dst, dp, pr, cnt])
        reports_written.append(flows_path)
        logger.info(f"Flows CSV written to {flows_path}")
    except Exception as e:
        logger.error(f"Failed to write flows CSV: {e}")
    
    return reports_written

# ===================== Packet parsing =====================
def parse_pcap_file(pcap_path:Path, conn, geo:Geo, deep=False, want_ja4=False, outdir:Path=None, enable_warpack=True, cir_mbps=None, export_csv=False):
    """Parse a PCAP file with proper error handling and state management"""
    # Input validation
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file does not exist: {pcap_path}")
    if not pcap_path.is_file():
        raise ValueError(f"Path is not a file: {pcap_path}")
    if not os.access(pcap_path, os.R_OK):
        raise PermissionError(f"Cannot read PCAP file: {pcap_path}")
    
    # Initialize state (no global variables)
    state = AnalysisState()
    stats = Counter()
    by_proto = Counter()
    flows = Counter()
    rows = []
    enrich_cache = set()
    http_guess_ports = {80, 8080, 8000, 8888}
    BATCH_SIZE = 10000  # Insert packets in batches

    def bin_sample(ts, byt):
        b = int(ceil(ts * 1000 / MICROBURST_BUCKET_MS))
        state.buckets[b] += byt

    try:
        with open(pcap_path, "rb") as f:
            reader = dpkt.pcap.Reader if pcap_path.suffix.lower() == ".pcap" else dpkt.pcapng.Reader
            pcap = reader(f)
            for ts, buf in pcap:
                stats["total_frames"] += 1
                bin_sample(ts, len(buf))
                try:
                    # Check for Linux cooked capture (SLL) - loopback traffic
                    # SLL header structure varies, but IP header often starts around offset 4-16
                    # Look for IP header pattern (0x45 = IPv4) after SLL header
                    is_sll = False
                    ip_data = None
                    if len(buf) >= 20:
                        # Check if this looks like SLL (starts with small packet type values)
                        packet_type = int.from_bytes(buf[0:2], 'little') if len(buf) >= 2 else 0
                        if packet_type in (0, 1, 2, 3, 4) and len(buf) > 14:
                            # Try to find IP header - look for 0x45 (IPv4) pattern
                            for offset in [4, 6, 8, 10, 12, 14, 16]:
                                if len(buf) > offset + 1 and buf[offset] == 0x45:  # IPv4 header
                                    ip_data = buf[offset:]
                                    is_sll = True
                                    break
                            # Also check protocol field at common offsets
                            if not is_sll and len(buf) >= 16:
                                for proto_offset in [12, 14]:
                                    if len(buf) > proto_offset + 1:
                                        protocol = int.from_bytes(buf[proto_offset:proto_offset+2], 'big')
                                        if protocol == 0x0800:  # IPv4
                                            ip_data = buf[proto_offset + 2:]
                                            is_sll = True
                                            break
                    
                    if is_sll and ip_data:
                        # Parse IP directly from SLL payload
                        try:
                            ip = dpkt.ip.IP(ip_data)
                            l4 = ip.data
                        except Exception:
                            # If IP parsing fails, treat as non-IP
                            stats["non_ip"] += 1
                            continue
                    else:
                        # Standard Ethernet frame
                        eth = dpkt.ethernet.Ethernet(buf)
                        if eth.type == dpkt.ethernet.ETH_TYPE_ARP:
                            arp = eth.data
                            # 1=request, 2=reply
                            op = "request" if arp.op == 1 else "reply" if arp.op == 2 else str(arp.op)
                            # Validate ARP address lengths
                            if len(arp.spa) == 4:
                                ip_src = socket.inet_ntoa(arp.spa)
                            else:
                                ip_src = ""
                            mac_src = ":".join(f"{b:02x}" for b in arp.sha) if len(arp.sha) > 0 else ""
                            if len(arp.tpa) == 4:
                                ip_tgt = socket.inet_ntoa(arp.tpa)
                            else:
                                ip_tgt = ""
                            mac_tgt = ":".join(f"{b:02x}" for b in arp.tha) if len(arp.tha) > 0 else ""
                            if ip_src and mac_src:
                                state.ip2macs[ip_src].add(mac_src)
                                state.mac2ips[mac_src].add(ip_src)
                            # continue to next frame after ARP handling
                            continue

                        ip = eth.data
                        if not hasattr(ip, "p"):
                            stats["non_ip"] += 1
                            continue
                        l4 = ip.data
                except (dpkt.dpkt.UnpackError, AttributeError, IndexError) as e:
                    stats["malformed"] += 1
                    continue
                except Exception as e:
                    logger.debug(f"Unexpected error parsing packet: {e}")
                    stats["malformed"] += 1
                    continue

                src = inet_to_str(getattr(ip,"src",b""))
                dst = inet_to_str(getattr(ip,"dst",b""))
                proto_num = getattr(ip, "p", None)
                proto = {6:"TCP",17:"UDP",1:"ICMP"}.get(proto_num, f"P{proto_num}")
                by_proto[proto] += 1

                sport = getattr(l4, "sport", None)
                dport = getattr(l4, "dport", None)

                tcp_flags = ""
                if proto=="TCP" and hasattr(l4,"flags"):
                    fl=l4.flags
                    tcp_flags = "".join([
                        "F" if fl & 0x01 else "",
                        "S" if fl & 0x02 else "",
                        "R" if fl & 0x04 else "",
                        "P" if fl & 0x08 else "",
                        "A" if fl & 0x10 else "",
                        "U" if fl & 0x20 else "",
                        "E" if fl & 0x40 else "",
                        "C" if fl & 0x80 else "",
                    ])

                total_len = len(buf)
                service = port_name(dport, proto) if dport is not None else ""

                # Cheap HTTP peek (optional)
                if proto=="TCP" and dport in http_guess_ports:
                    try:
                        dpkt.http.Request(l4.data)  # just to see if parsable; fields could be added later
                    except Exception:
                        pass

                # Store packet row
                rows.append((
                    pcap_path.name, ts, src, sport if sport is not None else None,
                    dst, dport if dport is not None else None, proto, total_len, tcp_flags, service
                ))
                flows[(src, sport, dst, dport, proto)] += 1
                stats["packets"] += 1
                stats["bytes"] += total_len

                # War-pack state tracking
                if enable_warpack:
                    # Flow timing/bytes
                    state.flow_times[(src, dst, dport, proto)].append(ts)
                    if dport is not None:
                        state.src_to_dstports[src].add(dport)
                    state.src_to_dsts[src].add(dst)
                    state.flow_bytes[(src, dst, dport, proto)] += total_len
                    state.src_out_bytes[src] += total_len

                    # SYN/SYN-ACK options
                    if proto == "TCP":
                        if tcp_flags and "S" in tcp_flags and "A" not in tcp_flags:
                            try:
                                opts = parse_tcp_options(l4.opts if hasattr(l4, "opts") else b"")
                                state.syn_opts[(src, dst, sport, dport)] = opts
                            except Exception as e:
                                logger.debug(f"Error parsing TCP options: {e}")
                        elif tcp_flags and "S" in tcp_flags and "A" in tcp_flags:
                            try:
                                opts = parse_tcp_options(l4.opts if hasattr(l4, "opts") else b"")
                                state.synack_opts[(dst, src, dport, sport)] = opts
                            except Exception as e:
                                logger.debug(f"Error parsing TCP SYN-ACK options: {e}")
                        # Improved retransmission detection with flow context
                        if hasattr(l4, "seq") and sport is not None and dport is not None:
                            flow_key = (src, dst, sport, dport)
                            seq = getattr(l4, "seq", None)
                            if seq is not None:
                                if flow_key not in state._seen_seq:
                                    state._seen_seq[flow_key] = set()
                                if seq in state._seen_seq[flow_key]:
                                    state.retrans_counter += 1
                                else:
                                    state._seen_seq[flow_key].add(seq)

                    # ICMP(6) PTB / frag-needed
                    if proto_num == 58:  # ICMPv6
                        try:
                            ic6 = ip.data
                            if getattr(ic6, 'type', None) == 2:
                                state.saw_ptb_v6 = True
                        except Exception:
                            pass
                    if proto_num == 1 and proto == "ICMP":
                        try:
                            ic = ip.data
                            # type 3 code 4 => fragmentation needed
                            if getattr(ic, 'type', None) == 3 and getattr(ic, 'code', None) == 4:
                                state.saw_fragneeded_v4 = True
                        except Exception:
                            pass

                    # Quick per-packet rule (ports)
                    hit = rule_port_anomaly(src, dst, dport, proto)
                    if hit:
                        state.flag_issue(hit[0], hit[1], {"src": src, "dst": dst, "dport": dport, "proto": proto})

                # Geo enrichment (write-through cache)
                if geo:
                    if src and src not in enrich_cache:
                        try:
                            e = geo.lookup(src)
                            db_upsert_enrich(conn, src, e)
                            enrich_cache.add(src)
                        except Exception as e:
                            logger.debug(f"Error enriching IP {src}: {e}")
                    if dst and dst not in enrich_cache:
                        try:
                            e = geo.lookup(dst)
                            db_upsert_enrich(conn, dst, e)
                            enrich_cache.add(dst)
                        except Exception as e:
                            logger.debug(f"Error enriching IP {dst}: {e}")
                
                # Batch insert to avoid memory issues
                if len(rows) >= BATCH_SIZE:
                    try:
                        db_insert_packets(conn, rows, batch_size=BATCH_SIZE)
                        rows = []  # Clear after insert
                    except Exception as e:
                        logger.error(f"Error inserting packet batch: {e}")
                        raise

        # Commit remaining packets
        if rows:
            try:
                db_insert_packets(conn, rows, batch_size=BATCH_SIZE)
            except Exception as e:
                logger.error(f"Error inserting final packet batch: {e}")
                raise

        # Aggregated detections (war-pack)
        if enable_warpack:
            # scan/volume per source
            for srcip in set(list(state.src_to_dstports.keys()) + list(state.src_to_dsts.keys())):
                r1 = rule_scan_behavior(state, srcip)
                if r1:
                    state.flag_issue(r1[0], r1[1], {"src": srcip})
                rV = rule_volume_spike(state, srcip)
                if rV:
                    state.flag_issue(rV[0], rV[1], {"src": srcip})
            # beaconing per flow
            for (src, dst, dport, proto), times in state.flow_times.items():
                rB = rule_beacon(state, src, dst, dport, proto)
                if rB:
                    state.flag_issue(rB[0], rB[1], {"src": src, "dst": dst, "dport": dport, "proto": proto})
            # option stripping
            check_option_stripping(state)
            # microbursts & MTU blackhole
            finalize_microbursts(state, cir_mbps=cir_mbps)
            finalize_path_mtu(state)
            # ARP weirdness
            finalize_arp_checks(state)

    except FileNotFoundError:
        raise
    except PermissionError:
        raise
    except Exception as e:
        logger.error(f"Error parsing PCAP file {pcap_path}: {e}")
        raise

    # Console output
    _print_summary(pcap_path, stats, by_proto, flows)
    _print_detections(state.issues)

    # Store detections
    try:
        for it in state.issues:
            db_insert_detection(conn, pcap_path.name, it["cat"], it["msg"], it["ctx"])
        conn.commit()
    except Exception as e:
        logger.error(f"Error storing detections: {e}")
        conn.rollback()

    # Deep scan on flagged flows
    if deep and state.issues:
        try:
            filters = build_filters_from_issues(state.issues)
            if filters:
                artifacts = tshark_deep_scan(pcap_path, filters, want_ja4=want_ja4)
                for item in artifacts.get("tshark", []):
                    if "json" in item:
                        db_insert_tls_artifacts(conn, pcap_path.name, item["filter"], item["json"])
                conn.commit()
                console.print(Panel(Text(f"Deep scan complete for {len(filters)} filters"), border_style="magenta"))
        except Exception as e:
            logger.error(f"Error during deep scan: {e}")

    # HTML report
    if outdir:
        try:
            pcap_source = get_pcap_source(pcap_path.name)
            report_path = write_html_report(outdir, pcap_path.name, stats, by_proto, flows, state.issues, pcap_source=pcap_source)
            console.print(f"[bold]Report:[/bold] {report_path}")
            if pcap_source:
                console.print(f"[dim]Source:[/dim] {pcap_source}")
        except Exception as e:
            logger.error(f"Error writing HTML report: {e}")

    # CSV export
    if export_csv and outdir:
        try:
            csv_reports = write_csv_report(outdir, pcap_path.name, stats, by_proto, flows, state.issues)
            if csv_reports:
                console.print(f"[bold]CSV reports:[/bold] {', '.join(str(p) for p in csv_reports)}")
        except Exception as e:
            logger.error(f"Error writing CSV reports: {e}")

    return stats

# ===================== Driver / CLI =====================
def process_path(path:Path, conn, geo, deep=False, ja4=False, outdir:Path=None, profile="default", cir_mbps=None, export_csv=False):
    """Process a single file or directory of PCAP files"""
    enable_warpack = (profile == "noc")
    
    # Input validation
    if not path.exists():
        raise FileNotFoundError(f"Input path does not exist: {path}")
    
    if path.is_dir():
        pcap_files = [p for p in sorted(path.iterdir()) if p.suffix.lower() in (".pcap", ".pcapng")]
        if not pcap_files:
            logger.warning(f"No PCAP files found in directory: {path}")
            return
        for p in pcap_files:
            try:
                parse_pcap_file(p, conn, geo, deep=deep, want_ja4=ja4, outdir=outdir, 
                              enable_warpack=enable_warpack, cir_mbps=cir_mbps, export_csv=export_csv)
            except Exception as e:
                logger.error(f"Error processing {p}: {e}")
                continue
    else:
        parse_pcap_file(path, conn, geo, deep=deep, want_ja4=ja4, outdir=outdir, 
                       enable_warpack=enable_warpack, cir_mbps=cir_mbps, export_csv=export_csv)

def main():
    ap = argparse.ArgumentParser(description="PCAP autoparser → SQLite + heuristics + GeoIP/ASN + targeted deep scan + HTML")
    ap.add_argument("input", help="PCAP/PCAPNG file or directory")
    ap.add_argument("--db", default="pcap_out/pcaps.sqlite", help="SQLite DB path")
    ap.add_argument("--outdir", default="pcap_out", help="Output directory (reports/artifacts)")
    ap.add_argument("--geoip-city", default=os.environ.get("GEOIP_CITY_DB",""), help="Path to GeoLite2-City.mmdb")
    ap.add_argument("--geoip-asn",  default=os.environ.get("GEOIP_ASN_DB",""), help="Path to GeoLite2-ASN.mmdb")
    ap.add_argument("--deep", action="store_true", help="Enable targeted tshark deep scans on flagged flows")
    ap.add_argument("--ja4", action="store_true", help="Request JA4/JA4S fields (if tshark build supports)")
    ap.add_argument("--csv", action="store_true", help="Export CSV reports for detections and flows")
    ap.add_argument("--processes", type=int, default=1, help="Parallel workers for multiple pcaps (dir mode only). Note: SQLite with multiple processes may have concurrency issues")
    ap.add_argument("--profile", choices=["default","noc"], default="noc", help="Enable NOC war-story detectors")
    ap.add_argument("--cir-mbps", type=int, default=None, help="Committed Information Rate for microburst comparison")
    args = ap.parse_args()

    # Input validation
    indir = Path(args.input).expanduser().resolve()
    if not indir.exists():
        console.print(f"[red]Error:[/red] Input path does not exist: {indir}")
        return 1
    if not indir.is_file() and not indir.is_dir():
        console.print(f"[red]Error:[/red] Input path is not a file or directory: {indir}")
        return 1

    # Output directory validation
    outdir = Path(args.outdir).expanduser().resolve()
    try:
        outdir.mkdir(parents=True, exist_ok=True)
        if not os.access(outdir, os.W_OK):
            console.print(f"[red]Error:[/red] Output directory is not writable: {outdir}")
            return 1
    except Exception as e:
        console.print(f"[red]Error:[/red] Cannot create output directory {outdir}: {e}")
        return 1

    # Database validation
    try:
        conn = db_connect(str(Path(args.db)))
    except Exception as e:
        console.print(f"[red]Error:[/red] Cannot connect to database: {e}")
        return 1

    # GeoIP validation
    geo = None
    if args.geoip_city or args.geoip_asn:
        if args.geoip_city and not Path(args.geoip_city).exists():
            logger.warning(f"GeoIP City database not found: {args.geoip_city}")
        if args.geoip_asn and not Path(args.geoip_asn).exists():
            logger.warning(f"GeoIP ASN database not found: {args.geoip_asn}")
        geo = Geo(args.geoip_city, args.geoip_asn)

    # Multiprocessing warning
    if args.processes > 1:
        if not indir.is_dir():
            logger.warning("--processes > 1 only works with directories, ignoring")
            args.processes = 1
        else:
            logger.warning("Using multiprocessing with SQLite. Each process uses its own connection. "
                         "Consider using a single process for better SQLite performance.")

    try:
        if args.processes > 1 and indir.is_dir():
            from multiprocessing import Pool
            files = [p for p in sorted(indir.iterdir()) if p.suffix.lower() in (".pcap", ".pcapng")]
            if not files:
                console.print(f"[yellow]Warning:[/yellow] No PCAP files found in {indir}")
                return 0
            
            def _worker(p):
                """Worker function for multiprocessing - each process gets its own DB connection"""
                try:
                    c = db_connect(str(Path(args.db)))
                    g = Geo(args.geoip_city, args.geoip_asn) if (args.geoip_city or args.geoip_asn) else None
                    parse_pcap_file(p, c, g, deep=args.deep, want_ja4=args.ja4, outdir=outdir, 
                                  enable_warpack=(args.profile=="noc"), cir_mbps=args.cir_mbps, 
                                  export_csv=args.csv)
                    c.close()
                except Exception as e:
                    logger.error(f"Worker error processing {p}: {e}")
                    return 1
                return 0
            
            with Pool(processes=args.processes) as pool:
                results = pool.map(_worker, files)
            if any(r != 0 for r in results):
                console.print("[yellow]Warning:[/yellow] Some files failed to process")
        else:
            process_path(indir, conn, geo, deep=args.deep, ja4=args.ja4, outdir=outdir, 
                       profile=args.profile, cir_mbps=args.cir_mbps, export_csv=args.csv)
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
        return 1
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        console.print(f"[red]Fatal error:[/red] {e}")
        return 1
    finally:
        conn.close()
    
    return 0

if __name__=="__main__":
    import sys
    sys.exit(main())
