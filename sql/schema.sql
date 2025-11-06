PRAGMA journal_mode=WAL;

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
