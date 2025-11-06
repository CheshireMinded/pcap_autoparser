CREATE VIEW IF NOT EXISTS top_talkers AS
SELECT src, SUM(len_bytes) AS bytes
FROM packets GROUP BY src ORDER BY bytes DESC;

CREATE VIEW IF NOT EXISTS top_flows AS
SELECT src, sport, dst, dport, proto,
       COUNT(*) AS packets, SUM(len_bytes) AS bytes
FROM packets
GROUP BY src, sport, dst, dport, proto
ORDER BY packets DESC;

CREATE VIEW IF NOT EXISTS uncommon_high_ports AS
SELECT dport, COUNT(*) AS packets
FROM packets
WHERE dport > 49151
GROUP BY dport
ORDER BY packets DESC;
