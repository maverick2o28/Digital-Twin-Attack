"""
Digital Twin - Network Log Analyzer & IDS/IPS Defense Module
Analyzes incoming packets, detects anomalies, applies defense rules.
"""

import re
import time
import collections
import datetime
import threading
import json
from dataclasses import dataclass, field
from typing import Optional

# ─── DATA STRUCTURES ──────────────────────────────────────────────────────────
@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    port: int
    proto: str
    flags: str = ""
    size: int = 0

@dataclass
class ThreatAlert:
    timestamp: str
    threat_type: str
    severity: str
    src_ip: str
    description: str
    action_taken: str
    confidence: float

# ─── IDS RULES ────────────────────────────────────────────────────────────────
IDS_RULES = [
    {
        "id": "IDS-001",
        "name": "SYN Flood Detection",
        "condition": lambda tracker, pkt: tracker.count_src_in_window(pkt.src_ip, window=5) > 100,
        "severity": "CRITICAL",
        "action": "BLOCK",
        "description": "More than 100 SYN packets from single source in 5 seconds",
    },
    {
        "id": "IDS-002",
        "name": "Port Scan Detection",
        "condition": lambda tracker, pkt: tracker.unique_ports_from(pkt.src_ip, window=10) > 20,
        "severity": "HIGH",
        "action": "ALERT",
        "description": "Single source accessed more than 20 unique ports in 10 seconds",
    },
    {
        "id": "IDS-003",
        "name": "SSH Brute Force",
        "condition": lambda tracker, pkt: (pkt.port == 22 and
                      tracker.count_src_in_window(pkt.src_ip, window=60) > 15),
        "severity": "HIGH",
        "action": "THROTTLE",
        "description": "Excessive SSH connection attempts from single source",
    },
    {
        "id": "IDS-004",
        "name": "DNS Flood",
        "condition": lambda tracker, pkt: (pkt.port == 53 and
                      tracker.count_src_in_window(pkt.src_ip, window=5) > 50),
        "severity": "CRITICAL",
        "action": "BLOCK",
        "description": "DNS query flood from single source",
    },
    {
        "id": "IDS-005",
        "name": "Large Traffic Volume",
        "condition": lambda tracker, pkt: tracker.total_packets_in_window(window=1) > 500,
        "severity": "MEDIUM",
        "action": "ALERT",
        "description": "Unusually high packet volume (>500/sec) across all sources",
    },
]

# ─── TRAFFIC TRACKER ──────────────────────────────────────────────────────────
class TrafficTracker:
    def __init__(self, max_history=10000):
        self._lock = threading.Lock()
        self._packets = collections.deque(maxlen=max_history)
        self._blocked_ips: set = set()
        self._throttled_ips: set = set()

    def record(self, pkt: PacketRecord):
        with self._lock:
            self._packets.append(pkt)

    def _recent(self, window: float):
        cutoff = time.time() - window
        return [p for p in self._packets if p.timestamp >= cutoff]

    def count_src_in_window(self, src_ip: str, window: float) -> int:
        return sum(1 for p in self._recent(window) if p.src_ip == src_ip)

    def unique_ports_from(self, src_ip: str, window: float) -> int:
        ports = {p.port for p in self._recent(window) if p.src_ip == src_ip}
        return len(ports)

    def total_packets_in_window(self, window: float) -> int:
        return len(self._recent(window))

    def top_sources(self, window=60, n=5):
        counter = collections.Counter(p.src_ip for p in self._recent(window))
        return counter.most_common(n)

    def block_ip(self, ip: str):
        with self._lock:
            self._blocked_ips.add(ip)

    def is_blocked(self, ip: str) -> bool:
        return ip in self._blocked_ips

    def get_stats(self) -> dict:
        recent_1s  = self.total_packets_in_window(1)
        recent_60s = self.total_packets_in_window(60)
        return {
            "packets_per_second": recent_1s,
            "packets_per_minute": recent_60s,
            "blocked_ips": len(self._blocked_ips),
            "total_recorded": len(self._packets),
            "top_sources": self.top_sources(),
        }

# ─── IDS ENGINE ───────────────────────────────────────────────────────────────
class IDSEngine:
    def __init__(self, tracker: TrafficTracker, alert_callback=None):
        self.tracker  = tracker
        self._callback = alert_callback
        self._alerted: dict = {}   # rule_id → last alert time (rate limit)
        self.alerts: list = []

    def analyze(self, pkt: PacketRecord) -> Optional[ThreatAlert]:
        self.tracker.record(pkt)

        if self.tracker.is_blocked(pkt.src_ip):
            return None  # Already blocked, skip

        for rule in IDS_RULES:
            try:
                triggered = rule["condition"](self.tracker, pkt)
            except Exception:
                continue

            if triggered:
                # Rate-limit: only fire same rule once per 5 seconds per source
                key = f"{rule['id']}:{pkt.src_ip}"
                if time.time() - self._alerted.get(key, 0) < 5:
                    continue
                self._alerted[key] = time.time()

                # Determine action
                action_taken = "ALERT GENERATED"
                if rule["action"] == "BLOCK":
                    self.tracker.block_ip(pkt.src_ip)
                    action_taken = f"IP {pkt.src_ip} BLOCKED"
                elif rule["action"] == "THROTTLE":
                    action_taken = f"IP {pkt.src_ip} THROTTLED"

                alert = ThreatAlert(
                    timestamp=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    threat_type=rule["name"],
                    severity=rule["severity"],
                    src_ip=pkt.src_ip,
                    description=f"[{rule['id']}] {rule['description']}",
                    action_taken=action_taken,
                    confidence=0.85 + (hash(rule["id"]) % 15) / 100,
                )
                self.alerts.append(alert)
                if self._callback:
                    self._callback(alert)
                return alert
        return None

# ─── LOG PARSER ───────────────────────────────────────────────────────────────
class LogParser:
    """Parse various log formats into PacketRecord objects."""

    # Example: "2024-01-15 10:23:45.123 SRC=1.2.3.4 DST=192.168.1.100 PROTO=TCP DPT=80"
    IPTABLES_PATTERN = re.compile(
        r"SRC=(\S+)\s+DST=(\S+)\s+.*?PROTO=(\w+).*?DPT=(\d+)"
    )
    # Tcpdump: "12:34:56.789 IP 1.2.3.4.1234 > 192.168.1.100.80: ..."
    TCPDUMP_PATTERN = re.compile(
        r"IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+)"
    )

    @classmethod
    def parse_iptables(cls, line: str) -> Optional[PacketRecord]:
        m = cls.IPTABLES_PATTERN.search(line)
        if m:
            return PacketRecord(
                timestamp=time.time(),
                src_ip=m.group(1), dst_ip=m.group(2),
                port=int(m.group(4)), proto=m.group(3))
        return None

    @classmethod
    def parse_tcpdump(cls, line: str) -> Optional[PacketRecord]:
        m = cls.TCPDUMP_PATTERN.search(line)
        if m:
            return PacketRecord(
                timestamp=time.time(),
                src_ip=m.group(1), dst_ip=m.group(3),
                port=int(m.group(4)), proto="TCP")
        return None

    @classmethod
    def parse_json_log(cls, line: str) -> Optional[PacketRecord]:
        """Parse JSON log format from our web app."""
        try:
            d = json.loads(line)
            return PacketRecord(
                timestamp=time.time(),
                src_ip=d.get("src_ip", "0.0.0.0"),
                dst_ip=d.get("dst_ip", "0.0.0.0"),
                port=int(d.get("port", 0)),
                proto=d.get("proto", "TCP"))
        except Exception:
            return None

# ─── REPORT GENERATOR ─────────────────────────────────────────────────────────
class ReportGenerator:
    def __init__(self, tracker: TrafficTracker, ids: IDSEngine):
        self.tracker = tracker
        self.ids     = ids

    def summary(self) -> str:
        stats = self.tracker.get_stats()
        lines = [
            "=" * 60,
            f"  DIGITAL TWIN - NETWORK ANALYSIS REPORT",
            f"  Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "=" * 60,
            f"  Packets/sec:    {stats['packets_per_second']}",
            f"  Packets/min:    {stats['packets_per_minute']}",
            f"  Total recorded: {stats['total_recorded']}",
            f"  Blocked IPs:    {stats['blocked_ips']}",
            f"  Alerts fired:   {len(self.ids.alerts)}",
            "",
            "  TOP SOURCES (last 60s):",
        ]
        for ip, count in stats["top_sources"]:
            lines.append(f"    {ip:<20} {count:>5} packets")
        lines += [
            "",
            "  RECENT ALERTS:",
        ]
        for a in self.ids.alerts[-10:]:
            lines.append(f"    [{a.severity}] {a.threat_type} | {a.src_ip} | {a.action_taken}")
        lines.append("=" * 60)
        return "\n".join(lines)

# ─── QUICK TEST ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import random as rnd

    alerts_received = []

    def on_alert(alert: ThreatAlert):
        print(f"\n🚨 ALERT: [{alert.severity}] {alert.threat_type}")
        print(f"   Source: {alert.src_ip}")
        print(f"   Action: {alert.action_taken}")
        print(f"   Info:   {alert.description}\n")
        alerts_received.append(alert)

    tracker = TrafficTracker()
    ids_engine = IDSEngine(tracker, alert_callback=on_alert)

    print("[*] Simulating normal traffic...")
    for _ in range(20):
        pkt = PacketRecord(
            timestamp=time.time(),
            src_ip=f"192.168.1.{rnd.randint(2,20)}",
            dst_ip="192.168.1.100",
            port=rnd.choice([80, 443, 53]),
            proto=rnd.choice(["TCP", "UDP"]))
        ids_engine.analyze(pkt)
        time.sleep(0.01)

    print("[*] Simulating SYN flood (200 packets from 10.0.0.1)...")
    for _ in range(200):
        pkt = PacketRecord(
            timestamp=time.time(),
            src_ip="10.0.0.1",
            dst_ip="192.168.1.100",
            port=80, proto="TCP", flags="SYN")
        ids_engine.analyze(pkt)

    report = ReportGenerator(tracker, ids_engine)
    print(report.summary())
