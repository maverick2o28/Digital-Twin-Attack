"""
Digital Twin — MongoDB Database Manager
Handles all persistence: network logs, attack sessions, threat alerts, blocked IPs.

Collections:
    network_logs    — every packet/event logged
    attack_sessions — start/stop records per attack run
    threat_alerts   — IDS-fired alerts
    blocked_ips     — firewall block list with timestamps
    stats_snapshots — periodic stats for trend analysis

Requires: pip install pymongo
MongoDB must be running locally:
    sudo apt install mongodb          # Raspberry Pi / Debian
    brew install mongodb-community    # macOS
    docker run -d -p 27017:27017 mongo  # Docker
"""

import datetime
import threading
import time
import os
from typing import Optional, List, Dict, Any

try:
    from pymongo import MongoClient, ASCENDING, DESCENDING, errors as mongo_errors
    from pymongo.collection import Collection
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False
    print("[DB] pymongo not installed. Run: pip install pymongo")


# ─── CONFIG ───────────────────────────────────────────────────────────────────
MONGO_URI  = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
DB_NAME    = os.environ.get("MONGO_DB",  "digital_twin")
MAX_LOG_DOCS = 50_000   # cap on network_logs collection size


# ─── FALLBACK STUB (when MongoDB unavailable) ─────────────────────────────────
class _StubCollection:
    """Silent no-op when MongoDB is not available."""
    def insert_one(self, *a, **kw): return type("R", (), {"inserted_id": None})()
    def insert_many(self, *a, **kw): return type("R", (), {"inserted_ids": []})()
    def find(self, *a, **kw): return iter([])
    def find_one(self, *a, **kw): return None
    def count_documents(self, *a, **kw): return 0
    def update_one(self, *a, **kw): return None
    def update_many(self, *a, **kw): return None
    def delete_many(self, *a, **kw): return None
    def create_index(self, *a, **kw): return None
    def aggregate(self, *a, **kw): return iter([])
    def distinct(self, *a, **kw): return []


class _StubDB:
    def __getitem__(self, name): return _StubCollection()
    def __getattr__(self, name): return _StubCollection()
    def list_collection_names(self): return []
    def command(self, *a, **kw): return {}


# ─── DATABASE MANAGER ─────────────────────────────────────────────────────────
class DatabaseManager:
    def __init__(self, uri: str = MONGO_URI, db_name: str = DB_NAME):
        self._lock      = threading.Lock()
        self._connected = False
        self._uri       = uri
        self._db_name   = db_name
        self.client     = None
        self.db         = _StubDB()

        # Collections (start as stubs)
        self.logs      = _StubCollection()
        self.sessions  = _StubCollection()
        self.alerts    = _StubCollection()
        self.blocked   = _StubCollection()
        self.snapshots = _StubCollection()

        if MONGO_AVAILABLE:
            self._connect()
        else:
            print("[DB] Running without MongoDB (stub mode).")

    # ── CONNECTION ─────────────────────────────────────────────────────────────
    def _connect(self):
        try:
            self.client = MongoClient(self._uri, serverSelectionTimeoutMS=3000)
            self.client.admin.command("ping")   # Test connection
            self.db         = self.client[self._db_name]
            self.logs       = self.db["network_logs"]
            self.sessions   = self.db["attack_sessions"]
            self.alerts     = self.db["threat_alerts"]
            self.blocked    = self.db["blocked_ips"]
            self.snapshots  = self.db["stats_snapshots"]
            self._connected = True
            self._setup_indexes()
            print(f"[DB] ✅ Connected to MongoDB at {self._uri} → database: '{self._db_name}'")
        except Exception as e:
            print(f"[DB] ⚠  MongoDB unavailable ({e}). Running in stub mode.")
            self._connected = False

    def _setup_indexes(self):
        """Create indexes for fast querying."""
        try:
            self.logs.create_index([("timestamp", DESCENDING)])
            self.logs.create_index([("level", ASCENDING)])
            self.logs.create_index([("src_ip", ASCENDING)])
            self.logs.create_index([("session_id", ASCENDING)])
            self.sessions.create_index([("started_at", DESCENDING)])
            self.sessions.create_index([("attack_type", ASCENDING)])
            self.alerts.create_index([("fired_at", DESCENDING)])
            self.alerts.create_index([("severity", ASCENDING)])
            self.blocked.create_index([("ip", ASCENDING)], unique=True)
            self.snapshots.create_index([("recorded_at", DESCENDING)])
            print("[DB] Indexes created.")
        except Exception as e:
            print(f"[DB] Index creation warning: {e}")

    @property
    def connected(self) -> bool:
        return self._connected

    def reconnect(self):
        if MONGO_AVAILABLE:
            self._connect()

    # ── NETWORK LOGS ──────────────────────────────────────────────────────────
    def save_log(self, log: dict, session_id: Optional[str] = None) -> Optional[str]:
        """Persist a network log entry. Returns inserted _id as string."""
        doc = {
            "timestamp":  log.get("timestamp"),
            "level":      log.get("level", "INFO"),
            "event":      log.get("event", ""),
            "src_ip":     log.get("src_ip", ""),
            "dst_ip":     log.get("dst_ip", ""),
            "port":       log.get("port", 0),
            "proto":      log.get("proto", "TCP"),
            "extra":      log.get("extra", ""),
            "session_id": session_id,
            "saved_at":   datetime.datetime.utcnow(),
        }
        try:
            result = self.logs.insert_one(doc)
            return str(result.inserted_id)
        except Exception as e:
            print(f"[DB] save_log error: {e}")
            return None

    def save_logs_bulk(self, logs: List[dict], session_id: Optional[str] = None):
        """Bulk insert for performance."""
        if not logs:
            return
        docs = [{
            "timestamp":  l.get("timestamp"),
            "level":      l.get("level", "INFO"),
            "event":      l.get("event", ""),
            "src_ip":     l.get("src_ip", ""),
            "dst_ip":     l.get("dst_ip", ""),
            "port":       l.get("port", 0),
            "proto":      l.get("proto", "TCP"),
            "extra":      l.get("extra", ""),
            "session_id": session_id,
            "saved_at":   datetime.datetime.utcnow(),
        } for l in logs]
        try:
            self.logs.insert_many(docs, ordered=False)
        except Exception as e:
            print(f"[DB] save_logs_bulk error: {e}")

    def get_logs(self, limit: int = 200, level: Optional[str] = None,
                 src_ip: Optional[str] = None, session_id: Optional[str] = None,
                 since_minutes: Optional[int] = None) -> List[dict]:
        """Query logs with optional filters."""
        filt: Dict[str, Any] = {}
        if level:      filt["level"]      = level
        if src_ip:     filt["src_ip"]     = src_ip
        if session_id: filt["session_id"] = session_id
        if since_minutes:
            cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=since_minutes)
            filt["saved_at"] = {"$gte": cutoff}
        try:
            cursor = self.logs.find(filt, {"_id": 0}).sort("saved_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            print(f"[DB] get_logs error: {e}")
            return []

    def count_logs(self, level: Optional[str] = None) -> int:
        filt = {"level": level} if level else {}
        try:
            return self.logs.count_documents(filt)
        except Exception:
            return 0

    def prune_old_logs(self, keep: int = MAX_LOG_DOCS):
        """Keep only the most recent `keep` documents."""
        try:
            total = self.logs.count_documents({})
            if total > keep:
                # Find the _id cutoff
                cutoff_doc = list(
                    self.logs.find({}, {"_id": 1}).sort("saved_at", DESCENDING).skip(keep).limit(1)
                )
                if cutoff_doc:
                    self.logs.delete_many({"_id": {"$lte": cutoff_doc[0]["_id"]}})
                    print(f"[DB] Pruned logs. Kept {keep} most recent.")
        except Exception as e:
            print(f"[DB] prune_old_logs error: {e}")

    # ── ATTACK SESSIONS ────────────────────────────────────────────────────────
    def start_session(self, attack_key: str, attack_name: str, severity: str,
                      description: str) -> Optional[str]:
        """Record an attack session start. Returns session_id string."""
        doc = {
            "attack_key":   attack_key,
            "attack_name":  attack_name,
            "severity":     severity,
            "description":  description,
            "started_at":   datetime.datetime.utcnow(),
            "ended_at":     None,
            "duration_sec": None,
            "packets_sent": 0,
            "threats_fired":0,
            "ips_blocked":  [],
            "status":       "RUNNING",
        }
        try:
            result = self.sessions.insert_one(doc)
            sid = str(result.inserted_id)
            print(f"[DB] Session started: {sid} ({attack_name})")
            return sid
        except Exception as e:
            print(f"[DB] start_session error: {e}")
            return None

    def end_session(self, session_id: str, packets_sent: int = 0,
                    threats_fired: int = 0, ips_blocked: List[str] = None):
        """Record attack session end with stats."""
        if not session_id:
            return
        try:
            from bson import ObjectId
            now = datetime.datetime.utcnow()
            doc = self.sessions.find_one({"_id": ObjectId(session_id)})
            duration = (now - doc["started_at"]).total_seconds() if doc else 0
            self.sessions.update_one(
                {"_id": ObjectId(session_id)},
                {"$set": {
                    "ended_at":     now,
                    "duration_sec": round(duration, 1),
                    "packets_sent": packets_sent,
                    "threats_fired":threats_fired,
                    "ips_blocked":  ips_blocked or [],
                    "status":       "COMPLETED",
                }}
            )
            print(f"[DB] Session ended: {session_id} ({duration:.1f}s)")
        except Exception as e:
            print(f"[DB] end_session error: {e}")

    def get_sessions(self, limit: int = 50) -> List[dict]:
        try:
            cursor = self.sessions.find({}, {"_id": 0}).sort("started_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception:
            return []

    def get_session_count(self) -> int:
        try:
            return self.sessions.count_documents({})
        except Exception:
            return 0

    # ── THREAT ALERTS ─────────────────────────────────────────────────────────
    def save_alert(self, alert_dict: dict, session_id: Optional[str] = None):
        doc = {
            "fired_at":    datetime.datetime.utcnow(),
            "threat_type": alert_dict.get("threat_type", ""),
            "severity":    alert_dict.get("severity", ""),
            "src_ip":      alert_dict.get("src_ip", ""),
            "description": alert_dict.get("description", ""),
            "action_taken":alert_dict.get("action_taken", ""),
            "confidence":  alert_dict.get("confidence", 0.0),
            "session_id":  session_id,
        }
        try:
            self.alerts.insert_one(doc)
        except Exception as e:
            print(f"[DB] save_alert error: {e}")

    def get_alerts(self, limit: int = 100, severity: Optional[str] = None) -> List[dict]:
        filt = {"severity": severity} if severity else {}
        try:
            cursor = self.alerts.find(filt, {"_id": 0}).sort("fired_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception:
            return []

    # ── BLOCKED IPs ───────────────────────────────────────────────────────────
    def add_blocked_ip(self, ip: str, reason: str = "", session_id: Optional[str] = None):
        doc = {
            "ip":         ip,
            "blocked_at": datetime.datetime.utcnow(),
            "reason":     reason,
            "session_id": session_id,
            "active":     True,
        }
        try:
            self.blocked.update_one({"ip": ip}, {"$set": doc}, upsert=True)
        except Exception as e:
            print(f"[DB] add_blocked_ip error: {e}")

    def get_blocked_ips(self, active_only: bool = True) -> List[dict]:
        filt = {"active": True} if active_only else {}
        try:
            cursor = self.blocked.find(filt, {"_id": 0}).sort("blocked_at", DESCENDING)
            return list(cursor)
        except Exception:
            return []

    def unblock_ip(self, ip: str):
        try:
            self.blocked.update_one({"ip": ip}, {"$set": {"active": False}})
        except Exception as e:
            print(f"[DB] unblock_ip error: {e}")

    def clear_blocked_ips(self):
        try:
            self.blocked.delete_many({})
        except Exception as e:
            print(f"[DB] clear_blocked_ips error: {e}")

    # ── STATS SNAPSHOTS ────────────────────────────────────────────────────────
    def save_snapshot(self, stats: dict):
        doc = {**stats, "recorded_at": datetime.datetime.utcnow()}
        # Convert set to list for BSON
        if "blocked_ips" in doc and isinstance(doc["blocked_ips"], set):
            doc["blocked_ips"] = list(doc["blocked_ips"])
        try:
            self.snapshots.insert_one(doc)
        except Exception as e:
            print(f"[DB] save_snapshot error: {e}")

    def get_snapshots(self, limit: int = 1440) -> List[dict]:
        """Get up to 1440 snapshots (1 per minute = 24h)."""
        try:
            cursor = self.snapshots.find({}, {"_id": 0}).sort("recorded_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception:
            return []

    # ── AGGREGATIONS ──────────────────────────────────────────────────────────
    def top_attacker_ips(self, limit: int = 10) -> List[dict]:
        """Most frequent src_ips across all logs."""
        try:
            pipeline = [
                {"$match": {"level": {"$in": ["WARNING", "CRITICAL"]}}},
                {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
                {"$sort": {"count": -1}},
                {"$limit": limit},
                {"$project": {"ip": "$_id", "count": 1, "_id": 0}},
            ]
            return list(self.logs.aggregate(pipeline))
        except Exception:
            return []

    def attack_frequency(self) -> List[dict]:
        """Count sessions per attack type."""
        try:
            pipeline = [
                {"$group": {"_id": "$attack_key",
                            "count": {"$sum": 1},
                            "name":  {"$first": "$attack_name"}}},
                {"$sort": {"count": -1}},
                {"$project": {"attack_key": "$_id", "count": 1, "name": 1, "_id": 0}},
            ]
            return list(self.sessions.aggregate(pipeline))
        except Exception:
            return []

    def severity_breakdown(self) -> dict:
        """Count alerts by severity."""
        try:
            pipeline = [
                {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
            ]
            return {r["_id"]: r["count"] for r in self.alerts.aggregate(pipeline)}
        except Exception:
            return {}

    def logs_per_hour(self, hours: int = 24) -> List[dict]:
        """Hourly log counts for the last N hours."""
        try:
            since = datetime.datetime.utcnow() - datetime.timedelta(hours=hours)
            pipeline = [
                {"$match": {"saved_at": {"$gte": since}}},
                {"$group": {
                    "_id": {
                        "year":  {"$year":  "$saved_at"},
                        "month": {"$month": "$saved_at"},
                        "day":   {"$dayOfMonth": "$saved_at"},
                        "hour":  {"$hour":  "$saved_at"},
                    },
                    "count": {"$sum": 1},
                }},
                {"$sort": {"_id": 1}},
            ]
            return list(self.logs.aggregate(pipeline))
        except Exception:
            return []

    # ── DATABASE INFO ─────────────────────────────────────────────────────────
    def db_stats(self) -> dict:
        """Return collection counts and DB size."""
        try:
            stats = self.db.command("dbStats")
            return {
                "connected":        self._connected,
                "db_name":          self._db_name,
                "data_size_mb":     round(stats.get("dataSize", 0) / 1024 / 1024, 2),
                "storage_size_mb":  round(stats.get("storageSize", 0) / 1024 / 1024, 2),
                "collections": {
                    "network_logs":    self.logs.count_documents({}),
                    "attack_sessions": self.sessions.count_documents({}),
                    "threat_alerts":   self.alerts.count_documents({}),
                    "blocked_ips":     self.blocked.count_documents({}),
                    "stats_snapshots": self.snapshots.count_documents({}),
                },
                "top_attackers": self.top_attacker_ips(5),
                "attack_frequency": self.attack_frequency(),
                "severity_breakdown": self.severity_breakdown(),
            }
        except Exception as e:
            return {
                "connected": self._connected,
                "db_name":   self._db_name,
                "error":     str(e),
                "collections": {},
            }

    def full_reset(self):
        """Drop all collections — use carefully."""
        for col in [self.logs, self.sessions, self.alerts, self.blocked, self.snapshots]:
            try:
                col.delete_many({})
            except Exception:
                pass
        print("[DB] All collections cleared.")


# ─── SINGLETON ────────────────────────────────────────────────────────────────
db = DatabaseManager()


# ─── BACKGROUND SNAPSHOT WORKER ───────────────────────────────────────────────
def _snapshot_worker(get_state_fn, interval_sec: int = 60):
    """Saves a stats snapshot every `interval_sec` seconds."""
    while True:
        time.sleep(interval_sec)
        try:
            db.save_snapshot(get_state_fn())
        except Exception:
            pass

def start_snapshot_worker(get_state_fn, interval_sec: int = 60):
    t = threading.Thread(
        target=_snapshot_worker,
        args=(get_state_fn, interval_sec),
        daemon=True
    )
    t.start()
    print(f"[DB] Snapshot worker started (every {interval_sec}s).")


# ─── CLI TEST ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import json

    print("\n=== Digital Twin — Database Manager Test ===\n")

    # Save some logs
    test_logs = [
        {"timestamp": "2024-01-15 10:00:00.000", "level": "INFO",
         "event": "HTTP GET /", "src_ip": "192.168.1.5", "dst_ip": "192.168.1.100",
         "port": 80, "proto": "TCP", "extra": ""},
        {"timestamp": "2024-01-15 10:00:01.000", "level": "CRITICAL",
         "event": "SYN Flood detected", "src_ip": "10.0.0.99", "dst_ip": "192.168.1.100",
         "port": 80, "proto": "TCP", "extra": "Seq=1"},
    ]
    for l in test_logs:
        db.save_log(l)

    # Start a session
    sid = db.start_session("syn_flood", "SYN Flood DDoS", "CRITICAL", "TCP SYN flood")
    time.sleep(0.5)
    db.end_session(sid, packets_sent=500, threats_fired=12, ips_blocked=["10.0.0.99"])

    # Save alert
    db.save_alert({"threat_type": "SYN Flood Detection", "severity": "CRITICAL",
                   "src_ip": "10.0.0.99", "description": "IDS-001 triggered",
                   "action_taken": "IP BLOCKED", "confidence": 0.95})

    # Block an IP
    db.add_blocked_ip("10.0.0.99", reason="SYN flood", session_id=sid)

    # Print stats
    stats = db.db_stats()
    print(json.dumps(stats, indent=2, default=str))
