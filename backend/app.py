"""
Digital Twin Attack Simulation - Flask Backend
Real-time network log analysis with WebSocket streaming + MongoDB persistence
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import random
import json
import datetime
import queue
import os
import sys

# Try to import GPIO (only available on Raspberry Pi)
try:
    import RPi.GPIO as GPIO
    GPIO_AVAILABLE = True
except ImportError:
    GPIO_AVAILABLE = False
    print("[WARNING] RPi.GPIO not available - running in simulation mode")

# ─── DATABASE ──────────────────────────────────────────────────────────────────
from db_manager import db, start_snapshot_worker

app = Flask(__name__, template_folder="../frontend", static_folder="../frontend/static")
app.config["SECRET_KEY"] = "digital-twin-2024-secret"
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ─── GPIO PIN CONFIGURATION ──────────────────────────────────────────────────
PINS = {
    "led_normal":   17,
    "led_warning":  27,
    "led_attack":   22,
    "buzzer":       18,
}

# ─── GLOBAL STATE ─────────────────────────────────────────────────────────────
state = {
    "attack_active": False,
    "attack_type": None,
    "packets_analyzed": 0,
    "threats_detected": 0,
    "blocked_ips": set(),
    "network_status": "NORMAL",
    "defense_mode": "ACTIVE",
}
log_queue = queue.Queue()
current_session_id = None

_log_buffer = []
_log_buffer_lock = threading.Lock()
LOG_FLUSH_SIZE = 20
LOG_FLUSH_SECS = 5

# ─── ATTACK PROFILES ──────────────────────────────────────────────────────────
ATTACK_PROFILES = {
    "syn_flood": {
        "name": "SYN Flood DDoS",
        "severity": "CRITICAL",
        "description": "TCP SYN flood overwhelming target ports",
        "ports": [80, 443, 8080, 22],
        "rate": 0.05,
    },
    "arp_spoofing": {
        "name": "ARP Spoofing / MITM",
        "severity": "HIGH",
        "description": "ARP cache poisoning for man-in-the-middle attack",
        "ports": [0],
        "rate": 0.15,
    },
    "port_scan": {
        "name": "Port Scan (Nmap-style)",
        "severity": "MEDIUM",
        "description": "Systematic port enumeration and service fingerprinting",
        "ports": list(range(20, 1025)),
        "rate": 0.08,
    },
    "brute_force": {
        "name": "SSH Brute Force",
        "severity": "HIGH",
        "description": "Credential stuffing attack on SSH service",
        "ports": [22],
        "rate": 0.1,
    },
    "dns_amplification": {
        "name": "DNS Amplification",
        "severity": "CRITICAL",
        "description": "DNS reflection/amplification DDoS vector",
        "ports": [53],
        "rate": 0.06,
    },
}

FAKE_IPS = [
    "192.168.1." + str(i) for i in range(2, 30)
] + [
    f"10.0.{random.randint(0,5)}.{random.randint(1,254)}" for _ in range(20)
] + [
    f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    for _ in range(30)
]

TARGET_IP = "192.168.1.100"

# ─── GPIO CONTROL ─────────────────────────────────────────────────────────────
def gpio_setup():
    if not GPIO_AVAILABLE:
        return
    GPIO.setmode(GPIO.BCM)
    GPIO.setwarnings(False)
    for name, pin in PINS.items():
        GPIO.setup(pin, GPIO.OUT)
        GPIO.output(pin, GPIO.LOW)
    GPIO.output(PINS["led_normal"], GPIO.HIGH)

def gpio_cleanup():
    if not GPIO_AVAILABLE:
        return
    for pin in PINS.values():
        GPIO.output(pin, GPIO.LOW)
    GPIO.cleanup()

def set_leds(mode: str):
    if not GPIO_AVAILABLE:
        return
    GPIO.output(PINS["led_normal"],  GPIO.LOW)
    GPIO.output(PINS["led_warning"], GPIO.LOW)
    GPIO.output(PINS["led_attack"],  GPIO.LOW)
    if mode == "NORMAL":
        GPIO.output(PINS["led_normal"], GPIO.HIGH)
    elif mode == "WARNING":
        GPIO.output(PINS["led_warning"], GPIO.HIGH)
    elif mode == "ATTACK":
        GPIO.output(PINS["led_attack"], GPIO.HIGH)

def buzzer_alert(duration=0.5, pulses=3):
    if not GPIO_AVAILABLE:
        return
    def _buzz():
        for _ in range(pulses):
            GPIO.output(PINS["buzzer"], GPIO.HIGH)
            time.sleep(duration)
            GPIO.output(PINS["buzzer"], GPIO.LOW)
            time.sleep(0.1)
    threading.Thread(target=_buzz, daemon=True).start()

# ─── LOG BUFFER & DB FLUSH ────────────────────────────────────────────────────
def _flush_log_buffer():
    global _log_buffer
    with _log_buffer_lock:
        batch = list(_log_buffer)
        _log_buffer = []
    if batch:
        db.save_logs_bulk(batch, session_id=current_session_id)

def _periodic_flush():
    while True:
        time.sleep(LOG_FLUSH_SECS)
        _flush_log_buffer()

# ─── LOG GENERATION ───────────────────────────────────────────────────────────
def make_log(level, event, src_ip=None, dst_ip=None, port=None, proto="TCP", extra=None):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    return {
        "timestamp": ts,
        "level": level,
        "event": event,
        "src_ip": src_ip or random.choice(FAKE_IPS),
        "dst_ip": dst_ip or TARGET_IP,
        "port": port or random.randint(1024, 65535),
        "proto": proto,
        "extra": extra or "",
    }

def emit_log(log):
    state["packets_analyzed"] += 1
    socketio.emit("network_log", log)
    socketio.emit("stats_update", {
        "packets_analyzed": state["packets_analyzed"],
        "threats_detected": state["threats_detected"],
        "blocked_ips": len(state["blocked_ips"]),
        "network_status": state["network_status"],
        "attack_active": state["attack_active"],
        "attack_type": state["attack_type"],
        "defense_mode": state["defense_mode"],
    })
    # Persist to MongoDB
    with _log_buffer_lock:
        _log_buffer.append(log)
        should_flush = len(_log_buffer) >= LOG_FLUSH_SIZE
    if should_flush:
        _flush_log_buffer()

# ─── NORMAL TRAFFIC SIMULATION ────────────────────────────────────────────────
def simulate_normal_traffic():
    normal_events = [
        ("INFO",  "HTTP GET /index.html",     80,  "TCP"),
        ("INFO",  "HTTPS GET /api/data",      443, "TCP"),
        ("INFO",  "DNS Query: example.com",   53,  "UDP"),
        ("INFO",  "ICMP Echo Request",        0,   "ICMP"),
        ("INFO",  "NTP Sync",                 123, "UDP"),
        ("INFO",  "SSH Session Keep-alive",   22,  "TCP"),
        ("DEBUG", "ARP Request",              0,   "ARP"),
        ("INFO",  "DHCP Renewal",             67,  "UDP"),
    ]
    while True:
        if not state["attack_active"]:
            ev = random.choice(normal_events)
            log = make_log(ev[0], ev[1], port=ev[2], proto=ev[3])
            emit_log(log)
        time.sleep(random.uniform(0.3, 1.2))

# ─── ATTACK SIMULATION ────────────────────────────────────────────────────────
def run_attack(attack_key: str):
    global current_session_id
    profile = ATTACK_PROFILES[attack_key]
    state["attack_active"] = True
    state["attack_type"]   = profile["name"]
    state["network_status"] = "UNDER_ATTACK"

    current_session_id = db.start_session(
        attack_key=attack_key,
        attack_name=profile["name"],
        severity=profile["severity"],
        description=profile["description"],
    )

    set_leds("ATTACK")
    buzzer_alert(duration=0.3, pulses=5)

    emit_log(make_log(
        "CRITICAL",
        f"ATTACK DETECTED: {profile['name']}",
        extra=profile["description"],
    ))
    socketio.emit("attack_started", {"attack": profile, "key": attack_key})

    attacker_ip = random.choice(FAKE_IPS)
    ports = profile["ports"]
    attack_count = 0
    session_blocked_ips = []

    while state["attack_active"]:
        port = random.choice(ports) if ports else 0
        log  = make_log(
            "CRITICAL" if profile["severity"] == "CRITICAL" else "WARNING",
            f"[{profile['name']}] Malicious packet detected",
            src_ip=attacker_ip,
            port=port,
            extra=f"Severity={profile['severity']} Seq={attack_count}",
        )
        emit_log(log)
        attack_count += 1
        state["threats_detected"] += 1

        if attack_count % 8 == 0:
            state["blocked_ips"].add(attacker_ip)
            session_blocked_ips.append(attacker_ip)
            db.add_blocked_ip(attacker_ip,
                              reason=f"{profile['name']} auto-blocked",
                              session_id=current_session_id)
            emit_log(make_log(
                "INFO",
                f"DEFENSE: Blocked {attacker_ip} | Rule auto-applied",
                src_ip="192.168.1.1",
                dst_ip=attacker_ip,
                extra=f"Firewall rule added. Total blocked: {len(state['blocked_ips'])}",
            ))
            db.save_alert({
                "threat_type":  profile["name"],
                "severity":     profile["severity"],
                "src_ip":       attacker_ip,
                "description":  f"Auto-block after {attack_count} packets",
                "action_taken": f"IP {attacker_ip} BLOCKED",
                "confidence":   0.92,
            }, session_id=current_session_id)
            attacker_ip = random.choice(FAKE_IPS)

        time.sleep(profile["rate"])

    _flush_log_buffer()
    db.end_session(
        session_id=current_session_id,
        packets_sent=attack_count,
        threats_fired=state["threats_detected"],
        ips_blocked=list(set(session_blocked_ips)),
    )
    current_session_id = None

    state["network_status"] = "RECOVERY"
    set_leds("WARNING")
    socketio.emit("attack_stopped", {})
    emit_log(make_log("INFO", "Attack simulation terminated. Entering recovery mode."))
    time.sleep(3)
    state["network_status"] = "NORMAL"
    set_leds("NORMAL")
    emit_log(make_log("INFO", "Network status NORMAL. All defenses active."))

# ─── ROUTES ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def api_status():
    return jsonify({
        **state,
        "blocked_ips": list(state["blocked_ips"]),
        "gpio_available": GPIO_AVAILABLE,
        "db_connected": db.connected,
        "attack_profiles": {k: {
            "name": v["name"],
            "severity": v["severity"],
            "description": v["description"],
        } for k, v in ATTACK_PROFILES.items()},
    })

@app.route("/api/start_attack", methods=["POST"])
def start_attack():
    data = request.get_json()
    attack_key = data.get("attack_type", "syn_flood")
    if attack_key not in ATTACK_PROFILES:
        return jsonify({"error": "Unknown attack type"}), 400
    if state["attack_active"]:
        return jsonify({"error": "Attack already running"}), 409
    threading.Thread(target=run_attack, args=(attack_key,), daemon=True).start()
    return jsonify({"status": "started", "attack": ATTACK_PROFILES[attack_key]["name"]})

@app.route("/api/stop_attack", methods=["POST"])
def stop_attack():
    state["attack_active"] = False
    state["attack_type"]   = None
    return jsonify({"status": "stopped"})

@app.route("/api/reset", methods=["POST"])
def reset():
    state["attack_active"]   = False
    state["attack_type"]     = None
    state["packets_analyzed"] = 0
    state["threats_detected"] = 0
    state["blocked_ips"]     = set()
    state["network_status"]  = "NORMAL"
    set_leds("NORMAL")
    socketio.emit("reset", {})
    return jsonify({"status": "reset"})

@app.route("/api/toggle_defense", methods=["POST"])
def toggle_defense():
    state["defense_mode"] = "INACTIVE" if state["defense_mode"] == "ACTIVE" else "ACTIVE"
    return jsonify({"defense_mode": state["defense_mode"]})

# ─── DATABASE API ROUTES ──────────────────────────────────────────────────────
@app.route("/api/db/stats")
def api_db_stats():
    return jsonify(db.db_stats())

@app.route("/api/db/logs")
def api_db_logs():
    limit  = int(request.args.get("limit",   200))
    level  = request.args.get("level",   None)
    src_ip = request.args.get("src_ip",  None)
    since  = request.args.get("since_minutes", None)
    logs   = db.get_logs(
        limit=min(limit, 1000),
        level=level,
        src_ip=src_ip,
        since_minutes=int(since) if since else None,
    )
    return jsonify({"count": len(logs), "logs": logs})

@app.route("/api/db/sessions")
def api_db_sessions():
    limit    = int(request.args.get("limit", 50))
    sessions = db.get_sessions(limit=limit)
    return jsonify({"count": len(sessions), "sessions": sessions})

@app.route("/api/db/alerts")
def api_db_alerts():
    limit    = int(request.args.get("limit", 100))
    severity = request.args.get("severity", None)
    alerts   = db.get_alerts(limit=limit, severity=severity)
    return jsonify({"count": len(alerts), "alerts": alerts})

@app.route("/api/db/blocked_ips")
def api_db_blocked_ips():
    ips = db.get_blocked_ips()
    return jsonify({"count": len(ips), "blocked_ips": ips})

@app.route("/api/db/blocked_ips/<ip>", methods=["DELETE"])
def api_unblock_ip(ip):
    db.unblock_ip(ip)
    return jsonify({"status": "unblocked", "ip": ip})

@app.route("/api/db/snapshots")
def api_db_snapshots():
    limit     = int(request.args.get("limit", 60))
    snapshots = db.get_snapshots(limit=limit)
    return jsonify({"count": len(snapshots), "snapshots": snapshots})

@app.route("/api/db/top_attackers")
def api_top_attackers():
    return jsonify(db.top_attacker_ips(10))

@app.route("/api/db/reset", methods=["POST"])
def api_db_reset():
    db.full_reset()
    return jsonify({"status": "database cleared"})

# ─── SOCKETIO EVENTS ──────────────────────────────────────────────────────────
@socketio.on("connect")
def on_connect():
    emit("connected", {"message": "Connected to Digital Twin Monitor"})
    emit("stats_update", {
        "packets_analyzed": state["packets_analyzed"],
        "threats_detected": state["threats_detected"],
        "blocked_ips": len(state["blocked_ips"]),
        "network_status": state["network_status"],
        "attack_active": state["attack_active"],
        "attack_type": state["attack_type"],
        "defense_mode": state["defense_mode"],
    })
    emit("db_status", {"connected": db.connected, "db_name": "digital_twin"})

# ─── MAIN ─────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    gpio_setup()
    threading.Thread(target=simulate_normal_traffic, daemon=True).start()
    threading.Thread(target=_periodic_flush, daemon=True).start()
    start_snapshot_worker(lambda: {
        **state, "blocked_ips": list(state["blocked_ips"])
    }, interval_sec=60)
    try:
        print("[*] Digital Twin Attack Simulator starting on http://0.0.0.0:5000")
        socketio.run(app, host="0.0.0.0", port=5000, debug=False)
    finally:
        _flush_log_buffer()
        gpio_cleanup()
