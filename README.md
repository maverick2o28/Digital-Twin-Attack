# Digital Twin Attack Simulator
### Raspberry Pi 2W · Python · Flask · WebSockets · GPIO LEDs + Buzzer · MongoDB

A full-stack IT security lab project simulating **digital twin** network attack and defense scenarios with real-time web UI, live log streaming, physical hardware indicators on a Raspberry Pi 2W, and persistent MongoDB logging.

## Table of Contents

1. [Abstract](#abstract)
2. [Project Structure](#project-structure)
3. [Hardware: Raspberry Pi 2W Wiring](#hardware-raspberry-pi-2w-wiring)
   - [Components Needed](#components-needed)
   - [GPIO Pinout](#gpio-pinout-bcm-numbering)
   - [LED State Meanings](#led-state-meanings)
   - [Buzzer Alert Patterns](#buzzer-alert-patterns)
4. [Setup & Run](#setup--run)
   - [1. Clone and Install Dependencies](#1-clone-and-install-dependencies)
   - [2. Run the Server](#2-run-the-server)
   - [3. Test GPIO Hardware](#3-test-gpio-hardware-alone)
   - [4. Run Standalone Attack Scripts](#4-run-standalone-attack-scripts-cli)
5. [Web Dashboard Features](#web-dashboard-features)
6. [Attack Types Simulated](#attack-types-simulated)
7. [IDS/IPS Defense Rules](#idsips-defense-rules)
8. [MongoDB Database](#mongodb-database)
   - [Collections](#collections)
   - [REST API Endpoints](#rest-api-endpoints)
9. [Two-RPi Lab Setup](#two-rpi-lab-setup-offensive--defensive)
10. [Customization](#customization)
11. [Technologies Used](#technologies-used)
12. [Troubleshooting](#troubleshooting)


## Abstract

This project demonstrates the use of a **digital twin** as a real-time replica of a physical system within a simulated small business environment. A Raspberry Pi Zero 2W functions as an edge IoT device by transmitting data to a centralized dashboard that visualizes a network of virtualized office servers and services.

The project further explores how cyberattacks targeting IoT devices and data flows can manipulate the digital twin, resulting in inaccurate system representations and potential real-world consequences. This simulation highlights key challenges at the intersection of IoT, cybersecurity, and digital twin technology — with a focus on both vulnerabilities and defensive strategies.

All network events, attack sessions, IDS alerts, and blocked IPs are persisted in a local **MongoDB** database and viewable through the built-in DB Explorer panel in the web dashboard.


## Project Structure

```
digital-twin-attack/
├── backend/
│   ├── app.py               ← Flask + SocketIO server (main entrypoint)
│   ├── gpio_controller.py   ← RPi GPIO: LEDs + Buzzer control
│   ├── attack_simulator.py  ← Standalone attack scripts (CLI)
│   ├── network_analyzer.py  ← IDS/IPS engine + log parser
│   └── db_manager.py        ← MongoDB persistence layer
├── frontend/
│   ├── index.html           ← Dashboard UI
│   └── static/
│       ├── style.css        ← Dark terminal theme
│       └── app.js           ← WebSocket client, charts, topology, DB explorer
├── requirements.txt
└── README.md
```

## Hardware: Raspberry Pi 2W Wiring

### Components Needed
- Raspberry Pi Zero 2W
- 1× Green LED   (Normal traffic)
- 1× Yellow LED  (Warning / suspicious)
- 1× Red LED     (Active attack)
- 3× 220Ω resistors (for LEDs)
- 1× Active piezo buzzer
- 1× NPN transistor (e.g. 2N2222) for buzzer
- Breadboard + jumper wires

### GPIO Pinout (BCM numbering)

```
RPi 2W Pin  │ BCM  │ Connected To
────────────┼──────┼──────────────────────────────────
Pin 11      │ 17   │ 220Ω → Green  LED → GND (Pin 9)
Pin 13      │ 27   │ 220Ω → Yellow LED → GND
Pin 15      │ 22   │ 220Ω → Red    LED → GND
Pin 12      │ 18   │ NPN base → Buzzer+ (5V) → GND
Pin 2       │ 5V   │ Buzzer VCC (via transistor)
Pin 6,9,14  │ GND  │ Common ground
```

### LED State Meanings

| State        | LED       | Meaning                         |
|--------------|-----------|---------------------------------|
| NORMAL       | Green  | Normal traffic flowing          |
| WARNING      | Yellow | Suspicious / recovery mode      |
| UNDER_ATTACK | Red    | Active attack + buzzer sounding |

### Buzzer Alert Patterns
- **Attack start:** 5 short pulses
- **Ongoing attack:** Continuous while red LED is on
- **Recovery:** 2 long pulses, then off


## Setup & Run

### 1. Clone and Install Dependencies

```bash
git clone <repo> digital-twin-attack
cd digital-twin-attack
```

**Install with `apt` (recommended on Raspberry Pi OS):**

```bash
sudo apt update

# Core Python packages
sudo apt install -y python3-flask
sudo apt install -y python3-flask-socketio
sudo apt install -y python3-pymongo

# GPIO (already available on RPi OS, but just in case)
sudo apt install -y python3-rpi.gpio

# MongoDB database
sudo apt install -y mongodb
sudo systemctl enable mongodb
sudo systemctl start mongodb
```

**Or all in one line:**

```bash
sudo apt update && sudo apt install -y \
  python3-flask python3-flask-socketio \
  python3-pymongo python3-rpi.gpio mongodb
sudo systemctl enable mongodb && sudo systemctl start mongodb
```

> **Note on `eventlet`:** If `python3-eventlet` is unavailable in your repo version, fall back to pip:
> ```bash
> sudo apt install -y python3-eventlet   # try apt first
> # if not found:
> pip3 install eventlet --break-system-packages
> ```

**Verify all imports are working:**

```bash
python3 -c "import flask; import flask_socketio; import pymongo; print('All imports OK')"
```

### 2. Run the Server

```bash
cd backend
python3 app.py
```

Open browser → `http://<rpi-ip>:5000`

Or on your desktop (demo mode, no GPIO):
```bash
python3 app.py
# Open http://localhost:5000
```

### 3. Test GPIO Hardware Alone

```bash
python3 backend/gpio_controller.py test
```

### 4. Run Standalone Attack Scripts (CLI)

```bash
# SYN Flood for 30 seconds
python3 backend/attack_simulator.py syn_flood --target 192.168.1.100 --duration 30

# Port scan
python3 backend/attack_simulator.py port_scan --target 192.168.1.100

# SSH brute force simulation
python3 backend/attack_simulator.py brute_force --target 192.168.1.100

# ARP spoofing simulation
python3 backend/attack_simulator.py arp_spoof --target 192.168.1.100 --gateway 192.168.1.1

# DNS amplification simulation
python3 backend/attack_simulator.py dns_amp --target 192.168.1.100 --duration 20
```

> **Note:** Raw socket attacks (SYN flood) require `sudo`. Only use on your own lab network.

## Web Dashboard Features

| Feature | Description |
|---------|-------------|
| **Live Network Log** | Real-time scrolling log with color-coded severity levels |
| **Traffic Rate Chart** | 60-second rolling packet/second chart |
| **Network Topology** | Animated canvas showing Internet → Router → RPi → Devices |
| **Attack Launcher** | 5 attack types: SYN Flood, ARP Spoof, Port Scan, Brute Force, DNS Amp |
| **Defense Stats** | Packets analyzed, threats detected, blocked IPs |
| **GPIO Indicators** | Virtual LED/buzzer mirror in the UI header |
| **Alert Overlay** | Full-screen attack alert with acknowledge |
| **MongoDB Explorer** | Built-in DB browser: logs, sessions, alerts, blocked IPs |
| **Demo Mode** | Works fully without backend (simulates in-browser) |

## Attack Types Simulated
**SYN Flood (DDoS) — CRITICAL**
Floods target with TCP SYN packets from spoofed IPs, exhausting connection tables. Requires root for raw sockets.

**ARP Spoofing / MITM — HIGH**
Poisons ARP cache tables so traffic is intercepted by the attacker (man-in-the-middle).

**Port Scan — MEDIUM**
Enumerates all open ports on target (Nmap-style), revealing running services.

**SSH Brute Force — HIGH**
Tries common username/password combinations against SSH service.

**DNS Amplification — CRITICAL**
Sends small spoofed DNS queries to open resolvers; large responses flood the victim.

## IDS/IPS Defense Rules

The `network_analyzer.py` IDS engine watches for:

| Rule    | Trigger                              | Action    |
|---------|--------------------------------------|-----------|
| IDS-001 | >100 SYN from same IP in 5s          | BLOCK IP  |
| IDS-002 | >20 unique ports from same IP in 10s | ALERT     |
| IDS-003 | >15 SSH attempts in 60s              | THROTTLE  |
| IDS-004 | >50 DNS from same IP in 5s           | BLOCK IP  |
| IDS-005 | >500 total packets/sec               | ALERT     |


## MongoDB Database

All events are persisted locally via `backend/db_manager.py`. The system operates in **stub mode** (silent no-ops) if MongoDB is not running, so the app always starts regardless.

### Collections

| Collection        | Contents                                                   |
|-------------------|------------------------------------------------------------|
| `network_logs`    | Every packet/event (bulk-buffered, flushed every 20 pkts)  |
| `attack_sessions` | Per-attack records: start/end time, duration, packet count |
| `threat_alerts`   | IDS/IPS-fired alerts with severity and confidence score    |
| `blocked_ips`     | Firewall block list with timestamps (upsert, no dupes)     |
| `stats_snapshots` | 60-second rolling snapshots for trend analysis             |

### REST API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/db/stats` | Collection counts, DB size, aggregations |
| `GET` | `/api/db/logs` | Query logs (filter: `level`, `src_ip`, `since_minutes`) |
| `GET` | `/api/db/sessions` | All recorded attack sessions |
| `GET` | `/api/db/alerts` | IDS/IPS alerts (filter: `severity`) |
| `GET` | `/api/db/blocked_ips` | Currently blocked IP list |
| `DELETE` | `/api/db/blocked_ips/<ip>` | Unblock a specific IP |
| `GET` | `/api/db/top_attackers` | Top 10 attacker IPs by packet count |
| `GET` | `/api/db/snapshots` | Historical stats snapshots |
| `POST` | `/api/db/reset` | Wipe all collections |


## Two-RPi Lab Setup (Offensive + Defensive)

```
[RPi #1 — ATTACKER]          [RPi #2 — DEFENDER / MONITOR]
  attack_simulator.py    →      app.py (web dashboard)
  Red LED = attacking           Green/Yellow/Red LEDs
  Buzzer = attack active        Buzzer = attack received
        └────── Same LAN ──────┘
              192.168.1.x
```

1. Run `app.py` on the **defender** RPi → opens dashboard on port 5000
2. Run `attack_simulator.py` on the **attacker** RPi targeting defender's IP
3. Watch logs stream in real-time on the web UI
4. Physical LEDs + buzzer respond to detected threats


## Customization

- **Add attack profiles:** Edit `ATTACK_PROFILES` dict in `app.py`
- **Add IDS rules:** Add to `IDS_RULES` list in `network_analyzer.py`
- **Change GPIO pins:** Edit `PINS` dict in `app.py` or `PIN_*` constants in `gpio_controller.py`
- **Adjust log retention:** Change `maxLogRows` in `app.js`
- **Change attack duration:** Edit the `duration` param or auto-stop timer
- **Change DB flush rate:** Edit `LOG_FLUSH_SIZE` / `LOG_FLUSH_SECS` in `app.py`
- **Change snapshot interval:** Edit `interval_sec` in `start_snapshot_worker()` call in `app.py`


## Technologies Used

- **Python 3** — Core language
- **Flask + Flask-SocketIO** — Web server + WebSockets
- **RPi.GPIO** — Hardware GPIO control
- **Socket.IO** — Real-time browser ↔ server communication
- **MongoDB + PyMongo** — Local persistent database
- **HTML5 Canvas** — Traffic chart + topology map
- **CSS3 Animations** — Scanlines, glow effects, attack flicker
- **Vanilla JS** — No frameworks needed

## Troubleshooting

**MongoDB won't start:**
```bash
sudo systemctl status mongodb
sudo systemctl restart mongodb
# Check logs:
sudo journalctl -u mongodb -n 50
```

**`python3-flask-socketio` not found via apt:**
```bash
pip3 install flask-socketio --break-system-packages
```

**GPIO permission denied:**
```bash
sudo usermod -aG gpio $USER
# Then log out and back in
```

**Port 5000 already in use:**
```bash
sudo lsof -i :5000
# Change port in app.py: socketio.run(app, host="0.0.0.0", port=5001)
```

**Dashboard loads but no logs appear:**
- Check that the backend is running (`python3 app.py`)
- Check browser console for WebSocket errors
- Try opening `http://localhost:5000/api/status` to confirm the API is responding

*Educational use only. Only run attack simulations on networks and devices you own or have explicit written permission to test.*
