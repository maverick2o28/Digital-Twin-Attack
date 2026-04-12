/* ─── DIGITAL TWIN MONITOR — FRONTEND APP ─── */

"use strict";

// ─── SOCKET CONNECTION ────────────────────────────────────────────────────────
const socket = io();
let logPaused = false;
let maxLogRows = 300;
let packetHistory = new Array(60).fill(0);
let lastPacketCount = 0;
let attackActive = false;

// ─── CLOCK ────────────────────────────────────────────────────────────────────
function updateClock() {
  const now = new Date();
  document.getElementById("clock").textContent =
    now.toTimeString().slice(0, 8);
}
setInterval(updateClock, 1000);
updateClock();

// ─── SOCKET EVENTS ────────────────────────────────────────────────────────────
socket.on("connect", () => {
  addLogRow({
    timestamp: new Date().toISOString().replace("T"," ").slice(0,23),
    level: "INFO",
    src_ip: "localhost",
    dst_ip: "monitor",
    port: 5000,
    proto: "WS",
    event: "WebSocket connected to Digital Twin backend",
    extra: ""
  });
});

socket.on("network_log", (log) => {
  if (!logPaused) addLogRow(log);
  bumpPacketTick();
});

socket.on("stats_update", (stats) => {
  updateStats(stats);
});

socket.on("attack_started", (data) => {
  const { attack } = data;
  showAttackBanner(attack.name);
  showAlertOverlay(attack.name, attack.description, attack.severity);
  document.getElementById("btn-stop").disabled = false;
  document.querySelectorAll(".attack-btn").forEach(b => b.disabled = true);
  document.querySelector(`[data-attack="${data.key}"]`)?.classList.add("active");
  document.body.classList.add("attack-mode");
  attackActive = true;
  setHWLEDs("ATTACK");
});

socket.on("attack_stopped", () => {
  hideAttackBanner();
  document.getElementById("btn-stop").disabled = true;
  document.querySelectorAll(".attack-btn").forEach(b => {
    b.disabled = false;
    b.classList.remove("active");
  });
  document.body.classList.remove("attack-mode");
  attackActive = false;
  setHWLEDs("WARNING");
  setTimeout(() => setHWLEDs("NORMAL"), 3000);
});

socket.on("reset", () => {
  clearLog();
  updateStats({ packets_analyzed: 0, threats_detected: 0, blocked_ips: 0,
                network_status: "NORMAL", attack_active: false, defense_mode: "ACTIVE" });
  packetHistory = new Array(60).fill(0);
  drawChart();
});

// ─── LOG RENDERING ────────────────────────────────────────────────────────────
function addLogRow(log) {
  const container = document.getElementById("log-container");
  const row = document.createElement("div");
  const level = (log.level || "INFO").toUpperCase();
  row.className = `log-row ${level === "CRITICAL" ? "critical" : level === "WARNING" ? "warning" : "info"}`;
  const ts = log.timestamp ? log.timestamp.split(" ")[1] || log.timestamp : "—";
  row.innerHTML = `
    <span class="log-ts">${escHtml(ts)}</span>
    <span class="log-level ${level}">${level}</span>
    <span class="log-ip">${escHtml(log.src_ip || "—")}</span>
    <span class="log-port">${log.port || "—"}</span>
    <span class="log-proto">${escHtml(log.proto || "—")}</span>
    <span class="log-event ${log.extra ? 'has-extra' : ''}">${escHtml(log.event || "—")}${log.extra ? " · "+escHtml(log.extra) : ""}</span>
  `;
  container.insertBefore(row, container.firstChild);
  // Trim old rows
  while (container.children.length > maxLogRows) {
    container.removeChild(container.lastChild);
  }
}

function escHtml(str) {
  return String(str)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
}

function toggleLogPause() {
  logPaused = !logPaused;
  const btn = document.getElementById("btn-pause-log");
  btn.textContent = logPaused ? "▶ RESUME" : "⏸ PAUSE";
}

function clearLog() {
  document.getElementById("log-container").innerHTML = "";
}

// ─── STATS ────────────────────────────────────────────────────────────────────
function updateStats(stats) {
  setEl("stat-packets", fmt(stats.packets_analyzed));
  setEl("stat-threats", fmt(stats.threats_detected));
  setEl("stat-blocked", fmt(stats.blocked_ips));
  setEl("stat-defense", stats.defense_mode || "ACTIVE");

  // Progress bars (relative / capped)
  setBarWidth("bar-packets", Math.min(100, (stats.packets_analyzed / 5000) * 100));
  setBarWidth("bar-threats", Math.min(100, (stats.threats_detected / 100) * 100));
  setBarWidth("bar-blocked", Math.min(100, (stats.blocked_ips / 50) * 100));

  // Status pill
  const status = stats.network_status || "NORMAL";
  setEl("status-label", status.replace("_", " "));
  const dot = document.getElementById("status-dot");
  dot.className = "status-dot";
  if (status === "UNDER_ATTACK") dot.classList.add("red");
  else if (status === "WARNING" || status === "RECOVERY") dot.classList.add("yellow");

  // Status pill border color
  const pill = document.getElementById("network-status-pill");
  pill.style.borderColor =
    status === "UNDER_ATTACK" ? "var(--accent-red)" :
    status === "RECOVERY"     ? "var(--accent-yellow)" :
                                "var(--border-glow)";
}

function setEl(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function setBarWidth(id, pct) {
  const el = document.getElementById(id);
  if (el) el.style.width = pct + "%";
}

function fmt(n) {
  if (n >= 1000000) return (n/1000000).toFixed(1) + "M";
  if (n >= 1000)    return (n/1000).toFixed(1) + "K";
  return String(n);
}

// ─── HARDWARE LED SIMULATION ──────────────────────────────────────────────────
function setHWLEDs(mode) {
  const g = document.getElementById("hw-green");
  const y = document.getElementById("hw-yellow");
  const r = document.getElementById("hw-red");
  g.classList.remove("active");
  y.classList.remove("active");
  r.classList.remove("active");
  if (mode === "NORMAL")  g.classList.add("active");
  if (mode === "WARNING") y.classList.add("active");
  if (mode === "ATTACK")  r.classList.add("active");
}
setHWLEDs("NORMAL");

// ─── TRAFFIC RATE CHART ───────────────────────────────────────────────────────
const chartCanvas = document.getElementById("traffic-chart");
const ctx = chartCanvas.getContext("2d");
let pktPerSecond = 0;

function bumpPacketTick() {
  pktPerSecond++;
}

setInterval(() => {
  packetHistory.push(pktPerSecond);
  packetHistory.shift();
  pktPerSecond = 0;
  drawChart();
}, 1000);

function drawChart() {
  const W = chartCanvas.width;
  const H = chartCanvas.height;
  const pad = { t: 10, r: 8, b: 24, l: 32 };
  ctx.clearRect(0, 0, W, H);

  // Background grid
  ctx.strokeStyle = "rgba(13,58,92,0.4)";
  ctx.lineWidth = 0.5;
  for (let i = 0; i <= 4; i++) {
    const y = pad.t + ((H - pad.t - pad.b) / 4) * i;
    ctx.beginPath(); ctx.moveTo(pad.l, y); ctx.lineTo(W - pad.r, y); ctx.stroke();
  }

  const max = Math.max(...packetHistory, 10);
  const iW = (W - pad.l - pad.r) / (packetHistory.length - 1);
  const iH = H - pad.t - pad.b;

  // Gradient fill
  const grad = ctx.createLinearGradient(0, pad.t, 0, H - pad.b);
  if (attackActive) {
    grad.addColorStop(0, "rgba(255,34,68,0.4)");
    grad.addColorStop(1, "rgba(255,34,68,0)");
  } else {
    grad.addColorStop(0, "rgba(0,212,255,0.3)");
    grad.addColorStop(1, "rgba(0,212,255,0)");
  }

  ctx.beginPath();
  ctx.moveTo(pad.l, H - pad.b);
  packetHistory.forEach((v, i) => {
    const x = pad.l + i * iW;
    const y = pad.t + iH * (1 - v / max);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.lineTo(pad.l + (packetHistory.length - 1) * iW, H - pad.b);
  ctx.closePath();
  ctx.fillStyle = grad;
  ctx.fill();

  // Line
  ctx.beginPath();
  ctx.lineWidth = 1.5;
  ctx.strokeStyle = attackActive ? "#ff2244" : "#00d4ff";
  ctx.shadowColor  = attackActive ? "#ff2244" : "#00d4ff";
  ctx.shadowBlur   = 6;
  packetHistory.forEach((v, i) => {
    const x = pad.l + i * iW;
    const y = pad.t + iH * (1 - v / max);
    i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
  });
  ctx.stroke();
  ctx.shadowBlur = 0;

  // Y labels
  ctx.fillStyle = "rgba(74,122,155,0.8)";
  ctx.font = "9px 'Share Tech Mono'";
  ctx.textAlign = "right";
  ctx.fillText(max, pad.l - 3, pad.t + 4);
  ctx.fillText(Math.round(max/2), pad.l - 3, pad.t + iH/2 + 4);
  ctx.fillText("0", pad.l - 3, H - pad.b + 4);

  // X label
  ctx.textAlign = "center";
  ctx.fillText("60s", W/2, H);
}
drawChart();

// ─── TOPOLOGY MAP ─────────────────────────────────────────────────────────────
const topoCanvas = document.getElementById("topo-canvas");
const tCtx = topoCanvas.getContext("2d");

const NODES = [
  { id: "internet",  label: "INTERNET",   x: 0.15, y: 0.5,  color: "#4a7a9b",  r: 18 },
  { id: "router",    label: "ROUTER",     x: 0.38, y: 0.5,  color: "#00d4ff",  r: 14 },
  { id: "rpi",       label: "RPi 2W",     x: 0.62, y: 0.5,  color: "#00ff88",  r: 16 },
  { id: "pc1",       label: "PC-1",       x: 0.82, y: 0.22, color: "#7ec8e3",  r: 10 },
  { id: "pc2",       label: "PC-2",       x: 0.82, y: 0.5,  color: "#7ec8e3",  r: 10 },
  { id: "pc3",       label: "PC-3",       x: 0.82, y: 0.78, color: "#7ec8e3",  r: 10 },
];
const LINKS = [
  ["internet","router"],["router","rpi"],
  ["rpi","pc1"],["rpi","pc2"],["rpi","pc3"]
];

let topoAttackActive = false;
let topoAnimFrame = 0;

function drawTopo() {
  const W = topoCanvas.width;
  const H = topoCanvas.height;
  tCtx.clearRect(0, 0, W, H);

  // Draw links
  LINKS.forEach(([a, b]) => {
    const na = NODES.find(n => n.id === a);
    const nb = NODES.find(n => n.id === b);
    const ax = na.x * W, ay = na.y * H;
    const bx = nb.x * W, by = nb.y * H;

    tCtx.beginPath();
    tCtx.moveTo(ax, ay); tCtx.lineTo(bx, by);
    tCtx.lineWidth = 1;
    tCtx.strokeStyle = topoAttackActive && (a === "internet" || b === "router" || a === "router")
      ? "rgba(255,34,68,0.5)" : "rgba(0,212,255,0.25)";
    tCtx.stroke();

    // Animated packet dot
    const t = (topoAnimFrame / 40 + LINKS.indexOf([a,b]) * 0.2) % 1;
    const px = ax + (bx - ax) * t;
    const py = ay + (by - ay) * t;
    tCtx.beginPath();
    tCtx.arc(px, py, 2.5, 0, Math.PI * 2);
    tCtx.fillStyle = topoAttackActive ? "#ff2244" : "#00d4ff";
    tCtx.fill();
  });

  // Draw nodes
  NODES.forEach(node => {
    const x = node.x * W, y = node.y * H;
    const isAttacked = topoAttackActive && (node.id === "rpi" || node.id === "router");
    const r = node.r;

    // Glow
    const gCol = isAttacked ? "#ff2244" : node.color;
    tCtx.shadowColor = gCol;
    tCtx.shadowBlur = isAttacked ? 18 : 8;

    tCtx.beginPath();
    tCtx.arc(x, y, r, 0, Math.PI * 2);
    tCtx.fillStyle = isAttacked ? "rgba(255,34,68,0.2)" : "rgba(8,15,21,0.8)";
    tCtx.strokeStyle = isAttacked ? "#ff2244" : node.color;
    tCtx.lineWidth = 1.5;
    tCtx.fill();
    tCtx.stroke();
    tCtx.shadowBlur = 0;

    // Label
    tCtx.fillStyle = node.color;
    tCtx.font = `bold 7px 'Share Tech Mono'`;
    tCtx.textAlign = "center";
    tCtx.textBaseline = "middle";
    tCtx.fillText(node.label, x, y + r + 9);
  });

  topoAnimFrame = (topoAnimFrame + 1) % 40;
  requestAnimationFrame(drawTopo);
}
drawTopo();

socket.on("attack_started", () => { topoAttackActive = true; });
socket.on("attack_stopped", () => { topoAttackActive = false; });

// ─── ATTACK CONTROLS ──────────────────────────────────────────────────────────
async function launchAttack(attackType) {
  try {
    const res = await fetch("/api/start_attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attack_type: attackType })
    });
    const data = await res.json();
    if (!res.ok) console.error("Attack error:", data.error);
  } catch (e) {
    console.error("Network error:", e);
    // Demo mode: simulate locally if backend not reachable
    simulateAttackLocally(attackType);
  }
}

async function stopAttack() {
  try {
    await fetch("/api/stop_attack", { method: "POST" });
  } catch (e) {
    // Demo mode
    socket.emit("demo_stop");
    hideAttackBanner();
    attackActive = false;
    topoAttackActive = false;
    document.body.classList.remove("attack-mode");
    document.getElementById("btn-stop").disabled = true;
    document.querySelectorAll(".attack-btn").forEach(b => {
      b.disabled = false; b.classList.remove("active");
    });
    setHWLEDs("NORMAL");
  }
}

async function resetAll() {
  try {
    await fetch("/api/reset", { method: "POST" });
  } catch (e) {
    clearLog();
    packetHistory = new Array(60).fill(0);
    attackActive = false;
    topoAttackActive = false;
    hideAttackBanner();
    document.body.classList.remove("attack-mode");
    setHWLEDs("NORMAL");
    updateStats({ packets_analyzed: 0, threats_detected: 0, blocked_ips: 0,
                  network_status: "NORMAL", attack_active: false, defense_mode: "ACTIVE" });
  }
}

// ─── DEMO MODE (no backend) ───────────────────────────────────────────────────
const ATTACK_PROFILES_CLIENT = {
  syn_flood:       { name: "SYN Flood DDoS",      severity: "CRITICAL", description: "TCP SYN flood overwhelming target ports" },
  arp_spoofing:    { name: "ARP Spoofing / MITM",  severity: "HIGH",     description: "ARP cache poisoning for MITM" },
  port_scan:       { name: "Port Scan",            severity: "MEDIUM",   description: "Systematic port enumeration" },
  brute_force:     { name: "SSH Brute Force",      severity: "HIGH",     description: "Credential stuffing on SSH" },
  dns_amplification:{ name: "DNS Amplification",  severity: "CRITICAL", description: "DNS reflection/amplification DDoS" },
};

let demoInterval = null;
let demoStats = { packets_analyzed: 0, threats_detected: 0, blocked_ips: 0 };

function simulateAttackLocally(attackType) {
  const profile = ATTACK_PROFILES_CLIENT[attackType] || ATTACK_PROFILES_CLIENT.syn_flood;
  attackActive = true;
  topoAttackActive = true;
  document.body.classList.add("attack-mode");
  document.getElementById("btn-stop").disabled = false;
  document.querySelectorAll(".attack-btn").forEach(b => b.disabled = true);
  document.querySelector(`[data-attack="${attackType}"]`)?.classList.add("active");
  setHWLEDs("ATTACK");
  showAttackBanner(profile.name);
  showAlertOverlay(profile.name, profile.description, profile.severity);
  updateStats({ packets_analyzed: demoStats.packets_analyzed,
                threats_detected: demoStats.threats_detected,
                blocked_ips: demoStats.blocked_ips,
                network_status: "UNDER_ATTACK", attack_active: true, defense_mode: "ACTIVE" });

  const ATTACKER_IPS = Array.from({length:20}, (_,i)=>`${rndInt(1,223)}.${rndInt(0,255)}.${rndInt(0,255)}.${rndInt(1,254)}`);
  const PORTS = [22, 80, 443, 8080, 53, 3389, 21];
  let localAttackerIdx = 0;

  demoInterval = setInterval(() => {
    const attIp = ATTACKER_IPS[localAttackerIdx % ATTACKER_IPS.length];
    demoStats.packets_analyzed += rndInt(3,12);
    demoStats.threats_detected += 1;
    if (demoStats.threats_detected % 8 === 0) {
      demoStats.blocked_ips++;
      localAttackerIdx++;
      addLogRow({ timestamp: nowTs(), level: "INFO",
        src_ip: "192.168.1.1", dst_ip: attIp,
        port: 0, proto: "FW",
        event: `🛡 DEFENSE: Blocked ${attIp}`, extra: `Total blocked: ${demoStats.blocked_ips}` });
    }
    addLogRow({ timestamp: nowTs(), level: profile.severity === "CRITICAL" ? "CRITICAL" : "WARNING",
      src_ip: attIp, dst_ip: "192.168.1.100",
      port: PORTS[rndInt(0, PORTS.length-1)], proto: "TCP",
      event: `[${profile.name}] Malicious packet detected`, extra: `Seq=${demoStats.threats_detected}` });

    updateStats({ packets_analyzed: demoStats.packets_analyzed,
                  threats_detected: demoStats.threats_detected,
                  blocked_ips: demoStats.blocked_ips,
                  network_status: "UNDER_ATTACK", attack_active: true, defense_mode: "ACTIVE" });
    bumpPacketTick(); bumpPacketTick(); bumpPacketTick();
  }, 150);

  // Normal traffic alongside attack
  const normalInterval = setInterval(() => {
    if (!attackActive) { clearInterval(normalInterval); return; }
    addLogRow({ timestamp: nowTs(), level: "INFO",
      src_ip: `192.168.1.${rndInt(2,20)}`, dst_ip: "192.168.1.100",
      port: [80,443,53][rndInt(0,2)], proto: "TCP",
      event: "HTTP GET /status", extra: "" });
    bumpPacketTick();
  }, 800);

  // Auto-stop after 45 seconds
  setTimeout(() => {
    if (attackActive) stopDemoAttack();
  }, 45000);

  function stopDemoAttack() {
    clearInterval(demoInterval);
    attackActive = false;
    topoAttackActive = false;
    document.body.classList.remove("attack-mode");
    document.getElementById("btn-stop").disabled = true;
    document.querySelectorAll(".attack-btn").forEach(b => { b.disabled=false; b.classList.remove("active"); });
    hideAttackBanner();
    setHWLEDs("WARNING");
    addLogRow({ timestamp: nowTs(), level: "INFO",
      src_ip: "monitor", dst_ip: "all",
      port: 0, proto: "SYS",
      event: "✅ Attack simulation terminated. Network recovering.", extra: "" });
    setTimeout(() => setHWLEDs("NORMAL"), 3000);
    updateStats({ packets_analyzed: demoStats.packets_analyzed,
                  threats_detected: demoStats.threats_detected,
                  blocked_ips: demoStats.blocked_ips,
                  network_status: "RECOVERY", attack_active: false, defense_mode: "ACTIVE" });
  }

  // Override stopAttack for demo
  document.getElementById("btn-stop").onclick = () => {
    clearInterval(demoInterval);
    stopDemoAttack();
  };
}

// ─── ALERT OVERLAY ────────────────────────────────────────────────────────────
function showAlertOverlay(name, desc, severity) {
  document.getElementById("alert-type").textContent =
    severity === "CRITICAL" ? "⚠ CRITICAL ATTACK DETECTED" : "⚠ ATTACK DETECTED";
  document.getElementById("alert-msg").textContent =
    `${name}\n\n${desc}\n\nRaspberry Pi GPIO: RED LED + BUZZER ACTIVATED`;
  document.getElementById("alert-overlay").classList.remove("hidden");
}
function dismissAlert() {
  document.getElementById("alert-overlay").classList.add("hidden");
}

// ─── ATTACK BANNER ────────────────────────────────────────────────────────────
function showAttackBanner(name) {
  document.getElementById("banner-name").textContent = name;
  document.getElementById("attack-banner").classList.remove("hidden");
  const bar = document.getElementById("attack-progress");
  bar.style.animation = "none";
  bar.offsetHeight; // reflow
  bar.style.animation = "";
}
function hideAttackBanner() {
  document.getElementById("attack-banner").classList.add("hidden");
}

// ─── DEMO STARTUP ─────────────────────────────────────────────────────────────
// If we can't connect to the backend, start demo normal traffic after 2s
setTimeout(async () => {
  if (!socket.connected) {
    startDemoNormalTraffic();
    setHWLEDs("NORMAL");
  }
  // Load initial status
  try {
    const res = await fetch("/api/status");
    const data = await res.json();
    updateStats(data);
  } catch (e) {
    startDemoNormalTraffic();
  }
}, 2000);

function startDemoNormalTraffic() {
  const NORMAL_EVENTS = [
    ["INFO",  "HTTP GET /index.html",    80,  "TCP"],
    ["INFO",  "HTTPS POST /api/login",  443,  "TCP"],
    ["INFO",  "DNS Query: google.com",   53,  "UDP"],
    ["INFO",  "ICMP Echo Request",        0, "ICMP"],
    ["DEBUG", "ARP Request",              0,  "ARP"],
    ["INFO",  "NTP Sync request",       123,  "UDP"],
    ["INFO",  "SSH Keepalive",           22,  "TCP"],
  ];
  const NORMAL_IPS = Array.from({length:10}, (_,i) => `192.168.1.${i+2}`);
  let normalDemoStats = { packets_analyzed: 0, threats_detected: 0, blocked_ips: 0 };

  setInterval(() => {
    if (attackActive) return;
    const ev = NORMAL_EVENTS[rndInt(0, NORMAL_EVENTS.length-1)];
    addLogRow({
      timestamp: nowTs(), level: ev[0],
      src_ip: NORMAL_IPS[rndInt(0,9)],
      dst_ip: "192.168.1.100",
      port: ev[2], proto: ev[3], event: ev[1], extra: ""
    });
    normalDemoStats.packets_analyzed++;
    bumpPacketTick();
    updateStats({ packets_analyzed: normalDemoStats.packets_analyzed,
                  threats_detected: normalDemoStats.threats_detected,
                  blocked_ips: normalDemoStats.blocked_ips,
                  network_status: "NORMAL", attack_active: false, defense_mode: "ACTIVE" });
    demoStats = normalDemoStats;
  }, 600);
}

// ─── UTILS ────────────────────────────────────────────────────────────────────
function rndInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
function nowTs() {
  return new Date().toISOString().replace("T"," ").slice(0,23);
}

// ─── DB EXPLORER ──────────────────────────────────────────────────────────────
let currentDbTab = "overview";

// Handle db_status socket event
socket.on("db_status", (data) => {
  setDbBadge(data.connected);
});

function setDbBadge(connected) {
  const dot = document.getElementById("db-dot");
  if (!dot) return;
  dot.className = "db-dot " + (connected ? "connected" : "disconnected");
  const badge = document.getElementById("db-badge");
  if (badge) badge.title = connected ? "MongoDB connected" : "MongoDB offline (stub mode)";
}

function openDbModal() {
  document.getElementById("db-modal").classList.remove("hidden");
  loadDbTab(currentDbTab);
}

function closeDbModal() {
  document.getElementById("db-modal").classList.add("hidden");
}

// Close on backdrop click
document.addEventListener("DOMContentLoaded", () => {
  const modal = document.getElementById("db-modal");
  if (modal) {
    modal.addEventListener("click", (e) => {
      if (e.target === modal) closeDbModal();
    });
  }
});

function switchDbTab(tab) {
  currentDbTab = tab;
  document.querySelectorAll(".db-tab").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(".db-tab-content").forEach(c => c.classList.add("hidden"));
  document.querySelector(`[data-tab="${tab}"]`)?.classList.add("active");
  document.getElementById(`db-tab-${tab}`)?.classList.remove("hidden");
  loadDbTab(tab);
}

function loadDbTab(tab) {
  if (tab === "overview")  fetchDbOverview();
  if (tab === "logs")      fetchDbLogs();
  if (tab === "sessions")  fetchDbSessions();
  if (tab === "alerts")    fetchDbAlerts();
  if (tab === "blocked")   fetchDbBlocked();
}

// ── OVERVIEW ─────────────────────────────────────────────────────────────────
async function fetchDbOverview() {
  const el = document.getElementById("db-overview-content");
  if (!el) return;
  el.innerHTML = '<div class="db-loading">Querying MongoDB…</div>';
  try {
    const res  = await fetch("/api/db/stats");
    const data = await res.json();
    renderDbOverview(data);
    setDbBadge(data.connected);
  } catch (e) {
    el.innerHTML = '<div class="db-loading">Backend offline — demo mode active</div>';
    setDbBadge(false);
  }
}

function renderDbOverview(data) {
  const el = document.getElementById("db-overview-content");
  const cols = data.collections || {};
  const statusColor = data.connected ? "green" : "red";
  const statusText  = data.connected ? "CONNECTED" : "OFFLINE";

  let topAttackers = "";
  const attackers = data.top_attackers || [];
  const maxCount  = attackers[0]?.count || 1;
  attackers.forEach(a => {
    const pct = Math.round((a.count / maxCount) * 100);
    topAttackers += `
      <div class="db-rank-row">
        <span class="db-rank-ip">${escHtml(a.ip || "—")}</span>
        <div class="db-rank-bar"><div class="db-rank-bar-fill red" style="width:${pct}%"></div></div>
        <span class="db-rank-count">${a.count} pkts</span>
      </div>`;
  });
  if (!topAttackers) topAttackers = '<div class="db-empty">No attack data yet</div>';

  let freqHtml = "";
  (data.attack_frequency || []).forEach(f => {
    freqHtml += `
      <div class="db-rank-row">
        <span class="db-rank-ip">${escHtml(f.name || f.attack_key)}</span>
        <span class="db-rank-count">${f.count} sessions</span>
      </div>`;
  });
  if (!freqHtml) freqHtml = '<div class="db-empty">No sessions recorded yet</div>';

  const sev  = data.severity_breakdown || {};
  const sevHtml = Object.entries(sev).map(([k,v]) =>
    `<div class="db-rank-row"><span class="db-rank-ip">${k}</span><span class="db-rank-count">${v}</span></div>`
  ).join("") || '<div class="db-empty">No alerts yet</div>';

  el.innerHTML = `
    <div class="db-overview-grid">
      <div class="db-stat-box">
        <div class="db-stat-box-label">CONNECTION</div>
        <div class="db-stat-box-value ${statusColor}">${statusText}</div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">DATABASE</div>
        <div class="db-stat-box-value">${escHtml(data.db_name || "digital_twin")}</div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">DATA SIZE</div>
        <div class="db-stat-box-value">${data.data_size_mb ?? "—"} <small style="font-size:0.6rem;color:var(--text-dim)">MB</small></div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">NETWORK LOGS</div>
        <div class="db-stat-box-value">${fmt(cols.network_logs ?? 0)}</div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">ATTACK SESSIONS</div>
        <div class="db-stat-box-value yellow">${fmt(cols.attack_sessions ?? 0)}</div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">THREAT ALERTS</div>
        <div class="db-stat-box-value red">${fmt(cols.threat_alerts ?? 0)}</div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">BLOCKED IPs</div>
        <div class="db-stat-box-value red">${fmt(cols.blocked_ips ?? 0)}</div>
      </div>
      <div class="db-stat-box">
        <div class="db-stat-box-label">STATS SNAPSHOTS</div>
        <div class="db-stat-box-value">${fmt(cols.stats_snapshots ?? 0)}</div>
      </div>
    </div>
    <div class="db-section-title">TOP ATTACKER IPs (by packet count)</div>
    ${topAttackers}
    <div class="db-section-title">ATTACK FREQUENCY (by session count)</div>
    ${freqHtml}
    <div class="db-section-title">ALERT SEVERITY BREAKDOWN</div>
    ${sevHtml}
  `;
}

// ── LOGS TABLE ────────────────────────────────────────────────────────────────
async function fetchDbLogs() {
  const el = document.getElementById("db-logs-table");
  if (!el) return;
  el.innerHTML = '<div class="db-loading">Querying network_logs…</div>';
  const level = document.getElementById("db-log-level")?.value || "";
  const ip    = document.getElementById("db-log-ip")?.value.trim() || "";
  const since = document.getElementById("db-log-since")?.value || "";
  const params = new URLSearchParams({ limit: 200 });
  if (level) params.set("level",   level);
  if (ip)    params.set("src_ip",  ip);
  if (since) params.set("since_minutes", since);
  try {
    const res  = await fetch("/api/db/logs?" + params);
    const data = await res.json();
    renderLogsTable(el, data.logs || [], data.count);
    document.getElementById("db-footer-note").textContent =
      `${data.count} records returned`;
  } catch (e) {
    el.innerHTML = '<div class="db-empty">Backend offline</div>';
  }
}

function renderLogsTable(el, rows, total) {
  if (!rows.length) { el.innerHTML = '<div class="db-empty">No logs match the query</div>'; return; }
  const header = `<tr>
    <th>TIMESTAMP</th><th>LEVEL</th><th>SRC IP</th><th>PORT</th>
    <th>PROTO</th><th>EVENT</th><th>EXTRA</th>
  </tr>`;
  const body = rows.map(r => {
    const lvl = (r.level||"").toUpperCase();
    const cls = lvl === "CRITICAL" ? "cell-critical" : lvl === "WARNING" ? "cell-warning" : "cell-info";
    return `<tr>
      <td class="cell-ts">${escHtml(r.timestamp||"")}</td>
      <td class="${cls}">${lvl}</td>
      <td class="cell-ip">${escHtml(r.src_ip||"")}</td>
      <td class="cell-num">${r.port||""}</td>
      <td>${escHtml(r.proto||"")}</td>
      <td>${escHtml((r.event||"").slice(0,60))}</td>
      <td style="color:var(--text-dim)">${escHtml((r.extra||"").slice(0,50))}</td>
    </tr>`;
  }).join("");
  el.innerHTML = `<table class="db-table"><thead>${header}</thead><tbody>${body}</tbody></table>`;
}

// ── SESSIONS TABLE ────────────────────────────────────────────────────────────
async function fetchDbSessions() {
  const el = document.getElementById("db-sessions-table");
  if (!el) return;
  el.innerHTML = '<div class="db-loading">Querying attack_sessions…</div>';
  try {
    const res  = await fetch("/api/db/sessions?limit=50");
    const data = await res.json();
    const rows = data.sessions || [];
    if (!rows.length) { el.innerHTML = '<div class="db-empty">No attack sessions recorded yet</div>'; return; }
    const header = `<tr>
      <th>STARTED</th><th>ATTACK</th><th>SEVERITY</th>
      <th>DURATION</th><th>PACKETS</th><th>THREATS</th><th>IPs BLOCKED</th><th>STATUS</th>
    </tr>`;
    const body = rows.map(r => {
      const sev = (r.severity||"").toUpperCase();
      const cls = sev === "CRITICAL" ? "cell-critical" : sev === "HIGH" ? "cell-warning" : "";
      const started = r.started_at ? new Date(r.started_at).toLocaleString() : "—";
      return `<tr>
        <td class="cell-ts">${escHtml(started)}</td>
        <td>${escHtml(r.attack_name||"")}</td>
        <td class="${cls}">${sev}</td>
        <td class="cell-num">${r.duration_sec != null ? r.duration_sec + "s" : "—"}</td>
        <td class="cell-num">${r.packets_sent ?? "—"}</td>
        <td class="cell-num cell-critical">${r.threats_fired ?? "—"}</td>
        <td class="cell-num">${(r.ips_blocked||[]).length}</td>
        <td style="color:${r.status==='RUNNING'?'var(--accent-yellow)':'var(--accent-green)'}">${r.status||""}</td>
      </tr>`;
    }).join("");
    el.innerHTML = `<table class="db-table"><thead>${header}</thead><tbody>${body}</tbody></table>`;
    document.getElementById("db-footer-note").textContent = `${data.count} sessions total`;
  } catch (e) {
    el.innerHTML = '<div class="db-empty">Backend offline</div>';
  }
}

// ── ALERTS TABLE ──────────────────────────────────────────────────────────────
async function fetchDbAlerts() {
  const el = document.getElementById("db-alerts-table");
  if (!el) return;
  el.innerHTML = '<div class="db-loading">Querying threat_alerts…</div>';
  try {
    const res  = await fetch("/api/db/alerts?limit=100");
    const data = await res.json();
    const rows = data.alerts || [];
    if (!rows.length) { el.innerHTML = '<div class="db-empty">No threat alerts recorded yet</div>'; return; }
    const header = `<tr><th>FIRED AT</th><th>THREAT TYPE</th><th>SEVERITY</th><th>SRC IP</th><th>CONFIDENCE</th><th>ACTION</th></tr>`;
    const body = rows.map(r => {
      const sev = (r.severity||"").toUpperCase();
      const cls = sev === "CRITICAL" ? "cell-critical" : sev === "HIGH" ? "cell-warning" : "";
      const firedAt = r.fired_at ? new Date(r.fired_at).toLocaleString() : "—";
      const conf = r.confidence ? (r.confidence * 100).toFixed(0) + "%" : "—";
      return `<tr>
        <td class="cell-ts">${escHtml(firedAt)}</td>
        <td>${escHtml(r.threat_type||"")}</td>
        <td class="${cls}">${sev}</td>
        <td class="cell-ip">${escHtml(r.src_ip||"")}</td>
        <td class="cell-num">${conf}</td>
        <td style="color:var(--accent-green)">${escHtml(r.action_taken||"")}</td>
      </tr>`;
    }).join("");
    el.innerHTML = `<table class="db-table"><thead>${header}</thead><tbody>${body}</tbody></table>`;
    document.getElementById("db-footer-note").textContent = `${data.count} alerts total`;
  } catch (e) {
    el.innerHTML = '<div class="db-empty">Backend offline</div>';
  }
}

// ── BLOCKED IPs TABLE ─────────────────────────────────────────────────────────
async function fetchDbBlocked() {
  const el = document.getElementById("db-blocked-table");
  if (!el) return;
  el.innerHTML = '<div class="db-loading">Querying blocked_ips…</div>';
  try {
    const res  = await fetch("/api/db/blocked_ips");
    const data = await res.json();
    const rows = data.blocked_ips || [];
    if (!rows.length) { el.innerHTML = '<div class="db-empty">No IPs currently blocked</div>'; return; }
    const header = `<tr><th>IP ADDRESS</th><th>BLOCKED AT</th><th>REASON</th><th>STATUS</th><th>ACTION</th></tr>`;
    const body = rows.map(r => {
      const blockedAt = r.blocked_at ? new Date(r.blocked_at).toLocaleString() : "—";
      return `<tr>
        <td class="cell-ip">${escHtml(r.ip||"")}</td>
        <td class="cell-ts">${escHtml(blockedAt)}</td>
        <td style="color:var(--text-dim)">${escHtml(r.reason||"")}</td>
        <td style="color:${r.active?'var(--accent-red)':'var(--text-muted)'}">${r.active?"ACTIVE":"INACTIVE"}</td>
        <td><span class="cell-action" onclick="unblockIp('${escHtml(r.ip||"")}')">UNBLOCK</span></td>
      </tr>`;
    }).join("");
    el.innerHTML = `<table class="db-table"><thead>${header}</thead><tbody>${body}</tbody></table>`;
    document.getElementById("db-footer-note").textContent = `${data.count} blocked IPs`;
  } catch (e) {
    el.innerHTML = '<div class="db-empty">Backend offline</div>';
  }
}

async function unblockIp(ip) {
  try {
    await fetch(`/api/db/blocked_ips/${encodeURIComponent(ip)}`, { method: "DELETE" });
    fetchDbBlocked();
  } catch (e) { console.error("Unblock error:", e); }
}

// ── DB RESET ──────────────────────────────────────────────────────────────────
async function confirmDbReset() {
  if (!confirm("Clear ALL MongoDB data? This cannot be undone.")) return;
  try {
    const res  = await fetch("/api/db/reset", { method: "POST" });
    const data = await res.json();
    document.getElementById("db-footer-note").textContent = "Database cleared.";
    loadDbTab(currentDbTab);
  } catch (e) {
    alert("Backend offline — cannot clear DB.");
  }
}
