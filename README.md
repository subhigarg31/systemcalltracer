# System Call Tracer with Real-Time Anomaly Detection

A full-stack cybersecurity operations and telemetry monitoring system built for macOS. This application simulates system-call events, analyzes them using a real-time rule-based anomaly detection engine, computes a deterministic risk score with a documented decay policy, and streams live telemetry to a Security Operations Center (SOC) dashboard.

![Project Status](https://img.shields.io/badge/Status-Complete-emerald?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Apple%20Silicon%20%26%20Intel-blue?style=flat-square)
![Language](https://img.shields.io/badge/C%2B%2B-17-blue?style=flat-square)
![Node](https://img.shields.io/badge/Node.js-Express%20%2B%20WebSocket-green?style=flat-square)
![Frontend](https://img.shields.io/badge/React-Vite%20%2B%20TailwindCSS-cyan?style=flat-square)

---

## 1. Project Overview

Modern Endpoint Detection and Response (EDR) platforms monitor system-call sequences to identify zero-day attacks, ransomware encryption, credential harvesting, and command-and-control (C2) beacons. Because macOS restricts kernel tracing (`ptrace` / DTrace) without disabling System Integrity Protection (SIP) or loading kernel extensions, this project implements a **C++ System Call Event Simulator** that produces high-fidelity, structured JSON telemetry safely in user space.

### Key Highlights
- **Real C++ Telemetry Simulator**: Generates realistic syscall events (`openat`, `read`, `write`, `close`, `connect`, `fork`, `clone`, `execve`) across Automatic Monitoring, Normal, Suspicious, and Mixed modes.
- **Scenario-Independent Detection**: The detection engine evaluates events strictly based on actual system-call names, target file paths, ports, and behavioral thresholds—never relying on simulator modes or scenario labels.
- **Automatic Monitoring Mode (Default)**: Streams a realistic baseline of routine telemetry while periodically injecting controlled threat episodes at configurable intervals (not every cycle), demonstrating realistic detection and decay in a single stream.
- **Rule-Based Threat Detection Engine**: Implements MITRE ATT&CK-aligned behavioral detection rules for credential access, ransomware patterns, anomalous outbound connections, and fork-burst activity.
- **Dynamic 0–100 Risk Scoring Model**: Calculates deterministic risk with multi-category threat correlation boosts and a continuous decay/recovery policy.
- **Real-Time SOC Dashboard**: Developer-oriented dark theme interface built with React, Tailwind CSS, Recharts, and WebSockets.
- **Forensics & Multi-Format Reporting**: Full event inspection drawers, alert lifecycle management (active vs. acknowledged), and one-click JSON, CSV, and printable PDF exports.

---

## 2. System Architecture

The pipeline processes all events on the backend before broadcasting them to connected dashboard clients:

```
┌────────────────────────┐
│  C++ Event Simulator   │  (POSIX C++17 Binary)
│  syscall_tracer_sim    │  Emits Newline-Delimited JSON (NDJSON) on stdout
└───────────┬────────────┘
            │ Pipe / Child Process IPC
            ▼
┌────────────────────────┐
│   Node.js Backend      │  (Express + WebSocket Server)
│  ┌──────────────────┐  │
│  │ Detection Engine │  │  Evaluates Rules A, B, C, D
│  │   & Deduplicator │  │  Applies rolling time windows
│  └────────┬─────────┘  │
│           ▼            │
│  ┌──────────────────┐  │
│  │   Risk Scorer    │  │  Calculates deterministic 0–100 score
│  │  & Decay Engine  │  │  Applies decay ticks every 1.5s
│  └────────┬─────────┘  │
└───────────┼────────────┘
            │ Real-Time WebSocket Streaming (ws) & REST API
            ▼
┌────────────────────────┐
│  React SOC Dashboard   │  (Vite + Tailwind CSS + Recharts)
│  - Real-Time Table     │  Pause/Resume, filters, JSON inspection drawer
│  - Threat Alerts Feed  │  Forensic evidence dossier & ACK workflow
│  - Frequency Charts    │  Sliding window syscall volume & risk graphs
│  - Reports & Settings  │  JSON/CSV/Printable PDF exports & tuning
└────────────────────────┘
```

### Repository Structure
```
systemcalltracer/
├── Makefile                # Unified build, test, and run automation
├── package.json            # Root workspace scripts
├── simulator/              # C++ Event Simulator
│   ├── Makefile            # clang++ build configuration
│   ├── src/
│   │   ├── main.cpp        # CLI parsing, signal handling, live stdin controls
│   │   ├── generator.cpp   # Normal, suspicious, and mixed telemetry generators
│   │   ├── generator.hpp   # Event generator class declarations
│   │   ├── event.hpp       # SyscallEvent struct & JSON serialization
│   │   └── utils.hpp       # ISO 8601 timestamps, string escaping, RNG
│   └── README.md           # Simulator standalone documentation
├── server/                 # Node.js / Express Backend & Detection Engine
│   ├── package.json
│   ├── src/
│   │   ├── index.js        # Main server entry, Express, WebSocket, timers
│   │   ├── config.js       # Thresholds, rules config, risk scoring parameters
│   │   ├── store.js        # In-memory circular buffer, process ledger, metrics
│   │   ├── simulatorManager.js # Child process spawn, stream reader, mode IPC
│   │   ├── websocket.js    # WebSocket connection manager & broadcast
│   │   ├── detection/
│   │   │   ├── engine.js   # Detection engine coordinator
│   │   │   ├── rules.js    # Threat detection rules A, B, C, D & dedup
│   │   │   └── riskScorer.js # Deterministic 0-100 score & decay model
│   │   └── routes/
│   │       ├── api.js      # REST API endpoints (health, status, controls)
│   │       └── reports.js  # Report generation (JSON, CSV, Printable HTML)
│   └── tests/              # Automated Test Suite (36 passing tests)
│       ├── eventValidation.test.js
│       ├── rules.test.js
│       ├── riskScorer.test.js
│       ├── api.test.js
│       └── report.test.js
├── client/                 # React Dashboard (Vite + Tailwind CSS)
│   ├── src/
│   │   ├── App.jsx         # Navigation tabs and modal coordinator
│   │   ├── context/
│   │   │   └── SystemContext.jsx # WebSocket & REST state management
│   │   ├── components/     # Navbar, Sidebar, RiskGauge, StatCard, Drawers
│   │   └── pages/          # Overview, LiveFeed, Alerts, Processes, Reports, Settings
├── reports/                # Export directory for offline audit reports
└── README.md               # Complete project documentation
```

---

## 3. Threat Detection Engine

The detection engine analyzes events in real time using four behavioral rules:

### Rule A: Sensitive Credential Access (MITRE ATT&CK T1003)
- **Target Syscalls:** `openat`, `read`
- **Pattern:** Detects simulated read or open operations on credential stores: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/root/.ssh`.
- **Severity:** `Critical`
- **Recommended Action:** Audit process user privileges, isolate process tree, and inspect parent process execution origin.

### Rule B: Ransomware-Like Mass File Modification (MITRE ATT&CK T1486)
- **Target Syscalls:** `write`, `openat` (`O_CREAT` / `O_WRONLY` / `O_TRUNC`)
- **Pattern:** Detects high-velocity modifications across $\ge 4$ distinct files within a 5-second sliding window by a single process.
- **Severity:** `Critical`
- **Recommended Action:** Instantly terminate process, create volume snapshots, and inspect for encryption file extensions (`.locked`, `.enc`).

### Rule C: Suspicious Outbound Connection & Exfiltration (MITRE ATT&CK T1071 / T1041)
- **Target Syscalls:** `connect`
- **Pattern:** Evaluates outbound socket connections against a known baseline. Standard web/DNS traffic (ports 80, 443, 53) to trusted IPs is permitted. Flags connections to suspicious C2/backdoor ports (`4444`, `1337`, `6667`, `31337`) or external connections correlated with prior sensitive credential reads by the same PID within 15 seconds.
- **Severity:** `High` (escalated to `Critical` if correlated with credential theft)
- **Recommended Action:** Block destination IP/port at perimeter firewall and capture active socket descriptors.

### Rule D: Abnormal Process Creation Burst (MITRE ATT&CK T1106)
- **Target Syscalls:** `fork`, `clone`, `execve`
- **Pattern:** Detects rapid burst spawning of $\ge 5$ child processes within a 4-second rolling window by the same parent PID.
- **Severity:** `Medium`
- **Recommended Action:** Inspect process tree for runaway fork-bomb scripts or multi-threaded payload deployment.

### Alert Deduplication
To prevent alerts from flooding the stream during continuous loops, each rule implements an in-memory deduplication window (4–6 seconds) per `ruleId:pid:target`. Duplicate alerts within this window are suppressed while underlying metrics continue to record telemetry.

### Telemetry Scenarios vs. Independent Behavioral Detection

A fundamental architectural principle of this system is the strict decoupling between **telemetry generation** and **threat detection**:

1. **Simulator Scenarios (Event Generation Only):**
   - **Automatic Monitoring (Default):** Generates an authentic operational baseline (file reads/writes, routine network queries) and periodically injects rotating threat patterns at a configurable interval (default: every 25 events). This allows operators to observe detection spikes, active alert investigation, and natural score decay in a single continuous demonstration without manual intervention.
   - **Normal Activity:** Generates exclusively routine operational telemetry (web requests, configuration reads, log writes).
   - **Suspicious Activity:** Generates concentrated bursts of malicious patterns for targeted rule testing.
   - **Mixed Activity:** Emits a continuous mixture (~75% normal, 25% suspicious).

2. **Detection Engine Independence:**
   - The Detection Engine evaluates **every event independently** against Rules A, B, C, and D based exclusively on `syscall`, `args` (file paths, ports, flags), and historical per-PID event tracking.
   - The engine **never** inspects `event.scenario` or the active simulator mode.
   - Switching simulator modes **never** directly mutates the risk score or creates alerts without actual event evaluation.
   - If an anomalous event (e.g., `connect` to port `4444`) arrives labeled `scenario: "normal"`, it is immediately flagged as a threat alert. Conversely, routine web browsing (`port 443`) arriving under `scenario: "suspicious"` will never generate false-positive alerts.

---

## 4. Deterministic Risk Scoring & Decay Model

The system maintains a dynamic risk score from **0 to 100**:

$$\text{RiskScore} = \min\left(100, \sum \text{SeverityWeight}(\text{ActiveAlert}_i) + \text{CorrelationBonus}\right)$$

### Severity Weights
- **Critical Alert:** $+35$ points
- **High Alert:** $+20$ points
- **Medium Alert:** $+10$ points
- **Low Alert:** $+5$ points

### Multi-Threat Correlation Bonus
If active alerts span multiple distinct threat categories (e.g., *Credential Access* AND *Command & Control*):
- 2 unique categories: $+15$ bonus points
- 3+ unique categories: $+25$ bonus points

### Display Bands
| Band | Range | Color | Description |
|---|:---:|:---:|---|
| **Low** | 0–24 | Emerald | Nominal operational baseline; safe background activity |
| **Guarded** | 25–49 | Amber | Isolated non-critical anomaly detected |
| **High** | 50–74 | Orange | Multiple significant suspicious behaviors |
| **Critical** | 75–100 | Red | Active high-confidence compromise or multi-vector attack |

### Score Decay & Recovery Policy
When activity normalizes or alerts are acknowledged:
- Every **1.5 seconds** (`decayIntervalMs`) without new threat alerts, the score automatically decays by **10 points** (`decayStep`) toward baseline.
- When all active alerts are acknowledged, the target score drops to 0, allowing the gauge to recover to the **Low band** smoothly.

> **Academic Disclaimer:** This scoring engine is an educational heuristic model designed for SOC workflow training, not a validated machine learning probability index.

---

## 5. Installation & Setup on macOS

### Prerequisites
- macOS (Apple Silicon M1/M2/M3/M4 or Intel)
- Node.js $\ge$ v18 (Tested on Node.js v25.8.2)
- Apple Clang / Xcode Command Line Tools (`clang++ -v`)

### Step 1: Clone and Build
Build the C++ simulator and the React frontend in one step:
```bash
make all
```
*Alternatively, using npm:*
```bash
npm run build
```

### Step 2: Start the Application
```bash
make start
```
*Or:*
```bash
npm start
```

### Step 3: Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:3001
```
The Express backend serves the REST API, the WebSocket streaming endpoint (`ws://localhost:3001`), and the pre-built React frontend from `client/dist`.

*(Optional) Development Mode with Hot-Reloading:*
If modifying frontend code, run Vite dev server concurrently:
```bash
npm run dev:client
```
Visit `http://localhost:5173` (requests to `/api` are automatically proxied to port 3001).

---

## 6. Demonstration Script (For College Faculty Presentation)

Use the following step-by-step walkthrough to demonstrate the application:

### Demo 1: Automatic Monitoring & Dynamic Detection (Default)
1. Open `http://localhost:3001`.
2. Confirm the top bar displays **Telemetry: Automatic Monitoring (Default)**.
3. Click the **Start** button in the top bar.
4. **Observations:**
   - The *Live Syscall Feed* begins streaming an authentic baseline of normal file reads, writes, and network connections.
   - The *Overview* charts plot live syscall frequency while the **Risk Gauge stays in the green Low band (0–24)**.
   - At the configured interval (~25 events), the simulator injects a controlled threat pattern into the stream (e.g., credential access, ransomware write burst, C2 beacon, or fork burst).
   - The **Detection Engine flags the suspicious behavior immediately**, elevating the Risk Score and triggering a new entry in *Threat Alerts*.
   - Once the threat pattern concludes and telemetry returns to routine operations, observe the **Risk Score smoothly decay** back toward baseline without manual intervention.

### Demo 2: Scenario Independence & Controlled Testing
1. In the top bar, switch between **Normal Only (Baseline)**, **Suspicious (Test Bursts)**, and **Mixed Traffic**.
2. **Observations:**
   - Switching the dropdown does **not** directly set the risk score or create alerts; the detection engine evaluates each event independently.
   - Under *Normal Only*, hundreds of routine events stream without any false-positive high-severity alerts.
   - Under *Suspicious*, malicious patterns arrive in concentration, triggering Rules A–D and elevating the risk score to Critical (75–100) purely through behavioral event evaluation.


### Demo 3: Forensic Investigation & Multi-Format Reporting
1. Click the **Threat Alerts** tab in the sidebar.
2. Click on a **Critical** alert (e.g., `ALT-CRED-...` or `ALT-RANSOM-...`).
3. An **Investigation Modal** opens showing:
   - Threat synopsis and MITRE category.
   - Forensic evidence dossier (exact targeted file, PID, write rate, destination IP/port).
   - Prescriptive recommended SOC action.
4. Click **Acknowledge Alert**. Note that the active alert count decreases while historical telemetry remains preserved.
5. Navigate to the **Reports** tab:
   - Click **Export JSON** to download a structured forensic dossier.
   - Click **Export CSV** to download a tabular log suitable for spreadsheet audits.
   - Click **Printable PDF View** to open the print-optimized HTML executive summary and trigger browser PDF printing.

### Demo 4: Recovery & Risk Score Decay
1. In the top bar, switch the **Mode** dropdown back to `Normal`.
2. In the *Threat Alerts* tab, click **Acknowledge** on any remaining active alerts.
3. Watch the **Overview** screen:
   - As normal telemetry flows and no new alerts trigger, the **Risk Score decays every 1.5 seconds** (100 $\rightarrow$ 90 $\rightarrow$ 80 $\rightarrow$ ... $\rightarrow$ Low).
   - The system status returns to green **Low Band (Baseline Secure)**, proving that the decay policy functions deterministically.

---

## 7. Automated Test Suite

The project includes an automated test suite verifying all engine rules, scoring formulas, API endpoints, and report generators:

```bash
make test
```
*Or:*
```bash
npm test
```

### Test Suite Output
```
▶ REST API Endpoints
  ✔ GET /api/health returns ok (1.05ms)
  ✔ GET /api/status returns valid state (0.17ms)
  ✔ GET /api/events returns event list and handles filters (10.81ms)
  ✔ Alert lifecycle and acknowledgement (0.52ms)
  ✔ GET /api/metrics returns aggregated metrics (0.13ms)
  ✔ POST /api/settings updates configuration safely (0.16ms)
  ✔ POST /api/reset clears session data (0.10ms)
✔ REST API Endpoints (14.76ms)

▶ Event Schema Validation
  ✔ accepts valid event (0.42ms)
  ✔ rejects non-object or null (0.05ms)
  ✔ rejects missing timestamp (0.11ms)
  ✔ rejects missing or non-numeric pid (0.06ms)
  ✔ rejects missing syscall (0.06ms)
  ✔ rejects missing category (0.06ms)
✔ Event Schema Validation (1.49ms)

▶ Detection Engine Scenario Independence Tests
  ✔ Identical event sequence yields identical alerts and risk scores regardless of scenario label (4.46ms)
  ✔ Rule A fires based on sensitive file path, not scenario label (0.24ms)
  ✔ Rule B fires based on multi-file write pattern, not scenario label (1.03ms)
  ✔ Rule C fires based on destination port without synthetic flags (0.22ms)
  ✔ Rule D fires based on spawn burst frequency per PID, not scenario label (0.23ms)
  ✔ Routine telemetry stream does not systematically trigger high-severity alerts (0.65ms)
  ✔ Alert objects contain riskScore, riskBand, ruleId, severity, pid, and evidence (0.11ms)
✔ Detection Engine Scenario Independence Tests (8.48ms)

▶ Report Generation & Export
  ✔ GET /api/reports/summary returns comprehensive report structure (1.22ms)
  ✔ GET /api/reports/download?format=json serves valid downloadable JSON (0.37ms)
  ✔ GET /api/reports/download?format=csv serves structured CSV (0.15ms)
  ✔ GET /api/reports/html returns printable HTML document (0.30ms)
✔ Report Generation & Export (16.54ms)

▶ Risk Scoring Model & Decay Policy
  ✔ Initial score starts at 0 (Low band) (1.03ms)
  ✔ Score bands correctly mapped (0.12ms)
  ✔ Accumulates score based on alert severities (0.10ms)
  ✔ Applies correlation bonus for multi-category threats reaching Critical (0.08ms)
  ✔ Caps score at 100 (0.11ms)
  ✔ Decays score when no active alerts present (81.88ms)
  ✔ Force decay step decrements score gracefully (0.11ms)
✔ Risk Scoring Model & Decay Policy (85.08ms)

▶ Threat Detection Rules & Deduplication
  ✔ Rule A: Detects sensitive file access to /etc/passwd (2.10ms)
  ✔ Rule A: Deduplicates subsequent access within window (0.16ms)
  ✔ Rule B: Detects ransomware-like multi-file modification (0.18ms)
  ✔ Rule C: Flags port 4444 and ignores port 443 (0.98ms)
  ✔ Rule C: Detects correlated exfiltration (credential access + connection) (0.42ms)
  ✔ Rule D: Detects abnormal process creation burst (0.37ms)
  ✔ Normal activity scenario does not trigger high-severity alerts (0.12ms)
✔ Threat Detection Rules & Deduplication (5.94ms)

ℹ tests 44 | pass 44 | fail 0 | cancelled 0 | duration_ms 184.77ms
```

---

## 8. REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Health check endpoint returning uptime and timestamp |
| `GET` | `/api/status` | Current session status, simulator process status, and metrics |
| `POST` | `/api/simulator/start` | Start C++ simulator (`{ mode: "automatic", interval: 200, threatInterval: 25 }`) |
| `POST` | `/api/simulator/stop` | Terminate C++ simulator cleanly |
| `POST` | `/api/simulator/mode` | Change mode on the fly (`{ mode: "automatic" \| "normal" \| "suspicious" \| "mixed" }`) |
| `POST` | `/api/simulator/interval` | Update event interval in ms (`{ interval: 200 }`) |
| `POST` | `/api/simulator/threat-interval` | Update automatic mode threat interval in events (`{ threatInterval: 25 }`) |
| `GET` | `/api/events` | Query buffered events with filter options (`category`, `pid`, `search`) |
| `GET` | `/api/alerts` | Query detected alerts (`status=active`, `severity=critical`) |
| `POST` | `/api/alerts/:id/acknowledge` | Acknowledge alert without deleting evidence |
| `GET` | `/api/metrics` | Time-series and aggregated metric values |
| `GET` | `/api/processes` | List of observed simulated processes with syscall counts |
| `GET` | `/api/settings` | Read current engine thresholds |
| `POST` | `/api/settings` | Update permitted thresholds and decay settings |
| `POST` | `/api/reset` | Purge current session telemetry and reset score to 0 |
| `GET` | `/api/reports/summary` | JSON summary for reporting |
| `GET` | `/api/reports/download?format=json\|csv` | Download report file |
| `GET` | `/api/reports/html` | Printable executive HTML report |

---

## 9. Troubleshooting & FAQ

#### Simulator compilation fails with `clang++: command not found`
Install the command-line developer tools on macOS:
```bash
xcode-select --install
```

#### Port 3001 is already in use
Specify a different port using the `PORT` environment variable:
```bash
PORT=3005 npm start
```

#### How does the simulator clean up when the server stops?
The server listens for `SIGINT` (Ctrl+C) and `SIGTERM`. When received, it sends `STOP\n` over stdin and issues `SIGTERM` to the simulator process, ensuring zero orphaned child processes.

---

## 10. License & Academic Attribution
Developed as an educational cybersecurity demonstration of real-time behavioral anomaly detection and SOC dashboard workflows on macOS. Released under the MIT License.
