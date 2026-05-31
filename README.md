# SentinelLite // Modular Security Information & Event Management Framework

SentinelLite is a lightweight, high-performance, format-agnostic SIEM and log analysis utility built to process heterogeneous security telemetry. Operating as a pluggable triage pipeline, the framework ingests distinct structural log formats, cross-references logs against static signature heuristics, compiles remediation sequences via an on-demand SOAR decision engine, and applies an asynchronous local AI coprocessor for contextual threat analysis.

---

## 🏗️ System Architecture

The core framework follows a deterministic, pipeline-based data flow model, enforcing strict boundary isolation between data ingestion and alert correlation:

[ Raw Ingestion Stream ]
│
▼
┌───────────────┐      Forced Routing
│ Engine Router │ ──────────────────────────┐
└───────────────┘                           │
│ (Auto-Detect Engine)              ▼
▼                          ┌─────────────────┐
┌───────────────┐                  │ Parser Override │
│ Content Type  │                  └─────────────────┘
│  Classifier   │                           │
└───────────────┘                           │
│                                   │
▼                                   ▼
┌───────────────┐ 🛡️ Error         ┌─────────────────┐
│ Data Parser   │ ── Invalidation ─►│ Volatile Stream │
│   Isolation   │    Handling       │     Drop        │
└───────────────┘                   └─────────────────┘
│
▼
┌───────────────┐
│ Rules Engine  │ ◄── [ Static Signature Matrix ]
└───────────────┘
│
├──► [ UI Presentation Canvas ]
│
├──► [ SOAR Decision Engine ] ──► (Actionable Remediation Playbook)
│
└──► [ Local AI Coprocessor ] ──► (Heuristic Context Analytics)


---

## 🚀 Key Architectural Layers

* **Format-Agnostic Classifier & Parsing Core:** Features an automated payload routing engine that inspects byte structures to identify telemetry schemas (Binary PCAP, Auth/SSHD Syslog, Nginx Web Logs, and Structured JSON) with line-by-line exception isolation to survive malformed streams.
* **Static Correlation Matrix:** Executes deterministic rule matching across all normalized events to track Indicators of Compromise (IoCs) like brute-force thresholds, directory traversals, and multi-stage exploitation pivots.
* **Automated SOAR Decision Engine:** Generates real-time, copy-pasteable terminal recipes (iptables drops, service isolation blocks) immediately upon signature matches to optimize Mean Time to Respond (MTTR).
* **Local AI Analytical Coprocessor:** Integrates with local model instances via zero-dependency APIs to perform on-demand tactical reviews of complex attack sequences without leaking data to external infrastructure.

---

## 🛠️ Installation & Workspace Setup

### Prerequisites
* Python 3.8+
* Local administrative privileges (required for high-precision packet processing bindings)

### Step 1: Clone and Prepare Environment
```bash
git clone [https://github.com/your-username/sentinel-lite.git](https://github.com/your-username/sentinel-lite.git)
cd sentinel-lite

Step 2: Establish Virtual Environment & Dependencies
Bash

# Create and activate environment
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

# Install third-party framework dependencies
pip install -r requirements.txt

    Note: Ensure packages like Flask and scapy are specified within your requirements.txt file.

Step 3: Run the Local AI Engine (Optional)

If utilizing the local analytical coprocessor feature, ensure your local AI instance is running and reachable via your environment's local endpoints:
Bash

ollama run llama3  # Or your specific local target model configuration

💻 Running the Application

Launch the primary Flask web server from your workspace root directory:
Bash

python app.py

Open your browser and navigate to the local presentation canvas:
Plaintext

[http://127.0.0.1:5000](http://127.0.0.1:5000)

📁 Directory Architecture
Plaintext

sentinel_lite/
│
├── app.py                     # Flask Application Controller & API Endpoint Bindings
├── requirements.txt           # Framework Third-Party Application Dependencies
├── README.md                  # System Documentation Matrix
│
├── core/                      # Core Logical Analysis Packages
│   ├── __init__.py
│   ├── parsers.py             # Line-Isolated Ingestion Parsers (PCAP, Syslog, Web, JSON)
│   ├── rules_engine.py        # Static Heuristic Rules Matrix & Threshold Trackers
│   └── soar.py                # Automated Remediation Playbook Compilers
│
├── artifacts/                 # Volatile Output Storage Matrix
│   └── playbooks/             # Hot-Compiled Mitigation Scripts & Action Targets
│
└── templates/                 # Presentation Layer Templates
    └── index.html             # Minimalist Operational UI Dashboard

🔒 Production Security Standard

    Line-Level Invalidation Isolation: Every log parser enforces strict local try-except contexts per element row. If a single line contains corrupt data or anomalous byte injections, that row is safely flagged and dropped without compromising the runtime state of the active analysis cycle.

    Zero External Overhead: Telemetry logs and packet matrices are parsed entirely inside memory constraints, and AI classification runs strictly on local hardware scopes. No operational data is ever transmitted to external nodes or commercial cloud APIs.