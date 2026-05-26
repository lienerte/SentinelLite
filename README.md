# SentinelLite: Pluggable & AI-Optimized SIEM Architectural Framework

SentinelLite is an agile, factory-driven Security Information and Event Management (SIEM) simulation framework built to ingest, auto-classify, parse, and correlate disparate multi-format log arrays (PCAP, Linux Syslog, Combined Web/Nginx). 

The architecture leverages strict protocol normalization layers to completely decouple core telemetry ingestion from downstream behavioral signature matching and an asynchronous local AI Coprocessor engine.

---

## 🏗️ Core Architectural Blueprint

The engine is engineered around standard object-oriented patterns to avoid the fragility of raw script automation:

1. **Intelligent Ingestion Layer (`LogClassifier`):** Reads early byte streams to evaluate content-based structural heuristics (e.g., matching hex magic numbers for binary files or regex boundaries for strings), completely bypassing fragile file-extension dependency.
2. **Unified Normalized Event Schema (`BaseParser`):** Enforces a strict schema map across all dynamic parsers. Whether log data originates as a binary network packet capture or a plaintext web-server string, it maps to a uniform dictionary payload containing immutable properties (`src_ip`, `dst_ip`, `payload`, `event_type`).
3. **Pluggable Cross-Protocol Correlation Engine (`AnalysisEngine`):** Utilizes a dynamic plugin manifest matrix. It looks across distinct protocols over a timeline, tracing a single actor IP as it pivots from perimeter recons into internal authorization brute-forcing.
4. **Asynchronous Local AI Coprocessor Layer (`AIIntegrationLayer`):** Interacts natively with a local offline LLM daemon (Ollama/Llama3). To shield high-velocity file ingestion from blocking execution queues, inference processes run asynchronously, keeping the UI highly responsive.

---

## 🛠️ Technology Stack & Dependencies

* **Core Pipeline Engine:** Python 3.10+
* **Asynchronous Web Interface:** Flask, JavaScript (Fetch API / Worker Progress Tracking)
* **Low-Level Telemetry Extraction:** Scapy (High-precision PCAP layer parsing)
* **Local Generative Coprocessor:** Ollama Engine API Layer

---

## 🚀 Step-by-Step Execution Guide

### 1. Initialize the Local Inference Engine
Ensure your local Ollama daemon is active in the background and hosting your targeted language model weights:
```bash
ollama run llama3

pip install flask scapy requests

python app.py
```

Open your browser and navigate to http://127.0.0.1:5000 to interact with the dashboard.
🔬 Complex Ingestion Case Studies
Case Study A: Cleartext Administrative Network Audit

    Target Artifact: samples/tcp-ecn-sample.pcap

    Pipeline Action: The framework sniffs the binary magic bytes, overrides default text lines, routes to the PcapParser, handles Scapy's microsecond-precision EDecimal timestamp casting dynamically to protect JSON serialization streams, and isolates unencrypted Cisco IOS diagnostic summaries (GET /show-tech).

    AI Realization: The local LLM contextualizes the traffic as non-malicious but insecure infrastructure management, automatically rendering real-world remediation advice focused on protocol encapsulation and transport encryption rather than connection-breaking firewall rules.

Case Study B: Multi-Stage Cross-Protocol Attack Sequence

    Target Artifact: samples/multi_stage_attack.log

    Pipeline Action: Ingests a multiplexed file containing mixed Nginx web proxy scans and Linux SSH authentication failures. The MultiParser layer strips out the lines concurrently. The CrossProtocolCorrelationPlugin tracks the unified malicious footprint, flagging a CRITICAL alert for an adversary tactical pivot.

🛡️ Error Handling & Defensive Boundaries

    Total Parser Incompatibility Shielding: If a user forces a mismatched parser selection via the frontend UI dropdown (e.g., executing the JSON engine on text streams), the backend maps the classification collision and suppresses downstream empty-state AI parsing errors. The frontend UI immediately transforms into an amber/red validation warning panel to guard metric collection parameters.