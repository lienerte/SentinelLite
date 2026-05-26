# SentinelLite
A local, lightweight, and extensible SIEM framework with automatic log classification, an abstracted parser factory, a plugin-based detection engine, and a Flask-based Web UI.

## Core Architectural Layers

### 1. The Automatic Log Classification Strategy
When a telemetry package reaches the ingestion layer without structural context, the system reads its front-end data streams. It uses binary magic byte arrays to isolate network captures (`PCAP`), maps keyword configurations (`sshd` components for authentication files), checks regex indicators (Combined access models for web files), and validates json parsing maps.

### 2. Step-by-Step Execution Pathways
1. Run the terminal-driven CLI ingestion script:
   ```bash
   python main.py --file samples/sample_auth.log