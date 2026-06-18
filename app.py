# app.py
"""
app.py - Primary SentinelLite Control Surface
Orchestrates the entire asynchronous SIEM pipeline: Ingestion, Triage, 
Normalization, Threat Rule Correlation, Manual Playbook Compilation, and Local AI Inference.
"""
import os
from flask import Flask, render_template, request, jsonify

# Core System Structural Imports
from core.rules_engine import AdvancedRulesEngine
from core.log_classifier import LogClassifier
from core.parser_factory import ParserFactory
from core.analysis_engine import AnalysisEngine
from core.remediation_orchestrator import RemediationOrchestrator
from core.ai_analyzer import AIIntegrationLayer
from core.live_sniffer import LiveSnifferManager, LIVE_ALERT_CACHE, LIVE_SNIFFER_ACTIVE

from flask import Flask, render_template, jsonify, session, request
import json

app = Flask(__name__)
app.secret_key = "sentinel_secure_session_token_key" # Required for temporary storage caching

@app.route('/process_log', methods=['POST'])
def process_log():
    # 1. Gather all raw parsed alerts from your rules engine
    # (Assuming raw_alerts is your original list of triggered rule objects)
    raw_alerts = engine.evaluate_telemetry(request.files['logfile'])
    
    # 2. Store the total raw dataset in the session cache for the downloader button
    session['cached_raw_alerts'] = raw_alerts
    
    # 3. Deduplication Matrix (Group by unique Rule ID + Source Target)
    aggregated_map = {}
    for alert in raw_alerts:
        rule_id = alert.get('rule_id', 'UNKNOWN-RULE')
        source_ip = alert.get('source_ip', '0.0.0.0')
        
        # Define the unique aggregation fingerprint key
        fingerprint = f"{rule_id}_{source_ip}"
        
        if fingerprint not in aggregated_map:
            # Initialize the base record structure with a hit count tracker
            aggregated_map[fingerprint] = {
                "rule_id": rule_id,
                "signature_name": alert.get('signature_name', 'Generic Rule Match'),
                "severity": alert.get('severity', 'LOW'),
                "severity_score": {"CRITICAL": 3, "WARNING": 2, "LOW": 1}.get(alert.get('severity'), 0),
                "source_ip": source_ip,
                "mitre_mapping": alert.get('mitre_mapping', 'N/A'),
                "timestamp": alert.get('timestamp'),
                "hit_count": 1 # Start counting occurrences
            }
        else:
            # Increment tracking tally if the unique alert signature repeats
            aggregated_map[fingerprint]["hit_count"] += 1

    # 4. Sort strictly by Severity Rank first, then by internal hit volumes
    sorted_alerts = sorted(
        aggregated_map.values(), 
        key=lambda x: (x['severity_score'], x['hit_count']), 
        reverse=True
    )
    
    # 5. Enforce safety threshold limit (Slice the list to the top 100 entries)
    display_alerts = sorted_alerts[:100]
    
    return render_template('index.html', alerts=display_alerts, total_raw_count=len(raw_alerts))

@app.route('/download_all_alerts')
def download_all_alerts():
    """Compiles the complete un-truncated log array into a clean JSON attachment."""
    cached_data = session.get('cached_raw_alerts', [])
    
    return jsonify(cached_data), 200, {
        'Content-Type': 'application/json',
        'Content-Disposition': 'attachment; filename=sentinel_full_triage_export.json'
    }

app = Flask(__name__)

# Pipeline Environment Parameters
UPLOAD_FOLDER = "uploads"
ARTIFACT_FOLDER = "artifacts"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
rules_engine = AdvancedRulesEngine()

# Ensure processing directories exist on local disk initialization
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ARTIFACT_FOLDER, exist_ok=True)

@app.route('/')
def index():
    """Renders the central unified security orchestration dashboard."""
    return render_template('index.html')

@app.route('/analyze-async', methods=['POST'])
def analyze_async():
    """
    Asynchronously processes uploaded network/syslog telemetry payloads.
    Protects user experience matrix using distinct execution boundaries.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file payload detected"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file name found"}), 400
        
    try:
        # Commit file payload safely to disk storage
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(save_path)
        
        # Extract UI request configuration state values
        override_type = request.form.get('override_type') or None
        run_ai_checkbox = request.form.get('run_ai') == 'true'

        # 1. Triage Phase: Run auto-detect to establish baseline file truth
        auto_detected_type, _ = LogClassifier.classify(save_path)
        
        # Decide which routing tag to execute based on dropdown state
        if override_type:
            log_type = override_type.upper()
        else:
            log_type = auto_detected_type
            
        # 2. Validation Boundary: Check for explicit parser mismatch states
        mismatch_detected = False
        if override_type and auto_detected_type != "UNKNOWN" and override_type.upper() != auto_detected_type:
            mismatch_detected = True

        # ─── NEW INTERCEPTION BLOCK: UNIVERSAL RULE SCAN FOR UNKNOWN FILES ───
        if log_type == "UNKNOWN":
            with open(save_path, 'rb') as f:
                raw_bytes = f.read()
            
            # Universal fallback scanner execution loop
            alerts = rules_engine.evaluate_log_data(raw_bytes)
            
            # Initialize default fallbacks
            ai_summary_text = ""
            tactical_playbook = ""
            
            # If rules caught malicious indicators, let Ollama or the SOAR engine build it
            if alerts and run_ai_checkbox:
                # Let Ollama handle both dynamically with context
                #ai_summary_text, tactical_playbook = generate_sentinel_summary(alerts)
                ai_summary_text, tactical_playbook = "holder", "holder"

            elif alerts:
                # Fallback to standard hardcoded SOAR if checkbox is disabled
                soar_engine = RemediationOrchestrator()
                tactical_playbook = soar_engine.generate_playbook(alerts, file.filename)
                ai_summary_text = f"### 🤖 Local AI Analysis Matrix\nIdentified {len(alerts)} threat indicators matching open-source Sigma rules inside unclassified telemetry payload structure."
            else:
                if run_ai_checkbox:
                    ai_summary_text = "### 🤖 Ingestion Error\nFramework parsing skipped: Unrecognized file structural fingerprints."

            # FIXED: "playbook_meta" now accurately points to the updated tactical_playbook variable
            return jsonify({
                "filename": file.filename,
                "log_type": "UNKNOWN",
                "auto_detect_type": auto_detected_type,
                "mismatch_detected": False,
                "alerts": alerts,
                "playbook_meta": tactical_playbook, 
                "ai_analysis": ai_summary_text
            })

        # 3. Normalization Phase: Resolve factory object and parse bytes to schema dictionaries
        parser = ParserFactory.get_parser(log_type)
        events = parser.parse(save_path)

        # 4. Correlation Phase: Run your new global 3k+ Sigma rules engine
        with open(save_path, 'rb') as f:
            raw_bytes = f.read()
        alerts = rules_engine.evaluate_log_data(raw_bytes)

        # 5. SOAR Advisory Phase / Generative Coprocessor Phase
        # Initialize variables so they are guaranteed to exist
        ai_summary = "No analysis generated or AI checkbox was disabled."
        tactical_playbook = ""

        if run_ai_checkbox:
            # If the user requested AI, offload BOTH the analysis and playbook text to Ollama
                #ai_summary_text, tactical_playbook = generate_sentinel_summary(alerts)
                ai_summary_text, tactical_playbook = "holder", "holder"
        else:
            # If the checkbox is off, fall back to your native hardcoded rule framework
            soar_engine = RemediationOrchestrator()
            tactical_playbook = soar_engine.generate_playbook(alerts, file.filename)

        # Return full payload synchronization mapping back to frontend JavaScript renderer
        return jsonify({
            "filename": file.filename,
            "log_type": log_type,
            "auto_detect_type": auto_detected_type,
            "mismatch_detected": mismatch_detected,
            "alerts": alerts,
            "playbook_meta": tactical_playbook, # <-- Consistently maps variable to frontend key
            "ai_analysis": ai_summary
        })

    except Exception as e:
        print(f"[-] Catastrophic pipeline breakdown inside app.py loop: {e}")
        return jsonify({"error": f"Internal pipeline exception: {str(e)}"}), 500

'''@app.route('/generate_sentinel_summary', methods=['POST'])
def generate_sentinel_summary(parsed_alerts):
    if not parsed_alerts:
        return "No threats detected.", "No remediation required."
    
    # Format the parsed alerts cleanly so the LLM can read them
    alerts_context = ""
    for idx, alert in enumerate(parsed_alerts):
        alerts_context += f"- Alert [{idx+1}]: Rule {alert.get('rule_id')}, Severity {alert.get('severity')}, Indicator Asset: {alert.get('src_ip') or alert.get('ip') or alert.get('host')}\n"
        alerts_context += f"  Description: {alert.get('description') or alert.get('message')}\n\n"

    # Construct a highly specific prompt for the technical playbook requirements
    prompt = f"""
    You are the Sentinel Lite Local Security Coprocessor. Analyze these network alert indicators and generate two separate blocks of output.
    
    ALERTS DATA TO PARSE:
    {alerts_context}

    CRITICAL INSTRUCTIONS FOR RECOVERY UTILITIES:
    - If an indicator asset is an internal loopback address (127.0.0.1, localhost, ::1), DO NOT provide firewall blocking commands. Provide system diagnostic steps (e.g., password rotations, auditing listening sockets with 'ss -tulpn').
    - If an asset is a local network IP (192.168.x.x, 10.x.x.x, 172.16.x.x), recommend internal host isolation and connection tracking termination ('sudo conntrack -D -s [IP]').
    - Only provide hard firewall blocks ('sudo iptables -A INPUT -s [IP] -j DROP') for public, external internet addresses.

    You must respond ONLY with a valid JSON object matching this structure (do not include markdown block wrapping):
    {{
        "ai_analysis": "Write a clean markdown executive threat summary of the findings for the dashboard view.",
        "playbook_meta": "Write a point-and-click mitigation playbook for an IT generalist. Use clear section headers, separate items sequentially, and output clean copy-pasteable bash terminal commands wrapped safely according to the IP types analyzed."
    }}
    """

    try:
        # Call the local Ollama API instance
        response = requests.post(
            "http://localhost:11434/api/generate",
            json={
                "model": "llama3", # Change to whatever model you have pulled locally
                "prompt": prompt,
                "format": "json", # Forces Ollama to output valid JSON
                "stream": False
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result_json = response.json()
            # Parse the inner text string string returned by the model
            payload = json.loads(result_json.get("response", "{}"))
            return payload.get("ai_analysis", ""), payload.get("playbook_meta", "")
            
    except Exception as e:
        print(f"Ollama Coprocessor Error: {e}")
        
    return "Error communicating with local AI engine.", "System remediation logic unavailable."
'''
@app.route('/live-sniffer/toggle', methods=['POST'])
def toggle_live_sniffer():
    """Starts or stops the background live telemetry worker threads."""
    global LIVE_SNIFFER_ACTIVE
    data = request.get_json() or {}
    enable = data.get("enable", False)

    # Initialize manager wrapper instance (None defaults to primary system interface)
    sniffer = LiveSnifferManager()

    if enable and not LIVE_SNIFFER_ACTIVE:
        sniffer.start()
        return jsonify({"status": "running", "message": "Live packet capture engine deployed successfully."})
    elif not enable and LIVE_SNIFFER_ACTIVE:
        sniffer.stop()
        return jsonify({"status": "stopped", "message": "Live sniffer paused."})
        
    return jsonify({"status": "no_change", "running": LIVE_SNIFFER_ACTIVE})

@app.route('/live-sniffer/alerts', methods=['GET'])
def get_live_alerts():
    """Endpoint for frontend polling loop to pull newly caught live threats."""
    return jsonify({
        "sniffer_active": LIVE_SNIFFER_ACTIVE,
        "alerts": LIVE_ALERT_CACHE,
        # Check if the playbook file exists to inform the UI panel
        "playbook_compiled": os.path.exists("artifacts/live_remediation_playbook.txt")
    })

@app.route('/live-sniffer/clear', methods=['POST'])
def clear_live_cache():
    """Clears the current volatile memory alert array index."""
    global LIVE_ALERT_CACHE
    LIVE_ALERT_CACHE.clear()
    if os.path.exists("artifacts/live_remediation_playbook.txt"):
        try:
            os.remove("artifacts/live_remediation_playbook.txt")
        except OSError:
            pass
    return jsonify({"status": "cleared"})

if __name__ == '__main__':
    import os
    # Initialize development server boundary on standard port structure
    if __name__ == '__main__':
    # Check if this is the main worker thread, preventing double execution
        if os.environ.get('WERZEUG_RUN_MAIN') == 'true':
            print("[*] Running application initialization sequences...")
            # Put your rule loading/diagnostic function calls here if they are in functions:
            # load_sigma_rules()
            
    # Flask app runs outside the wrapper so both processes know how to handle the server
    app.run(debug=True, port=5000)