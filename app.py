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
            
            # Generate playbook if dynamic rules caught malicious text indicators
            playbook_meta = None
            if alerts:
                soar_engine = RemediationOrchestrator()
                playbook_meta = soar_engine.generate_playbook(alerts, file.filename)
            
            # Set up a conditional message for the AI layer
            ai_report = ""
            if run_ai_checkbox:
                if alerts:
                    ai_report = f"### 🤖 Local AI Analysis Matrix\nIdentified {len(alerts)} threat indicators matching open-source Sigma rules inside unclassified telemetry payload structure."
                else:
                    ai_report = "### 🤖 Ingestion Error\nFramework parsing skipped: Unrecognized file structural fingerprints."

            return jsonify({
                "filename": file.filename,
                "log_type": "UNKNOWN",
                "auto_detect_type": auto_detected_type,
                "mismatch_detected": False,
                "alerts": alerts,
                "playbook_meta": playbook_meta,
                "ai_report": ai_report
            })

        # 3. Normalization Phase: Resolve factory object and parse bytes to schema dictionaries
        parser = ParserFactory.get_parser(log_type)
        events = parser.parse(save_path)

        # 4. Correlation Phase: Run your new global 3k+ Sigma rules engine
        # Read the raw bytes or iterate across reconstructed text events
        with open(save_path, 'rb') as f:
            raw_bytes = f.read()
        alerts = rules_engine.evaluate_log_data(raw_bytes)

        # 5. SOAR Advisory Phase: Compile point-and-click mitigation instructions if threats exist
        soar_engine = RemediationOrchestrator()
        playbook_meta = soar_engine.generate_playbook(alerts, file.filename)

        # 6. Generative Coprocessor Phase: Pass context arrays downstream to local LLM
        ai_layer = AIIntegrationLayer(use_local_ai=run_ai_checkbox)
        ai_report = ai_layer.generate_incident_summary(events, log_type)

        # Return full payload synchronization mapping back to frontend JavaScript renderer
        return jsonify({
            "filename": file.filename,
            "log_type": log_type,
            "auto_detect_type": auto_detected_type,
            "mismatch_detected": mismatch_detected,
            "alerts": alerts,
            "playbook_meta": playbook_meta,
            "ai_report": ai_report
        })

    except Exception as e:
        print(f"[-] Catastrophic pipeline breakdown inside app.py loop: {e}")
        return jsonify({"error": f"Internal pipeline exception: {str(e)}"}), 500

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