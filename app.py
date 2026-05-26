# app.py (Updated for Asynchronous Processing)
from flask import Flask, render_template, request, jsonify
import os
from core import LogClassifier, ParserFactory, AnalysisEngine, AIIntegrationLayer

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/', methods=['GET'])
def index():
    # Instantly renders the clean dashboard frame without any processing lag
    return render_template('index.html', run_analysis=False)

# inside app.py

@app.route('/analyze-async', methods=['POST'])
def analyze_async():
    if 'file' not in request.files:
        return jsonify({"error": "No file payload detected"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file name found"}), 400
        
    try:
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(save_path)
        
        override_type = request.form.get('override_type') or None
        run_ai_checkbox = request.form.get('run_ai') == 'true'

        # Run auto-detect behind the scenes to establish a baseline truth
        auto_detected_type, _ = LogClassifier.classify(save_path)
        
        # Decide which routing tag to execute
        if override_type:
            log_type = override_type.upper()
        else:
            log_type = auto_detected_type
            
        # Determine if a validation mismatch occurred
        # (Ignore mismatch if override matches auto, or if auto is UNKNOWN but user tried to force a type)
        mismatch_detected = False
        if override_type and auto_detected_type != "UNKNOWN" and override_type.upper() != auto_detected_type:
            mismatch_detected = True

        if log_type == "UNKNOWN":
            return jsonify({
                "filename": file.filename,
                "log_type": "UNKNOWN",
                "auto_detect_type": auto_detected_type,
                "mismatch_detected": False,
                "alerts": [],
                "ai_report": "### 🤖 Ingestion Error\nFramework parsing skipped: Unrecognized file structural fingerprints."
            })

        # Process through normal engineering pipeline steps
        parser = ParserFactory.get_parser(log_type)
        events = parser.parse(save_path)

        engine = AnalysisEngine()
        alerts = engine.execute_pipeline(events)

        ai_layer = AIIntegrationLayer(use_local_ai=run_ai_checkbox)
        ai_report = ai_layer.generate_incident_summary(events, log_type)

        # Pack payload returning the mismatch context parameters
        return jsonify({
            "filename": file.filename,
            "log_type": log_type,
            "auto_detect_type": auto_detected_type,
            "mismatch_detected": mismatch_detected,
            "alerts": alerts,
            "ai_report": ai_report
        })

    except Exception as e:
        return jsonify({"error": f"Internal pipeline exception: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)