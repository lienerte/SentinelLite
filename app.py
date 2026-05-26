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

@app.route('/analyze-async', methods=['POST'])
def analyze_async():
    """
    Asynchronous API Endpoint called via JavaScript.
    Processes data background loops and returns a clean JSON summary object.
    """
    if 'file' not in request.files:
        return jsonify({"error": "No file payload detected"}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file name found"}), 400
        
    try:
        # Save target file to storage cache
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(save_path)
        
        # Read parameters sent from the frontend form metadata
        override_type = request.form.get('override_type') or None
        run_ai_checkbox = request.form.get('run_ai') == 'true'

        # 1. Structural Classification
        if override_type:
            log_type = override_type.upper()
        else:
            log_type, _ = LogClassifier.classify(save_path)
            
        if log_type == "UNKNOWN":
            return jsonify({
                "filename": file.filename,
                "log_type": "UNKNOWN",
                "alerts": [],
                "ai_report": "### 🤖 Ingestion Error\nFramework parsing skipped: Unrecognized file metadata structural signatures."
            })

        # 2. Extract Data via Factory
        parser = ParserFactory.get_parser(log_type)
        events = parser.parse(save_path)

        # 3. Static Engine Heuristics Scanning
        engine = AnalysisEngine()
        alerts = engine.execute_pipeline(events)

        # 4. Downstream Local AI Inference Call
        ai_layer = AIIntegrationLayer(use_local_ai=run_ai_checkbox)
        ai_report = ai_layer.generate_incident_summary(events, log_type)

        # Return data directly as a JSON payload object instead of reloading the page
        return jsonify({
            "filename": file.filename,
            "log_type": log_type,
            "alerts": alerts,
            "ai_report": ai_report
        })

    except Exception as e:
        return jsonify({"error": f"Internal pipeline exception: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)