# app.py (Updated Routing Architecture)
from flask import Flask, render_template, request, redirect
import os
from core.log_classifier import LogClassifier
from core.parser_factory import ParserFactory
from core.analysis_engine import AnalysisEngine
from core.ai_analyzer import AIIntegrationLayer  # Import our AI Layer

app = Flask(__name__)
UPLOAD_FOLDER = './uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def process_pipeline(file_path, manual_override=None, run_ai=False):
    # 1. Classification
    if manual_override:
        log_type = manual_override.upper()
    else:
        log_type, _ = LogClassifier.classify(file_path)
        
    if log_type == "UNKNOWN":
        return [], log_type, None
        
    # 2. Parse Data
    parser = ParserFactory.get_parser(log_type)
    events = parser.parse(file_path)
    
    # 3. Standard Signature Engine Analytics
    engine = AnalysisEngine()
    alerts = engine.execute_pipeline(events)
    
    # 4. Local AI Simulation Execution
    ai_layer = AIIntegrationLayer(use_local_ai=run_ai)
    ai_report = ai_layer.generate_incident_summary(events, log_type)
    
    return alerts, log_type, ai_report

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            return redirect(request.url)
            
        if file:
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(save_path)
            
            # Read variables from the HTML form post context
            override_type = request.form.get('override_type') or None
            run_ai_checkbox = 'run_ai' in request.form  # True if box is checked
            
            alerts, detected_type, ai_report = process_pipeline(
                save_path, override_type, run_ai_checkbox
            )
            
            return render_template(
                'index.html', run_analysis=True, filename=file.filename,
                log_type=detected_type, alerts=alerts, ai_report=ai_report
            )
                                   
    return render_template('index.html', run_analysis=False)

if __name__ == '__main__':
    app.run(debug=True, port=5000)