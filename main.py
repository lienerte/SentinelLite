import argparse
import sys
from core.log_classifier import LogClassifier
from core.parser_factory import ParserFactory
from core.analysis_engine import AnalysisEngine

def process_pipeline(file_path, manual_override=None):
    # 1. Classification
    if manual_override:
        log_type, confidence = manual_override.upper(), 1.0
    else:
        log_type, confidence = LogClassifier.classify(file_path)
        
    print(f"[*] Pipeline Routing Target -> Format: {log_type} (Confidence: {confidence:.2f})")
    
    if log_type == "UNKNOWN":
        print("[-] Aborting: Incapable of structurally routing file context types safely.")
        return [], log_type
        
    # 2. Ingestion Routing via Factory
    parser = ParserFactory.get_parser(log_type)
    events = parser.parse(file_path)
    print(f"[+] Operational Ingestion Stage Complete: Normalized {len(events)} tracking entries.")
    
    # 3. Detection Processing Loop
    engine = AnalysisEngine()
    alerts = engine.execute_pipeline(events)
    return alerts, log_type

def main():
    parser = argparse.ArgumentParser(description="OmniSIEM Extensible Parsing & Analytics Driver")
    parser.add_argument("-f", "--file", required=True, help="Target capture log telemetry node path")
    parser.add_argument("-t", "--type", help="Manual structural override flag (PCAP, AUTH, WEB, JSON)")
    args = parser.parse_args()

    alerts, detected_as = process_pipeline(args.file, args.type)
    
    print(f"\n================= OMNISIEM REPORT: [{len(alerts)}] INCIDENTS =================")
    for idx, alert in enumerate(alerts, 1):
        print(f"[{idx}] {alert['title']} - [{alert['severity']}]")
        print(f"    Source Vector: {alert['source']}")
        print(f"    Contextual Impact: {alert['why_it_matters']}\n")

if __name__ == "__main__":
    main()