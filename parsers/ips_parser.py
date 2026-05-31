# parsers/ips_parser.py
import re
from parsers.base_parser import BaseParser

class IpsParser(BaseParser):
    def parse(self, file_path):
        normalized_records = []
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
        # Leverage a global regex iterator to cleanly isolate the embedded Fortinet 
        # log blocks hidden within the structured text wrapper strings
        log_entries = re.findall(r'date=\d{4}-\d{2}-\d{2},time=[^\n]+', content)
        
        for entry in log_entries:
            try:
                # 1. Exact, precise extraction matching for key telemetry indicators
                src_match = re.search(r'\bsrc=([\d\.]+)', entry)
                dst_match = re.search(r'\bdst=([\d\.]+)', entry)
                attack_match = re.search(r'attack_name=([^,\s"]+)', entry)
                severity_match = re.search(r'severity=([^,\s"]+)', entry)
                
                # 2. Extract out service port if available, default to database targets
                port_match = re.search(r'service=(\d+)', entry)
                target_port = int(port_match.group(1)) if port_match else 1521
                
                if attack_match:
                    # Leverage the normalization layout defined in BaseParser
                    record = self.normalize_event(
                        timestamp=None, # Fallback to server triage timestamp 
                        src_ip=src_match.group(1) if src_match else "0.0.0.0",
                        dst_ip=dst_match.group(1) if dst_match else "0.0.0.0",
                        target_port=target_port,
                        user="N/A",
                        event_type="NETWORK_IDS_ALERT",
                        payload=f"[{severity_match.group(1).upper() if severity_match else 'ALERT'}] IDS Signature Flagged: {attack_match.group(1)}"
                    )
                    normalized_records.append(record)
                
            except Exception as e:
                print(f"[-] Parsing exception encountered inside IpsParser matrix: {e}")
                continue
            
        return normalized_records