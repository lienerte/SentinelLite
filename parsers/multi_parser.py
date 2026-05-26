# parsers/multi_parser.py
"""
parsers/multi_parser.py - Robust Multiplexing Ingestion Layer
Uses flexible regular expressions to capture mixed protocol lines safely.
"""
import re
from parsers.base_parser import BaseParser

class MultiParser(BaseParser):
    def parse(self, file_path):
        normalized_records = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    clean_line = line.strip()
                    if not clean_line:
                        continue
                    
                    # 1. Fortinet IPS / Firewall Lines Check
                    # Looks for 'attack_name=' anywhere in the line, with or without quotes
                    if re.search(r'attack_name\s*=', clean_line, re.IGNORECASE):
                        src_match = re.search(r'\bsrc=([^\s,"]+)', clean_line) or re.search(r'\bsrc_ip=([^\s,"]+)', clean_line)
                        dst_match = re.search(r'\bdst=([^\s,"]+)', clean_line) or re.search(r'\bdst_ip=([^\s,"]+)', clean_line)
                        attack_match = re.search(r'attack_name=([^,\s"]+)', clean_line)
                        severity_match = re.search(r'severity=([^,\s"]+)', clean_line)
                        
                        if attack_match:
                            normalized_records.append(self.normalize_event(
                                timestamp=None,
                                src_ip=src_match.group(1) if src_match else "0.0.0.0",
                                dst_ip=dst_match.group(1) if dst_match else "0.0.0.0",
                                target_port=1521,
                                user="N/A",
                                event_type="FORTINET_IDS_ALERT",
                                payload=f"[{severity_match.group(1).upper() if severity_match else 'ALERT'}] IPS Flagged: {attack_match.group(1)}"
                            ))
                            continue  # Cleanly move to the next log line

                    # 2. Nginx / Apache Web Access Log Check
                    # Matches lines containing standard HTTP methods (GET, POST, PUT, DELETE)
                    if re.search(r'\]\s*"(?:GET|POST|PUT|DELETE|HEAD)\s', clean_line, re.IGNORECASE) or re.search(r'"(?:GET|POST)\s', clean_line):
                        # Capture the leading IP address component safely
                        ip_match = re.match(r'^([\d\.]+)', clean_line) or re.search(r'\b(?:src|src_ip)=([\d\.]+)', clean_line)
                        if ip_match:
                            normalized_records.append(self.normalize_event(
                                timestamp=None,
                                src_ip=ip_match.group(1),
                                dst_ip="10.0.0.80",
                                target_port=80,
                                user="N/A",
                                event_type="WEB_ACCESS_RECON",
                                payload=f"Web Scan Endpoint Target: {clean_line[:120]}..."
                            ))
                            continue

                    # 3. Linux Syslog Authentication Check
                    # Matches common authentication failure signature phrases
                    if re.search(r'(Failed password|Accepted password|authentication failure|AUTH_FAILED)', clean_line, re.IGNORECASE):
                        ip_match = re.search(r'from\s+([\d\.]+)', clean_line) or re.search(r'\b(?:src|src_ip)=([\d\.]+)', clean_line)
                        user_match = re.search(r'for\s+(?:invalid\s+user\s+)?(\S+)', clean_line, re.IGNORECASE)
                        
                        if ip_match:
                            normalized_records.append(self.normalize_event(
                                timestamp=None,
                                src_ip=ip_match.group(1),
                                dst_ip="10.0.0.22",
                                target_port=22,
                                user=user_match.group(1) if user_match else "root",
                                event_type="AUTH_FAILED",
                                payload="SSH Credential Attack Sequence Detected"
                            ))
                            continue
                            
        except Exception as e:
            print(f"[!] Warning: Structural parsing bypass on line {line_num}: {e}")
            continue
            
        return normalized_records