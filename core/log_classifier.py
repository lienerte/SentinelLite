# core/log_classifier.py
"""
core/log_classifier.py - Intelligent Multi-Protocol Ingestion Classifier
Heuristically fingerprints file headers to automatically detect single-format
or mixed multiplexed log streams.
"""
import os
import re

class LogClassifier:
    @classmethod
    def classify(cls, file_path):
        """
        Reads the initial bytes of a file to detect structural markers.
        Returns a tuple: (classification_string, mime_hint)
        """
        if not os.path.exists(file_path):
            return "UNKNOWN", "text/plain"

        # Read the first 4KB for high-performance sniffing
        try:
            with open(file_path, 'rb') as f:
                header_bytes = f.read(4096)
        except Exception as e:
            print(f"[-] Critical read error encountered during triage: {e}")
            return "UNKNOWN", "text/plain"

        if not header_bytes:
            return "UNKNOWN", "text/plain"

        # 1. PCAP Magic Number Validation (Stays binary-first)
        if (header_bytes.startswith(b'\xa1\xb2\xc3\xd4') or 
            header_bytes.startswith(b'\xd4\xc3\xb2\xa1') or 
            header_bytes.startswith(b'\x0a\x0d\x0d\x0a')):
            return "PCAP", "application/vnd.tcpdump.pcap"

        try:
            sample_text = header_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return "UNKNOWN", "application/octet-stream"

        # 2. Multiplexed Mixed-Log Detection Matrix
        # Count how many unique protocol footprints exist in the same sample snippet
        detected_formats = set()

        if re.search(r'attack_name\s*=|fortinet', sample_text, re.IGNORECASE):
            detected_formats.add("FORTINET_IPS")
            
        if re.search(r'(Failed password|authentication failure|sshd|AUTH_FAILED)', sample_text, re.IGNORECASE):
            detected_formats.add("AUTH")
            
        if re.search(r'\]\s*"(?:GET|POST|PUT|DELETE)\s', sample_text, re.IGNORECASE):
            detected_formats.add("WEB")

        # CRITICAL PIVOT: If more than one format type is flagged, it's a mixed attack narrative!
        if len(detected_formats) > 1:
            return "MULTI", "text/plain"

        # 3. Fallback to individual single-format matchers if it wasn't a mixed file
        if "FORTINET_IPS" in detected_formats:
            return "FORTINET_IPS", "text/csv"
            
        if "AUTH" in detected_formats:
            return "AUTH", "text/plain"
            
        if "WEB" in detected_formats:
            return "WEB", "text/plain"

        # Structured JSON Check
        stripped_sample = sample_text.strip()
        if stripped_sample.startswith('{') or stripped_sample.startswith('['):
            return "JSON", "application/json"

        return "UNKNOWN", "text/plain"