# core/log_classifier.py
"""
core/log_classifier.py - Ingestion Classification Engine
Performs lightning-fast, zero-dependency pattern fingerprinting 
on raw file headers to determine the appropriate parsing strategy.
"""
import os

class LogClassifier:
    @classmethod  # ◄ Changed from @staticmethod
    def classify(cls, file_path):  # ◄ Uses cls instead of self or raw parameters
        """
        Reads the initial bytes of a file to detect structural markers.
        """
        if not os.path.exists(file_path):
            return "UNKNOWN", "text/plain"

        # Read the first 4KB of data for high-performance sniffing
        try:
            with open(file_path, 'rb') as f:
                header_bytes = f.read(4096)
        except Exception as e:
            print(f"[-] Critical read error encountered during triage: {e}")
            return "UNKNOWN", "text/plain"

        if not header_bytes:
            return "UNKNOWN", "text/plain"

        # 1. PCAP Magic Number Validation
        # 0xa1b2c3d4 or 0xd4c3b2a1 (Standard PCAP) | 0x0a0d0d0a (PCAPNG)
        if (header_bytes.startswith(b'\xa1\xb2\xc3\xd4') or 
            header_bytes.startswith(b'\xd4\xc3\xb2\xa1') or 
            header_bytes.startswith(b'\x0a\x0d\x0d\x0a')):
            return "PCAP", "application/vnd.tcpdump.pcap"

        # Decode sample data securely for text-based signature mapping
        try:
            sample_text = header_bytes.decode('utf-8', errors='ignore')
        except Exception:
            return "UNKNOWN", "application/octet-stream"

        # 2. FORTINET IPS Dataset Fingerprint Detection
        # Searches for embedded signature metadata strings found in firewall threat logs
        if ("fortinet_ips" in sample_text.lower() or 
            "attack_name=" in sample_text.lower() or 
            "incident_serialno=" in sample_text.lower()):
            return "FORTINET_IPS", "text/csv"

        # 3. Structured JSON Schema Check
        stripped_sample = sample_text.strip()
        if stripped_sample.startswith('{') or stripped_sample.startswith('['):
            return "JSON", "application/json"

        # 4. Standard Syslog Authentication Engine Heuristics
        if "sshd[" in sample_text or "password for" in sample_text or "auth_failed" in sample_text:
            return "AUTH", "text/plain"

        # 5. Combined Web Server / Gateway Access Log Footprints
        if ("GET /" in sample_text or "POST /" in sample_text or 
            "HTTP/1.1" in sample_text or "HTTP/2.0" in sample_text):
            return "WEB", "text/plain"

        # Fallback boundary if file contains unstructured data
        return "UNKNOWN", "text/plain"