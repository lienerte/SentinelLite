import os
import json
import re

class LogClassifier:
    @staticmethod
    def classify(file_path):
        """Inspects file headers, extensions, and content patterns to determine log type."""
        if not os.path.exists(file_path):
            return "UNKNOWN", 0.0

        filename = file_path.lower()
        
        # 1. Binary Magic Byte check for PCAP/PCAPNG
        try:
            with open(file_path, 'rb') as f:
                magic_bytes = f.read(4)
                if magic_bytes in [b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\xc3\xd4', b'\n\r\r\n']:
                    return "PCAP", 1.0
        except IOError:
            pass

        if filename.endswith('.pcap') or filename.endswith('.pcapng'):
            return "PCAP", 1.0

        # 2. String-based structural inspection
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                sample_lines = [f.readline() for _ in range(10)]
                sample_content = "".join(sample_lines)

            # Check JSON
            try:
                json.loads(sample_content.strip().split('\n')[0])
                return "JSON", 1.0
            except (json.JSONDecodeError, IndexError):
                pass

            # Check Auth Logs (sshd, pam, failed credentials keyword tracking)
            auth_keywords = re.compile(r'(sshd|pam_unix|failed\s+password|accepted\s+publickey|authentication\s+failure)', re.IGNORECASE)
            if auth_keywords.search(sample_content):
                return "AUTH", 0.90

            # Check Web Server Logs (Nginx / Apache Common/Combined pattern matches)
            web_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\s"([A-Z]{3,7})\s.*?\sHTTP/\d\.\d"', re.IGNORECASE)
            if web_pattern.search(sample_content):
                return "WEB", 0.95

        except Exception:
            return "UNKNOWN", 0.0

        return "UNKNOWN", 0.10