# parsers/auth_parser.py
from parsers.base_parser import BaseParser
import re

class AuthParser(BaseParser):
    def parse(self, file_path):
        events = []
        
        # RESILIENT REGEX: Loosened mid-line boundaries using .*? to tolerate log line variances
        pattern = re.compile(
            r'(?P<ts>\b[A-Z][a-z]{2}\s+\d+\s+\d+:\d+:\d+).*?'
            r'sshd\[\d+\]:\s+(?P<status>Failed|Accepted)\s+password\s+(?:for\s+)?(?:invalid\s+user\s+)?'
            r'(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+port\s+(?P<port>\d+)'
        )
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                clean_line = line.strip()
                if not clean_line:
                    continue
                    
                match = pattern.search(clean_line)
                if match:
                    data = match.groupdict()
                    events.append(self.normalize_event(
                        timestamp=data['ts'], 
                        src_ip=data['ip'], 
                        dst_ip="127.0.0.1",
                        target_port=data['port'], 
                        user=data['user'],
                        event_type=f"AUTH_{data['status'].upper()}", 
                        payload=clean_line
                    ))
                else:
                    # Echo drops to terminal standard out to verify tracking mismatches
                    print(f"[PARSER DEBUG] Regular expression failed to extract line fields: {clean_line}")
                    
        return events