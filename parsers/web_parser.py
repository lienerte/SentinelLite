from parsers.base_parser import BaseParser
import re

class WebParser(BaseParser):
    def parse(self, file_path):
        events = []
        # Web regex configuration matching Nginx / Apache Standard Combined structures
        pattern = re.compile(r'(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?\[(?P<ts>.*?)\].*?"(?P<verb>[A-Z]+)\s(?P<uri>\S+)\s.*?".*?(?P<status>\d{3})')
        
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    data = match.groupdict()
                    events.append(self.normalize_event(
                        timestamp=data['ts'], src_ip=data['ip'], dst_ip="0.0.0.0",
                        target_port=80 if data['verb'] != "CONNECT" else 443, user=None,
                        event_type=f"WEB_{data['status']}", payload=f"{data['verb']} {data['uri']}"
                    ))
        return events