from parsers.base_parser import BaseParser
import json

class JsonParser(BaseParser):
    def parse(self, file_path):
        events = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line)
                    events.append(self.normalize_event(
                        timestamp=obj.get("timestamp") or obj.get("time"),
                        src_ip=obj.get("source_ip") or obj.get("src"),
                        dst_ip=obj.get("destination_ip") or obj.get("dst"),
                        target_port=obj.get("port") or obj.get("dport"),
                        user=obj.get("username") or obj.get("user"),
                        event_type=obj.get("event_type") or "JSON_RECORD",
                        payload=str(obj.get("message") or obj)
                    ))
                except json.JSONDecodeError:
                    continue
        return events