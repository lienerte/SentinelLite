# parsers/base_parser.py
class BaseParser:
    """Enforces common interfaces and standard internal data definitions across log layers."""
    def parse(self, file_path):
        raise NotImplementedError("Parsers must explicitly build custom event transformation loops.")
        
    def normalize_event(self, timestamp, src_ip, dst_ip, target_port, user, event_type, payload):
        """Returns standard data structures for ingestion across the framework ecosystem."""
        return {
            "timestamp": timestamp or "UNKNOWN_TIME",
            "src_ip": src_ip or "0.0.0.0",
            "dst_ip": dst_ip or "0.0.0.0",
            "target_port": int(target_port) if target_port else None,
            "user": user or "SYSTEM",
            "event_type": event_type or "GENERIC",
            "payload": payload or ""
        }
