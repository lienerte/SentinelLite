# plugins/port_scan_plugin.py
from collections import defaultdict

class PortScanPlugin:
    def analyze(self, events):
        alerts = []
        tracker = defaultdict(set)
        
        for e in events:
            if e['target_port'] is not None:
                tracker[e['src_ip']].add(e['target_port'])

        for src_ip, ports in tracker.items():
            if len(ports) >= 10:
                alerts.append({
                    "rule_id": "R02_PORT_SCAN",
                    "severity": "MEDIUM",
                    "source": src_ip,
                    "title": "Reconnaissance: Network Port Scan Flagged",
                    "why_it_matters": "Before an exploit takes place, adversaries systematically interrogate hosts to discover exposed services and entry points."
                })
        return alerts