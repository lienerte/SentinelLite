# plugins/volume_spike_plugin.py
from collections import defaultdict

class VolumeSpikePlugin:
    def analyze(self, events):
        alerts = []
        tracker = defaultdict(int)
        
        for e in events:
            tracker[e['src_ip']] += 1

        for src_ip, count in tracker.items():
            if count > 200:
                alerts.append({
                    "rule_id": "R03_VOLUME_SPIKE",
                    "severity": "LOW",
                    "source": src_ip,
                    "title": "Anomalous Volumetric Baseline Exceeded",
                    "why_it_matters": "Massive sudden packet volumes can indicate either a denial-of-service attack pattern or an active internal data exfiltration event."
                })
        return alerts