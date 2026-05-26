# plugins/brute_force_plugin.py
from collections import defaultdict

class BruteForcePlugin:
    def analyze(self, events):
        alerts = []
        tracker = defaultdict(int)
        
        for e in events:
            if "AUTH_FAILED" in e['event_type'] or e['target_port'] in [22, 3389]:
                tracker[e['src_ip']] += 1

        for src_ip, count in tracker.items():
            if count >= 5: # Small threshold for fast prototyping
                alerts.append({
                    "rule_id": "R01_AUTH_BRUTE_FORCE",
                    "severity": "HIGH",
                    "source": src_ip,
                    "title": "Credential Access: High Authentication Failures",
                    "why_it_matters": "Adversaries utilize high-velocity password guessing (credential stuffing) against authentication ports to gain initial unauthorized network access."
                })
        return alerts