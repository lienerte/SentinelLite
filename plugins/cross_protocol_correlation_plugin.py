# plugins/cross_protocol_correlation_plugin.py
"""
plugins/cross_protocol_correlation_plugin.py - Multi-Stage Cross-Log Correlation
Scans the unified, normalized telemetry cache to track malicious lifecycle pivots.
"""
from collections import defaultdict

class CrossProtocolCorrelationPlugin:
    def __init__(self):
        self.rule_id = "R04_CROSS_PROTOCOL_PIVOT"

    def analyze(self, normalized_events):
        """
        Evaluates the global event stream to map source footprint behaviors
        across differing protocol boundaries.
        """
        alerts = []
        # Group historical protocol sightings per unique source actor IP
        ip_footprints = defaultdict(set)
        
        for event in normalized_events:
            src_ip = event.get('src_ip', '0.0.0.0')
            event_type = event.get('event_type', '')
            
            # Filter out generic loopback, placeholder, or invalid strings
            if src_ip in ['0.0.0.0', '127.0.0.1', 'N/A', 'Unknown', None]:
                continue
                
            # Track behaviors matching our standardized system categories
            if "WEB" in event_type:
                ip_footprints[src_ip].add("WEB_RECON")
            if "IDS" in event_type or "FORTINET" in event_type:
                ip_footprints[src_ip].add("PERIMETER_EXPLOITATION")
            if "AUTH_FAILED" in event_type:
                ip_footprints[src_ip].add("CREDENTIAL_BRUTE_FORCE")

        # Evaluate the compiled behavior footprint states
        for src_ip, phases in ip_footprints.items():
            # Flag if the same actor transitioned from perimeter targeting to credential hunting
            has_perimeter_activity = "WEB_RECON" in phases or "PERIMETER_EXPLOITATION" in phases
            has_credential_activity = "CREDENTIAL_BRUTE_FORCE" in phases
            
            if has_perimeter_activity and has_credential_activity:
                alerts.append({
                    "rule_id": self.rule_id,
                    "severity": "CRITICAL",
                    "source": src_ip,
                    "title": "Adversarial Tactic Shift: Cross-Protocol Recon-to-Auth Pivot Detected",
                    "why_it_matters": (
                        f"The host infrastructure node `{src_ip}` was flagged transitioning from "
                        f"unauthorized perimeter vulnerability scans/exploitation directly into targeted "
                        f"credential brute-force routines. This behavior strongly indicates an intentional, "
                        f"multi-stage intrusion lifecycle rather than automated internet background noise."
                    )
                })
                
        return alerts