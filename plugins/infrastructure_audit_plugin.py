# plugins/infrastructure_audit_plugin.py
"""
plugins/infrastructure_audit_plugin.py - Sensitive Operational Visibility
Flags plain-text administrative infrastructure data exchanges within network telemetry.
"""
class InfrastructureAuditPlugin:
    def __init__(self):
        self.rule_id = "R05_INFRA_AUDIT_EXCHANGE"

    def analyze(self, normalized_events):
        alerts = []
        
        for event in normalized_events:
            event_type = event.get('event_type', '')
            payload = event.get('payload', '')
            
            if event_type == "INFRASTRUCTURE_AUDIT_COMMAND" or "show-tech" in payload.lower():
                alerts.append({
                    "rule_id": self.rule_id,
                    "severity": "MEDIUM",
                    "source": event.get('src_ip', 'Unknown'),
                    "title": "Sensitive Infrastructure Audit Transmission Detected",
                    "why_it_matters": (
                        f"An asset generated an unencrypted cleartext administrative data request: `{payload[:60]}`. "
                        f"While completely benign and non-malicious, transmitting operational metrics "
                        f"(like Cisco show-tech summaries) over raw packet streams leaks topological architecture parameters "
                        f"to potential internal eavesdroppers."
                    )
                })
                
        return alerts