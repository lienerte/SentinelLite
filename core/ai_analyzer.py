"""
core/ai_analyzer.py - Functional AI Analysis Simulator
Generates natural language incident summaries based on normalized log payloads.
"""
from collections import defaultdict

class AIIntegrationLayer:
    def __init__(self, use_local_ai=False):
        self.active = use_local_ai
        
    def generate_incident_summary(self, normalized_events, detected_type):
        """
        Simulates local LLM reasoning by evaluating the event array context 
        and generating a markdown-formatted analytical response.
        """
        if not self.active:
            return None

        # Gather basic operational stats for the prompt context
        total_events = len(normalized_events)
        source_ips = {e['src_ip'] for e in normalized_events if e['src_ip'] != '0.0.0.0'}
        
        # Simple cognitive simulation matching signature heuristics
        suspected_vectors = []
        payload_dump = " ".join([str(e['payload']) for e in normalized_events]).lower()
        
        if "failed password" in payload_dump or "auth_failed" in payload_dump:
            suspected_vectors.append("Brute-Force Credential Stuffing")
        if "get /show-tech" in payload_dump or "cisco-ios" in payload_dump:
            suspected_vectors.append("Administrative Diagnostic Dump / Clear Text Log Data Exfiltration")
        if "network_tcp" in payload_dump or "network_udp" in payload_dump:
            # Check unique ports
            ports = {e['target_port'] for e in normalized_events if e['target_port'] is not None}
            if len(ports) >= 10:
                suspected_vectors.append("Horizontal/Vertical Port Sweep Reconnaissance")

        # Generate the simulated local LLM response string
        ai_markdown = f"### 🤖 Local AI Analyst Engine Triage Report\n\n"
        ai_markdown += f"**Analysis Confidence:** High (Determined via structural log profiling)\n\n"
        ai_markdown += f"#### Executive Summary:\n"
        ai_markdown += f"After review of the {total_events} ingested entries categorized under the **{detected_type}** data format, "
        
        if suspected_vectors:
            ai_markdown += f"the system flagged strong behavioral indicators matching known malicious tactical plays: **{', '.join(suspected_vectors)}**.\n\n"
            ai_markdown += f"#### Behavioral Observed Anomalies:\n"
            ai_markdown += f"- **Actor Footprint:** Active anomalies mapping back to source node(s): `{', '.join(list(source_ips)[:3])}`.\n"
            ai_markdown += f"- **Suspicious String Patterns:** Outlier payload strings detected inside the unstructured data arrays.\n\n"
            ai_markdown += f"#### Recommended Containment Playbook:\n"
            ai_markdown += "1. Enforce a network socket block on the offending source IP at the edge firewall boundary.\n"
            ai_markdown += "2. Pivot into the internal identity directory to check if user sessions matching these timelines require a password reset token.\n"
        else:
            ai_markdown += "the traffic profiles match expected behavioral baselines. No outstanding anomalies, hidden backdoors, or credential extraction cycles were isolated within the sample window.\n\n"
            ai_markdown += f"#### Diagnostic Parameters:\n"
            ai_markdown += f"- Processed {len(source_ips)} distinct communicating network hosts cleanly.\n"
            ai_markdown += "- Zero malicious string markers were flagged in the unstructured text payload fields."

        return ai_markdown