# core/remediation_orchestrator.py
"""
core/remediation_orchestrator.py - SOAR Advisory Playbook Generator
Consumes pipeline alerts to compile an actionable, point-and-click interactive 
remediation playbook file for system administrators.
"""
import os
import datetime

class RemediationOrchestrator:
    def __init__(self, output_path="artifacts/remediation_playbook.txt"):
        self.output_path = output_path
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)

    def generate_playbook(self, alerts, filename):
        """
        Evaluates the current alerts array. If actionable incidents are found, 
        compiles a structured, on-demand text file outlining explicit manual 
        remediation steps an engineer can copy-paste directly.
        """
        if not alerts:
            return None

        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Build file-level executive layout headers
        playbook_content = []
        playbook_content.append("=" * 80)
        playbook_content.append(f"🛡️  SENTINELLITE ON-DEMAND REMEDIATION PLAYBOOK")
        playbook_content.append(f"Generated:   {timestamp}")
        playbook_content.append(f"Target Log:  {filename}")
        playbook_content.append(f"Status:      PENDING ADMINISTRATIVE REVIEW (MANUAL EXECUTION ONLY)")
        playbook_content.append("=" * 80)
        playbook_content.append("\nThis document provides point-and-click mitigation operations compiled specifically")
        playbook_content.append("from the structural indicators extracted during the active parsing cycle.\n")
        
        actionable_count = 0

        for idx, alert in enumerate(alerts, 1):
            src_ip = alert.get("source", "0.0.0.0")
            severity = alert.get("severity", "LOW")
            rule_id = alert.get("rule_id", "UNKNOWN_RULE")
            title = alert.get("title", "Generic Incident Marker")
            
            # Skip loopbacks, internal placeholders, or unassigned scopes
            if src_ip in ["0.0.0.0", "127.0.0.1", "N/A", "Unknown", None]:
                continue
                
            actionable_count += 1
            playbook_content.append(f"[{actionable_count}] INCIDENT TIER: {severity} | TRIGGER RULE: {rule_id}")
            playbook_content.append(f"    Symptom Summary: {title}")
            playbook_content.append(f"    Target Actor Host: {src_ip}\n")
            playbook_content.append("    👉 MANDATORY REMEDIATION COMMANDS (Copy & Paste to Server Terminal):")
            
            # Formulate granular recipes based on exact signature tiers
            if severity == "CRITICAL" or rule_id == "R04_CROSS_PROTOCOL_PIVOT":
                playbook_content.append(f"        # Option A: Isolate network layer via Linux Netfilter firewall")
                playbook_content.append(f"        sudo iptables -A INPUT -s {src_ip} -j DROP -m comment --comment 'SentinelLite Manual Block'")
                playbook_content.append(f"        ")
                playbook_content.append(f"        # Option B: Commit instant SSH service ban via host-based IDS")
                playbook_content.append(f"        sudo fail2ban-client set sshd banip {src_ip}")
            elif severity == "HIGH":
                playbook_content.append(f"        # Restrict standard port connectivity for the target host node")
                playbook_content.append(f"        sudo iptables -A INPUT -s {src_ip} -p tcp --dport 22 -j REJECT")
            elif severity == "MEDIUM" or "AUDIT" in rule_id:
                playbook_content.append(f"        # Audit cleartext administrative footprint. Enforce connection pooling / TLS encapsulation.")
                playbook_content.append(f"        # Review target device configurations matching source management node: {src_ip}")
                playbook_content.append(f"        echo '[WARN] Transition cleartext HTTP endpoint interactions to SSHv2 or HTTPS immediately.'")
            else:
                playbook_content.append(f"        # Low-risk triage block. Monitor host footprints for escalation indicators.")
                playbook_content.append(f"        echo '[INFO] Monitor traffic trends for source IP: {src_ip}'")
                
            playbook_content.append("\n" + "-" * 80 + "\n")

        # Only commit to disk if we mapped actual actionable infrastructure targets
        if actionable_count > 0:
            full_text = "\n".join(playbook_content)
            with open(self.output_path, "w", encoding="utf-8") as f:
                f.write(full_text)
            return {
                "file_created": True,
                "output_path": self.output_path,
                "actionable_targets": actionable_count
            }
        
        return None