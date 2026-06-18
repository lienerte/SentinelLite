"""
core/ai_analyzer.py - Live Local LLM Ingestion Connector
Architected to bridge SentinelLite's normalized event telemetry to local models.
"""
import json
import requests

class AIIntegrationLayer:
    def __init__(self, use_local_ai=True):
        self.active = use_local_ai
        # Default local engine listening port for Ollama instances
        self.ollama_url = "http://localhost:11434/api/generate"
        # Using llama3 as the dedicated security analyzer target
        self.model_target = "llama3:latest"
        
    def generate_incident_summary(self, normalized_events, detected_type):
        """
        Pipes normalized event context strings to a local LLM inference boundary,
        enforces structured JSON output matching domain protocols, and returns 
        both a Markdown assessment and a copy-pasteable mitigation playbook.
        """
        # Maintain your existing state check variable (self.active or self.use_local_ai)
        if hasattr(self, 'active') and not self.active:
            return "No analysis generated or AI checkbox was disabled.", ""
        if hasattr(self, 'use_local_ai') and not self.use_local_ai:
            return "No analysis generated or AI checkbox was disabled.", ""

        if not normalized_events:
            return "### 🤖 Local AI Analyst Engine\n*Ingestion stream empty. No analytical matrix context available to evaluate.*", ""

        # TRUNCATION STRATEGY: Sample the first 15 events to comfortably fit 
        # inside standard local context windows while preserving execution speeds.
        log_sample = normalized_events[:15]
        
        # PROMPT ENGINEERING: Hardened structural guardrails for deterministic output layout
        prompt = (
            f"You are an expert Principal SOC Analyst and Infrastructure Security Engineer. Analyze the provided "
            f"normalized alert matrix with strict technical accuracy. Be precise and realistic.\n\n"
            
            f"CRITICAL ANALYSIS RULES:\n"
            f"1. CONTEXTUAL REASONING: Differentiate between adversarial attacks and cleartext operational audits. "
            f"A 'show-tech' command from a 'cisco-IOS' User-Agent indicates a benign network management tool, "
            f"NOT an external hacker penetration attempt. The risk is strictly DATA LEAKAGE via cleartext transport.\n"
            f"2. PROTOCOL SANITY CHECK: High volume TCP ACK ('A') packets inside a data stream are standard network "
            f"acknowledgements for file/payload delivery, not automated scanning routines.\n"
            f"3. PERFORMANCE SAFEGUARDS: Never suggest blocking critical baseline protocol behaviors like TCP ACK flags, "
            f"as doing so disrupts legitimate state tracking and breaks active user connections. "
            f"Focus remediation entirely on forcing protocol encapsulation (e.g., migrating HTTP to HTTPS/SSH), "
            f"implementing network segmentation, or configuring restrictive management plane Access Control Lists (ACLs).\n\n"
            
            f"CRITICAL COMMAND EXECUTION RULES:\n"
            f"4. INTERNAL LOOPBACK IPS: If an asset is 127.0.0.1 or localhost, DO NOT provide firewall blocking commands. Provide system diagnostic steps (e.g., 'ss -tulpn').\n"
            f"5. LOCAL LAN IPS: If an asset is a private network node (192.168.x.x, 10.x.x.x, 172.16.x.x), recommend host isolation and 'sudo conntrack -D -s [IP]'.\n"
            f"6. EXTERNAL PUBLIC IPS: Provide 'sudo iptables -A INPUT -s [IP] -j DROP' and 'fail2ban-client' commands ONLY for remote public internet addresses.\n\n"
            
            f"LOG DATA TO EVALUATE (JSON Format):\n{json.dumps(log_sample, indent=2)}\n\n"
            
            f"STRICT OUTPUT MANDATE:\n"
            f"You must respond ONLY with a valid JSON object matching this schema structure. Do not include markdown block wrapping or backticks outside the values:\n"
            f"{{\n"
            f"    \"ai_analysis\": \"### **Threat Overview: [Insert 'Malicious Activity Detected' OR 'No Malicious Activity Indicated']**\\n\\n[Write a clean, 2-paragraph executive assessment here. Apply the contextual reasoning rules, protocol sanity checks, and performance safeguards directly to explain the findings.]\\n\\n### **Recommendations:**\\n1. [Recommendation 1]\\n2. [Recommendation 2]\\n3. [Recommendation 3]\\n4. [Recommendation 4]\\n\\n**[Conclude with a final, single-sentence explicit callout stating exactly whether or not malicious activity was verified.]**\",\n"
            f"    \"playbook_meta\": \"Write an on-demand, point-and-click mitigation runbook for an IT generalist. Use clear section headers, separate items sequentially, and output clean copy-pasteable bash terminal commands wrapped safely according to the IP type boundaries outlined above.\"\n"
            f"}}"
        )

        try:
            # Target URL evaluation (synchronizing self.ollama_url or self.endpoint)
            url = getattr(self, 'ollama_url', None) or getattr(self, 'endpoint', "http://localhost:11434/api/generate")
            
            response = requests.post(
                url,
                json={
                    "model": self.model_target, 
                    "prompt": prompt, 
                    "format": "json", # Instructs Ollama to strictly enforce a valid JSON return array
                    "stream": False   
                },
                timeout=90  # Bumped to 90s to give consumer hardware room to process dual output blocks safely
            )
            
            if response.status_code == 200:
                result_json = response.json()
                # Parse the inner stringified response returned by the model
                payload = json.loads(result_json.get("response", "{}"))
                
                ai_analysis = payload.get("ai_analysis", "No dashboard overview generated.")
                playbook_meta = payload.get("playbook_meta", "No automated remediation commands compiled.")
                
                return ai_analysis, playbook_meta
            else:
                err_msg = (
                    f"### 🤖 AI Core Exception\n"
                    f"Local engine returned status code: `{response.status_code}`.\n"
                    f"Verify that model tracking registers match target: `{self.model_target}`."
                )
                return err_msg, "System remediation playbook generation aborted."
                
        except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
            # Synchronized fallback error documentation for non-technical administrators
            fallback_summary = (
                f"### 🤖 Local AI Analyst Engine Triage Report\n\n"
                f"**Status:** Communication with Core Local LLM Aborted\n\n"
                f"**Error Context:** `{str(e)}` \n\n"
                f"**Remediation Steps to Activate:**\n"
                f"1. Ensure the **Ollama** engine is actively running on your host machine.\n"
                f"2. Open a terminal and run `ollama list` to confirm that `{self.model_target}` is successfully cached.\n"
                f"3. Re-execute the SentinelLite upload analyzer routine."
            )
            return fallback_summary, "System remediation logic unavailable."