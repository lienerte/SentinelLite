"""
core/ai_analyzer.py - Live Local LLM Ingestion Connector
Architected to bridge SentinelLite's normalized event telemetry to local models.
Optimized with a parallel consensus council execution strategy.
"""
import json
import requests
from concurrent.futures import ThreadPoolExecutor

class AIIntegrationLayer:
    def __init__(self, use_local_ai=True):
        self.active = use_local_ai
        # Default local engine listening port for Ollama instances
        self.ollama_url = "http://localhost:11434/api/generate"
        # Using llama3 as the dedicated security analyzer target
        self.model_target = "llama3:latest"
        
    def _query_council_member(self, url, persona_prompt, log_context):
        """
        Helper worker function to process an individual agent thread transaction.
        """
        full_prompt = f"{persona_prompt}\n\nLOG DATA TO EVALUATE:\n{log_context}"
        try:
            response = requests.post(
                url,
                json={
                    "model": self.model_target,
                    "prompt": full_prompt,
                    "stream": False
                },
                timeout=45
            )
            if response.status_code == 200:
                return response.json().get("response", "Agent did not provide an analysis.")
        except Exception as e:
            return f"Agent analysis path encountered an exception: {str(e)}"
        return "Agent remained silent."

    def generate_incident_summary(self, normalized_events, detected_type):
        """
        Pipes normalized event context strings to a parallel local LLM council inference boundary,
        enforces structured JSON output matching domain protocols via a consensus chairperson, 
        and returns both a Markdown assessment and a copy-pasteable mitigation playbook.
        """
        if hasattr(self, 'active') and not self.active:
            return "No analysis generated or AI checkbox was disabled.", ""
        if hasattr(self, 'use_local_ai') and not self.use_local_ai:
            return "No analysis generated or AI checkbox was disabled.", ""

        if not normalized_events:
            return "### 🤖 Local AI Analyst Engine\n*Ingestion stream empty. No analytical matrix context available to evaluate.*", ""

        log_sample = normalized_events[:15]
        log_sample_json = json.dumps(log_sample, indent=2)
        
        url = getattr(self, 'ollama_url', None) or getattr(self, 'endpoint', "http://localhost:11434/api/generate")

        # 1. PERSONA ENGINE MATRIX: Calibrated to prevent default baseline panic loops
        personas = {
            "forensics": (
                "You are an expert Network Forensic Analyst reviewing SIEM alerts. "
                "CRITICAL: Distinguish raw packet byte indicators from active compromise signatures. "
                "The presence of default administration credentials (e.g., 'Basic YWRtaW46Y2lzY28=') or standard text "
                "outputs of internal router configurations (like Cisco IOS 'show-tech') indicates cleartext operational collection "
                "and auditing telemetry, NOT active malware deployment or malware execution. Treat this strictly as a benign audit state."
            ),
            "threat_intel": (
                "You are a Cyber Threat Intelligence Specialist. "
                "CRITICAL: Differentiate routine admin tools from attacker tools. The execution of 'curl.exe' or 'bitsadmin.exe' "
                "with an infrastructure User-Agent (like 'cisco-IOS') downloading router information is standard network administration tradecraft. "
                "Do not flag administrative data collection as a hostile hacking penetration phase or active callback communication unless a known external malicious IP command control handoff is verified."
            ),
            "risk_compliance": (
                "You are an Infrastructure Risk Auditor. "
                "CRITICAL: Evaluate data exposure over malicious intent. If network management telemetry is running over unencrypted HTTP, "
                "flag it as an operational exposure and lack of encryption protocol compliance. "
                "Do not classify configuration audits or standard operational scripts as a host compromise or credential extraction event."
            )
        }

        # 2. PARALLEL DEBATE PIPELINE: Execute all workers simultaneously
        council_debates = {}
        try:
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    role: executor.submit(self._query_council_member, url, persona_prompt, log_sample_json)
                    for role, persona_prompt in personas.items()
                }
                for role, future in futures.items():
                    council_debates[role] = future.result()
        except Exception as e:
            print(f"[-] ThreadPoolExecutor processing failure: {e}")

        # 3. CHAIRPERSON AGGREGATION PROMPT: Strict calibration, few-shot grounding, and anti-meta guidelines
        prompt = (
            f"You are a Senior Principal Security Engineer synthesizing raw technical input streams into a single, seamless, authoritative executive dashboard report.\n\n"
            
            f"TECHNICAL INPUT STREAM MATRIX TO EVALUATE:\n"
            f"[Stream A]: {council_debates.get('forensics', 'Analysis unavailable.')}\n"
            f"[Stream B]: {council_debates.get('threat_intel', 'Analysis unavailable.')}\n"
            f"[Stream C]: {council_debates.get('risk_compliance', 'Analysis unavailable.')}\n\n"
            
            f"CRITICAL ANALYSIS & CALIBRATION RULES:\n"
            f"1. FALSE POSITIVE OVERRIDE: If the input streams or log files reveal network architecture audits (such as Cisco 'show-tech' dumps, standard routing tables, or default embedded device admin strings), you must override any alarmist language. Classify the threat level definitively as 'No Malicious Activity Indicated'.\n"
            f"2. CONTEXTUAL REASONING: Differentiate between adversarial attacks and cleartext operational audits. A configuration table running under a cisco-IOS user-agent is benign management traffic, not a breach.\n"
            f"3. PROTOCOL SANITY CHECK: High volume TCP ACK ('A') packets inside a data stream are standard network acknowledgements for file/payload delivery, not automated scanning routines.\n"
            f"4. PERFORMANCE SAFEGUARDS: Never suggest blocking critical baseline protocol behaviors like TCP ACK flags.\n\n"

            f"FEW-SHOT CALIBRATION EXAMPLE (BENIGN TRUTH):\n"
            f"- Scenario: A packet capture containing basic authentication parameters (`Basic YWRtaW46Y2lzY28=`), a 'cisco-IOS' User-Agent, and text outputs of routing tables or crypto engines.\n"
            f"- Correct Analysis: This represents benign network configuration collection and infrastructure auditing. The risk is strictly transport-layer cleartext exposure (HTTP instead of HTTPS), NOT active adversarial malware deployment or a system compromise.\n"
            f"- Correct Threat Header: No Malicious Activity Indicated\n\n"
            
            f"ANTI-META DICTUM:\n"
            f"Do not reference the synthesis process. Completely avoid using phrases like 'the council', 'the sub-agents', 'based on the council's findings', 'agent A states', or 'we conclude'. Write the final output from a singular, unified, independent professional engineering perspective.\n\n"
            
            f"CRITICAL COMMAND EXECUTION RULES:\n"
            f"5. INTERNAL LOOPBACK IPS: If an asset is 127.0.0.1 or localhost, DO NOT provide firewall blocking commands. Provide system diagnostic steps (e.g., 'ss -tulpn').\n"
            f"6. LOCAL LAN IPS: If an asset is a private network node (192.168.x.x, 10.x.x.x, 172.16.x.x), recommend host isolation and 'sudo conntrack -D -s [IP]'.\n"
            f"7. EXTERNAL PUBLIC IPS: Provide 'sudo iptables -A INPUT -s [IP] -j DROP' and 'fail2ban-client' commands ONLY for remote public internet addresses.\n\n"
            
            f"STRICT OUTPUT MANDATE:\n"
            f"Respond ONLY with a valid JSON object matching this schema structure. Do not include markdown block wrapping or backticks outside the values:\n"
            f"{{\n"
            f"    \"ai_analysis\": \"### **Threat Overview: [Insert 'Malicious Activity Detected' OR 'No Malicious Activity Indicated']**\\n\\n[Write a clean, 2-paragraph executive assessment here. Apply the false positive mitigation, contextual reasoning rules, and few-shot calibration directly to evaluate the stream inputs objectively without default bias.]\\n\\n### **Recommendations:**\\n1. [Recommendation 1]\\n2. [Recommendation 2]\\n3. [Recommendation 3]\\n4. [Recommendation 4]\\n\\n**[Conclude with a final, single-sentence explicit callout stating exactly whether or not malicious activity was verified.]**\",\n"
            f"    \"playbook_meta\": \"Write an on-demand, point-and-click mitigation runbook for an IT generalist. Use clear section headers, separate items sequentially, and output clean copy-pasteable bash terminal commands wrapped safely according to the IP type boundaries outlined above.\"\n"
            f"}}"
        )

        # 4. FINAL SYNTHESIS DISPATCH
        try:
            response = requests.post(
                url,
                json={
                    "model": self.model_target, 
                    "prompt": prompt, 
                    "format": "json", 
                    "stream": False   
                },
                timeout=90
            )
            
            if response.status_code == 200:
                result_json = response.json()
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