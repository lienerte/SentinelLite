"""
core/ai_analyzer.py - Live Local LLM Ingestion Connector
Architected to bridge SentinelLite's normalized event telemetry to local models.
"""
import json
import requests

class AIIntegrationLayer:
    def __init__(self, use_local_ai=False):
        self.active = use_local_ai
        # Default local engine listening port for Ollama instances
        self.ollama_url = "http://localhost:11434/api/generate"
        # Using llama3 as the dedicated security analyzer target
        self.model_target = "llama3"
        
    def generate_incident_summary(self, normalized_events, detected_type):
        """
        Pipes normalized event context strings to a local LLM inference boundary
        and returns structured Markdown security assessments.
        """
        if not self.active:
            return None

        if not normalized_events:
            return "### 🤖 Local AI Analyst Engine\n*Ingestion stream empty. No analytical matrix context available to evaluate.*"

        # TRUNCATION STRATEGY: Sample the first 15 events to comfortably fit 
        # inside standard local context windows while preserving execution speeds.
        log_sample = normalized_events[:15]
        
        # PROMPT ENGINEERING: Establish role definitions and strict response parameters
        prompt = (
            # Inside your AI prompt construction loop
            f"You are an expert Principal SOC Analyst and Infrastructure Security Engineer. Analyze the provided "
            f"normalized SIEM alert matrix with strict technical accuracy. Be precise and realistic.\n"
            f"CRITICAL RULES:\n"
            f"1. CONTEXTUAL REASONING: Differentiate between adversarial attacks and cleartext operational audits. "
            f"A 'show-tech' command from a 'cisco-IOS' User-Agent indicates a benign network management tool, "
            f"NOT an external hacker penetration attempt. The risk is strictly DATA LEAKAGE via cleartext transport.\n"
            f"2. PROTOCOL SANITY CHECK: High volume TCP ACK ('A') packets inside a data stream are standard network "
            f"acknowledgements for file/payload delivery, not automated scanning routines.\n"
            f"3. SAFE REMEDIATION: Never suggest blocking critical baseline protocol behaviors like TCP ACK flags, "
            f"as doing so disrupts legitimate state tracking and breaks active user connections. "
            f"Focus remediation entirely on forcing protocol encapsulation (e.g., migrating HTTP to HTTPS/SSH), "
            f"implementing network segmentation, or configuring restrictive management plane Access Control Lists (ACLs).\n\n"
            f"Format your analysis professionally with an 'Executive Threat Overview Summary' and specific, actionable 'Remediation Steps'."
            f"steps using clean Markdown styling.\n\n"
            f"LOG DATA TO EVALUATE (JSON Format):\n{json.dumps(log_sample, indent=2)}"             
        )

        try:
            # Deliver synchronous POST transaction block to local socket loop
            response = requests.post(
                self.ollama_url,
                json={
                    "model": self.model_target, 
                    "prompt": prompt, 
                    "stream": False  # Return complete text block at once to simplify UI rendering
                },
                timeout=25  # Prevent slow inferences from locking up the UI thread indefinitely
            )
            
            if response.status_code == 200:
                # Extract response text straight out of Ollama's unified return object
                return response.json().get("response")
            else:
                return (
                    f"### 🤖 AI Core Exception\n"
                    f"Local engine returned status code: `{response.status_code}`.\n"
                    f"Verify that model tracking registers match target: `{self.model_target}`."
                )
                
        except requests.exceptions.RequestException:
            # Fallback error card providing user action options if the background server drops
            return (
                "### 🤖 Local AI Analyst Engine Triage Report\n\n"
                "**Status:** Connection to Core Local LLM Refused\n\n"
                "**Remediation Steps to Activate:**\n"
                "1. Ensure the **Ollama** engine is actively running on your host machine.\n"
                "2. Open a terminal and run `ollama run llama3` to confirm the model file is cached locally.\n"
                "3. Re-execute the SentinelLite upload analyzer routine."
            )