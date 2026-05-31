# core/sigma_importer.py
import os
import yaml
from pathlib import Path

class SigmaRuleImporter:
    def __init__(self, rules_directory="sigma_rules"):
        # Force Python to evaluate the absolute path relative to this script's location
        # This prevents space-in-username and execution context bugs on Windows
        script_dir = Path(__file__).resolve().parent.parent
        self.rules_directory = (script_dir / rules_directory).resolve()
        
        """print("\n" + "="*60)
        print("🚨 SENTINELLITE SYSTEM DIAGNOSTIC MATRIX")
        print("="*60)
        print(f"[*] Active Script Root Directory: {script_dir}")
        print(f"[*] Target Rules Folder Absolute Path: {self.rules_directory}")
        print(f"[*] Does the rules folder exist? -> {self.rules_directory.exists()}")
        """
        """
        if not self.rules_directory.exists():
            self.rules_directory.mkdir(parents=True, exist_ok=True)
            print("[+] Target folder was missing. Generated empty repository directory.")
        else:
            top_level_items = list(self.rules_directory.iterdir())
            print(f"[*] Total items found directly inside root folder: {len(top_level_items)}")
            for item in top_level_items[:5]:  # Diagnostic printout of top folders
                print(f"    -> Found item: {item.name} (Is Directory: {item.is_dir()})")
        print("="*60 + "\n")
        """

    def compile_all_rules(self):
        """
        Recursively traverses through all nested subfolders using pathlib's 
        space-safe rglob engine to ingest and map Sigma YAML signatures.
        """
        compiled_rules = []
        
        # Crawl through absolutely everything recursively down the tree folder
        all_files_discovered = list(self.rules_directory.rglob("*"))
        
        # Filter strictly for valid YAML extensions
        rule_files = [f for f in all_files_discovered if f.is_file() and f.suffix.lower() in ['.yml', '.yaml']]
        
        print(f"[*] Discovered {len(all_files_discovered)} total filesystem objects recursively.")
        print(f"[*] Filtered down to {len(rule_files)} valid YAML signature configurations.\n")

        for filepath in rule_files:
            try:
                with filepath.open('r', encoding='utf-8', errors='ignore') as f:
                    yaml_documents = yaml.safe_load_all(f)
                    
                    for doc in yaml_documents:
                        if not doc or not isinstance(doc, dict):
                            continue
                        
                        # 1. Base Threat Attribute Parsing
                        title = doc.get('title', 'Unknown Threat Indicator')
                        description = doc.get('description', 'No baseline analysis summary provided.')
                        severity = str(doc.get('level', 'LOW')).upper()
                        tags = doc.get('tags', []) if isinstance(doc.get('tags'), list) else []
                        
                        keywords = []

                        # 2. Targeted String Extraction Engine
                        # Deep crawls the structure to extract raw strings while filtering out administrative noise
                        def extract_strings_recursive(element, parent_key=""):
                            if isinstance(element, dict):
                                for k, v in element.items():
                                    if k in ['condition', 'author', 'date', 'status', 'references', 
                                             'logsource', 'category', 'product', 'service', 'level', 
                                             'id', 'modified', 'falsepositives', 'fields', 'tags']:
                                        continue
                                    extract_strings_recursive(v, parent_key=k)
                                    
                            elif isinstance(element, list):
                                for item in element:
                                    extract_strings_recursive(item, parent_key)
                                    
                            elif isinstance(element, (str, int, float)):
                                val_str = str(element).strip()
                                
                                if val_str and len(val_str) > 1:
                                    # Filter structural layout keywords and booleans
                                    if val_str.lower() in ['true', 'false', 'null', 'selection', 'filter']:
                                        return
                                    if val_str in ['c-uri', 'cs-method', 'UserAgent', 'CommandLine', 'Image', 'EventID']:
                                        return
                                        
                                    keywords.append(val_str)

                        # Evaluate raw indicators strictly within the rule's operational matching block
                        if 'detection' in doc:
                            extract_strings_recursive(doc['detection'])

                        clean_keywords = list(set([k.replace('*', '') for k in keywords if k]))
                        
                        if not clean_keywords:
                            continue 
                        
                        # 3. Threat Intel Framework Integration (MITRE & CVE)
                        import re

                        mitre_techniques = []
                        cves = []

                        for tag in tags:
                            tag_clean = tag.lower().strip()
                            
                            # A. Resilient MITRE Extraction (Handles attack.t1003 AND attack.t1574.001)
                            if tag_clean.startswith('attack.'):
                                # Regex captures the 't' followed by digits and optional sub-technique dots
                                match = re.search(r't\d{4}(?:\.\d{3})?', tag_clean)
                                if match:
                                    tech_id = match.group(0).upper() # Guarantees 'T1003' or 'T1574.001'
                                    mitre_techniques.append(tech_id)
                            
                            # B. Resilient CVE Extraction (Handles cve-2021-44228, cve.2021.44228, and cve_2021_44228)
                            elif 'cve' in tag_clean:
                                # Standardizes delimiters to hyphens so regex can capture cleanly
                                standardized_tag = tag_clean.replace('.', '-').replace('_', '-')
                                cve_match = re.search(r'cve-\d{4}-\d{4,}', standardized_tag)
                                if cve_match:
                                    cves.append(cve_match.group(0).upper())

                        # 4. Final Compilation Append Step
                        compiled_rules.append({
                            "title": title,
                            "severity": severity,
                            "why_it_matters": description,
                            "signature_keywords": clean_keywords,
                            "potential_cves": cves,
                            "mitre_attack": mitre_techniques,
                            "nist_mapping": self._derive_nist(mitre_techniques)
                        })

            except Exception as e:
                # Keep parent process alive if a single file has malformed or abstract syntax
                print(f"[!] Bypassing unreadable rule structure ({filepath.name}): {e}")
                continue

        print(f"[+] Total Active Rules Map Complete: {len(compiled_rules)} signatures successfully compiled into memory.")
        return compiled_rules

    def _derive_nist(self, mitre_techniques):
        """
        Dynamically maps MITRE ATT&CK techniques down to the exact 
        NIST Cyber Security Framework (CSF) v1.1 Subcategory index.
        """
        if not mitre_techniques:
            return {"function": "DETECT", "id": "DE.CM-1", "desc": "Network & host boundaries monitored for anomalies."}
            
        for tech in mitre_techniques:
            # Reconnaissance & Discovery (e.g., T1083, T1018, T1046)
            if tech in ['T1083', 'T1018', 'T1046', 'T1595']:
                return {"function": "DETECT", "id": "DE.AE-2", "desc": "Anomalous events are analyzed to determine potential impact."}
            # Credential Access & Brute Force Operations (e.g., T1110, T1003)
            elif tech in ['T1110', 'T1003', 'T1056']:
                return {"function": "DETECT", "id": "DE.AE-3", "desc": "Incidents are checked against baseline user thresholds."}
            # Execution & Lateral Movement Frameworks (e.g., T1059, T1021)
            elif tech in ['T1059', 'T1021', 'T1204', 'T1566']:
                return {"function": "DETECT", "id": "DE.CM-1", "desc": "Malicious script and command execution streams monitored."}
            # Persistence & Privilege Escalation Hooks (e.g., T1543, T1068)
            elif tech in ['T1543', 'T1068', 'T1078']:
                return {"function": "PROTECT", "id": "PR.AC-4", "desc": "Access permissions and system integrity are managed."}
                
        return {"function": "DETECT", "id": "DE.CM-1", "desc": "Security telemetry events parsed against baseline signatures."}