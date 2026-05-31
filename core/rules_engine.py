from core.sigma_importer import SigmaRuleImporter

class AdvancedRulesEngine:
    def __init__(self):
        # Fire up the importer seamlessly on startup
        importer = SigmaRuleImporter(rules_directory="sigma_rules")
        self.active_rules = importer.compile_all_rules()
        """print(f"[*] Rules Engine Hot-Loaded: {len(self.active_rules)} dynamic Sigma rules active in memory.")
        # At the bottom of __init__ in core/rules_engine.py
        print("\n" + "="*50)
        print("🔍 ENGINE MEMORY SAMPLE CHECK")
        print("="*50)
        if self.active_rules:
            for i, rule in enumerate(self.active_rules[:3]):
                print(f"Rule [{i+1}]: {rule['title']}")
                print(f"  -> Keywords in memory: {rule['signature_keywords']}")
        else:
            print("[!] Engine is completely empty!")
        print("="*50 + "\n")
        """

    def evaluate_log_data(self, raw_file_content, source_ip="127.0.0.1"):
        triggered_alerts = []
        
        # Decode the log file safely and split into clean lines
        lines = raw_file_content.decode('utf-8', errors='ignore').splitlines()
        
        for line in lines:
            # Convert the active log line to lowercase once to save execution cycles
            line_lower = line.lower().strip()
            if not line_lower:
                continue
                
            for rule in self.active_rules:
                matched = False
                
                for keyword in rule["signature_keywords"]:
                    # Clean up the scraped keyword (lowercase it, strip quotes or trailing spaces)
                    clean_kw = str(keyword).lower().strip().strip("'").strip('"')
                    
                    # Guard rail: skip empty strings or single characters to prevent false positives
                    if not clean_kw or len(clean_kw) <= 2:
                        continue
                    
                    # Execute a true case-insensitive substring search
                    if clean_kw in line_lower:
                        triggered_alerts.append({
                            "title": rule["title"],
                            "severity": rule["severity"],
                            "source": source_ip,
                            "why_it_matters": rule["why_it_matters"],
                            "potential_cves": rule["potential_cves"],
                            "mitre_attack": rule["mitre_attack"],   # New data bridge
                            "nist_mapping": rule["nist_mapping"]     # New data bridge
                        })
                        matched = True
                        break  # Stop checking keywords for this specific rule on this line
                
                if matched:
                    break  # Move to the next log line immediately if a rule already fired
                    
        return triggered_alerts