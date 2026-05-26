# core/analysis_engine.py
from plugins import ACTIVE_PLUGINS  # Leverages the new __init__.py registry layout

class AnalysisEngine:
    def __init__(self):
        # Automatically registers any rules managed by the plugins package surface
        self.plugins = ACTIVE_PLUGINS

    def execute_pipeline(self, normalized_events):
        compiled_alerts = []
        for plugin in self.plugins:
            try:
                alerts = plugin.analyze(normalized_events)
                compiled_alerts.extend(alerts)
            except Exception as e:
                print(f"[-] Rule Exception on execution layer: {e}")
        return compiled_alerts