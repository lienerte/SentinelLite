# core/analysis_engine.py
from plugins.brute_force_plugin import BruteForcePlugin
from plugins.port_scan_plugin import PortScanPlugin
from plugins.volume_spike_plugin import VolumeSpikePlugin

class AnalysisEngine:
    def __init__(self):
        # Explicit plugin matrix attachment architecture
        self.plugins = [
            BruteForcePlugin(),
            PortScanPlugin(),
            VolumeSpikePlugin()
        ]

    def execute_pipeline(self, normalized_events):
        compiled_alerts = []
        for plugin in self.plugins:
            try:
                alerts = plugin.analyze(normalized_events)
                compiled_alerts.extend(alerts)
            except Exception as e:
                print(f"[-] Rule Exception on execution layer: {e}")
        return compiled_alerts