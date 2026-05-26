# plugins/__init__.py
"""
SentinelLite Pluggable Detection Signatures.
Contains modular behavioral rules that scan normalized logs for attack indicators.
"""

from .brute_force_plugin import BruteForcePlugin
from .port_scan_plugin import PortScanPlugin
from .volume_spike_plugin import VolumeSpikePlugin

# Automated Manifest Compilation
# The Analysis Engine reads this list directly to run active checks
ACTIVE_PLUGINS = [
    BruteForcePlugin(),
    PortScanPlugin(),
    VolumeSpikePlugin()
]

__all__ = [
    "BruteForcePlugin",
    "PortScanPlugin",
    "VolumeSpikePlugin",
    "ACTIVE_PLUGINS"
]