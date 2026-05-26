# plugins/__init__.py
"""
SentinelLite Pluggable Detection Signatures.
Contains modular behavioral rules that scan normalized logs for attack indicators.
"""

from .brute_force_plugin import BruteForcePlugin
from .port_scan_plugin import PortScanPlugin
from .volume_spike_plugin import VolumeSpikePlugin
from .cross_protocol_correlation_plugin import CrossProtocolCorrelationPlugin # ◄ 1. IMPORT
from .infrastructure_audit_plugin import InfrastructureAuditPlugin

# Automated Manifest Compilation
ACTIVE_PLUGINS = [
    BruteForcePlugin(),
    PortScanPlugin(),
    VolumeSpikePlugin(),
    CrossProtocolCorrelationPlugin(), # ◄ 2. REGISTER
    InfrastructureAuditPlugin()
]

__all__ = [
    "BruteForcePlugin",
    "PortScanPlugin",
    "VolumeSpikePlugin",
    "CrossProtocolCorrelationPlugin",
    "infrastructureAuditPlugin",
    "ACTIVE_PLUGINS"
]