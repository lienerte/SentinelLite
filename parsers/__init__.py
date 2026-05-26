# parsers/__init__.py
"""
SentinelLite Telemetry Parsing Modules.
Standardizes messy, unstructured text streams and binary captures 
into a unified internal data event schema.
"""

from .base_parser import BaseParser
from .pcap_parser import PcapParser
from .auth_parser import AuthParser
from .web_parser import WebParser
from .json_parser import JsonParser

__all__ = [
    "BaseParser",
    "PcapParser",
    "AuthParser",
    "WebParser",
    "JsonParser"
]