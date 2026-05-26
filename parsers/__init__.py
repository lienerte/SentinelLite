# parsers/__init__.py
from .base_parser import BaseParser
from .pcap_parser import PcapParser
from .auth_parser import AuthParser
from .web_parser import WebParser
from .json_parser import JsonParser
from .ips_parser import IpsParser
from .multi_parser import MultiParser # ◄ 1. IMPORT

__all__ = [
    "BaseParser",
    "PcapParser",
    "AuthParser",
    "WebParser",
    "JsonParser",
    "IpsParser",
    "MultiParser"                     # ◄ 2. REGISTER
]