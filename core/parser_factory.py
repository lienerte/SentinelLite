# core/parser_factory.py
from parsers.pcap_parser import PcapParser
from parsers.auth_parser import AuthParser
from parsers.web_parser import WebParser
from parsers.json_parser import JsonParser
from parsers.ips_parser import IpsParser
from parsers.multi_parser import MultiParser  # ◄ 1. IMPORT

class ParserFactory:
    _parsers = {
        "PCAP": PcapParser,
        "AUTH": AuthParser,
        "WEB": WebParser,
        "JSON": JsonParser,
        "FORTINET_IPS": IpsParser,
        "MULTI": MultiParser                  # ◄ 2. REGISTER
    }

    @classmethod
    def get_parser(cls, log_type):
        parser_class = cls._parsers.get(log_type)
        if not parser_class:
            raise ValueError(f"No appropriate parser register matches format classification: {log_type}")
        return parser_class()