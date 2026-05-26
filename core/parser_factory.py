# core/parser_factory.py
from parsers.pcap_parser import PcapParser
from parsers.auth_parser import AuthParser
from parsers.web_parser import WebParser
from parsers.json_parser import JsonParser
from parsers.ips_parser import IpsParser  # 1. Import your new parser class here

class ParserFactory:
    # 2. Add the routing token mapper to your class dictionary registry
    _parsers = {
        "PCAP": PcapParser,
        "AUTH": AuthParser,
        "WEB": WebParser,
        "JSON": JsonParser,
        "FORTINET_IPS": IpsParser  # Maps the signature to the new class object
    }

    @classmethod
    def get_parser(cls, log_type):
        """
        Dynamically instantiates and returns the appropriate parser object 
        based on the identified log type classification string.
        """
        parser_class = cls._parsers.get(log_type)
        if not parser_class:
            raise ValueError(f"No appropriate parser register matches format classification: {log_type}")
        
        # 3. This returns a running instance of the parser back to app.py/main.py
        return parser_class()