# parsers/pcap_parser.py
"""
parsers/pcap_parser.py - Raw PCAP Extraction Parser
Surgically extracts transport and application layer text footprints out of binary network streams,
safely handling high-precision packet timestamps for JSON serialization.
"""
import os
from parsers.base_parser import BaseParser

class PcapParser(BaseParser):
    def parse(self, file_path):
        normalized_records = []
        
        # Defensive check to shield from import delays or missing environment tools
        try:
            from scapy.all import rdpcap, TCP, IP, Raw
        except ImportError:
            print("[-] Critical Dependency Error: Scapy module missing. Run: pip install scapy")
            return normalized_records

        try:
            # Read binary file packets into an iterable memory index array
            packets = rdpcap(file_path)
            
            for idx, pkt in enumerate(packets):
                # We target IP and TCP transport layer payloads (like HTTP)
                if pkt.haslayer(IP) and pkt.haslayer(TCP):
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]
                    
                    payload = ""
                    event_type = "NETWORK_PACKET_RAW"
                    
                    # Look inside the Raw data layer where HTTP text payloads live
                    if pkt.haslayer(Raw):
                        try:
                            # Safely extract application strings (e.g., GET /show-tech)
                            raw_data = pkt[Raw].load.decode('utf-8', errors='ignore')
                            payload = raw_data.strip()
                            
                            # Heuristically classify sensitive administrative diagnostic lookups
                            if "show-tech" in payload or "show running-config" in payload:
                                event_type = "INFRASTRUCTURE_AUDIT_COMMAND"
                            elif "GET " in payload or "POST " in payload:
                                event_type = "WEB_HTTP_REQUEST"
                        except Exception:
                            payload = "[Binary Payload Block]"

                    # CRITICAL FIX: Handle Scapy's high-precision EDecimal safely for JSON serialization
                    pkt_time = getattr(pkt, 'time', None)
                    if pkt_time is not None:
                        try:
                            # Cast the custom EDecimal object to a standard Python float
                            serializable_time = float(pkt_time)
                        except (TypeError, ValueError):
                            serializable_time = None
                    else:
                        serializable_time = None

                    # Map into the unified SIEM dictionary framework inheriting from BaseParser
                    normalized_records.append(self.normalize_event(
                        timestamp=serializable_time,
                        src_ip=ip_layer.src,
                        dst_ip=ip_layer.dst,
                        target_port=tcp_layer.dport,
                        user="admin_session" if "show-" in payload else "N/A",
                        event_type=event_type,
                        payload=payload if payload else f"TCP Packet flag_summary: {tcp_layer.flags}"
                    ))
                    
        except Exception as e:
            print(f"[!] Warning: Structural parsing bypass on line {line_num}: {e}")
            continue
            
        return normalized_records