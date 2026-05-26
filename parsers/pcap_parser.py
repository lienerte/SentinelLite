from parsers.base_parser import BaseParser
from scapy.all import rdpcap, IP, TCP, UDP
import datetime

class PcapParser(BaseParser):
    def parse(self, file_path):
        normalized_events = []
        try:
            packets = rdpcap(file_path)
        except Exception as e:
            print(f"[-] Error parsing PCAP stream: {e}")
            return normalized_events

        for pkt in packets:
            if pkt.haslayer(IP):
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = None
                proto = "RAW_IP"

                if pkt.haslayer(TCP):
                    dport = pkt[TCP].dport
                    proto = "TCP"
                elif pkt.haslayer(UDP):
                    dport = pkt[UDP].dport
                    proto = "UDP"

                ts = datetime.datetime.fromtimestamp(float(pkt.time)).isoformat()
                
                normalized_events.append(self.normalize_event(
                    timestamp=ts, src_ip=src, dst_ip=dst, target_port=dport,
                    user=None, event_type=f"NETWORK_{proto}", payload=f"Len: {len(pkt)}"
                ))
        return normalized_events