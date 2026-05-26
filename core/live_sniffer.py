# core/live_sniffer.py
"""
core/live_sniffer.py - Threaded Live Telemetry Network Sniffer
Captures raw packet matrices from local interfaces concurrently without blocking web surfaces.
"""
import threading
import queue
import time
from core.analysis_engine import AnalysisEngine
from core.remediation_orchestrator import RemediationOrchestrator

# Thread-safe global alert repository for the live web surface
LIVE_ALERT_CACHE = []
LIVE_SNIFFER_ACTIVE = False

class LiveSnifferManager:
    def __init__(self, interface=None):
        self.interface = interface
        self.packet_queue = queue.Queue()
        self.sniffer_thread = None
        self.worker_thread = None

    def start(self):
        """Spins up the concurrent producer-consumer background workers."""
        global LIVE_SNIFFER_ACTIVE
        if LIVE_SNIFFER_ACTIVE:
            print("[!] Live sniffer engine already running.")
            return

        LIVE_SNIFFER_ACTIVE = True
        
        # 1. Start the Consumer Thread (Processes queue items)
        self.worker_thread = threading.Thread(target=self._process_queue_loop, daemon=True)
        self.worker_thread.start()

        # 2. Start the Producer Thread (Sniffs raw network packets)
        self.sniffer_thread = threading.Thread(target=self._sniff_packets_loop, daemon=True)
        self.sniffer_thread.start()
        print(f"[+] SentinelLite live packet sniffing loops active on interface: {self.interface or 'DEFAULT'}")

    def stop(self):
        """Gracefully signs off background concurrent threads."""
        global LIVE_SNIFFER_ACTIVE
        LIVE_SNIFFER_ACTIVE = False
        print("[*] Terminating live sniffer engine matrices...")

    def _sniff_packets_loop(self):
        """PRODUCER: Binds to raw sockets to catch packets line-rate."""
        try:
            from scapy.all import sniff
        except ImportError:
            print("[-] Cannot start live sniffer. Scapy is missing.")
            return

        def _packet_callback(pkt):
            if not LIVE_SNIFFER_ACTIVE:
                return True # Stops Scapy's internal loop if false
            self.packet_queue.put(pkt)

        # Sniff indefinitely until active flag drops
        sniff(iface=self.interface, prn=_packet_callback, store=0)

    def _process_queue_loop(self):
        """CONSUMER: Extracts items from queue, normalizes, and triggers rules."""
        global LIVE_ALERT_CACHE
        from scapy.all import IP, TCP, Raw
        engine = AnalysisEngine()
        soar_engine = RemediationOrchestrator(output_path="artifacts/live_remediation_playbook.txt")

        while LIVE_SNIFFER_ACTIVE:
            try:
                # Non-blocking get with short timeout to allow thread termination checks
                pkt = self.packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                # We surgically isolate IP and TCP transport traffic
                if pkt.haslayer(IP) and pkt.haslayer(TCP):
                    ip_layer = pkt[IP]
                    tcp_layer = pkt[TCP]
                    
                    payload = ""
                    event_type = "LIVE_PACKET"
                    
                    if pkt.haslayer(Raw):
                        try:
                            payload = pkt[Raw].load.decode('utf-8', errors='ignore').strip()
                            if "show-tech" in payload or "show running-config" in payload:
                                event_type = "INFRASTRUCTURE_AUDIT_COMMAND"
                        except Exception:
                            payload = "[Binary Application Data]"

                    # Map to the strict, system-wide Normalized Event Schema
                    pkt_time = float(getattr(pkt, 'time', time.time()))
                    normalized_event = {
                        "timestamp": pkt_time,
                        "src_ip": ip_layer.src,
                        "dst_ip": ip_layer.dst,
                        "target_port": tcp_layer.dport,
                        "user": "live_wire_capture",
                        "event_type": event_type,
                        "payload": payload if payload else f"TCP Flags: {tcp_layer.flags}"
                    }

                    # Evaluate live telemetry against your pluggable rules matrix array
                    new_alerts = engine.execute_pipeline([normalized_event])
                    
                    if new_alerts:
                        for alert in new_alerts:
                            # Avoid appending duplicate tracking spikes rapidly
                            if alert not in LIVE_ALERT_CACHE:
                                LIVE_ALERT_CACHE.append(alert)
                        
                        # Compile on-demand mitigation playbooks for discovered live threats
                        soar_engine.generate_playbook(new_alerts, "LIVE_SOCKET_STREAM")
                        
            except Exception as e:
                print(f"[-] Live telemetry processing pipeline exception: {e}")
            finally:
                self.packet_queue.task_done()