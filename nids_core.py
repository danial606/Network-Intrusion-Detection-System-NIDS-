import threading
from collections import defaultdict
from scapy.all import sniff

import detection_modules
from logging_utils import Logger

class NIDS:
    def __init__(self):
        self.stop_sniffing = threading.Event()
        self.is_running = False
        self.sniff_thread = None
        self.interface = None
        self.logger = Logger()
        
        self.trackers = {
            'port_scan': defaultdict(dict),
            'syn_flood': defaultdict(list),
            'arp': {}
        }

    def process_packet(self, packet):
        try:
            detection_modules.detect_port_scan(packet, self.trackers, self.logger)
            detection_modules.detect_syn_flood(packet, self.trackers, self.logger)
            detection_modules.detect_arp_spoofing(packet, self.trackers, self.logger)
            detection_modules.detect_malicious_payload(packet, self.logger)
            detection_modules.log_dns_request(packet, self.logger)
            detection_modules.log_http_request(packet, self.logger)
        except Exception:
            pass

    def start(self):
        """Starts the NIDS sniffing thread on the configured interface."""
        if self.is_running:
            print("NIDS is already running.")
            return
        if not self.interface:
            print("Error: Network interface not set.")
            return
            
        print(f"Starting NIDS on interface: {self.interface}...")
        self.stop_sniffing.clear()
        self.is_running = True
        
        self.sniff_thread = threading.Thread(
            target=lambda: sniff(iface=self.interface, prn=self.process_packet, store=False, stop_filter=lambda p: self.stop_sniffing.is_set())
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        print("NIDS started successfully. Monitoring network traffic...")

    def stop(self):
        """Stops the NIDS sniffing."""
        if not self.is_running:
            print("NIDS is not running.")
            return
            
        print("Stopping NIDS...")
        self.stop_sniffing.set()
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
        self.is_running = False
        print("NIDS stopped.")
