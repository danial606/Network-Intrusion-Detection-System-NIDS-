import time
from scapy.all import TCP, IP, ARP, Raw, DNS, DNSQR, UDP
import config

def detect_port_scan(packet, trackers, logger):
    if not packet.haslayer(TCP) or not packet.haslayer(IP): return
    src_ip = packet[IP].src
    dst_port = packet[TCP].dport
    current_time = time.time()
    tracker = trackers['port_scan'].setdefault(src_ip, {})
    tracker[dst_port] = current_time
    tracker = {p: t for p, t in tracker.items() if current_time - t < config.PORT_SCAN_WINDOW}
    trackers['port_scan'][src_ip] = tracker
    if len(tracker) > config.PORT_SCAN_THRESHOLD:
        logger.log_alert("Port Scan", f"Source: {src_ip} scanned ports: {list(tracker.keys())}", src_ip)
        del trackers['port_scan'][src_ip]

def detect_syn_flood(packet, trackers, logger):
    if not packet.haslayer(TCP) or not packet.haslayer(IP) or packet[TCP].flags != 'S': return
    src_ip = packet[IP].src
    current_time = time.time()
    tracker = trackers['syn_flood'].setdefault(src_ip, [])
    tracker.append(current_time)
    # Clean up old entries
    tracker = [t for t in tracker if current_time - t < config.SYN_FLOOD_WINDOW]
    trackers['syn_flood'][src_ip] = tracker
    if len(tracker) > config.SYN_FLOOD_THRESHOLD:
        logger.log_alert("SYN Flood", f"Source: {src_ip} sent {len(tracker)} SYN packets.", src_ip)
        del trackers['syn_flood'][src_ip]

def detect_arp_spoofing(packet, trackers, logger):
    if not packet.haslayer(ARP) or packet[ARP].op != 2: return # op=2 is 'is-at'
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc
    arp_table = trackers['arp']
    if src_ip in arp_table and arp_table[src_ip] != src_mac:
        logger.log_alert("ARP Spoofing", f"IP {src_ip} claimed by {src_mac} (was {arp_table[src_ip]}).", src_ip)
    arp_table[src_ip] = src_mac

def detect_malicious_payload(packet, logger):
    payload = b''
    if packet.haslayer(Raw): payload = packet[Raw].load
    elif packet.haslayer(TCP) and hasattr(packet[TCP], 'load'): payload = packet[TCP].load
    elif packet.haslayer(UDP) and hasattr(packet[UDP], 'load'): payload = packet[UDP].load

    if payload:
        for signature, description in config.MALICIOUS_SIGNATURES.items():
            if signature in payload:
                src_ip = packet[IP].src if packet.haslayer(IP) else 'N/A'
                logger.log_alert("Malicious Payload", f"'{description}' detected from {src_ip}", src_ip)
                break

def log_dns_request(packet, logger):
    if packet.haslayer(DNS) and packet[DNS].opcode == 0 and packet[DNS].qr == 0:
        if packet.haslayer(DNSQR):
            try:
                log_entry = {
                    "timestamp": time.time(), "source_ip": packet[IP].src,
                    "query_name": packet[DNSQR].qname.decode(), "query_type": packet[DNSQR].qtype
                }
                logger.log_metadata(config.DNS_LOG_FILE, log_entry)
            except: pass

def log_http_request(packet, logger):
    if packet.haslayer(TCP) and (packet[TCP].dport == 80 or packet[TCP].sport == 80) and packet.haslayer(Raw):
        try:
            payload = packet[Raw].load.decode('utf-8', errors='ignore')
            headers = payload.split('\r\n')
            request_line = headers[0]
            if "HTTP/" in request_line:
                host = next((h for h in headers if h.lower().startswith('host:')), "N/A")
                user_agent = next((h for h in headers if h.lower().startswith('user-agent:')), "N/A")
                log_entry = {
                    "timestamp": time.time(), "source_ip": packet[IP].src, "dest_ip": packet[IP].dst,
                    "request_line": request_line, "host": host, "user_agent": user_agent
                }
                logger.log_metadata(config.HTTP_LOG_FILE, log_entry)
        except: pass
