"""
Configuration file for the NIDS.
Contains all tunable parameters and constants.
"""

PORT_SCAN_THRESHOLD = 15
PORT_SCAN_WINDOW = 30  

SYN_FLOOD_THRESHOLD = 50
SYN_FLOOD_WINDOW = 10 

ALERTS_LOG_FILE = "nids_alerts.json"
DNS_LOG_FILE = "nids_dns.json"
HTTP_LOG_FILE = "nids_http.json"
MAX_LOG_ENTRIES = 500 

MALICIOUS_SIGNATURES = {
    b"/bin/bash": "Suspicious Shell Command",
    b"etc/passwd": "Potential Password File Access",
    b"<script>alert": "Potential XSS Attack",
    b"SELECT * FROM": "Potential SQL Injection"
}
