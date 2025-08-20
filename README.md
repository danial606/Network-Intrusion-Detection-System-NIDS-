# Advanced Network Intrusion Detection System (NIDS) with Web Dashboard

This project is a Python-based Network Intrusion Detection System (NIDS) that monitors network traffic in real-time for various types of malicious activity. It features a web-based dashboard for visualizing alerts, viewing statistics, and controlling the NIDS.

---

##  Getting Started

It can detect common network attacks such as:
- **Port Scanning**
- **SYN Floods**
- **ARP Spoofing**
- **Malicious Payloads**

The system also logs all **DNS queries**, **HTTP requests**, and **security alerts** to JSON files for later analysis.

---

###  Installation

You will need **Python 3** and **pip**.

Install the required dependencies:

```
pip install scapy flask
```

Because the script needs to capture network packets, it requires root/administrator privileges to run.


On Windows (Run as Administrator):
```
python main.py
```
After execution, you will be prompted to select a network interface to monitor.
Once selected, the web dashboard will be available at:
```
 http://127.0.0.1:5000
```

Configuration

All tunable parameters are located in config.py. You can modify this file to change the NIDS's behavior.

PORT_SCAN_THRESHOLD: Number of unique ports scanned from a single IP to trigger a port scan alert.

PORT_SCAN_WINDOW: Time window (in seconds) for port scan detection.

SYN_FLOOD_THRESHOLD: Number of SYN packets from a single IP to trigger a SYN flood alert.

SYN_FLOOD_WINDOW: Time window (in seconds) for SYN flood detection.

ALERTS_LOG_FILE: File path for storing alert logs.

DNS_LOG_FILE: File path for storing DNS query logs.

HTTP_LOG_FILE: File path for storing HTTP request logs.

MAX_LOG_ENTRIES: Maximum number of recent alerts to keep in memory for the dashboard.

MALICIOUS_SIGNATURES: Dictionary of byte strings to look for in packet payloads and their corresponding descriptions.
