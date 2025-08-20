import datetime
import json
from collections import deque, Counter
import config

class Logger:
    def __init__(self):
        self.alerts_log = deque(maxlen=config.MAX_LOG_ENTRIES)
        self.dns_log_count = 0
        self.http_log_count = 0

    def log_alert(self, attack_type, details, src_ip=None):
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            "timestamp": timestamp,
            "attack_type": attack_type,
            "details": details,
            "source_ip": src_ip
        }
        
        self.alerts_log.appendleft(log_entry)
        print(f"\033[91m[ALERT] {timestamp}: {attack_type} - {details}\033[0m")
        with open(config.ALERTS_LOG_FILE, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    def log_metadata(self, log_file, data):
        with open(log_file, "a") as f:
            f.write(json.dumps(data) + "\n")
        
        if log_file == config.DNS_LOG_FILE:
            self.dns_log_count += 1
        elif log_file == config.HTTP_LOG_FILE:
            self.http_log_count += 1
            
    def get_alert_stats(self):
        alerts_by_type = Counter(alert['attack_type'] for alert in self.alerts_log)
        top_attackers = Counter(alert['source_ip'] for alert in self.alerts_log if alert['source_ip']).most_common(5)
        return {"by_type": alerts_by_type, "top_attackers": top_attackers}

    def get_log_counts(self):
        """Returns the counts of metadata logs."""
        return {"dns": self.dns_log_count, "http": self.http_log_count}