"""
anomaly_detector.py  —  Detect Suspicious Network Patterns
Author: Kadari Eshwar | B.Tech ECE, JNTU Hyderabad
"""

from collections import defaultdict, Counter

class AnomalyDetector:
    def __init__(self):
        self.ip_port_map    = defaultdict(set)
        self.ip_pkt_count   = Counter()
        self.alerts         = []

    def check(self, pkt):
        src = pkt.get("src_ip", "?")
        dst_port = pkt.get("dst_port")

        self.ip_pkt_count[src] += 1

        # Port scan detection — one IP hitting many ports
        if dst_port:
            self.ip_port_map[src].add(dst_port)
            if len(self.ip_port_map[src]) > 20:
                alert = f"⚠️  PORT SCAN detected from {src} ({len(self.ip_port_map[src])} ports)"
                if alert not in self.alerts:
                    self.alerts.append(alert)
                    print(alert)

        # High traffic from single IP
        if self.ip_pkt_count[src] > 500:
            if self.ip_pkt_count[src] % 100 == 0:
                print(f"⚠️  HIGH TRAFFIC from {src}: {self.ip_pkt_count[src]} packets")

    def get_alerts(self):
        return self.alerts
