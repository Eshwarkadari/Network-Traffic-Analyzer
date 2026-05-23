"""
statistics.py  —  Traffic Statistics Engine
Author: Kadari Eshwar | B.Tech ECE, JNTU Hyderabad
"""

import csv
from collections import defaultdict, Counter
from datetime import datetime

class TrafficStats:
    def __init__(self):
        self.total_packets    = 0
        self.total_bytes      = 0
        self.protocol_counts  = Counter()
        self.src_ip_counts    = Counter()
        self.dst_ip_counts    = Counter()
        self.port_counts      = Counter()
        self.packets          = []
        self.start_time       = datetime.now()

    def add_packet(self, pkt):
        self.total_packets += 1
        self.total_bytes   += pkt.get("size", 0)
        self.protocol_counts[pkt.get("protocol", "OTHER")] += 1
        self.src_ip_counts[pkt.get("src_ip", "?")] += 1
        self.dst_ip_counts[pkt.get("dst_ip", "?")] += 1
        if pkt.get("dst_port"):
            self.port_counts[pkt["dst_port"]] += 1
        self.packets.append(pkt)

    def print_summary(self):
        duration = (datetime.now() - self.start_time).seconds or 1
        print(f"\n{'='*50}")
        print(f"  Total Packets : {self.total_packets:,}")
        print(f"  Total Bytes   : {self.total_bytes:,}")
        print(f"  Duration      : {duration}s")
        print(f"  Packets/sec   : {self.total_packets // duration}")
        print(f"\n  Protocol Breakdown:")
        for proto, count in self.protocol_counts.most_common():
            pct = (count / self.total_packets) * 100
            print(f"    {proto:<10} {count:>6} packets ({pct:.1f}%)")
        print(f"\n  Top 5 Source IPs:")
        for ip, count in self.src_ip_counts.most_common(5):
            print(f"    {ip:<20} → {count} packets")
        print(f"\n  Top 5 Destination Ports:")
        port_services = {80:"HTTP",443:"HTTPS",53:"DNS",22:"SSH",21:"FTP",25:"SMTP"}
        for port, count in self.port_counts.most_common(5):
            svc = port_services.get(int(port), "OTHER")
            print(f"    Port {port:<6} ({svc:<5}) → {count} packets")
        print("="*50)

    def export_csv(self, path="traffic_report.csv"):
        if not self.packets:
            return
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.packets[0].keys())
            writer.writeheader()
            writer.writerows(self.packets)
        print(f"✅ Exported {len(self.packets)} packets to {path}")
