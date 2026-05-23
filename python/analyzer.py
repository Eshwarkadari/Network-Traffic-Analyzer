"""
analyzer.py  —  Main Network Traffic Analyzer
Author: Kadari Eshwar | B.Tech ECE, JNTU Hyderabad
CCNA Knowledge Applied: OSI Model, TCP/IP, Protocols
"""

import argparse, time, csv
from datetime import datetime
from collections import defaultdict
from packet_parser import parse_packet
from statistics import TrafficStats
from anomaly_detector import AnomalyDetector

def analyze_sample():
    """Analyze sample traffic data from CSV."""
    import pandas as pd
    df = pd.read_csv("../data/sample_traffic.csv")
    stats = TrafficStats()

    print("\n🌐 Network Traffic Analyzer — Sample Data Analysis")
    print("━" * 50)

    for _, row in df.iterrows():
        packet = {
            "timestamp":  row["timestamp"],
            "src_ip":     row["src_ip"],
            "dst_ip":     row["dst_ip"],
            "protocol":   row["protocol"],
            "src_port":   row["src_port"],
            "dst_port":   row["dst_port"],
            "size":       row["size"],
            "flags":      row.get("flags", "")
        }
        stats.add_packet(packet)

    stats.print_summary()
    stats.export_csv("traffic_report.csv")
    print("\n✅ Report saved to traffic_report.csv")

def live_capture(interface="eth0", duration=60):
    """Live packet capture using Scapy."""
    try:
        from scapy.all import sniff
        stats    = TrafficStats()
        detector = AnomalyDetector()

        print(f"\n📡 Capturing on {interface} for {duration} seconds...")
        print("   Press Ctrl+C to stop early\n")

        def process(pkt):
            parsed = parse_packet(pkt)
            if parsed:
                stats.add_packet(parsed)
                detector.check(parsed)

        sniff(iface=interface, prn=process, timeout=duration, store=False)
        stats.print_summary()
        stats.export_csv("live_capture_report.csv")

    except ImportError:
        print("Scapy not found. Running sample mode instead.")
        analyze_sample()
    except PermissionError:
        print("❌ Need admin/root permissions for live capture.")
        print("   Running sample mode instead.\n")
        analyze_sample()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--duration",  type=int, default=60)
    parser.add_argument("--sample",    action="store_true")
    args = parser.parse_args()

    if args.sample:
        analyze_sample()
    else:
        live_capture(args.interface, args.duration)
