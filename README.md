# 🌐 Network Traffic Analyzer

> A Python-based network traffic analyzer built using **CCNA concepts** — packet capture, protocol detection, live statistics and Power BI visualization.

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Networking](https://img.shields.io/badge/CCNA-1BA0D7?style=for-the-badge&logo=cisco&logoColor=white)
![Power BI](https://img.shields.io/badge/Power_BI-F2C811?style=for-the-badge&logo=powerbi&logoColor=black)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)

---

## 📌 Project Overview

A professional network traffic analysis tool that captures, decodes and visualizes network packets — directly applying **CCNA networking knowledge** in a Python project.

This project stands out for:
- 🏢 **Cisco, Juniper, Nokia** (Network Engineer roles)
- 💻 **TCS, Wipro, HCL** (Network Operations roles)
- 🔒 **Cybersecurity internships** (SOC Analyst roles)

---

## ✨ Features

- 📦 **Packet capture** using Scapy
- 🔍 **Protocol detection** — TCP, UDP, HTTP, DNS, ICMP, ARP
- 📊 **Live traffic statistics** — packets/second, top IPs, top protocols
- 🌍 **IP geolocation** — map source/destination countries
- ⚠️ **Anomaly detection** — port scans, high traffic alerts
- 💾 **Export to CSV/PCAP** for Power BI analysis
- 📈 **Power BI dashboard** — protocol breakdown, traffic trends

---

## 🗂️ Project Structure

```
Network-Traffic-Analyzer/
├── python/
│   ├── analyzer.py             # Main packet analyzer
│   ├── packet_parser.py        # Parse and decode packets
│   ├── statistics.py           # Traffic statistics engine
│   ├── anomaly_detector.py     # Detect suspicious patterns
│   └── report_generator.py     # Generate CSV reports
├── data/
│   └── sample_traffic.csv      # Sample network traffic data
├── powerbi/
│   └── dashboard_guide.md      # Power BI setup
├── requirements.txt
└── README.md
```

---

## 🚀 Getting Started

```bash
pip install scapy pandas flask
# Run as administrator/root for packet capture
python python/analyzer.py --interface eth0 --duration 60
# Or analyze sample data (no admin needed)
python python/analyzer.py --sample
```

---

## 📊 Sample Output

```
🌐 Network Traffic Analyzer — Live Stats
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Packets  : 1,245
TCP Packets    : 892  (71.6%)
UDP Packets    : 287  (23.0%)
ICMP Packets   :  66  ( 5.4%)

Top Source IPs:
  192.168.1.5   → 423 packets
  192.168.1.10  → 198 packets
  10.0.0.1      →  87 packets

⚠️  ALERT: Port scan detected from 192.168.1.99
```

---

## 🔧 CCNA Concepts Applied

| Concept | Implementation |
|---------|---------------|
| OSI Model | Packet parsed at Layer 2, 3, 4 |
| TCP/IP | TCP flags, handshake detection |
| Subnetting | IP classification (private/public) |
| DNS | DNS query/response parsing |
| ARP | ARP request/reply monitoring |
| Port Numbers | Service identification by port |

---

## 👨‍💻 Author

**Kadari Eshwar** — ECE Student, JNTU Hyderabad
[GitHub](https://github.com/Eshwarkadari) | [LinkedIn](https://www.linkedin.com/in/eshwar-kadari-134aa4278)
