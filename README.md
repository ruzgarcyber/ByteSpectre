# 🚀 ByteSpectre

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green)

ByteSpectre — Minimal Python/Scapy packet sniffer for learning network traffic analysis.  
Lightweight, educational tool to capture and inspect basic network traffic. Use only on networks you own or have explicit permission to test. 🛡️

## ✨ Features
- 🐍 Capture N packets or run until interrupted (Ctrl+C)  
- 📊 Show protocol counts (TCP / UDP / ICMP)  
- 🌐 Top 5 source & destination IPs  
- 💾 Optional pcap save for offline analysis  

## ⚙️ Requirements
- Python 3.8+  
- scapy (`pip install -r requirements.txt`)  
- Root / Administrator privileges often required for sniffing

## ⚡ Quick usage
```bash
# Capture 100 packets on iface wlan0 and save to capture.pcap
sudo python3 bytespectre.py -i wlan0 -c 100 -s capture.pcap

# Run until Ctrl+C, show summary at the end
sudo python3 bytespectre.py -i eth0
```

## 📄 License
- **MIT**

## ⚠️ Disclaimer
- **This tool is for educational purposes. Do not use it to capture traffic on networks you do not own or have permission to test. 🛑**
