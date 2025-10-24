
import argparse
from collections import Counter
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP

def parse_packet(pkt, istatistik, yakalama):
    istatistik["total"] += 1
    if pkt.haslayer(IP):
        ip = pkt[IP]
        istatistik["src"][ip.src] += 1
        istatistik["dst"][ip.dst] += 1
    if pkt.haslayer(TCP):
        istatistik["proto"]["TCP"] += 1
    if pkt.haslayer(UDP):
        istatistik["proto"]["UDP"] += 1
    if pkt.haslayer(ICMP):
        istatistik["proto"]["ICMP"] += 1

    yakalama.append(pkt)

def print_summary(stats):
    print("\n=== Summary ===")
    print(f"Total packets: {stats['total']}")
    print("Protocols:")
    for proto, count in stats["proto"].items():
        print(f"  {proto}: {count}")
    print("Top 5 source IPs:")
    for ip, count in stats["src"].most_common(5):
        print(f"  {ip}: {count}")
    print("Top 5 dest IPs:")
    for ip, count in stats["dst"].most_common(5):
        print(f"  {ip}: {count}")

def main():
    parser = argparse.ArgumentParser(description="ByteSpectre -- Packet Sniffer with Python (Scapy)")
    parser.add_argument("-i", "--iface", help="Interface (e.g. eth0, wlan0)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 = unlimited)")
    parser.add_argument("-s", "--save", help="Save captured packets to pcap file")
    parser.add_argument("-f", "--filter", default=None, help="BPF filter string, e.g. 'tcp port 80'")
    args = parser.parse_args()

    istatistikler = {
        "total": 0,
        "proto": Counter(),
        "src": Counter(),
        "dst": Counter()
    }
    captured = []

    def _callback(pkt):
        try:
            parse_packet(pkt, istatistikler, captured)
        except Exception:
            pass

    sniff_kwargs = {"prn": _callback, "store": False}
    if args.iface:
        sniff_kwargs["iface"] = args.iface
    if args.count > 0:
        sniff_kwargs["count"] = args.count
    if args.filter:
        sniff_kwargs["filter"] = args.filter

    print("Sniffing... (Run as root if required) — Ctrl+C to stop")
    try:
        sniff(**sniff_kwargs)
    except KeyboardInterrupt:
        print("\nStopped by user.")
    except Exception as e:
        print("Sniff error:", e)

    print_summary(istatistikler)

    if args.save and captured:
        try:
            wrpcap(args.save, captured)
            print(f"Saved {len(captured)} packets to {args.save}")
        except Exception as e:
            print("Error saving pcap:", e)

if __name__ == "__main__":
    main()
