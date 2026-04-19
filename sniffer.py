from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, conf
from datetime import datetime
import sys

# ------------------------------
# Configuration & Metrics
# ------------------------------
stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "Total": 0}

def get_service(port):
    """Maps common ports to service names."""
    services = {
        20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet",
        25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
        143: "IMAP", 443: "HTTPS", 3306: "MySQL", 5432: "PostgreSQL"
    }
    return services.get(port, "Unknown")

# ------------------------------
# Packet Processing Logic
# ------------------------------
def process_packet(packet):
    global stats
    stats["Total"] += 1
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    print(f"\n[+] Packet #{stats['Total']} | Captured at: {timestamp}")
    
    if IP in packet:
        ip_layer = packet[IP]
        print(f"    [IP Layer] {ip_layer.src} -> {ip_layer.dst} | TTL: {ip_layer.ttl}")

        # --- TCP Analysis ---
        if packet.haslayer(TCP):
            stats["TCP"] += 1
            tcp = packet[TCP]
            srv_src = get_service(tcp.sport)
            srv_dst = get_service(tcp.dport)
            print(f"    [TCP] Port: {tcp.sport}({srv_src}) -> {tcp.dport}({srv_dst})")
            print(f"    [Flags] {tcp.flags}")

        # --- UDP Analysis ---
        elif packet.haslayer(UDP):
            stats["UDP"] += 1
            udp = packet[UDP]
            print(f"    [UDP] Port: {udp.sport} -> {udp.dport} | Len: {udp.len}")

        # --- ICMP Analysis ---
        elif packet.haslayer(ICMP):
            stats["ICMP"] += 1
            print(f"    [ICMP] Type: {packet[ICMP].type} | Code: {packet[ICMP].code}")

        # --- Payload Extraction ---
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            # Displaying first 64 characters of the payload
            printable_data = "".join([chr(b) if 32 <= b < 127 else "." for b in payload])
            print(f"    [Payload] {printable_data[:64]}...")

def main():
    print("="*60)
    print("        🕵️  REAL-TIME PACKET ANALYZER (SCAPY) ")
    print("        Note: Run as Sudo/Administrator")
    print("="*60)

    try:
        # filter="" captures everything; change to "tcp" or "udp" if needed
        sniff(filter="ip", prn=process_packet, store=False, count=10)
        
        print("\n" + "="*60)
        print("📊 SESSION SUMMARY")
        print(f"Total Captured: {stats['Total']}")
        print(f"TCP: {stats['TCP']} | UDP: {stats['UDP']} | ICMP: {stats['ICMP']}")
        print("="*60)
        
    except PermissionError:
        print("[!] Error: Root/Admin privileges required to sniff packets.")
    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
        sys.exit()

if __name__ == "__main__":
    main()
