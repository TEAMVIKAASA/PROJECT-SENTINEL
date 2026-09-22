from scapy.all import sniff, IP, TCP, UDP, conf
from core.engine import ThreatEngine
from core.forensics import record_raw_packet

engine = ThreatEngine()

def handle_packet(packet):
    # Store raw packet in memory buffer for instant forensic snapshot
    record_raw_packet(packet)

    if IP in packet and (TCP in packet or UDP in packet):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
        flags = str(packet[TCP].flags) if TCP in packet else ""
        engine.process_packet(src_ip, dst_port, flags, dst_ip)

def start_sniffing():
    print("[*] Project Sentinel: Boundary Sniffer Active.")
    print("[*] Monitoring TCP/UDP packets with active forensic ring-buffer...")
    iface = conf.loopback_name if hasattr(conf, "loopback_name") else None
    sniff(iface=iface, prn=handle_packet, store=False)