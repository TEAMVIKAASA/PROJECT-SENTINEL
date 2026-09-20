import os
import time
from collections import deque
from scapy.all import wrpcap

EVIDENCE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence")
os.makedirs(EVIDENCE_DIR, exist_ok=True)

# Sliding memory buffer to hold the last 150 raw network packets
packet_buffer = deque(maxlen=150)

def record_raw_packet(packet):
    """Keeps the last N packets in memory without writing to disk continuously."""
    packet_buffer.append(packet)

def dump_attack_pcap(source_ip: str, attack_type: str) -> str:
    """
    Saves current buffer of raw packets to a timestamped .pcap file for Wireshark inspection.
    """
    clean_ip = source_ip.replace(":", "_").replace(".", "_")
    timestamp = int(time.time())
    filename = f"incident_{clean_ip}_{timestamp}.pcap"
    filepath = os.path.join(EVIDENCE_DIR, filename)

    try:
        packets_to_save = list(packet_buffer)
        if packets_to_save:
            wrpcap(filepath, packets_to_save)
            print(f"[📁 FORENSICS] Saved raw attack trace: {filename} ({len(packets_to_save)} packets)")
            return filename
    except Exception as e:
        print(f"[-] Failed to dump PCAP forensic file: {e}")

    return None