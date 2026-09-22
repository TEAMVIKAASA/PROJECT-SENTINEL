import time
from collections import defaultdict
from database.database import log_alert
from core.firewall import block_ip
from core.geoip import get_ip_location
from core.notifier import send_security_alert
from core.forensics import dump_attack_pcap

SCAN_THRESHOLD = 50
SCAN_TIME_WINDOW = 3.0

SYN_FLOOD_THRESHOLD = 40
SYN_FLOOD_TIME_WINDOW = 2.0

class ThreatEngine:
    def __init__(self):
        self.ip_port_activity = defaultdict(list)
        self.ip_syn_activity = defaultdict(list)
        self.flagged_scanners = set()
        self.flagged_flooders = set()

    def process_packet(self, src_ip: str, dst_port: int, flags: str = "", dst_ip: str = ""):
        now = time.time()

        # --- Rule 1: Port Scan Reconnaissance ---
        self.ip_port_activity[src_ip].append((now, dst_port))
        self.ip_port_activity[src_ip] = [
            (t, p) for t, p in self.ip_port_activity[src_ip] if now - t <= SCAN_TIME_WINDOW
        ]
        unique_ports = {p for _, p in self.ip_port_activity[src_ip]}

        if len(unique_ports) >= SCAN_THRESHOLD:
            if src_ip not in self.flagged_scanners:
                geo = get_ip_location(src_ip)
                print(f"\n[🚨 ALERT] Port Scan from {src_ip} ({geo['country']}, {geo['city']}) | Hit {len(unique_ports)} ports")

                # 1. Forensic Snapshot (.pcap)
                pcap_file = dump_attack_pcap(src_ip, "Port Scan Reconnaissance")

                # 2. Log to Database
                log_alert(
                    source_ip=src_ip,
                    attack_type="Port Scan Reconnaissance",
                    ports_hit=len(unique_ports),
                    severity="Critical",
                    geo_data=geo,
                    destination_ip=dst_ip
                )

                # 3. Block IP at Firewall
                block_ip(src_ip)

                # 4. Dispatch Discord Webhook
                send_security_alert(
                    source_ip=src_ip,
                    attack_type="Port Scan Reconnaissance",
                    severity="Critical",
                    ports_hit=len(unique_ports),
                    geo_data=geo
                )

                self.flagged_scanners.add(src_ip)
        else:
            if src_ip in self.flagged_scanners:
                self.flagged_scanners.remove(src_ip)

        # --- Rule 2: TCP SYN Flood DoS ---
        if flags == "S":
            self.ip_syn_activity[src_ip].append(now)
            self.ip_syn_activity[src_ip] = [
                t for t in self.ip_syn_activity[src_ip] if now - t <= SYN_FLOOD_TIME_WINDOW
            ]

            if len(self.ip_syn_activity[src_ip]) >= SYN_FLOOD_THRESHOLD:
                if src_ip not in self.flagged_flooders:
                    geo = get_ip_location(src_ip)
                    print(f"\n[🚨 ALERT] SYN Flood from {src_ip} ({geo['country']}) | {len(self.ip_syn_activity[src_ip])} SYNs")

                    pcap_file = dump_attack_pcap(src_ip, "TCP SYN Flood DoS")

                    log_alert(
                        source_ip=src_ip,
                        attack_type="TCP SYN Flood DoS",
                        ports_hit=len(self.ip_syn_activity[src_ip]),
                        severity="Critical",
                        geo_data=geo,
                        destination_ip=dst_ip
                    )

                    block_ip(src_ip)

                    send_security_alert(
                        source_ip=src_ip,
                        attack_type="TCP SYN Flood DoS",
                        severity="Critical",
                        ports_hit=len(self.ip_syn_activity[src_ip]),
                        geo_data=geo
                    )

                    self.flagged_flooders.add(src_ip)
            else:
                if src_ip in self.flagged_flooders:
                    self.flagged_flooders.remove(src_ip)