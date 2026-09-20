# 🛡️ Project Sentinel: Virtual Intrusion Detection & Prevention System (VIDS/IPS)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Network-Scapy-red.svg)](https://scapy.net/)
[![Database](https://img.shields.io/badge/Cloud_DB-Supabase_(PostgreSQL)-emerald.svg)](https://supabase.com/)
[![Dashboard](https://img.shields.io/badge/SOC_Console-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![Docker](https://img.shields.io/badge/Deployment-Docker_Compose-2496ED.svg)](https://www.docker.com/)

**Project Sentinel** is an automated, cloud-integrated Network Intrusion Detection and Prevention System (NIDS/IPS) engineered from scratch. It inspects live packet traffic at the network boundary, evaluates behavioral heuristics to identify reconnaissance and Denial-of-Service (DoS) attacks, neutralizes threats via operating system firewall automation, captures raw PCAP traces for digital forensics, and streams telemetry to a live Security Operations Center (SOC) dashboard.

---

## 🏛️ System Architecture

```text
               [ Inbound Network Traffic ]
                            │
                            ▼
              [ 1. Network Boundary Sniffer ] (Scapy Raw Sockets)
                            │
                            ▼
               [ 2. Threat Logic Engine ]
       (Sliding Time-Window Heuristic Evaluation)
                            │
    ┌───────────────────────┼───────────────────────┬───────────────────────┐
    ▼                       ▼                       ▼                       ▼
[ 3. Active IPS ]     [ 4. Forensics ]       [ 5. Push Alerts ]     [ 6. Cloud Store ]
 Host Firewall Drops   Circular PCAP Dump    Discord Webhook API     Supabase (Postgres)
 (netsh / iptables)   (Wireshark-ready)      (Real-time Embeds)      (RLS Encrypted)
                                                                            │
                                                                            ▼
                                                                [ 7. Analyst Console ]
                                                                 Streamlit SOC UI
                                                                 (GeoIP Map & Analytics)