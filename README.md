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

## Publish the Dashboard Online

The Streamlit dashboard can be deployed from GitHub with [Streamlit Community Cloud](https://streamlit.io/cloud). The packet sniffer and firewall controller cannot run on Vercel, GitHub Pages, or a normal serverless host because they require raw network access and host firewall privileges.

### Recommended deployment

1. Push this repository to GitHub.
2. Open Streamlit Community Cloud and choose **Create app**.
3. Select the repository and branch, then set the main file to `dashboard/app.py`.
4. In the app settings, add these secrets:

    ```toml
    SUPABASE_URL = "https://your-project.supabase.co"
    SUPABASE_KEY = "your-supabase-anon-key"
    ```

5. Deploy the app. Streamlit will provide a public URL that can be shared.

Keep the Supabase service-role key out of the dashboard secrets. The dashboard only needs a key that is safe for client-side data access under the database's Row Level Security policies.

### Run the sensor separately

Run the backend on a Linux host, home server, or VM that can see the traffic being monitored:

```bash
cp .env.example .env
docker compose up --build
```

The backend writes alerts to Supabase; the hosted Streamlit dashboard reads those alerts. A cloud dashboard by itself will show `Perimeter quiet` until a sensor or test data writes rows to the `alerts` table.

### Platform limitations

- **GitHub Pages:** static files only; it cannot run this Python/Streamlit app.
- **Vercel:** suitable for serverless web apps, but not for Scapy raw packet capture or `iptables`/`netsh` firewall actions.
- **Streamlit Community Cloud:** suitable for the dashboard only.
- **Docker on a VM or dedicated host:** suitable for the sensor and dashboard together.

## Contributors

- [Sarvottam Kumar Jha](https://github.com/SarvottamKumarJha)
- [MishraJi Developer](https://github.com/MishraJi-Devloper)
