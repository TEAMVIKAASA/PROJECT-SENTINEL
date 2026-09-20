import os
import sys
import pandas as pd
import streamlit as st
from dotenv import load_dotenv

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from core.firewall import unblock_ip

st.set_page_config(
    page_title="Project Sentinel | VIDS/IPS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase = None
if SUPABASE_URL and SUPABASE_KEY and "your-project" not in SUPABASE_URL:
    try:
        from supabase import create_client
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        st.sidebar.warning(f"Supabase connection error: {e}")

def fetch_data():
    if supabase:
        try:
            res = supabase.table("alerts").select("*").order("created_at", desc=True).limit(200).execute()
            if res.data:
                df = pd.DataFrame(res.data)
                parsed_dates = pd.to_datetime(df["created_at"], format="ISO8601")
                df["created_at"] = parsed_dates.dt.strftime("%Y-%m-%d %H:%M:%S")
                return df
        except Exception as e:
            st.error(f"Database error: {e}")
    return pd.DataFrame()

# Sidebar Controls
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=70)
    st.title("Sentinel Console")
    st.caption("Virtual Intrusion Prevention System (IPS)")
    st.divider()

    severity_filter = st.multiselect(
        "Filter by Severity",
        options=["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium", "Low"]
    )

    st.divider()
    st.subheader("🔓 Firewall Controls")
    ip_to_unblock = st.text_input("Enter IP to Unban:")
    if st.button("Lift IP Block"):
        if ip_to_unblock:
            unblock_ip(ip_to_unblock.strip())
            st.success(f"Unblock rule dispatched for {ip_to_unblock.strip()}")

# Main SOC View
@st.fragment(run_every="3s")
def render_live_board():
    df = fetch_data()

    st.markdown("## 🛡️ Project Sentinel: Global SOC Operations")
    st.markdown("Real-time network telemetry, automated threat suppression, and global origin mapping.")
    st.divider()

    col1, col2, col3, col4 = st.columns(4)
    total_count = len(df)
    critical_count = len(df[df["severity"] == "Critical"]) if not df.empty and "severity" in df else 0
    high_count = len(df[df["severity"] == "High"]) if not df.empty and "severity" in df else 0
    unique_ips = df["source_ip"].nunique() if not df.empty and "source_ip" in df else 0

    col1.metric(label="Total Incidents", value=total_count)
    col2.metric(label="Critical Attacks", value=critical_count)
    col3.metric(label="High Alerts", value=high_count)
    col4.metric(label="Unique Adversaries", value=unique_ips)

    st.write("")

    if not df.empty:
        # Visual Analytics Section
        chart_col, map_col = st.columns([1, 1])

        with chart_col:
            st.subheader("📊 Threat Breakdown")
            threat_counts = df["attack_type"].value_counts()
            st.bar_chart(threat_counts, use_container_width=True)

        with map_col:
            st.subheader("🌍 Attack Origin Map")
            # Filter coordinates for plotting
            if "latitude" in df.columns and "longitude" in df.columns:
                map_df = df.dropna(subset=["latitude", "longitude"])
                if not map_df.empty:
                    st.map(map_df, latitude="latitude", longitude="longitude", size=20, zoom=1)
                else:
                    st.info("No coordinate data available yet.")
            else:
                st.info("Map data pending schema update.")

        # Incident Logbook
        col_table_header, col_export = st.columns([4, 1])
        with col_table_header:
            st.subheader("📋 Security Incident Logbook")
        with col_export:
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export CSV Log",
                data=csv_data,
                file_name="sentinel_incident_report.csv",
                mime="text/csv",
                use_container_width=True
            )

        filtered_df = df[df["severity"].isin(severity_filter)] if "severity" in df.columns and severity_filter else df

        st.dataframe(
            filtered_df,
            use_container_width=True,
            column_config={
                "id": st.column_config.NumberColumn("ID", width="small"),
                "created_at": st.column_config.TextColumn("Timestamp (UTC)", width="medium"),
                "source_ip": st.column_config.TextColumn("Attacker IP", width="medium"),
                "country": st.column_config.TextColumn("Origin Country", width="small"),
                "city": st.column_config.TextColumn("Origin City", width="small"),
                "attack_type": st.column_config.TextColumn("Threat Profile", width="large"),
                "target_ports_hit": st.column_config.NumberColumn("Hits / Volume", width="small"),
                "severity": st.column_config.TextColumn("Severity", width="small"),
            },
            hide_index=True
        )
    else:
        st.info("Perimeter quiet. No anomalies flagged.")

    # Forensic PCAP Section
    st.divider()
    st.subheader("🔬 Forensic PCAP Evidence Locker")
    st.caption("Download raw network packet traces to inspect headers, sequence numbers, and payloads in Wireshark.")

    evidence_folder = os.path.join(os.path.dirname(os.path.dirname(__file__)), "evidence")
    if os.path.exists(evidence_folder):
        pcap_files = [f for f in os.listdir(evidence_folder) if f.endswith(".pcap")]
        if pcap_files:
            selected_pcap = st.selectbox("Select Evidence Trace", pcap_files)
            file_path = os.path.join(evidence_folder, selected_pcap)
            with open(file_path, "rb") as f:
                st.download_button(
                    label=f"⬇️ Download {selected_pcap}",
                    data=f,
                    file_name=selected_pcap,
                    mime="application/vnd.tcpdump.pcap",
                    use_container_width=True
                )
        else:
            st.info("Evidence locker is clean. No incident traces generated yet.")
    else:
        st.info("Evidence directory not found. Trigger an intrusion to generate the first trace.")

render_live_board()