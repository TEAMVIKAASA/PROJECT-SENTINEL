import os
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")

supabase: Client = None
if SUPABASE_URL and SUPABASE_KEY and "your-project" not in SUPABASE_URL:
    try:
        supabase = create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        print(f"[-] Supabase connection error: {e}")

def log_alert(source_ip: str, attack_type: str, ports_hit: int, severity: str = "Critical", geo_data: dict = None):
    """Inserts a detected intrusion alert along with GeoIP data into Supabase."""
    if not supabase:
        print(f"[!] Alert detected (Supabase offline): {source_ip} rattled {ports_hit} ports.")
        return None

    geo = geo_data or {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None}

    payload = {
        "source_ip": source_ip,
        "attack_type": attack_type,
        "target_ports_hit": ports_hit,
        "severity": severity,
        "country": geo.get("country", "Unknown"),
        "city": geo.get("city", "Unknown"),
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude")
    }
    try:
        response = supabase.table("alerts").insert(payload).execute()
        return response.data
    except Exception as e:
        print(f"[-] Failed to push alert to Supabase: {e}")
        return None