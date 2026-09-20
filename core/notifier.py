import os
import requests
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL")

def send_security_alert(source_ip: str, attack_type: str, severity: str, ports_hit: int, geo_data: dict = None):
    """
    Sends an automated JSON alert payload to an external security channel (Discord/Slack).
    Falls back gracefully if no webhook URL is configured.
    """
    geo = geo_data or {"country": "Unknown", "city": "Unknown"}
    
    if not ALERT_WEBHOOK_URL:
        print(f"[Notifier] Webhook not configured in .env. Skipping external push notification.")
        return False

    # Discord-compatible Rich Embed payload
    payload = {
        "username": "Sentinel SOC Watchdog",
        "avatar_url": "https://img.icons8.com/fluency/96/shield.png",
        "embeds": [
            {
                "title": f"🚨 {severity.upper()} SECURITY ALERT: Intrusion Neutralized",
                "description": f"Project Sentinel detected and mitigated malicious traffic at the perimeter.",
                "color": 15158332 if severity == "Critical" else 15105570, # Red for Critical, Orange for High
                "fields": [
                    {"name": "Threat Actor IP", "value": f"`{source_ip}`", "inline": True},
                    {"name": "Threat Profile", "value": attack_type, "inline": True},
                    {"name": "Severity", "value": f"**{severity}**", "inline": True},
                    {"name": "Origin", "value": f"{geo.get('city')}, {geo.get('country')}", "inline": True},
                    {"name": "Volume / Ports Rattled", "value": str(ports_hit), "inline": True},
                    {"name": "Defense Action", "value": "Firewall Rule Created (Packet Dropped)", "inline": True}
                ],
                "footer": {"text": "Project Sentinel VIDS/IPS Engine"},
                "timestamp": datetime.utcnow().isoformat()
            }
        ]
    }

    try:
        response = requests.post(ALERT_WEBHOOK_URL, json=payload, timeout=4)
        if response.status_code in (200, 204):
            print(f"[+] Emergency alert dispatched via Webhook.")
            return True
        else:
            print(f"[-] Webhook push failed with status code {response.status_code}")
            return False
    except Exception as e:
        print(f"[-] Error dispatching alert webhook: {e}")
        return False