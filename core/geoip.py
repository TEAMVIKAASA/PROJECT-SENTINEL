import requests
import random

# Cache to prevent making duplicate API calls for the same IP
GEO_CACHE = {}

# Fallback coordinates for private/local IP simulations so testing looks real on the map
SIMULATED_GLOBAL_LOCATIONS = [
    {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821},
    {"country": "United States", "city": "Ashburn", "lat": 39.0438, "lon": -77.4874},
    {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198},
    {"country": "Netherlands", "city": "Amsterdam", "lat": 52.3676, "lon": 4.9041},
    {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503}
]

def get_ip_location(ip: str) -> dict:
    """
    Resolves an IP to geographical coordinates (lat, lon, country, city).
    Uses ip-api.com for public IPs; uses mock geolocations for local/private test IPs.
    """
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    # Handle local / private networks (RFC 1918)
    if ip in ("127.0.0.1", "localhost", "::1") or ip.startswith(("192.168.", "10.", "172.16.")):
        simulated = random.choice(SIMULATED_GLOBAL_LOCATIONS)
        result = {
            "country": simulated["country"],
            "city": simulated["city"],
            "latitude": simulated["lat"],
            "longitude": simulated["lon"]
        }
        GEO_CACHE[ip] = result
        return result

    # Resolve real public IPs via free API
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,city,lat,lon", timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "latitude": data.get("lat"),
                    "longitude": data.get("lon")
                }
                GEO_CACHE[ip] = result
                return result
    except Exception as e:
        print(f"[-] GeoIP lookup failed for {ip}: {e}")

    fallback = {"country": "Unknown", "city": "Unknown", "latitude": None, "longitude": None}
    GEO_CACHE[ip] = fallback
    return fallback