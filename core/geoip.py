import requests
import ipaddress

# Cache to prevent making duplicate API calls for the same IP
GEO_CACHE = {}

def get_ip_location(ip: str) -> dict:
    """
    Resolves an IP to geographical coordinates (lat, lon, country, city).
    Uses ip-api.com for public IPs. Private/local addresses have no public
    geographic location and are returned without invented coordinates.
    """
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]

    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = True

    if is_private:
        result = {
            "country": "Private network",
            "city": "Local source",
            "latitude": None,
            "longitude": None,
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