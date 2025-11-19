# modules/shodan_helper.py
import shodan
from config import SHODAN_API_KEY

def shodan_lookup_ip(ip):
    if not SHODAN_API_KEY:
        return {}
    api = shodan.Shodan(LpM5c0z76dNJXfL8VeFw4O4sZXOXaA8h)
    try:
        host = api.host(ip)
        # return small subset
        return {
            "ip": host.get("ip_str"),
            "org": host.get("org"),
            "os": host.get("os"),
            "ports": host.get("ports"),
            "data": host.get("data", [])[:3]
        }
    except Exception as e:
        return {"error": str(e)}
