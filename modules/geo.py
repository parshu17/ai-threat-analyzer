# modules/geo.py
import requests
from config import IPINFO_TOKEN
import pycountry

def ipinfo_lookup(ip):
    """
    Use ipinfo.io token (if available) to get geo data.
    Falls back to free ipinfo endpoint w/ limited rate.
    """
    base = "https://ipinfo.io/"
    token = IPINFO_TOKEN
    url = f"{base}{ip}/json"
    params = {}
    if token:
        params["token"] = token
    resp = requests.get(url, params=params, timeout=10)
    if resp.status_code != 200:
        return {}
    d = resp.json()
    # fields: ip, hostname, city, region, country, loc (lat,long), org
    if "country" in d:
        try:
            d["country_name"] = pycountry.countries.get(alpha_2=d["country"]).name
        except Exception:
            d["country_name"] = d.get("country")
    return d

def enrich_df_with_geo(df, ip_field="ipAddress"):
    """
    df: pandas.DataFrame
    returns df with columns: ip, city, region, country, latitude, longitude
    """
    import pandas as pd
    df2 = df.copy()
    lat = []
    lon = []
    country = []
    city = []
    region = []
    for ip in df2[ip_field].fillna("").astype(str).tolist():
        if not ip:
            lat.append(None); lon.append(None); country.append(None); city.append(None); region.append(None)
            continue
        info = ipinfo_lookup(ip)
        loc = info.get("loc")
        if loc:
            try:
                la, lo = loc.split(",")
            except:
                la, lo = None, None
        else:
            la, lo = None, None
        lat.append(la); lon.append(lo)
        country.append(info.get("country_name") or info.get("country"))
        city.append(info.get("city"))
        region.append(info.get("region"))
    df2["geo_lat"] = lat
    df2["geo_lon"] = lon
    df2["geo_country"] = country
    df2["geo_city"] = city
    df2["geo_region"] = region
    return df2
