# modules/collector.py
import requests
import json
from datetime import datetime
from config import ABUSEIPDB_API_KEY, DATA_FILE, MAX_FETCH
import os

os.makedirs("data", exist_ok=True)

def fetch_abuseipdb_blacklist(max_rows=MAX_FETCH):
    """
    Fetches AbuseIPDB blacklist (requires API key).
    Note: AbuseIPDB has a free tier and a specific endpoint for blacklist export.
    """
    if not ABUSEIPDB_API_KEY:
        raise ValueError("ABUSEIPDB_API_KEY is not set in .env")

    url = "https://api.abuseipdb.com/api/v2/blacklist"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "confidenceMinimum": 75  # example param
    }
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    # Limit results
    if isinstance(data, dict) and "data" in data:
        data["data"] = data["data"][:max_rows]
    data["fetched_at"] = datetime.utcnow().isoformat()
    return data

def save_data(obj, path=DATA_FILE):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def load_data(path=DATA_FILE):
    if not os.path.exists(path):
        return {"data": [], "fetched_at": None}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    try:
        d = fetch_abuseipdb_blacklist()
        save_data(d)
        print("Saved", len(d.get("data", [])), "records to", DATA_FILE)
    except Exception as e:
        print("Error fetching:", e)
        # fallback: create empty file
        save_data({"data": [], "fetched_at": datetime.utcnow().isoformat()})
