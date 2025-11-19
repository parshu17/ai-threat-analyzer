# config.py
from dotenv import load_dotenv
import os

load_dotenv()  # loads .env

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
IPINFO_TOKEN = os.getenv("IPINFO_TOKEN")

# small config
DATA_FILE = "data/threats.json"
MAX_FETCH = 50
