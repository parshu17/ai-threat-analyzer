# modules/analyzer.py

from transformers import pipeline
from sentence_transformers import SentenceTransformer, util

# --- Load Models ---
classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
embedder = SentenceTransformer("all-MiniLM-L6-v2")

# --- MITRE ATT&CK Fake Mapping (Expandable) ---
mitre_map = {
    "scan": "T1046 – Network Service Scanning",
    "bruteforce": "T1110 – Brute Force",
    "login": "T1110 – Credential Access",
    "dos": "T1499 – Denial of Service",
    "malware": "T1204 – User Execution",
    "ransom": "T1486 – Data Encrypted for Impact",
    "phishing": "T1566 – Phishing"
}

def map_text_to_mitre(text):
    text = text.lower()
    for keyword, technique in mitre_map.items():
        if keyword in text:
            return technique
    return "Unknown Technique"

# --- Main Function ---
def analyze_list(records, text_field):
    """
    Takes a list of dicts and analyzes text inside the selected field.
    Returns a list with appended `_label`, `_score`, `_mitre` fields.
    """
    results = []
    
    for r in records:
        text = r.get(text_field, "")

        # clean empty records
        if not isinstance(text, str):
            text = str(text)

        # Perform sentiment/label classification
        try:
            pred = classifier(text)[0]
            label = pred["label"]
            score = float(pred["score"])
        except Exception:
            label = "unknown"
            score = 0.0

        # Build new dict safely
        r2 = r.copy()
        r2["_label"] = label
        r2["_score"] = score
        
        # MITRE mapping
        r2["_mitre"] = map_text_to_mitre(text)

        results.append(r2)

    return results
