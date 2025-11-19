# modules/mitre_map.py
MITRE_KEYWORDS = {
    "phishing": ["T1566", "Phishing"],
    "bruteforce": ["T1110", "Brute Force"],
    "port scan": ["T1595", "Active Scanning"],
    "malware": ["T1204", "User Execution / Malware"],
    "ransomware": ["T1486", "Data Encrypted for Impact"],
    "cmd_injection": ["T1059", "Command and Scripting Interpreter"],
    "exfiltration": ["T1041", "Exfiltration Over C2 Channel"],
    "recon": ["T1595", "Active Scanning"],
    "credential": ["T1555", "Credentials from Password Stores"]
}

def map_text_to_mitre(text):
    text_l = text.lower()
    tags = []
    for k,v in MITRE_KEYWORDS.items():
        if k in text_l or any(word in text_l for word in k.split()):
            tags.append({"tech_id": v[0], "tech_name": v[1], "keyword": k})
    return tags
