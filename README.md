🚀 ThreatVision AI – SOC Intelligence Dashboard
AI-Powered Threat Intelligence, MITRE ATT&CK Mapping & Real-Time Analysis

ThreatVision AI is an advanced AI-powered Threat Intelligence Dashboard designed for SOC analysts, penetration testers, and cybersecurity researchers.
It combines Threat Feeds, NLP Classification, MITRE ATT&CK Mapping, Visual Analytics, and AI-driven anomaly detection into one powerful tool.

Built using:

Streamlit (Dashboard UI)
Python

Transformers / Sentence-Transformers

Pandas, Plotly

AbuseIPDB API

Custom MITRE Mapping Engine

⭐ Features

🔥 1. Real-Time Threat Feed Collection

Automatically fetch malicious IPs from AbuseIPDB

Import JSON threat data manually

Auto-save + timestamp logs

🤖 2. AI-Based Threat Classification

Uses NLP models to classify:

Brute-force attacks

Port scanning

Malware behavior

Botnet traffic

C2 interaction

Suspicious recon activities

🧠 3. MITRE ATT&CK Mapping (AI-Enhanced)

Maps threat descriptions → MITRE ATT&CK techniques

Displays frequency and summary table

Helps analysts understand attack context

📊 4. Interactive Visual Dashboards

Attack category charts

Time-series attack patterns

MITRE technique stats

Top severity threats

🛡️ 5. SOC-Ready Architecture

Clean modular design (collector, analyzer, visualizer)

Expandable to Shodan, VirusTotal, GreyNoise, OSINT feeds

Easy for recruiters to understand and evaluate

🛠️ Installation

git clone https://github.com/parshu17/threatvision-ai.git

cd threatvision-ai

python -m venv venv 

source venv/bin/activate   # Mac/Linux

venv\Scripts\activate      # Windows

pip install --upgrade pip

pip install -r requirements.txt

.env

ABUSEIPDB_KEY=your_key_here

streamlit run app.py

Dashboard will open at:

http://localhost:8501

