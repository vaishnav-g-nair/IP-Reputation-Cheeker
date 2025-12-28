#  Threat Intelligence Dashboard  
### Bulk IP Reputation Analysis using VirusTotal

> Built to reduce friction in real-world security investigations.

---

## Background & Motivation

This project started from a **real operational problem**.

During a discussion with a cybersecurity professional, one pain point came up clearly:

> *“Checking IP addresses one by one in VirusTotal is time-consuming and frustrating when working with bulk indicators.”*

That inefficiency is something many SOC analysts, students, and threat researchers silently accept.

So instead of accepting it, I decided to **design a simpler workflow**.



## 🎯 Project Intent

The intention of this project is **not to replace VirusTotal**,  
but to **improve how analysts interact with it** when dealing with multiple IPs.

This dashboard is built to:
- Reduce repetitive manual work
- Respect VirusTotal free-tier limitations
- Present results in an analyst-friendly way
- Support investigation and learning workflows

---

## 🔍 What This Tool Does

- Accepts a list of IP addresses (bulk input)
- Queries VirusTotal for each IP
- Handles API rate limits gracefully
- Aggregates threat intelligence results
- Displays insights in a SOC-style dashboard
- Allows exporting results for reporting or escalation

---

## 📊 Key Features

- 🧪 Bulk IP reputation analysis  
- 🛡️ VirusTotal engine correlation  
- ⏱ Free-tier API rate-limit handling  
- 📈 Threat overview dashboard (Malicious / Suspicious / Clean)  
- 📄 CSV export for investigation reports  
- 🌐 Web-based interface using Streamlit  

---

## 🚀 Live Demo

🔗 **Demo Application:**  
👉 [https://your-streamlit-app-link-here](https://ip-reputation-cheeker-6olxx3udrseofycr5kn4ph.streamlit.app/)

> You will need your own VirusTotal API key to run scans.

---

## 🛠️ How to Use

1. Open the dashboard using the demo link or run locally
2. Enter your VirusTotal API key (free tier supported)
3. Upload a `.txt` file containing IP addresses (one per line)
4. Click **Initiate Scan**
5. Review the threat overview and detailed results
6. Download the CSV for reporting or further analysis

---

## ▶️ Run Locally

```bash
git clone this repo
cd your-repo-name
pip install -r requirements.txt
streamlit run app.py
