import streamlit as st
import requests
import time
import pandas as pd
from io import StringIO

# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="Threat Intelligence Dashboard",
    page_icon="🛡️",
    layout="wide"
)

# ---------------- SIDEBAR ----------------
with st.sidebar:
    st.markdown("## SOC Console")
    st.caption("Threat Intelligence Dashboard")

    st.divider()

    api_key = st.text_input(
        "VirusTotal API Key",
        type="password"
    )

    st.info("Free API: 4 requests/minute")

    st.divider()
    st.caption("Module: IP Reputation Analysis")

# ---------------- DASHBOARD HEADER ----------------
st.markdown("# Threat Intelligence Dashboard")
st.caption("VirusTotal IP Reputation · SOC View")

st.divider()

# ---------------- SCAN PANEL ----------------
with st.container():
    st.markdown("### IP Reputation Scan")

    col1, col2 = st.columns([3, 1])

    with col1:
        uploaded_file = st.file_uploader(
            "Upload IP list (.txt – one IP per line)",
            type=["txt"]
        )

    with col2:
        start_scan = st.button(
            "Initiate Scan",
            use_container_width=True
        )

# ---------------- MAIN LOGIC ----------------
if uploaded_file and api_key and start_scan:

    stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
    ips = [line.strip() for line in stringio.readlines() if line.strip()]

    st.divider()
    st.markdown("### ⚙️ Scan Progress")

    progress_bar = st.progress(0)
    status_text = st.empty()

    results = []

    for index, ip in enumerate(ips):
        status_text.info(f"Analyzing **{ip}** ({index + 1}/{len(ips)})")

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": api_key}

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                stats = data["data"]["attributes"]["last_analysis_stats"]
                country = data["data"]["attributes"].get("country", "Unknown")

                results.append({
                    "IP Address": ip,
                    "Malicious": stats["malicious"],
                    "Suspicious": stats["suspicious"],
                    "Harmless": stats["harmless"],
                    "Country": country,
                    "Status": "Completed"
                })

            elif response.status_code == 429:
                st.warning("Rate limit hit. Waiting 60 seconds...")
                time.sleep(60)

            else:
                results.append({
                    "IP Address": ip,
                    "Status": f"Error {response.status_code}"
                })

        except Exception:
            results.append({
                "IP Address": ip,
                "Status": "Connection Error"
            })

        progress_bar.progress((index + 1) / len(ips))

        if index < len(ips) - 1:
            time.sleep(15)

    # ---------------- RESULTS DASHBOARD ----------------
    st.success("Scan Completed")

    df = pd.DataFrame(results)

    # ---------------- KPI METRICS ----------------
    st.divider()
    st.markdown("### Threat Overview")

    total = len(df)
    malicious = df["Malicious"].gt(0).sum()
    suspicious = df["Suspicious"].gt(0).sum()
    clean = total - malicious - suspicious

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Total IPs", total)
    k2.metric("Malicious", malicious)
    k3.metric("Suspicious", suspicious)
    k4.metric("Clean", clean)

    # ---------------- RESULTS TABLE ----------------
    st.divider()
    st.markdown("###  Detailed IP Analysis")

    st.dataframe(
        df,
        use_container_width=True
    )

    # ---------------- DOWNLOAD ----------------
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download CSV",
        csv,
        "ip_reputation_results.csv",
        "text/csv"
    )
