import streamlit as st
import requests
import time
import pandas as pd
from io import StringIO

# Page Config
st.set_page_config(page_title="VT Bulk IP Checker", page_icon="🛡️")

st.title("🛡️ Team IP Reputation Checker")
st.markdown("Upload a list of IPs to check them against the VirusTotal database.")

# --- SIDEBAR CONFIG ---
with st.sidebar:
    st.header("Settings")
    api_key = st.text_input("Enter VirusTotal API Key", type="password")
    st.info("Note: Free API keys are limited to 4 requests per minute.")

# --- FILE UPLOAD ---
uploaded_file = st.file_uploader("Upload ips.txt (one IP per line)", type=['txt'])

if uploaded_file and api_key:
    # Read IPs from file
    stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
    ips = [line.strip() for line in stringio.readlines() if line.strip()]
    
    if st.button("Start Analysis"):
        results = []
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        for index, ip in enumerate(ips):
            # Update Status
            status_text.text(f"Checking {ip} ({index + 1}/{len(ips)})...")
            
            # --- VIRUSTOTAL LOGIC ---
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": api_key}
            
            try:
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data['data']['attributes']['last_analysis_stats']
                    country = data['data']['attributes'].get('country', 'Unknown')
                    
                    results.append({
                        "IP Address": ip,
                        "Malicious": stats['malicious'],
                        "Suspicious": stats['suspicious'],
                        "Harmless": stats['harmless'],
                        "Country": country,
                        "Status": "✅ Success"
                    })
                elif response.status_code == 429:
                    st.warning("Rate limit hit! Waiting 60 seconds...")
                    time.sleep(60)
                    # Simple retry logic could be added here
                else:
                    results.append({"IP Address": ip, "Status": f"❌ Error {response.status_code}"})
            
            except Exception as e:
                results.append({"IP Address": ip, "Status": f"⚠️ Connection Error"})

            # Update Progress
            progress_bar.progress((index + 1) / len(ips))

            # --- RATE LIMIT HANDLING ---
            if index < len(ips) - 1:  # Don't sleep after the last IP
                countdown = st.empty()
                for i in range(15, 0, -1):
                    countdown.text(f"Next request in {i} seconds (VT Free Tier Limit)...")
                    time.sleep(1)
                countdown.empty()

        # --- DISPLAY RESULTS ---
        st.success("Analysis Complete!")
        df = pd.DataFrame(results)
        
        # Highlight malicious IPs in red
        def highlight_malicious(val):
            color = 'red' if isinstance(val, int) and val > 0 else 'white'
            return f'color: {color}'

        st.dataframe(df)
        
        # Download Button
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Results as CSV",
            data=csv,
            file_name='vt_results.csv',
            mime='text/csv',
        )
