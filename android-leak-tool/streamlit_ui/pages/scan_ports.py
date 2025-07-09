import streamlit as st
import os
import pandas as pd
from model_func.nmap_scanner import scan_ips_from_file

st.set_page_config(page_title="Port Scan", layout="wide")

st.markdown("""
    <div style='text-align: center; padding: 10px 0 20px 0;'>
        <h1>🛡️ Port Scan for Suspicious IPs</h1>
    </div>
""", unsafe_allow_html=True)
st.markdown("-----")

#display case info

if "case_path" not in st.session_state:
    st.error("Please load a case first.")
    st.stop()

case_path = st.session_state.case_path
case_name = os.path.basename(case_path)
st.markdown(f"### Case Name - `{case_name}`")
st.markdown(f"**Case Path:** `{case_path}`")

# i/o file
ip_input_file = os.path.join(case_path, f"{case_name}_IP_FINAL_REPORT.csv")
output_csv = os.path.join(case_path, f"{case_name}_PORT_SCAN.csv")

#sus file
st.markdown(f"**Suspicious IP file:** `{os.path.basename(ip_input_file)}`")

if not os.path.exists(ip_input_file):
    st.warning("Suspicious IP file not found. Make sure the IP report exists.")
    st.stop()

if "port_scan_df" not in st.session_state:
    st.session_state.port_scan_df = None
if "port_scan_msg" not in st.session_state:
    st.session_state.port_scan_msg = ""

if st.button("🚀 Run Port Scan"):
    with st.spinner("Scanning all suspicious IPs...processing may take longer than usual...😞"):
        cache_file = os.path.join(case_path, "port_scan_cache.json")
        df, msg = scan_ips_from_file(ip_input_file, output_csv)
        if not df.empty:
            st.session_state.port_scan_df = df
            st.session_state.port_scan_msg = msg
        else:
            st.session_state.port_scan_df = None
            st.session_state.port_scan_msg = msg
            
if st.session_state.port_scan_df is not None:
    df = st.session_state.port_scan_df
    msg = st.session_state.port_scan_msg
    st.success(msg)

    st.subheader("Filter Results Before Download")

    cols = st.columns(2)
    with cols[0]:
        tag_options = ["All"] + sorted(df["tag"].dropna().unique())
        tag_filter = st.selectbox("🔍 Filter by Tag", options=tag_options, index=0, key="tag_filter")

    with cols[1]:
        risk_options = ["All"] + sorted(df["risk_level"].dropna().unique())
        risk_filter = st.selectbox("🚨 Filter by Risk Level", options=risk_options, index=0, key="risk_filter")

    filtered_df = df.copy()
    if tag_filter != "All":
        filtered_df = filtered_df[filtered_df["tag"] == tag_filter]
    if risk_filter != "All":
        filtered_df = filtered_df[filtered_df["risk_level"] == risk_filter]

    display_df = filtered_df.rename(columns={
        "ip": "IP",
        "port": "Port",
        "service": "Service",
        "banner": "Banner / Version",
        "risk_level": "Risk Level",
        "threat": "Threat"
    })[["IP", "Port", "Service", "Banner / Version", "Risk Level", "Threat"]]

    if not display_df.empty:
        st.markdown("### 📋 Filtered Scan Results")
        st.dataframe(display_df, use_container_width=True)

        st.download_button(
            "📥 Download Filtered CSV",
            display_df.to_csv(index=False),
            file_name=f"{case_name}_PORT_SCAN_FILTERED.csv"
        )
    else:
        st.info("No results match selected filters.")
elif "port_scan_msg" in st.session_state and st.session_state.port_scan_msg:
    st.info(st.session_state.port_scan_msg)




# Back Button 
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py") 