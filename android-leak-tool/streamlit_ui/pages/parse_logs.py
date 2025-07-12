import streamlit as st
import os
import sys
import socket
import pandas as pd

# Add parser path
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..", "..")))
from parsers.parse_log import parse_log_file

st.set_page_config(page_title="Parse logs", layout="centered")
st.title("EXTRACT AND RESOLVE IP's")

with st.expander("INSTRUCTIONS"):
    st.markdown("""<center> 
        PARSE - WILL EXTRACT USEFUL INFOMATION FROM RAW LOGS
        <br>
        Enter your <span style='color:red; font-weight:bold;'>raw data extracted</span> from device (.txt files)                                                                               
        <br> <b>OR</b> <br>
        Input <span style='color:red; font-weight:bold;'>RAW DNS logs</span> to extract useful info (.csv or .xlsx files)
        <br>
        RESOLVE IP - uses domian to fetch IPs for futher investigation      
        </center>
    """, unsafe_allow_html=True)

# === Load case path ===
case_path = st.session_state.get("case_path", "")
case_name = os.path.basename(case_path)

if not case_path:
    st.error("No case path found. Please extract logs first.")
    st.stop()

st.markdown(f"### Case Name - `{case_name}`")

# === Show available log files ===
log_files = [f for f in os.listdir(case_path) if f.endswith((".txt", ".xlsx", ".csv"))]
selected_file = st.selectbox("Choose a log file to parse", log_files)

# === Parse button ===
if st.button("Parse"):
    full_path = os.path.join(case_path, selected_file)
    df = parse_log_file(full_path)
    st.session_state["parsed_df"] = df
    st.session_state["case_path"] = case_path  # Persist case_path

    st.success(f"Parsed {len(df)} entries.")
    st.dataframe(df[["timestamp", "pid", "domain", "record_class", "class_method", "ip", "message"]
                    if "message" in df.columns else df.columns.tolist()])

# === Resolve IPs button ===
if "parsed_df" in st.session_state:
    if st.button("Resolve IP Domains"):
        df = st.session_state["parsed_df"]

        # Spinner while resolving
        with st.spinner("Resolving domains to IPs..."):
            def resolve_domain(domain):
                try:
                    return socket.gethostbyname(domain)
                except Exception:
                    return None

            df["ip"] = df["domain"].apply(lambda d: resolve_domain(d) if pd.notna(d) else None)

            resolved_count = df["ip"].notna().sum()

            if resolved_count == 0:
                st.warning("⚠️ No IPs were resolved from the domains.")
            else:
                st.success(f"{resolved_count} IPs resolved. File saved as **resolved_dns_log.csv**")

                # Ensure required columns
                for col in ["timestamp", "domain", "record_class", "ip", "pid"]:
                    if col not in df.columns:
                        df[col] = None

                output_df = df[["timestamp", "domain", "record_class", "ip", "pid"]]
                output_df = output_df.sort_values(by="ip", ascending=False, na_position="last")

                resolved_path = os.path.join(case_path, "resolved_dns_log.csv")
                output_df.to_csv(resolved_path, index=False)

                st.success(f"**Open the location of file using this path :**  `{resolved_path}`")
                st.subheader("Resolved Domain → IP Table")
                st.dataframe(output_df)

                st.info(" USE resolved_dns_log.csv to flag suspicious IPs")
    
# Back Button 
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py")               
