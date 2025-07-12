import streamlit as st
import pandas as pd
import altair as alt
from pathlib import Path
import tempfile
import os
from datetime import time
import sys

#filter by hours func
def get_time_range(preset):
    if preset == "Office Hours (9AM-6PM)":
        return time(9, 0), time(18, 0)
    elif preset == "Night Activity (10PM-6AM)":
        return time(22, 0), time(6, 0)
    elif preset == "Early Morning (4AM-9AM)":
        return time(4, 0), time(9, 0)
    else:
        return time(0, 0), time(23, 59)

# Load builder
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from model_func.timeline_builder import build_timeline

st.set_page_config(page_title="Timeline Viewer", layout="wide")
st.title("📊 Timeline Viewer – Chronological Activity Analysis")

# Route from session
if "trigger_parse" not in st.session_state:
    st.warning("⚠️ No timeline trigger found. Go back and select/upload case.")
    st.stop()

use_uploaded = st.session_state.get("upload_mode", False)

# Existing case
if not use_uploaded:
    case_path = Path(st.session_state.get("case_path", ""))
    if not case_path.exists():
        st.error("Selected case folder does not exist.")
        st.stop()

    with st.spinner("Parsing selected case..."):
        df = build_timeline(str(case_path))
        timeline_file = case_path / "timeline.csv"
        st.success("✅ Timeline generated for case: " + case_path.name)

# Uploaded files
else:
    temp_dir = tempfile.TemporaryDirectory()
    temp_path = Path(temp_dir.name)

    def save_uploaded(name, file):
     if file is None:
        return
     try:
        df = pd.read_excel(file) if file.name.endswith(".xlsx") else pd.read_csv(file)
        if df.empty or df.columns.size == 0:
            st.warning(f"⚠️ Uploaded file '{file.name}' is empty or has no valid columns.")
            return
        df.to_csv(temp_path / name, index=False)
     except pd.errors.EmptyDataError:
        st.warning(f"Uploaded file '{file.name}' is completely empty or unparseable.")
        return
     except Exception as e:
        st.warning(f"Error while reading uploaded file '{file.name}': {e}")
        return


    save_uploaded("resolved_dns_log.csv", st.session_state.uploaded_dns)
    save_uploaded("ranked_suspicious_ips.csv", st.session_state.uploaded_ips)
    save_uploaded("app_logcat.csv", st.session_state.uploaded_logs)

    with st.spinner("Parsing uploaded files..."):
        df = build_timeline(str(temp_path))
        st.success("✅ Timeline generated from uploaded files")

# Show timeline
if df.empty or "Timestamp" not in df.columns:
    st.dataframe(df)
    if st.button("⬅️ Back to Case View"):
     st.switch_page("pages/case_creation.py") 
    st.stop()

df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
df.dropna(subset=["Timestamp"], inplace=True)


if df.empty:
    st.warning("No timeline events found.")
else:
    st.subheader("🕒 Event Table")

    # Time range filter UI
    time_filter = st.selectbox(
        "Select Time Range",
        options=["All Time", "Office Hours (9AM-6PM)", "Night Activity (10PM-6AM)", "Early Morning (4AM-9AM)"],
        index=0
    )

    # Apply time filter
    if time_filter != "All Time":
        start_time, end_time = get_time_range(time_filter)
        df["event_time"] = df["Timestamp"].dt.time

        if start_time < end_time:
            df = df[
                (df["event_time"] >= start_time) &
                (df["event_time"] <= end_time)
            ]
        else:
            df = df[
                (df["event_time"] >= start_time) |
                (df["event_time"] <= end_time)
            ]

        df = df.drop(columns=["event_time"])  

    if df.empty:
        st.warning("No events match this time filter.")
        st.stop()
    else:
        st.dataframe(df)
        custom_filename = st.text_input("Enter filename for download (without .csv)" , value = "timeline")
        st.download_button(
           label="⬇️ Download CSV",
           data=df.to_csv(index=False),
           file_name=f"{custom_filename.strip() or 'timeline'}.csv",
           mime="text/csv"
       )

        # Prepare vertical position
        df = df.sort_values("Timestamp").reset_index(drop=True)
        df["y_pos"] = range(len(df))

        # Altair Chart
        timeline_chart = alt.Chart(df).mark_circle(size=100).encode(
            x=alt.X("Timestamp:T", title="Time"),
            y=alt.Y("y_pos:O", axis=None),
            color=alt.Color("Event Type:N", legend=alt.Legend(title="Event Type")),
            tooltip=[
                alt.Tooltip("Timestamp:T", title="Time"),
                alt.Tooltip("App/Process:N", title="App"),
                alt.Tooltip("Domain/IP:N", title="Domain or IP"),
                alt.Tooltip("Description:N", title="Details")
            ]
        ).properties(
            width=900,
            height=600,
            title="📊 Android Activity Timeline"
        ).interactive()

        st.altair_chart(timeline_chart, use_container_width=True)



# Back Button 
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py") 