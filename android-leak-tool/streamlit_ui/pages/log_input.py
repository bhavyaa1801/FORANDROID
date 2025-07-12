import streamlit as st
import os
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

st.set_page_config(page_title="Log Input", layout="centered")

st.markdown("""
    <div style='text-align: center; padding: 10px 0 20px 0;'>
        <h1>Add Logs to Case</h1>
    </div>
""", unsafe_allow_html=True)
st.markdown("------")

if "case_path" not in st.session_state:
    st.warning("Please create or load a case first.")
    st.stop()

case_path = st.session_state.case_path
case_name = os.path.basename(case_path)
st.markdown(f"### Case Name - `{case_name}`")
st.markdown(f"**Case Path:** `{case_path}`")

st.subheader("Choose Log Input Method")

input_method = st.radio(
    "How do you want to add logs?",
    options=["Extract from Android phone", "Upload log files manually"]
)

# Manual Upload
if input_method == "Upload log files manually":
    uploaded_files = st.file_uploader(
        "Upload log files or data sheets",
        type=["txt", "log", "json", "csv", "xlsx"],
        accept_multiple_files=True
    )

    if uploaded_files:
        st.success(f"{len(uploaded_files)} file(s) uploaded.")
        for uploaded_file in uploaded_files:
            file_path = os.path.join(st.session_state.case_path, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
        st.info("Files saved to case folder.")

        col1, col2, col3 = st.columns([6, 1, 2])
        with col3:
                if st.button("NEXT"):
                  st.session_state.move_to_parse = True
                  if st.session_state.get("move_to_parse"):
                    st.switch_page("pages/parse_logs.py")


# ADB Extraction 
elif input_method == "Extract from Android phone":
    with st.expander("MAKE SURE TO FOLLOW THESE STEPS"):
        st.write("""
        1. Enable **Developer Options** on your device.
        2. Enable **USB Debugging**.
        3. Connect your phone via USB and **allow ADB authorization** when prompted.
        """)

    if st.button("📱 Extract Logs"):
        try:
            with st.spinner("Extracting logs from connected device..."):
                from extract_logs import extract_from_phone  
                extract_from_phone(st.session_state.case_path)

            st.success("Logs extracted and saved successfully.")

            # Display extracted files
            extracted_files = [
                f for f in os.listdir(st.session_state.case_path)
                if f.endswith(".txt")
            ]

            if extracted_files:
                st.markdown("### 📄Extracted Files:")
                st.write(""" Paste the above path in your file manager to access the files
                                      OR 
                             Open your case folder    
                         """)
                for f in extracted_files:
                    st.markdown(f"• `{f}`")
            else:
                st.info("No .txt log files found.")


            col1, col2, col3 = st.columns([6, 1, 2])
            with col3:
                if st.button("NEXT"):
                  st.session_state.move_to_parse = True
            if st.session_state.get("move_to_parse"):
                  st.switch_page("pages/parse_logs.py")  

        except Exception as e:
            st.error(f"Failed to extract logs: {e}")

# Back Button 
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py")