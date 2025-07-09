import streamlit as st
import time
import sys

st.set_page_config(
    page_title="Forensic Tool",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# === Hide sidebar, toolbar, and footer ===
hide_all = """
    <style>
        /* Hide the sidebar completely */
        [data-testid="stSidebar"] {
            display: none;
        }

        /* Hide the sidebar nav label (e.g., "launch") */
        section[data-testid="stSidebarNav"] {
            display: none;
        }

        /* Hide the top-right toolbar */
        [data-testid="stToolbar"] {
            display: none;
        }

        /* Hide footer ("Made with Streamlit") */
        footer {
            visibility: hidden;
        }

        /* Optional: hide fullscreen expanding button */
        [data-testid="stFullscreenButton"] {
            display: none;
        }
    </style>
"""
st.markdown(hide_all, unsafe_allow_html=True)
st.sidebar.markdown(f"🐍 Python used: `{sys.executable}`")
# === Splash screen logic ===
if "splash_shown" not in st.session_state:
    st.session_state.splash_shown = True

    st.markdown("""
        <div style='text-align: center; padding-top: 100px;'>
            <h1>Welcome to <span style='color:#1f77b4;'>FORANDROID</span></h1>
            <h2 style='margin-top: -10px;'>A Tool for Android Leak Detection</h2>
            <p style='color:lightblue;'>Loading modules...</p>
        </div>
    """, unsafe_allow_html=True)

    # Simulated loading animation
    progress_bar = st.progress(0)
    status_text = st.empty()
    for i in range(100):
        progress_bar.progress(i + 1)
        time.sleep(0.03)

    # Redirect to main app page
    st.switch_page("pages/case_creation.py")

else:
    st.switch_page("pages/case_creation.py")


