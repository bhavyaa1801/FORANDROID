import streamlit as st
import os
import re
import pandas as pd


def sanitize_key(name):
    return re.sub(r"\W|^(?=\d)", "_", name)

#title
st.markdown("""
    <div style='text-align: center; padding: 10px 0 20px 0;'>
        <h1>📂 View Existing Files 📂</h1>
        <h4 style='margin-top: -10px; color:#1f77b4;'>...& Create Personalised Reports...</h4>
    </div>
""", unsafe_allow_html=True)
st.markdown("---")

if "case_path" not in st.session_state:
    st.warning("Please create or load a case first.")
    st.stop()

case_path = st.session_state.case_path
case_name = os.path.basename(case_path)
st.markdown(f"### Case Name - `{case_name}`")
st.markdown(f"**Case Path:** `{case_path}`")

files =[
    f for f in os.listdir(case_path)
    if os.path.isfile(os.path.join(case_path , f)) and f.lower().endswith((".csv", ".xlsx", ".txt"))
]

if not files:
    st.info("No supported files (.csv, .xlsx, .txt) found.")
else:
    st.markdown("### 📂 Case Files:")
    for file_name in files:
        file_path = os.path.join(case_path , file_name)
        safe_key = sanitize_key(file_name)
        df_key =f"df_{safe_key}"

        if df_key not in st.session_state:
            try:
                if file_name.lower().endswith(".csv"):
                    st.session_state[df_key] = pd.read_csv(file_path)
                elif file_name.lower().endswith(".xlsx"):
                    st.session_state[df_key] = pd.read_excel(file_path)
                elif file_name.lower().endswith(".txt"):
                    continue  

            except Exception as e:
                st.error(f"Couldn't load `{file_name}` : {e}")
                st.session_state[df_key] = None

        df = st.session_state[df_key]
        
        with st.expander(f"📄 {file_name}"):
            if df is not None and isinstance(df, pd.DataFrame):
                st.markdown("#### 🧾 Customize & Export Report")
                columns = df.columns.tolist()
                selected_key = f"columns_{safe_key}"
                filename_key = f"filename_input_{safe_key}"

                previous_selection = st.session_state.get(selected_key, columns)
                valid_selection = [col for col in previous_selection if col in columns]

                selected_columns = st.multiselect(
                    "select columns to include: ",
                     options=columns,
                     default=valid_selection,
                     key=selected_key
                )

                filtered_columns = [col for col in selected_columns if col in df.columns]

                if filtered_columns:
                    try:
                        filtered_df = df[filtered_columns]
                        st.dataframe(filtered_df , use_container_width=True)

                        output_name = st.text_input(
                            "Enter output filename (no extension)",
                            value=f"{safe_key}_filtered",
                            key=filename_key
                        ).strip() or "filtered_report"

                        csv_data = filtered_df.to_csv(index=False).encode("utf-8")

                        st.download_button(
                            label="📥 DOWNLOAD CSV",
                            data=csv_data,
                            file_name=f"{output_name}.csv",
                            mime="text/csv",
                            key=f"download_{safe_key}"
                        )

                        if st.button(f"💾 SAVE TO CASE FOLDER", key=f"save_{safe_key}"):
                            save_path = os.path.join(case_path, f"{output_name}.csv")
                            with open(save_path , "wb") as f:
                                f.write(csv_data)
                            st.success(f"Saved as: `{output_name}.csv` in case folder.")

                    except Exception as e:
                         st.error(f"❌ Export failed: {e}")
                else:
                    st.warning("⚠️ Please select at least one valid column.")
# Back Button 
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py") 
