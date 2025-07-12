import streamlit as st
import pandas as pd
import os
import joblib
import subprocess
import altair as alt
import json
from model_func.ensure_model_feature import ensure_model_features 

st.markdown("""
    <div style='text-align: center; padding: 10px 0 5px 0;'>
        <h1>🚨 Suspicious IP Detection 🚨</h1>
    </div>
""", unsafe_allow_html=True)
st.markdown("---")
# === Load paths ===
case_path = st.session_state.get("resolved_case_path", "")
if not case_path:
    st.error(" Case path missing. Please resolve domains first.")
    st.stop()

log_file = os.path.join(case_path, "resolved_dns_log.csv")
if not os.path.exists(log_file):
    st.error(f"Could not find log file at {log_file}")
    st.stop()
    
#file detals
case_name = os.path.basename(case_path)
st.subheader(f"Case Name: `{case_name}`")
st.write(f"Case Path: `{case_path}`")

# MODEL
if st.button("Start Processing"):
 with st.spinner("Scanning for suspicious activity..."):
  global_model_dir = r"D:\Projects\android-leak-tool\my_android_logs\models"
  model_path = os.path.join(global_model_dir, "suspicious_model.pkl")
  scaler_path = os.path.join(global_model_dir, "scaler.pkl")
  feature_list_path = os.path.join(global_model_dir, "feature_list.json")

  try:
    model = joblib.load(model_path)
    scaler = joblib.load(scaler_path)
  except Exception as e:
    st.error(f"❌ Could not load model or scaler from 'models' folder:\n{e}")
    st.stop()

  # Load and preprocess log file
  df = pd.read_csv(log_file)

  #Time-based feature engineering (before feature alignment)
  if 'timestamp' in df.columns:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    df['dayofweek'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = (df['dayofweek'] >= 5).astype(int)
    df['flag_odd_hour'] = df['hour'].apply(lambda h: h < 5 or h > 23 if pd.notnull(h) else 0)

  # Align features with model
  df = ensure_model_features(df, feature_list_path)
  with open(feature_list_path, "r") as f:
    expected_features = json.load(f)

  # Extract features for model prediction
  X = df[expected_features].fillna(0)
  X_scaled = scaler.transform(X)

  
  df['predicted_suspicious'] = model.predict(X_scaled)
  df['suspicion_probability'] = model.predict_proba(X_scaled)[:, 1]

  flagged_df = df[df['predicted_suspicious'] == 1]
  flagged_path = os.path.join(case_path, "ml_flagged_suspicious.csv")
  flagged_df.to_csv(flagged_path, index=False)

    # Rank IPs
  agg_dict = {'suspicion_probability': 'max' }
  if 'timestamp' in flagged_df.columns:
        agg_dict['timestamp'] = 'min'
  if 'domain' in flagged_df.columns:
    agg_dict['domain'] = lambda x: list(set(x))

  ranked = flagged_df.groupby('ip', as_index=False).agg(agg_dict)
  ranked['event_count'] = flagged_df.groupby('ip').size().values

  def risk_level(score):
        if score >= 0.9:
            return "High"
        elif score >= 0.7:
            return "Medium"
        else:
            return "Low"

  ranked['risk_level'] = ranked['suspicion_probability'].apply(risk_level)

  ranked_path = os.path.join(case_path, "ranked_suspicious_ips.csv")
  ranked.to_csv(ranked_path, index=False)

    # Append data to global training file
  global_data_path = os.path.join(global_model_dir, "global_training_data.csv")
  df_training = df[expected_features].copy()
  df_training['is_suspicious'] = df['predicted_suspicious']

  df_training.to_csv(
        global_data_path,
        mode='a',
        index=False,
        header=not os.path.exists(global_data_path)
    )
    # st.success("✅ Case data appended to global training set.")            for my reference
 
    # === Display Output ===
  st.success(f"{len(flagged_df)} suspicious IPs flagged.")
  st.subheader("📊 Top Ranked Suspicious IPs")
  st.dataframe(ranked.sort_values(by="suspicion_probability", ascending=False).head(10))
  with st.expander("📁 View full file location for ranked suspicious IPs"):
      st.code(ranked_path, language='text')

  st.subheader("📈 Risk Level Distribution")
  ranked_full = pd.read_csv(ranked_path)  
  risk_counts = ranked_full['risk_level'].value_counts().reindex(["High", "Medium", "Low"]).fillna(0).reset_index() 
  risk_counts.columns = ['Risk Level', 'Count']
  chart = alt.Chart(risk_counts).mark_bar(size=40).encode(
             x=alt.X('Risk Level:N', sort=['High', 'Medium', 'Low'], axis=alt.Axis(labelAngle=0)),
             y='Count:Q',
             color=alt.Color('Risk Level:N', scale=alt.Scale(domain=["High", "Medium", "Low"], range=["red", "orange", "green"]))
            ).properties(
            title="📊 Distribution of Risk Levels Across All Suspicious IPs"
            )

  st.altair_chart(chart, use_container_width=True)



# === Retrain Global Model Button ===
st.markdown("---")
st.subheader("Retrain Global AI Model")
retrain_script = os.path.abspath("retrain_global_model.py")

if st.button("Retrain Global Model"):
    with st.spinner("Updating global model..."):
        try:
            result = subprocess.run(
                ["python", retrain_script],
                capture_output=True, text=True, check=True
            )
            st.success("Global model retrained successfully.")
            st.code(result.stdout)
        except subprocess.CalledProcessError as e:
            st.error(" Failed to retrain model.")
            st.code(e.stderr)

# === Back Button ===
if st.button("⬅️ Back to Case View"):
    st.switch_page("pages/case_creation.py")
