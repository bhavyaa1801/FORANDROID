import pandas as pd
import os
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
import joblib
import json
from model_func.ensure_model_feature import ensure_model_features 

# === User Input - Case Folder ===
base_path = r"D:\Projects\android-leak-tool\my_android_logs\CASE_FILES_raw_logs"
case_name = input("📂 Enter the case folder name: ")
case_folder = os.path.join(base_path, case_name)
log_file = os.path.join(case_folder, "resolved_dns_log.csv")

if not os.path.exists(log_file):
    raise FileNotFoundError(f"❌ Log file not found at: {log_file}")

print(f"✅ Using log file: {log_file}")

# === Load the Log Data ===
df = pd.read_csv(log_file)

# === Timestamp-Based Features ===
if 'timestamp' in df.columns:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    df['dayofweek'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = (df['dayofweek'] >= 5).astype(int)
    df['flag_odd_hour'] = df['hour'].apply(lambda h: h < 5 or h > 23 if pd.notnull(h) else 0)
    print("⏱️ Timestamp-based features enabled.")
else:
    print("⚠️ No 'timestamp' column found — skipping time-based features.")

#load model features
model_dir= r"D:\Projects\android-leak-tool\my_android_logs\models"
feature_list_path = os.path.join(model_dir , "feature_list.json")
with open(feature_list_path ,"r") as f:
    features = json.load(f)

#align column
df = ensure_model_features(df, feature_list_path)

# Ensure 'is_suspicious' column exists
if 'is_suspicious' not in df.columns:
    if 'ip' in df.columns and df['ip'].notna().any():
        master_list_path = os.path.join(case_folder, "master_list.csv")
        if os.path.exists(master_list_path):
            master_df = pd.read_csv(master_list_path)
            master_ips = set(master_df["ip"].dropna())
            print(f"✅ Loaded master IP list with {len(master_ips)} entries.")
        else:
            master_ips = set()
            print("⚠️ No master list found — assuming empty list.")

        df["is_suspicious"] = df["ip"].apply(lambda ip: ip in master_ips if pd.notna(ip) else False)
        print("✅ 'is_suspicious' column created based on master list.")
    else:
        print("⚠️ No IPs found — creating dummy 'is_suspicious' column (all 0).")
        df["is_suspicious"] = 0

y = df['is_suspicious'].astype(int)

# scale the features
X = df[features].fillna(0)                 ##
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# train test split
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.3, random_state=42
)

# train rf
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# evaluate
y_pred = model.predict(X_test)
print("📊 Classification Report:")
print(classification_report(y_test, y_pred))

# predict all logs
df['predicted_suspicious'] = model.predict(X_scaled)
df['suspicion_probability'] = model.predict_proba(X_scaled)[:, 1]

# Export Flagged Entries to Case Folder 
flagged_output = os.path.join(case_folder, "ml_flagged_suspicious.csv")
df[df['predicted_suspicious'] == 1].to_csv(flagged_output, index=False)
print(f"📁 Saved flagged logs → {flagged_output}")

# === Save Model and Scaler to Case Folder ===
model_path = os.path.join(case_folder, "suspicious_model.pkl")
scaler_path = os.path.join(case_folder, "scaler.pkl")
joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)
print(f"📁 Model saved at → {model_path}")
print(f"📁 Scaler saved at → {scaler_path}")

# === Rank IPs by Risk (and Timestamp if available) ===
suspicious_df = df[df['predicted_suspicious'] == 1]
agg_dict = {'suspicion_probability': 'max'}
if 'timestamp' in df.columns:
    agg_dict['timestamp'] = 'min'

ip_risk_scores = suspicious_df.groupby('ip').agg(agg_dict).reset_index()

def risk_level(score):
    if score >= 0.9:
        return "High"
    elif score >= 0.7:
        return "Medium"
    else:
        return "Low"

ip_risk_scores["risk_level"] = ip_risk_scores["suspicion_probability"].apply(risk_level)

ranked_ip_path = os.path.join(case_folder, "ranked_suspicious_ips.csv")
ip_risk_scores.to_csv(ranked_ip_path, index=False)
print(f"📁 Ranked suspicious IPs saved → {ranked_ip_path}")
print("🔝 Top 10 Most Suspicious IPs:")
print(ip_risk_scores.head(10))

# === Append to Global Training Data ===
global_data_path = r"D:\Projects\android-leak-tool\my_android_logs\models\global_training_data.csv"
case_training_data = df[features + ['is_suspicious']].copy()
case_training_data.to_csv(global_data_path, mode='a', index=False, header=not os.path.exists(global_data_path))
print(f"📁 Appended case training data to → {global_data_path}")
