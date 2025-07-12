import os
import pandas as pd
import json
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from model_func.ensure_model_feature import ensure_model_features 

# === PATHS ===
model_dir = r"D:\Projects\android-leak-tool\my_android_logs\models"
global_dataset_path = os.path.join(model_dir, "global_training_data.csv")
model_path = os.path.join(model_dir, "suspicious_model.pkl")
scaler_path = os.path.join(model_dir, "scaler.pkl")
feature_list_path = os.path.join(model_dir,"feature_list.json")

#checking if global dataset exist or not
if not os.path.exists(global_dataset_path):
    raise FileNotFoundError(f"❌ Global training dataset not found at: {global_dataset_path}")

df = pd.read_csv(global_dataset_path)
if "is_suspicious" not in df.columns:
    raise ValueError("⚠️ 'is_suspicious' column not found. This column is required for training.")

print(f"Loaded global training data with {len(df)} rows.")

#timestampa based features
if 'timestamp' in df.columns:
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df['hour'] = df['timestamp'].dt.hour
    df['dayofweek'] = df['timestamp'].dt.dayofweek
    df['is_weekend'] = (df['dayofweek'] >= 5).astype(int)
    df['flag_odd_hour'] = df['hour'].apply(lambda h: h < 5 or h > 23 if pd.notnull(h) else 0)

# defing them
features = [
    'flag_uncommon_tld', 'domain_count', 'ip_count',
    'flag_foreign_ip', 'abuse_score', 'hour',
    'dayofweek', 'is_weekend', 'flag_odd_hour'
]

#aligning them using func
with open(feature_list_path, "w") as f:
    json.dump(features ,f)

df = ensure_model_features(df, feature_list_path)

#train 
X = df[features].fillna(0)
y = df["is_suspicious"].astype(int)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.25, random_state=42)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === Step 4: Evaluation ===
y_pred = model.predict(X_test)
print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred))

# === Step 5: Save Model and Scaler ===
joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)
print(f"\n✅ Model saved to → {model_path}")
print(f"✅ Scaler saved to → {scaler_path}")
