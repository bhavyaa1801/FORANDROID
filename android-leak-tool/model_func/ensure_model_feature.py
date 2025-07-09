import json
import pandas as pd

def ensure_model_features(df: pd.DataFrame, feature_list_path: str) -> pd.DataFrame:
    """Ensures all expected features from the JSON file exist in the dataframe."""
    with open(feature_list_path, "r") as f:
        expected_features = json.load(f)

    for feat in expected_features:
        if feat not in df.columns:
            df[feat] = 0  

    return df
