import pandas as pd
from pathlib import Path

def build_timeline(case_folder_path: str) -> pd.DataFrame:
    """
    Constructs a timeline DataFrame by parsing various logs in the given case folder.
    Returns a valid (possibly empty) DataFrame with expected columns.
    """
    case_path = Path(case_folder_path)
    events = []

    # DNS Log Parsing
    dns_path = case_path / "resolved_dns_log.csv"
    if dns_path.exists():
        try:
            dns_df = pd.read_csv(dns_path)
            if not dns_df.empty and "timestamp" in dns_df.columns:
                for _, row in dns_df.iterrows():
                    events.append({
                        "Timestamp": row.get("timestamp", ""),
                        "Event Type": "DNS Resolution",
                        "App/Process": row.get("app_name", "Unknown"),
                        "Domain/IP": row.get("domain", ""),
                        "Description": f"Resolved {row.get('domain', '')} → {row.get('ip', '')}"
                    })
        except Exception as e:
            print(f"[!] Error reading DNS log: {e}")

    # Suspicious IPs Parsing
    ip_path = case_path / "ranked_suspicious_ips.csv"
    if ip_path.exists():
        try:
            ip_df = pd.read_csv(ip_path)
            if not ip_df.empty and "timestamp" in ip_df.columns:
                for _, row in ip_df.iterrows():
                    events.append({
                        "Timestamp": row.get("timestamp", ""),
                        "Event Type": "Suspicious Communication",
                        "App/Process": row.get("app_name", "Unknown"),
                        "Domain/IP": row.get("ip", ""),
                        "Description": f"Flagged IP {row.get('ip')} (Risk: {row.get('risk_score')})"
                    })
        except Exception as e:
            print(f"[!] Error reading suspicious IP log: {e}")

    # App Logs
    log_path = case_path / "app_logcat.csv"
    if log_path.exists():
        try:
            app_df = pd.read_csv(log_path)
            if not app_df.empty and "timestamp" in app_df.columns:
                for _, row in app_df.iterrows():
                    events.append({
                        "Timestamp": row.get("timestamp", ""),
                        "Event Type": "App Event",
                        "App/Process": row.get("package", "Unknown"),
                        "Domain/IP": "-",
                        "Description": row.get("message", "App log entry")
                    })
        except Exception as e:
            print(f"[!] Error reading app log: {e}")

    # Final Timeline Construction
    df = pd.DataFrame(events)

    expected_cols = ["Timestamp", "Event Type", "App/Process", "Domain/IP", "Description"]
    for col in expected_cols:
        if col not in df.columns:
            df[col] = ""

    if not df.empty:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df.dropna(subset=["Timestamp"], inplace=True)
        df.sort_values(by="Timestamp", inplace=True)

    return df[expected_cols]