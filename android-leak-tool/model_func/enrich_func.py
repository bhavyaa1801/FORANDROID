import pandas as pd
import os 
import json
import requests
from ipwhois import IPWhois
from datetime import datetime, timedelta 

def enrich_suspicious_ips(ip_list, case_folder):
    # Define all paths
    models_dir = r"D:\Projects\android-leak-tool\my_android_logs\models"
    geo_path = os.path.join(case_folder, "geo_cache.json")
    whois_path = os.path.join(case_folder, "whois_cache.json")
    master_geo_path = os.path.join(models_dir, "master_suspicious_geo_cache.json")
    master_whois_path = os.path.join(models_dir, "master_suspicious_whois_cache.json")
    report_path = os.path.join(models_dir, "master_suspicious_ip_report.csv")
    ranked_path = os.path.join(case_folder, "ranked_suspicious_ips.csv")

    # Load all caches
    def safe_load(path):
        if not os.path.exists(path): return {}
        try:
            with open(path, "r") as f:
                return json.load(f)
        except:
            return {}

    geo_map = safe_load(geo_path)
    whois_map = safe_load(whois_path)
    master_geo_map = safe_load(master_geo_path)
    master_whois_map = safe_load(master_whois_path)

    def is_expired(ts, days=365):
        try:
            return datetime.now() - datetime.fromisoformat(ts) > timedelta(days=days)
        except:
            return True

    def geoip_lookup(ip):
        if ip in geo_map and not is_expired(geo_map[ip].get("timestamp", "")):
            return geo_map[ip]
        try:
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5).json()
            result = {
                "lat": r.get("lat"), "lon": r.get("lon"),
                "country": r.get("countryCode", "Unknown")
            }
        except:
            result = {"lat": None, "lon": None, "country": "Unknown"}
        result["timestamp"] = datetime.now().isoformat()
        return result

    def whois_lookup(ip):
        if ip in whois_map and not is_expired(whois_map[ip].get("timestamp", "")):
            return whois_map[ip]
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap()
            info = {
                "asn": res.get("asn"),
                "asn_description": res.get("asn_description"),
                "org_name": res["network"].get("name"),
                "cidr": res["network"].get("cidr"),
                "start_address": res["network"].get("start_address"),
                "end_address": res["network"].get("end_address"),
                "created": str(res["network"].get("created")),
                "updated": str(res["network"].get("updated"))
            }
        except:
            info = {k: None for k in ["asn", "asn_description", "org_name", "cidr", "start_address", "end_address", "created", "updated"]}
        info["timestamp"] = datetime.now().isoformat()
        return info

    # Load ranked IP metadata
    if not os.path.exists(ranked_path):
        raise FileNotFoundError(f"Missing ranked suspicious file at {ranked_path}")
    ranked_df = pd.read_csv(ranked_path)
    ranked_df = ranked_df[ranked_df['ip'].isin(ip_list)]

    existing = set(master_geo_map.keys())
    new_ips = [ip for ip in ip_list if ip not in existing]

    rows = []
    for ip in ip_list:
        if ip in new_ips:
            geo = geoip_lookup(ip)
            whois = whois_lookup(ip)

            matched = ranked_df[ranked_df['ip'] == ip]
            if matched.empty:
                continue

            meta = matched.iloc[0].to_dict()
            original_timestamp = meta.get("timestamp")

            if pd.isna(original_timestamp) or str(original_timestamp).strip().lower() in ("", "nat", "nan"):
                safe_timestamp = None
            else:
                try:
                    parsed_ts = pd.to_datetime(original_timestamp, errors="coerce")
                    safe_timestamp = parsed_ts.isoformat() if pd.notna(parsed_ts) else None
                except:
                    safe_timestamp = None

            geo["timestamp"] = safe_timestamp
            whois["timestamp"] = safe_timestamp

            geo_map[ip] = geo
            whois_map[ip] = whois
            master_geo_map[ip] = geo
            master_whois_map[ip] = whois
        else:
            geo = geo_map.get(ip, {})
            whois = whois_map.get(ip, {})

        # This must run for all IPs
        matched = ranked_df[ranked_df['ip'] == ip]
        if matched.empty:
            continue

        meta = matched.iloc[0].to_dict()

        rows.append({
            "ip": ip,
            "country": geo.get("country"),
            "latitude": geo.get("lat"),
            "longitude": geo.get("lon"),
            "case_name": os.path.basename(case_folder),
            "timestamp": meta.get("timestamp"),
            "risk_level": meta.get("risk_level"),
            "suspicion_probability": meta.get("suspicion_probability"),
            **whois
        })

    if rows:
        enriched_path = os.path.join(case_folder, "suspicious_ip_geo_whois.csv")
        pd.DataFrame(rows).to_csv(enriched_path, index=False)

        if os.path.exists(report_path):
            existing_df = pd.read_csv(report_path)
            combined = pd.concat([existing_df, pd.DataFrame(rows)], ignore_index=True)
            combined.drop_duplicates(subset="ip", keep="last").to_csv(report_path, index=False)
        else:
            pd.DataFrame(rows).to_csv(report_path, index=False)

    # Save updated caches
    with open(geo_path, "w") as f: json.dump(geo_map, f)
    with open(whois_path, "w") as f: json.dump(whois_map, f)
    with open(master_geo_path, "w") as f: json.dump(master_geo_map, f)
    with open(master_whois_path, "w") as f: json.dump(master_whois_map, f)

    return len(new_ips)
