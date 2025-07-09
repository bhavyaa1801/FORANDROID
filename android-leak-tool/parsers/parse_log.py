# parse_log.py
import os
import re
import pandas as pd

def is_valid_hostname(domain):
    return re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain) is not None

def parse_log_file(full_log_path):
    parsed_logs = []
    
    if not os.path.exists(full_log_path):
        raise FileNotFoundError(f"File '{full_log_path}' does not exist.")

    if full_log_path.endswith(".txt"):
        # === Parse logcat-style .txt file ===
        with open(full_log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        log_pattern = re.compile(
            r"(?P<timestamp>\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+)\s+"     # timestamp
            r"(?P<level>[A-Z])/"                                        # log level (D/I/W/E)
            r"(?P<tag>[^\(]+)"                                          # tag before PID
            r"\(\s*(?P<pid>\d+)\):\s+"                                  # PID
            r"(?P<message>.*)"                                          # message
        )

        for line in lines:
            match = log_pattern.match(line)
            if match:
                data = match.groupdict()
                msg = data["message"]

                # Class + method extraction (like com.example.Class.method())
                class_method = re.findall(r'\b[\w$]+\.[\w$]+\([^)]*\)', msg)
                data["class_method"] = class_method[0] if class_method else None

                # Domain extraction
                domain_match = re.search(r"((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})", msg)
                domain = domain_match.group(1) if domain_match else None
                data["domain"] = domain if domain and is_valid_hostname(domain) else None

                # Fill blanks for consistency
                data["record_class"] = None
                data["ip"] = None

                parsed_logs.append(data)

    elif full_log_path.endswith(".xlsx") or full_log_path.endswith(".csv"):
        # === Parse DNS logs from Excel or CSV ===
        if full_log_path.endswith(".xlsx"):
            df_excel = pd.read_excel(full_log_path)
        else:
            df_excel = pd.read_csv(full_log_path)

        required_cols = ["Timestamp", "Query Domain"]
        for col in required_cols:
            if col not in df_excel.columns:
                raise ValueError(f"Required column '{col}' not found.")

        for _, row in df_excel.iterrows():
            data = {
                "timestamp": row.get("Timestamp", ""),
                "domain": row.get("Query Domain", ""),
                "record_type": row.get("Record Type", ""),
                "record_class": row.get("Record Class", ""),
                "server": row.get("Server", ""),
                "service": row.get("Service", ""),
                "client_ip": row.get("Client IP", ""),
                "port": row.get("Port", ""),
                "class_method": None,
                "pid": None,
                "ip": None
            }

            if not is_valid_hostname(str(data["domain"])):
                data["domain"] = None

            parsed_logs.append(data)

    else:
        raise ValueError("Unsupported file type. Only .txt, .xlsx, and .csv supported.")

    df = pd.DataFrame(parsed_logs)
    return df
