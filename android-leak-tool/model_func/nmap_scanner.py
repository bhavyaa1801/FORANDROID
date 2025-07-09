import os
import subprocess
import re
import pandas as pd
import json


# === Define Suspicious Ports and Their Threats ===
PORT_THREAT_MAP = {
    21: "FTP - Unencrypted login",
    22: "SSH - Remote shell",
    23: "Telnet - Insecure remote login",
    25: "SMTP - Open mail relay risk",
    53: "DNS - May allow zone transfer",
    80: "HTTP - Web server",
    110: "POP3 - Unencrypted mail",
    135: "MSRPC - DCOM attack surface",
    139: "NetBIOS - Lateral movement",
    143: "IMAP - Email access",
    445: "SMB - EternalBlue, wormable",
    3306: "MySQL - Database exposed",
    3389: "RDP - Remote desktop",
    5900: "VNC - Unauthenticated access",
    6379: "Redis - Unsecured DB",
    27017: "MongoDB - Exposed NoSQL DB",
    11211: "Memcached - DDoS reflection",
    6667: "IRC - Botnet C2",
    8080: "Alt HTTP - Dev servers",
    8443: "Alt HTTPS - Web admin panels",
    8888: "Jupyter/Alt web UI",
    9001: "Tor relay / backend",
    25565: "Minecraft server - Bot target"                        
}

DEFAULT_PORTS = ",".join(str(p) for p in PORT_THREAT_MAP)
# Nmap Scan Functions
def scan_ip(ip, ports=DEFAULT_PORTS):
    try:
        result = subprocess.run(
            ["nmap", "-p", ports, "-sV", "-T4", "--host-timeout", "25s", ip],
            capture_output=True, text=True, timeout=60
        )
        return result.stdout
    except subprocess.TimeoutExpired:
        print(f"[Timeout] {ip}")
        return ""
    except Exception as e:
        print(f"[Error] {ip}: {e}")
        return ""

def get_risk_level(port):
    if port in {22, 23, 445, 3389, 5900}:
        return "high"
    elif port in {21, 25, 139, 3306, 27017, 11211, 6667}:
        return "medium"
    elif port in PORT_THREAT_MAP:
        return "low"
    else:
        return "info"

# formating raw output
def parse_nmap_output(ip, raw_output):
    records = []
    for line in raw_output.splitlines():
        match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s+(.*)", line)
        if match:
            port = int(match.group(1))
            service = match.group(2)
            banner = match.group(3).strip()
            tag = "suspicious" if port in PORT_THREAT_MAP else "normal"
            threat = PORT_THREAT_MAP.get(port, "")
            risk = get_risk_level(port)
            records.append({
                "ip": ip,
                "port": port,
                "service": service,
                "banner": banner,
                "threat": threat,
                "tag": tag,
                "risk_level": risk
            })
    return records

def scan_ips_from_file(ip_input_file, output_csv, ):
    if not os.path.exists(ip_input_file):
        print(f"[ERROR] Input file does not exist: {ip_input_file}")
        return pd.DataFrame()

    df_ips = pd.read_csv(ip_input_file)
    ip_list = df_ips["ip"].dropna().unique().tolist()

    case_folder = os.path.dirname(output_csv)
    if not os.path.exists(case_folder):
        os.makedirs(case_folder)

    all_results = []
    for ip in ip_list:
        raw = scan_ip(ip)
        parsed = parse_nmap_output(ip, raw)
        if parsed:
            all_results.extend(parsed)

       

    df = pd.DataFrame(all_results)
    if not df.empty:
        df.to_csv(output_csv, index=False)
        return df,f"Scan complete. Results saved to: {output_csv}"      #remove path 
    else:
        return df, "No open ports found or all scans failed."

    
