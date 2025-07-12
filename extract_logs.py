# extraction.py

import subprocess
import platform
import ctypes
import os
import hashlib
from datetime import datetime
import json

def hide_file(path):
    system = platform.system()
    if system == "Windows":
        ctypes.windll.kernel32.SetFileAttributesW(path, 0x02)
    elif system in ["Linux", "Darwin"]:
        hidden_path = os.path.join(os.path.dirname(path), "." + os.path.basename(path))
        os.rename(path, hidden_path)
        return hidden_path
    return path

def is_device_connected():
    result = subprocess.run(["adb", "get-state"], capture_output=True, text=True)
    return result.stdout.strip() == "device"


def compute_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

#  MAIN FUNCTION YOU'LL CALL FROM STREAMLIT
def extract_from_phone(case_path: str):
    if not is_device_connected():
      raise RuntimeError("No Android device connected or ADB not authorized.")

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_suffix = f"{timestamp}.txt"

    full_log = os.path.join(case_path, f"full_app_logs_{file_suffix}")
    activity_log = os.path.join(case_path, f"app_activity_logs_{file_suffix}")
    dns_log = os.path.join(case_path, f"dns_logs_{file_suffix}")

    commands = {
        "📄 Full logcat": f"adb logcat -v time -d > \"{full_log}\"",
        "📲 App Activity": f"adb logcat -v time -d | findstr /i \"ActivityManager Start proc cmp=\" > \"{activity_log}\"",
        "🌐 DNS logs": f"adb logcat -v time -d | findstr /i \"Dns resolv Query netd\" > \"{dns_log}\""
    }

    for desc, cmd in commands.items():
        result = subprocess.run(cmd, shell=True)
        if result.returncode != 0:
            raise RuntimeError(f"Failed to extract: {desc}")

    hashes = {
        "timestamp": timestamp,
        "log_file_hashes": {
            os.path.basename(full_log): compute_sha256(full_log),
            os.path.basename(activity_log): compute_sha256(activity_log),
            os.path.basename(dns_log): compute_sha256(dns_log)
        }
    }

    hash_path = os.path.join(case_path, "hashes.json")
    with open(hash_path, "w") as f:
        json.dump(hashes, f, indent=4)

    hide_file(hash_path)
