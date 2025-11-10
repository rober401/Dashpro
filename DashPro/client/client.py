import os
import time
import json
import threading
import requests
from utils.system_info import get_system_info, get_device_id, flags
from utils.config_loader import load_config
from utils.network import send_data
#from utils.email_detection import * # Func name $ Not Finished
#from utils.UrlScanner import UrlScanner $ Not Finished
from utils import filescannerDown
from datetime import datetime


def get_local_time():
    return datetime.now().strftime("%I:%M:%S %p")

def threatHandler(file_path=None, status=None):
    global flags
    print("[Debug] ThreatHandler Active")

    """Handle detected threats reported by the scanner."""
    if not file_path or not status:
        print("Null")
        return  # nothing to process if no data is passed

    payload = {
        "device_id": device_id,
        "timestamp": get_local_time(),
        "status": status,
        "file_path": file_path,
    }

    print(f"[THREAT] {status}: {file_path}")
    alert_url = api_url.replace("/api/heartbeat", "/api/alert")
    success = send_data(alert_url, token, payload)
    if success:
        print(f"[{time.ctime()}] Threat alert sent successfully (ID: {device_id})")
        flags += 1
    else:
        print(f"[{time.ctime()}] Failed to send threat alert")


if __name__ == '__main__':
    try:
        config = load_config()
        api_url = config["server"]["api_url"]
        token = config["server"]["auth_token"]
    except Exception as e:
        print(f"[ERROR] Failed to load configuration: {e}")
        exit(1)

    print(f"[INIT] Client started. Sending updates to {api_url}")
    threading.Thread(target=lambda: filescannerDown.main(threatHandler), daemon=True).start()
    print("[INIT] Started Monitoring Downloads Folder")
    #print(f"[INIT] Started Monitoring Downloads Folder")

    device_id = get_device_id()
    print(f"[INIT] Device ID: {device_id}")

    while True:
        try:


            # Gather system info
            payload = get_system_info()

            payload["device_id"] = device_id

            # Send data to API
            success = send_data(api_url, token, payload)

            # Log the result
            if success:
                print(f"[{time.ctime()}] Data sent successfully (ID: {device_id})")
            else:
                print(f"[{time.ctime()}] Data send failed")

        except Exception as e:
            print(f"[{time.ctime()}] Unexpected error: {e}")

        # Wait before next cycle
        time.sleep(60)

