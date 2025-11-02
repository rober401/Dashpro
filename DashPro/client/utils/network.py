# utils/network.py

import requests
import logging

def send_data(api_url, auth_token, payload):
    "Sends the collected data to the server VIA POST REQUEST"

    headers = {
        "Authorization": "Bearer {}".format(auth_token),
        "Content-Type": "application/json"
    }

    try:
        response = requests.post(api_url, json=payload, headers=headers, timeout=5)

        if response.status_code == 200:
            logging.info("[INFO] Data sent successfully. Server response: {}".format(response.text))
            return True
        else:
            logging.warning("[ERROR] Data sent failed. Server response: {}".format(response.text))
            return False

    except requests.exceptions.Timeout:
        logging.error("[ERROR] Connection timed out. Server may be unreachable.")
        return False

    except requests.exceptions.ConnectionError:
        logging.error("[ERROR] Connection error. Server may be unreachable.")
        return False

    except Exception as e:
        logging.error("[ERROR] Unknown error while sending data. {}".format(e))
        return False