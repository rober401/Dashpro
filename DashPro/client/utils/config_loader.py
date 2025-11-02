# utils/config_loader.py

import json
import os

Default_config = {
    "server": {
        "api_url": "http://127.0.0.1:8000/api/heartbeat",
        "auth_token": "3f91a2d4a77b2e9a437b25f2acfe99405df2c1cb9e07a94f3f5d1df5d7f8e6b8"
    },

    "settings": {
        "interval_seconds": 60,
        "log_level": "INFO"
    }
}

def load_config(config_path="config.json"):
    "Loads and validates config file"
    if not os.path.exists(config_path):
        print("[WARNING] Config File not found | Creating Default @ {}".format(config_path))
        save_default_config(config_path)
        return Default_config

    try:
        with open(config_path, "r") as f:
            config = json.load(f)

        # Validate expected key
        if "server" not in config or "settings" not in config:
            raise ValueError("Invalid config file. Missing required key.")

        return config

    except Exception as e:
        print("[ERROR] Failed to load config. {}".format(e))
        return Default_config

def save_default_config(config_path="config.json"):
    with open(config_path, "w") as f:
        json.dump(Default_config, f, indent=4)
    print("[INFO] Default config saved to {}".format(config_path))