import json
import os

CONFIG_FILE = "config.json"

def load_config():
    default_config = {
        "threads": 10,
        "proxy_type": "socks5",
        "proxies_file": "data/proxies.txt",
        "targets_file": "data/target_ips.txt",
        "output_file": "data/results.txt"
    }
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=4)
        return default_config
    with open(CONFIG_FILE, 'r') as f:
        return json.load(f)

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=4)