import json
import os
import subprocess
import time
import requests

# Конфигурация
CONFIG_PATH = 'client/config_test.json'

with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "./core/xray"
TEMP_CONFIG = "temp_config.json"


def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")


# ✅ БЕЗОПАСНЫЙ ПАРСЕР VLESS
def parse_vless(link):
    try:
        if not link.startswith("vless://"):
            return None

        payload = link.split("://", 1)[1].split("#")[0]

        if "@" not in payload:
            return None

        uuid_part, address_part = payload.split("@", 1)

        if ":" not in address_part:
            return None

        host, port = address_part.split(":", 1)

        if not uuid_part or not host or not port:
            return None

        return uuid_part, host, port

    except Exception:
        return None


def generate_xray_config(uuid, host, port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "port": 10808,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"udp": True}
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": host,
                            "port": int(port),
                            "users": [
                                {
                                    "id": uuid,
                                    "encryption": "none"
                                }
                            ]
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "none"
                }
            },
            {
                "protocol": "freedom",
                "tag": "direct"
            }
        ]
    }


def check_vless_link(link):
    process = None

    try:
        # ✅ безопасный парсинг
        parsed = parse_vless(link)

        if not parsed:
            print(f"[-] BAD LINK: {link}")
            return False

        uuid_part, host, port = parsed

        # write config
        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_xray_config(uuid_part, host, port), f)

        # start xray
        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", TEMP_CONFIG],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(3)

        if process.poll() is not None:
            print(f"[-] Xray failed: {host}")
            return False

        # test proxy
        proxies = {
            'http': 'socks5h://127.0.0.1:10808',
            'https': 'socks5h://127.0.0.1:10808'
        }

        resp = requests.get(
            "http://www.gstatic.com/generate_204",
            proxies=proxies,
            timeout=8
        )

        if resp.status_code in [200, 204]:
            print(f"[+] WORKING: {host}")
            return True

    except Exception as e:
        print(f"[-] Error: {e}")

    finally:
        if process:
            process.terminate()
        if os.path.exists(TEMP_CONFIG):
            os.remove(TEMP_CONFIG)

    return False


if __name__ == "__main__":
    if not os.path.exists('targets.txt'):
        print("[!] targets.txt not found")
        exit(1)

    with open('targets.txt', 'r') as f:
        links = f.read().splitlines()

    for link in links:
        link = link.strip()
        if link and check_vless_link(link):
            save_result(link)
