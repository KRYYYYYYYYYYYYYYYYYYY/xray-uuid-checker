import json
import os
import subprocess
import time
import requests
import re


# =========================
# CONFIG
# =========================
CONFIG_PATH = 'client/config_test.json'

with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "core/scripts/install_xray.sh"
TEMP_CONFIG = "temp_config.json"


# =========================
# SAVE RESULT
# =========================
def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")


# =========================
# RAW FETCH (IMPROVED)
# =========================
def fetch_vless_from_url(url):
    try:
        r = requests.get(url, timeout=15)
        text = r.text

        # более умный regex (останавливается на пробелах/кавычках/скобках)
        links = re.findall(r"vless://[^\s\"'<>()]+", text)

        return links

    except Exception as e:
        print(f"[-] RAW FETCH ERROR: {url} -> {e}")
        return []


# =========================
# SAFE PARSER (FIXED)
# =========================
def parse_vless(link):
    try:
        if not link or not link.startswith("vless://"):
            return None

        payload = link[8:].split("#")[0]

        if "@" not in payload:
            return None

        uuid_part, address_part = payload.split("@", 1)

        if ":" not in address_part:
            return None

        host, port = address_part.split(":", 1)

        # убираем ?params если вдруг остались
        port = port.split("?")[0]

        if not port.isdigit():
            return None

        return uuid_part, host, port

    except Exception:
        return None


# =========================
# XRAY CONFIG
# =========================
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


# =========================
# CHECK LINK
# =========================
def check_vless_link(link):
    process = None

    try:
        parsed = parse_vless(link)

        if not parsed:
            print(f"[-] BAD LINK: {link}")
            return False

        uuid_part, host, port = parsed

        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_xray_config(uuid_part, host, port), f)

        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", TEMP_CONFIG],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(3)

        if process.poll() is not None:
            print(f"[-] XRAY FAIL: {host}")
            return False

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
        print(f"[-] ERROR: {e}")

    finally:
        if process:
            process.terminate()
        if os.path.exists(TEMP_CONFIG):
            os.remove(TEMP_CONFIG)

    return False


# =========================
# MAIN
# =========================
if __name__ == "__main__":
    if not os.path.exists('targets.txt'):
        print("[!] targets.txt not found")
        exit(1)

    with open('targets.txt', 'r') as f:
        lines = f.read().splitlines()

    all_links = []

    for line in lines:
        line = line.strip()

        if not line:
            continue

        # RAW URL
        if line.startswith("http://") or line.startswith("https://"):
            print(f"[i] FETCH RAW: {line}")
            all_links.extend(fetch_vless_from_url(line))
            continue

        # VLESS link
        all_links.append(line)

    # cleanup + unique
    cleaned = []
    seen = set()

    for link in all_links:
        if link not in seen:
            seen.add(link)
            cleaned.append(link)

    for link in cleaned:
        if check_vless_link(link):
            save_result(link)
