import json
import os
import subprocess
import time
import requests
import re
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

# =========================
# CONFIG
# =========================
RESULTS_FILE = "results/valid.txt"
TEMP_CONFIG = "temp_config.json"
XRAY_BIN = "core/xray"
SOCKS_PORT = 10808


# =========================
# SAVE
# =========================
def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")


# =========================
# FETCH RAW
# =========================
def fetch_vless(url):
    try:
        r = requests.get(url, timeout=15)
        return re.findall(r"vless://[^\s\"'<>()]+", r.text)
    except:
        return []


# =========================
# ULTRA PARSER
# =========================
def parse_vless(link):
    try:
        if not link.startswith("vless://"):
            return None

        raw = link[8:]

        if "@" not in raw:
            return None

        user, rest = raw.split("@", 1)

        host_port = rest.split("?")[0]
        host, port = host_port.split(":")
        port = int(port)

        parsed_url = urlparse(link)
        params = parse_qs(parsed_url.query)

        return {
            "uuid": user,
            "host": host,
            "port": port,
            "params": params
        }

    except:
        return None


# =========================
# XRAY BUILDER (ULTRA)
# =========================
def build_config(d):
    params = d["params"]

    network = params.get("type", ["tcp"])[0]
    security = params.get("security", ["none"])[0]

    stream = {
        "network": network,
        "security": security
    }

    # WS
    if network == "ws":
        stream["wsSettings"] = {
            "path": params.get("path", [""])[0]
        }

    # GRPC
    if network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0]
        }

    # REALITY (best-effort)
    if security == "reality":
        stream["realitySettings"] = {
            "serverName": params.get("sni", [""])[0],
            "fingerprint": "chrome"
        }

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": SOCKS_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": d["host"],
                    "port": d["port"],
                    "users": [{
                        "id": d["uuid"],
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": stream
        }, {
            "protocol": "freedom",
            "tag": "direct"
        }]
    }


# =========================
# CHECK NODE (ULTRA)
# =========================
def check(link):
    d = parse_vless(link)
    if not d:
        return False

    process = None

    try:
        with open(TEMP_CONFIG, "w") as f:
            json.dump(build_config(d), f)

        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", TEMP_CONFIG],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        time.sleep(2.5)

        if process.poll() is not None:
            return False

        proxies = {
            "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
            "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"
        }

        r = requests.get(
            "http://www.gstatic.com/generate_204",
            proxies=proxies,
            timeout=6
        )

        return r.status_code in (200, 204)

    except:
        return False

    finally:
        if process:
            process.terminate()
        if os.path.exists(TEMP_CONFIG):
            os.remove(TEMP_CONFIG)


# =========================
# MAIN
# =========================
if __name__ == "__main__":

    with open("targets.txt") as f:
        lines = [x.strip() for x in f if x.strip()]

    links = []

    for l in lines:
        if l.startswith("http"):
            links += fetch_vless(l)
        else:
            links.append(l)

    links = list(set(links))

    # 🔥 ULTRA SPEED
    with ThreadPoolExecutor(max_workers=15) as ex:
        results = list(ex.map(check, links))

    for link, ok in zip(links, results):
        if ok:
            print("[+] LIVE:", link)
            save_result(link)
