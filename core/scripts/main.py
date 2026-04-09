import json
import os
import subprocess
import time
import requests
import re
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor
import uuid

# =========================
# CONFIG
# =========================
RESULTS_FILE = "results/valid.txt"
TEMP_DIR = "client/tmp"
XRAY_BIN = "core/xray"
SOCKS_PORT = 10808

TG_BOT_TOKEN = ""   # optional
TG_CHAT_ID = ""     # optional


# =========================
# SAFE INIT
# =========================
os.makedirs("results", exist_ok=True)
os.makedirs(TEMP_DIR, exist_ok=True)


# =========================
# CHECK XRAY BIN EXISTS
# =========================
if not os.path.exists(XRAY_BIN):
    raise FileNotFoundError(
        f"[XRAY NOT FOUND] Path '{XRAY_BIN}' does not exist. "
        f"Fix it to your real xray binary location."
    )


# =========================
# SAVE RESULT
# =========================
def save_result(link):
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")


# =========================
# FETCH
# =========================
def fetch_vless(url):
    try:
        r = requests.get(url, timeout=15)
        return re.findall(r"vless://[^\s\"'<>()]+", r.text)
    except:
        return []


# =========================
# PARSER
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
# XRAY CONFIG
# =========================
def build_config(d):
    params = d["params"]

    network = params.get("type", ["tcp"])[0]
    security = params.get("security", ["none"])[0]

    stream = {
        "network": network,
        "security": security
    }

    if network == "ws":
        stream["wsSettings"] = {
            "path": params.get("path", [""])[0]
        }

    if network == "grpc":
        stream["grpcSettings"] = {
            "serviceName": params.get("serviceName", [""])[0]
        }

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
# WAIT SOCKS READY
# =========================
def wait_socks(timeout=6):
    for _ in range(timeout * 5):
        try:
            requests.get(
                "http://www.gstatic.com/generate_204",
                proxies={
                    "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
                    "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"
                },
                timeout=2
            )
            return True
        except:
            time.sleep(0.2)
    return False


# =========================
# CHECK NODE
# =========================
def check(link):
    d = parse_vless(link)
    if not d:
        return False

    process = None
    cfg_path = os.path.join(TEMP_DIR, f"{uuid.uuid4().hex}.json")

    try:
        with open(cfg_path, "w") as f:
            json.dump(build_config(d), f)

        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", cfg_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_socks():
            return False

        r = requests.get(
            "http://www.gstatic.com/generate_204",
            proxies={
                "http": f"socks5h://127.0.0.1:{SOCKS_PORT}",
                "https": f"socks5h://127.0.0.1:{SOCKS_PORT}"
            },
            timeout=6
        )

        return r.status_code in (200, 204)

    except:
        return False

    finally:
        if process:
            process.terminate()
        if os.path.exists(cfg_path):
            try:
                os.remove(cfg_path)
            except:
                pass


# =========================
# TELEGRAM (OPTIONAL ULTRA MODE)
# =========================
def tg_send(text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT_ID, "text": text},
            timeout=5
        )
    except:
        pass


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

    print(f"[ULTRA] TOTAL LINKS: {len(links)}")

    with ThreadPoolExecutor(max_workers=15) as ex:
        results = list(ex.map(check, links))

    for link, ok in zip(links, results):
        if ok:
            print("[+] LIVE:", link)
            save_result(link)
            tg_send(f"LIVE NODE:\n{link}")
