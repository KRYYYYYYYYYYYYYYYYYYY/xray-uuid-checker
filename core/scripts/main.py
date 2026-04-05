import os
import json
import time
import socket
import subprocess
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
import urllib3

# ================= CONFIG =================

TARGETS_PATH = "targets.txt"
RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "/usr/local/bin/xray"
TEMP_DIR = "temp_configs"

MAX_WORKERS = 10

WHITELIST_URLS = [
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/outside-kvas.lst",
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36"
}

# ================= GLOBAL =================

lock = Lock()
session = requests.Session()
session.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= WHITELIST =================

def load_whitelist():
    r = session.get(WHITELIST_URL, timeout=10)
    domains = [f"https://{d.strip()}" for d in r.text.splitlines() if d.strip()]

    if not domains:
        raise Exception("Whitelist пуст")

    print(f"[+] Whitelist загружен: {len(domains)} доменов")
    return domains

WHITELIST = load_whitelist()
WHITELIST_DOMAINS = {d.replace("https://", "").strip().lower() for d in WHITELIST}

# ================= UTILS =================

def wait_socks(port, timeout=5):
    for _ in range(timeout * 10):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except:
            time.sleep(0.1)
    return False

def test_proxy(proxies):
    success = 0
    test_domains = WHITELIST[:20]

    for url in test_domains:
        try:
            r = session.get(url, proxies=proxies, timeout=10, headers=HEADERS)
            if r.status_code == 200:
                success += 1
        except:
            continue

        if success >= 3:
            return True

    return False

# ================= XRAY =================

def generate_config(uuid, host, port, params, local_port):
    security = params.get('security', ['none'])[0]
    sni = params.get('sni', [''])[0]
    pbk = params.get('pbk', [''])[0]
    sid = params.get('sid', [''])[0]
    fp = params.get('fp', ['chrome'])[0]
    flow = params.get('flow', [''])[0]
    net = params.get('type', ['tcp'])[0]

    stream_settings = {"network": net, "security": security}

    if security == "reality":
        stream_settings["realitySettings"] = {
            "serverName": sni,
            "fingerprint": fp,
            "publicKey": pbk,
            "shortId": sid,
            "spiderX": ""
        }
    elif security == "tls":
        stream_settings["tlsSettings"] = {"serverName": sni}

    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks"
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": int(port),
                    "users": [{
                        "id": uuid,
                        "encryption": "none",
                        "flow": flow
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    }

# ================= CORE =================

def check_link(link, idx):
    local_port = 20000 + idx
    temp_config = os.path.join(TEMP_DIR, f"cfg_{idx}.json")
    process = None

    try:
        parsed = urllib.parse.urlparse(link)
        if parsed.scheme != "vless":
            return False

        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host

        # ================= SNI FILTER =================
        sni = params.get('sni', [''])[0].lower()
        if not sni or sni not in WHITELIST_DOMAINS:
            print(f"[-] SKIP (SNI не в whitelist): {sni} | {remark}")
            return False
        # =================================================

        print(f"[*] {remark}")

        config = generate_config(uuid, host, port, params, local_port)
        os.makedirs(TEMP_DIR, exist_ok=True)
        with open(temp_config, "w") as f:
            json.dump(config, f)

        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", temp_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if not wait_socks(local_port):
            print("[-] Xray не стартовал")
            return False

        proxies = {
            "http": f"socks5h://127.0.0.1:{local_port}",
            "https": f"socks5h://127.0.0.1:{local_port}"
        }

        if test_proxy(proxies):
            print(f"[+] OK: {remark}")
            return True
        else:
            print(f"[-] FAIL: {remark}")

    except Exception as e:
        print(f"[-] Ошибка: {e}")

    finally:
        if process:
            process.terminate()
            process.wait()

        if os.path.exists(temp_config):
            os.remove(temp_config)

    return False

# ================= SAVE =================

def save(link):
    with lock:
        os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
        with open(RESULTS_FILE, "a") as f:
            f.write(link.strip() + "\n")
        print("[SAVE OK]")

# ================= MAIN =================

def fetch_links_from_url(url):
    try:
        r = session.get(url, timeout=15, headers=HEADERS)
        r.raise_for_status()
        lines = [l.strip() for l in r.text.splitlines() if l.strip()]
        print(f"[+] Получено {len(lines)} ссылок из {url}")
        return lines
    except Exception as e:
        print(f"[-] Ошибка загрузки подписки {url}: {e}")
        return []

def main():
    if not os.path.exists(TARGETS_PATH):
        print("targets.txt не найден")
        return

    open(RESULTS_FILE, "w").close()

    links = []
    with open(TARGETS_PATH) as f:
        for l in f:
            l = l.strip()
            if not l:
                continue
            # Проверяем на URL подписки
            if l.startswith("http://") or l.startswith("https://"):
                fetched = fetch_links_from_url(l)
                links.extend(fetched)
            else:
                links.append(l)

    print(f"[*] Всего ссылок для проверки: {len(links)}")

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {ex.submit(check_link, link, i): link for i, link in enumerate(links)}
        for f in as_completed(futures):
            link = futures[f]
            if f.result():
                save(link)

if __name__ == "__main__":
    main()
