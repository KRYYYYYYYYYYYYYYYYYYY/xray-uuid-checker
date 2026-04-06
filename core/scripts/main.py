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

# ================= LOAD MOBILE CONFIG =================

CONFIG_PATH = "config_test.json"

if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH) as f:
        CFG = json.load(f)
else:
    CFG = {}

# ================= CONFIG =================

TARGETS_PATH = "targets.txt"
RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "/usr/local/bin/xray"
TEMP_DIR = "temp_configs"

MAX_WORKERS = CFG.get("workers", 20)
MAX_SUCCESS = CFG.get("l7_max_candidates", 200)

PROBE_ATTEMPTS = CFG.get("probe_attempts", 3)
MAX_LATENCY = CFG.get("max_latency_ms", 2000)
HANDSHAKE_LIMIT = CFG.get("max_handshake_ms", 1200)
RECV_TIMEOUT = CFG.get("recv_timeout", 1.0)
SLEEP_BETWEEN = CFG.get("between_attempts_sleep", 0.2)

WHITELIST_URLS = [
    CFG.get("mobile_whitelist_domains_url"),
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/outside-kvas.lst",
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/outside-kvas.lst",
    "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/KRYYYYYYYYYYYYYYYYYYY/xray-uuid-checker/refs/heads/main/Wl2.txt",
    
]

HEADERS = CFG.get("mobile_header_profiles", [{}])[0].get("headers", {})
HEADERS["User-Agent"] = CFG.get("mobile_header_profiles", [{}])[0].get("user_agent", "Mozilla/5.0")

# ================= GLOBAL =================

lock = Lock()
session = requests.Session()
session.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

success_count = 0

# ================= WHITELIST =================

def load_whitelist():
    domains = set()

    for url in WHITELIST_URLS:
        if not url:
            continue
        try:
            r = session.get(url.strip(), timeout=10)
            r.raise_for_status()

            for line in r.text.splitlines():
                d = line.strip()
                if d and not d.startswith("#"):
                    domains.add(d.lower())

            print(f"📥 whitelist: {url}")

        except Exception as e:
            print(f"❌ whitelist fail: {url} → {e}")

    if not domains:
        raise Exception("❌ whitelist пуст")

    print(f"✅ доменов: {len(domains)}")
    return domains

WHITELIST_DOMAINS = load_whitelist()
WHITELIST = [f"https://{d}" for d in WHITELIST_DOMAINS]

# ================= UTILS =================

def wait_socks(port, timeout=5):
    start = time.time()

    for _ in range(timeout * 10):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                elapsed = (time.time() - start) * 1000
                return True, elapsed
        except:
            time.sleep(0.1)

    return False, None

def test_proxy(proxies):
    success = 0
    latencies = []

    for url in WHITELIST[:10]:
        try:
            t0 = time.time()
            r = session.get(url, proxies=proxies, timeout=RECV_TIMEOUT, headers=HEADERS)
            latency = (time.time() - t0) * 1000

            if r.status_code == 200:
                success += 1
                latencies.append(latency)

        except:
            pass

        if success >= CFG.get("min_success", 1):
            avg_latency = sum(latencies) / len(latencies)
            return True, avg_latency

    return False, None

# ================= XRAY =================

def generate_config(uuid, host, port, params, local_port):
    security = params.get('security', ['none'])[0]
    sni = params.get('sni', [''])[0]

    stream_settings = {"network": "tcp", "security": security}

    if security == "reality":
        stream_settings["realitySettings"] = {
            "serverName": sni,
            "fingerprint": params.get('fp', ['chrome'])[0],
            "publicKey": params.get('pbk', [''])[0],
            "shortId": params.get('sid', [''])[0],
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
                        "encryption": "none"
                    }]
                }]
            },
            "streamSettings": stream_settings
        }]
    }

# ================= CORE =================

def check_link(link, idx):
    global success_count

    with lock:
        if success_count >= MAX_SUCCESS:
            return None

    local_port = 20000 + (idx % 1000)
    temp_config = os.path.join(TEMP_DIR, f"cfg_{idx}.json")
    process = None

    try:
        parsed = urllib.parse.urlparse(link)

        if parsed.scheme != "vless":
            return False, "❌ не VLESS"

        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host

        sni = params.get('sni', [''])[0].lower()

        if not sni:
            return False, "❌ нет SNI"

        if sni not in WHITELIST_DOMAINS:
            return False, f"🚫 SNI вне whitelist"

        print(f"🔍 {remark}")

        config = generate_config(uuid, host, port, params, local_port)

        os.makedirs(TEMP_DIR, exist_ok=True)
        with open(temp_config, "w") as f:
            json.dump(config, f)

        start = time.time()

        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", temp_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        ok, handshake_ms = wait_socks(local_port)

        if not ok:
            return False, "❌ Xray не поднялся"

        if handshake_ms > HANDSHAKE_LIMIT:
            return False, f"⏱ медленный handshake ({int(handshake_ms)} ms)"

        proxies = {
            "http": f"socks5h://127.0.0.1:{local_port}",
            "https": f"socks5h://127.0.0.1:{local_port}"
        }

        # RETRY LOGIC
        for attempt in range(PROBE_ATTEMPTS):
            ok, latency = test_proxy(proxies)

            if ok:
                if latency and latency > MAX_LATENCY:
                    return False, f"🐢 высокий latency ({int(latency)} ms)"

                return True, f"⚡ OK ({int(latency)} ms)"

            time.sleep(SLEEP_BETWEEN)

        return False, "❌ нестабильный / не проходит пробы"

    except Exception as e:
        return False, f"💥 {str(e)[:60]}"

    finally:
        if process:
            process.terminate()
            process.wait()

        if os.path.exists(temp_config):
            os.remove(temp_config)

# ================= SAVE =================

def save(link):
    global success_count

    with lock:
        if success_count >= MAX_SUCCESS:
            return False

        os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)

        with open(RESULTS_FILE, "a") as f:
            f.write(link.strip() + "\n")

        success_count += 1
        print(f"💾 [{success_count}/{MAX_SUCCESS}]")

        return True

# ================= MAIN =================

def fetch_links_from_url(url):
    try:
        r = session.get(url, timeout=15)
        r.raise_for_status()
        return [l.strip() for l in r.text.splitlines() if l.strip()]
    except:
        return []

def main():
    if not os.path.exists(TARGETS_PATH):
        print("❌ нет targets.txt")
        return

    open(RESULTS_FILE, "w").close()

    links = []
    with open(TARGETS_PATH) as f:
        for l in f:
            l = l.strip()
            if not l:
                continue
            if l.startswith("http"):
                links.extend(fetch_links_from_url(l))
            else:
                links.append(l)

    print(f"🚀 всего: {len(links)}\n")

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {ex.submit(check_link, link, i): link for i, link in enumerate(links)}

        for f in as_completed(futures):
            if success_count >= MAX_SUCCESS:
                print("🛑 лимит достигнут")
                break

            result = f.result()
            if result is None:
                continue

            ok, reason = result

            if ok:
                print(f"✅ {reason}")
                save(futures[f])
            else:
                print(f"❌ {reason}")

    print(f"\n🎯 готово: {success_count}")

if __name__ == "__main__":
    main()
