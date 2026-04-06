import os
import json
import time
import socket
import subprocess
import urllib.parse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import Counter
import urllib3

# ================= LOAD CONFIG =================

CONFIG_PATH_CANDIDATES = (
    "config_test.json",
    os.path.join("client", "config_test.json"),
)


def load_runtime_config():
    for path in CONFIG_PATH_CANDIDATES:
        if os.path.exists(path):
            with open(path) as f:
                cfg = json.load(f)
            print(f"📦 config: {path}")
            return cfg
    print("⚠️ config_test.json не найден, используются значения по умолчанию")
    return {}


CFG = load_runtime_config()

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
RECV_TIMEOUT = CFG.get("recv_timeout", 0.9)
SLEEP_BETWEEN = CFG.get("between_attempts_sleep", 0.2)
L7_TIMEOUT = CFG.get("l7_timeout_sec", max(2.5, RECV_TIMEOUT))

WHITELIST_URLS = [
    CFG.get("mobile_whitelist_domains_url"),
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/outside-kvas.lst",
    "https://raw.githubusercontent.com/KRYYYYYYYYYYYYYYYYYYY/xray-uuid-checker/refs/heads/main/Wl2.txt",
]

# L7 endpoint'ы (только проверка факта HTTP-доступа)
TEST_URLS = CFG.get("l7_test_urls") or [
    "http://1.1.1.1",
    "http://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
]

HEADERS = CFG.get("mobile_header_profiles", [{}])[0].get("headers", {})
HEADERS["User-Agent"] = CFG.get("mobile_header_profiles", [{}])[0].get("user_agent", "Mozilla/5.0")
STRICT_SNI_WHITELIST = CFG.get("mobile_whitelist_strict", True)

# ================= GLOBAL =================

lock = Lock()
session = requests.Session()
session.verify = False
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

success_count = 0
fail_reasons = Counter()

# ================= WHITELIST =================

def normalize_domain(raw_domain):
    if not raw_domain:
        return ""
    val = raw_domain.strip().lower()
    if not val or val.startswith("#"):
        return ""
    val = val.replace("https://", "").replace("http://", "")
    return val.split("/")[0].strip().strip(".")


def load_whitelist():
    domains = set()

    for url in WHITELIST_URLS:
        if not url:
            continue
        try:
            r = session.get(url.strip(), timeout=10)
            r.raise_for_status()

            for line in r.text.splitlines():
                domain = normalize_domain(line)
                if domain:
                    domains.add(domain)

            print(f"📥 whitelist: {url}")

        except Exception as e:
            print(f"❌ whitelist fail: {url} → {e}")

    if not domains:
        raise Exception("❌ whitelist пуст")

    print(f"✅ доменов: {len(domains)}")
    return domains

WHITELIST_DOMAINS = load_whitelist()

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
    last_error = "нет ответа от test_url"

    for url in TEST_URLS:
        try:
            t0 = time.time()
            r = session.get(url, proxies=proxies, timeout=L7_TIMEOUT, headers=HEADERS)
            latency = (time.time() - t0) * 1000

            if r.status_code:
                return True, latency, f"{r.status_code} {url}"
            last_error = f"empty_status {url}"

        except Exception as e:
            last_error = f"{type(e).__name__} {url}"
            continue

    return False, None, last_error

# ================= XRAY =================

def generate_config(uuid, host, port, params, local_port):
    security = params.get('security', ['none'])[0]
    sni = params.get('sni', [''])[0]
    net = params.get('type', ['tcp'])[0]
    flow = params.get('flow', [''])[0]

    stream_settings = {"network": net, "security": security}

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

    if net == "ws":
        stream_settings["wsSettings"] = {
            "path": params.get('path', ['/'])[0] or "/",
            "headers": {"Host": params.get('host', [''])[0]} if params.get('host', [''])[0] else {}
        }
    elif net == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": params.get('serviceName', [''])[0],
            "authority": params.get('authority', [''])[0],
            "multiMode": params.get('mode', ['gun'])[0] == "multi",
        }

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
                        **({"flow": flow} if flow else {})
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

        if not uuid or not host:
            return False, "❌ битый VLESS (нет uuid/host)"

        sni = params.get('sni', [''])[0].lower()

        if not sni:
            return False, "❌ нет SNI"

        if sni not in WHITELIST_DOMAINS:
            if STRICT_SNI_WHITELIST:
                return False, "🚫 SNI вне whitelist"
            print(f"⚠️ [{idx}] SNI не в whitelist: {sni}")

        print(f"🔍 [{idx}] {remark}")

        config = generate_config(uuid, host, port, params, local_port)

        os.makedirs(TEMP_DIR, exist_ok=True)
        with open(temp_config, "w") as f:
            json.dump(config, f)

        process = subprocess.Popen(
            [XRAY_BIN, "run", "-c", temp_config],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        ok, handshake_ms = wait_socks(local_port)

        if not ok:
            return False, "❌ Xray не поднялся"

        if handshake_ms > HANDSHAKE_LIMIT:
            return False, f"⏱ handshake {int(handshake_ms)} ms"

        proxies = {
            "http": f"socks5h://127.0.0.1:{local_port}",
            "https": f"socks5h://127.0.0.1:{local_port}"
        }

        for _ in range(PROBE_ATTEMPTS):
            ok, latency, l7_reason = test_proxy(proxies)

            if ok:
                if latency and latency > MAX_LATENCY:
                    return False, f"🐢 latency {int(latency)} ms"

                return True, f"⚡ {int(latency)} ms ({l7_reason})"

            time.sleep(SLEEP_BETWEEN)

        return False, f"❌ не проходит L7 ({l7_reason})"

    except Exception as e:
        return False, f"💥 {str(e)[:60]}"

    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

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
    seen = set()
    with open(TARGETS_PATH) as f:
        for l in f:
            l = l.strip()
            if not l:
                continue
            if l.startswith("http"):
                for remote_link in fetch_links_from_url(l):
                    if remote_link not in seen:
                        seen.add(remote_link)
                        links.append(remote_link)
            else:
                if l not in seen:
                    seen.add(l)
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
                fail_reasons[reason] += 1

    if fail_reasons:
        print("\n📉 ТОП причин отказа:")
        for reason, count in fail_reasons.most_common(5):
            print(f"  - {count}x {reason}")

    print(f"\n🎯 готово: {success_count}")

if __name__ == "__main__":
    main()
