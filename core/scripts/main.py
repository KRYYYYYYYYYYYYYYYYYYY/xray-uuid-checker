import os
import json
import time
import socket
import subprocess
import urllib.parse
import random
import ipaddress
import uuid as uuidlib
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
REPORT_FILE = CFG.get("report_file", "results/report.json")
XRAY_BIN = CFG.get("xray_bin", "/usr/local/bin/xray")
TEMP_DIR = "temp_configs"

MAX_WORKERS = CFG.get("workers", 20)
LEGACY_L7_MAX_CANDIDATES = CFG.get("l7_max_candidates")
MAX_SUCCESS = CFG.get("max_success", CFG.get("max_valid_links", 200))

if "max_success" not in CFG and "max_valid_links" not in CFG:
    if isinstance(LEGACY_L7_MAX_CANDIDATES, int) and LEGACY_L7_MAX_CANDIDATES > 2:
        MAX_SUCCESS = LEGACY_L7_MAX_CANDIDATES
    elif isinstance(LEGACY_L7_MAX_CANDIDATES, int) and LEGACY_L7_MAX_CANDIDATES <= 2:
        print(
            f"⚠️ l7_max_candidates={LEGACY_L7_MAX_CANDIDATES} выглядит как лимит этапа отбора, "
            "не лимит результата; используется MAX_SUCCESS=200. "
            "Задай max_success в config_test.json, если нужен другой предел."
        )

PROBE_ATTEMPTS = CFG.get("probe_attempts", 3)
MAX_LATENCY = CFG.get("max_latency_ms", 2000)
HANDSHAKE_LIMIT = CFG.get("max_handshake_ms", 1200)
RECV_TIMEOUT = CFG.get("recv_timeout", 0.9)
SLEEP_BETWEEN = CFG.get("between_attempts_sleep", 0.2)
L7_TIMEOUT = CFG.get("l7_timeout_sec", max(2.5, RECV_TIMEOUT))
MIMIC_DPI_DELAY = CFG.get("mimic_dpi_delay", False)
MIMIC_DPI_DELAY_MIN = CFG.get("mimic_dpi_delay_min_sec", 0.08)
MIMIC_DPI_DELAY_MAX = CFG.get("mimic_dpi_delay_max_sec", 0.22)

NETWORK_EMULATION = CFG.get("network_emulation", {})
NET_EMU_ENABLED = NETWORK_EMULATION.get("enabled", False)
NET_EMU_BASE_LATENCY_MS = NETWORK_EMULATION.get("base_latency_ms", 0)
NET_EMU_JITTER_MS = NETWORK_EMULATION.get("jitter_ms", 0)
NET_EMU_PACKET_LOSS = NETWORK_EMULATION.get("packet_loss_probability", 0.0)
NET_EMU_BURST_DELAY_MS = NETWORK_EMULATION.get("burst_delay_ms", 0)
NET_EMU_DROP_AFFECTS_VERDICT = NETWORK_EMULATION.get("drop_affects_verdict", False)

WHITELIST_URLS = [
    CFG.get("mobile_whitelist_domains_url"),
    "https://raw.githubusercontent.com/itdoginfo/allow-domains/refs/heads/main/Russia/outside-kvas.lst",
    "https://raw.githubusercontent.com/KRYYYYYYYYYYYYYYYYYYY/xray-uuid-checker/refs/heads/main/Wl2.txt",
]

EXCLUDED_L7_URLS = {
    "https://connectivitycheck.gstatic.com/generate_204",
}


def sanitize_l7_urls(urls):
    cleaned = []
    for raw in urls:
        if not raw:
            continue
        u = raw.strip()
        if not u:
            continue
        if u in EXCLUDED_L7_URLS:
            print(f"⚠️ исключен из L7-проверки: {u}")
            continue
        cleaned.append(u)
    return cleaned


def maybe_multi_unquote(value, max_rounds=3):
    current = value or ""
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def parse_alpn_list(params):
    raw = maybe_multi_unquote(get_param(params, "alpn", ""))
    if not raw:
        return []
    allowed = {"h2", "http/1.1"}
    parsed = []
    for part in raw.split(","):
        token = part.strip().lower()
        if not token:
            continue
        if token in allowed:
            parsed.append(token)
    deduped = []
    seen = set()
    for p in parsed:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


def fetch_ip_info(ip):
    if not ip:
        return None
    try:
        url = IP_REGION_URL.format(ip=ip)
        resp = session.get(url, timeout=L7_TIMEOUT, headers=HEADERS)
        data = resp.json()
        if data.get("status") == "success":
            return data
    except Exception:
        return None
    return None


def extract_ip_from_payload(payload):
    if not isinstance(payload, dict):
        return ""
    return (payload.get("ip") or payload.get("ip_addr") or payload.get("query") or "").strip()


def fetch_proxy_ip(proxies=None):
    last_err = "unknown"
    for _ in range(STAGE_D_RETRIES):
        for url in IP_ECHO_URLS:
            try:
                resp = session.get(
                    url,
                    proxies=proxies,
                    timeout=L7_TIMEOUT,
                    headers=HEADERS,
                )
                ip = extract_ip_from_payload(resp.json())
                if ip:
                    return ip, None
            except Exception as e:
                last_err = type(e).__name__
                continue
    return "", last_err


def do_request(url, proxies):
    if MIMIC_DPI_DELAY:
        time.sleep(random.uniform(MIMIC_DPI_DELAY_MIN, MIMIC_DPI_DELAY_MAX))
    if not emulate_network_conditions():
        if NET_EMU_DROP_AFFECTS_VERDICT:
            return None, None, "synthetic_packet_loss"
        # emulate congestion without causing deterministic false-negative
        time.sleep(random.uniform(0.03, 0.15))
    t0 = time.time()
    r = session.get(url, proxies=proxies, timeout=L7_TIMEOUT, headers=HEADERS, stream=False)
    latency = (time.time() - t0) * 1000
    return r, latency, None


# Stage A: primary mobile-like check (по умолчанию gstatic, как самый показательный для РФ-кейса)
STAGE_A_URLS = sanitize_l7_urls(CFG.get("l7_stage_a_urls") or [
    "https://www.gstatic.com/generate_204",
])
STAGE_A_OK_STATUSES = set(CFG.get("l7_stage_a_ok_statuses", [200, 204]))
L7_REQUIRE_STAGE_A_ALL = CFG.get("l7_require_stage_a_all", True)

# Stage B: optional cross-check (по умолчанию выключен, URL нужно задать явно)
L7_STAGE_B_ENABLED = CFG.get("l7_stage_b_enabled", False)
STAGE_B_URLS = sanitize_l7_urls(CFG.get("l7_stage_b_urls") or [])
STAGE_B_OK_STATUSES = set(CFG.get("l7_stage_b_ok_statuses", [200, 204]))
HIJACK_GUARD_ENABLED = CFG.get("hijack_guard_enabled", True)
REJECT_PRIVATE_EGRESS_IP = CFG.get("reject_private_egress_ip", True)
IP_ECHO_URL = CFG.get("ip_echo_url", "https://api64.ipify.org?format=json")
IP_ECHO_URLS = CFG.get("ip_echo_urls") or [IP_ECHO_URL, "https://api.ipify.org?format=json", "https://ifconfig.me/all.json"]
VERIFY_EGRESS_IP = CFG.get("verify_egress_ip", False)
IP_REGION_URL = CFG.get("ip_region_url", "http://ip-api.com/json/{ip}?fields=status,country,countryCode,query")
EXPECTED_COUNTRY_CODES = set(CFG.get("expected_country_codes") or [])
STABILITY_ATTEMPTS = max(1, int(CFG.get("stability_attempts", 3)))
STABILITY_MIN_SUCCESS = max(1, int(CFG.get("stability_min_success", 2)))
REAL_DOWNLOAD_URL = CFG.get("real_download_url", "https://speed.cloudflare.com/__down?bytes=1048576")
REAL_DOWNLOAD_MIN_BYTES = int(CFG.get("real_download_min_bytes", 300 * 1024))
REAL_DOWNLOAD_MIN_KBPS = int(CFG.get("real_download_min_kbps", 32))
STAGE_D_STRICT = CFG.get("stage_d_strict", False)
STAGE_D_RETRIES = max(1, int(CFG.get("stage_d_retries", 2)))

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
report_items = []

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
        except Exception:
            time.sleep(0.1)

    return False, None


def get_param(params, key, default=""):
    values = params.get(key)
    if not values:
        return default
    return values[-1]


def is_valid_uuid(value):
    try:
        parsed = uuidlib.UUID(str(value))
        return str(parsed) == str(value).lower()
    except ValueError:
        return False


def emulate_network_conditions():
    if not NET_EMU_ENABLED:
        return True

    if NET_EMU_PACKET_LOSS > 0 and random.random() < NET_EMU_PACKET_LOSS:
        return False

    extra_ms = NET_EMU_BASE_LATENCY_MS
    if NET_EMU_JITTER_MS > 0:
        extra_ms += random.uniform(-NET_EMU_JITTER_MS, NET_EMU_JITTER_MS)
    if NET_EMU_BURST_DELAY_MS > 0 and random.random() < 0.15:
        extra_ms += NET_EMU_BURST_DELAY_MS

    if extra_ms > 0:
        time.sleep(extra_ms / 1000.0)

    return True


def classify_result(ok, reason):
    if ok:
        return "ok"

    r = (reason or "").lower()
    if "невалидный uuid" in r or "не vless" in r or "битый vless" in r:
        return "bad_uuid_or_link"
    if "нет sni" in r or "вне whitelist" in r:
        return "config_mismatch"
    if "xray не поднялся" in r:
        return "xray_runtime_error"
    if "не проходит l7" in r or "timeout" in r or "proxyerror" in r or "stage" in r or "unstable" in r:
        return "provider_block_suspected"
    return "unknown"


def run_validation_layers(proxies):
    result = {
        "ok": False,
        "latency_ms": None,
        "download_kbps": 0,
        "ip": "",
        "reason": "",
    }

    # Layer A: handshake-equivalent real request set
    stage_a_latencies = []
    for url in STAGE_A_URLS:
        try:
            r, latency, err = do_request(url, proxies)
            if err:
                if L7_REQUIRE_STAGE_A_ALL:
                    result["reason"] = f"stageA {err} {url}"
                    return result
                continue
            if r.status_code not in STAGE_A_OK_STATUSES:
                result["reason"] = f"stageA bad_status={r.status_code} {url}"
                if L7_REQUIRE_STAGE_A_ALL:
                    return result
                continue
            if HIJACK_GUARD_ENABLED:
                expected_host = urllib.parse.urlparse(url).hostname or ""
                final_host = urllib.parse.urlparse(r.url).hostname or ""
                if expected_host and final_host and expected_host != final_host:
                    result["reason"] = f"stageA hijack {expected_host}->{final_host}"
                    return result
            stage_a_latencies.append(latency)
        except Exception as e:
            result["reason"] = f"stageA {type(e).__name__} {url}"
            if L7_REQUIRE_STAGE_A_ALL:
                return result

    if not stage_a_latencies:
        result["reason"] = result["reason"] or "stageA no successful probes"
        return result
    result["latency_ms"] = int(min(stage_a_latencies))

    # Layer B: anti-fallback check on non-whitelisted domains
    if not L7_STAGE_B_ENABLED or not STAGE_B_URLS:
        result["reason"] = "stageB disabled"
        return result

    stage_b_passed = False
    for url in STAGE_B_URLS:
        try:
            r, _, err = do_request(url, proxies)
            if err:
                continue
            expected_host = urllib.parse.urlparse(url).hostname or ""
            final_host = urllib.parse.urlparse(r.url).hostname or ""
            body = (r.text or "")[:200].lower()
            if r.status_code not in STAGE_B_OK_STATUSES:
                continue
            if expected_host and final_host and expected_host != final_host:
                continue
            if expected_host and expected_host not in (final_host + body):
                continue
            stage_b_passed = True
            break
        except Exception:
            continue
    if not stage_b_passed:
        result["reason"] = "stageB fallback_or_mismatch"
        return result

    # Layer C: sustained traffic test (>=1MB endpoint)
    try:
        if MIMIC_DPI_DELAY:
            time.sleep(random.uniform(MIMIC_DPI_DELAY_MIN, MIMIC_DPI_DELAY_MAX))
        t0 = time.time()
        resp = session.get(
            REAL_DOWNLOAD_URL,
            proxies=proxies,
            timeout=L7_TIMEOUT * 2,
            headers=HEADERS,
            stream=True,
        )
        total = 0
        for chunk in resp.iter_content(chunk_size=16384):
            if not chunk:
                continue
            total += len(chunk)
            if NET_EMU_ENABLED and random.random() < 0.1:
                time.sleep(random.uniform(0.01, 0.08))
        elapsed = max(time.time() - t0, 0.001)
        kbps = int((total / 1024.0) / elapsed)
        result["download_kbps"] = kbps
        if total < REAL_DOWNLOAD_MIN_BYTES:
            result["reason"] = f"stageC low_bytes={total}"
            return result
        if kbps < REAL_DOWNLOAD_MIN_KBPS:
            result["reason"] = f"stageC low_speed={kbps}KB/s"
            return result
    except Exception as e:
        result["reason"] = f"stageC {type(e).__name__}"
        return result

    # Layer D: egress IP verification
    try:
        proxy_ip, proxy_err = fetch_proxy_ip(proxies=proxies)
        result["ip"] = proxy_ip
        if not proxy_ip:
            if STAGE_D_STRICT:
                result["reason"] = f"stageD no_proxy_ip ({proxy_err})"
                return result
            result["reason"] = f"stageD skipped_no_ip ({proxy_err})"
            result["ok"] = True
            return result
        if REJECT_PRIVATE_EGRESS_IP:
            parsed_ip = ipaddress.ip_address(proxy_ip)
            if parsed_ip.is_private or parsed_ip.is_loopback:
                result["reason"] = "stageD private_or_loopback_ip"
                return result

        if VERIFY_EGRESS_IP:
            direct_ip, _ = fetch_proxy_ip(proxies=None)
            if direct_ip and direct_ip == proxy_ip:
                result["reason"] = "stageD same_as_local_ip"
                return result

        if EXPECTED_COUNTRY_CODES:
            info = fetch_ip_info(proxy_ip)
            cc = (info or {}).get("countryCode", "")
            if cc and cc not in EXPECTED_COUNTRY_CODES:
                result["reason"] = f"stageD wrong_country={cc}"
                return result
    except Exception as e:
        result["reason"] = f"stageD {type(e).__name__}"
        return result

    result["ok"] = True
    result["reason"] = "all_layers_passed"
    return result

# ================= XRAY =================


def generate_config(uuid, host, port, params, local_port):
    security = get_param(params, "security", "none")
    sni = get_param(params, "sni", "")
    net = get_param(params, "type", "tcp")
    flow = get_param(params, "flow", "")

    stream_settings = {"network": net, "security": security}

    if security == "reality":
        stream_settings["realitySettings"] = {
            "serverName": sni,
            "fingerprint": get_param(params, "fp", "chrome"),
            "publicKey": get_param(params, "pbk", ""),
            "shortId": get_param(params, "sid", ""),
            "spiderX": ""
        }
        alpns = parse_alpn_list(params)
        if alpns:
            stream_settings["realitySettings"]["alpn"] = alpns

    elif security == "tls":
        stream_settings["tlsSettings"] = {"serverName": sni}
        alpns = parse_alpn_list(params)
        if alpns:
            stream_settings["tlsSettings"]["alpn"] = alpns

    if net == "ws":
        stream_settings["wsSettings"] = {
            "path": get_param(params, "path", "/") or "/",
            "headers": {"Host": get_param(params, "host", "")} if get_param(params, "host", "") else {}
        }
    elif net == "grpc":
        stream_settings["grpcSettings"] = {
            "serviceName": get_param(params, "serviceName", ""),
            "authority": get_param(params, "authority", ""),
            "multiMode": get_param(params, "mode", "gun") == "multi",
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
    metadata = {
        "index": idx,
        "link": link,
        "status": "DEAD",
        "latency_ms": None,
        "download_kbps": 0,
        "ip": "",
        "classification": "unknown",
        "reason": "",
        "remark": "",
    }

    try:
        parsed = urllib.parse.urlparse(link)

        if parsed.scheme != "vless":
            metadata["reason"] = "❌ не VLESS"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
        metadata["remark"] = remark
        metadata["uuid"] = uuid

        if not uuid or not host:
            metadata["reason"] = "❌ битый VLESS (нет uuid/host)"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        if not is_valid_uuid(uuid):
            metadata["reason"] = "❌ невалидный UUID"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        alpn_raw = get_param(params, "alpn", "")
        alpn_decoded = maybe_multi_unquote(alpn_raw)
        if "%2" in alpn_decoded.lower():
            metadata["reason"] = "❌ битый ALPN (многократное кодирование)"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        sni = get_param(params, "sni", "").lower()

        if not sni:
            metadata["reason"] = "❌ нет SNI"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        if sni not in WHITELIST_DOMAINS:
            if STRICT_SNI_WHITELIST:
                metadata["reason"] = "🚫 SNI вне whitelist"
                metadata["classification"] = classify_result(False, metadata["reason"])
                return False, metadata["reason"], metadata
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
            metadata["reason"] = "❌ Xray не поднялся"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        if handshake_ms > HANDSHAKE_LIMIT:
            metadata["reason"] = f"⏱ handshake {int(handshake_ms)} ms"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        proxies = {
            "http": f"socks5h://127.0.0.1:{local_port}",
            "https": f"socks5h://127.0.0.1:{local_port}"
        }

        success_runs = []
        last_reason = "no_attempts"
        for _ in range(STABILITY_ATTEMPTS):
            run = run_validation_layers(proxies)
            if run["ok"]:
                success_runs.append(run)
            else:
                last_reason = run["reason"]
            time.sleep(SLEEP_BETWEEN)

        if len(success_runs) < STABILITY_MIN_SUCCESS:
            metadata["reason"] = f"❌ unstable ({len(success_runs)}/{STABILITY_ATTEMPTS}) {last_reason}"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        best = min(success_runs, key=lambda x: x["latency_ms"] or 10**9)
        if best["latency_ms"] and best["latency_ms"] > MAX_LATENCY:
            metadata["reason"] = f"🐢 latency {int(best['latency_ms'])} ms"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        metadata["status"] = "WORKING"
        metadata["latency_ms"] = int(best["latency_ms"]) if best["latency_ms"] else None
        metadata["download_kbps"] = int(best["download_kbps"])
        metadata["ip"] = best["ip"]
        metadata["reason"] = best["reason"]
        metadata["classification"] = classify_result(True, metadata["reason"])
        return True, f"⚡ {metadata['latency_ms']} ms {metadata['download_kbps']}KB/s {metadata['ip']}", metadata

    except Exception as e:
        metadata["reason"] = f"💥 {str(e)[:60]}"
        metadata["classification"] = classify_result(False, metadata["reason"])
        return False, metadata["reason"], metadata

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


def save_report():
    report_dir = os.path.dirname(REPORT_FILE)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    abs_report = os.path.abspath(REPORT_FILE)
    payload = {
        "summary": {
            "checked": len(report_items),
            "ok": sum(1 for i in report_items if i.get("status") == "WORKING"),
            "provider_block_suspected": sum(1 for i in report_items if i.get("classification") == "provider_block_suspected"),
            "bad_uuid_or_link": sum(1 for i in report_items if i.get("classification") == "bad_uuid_or_link"),
        },
        "network_emulation": {
            "enabled": NET_EMU_ENABLED,
            "base_latency_ms": NET_EMU_BASE_LATENCY_MS,
            "jitter_ms": NET_EMU_JITTER_MS,
            "packet_loss_probability": NET_EMU_PACKET_LOSS,
            "burst_delay_ms": NET_EMU_BURST_DELAY_MS,
        },
        "items": report_items,
    }

    tmp_report = f"{REPORT_FILE}.tmp"
    with open(tmp_report, "w") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp_report, REPORT_FILE)

    print(f"🧾 report: {REPORT_FILE} ({abs_report})")

# ================= MAIN =================


def fetch_links_from_url(url):
    try:
        r = session.get(url, timeout=15)
        r.raise_for_status()
        return [l.strip() for l in r.text.splitlines() if l.strip()]
    except Exception:
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
    print(f"⚙️ workers={MAX_WORKERS}, max_success={MAX_SUCCESS}\n")
    print(
        "🧪 L7 profile: "
        f"stage_a_all={L7_REQUIRE_STAGE_A_ALL}, "
        f"stage_b_enabled={L7_STAGE_B_ENABLED}, "
        f"mimic_dpi_delay={MIMIC_DPI_DELAY}, "
        f"network_emu={NET_EMU_ENABLED}\n"
    )

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {ex.submit(check_link, link, i): link for i, link in enumerate(links)}

        for f in as_completed(futures):
            if success_count >= MAX_SUCCESS:
                print("🛑 лимит достигнут")
                break

            result = f.result()
            if result is None:
                continue

            ok, reason, metadata = result
            report_items.append(metadata)

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

    save_report()
    print(f"\n🎯 готово: {success_count}")


if __name__ == "__main__":
    main()
