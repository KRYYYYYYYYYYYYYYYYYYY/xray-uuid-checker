import os
import json
import time
import socket
import subprocess
import urllib.parse
import random
import ipaddress
import uuid as uuidlib
from datetime import datetime, timezone
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from collections import Counter
import urllib3

# ================= LOAD CONFIG =================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))

CONFIG_PATH_CANDIDATES = (
    "config_test.json",
    os.path.join("client", "config_test.json"),
    os.path.join(REPO_ROOT, "config_test.json"),
    os.path.join(REPO_ROOT, "client", "config_test.json"),
)


def resolve_repo_path(path_value):
    if not path_value:
        return path_value
    if os.path.isabs(path_value):
        return path_value
    return os.path.join(REPO_ROOT, path_value)


def load_runtime_config():
    for path in CONFIG_PATH_CANDIDATES:
        if os.path.exists(path):
            with open(path) as f:
                cfg = json.load(f)
            print(f"📦 config: {os.path.abspath(path)}")
            return cfg
    print("⚠️ config_test.json не найден, используются значения по умолчанию")
    return {}


CFG = load_runtime_config()

# ================= CONFIG =================

TARGETS_PATH = resolve_repo_path(CFG.get("targets_file", "targets.txt"))
RESULTS_FILE = resolve_repo_path(CFG.get("results_file", "results/valid.txt"))
REPORT_FILE = resolve_repo_path(CFG.get("report_file", "results/report.json"))
XRAY_BIN = CFG.get("xray_bin", "/usr/local/bin/xray")
TEMP_DIR = resolve_repo_path(CFG.get("temp_dir", "temp_configs"))

MAX_WORKERS = CFG.get("workers", 20)
LEGACY_L7_MAX_CANDIDATES = CFG.get("l7_max_candidates")
MAX_SUCCESS = CFG.get("max_success", CFG.get("max_valid_links", 200))
# Дедупликация по egress IP по умолчанию отключена (0),
# чтобы не отбрасывать валидные UUID с общим серверным выходом.
MAX_SUCCESS_PER_EGRESS_IP = max(0, int(CFG.get("max_success_per_egress_ip", 0)))

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


def build_stage_b_targets(raw_targets):
    targets = []
    for item in (raw_targets or []):
        if isinstance(item, str):
            url = item.strip()
            if not url:
                continue
            targets.append({
                "url": url,
                "ok_statuses": [200],
                "expect_contains": [],
                "expect_json_key": "",
            })
            continue
        if not isinstance(item, dict):
            continue
        url = str(item.get("url", "")).strip()
        if not url:
            continue
        targets.append({
            "url": url,
            "ok_statuses": item.get("ok_statuses", [200]),
            "expect_contains": item.get("expect_contains", []),
            "expect_json_key": item.get("expect_json_key", ""),
            "expect_headers": item.get("expect_headers", {}),
            "forbid_headers": item.get("forbid_headers", {}),
        })
    return targets


def maybe_multi_unquote(value, max_rounds=3):
    current = value or ""
    for _ in range(max_rounds):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def parse_alpn_list(params):
    raw_value = get_param(params, "alpn", "")
    decoded = maybe_multi_unquote(raw_value)
    if not decoded:
        return [], False

    # В реальных ссылках встречаются сломанные разделители и многократное кодирование.
    normalized = (
        decoded.replace(";", ",")
        .replace("|", ",")
        .replace(" ", ",")
        .strip(",")
    )
    allowed = {"h2", "http/1.1", "h3"}
    parsed = []
    malformed = False
    for part in normalized.split(","):
        token = part.strip().lower()
        if not token:
            continue
        if token in allowed:
            parsed.append(token)
        else:
            malformed = True

    # Если после нескольких раундов декодирования осталось %-кодирование,
    # считаем это признаком "битого" ALPN, но пытаемся восстановить корректные токены.
    if "%" in decoded or "%" in raw_value:
        malformed = True

    deduped = []
    seen = set()
    for p in parsed:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped, malformed


def normalize_vless_link(link):
    # Некоторые генераторы многократно %-кодируют query-параметры (особенно ALPN).
    # Декодируем ограниченным числом раундов, чтобы не повредить ссылку бесконечным циклом.
    current = (link or "").strip()
    for _ in range(5):
        decoded = urllib.parse.unquote(current)
        if decoded == current:
            break
        current = decoded
    return current


def resolve_expected_server_ip(host):
    if not host:
        return ""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        for info in infos:
            sockaddr = info[4]
            if sockaddr and sockaddr[0]:
                return str(sockaddr[0]).strip()
    except Exception:
        return ""
    return ""


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


def extract_asn_number(info):
    if not info:
        return None
    raw_as = str(info.get("as") or "").strip().upper()
    if raw_as.startswith("AS"):
        raw_as = raw_as[2:].split()[0]
    return int(raw_as) if raw_as.isdigit() else None


def do_request(url, proxies):
    if MIMIC_DPI_DELAY:
        time.sleep(random.uniform(MIMIC_DPI_DELAY_MIN, MIMIC_DPI_DELAY_MAX))
    if not emulate_network_conditions():
        # Для реалистичного режима добавляем "потерю" только как задержку,
        # но не считаем это фатальной ошибкой валидации.
        time.sleep(random.uniform(0.05, 0.2))
    t0 = time.time()
    r = session.get(url, proxies=proxies, timeout=L7_TIMEOUT, headers=HEADERS, stream=False)
    latency = (time.time() - t0) * 1000
    return r, latency, None


def get_echo_ip(proxies=None):
    for _ in range(STAGE_D_RETRIES):
        for url in IP_ECHO_URLS:
            try:
                r = session.get(url, proxies=proxies, timeout=L7_TIMEOUT, headers=HEADERS)
                data = r.json()
                ip = data.get("ip") or data.get("ip_addr") or data.get("ip_address")
                if not ip and "addr" in data:
                    ip = data.get("addr")
                if ip:
                    return str(ip).strip()
            except Exception:
                continue
    return ""


LOCAL_EGRESS_IP_CACHE = None


def get_local_egress_ip():
    global LOCAL_EGRESS_IP_CACHE
    if LOCAL_EGRESS_IP_CACHE is None:
        LOCAL_EGRESS_IP_CACHE = get_echo_ip(proxies=None)
    return LOCAL_EGRESS_IP_CACHE


def ensure_parent_dir(path):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)


# Stage A: primary mobile-like check (по умолчанию gstatic, как самый показательный для РФ-кейса)
STAGE_A_URLS = sanitize_l7_urls(CFG.get("l7_stage_a_urls") or [
    "https://www.gstatic.com/generate_204",
])
STAGE_A_FALLBACK_ENABLED = CFG.get("l7_stage_a_fallback_enabled", True)
STAGE_A_FALLBACK_URLS = sanitize_l7_urls(CFG.get("l7_stage_a_fallback_urls") or [
    "https://www.msftconnecttest.com/connecttest.txt",
    "https://cp.cloudflare.com/generate_204",
])
STAGE_A_OK_STATUSES = set(CFG.get("l7_stage_a_ok_statuses", [200, 204]))
L7_REQUIRE_STAGE_A_ALL = CFG.get("l7_require_stage_a_all", True)
STAGE_A_FORBIDDEN_SERVER_MARKERS = {
    str(k).lower(): [str(v).lower() for v in vals]
    for k, vals in (CFG.get("stage_a_forbidden_server_markers") or {
        "www.gstatic.com": ["nginx"],
        "www.google.com": ["nginx"],
    }).items()
}

# Stage B: anti-fallback cross-check (по умолчанию включен)
L7_STAGE_B_ENABLED = CFG.get("l7_stage_b_enabled", True)
_raw_stage_b_targets = CFG.get("l7_stage_b_targets") or [
    {
        "url": "https://api.ipify.org?format=json",
        "ok_statuses": [200],
        "expect_json_key": "ip",
    },
    {
        "url": "https://www.cloudflare.com/cdn-cgi/trace",
        "ok_statuses": [200],
        "expect_contains": ["h=", "ip=", "ts="],
    },
]
STAGE_B_TARGETS = build_stage_b_targets(_raw_stage_b_targets)
# legacy compatibility
STAGE_B_URLS = sanitize_l7_urls(CFG.get("l7_stage_b_urls") or [])
if STAGE_B_URLS:
    STAGE_B_TARGETS.extend(build_stage_b_targets(STAGE_B_URLS))
STAGE_B_OK_STATUSES = set(CFG.get("l7_stage_b_ok_statuses", [200, 204]))
HIJACK_GUARD_ENABLED = CFG.get("hijack_guard_enabled", True)
REJECT_PRIVATE_EGRESS_IP = CFG.get("reject_private_egress_ip", True)
IP_ECHO_URL = CFG.get("ip_echo_url", "https://api64.ipify.org?format=json")
IP_ECHO_URLS = CFG.get("ip_echo_urls") or [IP_ECHO_URL, "https://api.ipify.org?format=json", "https://ifconfig.me/all.json"]
VERIFY_EGRESS_IP = CFG.get("verify_egress_ip", True)
VERIFY_IP_NOT_LOCAL = CFG.get("verify_ip_not_local", True)
IP_REGION_URL = CFG.get("ip_region_url", "http://ip-api.com/json/{ip}?fields=status,country,countryCode,query,as,asname")
EXPECTED_COUNTRY_CODES = set(CFG.get("expected_country_codes") or [])
EXPECTED_ASN_NUMBERS = {
    int(x) for x in (CFG.get("expected_asn_numbers") or []) if str(x).strip().isdigit()
}
EXPECTED_ASN_PREFIXES = [
    str(x).strip().upper() for x in (CFG.get("expected_asn_prefixes") or []) if str(x).strip()
]
STABILITY_ATTEMPTS = max(1, int(CFG.get("stability_attempts", 3)))
LEGACY_L7_MIN_SUCCESS = CFG.get("l7_min_success")
STABILITY_MIN_SUCCESS = max(1, int(CFG.get("stability_min_success", LEGACY_L7_MIN_SUCCESS or 2)))
REAL_DOWNLOAD_URL = CFG.get("real_download_url", "https://speed.cloudflare.com/__down?bytes=1048576")
REAL_DOWNLOAD_MIN_BYTES = int(CFG.get("real_download_min_bytes", 300 * 1024))
REAL_DOWNLOAD_MIN_KBPS = int(CFG.get("real_download_min_kbps", 32))
STAGE_D_FAIL_OPEN = CFG.get("stage_d_fail_open", False)
STAGE_D_RETRIES = max(1, int(CFG.get("stage_d_retries", 2)))
REAL_WORLD_CHECK_ENABLED = CFG.get("real_world_check_enabled", True)
REAL_WORLD_TARGETS = build_stage_b_targets(CFG.get("real_world_targets") or [
    {
        "url": "https://www.wikipedia.org/",
        "ok_statuses": [200],
        "expect_contains": ["wikipedia"],
    },
    {
        "url": "https://api.ipify.org?format=json",
        "ok_statuses": [200],
        "expect_json_key": "ip",
    },
    {
        "url": "https://www.cloudflare.com/cdn-cgi/trace",
        "ok_statuses": [200],
        "expect_contains": ["h=", "ip=", "ts="],
    },
])
REAL_WORLD_MIN_SUCCESS = max(1, int(CFG.get("real_world_min_success", 2)))
NONCE_PROBE_ENABLED = CFG.get("nonce_probe_enabled", True)
NONCE_PROBE_URLS = CFG.get("nonce_probe_urls") or [
    "https://httpbin.org/anything/{nonce}?r={nonce}",
    "https://postman-echo.com/get?nonce={nonce}",
]
NEGATIVE_PROBE_ENABLED = CFG.get("negative_probe_enabled", True)
NEGATIVE_PROBE_TARGETS = build_stage_b_targets(CFG.get("negative_probe_targets") or [
    {
        "url": "https://www.example.com/",
        "ok_statuses": [200],
        "expect_contains": ["example domain"],
    },
    {
        "url": "https://www.gnu.org/licenses/gpl-3.0.txt",
        "ok_statuses": [200],
        "expect_contains": ["gnu general public license"],
    },
])
NEGATIVE_PROBE_MIN_SUCCESS = max(1, int(CFG.get("negative_probe_min_success", 1)))

HEADERS = CFG.get("mobile_header_profiles", [{}])[0].get("headers", {})
HEADERS["User-Agent"] = CFG.get("mobile_header_profiles", [{}])[0].get("user_agent", "Mozilla/5.0")
STRICT_SNI_WHITELIST = CFG.get("mobile_whitelist_strict", True)
VERIFY_TLS_CERTS = CFG.get("verify_tls_certs", True)
STRICT_EGRESS_MATCH_SERVER_IP = CFG.get("strict_egress_match_server_ip", True)

# ================= GLOBAL =================

lock = Lock()
session = requests.Session()
session.verify = VERIFY_TLS_CERTS
if not VERIFY_TLS_CERTS:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

success_count = 0
fail_reasons = Counter()
report_items = []
success_ip_counter = Counter()

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
        uuidlib.UUID(str(value).strip())
        return True
    except ValueError:
        return False


def normalize_uuid(value):
    if value is None:
        return ""
    candidate = maybe_multi_unquote(str(value)).strip()
    if not candidate:
        return ""
    candidate = candidate.strip("{}")
    try:
        return str(uuidlib.UUID(candidate))
    except ValueError:
        return ""


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


def check_target_via_proxy(target, proxies, expected_server_ip=""):
    url = target["url"]
    r, _, err = do_request(url, proxies)
    if err:
        return False, "request_error"
    expected_host = urllib.parse.urlparse(url).hostname or ""
    final_host = urllib.parse.urlparse(r.url).hostname or ""
    body = (r.text or "")[:512].lower()
    allowed_statuses = set(target.get("ok_statuses") or [200])
    if r.status_code not in allowed_statuses:
        return False, f"bad_status={r.status_code}"
    if expected_host and final_host and expected_host != final_host:
        return False, f"host_mismatch={expected_host}->{final_host}"
    if expected_host and expected_host not in (final_host + body):
        return False, "host_not_in_body"
    expect_contains = [str(x).lower() for x in target.get("expect_contains", []) if str(x).strip()]
    if expect_contains and not all(marker in body for marker in expect_contains):
        return False, "missing_markers"
    expect_json_key = str(target.get("expect_json_key", "")).strip()
    if expect_json_key:
        try:
            data = r.json()
        except Exception:
            return False, "bad_json"
        if expect_json_key not in data:
            return False, f"missing_json_key={expect_json_key}"
        if (
            STRICT_EGRESS_MATCH_SERVER_IP
            and expected_server_ip
            and expect_json_key == "ip"
        ):
            detected_ip = str(data.get(expect_json_key, "")).strip()
            if detected_ip and detected_ip != expected_server_ip:
                return False, f"ip_mismatch={detected_ip}!={expected_server_ip}"
    expect_headers = target.get("expect_headers") or {}
    for header_name, expected_value in expect_headers.items():
        actual = str(r.headers.get(header_name, "")).lower()
        if str(expected_value).lower() not in actual:
            return False, f"missing_header_marker={header_name}"
    forbid_headers = target.get("forbid_headers") or {}
    for header_name, forbidden_value in forbid_headers.items():
        actual = str(r.headers.get(header_name, "")).lower()
        if actual and str(forbidden_value).lower() in actual:
            return False, f"forbidden_header_marker={header_name}"
    return True, "ok"


def nonce_probe_check(proxies):
    nonce = uuidlib.uuid4().hex[:12]
    for template in NONCE_PROBE_URLS:
        try:
            url = template.format(nonce=nonce)
            r, _, err = do_request(url, proxies)
            if err:
                continue
            if r.status_code != 200:
                continue
            final_host = urllib.parse.urlparse(r.url).hostname or ""
            expected_host = urllib.parse.urlparse(url).hostname or ""
            if expected_host and final_host and expected_host != final_host:
                continue
            payload = r.text or ""
            if nonce in payload:
                return True, f"nonce_ok host={final_host or expected_host}"
            try:
                data = r.json()
            except Exception:
                continue
            serialized = json.dumps(data, ensure_ascii=False)
            if nonce in serialized:
                return True, f"nonce_ok_json host={final_host or expected_host}"
        except Exception:
            continue
    return False, "nonce_probe_failed"


def run_validation_layers(proxies, expected_server_ip=""):
    result = {
        "ok": False,
        "latency_ms": None,
        "download_kbps": 0,
        "ip": "",
        "reason": "",
        "layer_trace": [],
    }

    # Layer A: handshake-equivalent real request set
    stage_a_latencies = []
    for url in STAGE_A_URLS:
        try:
            r, latency, err = do_request(url, proxies)
            if err:
                result["layer_trace"].append({"stage": "A", "url": url, "ok": False, "reason": err})
                if L7_REQUIRE_STAGE_A_ALL:
                    result["reason"] = f"stageA {err} {url}"
                    return result
                continue
            if r.status_code not in STAGE_A_OK_STATUSES:
                result["layer_trace"].append({"stage": "A", "url": url, "ok": False, "reason": f"bad_status={r.status_code}"})
                result["reason"] = f"stageA bad_status={r.status_code} {url}"
                if L7_REQUIRE_STAGE_A_ALL:
                    return result
                continue
            if HIJACK_GUARD_ENABLED:
                expected_host = urllib.parse.urlparse(url).hostname or ""
                final_host = urllib.parse.urlparse(r.url).hostname or ""
                if expected_host and final_host and expected_host != final_host:
                    result["layer_trace"].append({"stage": "A", "url": url, "ok": False, "reason": f"hijack {expected_host}->{final_host}"})
                    result["reason"] = f"stageA hijack {expected_host}->{final_host}"
                    return result
                server_header = str(r.headers.get("Server", "")).lower()
                forbidden_markers = STAGE_A_FORBIDDEN_SERVER_MARKERS.get(expected_host.lower(), [])
                if server_header and any(marker in server_header for marker in forbidden_markers):
                    result["layer_trace"].append({"stage": "A", "url": url, "ok": False, "reason": "suspicious_server_header"})
                    result["reason"] = f"stageA suspicious_server_header={server_header}"
                    return result
            stage_a_latencies.append(latency)
            result["layer_trace"].append({"stage": "A", "url": url, "ok": True, "latency_ms": int(latency)})
        except Exception as e:
            result["layer_trace"].append({"stage": "A", "url": url, "ok": False, "reason": type(e).__name__})
            result["reason"] = f"stageA {type(e).__name__} {url}"
            if L7_REQUIRE_STAGE_A_ALL:
                return result

    if not stage_a_latencies and STAGE_A_FALLBACK_ENABLED and STAGE_A_FALLBACK_URLS:
        for url in STAGE_A_FALLBACK_URLS:
            try:
                r, latency, err = do_request(url, proxies)
                if err:
                    continue
                if r.status_code not in STAGE_A_OK_STATUSES:
                    continue
                if HIJACK_GUARD_ENABLED:
                    expected_host = urllib.parse.urlparse(url).hostname or ""
                    final_host = urllib.parse.urlparse(r.url).hostname or ""
                    if expected_host and final_host and expected_host != final_host:
                        continue
                    server_header = str(r.headers.get("Server", "")).lower()
                    forbidden_markers = STAGE_A_FORBIDDEN_SERVER_MARKERS.get(expected_host.lower(), [])
                    if server_header and any(marker in server_header for marker in forbidden_markers):
                        continue
                stage_a_latencies.append(latency)
                result["layer_trace"].append({"stage": "A_fallback", "url": url, "ok": True, "latency_ms": int(latency)})
                break
            except Exception:
                continue

    if not stage_a_latencies:
        result["reason"] = result["reason"] or "stageA no successful probes"
        return result
    result["latency_ms"] = int(min(stage_a_latencies))

    # Layer B: anti-fallback check on non-whitelisted domains
    if not L7_STAGE_B_ENABLED or not STAGE_B_TARGETS:
        result["reason"] = "stageB disabled"
        return result

    stage_b_passed = False
    for target in STAGE_B_TARGETS:
        try:
            ok, reason = check_target_via_proxy(
                target,
                proxies,
                expected_server_ip=expected_server_ip,
            )
            result["layer_trace"].append({
                "stage": "B",
                "url": target["url"],
                "ok": ok,
                "reason": reason,
            })
            if ok:
                stage_b_passed = True
                break
        except Exception:
            continue
    if not stage_b_passed:
        result["reason"] = "stageB fallback_or_mismatch"
        return result

    # Layer F: real-world browsing profile (несколько доменов, минимум N успешных)
    if REAL_WORLD_CHECK_ENABLED and REAL_WORLD_TARGETS:
        passed = 0
        for target in REAL_WORLD_TARGETS:
            try:
                ok, reason = check_target_via_proxy(
                    target,
                    proxies,
                    expected_server_ip=expected_server_ip,
                )
                result["layer_trace"].append({
                    "stage": "F",
                    "url": target["url"],
                    "ok": ok,
                    "reason": reason,
                })
                if ok:
                    passed += 1
            except Exception:
                continue
        if passed < REAL_WORLD_MIN_SUCCESS:
            result["reason"] = f"stageF real_world_failed {passed}/{len(REAL_WORLD_TARGETS)}"
            return result
        result["real_world_passed"] = passed
    else:
        result["real_world_passed"] = 0

    # Layer G: nonce echo integrity (anti-facade / anti-static-fallback)
    if NONCE_PROBE_ENABLED:
        nonce_ok, nonce_reason = nonce_probe_check(proxies)
        result["layer_trace"].append({
            "stage": "G",
            "ok": nonce_ok,
            "reason": nonce_reason,
        })
        if not nonce_ok:
            result["reason"] = f"stageG {nonce_reason}"
            return result
        result["nonce_probe"] = nonce_reason

    # Layer H: negative probes (анти-фасадный набор мало-вероятных для fallback страниц)
    if NEGATIVE_PROBE_ENABLED and NEGATIVE_PROBE_TARGETS:
        passed = 0
        for target in NEGATIVE_PROBE_TARGETS:
            try:
                ok, reason = check_target_via_proxy(
                    target,
                    proxies,
                    expected_server_ip=expected_server_ip,
                )
                result["layer_trace"].append({
                    "stage": "H",
                    "url": target["url"],
                    "ok": ok,
                    "reason": reason,
                })
                if ok:
                    passed += 1
            except Exception:
                continue
        if passed < NEGATIVE_PROBE_MIN_SUCCESS:
            result["reason"] = f"stageH negative_probe_failed {passed}/{len(NEGATIVE_PROBE_TARGETS)}"
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
            result["layer_trace"].append({"stage": "C", "ok": False, "reason": result["reason"]})
            return result
        if kbps < REAL_DOWNLOAD_MIN_KBPS:
            result["reason"] = f"stageC low_speed={kbps}KB/s"
            result["layer_trace"].append({"stage": "C", "ok": False, "reason": result["reason"]})
            return result
        result["layer_trace"].append({"stage": "C", "ok": True, "bytes": total, "kbps": kbps})
    except Exception as e:
        result["reason"] = f"stageC {type(e).__name__}"
        result["layer_trace"].append({"stage": "C", "ok": False, "reason": result["reason"]})
        return result

    # Layer D: egress IP verification
    try:
        proxy_ip = get_echo_ip(proxies=proxies)
        result["ip"] = proxy_ip
        if not proxy_ip:
            if STAGE_D_FAIL_OPEN:
                result["ip"] = "unknown"
            else:
                result["reason"] = "stageD no_proxy_ip"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result
        if REJECT_PRIVATE_EGRESS_IP:
            parsed_ip = ipaddress.ip_address(proxy_ip) if proxy_ip and proxy_ip != "unknown" else None
            if parsed_ip and (parsed_ip.is_private or parsed_ip.is_loopback):
                result["reason"] = "stageD private_or_loopback_ip"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result

        if VERIFY_IP_NOT_LOCAL and proxy_ip and proxy_ip != "unknown":
            direct_ip = get_local_egress_ip()
            if direct_ip and direct_ip == proxy_ip:
                result["reason"] = "stageD same_as_local_ip"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result

        if STRICT_EGRESS_MATCH_SERVER_IP and expected_server_ip and proxy_ip and proxy_ip != "unknown":
            if proxy_ip != expected_server_ip:
                result["reason"] = f"stageD ip_mismatch proxy={proxy_ip} expected={expected_server_ip}"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result

        if VERIFY_EGRESS_IP and proxy_ip and proxy_ip != "unknown":
            direct_ip = get_local_egress_ip()
            if not direct_ip:
                result["reason"] = "stageD cannot_get_local_ip"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result

        if (EXPECTED_COUNTRY_CODES or EXPECTED_ASN_NUMBERS or EXPECTED_ASN_PREFIXES) and proxy_ip and proxy_ip != "unknown":
            info = fetch_ip_info(proxy_ip)
            cc = (info or {}).get("countryCode", "")
            if EXPECTED_COUNTRY_CODES and cc and cc not in EXPECTED_COUNTRY_CODES:
                result["reason"] = f"stageD wrong_country={cc}"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result
            asn_num = extract_asn_number(info)
            if EXPECTED_ASN_NUMBERS and asn_num not in EXPECTED_ASN_NUMBERS:
                result["reason"] = f"stageD wrong_asn={asn_num}"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
                return result
            as_name = str((info or {}).get("asname") or "").upper()
            if EXPECTED_ASN_PREFIXES and not any(as_name.startswith(p) for p in EXPECTED_ASN_PREFIXES):
                result["reason"] = "stageD wrong_as_name"
                result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"], "asname": as_name})
                return result
            result["egress_geo"] = {
                "countryCode": cc,
                "as": (info or {}).get("as", ""),
                "asname": (info or {}).get("asname", ""),
            }
    except Exception as e:
        if not STAGE_D_FAIL_OPEN:
            result["reason"] = f"stageD {type(e).__name__}"
            result["layer_trace"].append({"stage": "D", "ok": False, "reason": result["reason"]})
            return result
        result["ip"] = result["ip"] or "unknown"

    result["ok"] = True
    result["reason"] = "all_layers_passed"
    result["layer_trace"].append({"stage": "D", "ok": True, "ip": result["ip"]})
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
        alpns, _ = parse_alpn_list(params)
        if alpns:
            stream_settings["realitySettings"]["alpn"] = alpns

    elif security == "tls":
        stream_settings["tlsSettings"] = {"serverName": sni}
        alpns, _ = parse_alpn_list(params)
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
    normalized_link = normalize_vless_link(link)
    metadata = {
        "index": idx,
        "link": normalized_link,
        "original_link": link,
        "status": "DEAD",
        "latency_ms": None,
        "download_kbps": 0,
        "ip": "",
        "classification": "unknown",
        "reason": "",
        "remark": "",
    }

    try:
        parsed = urllib.parse.urlparse(normalized_link)

        if parsed.scheme != "vless":
            metadata["reason"] = "❌ не VLESS"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        raw_uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        params = urllib.parse.parse_qs(parsed.query)
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
        metadata["remark"] = remark
        metadata["raw_uuid"] = raw_uuid
        alpns, alpn_malformed = parse_alpn_list(params)
        metadata["alpn"] = alpns
        metadata["alpn_malformed"] = alpn_malformed
        if alpn_malformed:
            print(f"⚠️ [{idx}] ALPN нормализован: {get_param(params, 'alpn', '')} -> {','.join(alpns) or 'none'}")

        uuid = normalize_uuid(raw_uuid)
        metadata["uuid"] = uuid
        expected_server_ip = resolve_expected_server_ip(host)
        metadata["expected_server_ip"] = expected_server_ip

        if not uuid or not host:
            metadata["reason"] = "❌ битый VLESS (нет uuid/host)"
            metadata["classification"] = classify_result(False, metadata["reason"])
            return False, metadata["reason"], metadata

        if not is_valid_uuid(raw_uuid):
            metadata["reason"] = "❌ невалидный UUID"
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
        attempt_runs = []
        last_reason = "no_attempts"
        for attempt_idx in range(STABILITY_ATTEMPTS):
            run = run_validation_layers(proxies, expected_server_ip=expected_server_ip)
            attempt_runs.append({
                "attempt": attempt_idx + 1,
                "ok": run.get("ok", False),
                "reason": run.get("reason", ""),
                "latency_ms": run.get("latency_ms"),
                "download_kbps": run.get("download_kbps", 0),
                "ip": run.get("ip", ""),
                "layer_trace": run.get("layer_trace", []),
            })
            if run["ok"]:
                success_runs.append(run)
            else:
                last_reason = run["reason"]
            time.sleep(SLEEP_BETWEEN)
        metadata["attempt_runs"] = attempt_runs

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
        metadata["why_accepted"] = {
            "stable_successes": f"{len(success_runs)}/{STABILITY_ATTEMPTS}",
            "best_latency_ms": metadata["latency_ms"],
            "best_download_kbps": metadata["download_kbps"],
            "egress_ip": metadata["ip"],
            "layer_trace": best.get("layer_trace", []),
            "nonce_probe": best.get("nonce_probe", ""),
            "real_world_passed": best.get("real_world_passed", 0),
            "egress_geo": best.get("egress_geo", {}),
        }
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

        ensure_parent_dir(RESULTS_FILE)

        with open(RESULTS_FILE, "a") as f:
            f.write(link.strip() + "\n")

        success_count += 1
        print(f"💾 [{success_count}/{MAX_SUCCESS}]")

        return True


def reserve_success_ip(ip_value):
    if MAX_SUCCESS_PER_EGRESS_IP <= 0:
        return True
    ip = (ip_value or "").strip()
    if not ip or ip == "unknown":
        return True
    with lock:
        if success_ip_counter[ip] >= MAX_SUCCESS_PER_EGRESS_IP:
            return False
        success_ip_counter[ip] += 1
    return True


def save_report():
    ensure_parent_dir(REPORT_FILE)
    payload = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "paths": {
            "targets_file": TARGETS_PATH,
            "results_file": RESULTS_FILE,
            "report_file": REPORT_FILE,
        },
        "summary": {
            "checked": len(report_items),
            "ok": sum(1 for i in report_items if i.get("status") == "WORKING"),
            "provider_block_suspected": sum(1 for i in report_items if i.get("classification") == "provider_block_suspected"),
            "bad_uuid_or_link": sum(1 for i in report_items if i.get("classification") == "bad_uuid_or_link"),
            "duplicate_egress_ip": sum(1 for i in report_items if i.get("classification") == "duplicate_egress_ip"),
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

    temp_report_file = f"{REPORT_FILE}.tmp"
    with open(temp_report_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    os.replace(temp_report_file, REPORT_FILE)

    print(f"🧾 report: {os.path.abspath(REPORT_FILE)}")

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

    ensure_parent_dir(RESULTS_FILE)
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
        f"stage_b_enabled={L7_STAGE_B_ENABLED}({len(STAGE_B_TARGETS)} targets), "
        f"real_world={REAL_WORLD_CHECK_ENABLED}({REAL_WORLD_MIN_SUCCESS}/{len(REAL_WORLD_TARGETS)}), "
        f"nonce_probe={NONCE_PROBE_ENABLED}, "
        f"mimic_dpi_delay={MIMIC_DPI_DELAY}, "
        f"network_emu={NET_EMU_ENABLED}\n"
    )

    with ThreadPoolExecutor(MAX_WORKERS) as ex:
        futures = {ex.submit(check_link, link, i): link for i, link in enumerate(links)}

        for f in as_completed(futures):
            if success_count >= MAX_SUCCESS:
                print("🛑 лимит достигнут")
                break

            try:
                result = f.result()
            except Exception as e:
                reason = f"💥 future_error {type(e).__name__}"
                print(f"❌ {reason}")
                fail_reasons[reason] += 1
                report_items.append({
                    "index": -1,
                    "link": futures[f],
                    "status": "DEAD",
                    "latency_ms": None,
                    "download_kbps": 0,
                    "ip": "",
                    "classification": "unknown",
                    "reason": reason,
                    "remark": "",
                })
                continue
            if result is None:
                continue

            ok, reason, metadata = result
            if ok and not reserve_success_ip(metadata.get("ip", "")):
                ok = False
                reason = f"❌ duplicate_egress_ip limit={MAX_SUCCESS_PER_EGRESS_IP} ip={metadata.get('ip', '')}"
                metadata["status"] = "DEAD"
                metadata["reason"] = reason
                metadata["classification"] = "duplicate_egress_ip"

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
