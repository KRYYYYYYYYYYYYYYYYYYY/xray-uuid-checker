import json
import time
import os
import subprocess
import requests
import urllib.parse

CONFIG_PATH = 'config_test.json'
TARGETS_PATH = 'targets.txt'
RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "/usr/local/bin/xray" 
TEMP_CONFIG = "temp_client_config.json"

def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    existing = []
    if os.path.exists(RESULTS_FILE):
        with open(RESULTS_FILE, "r", encoding="utf-8") as f:
            existing = [l.strip() for l in f]
    if link not in existing:
        with open(RESULTS_FILE, "a", encoding="utf-8") as f:
            f.write(link + "\n")
        print(f"[SUCCESS] Добавлено в {RESULTS_FILE}")

def generate_temp_config(uuid, host, port, params):
    # Извлекаем параметры безопасности
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
        "inbounds": [{"port": 10808, "listen": "127.0.0.1", "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host, 
                    "port": int(port), 
                    "users": [{"id": uuid, "encryption": "none", "flow": flow}]
                }]
            },
            "streamSettings": stream_settings
        }]
    }

def check_vless_link(link):
    process = None
    try:
        # Умный парсинг через urllib
        parsed = urllib.parse.urlparse(link)
        if parsed.scheme != 'vless': return False
        
        uuid = parsed.username
        host = parsed.hostname
        port = parsed.port or 443
        # Вытаскиваем параметры (?security=reality&sni=...)
        params = urllib.parse.parse_qs(parsed.query)
        # Название из фрагмента (#Name)
        remark = urllib.parse.unquote(parsed.fragment) if parsed.fragment else host
        
        print(f"[*] Проверка: {remark} ({host}:{port}) | Sec: {params.get('security',['none'])[0]}")

        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_temp_config(uuid, host, port, params), f)
        
        process = subprocess.Popen([XRAY_BIN, "run", "-c", TEMP_CONFIG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) 

        proxies = {'http': 'socks5h://127.0.0.1:10808', 'https': 'socks5h://127.0.0.1:10808'}
        # Точный URL для 204
        resp = requests.get("http://gstatic.com", proxies=proxies, timeout=12)
        
        if resp.status_code == 204:
            print(f"[+] {remark}: РАБОТАЕТ")
            return True
        else:
            print(f"[-] {remark}: Ошибка (Status: {resp.status_code})")
    except Exception as e:
        print(f"[-] Ошибка: {e}")
    finally:
        if process:
            process.terminate()
            process.wait()
        if os.path.exists(TEMP_CONFIG):
            os.remove(TEMP_CONFIG)
    return False

if __name__ == "__main__":
    if not os.path.exists(TARGETS_PATH):
        print(f"[!] {TARGETS_PATH} не найден!"); exit(1)

    with open(TARGETS_PATH, 'r') as f:
        links = [l.strip() for l in f if l.strip()]
        
    print(f"[*] Найдено ссылок: {len(links)}")
    for link in links:
        if check_vless_link(link):
            save_result(link)
