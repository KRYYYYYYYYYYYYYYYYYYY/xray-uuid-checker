import json
import time
import os
import subprocess
import requests

CONFIG_PATH = 'config_test.json'
TARGETS_PATH = 'targets.txt'
RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "/usr/local/bin/xray" 
TEMP_CONFIG = "temp_client_config.json"

# Загружаем конфиг (проверяем наличие)
if os.path.exists(CONFIG_PATH):
    with open(CONFIG_PATH, 'r') as f:
        config = json.load(f)
else:
    config = {"xray_stats_min_downlink_bytes": 1}

def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")

def generate_temp_config(uuid, host, port):
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": 10808, "listen": "127.0.0.1", "protocol": "socks"}],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": int(port), "users": [{"id": uuid, "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "none"}
        }]
    }

def check_vless_link(link):
    process = None
    try:
        # Чистим ссылку от мусора
        base_link = link.split('#')[0]
        remark = link.split('#')[1] if '#' in link else "NoName"
        
        # Вынимаем UUID и Адрес
        uuid = base_link.split('://')[1].split('@')[0]
        address = base_link.split('@')[1].split('?')[0]
        host, port = address.split(':')
        
        print(f"[*] Проверка {remark} ({host}:{port})...")

        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_temp_config(uuid, host, port), f)
        
        process = subprocess.Popen([XRAY_BIN, "run", "-c", TEMP_CONFIG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) 

        proxies = {'http': 'socks5h://127.0.0.1:10808', 'https': 'socks5h://127.0.0.1:10808'}
        # Используем 204 для быстрой проверки
        resp = requests.get("http://google.com", proxies=proxies, timeout=7)
        
        if resp.status_code == 204:
            print(f"[+] {remark}: РАБОТАЕТ")
            return True
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
        print(f"[!] {TARGETS_PATH} не найден!")
        exit(1)

    with open(TARGETS_PATH, 'r') as f:
        links = [l.strip() for l in f if l.strip()]
        
    print(f"[*] Найдено ссылок: {len(links)}")
    for link in links:
        if check_vless_link(link):
            save_result(link)
