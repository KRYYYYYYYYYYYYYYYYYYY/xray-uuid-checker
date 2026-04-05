import json
import time
import os
import subprocess
import requests
import re

CONFIG_PATH = 'config_test.json'
TARGETS_PATH = 'targets.txt'
RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "/usr/local/bin/xray" 
TEMP_CONFIG = "temp_client_config.json"

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
        # 1. Более надежный парсинг через регулярки или умный split
        remark = link.split('#')[1] if '#' in link else "NoName"
        clean_link = link.split('#')[0].replace('vless://', '')
        
        auth_part, address_part = clean_link.split('@')
        uuid = auth_part
        
        # Очищаем адрес от параметров (?...) и слешей
        host_port = address_part.split('?')[0].split('/')[0]
        if ':' in host_port:
            host, port_raw = host_port.split(':')
            port = int(''.join(filter(str.isdigit, port_raw)))
        else:
            host = host_port
            port = 443
        
        print(f"[*] Проверка {remark} ({host}:{port})...")

        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_temp_config(uuid, host, port), f)
        
        # Запускаем Xray
        process = subprocess.Popen([XRAY_BIN, "run", "-c", TEMP_CONFIG], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3) # Ждем прогрузки

        # 2. Правильный URL для проверки статуса 204
        proxies = {'http': 'socks5h://127.0.0.1:10808', 'https': 'socks5h://127.0.0.1:10808'}
        resp = requests.get("http://gstatic.com", proxies=proxies, timeout=10)
        
        if resp.status_code == 204:
            print(f"[+] {remark}: РАБОТАЕТ")
            return True
        else:
            print(f"[-] {remark}: Ошибка (Status: {resp.status_code})")
            
    except Exception as e:
        print(f"[-] Ошибка парсинга или связи: {e}")
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

    # Очищаем файл результатов перед новым запуском (опционально)
    if os.path.exists(RESULTS_FILE):
        os.remove(RESULTS_FILE)

    with open(TARGETS_PATH, 'r') as f:
        links = [l.strip() for l in f if l.strip()]
        
    print(f"[*] Найдено ссылок: {len(links)}")
    for link in links:
        if check_vless_link(link):
            save_result(link)
