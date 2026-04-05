import json
import time
import os
import subprocess
import requests

# 1. Загружаем конфиг
CONFIG_PATH = 'config_test.json'
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

RESULTS_FILE = "results/valid.txt"
# В логах было видно, что скрипт ставит xray в /usr/local/bin/xray
XRAY_BIN = "/usr/local/bin/xray" 
TEMP_CONFIG = "temp_client_config.json"

def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")

def generate_temp_config(uuid, host, port):
    """Генерирует конфиг для проверки связи через SOCKS5"""
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
        # Парсим UUID и адрес
        addr_part = link.split('//')[1].split('#')[0]
        uuid = addr_part.split('@')[0]
        host_port = addr_part.split('@')[1].split('?')[0]
        host, port = host_port.split(':')
        
        remark = link.split('#')[1] if '#' in link else uuid[:8]
        print(f"[*] Проверка {remark} (Host: {host})...")

        # Создаем конфиг и запускаем Xray
        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_temp_config(uuid, host, port), f)
        
        process = subprocess.Popen([XRAY_BIN, "run", "-c", TEMP_CONFIG], stdout=subprocess.DEVNULL)
        time.sleep(2) # Даем время на запуск

        # РЕАЛЬНАЯ ПРОВЕРКА: идем в интернет через поднятый SOCKS5
        proxies = {'http': 'socks5h://127.0.0.1:10808', 'https': 'socks5h://127.0.0.1:10808'}
        resp = requests.get("http://google.com", proxies=proxies, timeout=5)
        
        if resp.status_code == 204:
            print(f"[+] {remark}: РАБОТАЕТ (Провайдер OK)")
            return True
    except Exception as e:
        print(f"[-] {link}: Ошибка ({e})")
    finally:
        if process: process.terminate()
        if os.path.exists(TEMP_CONFIG): os.remove(TEMP_CONFIG)
    return False

if __name__ == "__main__":
    if not os.path.exists('targets.txt'):
        print("[!] Файл targets.txt не найден!")
        exit(1)

    with open('targets.txt', 'r') as f:
        links = f.read().splitlines()
        
    for l in links:
        link = l.strip()
        if link and check_vless_link(link):
            save_result(link)
            print(f"[OK] Сохранено в {RESULTS_FILE}")
