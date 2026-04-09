import json
import os
import subprocess
import time
import requests
from v2ray_python.rpc import V2RayClient

# Конфигурация
CONFIG_PATH = 'config_test.json'
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "./core/xray"
TEMP_CONFIG = "temp_config.json"

def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")

def generate_xray_config(uuid, host, port, sni):
    """Создает минимальный конфиг клиента для теста"""
    return {
        "log": {"loglevel": "none"},
        "stats": {},
        "api": {"tag": "api", "services": ["StatsService"]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": [{
            "port": 10085, "listen": "127.0.0.1", "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"}, "tag": "api"
        }, {
            "port": 10808, "listen": "127.0.0.1", "protocol": "socks", "settings": {"udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{"address": host, "port": int(port), "users": [{"id": uuid, "encryption": "none"}]}]},
            "streamSettings": {"network": "tcp", "security": "none"}, # Тут можно добавить Reality/TLS из параметров ссылки
            "tag": "proxy"
        }, {"protocol": "freedom", "tag": "direct"}]
    }

def check_vless_link(link):
    process = None
    try:
        # Базовый парсинг (uuid, host, port)
        payload = link.split("://")[1].split("#")[0]
        uuid_part, address_part = payload.split("@")
        host, port = address_part.split("?")[0].split(":")
        
        # Создаем конфиг и запускаем Xray
        with open(TEMP_CONFIG, 'w') as f:
            json.dump(generate_xray_config(uuid_part, host, port, host), f)
        
        process = subprocess.Popen([XRAY_BIN, "run", "-c", TEMP_CONFIG], stdout=subprocess.DEVNULL)
        time.sleep(2) # Ждем инициализации

        # Проверка: пробуем сделать запрос через SOCKS5 прокси поднятого Xray
        proxies = {'http': 'socks5h://127.0.0.1:10808', 'https': 'socks5h://127.0.0.1:10808'}
        resp = requests.get("http://google.com", proxies=proxies, timeout=5)
        
        if resp.status_code == 204:
            print(f"[+] {host}: РАБОТАЕТ")
            return True
    except Exception as e:
        print(f"[-] Ошибка: {e}")
    finally:
        if process: process.terminate()
        if os.path.exists(TEMP_CONFIG): os.remove(TEMP_CONFIG)
    return False

if __name__ == "__main__":
    if not os.path.exists('targets.txt'):
        print("[!] targets.txt не найден"); exit(1)

    with open('targets.txt', 'r') as f:
        links = f.read().splitlines()
        
    for link in links:
        if link.strip() and check_vless_link(link.strip()):
            save_result(link.strip())
