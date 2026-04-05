import json
import time
import os
import subprocess
from v2ray_python.rpc import V2RayClient

# 1. Загружаем конфиг
CONFIG_PATH = 'config_test.json'
with open(CONFIG_PATH, 'r') as f:
    config = json.load(f)

RESULTS_FILE = "results/valid.txt"
XRAY_BIN = "./core/xray" # Путь, куда скачали ядро

def save_result(link):
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")

def check_vless_link(link):
    try:
        # Парсим UUID: vless://UUID@host...
        parts = link.split('//')[1].split('@')
        uuid = parts[0]
        remark = link.split('#')[1] if '#' in link else uuid[:8]
        
        print(f"[*] Проверка {remark} (UUID: {uuid})...")

        # --- ТУТ ДОЛЖЕН БЫТЬ ЗАПУСК XRAY С ЭТИМ UUID ---
        # Для полноценной проверки нужно сгенерировать временный config.json 
        # и запустить Xray. Но пока проверим через API уже запущенного сервера:
        
        client = V2RayClient(config['xray_api_host'], config['xray_api_port'])
        stats = client.get_user_stats(uuid) 
        
        if stats and stats.downlink >= config.get('xray_stats_min_downlink_bytes', 1):
            print(f"[+] {remark}: РАБОТАЕТ. Трафик: {stats.downlink} байт")
            return True
        else:
            print(f"[-] {remark}: НЕТ ТРАФИКА (Блокировка или неверный ID)")
            return False
    except Exception as e:
        print(f"[!] Ошибка парсинга {link}: {e}")
        return False

if __name__ == "__main__":
    # Проверяем наличие входного файла
    if not os.path.exists('targets.txt'):
        print("[!] Файл targets.txt не найден!")
        exit(1)

    with open('targets.txt', 'r') as f:
        links = f.read().splitlines()
        
    for l in links:
        link = l.strip()
        if link:
            if check_vless_link(link):
                save_result(link)
                print(f"[OK] Сохранено в {RESULTS_FILE}")
