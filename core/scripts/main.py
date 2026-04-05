import json
import time
import os
from v2ray_python.rpc import V2RayClient

# Загружаем твой навороченный конфиг
with open('config_test.json', 'r') as f:
    config = json.load(f)

client = V2RayClient(config['xray_api_host'], config['xray_api_port'])

# Путь к результатам
RESULTS_FILE = "results/valid.txt"

def save_result(link):
    # Создаем папку, если её нет
    os.makedirs(os.path.dirname(RESULTS_FILE), exist_ok=True)
    
    with open(RESULTS_FILE, "a", encoding="utf-8") as f:
        f.write(link + "\n")

# В основной логике:
if check_vless_link(l): # Если проверка пройдена
    save_result(l)
    print(f"[OK] Сохранено в {RESULTS_FILE}")

def check_vless_link(link):
    # Упрощенный парсинг UUID из ссылки vless://uuid@host...
    try:
        uuid = link.split('@')[0].split('//')[1]
        remark = link.split('#')[1] if '#' in link else uuid[:8]
        
        print(f"[*] Проверка {remark} (UUID: {uuid})...")
        
        # Запрашиваем статистику (email в Xray обычно равен UUID или задан в базе)
        stats = client.get_user_stats(uuid) 
        
        if stats and stats.downlink >= config['xray_stats_min_downlink_bytes']:
            print(f"[+] {remark}: РАБОТАЕТ. Трафик: {stats.downlink} байт")
            return True
        else:
            print(f"[-] {remark}: НЕБОЕВОЙ. Трафика 0 или UUID не найден в API")
            return False
    except Exception as e:
        print(f"[!] Ошибка парсинга: {e}")
        return False

if __name__ == "__main__":
    with open('targets.txt', 'r') as f:
        links = f.read().splitlines()
        
    for l in links:
        if l.strip():
            check_vless_link(l)
