import subprocess
import time
import socket
import requests
import random
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WHITELIST_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"


# ================= LOAD WHITELIST =================

def load_whitelist():
    try:
        r = requests.get(WHITELIST_URL, timeout=10)
        domains = [d.strip() for d in r.text.splitlines() if d.strip()]

        if not domains:
            raise Exception("Whitelist пуст")

        print(f"[+] Whitelist: {len(domains)} доменов")
        return domains

    except Exception as e:
        print(f"[!] Ошибка загрузки whitelist: {e}")
        return []


WHITELIST = load_whitelist()


# ================= UTILS =================

def wait_socks(port=10808, timeout=5):
    for _ in range(timeout * 10):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except:
            time.sleep(0.1)
    return False


# ================= CORE =================

def run_test_connection(config_path):
    print("[*] Запуск Xray...")

    process = subprocess.Popen(
        ["xray", "run", "-c", config_path],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    try:
        if not wait_socks():
            print("[-] Xray не поднялся")
            return False

        if not WHITELIST:
            print("[-] Whitelist пуст — пропуск проверки")
            return False

        print("[*] Проверка через whitelist...")

        proxies = {
            "http": "socks5h://127.0.0.1:10808",
            "https": "socks5h://127.0.0.1:10808"
        }

        # берём случайные домены (важно!)
        test_domains = random.sample(WHITELIST, min(5, len(WHITELIST)))

        success = 0

        for domain in test_domains:
            url = f"https://{domain}"

            try:
                r = requests.get(
                    url,
                    proxies=proxies,
                    timeout=10,
                    verify=False,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Android 14; Mobile)",
                        "Accept-Language": "ru,en;q=0.9"
                    }
                )

                if r.status_code < 500:
                    print(f"[+] OK через {domain}")
                    success += 1

                    # 💡 ключевая логика: не один домен, а минимум 2
                    if success >= 2:
                        print("[+] ПРОКСИ РАБОТАЕТ (multi-check)")
                        return True

            except:
                continue

        print("[-] Недостаточно успешных запросов")
        return False

    finally:
        process.terminate()
        process.wait()
