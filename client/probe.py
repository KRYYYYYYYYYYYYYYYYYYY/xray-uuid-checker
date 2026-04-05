import subprocess
import time
import socket


def wait_socks(port=10808, timeout=5):
    for _ in range(timeout * 10):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except:
            time.sleep(0.1)
    return False


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

        print("[*] Проверка соединения...")

        curl_cmd = [
            "curl",
            "-x", "socks5h://127.0.0.1:10808",
            "-I",  # только заголовки
            "https://clients3.google.com/generate_204",
            "--max-time", "10",
            "-A", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.0.0 Mobile Safari/537.36"
        ]

        result = subprocess.run(curl_cmd, capture_output=True, text=True)

        if "204" in result.stdout or "200" in result.stdout:
            print("[+] ПРОКСИ РАБОТАЕТ")
            return True
        else:
            print("[-] Ответ невалидный:")
            print(result.stdout)
            return False

    finally:
        process.terminate()
        process.wait()
