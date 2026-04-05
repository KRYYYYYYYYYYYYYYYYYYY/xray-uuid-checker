import os
import subprocess

def run_test_connection(config_path):
    print("[*] Запуск тестового соединения через Xray core...")
    # Команда запускает xray локально с вашим UUID и пробует скачать страницу
    # Это создаст всплеск трафика, который поймает серверный скрипт
    cmd = f"xray run -c {config_path} & sleep 5 && curl -x socks5://127.0.0.1:10808 http://google.com && pkill xray"
    os.system(cmd)

# Этот скрипт имитирует активность пользователя
