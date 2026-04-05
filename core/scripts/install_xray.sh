#!/bin/bash
set -e

mkdir -p ./core

# Фиксированная версия, чтобы не зависеть от капризов API GitHub
VERSION="v1.8.24"
URL="https://github.com{VERSION}/Xray-linux-64.zip"

echo "[*] Попытка скачивания: $URL"

# Используем флаг -sS (silent, но показывать ошибки) и -L (редиректы)
if curl -sSL -o xray.zip "$URL"; then
    echo "[+] Файл xray.zip успешно скачан."
else
    echo "[!] Ошибка при скачивании. Проверь URL или интернет."
    exit 1
fi

echo "[*] Распаковка в ./core..."
unzip -o xray.zip -d ./core

if [ -f "./core/xray" ]; then
    chmod +x ./core/xray
    echo "[SUCCESS] Xray установлен:"
    ./core/xray version
else
    echo "[ERROR] Бинарник xray не найден!"
    exit 1
fi

rm -f xray.zip
