#!/bin/bash
set -e

# Создаем папку для ядра
mkdir -p ./core

echo "[*] Определение последней версии Xray..."
# Используем более надежный способ получения тега
VERSION=$(curl -sL https://github.com | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$VERSION" ]; then
    echo "[!] Не удалось получить версию. Используем дефолтную v1.8.23"
    VERSION="v1.8.23"
fi

URL="https://github.com{VERSION}/Xray-linux-64.zip"
echo "[*] Скачивание Xray ${VERSION} из ${URL}..."

# Скачиваем с флагом -L для следования редиректам
curl -L -o xray.zip "$URL"

if [ ! -f xray.zip ]; then
    echo "[!] Файл xray.zip не скачался!"
    exit 1
fi

echo "[*] Распаковка..."
unzip -o xray.zip -d ./core

if [ -f ./core/xray ]; then
    chmod +x ./core/xray
    echo "[+] Xray успешно установлен в ./core/xray"
    ./core/xray version
else
    echo "[!] Бинарный файл xray не найден после распаковки!"
    exit 1
fi

# Убираем мусор
rm xray.zip
