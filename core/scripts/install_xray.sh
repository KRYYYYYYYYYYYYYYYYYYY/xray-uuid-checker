#!/bin/bash
set -e
# Получаем последнюю версию
VERSION=$(curl -s https://github.com | grep tag_name | cut -d '"' -f 4)
echo "Downloading Xray $VERSION..."
URL="https://github.com{VERSION}/Xray-linux-64.zip"

curl -L -o xray.zip "$URL"
unzip -o xray.zip -d ./core
chmod +x ./core/xray
echo "Xray installed to ./core/xray"
