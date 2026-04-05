#!/bin/bash
# Скачиваем в корень, распаковываем в ./core/
mkdir -p ./core
VERSION=$(curl -s https://github.com | grep tag_name | cut -d '"' -f 4)
URL="https://github.com{VERSION}/Xray-linux-64.zip"

curl -L -o xray.zip "$URL"
unzip -o xray.zip -d ./core
chmod +x ./core/xray
