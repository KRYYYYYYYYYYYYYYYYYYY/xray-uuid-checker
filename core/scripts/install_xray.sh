#!/bin/bash
VERSION=$(curl -s https://github.com | jq -r .tag_name)
PLATFORM="linux-64" # или darwin-64 / windows-64
URL="https://github.com{VERSION}/Xray-${PLATFORM}.zip"

curl -L -o xray.zip $URL
unzip xray.zip -d ./core
chmod +x ./core/xray
