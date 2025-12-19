#!/usr/bin/env bash
set -e

echo "======================================="
echo "  Network Scanner & ARP Inspector"
echo "  Author: Reza Javadi"
echo "  GitHub: https://github.com/rezajavadi995"
echo "======================================="
echo

# فقط لینوکس
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
  echo "[!] این اسکریپت فقط روی لینوکس اجرا می‌شود"
  exit 1
fi

# بررسی Python3
if ! command -v python3 >/dev/null 2>&1; then
  echo "[+] Python3 نصب نیست، در حال نصب..."
  sudo apt update
  sudo apt install -y python3
fi

# بررسی curl
if ! command -v curl >/dev/null 2>&1; then
  echo "[+] curl نصب نیست، در حال نصب..."
  sudo apt update
  sudo apt install -y curl
fi

INSTALL_DIR="/opt/network-scanner"
BIN_PATH="/usr/local/bin/netscan"

echo "[+] ساخت مسیر نصب: $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"

cd "$INSTALL_DIR"

echo "[+] دانلود اسکریپت اصلی از GitHub..."
curl -fsSL \
https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/network_scan.py \
-o network_scan.py

if [[ ! -f "network_scan.py" ]]; then
  echo "[!] خطا در دانلود فایل"
  exit 1
fi

chmod +x network_scan.py

# ساخت symlink اجرایی
if [[ -L "$BIN_PATH" || -f "$BIN_PATH" ]]; then
  echo "[*] لینک اجرایی قبلاً وجود دارد، بازنویسی می‌شود"
  sudo rm -f "$BIN_PATH"
fi

sudo ln -s "$INSTALL_DIR/network_scan.py" "$BIN_PATH"

echo
echo "[✓] نصب با موفقیت انجام شد"
echo
echo "برای اجرا از هرجای سیستم:"
echo "sudo netscan"
echo
echo "مسیر نصب:"
echo "$INSTALL_DIR"
echo
