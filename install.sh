#!/usr/bin/env bash
set -e

echo "======================================="
echo "  Network Scanner & ARP Inspector"
echo "  Author: Reza Javadi"
echo "  GitHub: https://github.com/rezajavadi995"
echo "======================================="
echo


if [[ "$OSTYPE" != "linux-gnu"* ]]; then
  echo "[!] این اسکریپت فقط روی لینوکس اجرا می‌شود"
  exit 1
fi


if ! command -v python3 &>/dev/null; then
  echo "[+] Python3 نصب نیست، در حال نصب..."
  sudo apt update
  sudo apt install -y python3
fi


if ! command -v curl &>/dev/null; then
  echo "[+] curl نصب نیست، در حال نصب..."
  sudo apt update
  sudo apt install -y curl
fi


INSTALL_DIR="/opt/network-scanner"

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

echo
echo "[✓] نصب با موفقیت انجام شد"
echo
echo "برای اجرا دستور زیر را بزن:"
echo
echo "sudo python3 $INSTALL_DIR/network_scan.py"
echo
echo "یا اگر خواستی alias بسازی:"
echo "alias netscan='sudo python3 $INSTALL_DIR/network_scan.py'"
echo
