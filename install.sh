#!/usr/bin/env bash
set -e

# =======================================
#  Network Scanner & ARP Inspector
#  Author: Reza Javadi
#  GitHub: https://github.com/rezajavadi995
# =======================================
echo

# فقط لینوکس
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
  echo "[!] This script runs only on Linux"
  exit 1
fi

# -------------------------------
# انتخاب زبان (پایدار)
# -------------------------------
echo "Select language / انتخاب زبان:"
echo "1) English"
echo "2) فارسی"
read -p "> " LANG_CHOICE

if [[ "$LANG_CHOICE" == "2" ]]; then
  NETSCAN_LANG="fa"
else
  NETSCAN_LANG="en"
fi

# -------------------------------
# تابع چاپ پیام دوزبانه
# -------------------------------
msg() {
  local fa="$1"
  local en="$2"

  if [[ "$NETSCAN_LANG" == "fa" ]]; then
    echo "$fa"
  else
    echo "$en"
  fi
}

# -------------------------------
# بررسی پیش‌نیازها
# -------------------------------
if ! command -v python3 >/dev/null 2>&1; then
  msg "[+] Python3 نصب نیست، در حال نصب..." "[+] Python3 not found, installing..."
  sudo apt update
  sudo apt install -y python3
fi

if ! command -v curl >/dev/null 2>&1; then
  msg "[+] curl نصب نیست، در حال نصب..." "[+] curl not found, installing..."
  sudo apt update
  sudo apt install -y curl
fi

if ! command -v ip >/dev/null 2>&1; then
  msg "[+] iproute2 نصب نیست، در حال نصب..." "[+] iproute2 not found, installing..."
  sudo apt update
  sudo apt install -y iproute2
fi

if ! command -v ping >/dev/null 2>&1; then
  msg "[+] ping نصب نیست، در حال نصب..." "[+] ping not found, installing..."
  sudo apt update
  sudo apt install -y iputils-ping
fi

# -------------------------------
# مسیرها
# -------------------------------
INSTALL_DIR="/opt/network-scanner"
BIN_PATH="/usr/local/bin/netscan"
CONF_FILE="$INSTALL_DIR/.netscan.conf"

# تشخیص نصب قبلی
if [[ -d "$INSTALL_DIR" && -f "$INSTALL_DIR/network_scan.py" ]]; then
  msg "[*] نصب قبلی شناسایی شد → بروزرسانی" "[*] Existing installation detected → Updating"
else
  msg "[*] نصب جدید" "[*] Fresh installation"
fi

# -------------------------------
# ساخت مسیر نصب
# -------------------------------
msg "[+] ساخت مسیر نصب: $INSTALL_DIR" "[+] Creating install directory: $INSTALL_DIR"
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"

cd "$INSTALL_DIR"

# -------------------------------
# دانلود اسکریپت اصلی
# -------------------------------
msg "[+] دانلود اسکریپت اصلی از GitHub..." "[+] Downloading main script from GitHub..."
curl -fsSL \
https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/network_scan.py \
-o network_scan.py

if [[ ! -f "network_scan.py" ]]; then
  msg "[!] خطا در دانلود فایل" "[!] Failed to download main file"
  exit 1
fi

chmod +x network_scan.py

# -------------------------------
# ذخیره تنظیمات زبان (پایدار)
# -------------------------------
echo "NETSCAN_LANG=$NETSCAN_LANG" > "$CONF_FILE"
chmod 600 "$CONF_FILE"

# -------------------------------
# ساخت symlink اجرایی
# -------------------------------
if [[ -L "$BIN_PATH" || -f "$BIN_PATH" ]]; then
  msg "[*] لینک اجرایی قبلاً وجود دارد، بازنویسی می‌شود" "[*] Existing executable link found, replacing"
  sudo rm -f "$BIN_PATH"
fi

sudo ln -s "$INSTALL_DIR/network_scan.py" "$BIN_PATH"

# -------------------------------
# پایان
# -------------------------------
echo
msg "[✓] نصب با موفقیت انجام شد" "[✓] Installation completed successfully"
echo
msg "برای اجرا از هرجای سیستم:" "Run from anywhere:"
msg "sudo NETSCAN_LANG=$NETSCAN_LANG netscan" "sudo NETSCAN_LANG=$NETSCAN_LANG netscan"
echo
msg "مسیر نصب:" "Install path:"
echo "$INSTALL_DIR"
echo
msg "تنظیمات:" "Configuration file:"
echo "$CONF_FILE"
echo
