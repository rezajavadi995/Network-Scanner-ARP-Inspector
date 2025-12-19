#!/usr/bin/env bash
set -e

echo "======================================="
echo "  Network Scanner & ARP Inspector"
echo "  Auto Installer + OUI Database"
echo "  Author: Reza Javadi"
echo "======================================="
echo

# فقط لینوکس
if [[ "$OSTYPE" != "linux-gnu"* ]]; then
  echo "[!] This script runs only on Linux"
  exit 1
fi

# -------------------------------
# مسیرها
# -------------------------------
INSTALL_DIR="/opt/network-scanner"
BIN_PATH="/usr/local/bin/netscan"
CONF_FILE="$INSTALL_DIR/.netscan.conf"
OUI_DB_FILE="$INSTALL_DIR/oui.db"
TMP_DIR="/tmp/netscan-oui"

# -------------------------------
# انتخاب زبان
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
# بررسی پیش‌نیازها (اصلاح حرفه‌ای)
# -------------------------------
REQUIRED_PACKAGES=(
  python3
  curl
  iproute2
  iputils-ping
  awk
  coreutils
)

echo
echo "[+] Checking system dependencies..."

NEED_UPDATE=false
for pkg in "${REQUIRED_PACKAGES[@]}"; do
  if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    NEED_UPDATE=true
    break
  fi
done

if $NEED_UPDATE; then
  sudo apt update
  sudo apt install -y "${REQUIRED_PACKAGES[@]}"
fi

# -------------------------------
# ساخت مسیر نصب
# -------------------------------
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# -------------------------------
# دانلود اسکریپت اصلی
# -------------------------------
echo "[+] Downloading main scanner script..."
curl -fsSL \
https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/network_scan.py \
-o network_scan.py

chmod +x network_scan.py

# -------------------------------
# ذخیره تنظیمات
# -------------------------------
echo "NETSCAN_LANG=$NETSCAN_LANG" > "$CONF_FILE"
chmod 600 "$CONF_FILE"

# -------------------------------
# ساخت symlink اجرایی
# -------------------------------
if [[ -L "$BIN_PATH" || -f "$BIN_PATH" ]]; then
  sudo rm -f "$BIN_PATH"
fi
sudo ln -s "$INSTALL_DIR/network_scan.py" "$BIN_PATH"

# =========================================================
# ============== ساخت دیتابیس بزرگ OUI ===================
# =========================================================
echo
echo "[+] Building large OUI database (one-time)..."

mkdir -p "$TMP_DIR"

RAW_FILE="$TMP_DIR/oui_raw.txt"

curl -fsSL \
https://gist.githubusercontent.com/aallan/b4bb86db86079509e6159810ae9bd3e4/raw \
-o "$RAW_FILE"

if [[ ! -s "$RAW_FILE" ]]; then
  echo "[!] Failed to download OUI database"
  exit 1
fi

awk '
BEGIN { FS=" "; OFS="|" }
{
  if ($1 ~ /^[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}$/) {
    gsub("-", "", $1)
    vendor=""
    for (i=3; i<=NF; i++) vendor = vendor $i " "
    sub(/[ \t]+$/, "", vendor)
    print toupper($1), vendor
  }
}
' "$RAW_FILE" | sort -u > "$OUI_DB_FILE"

chmod 644 "$OUI_DB_FILE"
rm -rf "$TMP_DIR"

echo "[✓] OUI database ready:"
ls -lh "$OUI_DB_FILE"

# -------------------------------
# پایان
# -------------------------------
echo
echo "[✓] Installation completed successfully"
echo
echo "Run from anywhere:"
echo "  netscan"
echo
echo "Install path:"
echo "  $INSTALL_DIR"
echo
