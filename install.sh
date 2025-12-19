#!/usr/bin/env bash
set -e

# =========================================================
# Config
# =========================================================
INSTALL_DIR="/opt/network-scanner"
BIN_PATH="/usr/local/bin/netscan"
CONF_FILE="$INSTALL_DIR/.netscan.conf"
OUI_DB_FILE="$INSTALL_DIR/oui.db"
TMP_DIR="/tmp/netscan-oui"

# =========================================================
# Welcome / Language Selection
# =========================================================
echo "======================================="
echo "  Network Scanner & ARP Inspector"
echo "  Auto Installer + OUI Database"
echo "  Author: Reza Javadi"
echo "======================================="
echo

echo "Select language / انتخاب زبان:"
echo "1) English"
echo "2) فارسی"
read -p "> " LANG_CHOICE

if [[ "$LANG_CHOICE" == "2" ]]; then
  LANG="fa"
else
  LANG="en"
fi

msg() {
  case "$LANG:$1" in
    fa:checking) echo "[+] بررسی پیش‌نیازها..." ;;
    fa:downloading) echo "[+] دانلود اسکریپت اصلی..." ;;
    fa:building) echo "[+] ساخت دیتابیس بزرگ OUI..." ;;
    fa:done) echo "[✓] نصب با موفقیت انجام شد" ;;
    en:checking) echo "[+] Checking system dependencies..." ;;
    en:downloading) echo "[+] Downloading main scanner script..." ;;
    en:building) echo "[+] Building large OUI database..." ;;
    en:done) echo "[✓] Installation completed successfully" ;;
  esac
}

# =========================================================
# OS Check
# =========================================================
[[ "$OSTYPE" == "linux-gnu"* ]] || { echo "Linux only"; exit 1; }

# =========================================================
# Dependencies
# =========================================================
msg checking
sudo apt update

DEPENDENCIES=(python3 curl iproute2 iputils-ping gawk coreutils)
for pkg in "${DEPENDENCIES[@]}"; do
  printf "[*] Checking %-15s ... " "$pkg"
  if ! command -v "$pkg" >/dev/null 2>&1 && ! dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "Installing..."
    sudo apt install -y "$pkg"
  else
    echo "OK"
  fi
done

# =========================================================
# Install Directory
# =========================================================
sudo mkdir -p "$INSTALL_DIR"
sudo chown "$USER":"$USER" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# =========================================================
# Download Main Script
# =========================================================
msg downloading
curl -# -fsSL \
https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/network_scan.py \
-o network_scan.py
chmod +x network_scan.py

# Save language configuration
echo "NETSCAN_LANG=$LANG" > "$CONF_FILE"
chmod 600 "$CONF_FILE"

# Symlink
sudo ln -sf "$INSTALL_DIR/network_scan.py" "$BIN_PATH"

# =========================================================
# Build OUI Database
# =========================================================
msg building
mkdir -p "$TMP_DIR"
RAW_FILE="$TMP_DIR/oui_raw.txt"

curl -# -fsSL \
https://gist.githubusercontent.com/aallan/b4bb86db86079509e6159810ae9bd3e4/raw \
-o "$RAW_FILE"

if [[ ! -s "$RAW_FILE" ]]; then
  echo "[!] Failed to download OUI database"
  exit 1
fi

# Process OUI with gawk, handle all common formats
gawk '
{
  gsub(/[:-]/,"",$1)
  if ($1 ~ /^[0-9A-Fa-f]{6}$/) {
    vendor=""
    for (i=2;i<=NF;i++) vendor=vendor $i " "
    sub(/[ \t]+$/,"",vendor)
    print toupper($1) "|" vendor
  }
}
' "$RAW_FILE" | sort -u > "$OUI_DB_FILE"

chmod 644 "$OUI_DB_FILE"
rm -rf "$TMP_DIR"

# =========================================================
# Finish
# =========================================================
msg done
echo
echo "Run from anywhere:"
echo "  netscan"
echo
echo "Install path:"
echo "  $INSTALL_DIR"
