#!/usr/bin/env bash
set -e
trap 'echo; echo "[!] Installation interrupted"; exit 1' INT

# =========================================================
# Config
# =========================================================
INSTALL_DIR="/opt/network-scanner"
BIN_PATH="/usr/local/bin/netscan"
CONF_FILE="$INSTALL_DIR/.netscan.conf"
OUI_DB_FILE="$INSTALL_DIR/oui.db"
TMP_DIR="/tmp/netscan-oui"

# =========================================================
# Welcome
# =========================================================
clear
echo "======================================="
echo "  Network Scanner & ARP Inspector"
echo "  Smart Installer"
echo "  Author: Reza Javadi"
echo "======================================="
echo

# =========================================================
# Language Selection
# =========================================================
echo "Select language / انتخاب زبان:"
echo "1) English"
echo "2) فارسی"
read -p "> " LANG_CHOICE

[[ "$LANG_CHOICE" == "2" ]] && LANG="fa" || LANG="en"

msg() {
  case "$LANG:$1" in
    fa:checking) echo "[+] بررسی پیش‌نیازها..." ;;
    fa:downloading) echo "[+] دانلود اسکریپت اصلی..." ;;
    fa:dbmode) echo "[+] انتخاب حالت دیتابیس OUI" ;;
    fa:online) echo "[+] استفاده از دیتابیس آنلاین (به‌روز)" ;;
    fa:offline_warn) echo "[!] هشدار: دیتابیس آفلاین ممکن است قدیمی باشد" ;;
    fa:building) echo "[+] ساخت دیتابیس آفلاین OUI (ممکن است کمی زمان ببرد)..." ;;
    fa:utils) echo "[+] نصب ماژول‌های کمکی..." ;;
    fa:done) echo "[✓] نصب با موفقیت انجام شد" ;;
    en:checking) echo "[+] Checking system dependencies..." ;;
    en:downloading) echo "[+] Downloading main scanner script..." ;;
    en:dbmode) echo "[+] Select OUI database mode" ;;
    en:online) echo "[+] Using online OUI database (always up-to-date)" ;;
    en:offline_warn) echo "[!] Warning: Offline database may be outdated" ;;
    en:building) echo "[+] Building offline OUI database (this may take a while)..." ;;
    en:utils) echo "[+] Setting up utility modules..." ;;
    en:done) echo "[✓] Installation completed successfully" ;;
  esac
}

# =========================================================
# Helper: Online check
# =========================================================
check_online_access() {
  curl -fsI --max-time 3 https://standards-oui.ieee.org >/dev/null 2>&1
}

# =========================================================
# OS Check
# =========================================================
[[ "$OSTYPE" == "linux-gnu"* ]] || { echo "Linux only"; exit 1; }

# =========================================================
# Dependencies
# =========================================================
msg checking
sudo -v
sudo apt update

DEPENDENCIES=(python3 curl iproute2 iputils-ping gawk coreutils)
for pkg in "${DEPENDENCIES[@]}"; do
  printf "[*] %-18s : " "$pkg"
  if ! command -v "$pkg" >/dev/null 2>&1 && ! dpkg -s "$pkg" >/dev/null 2>&1; then
    echo "Installing"
    sudo apt install -y "$pkg"
  else
    echo "OK"
  fi
done

# =========================================================
# Detect Existing Install
# =========================================================
if [[ -d "$INSTALL_DIR" ]]; then
  echo
  echo "[!] Existing installation detected at $INSTALL_DIR"
  read -p "Overwrite existing installation? (y/N): " overwrite
  [[ "$overwrite" =~ ^[Yy]$ ]] || exit 1
fi

# =========================================================
# OUI Mode Selection
# =========================================================
echo
msg dbmode
echo "1) Online  (Recommended)"
echo "2) Offline (Local database)"
read -p "> " OUI_CHOICE

if [[ "$OUI_CHOICE" == "2" ]]; then
  OUI_MODE="offline"
else
  if check_online_access; then
    OUI_MODE="online"
  else
    echo
    echo "[!] Online access is not available."
    echo "[!] IEEE OUI server not reachable."
    read -p "Switch to Offline mode instead? (y/N): " fallback
    if [[ "$fallback" =~ ^[Yy]$ ]]; then
      OUI_MODE="offline"
    else
      echo "[!] Installation cancelled."
      exit 1
    fi
  fi
fi

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

# =========================================================
# Download Utils Module (NEW)
# =========================================================
msg utils

# ساخت پوشه utils
mkdir -p utils

# دانلود __init__.py
echo "  [*] Downloading utils/__init__.py ..."
curl -# -fsSL \
https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/utils/__init__.py \
-o utils/__init__.py

# دانلود validators.py
echo "  [*] Downloading utils/validators.py ..."
curl -# -fsSL \
https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/utils/validators.py \
-o utils/validators.py

# تنظیم دسترسی‌ها
chmod 644 utils/__init__.py
chmod 644 utils/validators.py

echo "[✓] Utils module installed successfully"

# =========================================================
# OUI Handling
# =========================================================
if [[ "$OUI_MODE" == "online" ]]; then
  msg online
else
  msg offline_warn
  read -p "Continue? (y/N): " confirm
  [[ "$confirm" =~ ^[Yy]$ ]] || exit 1

  msg building
  mkdir -p "$TMP_DIR"
  RAW_FILE="$TMP_DIR/oui_raw.txt"

  if ! curl -# -fsSL https://standards-oui.ieee.org/oui/oui.txt -o "$RAW_FILE"; then
    echo "[!] Failed to download OUI database."
    exit 1
  fi

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

  RECORDS=$(wc -l < "$OUI_DB_FILE")
  SIZE=$(du -h "$OUI_DB_FILE" | cut -f1)

  echo "[✓] OUI database built successfully"
  echo "    Records : $RECORDS"
  echo "    Size    : $SIZE"

  rm -rf "$TMP_DIR"
fi

# =========================================================
# Save Config
# =========================================================
{
  echo "OUI_MODE=$OUI_MODE"
  echo "LANG=$LANG"
} > "$CONF_FILE"

chmod 600 "$CONF_FILE"

# Symlink
sudo ln -sf "$INSTALL_DIR/network_scan.py" "$BIN_PATH"

# =========================================================
# Finish
# =========================================================
msg done
echo
echo "Run command:"
echo "  netscan"
echo
echo "Install path:"
echo "  $INSTALL_DIR"
