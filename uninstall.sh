#!/usr/bin/env bash
set -e

echo "======================================="
echo "  Network Scanner & ARP Inspector"
echo "  Uninstall Script"
echo "======================================="
echo

INSTALL_DIR="/opt/network-scanner"
BIN_PATH="/usr/local/bin/netscan"

# حذف symlink اجرایی
if [[ -L "$BIN_PATH" ]]; then
  echo "[+] حذف لینک اجرایی: $BIN_PATH"
  sudo rm -f "$BIN_PATH"
else
  echo "[*] لینک اجرایی وجود ندارد"
fi

# حذف دایرکتوری برنامه
if [[ -d "$INSTALL_DIR" ]]; then
  echo "[+] حذف مسیر نصب: $INSTALL_DIR"
  sudo rm -rf "$INSTALL_DIR"
else
  echo "[*] مسیر نصب وجود ندارد"
fi

echo
echo "[✓] حذف برنامه با موفقیت انجام شد"
echo
