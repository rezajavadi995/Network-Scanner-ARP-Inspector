#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import time
import re
import socket
import struct
import shutil
import os
from datetime import datetime
import ipaddress

# ===================== Colors ===========================
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"

FG_GREEN = "\033[92m"
FG_BLUE  = "\033[94m"
FG_YELLOW= "\033[93m"
FG_RED   = "\033[91m"
FG_CYAN  = "\033[96m"
FG_GRAY  = "\033[90m"

# =========================================================
# ===================== Paths =============================
# =========================================================
BASE_DIR = "/opt/network-scanner"
CONF_FILE = f"{BASE_DIR}/.netscan.conf"
OUI_DB_FILE = f"{BASE_DIR}/oui.db"
BIN_PATH = "/usr/local/bin/netscan"

# =========================================================
# ===================== Language & Tone ===================
# =========================================================
NETSCAN_LANG = "en"
NETSCAN_TONE = "human"

if os.path.exists(CONF_FILE):
    try:
        with open(CONF_FILE) as f:
            for line in f:
                if line.startswith("NETSCAN_LANG="):
                    NETSCAN_LANG = line.strip().split("=", 1)[1]
                elif line.startswith("NETSCAN_TONE="):
                    NETSCAN_TONE = line.strip().split("=", 1)[1]
    except:
        pass

# =========================================================
# ===================== TEXT (FULL MERGED) ================
# =========================================================
TEXT = {
    "en": {
        # ---- Menu ----
        "menu_title": "Network Scanner & ARP Inspector",
        "menu_option_scan": "1) Start Network Scan",
        "menu_option_update": "2) Update Script",
        "menu_option_uninstall": "3) Uninstall",
        "menu_option_exit": "4) Exit",
        "prompt_choice": "Enter your choice",

        # ---- Info ----
        "info_interface": "Interface",
        "info_mode": "Mode",
        "info_network": "Network Range",
        "info_delay": "Ping Delay",
        "info_arp": "ARP Source",
        "info_started": "Started At",

        "mode": "adaptive (human-like)",
        "arp_ip": "ip neigh",

        # ---- Scan ----
        "scan_start": "Starting network scan",
        "ping_done": "Ping scan completed",
        "arp_read": "Reading ARP table",

        "active": "Active Devices (Ping OK)",
        "arp_only": "ARP Only (No Ping)",
        "incomplete": "ARP Incomplete",

        "total": "Total devices (excluding yourself)",
        "total_self": "Total with yourself",

        "done": "Operation completed successfully",
        "press_enter": "Press Enter to continue...",

        # ---- Exit ----
        "exit_human": "Session closed calmly. Nothing unusual happened.",
        "exit_neutral": "Exited.",
        "exit_message": "Exited normally.",
        "exit_uninstall": "Application removed successfully.",

        "invalid_choice": "Invalid selection",

        # ---- Dynamic Network ----
        "range_detected": "Detected network range",
        "range_change": "Do you want to change the network range? (Y/N)",
        "range_keep": "Keeping current network range",
        "range_back": "Returning to menu to change range",

        # ---- Interface Warnings ----
        "iface_nat": "Interface is NAT (VirtualBox)",
        "iface_nat_warn": "Network scan results may be incomplete",
        "iface_wifi": "Interface Mode : Wi-Fi (Managed)",
        "iface_gateway": "Gateway Detected",
        "iface_arp_limited": "ARP visibility : Limited",

        "menu_width": 54
    },

    "fa": {
        "menu_title": "Network Scanner & ARP Inspector",
        "menu_option_scan": "1) شروع اسکن شبکه",
        "menu_option_update": "2) بروزرسانی اسکریپت",
        "menu_option_uninstall": "3) حذف برنامه",
        "menu_option_exit": "4) خروج",
        "prompt_choice": "انتخاب شما",

        "info_interface": "اینترفیس",
        "info_mode": "حالت",
        "info_network": "رنج شبکه",
        "info_delay": "تاخیر پینگ",
        "info_arp": "منبع ARP",
        "info_started": "زمان شروع",

        "mode": "تطبیقی (رفتار انسانی)",
        "arp_ip": "ip neigh",

        "scan_start": "شروع اسکن شبکه",
        "ping_done": "پایان اسکن Ping",
        "arp_read": "در حال خواندن جدول ARP",

        "active": "دستگاه‌های فعال (Ping OK)",
        "arp_only": "بدون Ping ولی در ARP",
        "incomplete": "ARP ناقص",

        "total": "تعداد دستگاه‌ها (بدون خودت)",
        "total_self": "تعداد کل با خودت",

        "done": "عملیات با موفقیت انجام شد",
        "press_enter": "برای ادامه Enter بزنید...",

        "exit_human": "خروج انجام شد. همه‌چیز عادی بود.",
        "exit_neutral": "خروج انجام شد.",
        "exit_message": "خروج عادی انجام شد.",
        "exit_uninstall": "برنامه با موفقیت حذف شد.",

        "invalid_choice": "انتخاب نامعتبر",

        "range_detected": "رنج شبکه شناسایی شد",
        "range_change": "آیا می‌خواهید رنج شبکه را تغییر دهید؟ (Y/N)",
        "range_keep": "رنج فعلی حفظ شد",
        "range_back": "بازگشت به منو برای تغییر رنج",

        "iface_nat": "اینترفیس در حالت NAT (VirtualBox)",
        "iface_nat_warn": "نتایج اسکن ممکن است ناقص باشند",
        "iface_wifi": "حالت اینترفیس : وای‌فای (Managed)",
        "iface_gateway": "گیت‌وی شناسایی شد",
        "iface_arp_limited": "دسترسی ARP محدود است",

        "menu_width": 60
    }
}

T = TEXT.get(NETSCAN_LANG, TEXT["en"])
MENU_WIDTH = T.get("menu_width", 54)

# =========================================================
# ===================== Network ===========================
# =========================================================
NETWORK_BASE = "192.168.1."
START = 1
END = 254
PING_TIMEOUT = "1"
BASE_DELAY = 0.03
ARP_DELAY = 0.4

# =========================================================
# ===================== Helpers ===========================
# =========================================================
def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def normalize_mac(mac):
    if not mac or mac == "<incomplete>":
        return None
    return re.sub(r'[^0-9A-Fa-f]', '', mac).upper()

def is_locally_administered(mac_hex):
    try:
        return bool(int(mac_hex[0:2], 16) & 0b00000010)
    except:
        return False

# =========================================================
# ===================== Interface Detection ===============
# =========================================================
def detect_interface_mode(iface):
    warnings = []

    try:
        if iface.startswith("wlan"):
            warnings.append(T["iface_wifi"])
            warnings.append(T["iface_gateway"])
            warnings.append(T["iface_arp_limited"])
    except:
        pass

    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        if "vbox" in out.lower():
            warnings.append(T["iface_nat"])
            warnings.append(T["iface_nat_warn"])
    except:
        pass

    return warnings

# =========================================================
# ===================== Dynamic Network ===================
# =========================================================
def detect_network_range():
    try:
        iface = get_interface()
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        for line in out.splitlines():
            if "inet " in line:
                cidr = line.split()[1]
                return ipaddress.ip_network(cidr, strict=False)
    except:
        pass
    return ipaddress.ip_network("192.168.1.0/24")

# =========================================================
# ===================== OUI DB =============================
# =========================================================
_OUI_CACHE = None

def load_oui_db():
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    _OUI_CACHE = {}
    if not os.path.exists(OUI_DB_FILE):
        return _OUI_CACHE

    with open(OUI_DB_FILE, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "|" in line:
                oui, vendor = line.strip().split("|", 1)
                _OUI_CACHE[oui.upper()] = vendor.strip()
    return _OUI_CACHE

def get_vendor(mac):
    mac_hex = normalize_mac(mac)
    if not mac_hex:
        return "Unknown"
    if is_locally_administered(mac_hex):
        return "Randomized / Locally Administered"
    return load_oui_db().get(mac_hex[:6], "Unknown")

# =========================================================
# ===================== System ===========================
# =========================================================
def get_interface():
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for l in out.splitlines():
            if l.startswith("default"):
                return l.split()[l.split().index("dev") + 1]
    except:
        pass
    return "unknown"

def get_my_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "unknown"

def get_my_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except:
        return None

# =========================================================
# ===================== ARP ===============================
# =========================================================
def read_arp():
    entries = []
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True)
        for line in out.splitlines():
            parts = line.split()
            ip = parts[0]
            mac = "<incomplete>"
            if "lladdr" in parts:
                mac = parts[parts.index("lladdr") + 1]
            entries.append({
                "ip": ip,
                "mac": mac,
                "vendor": get_vendor(mac)
            })
    except:
        pass
    return entries

# =========================================================
# ===================== Scan ==============================
# =========================================================
def perform_scan():
    global NETWORK_BASE, START, END

    iface = get_interface()
    net = detect_network_range()

    print(f"\n[INFO] {T['range_detected']} : {net}")
    ans = input(f"[?] {T['range_change']} ").strip().lower()
    if ans == "y":
        print(FG_YELLOW + T["range_back"] + RESET)
        time.sleep(1)
        return

    NETWORK_BASE = str(net.network_address).rsplit(".", 1)[0] + "."
    START = 1
    END = net.num_addresses - 2

    for w in detect_interface_mode(iface):
        print(FG_YELLOW + "[WARN] " + w + RESET)

    my_ip = get_my_ip()
    my_mac_raw = get_my_mac(iface)
    my_vendor = get_vendor(my_mac_raw)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"\n[INFO] {T['info_interface']} : {iface}")
    print(f"[INFO] {T['info_network']} : {net}")
    print(f"[INFO] {T['info_started']} : {now}\n")

    print(FG_CYAN + BOLD + "[Local Device]" + RESET)
    print(f"IP     : {my_ip}")
    print(f"MAC    : {my_mac_raw}")
    print(f"Vendor : {my_vendor}\n")

    print(f"[+] {T['scan_start']}")

    ping_ok = {}
    for i in range(START, END + 1):
        ip = f"{NETWORK_BASE}{i}"
        r = subprocess.run(
            ["ping", "-c", "1", "-W", PING_TIMEOUT, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        ping_ok[ip] = (r.returncode == 0)
        percent = int(((i-START+1)/(END-START+1))*100)
        sys.stdout.write(f"\rScanning {ip}... {percent}%")
        sys.stdout.flush()
        time.sleep(BASE_DELAY)

    print(f"\n[+] {T['ping_done']}")
    time.sleep(ARP_DELAY)

    print(f"\n[+] {T['arp_read']}\n")
    arp = read_arp()

    active, arp_only, incomplete = [], [], []

    for d in arp:
        if d["ip"] == my_ip:
            continue
        if d["mac"] == "<incomplete>":
            incomplete.append(d)
        elif ping_ok.get(d["ip"]):
            active.append(d)
        else:
            arp_only.append(d)

    for title, data, icon in [
        (T["active"], active, "✅"),
        (T["arp_only"], arp_only, "⚠️"),
        (T["incomplete"], incomplete, "❌")
    ]:
        print(f"\n========== {title} ==========")
        for d in data:
            print(f"{icon} {d['ip']}  {d['mac']}  [{d['vendor']}]")

    total = len(active) + len(arp_only) + len(incomplete)
    print(f"\n{T['total']}: {total}")
    print(f"{T['total_self']}: {total + 1}")
    print(f"[✓] {T['done']}")
    input(T["press_enter"])

# =========================================================
# ===================== Menu ==============================
# =========================================================
def main_menu():
    while True:
        os.system("clear")

        print(FG_CYAN + BOLD + "╔" + "═"*MENU_WIDTH + "╗" + RESET)
        print(FG_CYAN + BOLD + "║" + RESET + f"{T['menu_title']:^{MENU_WIDTH}}" + FG_CYAN + BOLD + "║" + RESET)
        print(FG_CYAN + BOLD + "╠" + "═"*MENU_WIDTH + "╣" + RESET)

        print(FG_GREEN  + "║  [1] ▶  " + RESET + T["menu_option_scan"][3:].ljust(MENU_WIDTH-8) + "║")
        print(FG_BLUE   + "║  [2] ⟳  " + RESET + T["menu_option_update"][3:].ljust(MENU_WIDTH-8) + "║")
        print(FG_YELLOW + "║  [3] ✖  " + RESET + T["menu_option_uninstall"][3:].ljust(MENU_WIDTH-8) + "║")
        print(FG_RED    + "║  [4] ⏻  " + RESET + T["menu_option_exit"][3:].ljust(MENU_WIDTH-8) + "║")
        print(FG_CYAN + BOLD + "╚" + "═"*MENU_WIDTH + "╝" + RESET)

        choice = input("\n" + T["prompt_choice"] + " > ").strip()

        if choice == "1":
            perform_scan()
        elif choice == "2":
            subprocess.run(["python3", f"{BASE_DIR}/network_scan.py"])
        elif choice == "3":
            subprocess.run(["sudo", "rm", "-f", BIN_PATH])
            subprocess.run(["sudo", "rm", "-rf", BASE_DIR])
            print(FG_GREEN + T["exit_uninstall"] + RESET)
            break
        elif choice == "4":
            msg = T["exit_human"] if NETSCAN_TONE == "human" else T["exit_neutral"]
            print(FG_GREEN + msg + RESET)
            break
        else:
            print(FG_RED + T["invalid_choice"] + RESET)
            time.sleep(1)

if __name__ == "__main__":
    main_menu()
