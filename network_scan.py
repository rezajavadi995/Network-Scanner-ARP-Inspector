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

# =========================================================
# ===================== Language Layer ====================
# =========================================================

LANG = os.environ.get("NETSCAN_LANG", "en")

TEXT = {
    "en": {
        "info_interface": "Interface",
        "info_mode": "Mode",
        "info_network": "Network Range",
        "info_delay": "Ping Delay",
        "info_arp": "ARP Source",
        "info_started": "Started At",
        "mode": "adaptive (human-like)",
        "arp_ip": "ip neigh",
        "scan_start": "Starting network scan",
        "ping_done": "Ping scan completed",
        "arp_read": "Reading ARP table",
        "active": "Active Devices (Ping OK)",
        "arp_only": "ARP Only (No Ping)",
        "incomplete": "ARP Incomplete",
        "total": "Total devices (excluding yourself)",
        "total_self": "Total with yourself",
        "done": "Operation completed successfully",
        "stopped": "Scan interrupted by user"
    },
    "fa": {
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
        "stopped": "اسکن توسط کاربر متوقف شد"
    }
}

T = TEXT.get(LANG, TEXT["en"])

# =========================================================
# =================== Core Configuration ==================
# =========================================================

NETWORK_BASE = "192.168.1."
START = 1
END = 255

PING_TIMEOUT = "1"
BASE_DELAY = 0.03
ARP_DELAY = 0.5

# =========================================================
# ======================= Utilities =======================
# =========================================================

def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def progress_bar(cur, total):
    percent = int((cur / total) * 100)
    bar = "#" * (percent // 2) + "-" * (50 - percent // 2)
    sys.stdout.write(f"\r[{bar}] {percent}%")
    sys.stdout.flush()

# =========================================================
# ==================== MAC & Vendor =======================
# =========================================================

OUI_DB = {
    "001A79": "Apple",
    "F099BF": "Samsung",
    "1063C8": "Huawei",
    "DCA632": "Xiaomi",
    "0004ED": "TP-Link",
    "FCFBFB": "Ubiquiti",
    "D8EB97": "Intel",
    "AC1203": "Cisco",
    "BC926B": "ASUS",
    "B827EB": "Raspberry Pi",
    "080027": "VirtualBox",
    "000569": "VMware"
}

def normalize_mac(mac):
    if not mac or mac == "<incomplete>":
        return None
    return re.sub(r'[^0-9A-Fa-f]', '', mac).upper()

def is_locally_administered(mac_hex):
    try:
        first_octet = int(mac_hex[0:2], 16)
        return bool(first_octet & 0b00000010)
    except:
        return False

def get_vendor(mac):
    mac_hex = normalize_mac(mac)
    if not mac_hex:
        return "Unknown"
    if is_locally_administered(mac_hex):
        return "Randomized / Locally Administered"
    return OUI_DB.get(mac_hex[:6], "Unknown")

# =========================================================
# ================= System Information ====================
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
        return subprocess.check_output(["hostname", "-I"], text=True).split()[0]
    except:
        return "unknown"

# =========================================================
# ===================== ARP Reader ========================
# =========================================================

def read_arp():
    entries = []
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True)
        for l in out.splitlines():
            p = l.split()
            ip = p[0]
            mac = "<incomplete>"
            if "lladdr" in p:
                mac = p[p.index("lladdr") + 1]
            entries.append({
                "ip": ip,
                "mac": mac,
                "vendor": get_vendor(mac)
            })
    except:
        pass
    return entries

# =========================================================
# ========================= MAIN ==========================
# =========================================================

def main():
    iface = get_interface()
    my_ip = get_my_ip()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n[INFO] {}        : {}".format(T["info_interface"], iface))
    print("[INFO] {}             : {}".format(T["info_mode"], T["mode"]))
    print("[INFO] {}    : {}0/24".format(T["info_network"], NETWORK_BASE))
    print("[INFO] {}       : {} ms".format(T["info_delay"], int(BASE_DELAY*1000)))
    print("[INFO] {}       : {}".format(T["info_arp"], T["arp_ip"]))
    print("[INFO] {}       : {}\n".format(T["info_started"], now))

    print("[+] {}".format(T["scan_start"]))

    total_ips = END - START + 1
    ping_results = {}

    for idx, i in enumerate(range(START, END + 1), 1):
        ip = f"{NETWORK_BASE}{i}"
        r = subprocess.run(
            ["ping", "-c", "1", "-W", PING_TIMEOUT, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        ping_results[ip] = (r.returncode == 0)
        progress_bar(idx, total_ips)
        time.sleep(BASE_DELAY)

    print("\n[+] {}".format(T["ping_done"]))
    time.sleep(ARP_DELAY)

    print("\n[+] {}\n".format(T["arp_read"]))
    arp = read_arp()

    active, arp_only, incomplete = [], [], []

    for d in arp:
        if d["ip"] == my_ip:
            continue
        if d["mac"] == "<incomplete>":
            incomplete.append(d)
        elif ping_results.get(d["ip"]):
            active.append(d)
        else:
            arp_only.append(d)

    active.sort(key=lambda x: ip_to_int(x["ip"]))
    arp_only.sort(key=lambda x: ip_to_int(x["ip"]))
    incomplete.sort(key=lambda x: ip_to_int(x["ip"]))

    print("========== {} ==========".format(T["active"]))
    for d in active:
        print(f"✅ {d['ip']}  {d['mac']}  [{d['vendor']}]")

    print("\n========== {} ==========".format(T["arp_only"]))
    for d in arp_only:
        print(f"⚠️  {d['ip']}  {d['mac']}  [{d['vendor']}]")

    print("\n========== {} ==========".format(T["incomplete"]))
    for d in incomplete:
        print(f"❌ {d['ip']}  <incomplete>")

    total = len(active) + len(arp_only) + len(incomplete)
    print("\n{}: {}".format(T["total"], total))
    print("{}: {}".format(T["total_self"], total + 1))
    print("[✓] {}".format(T["done"]))

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] {}".format(T["stopped"]))
