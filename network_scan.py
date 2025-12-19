#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import time
import re
import socket
import struct
import shutil

# =========================================================
# ========== تنظیمات اصلی (رفتار انسانی و کم‌ردپا) ==========
# =========================================================

NETWORK_BASE = "192.168.1."
START = 1
END = 255
PING_TIMEOUT = "1"          # ثانیه
PING_DELAY = 0.03           # تاخیر طبیعی بین پینگ‌ها (انسانی)
ARP_READ_DELAY = 0.5        # مکث قبل از خواندن ARP

# =========================================================
# ===================== ابزارهای پایه =====================
# =========================================================

def ip_to_int(ip):
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except:
        return 0

def progress_bar(current, total):
    percent = int((current / total) * 100)
    bar = "#" * (percent // 2) + "-" * (50 - percent // 2)
    sys.stdout.write(f"\r[{bar}] {percent}%")
    sys.stdout.flush()

# =========================================================
# ======================= Ping ساده =======================
# =========================================================

PING_RESULTS = {}

def ping_ip(ip):
    try:
        r = subprocess.run(
            ["ping", "-c", "1", "-W", PING_TIMEOUT, ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return r.returncode == 0
    except:
        return False

# =========================================================
# ==================== اطلاعات سیستم =====================
# =========================================================

def get_active_interface():
    try:
        if shutil.which("ip") is None:
            return "unknown"
        route = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
        for line in route.splitlines():
            if line.startswith("default") and "dev" in line:
                return line.split()[line.split().index("dev") + 1]
    except:
        pass
    return "unknown"

def get_my_ip():
    try:
        out = subprocess.check_output(["hostname", "-I"], text=True).strip()
        if out:
            return out.split()[0]
    except:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except:
        return "unknown"

def get_my_mac(interface):
    try:
        if interface != "unknown":
            with open(f"/sys/class/net/{interface}/address") as f:
                return f.read().strip().lower()
    except:
        pass
    return ""

# =========================================================
# ======================= Vendor DB =======================
# =========================================================

OUI_DB = {
    "00:1A:79": "Apple",
    "3C:5A:B4": "Google",
    "F0:99:BF": "Samsung",
    "DC:A6:32": "Xiaomi",
    "B8:27:EB": "Raspberry Pi",
    "08:00:27": "VirtualBox",
    "00:05:69": "VMware",
    "00:1C:42": "Parallels",
    "00:04:ED": "TP-Link",
    "10:63:C8": "Huawei",
    "FC:FB:FB": "Ubiquiti",
    "D8:EB:97": "Intel",
    "AC:12:03": "Cisco",
    "BC:92:6B": "ASUS",
    "9A:6C:31": "Randomized MAC (Mobile)"
}

def normalize_mac(mac):
    if not mac:
        return ""
    if mac.lower() == "<incomplete>":
        return "<INCOMPLETE>"
    hex_only = re.sub(r'[^0-9a-fA-F]', '', mac).upper()
    if len(hex_only) < 6:
        return mac.upper()
    prefix = hex_only[:6]
    return ":".join([prefix[i:i+2] for i in range(0, 6, 2)])

def get_vendor(mac):
    prefix = normalize_mac(mac)
    if prefix == "<INCOMPLETE>":
        return "Unknown"
    return OUI_DB.get(prefix, "Unknown")

# =========================================================
# ===================== خواندن ARP ========================
# =========================================================

def parse_arp():
    entries = []

    # اول ip neigh (طبیعی‌تر در لینوکس)
    try:
        if shutil.which("ip"):
            out = subprocess.check_output(["ip", "neigh"], text=True, errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                ip = parts[0]
                mac = "<incomplete>"
                if "lladdr" in parts:
                    mac = parts[parts.index("lladdr") + 1]
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac)
                })
            if entries:
                return entries
    except:
        pass

    # fallback: arp -a
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
        for line in out.splitlines():
            m = re.search(r"\((.*?)\) at ([0-9a-f:]+)", line, re.I)
            if m:
                ip = m.group(1)
                mac = m.group(2)
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac)
                })
    except:
        pass

    return entries

# =========================================================
# ========================== main =========================
# =========================================================

def main():
    total_ips = END - START + 1
    interface = get_active_interface()
    my_ip = get_my_ip()
    my_mac = normalize_mac(get_my_mac(interface))

    print("\n[+] شروع اسکن شبکه (رفتار عادی و انسانی)")
    print(f"[+] اینترفیس فعال: {interface}")
    print(f"[+] IP سیستم: {my_ip}")
    print(f"[+] رنج: {NETWORK_BASE}{START} → {NETWORK_BASE}{END}\n")

    for idx, i in enumerate(range(START, END + 1), start=1):
        ip = f"{NETWORK_BASE}{i}"
        alive = ping_ip(ip)
        PING_RESULTS[ip] = alive
        progress_bar(idx, total_ips)
        time.sleep(PING_DELAY)

    print("\n\n[+] Ping scan تمام شد")
    time.sleep(ARP_READ_DELAY)

    print("\n[+] خواندن جدول ARP ...\n")
    arp_entries = parse_arp()

    # حذف خود سیستم
    filtered = []
    for d in arp_entries:
        if d["ip"] == my_ip:
            continue
        if normalize_mac(d["mac"]) == my_mac:
            continue
        filtered.append(d)

    ping_ok = []
    arp_only = []
    incomplete = []

    for d in filtered:
        ip = d["ip"]
        mac_norm = normalize_mac(d["mac"])
        if mac_norm == "<INCOMPLETE>":
            incomplete.append(d)
        elif PING_RESULTS.get(ip):
            ping_ok.append(d)
        else:
            arp_only.append(d)

    ping_ok.sort(key=lambda x: ip_to_int(x["ip"]))
    arp_only.sort(key=lambda x: ip_to_int(x["ip"]))
    incomplete.sort(key=lambda x: ip_to_int(x["ip"]))

    print("========== دستگاه‌های فعال (Ping OK) ==========")
    for d in ping_ok:
        print(f"✅ {d['ip']}  {d['mac']}  [{d['vendor']}]")

    print("\n========== بدون Ping ولی در ARP ==========")
    for d in arp_only:
        print(f"⚠️  {d['ip']}  {d['mac']}  [{d['vendor']}]")

    print("\n========== ARP Incomplete ==========")
    for d in incomplete:
        print(f"❌ {d['ip']}  <incomplete>")

    total = len(ping_ok) + len(arp_only) + len(incomplete)

    print("\n==========================================")
    print(f"تعداد دستگاه‌ها (بدون خودت): {total}")
    print(f"تعداد کل با خودت: {total + 1}")
    print("[✓] عملیات با موفقیت انجام شد")

# =========================================================

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] اسکن توسط کاربر متوقف شد")
