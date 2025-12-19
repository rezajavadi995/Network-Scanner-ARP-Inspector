#!/usr/bin/env python3
import subprocess
import sys
import time
import re
import socket
import struct
import fcntl
from collections import defaultdict


NETWORK_BASE = "192.168.1."
START = 1
END = 255
PING_TIMEOUT = "1"  # ثانیه

def ping_ip(ip):
    subprocess.run(
        ["ping", "-c", "1", "-W", PING_TIMEOUT, ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

def get_arp_table():
    output = subprocess.check_output(["arp", "-a"]).decode(errors="ignore")
    devices = []
    for line in output.splitlines():
        if "(" in line and ")" in line and "at" in line:
            devices.append(line)
    return devices

def get_my_ip():
    out = subprocess.check_output(["hostname", "-I"]).decode().strip()
    return out.split()[0] if out else "unknown"

def progress_bar(current, total):
    percent = int((current / total) * 100)
    bar = "#" * (percent // 2) + "-" * (50 - percent // 2)
    sys.stdout.write(f"\r[{bar}] {percent}%")
    sys.stdout.flush()


PING_RESULTS = {}
ARP_PARSED = []

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
    "9A:6C:31": "Randomized MAC (Mobile)"
}

def normalize_mac(mac):
    return mac.upper()[0:8]

def get_vendor(mac):
    if mac == "<incomplete>":
        return "Unknown"
    prefix = normalize_mac(mac)
    return OUI_DB.get(prefix, "Unknown")

def get_active_interface():
    try:
        route = subprocess.check_output(["ip", "route"]).decode()
        for line in route.splitlines():
            if line.startswith("default"):
                return line.split()[4]
    except:
        pass
    return "unknown"

def get_my_mac(interface):
    try:
        with open(f"/sys/class/net/{interface}/address") as f:
            return f.read().strip().lower()
    except:
        return None

def ip_to_int(ip):
    return struct.unpack("!I", socket.inet_aton(ip))[0]

def parse_arp():
    parsed = []
    try:
        output = subprocess.check_output(["arp", "-a"]).decode(errors="ignore")
        for line in output.splitlines():
            m = re.search(r"\((.*?)\) at (.*?) ", line)
            if m:
                ip = m.group(1)
                mac = m.group(2)
                parsed.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac)
                })
    except:
        pass
    return parsed


def main():
    total_ips = END - START + 1
    interface = get_active_interface()
    my_ip = get_my_ip()
    my_mac = get_my_mac(interface)

    print("\n[+] شروع اسکن شبکه با ping")
    print(f"[+] اینترفیس فعال: {interface}")
    print(f"[+] IP سیستم: {my_ip}")
    print(f"[+] رنج: {NETWORK_BASE}{START} → {NETWORK_BASE}{END}\n")

    for idx, i in enumerate(range(START, END + 1), start=1):
        ip = f"{NETWORK_BASE}{i}"
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", PING_TIMEOUT, ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            PING_RESULTS[ip] = (result.returncode == 0)
        except:
            PING_RESULTS[ip] = False

        progress_bar(idx, total_ips)
        time.sleep(0.01)

    print("\n\n[+] ping scan تمام شد")
    time.sleep(1)

    print("\n[+] خواندن جدول ARP ...\n")
    arp_entries = parse_arp()

    # حذف خود سیستم
    arp_entries = [
        d for d in arp_entries
        if d["ip"] != my_ip and d["mac"] != my_mac
    ]

    # دسته‌بندی
    ping_ok = []
    arp_only = []
    incomplete = []

    for d in arp_entries:
        ip = d["ip"]
        if d["mac"] == "<incomplete>":
            incomplete.append(d)
        elif PING_RESULTS.get(ip):
            ping_ok.append(d)
        else:
            arp_only.append(d)

    # مرتب‌سازی عددی IP
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

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] اسکن توسط کاربر متوقف شد")
