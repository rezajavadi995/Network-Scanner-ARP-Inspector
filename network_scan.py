#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess, sys, time, re, socket, struct, shutil, os
from datetime import datetime

# =========================================================
# ===================== Language Layer ====================
# =========================================================
CONF_FILE = "/opt/network-scanner/.netscan.conf"
NETSCAN_LANG = "en"
if os.path.exists(CONF_FILE):
    try:
        with open(CONF_FILE) as f:
            for l in f:
                if l.startswith("NETSCAN_LANG="):
                    NETSCAN_LANG = l.strip().split("=")[1]
    except:
        pass

TEXT = {
    "en": {
        "menu_title": "Network Scanner & ARP Inspector",
        "menu_option_scan": "1) Start Network Scan",
        "menu_option_update": "2) Update Script from GitHub",
        "menu_option_uninstall": "3) Uninstall",
        "menu_option_exit": "4) Exit",
        "prompt_choice": "Enter your choice:",
        "prompt_language": "Select language:",
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
        "stopped": "Scan interrupted by user",
        "updating": "Updating script from GitHub...",
        "update_done": "Update completed.",
        "uninstalling": "Uninstalling...",
        "uninstall_done": "Uninstallation completed.",
        "press_enter": "Press Enter to continue..."
    },
    "fa": {
        "menu_title": "Network Scanner & ARP Inspector",
        "menu_option_scan": "1) شروع اسکن شبکه",
        "menu_option_update": "2) بروزرسانی اسکریپت از GitHub",
        "menu_option_uninstall": "3) حذف برنامه",
        "menu_option_exit": "4) خروج",
        "prompt_choice": "انتخاب شما:",
        "prompt_language": "انتخاب زبان:",
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
        "stopped": "اسکن توسط کاربر متوقف شد",
        "updating": "در حال بروزرسانی از GitHub...",
        "update_done": "بروزرسانی انجام شد.",
        "uninstalling": "در حال حذف برنامه...",
        "uninstall_done": "حذف با موفقیت انجام شد.",
        "press_enter": "برای ادامه Enter بزنید..."
    }
}

T = TEXT.get(NETSCAN_LANG, TEXT["en"])

# =========================================================
# ===================== Utilities ========================
# =========================================================

NETWORK_BASE = "192.168.1."
START = 1
END = 255
PING_TIMEOUT = "1"
BASE_DELAY = 0.03
ARP_DELAY = 0.5

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
# =================== MAC & Vendor =======================
# =========================================================

OUI_DB = {
    "001A79": "Apple", "F099BF": "Samsung", "1063C8": "Huawei", "DCA632": "Xiaomi",
    "0004ED": "TP-Link", "FCFBFB": "Ubiquiti", "D8EB97": "Intel", "AC1203": "Cisco",
    "BC926B": "ASUS", "B827EB": "Raspberry Pi", "080027": "VirtualBox", "000569": "VMware"
}

def normalize_mac(mac):
    if not mac or mac=="<incomplete>":
        return None
    return re.sub(r'[^0-9A-Fa-f]', '', mac).upper()

def is_locally_administered(mac_hex):
    try:
        first_octet = int(mac_hex[0:2],16)
        return bool(first_octet & 0b00000010)
    except:
        return False

def get_vendor(mac):
    mac_hex = normalize_mac(mac)
    if not mac_hex:
        return "Unknown"
    if is_locally_administered(mac_hex):
        return "Randomized / Locally Administered"
    return OUI_DB.get(mac_hex[:6],"Unknown")

# =========================================================
# ================= System Information ====================
# =========================================================

def get_interface():
    try:
        out = subprocess.check_output(["ip","route"], text=True)
        for l in out.splitlines():
            if l.startswith("default"):
                return l.split()[l.split().index("dev")+1]
    except:
        pass
    return "unknown"

def get_my_ip():
    try:
        return subprocess.check_output(["hostname","-I"], text=True).split()[0]
    except:
        return "unknown"

def get_my_mac(interface):
    try:
        if interface!="unknown":
            with open(f"/sys/class/net/{interface}/address") as f:
                return f.read().strip().lower()
    except:
        pass
    return "<incomplete>"

# =========================================================
# ===================== ARP Reader ========================
# =========================================================

def read_arp():
    entries=[]
    try:
        out = subprocess.check_output(["ip","neigh"], text=True)
        for l in out.splitlines():
            p=l.split()
            ip=p[0]
            mac="<incomplete>"
            if "lladdr" in p:
                mac=p[p.index("lladdr")+1]
            entries.append({"ip":ip,"mac":mac,"vendor":get_vendor(mac)})
    except:
        pass
    return entries

# =========================================================
# ==================== Actions ===========================
# =========================================================

def perform_scan():
    iface = get_interface()
    my_ip = get_my_ip()
    my_mac = get_my_mac(iface)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n[INFO] {}        : {}".format(T["info_interface"], iface))
    print("[INFO] {}             : {}".format(T["info_mode"], T["mode"]))
    print("[INFO] {}    : {}0/24".format(T["info_network"], NETWORK_BASE))
    print("[INFO] {}       : {} ms".format(T["info_delay"], int(BASE_DELAY*1000)))
    print("[INFO] {}       : {}".format(T["info_arp"], T["arp_ip"]))
    print("[INFO] {}       : {}\n".format(T["info_started"], now))

    print("[+] {}".format(T["scan_start"]))

    total_ips = END-START+1
    ping_results={}

    for idx,i in enumerate(range(START,END+1),1):
        ip=f"{NETWORK_BASE}{i}"
        r=subprocess.run(["ping","-c","1","-W",PING_TIMEOUT,ip],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        ping_results[ip]=(r.returncode==0)
        progress_bar(idx,total_ips)
        time.sleep(BASE_DELAY)

    print("\n[+] {}".format(T["ping_done"]))
    time.sleep(ARP_DELAY)

    print("\n[+] {}\n".format(T["arp_read"]))
    arp=read_arp()

    active,arp_only,incomplete=[],[],[]

    for d in arp:
        if d["ip"]==my_ip: continue
        if normalize_mac(d["mac"])==normalize_mac(my_mac): continue
        if d["mac"]=="<incomplete>": incomplete.append(d)
        elif ping_results.get(d["ip"]): active.append(d)
        else: arp_only.append(d)

    active.sort(key=lambda x:ip_to_int(x["ip"]))
    arp_only.sort(key=lambda x:ip_to_int(x["ip"]))
    incomplete.sort(key=lambda x:ip_to_int(x["ip"]))

    print("========== {} ==========".format(T["active"]))
    for d in active:
        print(f"✅ {d['ip']}  {d['mac']}  [{d['vendor']}]")

    print("\n========== {} ==========".format(T["arp_only"]))
    for d in arp_only:
        print(f"⚠️  {d['ip']}  {d['mac']}  [{d['vendor']}]")

    print("\n========== {} ==========".format(T["incomplete"]))
    for d in incomplete:
        print(f"❌ {d['ip']}  <incomplete>")

    total=len(active)+len(arp_only)+len(incomplete)
    print("\n{}: {}".format(T["total"],total))
    print("{}: {}".format(T["total_self"],total+1))
    print("[✓] {}".format(T["done"]))

def perform_update():
    print("\n[+] {}".format(T["updating"]))
    url="https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/network_scan.py"
    subprocess.run(["curl","-fsSL",url,"-o","network_scan.py"])
    subprocess.run(["chmod","+x","network_scan.py"])
    print("[✓] {}".format(T["update_done"]))
    input(f"{T['press_enter']}")

def perform_uninstall():
    print("\n[+] {}".format(T["uninstalling"]))
    BIN_PATH="/usr/local/bin/netscan"
    INSTALL_DIR="/opt/network-scanner"
    if os.path.islink(BIN_PATH) or os.path.exists(BIN_PATH):
        os.remove(BIN_PATH)
    if os.path.exists(INSTALL_DIR):
        shutil.rmtree(INSTALL_DIR)
    print("[✓] {}".format(T["uninstall_done"]))
    input(f"{T['press_enter']}")

# =========================================================
# ==================== Menu ==============================
# =========================================================

def main_menu():
    while True:
        print("\n==================== {} ====================".format(T["menu_title"]))
        print(T["menu_option_scan"])
        print(T["menu_option_update"])
        print(T["menu_option_uninstall"])
        print(T["menu_option_exit"])
        choice=input(f"{T['prompt_choice']} ")
        if choice=="1": perform_scan()
        elif choice=="2": perform_update()
        elif choice=="3": perform_uninstall(); break
        elif choice=="4": break
        else: print("[!] Invalid choice / انتخاب نامعتبر")

if __name__=="__main__":
    main_menu()
