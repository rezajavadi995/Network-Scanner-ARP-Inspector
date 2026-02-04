#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import time
import itertools
import re
import socket
import struct
import shutil
import signal
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
FG_MAGENTA = "\033[95m"

# =========================================================
# ===================== Paths =============================
# =========================================================
BASE_DIR = "/opt/network-scanner"
CONF_FILE = f"{BASE_DIR}/.netscan.conf"
OUI_DB_FILE = f"{BASE_DIR}/oui.db"
BIN_PATH = "/usr/local/bin/netscan"
OUI_LOCAL_DB = OUI_DB_FILE

# ===================== style progress bar  =====================
BRAILLE_FRAMES = ["⠷", "⠿", "⠾", "⠶", "⠦", "⠤", "⠠"]
spinner_cycle = itertools.cycle(BRAILLE_FRAMES)


def render_progress_bar(percent, width=10):
    """
    ▓▓▓░░░░░░ style progress bar
    """
    filled = int((percent / 100) * width)
    return "▓" * filled + "░" * (width - filled)
# =========================================================
# ===================== OUI Mode ==========================
# =========================================================
OUI_MODE = "offline"
#=============================


if os.path.exists(CONF_FILE):
    try:
        with open(CONF_FILE, "r") as f:
            for line in f:
                line = line.strip()

                if not line:
                    continue
                if line.startswith("#"):
                    continue

                if line.startswith("OUI_MODE="):
                    value = line.split("=", 1)[1].strip().lower()
                    if value in ("online", "offline"):
                        OUI_MODE = value
    except Exception as e:
        print(f"[WARN] Failed to read config file: {e}")

print(f"[OUI] Vendor lookup mode: {OUI_MODE.upper()}")


_OUI_CACHE = None

def load_oui_db():
    global _OUI_CACHE
    if _OUI_CACHE is not None:
        return _OUI_CACHE

    db = {}
    if not os.path.exists(OUI_DB_FILE):
        return db

    try:
        with open(OUI_DB_FILE, "r", errors="ignore") as f:
            for line in f:
                if "|" in line:
                    k, v = line.strip().split("|", 1)
                    db[k.strip()] = v.strip()
    except:
        pass

    _OUI_CACHE = db
    return db
    


def lookup_oui_online(prefix):
    try:
        import urllib.request
        url = f"https://api.macvendors.com/{prefix}"
        with urllib.request.urlopen(url, timeout=2) as r:
            return r.read().decode().strip()
    except:
        return None
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

        #new
        "scan_continue": "Scan will continue with current network",
        "scan_cancelled": "Scan cancelled by user",
        "range_edit": "Enter new network range",
        "enter_new_range": "New network range (CIDR)",
        "invalid_range": "Invalid network range",
        "range_set": "Network range set to",
        "network_name": "Network name" ,
        

        "menu_width": 54 ,
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

        
        "scan_continue": "اسکن با رنج فعلی ادامه پیدا می‌کند",
        "scan_cancelled": "اسکن توسط کاربر لغو شد",
        "range_edit": "رنج جدید شبکه را وارد کنید",
        "enter_new_range": "رنج جدید (CIDR)",
        "invalid_range": "رنج واردشده نامعتبر است",
        "range_set": "رنج شبکه تنظیم شد",
        "network_name": "نام شبکه" ,

        "menu_width": 60 ,
    }
}

T = TEXT.get(NETSCAN_LANG, TEXT["en"])
MENU_WIDTH = T.get("menu_width", 54)



def Tget(key):
    """
    FA: گرفتن متن امن از دیکشنری زبان
    EN: Safely fetch localized text with fallback
    """
    try:
        return T.get(key, TEXT["en"].get(key, key))
    except Exception:
        return key



#=====TTL HELPER =============================================
def stable_ttl_lookup(ip, retries=2, timeout=1):
    """
    Safe TTL extraction with retries
    Returns int TTL or None
    """
    for _ in range(retries + 1):
        try:
            ttl = extract_ttl_from_ping(ip, timeout=timeout)
            if isinstance(ttl, int) and 1 <= ttl <= 255:
                return ttl
        except Exception:
            pass
    return None
    
# =========================================================
# ===================== Network ===========================
# =========================================================
NETWORK_BASE = None
START = None
END = None

PING_TIMEOUT = 1
BASE_DELAY = 0.03
ARP_DELAY = 0.4

# =========================================================
# ===================== Helpers ===========================
# =========================================================

def analyze_underlying_medium(ctx):
    score = 0
    reasons = []

    # Virtual NIC
    if ctx.get("virtual_suspected"):
        score += 0.25
        reasons.append("Virtual NIC detected")

    # Private gateway
    if ctx.get("gateway", "").startswith(("192.168.", "10.", "172.")):
        score += 0.2
        reasons.append("Private gateway")

    # NAT suspected
    if ctx.get("nat_suspected"):
        score += 0.2
        reasons.append("NAT detected")

    # TTL variance (اگر داشتی)
    if ctx.get("ttl_variance"):
        score += 0.15
        reasons.append("TTL variance")

    # Cap
    score = min(score, 1.0)

    if score >= 0.6:
        underlying = "Likely Wi-Fi (Host)"
    else:
        underlying = "Unknown"

    return {
        "underlying": underlying,
        "confidence": round(score, 2),
        "reasons": reasons
    }


def print_network_overview(ctx, net_range, start_time):
    """
    چاپ اطلاعات کامل شبکه، دستگاه و هشدارها
    """
    print(FG_CYAN + BOLD + "\n\n==================== NETWORK SCAN INITIATED ====================" + RESET)
    print(FG_YELLOW + BOLD + "   Reza Javadi - Network Scanner" + RESET)
    print(FG_CYAN + BOLD + "================================================================\n" + RESET)

    # ---- CONNECTION OVERVIEW ----
    print(FG_CYAN + BOLD + "==================== CONNECTION OVERVIEW ====================" + RESET)
    print(f"""
[INFO] Interface        : {ctx['interface']}
[INFO] Interface Mode   : {ctx['iface_mode']}
[INFO] Connection Name  : {ctx['connection_name']}
[INFO] Medium (VM)      : {ctx.get('connection_medium')}
[INFO] Underlying Media : {ctx.get('underlying_medium')}
[INFO] SSID             : {ctx.get('ssid') or 'Unavailable (VM limitation)'}
[INFO] Confidence       : {ctx.get('confidence')}
""")

    oui_mode = ctx.get("oui_mode", "unknown")

    if oui_mode == "online":
        oui_display = "Online (Live lookup)"
    elif oui_mode == "offline":
        oui_display = "Offline (Local database)"
    else:
        oui_display = "Unknown"

    print(f"[INFO] OUI Database     : {oui_display}")
    



    
    if ctx.get("analysis_reasons"):
        print(FG_YELLOW + "[ANALYSIS]" + RESET)
        for r in ctx["analysis_reasons"]:
            print(" -", r)

    # ---- NETWORK CONTEXT ----
    print(FG_CYAN + BOLD + "==================== NETWORK CONTEXT ========================" + RESET)
    print(f"""
[INFO] Network Range    : {net_range}
[INFO] Scan Start Time  : {start_time}

""")

    # ---- LOCAL DEVICE ----
    print(FG_CYAN + BOLD + "==================== LOCAL DEVICE (YOU) =====================" + RESET)
    print(f"""
IP Address          : {ctx['ip']}
MAC Address         : {ctx['mac']}
Vendor              : {ctx['vendor']}
""")

    # ---- GATEWAY INFO ----
    print(FG_CYAN + BOLD + "==================== GATEWAY INFO ===========================" + RESET)
    print(f"""
Gateway IP          : {ctx['gateway']}
Gateway MAC         : {ctx['gateway_mac']}  ({ctx.get('gateway_vendor', 'Unknown')})
Vendor              : {ctx.get('gateway_vendor', 'Unknown')}
""")
    # ---- WARNINGS ----
    if ctx["warnings"]:
        print(FG_RED + BOLD + "==================== WARNINGS ===============================" + RESET)
        for w in ctx["warnings"]:
            print(FG_RED + f"⚠️  {w}" + RESET)
        print(FG_RED + "============================================================\n" + RESET)

    #print(FG_GREEN + BOLD + "[+] Scan started... | اسکن شبکه شروع شد" + RESET)
    print()


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


def box_width(min_width=40, max_width=100):
    try:
        cols = shutil.get_terminal_size().columns
        return max(min_width, min(cols - 4, max_width))
    except:
        return min_width

def pad(text, width):
    if len(text) > width:
        return text[:width]
    return text.ljust(width)

def ensure_safe_cwd():
    """
    FA: اطمینان از اینکه دایرکتوری کاری معتبر است
    EN: Ensure current working directory is valid
    """
    try:
        os.getcwd()
    except FileNotFoundError:
        # FA: اگر مسیر فعلی وجود نداشت، برگرد به مسیر امن
        # EN: If current directory is gone, switch to safe path
        try:
            os.chdir(BASE_DIR)
        except:
            os.chdir("/")
######
def run_update():
    """
    FA: اجرای فرآیند بروزرسانی با پیام واضح و کنترل کامل
    EN: Run update process with clear status, protection, and feedback
    """
    ensure_safe_cwd()
    os.system("clear")  # FA: پاک‌کردن صفحه قبل از شروع / EN: clear screen before starting

    print(FG_BLUE + BOLD + "=== UPDATE MODE ===" + RESET)
    print(FG_GRAY + "Updating... please wait." + RESET)
    print(FG_YELLOW + "Do NOT press Ctrl+C." + RESET)
    print()
    time.sleep(0.5)

    # FA: ذخیره وضعیت قبلی Ctrl+C / EN: Save previous SIGINT handler
    old_sigint = signal.getsignal(signal.SIGINT)

    try:
        # FA: غیرفعال‌کردن Ctrl+C در زمان بروزرسانی
        signal.signal(signal.SIGINT, signal.SIG_IGN)

        # FA: اجرای بروزرسانی با خروجی زنده
        process = subprocess.Popen(
            ["python3", f"{BASE_DIR}/network_scan.py", "--update"],
            stdin=sys.stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1
        )

        # FA: نمایش خروجی خط‌به‌خط به‌صورت امن
        if process.stdout:
            for line in iter(process.stdout.readline, ""):
                if line == "" and process.poll() is not None:
                    break
                if line:
                    print(FG_CYAN + line.rstrip() + RESET)

        retcode = process.wait()

        if retcode == 0:
            print("\n" + FG_GREEN + "[✓] Update completed successfully." + RESET)
        else:
            print("\n" + FG_RED + "[✗] Update failed." + RESET)

    except KeyboardInterrupt:
        # FA: این حالت عملاً نباید رخ دهد، ولی ایمن‌سازی شده
        print("\n" + FG_RED + "[!] Update interrupted by user!" + RESET)
        print(FG_YELLOW + "System state may be inconsistent." + RESET)

    finally:
        # FA: بازگرداندن Ctrl+C به حالت قبل (خیلی مهم)
        signal.signal(signal.SIGINT, old_sigint)

    input("\nPress Enter to return to menu...")





#brain 


def build_network_context():
    """
    FA:
    جمع‌آوری تمام اطلاعات پایه شبکه و محیط اجرا
    بدون هیچ اسکن تهاجمی

    EN:
    Build full base network reality context
    """
    context = {
    "interface": None,
    "medium": None,
    "iface_mode": None,
    "connection_name": None,

    # --- NEW ---
    "connection_medium": None,      # Ethernet / Wi-Fi (what VM sees)
    "underlying_medium": None,      # Likely Wi-Fi (Host)
    "ssid": None,                   # None → unavailable
    "confidence": None,
    "analysis_reasons": [],
    # -----------

    "ip": None,
    "mac": None,
    "vendor": None,
    "gateway": None,
    "gateway_mac": None,
    "nat_suspected": False,
    "virtual_suspected": False,
    "warnings": []
    }
    return context

# ===================== Interface Reality Detection new v1.2


def detect_active_interface():
    """
    FA: تشخیص اینترفیس فعال واقعی
    """
    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[line.split().index("dev") + 1]
    except Exception:
        pass
    return None
#rezajavadi995

def detect_medium(iface):
    """
    FA: تشخیص نوع رسانه اتصال (Wi-Fi یا Ethernet)
    """
    if os.path.exists(f"/sys/class/net/{iface}/wireless"):
        return "Wi-Fi"
    return "Ethernet"



def detect_wifi_mode(iface):
    """
    FA: تشخیص Managed / Monitor / Unknown
    """
    try:
        out = subprocess.check_output(["iw", "dev"], text=True)
        block = out.split(f"Interface {iface}")[1]
        for line in block.splitlines():
            if "type" in line:
                return line.split()[-1]
    except Exception:
        pass
    return "Unknown"


def detect_gateway():
    """
    FA: تشخیص Gateway و MAC آن
    """
    gw_ip = None
    gw_mac = None

    try:
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default"):
                gw_ip = line.split()[2]
                break

        if gw_ip:
            arp = subprocess.check_output(["ip", "neigh"], text=True)
            for l in arp.splitlines():
                if l.startswith(gw_ip) and "lladdr" in l:
                    gw_mac = l.split()[l.split().index("lladdr") + 1]
    except Exception:
        pass

    return gw_ip, gw_mac


def detect_nat_signs(context):
    """
    FA: تشخیص نشانه‌های NAT
    """
    gw = context["gateway"]
    ip = context["ip"]

    if not gw or not ip:
        return

    if gw.startswith("10.") or gw.startswith("192.168.") or gw.startswith("172."):
        context["nat_suspected"] = True
        context["warnings"].append("Private gateway detected (possible NAT)")


def detect_virtualization(context):
    """
    FA: تشخیص محیط مجازی
    """
    mac = context["mac"]
    iface = context["interface"]

    virtual_ouis = {
        "080027": "VirtualBox",
        "000569": "VMware",
        "001C14": "Hyper-V",
        "525400": "QEMU"
    }

    if mac:
        prefix = mac.upper().replace(":", "")[:6]
        if prefix in virtual_ouis:
            context["virtual_suspected"] = True
            context["warnings"].append(
                f"Virtual NIC detected ({virtual_ouis[prefix]})"
            )

    if iface and any(x in iface.lower() for x in ["vbox", "vm", "vir", "docker"]):
        context["virtual_suspected"] = True



def collect_base_reality():
    """
    جمع‌آوری تمام اطلاعات پایه شبکه و محیط اجرا
    شامل:
    - Interface، IP، MAC، Vendor سیستم
    - Gateway IP، MAC و Vendor
    - Medium واقعی و واسطه (Underlying Medium)
    - SSID (در VM محدودیت دارد)
    - تحلیل احتمال NAT و Virtualization
    - جمع‌آوری هشدارها
    """
    ctx = build_network_context()  # پایه شبکه

    # --------- شناسایی اولیه رابط و شبکه ---------
    iface = detect_active_interface()
    ctx["interface"] = iface

    ctx["medium"] = detect_medium(iface)
    if ctx["medium"] == "Wi-Fi":
        ctx["iface_mode"] = detect_wifi_mode(iface)

    else:
        ctx["iface_mode"] = "N/A"

    ctx["connection_name"] = get_connection_name(iface)
    ctx["ip"] = get_my_ip()
    ctx["mac"] = get_my_mac(iface)

    # Vendor خود سیستم
    ctx["vendor"] = get_vendor(ctx["mac"])

    # --------- Gateway ---------
    gw_ip, gw_mac = detect_gateway()
    ctx["gateway"] = gw_ip
    ctx["gateway_mac"] = gw_mac
    ctx["gateway_vendor"] = get_vendor(ctx["gateway_mac"])  # Vendor گیت‌وی

    # --------- تحلیل NAT و Virtualization ---------
    detect_nat_signs(ctx)
    detect_virtualization(ctx)

    # --------- OUI DATABASE MODE (NEW) ---------
    if os.path.exists(OUI_LOCAL_DB):
        ctx["oui_mode"] = "offline"
    else:
        ctx["oui_mode"] = "online"

    # --------- تحلیل Underlying / SSID ---------
    ctx["connection_medium"] = ctx.get("medium")  # آنچه VM می‌بیند

    analysis = analyze_underlying_medium(ctx)
    ctx["underlying_medium"] = analysis["underlying"]
    ctx["confidence"] = analysis["confidence"]
    ctx["analysis_reasons"] = analysis["reasons"]

    ctx["ssid"] = None  # محدودیت VM: SSID قابل دسترس نیست

    # --------- بازگشت Context کامل ---------
    return ctx


def print_base_reality(ctx):
    print(FG_CYAN + BOLD + "\n========== NETWORK REALITY CHECK ==========" + RESET)

    for k, v in ctx.items():
        if k == "warnings":
            continue
        print(f"{k:18} : {v}")

    if ctx["warnings"]:
        print(FG_RED + BOLD + "\n[WARNINGS]" + RESET)
        for w in ctx["warnings"]:
            print(FG_RED + f" - {w}" + RESET)

    print(FG_CYAN + "==========================================\n" + RESET)


#------------helper2--------------------


def extract_ttl_from_ping_output(ping_output):
    if not ping_output:
        return None

    for line in ping_output.splitlines():
        if "ttl=" in line.lower():
            try:
                return int(line.lower().split("ttl=")[1].split()[0])
            except:
                return None
    return None
    


#..
def detect_hidden_hops_by_ttl(topology):
    """
    FA:
    تشخیص NAT یا Router پنهان با تحلیل TTL

    EN:
    Detect hidden hops using TTL clustering
    """
    alerts = []

    for ap in topology.get("aps", []):
        ttl_map = {}
        ttl_count = 0

        for d in topology.get("devices", []):
            if d.get("behind") == ap["ip"]:
                ttl = d.get("ttl")
                if ttl:
                    ttl_map.setdefault(ttl, 0)
                    ttl_map[ttl] += 1
                    ttl_count += 1

        if ttl_count >= 2 and len(ttl_map) >= 2:
            ap["notes"].append("Multiple TTL clusters detected")
            ap["hidden_hops"] = True

            alerts.append({
                "type": "TTL_CLUSTER",
                "ap": ap["ip"],
                "ttls": ttl_map
            })
        else:
            ap["hidden_hops"] = False

    return alerts


def calculate_arp_density(topology):
    """
    FA:
    محاسبه تراکم ARP پشت هر AP

    EN:
    Calculate ARP density per AP
    """
    density = {}

    for ap in topology.get("aps", []):
        mac_set = set()
        for d in topology.get("devices", []):
            if d.get("behind") == ap["ip"]:
                mac_set.add(d.get("mac"))
        density[ap["ip"]] = len(mac_set)

    return density





#step2
#step2
def enrich_device(device, ctx, ping_ok):
    """
    تحلیل یک دستگاه بر اساس ARP / Vendor / Gateway / TTL
    """
    enriched = device.copy()

    ip = device.get("ip")
    ttl_value = None
    if ping_ok.get(ip):
        ttl_value = ping_ok[ip]["ttl"]

    enriched["ttl"] = ttl_value

    if ttl_value is not None:
        if ttl_value <= 64:
            enriched["ttl_display"] = f"{ttl_value} (Linux/Unix)"
        elif ttl_value <= 128:
            enriched["ttl_display"] = f"{ttl_value} (Windows)"
        else:
            enriched["ttl_display"] = f"{ttl_value} (Unknown OS)"
    else:
        enriched["ttl_display"] = "N/A"

    # ===================== نقش و یادداشت =====================
    enriched["role"] = "unknown"
    enriched["behind"] = None
    enriched["suspected_nat"] = False
    enriched["suspected_virtual"] = False
    enriched["notes"] = enriched.get("notes", [])

    mac = (device.get("mac") or "").lower()
    vendor = (device.get("vendor") or "").lower()

    # Gateway detection
    if device.get("ip") == ctx.get("gateway"):
        enriched["role"] = "gateway"
        enriched["notes"].append("Default Gateway")

    # AP / Router suspicion
    router_keywords = [
        "router", "wireless", "mikrotik", "ubiquiti",
        "tp-link", "d-link", "asus", "netgear", "huawei"
    ]

    if any(k in vendor for k in router_keywords):
        if enriched["role"] != "gateway":
            enriched["role"] = "ap"
            enriched["notes"].append("Vendor suggests AP/Router")

    # Virtual suspicion
    virtual_vendors = [
        "vmware", "virtualbox", "qemu", "parallels", "hyper-v"
    ]

    if any(v in vendor for v in virtual_vendors):
        enriched["suspected_virtual"] = True
        enriched["notes"].append("Virtual NIC detected")

    # NAT suspicion
    if ctx.get("medium") == "Wi-Fi" and enriched["role"] == "device":
        enriched["suspected_nat"] = True
        enriched["notes"].append("Possible NAT behind Wi-Fi")

    return enriched
    
#build topology


def build_topology(devices, ctx):
    """
    FA:
    ساخت توپولوژی حدسی شبکه

    EN:
    Build guessed network topology
    """
    topology = {
        "gateway": None,
        "aps": [],
        "devices": []
    }

    for d in devices:
        if d["role"] == "gateway":
            topology["gateway"] = d
        elif d["role"] == "ap":
            topology["aps"].append(d)
        else:
            topology["devices"].append(d)

    # ---- Assign parent (behind) ----
    for d in topology["devices"]:
        if topology["aps"]:
            d["behind"] = topology["aps"][0]["ip"]
            d["notes"].append("Behind AP")
        elif topology["gateway"]:
            d["behind"] = topology["gateway"]["ip"]
            d["notes"].append("Direct to Gateway")

    return topology





#


def print_topology(topology):
    print(FG_CYAN + BOLD + "\n==================== NETWORK TOPOLOGY (GUESS) ====================" + RESET)

    gw = topology.get("gateway")
    if gw:
        print(FG_GREEN + f"⚛ Gateway: {gw['ip']}  {gw.get('vendor','')}" + RESET)
        for note in gw.get("notes", []):
            print(FG_GREEN + f"   └─ {note}" + RESET)

    for ap in topology.get("aps", []):
        print(FG_BLUE + f"➿ AP: {ap['ip']}  {ap.get('vendor','')}" + RESET)
        for note in ap.get("notes", []):
            print(FG_BLUE + f"   └─ {note}" + RESET)

    for d in topology.get("devices", []):
        color = FG_GREEN
        icon = "✳️"

        if d.get("suspected_virtual"):
            color = FG_RED
            icon = "♨️"
        elif d.get("suspected_nat"):
            color = FG_YELLOW
            icon = "✴️"

        print(color + f"{icon} Device: {d['ip']}  {d.get('vendor','')}" + RESET)

        if d.get("behind"):
            print(color + f"   └─ Behind: {d['behind']}" + RESET)

        for note in d.get("notes", []):
            print(color + f"   └─ {note}" + RESET)

    print(FG_CYAN + "==================================================================\n" + RESET)



#ap spet3




def detect_multiple_networks_behind_ap(topology):
    """
    FA:
    تشخیص وجود چند Subnet پشت یک AP

    EN:
    Detect multiple networks behind an AP
    """
    alerts = []

    for ap in topology.get("aps", []):
        subnets = set()

        for d in topology.get("devices", []):
            if d.get("behind") == ap["ip"]:
                ip = d.get("ip")
                if ip:
                    subnet = ".".join(ip.split(".")[:3])
                    subnets.add(subnet)

        if len(subnets) > 1:
            ap["notes"].append("Multiple subnets detected behind this AP")
            ap["multiple_networks"] = True
            alerts.append({
                "type": "MULTI_SUBNET",
                "ap": ap["ip"],
                "subnets": list(subnets)
            })
        else:
            ap["multiple_networks"] = False

    return alerts

#amu_reza

#3.2
def detect_wifi_behind_wifi(topology, ctx):
    """
    FA:
    تشخیص Wi-Fi پشت Wi-Fi (Double NAT / Repeater)

    EN:
    Detect Wi-Fi behind Wi-Fi / Double NAT
    """
    alerts = []

    if ctx.get("medium") != "Wi-Fi":
        return alerts

    for ap in topology.get("aps", []):
        if ap.get("suspected_nat"):
            ap["notes"].append("AP behind Wi-Fi (Possible Repeater / Double NAT)")
            ap["double_nat"] = True

            alerts.append({
                "type": "DOUBLE_NAT_WIFI",
                "ap": ap["ip"],
                "reason": "AP is behind Wi-Fi and uses private gateway"
            })
        else:
            ap["double_nat"] = False

    return alerts

#3.3

def print_stage3_alerts(multi_net_alerts, wifi_nat_alerts, ttl_alerts):
    print(FG_RED + BOLD + "\n==================== TOPOLOGY WARNINGS ====================" + RESET)

    if not multi_net_alerts and not wifi_nat_alerts and not ttl_alerts:
        print(FG_GREEN + "✔ No critical topology anomalies detected" + RESET)
        return

    for a in multi_net_alerts:
        print(
            FG_YELLOW +
            f"⚠️  Multiple networks behind AP {a['ap']} -> {', '.join(a['subnets'])}"
            + RESET
        )

    for a in wifi_nat_alerts:
        print(
            FG_RED +
            f"🔥 Wi-Fi behind Wi-Fi detected at AP {a['ap']} ({a['reason']})"
            + RESET
        )

    for a in ttl_alerts:
        print(
            FG_RED +
            f"🧬 Hidden hops behind AP {a['ap']} | TTL clusters: {a['ttls']}"
            + RESET
        )

    print(FG_RED + "===========================================================\n" + RESET)


#step4--------- ARP density + Vendor clustering برای تشخیص Mesh و Load‑balancer

def cluster_vendors(topology):
    """
    FA:
    خوشه‌بندی دستگاه‌ها بر اساس Vendor پشت هر AP

    EN:
    Cluster devices by vendor per AP
    """
    clusters = {}

    for ap in topology.get("aps", []):
        vendors = {}
        for d in topology.get("devices", []):
            if d.get("behind") == ap["ip"]:
                vendor = d.get("vendor", "Unknown")
                vendors.setdefault(vendor, 0)
                vendors[vendor] += 1
        clusters[ap["ip"]] = vendors

    return clusters

def detect_mesh_or_hidden_subnets(topology):
    """
    FA:
    تشخیص Mesh یا شبکه‌های پنهان با ARP density و Vendor clustering

    EN:
    Detect Mesh or hidden subnets using ARP density and Vendor clustering
    """
    alerts = []

    arp_density = calculate_arp_density(topology)
    vendor_clusters = cluster_vendors(topology)

    for ap in topology.get("aps", []):
        dens = arp_density.get(ap["ip"], 0)
        vclusters = vendor_clusters.get(ap["ip"], {})

        # قانون ساده: density بالاتر از 5 و vendor متنوع → هشدار
        if dens > 5 and len(vclusters) > 1:
            ap["notes"].append("High ARP density & multiple vendors detected (possible Mesh / hidden subnet)")
            ap["mesh_suspected"] = True
            alerts.append({
                "type": "MESH_HIDDEN",
                "ap": ap["ip"],
                "arp_density": dens,
                "vendor_clusters": vclusters
            })
        else:
            ap["mesh_suspected"] = False

    return alerts


def print_stage4_alerts(multi_net_alerts, wifi_nat_alerts, ttl_alerts, mesh_alerts):
    print_stage3_alerts(multi_net_alerts, wifi_nat_alerts, ttl_alerts)

    if not mesh_alerts:
        return

    for a in mesh_alerts:
        print(
            FG_MAGENTA +
            f"🌐 Mesh/Hidden subnet suspected at AP {a['ap']} | ARP density: {a['arp_density']} | Vendors: {list(a['vendor_clusters'].keys())}"
            + RESET
        )



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
    """
    دریافت نام Vendor بر اساس MAC
    مسیر offline یا online بسته به OUI_MODE
    """
    #gateway_vendor = get_vendor(ctx.get("gateway_mac"))
    mac_hex = normalize_mac(mac)
    if not mac_hex:
        return "Unknown"

    if is_locally_administered(mac_hex):
        return "Randomized / Locally Administered"

    # مسیر آنلاین
    if OUI_MODE == "online":
        try:
            vendor = lookup_oui_online(mac_hex[:6])
            if vendor:
                return vendor
            # اگر آنلاین نبود fallback به offline
        except Exception as e:
            print(f"[WARN] Online lookup failed: {e}")
            print("[INFO] Falling back to offline database")

    # مسیر offline
    try:
        db = load_oui_db()  # بارگذاری دیتابیس offline
        return db.get(mac_hex[:6].upper(), "Unknown")
    except Exception as e:
        print(f"[WARN] Offline DB failed: {e}")
        return "Unknown"
    

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
def read_arp_enhanced():
    """
    خواندن ARP table و شناسایی دستگاه‌ها
    - IP واقعی
    - MAC واقعی
    - Vendor با OUI
    - نوع اتصال LAN یا Wi-Fi با حدس
    """
    entries = []
    try:
        out = subprocess.check_output(["ip", "neigh"], text=True)
        for line in out.splitlines():
            parts = line.split()
            ip = parts[0]
            mac = "<incomplete>"
            if "lladdr" in parts:
                mac = parts[parts.index("lladdr") + 1]

            vendor = get_vendor(mac)
            # حدس نوع اتصال از MAC یا prefix (LAN/Wi-Fi)
            conn_type = "Unknown"
            if mac != "<incomplete>":
                mac_prefix = mac.upper().replace(":", "")[:6]
                if mac_prefix in ["080027", "000569", "001C14"]:
                    conn_type = "Virtual / NAT"
                elif mac_prefix.startswith("AC") or mac_prefix.startswith("B4"):
                    conn_type = "Wi-Fi"
                else:
                    conn_type = "Ethernet"

            entries.append({
                "ip": ip,
                "mac": mac,
                "vendor": vendor,
                "connection": conn_type
            })

    except Exception:
        pass
    return entries





# ===================== Persistent Config =====================
def save_network_range(net):
    """
    FA: ذخیره رنج شبکه
    EN: Save detected network range
    """
    try:
        with open(CONF_FILE, "a") as f:
            f.write(f"\nNETWORK_RANGE={net}\n")
    except:
        pass
def load_network_range():
    """
    FA: بارگذاری رنج ذخیره‌شده
    EN: Load saved network range if exists
    """
    if not os.path.exists(CONF_FILE):
        return None

    try:
        with open(CONF_FILE) as f:
            for line in f:
                if line.startswith("NETWORK_RANGE="):
                    return ipaddress.ip_network(
                        line.strip().split("=", 1)[1],
                        strict=False
                    )
    except Exception:
        pass

    return None
# ===================== Network Range Flow =====================
def network_range_flow():
    """
    FA: تشخیص رنج شبکه و تصمیم نهایی کاربر در همان‌جا
    EN: Detect network range and let user decide once
    """

    net = detect_network_range()

    print(f"\n[INFO] {Tget('range_detected')} : {net}")

    ans = input(f"[?] {Tget('range_change')} ").strip().lower()

    # کاربر نمی‌خواهد تغییر دهد
    if ans != "y":
        print(FG_GREEN + Tget("range_keep") + RESET)
        print(FG_GRAY + Tget("scan_continue") + RESET)
        time.sleep(0.5)
        return net

    # کاربر می‌خواهد تغییر دهد
    print(FG_YELLOW + Tget("range_edit") + RESET)
    new_range = input(Tget("enter_new_range") + " ").strip()

    try:
        new_net = ipaddress.ip_network(new_range, strict=False)
    except ValueError:
        print(FG_RED + Tget("invalid_range") + RESET)
        print(FG_RED + Tget("scan_cancelled") + RESET)
        return None

    print(FG_GREEN + f"{Tget('range_set')} : {new_net}" + RESET)
    return new_net






#

def get_connection_name(iface):
    """
    FA: نام واقعی اتصال (SSID یا LAN)
    EN: Real connection name
    """
    name = "Unknown"
    try:
        # لینوکس: nmcli برای وایرلس و LAN
        out = subprocess.check_output(
            ["nmcli", "-t", "-f", "DEVICE,CONNECTION", "device"],
            text=True
        )
        for line in out.splitlines():
            dev, conn = line.split(":", 1)
            if dev == iface:
                name = conn if conn else "Unknown"
                break
    except Exception:
        # اگر خطایی بود، نام Unknown باقی می‌ماند
        pass
    return name
    

#####



# ===================== Interface Reality Detection =====================
def detect_interface_reality(iface):
    """
    تشخیص واقعی نوع اتصال:
    - NAT / Bridge / Wi-Fi / Ethernet واقعی / مجازی
    - بررسی می‌کند کارت وای‌فای است یا LAN
    - بررسی می‌کند مجازی است (VirtualBox, VMware, Hyper-V)
    - بررسی default gateway
    """
    mode = "Unknown"
    try:
        # بررسی اینکه آیا کارت وای‌فای است
        if os.path.exists(f"/sys/class/net/{iface}/wireless"):
            mode = "Wi-Fi"
        else:
            mode = "Ethernet"

        # بررسی default gateway برای تشخیص NAT/Bridge
        out = subprocess.check_output(["ip", "route"], text=True)
        for line in out.splitlines():
            if line.startswith("default") and iface in line:
                gw = line.split()[2]
                # اگر اینترفیس مربوط به ماشین مجازی باشد
                if "vbox" in iface.lower() or "vm" in iface.lower():
                    mode = "NAT / Virtual"
                break

        # بررسی MAC برای تشخیص کارت مجازی
        mac = get_my_mac(iface)
        if mac:
            mac_prefix = mac.upper().replace(":", "")[:6]
            virtual_prefixes = [
                "080027",  # VirtualBox
                "000569",  # VMware
                "001C14",  # Hyper-V
            ]
            if mac_prefix in virtual_prefixes:
                mode = "Virtual / NAT"

    except Exception as e:
        # اگر هر خطایی رخ داد، Unknown باقی می‌ماند
        pass
    return mode


####

# =========================================================
# ===================== Scan =============================
# =========================================================
def perform_scan(ctx):
    global NETWORK_BASE, START, END

    try:
        iface = ctx["interface"]
        my_ip = ctx["ip"]

        # ---- Range decision (dynamic) ----
        net = network_range_flow()
        if net is None:
            print(FG_YELLOW + "[!] Scan cancelled by user | الان داری اسکن را لغو می‌کنی" + RESET)
            time.sleep(1)
            return

        NETWORK_BASE = str(net.network_address).rsplit(".", 1)[0] + "."
        START = net.network_address.packed[-1]
        END = net.broadcast_address.packed[-1]

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ---- Overview ----
        print_network_overview(ctx, net_range=net, start_time=now)

        print(FG_GREEN + "[+] Scan started... | اسکن شبکه شروع شد" + RESET, flush=True)
        print()

        # =====================================================
        # ================= Stage 1: Ping Sweep ===============
        # =====================================================
        ping_ok = {}

        total_hosts = (END - START + 1)

        for idx, i in enumerate(range(START, END + 1), start=1):
            ip = f"{NETWORK_BASE}{i}"

            try:
                r = subprocess.run(
                    ["ping", "-c", "1", "-W", str(PING_TIMEOUT), ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True     
                )
                ttl = extract_ttl_from_ping_output(r.stdout)
                ping_ok[ip] = {
                    "alive": r.returncode == 0,
                    "ttl": ttl
                }

            except KeyboardInterrupt:
                # تمیز کردن خط progress قبل از خروج
                sys.stdout.write("\n")
                sys.stdout.flush()
                raise

            # ---- Progress calculation ----
            percent = int((idx / total_hosts) * 100)
            spinner = next(spinner_cycle)
            bar = render_progress_bar(percent)

            # ---- Render progress bar (overwrite single line) ----
            sys.stdout.write(
                "\r"
                + FG_RED
                + f"{spinner} [PING] {ip:<15}  {bar}  {percent:>3}%"
                + RESET
            )
            sys.stdout.flush()

            time.sleep(BASE_DELAY)

        # ---- Finalize progress bar line ----
        sys.stdout.write("\n")
        sys.stdout.flush()

        print(FG_GREEN + "[+] Ping phase done | مرحله پینگ تمام شد" + RESET, flush=True)
        time.sleep(ARP_DELAY)

        # =====================================================
        # ================= Stage 1.5: ARP ====================
        # =====================================================
        print("[+] Reading ARP table | خواندن جدول ARP\n")
        arp = read_arp_enhanced()
        active, arp_only, incomplete = [], [], []

        for d in arp:
            if d["ip"] == my_ip:
                continue

            if d["mac"] == "<incomplete>":
                incomplete.append(d)
            else:
                ping_info = ping_ok.get(d["ip"])
            if ping_info and ping_info["alive"]:
                active.append(d)
            else:
                    
                arp_only.append(d)

        # ===================== ENRICH BEFORE DISPLAY =====================
        enriched_active = [enrich_device(d, ctx, ping_ok) for d in active]
        enriched_arp_only = [enrich_device(d, ctx, ping_ok) for d in arp_only]
        enriched_incomplete = [enrich_device(d, ctx, ping_ok) for d in incomplete]
        # ---- Output (Hacker Style) ----
        def show_block(title_en, title_fa, data, icon):
            print(f"\n========== {title_en} | {title_fa} ==========")
            for d in data:
                print(
                    FG_CYAN + f"{icon} {d.get('ip')}" +
                    FG_GREEN + f"  [{d.get('vendor', 'Unknown')}]" +
                    FG_YELLOW + f"  MAC: {d.get('mac')}" +
                    FG_MAGENTA + f"  TTL: {d.get('ttl_display', 'N/A')}" +
                    RESET
                )

        show_block("Active Devices", "دستگاه‌های فعال", enriched_active, "✅")
        show_block("ARP Only", "فقط در ARP", enriched_arp_only, "⚠️")
        show_block("Incomplete", "ناقص", enriched_incomplete, "❌")

        total = len(active) + len(arp_only) + len(incomplete)

        print(FG_BLUE + "\n╔════════════════════════════════╗" + RESET)
        print(FG_BLUE + f"║ Total devices        : {total:<5}         ║" + RESET)
        print(FG_BLUE + f"║ Total with self      : {total + 1:<5}         ║" + RESET)
        print(FG_BLUE + "╚════════════════════════════════╝" + RESET)

        print(FG_GREEN + "\n[✓] Scan completed successfully | اسکن با موفقیت انجام شد" + RESET)

        # ===================== Stage 2: Topology =====================
        topology = build_topology(enriched_active + enriched_arp_only, ctx)
        print_topology(topology)

        # ===================== Stage 3: Logical Anomalies =====================
        multi_net_alerts = detect_multiple_networks_behind_ap(topology)
        wifi_nat_alerts = detect_wifi_behind_wifi(topology, ctx)
        ttl_alerts = detect_hidden_hops_by_ttl(topology)

        print_stage3_alerts(multi_net_alerts, wifi_nat_alerts, ttl_alerts)

        # ===================== Stage 4: Mesh / Hidden Networks =====================
        mesh_alerts = detect_mesh_or_hidden_subnets(topology)

        print_stage4_alerts(
            multi_net_alerts,
            wifi_nat_alerts,
            ttl_alerts,
            mesh_alerts
        )

        input("\nPress Enter to continue | برای ادامه Enter بزن")

    except KeyboardInterrupt:
        print("\n" + FG_RED + "[!] Scan interrupted by user" + RESET)
        print(FG_GRAY + "اسکن توسط کاربر متوقف شد" + RESET)
        time.sleep(0.5)
        return

# =========================================================
# ===================== Menu ==============================
# =========================================================
def main_menu(ctx):
    while True:
        os.system("clear")

        W = box_width()  # FA: پیدا کردن عرض مناسب ترمینال / EN: detect proper terminal width
        title = T["menu_title"]

        print(FG_CYAN + BOLD + "╔" + "═"*W + "╗" + RESET)
        print(FG_CYAN + BOLD + "║" + RESET + f"{title:^{W}}" + FG_CYAN + BOLD + "║" + RESET)
        print(FG_CYAN + BOLD + "╠" + "═"*W + "╣" + RESET)

        # FA: منوی اصلی با padding درست / EN: main menu with correct padding
        print(FG_GREEN  + "║  [1] ▶  " + RESET + pad(T["menu_option_scan"][3:], W-8) + FG_GREEN  + "║" + RESET)
        print(FG_BLUE   + "║  [2] ⟳  " + RESET + pad(T["menu_option_update"][3:], W-8) + FG_BLUE   + "║" + RESET)
        print(FG_YELLOW + "║  [3] ✖  " + RESET + pad(T["menu_option_uninstall"][3:], W-8) + FG_YELLOW + "║" + RESET)
        print(FG_RED    + "║  [4] ⏻  " + RESET + pad(T["menu_option_exit"][3:], W-8) + FG_RED    + "║" + RESET)

        print(FG_CYAN + BOLD + "╚" + "═"*W + "╝" + RESET)

        try:
            choice = input("\n" + T["prompt_choice"] + " > ").strip()
        except KeyboardInterrupt:
            print("\n" + FG_YELLOW + "[!] Use menu option to exit safely" + RESET)
            time.sleep(1)
            continue

        if choice == "1":
            perform_scan(ctx)  # FA: اجرای اسکن شبکه / EN: run network scan
        elif choice == "2":
            run_update()  # FA: اجرای آپدیت / EN: run update safely
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
    ctx = collect_base_reality()
    print_base_reality(ctx)
    main_menu(ctx)

    if ctx["warnings"]:
        time.sleep(1.5)
