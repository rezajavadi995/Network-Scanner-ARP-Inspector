#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import time
import itertools
import re
import random 
import socket
import struct
import shutil
import signal
import os
import urllib.request
from datetime import datetime
import ipaddress
from utils.validators import (
    append_operation_log,
    build_report_paths,
    build_scan_record,
    calculate_packet_loss,
    classify_device,
    compare_scan_summaries,
    compute_ip_usage,
    detect_gateway_mac_change,
    detect_high_latency,
    detect_low_response_rate,
    detect_scan_mismatch,
    detect_unknown_devices,
    detect_watchlist_hits,
    detect_duplicate_ips,
    detect_missing_hostnames,
    get_config_bool,
    get_profile,
    guess_os_by_ttl,
    guess_role,
    guess_vlan,
    is_random_mac,
    is_valid_ip,
    is_valid_cidr,
    load_last_scan,
    load_profiles,
    load_watchlist,
    parse_ping_time_ms,
    read_config_file,
    resolve_hostname,
    save_last_scan,
    save_profiles,
    summarize_changes,
    track_online_offline,
    unusual_vendor,
    vendor_confidence,
    write_config_file,
    write_html_report,
    write_json_report,
    append_scan_history,
    update_profile,
)

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

SILENT_MODE = False
COLOR_WARNINGS = True
ACTIVE_PROFILE = "default"

# =========================================================
# ===================== Paths =============================
# =========================================================
BASE_DIR = "/opt/network-scanner"
CONF_FILE = f"{BASE_DIR}/.netscan.conf"
OUI_DB_FILE = f"{BASE_DIR}/oui.db"
BIN_PATH = "/usr/local/bin/netscan"
OUI_LOCAL_DB = OUI_DB_FILE
DATA_DIR = f"{BASE_DIR}/data"
HISTORY_FILE = f"{DATA_DIR}/scan_history.json"
LAST_SCAN_FILE = f"{DATA_DIR}/last_scan.json"
LOG_FILE = f"{DATA_DIR}/scan.log"
WATCHLIST_FILE = f"{DATA_DIR}/watchlist.json"
PROFILE_FILE = f"{DATA_DIR}/profiles.json"

# ===================== style progress bar  =====================
BRAILLE_FRAMES = ["⠷", "⠿", "⠾", "⠶", "⠦", "⠤", "⠠"]
spinner_cycle = itertools.cycle(BRAILLE_FRAMES)


def render_progress_bar(percent, width=10):
    """
    ▓▓▓░░░░░░ style progress bar
    """
    filled = int((percent / 100) * width)
    return "▓" * filled + "░" * (width - filled)

def smooth_print(message="", delay=0.02):
    """
    Print lines with a small delay to make output more readable.
    """
    if SILENT_MODE:
        delay = 0
    for line in str(message).splitlines():
        print(line)
        time.sleep(delay)


def color_text(text, color_code):
    if COLOR_WARNINGS:
        return f"{color_code}{text}{RESET}"
    return text


def ensure_data_paths():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(WATCHLIST_FILE):
        with open(WATCHLIST_FILE, "w", encoding="utf-8") as f:
            f.write("{\"ips\": [], \"macs\": []}\n")
    if not os.path.exists(PROFILE_FILE):
        defaults = load_profiles(PROFILE_FILE)
        save_profiles(PROFILE_FILE, defaults)


def load_profile_settings():
    profiles = load_profiles(PROFILE_FILE)
    return get_profile(profiles, ACTIVE_PROFILE)


def apply_profile_settings():
    global PING_TIMEOUT, BASE_DELAY, ARP_DELAY
    settings = load_profile_settings()
    if "PING_TIMEOUT" in settings:
        PING_TIMEOUT = settings["PING_TIMEOUT"]
    if "BASE_DELAY" in settings:
        BASE_DELAY = settings["BASE_DELAY"]
    if "ARP_DELAY" in settings:
        ARP_DELAY = settings["ARP_DELAY"]
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

    _OUI_CACHE = {}

    if not os.path.exists(OUI_DB_FILE):
        return _OUI_CACHE

    try:
        with open(OUI_DB_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "|" in line:
                    oui, vendor = line.strip().split("|", 1)
                    _OUI_CACHE[oui.upper()] = vendor.strip()
    except Exception:
        pass

    return _OUI_CACHE
    
    


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
                elif line.startswith("LANG="):
                    NETSCAN_LANG = line.strip().split("=", 1)[1]
                elif line.startswith("NETSCAN_TONE="):
                    NETSCAN_TONE = line.strip().split("=", 1)[1]
    except:
        pass

config_values, _config_lines = read_config_file(CONF_FILE)
SILENT_MODE = get_config_bool(config_values, "SILENT_MODE", default=False)
COLOR_WARNINGS = get_config_bool(config_values, "COLOR_WARNINGS", default=True)
ACTIVE_PROFILE = config_values.get("ACTIVE_PROFILE", "default")
profiles = load_profiles(PROFILE_FILE)
active_profile = get_profile(profiles, ACTIVE_PROFILE)
if active_profile:
    SILENT_MODE = active_profile.get("silent_mode", SILENT_MODE)
    COLOR_WARNINGS = active_profile.get("color_warnings", COLOR_WARNINGS)

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
        "menu_option_settings": "4) Settings & Scheduler",
        "menu_option_exit": "5) Exit",
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
        "menu_option_settings": "4) تنظیمات و زمان‌بندی",
        "menu_option_exit": "5) خروج",
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
    smooth_print(FG_CYAN + BOLD + "\n\n==================== NETWORK SCAN INITIATED ====================" + RESET)
    smooth_print(FG_YELLOW + BOLD + "   Reza Javadi - Network Scanner" + RESET)
    smooth_print(FG_CYAN + BOLD + "================================================================\n" + RESET)
    time.sleep(0.1)

    # ---- CONNECTION OVERVIEW ----
    smooth_print(FG_CYAN + BOLD + "==================== CONNECTION OVERVIEW ====================" + RESET)
    smooth_print(f"""
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

    smooth_print(f"[INFO] OUI Database     : {oui_display}")
    



    
    if ctx.get("analysis_reasons"):
        smooth_print(FG_YELLOW + "[ANALYSIS]" + RESET)
        for r in ctx["analysis_reasons"]:
            smooth_print(" - " + str(r))

    # ---- NETWORK CONTEXT ----
    smooth_print(FG_CYAN + BOLD + "==================== NETWORK CONTEXT ========================" + RESET)
    smooth_print(f"""
[INFO] Network Range    : {net_range}
[INFO] Scan Start Time  : {start_time}

""")

    # ---- LOCAL DEVICE ----
    smooth_print(FG_CYAN + BOLD + "==================== LOCAL DEVICE (YOU) =====================" + RESET)
    smooth_print(f"""
IP Address          : {ctx['ip']}
MAC Address         : {ctx['mac']}
Vendor              : {ctx['vendor']}
""")

    # ---- GATEWAY INFO ----
    smooth_print(FG_CYAN + BOLD + "==================== GATEWAY INFO ===========================" + RESET)
    smooth_print(f"""
Gateway IP          : {ctx['gateway']}
Gateway MAC         : {ctx['gateway_mac']}  ({ctx.get('gateway_vendor', 'Unknown')})
Vendor              : {ctx.get('gateway_vendor', 'Unknown')}
""")
    # ---- WARNINGS ----
    if ctx["warnings"]:
        smooth_print(FG_RED + BOLD + "==================== WARNINGS ===============================" + RESET)
        for w in ctx["warnings"]:
            smooth_print(FG_RED + f"⚠️  {w}" + RESET)
        smooth_print(FG_RED + "============================================================\n" + RESET)

    #print(FG_GREEN + BOLD + "[+] Scan started... | اسکن شبکه شروع شد" + RESET)
    print()
    time.sleep(0.1)


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
def perform_update():
    """
    Download the latest script and utils from GitHub.
    """
    if not os.path.isdir(BASE_DIR):
        print(FG_RED + f"[✗] Update failed: {BASE_DIR} not found." + RESET)
        return 1

    update_map = {
        "network_scan.py": f"{BASE_DIR}/network_scan.py",
        "utils/__init__.py": f"{BASE_DIR}/utils/__init__.py",
        "utils/validators.py": f"{BASE_DIR}/utils/validators.py",
    }

    base_url = "https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main"

    for rel_path, dest_path in update_map.items():
        url = f"{base_url}/{rel_path}"
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        try:
            urllib.request.urlretrieve(url, dest_path)
        except Exception as exc:
            print(FG_RED + f"[✗] Failed to update {rel_path}: {exc}" + RESET)
            return 1

    try:
        os.chmod(f"{BASE_DIR}/network_scan.py", 0o755)
    except Exception:
        pass

    print(FG_GREEN + "[✓] Update completed successfully." + RESET)
    return 0

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
        if retcode != 0:
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
    ctx["ip"] = get_my_ip(iface)
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
    smooth_print(FG_CYAN + BOLD + "\n========== NETWORK REALITY CHECK ==========" + RESET)

    for k, v in ctx.items():
        if k == "warnings":
            continue
        smooth_print(f"{k:18} : {v}")

    if ctx["warnings"]:
        smooth_print(FG_RED + BOLD + "\n[WARNINGS]" + RESET)
        for w in ctx["warnings"]:
            smooth_print(FG_RED + f" - {w}" + RESET)

    smooth_print(FG_CYAN + "==========================================\n" + RESET)
    time.sleep(0.1)


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
    rtt_ms = None
    if ping_ok.get(ip):
        ttl_value = ping_ok[ip].get("ttl")
        rtt_ms = ping_ok[ip].get("rtt_ms")

    enriched["ttl"] = ttl_value
    os_guess = guess_os_by_ttl(ttl_value)
    if ttl_value is not None:
        enriched["ttl_display"] = f"{ttl_value} ({os_guess})"
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

    enriched["hostname"] = resolve_hostname(ip)
    enriched["vendor_confidence"] = vendor_confidence(device.get("vendor"))
    enriched["random_mac"] = is_random_mac(mac)
    enriched["unusual_vendor"] = unusual_vendor(device.get("vendor"))
    enriched["classification"] = classify_device(device.get("vendor"), enriched["role"])
    enriched["role_guess"] = guess_role(ip, ctx.get("gateway"))
    enriched["vlan_guess"] = guess_vlan(ip, ctx.get("network"))
    enriched["rtt_ms"] = rtt_ms

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
    smooth_print(FG_CYAN + BOLD + "\n==================== NETWORK TOPOLOGY (GUESS) ====================" + RESET)

    gw = topology.get("gateway")
    if gw:
        smooth_print(FG_GREEN + f"⚛ Gateway: {gw['ip']}  {gw.get('vendor','')}" + RESET)
        for note in gw.get("notes", []):
            smooth_print(FG_GREEN + f"   └─ {note}" + RESET)

    for ap in topology.get("aps", []):
        smooth_print(FG_BLUE + f"➿ AP: {ap['ip']}  {ap.get('vendor','')}" + RESET)
        for note in ap.get("notes", []):
            smooth_print(FG_BLUE + f"   └─ {note}" + RESET)

    for d in topology.get("devices", []):
        color = FG_GREEN
        icon = "✳️"

        if d.get("suspected_virtual"):
            color = FG_RED
            icon = "♨️"
        elif d.get("suspected_nat"):
            color = FG_YELLOW
            icon = "✴️"

        smooth_print(color + f"{icon} Device: {d['ip']}  {d.get('vendor','')}" + RESET)

        if d.get("behind"):
            smooth_print(color + f"   └─ Behind: {d['behind']}" + RESET)

        for note in d.get("notes", []):
            smooth_print(color + f"   └─ {note}" + RESET)

    smooth_print(FG_CYAN + "==================================================================\n" + RESET)



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
    smooth_print(FG_RED + BOLD + "\n==================== TOPOLOGY WARNINGS ====================" + RESET)

    if not multi_net_alerts and not wifi_nat_alerts and not ttl_alerts:
        smooth_print(FG_GREEN + "✔ No critical topology anomalies detected" + RESET)
        return

    for a in multi_net_alerts:
        smooth_print(
            FG_YELLOW +
            f"⚠️  Multiple networks behind AP {a['ap']} -> {', '.join(a['subnets'])}"
            + RESET
        )

    for a in wifi_nat_alerts:
        smooth_print(
            FG_RED +
            f"🔥 Wi-Fi behind Wi-Fi detected at AP {a['ap']} ({a['reason']})"
            + RESET
        )

    for a in ttl_alerts:
        smooth_print(
            FG_RED +
            f"🧬 Hidden hops behind AP {a['ap']} | TTL clusters: {a['ttls']}"
            + RESET
        )

    smooth_print(FG_RED + "===========================================================\n" + RESET)


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
        smooth_print(
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


# ===================== OUI DB =============================
# =========================================================

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

def get_my_ip(iface=None):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        pass

    try:
        out = subprocess.check_output(["ip", "-4", "route", "get", "1.1.1.1"], text=True)
        for token in out.split():
            if token == "src":
                return out.split()[out.split().index("src") + 1]
    except Exception:
        pass

    try:
        if not iface:
            iface = get_interface()
        out = subprocess.check_output(["ip", "-4", "addr", "show", iface], text=True)
        for line in out.splitlines():
            if "inet " in line:
                return line.split()[1].split("/")[0]
    except Exception:
        pass

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
def perform_scan(ctx, scheduled=False, net_override=None):
    global NETWORK_BASE, START, END

    try:
        iface = ctx["interface"]
        my_ip = ctx["ip"]
        ensure_data_paths()
        prev_scan = load_last_scan(LAST_SCAN_FILE)
        watchlist = load_watchlist(WATCHLIST_FILE)

        # ---- Range decision (dynamic) ----
        if scheduled and net_override:
            net = net_override
        else:
            net = network_range_flow()
        if net is None:
            print(FG_YELLOW + "[!] Scan cancelled by user | الان داری اسکن را لغو می‌کنی" + RESET)
            time.sleep(1)
            return
        ctx["network"] = str(net)

        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        timestamp_label = datetime.now().strftime("%Y%m%d_%H%M%S")
        append_operation_log(LOG_FILE, f"Scan started on iface={iface} range={net}")

        # ---- Overview ----
        print_network_overview(ctx, net_range=net, start_time=now)

        smooth_print(FG_GREEN + "[+] Scan started... | اسکن شبکه شروع شد" + RESET)
        time.sleep(0.1)
        print()

        # =====================================================
        # ================= Stage 1: Ping Sweep ===============
        # =====================================================
        ping_ok = {}

        hosts = list(net.hosts())
        if not hosts:
            hosts = list(net)
        host_ips = [str(ip) for ip in hosts]
        total_hosts = len(host_ips)

        if total_hosts <= 4096:
            random.shuffle(host_ips)

        for idx, ip in enumerate(host_ips, start=1):

            if not is_valid_ip(ip):
                print(f"{FG_RED}[SKIP] Invalid IP: {ip}{RESET}")
                continue

            try:
                r = subprocess.run(
                    ["ping", "-n", "-c", "1", "-W", str(PING_TIMEOUT), ip],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True     
                )
                ttl = extract_ttl_from_ping_output(r.stdout)
                rtt_ms = parse_ping_time_ms(r.stdout)
                ping_ok[ip] = {
                    "alive": r.returncode == 0,
                    "ttl": ttl,
                    "rtt_ms": rtt_ms,
                }

            except KeyboardInterrupt:
                # تمیز کردن خط progress قبل از خروج
                sys.stdout.write("\n")
                sys.stdout.flush()
                raise

            # ---- Progress calculation ----
            percent = int((idx / total_hosts) * 100) if total_hosts else 100
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
            sleep_time = random.uniform(0.1, 0.5) 
            time.sleep(sleep_time)

        

            #time.sleep(BASE_DELAY)
        

        # ---- Finalize progress bar line ----
        sys.stdout.write("\n")
        sys.stdout.flush()

        alive_count = sum(1 for v in ping_ok.values() if v.get("alive"))
        smooth_print(FG_GREEN + "[+] Ping phase done | مرحله پینگ تمام شد" + RESET)
        time.sleep(ARP_DELAY)

        # =====================================================
        # ================= Stage 1.5: ARP ====================
        # =====================================================
        smooth_print("[+] Reading ARP table | خواندن جدول ARP")
        print()
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
        enriched_devices = enriched_active + enriched_arp_only + enriched_incomplete

        packet_loss = calculate_packet_loss(total_hosts, alive_count)
        response_alert, response_rate = detect_low_response_rate(
            total_hosts, alive_count,
            threshold_percent=active_profile.get("low_response_threshold", 35)
        )
        high_latency = detect_high_latency(
            ping_ok,
            threshold_ms=active_profile.get("latency_threshold_ms", 150)
        )
        duplicate_ips = detect_duplicate_ips(enriched_active + enriched_arp_only)
        missing_hostnames = detect_missing_hostnames(enriched_active + enriched_arp_only)
        unknown_devices = detect_unknown_devices(prev_scan, {"devices": enriched_devices})
        watch_hits = detect_watchlist_hits(watchlist, enriched_active + enriched_arp_only)
        gw_change, prev_gw_mac, current_gw_mac = detect_gateway_mac_change(
            prev_scan, {"devices": enriched_devices}, ctx.get("gateway")
        )
        came_online, went_offline = track_online_offline(
            prev_scan, {"devices": enriched_devices}
        )
        usage_percent = compute_ip_usage(total_hosts, len(enriched_devices))
        # ---- Output (Hacker Style) ----
        def show_block(title_en, title_fa, data, icon):
            smooth_print(f"\n========== {title_en} | {title_fa} ==========")
            for d in data:
                smooth_print(
                    FG_CYAN + f"{icon} {d.get('ip')}" +
                    FG_GREEN + f"  [{d.get('vendor', 'Unknown')}]" +
                    FG_YELLOW + f"  MAC: {d.get('mac')}" +
                    FG_MAGENTA + f"  TTL: {d.get('ttl_display', 'N/A')}" +
                    RESET
                )
                smooth_print(
                    FG_GRAY
                    + f"   Hostname: {d.get('hostname') or 'N/A'} | "
                    + f"Class: {d.get('classification')} | "
                    + f"Role: {d.get('role')} | "
                    + f"RoleGuess: {d.get('role_guess')} | "
                    + f"VLAN: {d.get('vlan_guess')} | "
                    + f"VendorConf: {d.get('vendor_confidence')} | "
                    + f"RandomMAC: {d.get('random_mac')} | "
                    + f"UnusualVendor: {d.get('unusual_vendor')}"
                    + RESET
                )

        show_block("Active Devices", "دستگاه‌های فعال", enriched_active, "✅")
        show_block("ARP Only", "فقط در ARP", enriched_arp_only, "⚠️")
        show_block("Incomplete", "ناقص", enriched_incomplete, "❌")

        total = len(active) + len(arp_only) + len(incomplete)

        smooth_print(FG_BLUE + "\n╔════════════════════════════════╗" + RESET)
        smooth_print(FG_BLUE + f"║ Total devices        : {total:<5}         ║" + RESET)
        smooth_print(FG_BLUE + f"║ Total with self      : {total + 1:<5}         ║" + RESET)
        smooth_print(FG_BLUE + "╚════════════════════════════════╝" + RESET)
        smooth_print(FG_BLUE + f"Packet loss            : {packet_loss:.2f}% (rate {response_rate:.2f}%)" + RESET)
        if total_hosts:
            smooth_print(FG_BLUE + f"Range usage            : {usage_percent:.2f}% of {total_hosts}" + RESET)

        if response_alert:
            smooth_print(FG_RED + f"[!] Low response rate detected: {response_rate:.2f}%" + RESET)
        if high_latency:
            smooth_print(FG_YELLOW + "[!] High latency devices detected:" + RESET)
            for ip, rtt in high_latency:
                smooth_print(FG_YELLOW + f" - {ip} => {rtt} ms" + RESET)
        if duplicate_ips:
            smooth_print(FG_RED + "[!] Duplicate IPs detected (possible conflict):" + RESET)
            for item in duplicate_ips:
                smooth_print(FG_RED + f" - {item['ip']} => {', '.join(item['macs'])}" + RESET)
        if missing_hostnames:
            smooth_print(FG_YELLOW + "[!] Devices without hostname (mDNS/NetBIOS not resolved):" + RESET)
            for d in missing_hostnames:
                smooth_print(FG_YELLOW + f" - {d.get('ip')} ({d.get('vendor','Unknown')})" + RESET)
        if watch_hits:
            smooth_print(FG_RED + "[!] Watchlist hits:" + RESET)
            for d in watch_hits:
                smooth_print(FG_RED + f" - {d.get('ip')} {d.get('mac')} {d.get('vendor')}" + RESET)
        if gw_change:
            smooth_print(FG_RED + "[!] Gateway MAC change detected:" + RESET)
            smooth_print(FG_RED + f" - Previous: {prev_gw_mac}" + RESET)
            smooth_print(FG_RED + f" - Current : {current_gw_mac}" + RESET)
        if unknown_devices:
            smooth_print(FG_YELLOW + "[!] New/Unknown devices since last scan:" + RESET)
            for d in unknown_devices:
                smooth_print(FG_YELLOW + f" - {d.get('ip')} {d.get('mac')} {d.get('vendor')}" + RESET)
        if came_online or went_offline:
            smooth_print(FG_CYAN + "[INFO] Online/Offline changes:" + RESET)
            for ip in came_online:
                smooth_print(FG_GREEN + f" + Online: {ip}" + RESET)
            for ip in went_offline:
                smooth_print(FG_RED + f" - Offline: {ip}" + RESET)

        smooth_print(FG_GREEN + "\n[✓] Scan completed successfully | اسکن با موفقیت انجام شد" + RESET)

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

        gateway_mac = None
        for d in enriched_devices:
            if d.get("ip") == ctx.get("gateway"):
                gateway_mac = d.get("mac")
                break

        scan_summary = {
            "total_devices": total,
            "packet_loss": packet_loss,
            "response_rate": response_rate,
            "gateway_mac": gateway_mac,
            "high_latency_count": len(high_latency),
            "network_range": str(net),
            "range_usage_percent": usage_percent,
        }
        scan_record = build_scan_record(enriched_devices, scan_summary)
        save_last_scan(LAST_SCAN_FILE, scan_record)
        append_scan_history(
            HISTORY_FILE,
            scan_record,
            max_entries=active_profile.get("max_history", 50),
        )
        append_operation_log(LOG_FILE, f"Scan completed on {iface} range {net}")

        summary_diff = compare_scan_summaries(prev_scan, scan_record)
        change_summary = summarize_changes(prev_scan, scan_record)
        mismatch_alert, mismatch_percent = detect_scan_mismatch(prev_scan, scan_record)

        report_paths = build_report_paths(
            os.path.join(BASE_DIR, active_profile.get("report_dir", "data/reports")),
            timestamp_label,
        )
        if active_profile.get("report_json", True):
            write_json_report(report_paths["json"], scan_record)
        if active_profile.get("report_html", True):
            write_html_report(report_paths["html"], scan_record)

        if summary_diff:
            smooth_print(FG_CYAN + f"[i] Summary diff: {summary_diff}" + RESET)
        if change_summary and change_summary.get("status") != "no_previous_scan":
            smooth_print(
                FG_CYAN
                + f"[i] Added: {change_summary.get('added_count')} | Removed: {change_summary.get('removed_count')}"
                + RESET
            )
        if mismatch_alert:
            smooth_print(FG_RED + f"[!] Scan mismatch detected ({mismatch_percent:.2f}% change)" + RESET)

        if not scheduled:
            input("\nPress Enter to continue | برای ادامه Enter بزن")

    except KeyboardInterrupt:
        print("\n" + FG_RED + "[!] Scan interrupted by user" + RESET)
        print(FG_GRAY + "اسکن توسط کاربر متوقف شد" + RESET)
        time.sleep(0.5)
        return

# =========================================================
# ===================== Menu ==============================
# =========================================================
def run_scheduled_scans(ctx, interval_min, cycles, net_override=None):
    if interval_min <= 0:
        print(FG_RED + "[!] Interval must be greater than 0 minutes." + RESET)
        time.sleep(1)
        return
    if cycles <= 0:
        print(FG_RED + "[!] Cycles must be greater than 0." + RESET)
        time.sleep(1)
        return

    print(FG_CYAN + f"[INFO] Scheduled scan started: every {interval_min} minute(s), {cycles} cycle(s)." + RESET)
    for idx in range(cycles):
        print(FG_CYAN + f"[INFO] Cycle {idx + 1}/{cycles}" + RESET)
        perform_scan(ctx, scheduled=True, net_override=net_override)
        if idx < cycles - 1:
            print(FG_GRAY + f"[INFO] Next scan in {interval_min} minute(s)..." + RESET)
            time.sleep(interval_min * 60)


def schedule_menu(ctx):
    global profiles, active_profile
    os.system("clear")
    current_interval = active_profile.get("schedule_interval_min", 0)
    print(FG_CYAN + BOLD + "=== Scheduled Scan Menu ===" + RESET)
    print(FG_GRAY + "Example: Set interval to 30 minutes and run 3 cycles." + RESET)
    print(FG_GRAY + "You can disable scheduling by setting interval to 0." + RESET)
    print()
    print(FG_GREEN + f"[1] Set interval (current: {current_interval} min)" + RESET)
    print(FG_YELLOW + "[2] Run scheduled scan now" + RESET)
    print(FG_RED + "[3] Back" + RESET)
    choice = input("\nSelect > ").strip()

    if choice == "1":
        val = input("Enter interval in minutes (0 to disable): ").strip()
        try:
            interval = int(val)
        except ValueError:
            print(FG_RED + "Invalid number." + RESET)
            time.sleep(1)
            return
        active_profile["schedule_interval_min"] = max(0, interval)
        profiles = update_profile(profiles, ACTIVE_PROFILE, active_profile)
        save_profiles(PROFILE_FILE, profiles)
        print(FG_GREEN + f"Interval set to {active_profile['schedule_interval_min']} minutes." + RESET)
        time.sleep(1)
    elif choice == "2":
        if current_interval <= 0:
            print(FG_YELLOW + "Interval is 0. Set a valid interval first." + RESET)
            time.sleep(1)
            return
        cycles_val = input("How many cycles? (example: 3) ").strip()
        try:
            cycles = int(cycles_val)
        except ValueError:
            print(FG_RED + "Invalid cycles number." + RESET)
            time.sleep(1)
            return
        net_override = load_network_range()
        if not net_override:
            net_override = detect_network_range()
        run_scheduled_scans(ctx, current_interval, cycles, net_override=net_override)
    else:
        return


def profile_menu():
    global profiles, ACTIVE_PROFILE, active_profile, SILENT_MODE, COLOR_WARNINGS
    os.system("clear")
    print(FG_CYAN + BOLD + "=== Profile Manager ===" + RESET)
    print(FG_GRAY + f"Active profile: {ACTIVE_PROFILE}" + RESET)
    print()
    print(FG_GREEN + "[1] Create new profile (copy current)" + RESET)
    print(FG_YELLOW + "[2] Switch profile" + RESET)
    print(FG_RED + "[3] Back" + RESET)
    choice = input("\nSelect > ").strip()

    if choice == "1":
        name = input("New profile name: ").strip()
        if not name:
            print(FG_RED + "Invalid name." + RESET)
            time.sleep(1)
            return
        profiles = update_profile(profiles, name, active_profile)
        save_profiles(PROFILE_FILE, profiles)
        print(FG_GREEN + f"Profile '{name}' created." + RESET)
        time.sleep(1)
    elif choice == "2":
        name = input("Enter profile name to switch: ").strip()
        if name not in profiles:
            print(FG_RED + "Profile not found." + RESET)
            time.sleep(1)
            return
        ACTIVE_PROFILE = name
        write_config_file(CONF_FILE, {"ACTIVE_PROFILE": ACTIVE_PROFILE})
        active_profile = get_profile(profiles, ACTIVE_PROFILE)
        SILENT_MODE = active_profile.get("silent_mode", SILENT_MODE)
        COLOR_WARNINGS = active_profile.get("color_warnings", COLOR_WARNINGS)
        apply_profile_settings()
        print(FG_GREEN + f"Switched to profile '{ACTIVE_PROFILE}'." + RESET)
        time.sleep(1)
    else:
        return


def settings_menu(ctx):
    global profiles, active_profile, SILENT_MODE, COLOR_WARNINGS
    while True:
        os.system("clear")
        print(FG_CYAN + BOLD + "=== Settings & Scheduler ===" + RESET)
        print(FG_GRAY + f"Active profile: {ACTIVE_PROFILE}" + RESET)
        print()
        print(FG_GREEN + f"[1] Toggle silent mode (current: {SILENT_MODE})" + RESET)
        print(FG_GREEN + f"[2] Toggle colored warnings (current: {COLOR_WARNINGS})" + RESET)
        print(FG_GREEN + f"[3] Set latency threshold ms (current: {active_profile.get('latency_threshold_ms', 150)})" + RESET)
        print(FG_GREEN + f"[4] Set low response threshold % (current: {active_profile.get('low_response_threshold', 35)})" + RESET)
        print(FG_GREEN + f"[5] Toggle JSON report (current: {active_profile.get('report_json', True)})" + RESET)
        print(FG_GREEN + f"[6] Toggle HTML report (current: {active_profile.get('report_html', True)})" + RESET)
        print(FG_GREEN + f"[7] Set report directory (current: {active_profile.get('report_dir', 'data/reports')})" + RESET)
        print(FG_YELLOW + "[8] Profile manager" + RESET)
        print(FG_YELLOW + "[9] Scheduled scans" + RESET)
        print(FG_RED + "[0] Back" + RESET)
        choice = input("\nSelect > ").strip()

        if choice == "1":
            SILENT_MODE = not SILENT_MODE
            active_profile["silent_mode"] = SILENT_MODE
        elif choice == "2":
            COLOR_WARNINGS = not COLOR_WARNINGS
            active_profile["color_warnings"] = COLOR_WARNINGS
        elif choice == "3":
            val = input("Latency threshold ms (example: 150): ").strip()
            try:
                active_profile["latency_threshold_ms"] = int(val)
            except ValueError:
                print(FG_RED + "Invalid number." + RESET)
                time.sleep(1)
                continue
        elif choice == "4":
            val = input("Low response threshold % (example: 35): ").strip()
            try:
                active_profile["low_response_threshold"] = int(val)
            except ValueError:
                print(FG_RED + "Invalid number." + RESET)
                time.sleep(1)
                continue
        elif choice == "5":
            active_profile["report_json"] = not active_profile.get("report_json", True)
        elif choice == "6":
            active_profile["report_html"] = not active_profile.get("report_html", True)
        elif choice == "7":
            val = input("Report directory (example: data/reports): ").strip()
            if val:
                active_profile["report_dir"] = val
        elif choice == "8":
            profile_menu()
        elif choice == "9":
            schedule_menu(ctx)
        elif choice == "0":
            break
        else:
            print(FG_RED + "Invalid choice." + RESET)
            time.sleep(1)
            continue

        profiles = update_profile(profiles, ACTIVE_PROFILE, active_profile)
        save_profiles(PROFILE_FILE, profiles)

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
        print(FG_MAGENTA + "║  [4] ⚙  " + RESET + pad(T["menu_option_settings"][3:], W-8) + FG_MAGENTA + "║" + RESET)
        print(FG_RED    + "║  [5] ⏻  " + RESET + pad(T["menu_option_exit"][3:], W-8) + FG_RED    + "║" + RESET)

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
            settings_menu(ctx)
        elif choice == "5":
            msg = T["exit_human"] if NETSCAN_TONE == "human" else T["exit_neutral"]
            print(FG_GREEN + msg + RESET)
            break
        else:
            print(FG_RED + T["invalid_choice"] + RESET)
            time.sleep(1)
if __name__ == "__main__":
    if "--update" in sys.argv:
        sys.exit(perform_update())

    ensure_data_paths()
    apply_profile_settings()
    ctx = collect_base_reality()
    print_base_reality(ctx)
    main_menu(ctx)

    if ctx["warnings"]:
        time.sleep(1.5)
