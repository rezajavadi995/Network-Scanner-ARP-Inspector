#!/usr/bin/env python3
# coding: utf-8
import subprocess
import sys
import time
import re
import socket
import struct
import argparse
import platform
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any

# Default configuration (can be overridden via CLI)
NETWORK_BASE = "192.168.1."
START = 1
END = 255
PING_TIMEOUT = 1  # seconds (integer)
DEFAULT_WORKERS = 60

# Small OUI lookup database; keys normalized as 'AA:BB:CC' (uppercase)
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

# Utilities
def normalize_mac_for_lookup(mac: str) -> str:
    """Normalize various MAC string formats into uppercase colon-separated form and return first 3 bytes as prefix.
    Examples: '00:1a:79:xx:xx:xx' -> '00:1A:79' ; '001A79XXXXXX' -> '00:1A:79'
    If mac is '<incomplete>' or cannot be parsed, returns that marker uppercased.
    """
    if not mac:
        return ""
    mac = mac.strip()
    if mac.lower() == "<incomplete>":
        return "<INCOMPLETE>"
    # Keep only hex characters
    hex_only = re.sub(r'[^0-9a-fA-F]', '', mac).upper()
    if len(hex_only) < 6:
        return mac.upper()
    prefix = hex_only[:6]
    return ":".join([prefix[i:i+2] for i in range(0, 6, 2)])

def get_vendor(mac: str) -> str:
    p = normalize_mac_for_lookup(mac)
    if p == "<INCOMPLETE>":
        return "Unknown"
    return OUI_DB.get(p, "Unknown")

def ip_to_int(ip: str) -> int:
    try:
        return struct.unpack("!I", socket.inet_aton(ip))[0]
    except Exception:
        return 0

def progress_bar(current: int, total: int) -> None:
    try:
        percent = int((current / total) * 100) if total > 0 else 100
        bar = "#" * (percent // 2) + "-" * (50 - percent // 2)
        sys.stdout.write(f"\r[{bar}] {percent}%")
        sys.stdout.flush()
    except Exception:
        pass

# Network helpers
def get_active_interface() -> str:
    """Return the active interface from 'ip route' output by locating 'dev <iface>' on the default route.
    Falls back to 'unknown' if parsing fails.
    """
    try:
        if shutil.which("ip") is None:
            return "unknown"
        route = subprocess.check_output(["ip", "route"], text=True, errors="ignore")
        for line in route.splitlines():
            if line.startswith("default"):
                parts = line.split()
                if "dev" in parts:
                    return parts[parts.index("dev") + 1]
                # fallback: common position if output differs
                if len(parts) > 4:
                    return parts[4]
    except Exception:
        pass
    return "unknown"

def get_my_ip() -> str:
    try:
        # Prefer hostname -I (Linux). Fallback to socket-based discovery.
        if shutil.which("hostname"):
            out = subprocess.check_output(["hostname", "-I"], text=True, errors="ignore").strip()
            if out:
                return out.split()[0]
    except Exception:
        pass
    # Fallback: connect to a public DNS and get the local socket name (doesn't actually send data)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "unknown"

def get_my_mac(interface: str) -> str:
    try:
        if interface and interface != "unknown":
            path = f"/sys/class/net/{interface}/address"
            with open(path) as f:
                return f.read().strip().lower()
    except Exception:
        pass
    return ""

# ARP parsing: try 'ip neigh' first, then 'arp -a' as fallback. Keep output tolerant to different formats.
def parse_arp() -> List[Dict[str, Any]]:
    entries: List[Dict[str, Any]] = []
    try:
        if shutil.which("ip"):
            out = subprocess.check_output(["ip", "neigh"], text=True, errors="ignore")
            # lines like: '192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE'
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                ip = parts[0]
                mac = "<incomplete>"
                if "lladdr" in parts:
                    try:
                        mac = parts[parts.index("lladdr") + 1]
                    except Exception:
                        mac = "<incomplete>"
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac)
                })
            if entries:
                return entries
    except Exception:
        pass
    # Fallback to arp -a parsing (various formats)
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, errors="ignore")
        # Typical formats:
        # ? (192.168.1.1) at 00:11:22:33:44:55 [ether] on eth0
        # 192.168.1.1 ether 00:11:22:33:44:55 C eth0
        for line in out.splitlines():
            # try parentheses form first
            m = re.search(r"\((.*?)\) at ([0-9a-f:]+) ", line, re.I)
            if m:
                ip = m.group(1)
                mac = m.group(2)
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac)
                })
                continue
            # try other forms: ip ... ether mac ...
            m2 = re.search(r"([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*?([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})", line, re.I)
            if m2:
                ip = m2.group(1)
                mac = m2.group(2)
                entries.append({
                    "ip": ip,
                    "mac": mac,
                    "vendor": get_vendor(mac)
                })
    except Exception:
        pass
    return entries

# Ping helpers: attempt to use system 'ping'. If unavailable, treat hosts as unreachable.
def do_ping(ip: str, timeout: int) -> bool:
    if shutil.which("ping") is None:
        return False
    system = platform.system()
    # Build ping command: default to Linux syntax. For macOS, -W expects milliseconds for some implementations; we keep a simple approach.
    if system == "Darwin":
        # macOS: use -c 1 and -W in milliseconds if available; as heuristic multiply seconds by 1000
        args = ["ping", "-c", "1", "-W", str(max(1, int(timeout * 1000))), ip]
    else:
        args = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
    try:
        r = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return r.returncode == 0
    except Exception:
        return False

def scan_range(network_base: str, start: int, end: int, timeout: int, workers: int) -> Dict[str, bool]:
    results: Dict[str, bool] = {}
    ips = [f"{network_base}{i}" for i in range(start, end + 1)]
    total = len(ips)
    completed = 0
    if total == 0:
        return results
    # Limit workers to a reasonable number
    workers = max(1, min(workers, 500))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_to_ip = {ex.submit(do_ping, ip, timeout): ip for ip in ips}
        for fut in as_completed(future_to_ip):
            ip = future_to_ip[fut]
            try:
                alive = fut.result()
            except Exception:
                alive = False
            results[ip] = alive
            completed += 1
            progress_bar(completed, total)
    # newline after progress bar
    print()
    return results

def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description="Network scanner (Ping + ARP) — Persian UI")
    parser.add_argument("--base", default=NETWORK_BASE, help="Network base (e.g. 192.168.1.)")
    parser.add_argument("--start", type=int, default=START, help="Start host number")
    parser.add_argument("--end", type=int, default=END, help="End host number")
    parser.add_argument("--timeout", type=int, default=PING_TIMEOUT, help="Ping timeout (seconds)")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Parallel ping workers")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args(argv)

    network_base = args.base
    start = args.start
    end = args.end
    timeout = args.timeout
    workers = args.workers

    if start > end:
        print("[!] مقدار start بزرگتر از end است")
        sys.exit(1)

    interface = get_active_interface()
    my_ip = get_my_ip()
    my_mac = get_my_mac(interface)
    my_mac_norm = normalize_mac_for_lookup(my_mac)

    print(
        f"\n[+] شروع اسکن شبکه با ping\n[+] اینترفیس فعال: {interface}\n[+] IP سیستم: {my_ip}\n[+] رنج: {network_base}{start} → {network_base}{end}\n"
    )

    # Perform parallel ping scan
    ping_results = scan_range(network_base, start, end, timeout, workers)

    print("\n[+] ping scan تمام شد")
    time.sleep(0.3)

    print("\n[+] خواندن جدول ARP ...\n")
    arp_entries = parse_arp()

    # Normalize ARP mac addresses and vendors
    for e in arp_entries:
        e_mac = e.get("mac", "")
        e["mac_norm"] = normalize_mac_for_lookup(e_mac)
        e["vendor"] = get_vendor(e_mac)

    # Remove self entry by comparing normalized IP and MAC (if available)
    filtered = []
    for d in arp_entries:
        if d.get("ip") == my_ip:
            continue
        if my_mac_norm and d.get("mac_norm") and d.get("mac_norm") == my_mac_norm:
            continue
        filtered.append(d)
    arp_entries = filtered

    ping_ok = []
    arp_only = []
    incomplete = []

    for d in arp_entries:
        ip = d.get("ip")
        mac = d.get("mac")
        mac_norm = d.get("mac_norm")
        if mac_norm == "<INCOMPLETE>":
            incomplete.append(d)
        elif ping_results.get(ip):
            ping_ok.append(d)
        else:
            arp_only.append(d)

    # Sort numerically by IP
    ping_ok.sort(key=lambda x: ip_to_int(x.get("ip", "0.0.0.0")))
    arp_only.sort(key=lambda x: ip_to_int(x.get("ip", "0.0.0.0")))
    incomplete.sort(key=lambda x: ip_to_int(x.get("ip", "0.0.0.0")))

    if args.json:
        out = {
            "interface": interface,
            "my_ip": my_ip,
            "my_mac": my_mac,
            "ping_ok": ping_ok,
            "arp_only": arp_only,
            "incomplete": incomplete
        }
        import json
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    print("========== دستگاه‌های فعال (Ping OK) ==========")
    for d in ping_ok:
        print("✅ {}  {}  [{}]".format(d.get("ip"), d.get("mac"), d.get("vendor")))

    print("\n========== بدون Ping ولی در ARP ==========")
    for d in arp_only:
        print("⚠️  {}  {}  [{}]".format(d.get("ip"), d.get("mac"), d.get("vendor")))

    print("\n========== ARP Incomplete ==========")
    for d in incomplete:
        print("❌ {}  <incomplete>".format(d.get("ip")))

    total = len(ping_ok) + len(arp_only) + len(incomplete)
    print("\n==========================================")
    print("تعداد دستگاه‌ها (بدون خودت): {}".format(total))
    print("تعداد کل با خودت: {}".format(total + 1))
    print("[✓] عملیات با موفقیت انجام شد")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] اسکن توسط کاربر متوقف شد")
