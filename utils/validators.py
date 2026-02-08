#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
from datetime import datetime


CONFIG_BOOL_TRUE = {"1", "true", "yes", "on", "enable", "enabled"}
DEFAULT_PROFILE_SETTINGS = {
    "silent_mode": False,
    "color_warnings": True,
    "latency_threshold_ms": 150,
    "report_json": True,
    "report_html": True,
    "report_dir": "data/reports",
    "schedule_interval_min": 0,
    "max_history": 50,
    "low_response_threshold": 35,
    "PING_TIMEOUT": 1,
    "BASE_DELAY": 0.03,
    "ARP_DELAY": 0.4,
}


def ensure_dir(path):
    if path and not os.path.exists(path):
        os.makedirs(path, exist_ok=True)


def load_json(path, default=None):
    if default is None:
        default = {}
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        return default
    return default


def save_json(path, data):
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def read_config_file(path):
    config = {}
    lines = []
    if not os.path.exists(path):
        return config, lines
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        config[key.strip()] = value.strip()
    return config, lines


def write_config_file(path, updates):
    config, lines = read_config_file(path)
    config.update(updates)
    seen = set()
    output = []
    for line in lines:
        raw = line
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            output.append(raw.rstrip("\n"))
            continue
        key, _ = line.split("=", 1)
        key = key.strip()
        if key in config:
            output.append(f"{key}={config[key]}")
            seen.add(key)
        else:
            output.append(raw.rstrip("\n"))
    for key, value in config.items():
        if key not in seen:
            output.append(f"{key}={value}")
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(output) + "\n")


def get_config_bool(config, key, default=False):
    value = str(config.get(key, "")).strip().lower()
    if not value:
        return default
    return value in CONFIG_BOOL_TRUE


def parse_ping_time_ms(ping_output):
    match = re.search(r"time[=<]\s*([\d.]+)\s*ms", ping_output)
    if not match:
        return None
    try:
        return float(match.group(1))
    except ValueError:
        return None


def detect_gateway_mac_change(prev_scan, current_scan, gateway_ip):
    if not prev_scan or not gateway_ip:
        return False, None, None
    prev_mac = prev_scan.get("gateway_mac")
    current_mac = None
    for device in current_scan.get("devices", []):
        if device.get("ip") == gateway_ip:
            current_mac = device.get("mac")
            break
    if prev_mac and current_mac and prev_mac != current_mac:
        return True, prev_mac, current_mac
    return False, prev_mac, current_mac


def detect_unknown_devices(prev_scan, current_scan):
    prev_ips = {d.get("ip") for d in prev_scan.get("devices", [])} if prev_scan else set()
    unknown = []
    for d in current_scan.get("devices", []):
        if d.get("ip") not in prev_ips:
            unknown.append(d)
    return unknown


def detect_duplicate_ips(devices):
    seen = {}
    duplicates = []
    for d in devices:
        ip = d.get("ip")
        mac = d.get("mac")
        if not ip:
            continue
        if ip in seen:
            seen[ip].add(mac)
        else:
            seen[ip] = {mac}
    for ip, macs in seen.items():
        if len(macs) > 1:
            duplicates.append({"ip": ip, "macs": sorted([m for m in macs if m])})
    return duplicates


def detect_missing_hostnames(devices):
    missing = []
    for d in devices:
        if not d.get("hostname"):
            missing.append(d)
    return missing


def detect_scan_mismatch(prev_scan, current_scan, threshold_percent=30):
    if not prev_scan:
        return False, 0.0
    prev_total = prev_scan.get("summary", {}).get("total_devices") or 0
    current_total = current_scan.get("summary", {}).get("total_devices") or 0
    if prev_total == 0:
        return False, 0.0
    delta_percent = abs(current_total - prev_total) / prev_total * 100.0
    return delta_percent >= threshold_percent, round(delta_percent, 2)


def detect_watchlist_hits(watchlist, devices):
    hits = []
    for d in devices:
        ip = d.get("ip")
        mac = (d.get("mac") or "").lower()
        if ip in watchlist or mac in watchlist:
            hits.append(d)
    return hits


def track_online_offline(prev_scan, current_scan):
    prev_ips = {d.get("ip") for d in prev_scan.get("devices", [])} if prev_scan else set()
    current_ips = {d.get("ip") for d in current_scan.get("devices", [])}
    went_offline = prev_ips - current_ips
    came_online = current_ips - prev_ips
    return list(came_online), list(went_offline)


def calculate_packet_loss(total_hosts, alive_hosts):
    if total_hosts <= 0:
        return 0.0
    loss = 100.0 - ((alive_hosts / total_hosts) * 100.0)
    return round(loss, 2)


def detect_high_latency(ping_stats, threshold_ms):
    high = []
    for ip, stats in ping_stats.items():
        rtt = stats.get("rtt_ms")
        if rtt is not None and rtt >= threshold_ms:
            high.append((ip, rtt))
    return high


def detect_low_response_rate(total_hosts, alive_hosts, threshold_percent=35):
    if total_hosts <= 0:
        return False, 0.0
    rate = (alive_hosts / total_hosts) * 100.0
    return rate < threshold_percent, round(rate, 2)


def vendor_confidence(vendor):
    if not vendor or vendor.lower() == "unknown":
        return "low"
    if len(vendor.strip()) < 4:
        return "low"
    return "medium"


def is_random_mac(mac):
    if not mac or ":" not in mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0b00000010)
    except ValueError:
        return False


def unusual_vendor(vendor):
    if not vendor:
        return True
    vendor = vendor.lower()
    if vendor in {"unknown", "generic"}:
        return True
    return False


def guess_os_by_ttl(ttl_value):
    if ttl_value is None:
        return "unknown"
    if ttl_value <= 64:
        return "linux/unix"
    if ttl_value <= 128:
        return "windows"
    if ttl_value <= 255:
        return "network device"
    return "unknown"


def classify_device(vendor, role):
    vendor = (vendor or "").lower()
    if role == "gateway":
        return "gateway"
    if "camera" in vendor:
        return "iot-camera"
    if "printer" in vendor:
        return "printer"
    if any(k in vendor for k in ["phone", "samsung", "apple", "xiaomi", "huawei"]):
        return "phone"
    if any(k in vendor for k in ["intel", "dell", "hp", "lenovo", "asus"]):
        return "pc"
    if any(k in vendor for k in ["router", "wireless", "mikrotik", "ubiquiti", "tp-link", "d-link"]):
        return "router/ap"
    return "unknown"


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None


def get_hostname_mdns_netbios(ip):
    avahi = shutil.which("avahi-resolve-address")
    if avahi:
        try:
            out = subprocess.check_output([avahi, ip], text=True, timeout=2)
            parts = out.strip().split()
            if len(parts) >= 2:
                return parts[1].strip().rstrip(".")
        except Exception:
            pass

    nmb = shutil.which("nmblookup")
    if nmb:
        try:
            out = subprocess.check_output([nmb, "-A", ip], text=True, timeout=2)
            for line in out.splitlines():
                if "<00>" in line and "UNIQUE" in line:
                    return line.split()[0]
        except Exception:
            pass
    return None


def resolve_hostname(ip):
    name = get_hostname(ip)
    if name:
        return name
    return get_hostname_mdns_netbios(ip)


def guess_vlan(ip, network):
    try:
        if ipaddress.ip_address(ip) in ipaddress.ip_network(network, strict=False):
            return "same"
    except Exception:
        return "unknown"
    return "other"


def guess_role(ip, gateway_ip):
    if ip == gateway_ip:
        return "gateway"
    return "client"


def build_scan_record(devices, summary):
    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "devices": devices,
        "summary": summary,
        "gateway_mac": summary.get("gateway_mac"),
    }


def write_json_report(path, scan_record):
    save_json(path, scan_record)


def write_html_report(path, scan_record):
    ensure_dir(os.path.dirname(path))
    devices = scan_record.get("devices", [])
    summary = scan_record.get("summary", {})
    rows = []
    for d in devices:
        rows.append(
            "<tr>"
            f"<td>{d.get('ip','')}</td>"
            f"<td>{d.get('mac','')}</td>"
            f"<td>{d.get('vendor','')}</td>"
            f"<td>{d.get('role','')}</td>"
            f"<td>{d.get('classification','')}</td>"
            f"<td>{d.get('hostname','')}</td>"
            "</tr>"
        )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Network Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; background:#0b0f12; color:#e6e6e6; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #2b2f33; padding: 8px; }}
th {{ background:#1b1f23; }}
</style>
</head>
<body>
<h2>Network Scan Report</h2>
<p>Timestamp: {scan_record.get("timestamp")}</p>
<p>Total devices: {summary.get("total_devices")}</p>
<p>Packet loss: {summary.get("packet_loss")}%</p>
<table>
<thead>
<tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Role</th><th>Class</th><th>Hostname</th></tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


def append_operation_log(path, message):
    ensure_dir(os.path.dirname(path))
    stamp = datetime.utcnow().isoformat() + "Z"
    with open(path, "a", encoding="utf-8") as f:
        f.write(f"[{stamp}] {message}\n")


def load_watchlist(path):
    data = load_json(path, default=[])
    watchlist = set()
    if isinstance(data, dict):
        items = data.get("items")
        if items is None:
            items = data.get("ips", []) + data.get("macs", [])
    else:
        items = data
    for item in items:
        if not item:
            continue
        watchlist.add(str(item).strip().lower())
    return watchlist


def load_profiles(path):
    profiles = load_json(path, default={})
    if not profiles:
        profiles = {"default": DEFAULT_PROFILE_SETTINGS.copy()}
    return profiles


def get_profile(profiles, name):
    base = DEFAULT_PROFILE_SETTINGS.copy()
    if isinstance(profiles, dict) and isinstance(profiles.get("default"), dict):
        base.update(profiles["default"])
    if isinstance(profiles, dict) and isinstance(profiles.get(name), dict):
        merged = base.copy()
        merged.update(profiles[name])
        return merged
    return base


def update_profile(profiles, name, updates):
    base = profiles.get(name, profiles.get("default", {})).copy()
    base.update(updates)
    profiles[name] = base
    return profiles


def save_profiles(path, profiles):
    save_json(path, profiles)


def load_last_scan(path):
    return load_json(path, default=None)


def save_last_scan(path, scan_record):
    save_json(path, scan_record)


def append_scan_history(path, scan_record, limit=50, max_entries=None):
    if max_entries is not None:
        limit = max_entries
    history = load_json(path, [])
    if not isinstance(history, list):
        history = []
    history.append(scan_record)
    history = history[-limit:]
    save_json(path, history)
    return history


def build_report_paths(data_dir, timestamp_label=None):
    if timestamp_label:
        base = f"scan_{timestamp_label}"
    else:
        base = "latest_scan"
    return {
        "json": os.path.join(data_dir, f"{base}.json"),
        "html": os.path.join(data_dir, f"{base}.html"),
    }


def summarize_changes(prev_scan, current_scan):
    if not prev_scan:
        return {"status": "no_previous_scan", "added_count": 0, "removed_count": 0}
    prev_devices = {d.get("ip") for d in prev_scan.get("devices", [])}
    curr_devices = {d.get("ip") for d in current_scan.get("devices", [])}
    added = list(curr_devices - prev_devices)
    removed = list(prev_devices - curr_devices)
    return {
        "status": "ok",
        "added": added,
        "removed": removed,
        "added_count": len(added),
        "removed_count": len(removed),
    }


def compute_ip_usage(total_hosts, total_devices):
    if total_hosts <= 0:
        return 0.0
    return round((total_devices / total_hosts) * 100.0, 2)


def compare_scan_summaries(prev_scan, current_scan):
    if not prev_scan:
        return {}
    return {
        "prev_total": prev_scan.get("summary", {}).get("total_devices"),
        "current_total": current_scan.get("summary", {}).get("total_devices"),
        "prev_packet_loss": prev_scan.get("summary", {}).get("packet_loss"),
        "current_packet_loss": current_scan.get("summary", {}).get("packet_loss"),
    }


def is_valid_ip(ip_string):
    try:
        ipaddress.IPv4Address(ip_string)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False


def is_valid_cidr(cidr_string):
    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False
