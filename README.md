# 🌐 Network Scanner & ARP Inspector (Python)

**Professional Local Network Scanner using Python 3**

A professional Python 3 tool for scanning local networks (LAN / Wi‑Fi) and identifying connected devices using **Ping** and **ARP** techniques.

ابزاری حرفه‌ای با Python 3 برای اسکن شبکه‌های محلی (LAN / Wi‑Fi) و شناسایی دستگاه‌های متصل با استفاده از **Ping** و **ARP**.

---
## ⚡ One‑Click Install (نصب سریع)

فقط این دستور را کپی و اجرا کنید:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/rezajavadi995/Network-Scanner-ARP-Inspector/main/install.sh)
```
---
## 📌 About The Project

This tool scans your local network to discover active devices, extract IP and MAC addresses, detect device vendors using MAC OUI, and classify devices based on their network behavior.

این ابزار شبکه محلی شما را اسکن می‌کند، دستگاه‌های فعال را شناسایی می‌کند، IP و MAC آن‌ها را نمایش می‌دهد، سازنده دستگاه (Vendor) را با OUI مشخص می‌کند و دستگاه‌ها را بر اساس رفتار شبکه‌ای دسته‌بندی می‌کند.

---

## 🧠 How It Works

- Uses **Ping** to detect reachable devices
- Reads the system **ARP table**
- Combines Ping and ARP results for accurate detection
- Identifies devices that exist but do not respond to Ping

نحوه عملکرد:
- استفاده از **Ping** برای شناسایی دستگاه‌های پاسخ‌گو
- خواندن جدول **ARP** سیستم
- ترکیب نتایج Ping و ARP برای دقت بالاتر
- تشخیص دستگاه‌هایی که وجود دارند ولی Ping را بلاک کرده‌اند

---

## 🚀 Features

- ✅ Full network Ping scan
- 📡 ARP table inspection
- 🖥️ Display IP & MAC addresses
- 🏷️ Vendor detection via MAC OUI (offline)
- 🔄 Numeric IP sorting
- 🟢 Device classification:
  - Ping OK
  - ARP Only
  - Incomplete
- 📊 Progress indicator
- 🛡️ Safe & non-intrusive scanning

ویژگی‌ها:
- ✅ اسکن کامل Ping روی شبکه
- 📡 بررسی جدول ARP
- 🖥️ نمایش IP و MAC
- 🏷️ تشخیص سازنده دستگاه (آفلاین)
- 🔄 مرتب‌سازی عددی IP
- 🟢 دسته‌بندی دستگاه‌ها:
  - Ping OK
  - فقط ARP
  - ناقص
- 📊 نمایش وضعیت پیشرفت
- 🛡️ بدون ایجاد اختلال در شبکه

---

## 📤 Sample Output

```text
========== دستگاه‌های فعال (Ping OK) ==========
✅ 192.168.1.104  9A:6C:31:D9:EC:6A  [Randomized MAC (Mobile)]
✅ 192.168.1.254  00:04:ED:EF:E9:78  [TP-Link]

========== بدون Ping ولی در ARP ==========
⚠️  192.168.1.101  10:63:C8:5E:05:75  [Huawei]

========== ARP Incomplete ==========
❌ 192.168.1.175  <incomplete>

تعداد دستگاه‌ها (بدون خودت): 5
تعداد کل با خودت: 6
[✓] عملیات با موفقیت انجام شد
