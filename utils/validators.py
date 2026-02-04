#!/usr/bin/env python3
# -*- coding: utf-8 -*-



import ipaddress


def is_valid_ip(ip_string):

    try:
        # تبدیل رشته به شیء IP
        ipaddress.IPv4Address(ip_string)
        return True
        
    except (ipaddress.AddressValueError, ValueError):
        # اگه فرمت اشتباه بود
        return False


def is_valid_cidr(cidr_string):

    try:
        ipaddress.ip_network(cidr_string, strict=False)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False




if __name__ == "__main__":
    print("=== Testing validators.py ===\n")
    
    # تست is_valid_ip
    print("Test is_valid_ip():")
    test_ips = [
        ("192.168.1.1", True),
        ("8.8.8.8", True),
        ("999.999.999.999", False),
        ("hello", False),
        ("", False),
    ]
    
    for ip, expected in test_ips:
        result = is_valid_ip(ip)
        status = "✓" if result == expected else "✗"
        print(f"  {status} is_valid_ip('{ip}') = {result} (expected {expected})")
    
    print("\nTest is_valid_cidr():")
    test_cidrs = [
        ("192.168.1.0/24", True),
        ("10.0.0.0/8", True),
        ("192.168.1.0/999", False),
        ("invalid", False),
    ]
    
    for cidr, expected in test_cidrs:
        result = is_valid_cidr(cidr)
        status = "✓" if result == expected else "✗"
        print(f"  {status} is_valid_cidr('{cidr}') = {result} (expected {expected})")
