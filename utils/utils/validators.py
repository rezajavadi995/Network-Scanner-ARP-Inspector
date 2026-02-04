#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
validators.py
=============
توابع اعتبارسنجی برای Network Scanner

این فایل شامل:
- اعتبارسنجی IP address
- اعتبارسنجی MAC address (آینده)
- اعتبارسنجی CIDR (آینده)
"""

import ipaddress


def is_valid_ip(ip_string):
    """
    بررسی معتبر بودن IP address
    
    Args:
        ip_string (str): رشته IP برای بررسی
        
    Returns:
        bool: True اگه IP معتبر باشه، وگرنه False
        
    Examples:
        >>> is_valid_ip("192.168.1.1")
        True
        
        >>> is_valid_ip("999.999.999.999")
        False
        
        >>> is_valid_ip("hello")
        False
        
        >>> is_valid_ip("8.8.8.8")
        True
    """
    try:
        # تبدیل رشته به شیء IP
        ipaddress.IPv4Address(ip_string)
        return True
        
    except (ipaddress.AddressValueError, ValueError):
        # اگه فرمت اشتباه بود
        return False


def is_valid_cidr(cidr_string):
    """
    بررسی معتبر بودن CIDR notation (مثل 192.168.1.0/24)
    
    Args:
        cidr_string (str): رشته CIDR برای بررسی
        
    Returns:
        bool: True اگه CIDR معتبر باشه
        
    Examples:
        >>> is_valid_cidr("192.168.1.0/24")
        True
        
        >>> is_valid_cidr("192.168.1.0/999")
        False
    """
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
