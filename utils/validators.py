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

