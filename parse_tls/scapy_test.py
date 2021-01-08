#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: scapy_test.py
@time: 2020/12/25 17:10
"""

from scapy.all import *
from scapy_ssl_tls.ssl_tls import TLS


def read_pcap(filepath):
    pkgs = PcapReader(filepath)
    count = 1
    while True:
        try:
            data = pkgs.read_packet()
            print()
            if data.haslayer("TLS"):
                print(data["TLS"])
        except EOFError as e:
            print(e)
            break
    pkgs.close()


if __name__ == '__main__':
    oldfilepath = r"D:\sharing_F\test_data\test\pan.baidu('10.38.0.36', 49183, '180.149.145.241', 443)cf7c97ed-38ba-43e6-b734-d51067939e57.pcap"
    read_pcap(oldfilepath)
