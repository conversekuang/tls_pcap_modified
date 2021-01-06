#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: extract_domain_name.py
@time: 2020/12/25 14:21
"""
import dpkt
import json
import binascii
import os
from scripts.modified_3_Session2png import show_files


def calculate_features(oldfilepath):
    filename = os.path.split(oldfilepath)[1]
    f = open(oldfilepath, 'rb')
    packets = dpkt.pcap.Reader(f)
    baidu = [62, 106, 147, 578, 593, 721]
    qq = [79, 157, 302, 605]
    mail = [84, 104, 613]
    list_ = []
    try:
        for ts, buf in packets:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            payload = tcp.data
            # print("长度", len(payload))
            if len(payload):
                hexst = binascii.hexlify(payload)
                print(len(hexst)/2)
                if hexst[:2] == b"16":
                    inner_dict = {}
                    if "baidu" in oldfilepath:
                        for index in baidu:
                            # print("{}:{}".format(index, hexst[(index - 1) * 2:index * 2]))
                            inner_dict[index] = hexst[(index - 1) * 2:index * 2]
                    elif "qq" in oldfilepath:
                        for index in qq:
                            # print("{}:{}".format(index, hexst[(index - 1) * 2:index * 2]))
                            inner_dict[index] = hexst[(index - 1) * 2:index * 2]
                    else:
                        for index in mail:
                            # print("{}:{}".format(index, hexst[(index - 1) * 2:index * 2]))
                            inner_dict[index] = hexst[(index - 1) * 2:index * 2]
                    list_.append(inner_dict)
    except Exception as e:
        pass
    return filename, list_


if __name__ == '__main__':

    total_dict = {}
    srcbasepath = r"D:\sharing_F\2_\new_Session"
    src_pcap_files = show_files(srcbasepath, [])
    for filepath in src_pcap_files:
        # print(filepath)
        print(filepath)
        filename, result = calculate_features(filepath)
        print(filename, result)
        total_dict[filename] = str(result)

    json.dump(total_dict, open("res.json", "w"))
    # srcbasepath = r"D:\sharing_F\2_\new_Session\qq\qq-51.pcap"
    # calculate_features(srcbasepath)
