#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: L7.py
@time: 2020/12/22 15:02
"""
import dpkt
import socket
from scripts.modified_3_Session2png import show_files

def extract_L7_in_application_data(oldfilepath, newfilepath):
    """
    一个pcap中已经是session了，所以第一个认领127.0.0.1，剩下一个是127.0.0.2
    :param oldfilepath:
    :param newfilepath:
    :return:
    """
    total_size = 784
    test = open(newfilepath, "wb")
    # writer = dpkt.pcap.Writer(test)
    f = open(oldfilepath, 'rb')
    packets = dpkt.pcap.Reader(f)
    flag = True
    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if flag and tcp.data[:2] != b'\x17\x03':  # 17 代表application data 03代表的是TLS协议
            continue
        elif flag and tcp.data[:2] == b'\x17\x03':
            if len(tcp.data) < total_size:
                test.write(tcp.data)
                total_size = total_size - len(tcp.data)
                flag = False
                continue
            else:
                test.write(tcp.data[:total_size])
                break
        else:
            if len(tcp.data) > 0:
                if len(tcp.data) < total_size:
                    test.write(tcp.data)
                    total_size = total_size - len(tcp.data)
                else:
                    test.write(tcp.data[:total_size])
                    break
    test.close()


if __name__ == '__main__':
    # oldfilepath = r"E:\ml_project\own_dataset_process\extract_L7\baidu-7.pcap"
    # newfilepath = r"E:\ml_project\own_dataset_process\extract_L7\baidu-7.bin"
    # extract_L7_in_application_data(oldfilepath, newfilepath)

    import os
    srcbasepath = r"D:\sharing_F\test_data\non-vpn"
    dstbasepath = r"D:\sharing_F\L7\20201223-new-mailpcap\L7_bin"
    src_pcap_files = show_files(srcbasepath, [])
    for srcfilepath in src_pcap_files:
        print(srcfilepath)
        filename = os.path.split(srcfilepath)[1]
        dstfilepath = os.path.join(dstbasepath, filename)
        extract_L7_in_application_data(srcfilepath, dstfilepath)