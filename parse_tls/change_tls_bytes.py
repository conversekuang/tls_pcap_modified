#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: change_tls_bytes.py
@time: 2020/12/30 16:02
"""
import dpkt
from parse_tls.PraseTLS import parse_tcp_packet
from parse_tls.main import load_parse_file
from scripts.modified_3_Session2png import show_files
import json
import os

def change_tls_payload(oldfilepath, newfilepath):
    """
    修改payload
    :param oldfilepath:
    :param newfilepath:
    :return:
    """
    test = open(newfilepath, "wb")
    writer = dpkt.pcap.Writer(test)
    f = open(oldfilepath, 'rb')
    map_dict = {}
    packets = dpkt.pcap.Reader(f)
    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        stream = tcp.data
        # 当payload大于0的时候，
        if len(stream) > 0:
            res = parse_tcp_packet(tcp)
            for i in res:
                pass
            # [[[type, length],...,],...,] 多维数组
            # 看定位的在这个包的，修改该字节对应的字段的数目。然后修改。写入该包。
            # 当超过784，不用修改，直接把后面的包写入即可。784结束完的多写一包数据即可。不用往后写太多。

        writer.writepkt(eth, ts=ts)  # 如果不加ts参数的话，这个数据包的时间戳默认是当前时间！
        test.flush()
    test.close()


def construct_data(tcp):
    try:
        if len(tcp.data) > 0:
            res = parse_tcp_packet(tcp)
            yield res
    except Exception as e:
        print(e)


def search_index_byte_content(tcp, wanted_bytes_arr, number_of_caculate_indexes, mark_the_start_payload):
    """
    根据
    :param filepath:
    :param wanted_bytes_arr:
    :return:
    """
    # number_of_caculate_indexes = 0
    # mark_the_start_payload = [0]
    length_sum = mark_the_start_payload[-1]  # 这个sum是所有包payload的计数和，如何得到每一包tcp payload的坐标？
    index_byte = wanted_bytes_arr[number_of_caculate_indexes]
    for records in construct_data(tcp):
        # 返回的是每一个packet的数据生成的tcp_payload_list=[[[...,]]]
        for record in records:
            for packet in record:
                content = packet[0]  # content内容
                length = packet[1]   # content占据的长度
                while index_byte in range(length_sum, length_sum + length + 1):
                    yield content, length_sum - mark_the_start_payload[-1], length, number_of_caculate_indexes, mark_the_start_payload
                    # 如果index byte在其中，返回的是content type其对应的content开始字节号以及content长度
                    number_of_caculate_indexes += 1
                    if number_of_caculate_indexes >= len(wanted_bytes_arr):
                        return None
                    else:
                        index_byte = wanted_bytes_arr[number_of_caculate_indexes]
                else:
                    length_sum += length
        else:
            mark_the_start_payload.append(length_sum)


def main():
    """
    要查找的特征名称文件是：feature_set.json
    :return:
    """
    TOTAL_SIZE = 784

    change_content_list = json.load(open("feature_set.json"))
    extensions_list = ['server key_sharing', 'client server_name', 'server renegotiation_info', 'client supported_versions', 'client supported_groups', 'client SessionTicket_TLS', "client extended_master_secret"]

    srcbasepath = r"D:\sharing_F\test_data\test"
    dstbasepath = r"D:\sharing_F\test_data\modified"
    if not os.path.exists(dstbasepath):
        os.mkdir(dstbasepath)

    # oldfilepath = r"D:\sharing_F\test_data\test\pan.baidu('172.16.0.5', 50410, '180.149.145.241', 443)11a103bb-749b-4199-bcf1-cab82e711666.pcap"
    # newfilepath = r"D:\sharing_F\test_data\test\xxx.pcap"

    qq_count = 0
    baidu_count = 0
    mail_count = 0
    total_dict = load_parse_file()
    src_pcap_files = show_files(srcbasepath, [])

    for oldfilepath in src_pcap_files:
        newfilename = os.path.split(oldfilepath)[1]
        newfilepath = os.path.join(dstbasepath, 'modified_'+newfilename)
        print(oldfilepath)
        if "baidu" in oldfilepath:
            index_arr = total_dict["baidu"]
            baidu_count += 1
        elif "mail" in oldfilepath:
            index_arr = total_dict["mail"]
            mail_count += 1
        else:
            index_arr = total_dict["qq"]
            qq_count += 1

        print(sorted(index_arr.keys()))
        newfile = open(newfilepath, "wb")
        writer = dpkt.pcap.Writer(newfile)
        oldfile = open(oldfilepath, 'rb')
        packets = dpkt.pcap.Reader(oldfile)

        cumulative_payload_length = 0
        number_of_caculate_indexes = 0
        mark_the_start_payload = [0]

        for ts, buf in packets:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            payload_arr = bytearray(tcp.data)
            # 当payload大于0的时候，
            if len(tcp.data) > 0 and TOTAL_SIZE > cumulative_payload_length and number_of_caculate_indexes < len(index_arr.keys()):  #
                for result in search_index_byte_content(tcp, sorted(index_arr.keys()), number_of_caculate_indexes, mark_the_start_payload):
                    # 返回该包的content type，该content在该包payload起始的字节，以及content的长度
                    content_type = result[0]
                    starter = result[1]
                    length = result[2]
                    number_of_caculate_indexes = result[3]
                    mark_the_start_payload = result[4]
                    print(result, sorted(index_arr.keys())[number_of_caculate_indexes])
                    # 若content type在change_content_list中，则进行修改
                    if content_type in change_content_list:
                        if content_type in extensions_list:
                            # 若是extensions的字段，则筛选内容进行修改即可,content type2, length 2,所以内容从4开始，长度也要减4
                            # print(content_type, starter, length, tcp.data[starter+4:starter + length])
                            payload_arr[starter+4:starter + length] = [0 for i in range(length-4)]
                        else:
                            # print(content_type, starter, length, tcp.data[starter:starter+length])
                            # 修改payload, bytesarray可以替换，tcp.data
                            payload_arr[starter:starter+length] = [0 for i in range(length)]

                number_of_caculate_indexes += 1
                cumulative_payload_length += len(tcp.data)
                # [[[type, length],...,],...,] 多维数组
                # 看定位的在这个包的，修改该字节对应的字段的数目。然后修改。写入该包。
                # 当超过784，不用修改，直接把后面的包写入即可。784结束完的多写一包数据即可。不用往后写太多。
                tcp.data = payload_arr
                writer.writepkt(eth, ts=ts)  # 如果不加ts参数的话，这个数据包的时间戳默认是当前时间！
            newfile.flush()
        newfile.close()
    print("baidu:{},qq:{},mail:{}".format(baidu_count, qq_count, mail_count))


if __name__ == '__main__':
    main()
