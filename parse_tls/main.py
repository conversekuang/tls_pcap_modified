#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: main.py
@time: 2020/12/25 16:44
"""

import dpkt
from parse_tls.PraseTLS import parse_tcp_packet
from scripts.modified_3_Session2png import show_files
import json

TOTAL_SIZE = 784


def load_parse_file():
    parse_file = r"D:\sharing_F\test_data\feature_idx"
    datasets = json.load(open(parse_file))
    # 将原始的数组Byte类型，转换成int类型
    changed_type_dataset = []

    for dataset in datasets:
        tmp = {}
        for key, val in dataset.items():
            tmp[int(str(key))] = float(str(val))
        changed_type_dataset.append(tmp)
    # print(changed_type_dataset)

    total_dict = {}
    total_dict["baidu"] = changed_type_dataset[0]
    total_dict['qq'] = changed_type_dataset[1]
    total_dict['mail'] = changed_type_dataset[2]
    return total_dict


def main():
    """
    根据payload的下标返回的是对应的content字段名称，根据content type添加系数
    :return:
    """
    total_dict = load_parse_file()

    result_dict = {
        "baidu": {},
        "mail": {},
        "qq": {}
    }

    srcbasepath = r"D:\sharing_F\test_data\test"
    src_pcap_files = show_files(srcbasepath, [])
    qq_count = 0
    baidu_count = 0
    mail_count = 0
    record_logs = []
    for filepath in src_pcap_files:
        if "baidu" in filepath:
            index_type = "baidu"
            index_arr = total_dict["baidu"]
            baidu_count += 1
        elif "mail" in filepath:
            index_type = "mail"
            index_arr = total_dict["mail"]
            mail_count += 1
        else:
            index_type = "qq"
            index_arr = total_dict["qq"]
            qq_count += 1

        coefficiency_list = []
        for index in sorted(index_arr.keys()):
            coefficiency_list.append(index_arr[index])

        content_list = []
        contents = []
        for content_type in search_index_byte_content(filepath, sorted(index_arr.keys())):
            # if "unknown value extension_type" in content_type:
            #     print(filepath)
            content_list.append(content_type[0])
            contents.append(content_type)
        print(contents)
        assert len(content_list) == len(total_dict[index_type]), "输入index列表和输出类型列表，长度不一致"
        assert len(content_list) == len(coefficiency_list), "内容和系数列表，长度不一致"

        # print(filepath)
        calculate_by_coefficiency = zip(content_list, coefficiency_list)
        # print(list(calculate_by_coefficiency))

        record_logs.append(content_list)
        for element in zip(content_list, coefficiency_list):
            content_type = element[0]
            coefficiency = element[1]
            if content_type not in result_dict[index_type].keys():
                result_dict[index_type][content_type] = coefficiency
            else:
                result_dict[index_type][content_type] += coefficiency

    print(result_dict)
    json.dump(result_dict, open("res.json", "w"))
    print("baidu:{},qq:{},mail:{}, total_contents:{}".format(baidu_count, qq_count, mail_count, len(record_logs)))


def construct_data(filepath):
    f = open(filepath, 'rb')
    packets = dpkt.pcap.Reader(f)
    try:
        for ts, buf in packets:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            tcp = ip.data
            if len(tcp.data) > 0:
                res = parse_tcp_packet(tcp)
                yield res
    except Exception as e:
        print(e)


def search_index_byte_content(filepath, wanted_bytes_arr):
    """

    :param filepath:
    :param wanted_bytes_arr:
    :return:
    """
    number_of_cauculate_indexes = 0
    length_sum = 0
    index_byte = wanted_bytes_arr[number_of_cauculate_indexes]
    for records in construct_data(filepath):
        for record in records:
            for packet in record:
                content = packet[0]
                length = packet[1]
                while index_byte in range(length_sum, length_sum + length + 1):
                    yield content, index_byte
                    number_of_cauculate_indexes += 1
                    # 生成器中return None，直接停止生成器
                    if number_of_cauculate_indexes >= len(wanted_bytes_arr):
                        return None
                    else:
                        index_byte = wanted_bytes_arr[number_of_cauculate_indexes]
                else:
                    length_sum += length


if __name__ == '__main__':
    #　arr = [2570, 6682, 14906, 19018, 23130, 27242, 31354, 35466, 39578, 43690, 47802, 51914, 52394, 56026, 64250, 60138]
    # ['0XA0A', '0X1A1A', '0X3A3A', '0X4A4A', '0X5A5A', '0X6A6A', '0X7A7A', '0X8A8A', '0X9A9A', '0XAAAA', '0XBABA', '0XCACA', '0XCCAA', '0XDADA', '0XFAFA', '0XEAEA']
    main()

    # oldfilepath = r"D:\sharing_F\test_data\non-vpn\baidu\baidu-285.pcap"  # r"D:\sharing_F\test_data\non-vpn\qq"
    # # construct_data(oldfilepath)
    # arr = [157, 110, 84, 302, 150, 566, 96, 156, 614, 78, 161, 160, 689, 656, 79, 620, 700, 663, 605]
    # content_list = []
    # for content_type in search_index_byte_content(oldfilepath, sorted(arr)):
    #     content_list.append(content_type)
    #     print(content_type)
    # print(content_list)
    # assert len(content_list) == len(arr), "{},{}输入输出长度不一致".format(len(content_list), len(arr))

    # total_dict = load_parse_file()
    #
    # result_dict = {
    #     "baidu": {},
    #     "mail": {},
    #     "qq": {}
    # }
    #
    # srcbasepath = r"D:\sharing_F\test_data\non-vpn"
    # src_pcap_files = [r"D:\sharing_F\test_data\non-vpn\qq\qq('172.16.12.90', 64237, '58.251.150.31', 443)742c7317-c572-4377-9fa0-81cac1620c68.pcap"]
    # qq_count = 0
    # baidu_count = 0
    # mail_count = 0
    # record_logs = []
    # for filepath in src_pcap_files:
    #     if "baidu" in filepath:
    #         index_type = "baidu"
    #         index_arr = total_dict["baidu"]
    #         baidu_count += 1
    #     elif "mail" in filepath:
    #         index_type = "mail"
    #         index_arr = total_dict["mail"]
    #         mail_count += 1
    #     else:
    #         index_type = "qq"
    #         index_arr = total_dict["qq"]
    #         qq_count += 1
    #
    #     coefficiency_list = []
    #     for index in sorted(index_arr.keys()):
    #         coefficiency_list.append(index_arr[index])
    #
    #     content_list = []
    #     for content_type in search_index_byte_content(filepath, sorted(index_arr.keys())):
    #         # if "unknown value extension_type" in content_type:
    #         #     print(filepath)
    #         print(content_type)
    #         content_list.append(content_type)
    #
    #     assert len(content_list) == len(total_dict[index_type]), "输入index列表和输出类型列表，长度不一致"
    #     assert len(content_list) == len(coefficiency_list), "内容和系数列表，长度不一致"
    #
    #     print(filepath)
    #     calculate_by_coefficiency = zip(content_list, coefficiency_list)
    #     print(list(calculate_by_coefficiency))
    #
    #     record_logs.append(content_list)
    #     for element in zip(content_list, coefficiency_list):
    #         content_type = element[0]
    #         coefficiency = element[1]
    #         if content_type not in result_dict[index_type].keys():
    #             result_dict[index_type][content_type] = coefficiency
    #         else:
    #             result_dict[index_type][content_type] += coefficiency
    #
    # print(result_dict)
    # json.dump(result_dict, open("res.json", "w"))
    # print("baidu:{},qq:{},mail:{}, total_contents:{}".format(baidu_count, qq_count, mail_count, len(record_logs)))
    #
