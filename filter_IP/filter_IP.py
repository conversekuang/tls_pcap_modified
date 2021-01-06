#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: filter_IP.py
@time: 2020/12/21 16:07
"""
"""
将IP模糊掉，输入是pcap包，输出是pcap。但是IP和端口改变一下
"""
import dpkt
import datetime
import socket


def inet_to_str(inet):
    return socket.inet_ntop(socket.AF_INET, inet)


def print_packets(pcap):
    """Print out information about each packet in a pcap
       Args:
           pcap: dpkt pcap reader object (dpkt.pcap.Reader)
    """
    # packet num count
    r_num = 0
    # For each packet in the pcap process the contents
    for timestamp, buf in pcap:
        if r_num == 0:
            start_timestamp = timestamp
        r_num = r_num + 1
        # TODO
        print('\npacket num count :', r_num)
        # Print out the timestamp in UTC
        # TODO
        # 提取相对时间信息 变成
        relative_time = datetime.datetime.utcfromtimestamp(timestamp - start_timestamp)
        hour = relative_time.strftime("%H")
        minute = relative_time.strftime("%M")
        second = relative_time.strftime("%S")
        second_fragment = relative_time.strftime(".%f")
        # 时间单位是s，如果是ms，则timescale变成1000
        timescale = 1
        time_unit = (int(hour) * 3600 + int(minute) * 60 + int(second) + float(second_fragment)) * timescale

        # print("Timestamp:", hour, minute, second, float(second_fragment))
        print("Timestamp:", time_unit)

        # Unpack the Ethernet frame (mac src/dst, ethertype)
        eth = dpkt.ethernet.Ethernet(buf)
        # print('Ethernet Frame: ', mac_addr(eth.src), mac_addr(eth.dst), eth.type)
        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue
        # Now unpack the data within the Ethernet frame (the IP packet)
        # Pulling out src, dst, length, fragment info, TTL, and Protocol
        ip = eth.data
        # Pull out fragment information (flags and offset all packed into off field, so use bitmasks)

        do_not_fragment = bool(ip.off & dpkt.ip.IP_DF)
        more_fragments = bool(ip.off & dpkt.ip.IP_MF)
        fragment_offset = ip.off & dpkt.ip.IP_OFFMASK
        # Print out the info

        tcp = ip.data

        src_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.src), ip.data.sport)
        dst_ip = '{0}:{1}'.format(socket.inet_ntoa(ip.dst), ip.data.dport)

        # src_ip = '{}'.format(socket.inet_ntoa(ip.src))
        # src_port = '{}'.format(ip.data.sport)
        # dst_ip = '{}'.format(socket.inet_ntoa(ip.dst))
        # dst_port = '{}'.format(ip.data.dport)

        # FLAG 标志
        # fin_flag = 1 if (tcp.flags & dpkt.tcp.TH_FIN) != 0 else 0
        # syn_flag = 1 if (tcp.flags & dpkt.tcp.TH_SYN) != 0 else 0
        # rst_flag = 1 if (tcp.flags & dpkt.tcp.TH_RST) != 0 else 0
        # psh_flag = 1 if (tcp.flags & dpkt.tcp.TH_PUSH) != 0 else 0
        # ack_flag = 1 if (tcp.flags & dpkt.tcp.TH_ACK) != 0 else 0
        # urg_flag = 1 if (tcp.flags & dpkt.tcp.TH_URG) != 0 else 0
        # ece_flag = 1 if (tcp.flags & dpkt.tcp.TH_ECE) != 0 else 0
        # cwr_flag = 1 if (tcp.flags & dpkt.tcp.TH_CWR) != 0 else 0

        # OPTIONS 选项
        # option_list = dpkt.tcp.parse_opts(tcp.opts)

        # 显示窗口大小

        # seq = tcp.seq
        # ack = tcp.ack
        # print(tcp._off)
        # tcp._off:0101 ....(保留位) data offset 标识该TCP头部有多少个32bit（4字节）。0101代表5，所以5*4byte = 20 bytes
        # win = tcp.win

        # tcp.sum: 校验和（wireshark中HEX，这里还原出来是DEC）
        # tcp.urp: urgent pointer
        # print(option_list)
        # print("TCP段的内容{}\n".format(tcp.data))

        # if isinstance(tcp.data, dpkt.ssl.TLS):
        #     print("found")

        stream = tcp.data  # TCP 数据流

        if do_not_fragment == 1:
            #     print(r_num)
            print('IP: %s: %d-> %s:%d   (len=%d ttl=%d id=%d DF=%d MF=%d offset=%d,payload=%d)' % \
                  (inet_to_str(ip.src), tcp.sport, inet_to_str(ip.dst), tcp.dport, ip.len, ip.ttl, ip.id, do_not_fragment, more_fragments,
                   fragment_offset, len(stream)))
        # print(
        #     "time:,{}-->{},win:{},seq:{},ack {},urg:{} ack:{} psh:{} rst:{} syn:{} fin:{}".format(timestamp, src_ip,
        #                                                                                           dst_ip, win,
        #                                                                                           seq, ack,
        #                                                                                           urg_flag,
        #                                                                                           ack_flag,
        #                                                                                           psh_flag,
        #                                                                                           rst_flag,
        #                                                                                           syn_flag,
        #                                                                                           fin_flag))
        # print("options的大小是:{}".format(len(option_list)))
        # print("tcp--data")
        # print(stream)
        # print()
        # print("stream", stream.msg, stream.len)


def test(filename):
    """Open up a test pcap file and print out the packets"""
    with open(filename, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        print_packets(pcap)


def obscure_IP(oldfilepath, newfilepath):
    """
    一个pcap中已经是session了，所以第一个认领127.0.0.1，剩下一个是127.0.0.2
    :param oldfilepath:
    :param newfilepath:
    :return:
    """
    test = open(newfilepath, "wb")
    writer = dpkt.pcap.Writer(test)
    f = open(oldfilepath, 'rb')
    map_dict = {}
    packets = dpkt.pcap.Reader(f)
    count = 0
    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        if count == 0:
            IP1 = socket.inet_ntoa(eth.data.src)
            IP2 = socket.inet_ntoa(eth.data.dst)
            map_dict[IP1] = "127.0.0.1"
            map_dict[IP2] = "127.0.0.2"
            count += 1

        eth.data.src = socket.inet_pton(socket.AF_INET, map_dict[socket.inet_ntoa(eth.data.src)])  # 这里是将点分十进制转化成二进制
        eth.data.dst =socket.inet_pton(socket.AF_INET, map_dict[socket.inet_ntoa(eth.data.dst)])  # 这里是将点分十进制转化成二进制
        if eth.data.data.sport != 443:
            eth.data.data.sport = 1000
        if eth.data.data.dport != 443:
            eth.data.data.dport = 1000
        writer.writepkt(eth, ts=ts)  # 如果不加ts参数的话，这个数据包的时间戳默认是当前时间！
        test.flush()
    test.close()


def obscure_trim_pcap():
    """
    将trim截取后的文件模糊掉IP
    :return:
    """
    import os
    pcapfile = r"baidu-test.pcap"
    olddir_base = r"D:\sharing_F\2_\Session_AllLayers\non-vpn"
    newdir_base = r"D:\sharing_F\2_\Session_AllLayers\non-vpn"

    for appname in os.listdir(olddir_base):
        app_dirpath = os.path.join(olddir_base, appname)
        for classtype in os.listdir(app_dirpath):
            filedirpath = os.path.join(app_dirpath, classtype)
            for filename in os.listdir(filedirpath):
                newdirpath = newdir_base + "\\" + appname + "\\" + classtype
                olddirpath = filedirpath
                if not os.path.exists(newdirpath):
                    os.makedirs(newdirpath)
                # print("obscure_IP---{}".format(filename))
                try:
                    obscure_IP(olddirpath, newdirpath, filename)
                except Exception as e:
                    print("failure : obscure_IP---{}".format(filename))


def obscure_ori_pcap():
    """
    将原始文件模糊掉IP
    :return:
    """
    import os
    olddir_base = r"D:\sharing_F\2_\Session_AllLayers\non-vpn"
    newdir_base = r"D:\sharing_F\2_\Modified_Session_AllLayers\non-vpn"

    for appname in os.listdir(olddir_base):
        app_dirpath = os.path.join(olddir_base, appname)
        new_app_dirpath = os.path.join(newdir_base, appname)
        for filename in os.listdir(app_dirpath):
            oldfilepath = os.path.join(app_dirpath, filename)
            newfilepath = os.path.join(new_app_dirpath, filename+"_new.pcap")

            if not os.path.exists(new_app_dirpath):
                os.makedirs(new_app_dirpath)
            try:
                print("failure : obscure_IP---{}".format(filename))
                obscure_IP(oldfilepath, newfilepath)
            except Exception as e:
                print("failure : obscure_IP---{}".format(filename))


if __name__ == '__main__':
    obscure_ori_pcap()
    # import os
    # oldfilepath = r"D:\sharing_F\2_\Session_AllLayers\non-vpn\weiyun\baidu-1.pcap.TCP_10-38-0-36_52206_180-149-145-241_443.pcap"
    # newfilepath = r"D:\sharing_F\2_\Session_AllLayers\non-vpn\weiyun\baidu-1.pcap.TCP_10-38-0-36_52206_180-149-145-241_443_new.pcap"
    # obscure_IP(oldfilepath, newfilepath)
    # if os.path.exists(newfilepath):
    #     os.remove(oldfilepath)


