# -*- coding: utf-8 -*-
# Wei Wang (ww8137@mail.ustc.edu.cn)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file, You
# can obtain one at http://mozilla.org/MPL/2.0/.
# ==============================================================================
"""
@author: converse
@version: 1.0.0
@file: modified_3_Session2png.py.py
@time: 2020/11/5 19:26

目录：
session
  |__non-vpn
        |___Train
             |___chat
"""
import numpy
from PIL import Image
import binascii
import os

PNG_SIZE = 28


def show_files(path, all_files):
    # 首先遍历当前目录所有文件及文件夹
    file_list = os.listdir(path)
    # 准备循环判断每个元素是否是文件夹还是文件，是文件的话，把名称传入list，是文件夹的话，递归
    for file in file_list:
        # 利用os.path.join()方法取得路径全名，并存入cur_path变量，否则每次只能遍历一层目录
        cur_path = os.path.join(path, file)
        # 判断是否是文件夹
        if os.path.isdir(cur_path):
            show_files(cur_path, all_files)
        else:
            all_files.append(cur_path)
    return all_files


def getMatrixfrom_pcap(filename, width):
    with open(filename, 'rb') as f:
        content = f.read()
    hexst = binascii.hexlify(content)
    # 将\xaa这种的16进制改为bytes  'aa'
    fh = numpy.array([int(hexst[i:i + 2], 16) for i in range(0, len(hexst), 2)])
    # 每个字节是8bits，也就是2个hex，int将16进制转换成10进制
    rn = int(len(fh) / width)
    # 取整数倍的width长度。
    fh = numpy.reshape(fh[:rn * width], (-1, width))
    # 从一维数组变二维数组。宽度为with，长度也就是rn了
    fh = numpy.uint8(fh)
    return fh


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as e:  # Python >2.5
        print(e)


if __name__ == '__main__':
    # TODO 修改入口文件，根据自己放的文件情况,srcbasepath 不要以"/"结束
    srcbasepath = r"D:\sharing_F\L7\20201223-new-mailpcap\L7_bin"
    # 目标文件夹
    # dstbasepath = os.path.join("/".join(srcbasepath.split("/")[:-2]), "x_")
    dstbasepath = r"D:\sharing_F\L7\20201223-new-mailpcap\L7_png"
    src_pcap_files = show_files(srcbasepath, [])
    for src_pcap_file in src_pcap_files:
        # 对应到每个pcap文件
        # pcap_dir_arr = src_pcap_file.split("/")
        # # print(arr)
        # consists_dirs = pcap_dir_arr[-1].split("\\")
        # dir1 = consists_dirs[1]
        # dir2 = consists_dirs[2]
        # dir3 = consists_dirs[4]
        # dir4 = consists_dirs[3]
        # dst_dir = os.path.join(dstbasepath, dir1, dir2, dir3, dir4)
        # pcap_filename = consists_dirs[-1]

        # if not os.path.exists(dst_dir):
        #     mkdir_p(dst_dir)
        pcap_filename = os.path.split(src_pcap_file)[1]
        im = Image.fromarray(getMatrixfrom_pcap(src_pcap_file, PNG_SIZE))
        png_full = os.path.join(dstbasepath, os.path.splitext(pcap_filename)[0] + '.png')
        print(png_full)
        im.save(png_full)
        # 保存pcap对应的图片
