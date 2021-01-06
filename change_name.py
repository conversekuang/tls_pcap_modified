#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: change_name.py
@time: 2020/12/17 17:14
"""
"""
修改中科大文章处理数据的流程，在自己数据集上。
"""
import os
import shutil


def change_name(basedir, dir):
    """
    由于原来的文件名称太长，脚本报错。需要修改文件名称。命名方式为数字。因为提取后的流量也是按5元组命名的
    """
    currentdir = basedir + "\\" + dir
    count = 1
    for file in os.listdir(currentdir):
        print(file)
        newname = "{}-{}".format(dir, count)
        os.rename(currentdir + "\\" + file, currentdir + "\\" + newname + ".pcap")
        count += 1


def move_pcap_to_parent_dir(basedir):
    for appdir in os.listdir(basedir):
        # parentdir = D:\sharing_F\2_\Session_AllLayers\non-vpn\baidu
        parentdir = basedir + "\\" + appdir
        for subdir in os.listdir(parentdir):
            # subdir = D:\sharing_F\2_\Session_AllLayers\non-vpn\baidu\baidu-1
            subdir = parentdir + "\\" + subdir
            if os.path.isdir(subdir):
                os.rmdir(subdir)
                # for filename in os.listdir(subdir):
                #     subpath = subdir + "\\" + filename
                #     parentpath = parentdir + "\\" + filename
                #     shutil.move(subpath, parentpath)
                #     print("{}移动成功".format(filename))


if __name__ == '__main__':
    basedir = r"D:\sharing_F\2_\new_Session"
    # for dir in os.listdir(basedir):
    #    change_name(basedir, dir)

    # move_pcap_to_parent_dir(basedir)
