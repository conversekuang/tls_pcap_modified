# Wei Wang (ww8137@mail.ustc.edu.cn)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this file, You
# can obtain one at http://mozilla.org/MPL/2.0/.
# ==============================================================================
"""
@author: converse
@version: 1.0.0
@file: modified_4_Png2Mnist.py.py
@time: 2020/11/5 20:00

最终生成的5_文件夹中:

根据输入不同，选择不同的dict即可，将src dir目录。
如果是vpn-2: 以vpn 和non-vpn文件夹 0-1
如果是vpn-6：选择的是 vpn文件夹 0-5
如果是non-vpn-6：选择的是 non-vpn文件夹 6-11
如果是12：non-vpn 和vpn文件夹都选择    0-11
"""

import os
from PIL import Image
from array import *
from random import shuffle

label_dict_2class = {'non-vpn': 0, 'vpn': 1}
label_dict_6class_novpn = {"chat": 0, "email": 1, "transfer": 2, "p2p": 3, 'streaming': 4, 'voip': 5}
label_dict_6class_vpn = {'vpn_chat': 6, 'vpn_email': 7, 'vpn_transfer': 8, 'vpn_p2p': 9,
                         'vpn_streaming': 10, 'vpn_voip': 11}
label_dict_12class = {"chat": 0, "email": 1, "transfer": 2, "p2p": 3, "streaming": 4, "voip": 5, "vpn_chat": 6,
                      "vpn_email": 7, "vpn_transfer": 8, "vpn_p2p": 9, "vpn_streaming": 10, "vpn_voip": 11
                      }
our_dataset_dict = {
    "baidu": 0,
    "mail": 1,
    "qq": 2,
}


def entrance_label_dict_selection():
    """
    根据输入选择标签范围
    :return:
    """
    while True:
        number_of_class = int(input("选择哪种模式?请输入一个数字(2,6,12)"))
        if number_of_class == 2:
            result_label_dict = label_dict_2class
            break
        elif number_of_class == 6:
            whether_vpn = input("是否选择vpn数据?(Y or N)")
            if whether_vpn in ("y", "Y"):
                result_label_dict = label_dict_6class_vpn
                break
            else:
                result_label_dict = label_dict_6class_novpn
                break
        elif number_of_class == 12:
            result_label_dict = label_dict_12class
            break
        elif number_of_class == 3:
            result_label_dict = our_dataset_dict
            break
        else:
            print("输入数字错误，请重新输入:")
    return result_label_dict


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


def filter_filelist(srcdirpath, all_train_files, all_test_files, label_dict):
    """
    根据选择的label_dict, 从srcdirpath文件中返回所有文件，筛选对应的文件，形成文件列表
    :param srcdir: 源png文件的路径
    :return:
    """
    # 首先遍历当前目录所有文件及文件夹
    file_list = os.listdir(srcdirpath)
    # 准备循环判断每个元素是否是文件夹还是文件，是文件的话，把名称传入list，是文件夹的话，递归
    for file in file_list:
        # 利用os.path.join()方法取得路径全名，并存入cur_path变量，否则每次只能遍历一层目录
        cur_path = os.path.join(srcdirpath, file)
        # 判断是否是文件夹
        if os.path.isdir(cur_path):
            filter_filelist(cur_path, all_train_files, all_test_files, label_dict)
        else:
            # 不是文件夹，是文件的情况,检查是否是图片，检查文件是否符合所选类别，是测试数据 or 训练数据
            if cur_path.endswith(".png"):
                all_train_files.append(cur_path)
                # if check_file_validation(cur_path, label_dict):
                #     if "Train" in cur_path:
                #         all_train_files.append(cur_path)
                #     else:
                #         all_test_files.append(cur_path)

    return all_train_files, all_test_files


def check_file_validation(filepath, label_dict):
    """
    根据dict_label标签判断出，该文件是否符合要求
    eg:
    filepath_elements = [
    'F:', '迅雷下载', 'x', 'DeepTraffic-master', '2.encrypted_traffic_classification','2.PreprocessedTools',
    '4_', 'Session_AllLayers', 'non-vpn', 'Test', 'chat', 'AIMchat2.pcap.UDP_131-202-240-87_61827_224-0-0-252_5355.png']

    filepath_elements[-2]: chat voip streaming ...
    filepath_elements[-3]: Test or Train
    filepath_elements[-4]: vpn or non-vpn
    :return:
    """
    if len(label_dict.keys()) == 2 or len(label_dict.keys()) == 12:
        # 因为==2或者==12，该文件夹下的所有文件都是生效的，不用判断文件
        return True
    else:
        # 6的情况，只有一部分是有效的
        filepath_elements = filepath.split("\\")
        if "vpn" in list(label_dict.keys())[0]:
            if filepath_elements[-4] != "non-vpn":
                # 如果标签有vpn,就是要vpn的数据，且当前文件路径也不是non-vpn，符合条件的
                return True
            else:
                # 如果标签有vpn,就是要vpn的数据，且当前文件路径竟然是non-vpn，不符合条件的
                return False
        else:
            if filepath_elements[-4] == "non-vpn":
                # 如果标签没有vpn，且当前文件路径也是non vpn，符合条件的
                return True
            else:
                # 如果标签没有vpn，且当前文件路径有vpn，不符合条件的
                return False


def mark_file_with_label(filepath, label_dict):
    """
    根据所选的label_dict，将文件生成对应的label
    :param filepath: 文件路径
    :param label_dict: 所选的label字典
    :return: 返回的是label 数字
    """
    filepath_elements = filepath.split("\\")

    # if len(label_dict.keys()) == 2:
    #     if filepath_elements[-4] == "non-vpn":
    #         # non-vpn 是 0
    #         return 0
    #     else:
    #         # vpn 是 1
    #         return 1
    #
    # elif len(label_dict.keys()) == 12:
    #     # 根据映射可以找到，
    #     if filepath_elements[-4] == "non-vpn":
    #         # non-vpn
    #         return label_dict[filepath_elements[-2]]
    #     else:
    #         # vpn
    #         return label_dict["vpn_" + filepath_elements[-2]]
    #
    # else:
    #     # len(label_dict.keys()) == 6 的情况，因为文件匹配过了，具有一致性。
    #     if "vpn" not in list(label_dict.keys())[0]:
    #         return label_dict[filepath_elements[-2]]
    #     else:
    #         return label_dict["vpn_" + filepath_elements[-2]]

    filename = filepath_elements[-1]
    if "baidu" in filename:
        return label_dict["baidu"]
    elif "mail" in filename:
        return label_dict["mail"]
    else:
        return label_dict["qq"]


def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as e:  # Python >2.5
        print(e)


def png2Mist(FilePathList, dstdirpath, filename, label_dict):
    """

    :param name: list 0是src的路径，1是dst的路径
    :param FileList: 转换的文件List
    :return:
    """
    if not os.path.exists(dstdirpath):
        mkdir_p(dstdirpath)

    data_image = array('B')
    data_label = array('B')

    shuffle(FilePathList)  # Usefull for further segmenting the validation set

    # 将每个png文件转换为image和label
    for filepath in FilePathList:
        print(filepath)
        label = mark_file_with_label(filepath, label_dict)
        Im = Image.open(filepath)
        pixel = Im.load()
        width, height = Im.size
        # 添加data_image
        for x in range(0, width):
            for y in range(0, height):
                data_image.append(pixel[y, x])
        # 添加label
        data_label.append(label)  # labels start (one unsigned byte each) label
    print(data_label)

    # 头文件的制作
    hexval = "{0:#0{1}x}".format(len(FilePathList), 6)  # number of files in HEX
    hexval = '0x' + hexval[2:].zfill(8)

    # header for label array
    header = array('B')
    header.extend([0, 0, 8, 1])
    header.append(int('0x' + hexval[2:][0:2], 16))
    header.append(int('0x' + hexval[2:][2:4], 16))
    header.append(int('0x' + hexval[2:][4:6], 16))
    header.append(int('0x' + hexval[2:][6:8], 16))

    # label的头文件
    data_label = header + data_label
    # additional header for images array
    if max([width, height]) <= 256:
        header.extend([0, 0, 0, width, 0, 0, 0, height])
    else:
        raise ValueError('Image exceeds maximum size: 256x256 pixels')

    # imag的头文件
    header[3] = 3  # Changing MSB for image data (0x00000803)
    data_image = header + data_image

    # 生成label文件
    output_file = open(os.path.join(dstdirpath, filename + '-labels-idx1-ubyte'), 'wb')
    data_label.tofile(output_file)
    output_file.close()

    # 生成image文件
    output_file = open(os.path.join(dstdirpath, filename + '-images-idx3-ubyte'), 'wb')
    data_image.tofile(output_file)
    output_file.close()


# # gzip resulting files
# for name in Names:
#     # 将文件打包成gzip文件
#     os.system('gzip ' + name[1] + '-images-idx3-ubyte')
#     os.system('gzip ' + name[1] + '-labels-idx1-ubyte')


if __name__ == '__main__':
    # TODO 根据自己文件目录来设定 以及需要选择子目录下的pattern来手动修改
    basedir = r"D:\sharing_F"
    pattern_dir = "\\L7\\20201223-new-mailpcap"

    # 得到操作的数据文件夹
    srcdirpath = basedir + pattern_dir + "\\L7_png"

    label_dict = entrance_label_dict_selection()

    if len(label_dict.keys()) == 2:
        class_dir = "2class"
    elif len(label_dict.keys()) == 3:
        class_dir = "3class"
    elif len(label_dict.keys()) == 12:
        class_dir = "12class"
    else:
        if "vpn" in list(label_dict.keys())[0]:
            class_dir = "6class_vpn"
        else:
            class_dir = "6class_no_vpn"

    all_test_files = []
    all_train_files = []
    all_train_files, all_test_files = filter_filelist(srcdirpath, all_train_files, all_test_files, label_dict)

    # name 应该是dst文件夹
    # Names = [['4_Png\Train', '5_Mnist\\train'], ['4_Png\Test', '5_Mnist\\t10k']]

    dstdir = basedir + pattern_dir + "\\" + class_dir

    png2Mist(all_train_files, dstdir, "train", label_dict)
    # png2Mist(all_test_files, dstdir, "t10k", label_dict)
