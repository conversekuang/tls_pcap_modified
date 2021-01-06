#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: encryption_traffic_gpu.py
@time: 2020/11/12 14:49

资源有的cpu版本上，改成gpu版本
"""
import os
import numpy as np
import pandas as pd

import torch
import torch.nn as nn
import torchvision
from torchvision import datasets, transforms
from torchvision.datasets.mnist import read_image_file, read_label_file
from torch.autograd import Variable
import numpy
from torchsummary import summary

from sklearn.metrics import classification_report
from sklearn.metrics import confusion_matrix
from sklearn.metrics import accuracy_score, recall_score, precision_score
from sklearn.metrics import f1_score
from sklearn.metrics import precision_recall_curve
from sklearn.metrics import cohen_kappa_score
from sklearn.metrics import auc
from sklearn.metrics import average_precision_score
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from matplotlib import pyplot as plt
import seaborn as sns

from show_pic import MyDataSet

# from google.colab import drive
# drive.mount('/content/drive')

n_epochs = 50
batchsize = 64

dict_2class = {0: 'Novpn', 1: 'Vpn'}
dict_6class_novpn = {0: 'Chat', 1: 'Email', 2: 'File', 3: 'P2p', 4: 'Streaming', 5: 'Voip'}
dict_6class_vpn = {0: 'Vpn_Chat', 1: 'Vpn_Email', 2: 'Vpn_File', 3: 'Vpn_P2p', 4: 'Vpn_Streaming', 5: 'Vpn_Voip'}
dict_12class = {0: 'Chat', 1: 'Email', 2: 'File', 3: 'P2p', 4: 'Streaming', 5: 'Voip', 6: 'Vpn_Chat', 7: 'Vpn_Email',
                8: 'Vpn_File', 9: 'Vpn_P2p', 10: 'Vpn_Streaming', 11: 'Vpn_Voip'}

dict_3class = {0: 'baidu', 1: 'mail', 2: 'qq'}


BASE_DIR = r"D:\sharing_F\L7\20201223-new-mailpcap"
SUB_DIR = r"3class"
model_path = os.path.join(BASE_DIR, SUB_DIR, SUB_DIR + '_traffic_model_parameter_gpu_L7app-author1d.pkl')

train_imagepath = os.path.join(BASE_DIR, SUB_DIR, 'train-images-idx3-ubyte')
train_labelpath = os.path.join(BASE_DIR, SUB_DIR, 'train-labels-idx1-ubyte')

test_imagepath = os.path.join(BASE_DIR, SUB_DIR, 't10k-images-idx3-ubyte')
test_labelpath = os.path.join(BASE_DIR, SUB_DIR, 't10k-labels-idx1-ubyte')


if "12" in SUB_DIR:
    DICT = dict_12class
    CLASSNUM = 12
elif "2" in SUB_DIR:
    DICT = dict_2class
    CLASSNUM = 2
elif "3" in SUB_DIR:
    DICT = dict_3class
    CLASSNUM = 3
else:
    if "no" in SUB_DIR:
        DICT = dict_6class_novpn
        CLASSNUM = 6
    else:
        DICT = dict_6class_vpn
        CLASSNUM = 6


class Model(torch.nn.Module):

    def __init__(self):
        super(Model, self).__init__()
        # Mnist的model
        self.conv1 = torch.nn.Sequential(torch.nn.Conv2d(1, 32, kernel_size=(1, 25), stride=1, padding=1),
                                         torch.nn.ReLU(),
                                         torch.nn.MaxPool2d(stride=(1, 3), kernel_size=(1, 3)),
                                         torch.nn.Conv2d(32, 64, kernel_size=(1, 25), stride=1, padding=1),
                                         torch.nn.ReLU(),
                                         torch.nn.MaxPool2d(stride=(1, 3), kernel_size=(1, 3)))
        self.dense = torch.nn.Sequential(torch.nn.Linear(77 * 5 * 64, 1024),
                                         torch.nn.ReLU(),
                                         torch.nn.Dropout(p=0.5),
                                         torch.nn.Linear(1024, CLASSNUM))
        # 文章的model，padding无法修改
        # self.conv1 = torch.nn.Sequential(torch.nn.Conv2d(1, 32, kernel_size=(25, 1), stride=1),
        #                                  torch.nn.ReLU(),
        #                                  torch.nn.MaxPool2d(kernel_size=(3, 1), stride=3),
        #
        #                                  torch.nn.Conv2d(32, 64, kernel_size=(25, 1), stride=1),
        #                                  torch.nn.ReLU(),
        #                                  torch.nn.MaxPool2d(kernel_size=(3, 1), stride=3))
        #
        # self.dense = torch.nn.Sequential(torch.nn.Linear(88 * 64, 1024),
        #                                  torch.nn.ReLU(),
        #                                  torch.nn.Dropout(p=0.5),
        #                                  torch.nn.Linear(1024, 12))

    def forward(self, x):
        x = x.clone().detach().float()
        # x = torch.tensor(x, dtype=torch.float32)  # UserWarning: 数据转换
        x = self.conv1(x)
        x = x.view(-1, 77 * 5 * 64)
        x = self.dense(x)
        return x


model = Model()
summary(model, input_size=(1, 1, 784))

# add model to CUDA
device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
if torch.cuda.device_count() > 1:
    print("Let's use", torch.cuda.device_count(), "GPUs!")
model = nn.DataParallel(model)
model.to(device)

cost = torch.nn.CrossEntropyLoss()
optimizer = torch.optim.Adam(model.parameters(), lr=1e-4)

MIN_LOSS = 0
MAX_ACCURACY = 0


def train_model(train_image, train_label, test_image, test_label):
    global MAX_ACCURACY
    rr = list(range(len(train_image)))
    train_batchnum = len(rr) // batchsize

    test_rr = list(range(len(test_image)))
    test_batchnum = len(test_rr) // batchsize

    data_train_len = batchsize * train_batchnum  # 数字
    data_test_len = batchsize * test_batchnum  # 数字

    # 信息打印
    print("batchsize is {}".format(batchsize))
    print("total train images is {}, train batchnum is {}".format(data_train_len, train_batchnum))
    print("total test images is {}, test batchnum is {}".format(data_test_len, test_batchnum))

    for epoch in range(n_epochs):
        running_loss = 0.0
        running_correct = 0
        print("Epoch {}/{}".format(epoch, n_epochs))
        print("-" * 10)

        np.random.shuffle(rr)
        np.random.shuffle(test_rr)

        for j in range(train_batchnum):
            model.train()
            index = rr[j * batchsize: j * batchsize + batchsize]
            X_train = train_image[index]
            y_train = train_label[index]

            X_train, y_train = Variable(X_train).view(-1, 1, 1, 784), Variable(y_train)

            # copy tensor to GPU
            X_train_GPU = X_train.to(device)  #
            y_train_GPU = y_train.to(device)  #

            optimizer.zero_grad()  # 和model(X_train)改变了顺序
            outputs = model(X_train_GPU)  # X_train 输入数据接口问题
            loss = cost(outputs, y_train_GPU)
            loss.backward()
            optimizer.step()

            running_loss += loss.item()

            _, pred = torch.max(outputs.data, 1)
            running_correct += torch.sum(pred.cpu() == y_train.data)
        testing_correct = 0

        # 测试
        for i in range(test_batchnum):
            model.eval()
            index = test_rr[i * batchsize: i * batchsize + batchsize]
            X_test = test_image[index]
            y_test = test_label[index]
            X_test, y_test = Variable(X_test).view(-1, 1, 1, 784), Variable(y_test)

            X_test_GPU = X_test.to(device)  #
            y_test_GPU = y_test.to(device)  #

            outputs = model(X_test_GPU)
            _, pred = torch.max(outputs.data, 1)
            testing_correct += torch.sum(pred.cpu() == y_test.data)

        train_loss = running_loss / data_train_len
        train_accuracy = 100 * running_correct / data_train_len
        test_accuracy = 100 * testing_correct / data_test_len

        print("Loss is:{:.4f}, Train Accuracy is:{:.4f}%, Test Accuracy is:{:.4f}".format(
            train_loss, train_accuracy, test_accuracy))

        if test_accuracy > MAX_ACCURACY:
            torch.save(model.state_dict(), model_path)
            print(" Model Saved -- Epoach {}".format(epoch))
            MAX_ACCURACY = test_accuracy


def test_model(test_image, test_label):
    model.eval()
    test_rr = list(range(len(test_image)))
    np.random.shuffle(test_rr)
    test_batchnum = len(test_rr) // batchsize
    random_start = np.random.randint(0, test_batchnum)

    # index = test_rr[random_start * batchsize: random_start * batchsize + batchsize]
    index = test_rr[: test_batchnum * batchsize]

    X_test = test_image[index]
    y_test = test_label[index]

    X_test, y_test = Variable(X_test).view(-1, 1, 1, 784), Variable(y_test)  # 输入值的获取变形维度

    # copy tensor to GPU
    X_test_GPU = X_test.to(device)
    y_test_GPU = y_test.to(device)

    X_test_GPU = Variable(X_test_GPU)
    outputs = model(X_test_GPU)
    _, pred = torch.max(outputs, 1)  # 预测值的获取。

    # 转换成cpu
    pred = pred.cpu()

    print("Predict Label is:", [i for i in pred.data])
    print("Real Label is:", [i for i in y_test])

    # 2分类转多分类的指标选取
    test_loss = cost(outputs, y_test_GPU)
    test_accuracy = accuracy_score(y_test, pred)
    test_f1 = f1_score(y_test, pred, average='micro')
    precision = precision_score(y_test, pred, average='micro')
    recall = recall_score(y_test, pred, average='micro')

    # 多分类的直接指标
    kappa = cohen_kappa_score(y_test, pred)
    # confusion  report
    t = classification_report(y_test, pred, target_names=[DICT[i] for i in sorted(list(DICT.keys()))])
    print(t)

    # ap = average_precision_score(y_test, pred)
    # roc_auc = roc_auc_score(y_test, pred)

    # 画图
    # confusion matrix
    draw_confusion_matrix(y_test, pred)

    # pr-curve
    # precision, recall, thresholds = precision_recall_curve(y_test, pred)
    # pr_auc = auc(recall, precision)
    # draw_pr_curve(y_test, pred)

    # roc-curve
    # draw_roc_curve(y_test, pred)

    print('Test_loss: %.3f  Accuracy: %.3f  F1_score: %.3f  precision_score: %.3f  recall_score: %.3f' %
          (test_loss, test_accuracy, test_f1, precision, recall))

    print("kappa_score: %.3f" % kappa)


def draw_pr_curve(y_test, y_pred):
    # plot no skill
    precision, recall, thresholds = precision_recall_curve(y_test, y_pred)
    # plt.figure(1)
    plt.title("precision recall curve")
    plt.plot([0, 1], [0.5, 0.5], linestyle='--')
    plt.plot(recall, precision, marker='.')
    plt.xlabel('recall')
    plt.ylabel('precision')
    plt.savefig('pr_curve')


def draw_roc_curve(y_test, y_pred):
    # plt.figure(2)
    fpr, tpr, thresholds = roc_curve(y_test, y_pred)  # false positive rate, true positive rate
    plt.plot([0, 1], [0, 1], linestyle='--')
    plt.plot(fpr, tpr, marker='.')
    plt.title("roc_curve")
    plt.xlabel('false positive rate')
    plt.ylabel('true positive rate')
    plt.savefig('roc_curve')


def draw_confusion_matrix(y_test, y_pred):
    # 混淆矩阵 已修改
    # plt.figure(3)
    # cm = confusion_matrix(y_test, y_pred)
    # print(cm)
    # # Transform to df for easier plotting
    # start = min(list(DICT.keys()))
    # end = max(list(DICT.keys()))
    # cm_df = pd.DataFrame(cm, index=list(range(start, end+1)), columns=list(range(start, end+1)))
    # sns.heatmap(cm_df, annot=True, fmt="d")
    # plt.ylabel('True label')
    # plt.xlabel('Predicted label')
    # plt.xticks([i for i in range(start, end+1)], [DICT[i] for i in range(start, end+1)])
    # plt.yticks([i for i in range(start, end+1)], [DICT[i] for i in range(start, end+1)])
    # plt.savefig("confusion matrix")

    # 为了写成通用的
    start = min(list(DICT.keys()))
    end = max(list(DICT.keys()))
    indices = [i for i in range(start, end + 1)]
    classes = [DICT[i] for i in range(start, end + 1)]

    confusion = confusion_matrix(y_test, y_pred, labels=indices)
    print(confusion)

    ax = sns.heatmap(confusion, annot=True, fmt="d", xticklabels=classes, yticklabels=classes, cmap="Greys")
    ax.set_ylabel('True label')
    ax.set_xlabel('Predicted label')
    ax.set_title(SUB_DIR + " confusion matrix")
    # 保存文件的地址
    plt.savefig(os.path.join(BASE_DIR, SUB_DIR, "confusion matrix-1d"))
    plt.show()


def load_data(imagepath, labelpath):
    image = read_image_file(imagepath)
    label = read_label_file(labelpath)
    assert len(image) == len(label), "标签数量和图片数量不一致"
    return image, label


def iter_load_data(image, label, batchsize, batchnum):
    for each_batch in range(batchnum):
        batch_data = image[each_batch * batchsize:(each_batch + 1) * batchsize].view(-1, 1, 1, 784)
        batch_label = label[each_batch * batchsize:(each_batch + 1) * batchsize]
        yield (batch_data, batch_label)


def main(is_train):
    global model
    # train_image, train_label = load_data(train_imagepath, train_labelpath)
    # test_image, test_label = load_data(test_imagepath, test_labelpath)
    imagepath = os.path.join(r"D:\sharing_F\L7\20201223-new-mailpcap\3class", 'train-images-idx3-ubyte')
    labelpath = os.path.join(r"D:\sharing_F\L7\20201223-new-mailpcap\3class", 'train-labels-idx1-ubyte')

    main_datasets = MyDataSet(imagepath, labelpath)
    index = [i for i in range(len(main_datasets))]
    np.random.shuffle(index)
    train_length = int(len(main_datasets) / 10 * 8)

    train_image, train_label = [], []
    test_image, test_label = [], []
    for i in range(train_length):
        img, label = main_datasets[index[i]]
        train_image.append(img.numpy())
        train_label.append(label)

    for i in range(train_length, len(main_datasets)):
        img, label = main_datasets[index[i]]
        test_image.append(img.numpy())
        test_label.append(label)
    train_image = torch.from_numpy(numpy.array(train_image))
    train_label = torch.from_numpy(numpy.array(train_label))
    test_image = torch.from_numpy(numpy.array(test_image))
    test_label = torch.from_numpy(numpy.array(test_label))

    print("total train images is {} (not count in batchsize)".format(len(train_image)))
    print("total test  images is {} (not count in batchsize)".format(len(test_image)))

    if is_train == "train":
        if os.path.exists(model_path):
            print("load model and continue to train")
            model.load_state_dict(torch.load(model_path))
            train_model(train_image, train_label, test_image, test_label)
            test_model(test_image, test_label)
        else:
            print("No model loaded, we train first")
            train_model(train_image, train_label, test_image, test_label)
            test_model(test_image, test_label)

    else:
        if os.path.exists(model_path):
            model.load_state_dict(torch.load(model_path))
            test_model(test_image, test_label)
        else:
            raise Exception("No model saved, please train model first!")


if __name__ == '__main__':
    # show()
    is_train = "train"
    # is_train = "test"
    main(is_train)
