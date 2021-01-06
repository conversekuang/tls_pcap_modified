#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
@author: converse
@version: 1.0.0
@file: MyDataLoader.py
@time: 2020/11/13 15:56
"""

from torch.utils.data import Dataset, DataLoader, Sampler
from torchvision.datasets.mnist import read_image_file, read_label_file
import torch
import os
import torchvision
import matplotlib.pyplot as plt


class MyDataSet(Dataset):
    def __init__(self, imagepath, labelpath):
        self.data = read_image_file(imagepath)
        self.targets = read_label_file(labelpath)

    def __getitem__(self, index):
        """
        Args:
            index (int): Index

        Returns:
            tuple: (image, target) where target is index of the target class.
        """
        img, target = self.data[index], int(self.targets[index])
        return img, target

    def __len__(self):
        return len(self.data)


if __name__ == '__main__':
    imagepath = os.path.join(r"D:\sharing_F\y_\Modified_Session_AllLayers\3class", 'train-images-idx3-ubyte')
    labelpath = os.path.join(r"D:\sharing_F\y_\Modified_Session_AllLayers\3class", 'train-labels-idx1-ubyte')
    data_train = MyDataSet(imagepath, labelpath)
    data_loader_train = torch.utils.data.DataLoader(dataset=data_train,
                                                    batch_size=64,
                                                    shuffle=True,
                                                    )
    images, labels = next(iter(data_loader_train))
    images = images.view(-1, 1, 28, 28)
    img = torchvision.utils.make_grid(images)

    img = img.numpy().transpose(1, 2, 0)
    std = [0.5]
    mean = [0.5]
    img = img * std + mean
    print([labels[i] for i in range(64)])
    plt.imshow(img)
    plt.show()
