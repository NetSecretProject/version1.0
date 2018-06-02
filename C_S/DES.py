#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Author: Chunmin Lin (linchunmin1997@gmail.com)
#
# Description: DES implementation in Python 3
#
# ===========================================================

subKeyList = 16 * [[None] * 8]

# 初始置换
IPtable = (58, 50, 42, 34, 26, 18, 10, 2,
           60, 52, 44, 36, 28, 20, 12, 4,
           62, 54, 46, 38, 30, 22, 14, 6,
           64, 56, 48, 40, 32, 24, 16, 8,
           57, 49, 41, 33, 25, 17, 9, 1,
           59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5,
           63, 55, 47, 39, 31, 23, 15, 7)

# 扩展置换
EPtable = (32, 1, 2, 3, 4, 5,
           4, 5, 6, 7, 8, 9,
           8, 9, 10, 11, 12, 13,
           12, 13, 14, 15, 16, 17,
           16, 17, 18, 19, 20, 21,
           20, 21, 22, 23, 24, 25,
           24, 25, 26, 27, 28, 29,
           28, 29, 30, 31, 32, 1)

# P置换，32位数据重新排列
PFtable = (16, 7, 20, 21, 29, 12, 28, 17,
           1, 15, 23, 26, 5, 18, 31, 10,
           2, 8, 24, 14, 32, 27, 3, 9,
           19, 13, 30, 6, 22, 11, 4, 25)

# 末置换
FPtable = (40, 8, 48, 16, 56, 24, 64, 32,
           39, 7, 47, 15, 55, 23, 63, 31,
           38, 6, 46, 14, 54, 22, 62, 30,
           37, 5, 45, 13, 53, 21, 61, 29,
           36, 4, 44, 12, 52, 20, 60, 28,
           35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26,
           33, 1, 41, 9, 49, 17, 57, 25)

# S盒
sBox = 8 * [64 * [0]]

sBox[0] = (14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
           0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
           4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
           15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13)

sBox[1] = (15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
           3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
           0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
           13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9)

sBox[2] = (10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
           13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
           13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
           1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12)

sBox[3] = (7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
           13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
           10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
           3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14)

sBox[4] = (2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
           14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
           4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
           11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3)

sBox[5] = (12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
           10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
           9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
           4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13)

sBox[6] = (4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
           13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
           1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
           6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12)

sBox[7] = (13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
           1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
           7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
           2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11)


def bit2Byte(bitList):
    """将位串转换成字节串"""
    return [int("".join(map(str, bitList[i * 8:i * 8 + 8])), 2) for i in range(len(bitList) // 8)]


def byte2Bit(byteList):
    """将字节串转换为位串"""
    return [(byteList[i // 8] >> (7 - (i % 8))) & 0x01 for i in range(8 * len(byteList))]


def permBitList(inputBitList, permTable):
    """根据输入的置换表对位串进行置换"""
    return [inputBitList[e - 1] for e in permTable]


def permByteList(inByteList, permTable):
    """根据输入的置换表对字节串进行置换"""
    outByteList = (len(permTable) >> 3) * [0]
    for index, elem in enumerate(permTable):
        i = index % 8
        e = (elem - 1) % 8
        if i >= e:
            outByteList[index >> 3] |= \
                (inByteList[(elem - 1) >> 3] & (128 >> e)) >> (i - e)
        else:
            outByteList[index >> 3] |= \
                (inByteList[(elem - 1) >> 3] & (128 >> e)) << (e - i)
    return outByteList


def getIndex(inBitList):
    """将6bit进行置换，以适应S盒的格式（行列）"""
    return (inBitList[0] << 5) + (inBitList[1] << 3) + \
           (inBitList[2] << 2) + (inBitList[3] << 1) + \
           (inBitList[4] << 0) + (inBitList[5] << 4)


def padData(string):
    """给明文添加PKCS5填充（PKCS5 padding）"""
    padLength = 8 - (len(string) % 8)
    return [ord(s) for s in string] + padLength * [padLength]


def unpadData(byteList):
    """从明文中移除PKCS5填充"""
    return "".join(chr(e) for e in byteList[:-byteList[-1]])


def setKey(keyByteList):
    """产生所有的16轮子密钥"""
    PC1table = (57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20, 12, 4)

    PC2table = (14, 17, 11, 24, 1, 5, 3, 28,
                15, 6, 21, 10, 23, 19, 12, 4,
                26, 8, 16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55, 30, 40,
                51, 45, 33, 48, 44, 49, 39, 56,
                34, 53, 46, 42, 50, 36, 29, 32)

    def leftShift(inKeyBitList, round):
        """为密钥进行1位（或者2位）的左移操作"""
        LStable = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)

        outKeyBitList = 56 * [0]
        if LStable[round] == 2:
            outKeyBitList[:26] = inKeyBitList[2:28]
            outKeyBitList[26] = inKeyBitList[0]
            outKeyBitList[27] = inKeyBitList[1]
            outKeyBitList[28:54] = inKeyBitList[30:]
            outKeyBitList[54] = inKeyBitList[28]
            outKeyBitList[55] = inKeyBitList[29]
        else:
            outKeyBitList[:27] = inKeyBitList[1:28]
            outKeyBitList[27] = inKeyBitList[0]
            outKeyBitList[28:55] = inKeyBitList[29:]
            outKeyBitList[55] = inKeyBitList[28]
        return outKeyBitList

    # 密钥置换操作，去除8位奇偶校验位
    permKeyBitList = permBitList(byte2Bit(keyByteList), PC1table)
    for round in range(16):
        # 移位操作，根据轮数进行移位
        auxBitList = leftShift(permKeyBitList, round)
        # 压缩置换，从56位中选择48位
        subKeyList[round] = bit2Byte(permBitList(auxBitList, PC2table))
        permKeyBitList = auxBitList


def encryptBlock(inputBlock):
    """根据已经约定的密钥对8字节分组进行加密"""
    # 首先进行初始置换
    inputData = permByteList(inputBlock, IPtable)
    # 将明文分组分成左半部分与右半部分，各4byte（32bit）长
    leftPart, rightPart = inputData[:4], inputData[4:]
    for round in range(16):
        # 右半部分进行扩展置换，扩展成48位
        expRightPart = permByteList(rightPart, EPtable)
        # 获取该轮的子密钥
        key = subKeyList[round]
        # 将扩展后的右半部分与密钥异或,其中^为按位异或运算符
        indexList = byte2Bit([i ^ j for i, j in zip(key, expRightPart)])
        # S盒代替
        sBoxOutput = 4 * [0]
        for nBox in range(4):
            nBox12 = 12 * nBox
            leftIndex = getIndex(indexList[nBox12:nBox12 + 6])
            rightIndex = getIndex(indexList[nBox12 + 6:nBox12 + 12])
            sBoxOutput[nBox] = (sBox[nBox << 1][leftIndex] << 4) + \
                               sBox[(nBox << 1) + 1][rightIndex]
        # P盒代替
        aux = permByteList(sBoxOutput, PFtable)
        # 与左半部分异或
        newRightPart = [i ^ j for i, j in zip(aux, leftPart)]
        # 左、右半部分交换
        leftPart = rightPart
        rightPart = newRightPart
        # 末置换，返回结果
    return permByteList(rightPart + leftPart, FPtable)


def decryptBlock(inputBlock):
    """根据已经约定的密钥对8字节分组进行解密"""
    inputData = permByteList(inputBlock, IPtable)
    leftPart, rightPart = inputData[:4], inputData[4:]
    for round in range(16):
        expRightPart = permByteList(rightPart, EPtable)
        key = subKeyList[15 - round]
        indexList = byte2Bit([i ^ j for i, j in zip(key, expRightPart)])
        sBoxOutput = 4 * [0]
        for nBox in range(4):
            nBox12 = 12 * nBox
            leftIndex = getIndex(indexList[nBox12:nBox12 + 6])
            rightIndex = getIndex(indexList[nBox12 + 6:nBox12 + 12])
            sBoxOutput[nBox] = (sBox[nBox * 2][leftIndex] << 4) + \
                               sBox[nBox * 2 + 1][rightIndex]
        aux = permByteList(sBoxOutput, PFtable)
        newRightPart = [i ^ j for i, j in zip(aux, leftPart)]
        leftPart = rightPart
        rightPart = newRightPart
    return permByteList(rightPart + leftPart, FPtable)


def DESencrypt(key, inString):
    """用给定的key给明文字符串加密"""
    setKey(key)
    inByteList, outByteList = padData(inString), []
    for i in range(0, len(inByteList), 8):
        outByteList += encryptBlock(inByteList[i:i + 8])
    return outByteList


def DESdecrypt(key, inByteList):
    """用给定的key为密文进行解密"""
    setKey(key)
    outByteList = []
    for i in range(0, len(inByteList), 8):
        outByteList += decryptBlock(inByteList[i:i + 8])
    return unpadData(outByteList)