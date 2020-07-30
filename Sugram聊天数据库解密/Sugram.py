# -*- coding: utf-8 -*-

#-------------头文件-----------
import os
import sys
import base64
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
import json

#---------------------------------------------------------------------------------------------



'''

填充方式

'''
def pkcs7_unpadding(padded_data):
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data)

    try:
        uppadded_data = data + unpadder.finalize()
    except ValueError:
        raise Exception('无效的加密信息!')
    else:
        return uppadded_data


'''

#Sugram 聊天数据库解密 验证程序 POC ____by Lee

'''

def DecryptDatabaseMsg(msg):
    BS = AES.block_size
    pad = lambda s: s +(BS - len(s)% BS)* chr(BS - len(s)% BS)
    unpad =lambda s : s[0:-ord(s[-1])]
    
    #Base64解码
    sourcebytes = base64.b64decode(msg)
    
    #密钥 和 IV
    key  = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    #IV   = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

    #开始解密
    cipher = AES.new(key, AES.MODE_CBC)
    padoutput = cipher.decrypt(sourcebytes)
    output = pkcs7_unpadding(padoutput)
    print(output)
    
    

#kCCOptionPKCS7Padding
  
#DecryptDatabaseMsg("4z4c3GRkFgefG+5ZnFeWjA==")
#DecryptDatabaseMsg("+/M1puQFKWjLDjlc+RFMUg==")
DecryptDatabaseMsg("+/M1puQFKWjLDjIc+RFMUg==")
