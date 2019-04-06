# -*- coding: utf-8 -*-
__author__ = 'fgyro'
import rsa

# 先生成一对密钥，然后保存.pem格式文件，当然也可以直接使用
(pubkey, privkey) = rsa.newkeys(2048)


pub = pubkey.save_pkcs1()
pubfile = open('public2.pem','w+')
pubfile.write(pub)
pubfile.close()


pri = privkey.save_pkcs1()
prifile = open('private.pem','w+')
prifile.write(pri)
prifile.close()
