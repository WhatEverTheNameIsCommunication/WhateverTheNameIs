import hashlib # https://docs.python.org/3/library/hashlib.html
import hmac
from unittest import expectedFailure
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# from SystemSK import get_K
import pandas as pd
import numpy as np
import csv
import os

# t_str = "中国传媒大学"
# t_bytes = t_str.encode('utf8')

# m = hashlib.sha256() # 比 new('sha256') 方式的性能好
# m.update(t_bytes)


# hmac = hmac.new(b'password', t_bytes, 'sha256') # https://docs.python.org/3/library/hmac.html
# print(hmac.hexdigest()) # php -r 'echo hash_hmac('sha256', '中国传媒大学', 'password');'

# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

def get_hmac(symmetric_key,Ciphertext): #Bytes
    m=hmac(symmetric_key, Ciphertext, 'sha256')
    m=m.digest() # 字节流
    m=hmac.hexdigest() # str
    return m

def Vertify_hmac(mes,symmetric_key,Ciphertext): #Bytes
    m=hmac(symmetric_key, Ciphertext, 'sha256').digest()
    hmac.compare_digest(m, mes)
    try:
        hmac.compare_digest(m, mes)# Ciphertext字节流/str
        return True
    except Exception as err:
        return False

def Signature(private_key,symmetric_key,Ciphertext):
    loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key) #已解密的私钥
    # 对加密文件的hmac进行签名,HMAC 采用EtM，使用对称加密的密钥
    m= get_hmac(symmetric_key,Ciphertext) # 字节
    signature = loaded_private_key.sign(m)
    return signature

def VertifySignature(public_key,signature,Ciphertext):
    try:
        public_key.verify(signature, Ciphertext)# Ciphertext字节流
        return True
    except Exception as err:
        return False
    # public_key = private_key.public_key()
    # # Raises InvalidSignature if verification fails
    # public_key.verify(signature, b"my authenticated message")

def generateSPK(emaildata):
    # 生成公私钥对
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    print(private_bytes)
    new_private_bytes=Encode_SK(private_bytes)
    # loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    headers=['user','PK','SK']
    data = [emaildata,public_bytes,new_private_bytes]
    with open('UserSPK.csv', mode='a', newline='', encoding='utf-8-sig') as f:
        csv_writer = csv.writer(f, delimiter=',')
        if not os.path.getsize('UserSPK.csv'):    
            csv_writer.writerow(headers)
        csv_writer.writerow(data)
    private_text= hashlib.sha256(new_private_bytes)
    private_text=private_text.hexdigest()
    public_text= hashlib.sha256(public_bytes)
    public_text=public_text.hexdigest()
    listkey=[private_text]
    print(public_text)
    listkey.append(public_text)
    # return [private_text,public_text]
    return listkey
    # loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_bytes)

def Encode_SK(private_bytes):
    # 使用系统公钥对私钥进行加密
    # 提取csv文件 
    matrix=pd.read_csv('D:/homework-2022-s/XiaoXueQI/zcfxc/CUC/whatever/cuc/System.csv')  # 请更改为自己电脑上的完整路径
    matrix=np.array(matrix)
    PK=matrix[0,0]
    with open(PK, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read()
    )
    # 字节流
    ciphertext = public_key.encrypt(
        private_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def Decode_SK(private_bytes):
    # 使用系统私钥对私钥进行解密
    # 提取csv文件 
    matrix=pd.read_csv('D:/homework-2022-s/XiaoXueQI/zcfxc/CUC/whatever/cuc/System.csv')  # 请更改为自己电脑上的完整路径
    matrix=np.array(matrix)
    SK=matrix[0,1] 
    with open(SK, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'adminadmin',
        )
    plaintext = private_key.decrypt(
    private_bytes,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
    return plaintext

if __name__ == "__main__":
    
    matrix=pd.read_csv('D:/homework-2022-s/XiaoXueQI/zcfxc/CUC/whatever/cuc/UserSPK.csv')  # 请更改为自己电脑上的完整路径
    matrix=np.array(matrix)
    SK=matrix[3,2] 
    print(SK)
    # string=list[0].decode()

    # print(string)
    # print(string.encode())
    # # https://cryptography.io/en/latest/fernet/#implementation
    # symmetric_key = base64.urlsafe_b64encode(key)#AES-GCM-256
    # f = Fernet(symmetric_key)
    # token = f.encrypt(b"Secret message!") #b''
    # # token
    # # b'...'
    # decodeSK=f.decrypt(SK)
    # # b'Secret message!'