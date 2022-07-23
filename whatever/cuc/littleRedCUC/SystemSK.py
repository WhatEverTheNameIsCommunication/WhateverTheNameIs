# 密钥扩展
# # https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash

def generate_K():
    otherinfo = b"adminadmin" # 管理员口令
    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=otherinfo,
    )
    key = ckdf.derive(b"input key")
    # ckdf = ConcatKDFHash(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     otherinfo=otherinfo,
    # )
    # ckdf.verify(b"input key", key)
    return key

def get_K(passphrase):
    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=passphrase,
    )
    key = ckdf.derive(b"input key")
    return key

if __name__ == "__main__":
    key=generate_K()
    passphrase=b'adminadmin'
    key2=get_K(passphrase)
    print(key)
    print(key2)

