# 对称加密模块

import base64
import os
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFCMAC, Mode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import time
from cryptography.hazmat.primitives.ciphers import Cipher


def generate_key(keyword,label_,context_):
    tstmp = str(int(time.time()))
    ki = str(keyword) + tstmp
    ki = bytes(ki, 'utf-8')
    ki = base64.urlsafe_b64encode(ki)
    ki = ki[:16]
    label = base64.urlsafe_b64encode(bytes(str(label_), 'utf-8'))
    context = base64.urlsafe_b64encode(bytes(context_, 'utf-8'))
    kdf = KBKDFCMAC(
        algorithm=algorithms.AES,
        mode=Mode.CounterMode,
        length=32,
        rlen=4,
        llen=4,
        location=CounterLocation.BeforeFixed,
        label=label,
        context=context,
        fixed=None,
    )
    key = kdf.derive(base64.urlsafe_b64encode(ki))
    # current_app.logger.info('=========================')
    return key


def sym_encrypt(plaintext,k):

    iv = os.urandom(12)
    encryptor = Cipher(
        algorithms.AES(key=k),
        modes.GCM(iv),
    ).encryptor()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv, ciphertext, encryptor.tag


def sym_decrypt(key,iv,ciphertext,tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    file_text = decryptor.update(ciphertext)+decryptor.finalize()
    return file_text