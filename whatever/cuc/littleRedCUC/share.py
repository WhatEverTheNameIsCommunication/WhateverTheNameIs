import time
from pathlib import Path

from flask import current_app, flash
from littleRedCUC.db_models import Share_File, Post_File
from littleRedCUC.DigitalSignature import Decode_SK
from littleRedCUC.Sym_cryptography import sym_decrypt, generate_key, sym_encrypt


class share_and_download():
    def __init__(self, id):
        self.share_code = None
        self.file = Post_File.query.filter_by(file_id=id)
        self.file_name = self.file.file
        self.file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / self.file_name)

    # 用系统私钥解密之后得到key
    def get_key(self, id):
        file = Post_File.query.filter_by(file_id=id)
        e_key = file.key
        key = Decode_SK(e_key)
        return key

    def decode_file(self):
        with open(self.file_path, 'rb') as f:
            cipher_bytes = f.read()
            key = self.get_key()
            iv = self.file.iv
            tag = self.file.tag
            file_bytes = sym_decrypt(key, iv, cipher_bytes, tag)

        return file_bytes

    # 这里的逻辑是：用share_code 与 文件名 和 内置的 ‘sharing_file' 再次生成key，进行比对
    # 如果一致，则认为share_code 是对的
    # 验证成功后，再谈解密（对称、非对称）的事儿
    def share_encrypt(self):
        file_bytes = self.decode_file()
        keyword = self.file.tag + str(self.file.id) + self.file.iv + self.file.file
        code = keyword[::-1][::8]  # 纯属好玩，但也许也可以增添些个混淆性？哈哈哈哈
        self.share_code = code
        key = generate_key(code, self.file.file, 'sharing_file')
        share_bytes = sym_encrypt(file_bytes, key)
        return share_bytes

    def is_THE_ONE(self, url, code):
        try:
            shared = Share_File.query.filter_by(url)
            # 把两张表连起来吧
            code_key = generate_key(code,)
        except:
            flash('It seems that something goes wrong. Please check the code.')
            pass

    def sharing_text(self):
        shared = Share_File.query.filter_by(self.file.file_id)
        return '分享链接：' + shared.url + ';\n 分享码：' + self.share_code
