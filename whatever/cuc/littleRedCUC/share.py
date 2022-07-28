import time
from pathlib import Path

from flask import current_app, flash
from littleRedCUC.db_models import Share_File, Post_File
from littleRedCUC.extensions import db
from littleRedCUC.DigitalSignature import Decode_SK
from littleRedCUC.Sym_cryptography import sym_decrypt, generate_key, sym_encrypt

from littleRedCUC.extensions import bcrypt


class share_and_download:
    def __init__(self, id_):
        self.share_code = None
        self.file = Post_File.query.filter_by(file_id=id_).first()
        self.file_name = self.file.file
        self.file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / self.file_name)

    # 用系统私钥解密之后得到key,iv,tag
    def get_keys(self, id_):
        file = Post_File.query.filter_by(file_id=id_).first()
        e_key = file.key
        e_iv = file.iv
        e_tag = file.tag
        # key = Decode_SK(e_key)
        # iv = Decode_SK(e_iv)
        # tag = Decode_SK(e_tag)
        key = e_key
        iv = e_iv
        tag = e_tag
        return key, iv, tag

    def pre_decode(self):
        with open(self.file_path, 'rb') as f:
            cipher_bytes = f.read()
            key, iv, tag = self.get_keys(self.file.file_id)
            file_bytes = sym_decrypt(key, iv, cipher_bytes, tag)
            # print(file_bytes)
        return file_bytes

    # 返回 iv，share_bytes , tag
    def share_encrypt(self):
        # 这里的逻辑是：用share_code 与 文件名 和 内置的 ‘sharing_file' 再次生成key，进行比对
        # 如果一致，则认为share_code 是对的
        # 验证成功后，再谈解密（对称、非对称）的事儿
        file_bytes = self.pre_decode()
        keyword = str(self.file.tag) + str(self.file.file_id) + str(self.file.iv) + str(self.file.file)
        code = keyword[::-1][::8]  # 纯属好玩，但也许也可以增添些个混淆性？哈哈哈哈
        print(code)
        self.share_code = bcrypt.generate_password_hash(code)



        # 为了安全，不要让直接暴露的分享码作为keyword
        temp = code[::3]
        l = len(temp)
        keyword = keyword[:-l] + temp
        # 验证身份和解密的虎符就是code
        # lable 使用id 可以让文件在改名的情况下，也能顺利解码
        context = ['sharing_file', 'share_files', 'file_sharing', 'file_shared']
        context = context[self.file.file_id % 4]
        key = generate_key(keyword, self.file.file_id, context)
        iv, share_bytes, tag = sym_encrypt(file_bytes, key)
        return iv, share_bytes, tag, self.share_code



    def share_decrypt(self, url, code, share_text):
        if self.is_THE_ONE(url, code):
            shared = Share_File.query.filter_by(url)

            iv = Decode_SK(shared.iv)
            tag = Decode_SK(shared.tag)
            keyword = str(self.file.tag) + str(self.file.file_id) + str(self.file.iv) + str(self.file.file)
            code = keyword[::-1][::8]
            temp = code[::3]
            l = len(temp)
            keyword = keyword[:-l] + temp
            context = ['sharing_file', 'share_files', 'file_sharing', 'file_shared']
            context = context[self.file.file_id % 4]
            key = generate_key(keyword, self.file.file_id, context)
            file_bytes = sym_encrypt(key, iv, share_text, tag)
            return file_bytes

    def is_THE_ONE(self, url, code):
        try:
            shared = db.session.query(Share_File, Post_File).join(Share_File,
                                                                  Post_File.file_id == Share_File.file_id).filter(
                Share_File.url == url)
            if bcrypt.check_password_hash(shared.Share_File.share_code, code):
                flash('CORRECT!')
                # redirect?
                return True
            else:
                flash('Error!')
                return False

        except:
            flash('It seems that something goes wrong. Please check the code.')
            return False
            pass

    def sharing_text(self):
        shared = Share_File.query.filter_by(self.file.file_id).first()
        return '分享链接：' + shared.url + ';\n 分享码：' + self.share_code
