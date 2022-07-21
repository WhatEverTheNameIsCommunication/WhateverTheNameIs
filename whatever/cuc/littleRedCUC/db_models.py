from flask_login import UserMixin,current_user
from sqlalchemy.ext.hybrid import hybrid_property
from flask_restful import Resource, reqparse
from flask import request, current_app,redirect,url_for
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.fernet import Fernet
from datetime import datetime

import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from datetime import datetime
from pathlib import Path

from littleRedCUC.extensions import db,marshmallow
from littleRedCUC.extensions import bcrypt
from littleRedCUC.utils.paginate import paginate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


import enum

sys_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

sys_public_key = sys_private_key.public_key()


class UserRole(enum.Enum):
    ADMIN = 'Administrator'
    USERS = 'Normal users'

# user models
class User(db.Model, UserMixin):


    __tablename__ = "users"
    __table_args__ = {'mysql_collate': 'utf8_general_ci'}

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=True)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.USERS)
    _password = db.Column(db.String(128), nullable=False)
    created_time = db.Column(db.DateTime, default=datetime.now)
    pub_key = db.Column(db.String, nullable=False)
    sec_key = db.Column(db.String, nullable=False)


    # def __init__(self,email,password,role=UserRole.USERS):
    #     self.email = email.lower()
    #     # self._password(password)
    #     self.role=role




        


    @hybrid_property
    def password(self):
        return self._password

    @password.setter
    def password(self, plaintext):
        self._password = bcrypt.generate_password_hash(plaintext)




    def is_correct_password(self, plaintext):
        return bcrypt.check_password_hash(self._password, plaintext)

    def __repr__(self):
        return "<User %r>" % self.name


class Post_File(db.Model):
    __tablename__ = "Post_File"
    __table_args__ = {'mysql_collate': 'utf8_general_ci'}
    file_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    user_name = db.Column(db.String(100), nullable=False)
    upload_time = db.Column(db.DateTime, default=datetime.now)
    file = db.Column(db.String(255), nullable=False)
    if_pub = db.Column(db.Boolean, default=False)
    key = db.Column(db.String,nullable=False)   # 这是用系统公钥加密过的用来加密文件的对称密钥


class PostSchema(marshmallow.SQLAlchemyAutoSchema):

    id = marshmallow.Int(dump_only=True)

    class Meta:
        model = Post_File
        sql_session = db.session



class PostResource(Resource):
    def get(self, post_id):
        schema = PostSchema()
        post = Post_File.query.get_or_404(post_id)
        return {"post": schema.dump(User).data}

    def put(self, post_id):
        schema = PostSchema(partial=True)
        post = Post_File.query.get_or_404(post_id)
        post, errors = schema.load(request.json, instance=post)
        if errors:
            return errors, 422

        db.session.commit()
        
        return {"msg": "post updated", "post": schema.dump(post).data}

    
    def delete(self, post_id):
        post = Post_File.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()

        return {"msg": "post deleted"}
    

post_parser = reqparse.RequestParser()
# post_parser.add_argument('text', type=str, location='form')
post_parser.add_argument('file', type=FileStorage, location='files')


class PostList(Resource):
    def get(self):
        schema = PostSchema(many=True)
        query = Post_File.query
        return paginate(query, schema)

    # 用系统公钥加密对称密钥，self.key
    def generate_key(cls):
        return base64.urlsafe_b64encode(os.urandom(32))
    def encrypt(self, data):
        return self.encrypt_at_time(data, int(time.time()))

    def encrypt_at_time(self, data, current_time):
        iv = os.urandom(16)
        return self._encrypt_from_parts(data, current_time, iv)



    def _encrypt_from_parts(self, data, current_time, iv):
        utils._check_bytes("data", data)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()  # 设定填充模式为 PKCS7
        padded_data = padder.update(data) + padder.finalize()  # 使用PKCS对数据进行填充
        encryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        basic_parts = (b"\x80" + struct.pack(">Q", current_time) + iv + ciphertext)
        # 把current_time、iv、ciphertext三者合并得到一个basic_parts**

        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(basic_parts)
        hmac = h.finalize()
        return base64.urlsafe_b64encode(basic_parts + hmac)

    def decrypt(self, token, ttl=None):
        timestamp, data = Fernet._get_unverified_token_data(token)
        return self._decrypt_data(data, timestamp, ttl, int(time.time()))

    def decrypt_at_time(self, token, ttl, current_time):
        if ttl is None:
            raise ValueError(
                "decrypt_at_time() can only be used with a non-None ttl"
            )
        timestamp, data = Fernet._get_unverified_token_data(token)
        return self._decrypt_data(data, timestamp, ttl, current_time)

    def extract_timestamp(self, token):
        timestamp, data = Fernet._get_unverified_token_data(token)
        # Verify the token was not tampered with.
        self._verify_signature(data)
        return timestamp

    @staticmethod
    def _get_unverified_token_data(token):
        utils._check_bytes("token", token)
        try:
            data = base64.urlsafe_b64decode(token)
        except (TypeError, binascii.Error):
            raise InvalidToken

        if not data or six.indexbytes(data, 0) != 0x80:
            raise InvalidToken

        try:
            (timestamp,) = struct.unpack(">Q", data[1:9])
        except struct.error:
            raise InvalidToken
        return timestamp, data

    def _verify_signature(self, data):
        h = HMAC(self._signing_key, hashes.SHA256(), backend=self._backend)
        h.update(data[:-32])
        try:
            h.verify(data[-32:])
        except InvalidSignature:
            raise InvalidToken

    def _decrypt_data(self, data, timestamp, ttl, current_time):
        if ttl is not None:
            if timestamp + ttl < current_time:
                raise InvalidToken

            if current_time + _MAX_CLOCK_SKEW < timestamp:
                raise InvalidToken

        self._verify_signature(data)

        iv = data[9:25]
        ciphertext = data[25:-32]
        decryptor = Cipher(
            algorithms.AES(self._encryption_key), modes.CBC(iv), self._backend
        ).decryptor()
        plaintext_padded = decryptor.update(ciphertext)
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            raise InvalidToken
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        unpadded = unpadder.update(plaintext_padded)
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            raise InvalidToken
        return unpadded
    # 使用底层api ，先放放，感觉还可以弄
    # def generate_key_objection(self,filename):
    #     iv = b'filename'
    #     encryptor = Cipher(
    #         algorithms.AES(key=256),
    #         modes.GCM(iv),
    #     ).encryptor()
    #     return  encryptor
    #
    # def get_key(self,encryptor):
    #
    #
    # def encry_file(self,file,key):


    def post(self):
        schema = PostSchema()

        args = post_parser.parse_args()
        # 这里可以用来做文件限制
        # text = args.get('text')
        # if text is None:
        #     text = ''
        #
        # image = args.get('image')
        # if image is None:
        #     return {'msg': 'you must post file.'}, 422


        file = args.get('file')

        file = self._encrypt_from_parts(self,b'file',datetime,iv)
        file_name = str(int(datetime.now().timestamp() *1000)) + '-' + secure_filename(file.filename)



        file.save(str(Path(current_app.config['UPLOAD_FOLDER']) / file_name))
        try:
            post = Post_File(user_id=current_user.id,
                        user_name=current_user.name,
                        file=file_name)

            db.session.add(post)
            db.session.commit()
            return redirect(url_for('auth.layout'))
            # return {"msg": "post created", "post": schema.dump(post)}, 201
        except:
            return redirect(url_for('auth.login'))