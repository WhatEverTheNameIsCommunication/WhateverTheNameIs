from flask_login import UserMixin
from sqlalchemy.ext.hybrid import hybrid_property
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime
from littleRedCUC.extensions import db,marshmallow
from littleRedCUC.extensions import bcrypt

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
    text = db.Column(db.String(300))










