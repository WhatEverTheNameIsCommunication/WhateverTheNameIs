from flask_login import UserMixin,current_user
from sqlalchemy.ext.hybrid import hybrid_property
from flask_restful import Resource, reqparse
from flask import request, current_app,redirect,url_for


from datetime import datetime

from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
from datetime import datetime
from pathlib import Path

from littleRedCUC.extensions import db,marshmallow
from littleRedCUC.extensions import bcrypt
from littleRedCUC.utils.paginate import paginate



import enum

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
    PK = db.Column(db.String(128), nullable=False) # 哈希值
    SK = db.Column(db.String(128), nullable=False)


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


class Post(db.Model):
    __tablename__ = "posts"
    __table_args__ = {'mysql_collate': 'utf8_general_ci'}

    id = db.Column(db.Integer, primary_key=True)
    created_time = db.Column(db.DateTime, default=datetime.now)
    user_name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    text = db.Column(db.Text)
    image = db.Column(db.String(255), nullable=False)




class PostSchema(marshmallow.SQLAlchemyAutoSchema):

    id = marshmallow.Int(dump_only=True)

    class Meta:
        model = Post
        sql_session = db.session



class PostResource(Resource):
    def get(self, post_id):
        schema = PostSchema()
        post = Post.query.get_or_404(post_id)
        return {"post": schema.dump(user).data}

    def put(self, post_id):
        schema = PostSchema(partial=True)
        post = Post.query.get_or_404(post_id)
        post, errors = schema.load(request.json, instance=post)
        if errors:
            return errors, 422

        db.session.commit()
        
        return {"msg": "post updated", "post": schema.dump(post).data}

    
    def delete(self, post_id):
        post = post.query.get_or_404(post_id)
        db.session.delete(post)
        db.session.commit()

        return {"msg": "post deleted"}
    

post_parser = reqparse.RequestParser()
post_parser.add_argument('text', type=str, location='form')
post_parser.add_argument('image', type=FileStorage, location='files')


class PostList(Resource):
    def get(self):
        schema = PostSchema(many=True)
        query = Post.query
        return paginate(query, schema)

    def post(self):
        schema = PostSchema()

        args = post_parser.parse_args()

        text = args.get('text')
        if text is None:
            text = ''

        image = args.get('image')
        if image is None:
            return {'msg': 'you must post file.'}, 422

        file_name = str(int(datetime.now().timestamp() *1000)) + '-' + secure_filename(image.filename)
        image.save(str(Path(current_app.config['UPLOAD_FOLDER']) / file_name))
        try:
            post = Post(user_id=current_user.id,
                        user_name=current_user.name,
                        text=text,
                        image=file_name)

            db.session.add(post)
            db.session.commit()
            return redirect(url_for('auth.layout'))
            # return {"msg": "post created", "post": schema.dump(post)}, 201
        except:
            return redirect(url_for('auth.login'))