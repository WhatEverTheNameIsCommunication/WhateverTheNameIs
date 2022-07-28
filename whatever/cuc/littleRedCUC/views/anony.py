from email import message
import hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import redirect, render_template, send_from_directory, current_app ,request ,flash ,url_for ,logging,make_response,send_file
import flask
from flask_login import login_required
from littleRedCUC.forms import SignUpForm,ChangepasswdForm
from littleRedCUC.db_models import User, db,  UserRole,Post_File
from littleRedCUC.blueprints import anony
from littleRedCUC.extensions import bcrypt
import re
import os
from littleRedCUC.DigitalSignature import Encode_SK,VertifySignature,Vertify_hmac,Decode_SK,Signature
import hashlib
from pathlib import Path

@anony.route('/')
def home():
    return render_template('layout.html')



@anony.route('/posts' ,methods=['GET', 'POST'])
def force_to_login():
    
    return render_template('/auth/login.html')


@anony.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm(request.form)
    pattern=[]
    pattern.append(re.compile('[a-z]'))
    pattern.append(re.compile('[A-Z]'))
    pattern.append(re.compile('[0-9]'))
    pattern.append(re.compile('[!-/:-@[-`{-~]'))
    namepattern=re.compile('[0-9A-Za-z\\u4E00-\\u9FFF]+')
    threshold=0
    if request.method == 'POST':
    #     user =User(email=form.email.data, name=form.user_name.data,_password=bcrypt.generate_password_hash(form.password.data))
    #     db.session.add(user)
    #     db.session.commit()
    #     flash('welcome to littleRedCUC')
    #     return redirect(url_for('auth.login'))
    # return render_template('signup.html', form=form)
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            email=form.email.data
            password=form.password.data
            name=form.user_name.data
            confirm=form.confirm.data
            if user:
                flash('邮箱已存在')
                return render_template('signup.html',form=form)

            if not namepattern.fullmatch(name):
                flash('用户名不合法')
                return render_template('signup.html',form=form)

            user = User.query.filter_by(name=form.user_name.data).first()
            if user:
                flash('用户名已存在')
                return render_template('signup.html',form=form)
            
            
            for i in range(4):
                if pattern[i].search(password):
                    threshold+=1
            
            if threshold<3:
                flash("请使用强密码")
                return render_template('signup.html',form=form)

            # ========= 添加公私钥对的分界线 =========





            # 生成公私钥对
            private_key = ed25519.Ed25519PrivateKey.generate()
            private_bytes = private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            )
            print(private_bytes)
            new_private_bytes = Encode_SK(private_bytes)
            # loaded_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_bytes)
            public_key = private_key.public_key()
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )



            user =User(
                email=form.email.data,
                name=form.user_name.data,
                _password=bcrypt.generate_password_hash(form.password.data),
                pub_key=public_bytes,
                sec_key=new_private_bytes
            )
            db.session.add(user)
            db.session.commit()
            flash('welcome to littleRedCUC')
            return redirect(url_for('auth.login'))
            
        else:
            flash("确认密码与密码不符")
            return render_template('signup.html',form=form)

    return render_template('signup.html',form=form)


@anony.route('/changepasswd', methods=['GET', 'POST'])
def changepasswd2():
    form = ChangepasswdForm(request.form)
    pattern=[]
    pattern.append(re.compile('[a-z]'))
    pattern.append(re.compile('[A-Z]'))
    pattern.append(re.compile('[0-9]'))
    pattern.append(re.compile('[!-/:-@[-`{-~]'))
    threshold=0
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            email=form.email.data
            password=form.password.data
            confirm=form.confirm.data
            if user:
                for i in range(4):
                    if pattern[i].search(password):
                        threshold+=1
            
                if threshold<3:
                    flash("请使用强密码")
                    return render_template('changepasswd.html',form=form)
        
                user._password=bcrypt.generate_password_hash(form.password.data)
                db.session.commit()
                flash('welcome to littleRedCUC')
                return redirect(url_for('auth.login'))
            else:
                flash('邮箱不存在')
                return render_template('changepasswd.html',form=form)
        else:
            flash("确认密码与密码不符")
            return render_template('changepasswd.html',form=form)

    return render_template('changepasswd.html',form=form)

@anony.route('/images/<image_name>')
def images(image_name):
    try:
        return send_from_directory(current_app.config["UPLOAD_FOLDER"], path=image_name)
    except FileNotFoundError:
        abort(404)


@anony.route('/file/<code>') # {{ url_for('anony.vertify',code=file.file) }} 
def vertify(code): # 客户端进行数字签名验证
        try:
            post = Post_File.query.filter_by(file_id=code).first() # 改为客户端表
            file_name=post.file_name
            file_path=os.join(current_app.config["UPLOAD_FOLDER"], path=file_name) # 这里路径改为存放上传文件的路径
            file_object = open(file_path, 'wb')# 用户客户端上传的加密文件
            
            signature_path=os.join(current_app.config["UPLOAD_FOLDER"], path='signature'+file_name) # 用户上传的签名文件存放路径
            signature_object = open(signature_path, 'wb')
            post = Post_File.query.filter_by(file=file_name).first()
            code_id=post.user_id # 分享码表的id
            code=User.query.filter_by(id=user_id).first() 
            user_id=code.user_id# 分享码表得到上传者id
            hmac_mes=code.hmac_bytes
            user=User.query.filter_by(id=user_id).first()
            public_key=user.pub_key
            loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            m=VertifySignature(loaded_public_key,signature_object,hmac_mes)
            symmetric_key=Decode_SK(post.key)
            # 检验hmac
            mes=hmac_mes
            if Vertify_hmac(mes,symmetric_key,file_object):
                message='数字签名认证成功,且文件完整性得到认证'
            return message
        except FileNotFoundError:
            abort(404)

@anony.route('/file/<option>/') # 匿名者/已登录用户下载  {{ url_for('auth.download',option=1,file_id=file.file) }}  
#<a href="/file/{{'1' + '&'+code.code_id}}">下载。。</a> '/file/<option>&<code_id>'
def download(option,file_id): # 分享码认证成功后
    if option==1:
        try:
            file_id=flask.request.args.get('file_id')
            post = Post_File.query.filter_by(file=file_id).first() #这里数据库要为分享码对应数据库
            file_name=post.file_name
            hashfile_name = file_name + '-' +'Ehash.txt'
            hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /hashfile_name)
            if not Path(hashfile_path).exists():
                file_path=os.join(current_app.config["SHARED_FOLDER"], path=file_name) # application已改
                file_object = open(file_path, 'wb') # 分享码加密后的文件
                hash_text= hashlib.sha256(file_object)
                hash_text=hash_text.hexdigest() #加密后文件哈希值
                file_object = open(hashfile_path, 'wb')
                file_object.write(hash_text)
                file_object.close()
            return make_response(send_file(
              hashfile_path,
              attachment_filename="Encrypt-file-hash.txt",
              as_attachment=True
             )) # return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name)
        except FileNotFoundError:
            abort(404)
    if option==2:
        try:
            post = Post_File.query.filter_by(file=file_id).first()
            file_name=post.file_name
            hashfile_name = file_name + '-' +'hash.txt'
            hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /hashfile_name)
            if not Path(hashfile_path).exists():
                hash_text=post.hashtext #原始文件哈希值
                file_object = open(hashfile_path, 'wb')
                file_object.write(hash_text)
                file_object.close()
            return make_response(send_file(
              hashfile_path,
              attachment_filename="file-hash.txt",
              as_attachment=True
            )) # return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name)
        except FileNotFoundError:
            abort(404)
    if option==3:
        try:
            post = Post_File.query.filter_by(file=file_id).first()# 分享码数据库表 利用分享码id查询
            file_name=post.file_name # 分享码加密后保存的文件名
            signature_name = file_name + '-' +'signature.txt'
            signature_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /signature_name)
            if not Path(signature_path).exists():
                file_path=os.join(current_app.config["SHARED_FOLDER"], path=file_name)
                file_object = open(file_path, 'wb')
                post = Post_File.query.filter_by(file=file_id).first()# 分享码数据库表 利用分享码id查询
                user_id=post.user_id
                user=User.query.filter_by(id=user_id).first()
                private_key=Decode_SK(user.sec_key)
                symmetric_key=Decode_SK(post.key) # 分享码生成的密钥
                m=Signature(private_key,symmetric_key,file_object)
                file_object = open(signature_path, 'wb')
                file_object.write(m)
                file_object.close()
            return make_response(send_file(
              signature_path,
              attachment_filename="signature.txt",
              as_attachment=True
            )) # return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name)
        except FileNotFoundError:
            abort(404)