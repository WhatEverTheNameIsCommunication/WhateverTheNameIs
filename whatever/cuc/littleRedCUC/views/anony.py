from fileinput import filename
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import redirect, render_template, send_from_directory, current_app ,request ,flash ,url_for ,logging
import flask
from flask_login import login_required
from littleRedCUC.forms import SignUpForm,ChangepasswdForm,ShareForm
from littleRedCUC.db_models import User, db,  UserRole,Post_File
from littleRedCUC.blueprints import anony
from littleRedCUC.extensions import bcrypt
import re
from pathlib import Path
from littleRedCUC.DigitalSignature import Encode_SK
from itsdangerous import URLSafeTimedSerializer


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

@anony.route('/opensharedfile')
def sharedopenfile():
    p=request.args["token"]
    decoder=URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded=decoder.loads(p)
    trueDecoded=decoder.loads(p,decoded['expireIn'])
    if trueDecoded:
        file=Post_File.query.filter(Post_File.file_id==trueDecoded['id']).first()
        form=ShareForm()
        userid=file.user_id
        user=User.query.filter(User.id==userid).first()
        user=user.name
        return render_template('opensharefile.html',file = file,form=form,user=user,token=p)

@anony.route('/download',methods=['GET'])
def download():
    p=request.args["token"]
    decoder=URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded=decoder.loads(p)
    trueDecoded=decoder.loads(p,decoded['expireIn'])
    if trueDecoded:
        file=Post_File.query.filter(Post_File.file_id==trueDecoded['id']).first()
        filename=file.file
        path=os.path.isfile(current_app.instance_path+'/'+'upload'+'/'+filename)
        if file.times<1:
            return '下载次数已用完'
        else:
            if path:
                file.times=file.times-1
                db.session.commit()
                return send_from_directory(Path(current_app.instance_path)/'upload',filename,as_attachment=True)