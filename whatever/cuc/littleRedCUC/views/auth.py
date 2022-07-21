from email import message
from flask import render_template, redirect, url_for, request,send_from_directory,current_app,flash
# from flask_restful import reqparse
from flask_login import login_required, login_user, logout_user,current_user
# from werkzeug.datastructures import FileStorage
from littleRedCUC.forms import SignInForm,VertifyForm,FindForm,ChangepasswdForm,PostForm
from littleRedCUC.db_models import User, db,  UserRole,Post
from littleRedCUC.blueprints import auth
from littleRedCUC.extensions import login_manager
from littleRedCUC import TotpFactory
from littleRedCUC.emailway import generateToken,sendMail,vertifToken
import csv
import os
import pandas as pd
import numpy as np
import re
from littleRedCUC.extensions import bcrypt
from werkzeug.utils import secure_filename


@login_manager.user_loader
def load_user(userid):
    return User.query.filter(User.id == userid).first()


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = SignInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        if user.is_correct_password(form.password.data):
            # login_user(user)
            # next = request.args.get('next')
            # return redirect(next or url_for('auth.layout'))
            if form.emailway.data:
                totp=TotpFactory.new()
                data=totp.to_json()
                # totp = TOTP.from_source(data)
                sendMail(totp.generate().token,'','','',form.email.data,'')
                # 存文件cv2???里传参....
                headers=['email_address','totp']
                data = [form.email.data, data]
                with open('2FA.csv', mode='a', newline='', encoding='utf-8-sig') as f:
                        csv_writer = csv.writer(f, delimiter=',')
                        if not os.path.getsize('2FA.csv'):    
                            csv_writer.writerow(headers)
                        csv_writer.writerow(data)
            elif form.goole.data:
                print('You choose goole way')
            return redirect(url_for('auth.authentic'))
        else:
            return redirect(url_for('auth.login'))

    return render_template('login.html', form=form)

@auth.route('/2fa', methods=['GET', 'POST'])
def authentic():
    form = VertifyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        matrix=pd.read_csv('./2FA.csv')  # 请更改为自己电脑上的完整路径
        matrix=np.array(matrix)
        a=matrix.shape[0]
        for i in range(a-1,-1,-1):
            if matrix[i][0]==form.email.data:
                key=matrix[i][1]
                break
        print(key)
        print(form.vc.data)
        # if vertifToken(form.vc.data,key):
        try:
            match = TotpFactory.verify(form.vc.data, key)
            # totp.match(token,time=totp.generate().expire_time) #使用
            login_user(user)
            return redirect(url_for('auth.layout'))
        except Exception as err:
            return redirect(url_for('auth.authentic'))
    return render_template('2fa.html',form=form)

@auth.route('/find', methods=['GET', 'POST'])
def find():
    form = FindForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        email=form.email.data
        if user:
            totp=TotpFactory.new()
            data=totp.to_json()
            # totp = TOTP.from_source(data)
            sendMail(totp.generate().token,'','','',form.email.data,'')
            # 存文件cv2???里传参....
            headers=['email_address','totp']
            data = [form.email.data, data]
            with open('2FA.csv', mode='a', newline='', encoding='utf-8-sig') as f:
                    csv_writer = csv.writer(f, delimiter=',')
                    if not os.path.getsize('2FA.csv'):    
                        csv_writer.writerow(headers)
                    csv_writer.writerow(data)
            return redirect(url_for('auth.changepasswd'))
        else:
            flash('邮箱不存在')
            return redirect(url_for('auth.find'))
    return render_template('find.html',form=form)

@auth.route('/passwd', methods=['GET', 'POST'])
def changepasswd():
    form = VertifyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        matrix=pd.read_csv('./2FA.csv')  # 请更改为自己电脑上的完整路径
        matrix=np.array(matrix)
        a=matrix.shape[0]
        for i in range(a-1,-1,-1):
            if matrix[i][0]==form.email.data:
                key=matrix[i][1]
                break
        print(key)
        print(form.vc.data)
        # if vertifToken(form.vc.data,key):
        try:
            match = TotpFactory.verify(form.vc.data, key)
            # totp.match(token,time=totp.generate().expire_time) #使用
            return  redirect(url_for('auth.changepasswd2'))
        except Exception as err:
            return redirect(url_for('auth.changepasswd'))
    return render_template('passwd.html',form=form)


@auth.route('/changepasswd', methods=['GET', 'POST'])
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
            name=form.user_name.data
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

@auth.route('/layout')
def layout():
    return render_template('layout.html')

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully!'

@auth.route('/')
def layout2():
    return render_template('layout.html')

@auth.route('/images/<image_name>')
def images(image_name):
    try:
        return send_from_directory(current_app.config["UPLOAD_FOLDER"],
                                   path=image_name)
    except FileNotFoundError:
        abort(404)

@auth.route('/uploads',methods=['GET','POST'])
def uploads():
    form=PostForm()
    file=form.file.data
    text=form.text.data
    if request.method=='POST':
        if form.validate_on_submit():
            filename=secure_filename(file.filename)
            file.save('instance/upload/'+filename)
            post = Post(user_id=current_user.id,
                        user_name=current_user.name,
                        text=text,
                        filename=filename)

            db.session.add(post)
            db.session.commit()
            flash('上传成功')
            return render_template('upload.html',form=form)
        else:
            flash('请注意您上传文件的有效性。')
            return render_template('upload.html',form=form)
    
    flash('文件类型仅允许普通文件和Microsoft文档,大小限制在10M以内')
    return render_template('upload.html',form=form)

@auth.route('/index',methods=['GET','POST'])
def index():
    file = Post.query.filter(Post.user_id==current_user.id).all()
    return render_template('index.html',file=file)