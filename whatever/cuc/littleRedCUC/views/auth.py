import datetime
from email import message
from flask import render_template, redirect, url_for, request, send_from_directory, current_app, flash

from flask_login import login_required, login_user, logout_user, current_user
from flask_restful import reqparse
from sqlalchemy import null

from littleRedCUC.forms import SignInForm, VertifyForm, FindForm, ChangepasswdForm, PostForm,ShareForm
from littleRedCUC.db_models import User, db, UserRole, Post_File, Share_File
from littleRedCUC.blueprints import auth
from littleRedCUC.extensions import login_manager
from littleRedCUC import TotpFactory
from littleRedCUC.emailway import generateToken, sendMail, vertifToken
import csv
import os
import pandas as pd
import numpy as np
import re
from littleRedCUC.extensions import bcrypt

import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFCMAC, Mode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import time

from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer

@login_manager.user_loader
def load_user(userid):
    return User.query.filter(User.id == userid).first()


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = SignInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        if user.is_correct_password(form.password.data):
            login_user(user)
            next = request.args.get('next')
            return redirect(next or url_for('auth.layout'))
        #     if form.emailway.data:
        #         totp=TotpFactory.new()
        #         data=totp.to_json()
        #         # totp = TOTP.from_source(data)
        #         sendMail(totp.generate().token,'','','',form.email.data,'')
        #         # 存文件cv2???里传参....
        #         headers=['email_address','totp']
        #         data = [form.email.data, data]
        #         with open('2FA.csv', mode='a', newline='', encoding='utf-8-sig') as f:
        #                 csv_writer = csv.writer(f, delimiter=',')
        #                 if not os.path.getsize('2FA.csv'):
        #                     csv_writer.writerow(headers)
        #                 csv_writer.writerow(data)
        #     elif form.goole.data:
        #         print('You choose goole way')
        #     return redirect(url_for('auth.authentic'))
        # else:
        #     return redirect(url_for('auth.login'))

    return render_template('login.html', form=form)


@auth.route('/2fa', methods=['GET', 'POST'])
def authentic():
    form = VertifyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        matrix = pd.read_csv('D:/homework-2022-s/XiaoXueQI/zcfxc/CUC/whatever/cuc/2FA.csv')  # 请更改为自己电脑上的完整路径
        matrix = np.array(matrix)
        a = matrix.shape[0]
        for i in range(a - 1, -1, -1):
            if matrix[i][0] == form.email.data:
                key = matrix[i][1]
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
    return render_template('2fa.html', form=form)


@auth.route('/find', methods=['GET', 'POST'])
def find():
    form = FindForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        email = form.email.data
        if user:
            totp = TotpFactory.new()
            data = totp.to_json()
            # totp = TOTP.from_source(data)
            sendMail(totp.generate().token, '', '', '', form.email.data, '')
            # 存文件cv2???里传参....
            headers = ['email_address', 'totp']
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
    return render_template('find.html', form=form)


@auth.route('/passwd', methods=['GET', 'POST'])
def changepasswd():
    form = VertifyForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        matrix = pd.read_csv('./2FA.csv')  # 请更改为自己电脑上的完整路径
        matrix = np.array(matrix)
        a = matrix.shape[0]
        for i in range(a - 1, -1, -1):
            if matrix[i][0] == form.email.data:
                key = matrix[i][1]
                break
        print(key)
        print(form.vc.data)
        # if vertifToken(form.vc.data,key):
        try:
            match = TotpFactory.verify(form.vc.data, key)
            # totp.match(token,time=totp.generate().expire_time) #使用
            return redirect(url_for('auth.changepasswd2'))
        except Exception as err:
            return redirect(url_for('auth.changepasswd'))
    return render_template('passwd.html', form=form)


@auth.route('/changepasswd', methods=['GET', 'POST'])
def changepasswd2():
    form = ChangepasswdForm(request.form)
    pattern = []
    pattern.append(re.compile('[a-z]'))
    pattern.append(re.compile('[A-Z]'))
    pattern.append(re.compile('[0-9]'))
    pattern.append(re.compile('[!-/:-@[-`{-~]'))
    threshold = 0
    if request.method == 'POST':
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            email = form.email.data
            password = form.password.data
            name = form.user_name.data
            confirm = form.confirm.data
            if user:
                for i in range(4):
                    if pattern[i].search(password):
                        threshold += 1

                if threshold < 3:
                    flash("请使用强密码")
                    return render_template('changepasswd.html', form=form)

                user._password = bcrypt.generate_password_hash(form.password.data)
                db.session.commit()
                flash('welcome to littleRedCUC')
                return redirect(url_for('auth.login'))
            else:
                flash('邮箱不存在')
                return render_template('changepasswd.html', form=form)
        else:
            flash("确认密码与密码不符")
            return render_template('changepasswd.html', form=form)

    return render_template('changepasswd.html', form=form)


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


@auth.route('/file')
def display_file():
    files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
    form=ShareForm()
    return render_template('file.html',files = files,form=form)


@auth.route('/file_upload', methods=['GET', 'POST'])
def upload_file():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        print(current_user.id)
        print(user)
        print(user.password)
    except:
        flash('Please login first.')
        return redirect(url_for('auth.login'))

    tstmp = str(int(time.time()))
    ki = str(user.password)+tstmp
    ki = bytes(ki,'utf-8')
    ki = base64.urlsafe_b64encode(ki)
    ki = ki[:16]
    label = base64.urlsafe_b64encode(bytes(str(user.id), 'utf-8'))
    context = base64.urlsafe_b64encode(bytes(user.email, 'utf-8'))
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
    current_app.logger.info('=========================')
    # print(key)
    # return str(key)


    iv = os.urandom(12)
    # print(key)
    encryptor = Cipher(
        algorithms.AES(key=key),
        modes.GCM(iv),
    ).encryptor()

    form = PostForm()
    file = form.file.data
    text = form.text.data
    if request.method == 'POST':
        if form.validate_on_submit():
            file_bytes=file.read()
            # print(file_bytes)
            cipher_bytes = encryptor.update(file_bytes) + encryptor.finalize()
            # print(secure_filename(file.filename))
            file_name = str(user.id) + '-' + secure_filename(file.filename)
            file_path = str(Path(current_app.config['UPLOAD_FOLDER']) /file_name)
            file_object = open(file_path, 'wb')
            file_object.write(cipher_bytes)
            file_object.close()
            # print(cipher_bytes)
            # print(file.filename)
            # print(file_name)
            post = Post_File(user_id=current_user.id,
                             user_name=current_user.name,
                             text=text,
                             file=file_name,
                             key = key)

            db.session.add(post)
            db.session.commit()
            flash('上传成功')

            return redirect(url_for('auth.display_file'))
        else:
            flash('请注意您上传文件的有效性。')
            return render_template('file_upload.html', form=form)

    flash('文件类型仅允许普通文件和Microsoft文档,大小限制在10M以内')
    return render_template('file_upload.html', form=form)


@auth.route('/shared_file.html')
def shared_file():
    return render_template('shared_file.html')

@auth.route('/share',methods=['POST','GET'])
def share():
    
    # 若文件未分享
    if request.method=='POST':
        date=request.form["date"]
        times=request.form["times"]
        file_id=request.form["fileid"]
        date=list(map(int,date.split('-')))
        formdate=datetime.date.today().replace(date[0],date[1],date[2])
        today=datetime.date.today()
        
        #检验时间
        if today.__ge__(formdate): #if today is later than ddl day, which is impossible
            return "截止时间不能晚于提交时间"
        else:
            days=formdate.__sub__(today).days
            timescale=days*24*60*60 # seconds
        
        #检验次数
        if int(times)<1:
            return "至少允许一次下载"
        


        #推送修改数据
        sharefile=Post_File.query.filter(Post_File.file_id==file_id).first()
        sharefile.if_pub=True
        sharefile.timescale=timescale
        sharefile.times=times
        db.session.commit()

        #组成json
        requirement={'expireIn':timescale,'times':times,'id':file_id}

        #初始化签名器
        signer=URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token=signer.dumps(requirement)
        url='https://'+current_app.config['SERVER_NAME']+'/opensharedfile?token='+token
        flash('该文件的分享连接是：'+url)

        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form=ShareForm()
        return render_template('file.html',files = files,form=form)
    #取消分享
    else:
        file_id=request.args["id"]
        sharefile=Post_File.query.filter(Post_File.file_id==file_id).first()
        sharefile.if_pub=False
        sharefile.timescale=0
        sharefile.times=0
        db.session.commit()
        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form=ShareForm()
        db.session.commit()
        return render_template('file.html',files = files,form=form)

@auth.route('/delete')
def delete():
    file_id=request.args["id"]
    try:
        file=Post_File.query.filter(Post_File.file_id==file_id).first()
        name=file.file
        db.session.delete(file)
        db.session.commit()
    except:
        flash("删除出错") 
        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form=ShareForm()
        return render_template("file.html",files = files,form=form)
    
    #删除分享记录
    try:
        file=Share_File.query.filter(Share_File.file_id==file_id)
        db.session.delete(file)
        db.session.commit()
        try:
            path=current_app.instance_path+'/upload'
            os.remove(os.path.join(path,name))
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form=ShareForm()
            return render_template("file.html",files = files,form=form)
        except:
            flash("找不到文件")
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form=ShareForm()
            return render_template("file.html",files = files,form=form)
    except:
        try:
            path=current_app.instance_path+'/upload'
            os.remove(os.path.join(path,name))
            flash("成功删除")
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form=ShareForm()
            return render_template("file.html",files = files,form=form)
        except:
            flash("找不到文件")
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form=ShareForm()
            return render_template("file.html",files = files,form=form)