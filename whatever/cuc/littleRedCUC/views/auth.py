import datetime
from email import message
from flask import render_template, redirect, url_for, request, send_from_directory, current_app, flash, make_response, \
    send_file
import flask
from flask_login import login_required, login_user, logout_user, current_user
from flask_restful import reqparse
from itsdangerous import URLSafeTimedSerializer

from littleRedCUC.forms import SignInForm, VertifyForm, FindForm, ChangepasswdForm, PostForm, ShareForm

from littleRedCUC.db_models import User, db, UserRole, Post_File, Share_File
from littleRedCUC.blueprints import auth
from littleRedCUC.extensions import login_manager
from littleRedCUC import TotpFactory
from littleRedCUC.emailway import generateToken, sendMail, vertifToken
from littleRedCUC.DigitalSignature import Encode_SK
from littleRedCUC.Sym_cryptography import sym_encrypt, generate_key
from littleRedCUC.share import share_and_download
import csv
import os
import pandas as pd
import numpy as np
import re
from littleRedCUC.extensions import bcrypt
import hashlib 
import base64
import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.kdf.kbkdf import CounterLocation, KBKDFCMAC, Mode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from littleRedCUC.DigitalSignature import Decode_SK,Signature
import time

from werkzeug.utils import secure_filename


@login_manager.user_loader
def load_user(userid):
    return User.query.filter(User.id == userid).first()



@auth.route('/')
def home():
    files = Post_File.query.filter(Post_File.if_pub == True).all()
    return render_template('layout.html',files=files)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    form = SignInForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first_or_404()
        if user.is_correct_password(form.password.data):
            login_user(user)
            next = request.args.get('next')
            return redirect(next or url_for('auth.home'))
        #     if form.emailway.data:
        #         totp=TotpFactory.new()
        #         data=totp.to_json()
        #         # totp = TOTP.from_source(data)
        #         sendMail(totp.generate().token,'','','',form.email.data,'')
        #         # 存文件cv2???里传参....
        #         headers=['email_address','totp']
        #         data = [form.email.data, data]
        #         file_name='2FA.csv'
        #         file_path=os.path.join(current_app.config["SYSTEM_FOLDER"], file_name)
        #         with open(file_path, mode='a', newline='', encoding='utf-8-sig') as f:
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
        file_name='2FA.csv'
        file_path=os.path.join(current_app.config["SYSTEM_FOLDER"], file_name)
        matrix = pd.read_csv(file_path)
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
            return redirect(url_for('auth.home'))
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
            file_name='2FA.csv'
            file_path=os.path.join(current_app.config["SYSTEM_FOLDER"], file_name)
            with open(file_path, mode='a', newline='', encoding='utf-8-sig') as f:
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
        file_name='2FA.csv'
        file_path=os.path.join(current_app.config["SYSTEM_FOLDER"], file_name)
        matrix = pd.read_csv(file_path)  # 请更改为自己电脑上的完整路径
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


# @auth.route('/layout')
# def layout():
#     return render_template('layout.html')


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully!'


# @auth.route('/')
# def layout2():
#     return render_template('layout.html')


@auth.route('/file')
@login_required
def display_file():
    try:
        user = User.query.filter_by(id=current_user.id).first()
    except Exception as err:
        flash('Please login first.')
        return redirect(url_for('auth.login'))
    files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
    form = ShareForm()
    user = current_user.id
    user = User.query.filter_by(id=user).first()
    return render_template('file.html', files=files,form=form,user = user.name)


@auth.route('/file_upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    try:
        user = User.query.filter_by(id=current_user.id).first()
        print(current_user.id)
        print(user)
        print(user.password)
    except:
        flash('Please login first.')
        return redirect(url_for('auth.login'))
    form = PostForm()

    if request.method == 'POST':
        form = PostForm()
        file = form.file.data
        text = form.text.data
        if form.validate_on_submit():
            file_bytes = file.read()
            password = user.password
            email = user.email
            id = user.id
            key = generate_key(password, id, email)
            iv, cipher_bytes, en_tag = sym_encrypt(file_bytes, key)
            db_filename=secure_filename(file.filename)
            file_name = str(user.id) + '-' + secure_filename(file.filename)
            file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / file_name)
            file_object = open(file_path, 'wb')
            file_object.write(cipher_bytes)
            file_object.close()
            key = Encode_SK(key)
            iv = Encode_SK(iv)
            en_tag = Encode_SK(en_tag)
            # key = key
            # iv = iv
            # en_tag = en_tag
            ## 计算hmac
            private_key=Decode_SK(user.sec_key)
            symmetric_key=key
            m=Signature(private_key,symmetric_key,cipher_bytes)
            ##
            ## 计算原始文件散列值
            hash_text= hashlib.sha256(file_bytes)
            hash_text=hash_text.hexdigest() 
            ##

            post = Post_File(user_id=current_user.id,
                             user_name=current_user.name,
                             text=text,
                             file=db_filename,
                             key=key, # 加密存储
                             iv=iv,
                             tag=en_tag,
                             hashtext=hash_text,
                             hmac_text = m #字节流
                            )

            db.session.add(post)
            db.session.commit()
            flash('上传成功')

            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form = ShareForm()
            user = current_user.id
            user = User.query.filter_by(id=user).first()
            return render_template('file.html', files=files, form=form, user=user.name)

            # return redirect(url_for('auth.display_file'))
        else:
            flash('请注意您上传文件的有效性。')
            return render_template('file_upload.html', form=form)

    flash('文件类型仅允许普通文件和Microsoft文档,大小限制在10M以内')
    return render_template('file_upload.html', form=form)


@auth.route('/shared_file.html', methods=['GET', 'POST'])
@login_required
def shared_file():
    user_id= current_user.id
    files = Post_File.query.filter(Share_File.user_id==user_id,Post_File.if_share==True).all()
    return render_template('shared_file.html',files=files)


@auth.route('/share', methods=['POST', 'GET'])
@login_required
def share():
    # 若文件未分享
    if request.method == 'POST':
        date = request.form["date"]
        times = request.form["times"]
        file_id = request.form["fileid"]
        print(file_id)
        print(times)
        date = list(map(int, date.split('-')))
        formdate = datetime.date.today().replace(date[0], date[1], date[2])
        today = datetime.date.today()
        user_id = current_user.id
        # 检验时间
        if today.__ge__(formdate):  # if today is later than ddl day, which is impossible
            return "截止时间不能晚于提交时间"
        else:
            days = formdate.__sub__(today).days
            timescale = days * 24 * 60 * 60  # seconds

        # 检验次数
        if int(times) < 1:
            return "至少允许一次下载"

        # 修改Post_File的if_share
        db.session.query(Post_File).filter_by(file_id=file_id).update({"if_share": True})

        # 组成json
        requirement = {'expireIn': timescale, 'times': times, 'id': file_id}

        # 初始化签名器
        signer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        token = signer.dumps(requirement)
        url = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token=' + token


        ## 分享码加密文件
        sharefile = Post_File.query.filter(Post_File.file_id == file_id).first() # 这里是要分享的文件本身，即在postfile中
        id_ = sharefile.file_id     # file_id != share_id
        print('id_:')
        print(id_)
        sad = share_and_download(id_)
        iv, share_bytes, tag, share_code,stamp = sad.share_encrypt()
        share_code = bcrypt.generate_password_hash(share_code)
        en_iv = Encode_SK(iv)
        en_tag = Encode_SK(tag)


        # 生成分享文本
        msg = sad.sharing_text(url)
        flash(msg)


        # 把 if_share 字段设置为true
        post = Post_File.query.filter(Post_File.file_id == id_).first()
        post.if_share = True

        # hmac
        key = sad.hash_needed_key()
        key = Encode_SK(key)

        ## 计算hmac
        user=User.query.filter_by(id = current_user.id).first()
        print('user:',user)
        sec_key = user.sec_key
        private_key=Decode_SK(sec_key)
        symmetric_key=key
        m=Signature(private_key,symmetric_key,share_bytes)

        share = Share_File(
            user_id=current_user.id,
            file_id=file_id,
            share_code=share_code,
            TTL=times,
            DDL=timescale,
            url=url,
            hmac=m,
            iv=en_iv,
            tag=en_tag,
            stamp = stamp
        )
        db.session.add(share)
        db.session.commit()

        # 用分享码加密的文件保存下来，文件名： share_id-user_id-文件名（上传时）
        l = len(str(id_))
        shared = Share_File.query.filter_by(file_id = id_)[-1]
        # print(shared)
        name = post.file
        name = str(post.user_id)+'-'+name
        # name = name[l + 1:]
        share_id = shared.share_id
        # print(share_id)
        name = str(share_id) + '-' + name
        path_f = str(Path(current_app.config["SHARED_FOLDER"]) / name)
        path = str(Path(current_app.config["SHARED_FOLDER"]))
        temp = open(path_f, 'wb')
        temp.write(share_bytes)
        temp.close()

        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form = ShareForm()
        return render_template('file.html', files=files, form=form)
    # 取消分享
    else:
        file_id = request.args["id"]
        file = Post_File.query.filter(Post_File.file_id == file_id).first()
        file.if_share = False

        shared = Share_File.query.filter(file_id == file_id).all()
        for file in shared:
            file.DDL = 0
            file.TTL = 0
        db.session.commit()

        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form = ShareForm()
        user = current_user.id
        user = User.query.filter_by(id=user).first()
        return render_template('file.html', files=files, form=form, user=user.name)
        # return render_template('file.html', files=files, form=form)


@auth.route('/file/<option>/' ,methods=['GET']) # {{ url_for('auth.download',option=1,file_id=file.file_id) }} 
@login_required
def download(option): # 上传者下载

    # 下载加密文件哈希值
    if option=='1':
        try:
            file_id = request.args["file_id"]
            str_list=''.join(file_id)
            file_id=int(str_list)
            post = Post_File.query.filter_by(file_id=file_id).first()
            file_name = post.file
            file_name = str(post.user_id) + '-' + file_name
            file_name = file_name.split('.',1)[0]
            hashfile_name = file_name + '-' +'uploadEhash.txt'
            hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /hashfile_name)
            print(hashfile_path)
            if not Path(hashfile_path).exists():
                file_name = str(post.user_id) + '-' + post.file
                file_path=os.path.join(current_app.config["UPLOAD_FOLDER"], file_name)
                print(file_path)
                with open(file_path, "rb") as f:
                    f_bytes = f.read()
                    f.close()

                hash_text= hashlib.sha256(f_bytes)
                hash_text=hash_text.hexdigest() #加密后文件哈希值
                print(hash_text)
                file_object = open(hashfile_path, 'w',encoding='UTF-8')
                file_object.write(hash_text)
                file_object.close()
            # return make_response(send_file(
            #   signature_path,
            #   attachment_filename="uploadEhash.txt",
            #   as_attachment=True
            # ))
            user_id = post.user_id
            fname = hashfile_name[len(str(user_id)) + 1:]
            return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name,as_attachment=True,attachment_filename=fname)
        except Exception as err:
            flash('下载加密文件哈希值')
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form = ShareForm()
            user = current_user.id
            user = User.query.filter_by(id=user).first()
            return render_template('file.html', files=files, form=form, user=user.name)

    # 下载原始文件哈希值
    if option=='2':
        try:
            file_id = request.args["file_id"]
            str_list=''.join(file_id)
            file_id=int(str_list)
            post = Post_File.query.filter_by(file_id=file_id).first()
            file_name=post.file
            file_name = str(post.user_id) + '-' + file_name
            file_name = file_name.split('.', 1)[0]
            hashfile_name = file_name + '-' +'uploadhash.txt'
            hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /hashfile_name)
            if not Path(hashfile_path).exists():
                hash_text=post.hashtext #原始文件哈希值
                file_object = open(hashfile_path, 'w',encoding='UTF-8')
                file_object.write(hash_text)
                file_object.close()
            user_id = post.user_id
            fname = hashfile_name[len(str(user_id)) + 1:]
            return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name,as_attachment=True,attachment_filename=fname)
        except Exception as err:
            flash('下载原始文件哈希值')
            # return redirect('/auth/file')
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form = ShareForm()
            user = current_user.id
            user = User.query.filter_by(id=user).first()
            return render_template('file.html', files=files, form=form, user=user.name)

    # 下载签名文件
    if option=='3':
        try:
            file_id = request.args["file_id"]
            str_list=''.join(file_id)
            file_id=int(str_list)
            post = Post_File.query.filter_by(file_id=file_id).first()
            file_name = post.file
            file_name=str(post.user_id) + '-' + file_name
            file_name = file_name.split('.', 1)[0]
            signature_name = file_name + '-' +'uploadsignature.txt'
            signature_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /signature_name)
            if not Path(signature_path).exists():
                m=post.hmac_text
                file_object = open(signature_path, 'wb')
                file_object.write(m)
                file_object.close()
            user_id = post.user_id
            fname = signature_name[len(str(user_id))+1:]
            return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name,as_attachment=True,attachment_filename=fname)
        except Exception as err:
            flash('下载签名文件错误')
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form = ShareForm()
            user = current_user.id
            user = User.query.filter_by(id=user).first()
            return render_template('file.html', files=files, form=form, user=user.name)
            # return redirect('/auth/file')

    # 解密并下载
    if option=='4':
        try:
            file_id = request.args["file_id"]
            dl = share_and_download(file_id)
            path, name = dl.plain_download(False)
            return send_from_directory(path, name, as_attachment=True)
        except:
            print('ERROR!!!!!!!!!!!!!!!!!!!')
            flash('解密并下载错误')
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form = ShareForm()
            user = current_user.id
            user = User.query.filter_by(id=user).first()
            return render_template('file.html', files=files, form=form, user=user.name)
            # return redirect('/auth/file')

    # 下载(加密文件）
    if option=='5':
        try:
            file_id = request.args["file_id"]
            post = Post_File.query.filter_by(file_id=file_id).first()
            name = post.file
            name = str(post.user_id) + '-' + name

            l = len(str(post.user_id))
            fname = 'en-'+name[l+1:]

            file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / name)
            path = str(Path(current_app.config['UPLOAD_FOLDER']))

            return send_from_directory(path, name, as_attachment=True,attachment_filename=fname)
        except:
            print('ERROR!!!!!!!!!!!!!!!!!!!')
            flash('下载加密文件错误')
            files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
            form = ShareForm()
            user = current_user.id
            user = User.query.filter_by(id=user).first()
            return render_template('file.html', files=files, form=form, user=user.name)


@auth.route('/public')
@login_required
def public():
    file_id = request.args["file_id"]
    str_list = ''.join(file_id)
    file_id = int(str_list)
    post = Post_File.query.filter_by(file_id=file_id).first()
    post.if_pub = True
    files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
    form = ShareForm()
    db.session.commit()
    user = current_user.id
    user = User.query.filter_by(id=user).first()
    return render_template('file.html', files=files, form=form,user=user.name)

@auth.route('/private')
@login_required
def private():
    file_id = request.args["file_id"]
    str_list = ''.join(file_id)
    file_id = int(str_list)
    post = Post_File.query.filter_by(file_id=file_id).first()
    post.if_pub = False
    files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
    form = ShareForm()
    db.session.commit()
    return render_template('file.html', files=files, form=form)

@auth.route('/delete')
@login_required
def delete():
    file_id = request.args["id"]

    post = Post_File.query.filter(Post_File.file_id == file_id).first()
    share = Share_File.query.filter(Share_File.file_id == file_id).all()
    print(post,share)
    file_name = post.file
    file_name = str(post.user_id) + '-' + file_name

    try:
        # 删除upload中的原始文件
        path = str(Path(current_app.config['UPLOAD_FOLDER']))
        os.remove(os.path.join(path, file_name))
        print('upload')

        try:
            # 删除实体文件
            # 删除download中的各种文件
            dl_fname = file_name.split('.', 1)[0]
            path = str(Path(current_app.config['DOWNLOAD_FOLDER']))
            signature_name = dl_fname + '-' + 'uploadsignature.txt'
            signature_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / signature_name)
            hashfile_name = dl_fname + '-' + 'uploadhash.txt'
            hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / hashfile_name)
            Ehashfile_name = dl_fname + '-' + 'uploadEhash.txt'
            hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / hashfile_name)
            os.remove(os.path.join(path, signature_name))
            print('s 删除成功')
            os.remove(os.path.join(path, hashfile_name))
            print('hash 删除成功')
            os.remove(os.path.join(path, Ehashfile_name))
            print('EHASH ')



            # 删除shared中的所有有关文件
            for i in share:
                shared_id = i.share_id

                share_name = str(shared_id)+'-'+file_name
                path = str(Path(current_app.config["SHARED_FOLDER"]))
                os.remove(os.path.join(path, share_name))
                print('shared')
        except:
            # 认为没有share过，没有download过，所以直接放弃
            pass
    except:
        flash("找不到文件")
        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form = ShareForm()
        return render_template("file.html", files=files, form=form)

    try:
        file = Post_File.query.filter(Post_File.file_id == file_id).first()
        name = file.file
        db.session.delete(file)
        Share_File.query.filter(Share_File.file_id == file_id).delete()
        db.session.commit()
    except:
        flash("删除出错")
        files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
        form = ShareForm()
        return render_template("file.html", files=files, form=form)

    files = Post_File.query.filter(Post_File.user_id == current_user.id).all()
    form = ShareForm()
    return render_template("file.html", files=files, form=form)