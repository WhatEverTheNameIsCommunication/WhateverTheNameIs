import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import redirect, render_template, send_from_directory, current_app, request, flash, url_for, logging, \
    make_response, send_file
import flask
from flask_login import login_required
from itsdangerous import URLSafeTimedSerializer
from littleRedCUC.forms import SignUpForm, ChangepasswdForm,ClientPostForm,DecodeForm,VerifyForm
from littleRedCUC.db_models import User, db, UserRole, Post_File, Share_File,Client
from littleRedCUC.blueprints import anony
from littleRedCUC.extensions import bcrypt
from littleRedCUC.DigitalSignature import Encode_SK
from littleRedCUC.Sym_cryptography import sym_encrypt, generate_key
from littleRedCUC.share import share_and_download
import re
import os
from littleRedCUC.DigitalSignature import Encode_SK,VertifySignature,Vertify_hmac,Decode_SK,Signature
import hashlib
from littleRedCUC.forms import ShareForm
from littleRedCUC.views.auth import shared_file
from werkzeug.utils import secure_filename
import logging
from flask import Flask

app = Flask(__name__)

@anony.route('/')
def home():
    return render_template('layout.html')


@anony.route('/posts', methods=['GET', 'POST'])
def force_to_login():
    return render_template('/auth/login.html')


@anony.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm(request.form)
    pattern = []
    pattern.append(re.compile('[a-z]'))
    pattern.append(re.compile('[A-Z]'))
    pattern.append(re.compile('[0-9]'))
    pattern.append(re.compile('[!-/:-@[-`{-~]'))
    namepattern = re.compile('[0-9A-Za-z\\u4E00-\\u9FFF]+')
    threshold = 0
    if request.method == 'POST':
        #     user =User(email=form.email.data, name=form.user_name.data,_password=bcrypt.generate_password_hash(form.password.data))
        #     db.session.add(user)
        #     db.session.commit()
        #     flash('welcome to littleRedCUC')
        #     return redirect(url_for('auth.login'))
        # return render_template('signup.html', form=form)
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            email = form.email.data
            password = form.password.data
            name = form.user_name.data
            confirm = form.confirm.data
            if user:
                flash('邮箱已存在')
                return render_template('signup.html', form=form)

            if not namepattern.fullmatch(name):
                flash('用户名不合法')
                return render_template('signup.html', form=form)

            user = User.query.filter_by(name=form.user_name.data).first()
            if user:
                flash('用户名已存在')
                return render_template('signup.html', form=form)

            for i in range(4):
                if pattern[i].search(password):
                    threshold += 1

            if threshold < 3:
                flash("请使用强密码")
                return render_template('signup.html', form=form)

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

            user = User(
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
            return render_template('signup.html', form=form)

    return render_template('signup.html', form=form)


@anony.route('/changepasswd', methods=['GET', 'POST'])
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


# 验证分享码是否正确
@anony.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method=='GET':
        p = request.args["token"]
        print(p)
        app.logger.info('get token:%s',p)
        decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        decoded = decoder.loads(p)
        trueDecoded = decoder.loads(p, decoded['expireIn'])
        print(trueDecoded)
        app.logger.info('token is right')
        code = VerifyForm()
        if trueDecoded:
            return render_template('verify.html',token = p,form=code)
    elif request.method=='POST':
        # print('post!!')
        # print(p)
        # # p = requests.get('https://sec.whateveritis.cuc.edu.cn:5000/anony/verify',params={'token':token})
        # print(p)
        # app.logger.info('get token:%s', p)
        # decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        # decoded = decoder.loads(p)
        # trueDecoded = decoder.loads(p, decoded['expireIn'])
        # print(trueDecoded)
        # app.logger.info('token is right')
        # print(12312312)
        form2 = VerifyForm()
        code = form2.shared_code.data
        url_ = form2.url.data
        shared = Share_File.query.filter_by(url=url_).first()
        file = Post_File.query.filter(Post_File.file_id == shared.file_id).first()
        form = ShareForm()
        userid = file.user_id
        user = User.query.filter(User.id == userid).first()
        user = user.name

        print(code)
        # url = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token=' + p
        temp = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token='
        sad=share_and_download(file.file_id)
        p = url_.replace(temp,'')
        print(url_)
        print(code)
        if sad.is_THE_ONE(url_,code):
            print(33333)
            return render_template('opensharefile.html', file=file, form=form, user=user, token=p)
        else:
            print(44444)
            code=VerifyForm()
            return render_template('verify.html',form=code)



@anony.route('/opensharedfile')
def sharedopenfile():
    p = request.args["token"]
    decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded = decoder.loads(p)
    trueDecoded = decoder.loads(p, decoded['expireIn'])
    if trueDecoded:
        file = Post_File.query.filter(Post_File.file_id == trueDecoded['id']).first()
        form = ShareForm()
        userid = file.user_id
        user = User.query.filter(User.id == userid).first()
        user = user.name
        return render_template('opensharefile.html', file=file, form=form, user=user, token=p)


@anony.route('/download', methods=['GET'])
def download():
    p = request.args["token"]
    decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded = decoder.loads(p)
    trueDecoded = decoder.loads(p, decoded['expireIn'])
    url_ = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token=' + p
    print('粘贴的url')
    print(url_)
    if trueDecoded:
        file = Share_File.query.filter_by(url=url_).first()
        print('file:')
        print(file)
        post = Post_File.query.filter(Post_File.file_id == file.file_id).first()
        name = post.file
        if file.TTL < 1:
            return '下载次数已用完'
        # =============DDL有验证吗？？？？=================passphrase

        else:
            share_id = file.share_id
            user_id = post.user_id
            path_f = str(Path(current_app.config["SHARED_FOLDER"]) / name)
            path = str(Path(current_app.config["SHARED_FOLDER"]))
            name = str(share_id)+name
            l1 = len(str(share_id))
            l2 = len(str(user_id))
            fname=name[l1+1:][l2+1:]
            file.TTL = file.TTL - 1
            db.session.commit()
            return send_from_directory(path, name, as_attachment=True,attachment_filename=fname)

            # except:
            #     print('ERROR!!!!!!!!!!!!!!!!!!!')



            # 下载解密文件如下：
            # try:
            #     id_ = file.file_id
            #     plain_dl = share_and_download(id_)
            #     file_bytes = plain_dl.pre_decode()
            #     l = len(str(file.user_id))
            #     name = name[l + 1:]
            #
            #     k = 'temp'
            #     path_f = str(Path(current_app.instance_path) / k / name)
            #     path = str(Path(current_app.instance_path) / k)
            #     print(path_f)
            #     temp = open(path_f, 'wb')
            #     temp.write(file_bytes)
            #     temp.close()
            #     if_s = Post_File.query.filter(Post_File.file_id == id_).first()
            #     if_s.if_share = True
            #
            #     file.TTL = file.TTL - 1
            #     db.session.commit()
            #     return send_from_directory(path, name, as_attachment=True)
            #
            # except:
            #     print('ERROR!!!!!!!!!!!!!!!!!!!')


@anony.route('/files/<option>/', methods=['GET'])# 匿名者/已登录用户下载  {{ url_for('auth.download',option=1,share_id=file.file) }}  
#<a href="/file/{{'1' + '&'+code.code_id}}">下载。。</a> '/file/<option>&<code_id>'
def download2(option): # 分享码认证成功后
    p = request.args["token"]
    decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded = decoder.loads(p)
    trueDecoded = decoder.loads(p, decoded['expireIn'])
    url_ = 'https://' + current_app.config['SERVER_NAME'] + '/opensharedfile?token=' + p
    # print(url_)
    if trueDecoded:
        file = Share_File.query.filter(Share_File.url == url_).first()
        share_id=file.share_id
        # print(file)
        # name = Post_File.query.filter(Post_File.file_id == file.file_id).first()
        # name = name.file
        if file.TTL < 1:
            return '下载次数已用完'
        if option=='1':
            try:
                print(share_id)
                post = Share_File.query.filter_by(share_id=share_id).first() #分享码表
                file=Post_File.query.filter_by(file_id=post.file_id).first()
                hashfile_name = file.file + '-' +'Ehash.txt'
                hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / hashfile_name)
                if not Path(hashfile_path).exists():
                    file_path=os.path.join(current_app.config["SHARED_FOLDER"], file.file) 
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
                # 重定向返回页面,带文件路径参数
                return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name,as_attachment=True)
            except Exception as err:
                flash('错误')
                return redirect(url_)
        if option=='2':
            try:    
                Share_file=Share_File.query.filter_by(share_id=share_id).first()
                post= Post_File.query.filter_by(file_id=Share_file.file_id).first()
                file_name=post.file
                hashfile_name = file_name + '-' +'hash.txt'
                hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /hashfile_name)
                if not Path(hashfile_path).exists():
                    hash_text=post.hashtext #原始文件哈希值
                    file_object = open(hashfile_path, 'w',encoding='UTF-8')
                    file_object.write(hash_text)
                    file_object.close()
                return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name,as_attachment=True)
            except Exception as err:
                flash('错误')
                return redirect(url_)
        if option=='3':
            try:
                Share_file=Share_File.query.filter_by(share_id=share_id).first() #分享码表
                post= Post_File.query.filter_by(file_id=Share_file.file_id).first()
                signature_name = post.file + '-' +'signature.txt'
                signature_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) /signature_name)
                if not Path(signature_path).exists():
                # file_path=os.join(current_app.config["SHARED_FOLDER"], path=post.file_name)
                # file_object = open(file_path, 'rb')
                # user_id=post.user_id
                # user=User.query.filter_by(id=user_id).first()
                # private_key=Decode_SK(user.sec_key)
                # symmetric_key=Decode_SK(post.key) # 分享码生成的密钥
                # m=Signature(private_key,symmetric_key,file_object)
                    m=Share_file.hmac
                    file_object = open(signature_path, 'wb')
                    file_object.write(m)
                    file_object.close()
                return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name,as_attachment=True)
            except Exception as err:
                flash('错误')
                return redirect(url_)
        if option == '4':
            try:
                dl = share_and_download(share_id)
                path,name = dl.plain_download(if_share=True)
                return send_from_directory(path, name, as_attachment=True)
            except:
                print('ERROR!!!!!!!!!!!!!!!!!!!')
                return redirect(url_)



# 客户端

@anony.route('/De_file', methods=['GET', 'POST'])
def Decode_file():
    share_id = request.args["share_id"]
    form =DecodeForm()
    if form.Decode.data:
        message=vertify(share_id)
        flash(message)
        return render_template('De_file.html', form=form,share_id=share_id)
        # 直接传字节流,还是存成文件再删除


        # return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name)
    elif form.Vertify.data:
        message=vertify(share_id)
        flash(message)
        return render_template('De_file.html', form=form,share_id=share_id)
    else:
        return render_template('De_file.html', form=form,share_id=share_id)

@anony.route('/encrypted_file_upload', methods=['GET', 'POST']) # https://sec.whateveritis.cuc.edu.cn:5000/encrypted_file_upload
def upload_file():

    form = ClientPostForm()
    E_file = form.Encry_file.data
    S_file = form.S_file.data
    code = form.shared_code.data
    url= form.url.data
    if request.method == 'POST':
        if form.validate_on_submit():
            Share_file=Share_File.query.filter_by(url=url).first()
            share_code=Share_file.share_code
            if share_code==code:
                share_id=Share_file.share_id
                file_bytes=E_file.read()
                # print(file_bytes)
                Efile_name = str(int(datetime.now().timestamp() *
                            1000)) + '-' + secure_filename(E_file.filename)
                file_path = str(Path(current_app.config['UPLOAD_FOLDER']) /Efile_name)
                file_object = open(file_path, 'wb')
                file_object.write(file_bytes)
                file_object.close()
                try:
                    Sfile_bytes=S_file.read()
                    Sfile_name = str(int(datetime.now().timestamp() *
                            1000)) + '-' +'Signature'+ '-' + secure_filename(S_file.filename)
                    file_path = str(Path(current_app.config['UPLOAD_FOLDER']) /Sfile_name)
                    file_object = open(file_path, 'wb')
                    file_object.write(Sfile_bytes)
                    file_object.close()
                except Exception as err:
                    Sfile_name=None

                post = Client(
                            file=Efile_name,
                            S_file_name=Sfile_name,
                            share_id = share_id,
                            url=url
                )

                db.session.add(post)
                db.session.commit()
                flash('上传成功')
                url_ = 'https://' + current_app.config['SERVER_NAME'] + '/Decode_file?share_id=' + share_id
                return redirect(url_)
            else:
                flash('认证码错误')
                return render_template('encrypted_file_upload.html', form=form)
        else:
            flash('请注意您上传文件的有效性。')
            return render_template('encrypted_file_upload.html', form=form)

    flash('文件类型仅允许普通文件和Microsoft文档,大小限制在10M以内')
    return render_template('encrypted_file_upload.html', form=form)


@anony.route('/defile/<share_id>') # {{ url_for('anony.vertify',code=file.file) }} 
def vertify(share_id): # 客户端进行数字签名验证
        try:
            Clientpost = Client.query.filter_by(share_id=share_id).first() # 查询客户端表
            file_name=Clientpost.file_name # 用户上传的文件名
            file_path=os.join(current_app.config["UPLOAD_FOLDER"], path=file_name) # 存放上传文件的路径
            file_object = open(file_path, 'rb')# 用户客户端上传的加密文件
            
            signature_path=os.join(current_app.config["UPLOAD_FOLDER"], path=Clientpost.S_file_name) # 用户上传的签名文件存放路径
            signature_object = open(signature_path, 'rb')

            post = Share_File.query.filter_by(share_id=share_id).first()
            hmac_mes=post.hmac_bytes # 分享码加密后文件的hmac
            user_id=post.user_id# 分享码表得到上传者id
            user=User.query.filter_by(id=user_id).first() 
            public_key=user.pub_key
            loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            try:
                m=VertifySignature(loaded_public_key,signature_object,hmac_mes)
                symmetric_key=Decode_SK(post.key)
                # 检验hmac
                mes=hmac_mes # ?
                if Vertify_hmac(mes,symmetric_key,file_object):
                    message='数字签名认证成功,且文件完整性得到认证'
                else:
                    message='数字签名认证成功,但文件完整性未能保证'
            except Exception as err:
                message='数字签名认证失败'
            return message
        except FileNotFoundError:
            abort(404)
