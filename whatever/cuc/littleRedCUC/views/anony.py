from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from flask import redirect, render_template, send_from_directory, current_app, request, flash, url_for
from flask_login import login_required, current_user
from itsdangerous import URLSafeTimedSerializer

from littleRedCUC.forms import SignUpForm, ChangepasswdForm, ClientPostForm, DecodeForm, VerifyForm
from littleRedCUC.db_models import User, db, UserRole, Post_File, Share_File, Client
from littleRedCUC.blueprints import anony
from littleRedCUC.extensions import bcrypt
from littleRedCUC.DigitalSignature import Encode_SK
from littleRedCUC.Sym_cryptography import sym_encrypt, generate_key
from littleRedCUC.share import share_and_download
import re
import os
from littleRedCUC.DigitalSignature import Encode_SK, VertifySignature, Vertify_hmac, Decode_SK, Signature
import hashlib
from littleRedCUC.forms import ShareForm
from littleRedCUC.views.auth import shared_file
from werkzeug.utils import secure_filename
import logging
from flask import Flask

app = Flask(__name__)


@anony.route('/')
def home():
    files = Post_File.query.filter(Post_File.if_pub == True).all()
    return render_template('layout.html', files=files)


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

        # 注册合法性验证
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
    if request.method == 'GET':
        p = request.args["token"]
        app.logger.info('get token:%s', p)
        decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
        decoded = decoder.loads(p)
        trueDecoded = decoder.loads(p, decoded['expireIn'])
        app.logger.info('token is right')
        code = VerifyForm()
        if trueDecoded:
            return render_template('verify.html', token=p, form=code)
    elif request.method == 'POST':
        form2 = VerifyForm()
        code = form2.shared_code.data
        url_ = form2.url.data
        shared = Share_File.query.filter_by(url=url_).first()
        file = Post_File.query.filter(Post_File.file_id == shared.file_id).first()
        form = ShareForm()
        userid = file.user_id
        user = User.query.filter(User.id == userid).first()
        user = user.name

        # url = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token=' + p
        temp = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token='
        sad = share_and_download(file.file_id)
        p = url_.replace(temp, '')
        if sad.is_THE_ONE(url_, code):
            return render_template('opensharefile.html', file=file, form=form, user=user, token=p)
        else:
            code = VerifyForm()
            return render_template('verify.html', form=code)


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


# 下载加密文件
@anony.route('/download', methods=['GET'])
def download():
    p = request.args["token"]
    decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded = decoder.loads(p)
    trueDecoded = decoder.loads(p, decoded['expireIn'])
    url_ = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token=' + p
    if trueDecoded:
        file = Share_File.query.filter_by(url=url_).first()
        post = Post_File.query.filter(Post_File.file_id == file.file_id).first()
        name = post.file
        name = str(post.user_id) + '-' + name

        # 验证下载次数
        if file.TTL < 1:
            return '下载次数已用完'
        else:
            share_id = file.share_id
            user_id = post.user_id
            path_f = str(Path(current_app.config["SHARED_FOLDER"]) / name)
            path = str(Path(current_app.config["SHARED_FOLDER"]))

            name = str(share_id) + '-' + name
            print('sharedname:' + name)
            l1 = len(str(share_id))
            l2 = len(str(user_id))
            fname = name[l1 + 1:][l2 + 1:]
            fname = 'Sen-' + fname

            file.TTL = file.TTL - 1
            db.session.commit()
            return send_from_directory(path, name, as_attachment=True, attachment_filename=fname)


# 匿名者{{ url_for('auth.download',option=1,share_id=file.file) }}
# <a href="/file/{{'1' + '&'+code.code_id}}">下载。。</a> '/file/<option>&<code_id>'
@anony.route('/files/<option>/', methods=['GET'])
def download2(option):  # 分享码认证成功后
    p = request.args["token"]
    decoder = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    decoded = decoder.loads(p)
    trueDecoded = decoder.loads(p, decoded['expireIn'])
    url_ = 'https://' + current_app.config['SERVER_NAME'] + '/verify?token=' + p
    if trueDecoded:
        file = Share_File.query.filter(Share_File.url == url_).first()
        share_id = file.share_id

        if file.TTL < 1:
            return '下载次数已用完'

        # 下载加密文件hash值
        if option == '1':
            try:
                post = Share_File.query.filter_by(share_id=share_id).first()  # 分享码表
                file = Post_File.query.filter_by(file_id=post.file_id).first()
                file_name = file.file
                file_name = str(file.user_id) + '-' + file_name
                file_name = file_name.split('.', 1)[0]
                hashfile_name = file_name + '-' + 'Ehash.txt'
                hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / hashfile_name)

                if not Path(hashfile_path).exists():
                    fname = str(post.share_id) + '-' + str(post.user_id) + '-' + file.file
                    file_path = os.path.join(current_app.config["SHARED_FOLDER"], fname)
                    with open(file_path, "rb") as f:
                        f_bytes = f.read()
                        f.close()

                    hash_text = hashlib.sha256(f_bytes)
                    hash_text = hash_text.hexdigest()  # 加密后文件哈希值
                    file_object = open(hashfile_path, 'w', encoding='UTF-8')
                    file_object.write(hash_text)
                    file_object.close()

                # 重定向返回页面,带文件路径参数
                fname = hashfile_name[len(str(file.user_id)) + 1:]
                return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name,
                                           as_attachment=True, attachment_filename=fname)
            except Exception as err:
                flash('下载加密文件hash值错误')
                return redirect(url_)

        # 下载原始文件哈希值
        if option == '2':
            try:
                Share_file = Share_File.query.filter_by(share_id=share_id).first()
                post = Post_File.query.filter_by(file_id=Share_file.file_id).first()
                file_name = post.file
                file_name = str(post.user_id) + '-' + file_name
                file_name = file_name.split('.', 1)[0]
                hashfile_name = file_name + '-' + 'hash.txt'
                hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / hashfile_name)
                if not Path(hashfile_path).exists():
                    hash_text = post.hashtext  # 原始文件哈希值
                    file_object = open(hashfile_path, 'w', encoding='UTF-8')
                    file_object.write(hash_text)
                    file_object.close()
                fname = hashfile_name[len(str(file.user_id)) + 1:]
                return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name,
                                           as_attachment=True, attachment_filename=fname)
            except Exception as err:
                flash('下载原始文件哈希值错误')
                return redirect(url_)

        # 下载签名文件
        if option == '3':
            try:
                Share_file = Share_File.query.filter_by(share_id=share_id).first()  # 分享码表
                post = Post_File.query.filter_by(file_id=Share_file.file_id).first()

                # 处理一下后缀，以免文件名太粗糙了
                file_name = post.file
                file_name = str(post.user_id) + '-' + file_name
                file_name = file_name.split('.', 1)[0]
                signature_name = file_name + '-' + 'signature.txt'
                signature_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / signature_name)
                m = Share_file.hmac
                user_id = post.user_id
                user = User.query.filter_by(id=user_id).first()
                private_key = Decode_SK(user.sec_key)
                m = Signature(private_key, m)  # 对hmac签名
                file_object = open(signature_path, 'wb')
                file_object.write(m)
                file_object.close()
                fname = signature_name[len(str(file.user_id)) + 1:]
                return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name,
                                           as_attachment=True, attachment_filename=fname)
            except Exception as err:
                flash('下载签名文件错误')
                return redirect(url_)

        # 解密并下载
        if option == '4':
            try:
                current_user.id
                file_id = file.file_id
                dl = share_and_download(file_id)
                path, name = dl.plain_download(if_share=True)
                return send_from_directory(path, name, as_attachment=True)
            except:
                return redirect(url_for('auth.login'))



# 公开文件下载
@anony.route('/pubDL')
def pub_DL():
    option = request.args["option"]
    file_id = request.args["file_id"]
    # 公开文件直接解密下载
    if option == '1':
        plain_dl = share_and_download(file_id)
        path, name = plain_dl.plain_download(if_share=False)
        return send_from_directory(path, name, as_attachment=True)

    if option == '2':
        post = Post_File.query.filter_by(file_id=file_id).first()
        file_name = post.file
        file_name = str(post.user_id) + '-' + file_name
        file_name = file_name.split('.', 1)[0]
        hashfile_name = file_name + '-' + 'hash.txt'
        hashfile_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / hashfile_name)
        if not Path(hashfile_path).exists():
            hash_text = post.hashtext  # 原始文件哈希值
            file_object = open(hashfile_path, 'w', encoding='UTF-8')
            file_object.write(hash_text)
            file_object.close()
        fname = hashfile_name[len(str(post.user_id)) + 1:]
        return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=hashfile_name, as_attachment=True,
                                   attachment_filename=fname)

    # 下载签名文件
    if option == '3':
        post = Post_File.query.filter_by(file_id=file_id).first()
        # 处理一下后缀，以免文件名太粗糙了
        file_name = post.file
        file_name = str(post.user_id) + '-' + file_name
        file_name = file_name.split('.', 1)[0]
        signature_name = file_name + '-' + 'signature.txt'
        signature_path = str(Path(current_app.config['DOWNLOAD_FOLDER']) / signature_name)

        m = post.hmac_text
        user_id = post.user_id
        user = User.query.filter_by(id=user_id).first()
        private_key = Decode_SK(user.sec_key)
        m = Signature(private_key, m)  # 对hmac签名
        file_object = open(signature_path, 'wb')
        file_object.write(m)
        file_object.close()
        fname = signature_name[len(str(post.user_id)) + 1:]
        return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name, as_attachment=True,
                                   attachment_filename=fname)


# 客户端
@anony.route('/De_download', methods=['GET', 'POST'])
def De_download():
    file = request.args["file"]
    client_id = int(file.replace('<Client ', '').replace('>', ''))
    client = Client.query.filter_by(id=client_id)[-1]
    file_id = client.post_fID
    sad = share_and_download(file_id)
    path, name = sad.plain_download(False)
    return send_from_directory(path, name, as_attachment=True)


# 这个好像是我写的废墟来着。。。我忘了救命、、、
@anony.route('/De_file', methods=['GET', 'POST'])
def Decode_file():
    share_id = request.args["share_id"]
    form = DecodeForm()
    file = Client.query.filter_by(share_id=share_id).all()
    if request.method == 'POST':
        if form.Decode.data:
            pass
            # message=vertify(share_id)
            # flash(message)
            # return render_template('De_file.html', files=file,form=form,share_id=share_id)
            # 直接传字节流,还是存成文件再删除

            # return send_from_directory(current_app.config["DOWNLOAD_FOLDER"], path=signature_name)
        elif form.Vertify.data:
            pass
            # message=vertify(share_id)
        #     flash(message)
        #     return render_template('De_file.html', files=file,form=form,share_id=share_id)
        # else:
        #     return render_template('De_file.html', files=file,form=form,share_id=share_id)
    else:
        # flash(message)
        return render_template('De_file.html', files=file, form=form, share_id=share_id)



@anony.route('/encrypted_file_upload',methods=['GET', 'POST'])  # https://sec.whateveritis.cuc.edu.cn:5000/encrypted_file_upload
def upload_file():
    form = ClientPostForm()
    E_file = form.Encry_file.data
    S_file = form.S_file.data
    code = form.shared_code.data
    url = form.url.data
    if request.method == 'POST':
        if form.validate_on_submit():
            Share_file = Share_File.query.filter_by(url=url).first()
            share_code = Share_file.share_code
            sad = share_and_download(Share_file.file_id)

            if sad.is_THE_ONE(url, code):
                share_id = Share_file.share_id
                file_bytes = E_file.read()

                Efile_name = str(int(datetime.now().timestamp() * 1000)) + '-' + secure_filename(E_file.filename)
                file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / Efile_name)
                file_object = open(file_path, 'wb')
                file_object.write(file_bytes)
                file_object.close()
                try:
                    Sfile_bytes = S_file.read()
                    Sfile_name = str(int(datetime.now().timestamp() * 1000)) + '-' + 'Signature' + '-' + secure_filename(S_file.filename)
                    file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / Sfile_name)
                    file_object = open(file_path, 'wb')
                    file_object.write(Sfile_bytes)
                    file_object.close()
                except Exception as err:
                    Sfile_name = None

                post = Client(
                    file_name=Efile_name,
                    S_file_name=Sfile_name,
                    share_id=share_id,
                    url=url,
                    post_fID=Share_file.file_id
                )

                db.session.add(post)
                db.session.commit()
                flash('上传成功')
                url_ = 'https://' + current_app.config['SERVER_NAME'] + '/De_file?share_id=' + str(share_id)
                return redirect(url_)
            else:
                flash('认证码错误')
                return render_template('encrypted_file_upload.html', form=form)
        else:
            flash('请注意您上传文件的有效性。')
            return render_template('encrypted_file_upload.html', form=form)

    flash('文件类型仅允许普通图片和Microsoft文档,大小限制在10M以内')
    return render_template('encrypted_file_upload.html', form=form)


@anony.route('/defile')  # {{ url_for('anony.vertify',code=file.file) }}
def vertify():  # 客户端进行数字签名验证
    try:
        file = request.args["file"]
        client_id = int(file.replace('<Client ', '').replace('>', ''))
        client = Client.query.filter_by(id=client_id)[-1]
        share_id = client.share_id
        file_name = client.file_name  # 用户上传的文件名
        file_path = str(Path(current_app.config['UPLOAD_FOLDER']) / file_name)  # 存放上传文件 的路径

        with open(file_path, "rb") as f:
            file_bytes = f.read()
            f.close()

        signature_path = str(Path(current_app.config['UPLOAD_FOLDER']) / client.S_file_name) # 用户上传的签名文件存放路径
        with open(signature_path, "rb") as f:
            f_bytes = f.read()
            f.close()
        post = Share_File.query.filter_by(share_id=share_id).first()
        hmac_mes = post.hmac  # 分享码加密后文件的hmac
        user_id = post.user_id  # 分享码表得到上传者id
        user = User.query.filter_by(id=user_id).first()
        public_key = user.pub_key
        loaded_public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        m = VertifySignature(loaded_public_key, f_bytes, hmac_mes)  # 认证数字签名
        if m == 1:
            sad = share_and_download(post.file_id)
            key = sad.hash_needed_key()
            symmetric_key = key

            # 检验hmac
            mes = hmac_mes
            output = Vertify_hmac(mes, symmetric_key, file_bytes)
            if output == 1:
                message = '数字签名认证成功,且文件完整性得到认证'
            else:
                message = '数字签名认证成功,但文件完整性未能保证'
        else:
            message = '数字签名认证失败'
        flash(message)
        return render_template('De_file.html', share_id=share_id)
    except FileNotFoundError:
        abort(404)

