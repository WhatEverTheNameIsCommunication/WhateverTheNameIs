from telnetlib import STATUS
from flask import render_template, Flask, redirect, url_for, request
from forms.signin_form import SignInForm
from forms.watermark_form import WatermarkForm 
from forms.receive_form import ReceiveForm
from flask_login import LoginManager, login_required, login_user, logout_user
from models import User
from sender import send_post
from receiver import get_post
from function import encodeImage,decodeImage
from werkzeug.utils import secure_filename
import os

users = [{
    'id': '1',
    'email': 'admin@lfthw.com',
    'password': '111111'
}, {
    'id': '2',
    'email': 'anjing@cuc.edu.cn',
    'password': '123456'
}]

app = Flask('watermark')
app.secret_key = 'LearnFlaskTheHardWay2017'

upload_dir = os.path.join(app.instance_path, 'upload') 
# print(upload_dir) 

if not os.path.exists(upload_dir):
    os.makedirs(upload_dir, mode=0o755)

# Add LoginManager
login_manager = LoginManager()
login_manager.session_protection = 'AdminPassword4Me'
login_manager.login_view = 'signin'
login_manager.login_message = '未登录'
login_manager.login_message_category = "info"
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    for user in users:
        if user['id'] == user_id:
            user = User()
            user.id = user_id
            return user


def query_user(email):
    for user in users:
        if user['email'] == email:
            return user


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/home/?<string:messages>')
def home(messages):
    return render_template('home.html',messages=messages)

@app.route('/signoff')
@login_required
def signoff():
    logout_user()
    return 'Logged out successfully!'


@app.route('/signin', methods=['GET', 'POST'])
def signin():
    form = SignInForm()
    if form.validate_on_submit():
        user = query_user(form.email.data)
        if user is not None and user['password'] == form.password.data:
            current_user = User()
            current_user.id = user['id']

            login_user(current_user)

            next = request.args.get('next')
            status='登录成功'
            return redirect(next or url_for('home',messages=status))

    return render_template('signin.html', form=form)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    save_path = os.path.join(upload_dir, f.filename)
    f.save(save_path)

    return redirect(url_for('watermark'))

@app.route('/watermark', methods=['GET', 'POST'])
@login_required
def watermark():
    form = WatermarkForm()
    if form.validate_on_submit():
        watermark = form.watermark.data
        filename =  form.imagename.data
        save_path = os.path.join(upload_dir, str(filename))
        print(save_path)

        new_image = save_path[:-4]+'output.jpg' 
        post_user=form.emailaddress.data
        post_pwd=form.password.data
        post_text=form.text.data
        encodeImage(save_path,new_image,watermark)
        # embed_watermark(save_path, watermark, str(new_image)) #中文路径会有问题
        url = 'http://127.0.0.1:5000'
        send_post(post_user, post_pwd, post_text,  str(new_image), url)
        status='发送成功'
        return redirect(url_for('home',messages=status))

    return render_template('watermark.html', form=form)


@app.route('/recevier', methods=['GET','POST'])
def receiver():
    form = ReceiveForm()
    if form.validate_on_submit():
        name=form.username.data
        url = 'http://127.0.0.1:5000'
        get_post(url,name)
        mes='收取成功,请查收txt文件'
        return redirect(url_for('home',messages=mes))

    return render_template('receiver.html', form=form)

if __name__ == "__main__":
    app.run(host='127.0.1.3',port=5555,debug=True)
