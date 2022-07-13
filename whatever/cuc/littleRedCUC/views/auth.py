
import imp
from flask import render_template, redirect, url_for, request,send_from_directory,current_app,flash,abort
from flask_login import LoginManager as login_manager
from flask_login import login_required, login_user, logout_user
import re

from littleRedCUC.forms import SignInForm,SignUpForm

from littleRedCUC.blueprints import auth
from littleRedCUC.db_models import User,Post
from littleRedCUC.extensions import login_manager
from littleRedCUC.db_models import db




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
        else:
            return redirect(url_for('auth.login'))
    
    return render_template('login.html', form=form)
    # return redirect(url_for('auth.layout'))
    


@auth.route('/layout')
def layout():
    # posts=Post.query.all()
    # img = images(posts.)
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


@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignUpForm(request.form)
    pattern=[]
    pattern.append(re.compile('[a-z]'))
    pattern.append(re.compile('[A-Z]'))
    pattern.append(re.compile('[0-9]'))
    pattern.append(re.compile('[!-/:-@[-`{-~]'))
    namepattern=re.compile('[0-9A-Za-z\\u4E00-\\u9FFF]+')
    threshold=0
    if request.method == 'POST' :
    # and form.validate():
        # print(2222)
        if form.validate_on_submit():
            user = User.query.filter_by(email=form.email.data).first()
            email=form.email.data
            password=form.password.data
            name=form.name.data
            confirm=form.comfirm.data
            if user:
                flash('邮箱已存在')
                return render_template('signup.html',form=form)

            if not namepattern.fullmatch(name):
                flash('用户名不合法')
                return render_template('signup.html',form=form)

            user = User.query.filter_by(name=form.name.data).first()
            if user:
                flash('用户名已存在')
                return render_template('signup.html',form=form)
            
            
            for i in range(4):
                if pattern[i].search(password):
                    threshold+=1
            
            if threshold<3:
                flash("请使用强密码")
                return render_template('signup.html',form=form)
        
            user=User(email=form.email.data,_password=form.password.data)
            db.session.add(user)
            flash('welcome to littleRedCUC')
            return redirect(url_for('auth.login'))
            
        else:
            flash("确认密码与密码不符")
            return render_template('signup.html',form=form)

    return render_template('signup.html',form=form)
  
  
  
    # if request.method == 'POST':
    #     if request.form['password1'] != request.form['password2']:
    #         error = '两次密码不相同！'
    #     elif valid_regist(request.form['username'], request.form['email']):
    #         user = User(username=request.form['username'], password=request.form['password1'], email=request.form['email'])
    #         db.session.add(user)
    #         db.session.commit()
            
    #         flash("成功注册！")
    #         return redirect(url_for('login'))
    #     else:
    #         error = '该用户名或邮箱已被注册！'
    
    # return render_template('regist.html', error=error)