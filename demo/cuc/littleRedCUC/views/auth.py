
from flask import render_template, redirect, url_for, request,send_from_directory,current_app,flash
from flask_login import LoginManager as login_manager
from flask_login import login_required, login_user, logout_user
from flask_restful import abort

from littleRedCUC.forms import SignInForm,SignUpForm
import re

from littleRedCUC.blueprints import auth
from littleRedCUC.db_models import User,Post
from littleRedCUC.extensions import login_manager,db




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
    
    return render_template('auth/login.html', form=form)
    # return redirect(url_for('auth.layout'))
    
@auth.route('/signup', methods=['GET','POST'])
def signup():
    form=SignUpForm()
    pattern=[]
    pattern.append(re.compile('[a-z]'))
    pattern.append(re.compile('[A-Z]'))
    pattern.append(re.compile('[0-9]'))
    pattern.append(re.compile('[!-/:-@[-`{-~]'))
    namepattern=re.compile('[0-9A-Za-z\\u4E00-\\u9FFF]+')
    threshold=0
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        email=form.email.data
        password=form.password.data
        name=form.name.data
        if user:
            flash('邮箱已存在')
            return render_template('signup.html',form=form)
        user = User.query.filter_by(name=form.name.data).first()

        if not namepattern.fullmatch(name):
            flash('用户名不合法')
            return render_template('signup.html',form=form,m='用户名不合法')
            
        if user:
            flash('用户名已存在')
            return render_template('signup.html',form=form)
        
        
        for i in range(4):
            if pattern[i].search(password):
                threshold+=1
        
        if threshold<3:
            flash("请使用强密码")
            return render_template('signup.html',form=form)
        
        useradd = User(name=name, email=email,email_confirmed=False,role='USERS',_password=password,)
        try:
            db.session.add(useradd)
            db.session.commit()
            return render_template('auth/login.html',form=form)
        except:
            print("error")
    return render_template('signup.html',form=form)

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