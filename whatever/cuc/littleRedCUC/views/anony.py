

from flask import redirect, render_template, send_from_directory, current_app,request,flash,url_for,logging,abort
import flask
from flask_login import login_required
from littleRedCUC.forms import SignUpForm
from littleRedCUC.db_models import User,db
from littleRedCUC.blueprints import anony
import re

@anony.route('/')
def home():
    return render_template('layout.html')



@anony.route('/posts',methods=['GET', 'POST'])
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
    if request.method == 'POST' :
    # and form.validate():
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


@anony.route('/images/<image_name>')
def images(image_name):
    try:
        return send_from_directory(current_app.config["UPLOAD_FOLDER"],
                                   path=image_name)
    except FileNotFoundError:
        abort(404)