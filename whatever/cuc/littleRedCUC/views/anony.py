
from flask import redirect, render_template, send_from_directory, current_app ,request ,flash ,url_for ,logging
import flask
from flask_login import login_required
from littleRedCUC.forms import SignUpForm,ChangepasswdForm
from littleRedCUC.db_models import User, db,  UserRole
from littleRedCUC.blueprints import anony
from littleRedCUC.extensions import bcrypt
import re
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
        
            user =User(email=form.email.data, name=form.user_name.data,_password=bcrypt.generate_password_hash(form.password.data))
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
