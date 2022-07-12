
import imp
from flask import render_template, redirect, url_for, request,send_from_directory,current_app
from flask_login import LoginManager as login_manager
from flask_login import login_required, login_user, logout_user

from littleRedCUC.forms import SignInForm

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
    
    return render_template('auth/login.html', form=form)
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
    form = SignInForm(request.form)
    if request.method == 'POST' :
    # and form.validate():
        print(2222)
        user=User(form.email.data,form.password.data,form.password.data)
        db.session.add(user)
        flash('welcome to littleRedCUC')
        return redirect(url_for('auth.layout'))
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