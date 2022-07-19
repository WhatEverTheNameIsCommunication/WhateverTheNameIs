from flask import render_template, redirect, url_for, request,send_from_directory,current_app

from flask_login import login_required, login_user, logout_user

from littleRedCUC.forms import SignInForm

from littleRedCUC.blueprints import auth
from littleRedCUC.db_models import User,Post
from littleRedCUC.extensions import login_manager





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

@auth.route('/images/<image_name>')
def images(image_name):
    try:
        return send_from_directory(current_app.config["UPLOAD_FOLDER"],
                                   path=image_name)
    except FileNotFoundError:
        abort(404)



